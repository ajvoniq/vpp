/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/dpdk/dpdk.h>

#include <vnet/devices/virtio/vhost-user.h>

#define VHOST_USER_DEBUG_SOCKET 0

#if VHOST_USER_DEBUG_SOCKET == 1
#define DBG_SOCK(args...) clib_warning(args);
#else
#define DBG_SOCK(args...)
#endif

/*
 * DPDK vhost-user functions 
 */

/* portions taken from dpdk 
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


static uint64_t
qva_to_vva(struct virtio_net *dev, uint64_t qemu_va)
{
  struct virtio_memory_regions *region;
  uint64_t vhost_va = 0;
  uint32_t regionidx = 0;

  /* Find the region where the address lives. */
  for (regionidx = 0; regionidx < dev->mem->nregions; regionidx++) {
    region = &dev->mem->regions[regionidx];
    if ((qemu_va >= region->userspace_address) &&
      (qemu_va <= region->userspace_address +
      region->memory_size)) {
      vhost_va = qemu_va + region->guest_phys_address +
        region->address_offset -
        region->userspace_address;
      break;
    }
  }
  return vhost_va;
}

static dpdk_device_t *
dpdk_vhost_user_device_from_hw_if_index(u32 hw_if_index)
{
  vnet_main_t *vnm = vnet_get_main();
  dpdk_main_t * dm = &dpdk_main;
  vnet_hw_interface_t * hi = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  if (xd->dev_type != VNET_DPDK_DEV_VHOST_USER)
    return 0;

  return xd;
}

static dpdk_device_t *
dpdk_vhost_user_device_from_sw_if_index(u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main();
  vnet_sw_interface_t * sw = vnet_get_sw_interface (vnm, sw_if_index);
  ASSERT (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE);

  return dpdk_vhost_user_device_from_hw_if_index(sw->hw_if_index);
}

static inline void * map_guest_mem(dpdk_device_t * xd, u64 addr)
{
  dpdk_vu_intf_t * vui = xd->vu_intf;
  struct virtio_memory * mem = xd->vu_vhost_dev.mem;
  int i;
  for (i=0; i<mem->nregions; i++) {
    if ((mem->regions[i].guest_phys_address <= addr) &&
       ((mem->regions[i].guest_phys_address + mem->regions[i].memory_size) > addr)) {
         return (void *) (vui->region_addr[i] + addr - mem->regions[i].guest_phys_address);
       }
  }
  DBG_SOCK("failed to map guest mem addr %llx", addr);
  return 0;
}

static clib_error_t *
dpdk_create_vhost_user_if_internal (u32 * hw_if_index, u32 if_id)
{
  dpdk_main_t * dm = &dpdk_main;
  vlib_main_t * vm = vlib_get_main();
  vlib_thread_main_t * tm = vlib_get_thread_main();
  vnet_sw_interface_t * sw;
  clib_error_t * error;
  dpdk_device_and_queue_t * dq;

  dpdk_device_t * xd = NULL;
  u8 addr[6];
  int j;

  vlib_worker_thread_barrier_sync (vm);

  int inactive_cnt = vec_len(dm->vu_inactive_interfaces_device_index);
  // if there are any inactive ifaces
  if (inactive_cnt > 0) {
    // take last
    u32 vui_idx = dm->vu_inactive_interfaces_device_index[inactive_cnt - 1];
    if (vec_len(dm->devices) > vui_idx) {
      xd = vec_elt_at_index (dm->devices, vui_idx);
      if (xd->dev_type == VNET_DPDK_DEV_VHOST_USER) {
          DBG_SOCK("reusing inactive vhost-user interface sw_if_index %d", xd->vlib_sw_if_index);
      } else {
          clib_warning("error: inactive vhost-user interface sw_if_index %d not VHOST_USER type!",
                  xd->vlib_sw_if_index);
          // reset so new interface is created
          xd = NULL;
      }
    }
    // "remove" from inactive list
    _vec_len(dm->vu_inactive_interfaces_device_index) -= 1;
  }

  if (xd) {
      // existing interface used - do not overwrite if_id if not needed
      if (if_id != (u32)~0)
          xd->vu_if_id = if_id;

      // reset virtqueues
      for (j = 0; j < VIRTIO_QNUM; j++)
        {
          memset(xd->vu_vhost_dev.virtqueue[j], 0, sizeof(struct vhost_virtqueue));
        }
      // reset lockp
      memset ((void *) xd->lockp, 0, CLIB_CACHE_LINE_BYTES);

      // reset tx vectors
      for (j = 0; j < tm->n_vlib_mains; j++)
        {
          vec_validate_ha (xd->tx_vectors[j], DPDK_TX_RING_SIZE,
                           sizeof(tx_ring_hdr_t), CLIB_CACHE_LINE_BYTES);
          vec_reset_length (xd->tx_vectors[j]);
        }

      // reset rx vector
      for (j = 0; j < xd->rx_q_used; j++)
        {
          vec_validate_aligned (xd->rx_vectors[j], VLIB_FRAME_SIZE-1,
                                CLIB_CACHE_LINE_BYTES);
          vec_reset_length (xd->rx_vectors[j]);
        }
  } else {
      // vui was not retrieved from inactive ifaces - create new
      vec_add2_aligned (dm->devices, xd, 1, CLIB_CACHE_LINE_BYTES);
      xd->dev_type = VNET_DPDK_DEV_VHOST_USER;
      xd->rx_q_used = 1;
      vec_validate_aligned (xd->rx_vectors, xd->rx_q_used, CLIB_CACHE_LINE_BYTES);

      if (if_id == (u32)~0)
          xd->vu_if_id = dm->next_vu_if_id++;
      else
          xd->vu_if_id = if_id;

      xd->device_index = xd - dm->devices;
      xd->per_interface_next_index = ~0;
      xd->vu_intf = NULL;

      xd->vu_vhost_dev.mem = clib_mem_alloc (sizeof(struct virtio_memory) +
                                             VHOST_MEMORY_MAX_NREGIONS *
                                             sizeof(struct virtio_memory_regions));

      for (j = 0; j < VIRTIO_QNUM; j++)
        {
          xd->vu_vhost_dev.virtqueue[j] = clib_mem_alloc (sizeof(struct vhost_virtqueue));
          memset(xd->vu_vhost_dev.virtqueue[j], 0, sizeof(struct vhost_virtqueue));
        }

      xd->lockp = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
                                          CLIB_CACHE_LINE_BYTES);
      memset ((void *) xd->lockp, 0, CLIB_CACHE_LINE_BYTES);

      vec_validate_aligned (xd->tx_vectors, tm->n_vlib_mains,
                            CLIB_CACHE_LINE_BYTES);

      for (j = 0; j < tm->n_vlib_mains; j++)
        {
          vec_validate_ha (xd->tx_vectors[j], DPDK_TX_RING_SIZE,
                           sizeof(tx_ring_hdr_t), CLIB_CACHE_LINE_BYTES);
          vec_reset_length (xd->tx_vectors[j]);
        }

      // reset rx vector
      for (j = 0; j < xd->rx_q_used; j++)
        {
          vec_validate_aligned (xd->rx_vectors[j], VLIB_FRAME_SIZE-1,
                                CLIB_CACHE_LINE_BYTES);
          vec_reset_length (xd->rx_vectors[j]);
        }

      vec_validate_aligned (xd->frames, tm->n_vlib_mains,
                            CLIB_CACHE_LINE_BYTES);

  }
  {
    f64 now = vlib_time_now(vm);
    u32 rnd;
    rnd = (u32) (now * 1e6);
    rnd = random_u32 (&rnd);

    memcpy (addr+2, &rnd, sizeof(rnd));
    addr[0] = 2;
    addr[1] = 0xfe;
  }

  error = ethernet_register_interface
    (dm->vnet_main,
     dpdk_device_class.index,
     xd->device_index,
     /* ethernet address */ addr,
     &xd->vlib_hw_if_index,
     0);

  if (error)
    return error;

  sw = vnet_get_hw_sw_interface (dm->vnet_main, xd->vlib_hw_if_index);
  xd->vlib_sw_if_index = sw->sw_if_index;

  if (!xd->vu_intf)
      xd->vu_intf = clib_mem_alloc (sizeof(*(xd->vu_intf)));

  *hw_if_index = xd->vlib_hw_if_index;

  int cpu = (xd->device_index % dm->input_cpu_count) +
            dm->input_cpu_first_index;

  vec_add2(dm->devices_by_cpu[cpu], dq, 1);
  dq->device = xd->device_index;
  dq->queue_id = 0;

  // start polling if it was not started yet (because of no phys ifaces)
  if (tm->n_vlib_mains == 1 && dpdk_input_node.state != VLIB_NODE_STATE_POLLING)
    vlib_node_set_state (vm, dpdk_input_node.index, VLIB_NODE_STATE_POLLING);

  if (tm->n_vlib_mains > 1 && tm->main_thread_is_io_node)
    vlib_node_set_state (vm, dpdk_io_input_node.index, VLIB_NODE_STATE_POLLING);

  if (tm->n_vlib_mains > 1 && !tm->main_thread_is_io_node)
    vlib_node_set_state (vlib_mains[cpu], dpdk_input_node.index,
                         VLIB_NODE_STATE_POLLING);

  vlib_worker_thread_barrier_release (vm);
  return 0;
}

static clib_error_t *
dpdk_vhost_user_get_features(u32 hw_if_index, u64 * features)
{
  *features = rte_vhost_feature_get();

  DBG_SOCK("supported features: 0x%x", *features);
  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_features(u32 hw_if_index, u64 features)
{
  dpdk_device_t * xd;
  u16 hdr_len = sizeof(struct virtio_net_hdr);


  if (!(xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_index))) {
    clib_warning("not a vhost-user interface");
    return 0;
  }

  xd->vu_vhost_dev.features = features;

  if (xd->vu_vhost_dev.features & (1 << VIRTIO_NET_F_MRG_RXBUF))
    hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);

  xd->vu_vhost_dev.virtqueue[VIRTIO_RXQ]->vhost_hlen = hdr_len;
  xd->vu_vhost_dev.virtqueue[VIRTIO_TXQ]->vhost_hlen = hdr_len;

  xd->vu_is_running = 0;

  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_mem_table(u32 hw_if_index, vhost_user_memory_t * vum, int fd[])
{
  struct virtio_memory * mem;
  int i;
  dpdk_device_t * xd;
  dpdk_vu_intf_t * vui;

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_index))) {
    clib_warning("not a vhost-user interface");
    return 0;
  }

  vui = xd->vu_intf;
  mem = xd->vu_vhost_dev.mem;

  mem->nregions = vum->nregions;

  for (i=0; i < mem->nregions; i++) {
    u64 mapped_size, mapped_address;

    mem->regions[i].guest_phys_address     = vum->regions[i].guest_phys_addr;
    mem->regions[i].guest_phys_address_end = vum->regions[i].guest_phys_addr +
                                             vum->regions[i].memory_size;
    mem->regions[i].memory_size            = vum->regions[i].memory_size;
    mem->regions[i].userspace_address      = vum->regions[i].userspace_addr;

    mapped_size = mem->regions[i].memory_size + vum->regions[i].mmap_offset;
    mapped_address = (uint64_t)(uintptr_t)mmap(NULL, mapped_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd[i], 0);

    if ((void *)mapped_address == MAP_FAILED)
    {
      clib_warning("mmap error");
      return 0;
    }

    mapped_address +=  vum->regions[i].mmap_offset;
    vui->region_addr[i] = mapped_address;
    vui->region_fd[i] = fd[i];
    mem->regions[i].address_offset = mapped_address - mem->regions[i].guest_phys_address;

    if (vum->regions[i].guest_phys_addr == 0) {
      mem->base_address = vum->regions[i].userspace_addr;
      mem->mapped_address = mem->regions[i].address_offset;
    }
  }

  xd->vu_is_running = 0;

  DBG_SOCK("done");
  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_vring_num(u32 hw_if_index, u8 idx, u32 num)
{
  dpdk_device_t * xd;
  struct vhost_virtqueue *vq;

  DBG_SOCK("idx %u num %u", idx, num);

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_index))) {
    clib_warning("not a vhost-user interface");
    return 0;
  }
  vq = xd->vu_vhost_dev.virtqueue[idx];
  vq->size = num;

  xd->vu_is_running = 0;

  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_vring_addr(u32 hw_if_index, u8 idx, u64 desc, u64 used, u64 avail)
{
  dpdk_device_t * xd;
  struct vhost_virtqueue *vq;

  DBG_SOCK("idx %u desc 0x%x used 0x%x avail 0x%x", idx, desc, used, avail);

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_index))) {
    clib_warning("not a vhost-user interface");
    return 0;
  }
  vq = xd->vu_vhost_dev.virtqueue[idx];

  vq->desc = (struct vring_desc *) qva_to_vva(&xd->vu_vhost_dev, desc);
  vq->used = (struct vring_used *) qva_to_vva(&xd->vu_vhost_dev, used);
  vq->avail = (struct vring_avail *) qva_to_vva(&xd->vu_vhost_dev, avail);

  if (!(vq->desc && vq->used && vq->avail)) {
    clib_warning("falied to set vring addr");
  }

  xd->vu_is_running = 0;

  return 0;
}

static clib_error_t *
dpdk_vhost_user_get_vring_base(u32 hw_if_index, u8 idx, u32 * num)
{
  dpdk_device_t * xd;
  struct vhost_virtqueue *vq;

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_index))) {
    clib_warning("not a vhost-user interface");
    return 0;
  }

  vq = xd->vu_vhost_dev.virtqueue[idx];
  *num = vq->last_used_idx;

  DBG_SOCK("idx %u num %u", idx, *num);
  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_vring_base(u32 hw_if_index, u8 idx, u32 num)
{
  dpdk_device_t * xd;
  struct vhost_virtqueue *vq;

  DBG_SOCK("idx %u num %u", idx, num);

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_index))) {
    clib_warning("not a vhost-user interface");
    return 0;
  }

  vq = xd->vu_vhost_dev.virtqueue[idx];
  vq->last_used_idx = num;
  vq->last_used_idx_res = num;

  xd->vu_is_running = 0;

  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_vring_kick(u32 hw_if_index, u8 idx, int fd)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  struct vhost_virtqueue *vq, *vq0, *vq1;

  DBG_SOCK("idx %u fd %d", idx, fd);

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_index))) {
    clib_warning("not a vhost-user interface");
    return 0;
  }

  vq = xd->vu_vhost_dev.virtqueue[idx];
  vq->kickfd = fd;

  vq0 = xd->vu_vhost_dev.virtqueue[0];
  vq1 = xd->vu_vhost_dev.virtqueue[1];

  if (vq0->desc && vq0->avail && vq0->used &&
      vq1->desc && vq1->avail && vq1->used) {
    xd->vu_is_running = 1;
    if (xd->admin_up)
      vnet_hw_interface_set_flags (dm->vnet_main, xd->vlib_hw_if_index,
                           VNET_HW_INTERFACE_FLAG_LINK_UP |
                           ETH_LINK_FULL_DUPLEX );
  }

  return 0;
}


static clib_error_t *
dpdk_vhost_user_set_vring_call(u32 hw_if_index, u8 idx, int fd)
{
  dpdk_device_t * xd;
  struct vhost_virtqueue *vq;

  DBG_SOCK("idx %u fd %d", idx, fd);

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_index))) {
    clib_warning("not a vhost-user interface");
    return 0;
  }

  vq = xd->vu_vhost_dev.virtqueue[idx];
  /* reset callfd to force no interrupts */
  vq->callfd = -1;

  return 0;
}

u8
dpdk_vhost_user_want_interrupt(dpdk_device_t *xd, int idx)
{
    dpdk_vu_intf_t *vui = xd->vu_intf;
    ASSERT(vui != NULL);

    if (PREDICT_FALSE(vui->num_vrings <= 0))
        return 0;

    dpdk_vu_vring *vring = &(vui->vrings[idx]);
    struct vhost_virtqueue *vq = xd->vu_vhost_dev.virtqueue[idx];

    /* return if vm is interested in interrupts */
    return (vring->callfd > 0) && !(vq->avail->flags & VRING_AVAIL_F_NO_INTERRUPT);
}

void
dpdk_vhost_user_send_interrupt(vlib_main_t * vm, dpdk_device_t * xd, int idx)
{
    dpdk_main_t * dm = &dpdk_main;
    dpdk_vu_intf_t *vui = xd->vu_intf;
    ASSERT(vui != NULL);

    if (PREDICT_FALSE(vui->num_vrings <= 0))
        return;

    dpdk_vu_vring *vring = &(vui->vrings[idx]);
    struct vhost_virtqueue *vq = xd->vu_vhost_dev.virtqueue[idx];

    /* if vm is interested in interrupts */
    if((vring->callfd > 0) && !(vq->avail->flags & VRING_AVAIL_F_NO_INTERRUPT)) {
        u64 x = 1;
        int rv __attribute__((unused));
        /* $$$$ pay attention to rv */
        rv = write(vring->callfd, &x, sizeof(x));
        vring->n_since_last_int = 0;
        vring->int_deadline = vlib_time_now(vm) + dm->vhost_coalesce_time;
    }
}

/*
 * vhost-user interface management functions 
 */

// initialize vui with specified attributes
static void 
dpdk_vhost_user_vui_init(vnet_main_t * vnm,
                         dpdk_device_t *xd, int sockfd,
                         const char * sock_filename,
                         u8 is_server, u64 feature_mask,
                         u32 * sw_if_index)
{
  dpdk_vu_intf_t *vui = xd->vu_intf;
  memset(vui, 0, sizeof(*vui));

  vui->unix_fd = sockfd;
  vui->num_vrings = 2;
  vui->sock_is_server = is_server;
  strncpy(vui->sock_filename, sock_filename, ARRAY_LEN(vui->sock_filename)-1);
  vui->sock_errno = 0;
  vui->is_up = 0;
  vui->feature_mask = feature_mask;
  vui->active = 1;
  vui->unix_file_index = ~0;

  vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index,  0);

  if (sw_if_index)
      *sw_if_index = xd->vlib_sw_if_index;
}

// register vui and start polling on it
static void 
dpdk_vhost_user_vui_register(vlib_main_t * vm, dpdk_device_t *xd)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_vu_intf_t *vui = xd->vu_intf;

  hash_set (dm->vu_sw_if_index_by_listener_fd, vui->unix_fd,
            xd->vlib_sw_if_index);
}

static inline void
dpdk_vhost_user_if_disconnect(dpdk_device_t * xd)
{
    dpdk_vu_intf_t *vui = xd->vu_intf;
    vnet_main_t * vnm = vnet_get_main();
    dpdk_main_t * dm = &dpdk_main;

    xd->admin_up = 0;
    vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index,  0);

    if (vui->unix_file_index != ~0) {
        unix_file_del (&unix_main, unix_main.file_pool + vui->unix_file_index);
        vui->unix_file_index = ~0;
    }

    hash_unset(dm->vu_sw_if_index_by_sock_fd, vui->unix_fd);
    hash_unset(dm->vu_sw_if_index_by_listener_fd, vui->unix_fd);
    close(vui->unix_fd);
    vui->unix_fd = -1;
    vui->is_up = 0;

    DBG_SOCK("interface ifindex %d disconnected", xd->vlib_sw_if_index);
}

static clib_error_t * dpdk_vhost_user_callfd_read_ready (unix_file_t * uf)
{
  __attribute__((unused)) int n;
  u8 buff[8];
  n = read(uf->file_descriptor, ((char*)&buff), 8);
  return 0;
}

static clib_error_t * dpdk_vhost_user_socket_read (unix_file_t * uf)
{
  int n;
  int fd, number_of_fds = 0;
  int fds[VHOST_MEMORY_MAX_NREGIONS];
  vhost_user_msg_t msg;
  struct msghdr mh;
  struct iovec iov[1];
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t *xd;
  dpdk_vu_intf_t *vui;
  struct cmsghdr *cmsg;
  uword * p;
  u8 q;
  unix_file_t template = {0};
  vnet_main_t * vnm = vnet_get_main();

  p = hash_get (dm->vu_sw_if_index_by_sock_fd, uf->file_descriptor);
  if (p == 0) {
      DBG_SOCK ("FD %d doesn't belong to any interface",
                    uf->file_descriptor);
      return 0;
    }
  else
      xd = dpdk_vhost_user_device_from_sw_if_index(p[0]);

  ASSERT(xd != NULL);
  vui = xd->vu_intf;

  char control[CMSG_SPACE(VHOST_MEMORY_MAX_NREGIONS * sizeof(int))];

  memset(&mh, 0, sizeof(mh));
  memset(control, 0, sizeof(control));

  /* set the payload */
  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = VHOST_USER_MSG_HDR_SZ;

  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = control;
  mh.msg_controllen = sizeof(control);

  n = recvmsg(uf->file_descriptor, &mh, 0);

  if (n != VHOST_USER_MSG_HDR_SZ)
    goto close_socket;

  if (mh.msg_flags & MSG_CTRUNC) {
    goto close_socket;
  }

  cmsg = CMSG_FIRSTHDR(&mh);

  if (cmsg && (cmsg->cmsg_len > 0) && (cmsg->cmsg_level == SOL_SOCKET) &&
      (cmsg->cmsg_type == SCM_RIGHTS) &&
      (cmsg->cmsg_len - CMSG_LEN(0) <= VHOST_MEMORY_MAX_NREGIONS * sizeof(int))) {
        number_of_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        memcpy(fds, CMSG_DATA(cmsg), number_of_fds * sizeof(int));
  }

  /* version 1, no reply bit set*/
  if ((msg.flags & 7) != 1) {
    DBG_SOCK("malformed message received. closing socket");
    goto close_socket;
  }

  {
      int rv __attribute__((unused));
      /* $$$$ pay attention to rv */
      rv = read(uf->file_descriptor, ((char*)&msg) + n, msg.size);
  }

  switch (msg.request) {
    case VHOST_USER_GET_FEATURES:
      DBG_SOCK("if %d msg VHOST_USER_GET_FEATURES",
        xd->vlib_hw_if_index);

      msg.flags |= 4;

      dpdk_vhost_user_get_features(xd->vlib_hw_if_index, &msg.u64);
      msg.u64 &= vui->feature_mask;
      msg.size = sizeof(msg.u64);
      break;

    case VHOST_USER_SET_FEATURES:
      DBG_SOCK("if %d msg VHOST_USER_SET_FEATURES features 0x%016llx",
        xd->vlib_hw_if_index, msg.u64);

      dpdk_vhost_user_set_features(xd->vlib_hw_if_index, msg.u64);
      break;

    case VHOST_USER_SET_MEM_TABLE:
      DBG_SOCK("if %d msg VHOST_USER_SET_MEM_TABLE nregions %d",
        xd->vlib_hw_if_index, msg.memory.nregions);

      if ((msg.memory.nregions < 1) ||
          (msg.memory.nregions > VHOST_MEMORY_MAX_NREGIONS)) {

        DBG_SOCK("number of mem regions must be between 1 and %i",
          VHOST_MEMORY_MAX_NREGIONS);

        goto close_socket;
      }

      if (msg.memory.nregions != number_of_fds) {
        DBG_SOCK("each memory region must have FD");
        goto close_socket;
      }

      dpdk_vhost_user_set_mem_table(xd->vlib_hw_if_index, &msg.memory, fds);
      break;

    case VHOST_USER_SET_VRING_NUM:
      DBG_SOCK("if %d msg VHOST_USER_SET_VRING_NUM idx %d num %d",
        xd->vlib_hw_if_index, msg.state.index, msg.state.num);

      if ((msg.state.num > 32768) || /* maximum ring size is 32768 */
          (msg.state.num == 0) ||    /* it cannot be zero */
          (msg.state.num % 2))       /* must be power of 2 */
        goto close_socket;

      dpdk_vhost_user_set_vring_num(xd->vlib_hw_if_index, msg.state.index, msg.state.num);
      break;

    case VHOST_USER_SET_VRING_ADDR:
      DBG_SOCK("if %d msg VHOST_USER_SET_VRING_ADDR idx %d",
        xd->vlib_hw_if_index, msg.state.index);

      dpdk_vhost_user_set_vring_addr(xd->vlib_hw_if_index, msg.state.index,
                                    msg.addr.desc_user_addr,
                                    msg.addr.used_user_addr,
                                    msg.addr.avail_user_addr);
      break;

    case VHOST_USER_SET_OWNER:
      DBG_SOCK("if %d msg VHOST_USER_SET_OWNER",
        xd->vlib_hw_if_index);
      break;

    case VHOST_USER_RESET_OWNER:
      DBG_SOCK("if %d msg VHOST_USER_RESET_OWNER",
        xd->vlib_hw_if_index);
      break;

    case VHOST_USER_SET_VRING_CALL:
      DBG_SOCK("if %d msg VHOST_USER_SET_VRING_CALL u64 %d",
        xd->vlib_hw_if_index, msg.u64);

      q = (u8) (msg.u64 & 0xFF);

      if (!(msg.u64 & 0x100))
      {
        if (number_of_fds != 1)
          goto close_socket;

        /* if there is old fd, delete it */
        if (vui->vrings[q].callfd) {
          unix_file_t * uf = pool_elt_at_index (unix_main.file_pool,
            vui->vrings[q].callfd_idx);
          unix_file_del (&unix_main, uf);
        }
        vui->vrings[q].callfd = fds[0];
        template.read_function = dpdk_vhost_user_callfd_read_ready;
        template.file_descriptor = fds[0];
        vui->vrings[q].callfd_idx = unix_file_add (&unix_main, &template);
      }
      else
        vui->vrings[q].callfd = -1;

      dpdk_vhost_user_set_vring_call(xd->vlib_hw_if_index, q, vui->vrings[q].callfd);
      break;

    case VHOST_USER_SET_VRING_KICK:
      DBG_SOCK("if %d msg VHOST_USER_SET_VRING_KICK u64 %d",
        xd->vlib_hw_if_index, msg.u64);

      q = (u8) (msg.u64 & 0xFF);

      if (!(msg.u64 & 0x100))
      {
        if (number_of_fds != 1)
          goto close_socket;

        vui->vrings[q].kickfd = fds[0];
      }
      else
        vui->vrings[q].kickfd = -1;

      dpdk_vhost_user_set_vring_kick(xd->vlib_hw_if_index, q, vui->vrings[q].kickfd);
      break;

    case VHOST_USER_SET_VRING_ERR:
      DBG_SOCK("if %d msg VHOST_USER_SET_VRING_ERR u64 %d",
        xd->vlib_hw_if_index, msg.u64);

      q = (u8) (msg.u64 & 0xFF);

      if (!(msg.u64 & 0x100))
      {
        if (number_of_fds != 1)
          goto close_socket;

        fd = fds[0];
      }
      else
        fd = -1;

      vui->vrings[q].errfd = fd;
      break;

    case VHOST_USER_SET_VRING_BASE:
      DBG_SOCK("if %d msg VHOST_USER_SET_VRING_BASE idx %d num %d",
        xd->vlib_hw_if_index, msg.state.index, msg.state.num);

      dpdk_vhost_user_set_vring_base(xd->vlib_hw_if_index, msg.state.index, msg.state.num);
      break;

    case VHOST_USER_GET_VRING_BASE:
      DBG_SOCK("if %d msg VHOST_USER_GET_VRING_BASE idx %d num %d",
        xd->vlib_hw_if_index, msg.state.index, msg.state.num);

      msg.flags |= 4;
      msg.size = sizeof(msg.state);

      dpdk_vhost_user_get_vring_base(xd->vlib_hw_if_index, msg.state.index, &msg.state.num);
      break;

    case VHOST_USER_NONE:
      DBG_SOCK("if %d msg VHOST_USER_NONE",
        xd->vlib_hw_if_index);
      break;

    case VHOST_USER_SET_LOG_BASE:
      DBG_SOCK("if %d msg VHOST_USER_SET_LOG_BASE",
        xd->vlib_hw_if_index);
      break;

    case VHOST_USER_SET_LOG_FD:
      DBG_SOCK("if %d msg VHOST_USER_SET_LOG_FD",
        xd->vlib_hw_if_index);
      break;

    default:
      DBG_SOCK("unknown vhost-user message %d received. closing socket",
        msg.request);
      goto close_socket;
  }

  /* if we have pointers to descriptor table, go up*/
  if (!vui->is_up &&
      xd->vu_vhost_dev.virtqueue[VHOST_NET_VRING_IDX_TX]->desc &&
      xd->vu_vhost_dev.virtqueue[VHOST_NET_VRING_IDX_RX]->desc) {

      DBG_SOCK("interface %d connected", xd->vlib_sw_if_index);

      vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index,  VNET_HW_INTERFACE_FLAG_LINK_UP);
      vui->is_up = 1;
  }

  /* if we need to reply */
  if (msg.flags & 4)
  {
      n = send(uf->file_descriptor, &msg, VHOST_USER_MSG_HDR_SZ + msg.size, 0);
      if (n != (msg.size + VHOST_USER_MSG_HDR_SZ))
        goto close_socket;
  }

  return 0;

close_socket:
  DBG_SOCK("error: close_socket");
  dpdk_vhost_user_if_disconnect(xd);
  return 0;
}

static clib_error_t * dpdk_vhost_user_socket_error (unix_file_t * uf)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t *xd;
  uword * p;

  p = hash_get (dm->vu_sw_if_index_by_sock_fd, uf->file_descriptor);
  if (p == 0) {
      DBG_SOCK ("FD %d doesn't belong to any interface",
                    uf->file_descriptor);
      return 0;
    }
  else
      xd = dpdk_vhost_user_device_from_sw_if_index(p[0]);

  dpdk_vhost_user_if_disconnect(xd);
  return 0;
}

static clib_error_t * dpdk_vhost_user_socksvr_accept_ready (unix_file_t * uf)
{
  int client_fd, client_len;
  struct sockaddr_un client;
  unix_file_t template = {0};
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd = NULL;
  dpdk_vu_intf_t * vui;
  uword * p;

  p = hash_get (dm->vu_sw_if_index_by_listener_fd,
                uf->file_descriptor);
  if (p == 0) {
      DBG_SOCK ("fd %d doesn't belong to any interface",
                    uf->file_descriptor);
      return 0;
    }

  xd = dpdk_vhost_user_device_from_sw_if_index(p[0]);
  ASSERT(xd != NULL);
  vui = xd->vu_intf;

  client_len = sizeof(client);
  client_fd = accept (uf->file_descriptor,
                      (struct sockaddr *)&client,
                      (socklen_t *)&client_len);

  if (client_fd < 0)
      return clib_error_return_unix (0, "accept");

  template.read_function = dpdk_vhost_user_socket_read;
  template.error_function = dpdk_vhost_user_socket_error;
  template.file_descriptor = client_fd;
  vui->unix_file_index = unix_file_add (&unix_main, &template);

  vui->client_fd = client_fd;
  hash_set (dm->vu_sw_if_index_by_sock_fd, vui->client_fd,
            xd->vlib_sw_if_index);

  return 0;
}

// init server socket on specified sock_filename
static int dpdk_vhost_user_init_server_sock(const char * sock_filename, int *sockfd)
{
  int rv = 0, len;
  struct sockaddr_un un;
  int fd;
  /* create listening socket */
  fd = socket(AF_UNIX, SOCK_STREAM, 0);

  if (fd < 0) {
    return VNET_API_ERROR_SYSCALL_ERROR_1;
  }

  un.sun_family = AF_UNIX;
  strcpy((char *) un.sun_path, (char *) sock_filename);

  /* remove if exists */
  unlink( (char *) sock_filename);

  len = strlen((char *) un.sun_path) + strlen((char *) sock_filename);

  if (bind(fd, (struct sockaddr *) &un, len) == -1) {
    rv = VNET_API_ERROR_SYSCALL_ERROR_2;
    goto error;
  }

  if (listen(fd, 1) == -1) {
    rv = VNET_API_ERROR_SYSCALL_ERROR_3;
    goto error;
  }

  unix_file_t template = {0};
  template.read_function = dpdk_vhost_user_socksvr_accept_ready;
  template.file_descriptor = fd;
  unix_file_add (&unix_main, &template);
  *sockfd = fd;
  return rv;

error:
  close(fd);
  return rv;
}

/*
 * vhost-user interface control functions used from vpe api
 */

int dpdk_vhost_user_create_if(vnet_main_t * vnm, vlib_main_t * vm,
                              const char * sock_filename,
                              u8 is_server,
                              u32 * sw_if_index,
                              u64 feature_mask,
                              u8 renumber, u32 custom_dev_instance)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t *xd;
  u32 hw_if_idx = ~0;
  int sockfd = -1;
  int rv = 0;

  // using virtio vhost user?
  if (dm->use_virtio_vhost) {
      return vhost_user_create_if(vnm, vm, sock_filename, is_server,
              sw_if_index, feature_mask, renumber, custom_dev_instance);
  }

  if (is_server) {
    if ((rv = dpdk_vhost_user_init_server_sock (sock_filename, &sockfd)) != 0) {
        return rv;
    }
  }

  if (renumber) {
      // set next vhost-user if id if custom one is higher or equal
      if (custom_dev_instance >= dm->next_vu_if_id)
          dm->next_vu_if_id = custom_dev_instance + 1;

    dpdk_create_vhost_user_if_internal(&hw_if_idx, custom_dev_instance);
  } else 
    dpdk_create_vhost_user_if_internal(&hw_if_idx, (u32)~0);
  DBG_SOCK("dpdk vhost-user interface created hw_if_index %d", hw_if_idx);

  xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_idx);
  ASSERT(xd != NULL);

  dpdk_vhost_user_vui_init (vnm, xd, sockfd, sock_filename, is_server,
                            feature_mask, sw_if_index);

  dpdk_vhost_user_vui_register (vm, xd);
  return rv;
}

int dpdk_vhost_user_modify_if(vnet_main_t * vnm, vlib_main_t * vm,
                         const char * sock_filename,
                         u8 is_server,
                         u32 sw_if_index,
                         u64 feature_mask,
                         u8 renumber, u32 custom_dev_instance)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  dpdk_vu_intf_t * vui = NULL;
  u32 sw_if_idx = ~0;
  int sockfd = -1;
  int rv = 0;

  // using virtio vhost user?
  if (dm->use_virtio_vhost) {
      return vhost_user_modify_if(vnm, vm, sock_filename, is_server,
              sw_if_index, feature_mask, renumber, custom_dev_instance);
  }

  xd = dpdk_vhost_user_device_from_sw_if_index(sw_if_index);

  if (xd == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vui = xd->vu_intf;

  // interface is inactive
  vui->active = 0;
  // disconnect interface sockets
  dpdk_vhost_user_if_disconnect(xd);

  if (is_server) {
      if ((rv = dpdk_vhost_user_init_server_sock (sock_filename, &sockfd)) != 0) {
          return rv;
      }
  }

  dpdk_vhost_user_vui_init (vnm, xd, sockfd, sock_filename, is_server,
                       feature_mask, &sw_if_idx);

  if (renumber) {
    vnet_interface_name_renumber (sw_if_idx, custom_dev_instance);
  }

  dpdk_vhost_user_vui_register (vm, xd);

  return rv;
}

int dpdk_vhost_user_delete_if(vnet_main_t * vnm, vlib_main_t * vm,
                         u32 sw_if_index)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd = NULL;
  dpdk_vu_intf_t * vui;
  int rv = 0;

  // using virtio vhost user?
  if (dm->use_virtio_vhost) {
      return vhost_user_delete_if(vnm, vm, sw_if_index);
  }

  xd = dpdk_vhost_user_device_from_sw_if_index(sw_if_index);

  if (xd == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vui = xd->vu_intf;

  // interface is inactive
  vui->active = 0;
  // disconnect interface sockets
  dpdk_vhost_user_if_disconnect(xd);
  // add to inactive interface list
  vec_add1 (dm->vu_inactive_interfaces_device_index, xd->device_index);

  ethernet_delete_interface (vnm, xd->vlib_hw_if_index);
  DBG_SOCK ("deleted (deactivated) vhost-user interface sw_if_index %d", sw_if_index);

  return rv;
}

int dpdk_vhost_user_dump_ifs(vnet_main_t * vnm, vlib_main_t * vm, vhost_user_intf_details_t **out_vuids)
{
    int rv = 0;
    dpdk_main_t * dm = &dpdk_main;
    dpdk_device_t * xd;
    dpdk_vu_intf_t * vui;
    struct virtio_net * vhost_dev;
    vhost_user_intf_details_t * r_vuids = NULL;
    vhost_user_intf_details_t * vuid = NULL;
    u32 * hw_if_indices = 0;
    vnet_hw_interface_t * hi;
    u8 *s = NULL;
    int i;

    if (!out_vuids)
        return -1;

    // using virtio vhost user?
    if (dm->use_virtio_vhost) {
        return vhost_user_dump_ifs(vnm, vm, out_vuids);
    }

    vec_foreach (xd, dm->devices) {
      if (xd->dev_type == VNET_DPDK_DEV_VHOST_USER &&
              xd->vu_intf->active)
        vec_add1(hw_if_indices, xd->vlib_hw_if_index);
    }

    for (i = 0; i < vec_len (hw_if_indices); i++) {
      hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
      xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_indices[i]);
      if (!xd) {
          clib_warning("invalid vhost-user interface hw_if_index %d", hw_if_indices[i]);
          continue;
      }

      vui = xd->vu_intf;
      ASSERT(vui != NULL);
      vhost_dev = &xd->vu_vhost_dev;
      u32 virtio_net_hdr_sz = (vui->num_vrings > 0 ?
            vhost_dev->virtqueue[0]->vhost_hlen : 0);

      vec_add2(r_vuids, vuid, 1);
      vuid->sw_if_index = xd->vlib_sw_if_index;
      vuid->virtio_net_hdr_sz = virtio_net_hdr_sz;
      vuid->features = vhost_dev->features;
      vuid->is_server = vui->sock_is_server;
      vuid->num_regions = (vhost_dev->mem != NULL ? vhost_dev->mem->nregions : 0);
      vuid->sock_errno = vui->sock_errno;
      strncpy((char *)vuid->sock_filename, (char *)vui->sock_filename,
              ARRAY_LEN(vuid->sock_filename)-1);

      s = format (s, "%v%c", hi->name, 0);

      strncpy((char *)vuid->if_name, (char *)s,
              ARRAY_LEN(vuid->if_name)-1);
      _vec_len(s) = 0;
    }

    vec_free (s);
    vec_free (hw_if_indices);

    *out_vuids = r_vuids;

    return rv;
}

/*
 * Processing functions called from dpdk process fn
 */

typedef struct {
    struct sockaddr_un sun;
    int sockfd;
    unix_file_t template;
    uword *event_data;
} dpdk_vu_process_state;

void dpdk_vhost_user_process_init (void **ctx)
{
    dpdk_vu_process_state *state = clib_mem_alloc (sizeof(dpdk_vu_process_state));
    memset(state, 0, sizeof(*state));
    state->sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    state->sun.sun_family = AF_UNIX;
    state->template.read_function = dpdk_vhost_user_socket_read;
    state->template.error_function = dpdk_vhost_user_socket_error;
    state->event_data = 0;
    *ctx = state;
}

void dpdk_vhost_user_process_cleanup (void *ctx)
{
    clib_mem_free(ctx);
}

uword dpdk_vhost_user_process_if (vlib_main_t *vm, dpdk_device_t *xd, void *ctx)
{
    dpdk_main_t * dm = &dpdk_main;
    dpdk_vu_process_state *state = (dpdk_vu_process_state *)ctx;
    dpdk_vu_intf_t *vui = xd->vu_intf;

    if (vui->sock_is_server || !vui->active)
        return 0;

    if (vui->unix_fd == -1) {
        /* try to connect */
        strncpy(state->sun.sun_path,  (char *) vui->sock_filename, sizeof(state->sun.sun_path) - 1);

        if (connect(state->sockfd, (struct sockaddr *) &(state->sun), sizeof(struct sockaddr_un)) == 0) {
            vui->sock_errno = 0;
            vui->unix_fd = state->sockfd;
            state->template.file_descriptor = state->sockfd;
            vui->unix_file_index = unix_file_add (&unix_main, &(state->template));
            hash_set (dm->vu_sw_if_index_by_sock_fd, state->sockfd, xd->vlib_sw_if_index);

            state->sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (state->sockfd < 0)
                return -1;
        } else {
            vui->sock_errno = errno;
        }
    } else {
        /* check if socket is alive */
        int error = 0;
        socklen_t len = sizeof (error);
        int retval = getsockopt(vui->unix_fd, SOL_SOCKET, SO_ERROR, &error, &len);

        if (retval)
            dpdk_vhost_user_if_disconnect(xd);
    }
    return 0;
}

/*
 * CLI functions
 */

static clib_error_t *
dpdk_vhost_user_connect_command_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  dpdk_main_t * dm = &dpdk_main;
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 * sock_filename = NULL;
  u32 sw_if_index;
  u8 is_server = 0;
  u64 feature_mask = (u64)~0;
  u8 renumber = 0;
  u32 custom_dev_instance = ~0;

  if (dm->use_virtio_vhost) {
      return vhost_user_connect_command_fn(vm, input, cmd);
  }

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "socket %s", &sock_filename))
      ;
    else if (unformat (line_input, "server"))
      is_server = 1;
    else if (unformat (line_input, "feature-mask 0x%llx", &feature_mask))
      ;
    else if (unformat (line_input, "renumber %d", &custom_dev_instance)) {
        renumber = 1;
    }
    else
      return clib_error_return (0, "unknown input `%U'",
                                format_unformat_error, input);
  }
  unformat_free (line_input);

  vnet_main_t *vnm = vnet_get_main();
  if (sock_filename == NULL)
      return clib_error_return (0, "missing socket file");

  dpdk_vhost_user_create_if(vnm, vm, (char *)sock_filename,
                            is_server, &sw_if_index, feature_mask,
                            renumber, custom_dev_instance);

  vec_free(sock_filename);
  return 0;
}

VLIB_CLI_COMMAND (dpdk_vhost_user_connect_command, static) = {
    .path = "create vhost-user",
    .short_help = "create vhost-user socket <socket-filename> [server] [feature-mask <hex>] [renumber <dev_instance>]",
    .function = dpdk_vhost_user_connect_command_fn,
};

static clib_error_t *
dpdk_vhost_user_delete_command_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  dpdk_main_t * dm = &dpdk_main;
  clib_error_t * error = 0;
  unformat_input_t _line_input, * line_input = &_line_input;
  u32 sw_if_index = ~0;

  if (dm->use_virtio_vhost) {
      return vhost_user_delete_command_fn(vm, input, cmd);
  }

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "sw_if_index %d", &sw_if_index))
      ;
    else
      return clib_error_return (0, "unknown input `%U'",
                                format_unformat_error, input);
  }
  unformat_free (line_input);

  if (sw_if_index == ~0) {
      error = clib_error_return (0, "invalid sw_if_index",
                                 format_unformat_error, input);
      return error;
  }

  vnet_main_t *vnm = vnet_get_main();

  dpdk_vhost_user_delete_if(vnm, vm, sw_if_index);

  return 0;
}

VLIB_CLI_COMMAND (dpdk_vhost_user_delete_command, static) = {
    .path = "delete vhost-user",
    .short_help = "delete vhost-user sw_if_index <nn>",
    .function = dpdk_vhost_user_delete_command_fn,
};

#define foreach_dpdk_vhost_feature      \
 _ (VIRTIO_NET_F_MRG_RXBUF)             \
 _ (VIRTIO_NET_F_CTRL_VQ)               \
 _ (VIRTIO_NET_F_CTRL_RX)

static clib_error_t *
show_dpdk_vhost_user_command_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  clib_error_t * error = 0;
  dpdk_main_t * dm = &dpdk_main;
  vnet_main_t * vnm = vnet_get_main();
  dpdk_device_t * xd;
  dpdk_vu_intf_t * vui;
  struct virtio_net * vhost_dev;
  u32 hw_if_index, * hw_if_indices = 0;
  vnet_hw_interface_t * hi;
  int i, j, q;
  int show_descr = 0;
  struct virtio_memory * mem;
  struct feat_struct { u8 bit; char *str;};
  struct feat_struct *feat_entry;

  static struct feat_struct feat_array[] = {
#define _(f) { .str = #f, .bit = f, },
  foreach_dpdk_vhost_feature
#undef _
  { .str = NULL }
  };

  if (dm->use_virtio_vhost) {
    return show_vhost_user_command_fn(vm, input, cmd);
  }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index)) {
      vec_add1 (hw_if_indices, hw_if_index);
      vlib_cli_output(vm, "add %d", hw_if_index);
    }
    else if (unformat (input, "descriptors") || unformat (input, "desc") )
      show_descr = 1;
    else {
      error = clib_error_return (0, "unknown input `%U'",
                                     format_unformat_error, input);
      goto done;
    }
  }
  if (vec_len (hw_if_indices) == 0) {
    vec_foreach (xd, dm->devices) {
      if (xd->dev_type == VNET_DPDK_DEV_VHOST_USER && xd->vu_intf->active)
        vec_add1(hw_if_indices, xd->vlib_hw_if_index);
    }
  }

  vlib_cli_output (vm, "DPDK vhost-user interfaces");
  vlib_cli_output (vm, "Global:\n  coalesce frames %d time %e\n\n",
                   dm->vhost_coalesce_frames, dm->vhost_coalesce_time);

  for (i = 0; i < vec_len (hw_if_indices); i++) {
    hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);

    if (!(xd = dpdk_vhost_user_device_from_hw_if_index(hw_if_indices[i]))) {
        error = clib_error_return (0, "not dpdk vhost-user interface: '%s'",
                                       hi->name);
        goto done;
    }
    vui = xd->vu_intf;
    vhost_dev = &xd->vu_vhost_dev;
    mem = vhost_dev->mem;
    u32 virtio_net_hdr_sz = (vui->num_vrings > 0 ?
            vhost_dev->virtqueue[0]->vhost_hlen : 0);

    vlib_cli_output (vm, "Interface: %s (ifindex %d)",
                         hi->name, hw_if_indices[i]);

    vlib_cli_output (vm, "virtio_net_hdr_sz %d\n features (0x%llx): \n",
                         virtio_net_hdr_sz, xd->vu_vhost_dev.features);

    feat_entry = (struct feat_struct *) &feat_array;
    while(feat_entry->str) {
      if (xd->vu_vhost_dev.features & (1 << feat_entry->bit))
        vlib_cli_output (vm, "   %s (%d)", feat_entry->str, feat_entry->bit);
      feat_entry++;
    }

    vlib_cli_output (vm, "\n");

    vlib_cli_output (vm, " socket filename %s type %s errno \"%s\"\n\n",
                         vui->sock_filename, vui->sock_is_server ? "server" : "client",
                         strerror(vui->sock_errno));

    vlib_cli_output (vm, " Memory regions (total %d)\n", mem->nregions);

    if (mem->nregions){
      vlib_cli_output(vm, " region fd    guest_phys_addr    memory_size        userspace_addr     mmap_offset        mmap_addr\n");
      vlib_cli_output(vm, " ====== ===== ================== ================== ================== ================== ==================\n");
    }
    for (j = 0; j < mem->nregions; j++) {
      vlib_cli_output(vm, "  %d     %-5d 0x%016lx 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n", j,
        vui->region_fd[j],
        mem->regions[j].guest_phys_address,
        mem->regions[j].memory_size,
        mem->regions[j].userspace_address,
        mem->regions[j].address_offset,
        vui->region_addr[j]);
    }
    for (q = 0; q < vui->num_vrings; q++) {
      struct vhost_virtqueue *vq = vhost_dev->virtqueue[q];

      vlib_cli_output(vm, "\n Virtqueue %d\n", q);

      vlib_cli_output(vm, "  qsz %d last_used_idx %d last_used_idx_res %d\n",
              vq->size, vq->last_used_idx, vq->last_used_idx_res);

      if (vq->avail && vq->used)
        vlib_cli_output(vm, "  avail.flags %x avail.idx %d used.flags %x used.idx %d\n",
          vq->avail->flags, vq->avail->idx, vq->used->flags, vq->used->idx);

      vlib_cli_output(vm, "  kickfd %d callfd %d errfd %d\n",
        vui->vrings[q].kickfd,
        vui->vrings[q].callfd,
        vui->vrings[q].errfd);

      if (show_descr) {
        vlib_cli_output(vm, "\n  descriptor table:\n");
        vlib_cli_output(vm, "   id          addr         len  flags  next      user_addr\n");
        vlib_cli_output(vm, "  ===== ================== ===== ====== ===== ==================\n");
        for(j = 0; j < vq->size; j++) {
          vlib_cli_output(vm, "  %-5d 0x%016lx %-5d 0x%04x %-5d 0x%016lx\n",
            j,
            vq->desc[j].addr,
            vq->desc[j].len,
            vq->desc[j].flags,
            vq->desc[j].next,
            (u64) map_guest_mem(xd, vq->desc[j].addr));}
      }
    }
    vlib_cli_output (vm, "\n");
  }
done:
  vec_free (hw_if_indices);
  return error;
}

VLIB_CLI_COMMAND (show_vhost_user_command, static) = {
    .path = "show vhost-user",
    .short_help = "show vhost-user interface",
    .function = show_dpdk_vhost_user_command_fn,
};
