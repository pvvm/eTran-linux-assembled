/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * if_xdp: XDP socket user-space interface
 * Copyright(c) 2018 Intel Corporation.
 *
 * Author(s): Björn Töpel <bjorn.topel@intel.com>
 *	      Magnus Karlsson <magnus.karlsson@intel.com>
 */

#ifndef _LINUX_IF_XDP_H
#define _LINUX_IF_XDP_H

#include <linux/types.h>

/* Options for the sxdp_flags field */
#define XDP_SHARED_UMEM	(1 << 0)
#define XDP_COPY	(1 << 1) /* Force copy-mode */
#define XDP_ZEROCOPY	(1 << 2) /* Force zero-copy mode */
/* If this option is set, the driver might go sleep and in that case
 * the XDP_RING_NEED_WAKEUP flag in the fill and/or Tx rings will be
 * set. If it is set, the application need to explicitly wake up the
 * driver with a poll() (Rx and Tx) or sendto() (Tx only). If you are
 * running the driver and the application on the same core, you should
 * use this option so that the kernel will yield to the user space
 * application.
 */
#define XDP_USE_NEED_WAKEUP (1 << 3)
/* By setting this option, userspace application indicates that it can
 * handle multiple descriptors per packet thus enabling xsk core to split
 * multi-buffer XDP frames into multiple Rx descriptors. Without this set
 * such frames will be dropped by xsk.
 */
#define XDP_USE_SG     (1 << 4)

/* For xdp_egress */
#define XDP_EGRESS (1 << 5)

/* For xdp_gen xdp */
#define XDP_GEN (1 << 6)

/* Flags for xsk_umem_config flags */
#define XDP_UMEM_UNALIGNED_CHUNK_FLAG (1 << 0)

struct sockaddr_xdp {
	__u16 sxdp_family;
	__u16 sxdp_flags;
	__u32 sxdp_ifindex;
	__u32 sxdp_queue_id;
	__u32 sxdp_shared_umem_fd;
	__u32 sxdp_xdp_egress_prog_fd;
	__u32 sxdp_xdp_gen_prog_fd;
};

/* XDP_RING flags */
#define XDP_RING_NEED_WAKEUP (1 << 0)

struct xdp_ring_offset {
	__u64 producer;
	__u64 consumer;
	__u64 desc;
	__u64 flags;
};

struct xdp_mmap_offsets {
	struct xdp_ring_offset rx;
	struct xdp_ring_offset tx;
	struct xdp_ring_offset fr; /* Fill */
	struct xdp_ring_offset cr; /* Completion */
};

/* XDP socket options */
#define XDP_MMAP_OFFSETS		1
#define XDP_RX_RING			2
#define XDP_TX_RING			3
#define XDP_UMEM_REG			4
#define XDP_UMEM_FILL_RING		5
#define XDP_UMEM_COMPLETION_RING	6
#define XDP_STATISTICS			7
#define XDP_OPTIONS			8

struct xdp_umem_reg {
	__u64 addr; /* Start of packet data area */
	__u64 len; /* Length of packet data area */
	__u32 chunk_size;
	__u32 headroom;
	__u32 flags;
};

struct xdp_statistics {
	__u64 rx_dropped; /* Dropped for other reasons */
	__u64 rx_invalid_descs; /* Dropped due to invalid descriptor */
	__u64 tx_invalid_descs; /* Dropped due to invalid descriptor */
	__u64 rx_ring_full; /* Dropped due to rx ring being full */
	__u64 rx_fill_ring_empty_descs; /* Failed to retrieve item from fill ring */
	__u64 tx_ring_empty_descs; /* Failed to retrieve item from tx ring */
};

struct xdp_options {
	__u32 flags;
    __u32 umem_id;
};

/* Flags for the flags field of struct xdp_options */
#define XDP_OPTIONS_ZEROCOPY (1 << 0)

/* Pgoff for mmaping the rings */
#define XDP_PGOFF_RX_RING			  0
#define XDP_PGOFF_TX_RING		 0x80000000
#define XDP_UMEM_PGOFF_FILL_RING	0x100000000ULL
#define XDP_UMEM_PGOFF_COMPLETION_RING	0x180000000ULL

/* Masks for unaligned chunks mode */
#define XSK_UNALIGNED_BUF_OFFSET_SHIFT 48
#define XSK_UNALIGNED_BUF_ADDR_MASK \
	((1ULL << XSK_UNALIGNED_BUF_OFFSET_SHIFT) - 1)

/* Rx/Tx descriptor */
struct xdp_desc {
	__u64 addr;
	__u32 len;
	__u32 options;
};

/* Flag indicating that the packet continues with the buffer pointed out by the
 * next frame in the ring. The end of the packet is signalled by setting this
 * bit to zero. For single buffer packets, every descriptor has 'options' set
 * to 0 and this maintains backward compatibility.
 */
#define XDP_PKT_CONTD (1 << 0)

/*
 * Only used for case that forwarding packets between two XSKs.
 * Userspace uses it to determine if this packet is received from another XSK
*/
#define XDP_EGRESS_FWD (1 << 1)

/* When NIC driver encounters this flag, it should skip processing this descriptor,
 * and xsk_tx_release() should be called
 * This flag is only used internally by the kernel, this flag set by userspace will be ignored
 */
#define XDP_EGRESS_SKIP (1 << 2)

/* If this flag is set, there is no completion event for this queued packet */
#define XDP_EGRESS_NO_COMP (1 << 3)

/* UMEM descriptor is __u64 */

#endif /* _LINUX_IF_XDP_H */
