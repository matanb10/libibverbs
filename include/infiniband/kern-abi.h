/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef KERN_ABI_H
#define KERN_ABI_H

#include <linux/types.h>

/*
 * This file must be kept in sync with the kernel's version of
 * drivers/infiniband/include/ib_user_verbs.h
 */

/*
 * The minimum and maximum kernel ABI that we can handle.
 */
#define IB_USER_VERBS_MIN_ABI_VERSION	3
#define IB_USER_VERBS_MAX_ABI_VERSION	6

#define IB_USER_VERBS_CMD_THRESHOLD    50

enum {
	IB_USER_VERBS_CMD_GET_CONTEXT,
	IB_USER_VERBS_CMD_QUERY_DEVICE,
	IB_USER_VERBS_CMD_QUERY_PORT,
	IB_USER_VERBS_CMD_ALLOC_PD,
	IB_USER_VERBS_CMD_DEALLOC_PD,
	IB_USER_VERBS_CMD_CREATE_AH,
	IB_USER_VERBS_CMD_MODIFY_AH,
	IB_USER_VERBS_CMD_QUERY_AH,
	IB_USER_VERBS_CMD_DESTROY_AH,
	IB_USER_VERBS_CMD_REG_MR,
	IB_USER_VERBS_CMD_REG_SMR,
	IB_USER_VERBS_CMD_REREG_MR,
	IB_USER_VERBS_CMD_QUERY_MR,
	IB_USER_VERBS_CMD_DEREG_MR,
	IB_USER_VERBS_CMD_ALLOC_MW,
	IB_USER_VERBS_CMD_BIND_MW,
	IB_USER_VERBS_CMD_DEALLOC_MW,
	IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL,
	IB_USER_VERBS_CMD_CREATE_CQ,
	IB_USER_VERBS_CMD_RESIZE_CQ,
	IB_USER_VERBS_CMD_DESTROY_CQ,
	IB_USER_VERBS_CMD_POLL_CQ,
	IB_USER_VERBS_CMD_PEEK_CQ,
	IB_USER_VERBS_CMD_REQ_NOTIFY_CQ,
	IB_USER_VERBS_CMD_CREATE_QP,
	IB_USER_VERBS_CMD_QUERY_QP,
	IB_USER_VERBS_CMD_MODIFY_QP,
	IB_USER_VERBS_CMD_DESTROY_QP,
	IB_USER_VERBS_CMD_POST_SEND,
	IB_USER_VERBS_CMD_POST_RECV,
	IB_USER_VERBS_CMD_ATTACH_MCAST,
	IB_USER_VERBS_CMD_DETACH_MCAST,
	IB_USER_VERBS_CMD_CREATE_SRQ,
	IB_USER_VERBS_CMD_MODIFY_SRQ,
	IB_USER_VERBS_CMD_QUERY_SRQ,
	IB_USER_VERBS_CMD_DESTROY_SRQ,
	IB_USER_VERBS_CMD_POST_SRQ_RECV,
	IB_USER_VERBS_CMD_OPEN_XRCD,
	IB_USER_VERBS_CMD_CLOSE_XRCD,
	IB_USER_VERBS_CMD_CREATE_XSRQ,
	IB_USER_VERBS_CMD_OPEN_QP
};

#define IB_USER_VERBS_CMD_COMMAND_MASK		0xff
#define IB_USER_VERBS_CMD_FLAGS_MASK		0xff000000u
#define IB_USER_VERBS_CMD_FLAGS_SHIFT		24


#define IB_USER_VERBS_CMD_FLAG_EXTENDED		0x80ul

/* use this mask for creating extended commands */
#define IB_USER_VERBS_CMD_EXTENDED_MASK \
	(IB_USER_VERBS_CMD_FLAG_EXTENDED << \
	 IB_USER_VERBS_CMD_FLAGS_SHIFT)


enum {
	IB_USER_VERBS_CMD_QUERY_DEVICE_EX = IB_USER_VERBS_CMD_EXTENDED_MASK |
					    IB_USER_VERBS_CMD_QUERY_DEVICE,
	IB_USER_VERBS_CMD_CREATE_QP_EX = IB_USER_VERBS_CMD_EXTENDED_MASK |
					 IB_USER_VERBS_CMD_CREATE_QP,
	IB_USER_VERBS_CMD_CREATE_CQ_EX = IB_USER_VERBS_CMD_EXTENDED_MASK |
						IB_USER_VERBS_CMD_CREATE_CQ,
	IB_USER_VERBS_CMD_CREATE_FLOW = IB_USER_VERBS_CMD_EXTENDED_MASK +
					IB_USER_VERBS_CMD_THRESHOLD,
	IB_USER_VERBS_CMD_DESTROY_FLOW
};

/*
 * Make sure that all structs defined in this file remain laid out so
 * that they pack the same way on 32-bit and 64-bit architectures (to
 * avoid incompatibility between 32-bit userspace and 64-bit kernels).
 * Specifically:
 *  - Do not use pointer types -- pass pointers in __u64 instead.
 *  - Make sure that any structure larger than 4 bytes is padded to a
 *    multiple of 8 bytes.  Otherwise the structure size will be
 *    different between 32-bit and 64-bit architectures.
 */

struct hdr {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
};

struct response_hdr {
	__u64 response;
};

struct ex_hdr {
	struct {
		__u32 command;
		__u16 in_words;
		__u16 out_words;
	};
	struct {
		__u64 response;
	};
	struct {
		__u16 provider_in_words;
		__u16 provider_out_words;
		__u32 reserved;
	};
};

struct ibv_kern_async_event {
	__u64 element;
	__u32 event_type;
	__u32 reserved;
};

struct ibv_comp_event {
	__u64 cq_handle;
};

/*
 * All commands from userspace should start with a __u32 command field
 * followed by __u16 in_words and out_words fields (which give the
 * length of the command block and response buffer if any in 32-bit
 * words).  The kernel driver will read these fields first and read
 * the rest of the command struct based on these value.
 */

struct ibv_query_params {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
};

struct ibv_query_params_resp {
	__u32 num_cq_events;
};

struct ibv_get_context {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u64 driver_data[0];
};

struct ibv_get_context_resp {
	__u32 async_fd;
	__u32 num_comp_vectors;
};

struct ibv_query_device {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u64 driver_data[0];
};

struct ibv_query_device_resp {
	__u64 fw_ver;
	__u64 node_guid;
	__u64 sys_image_guid;
	__u64 max_mr_size;
	__u64 page_size_cap;
	__u32 vendor_id;
	__u32 vendor_part_id;
	__u32 hw_ver;
	__u32 max_qp;
	__u32 max_qp_wr;
	__u32 device_cap_flags;
	__u32 max_sge;
	__u32 max_sge_rd;
	__u32 max_cq;
	__u32 max_cqe;
	__u32 max_mr;
	__u32 max_pd;
	__u32 max_qp_rd_atom;
	__u32 max_ee_rd_atom;
	__u32 max_res_rd_atom;
	__u32 max_qp_init_rd_atom;
	__u32 max_ee_init_rd_atom;
	__u32 atomic_cap;
	__u32 max_ee;
	__u32 max_rdd;
	__u32 max_mw;
	__u32 max_raw_ipv6_qp;
	__u32 max_raw_ethy_qp;
	__u32 max_mcast_grp;
	__u32 max_mcast_qp_attach;
	__u32 max_total_mcast_qp_attach;
	__u32 max_ah;
	__u32 max_fmr;
	__u32 max_map_per_fmr;
	__u32 max_srq;
	__u32 max_srq_wr;
	__u32 max_srq_sge;
	__u16 max_pkeys;
	__u8  local_ca_ack_delay;
	__u8  phys_port_cnt;
	__u8  reserved[4];
};

struct ibv_query_device_ex {
	struct ex_hdr	hdr;
	__u32		comp_mask;
	__u32		reserved;
};

struct ibv_odp_caps_resp {
	__u64 general_caps;
	struct {
		__u32 rc_odp_caps;
		__u32 uc_odp_caps;
		__u32 ud_odp_caps;
	} per_transport_caps;
	__u32 reserved;
};

struct ibv_query_device_resp_ex {
	struct ibv_query_device_resp base;
	__u32 comp_mask;
	__u32 response_length;
	struct ibv_odp_caps_resp odp_caps;
	__u64 timestamp_mask;
	__u64 hca_core_clock;
	__u64 device_cap_flags_ex;
};

struct ibv_query_port {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u8  port_num;
	__u8  reserved[7];
	__u64 driver_data[0];
};

struct ibv_query_port_resp {
	__u32 port_cap_flags;
	__u32 max_msg_sz;
	__u32 bad_pkey_cntr;
	__u32 qkey_viol_cntr;
	__u32 gid_tbl_len;
	__u16 pkey_tbl_len;
	__u16 lid;
	__u16 sm_lid;
	__u8  state;
	__u8  max_mtu;
	__u8  active_mtu;
	__u8  lmc;
	__u8  max_vl_num;
	__u8  sm_sl;
	__u8  subnet_timeout;
	__u8  init_type_reply;
	__u8  active_width;
	__u8  active_speed;
	__u8  phys_state;
	__u8  link_layer;
	__u8  reserved[2];
};

struct ibv_alloc_pd {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u64 driver_data[0];
};

struct ibv_alloc_pd_resp {
	__u32 pd_handle;
};

struct ibv_dealloc_pd {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u32 pd_handle;
};

struct ibv_open_xrcd {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 fd;
	__u32 oflags;
	__u64 driver_data[0];
};

struct ibv_open_xrcd_resp {
	__u32 xrcd_handle;
};

struct ibv_close_xrcd {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u32 xrcd_handle;
};

struct ibv_reg_mr {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u64 start;
	__u64 length;
	__u64 hca_va;
	__u32 pd_handle;
	__u32 access_flags;
	__u64 driver_data[0];
};

struct ibv_reg_mr_resp {
	__u32 mr_handle;
	__u32 lkey;
	__u32 rkey;
};

struct ibv_rereg_mr {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 mr_handle;
	__u32 flags;
	__u64 start;
	__u64 length;
	__u64 hca_va;
	__u32 pd_handle;
	__u32 access_flags;
	__u64 driver_data[0];
};

struct ibv_rereg_mr_resp {
	__u32 lkey;
	__u32 rkey;
};

struct ibv_dereg_mr {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u32 mr_handle;
};

struct ibv_alloc_mw {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 pd_handle;
	__u8  mw_type;
	__u8  reserved[3];
};

struct ibv_alloc_mw_resp {
	__u32 mw_handle;
	__u32 rkey;
};

struct ibv_dealloc_mw {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u32 mw_handle;
	__u32 reserved;
};

struct ibv_create_comp_channel {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
};

struct ibv_create_comp_channel_resp {
	__u32 fd;
};

struct ibv_create_cq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u64 user_handle;
	__u32 cqe;
	__u32 comp_vector;
	__s32 comp_channel;
	__u32 reserved;
	__u64 driver_data[0];
};

struct ibv_create_cq_resp {
	__u32 cq_handle;
	__u32 cqe;
};

enum ibv_create_cq_ex_kernel_flags {
	IBV_CREATE_CQ_EX_KERNEL_FLAG_COMPLETION_TIMESTAMP = 1 << 0,
};

struct ibv_create_cq_ex {
	struct ex_hdr	hdr;
	__u64		user_handle;
	__u32		cqe;
	__u32		comp_vector;
	__s32		comp_channel;
	__u32		comp_mask;
	__u32		flags;
	__u32		reserved;
};

struct ibv_create_cq_resp_ex {
	struct ibv_create_cq_resp	base;
	__u32				comp_mask;
	__u32				response_length;
};

struct ibv_kern_wc {
	__u64  wr_id;
	__u32  status;
	__u32  opcode;
	__u32  vendor_err;
	__u32  byte_len;
	__u32  imm_data;
	__u32  qp_num;
	__u32  src_qp;
	__u32  wc_flags;
	__u16  pkey_index;
	__u16  slid;
	__u8   sl;
	__u8   dlid_path_bits;
	__u8   port_num;
	__u8   reserved;
};

struct ibv_poll_cq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 cq_handle;
	__u32 ne;
};

struct ibv_poll_cq_resp {
	__u32 count;
	__u32 reserved;
	struct ibv_kern_wc wc[0];
};

struct ibv_req_notify_cq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u32 cq_handle;
	__u32 solicited;
};

struct ibv_resize_cq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 cq_handle;
	__u32 cqe;
	__u64 driver_data[0];
};

struct ibv_resize_cq_resp {
	__u32 cqe;
	__u32 reserved;
	__u64 driver_data[0];
};

struct ibv_destroy_cq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 cq_handle;
	__u32 reserved;
};

struct ibv_destroy_cq_resp {
	__u32 comp_events_reported;
	__u32 async_events_reported;
};

struct ibv_kern_global_route {
	__u8  dgid[16];
	__u32 flow_label;
	__u8  sgid_index;
	__u8  hop_limit;
	__u8  traffic_class;
	__u8  reserved;
};

struct ibv_kern_ah_attr {
	struct ibv_kern_global_route grh;
	__u16 dlid;
	__u8  sl;
	__u8  src_path_bits;
	__u8  static_rate;
	__u8  is_global;
	__u8  port_num;
	__u8  reserved;
};

struct ibv_kern_qp_attr {
	__u32	qp_attr_mask;
	__u32	qp_state;
	__u32	cur_qp_state;
	__u32	path_mtu;
	__u32	path_mig_state;
	__u32	qkey;
	__u32	rq_psn;
	__u32	sq_psn;
	__u32	dest_qp_num;
	__u32	qp_access_flags;

	struct ibv_kern_ah_attr ah_attr;
	struct ibv_kern_ah_attr alt_ah_attr;

	/* ib_qp_cap */
	__u32	max_send_wr;
	__u32	max_recv_wr;
	__u32	max_send_sge;
	__u32	max_recv_sge;
	__u32	max_inline_data;

	__u16	pkey_index;
	__u16	alt_pkey_index;
	__u8	en_sqd_async_notify;
	__u8	sq_draining;
	__u8	max_rd_atomic;
	__u8	max_dest_rd_atomic;
	__u8	min_rnr_timer;
	__u8	port_num;
	__u8	timeout;
	__u8	retry_cnt;
	__u8	rnr_retry;
	__u8	alt_port_num;
	__u8	alt_timeout;
	__u8	reserved[5];
};

#define IBV_CREATE_QP_COMMON	\
	__u64 user_handle;	\
	__u32 pd_handle;	\
	__u32 send_cq_handle;	\
	__u32 recv_cq_handle;	\
	__u32 srq_handle;	\
	__u32 max_send_wr;	\
	__u32 max_recv_wr;	\
	__u32 max_send_sge;	\
	__u32 max_recv_sge;	\
	__u32 max_inline_data;	\
	__u8  sq_sig_all;	\
	__u8  qp_type;		\
	__u8  is_srq;		\
	__u8  reserved

struct ibv_create_qp {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	IBV_CREATE_QP_COMMON;
	__u64 driver_data[0];
};

struct ibv_create_qp_common {
	IBV_CREATE_QP_COMMON;
};

struct ibv_open_qp {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u64 user_handle;
	__u32 pd_handle;
	__u32 qpn;
	__u8  qp_type;
	__u8  reserved[7];
	__u64 driver_data[0];
};

/* also used for open response */
struct ibv_create_qp_resp {
	__u32 qp_handle;
	__u32 qpn;
	__u32 max_send_wr;
	__u32 max_recv_wr;
	__u32 max_send_sge;
	__u32 max_recv_sge;
	__u32 max_inline_data;
	__u32 reserved;
};

struct ibv_create_qp_ex {
	struct ex_hdr	hdr;
	struct ibv_create_qp_common base;
	__u32 comp_mask;
	__u32 create_flags;
};

struct ibv_create_qp_resp_ex {
	struct ibv_create_qp_resp base;
	__u32 comp_mask;
	__u32 response_length;
};

struct ibv_qp_dest {
	__u8  dgid[16];
	__u32 flow_label;
	__u16 dlid;
	__u16 reserved;
	__u8  sgid_index;
	__u8  hop_limit;
	__u8  traffic_class;
	__u8  sl;
	__u8  src_path_bits;
	__u8  static_rate;
	__u8  is_global;
	__u8  port_num;
};

struct ibv_query_qp {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 qp_handle;
	__u32 attr_mask;
	__u64 driver_data[0];
};

struct ibv_query_qp_resp {
	struct ibv_qp_dest dest;
	struct ibv_qp_dest alt_dest;
	__u32 max_send_wr;
	__u32 max_recv_wr;
	__u32 max_send_sge;
	__u32 max_recv_sge;
	__u32 max_inline_data;
	__u32 qkey;
	__u32 rq_psn;
	__u32 sq_psn;
	__u32 dest_qp_num;
	__u32 qp_access_flags;
	__u16 pkey_index;
	__u16 alt_pkey_index;
	__u8  qp_state;
	__u8  cur_qp_state;
	__u8  path_mtu;
	__u8  path_mig_state;
	__u8  sq_draining;
	__u8  max_rd_atomic;
	__u8  max_dest_rd_atomic;
	__u8  min_rnr_timer;
	__u8  port_num;
	__u8  timeout;
	__u8  retry_cnt;
	__u8  rnr_retry;
	__u8  alt_port_num;
	__u8  alt_timeout;
	__u8  sq_sig_all;
	__u8  reserved[5];
	__u64 driver_data[0];
};

struct ibv_modify_qp {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	struct ibv_qp_dest dest;
	struct ibv_qp_dest alt_dest;
	__u32 qp_handle;
	__u32 attr_mask;
	__u32 qkey;
	__u32 rq_psn;
	__u32 sq_psn;
	__u32 dest_qp_num;
	__u32 qp_access_flags;
	__u16 pkey_index;
	__u16 alt_pkey_index;
	__u8  qp_state;
	__u8  cur_qp_state;
	__u8  path_mtu;
	__u8  path_mig_state;
	__u8  en_sqd_async_notify;
	__u8  max_rd_atomic;
	__u8  max_dest_rd_atomic;
	__u8  min_rnr_timer;
	__u8  port_num;
	__u8  timeout;
	__u8  retry_cnt;
	__u8  rnr_retry;
	__u8  alt_port_num;
	__u8  alt_timeout;
	__u8  reserved[2];
	__u64 driver_data[0];
};

struct ibv_destroy_qp {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 qp_handle;
	__u32 reserved;
};

struct ibv_destroy_qp_resp {
	__u32 events_reported;
};

struct ibv_kern_send_wr {
	__u64 wr_id;
	__u32 num_sge;
	__u32 opcode;
	__u32 send_flags;
	__u32 imm_data;
	union {
		struct {
			__u64 remote_addr;
			__u32 rkey;
			__u32 reserved;
		} rdma;
		struct {
			__u64 remote_addr;
			__u64 compare_add;
			__u64 swap;
			__u32 rkey;
			__u32 reserved;
		} atomic;
		struct {
			__u32 ah;
			__u32 remote_qpn;
			__u32 remote_qkey;
			__u32 reserved;
		} ud;
	} wr;
	union {
		struct {
			__u32 remote_srqn;
		} xrc;
	} qp_type;
};

struct ibv_kern_eth_filter {
	__u8  dst_mac[6];
	__u8  src_mac[6];
	__u16  ether_type;
	__u16  vlan_tag;
};

struct ibv_kern_spec_eth {
	__u32 type;
	__u16  size;
	__u16 reserved;
	struct ibv_kern_eth_filter val;
	struct ibv_kern_eth_filter mask;
};

struct ibv_kern_ipv4_filter {
	__u32 src_ip;
	__u32 dst_ip;
};

struct ibv_kern_spec_ipv4 {
	__u32  type;
	__u16  size;
	__u16 reserved;
	struct ibv_kern_ipv4_filter val;
	struct ibv_kern_ipv4_filter mask;
};

struct ibv_kern_tcp_udp_filter {
	__u16 dst_port;
	__u16 src_port;
};

struct ibv_kern_spec_tcp_udp {
	__u32  type;
	__u16  size;
	__u16 reserved;
	struct ibv_kern_tcp_udp_filter val;
	struct ibv_kern_tcp_udp_filter mask;
};


struct ibv_kern_spec {
	union {
		struct {
			__u32 type;
			__u16 size;
			__u16 reserved;
		} hdr;
		struct ibv_kern_spec_eth eth;
		struct ibv_kern_spec_ipv4 ipv4;
		struct ibv_kern_spec_tcp_udp tcp_udp;
	};

};

struct ibv_kern_flow_attr {
	__u32 type;
	__u16 size;
	__u16 priority;
	__u8 num_of_specs;
	__u8 reserved[2];
	__u8 port;
	__u32 flags;
	/* Following are the optional layers according to user request
	 * struct ibv_kern_flow_spec_xxx
	 * struct ibv_kern_flow_spec_yyy
	 */
};

struct ibv_post_send {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 qp_handle;
	__u32 wr_count;
	__u32 sge_count;
	__u32 wqe_size;
	struct ibv_kern_send_wr send_wr[0];
};

struct ibv_post_send_resp {
	__u32 bad_wr;
};

struct ibv_kern_recv_wr {
	__u64 wr_id;
	__u32 num_sge;
	__u32 reserved;
};

struct ibv_post_recv {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 qp_handle;
	__u32 wr_count;
	__u32 sge_count;
	__u32 wqe_size;
	struct ibv_kern_recv_wr recv_wr[0];
};

struct ibv_post_recv_resp {
	__u32 bad_wr;
};

struct ibv_post_srq_recv {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 srq_handle;
	__u32 wr_count;
	__u32 sge_count;
	__u32 wqe_size;
	struct ibv_kern_recv_wr recv_wr[0];
};

struct ibv_post_srq_recv_resp {
	__u32 bad_wr;
};

struct ibv_create_ah {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u64 user_handle;
	__u32 pd_handle;
	__u32 reserved;
	struct ibv_kern_ah_attr attr;
};

struct ibv_create_ah_resp {
	__u32 handle;
};

struct ibv_destroy_ah {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u32 ah_handle;
};

struct ibv_attach_mcast {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u8  gid[16];
	__u32 qp_handle;
	__u16 mlid;
	__u16 reserved;
	__u64 driver_data[0];
};

struct ibv_create_flow  {
	struct ex_hdr hdr;
	__u32 comp_mask;
	__u32 qp_handle;
	struct ibv_kern_flow_attr flow_attr;
};

struct ibv_create_flow_resp {
	__u32 comp_mask;
	__u32 flow_handle;
};

struct ibv_destroy_flow  {
	struct ex_hdr hdr;
	__u32 comp_mask;
	__u32 flow_handle;
};

struct ibv_detach_mcast {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u8  gid[16];
	__u32 qp_handle;
	__u16 mlid;
	__u16 reserved;
	__u64 driver_data[0];
};

struct ibv_create_srq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u64 user_handle;
	__u32 pd_handle;
	__u32 max_wr;
	__u32 max_sge;
	__u32 srq_limit;
	__u64 driver_data[0];
};

struct ibv_create_xsrq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u64 user_handle;
	__u32 srq_type;
	__u32 pd_handle;
	__u32 max_wr;
	__u32 max_sge;
	__u32 srq_limit;
	__u32 reserved;
	__u32 xrcd_handle;
	__u32 cq_handle;
	__u64 driver_data[0];
};

struct ibv_create_srq_resp {
	__u32 srq_handle;
	__u32 max_wr;
	__u32 max_sge;
	__u32 srqn;
};

struct ibv_modify_srq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u32 srq_handle;
	__u32 attr_mask;
	__u32 max_wr;
	__u32 srq_limit;
	__u64 driver_data[0];
};

struct ibv_query_srq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 srq_handle;
	__u32 reserved;
	__u64 driver_data[0];
};

struct ibv_query_srq_resp {
	__u32 max_wr;
	__u32 max_sge;
	__u32 srq_limit;
	__u32 reserved;
};

struct ibv_destroy_srq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u32 srq_handle;
	__u32 reserved;
};

struct ibv_destroy_srq_resp {
	__u32 events_reported;
};

/*
 * Compatibility with older ABI versions
 */

enum {
	IB_USER_VERBS_CMD_QUERY_PARAMS_V2,
	IB_USER_VERBS_CMD_GET_CONTEXT_V2,
	IB_USER_VERBS_CMD_QUERY_DEVICE_V2,
	IB_USER_VERBS_CMD_QUERY_PORT_V2,
	IB_USER_VERBS_CMD_QUERY_GID_V2,
	IB_USER_VERBS_CMD_QUERY_PKEY_V2,
	IB_USER_VERBS_CMD_ALLOC_PD_V2,
	IB_USER_VERBS_CMD_DEALLOC_PD_V2,
	IB_USER_VERBS_CMD_CREATE_AH_V2,
	IB_USER_VERBS_CMD_MODIFY_AH_V2,
	IB_USER_VERBS_CMD_QUERY_AH_V2,
	IB_USER_VERBS_CMD_DESTROY_AH_V2,
	IB_USER_VERBS_CMD_REG_MR_V2,
	IB_USER_VERBS_CMD_REG_SMR_V2,
	IB_USER_VERBS_CMD_REREG_MR_V2,
	IB_USER_VERBS_CMD_QUERY_MR_V2,
	IB_USER_VERBS_CMD_DEREG_MR_V2,
	IB_USER_VERBS_CMD_ALLOC_MW_V2,
	IB_USER_VERBS_CMD_BIND_MW_V2,
	IB_USER_VERBS_CMD_DEALLOC_MW_V2,
	IB_USER_VERBS_CMD_CREATE_CQ_V2,
	IB_USER_VERBS_CMD_RESIZE_CQ_V2,
	IB_USER_VERBS_CMD_DESTROY_CQ_V2,
	IB_USER_VERBS_CMD_POLL_CQ_V2,
	IB_USER_VERBS_CMD_PEEK_CQ_V2,
	IB_USER_VERBS_CMD_REQ_NOTIFY_CQ_V2,
	IB_USER_VERBS_CMD_CREATE_QP_V2,
	IB_USER_VERBS_CMD_QUERY_QP_V2,
	IB_USER_VERBS_CMD_MODIFY_QP_V2,
	IB_USER_VERBS_CMD_DESTROY_QP_V2,
	IB_USER_VERBS_CMD_POST_SEND_V2,
	IB_USER_VERBS_CMD_POST_RECV_V2,
	IB_USER_VERBS_CMD_ATTACH_MCAST_V2,
	IB_USER_VERBS_CMD_DETACH_MCAST_V2,
	IB_USER_VERBS_CMD_CREATE_SRQ_V2,
	IB_USER_VERBS_CMD_MODIFY_SRQ_V2,
	IB_USER_VERBS_CMD_QUERY_SRQ_V2,
	IB_USER_VERBS_CMD_DESTROY_SRQ_V2,
	IB_USER_VERBS_CMD_POST_SRQ_RECV_V2,
	/*
	 * Set commands that didn't exist to -1 so our compile-time
	 * trick opcodes in IBV_INIT_CMD() doesn't break.
	 */
	IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL_V2 = -1,
	IB_USER_VERBS_CMD_OPEN_XRCD_V2 = -1,
	IB_USER_VERBS_CMD_CLOSE_XRCD_V2 = -1,
	IB_USER_VERBS_CMD_CREATE_XSRQ_V2 = -1,
	IB_USER_VERBS_CMD_OPEN_QP_V2 = -1,
	IB_USER_VERBS_CMD_CREATE_FLOW_V2 = -1,
	IB_USER_VERBS_CMD_DESTROY_FLOW_V2 = -1,
	IB_USER_VERBS_CMD_QUERY_DEVICE_EX_V2 = -1,
	IB_USER_VERBS_CMD_CREATE_QP_EX_V2 = -1,
	IB_USER_VERBS_CMD_CREATE_CQ_EX_V2 = -1,
};

struct ibv_modify_srq_v3 {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u32 srq_handle;
	__u32 attr_mask;
	__u32 max_wr;
	__u32 max_sge;
	__u32 srq_limit;
	__u32 reserved;
	__u64 driver_data[0];
};

struct ibv_create_qp_resp_v3 {
	__u32 qp_handle;
	__u32 qpn;
};

struct ibv_create_qp_resp_v4 {
	__u32 qp_handle;
	__u32 qpn;
	__u32 max_send_wr;
	__u32 max_recv_wr;
	__u32 max_send_sge;
	__u32 max_recv_sge;
	__u32 max_inline_data;
};

struct ibv_create_srq_resp_v5 {
	__u32 srq_handle;
};

#define IB_UVERBS_SCOPE_DRIVER	0x1000

enum {
	UVERBS_UHW_IN = IB_UVERBS_SCOPE_DRIVER,
	UVERBS_UHW_OUT,
};

#define UVERBS_UHW_SZ ((UVERBS_UHW_OUT & ~IB_UVERBS_SCOPE_DRIVER) + 1)

enum uverbs_common_types {
	UVERBS_TYPE_DEVICE, /* Don't use IDRs here */
	UVERBS_TYPE_PD,
	UVERBS_TYPE_COMP_CHANNEL,
	UVERBS_TYPE_CQ,
	UVERBS_TYPE_QP,
	UVERBS_TYPE_SRQ,
	UVERBS_TYPE_AH,
	UVERBS_TYPE_MR,
	UVERBS_TYPE_MW,
	UVERBS_TYPE_FLOW,
	UVERBS_TYPE_XRCD,
	UVERBS_TYPE_LAST,
};

enum uverbs_create_qp_cmd_attr {
	CREATE_QP_HANDLE,
	CREATE_QP_PD_HANDLE,
	CREATE_QP_SEND_CQ,
	CREATE_QP_RECV_CQ,
	CREATE_QP_SRQ,
	CREATE_QP_USER_HANDLE,
	CREATE_QP_CMD,
	CREATE_QP_CMD_FLAGS,
	CREATE_QP_RESP,
	CREATE_QP_RESERVED
};

enum uverbs_destroy_qp_cmd_attr {
	DESTROY_QP_HANDLE,
	DESTROY_QP_EVENTS_REPORTED,
	DESTROY_QP_RESERVED
};

enum uverbs_create_cq_cmd_attr {
	CREATE_CQ_HANDLE,
	CREATE_CQ_CQE,
	CREATE_CQ_USER_HANDLE,
	CREATE_CQ_COMP_CHANNEL,
	CREATE_CQ_COMP_VECTOR,
	CREATE_CQ_FLAGS,
	CREATE_CQ_RESP_CQE,
	CREATE_CQ_RESERVED,
};

enum uverbs_destroy_cq_cmd_attr {
	DESTROY_CQ_HANDLE,
	DESTROY_CQ_RESP,
	DESTROY_CQ_RESERVED
};

enum uverbs_create_qp_xrc_tgt_cmd_attr {
	CREATE_QP_XRC_TGT_HANDLE,
	CREATE_QP_XRC_TGT_XRCD,
	CREATE_QP_XRC_TGT_USER_HANDLE,
	CREATE_QP_XRC_TGT_CMD,
	CREATE_QP_XRC_TGT_CMD_FLAGS,
	CREATE_QP_XRC_TGT_RESP,
	CREATE_QP_XRC_TGT_RESERVED
};

enum uverbs_modify_qp_cmd_attr {
	MODIFY_QP_HANDLE,
	MODIFY_QP_STATE,
	MODIFY_QP_CUR_STATE,
	MODIFY_QP_EN_SQD_ASYNC_NOTIFY,
	MODIFY_QP_ACCESS_FLAGS,
	MODIFY_QP_PKEY_INDEX,
	MODIFY_QP_PORT,
	MODIFY_QP_QKEY,
	MODIFY_QP_AV,
	MODIFY_QP_PATH_MTU,
	MODIFY_QP_TIMEOUT,
	MODIFY_QP_RETRY_CNT,
	MODIFY_QP_RNR_RETRY,
	MODIFY_QP_RQ_PSN,
	MODIFY_QP_MAX_RD_ATOMIC,
	MODIFY_QP_ALT_PATH,
	MODIFY_QP_MIN_RNR_TIMER,
	MODIFY_QP_SQ_PSN,
	MODIFY_QP_MAX_DEST_RD_ATOMIC,
	MODIFY_QP_PATH_MIG_STATE,
	MODIFY_QP_DEST_QPN,
	MODIFY_QP_RESERVED
};

enum uverbs_create_comp_channel_cmd_attr {
	CREATE_COMP_CHANNEL_FD,
	CREATE_COMP_CHANNEL_RESERVED
};

enum uverbs_get_context {
	GET_CONTEXT_RESP,
	GET_CONTEXT_RESERVED,
};

enum uverbs_query_device {
	QUERY_DEVICE_RESP,
	QUERY_DEVICE_ODP,
	QUERY_DEVICE_TIMESTAMP_MASK,
	QUERY_DEVICE_HCA_CORE_CLOCK,
	QUERY_DEVICE_CAP_FLAGS,
	QUERY_DEVICE_CAP_RESERVED,
};

enum uverbs_query_port {
	QUERY_PORT_PORT_NUM,
	QUERY_PORT_RESP,
	QUERY_PORT_RESERVED
};

enum uverbs_alloc_pd {
	ALLOC_PD_HANDLE,
	ALLOC_PD_RESERVED,
};

enum uverbs_dealloc_pd {
	DEALLOC_PD_HANDLE,
	DEALLOC_PD_RESERVED,
};

enum uverbs_reg_mr {
	REG_MR_HANDLE,
	REG_MR_PD_HANDLE,
	REG_MR_CMD,
	REG_MR_RESP,
	REG_MR_RESERVED,
};

enum uverbs_dereg_mr {
	DEREG_MR_HANDLE,
	DEREG_MR_RESERVED
};

enum uverbs_actions_mr_ops {
	UVERBS_MR_REG,
	UVERBS_MR_DEREG,
};

enum uverbs_actions_comp_channel_ops {
	UVERBS_COMP_CHANNEL_CREATE,
};

enum uverbs_actions_cq_ops {
	UVERBS_CQ_CREATE,
	UVERBS_CQ_DESTROY,
};

enum uverbs_actions_qp_ops {
	UVERBS_QP_CREATE,
	UVERBS_QP_CREATE_XRC_TGT,
	UVERBS_QP_MODIFY,
	UVERBS_QP_DESTROY
};

enum uverbs_actions_pd_ops {
	UVERBS_PD_ALLOC,
	UVERBS_PD_DEALLOC,
};

enum uverbs_actions_device_ops {
	UVERBS_DEVICE_ALLOC_CONTEXT,
	UVERBS_DEVICE_QUERY,
	UVERBS_DEVICE_PORT_QUERY,
};

struct ib_uverbs_ioctl_create_qp {
	__u32 max_send_wr;
	__u32 max_recv_wr;
	__u32 max_send_sge;
	__u32 max_recv_sge;
	__u32 max_inline_data;
	__u8  sq_sig_all;
	__u8  qp_type;
	__u16 reserved;
};

struct ib_uverbs_ioctl_create_qp_resp {
	__u32 qpn;
	__u32 max_send_wr;
	__u32 max_recv_wr;
	__u32 max_send_sge;
	__u32 max_recv_sge;
	__u32 max_inline_data;
};

struct ib_uverbs_qp_alt_path {
	struct ibv_qp_dest dest;
	__u16 pkey_index;
	__u8  port_num;
	__u8  timeout;
};

#endif /* KERN_ABI_H */
