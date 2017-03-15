/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <alloca.h>
#include <string.h>
#include <sys/ioctl.h>

#include "ibverbs.h"

struct ibv_ioctl_cmd_get_context {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[GET_CONTEXT_RESERVED + UVERBS_UHW_SZ];
} __attribute__((packed, aligned(4)));

int ibv_cmd_get_context(struct ibv_context *context, struct ibv_get_context *legacy_cmd,
			size_t cmd_size, struct ibv_get_context_resp *legacy_resp,
			size_t resp_size)
{
	long ret;

	struct ibv_ioctl_cmd_get_context cmd;
	struct ibv_get_context_resp resp;
	struct ib_uverbs_attr *attr = cmd.attrs;

	if (abi_ver < IB_USER_VERBS_MIN_ABI_VERSION)
		return ENOSYS;

	fill_attr_out(attr++, GET_CONTEXT_RESP, sizeof(resp), &resp);
	if (cmd_size - sizeof(struct ibv_get_context))
		fill_attr_in(attr++, UVERBS_UHW_IN,
			     cmd_size - sizeof(struct ibv_get_context), legacy_cmd + 1);
	if (resp_size - sizeof(resp))
		fill_attr_out(attr++, UVERBS_UHW_OUT,
			      resp_size - sizeof(resp), legacy_resp + 1);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_DEVICE,
		       (void *)attr - (void *)&cmd, UVERBS_DEVICE_ALLOC_CONTEXT,
		       attr - cmd.attrs);

	ret = ioctl(context->cmd_fd, RDMA_VERBS_IOCTL, &cmd);
	printf("ret is %lu\n", ret);
	if (ret)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);
	return 0;
}

static void copy_query_dev_fields(struct ibv_device_attr *device_attr,
				  struct ibv_query_device_resp *resp,
				  uint64_t *raw_fw_ver)
{
	*raw_fw_ver				= resp->fw_ver;
	device_attr->node_guid			= resp->node_guid;
	device_attr->sys_image_guid		= resp->sys_image_guid;
	device_attr->max_mr_size		= resp->max_mr_size;
	device_attr->page_size_cap		= resp->page_size_cap;
	device_attr->vendor_id			= resp->vendor_id;
	device_attr->vendor_part_id		= resp->vendor_part_id;
	device_attr->hw_ver			= resp->hw_ver;
	device_attr->max_qp			= resp->max_qp;
	device_attr->max_qp_wr			= resp->max_qp_wr;
	device_attr->device_cap_flags		= resp->device_cap_flags;
	device_attr->max_sge			= resp->max_sge;
	device_attr->max_sge_rd			= resp->max_sge_rd;
	device_attr->max_cq			= resp->max_cq;
	device_attr->max_cqe			= resp->max_cqe;
	device_attr->max_mr			= resp->max_mr;
	device_attr->max_pd			= resp->max_pd;
	device_attr->max_qp_rd_atom		= resp->max_qp_rd_atom;
	device_attr->max_ee_rd_atom		= resp->max_ee_rd_atom;
	device_attr->max_res_rd_atom		= resp->max_res_rd_atom;
	device_attr->max_qp_init_rd_atom	= resp->max_qp_init_rd_atom;
	device_attr->max_ee_init_rd_atom	= resp->max_ee_init_rd_atom;
	device_attr->atomic_cap			= resp->atomic_cap;
	device_attr->max_ee			= resp->max_ee;
	device_attr->max_rdd			= resp->max_rdd;
	device_attr->max_mw			= resp->max_mw;
	device_attr->max_raw_ipv6_qp		= resp->max_raw_ipv6_qp;
	device_attr->max_raw_ethy_qp		= resp->max_raw_ethy_qp;
	device_attr->max_mcast_grp		= resp->max_mcast_grp;
	device_attr->max_mcast_qp_attach	= resp->max_mcast_qp_attach;
	device_attr->max_total_mcast_qp_attach	= resp->max_total_mcast_qp_attach;
	device_attr->max_ah			= resp->max_ah;
	device_attr->max_fmr			= resp->max_fmr;
	device_attr->max_map_per_fmr		= resp->max_map_per_fmr;
	device_attr->max_srq			= resp->max_srq;
	device_attr->max_srq_wr			= resp->max_srq_wr;
	device_attr->max_srq_sge		= resp->max_srq_sge;
	device_attr->max_pkeys			= resp->max_pkeys;
	device_attr->local_ca_ack_delay		= resp->local_ca_ack_delay;
	device_attr->phys_port_cnt		= resp->phys_port_cnt;
}

struct ibv_ioctl_cmd_query_device {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs;
} __attribute__((packed, aligned(4)));

int ibv_cmd_query_device(struct ibv_context *context,
			 struct ibv_device_attr *device_attr,
			 uint64_t *raw_fw_ver,
			 struct ibv_query_device *legacy_cmd, size_t cmd_size)
{
	long ret;
	struct ibv_ioctl_cmd_query_device cmd;
	struct ibv_query_device_resp resp;

	if (abi_ver < IB_USER_VERBS_MIN_ABI_VERSION)
		return ENOSYS;

	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_DEVICE, sizeof(cmd),
		       UVERBS_DEVICE_QUERY, 1);
	fill_attr_out(&cmd.attrs, QUERY_DEVICE_RESP, sizeof(resp), &resp);

	ret = ioctl(context->cmd_fd, RDMA_VERBS_IOCTL, &cmd);
	if (ret)
		return errno;

	memset(device_attr->fw_ver, 0, sizeof device_attr->fw_ver);
	copy_query_dev_fields(device_attr, &resp, raw_fw_ver);

	return 0;
}

struct ibv_ioctl_cmd_query_device_ex {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[QUERY_DEVICE_RESERVED];
} __attribute__((packed, aligned(4)));

int ibv_cmd_query_device_ex(struct ibv_context *context,
			    const struct ibv_query_device_ex_input *input,
			    struct ibv_device_attr_ex *attr, size_t attr_size,
			    uint64_t *raw_fw_ver,
			    struct ibv_query_device_ex *legacy_cmd,
			    size_t cmd_core_size,
			    size_t cmd_size,
			    struct ibv_query_device_resp_ex *legacy_resp,
			    size_t resp_core_size,
			    size_t resp_size)
{
	long ret;
	struct ibv_ioctl_cmd_query_device_ex cmd;
	struct ibv_query_device_resp resp;
	struct ibv_odp_caps_resp odp_caps = {};
	struct ib_uverbs_attr *cattr = cmd.attrs;
	__u64 timestamp_mask = 0;
	__u64 hca_core_clock = 0;
	__u64 device_cap_flags_ex = 0;

	if (abi_ver < IB_USER_VERBS_MIN_ABI_VERSION)
		return ENOSYS;

	fill_attr_out(cattr++, QUERY_DEVICE_RESP, sizeof(resp), &resp);
	fill_attr_out(cattr++, QUERY_DEVICE_ODP, sizeof(odp_caps), &odp_caps);
	fill_attr_out(cattr++, QUERY_DEVICE_TIMESTAMP_MASK,
		      sizeof(timestamp_mask), &timestamp_mask);
	fill_attr_out(cattr++, QUERY_DEVICE_HCA_CORE_CLOCK,
		      sizeof(hca_core_clock), &hca_core_clock);
	fill_attr_out(cattr++, QUERY_DEVICE_CAP_FLAGS,
		      sizeof(device_cap_flags_ex), &device_cap_flags_ex);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_DEVICE,
		       (void *)cattr - (void *)&cmd,
		       UVERBS_DEVICE_QUERY, cattr - cmd.attrs);

	ret = ioctl(context->cmd_fd, RDMA_VERBS_IOCTL, &cmd);
	if (ret)
		return errno;

	memset(attr->orig_attr.fw_ver, 0, sizeof(attr->orig_attr.fw_ver));

	(void)VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);
	copy_query_dev_fields(&attr->orig_attr, &resp, raw_fw_ver);
	/* Report back supported comp_mask bits. For now no comp_mask bit is
	 * defined */
	attr->odp_caps.general_caps = odp_caps.general_caps;
	attr->odp_caps.per_transport_caps.rc_odp_caps =
		odp_caps.per_transport_caps.rc_odp_caps;
	attr->odp_caps.per_transport_caps.uc_odp_caps =
		odp_caps.per_transport_caps.uc_odp_caps;
	attr->odp_caps.per_transport_caps.ud_odp_caps =
		odp_caps.per_transport_caps.ud_odp_caps;

	attr->completion_timestamp_mask = timestamp_mask;

	attr->hca_core_clock = hca_core_clock;

	attr->device_cap_flags_ex = device_cap_flags_ex;

	return 0;
}

struct ibv_ioctl_cmd_query_port {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[QUERY_PORT_RESERVED];
} __attribute__((packed, aligned(4)));

int ibv_cmd_query_port(struct ibv_context *context, uint8_t port_num,
		       struct ibv_port_attr *port_attr,
		       struct ibv_query_port *legacy_cmd, size_t legacy_cmd_size)
{
	int ret;
	struct ibv_query_port_resp resp;
	struct ibv_ioctl_cmd_query_port cmd;
	struct ib_uverbs_attr *cattr = cmd.attrs;

	fill_attr_in(cattr++, QUERY_PORT_PORT_NUM, sizeof(port_num), &port_num);
	fill_attr_out(cattr++, QUERY_PORT_RESP, sizeof(resp), &resp);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_DEVICE,
		       (void *)cattr - (void *)&cmd,
		       UVERBS_DEVICE_PORT_QUERY, cattr - cmd.attrs);

	ret = ioctl(context->cmd_fd, RDMA_VERBS_IOCTL, &cmd);
	if (ret) {
		printf("ret %d\n", ret);
		return errno;
	}

	(void) VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	port_attr->state      	   = resp.state;
	port_attr->max_mtu         = resp.max_mtu;
	port_attr->active_mtu      = resp.active_mtu;
	port_attr->gid_tbl_len     = resp.gid_tbl_len;
	port_attr->port_cap_flags  = resp.port_cap_flags;
	port_attr->max_msg_sz      = resp.max_msg_sz;
	port_attr->bad_pkey_cntr   = resp.bad_pkey_cntr;
	port_attr->qkey_viol_cntr  = resp.qkey_viol_cntr;
	port_attr->pkey_tbl_len    = resp.pkey_tbl_len;
	port_attr->lid 	      	   = resp.lid;
	port_attr->sm_lid 	   = resp.sm_lid;
	port_attr->lmc 	      	   = resp.lmc;
	port_attr->max_vl_num      = resp.max_vl_num;
	port_attr->sm_sl      	   = resp.sm_sl;
	port_attr->subnet_timeout  = resp.subnet_timeout;
	port_attr->init_type_reply = resp.init_type_reply;
	port_attr->active_width    = resp.active_width;
	port_attr->active_speed    = resp.active_speed;
	port_attr->phys_state      = resp.phys_state;
	port_attr->link_layer      = resp.link_layer;

	return 0;
}

struct ibv_ioctl_cmd_alloc_pd {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[ALLOC_PD_RESERVED + UVERBS_UHW_SZ];
} __attribute__((packed, aligned(4)));

int ibv_cmd_alloc_pd(struct ibv_context *context, struct ibv_pd *pd,
		     struct ibv_alloc_pd *legacy_cmd, size_t cmd_size,
		     struct ibv_alloc_pd_resp *legacy_resp, size_t resp_size)
{
	long ret;

	struct ibv_ioctl_cmd_alloc_pd cmd;
	struct ib_uverbs_attr *attr = cmd.attrs;

	if (abi_ver < IB_USER_VERBS_MIN_ABI_VERSION)
		return ENOSYS;

	fill_attr_obj(attr++, ALLOC_PD_HANDLE, 0);
	if (cmd_size - sizeof(struct ibv_alloc_pd))
		fill_attr_in(attr++, UVERBS_UHW_IN,
			     cmd_size - sizeof(struct ibv_alloc_pd), legacy_cmd + 1);
	if (resp_size - sizeof(struct ibv_alloc_pd_resp))
		fill_attr_out(attr++, UVERBS_UHW_OUT,
			      resp_size - sizeof(struct ibv_alloc_pd_resp), legacy_resp + 1);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_PD, (void *)attr - (void *)&cmd,
		       UVERBS_PD_ALLOC, attr - cmd.attrs);

	ret = ioctl(context->cmd_fd, RDMA_VERBS_IOCTL, &cmd);
	if (ret)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	pd->handle  = cmd.attrs[0].data;
	pd->context = context;

	return 0;
}

struct ibv_ioctl_cmd_dealloc_pd {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[DEALLOC_PD_RESERVED];
} __attribute__((packed, aligned(4)));

int ibv_cmd_dealloc_pd(struct ibv_pd *pd)
{
	struct ibv_ioctl_cmd_dealloc_pd cmd;
	struct ib_uverbs_attr *attr = cmd.attrs;

	fill_attr_obj(attr++, DEALLOC_PD_HANDLE, pd->handle);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_PD, (void *)attr - (void *)&cmd,
		       UVERBS_PD_DEALLOC, attr - cmd.attrs);

	if (ioctl(pd->context->cmd_fd, RDMA_VERBS_IOCTL, &cmd))
		return errno;

	return 0;
}

int ibv_cmd_open_xrcd(struct ibv_context *context, struct verbs_xrcd *xrcd,
		      int vxrcd_size,
		      struct ibv_xrcd_init_attr *attr,
		      struct ibv_open_xrcd *cmd, size_t cmd_size,
		      struct ibv_open_xrcd_resp *resp, size_t resp_size)
{
	IBV_INIT_CMD_RESP(cmd, cmd_size, OPEN_XRCD, resp, resp_size);

	if (attr->comp_mask >= IBV_XRCD_INIT_ATTR_RESERVED)
		return ENOSYS;

	if (!(attr->comp_mask & IBV_XRCD_INIT_ATTR_FD) ||
	    !(attr->comp_mask & IBV_XRCD_INIT_ATTR_OFLAGS))
		return EINVAL;

	cmd->fd = attr->fd;
	cmd->oflags = attr->oflags;
	if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	xrcd->xrcd.context = context;
	xrcd->comp_mask = 0;
	if (vext_field_avail(struct verbs_xrcd, handle, vxrcd_size)) {
		xrcd->comp_mask = VERBS_XRCD_HANDLE;
		xrcd->handle  = resp->xrcd_handle;
	}

	return 0;
}

int ibv_cmd_close_xrcd(struct verbs_xrcd *xrcd)
{
	struct ibv_close_xrcd cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, CLOSE_XRCD);
	cmd.xrcd_handle = xrcd->handle;

	if (write(xrcd->xrcd.context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}

struct ibv_ioctl_reg_mr {
	__u64 start;
	__u64 length;
	__u64 hca_va;
	__u32 access_flags;
	__u32 reserved;
};

struct ibv_ioctl_reg_mr_resp {
	__u32 lkey;
	__u32 rkey;
};

struct ibv_ioctl_cmd_reg_mr {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[REG_MR_RESERVED];
} __attribute__((packed, aligned(4)));
/* mr, pd, cmd, resp */

int ibv_cmd_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
		   uint64_t hca_va, int access,
		   struct ibv_mr *mr, struct ibv_reg_mr *legacy_cmd,
		   size_t cmd_size,
		   struct ibv_reg_mr_resp *legacy_resp, size_t resp_size)
{
	struct ibv_ioctl_cmd_reg_mr	cmd;
	struct ibv_ioctl_reg_mr		reg_mr_cmd;
	struct ibv_ioctl_reg_mr_resp	resp;
	struct ib_uverbs_attr *attr = cmd.attrs;
	int ret;

	fill_attr_obj(attr++, REG_MR_HANDLE, 0);
	fill_attr_obj(attr++, REG_MR_PD_HANDLE, pd->handle);
	fill_attr_in(attr++, REG_MR_CMD, sizeof(reg_mr_cmd), &reg_mr_cmd);
	fill_attr_out(attr++, REG_MR_RESP, sizeof(resp), &resp);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_MR, (void *)attr - (void *)&cmd,
		       UVERBS_MR_REG, attr - cmd.attrs);

	reg_mr_cmd.start	  = (uintptr_t)addr;
	reg_mr_cmd.length	  = length;
	reg_mr_cmd.hca_va	  = hca_va;
	reg_mr_cmd.access_flags = access;

	ret = ioctl(pd->context->cmd_fd, RDMA_VERBS_IOCTL, &cmd);
	if (ret)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	mr->handle  = cmd.attrs[0].data;
	mr->lkey    = resp.lkey;
	mr->rkey    = resp.rkey;
	mr->context = pd->context;

	return 0;
}

#define new_rereg_me
#ifdef new_rereg_me
struct ibv_ioctl_rereg_mr_cmd {
	__u64 response;
	__u32 mr_handle;
	__u32 flags;
	__u64 start;
	__u64 length;
	__u64 hca_va;
	__u32 pd_handle;
	__u32 access_flags;
};

struct ibv_ioctl_cmd_rereg_mr {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[REREG_MR_RESERVED];
}__attribute__((packed, aligned(4)));

int ibv_cmd_rereg_mr(struct ibv_mr *mr, uint32_t flags, void *addr,
		     size_t length, uint64_t hca_va, int access,
		     struct ibv_pd *pd, struct ibv_rereg_mr *cmd,
		     size_t cmd_sz, struct ibv_rereg_mr_resp *resp,
		     size_t resp_sz)
{
	struct ibv_ioctl_cmd_rereg_mr iocmd;
	struct ib_uverbs_attr         *cattr = iocmd.attrs;
	struct ibv_ioctl_rereg_mr_cmd rereg_mr_cmd;

	fill_attr_obj(cattr++, REREG_MR_HANDLE, mr->handle);

	if (flags & IBV_REREG_MR_CHANGE_PD)
		fill_attr_obj(cattr++, REREG_MR_PD_HANDLE, pd->handle);
	else
		fill_attr_obj(cattr++, REREG_MR_PD_HANDLE, 0);

	fill_attr_in(cattr++, REREG_MR_CMD, sizeof(struct ibv_ioctl_rereg_mr_cmd), &rereg_mr_cmd);
	fill_attr_out(cattr++, REREG_MR_RESP, sizeof(struct ibv_rereg_mr_resp), resp);

	rereg_mr_cmd.start         =  (uintptr_t)addr;
	rereg_mr_cmd.length        =  length;
	rereg_mr_cmd.hca_va        =  hca_va;
	rereg_mr_cmd.flags         =  flags;
	rereg_mr_cmd.access_flags  =  access;

	fill_ioctl_hdr(&iocmd.hdr, UVERBS_TYPE_MR, (void *)cattr - (void *)&iocmd,
		       UVERBS_MR_REREG, cattr - iocmd.attrs);

	if (ioctl(mr->context->cmd_fd, RDMA_VERBS_IOCTL, &iocmd))
		return errno;

	mr->lkey    = resp->lkey;
	mr->rkey    = resp->rkey;
	if (flags & IBV_REREG_MR_CHANGE_PD)
		mr->context = pd->context;

	return 0;
}
#else
int ibv_cmd_rereg_mr(struct ibv_mr *mr, uint32_t flags, void *addr,
		     size_t length, uint64_t hca_va, int access,
		     struct ibv_pd *pd, struct ibv_rereg_mr *cmd,
		     size_t cmd_sz, struct ibv_rereg_mr_resp *resp,
		     size_t resp_sz)
{
	IBV_INIT_CMD_RESP(cmd, cmd_sz, REREG_MR, resp, resp_sz);

	cmd->mr_handle	  = mr->handle;
	cmd->flags	  = flags;
	cmd->start	  = (uintptr_t)addr;
	cmd->length	  = length;
	cmd->hca_va	  = hca_va;
	cmd->pd_handle	  = (flags & IBV_REREG_MR_CHANGE_PD) ? pd->handle : 0;
	cmd->access_flags = access;

	if (write(mr->context->cmd_fd, cmd, cmd_sz) != cmd_sz)
		return errno;

	(void)VALGRIND_MAKE_MEM_DEFINED(resp, resp_sz);

	mr->lkey    = resp->lkey;
	mr->rkey    = resp->rkey;
	if (flags & IBV_REREG_MR_CHANGE_PD)
		mr->context = pd->context;

	return 0;
}
#endif

struct ibv_ioctl_cmd_dereg_mr {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[DEREG_MR_RESERVED];
} __attribute__((packed, aligned(4)));
/* mr, pd, cmd, resp */

int ibv_cmd_dereg_mr(struct ibv_mr *mr)
{
	struct ibv_ioctl_cmd_dereg_mr cmd;
	struct ib_uverbs_attr *cattr = cmd.attrs;

	fill_attr_obj(cattr++, DEREG_MR_HANDLE, mr->handle);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_MR, (void *)cattr - (void *)&cmd,
		       UVERBS_MR_DEREG, cattr - cmd.attrs);

	if (ioctl(mr->context->cmd_fd, RDMA_VERBS_IOCTL, &cmd))
		return errno;

	return 0;
}

int ibv_cmd_alloc_mw(struct ibv_pd *pd, enum ibv_mw_type type,
		     struct ibv_mw *mw, struct ibv_alloc_mw *cmd,
		     size_t cmd_size,
		     struct ibv_alloc_mw_resp *resp, size_t resp_size)
{
	IBV_INIT_CMD_RESP(cmd, cmd_size, ALLOC_MW, resp, resp_size);
	cmd->pd_handle	= pd->handle;
	cmd->mw_type	= type;
	memset(cmd->reserved, 0, sizeof(cmd->reserved));

	if (write(pd->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	mw->context = pd->context;
	mw->pd      = pd;
	mw->rkey    = resp->rkey;
	mw->handle  = resp->mw_handle;
	mw->type    = type;

	return 0;
}

int ibv_cmd_dealloc_mw(struct ibv_mw *mw,
		       struct ibv_dealloc_mw *cmd, size_t cmd_size)
{
	IBV_INIT_CMD(cmd, cmd_size, DEALLOC_MW);
	cmd->mw_handle = mw->handle;
	cmd->reserved = 0;

	if (write(mw->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	return 0;
}

struct ibv_ioctl_cmd_create_cq {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[CREATE_CQ_RESERVED + UVERBS_UHW_SZ];
} __attribute__((packed, aligned(4)));
/* handle, cqe, user_handle, comp_channel, comp_vector, <flags>, resp_cqe */

int ibv_cmd_create_cq(struct ibv_context *context, int cqe,
		      struct ibv_comp_channel *channel,
		      int comp_vector, struct ibv_cq *cq,
		      struct ibv_create_cq *legacy_cmd, size_t cmd_size,
		      struct ibv_create_cq_resp *legacy_resp, size_t resp_size)
{
	__s32 comp_channel = channel ? channel->fd : -1;
	struct ibv_ioctl_cmd_create_cq cmd;
	int ret;
	__u32 _cqe = cqe;
	__u64 _user_handle = (uintptr_t)cq;
	__u32 _comp_vector = comp_vector;
	__u32 _cqe_out;
	struct ib_uverbs_attr *attrs = cmd.attrs;

	printf("%s:%d\n", __func__, __LINE__);
	fill_attr_obj(attrs++, CREATE_CQ_HANDLE, 0);
	fill_attr_in(attrs++, CREATE_CQ_CQE, sizeof(_cqe), &_cqe);
	fill_attr_in(attrs++, CREATE_CQ_USER_HANDLE, sizeof(_user_handle),
		  &_user_handle);
	fill_attr_in(attrs++, CREATE_CQ_COMP_VECTOR, sizeof(_comp_vector),
		  &_comp_vector);
	fill_attr_out(attrs++, CREATE_CQ_RESP_CQE, sizeof(_cqe_out), &_cqe_out);
	if (cmd_size - sizeof(struct ibv_create_cq))
		fill_attr_in(attrs++, UVERBS_UHW_IN,
			     cmd_size - sizeof(struct ibv_create_cq), legacy_cmd + 1);
	if (resp_size - sizeof(struct ibv_create_cq_resp))
		fill_attr_out(attrs++, UVERBS_UHW_OUT,
			      resp_size - sizeof(struct ibv_create_cq_resp), legacy_resp + 1);
	if (channel)
		fill_attr_obj(attrs++, CREATE_CQ_COMP_CHANNEL, comp_channel);

	printf("%s:%d\n", __func__, __LINE__);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_CQ, (void *)attrs - (void *)&cmd,
		       UVERBS_CQ_CREATE,
		       attrs - cmd.attrs);
	ret = ioctl(context->cmd_fd, RDMA_VERBS_IOCTL, &cmd);
	if (ret)
		return errno;

	printf("%s:%d\n", __func__, __LINE__);
	cq->context = context;
	cq->cqe = _cqe_out;
	cq->handle = cmd.attrs[0].data;
	printf("%s:%d\n", __func__, __LINE__);

	return 0;
}

int ibv_cmd_create_cq_ex(struct ibv_context *context,
			 struct ibv_cq_init_attr_ex *cq_attr,
			 struct ibv_cq_ex *cq,
			 struct ibv_create_cq_ex *cmd,
			 size_t cmd_core_size,
			 size_t cmd_size,
			 struct ibv_create_cq_resp_ex *resp,
			 size_t resp_core_size,
			 size_t resp_size)
{
	int err;

	memset(cmd, 0, cmd_core_size);
	IBV_INIT_CMD_RESP_EX_V(cmd, cmd_core_size, cmd_size, CREATE_CQ_EX, resp,
			       resp_core_size, resp_size);

	if (cq_attr->comp_mask & ~(IBV_CQ_INIT_ATTR_MASK_RESERVED - 1))
		return EINVAL;

	cmd->user_handle   = (uintptr_t)cq;
	cmd->cqe           = cq_attr->cqe;
	cmd->comp_vector   = cq_attr->comp_vector;
	cmd->comp_channel  = cq_attr->channel ? cq_attr->channel->fd : -1;
	cmd->comp_mask = 0;

	if (cmd_core_size >= offsetof(struct ibv_create_cq_ex, flags) +
	    sizeof(cmd->flags)) {
		if ((cq_attr->comp_mask & IBV_CQ_INIT_ATTR_MASK_FLAGS) &&
		    (cq_attr->flags & ~(IBV_CREATE_CQ_ATTR_RESERVED - 1)))
			return EOPNOTSUPP;

		if (cq_attr->wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP)
			cmd->flags |= IBV_CREATE_CQ_EX_KERNEL_FLAG_COMPLETION_TIMESTAMP;
	}

	err = write(context->cmd_fd, cmd, cmd_size);
	if (err != cmd_size)
		return errno;

	(void)VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	cq->handle  = resp->base.cq_handle;
	cq->cqe     = resp->base.cqe;
	cq->context = context;

	return 0;
}

int ibv_cmd_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	struct ibv_poll_cq       cmd;
	struct ibv_poll_cq_resp *resp;
	int                      i;
	int                      rsize;
	int                      ret;

	rsize = sizeof *resp + ne * sizeof(struct ibv_kern_wc);
	resp  = malloc(rsize);
	if (!resp)
		return -1;

	IBV_INIT_CMD_RESP(&cmd, sizeof cmd, POLL_CQ, resp, rsize);
	cmd.cq_handle = ibcq->handle;
	cmd.ne        = ne;

	if (write(ibcq->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd) {
		ret = -1;
		goto out;
	}

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, rsize);

	for (i = 0; i < resp->count; i++) {
		wc[i].wr_id 	     = resp->wc[i].wr_id;
		wc[i].status 	     = resp->wc[i].status;
		wc[i].opcode 	     = resp->wc[i].opcode;
		wc[i].vendor_err     = resp->wc[i].vendor_err;
		wc[i].byte_len 	     = resp->wc[i].byte_len;
		wc[i].imm_data 	     = resp->wc[i].imm_data;
		wc[i].qp_num 	     = resp->wc[i].qp_num;
		wc[i].src_qp 	     = resp->wc[i].src_qp;
		wc[i].wc_flags 	     = resp->wc[i].wc_flags;
		wc[i].pkey_index     = resp->wc[i].pkey_index;
		wc[i].slid 	     = resp->wc[i].slid;
		wc[i].sl 	     = resp->wc[i].sl;
		wc[i].dlid_path_bits = resp->wc[i].dlid_path_bits;
	}

	ret = resp->count;

out:
	free(resp);
	return ret;
}

int ibv_cmd_req_notify_cq(struct ibv_cq *ibcq, int solicited_only)
{
	struct ibv_req_notify_cq cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, REQ_NOTIFY_CQ);
	cmd.cq_handle = ibcq->handle;
	cmd.solicited = !!solicited_only;

	if (write(ibcq->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}

int ibv_cmd_resize_cq(struct ibv_cq *cq, int cqe,
		      struct ibv_resize_cq *cmd, size_t cmd_size,
		      struct ibv_resize_cq_resp *resp, size_t resp_size)
{
	IBV_INIT_CMD_RESP(cmd, cmd_size, RESIZE_CQ, resp, resp_size);
	cmd->cq_handle = cq->handle;
	cmd->cqe       = cqe;

	if (write(cq->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	cq->cqe = resp->cqe;

	return 0;
}

struct ibv_ioctl_cmd_destroy_cq {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[DESTROY_CQ_RESERVED];
} __attribute__((packed, aligned(4)));
/* handle, cqe, user_handle, comp_channel, comp_vector, <flags>, resp_cqe */

int ibv_cmd_destroy_cq(struct ibv_cq *cq)
{
	struct ibv_destroy_cq_resp resp;
	struct ibv_ioctl_cmd_destroy_cq cmd;
	struct ib_uverbs_attr *cattr = cmd.attrs;

	fill_attr_obj(cattr++, DESTROY_CQ_HANDLE, cq->handle);
	fill_attr_out(cattr++, DESTROY_CQ_RESP, sizeof(resp), &resp);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_CQ,
		       (void *)cattr - (void *)&cmd,
		       UVERBS_CQ_DESTROY, cattr - cmd.attrs);

	if (ioctl(cq->context->cmd_fd, RDMA_VERBS_IOCTL, &cmd))
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	pthread_mutex_lock(&cq->mutex);
	while (cq->comp_events_completed  != resp.comp_events_reported ||
	       cq->async_events_completed != resp.async_events_reported)
		pthread_cond_wait(&cq->cond, &cq->mutex);
	pthread_mutex_unlock(&cq->mutex);

	return 0;
}

int ibv_cmd_create_srq(struct ibv_pd *pd,
		       struct ibv_srq *srq, struct ibv_srq_init_attr *attr,
		       struct ibv_create_srq *cmd, size_t cmd_size,
		       struct ibv_create_srq_resp *resp, size_t resp_size)
{
	IBV_INIT_CMD_RESP(cmd, cmd_size, CREATE_SRQ, resp, resp_size);
	cmd->user_handle = (uintptr_t) srq;
	cmd->pd_handle 	 = pd->handle;
	cmd->max_wr      = attr->attr.max_wr;
	cmd->max_sge     = attr->attr.max_sge;
	cmd->srq_limit   = attr->attr.srq_limit;

	if (write(pd->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	srq->handle  = resp->srq_handle;
	srq->context = pd->context;

	if (abi_ver > 5) {
		attr->attr.max_wr = resp->max_wr;
		attr->attr.max_sge = resp->max_sge;
	} else {
		struct ibv_create_srq_resp_v5 *resp_v5 =
			(struct ibv_create_srq_resp_v5 *) resp;

		memmove((void *) resp + sizeof *resp,
			(void *) resp_v5 + sizeof *resp_v5,
			resp_size - sizeof *resp);
	}

	return 0;
}

int ibv_cmd_create_srq_ex(struct ibv_context *context,
			  struct verbs_srq *srq, int vsrq_sz,
			  struct ibv_srq_init_attr_ex *attr_ex,
			  struct ibv_create_xsrq *cmd, size_t cmd_size,
			  struct ibv_create_srq_resp *resp, size_t resp_size)
{
	struct verbs_xrcd *vxrcd = NULL;

	IBV_INIT_CMD_RESP(cmd, cmd_size, CREATE_XSRQ, resp, resp_size);

	if (attr_ex->comp_mask >= IBV_SRQ_INIT_ATTR_RESERVED)
		return ENOSYS;

	if (!(attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_PD))
		return EINVAL;

	cmd->user_handle = (uintptr_t) srq;
	cmd->pd_handle   = attr_ex->pd->handle;
	cmd->max_wr      = attr_ex->attr.max_wr;
	cmd->max_sge     = attr_ex->attr.max_sge;
	cmd->srq_limit   = attr_ex->attr.srq_limit;

	cmd->srq_type = (attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_TYPE) ?
			attr_ex->srq_type : IBV_SRQT_BASIC;
	if (attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_XRCD) {
		if (!(attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_CQ))
			return EINVAL;

		vxrcd = container_of(attr_ex->xrcd, struct verbs_xrcd, xrcd);
		cmd->xrcd_handle = vxrcd->handle;
		cmd->cq_handle   = attr_ex->cq->handle;
	}

	if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	srq->srq.handle           = resp->srq_handle;
	srq->srq.context          = context;
	srq->srq.srq_context      = attr_ex->srq_context;
	srq->srq.pd               = attr_ex->pd;
	srq->srq.events_completed = 0;
	pthread_mutex_init(&srq->srq.mutex, NULL);
	pthread_cond_init(&srq->srq.cond, NULL);

	/*
	 * check that the last field is available.
	 * If it is than all the others exist as well
	 */
	if (vext_field_avail(struct verbs_srq, srq_num, vsrq_sz)) {
		srq->comp_mask = IBV_SRQ_INIT_ATTR_TYPE;
		srq->srq_type = (attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_TYPE) ?
				attr_ex->srq_type : IBV_SRQT_BASIC;
		if (srq->srq_type == IBV_SRQT_XRC) {
			srq->comp_mask |= VERBS_SRQ_NUM;
			srq->srq_num = resp->srqn;
		}
		if (attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_XRCD) {
			srq->comp_mask |= VERBS_SRQ_XRCD;
			srq->xrcd = vxrcd;
		}
		if (attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_CQ) {
			srq->comp_mask |= VERBS_SRQ_CQ;
			srq->cq = attr_ex->cq;
		}
	}

	attr_ex->attr.max_wr = resp->max_wr;
	attr_ex->attr.max_sge = resp->max_sge;

	return 0;
}


static int ibv_cmd_modify_srq_v3(struct ibv_srq *srq,
				 struct ibv_srq_attr *srq_attr,
				 int srq_attr_mask,
				 struct ibv_modify_srq *new_cmd,
				 size_t new_cmd_size)
{
	struct ibv_modify_srq_v3 *cmd;
	size_t cmd_size;

	cmd_size = sizeof *cmd + new_cmd_size - sizeof *new_cmd;
	cmd      = alloca(cmd_size);
	memcpy(cmd->driver_data, new_cmd->driver_data, new_cmd_size - sizeof *new_cmd);

	IBV_INIT_CMD(cmd, cmd_size, MODIFY_SRQ);

	cmd->srq_handle	= srq->handle;
	cmd->attr_mask	= srq_attr_mask;
	cmd->max_wr	= srq_attr->max_wr;
	cmd->srq_limit	= srq_attr->srq_limit;
	cmd->max_sge	= 0;
	cmd->reserved	= 0;

	if (write(srq->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	return 0;
}

int ibv_cmd_modify_srq(struct ibv_srq *srq,
		       struct ibv_srq_attr *srq_attr,
		       int srq_attr_mask,
		       struct ibv_modify_srq *cmd, size_t cmd_size)
{
	if (abi_ver == 3)
		return ibv_cmd_modify_srq_v3(srq, srq_attr, srq_attr_mask,
					     cmd, cmd_size);

	IBV_INIT_CMD(cmd, cmd_size, MODIFY_SRQ);

	cmd->srq_handle	= srq->handle;
	cmd->attr_mask	= srq_attr_mask;
	cmd->max_wr	= srq_attr->max_wr;
	cmd->srq_limit	= srq_attr->srq_limit;

	if (write(srq->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	return 0;
}

int ibv_cmd_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr,
		      struct ibv_query_srq *cmd, size_t cmd_size)
{
	struct ibv_query_srq_resp resp;

	IBV_INIT_CMD_RESP(cmd, cmd_size, QUERY_SRQ, &resp, sizeof resp);
	cmd->srq_handle = srq->handle;
	cmd->reserved   = 0;

	if (write(srq->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	srq_attr->max_wr    = resp.max_wr;
	srq_attr->max_sge   = resp.max_sge;
	srq_attr->srq_limit = resp.srq_limit;

	return 0;
}

int ibv_cmd_destroy_srq(struct ibv_srq *srq)
{
	struct ibv_destroy_srq      cmd;
	struct ibv_destroy_srq_resp resp;

	IBV_INIT_CMD_RESP(&cmd, sizeof cmd, DESTROY_SRQ, &resp, sizeof resp);
	cmd.srq_handle = srq->handle;
	cmd.reserved   = 0;

	if (write(srq->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	pthread_mutex_lock(&srq->mutex);
	while (srq->events_completed != resp.events_reported)
		pthread_cond_wait(&srq->cond, &srq->mutex);
	pthread_mutex_unlock(&srq->mutex);

	return 0;
}

static void create_qp_ioctl_handle_resp_common(struct ibv_context *context,
					       struct verbs_qp *qp,
					       struct ibv_qp_init_attr_ex *qp_attr,
					       struct ib_uverbs_ioctl_create_qp_resp *resp,
					       uint64_t qp_handle,
					       struct verbs_xrcd *vxrcd,
					       int vqp_sz)
{
	qp_attr->cap.max_recv_sge    = resp->max_recv_sge;
	qp_attr->cap.max_send_sge    = resp->max_send_sge;
	qp_attr->cap.max_recv_wr     = resp->max_recv_wr;
	qp_attr->cap.max_send_wr     = resp->max_send_wr;
	qp_attr->cap.max_inline_data = resp->max_inline_data;

	qp->qp.handle		= qp_handle;
	qp->qp.qp_num		= resp->qpn;
	qp->qp.context		= context;
	qp->qp.qp_context	= qp_attr->qp_context;
	qp->qp.pd		= qp_attr->pd;
	qp->qp.send_cq		= qp_attr->send_cq;
	qp->qp.recv_cq		= qp_attr->recv_cq;
	qp->qp.srq		= qp_attr->srq;
	qp->qp.qp_type		= qp_attr->qp_type;
	qp->qp.state		= IBV_QPS_RESET;
	qp->qp.events_completed = 0;
	pthread_mutex_init(&qp->qp.mutex, NULL);
	pthread_cond_init(&qp->qp.cond, NULL);

	qp->comp_mask = 0;
	if (vext_field_avail(struct verbs_qp, xrcd, vqp_sz) &&
	    (qp_attr->comp_mask & IBV_QP_INIT_ATTR_XRCD)) {
		qp->comp_mask |= VERBS_QP_XRCD;
		qp->xrcd = vxrcd;
	}
}

enum {
	CREATE_QP_EX2_SUP_CREATE_FLAGS = IBV_QP_CREATE_BLOCK_SELF_MCAST_LB |
		IBV_QP_CREATE_SCATTER_FCS,
};

struct ibv_ioctl_cmd_create_qp {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[CREATE_QP_RESERVED + UVERBS_UHW_SZ];
} __attribute__((packed, aligned(4)));
/* handle, cqe, user_handle, comp_channel, comp_vector, <flags>, resp_cqe */

static int create_qp_ioctl_common(struct ibv_qp_init_attr_ex *qp_attr,
				  struct verbs_xrcd *vxrcd,
				  struct ib_uverbs_attr *attrs,
				  struct ib_uverbs_ioctl_create_qp *cmd,
				  struct ib_uverbs_ioctl_create_qp_resp *resp)
{
	struct ib_uverbs_attr *attr = attrs;

	fill_attr_obj(attr++, CREATE_QP_HANDLE, 0);

	if (qp_attr->comp_mask & IBV_QP_INIT_ATTR_XRCD) {
		vxrcd = container_of(qp_attr->xrcd, struct verbs_xrcd, xrcd);
		fill_attr_obj(attr++, CREATE_QP_PD_HANDLE,
			      (uintptr_t)vxrcd->handle);
	} else {
		if (!(qp_attr->comp_mask & IBV_QP_INIT_ATTR_PD))
			return -EINVAL;

		fill_attr_obj(attr++, CREATE_QP_PD_HANDLE,
			      qp_attr->pd->handle);
		fill_attr_obj(attr++, CREATE_QP_SEND_CQ,
			      qp_attr->send_cq->handle);

		if (qp_attr->qp_type != IBV_QPT_XRC_SEND) {
			fill_attr_obj(attr++, CREATE_QP_RECV_CQ,
				      qp_attr->recv_cq->handle);
			if (qp_attr->srq) {
				fill_attr_obj(attr++, CREATE_QP_SRQ,
					      qp_attr->srq->handle);
			}
		}
	}

	cmd->max_send_wr     = qp_attr->cap.max_send_wr;
	cmd->max_recv_wr     = qp_attr->cap.max_recv_wr;
	cmd->max_send_sge    = qp_attr->cap.max_send_sge;
	cmd->max_recv_sge    = qp_attr->cap.max_recv_sge;
	cmd->max_inline_data = qp_attr->cap.max_inline_data;
	cmd->sq_sig_all	     = qp_attr->sq_sig_all;
	cmd->qp_type         = qp_attr->qp_type;
	fill_attr_in(attr++, CREATE_QP_CMD, sizeof(*cmd), cmd);

	fill_attr_out(attr++, CREATE_QP_RESP, sizeof(*resp), resp);

	return attr - attrs;
}

int ibv_cmd_create_qp_ex2(struct ibv_context *context,
			  struct verbs_qp *qp, int vqp_sz,
			  struct ibv_qp_init_attr_ex *qp_attr,
			  struct ibv_create_qp_ex *legacy_cmd,
			  size_t cmd_core_size,
			  size_t cmd_size,
			  struct ibv_create_qp_resp_ex *legacy_resp,
			  size_t resp_core_size,
			  size_t resp_size)
{
	struct verbs_xrcd *vxrcd = NULL;
	struct ib_uverbs_ioctl_create_qp qp_cmd;
	struct ibv_ioctl_cmd_create_qp cmd;
	struct ib_uverbs_ioctl_create_qp_resp resp;
	struct ib_uverbs_attr *attr;
	uintptr_t qp_handle = (uintptr_t)qp;
	int ret;

	/* CURRENTLY - THIS DOESN'T HANDLE XRC_TGT */

	if (qp_attr->comp_mask >= IBV_QP_INIT_ATTR_RESERVED)
		return EINVAL;

	if (resp_core_size <
	    offsetof(struct ibv_create_qp_resp_ex, response_length) +
	    sizeof(legacy_resp->response_length))
		return EINVAL;

	ret = create_qp_ioctl_common(qp_attr, vxrcd, cmd.attrs, &qp_cmd,
				     &resp);
	if (ret < 0)
		return ret;
	attr = cmd.attrs + ret;

	fill_attr_in(attr++, CREATE_QP_USER_HANDLE, sizeof(__u64), &qp_handle);

	if (qp_attr->comp_mask & IBV_QP_INIT_ATTR_CREATE_FLAGS) {
		if (qp_attr->create_flags & ~CREATE_QP_EX2_SUP_CREATE_FLAGS)
			return EINVAL;
		if (cmd_core_size < offsetof(struct ibv_create_qp_ex, create_flags) +
		    sizeof(qp_attr->create_flags))
			return EINVAL;
		fill_attr_in(attr++, CREATE_QP_CMD_FLAGS,
			  sizeof(qp_attr->create_flags),
			  &qp_attr->create_flags);
	}

	if (cmd_size - sizeof(struct ibv_create_qp))
		fill_attr_in(attr++, UVERBS_UHW_IN,
			  cmd_size - sizeof(struct ibv_create_qp), legacy_cmd + 1);
	if (resp_size - sizeof(struct ibv_create_qp_resp))
		fill_attr_out(attr++, UVERBS_UHW_OUT,
			      resp_size - sizeof(struct ibv_create_qp_resp), legacy_resp + 1);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_QP, (void *)attr - (void *)&cmd,
		       UVERBS_QP_CREATE, attr - cmd.attrs);
	ret = ioctl(context->cmd_fd, RDMA_VERBS_IOCTL, &cmd);
	if (ret)
		return errno;

	(void)VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	create_qp_ioctl_handle_resp_common(context, qp, qp_attr,
					   &resp,
					   cmd.attrs[0].data,
					   vxrcd,
					   vqp_sz);

	return 0;
}

int ibv_cmd_create_qp_ex(struct ibv_context *context,
			 struct verbs_qp *qp, int vqp_sz,
			 struct ibv_qp_init_attr_ex *attr_ex,
			 struct ibv_create_qp *legacy_cmd, size_t cmd_size,
			 struct ibv_create_qp_resp *legacy_resp, size_t resp_size)
{
	struct verbs_xrcd *vxrcd = NULL;
	struct ib_uverbs_ioctl_create_qp qp_cmd;
	struct ibv_ioctl_cmd_create_qp cmd;
	struct ib_uverbs_ioctl_create_qp_resp resp;
	struct ib_uverbs_attr *attr;
	uintptr_t qp_handle = (uintptr_t)qp;
	size_t legacy_resp_sz = (abi_ver == 4) ?
		sizeof(struct ibv_create_qp_resp_v4) :
		sizeof(struct ibv_create_qp_resp_v3);
	int err;

	if (attr_ex->comp_mask > (IBV_QP_INIT_ATTR_XRCD | IBV_QP_INIT_ATTR_PD))
		return ENOSYS;

	/* CURRENTLY - THIS DOESN'T HANDLE XRC_TGT */
	err = create_qp_ioctl_common(attr_ex, vxrcd, cmd.attrs, &qp_cmd,
				     &resp);
	if (err < 0)
		return err;
	attr = cmd.attrs + err;

	fill_attr_in(attr++, CREATE_QP_USER_HANDLE, sizeof(__u64), &qp_handle);
	if (cmd_size - sizeof(struct ibv_create_qp))
		fill_attr_in(attr++, UVERBS_UHW_IN,
			  cmd_size - sizeof(struct ibv_create_qp), legacy_cmd + 1);
	if (resp_size - legacy_resp_sz)
		fill_attr_out(attr++, UVERBS_UHW_OUT,
			      resp_size - legacy_resp_sz, legacy_resp + 1);

	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_QP, (void *)attr - (void *)&cmd,
		       UVERBS_QP_CREATE, attr - cmd.attrs);
	err = ioctl(context->cmd_fd, RDMA_VERBS_IOCTL, &cmd);
	if (err)
		return errno;

	create_qp_ioctl_handle_resp_common(context, qp, attr_ex,
					   &resp,
					   cmd.attrs[0].data,
					   vxrcd,
					   vqp_sz);

	return 0;
}

int ibv_cmd_create_qp(struct ibv_pd *pd,
		      struct ibv_qp *qp, struct ibv_qp_init_attr *attr,
		      struct ibv_create_qp *cmd, size_t cmd_size,
		      struct ibv_create_qp_resp *resp, size_t resp_size)
{
	IBV_INIT_CMD_RESP(cmd, cmd_size, CREATE_QP, resp, resp_size);

	cmd->user_handle     = (uintptr_t) qp;
	cmd->pd_handle       = pd->handle;
	cmd->send_cq_handle  = attr->send_cq->handle;
	cmd->recv_cq_handle  = attr->recv_cq->handle;
	cmd->srq_handle      = attr->srq ? attr->srq->handle : 0;
	cmd->max_send_wr     = attr->cap.max_send_wr;
	cmd->max_recv_wr     = attr->cap.max_recv_wr;
	cmd->max_send_sge    = attr->cap.max_send_sge;
	cmd->max_recv_sge    = attr->cap.max_recv_sge;
	cmd->max_inline_data = attr->cap.max_inline_data;
	cmd->sq_sig_all	     = attr->sq_sig_all;
	cmd->qp_type 	     = attr->qp_type;
	cmd->is_srq 	     = !!attr->srq;
	cmd->reserved	     = 0;

	if (write(pd->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	qp->handle 		  = resp->qp_handle;
	qp->qp_num 		  = resp->qpn;
	qp->context		  = pd->context;

	if (abi_ver > 3) {
		attr->cap.max_recv_sge    = resp->max_recv_sge;
		attr->cap.max_send_sge    = resp->max_send_sge;
		attr->cap.max_recv_wr     = resp->max_recv_wr;
		attr->cap.max_send_wr     = resp->max_send_wr;
		attr->cap.max_inline_data = resp->max_inline_data;
	}

	if (abi_ver == 4) {
		struct ibv_create_qp_resp_v4 *resp_v4 =
			(struct ibv_create_qp_resp_v4 *) resp;

		memmove((void *) resp + sizeof *resp,
			(void *) resp_v4 + sizeof *resp_v4,
			resp_size - sizeof *resp);
	} else if (abi_ver <= 3) {
		struct ibv_create_qp_resp_v3 *resp_v3 =
			(struct ibv_create_qp_resp_v3 *) resp;

		memmove((void *) resp + sizeof *resp,
			(void *) resp_v3 + sizeof *resp_v3,
			resp_size - sizeof *resp);
	}

	return 0;
}

int ibv_cmd_open_qp(struct ibv_context *context, struct verbs_qp *qp,
		    int vqp_sz,
		    struct ibv_qp_open_attr *attr,
		    struct ibv_open_qp *cmd, size_t cmd_size,
		    struct ibv_create_qp_resp *resp, size_t resp_size)
{
	struct verbs_xrcd *xrcd;
	IBV_INIT_CMD_RESP(cmd, cmd_size, OPEN_QP, resp, resp_size);

	if (attr->comp_mask >= IBV_QP_OPEN_ATTR_RESERVED)
		return ENOSYS;

	if (!(attr->comp_mask & IBV_QP_OPEN_ATTR_XRCD) ||
	    !(attr->comp_mask & IBV_QP_OPEN_ATTR_NUM) ||
	    !(attr->comp_mask & IBV_QP_OPEN_ATTR_TYPE))
		return EINVAL;

	xrcd = container_of(attr->xrcd, struct verbs_xrcd, xrcd);
	cmd->user_handle = (uintptr_t) qp;
	cmd->pd_handle   = xrcd->handle;
	cmd->qpn         = attr->qp_num;
	cmd->qp_type     = attr->qp_type;

	if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	qp->qp.handle     = resp->qp_handle;
	qp->qp.context    = context;
	qp->qp.qp_context = attr->qp_context;
	qp->qp.pd	  = NULL;
	qp->qp.send_cq	  = NULL;
	qp->qp.recv_cq    = NULL;
	qp->qp.srq	  = NULL;
	qp->qp.qp_num	  = attr->qp_num;
	qp->qp.qp_type	  = attr->qp_type;
	qp->qp.state	  = IBV_QPS_UNKNOWN;
	qp->qp.events_completed = 0;
	pthread_mutex_init(&qp->qp.mutex, NULL);
	pthread_cond_init(&qp->qp.cond, NULL);
	qp->comp_mask = 0;
	if (vext_field_avail(struct verbs_qp, xrcd, vqp_sz)) {
		qp->comp_mask = VERBS_QP_XRCD;
		qp->xrcd	 = xrcd;
	}

	return 0;
}

struct ibv_ioctl_cmd_query_qp {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[QUERY_QP_RESERVED];
} __attribute__((packed, aligned(4)));

int ibv_cmd_query_qp(struct ibv_qp *qp, 
		     struct ibv_qp_attr *attr,
		     int attr_mask,
		     struct ibv_qp_init_attr *init_attr,
		     struct ibv_query_qp *cmd, size_t cmd_size)
{
	struct ibv_ioctl_cmd_query_qp iocmd;
	struct ib_uverbs_attr         *cattr = iocmd.attrs;
	struct ibv_query_qp_resp resp;
	int ret;

	fill_attr_obj(cattr++, QUERY_QP_HANDLE, qp->handle);
	fill_attr_in(cattr++, QUERY_QP_ATTR_MASK, sizeof(__u32), &attr_mask);
	fill_attr_out(cattr++, QUERY_QP_RESP, sizeof(resp), &resp);

	fill_ioctl_hdr(&iocmd.hdr, UVERBS_TYPE_QP, (void *)cattr - (void *)&iocmd,
		       UVERBS_QP_QUERY, cattr - iocmd.attrs);

	ret = ioctl(qp->context->cmd_fd, RDMA_VERBS_IOCTL, &iocmd);
	if (ret)
		return errno;

	attr->qkey                          = resp.qkey;
	attr->rq_psn                        = resp.rq_psn;
	attr->sq_psn                        = resp.sq_psn;
	attr->dest_qp_num                   = resp.dest_qp_num;
	attr->qp_access_flags               = resp.qp_access_flags;
	attr->pkey_index                    = resp.pkey_index;
	attr->alt_pkey_index                = resp.alt_pkey_index;
	attr->qp_state                      = resp.qp_state;
	attr->cur_qp_state                  = resp.cur_qp_state;
	attr->path_mtu                      = resp.path_mtu;
	attr->path_mig_state                = resp.path_mig_state;
	attr->sq_draining                   = resp.sq_draining;
	attr->max_rd_atomic                 = resp.max_rd_atomic;
	attr->max_dest_rd_atomic            = resp.max_dest_rd_atomic;
	attr->min_rnr_timer                 = resp.min_rnr_timer;
	attr->port_num                      = resp.port_num;
	attr->timeout                       = resp.timeout;
	attr->retry_cnt                     = resp.retry_cnt;
	attr->rnr_retry                     = resp.rnr_retry;
	attr->alt_port_num                  = resp.alt_port_num;
	attr->alt_timeout                   = resp.alt_timeout;
	attr->cap.max_send_wr               = resp.max_send_wr;
	attr->cap.max_recv_wr               = resp.max_recv_wr;
	attr->cap.max_send_sge              = resp.max_send_sge;
	attr->cap.max_recv_sge              = resp.max_recv_sge;
	attr->cap.max_inline_data           = resp.max_inline_data;

	memcpy(attr->ah_attr.grh.dgid.raw, resp.dest.dgid, 16);
	attr->ah_attr.grh.flow_label        = resp.dest.flow_label;
	attr->ah_attr.dlid                  = resp.dest.dlid;
	attr->ah_attr.grh.sgid_index        = resp.dest.sgid_index;
	attr->ah_attr.grh.hop_limit         = resp.dest.hop_limit;
	attr->ah_attr.grh.traffic_class     = resp.dest.traffic_class;
	attr->ah_attr.sl                    = resp.dest.sl;
	attr->ah_attr.src_path_bits         = resp.dest.src_path_bits;
	attr->ah_attr.static_rate           = resp.dest.static_rate;
	attr->ah_attr.is_global             = resp.dest.is_global;
	attr->ah_attr.port_num              = resp.dest.port_num;

	memcpy(attr->alt_ah_attr.grh.dgid.raw, resp.alt_dest.dgid, 16);
	attr->alt_ah_attr.grh.flow_label    = resp.alt_dest.flow_label;
	attr->alt_ah_attr.dlid              = resp.alt_dest.dlid;
	attr->alt_ah_attr.grh.sgid_index    = resp.alt_dest.sgid_index;
	attr->alt_ah_attr.grh.hop_limit     = resp.alt_dest.hop_limit;
	attr->alt_ah_attr.grh.traffic_class = resp.alt_dest.traffic_class;
	attr->alt_ah_attr.sl                = resp.alt_dest.sl;
	attr->alt_ah_attr.src_path_bits     = resp.alt_dest.src_path_bits;
	attr->alt_ah_attr.static_rate       = resp.alt_dest.static_rate;
	attr->alt_ah_attr.is_global         = resp.alt_dest.is_global;
	attr->alt_ah_attr.port_num          = resp.alt_dest.port_num;

	init_attr->qp_context               = qp->qp_context;
	init_attr->send_cq                  = qp->send_cq;
	init_attr->recv_cq                  = qp->recv_cq;
	init_attr->srq                      = qp->srq;
	init_attr->qp_type                  = qp->qp_type;
	init_attr->cap.max_send_wr          = resp.max_send_wr;
	init_attr->cap.max_recv_wr          = resp.max_recv_wr;
	init_attr->cap.max_send_sge         = resp.max_send_sge;
	init_attr->cap.max_recv_sge         = resp.max_recv_sge;
	init_attr->cap.max_inline_data      = resp.max_inline_data;
	init_attr->sq_sig_all               = resp.sq_sig_all;

	return 0;

}

struct ibv_ioctl_cmd_modify_qp {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[MODIFY_QP_RESERVED];
} __attribute__((packed, aligned(4)));
/* handle, cqe, user_handle, comp_channel, comp_vector, <flags>, resp_cqe */

int ibv_cmd_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		      int attr_mask,
		      struct ibv_modify_qp *legacy_cmd, size_t cmd_size)
{
	struct ibv_qp_dest av;
	struct ib_uverbs_qp_alt_path alt_path;
	struct ibv_ioctl_cmd_modify_qp cmd;
	struct ib_uverbs_attr *cattr = cmd.attrs;
	int ret;

	fill_attr_obj(cattr++, MODIFY_QP_HANDLE, qp->handle);
	if (attr_mask & IBV_QP_QKEY)
		fill_attr_in(cattr++, MODIFY_QP_QKEY, sizeof(__u32), &attr->qkey);
	if (attr_mask & IBV_QP_RQ_PSN)
		fill_attr_in(cattr++, MODIFY_QP_RQ_PSN, sizeof(__u32),
			  &attr->rq_psn);
	if (attr_mask & IBV_QP_SQ_PSN)
		fill_attr_in(cattr++, MODIFY_QP_SQ_PSN, sizeof(__u32),
			  &attr->sq_psn);
	if (attr_mask & IBV_QP_DEST_QPN)
		fill_attr_in(cattr++, MODIFY_QP_DEST_QPN, sizeof(__u32),
			  &attr->dest_qp_num);
	if (attr_mask & IBV_QP_ACCESS_FLAGS)
		fill_attr_in(cattr++, MODIFY_QP_ACCESS_FLAGS, sizeof(__u32),
			  &attr->qp_access_flags);
	if (attr_mask & IBV_QP_PKEY_INDEX)
		fill_attr_in(cattr++, MODIFY_QP_PKEY_INDEX, sizeof(__u16),
			  &attr->pkey_index);
	if (attr_mask & IBV_QP_STATE)
		fill_attr_in(cattr++, MODIFY_QP_STATE, sizeof(__u8),
			  &attr->qp_state);
	if (attr_mask & IBV_QP_CUR_STATE)
		fill_attr_in(cattr++, MODIFY_QP_CUR_STATE, sizeof(__u8),
			  &attr->cur_qp_state);
	if (attr_mask & IBV_QP_PATH_MTU)
		fill_attr_in(cattr++, MODIFY_QP_PATH_MTU, sizeof(__u8),
			  &attr->path_mtu);
	if (attr_mask & IBV_QP_PATH_MIG_STATE)
		fill_attr_in(cattr++, MODIFY_QP_PATH_MIG_STATE, sizeof(__u8),
			  &attr->path_mig_state);
	if (attr_mask & IBV_QP_EN_SQD_ASYNC_NOTIFY)
		fill_attr_in(cattr++, MODIFY_QP_EN_SQD_ASYNC_NOTIFY, sizeof(__u8),
			  &attr->en_sqd_async_notify);
	if (attr_mask & IBV_QP_MAX_QP_RD_ATOMIC)
		fill_attr_in(cattr++, MODIFY_QP_MAX_RD_ATOMIC, sizeof(__u8),
			  &attr->max_rd_atomic);
	if (attr_mask & IBV_QP_MAX_DEST_RD_ATOMIC)
		fill_attr_in(cattr++, MODIFY_QP_MAX_DEST_RD_ATOMIC, sizeof(__u8),
			  &attr->max_dest_rd_atomic);
	if (attr_mask & IBV_QP_MIN_RNR_TIMER)
		fill_attr_in(cattr++, MODIFY_QP_MIN_RNR_TIMER, sizeof(__u8),
			  &attr->min_rnr_timer);
	if (attr_mask & IBV_QP_PORT)
		fill_attr_in(cattr++, MODIFY_QP_PORT, sizeof(__u8),
			  &attr->port_num);
	if (attr_mask & IBV_QP_TIMEOUT)
		fill_attr_in(cattr++, MODIFY_QP_TIMEOUT, sizeof(__u8),
			  &attr->timeout);
	if (attr_mask & IBV_QP_RETRY_CNT)
		fill_attr_in(cattr++, MODIFY_QP_RETRY_CNT, sizeof(__u8),
			  &attr->retry_cnt);
	if (attr_mask & IBV_QP_RNR_RETRY)
		fill_attr_in(cattr++, MODIFY_QP_RNR_RETRY, sizeof(__u8),
			  &attr->rnr_retry);

	if (attr_mask & IBV_QP_AV) {
		memcpy(av.dgid, attr->ah_attr.grh.dgid.raw, 16);
		av.flow_label	    = attr->ah_attr.grh.flow_label;
		av.dlid		    = attr->ah_attr.dlid;
		av.reserved	    = 0;
		av.sgid_index	    = attr->ah_attr.grh.sgid_index;
		av.hop_limit	    = attr->ah_attr.grh.hop_limit;
		av.traffic_class     = attr->ah_attr.grh.traffic_class;
		av.sl		    = attr->ah_attr.sl;
		av.src_path_bits     = attr->ah_attr.src_path_bits;
		av.static_rate	    = attr->ah_attr.static_rate;
		av.is_global	    = attr->ah_attr.is_global;
		av.port_num	    = attr->ah_attr.port_num;
		fill_attr_in(cattr++, MODIFY_QP_AV, sizeof(av), &av);
	}

	if (attr_mask & IBV_QP_ALT_PATH) {
		memcpy(alt_path.dest.dgid, attr->alt_ah_attr.grh.dgid.raw, 16);
		alt_path.dest.flow_label    = attr->alt_ah_attr.grh.flow_label;
		alt_path.dest.dlid	    = attr->alt_ah_attr.dlid;
		alt_path.dest.reserved	    = 0;
		alt_path.dest.sgid_index    = attr->alt_ah_attr.grh.sgid_index;
		alt_path.dest.hop_limit     = attr->alt_ah_attr.grh.hop_limit;
		alt_path.dest.traffic_class = attr->alt_ah_attr.grh.traffic_class;
		alt_path.dest.sl	    = attr->alt_ah_attr.sl;
		alt_path.dest.src_path_bits = attr->alt_ah_attr.src_path_bits;
		alt_path.dest.static_rate   = attr->alt_ah_attr.static_rate;
		alt_path.dest.is_global     = attr->alt_ah_attr.is_global;
		alt_path.dest.port_num	    = attr->alt_ah_attr.port_num;
		alt_path.pkey_index	 = attr->alt_pkey_index;
		alt_path.port_num	 = attr->alt_port_num;
		alt_path.timeout	 = attr->alt_timeout;
		fill_attr_in(cattr++, MODIFY_QP_ALT_PATH, sizeof(alt_path),
			  &alt_path);
	}

	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_QP, (void *)cattr - (void *)&cmd,
		       UVERBS_QP_MODIFY, cattr - cmd.attrs);

	ret = ioctl(qp->context->cmd_fd, RDMA_VERBS_IOCTL, &cmd);
	if (ret)
		return errno;

	return 0;
}

int ibv_cmd_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad_wr)
{
	struct ibv_post_send     *cmd;
	struct ibv_post_send_resp resp;
	struct ibv_send_wr       *i;
	struct ibv_kern_send_wr  *n, *tmp;
	struct ibv_sge           *s;
	unsigned                  wr_count = 0;
	unsigned                  sge_count = 0;
	int                       cmd_size;
	int                       ret = 0;

	for (i = wr; i; i = i->next) {
		wr_count++;
		sge_count += i->num_sge;
	}

	cmd_size = sizeof *cmd + wr_count * sizeof *n + sge_count * sizeof *s;
	cmd  = alloca(cmd_size);

	IBV_INIT_CMD_RESP(cmd, cmd_size, POST_SEND, &resp, sizeof resp);
	cmd->qp_handle = ibqp->handle;
	cmd->wr_count  = wr_count;
	cmd->sge_count = sge_count;
	cmd->wqe_size  = sizeof *n;

	n = (struct ibv_kern_send_wr *) ((void *) cmd + sizeof *cmd);
	s = (struct ibv_sge *) (n + wr_count);

	tmp = n;
	for (i = wr; i; i = i->next) {
		tmp->wr_id 	= i->wr_id;
		tmp->num_sge 	= i->num_sge;
		tmp->opcode 	= i->opcode;
		tmp->send_flags = i->send_flags;
		tmp->imm_data 	= i->imm_data;
		if (ibqp->qp_type == IBV_QPT_UD) {
			tmp->wr.ud.ah 	       = i->wr.ud.ah->handle;
			tmp->wr.ud.remote_qpn  = i->wr.ud.remote_qpn;
			tmp->wr.ud.remote_qkey = i->wr.ud.remote_qkey;
		} else {
			switch (i->opcode) {
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
			case IBV_WR_RDMA_READ:
				tmp->wr.rdma.remote_addr =
					i->wr.rdma.remote_addr;
				tmp->wr.rdma.rkey = i->wr.rdma.rkey;
				break;
			case IBV_WR_ATOMIC_CMP_AND_SWP:
			case IBV_WR_ATOMIC_FETCH_AND_ADD:
				tmp->wr.atomic.remote_addr =
					i->wr.atomic.remote_addr;
				tmp->wr.atomic.compare_add =
					i->wr.atomic.compare_add;
				tmp->wr.atomic.swap = i->wr.atomic.swap;
				tmp->wr.atomic.rkey = i->wr.atomic.rkey;
				break;
			default:
				break;
			}
		}

		if (tmp->num_sge) {
			memcpy(s, i->sg_list, tmp->num_sge * sizeof *s);
			s += tmp->num_sge;
		}

		tmp++;
	}

	resp.bad_wr = 0;
	if (write(ibqp->context->cmd_fd, cmd, cmd_size) != cmd_size)
		ret = errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	wr_count = resp.bad_wr;
	if (wr_count) {
		i = wr;
		while (--wr_count)
			i = i->next;
		*bad_wr = i;
	} else if (ret)
		*bad_wr = wr;

	return ret;
}

int ibv_cmd_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	struct ibv_post_recv     *cmd;
	struct ibv_post_recv_resp resp;
	struct ibv_recv_wr       *i;
	struct ibv_kern_recv_wr  *n, *tmp;
	struct ibv_sge           *s;
	unsigned                  wr_count = 0;
	unsigned                  sge_count = 0;
	int                       cmd_size;
	int                       ret = 0;

	for (i = wr; i; i = i->next) {
		wr_count++;
		sge_count += i->num_sge;
	}

	cmd_size = sizeof *cmd + wr_count * sizeof *n + sge_count * sizeof *s;
	cmd  = alloca(cmd_size);

	IBV_INIT_CMD_RESP(cmd, cmd_size, POST_RECV, &resp, sizeof resp);
	cmd->qp_handle = ibqp->handle;
	cmd->wr_count  = wr_count;
	cmd->sge_count = sge_count;
	cmd->wqe_size  = sizeof *n;

	n = (struct ibv_kern_recv_wr *) ((void *) cmd + sizeof *cmd);
	s = (struct ibv_sge *) (n + wr_count);

	tmp = n;
	for (i = wr; i; i = i->next) {
		tmp->wr_id   = i->wr_id;
		tmp->num_sge = i->num_sge;

		if (tmp->num_sge) {
			memcpy(s, i->sg_list, tmp->num_sge * sizeof *s);
			s += tmp->num_sge;
		}

		tmp++;
	}

	resp.bad_wr = 0;
	if (write(ibqp->context->cmd_fd, cmd, cmd_size) != cmd_size)
		ret = errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	wr_count = resp.bad_wr;
	if (wr_count) {
		i = wr;
		while (--wr_count)
			i = i->next;
		*bad_wr = i;
	} else if (ret)
		*bad_wr = wr;

	return ret;
}

int ibv_cmd_post_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	struct ibv_post_srq_recv *cmd;
	struct ibv_post_srq_recv_resp resp;
	struct ibv_recv_wr       *i;
	struct ibv_kern_recv_wr  *n, *tmp;
	struct ibv_sge           *s;
	unsigned                  wr_count = 0;
	unsigned                  sge_count = 0;
	int                       cmd_size;
	int                       ret = 0;

	for (i = wr; i; i = i->next) {
		wr_count++;
		sge_count += i->num_sge;
	}

	cmd_size = sizeof *cmd + wr_count * sizeof *n + sge_count * sizeof *s;
	cmd  = alloca(cmd_size);

	IBV_INIT_CMD_RESP(cmd, cmd_size, POST_SRQ_RECV, &resp, sizeof resp);
	cmd->srq_handle = srq->handle;
	cmd->wr_count  = wr_count;
	cmd->sge_count = sge_count;
	cmd->wqe_size  = sizeof *n;

	n = (struct ibv_kern_recv_wr *) ((void *) cmd + sizeof *cmd);
	s = (struct ibv_sge *) (n + wr_count);

	tmp = n;
	for (i = wr; i; i = i->next) {
		tmp->wr_id = i->wr_id;
		tmp->num_sge = i->num_sge;

		if (tmp->num_sge) {
			memcpy(s, i->sg_list, tmp->num_sge * sizeof *s);
			s += tmp->num_sge;
		}

		tmp++;
	}

	resp.bad_wr = 0;
	if (write(srq->context->cmd_fd, cmd, cmd_size) != cmd_size)
		ret = errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	wr_count = resp.bad_wr;
	if (wr_count) {
		i = wr;
		while (--wr_count)
			i = i->next;
		*bad_wr = i;
	} else if (ret)
		*bad_wr = wr;

	return ret;
}

int ibv_cmd_create_ah(struct ibv_pd *pd, struct ibv_ah *ah,
		      struct ibv_ah_attr *attr)
{
	struct ibv_create_ah      cmd;
	struct ibv_create_ah_resp resp;

	IBV_INIT_CMD_RESP(&cmd, sizeof cmd, CREATE_AH, &resp, sizeof resp);
	cmd.user_handle            = (uintptr_t) ah;
	cmd.pd_handle              = pd->handle;
	cmd.attr.dlid              = attr->dlid;
	cmd.attr.sl                = attr->sl;
	cmd.attr.src_path_bits     = attr->src_path_bits;
	cmd.attr.static_rate       = attr->static_rate;
	cmd.attr.is_global         = attr->is_global;
	cmd.attr.port_num          = attr->port_num;
	cmd.attr.grh.flow_label    = attr->grh.flow_label;
	cmd.attr.grh.sgid_index    = attr->grh.sgid_index;
	cmd.attr.grh.hop_limit     = attr->grh.hop_limit;
	cmd.attr.grh.traffic_class = attr->grh.traffic_class;
	memcpy(cmd.attr.grh.dgid, attr->grh.dgid.raw, 16);

	if (write(pd->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	ah->handle  = resp.handle;
	ah->context = pd->context;

	return 0;
}

int ibv_cmd_destroy_ah(struct ibv_ah *ah)
{
	struct ibv_destroy_ah cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, DESTROY_AH);
	cmd.ah_handle = ah->handle;

	if (write(ah->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}

struct ibv_ioctl_cmd_destroy_qp {
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_uverbs_attr attrs[DESTROY_QP_RESERVED];
} __attribute__((packed, aligned(4)));
int ibv_cmd_destroy_qp(struct ibv_qp *qp)
{
	__u32 events_reported;
	struct ibv_ioctl_cmd_destroy_qp cmd;
	struct ib_uverbs_attr *cattr = cmd.attrs;

	fill_attr_obj(cattr++, DESTROY_QP_HANDLE, qp->handle);
	fill_attr_out(cattr++, DESTROY_QP_EVENTS_REPORTED,
		      sizeof(events_reported), &events_reported);
	fill_ioctl_hdr(&cmd.hdr, UVERBS_TYPE_QP,
		       (void *)cattr - (void *)&cmd,
		       UVERBS_QP_DESTROY, cattr - cmd.attrs);

	if (ioctl(qp->context->cmd_fd, RDMA_VERBS_IOCTL, &cmd))
		return errno;

	(void) VALGRIND_MAKE_MEM_DEFINED(&events_reported,
					 sizeof(events_reported));

	pthread_mutex_lock(&qp->mutex);
	while (qp->events_completed != events_reported)
		pthread_cond_wait(&qp->cond, &qp->mutex);
	pthread_mutex_unlock(&qp->mutex);

	return 0;
}

int ibv_cmd_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	struct ibv_attach_mcast cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, ATTACH_MCAST);
	memcpy(cmd.gid, gid->raw, sizeof cmd.gid);
	cmd.qp_handle = qp->handle;
	cmd.mlid      = lid;
	cmd.reserved  = 0;

	if (write(qp->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}

int ibv_cmd_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	struct ibv_detach_mcast cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, DETACH_MCAST);
	memcpy(cmd.gid, gid->raw, sizeof cmd.gid);
	cmd.qp_handle = qp->handle;
	cmd.mlid      = lid;
	cmd.reserved  = 0;

	if (write(qp->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}

static int ib_spec_to_kern_spec(struct ibv_flow_spec *ib_spec,
				struct ibv_kern_spec *kern_spec)
{
	kern_spec->hdr.type = ib_spec->hdr.type;

	switch (ib_spec->hdr.type) {
	case IBV_FLOW_SPEC_ETH:
		kern_spec->eth.size = sizeof(struct ibv_kern_spec_eth);
		memcpy(&kern_spec->eth.val, &ib_spec->eth.val,
		       sizeof(struct ibv_flow_eth_filter));
		memcpy(&kern_spec->eth.mask, &ib_spec->eth.mask,
		       sizeof(struct ibv_flow_eth_filter));
		break;
	case IBV_FLOW_SPEC_IPV4:
		kern_spec->ipv4.size = sizeof(struct ibv_kern_spec_ipv4);
		memcpy(&kern_spec->ipv4.val, &ib_spec->ipv4.val,
		       sizeof(struct ibv_flow_ipv4_filter));
		memcpy(&kern_spec->ipv4.mask, &ib_spec->ipv4.mask,
		       sizeof(struct ibv_flow_ipv4_filter));
		break;
	case IBV_FLOW_SPEC_TCP:
	case IBV_FLOW_SPEC_UDP:
		kern_spec->tcp_udp.size = sizeof(struct ibv_kern_spec_tcp_udp);
		memcpy(&kern_spec->tcp_udp.val, &ib_spec->tcp_udp.val,
		       sizeof(struct ibv_flow_ipv4_filter));
		memcpy(&kern_spec->tcp_udp.mask, &ib_spec->tcp_udp.mask,
		       sizeof(struct ibv_flow_tcp_udp_filter));
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

struct ibv_flow *ibv_cmd_create_flow(struct ibv_qp *qp,
				     struct ibv_flow_attr *flow_attr)
{
	struct ibv_create_flow *cmd;
	struct ibv_create_flow_resp resp;
	struct ibv_flow *flow_id;
	size_t cmd_size;
	size_t written_size;
	int i, err;
	void *kern_spec;
	void *ib_spec;

	cmd_size = sizeof(*cmd) + (flow_attr->num_of_specs *
				  sizeof(struct ibv_kern_spec));
	cmd = alloca(cmd_size);
	flow_id = malloc(sizeof(*flow_id));
	if (!flow_id)
		return NULL;
	memset(cmd, 0, cmd_size);

	cmd->qp_handle = qp->handle;

	cmd->flow_attr.type = flow_attr->type;
	cmd->flow_attr.priority = flow_attr->priority;
	cmd->flow_attr.num_of_specs = flow_attr->num_of_specs;
	cmd->flow_attr.port = flow_attr->port;
	cmd->flow_attr.flags = flow_attr->flags;

	kern_spec = cmd + 1;
	ib_spec = flow_attr + 1;
	for (i = 0; i < flow_attr->num_of_specs; i++) {
		err = ib_spec_to_kern_spec(ib_spec, kern_spec);
		if (err)
			goto err;
		cmd->flow_attr.size +=
			((struct ibv_kern_spec *)kern_spec)->hdr.size;
		kern_spec += ((struct ibv_kern_spec *)kern_spec)->hdr.size;
		ib_spec += ((struct ibv_flow_spec *)ib_spec)->hdr.size;
	}

	written_size = sizeof(*cmd) + cmd->flow_attr.size;
	IBV_INIT_CMD_RESP_EX_VCMD(cmd, written_size, written_size, CREATE_FLOW,
				  &resp, sizeof(resp));
	if (write(qp->context->cmd_fd, cmd, written_size) != written_size)
		goto err;

	(void) VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof(resp));

	flow_id->context = qp->context;
	flow_id->handle = resp.flow_handle;
	return flow_id;
err:
	free(flow_id);
	return NULL;
}

int ibv_cmd_destroy_flow(struct ibv_flow *flow_id)
{
	struct ibv_destroy_flow cmd;
	int ret = 0;

	memset(&cmd, 0, sizeof(cmd));
	IBV_INIT_CMD_EX(&cmd, sizeof(cmd), DESTROY_FLOW);
	cmd.flow_handle = flow_id->handle;

	if (write(flow_id->context->cmd_fd, &cmd, sizeof(cmd)) != sizeof(cmd))
		ret = errno;
	free(flow_id);
	return ret;
}
