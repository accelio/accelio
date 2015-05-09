/*
 * Copyright (c) 2013 Mellanox Technologies®. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies® BSD license
 * below:
 *
 *      - Redistribution and use in source and binary forms, with or without
 *        modification, are permitted provided that the following conditions
 *        are met:
 *
 *      - Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 *      - Neither the name of the Mellanox Technologies® nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <xio_os.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_transport.h"
#include "xio_protocol.h"
#include "get_clock.h"
#include "xio_mem.h"
#include "xio_usr_transport.h"
#include "xio_mempool.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_rdma_utils.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"
#include "xio_rdma_transport.h"

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static LIST_HEAD(mr_list);
static spinlock_t mr_list_lock;
static uint32_t mr_num; /* checkpatch doesn't like initializing static vars */

/*---------------------------------------------------------------------------*/
/* xio_register_transport						     */
/*---------------------------------------------------------------------------*/
static int xio_register_transport(void)
{
	static int init_transport;

	/* this may the first call in application so initialize the rdma */
	if (!init_transport) {
		struct xio_transport *transport = xio_get_transport("rdma");

		if (!transport)
			return 0;

		init_transport = 1;
	}

	return init_transport;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_register_no_dev						     */
/*---------------------------------------------------------------------------*/
static inline int xio_mem_register_no_dev(void *addr, size_t length,
					  struct xio_reg_mem *reg_mem)
{
	static struct xio_mr dummy_mr;

	reg_mem->addr = addr;
	reg_mem->length = length;
	reg_mem->mr = &dummy_mr;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_dereg_no_dev							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mem_dereg_no_dev(struct xio_reg_mem *reg_mem)
{
	reg_mem->mr = NULL;
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_alloc_no_dev							     */
/*---------------------------------------------------------------------------*/
static int xio_mem_alloc_no_dev(size_t length, struct xio_reg_mem *reg_mem)
{
	size_t			real_size;
	int			alloced = 0;

	real_size = ALIGN(length, page_size);
	reg_mem->addr = umemalign(page_size, real_size);
	if (!reg_mem->addr) {
		ERROR_LOG("xio_memalign failed. sz:%zu\n", real_size);
		goto cleanup;
	}
	/*memset(reg_mem->addr, 0, real_size);*/
	alloced = 1;

	xio_mem_register_no_dev(reg_mem->addr, length, reg_mem);
	if (!reg_mem->mr) {
		ERROR_LOG("xio_reg_mr failed. addr:%p, length:%d\n",
			  reg_mem->addr, length, access);

		goto cleanup1;
	}
	reg_mem->length = length;

	return 0;

cleanup1:
	if (alloced)
		ufree(reg_mem->addr);
cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_free_no_dev							     */
/*---------------------------------------------------------------------------*/
static int xio_mem_free_no_dev(struct xio_reg_mem *reg_mem)
{
	int			retval = 0;

	if (reg_mem->addr)
		ufree(reg_mem->addr);

	retval = xio_mem_dereg_no_dev(reg_mem);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* ibv_wc_opcode_str	                                                     */
/*---------------------------------------------------------------------------*/
const char *ibv_wc_opcode_str(enum ibv_wc_opcode opcode)
{
	switch (opcode) {
	case IBV_WC_SEND:		return "IBV_WC_SEND";
	case IBV_WC_RDMA_WRITE:		return "IBV_WC_RDMA_WRITE";
	case IBV_WC_RDMA_READ:		return "IBV_WC_RDMA_READ";
	case IBV_WC_COMP_SWAP:		return "IBV_WC_COMP_SWAP";
	case IBV_WC_FETCH_ADD:		return "IBV_WC_FETCH_ADD";
	case IBV_WC_BIND_MW:		return "IBV_WC_BIND_MW";
	/* recv-side: inbound completion */
	case IBV_WC_RECV:		return "IBV_WC_RECV";
	case IBV_WC_RECV_RDMA_WITH_IMM: return "IBV_WC_RECV_RDMA_WITH_IMM";
	default:			return "IBV_WC_UNKNOWN";
	};
}

/*---------------------------------------------------------------------------*/
/* xio_dereg_mr								     */
/*---------------------------------------------------------------------------*/
static int xio_dereg_mr(struct xio_mr *tmr)
{
	struct xio_mr		*ptmr, *tmp_ptmr;
	struct xio_mr_elem	*tmr_elem, *tmp_tmr_elem;
	int			retval, found = 0;

	spin_lock(&mr_list_lock);
	list_for_each_entry_safe(ptmr, tmp_ptmr, &mr_list, mr_list_entry) {
		if (ptmr == tmr) {
			list_del(&tmr->mr_list_entry);
			found = 1;
			break;
		}
	}
	spin_unlock(&mr_list_lock);

	if (found) {
		list_for_each_entry_safe(tmr_elem, tmp_tmr_elem, &tmr->dm_list,
					 dm_list_entry) {
			retval = ibv_dereg_mr(tmr_elem->mr);
			if (unlikely(retval != 0)) {
				xio_set_error(errno);
				ERROR_LOG("ibv_dereg_mr failed, %m\n");
			}
			/* Remove the item from the list. */
			spin_lock(&dev_list_lock);
			list_del(&tmr_elem->dm_list_entry);
			list_del(&tmr_elem->xm_list_entry);
			spin_unlock(&dev_list_lock);
			ufree(tmr_elem);
		}
		ufree(tmr);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_reg_mr_ex_dev							     */
/*---------------------------------------------------------------------------*/
static struct xio_mr_elem *xio_reg_mr_ex_dev(struct xio_device *dev,
					     void **addr, size_t length,
					     uint64_t access)
{
	struct xio_mr_elem *mr_elem;
	struct ibv_mr	   *mr;
	int retval;
	struct ibv_exp_reg_mr_in reg_mr_in;
	int alloc_mr = !(*addr);

	reg_mr_in.pd = dev->pd;
	reg_mr_in.addr = *addr;
	reg_mr_in.length = length;
	reg_mr_in.exp_access = access;
	reg_mr_in.comp_mask = 0;

	TRACE_LOG("before ibv_reg_mr\n");
	mr = ibv_xio_reg_mr(&reg_mr_in);
	TRACE_LOG("after ibv_reg_mr\n");
	if (unlikely(!mr)) {
		xio_set_error(errno);
		if (!alloc_mr)
			ERROR_LOG("ibv_reg_mr failed, %m. " \
				  "addr:%p, length:%zd, access:0x%lx\n",
				  *addr, length, access);
		if (errno == ENOMEM)
			xio_validate_ulimit_memlock();
		return NULL;
	}
	mr_elem = (struct xio_mr_elem *)ucalloc(1, sizeof(*mr_elem));
	if (unlikely(!mr_elem))
		goto  cleanup;

	mr_elem->dev = dev;
	mr_elem->mr = mr;

	return mr_elem;

cleanup:
	retval = ibv_dereg_mr(mr);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("ibv_dereg_mr failed, %m\n");
	}

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_reg_mr_ex							     */
/*---------------------------------------------------------------------------*/
static struct xio_mr *xio_reg_mr_ex(void **addr, size_t length, uint64_t access)
{
	struct xio_mr			*tmr;
	struct xio_mr_elem		*tmr_elem;
	struct xio_device		*dev;
	int				retval;
	static int			init_transport = 1;

	/* Show a warning in case the memory is non aligned */
	if ((access & IBV_XIO_ACCESS_ALLOCATE_MR) == 0 &&
	    ((uintptr_t)(*addr) & (page_size - 1)) != 0) {
		WARN_LOG("Unaligned memory for address %p: length is %d while page size is %d.\n.", *addr, length, page_size);
	}
	/* this may the first call in application so initialize the rdma */
	if (init_transport) {
		struct xio_transport *transport = xio_get_transport("rdma");

		if (!transport) {
			ERROR_LOG("invalid protocol. proto: rdma\n");
			xio_set_error(XIO_E_ADDR_ERROR);
			return NULL;
		}
		init_transport = 0;
	}

	spin_lock(&dev_list_lock);
	if (list_empty(&dev_list)) {
		ERROR_LOG("dev_list is empty\n");
		spin_unlock(&dev_list_lock);
		goto cleanup2;
	}
	spin_unlock(&dev_list_lock);

	tmr = (struct xio_mr *)ucalloc(1, sizeof(*tmr));
	if (unlikely(!tmr)) {
		xio_set_error(errno);
		ERROR_LOG("malloc failed. (errno=%d %m)\n", errno);
		goto cleanup2;
	}
	INIT_LIST_HEAD(&tmr->dm_list);
	/* xio_dereg_mr may be called on error path and it will call
	 * list_del on mr_list_entry, make sure it is initialized
	 */
	INIT_LIST_HEAD(&tmr->mr_list_entry);

	spin_lock(&dev_list_lock);
	list_for_each_entry(dev, &dev_list, dev_list_entry) {
		tmr_elem = xio_reg_mr_ex_dev(dev, addr, length, access);
		if (!tmr_elem) {
			xio_set_error(errno);
			spin_unlock(&dev_list_lock);
			goto cleanup1;
		}
		list_add(&tmr_elem->dm_list_entry, &tmr->dm_list);
		list_add(&tmr_elem->xm_list_entry, &dev->xm_list);

		if (access & IBV_XIO_ACCESS_ALLOCATE_MR) {
			access  &= ~IBV_XIO_ACCESS_ALLOCATE_MR;
			*addr = tmr_elem->mr->addr;
		}
	}
	spin_unlock(&dev_list_lock);

	/* For dynamically discovered devices */
	tmr->addr   = *addr;
	tmr->length = length;
	tmr->access = access;

	spin_lock(&mr_list_lock);
	mr_num++;
	list_add(&tmr->mr_list_entry, &mr_list);
	spin_unlock(&mr_list_lock);

	return tmr;

cleanup1:
	retval = xio_dereg_mr(tmr);
	if (retval != 0)
		ERROR_LOG("xio_dereg_mr failed\n");
cleanup2:
	return  NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_dereg_mr_by_dev							     */
/*---------------------------------------------------------------------------*/
int xio_dereg_mr_by_dev(struct xio_device *dev)
{
	struct xio_mr_elem	*tmr_elem, *tmp_tmr_elem;
	int			retval;
	LIST_HEAD(tmp_list);

	spin_lock(&dev_list_lock);
	if (list_empty(&dev->xm_list)) {
		spin_unlock(&dev_list_lock);
		return 0;
	}

	list_splice_tail(&dev->xm_list, &tmp_list);
	INIT_LIST_HEAD(&dev->xm_list);
	list_for_each_entry_safe(tmr_elem, tmp_tmr_elem, &tmp_list,
				 xm_list_entry)
		list_del(&tmr_elem->dm_list_entry);
	spin_unlock(&dev_list_lock);

	list_for_each_entry_safe(tmr_elem, tmp_tmr_elem, &tmp_list,
				 xm_list_entry) {
		if (tmr_elem->mr) {
			retval = ibv_dereg_mr(tmr_elem->mr);
			if (unlikely(retval != 0)) {
				xio_set_error(errno);
				ERROR_LOG("ibv_dereg_mr failed, %m\n");
			}
		}
		/* Remove the item from the lists. */
		list_del(&tmr_elem->xm_list_entry);
		ufree(tmr_elem);
	}

	return 0;
}

/* The following functions is implemented in xio_connection.c,
 * We prefer not to add an include dependency on xio_connection here */
struct xio_msg;
const struct xio_transport_base *xio_req_to_transport_base(
	const struct xio_msg *req);

static inline const struct xio_device *xio_req_to_device(
	const struct xio_msg *req)
{
	struct xio_rdma_transport *transport = (struct xio_rdma_transport *)
		xio_req_to_transport_base(req);
	return transport->tcq->dev;
}

static inline const struct xio_device *xio_rsp_to_device(
	const struct xio_msg *rsp)
{
	return xio_req_to_device(rsp->request);
}

uint32_t xio_lookup_rkey_by_request(const struct xio_reg_mem *reg_mem,
				    const struct xio_msg *req)
{
	return xio_rdma_mr_lookup(reg_mem->mr, xio_req_to_device(req))->rkey;
}

uint32_t xio_lookup_rkey_by_response(const struct xio_reg_mem *reg_mem,
				     const struct xio_msg *rsp)
{
	return xio_rdma_mr_lookup(reg_mem->mr, xio_rsp_to_device(rsp))->rkey;
}

/*---------------------------------------------------------------------------*/
/* xio_reg_mr_add_dev							     */
/* add a new discovered device to a the mr list				     */
/*---------------------------------------------------------------------------*/
int xio_reg_mr_add_dev(struct xio_device *dev)
{
	struct xio_mr *tmr;
	struct xio_mr_elem *tmr_elem;

	spin_lock(&dev_list_lock);
	spin_lock(&mr_list_lock);
	list_for_each_entry(tmr, &mr_list, mr_list_entry) {
		tmr_elem = xio_reg_mr_ex_dev(dev,
					     &tmr->addr, tmr->length,
					     tmr->access);
		if (unlikely(!tmr_elem)) {
			xio_set_error(errno);
			ERROR_LOG("ibv_reg_mr failed, %m\n");
			spin_unlock(&mr_list_lock);
			spin_unlock(&dev_list_lock);
			goto cleanup;
		}
		list_add(&tmr_elem->dm_list_entry, &tmr->dm_list);
		list_add(&tmr_elem->xm_list_entry, &dev->xm_list);
	}
	spin_unlock(&mr_list_lock);
	spin_unlock(&dev_list_lock);

	return 0;

cleanup:
	xio_dereg_mr_by_dev(dev);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_register							     */
/*---------------------------------------------------------------------------*/
int xio_mem_register(void *addr, size_t length, struct xio_reg_mem *reg_mem)
{
	if (!addr || length == 0) {
		xio_set_error(EINVAL);
		return -1;
	}
	if (list_empty(&dev_list)) {
		if (!xio_register_transport() && list_empty(&dev_list))
			return xio_mem_register_no_dev(addr, length, reg_mem);
	}

	reg_mem->mr = xio_reg_mr_ex(&addr, length,
			     IBV_ACCESS_LOCAL_WRITE  |
			     IBV_ACCESS_REMOTE_WRITE |
			     IBV_ACCESS_REMOTE_READ);
	if (!reg_mem->mr)
		return -1;

	reg_mem->addr	= addr;
	reg_mem->length = length;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_dereg							     */
/*---------------------------------------------------------------------------*/
int xio_mem_dereg(struct xio_reg_mem *reg_mem)
{
	int retval;

	if (!reg_mem->mr) {
		xio_set_error(EINVAL);
		return -1;
	}
	if (list_empty(&dev_list))
		return xio_mem_dereg_no_dev(reg_mem);

	retval = xio_dereg_mr(reg_mem->mr);

	reg_mem->mr = NULL;

	return  retval;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_alloc							     */
/*---------------------------------------------------------------------------*/
int xio_mem_alloc(size_t length, struct xio_reg_mem *reg_mem)
{
	struct xio_device	*dev;
	size_t			real_size;
	uint64_t		access;

	if (length == 0 || !reg_mem) {
		xio_set_error(EINVAL);
		ERROR_LOG("xio_mem_alloc failed. length:%zu\n", length);
		return -1;
	}
	if (list_empty(&dev_list)) {
		if (!xio_register_transport() && list_empty(&dev_list))
			return xio_mem_alloc_no_dev(length, reg_mem);
	}

	access = IBV_ACCESS_LOCAL_WRITE  |
		 IBV_ACCESS_REMOTE_WRITE |
		 IBV_ACCESS_REMOTE_READ;

	dev = list_first_entry(&dev_list, struct xio_device, dev_list_entry);

	if (dev && IBV_IS_MPAGES_AVAIL(&dev->device_attr)) {
		access |= IBV_XIO_ACCESS_ALLOCATE_MR;
		reg_mem->addr = NULL;
		reg_mem->mr = xio_reg_mr_ex(&reg_mem->addr, length, access);
		if (reg_mem->mr) {
			reg_mem->length			= length;
			reg_mem->mr->addr_alloced	= 0;
			goto exit;
		}
		WARN_LOG("Contig pages allocation failed. (errno=%d %m)\n",
			 errno);
	}

	real_size = ALIGN(length, page_size);
	reg_mem->addr = umemalign(page_size, real_size);
	if (unlikely(!reg_mem->addr)) {
		xio_set_error(ENOMEM);
		ERROR_LOG("memalign failed. sz:%zu\n", real_size);
		goto cleanup;
	}
	reg_mem->mr = xio_reg_mr_ex(&reg_mem->addr, length, access);
	if (unlikely(!reg_mem->mr)) {
		ERROR_LOG("xio_reg_mr_ex failed. " \
			  "addr:%p, length:%d, access:0x%x\n",
			   reg_mem->addr, length, access);

		goto cleanup1;
	}
	/*memset(reg_mem->addr, 0, length);*/
	reg_mem->length			= length;
	reg_mem->mr->addr_alloced	= 1;

exit:
	return 0;

cleanup1:
	ufree(reg_mem->addr);
cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_free								     */
/*---------------------------------------------------------------------------*/
int xio_mem_free(struct xio_reg_mem *reg_mem)
{
	int retval;

	if (!reg_mem->mr) {
		xio_set_error(EINVAL);
		return -1;
	}
	if (list_empty(&dev_list))
		return xio_mem_free_no_dev(reg_mem);

	if (reg_mem->mr->addr_alloced) {
		ufree(reg_mem->addr);
		reg_mem->addr			= NULL;
		reg_mem->mr->addr_alloced	= 0;
	}

	retval = xio_dereg_mr(reg_mem->mr);

	reg_mem->mr	= NULL;

	return  retval;
}

/*---------------------------------------------------------------------------*/
/* xio_mr_list_init							     */
/*---------------------------------------------------------------------------*/
void xio_mr_list_init(void)
{
	INIT_LIST_HEAD(&mr_list);
	spin_lock_init(&mr_list_lock);
}

/*---------------------------------------------------------------------------*/
/* xio_mr_list_free							     */
/*---------------------------------------------------------------------------*/
int xio_mr_list_free(void)
{
	struct xio_mr		*tmr;

	while (!list_empty(&mr_list)) {
		tmr = list_first_entry(&mr_list, struct xio_mr, mr_list_entry);
		xio_dereg_mr(tmr);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rkey_table_create						     */
/*---------------------------------------------------------------------------*/
int xio_rkey_table_create(struct xio_device *old, struct xio_device *_new,
			  struct xio_rkey_tbl **htbl, uint16_t *len)
{
	struct xio_rkey_tbl *tbl, *te;
	struct list_head *old_h, *new_h;
	struct list_head *old_n, *new_n;
	struct xio_mr_elem *old_e, *new_e;

	if (!mr_num) {
		/* This is O.K. memory wasn't yet allocated and registered */
		*len = 0;
		return 0;
	}

	tbl = (struct xio_rkey_tbl *)ucalloc(mr_num, sizeof(*tbl));
	if (!tbl) {
		*len = 0;
		xio_set_error(ENOMEM);
		return -1;
	}

	/* MR elements are arranged in a matrix like fashion, were MR is one
	 * axis and device is the other axis
	 */
	old_h = &old->xm_list;
	new_h = &_new->xm_list;
	te = tbl;

	for (old_n = old_h->next, new_n = new_h->next;
	     old_n != old_h && new_n != new_h;
	     old_n = old_n->next, new_n = new_h->next) {
		old_e = list_entry(old_n, struct xio_mr_elem, xm_list_entry);
		new_e = list_entry(new_n, struct xio_mr_elem, xm_list_entry);
		te->old_rkey = old_e->mr->rkey;
		te->new_rkey = new_e->mr->rkey;
		te++;
	}

	if (old_n != old_h || new_n != new_h) {
		/* one list terminated before the other this is a program error
		 * there should be an entry per device
		 */
		ERROR_LOG("bug\n");
		goto cleanup;
	}

	*len = mr_num;
	*htbl = tbl;
	return 0;

cleanup:
	ufree(tbl);
	*len = 0;
	return -1;
}
