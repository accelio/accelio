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
#include "xio_os.h"
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include "libxio.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_context.h"
#include "xio_task.h"
#include "xio_transport.h"
#include "xio_conn.h"
#include "xio_protocol.h"
#include "get_clock.h"
#include "xio_mem.h"
#include "xio_rdma_mempool.h"
#include "xio_rdma_transport.h"


/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static LIST_HEAD(mr_list);


/*---------------------------------------------------------------------------*/
/* ibv_rdma_alloc_mr	                                                     */
/*---------------------------------------------------------------------------*/
struct ibv_mr *xio_rdma_alloc_mr(struct xio_device *dev, size_t length)
{
	if (!(dev->device_attr.device_cap_flags & IBV_DEVICE_MR_ALLOCATE)) {
		TRACE_LOG("M-pages not available on %s",
			  dev->verbs->device->name);
		return NULL;
	}
	return ibv_reg_mr(dev->pd, NULL, length,
			IBV_ACCESS_LOCAL_WRITE |
			IBV_ACCESS_REMOTE_WRITE|
			IBV_ACCESS_REMOTE_READ |
			IBV_ACCESS_ALLOCATE_MR);
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
/* xio_reg_mr								     */
/*---------------------------------------------------------------------------*/
static struct xio_mr *xio_reg_mr_ex(void **addr, size_t length, int access)
{
	struct xio_mr			*tmr;
	struct xio_mr_elem		*tmr_elem;
	struct xio_device		*dev;
	int				retval;
	struct ibv_mr			*mr;
	static int			init_transport = 1;

	/* this may the first call in application so initialize the rdma */
	if (init_transport) {
		struct xio_transport *transport = xio_get_transport("rdma");
		if (transport == NULL) {
			ERROR_LOG("invalid protocol. proto: rdma\n");
			xio_set_error(XIO_E_ADDR_ERROR);
			return NULL;
		}
		init_transport = 0;
	}

	if (list_empty(&dev_list))
		goto cleanup3;

	tmr = calloc(1, sizeof(*tmr));
	if (tmr == NULL) {
		xio_set_error(errno);
		ERROR_LOG("malloc failed. (errno=%d %m)\n", errno);
		goto cleanup3;
	}
	INIT_LIST_HEAD(&tmr->dm_list);

	list_for_each_entry(dev, &dev_list, dev_list_entry) {
		mr = ibv_reg_mr(dev->pd, *addr, length, access);
		if (mr == NULL) {
			xio_set_error(errno);
			ERROR_LOG("ibv_reg_mr failed, %m\n");

			if ((access & IBV_ACCESS_ALLOCATE_MR) &&
			    !(dev->device_attr.device_cap_flags &
			    IBV_DEVICE_MR_ALLOCATE)) {
				INFO_LOG(
				     "allocations are not supported on %s\n",
				     dev->verbs->device->name);
			}
			goto cleanup2;
		}
		tmr_elem = calloc(1, sizeof(*tmr_elem));
		if (tmr_elem == NULL)
			goto  cleanup1;
		tmr_elem->dev = dev;
		tmr_elem->mr = mr;
		list_add(&tmr_elem->dm_list_entry, &tmr->dm_list);

		if (access & IBV_ACCESS_ALLOCATE_MR) {
			access  &= ~IBV_ACCESS_ALLOCATE_MR;
			*addr = mr->addr;
		}
	}

	list_add(&tmr->mr_list_entry, &mr_list);

	return tmr;

cleanup1:
	retval = ibv_dereg_mr(mr);
	if (retval != 0) {
		xio_set_error(errno);
		ERROR_LOG("ibv_dereg_mr failed, %m\n");
	}
cleanup2:
	retval = xio_dereg_mr(&tmr);
	if (retval != 0)
		ERROR_LOG("xio_dereg_mr failed\n");
cleanup3:
	return  NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_reg_mr								     */
/*---------------------------------------------------------------------------*/
struct xio_mr *xio_reg_mr(void *addr, size_t length)
{
	if (addr == NULL) {
		xio_set_error(EINVAL);
		return NULL;
	}

	return xio_reg_mr_ex(&addr, length,
			     IBV_ACCESS_LOCAL_WRITE |
			     IBV_ACCESS_REMOTE_WRITE|
			     IBV_ACCESS_REMOTE_READ);
}

/*---------------------------------------------------------------------------*/
/* xio_dereg_mr								     */
/*---------------------------------------------------------------------------*/
int xio_dereg_mr(struct xio_mr **p_tmr)
{
	struct xio_mr		*tmr = *p_tmr;
	struct xio_mr_elem	*tmr_elem, *tmp_tmr_elem;
	int			retval;



	if (!list_empty(&tmr->dm_list)) {
		list_del(&tmr->mr_list_entry);

		list_for_each_entry_safe(tmr_elem, tmp_tmr_elem, &tmr->dm_list,
					 dm_list_entry) {
			retval = ibv_dereg_mr(tmr_elem->mr);
			if (retval != 0) {
				xio_set_error(errno);
				ERROR_LOG("ibv_dereg_mr failed, %m\n");
			}
			/* Remove the item from the list. */
			list_del(&tmr_elem->dm_list_entry);
			free(tmr_elem);
		}
	}
	free(tmr);
	*p_tmr = NULL;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_alloc								     */
/*---------------------------------------------------------------------------*/
struct xio_buf *xio_alloc(size_t length)
{
	struct xio_buf	*buf;


	buf = calloc(1, sizeof(*buf));
	if (!buf) {
		xio_set_error(errno);
		ERROR_LOG("calloc failed. (errno=%d %m)\n", errno);
		return NULL;
	}
	buf->mr = xio_reg_mr_ex(&buf->addr, length,
			    IBV_ACCESS_LOCAL_WRITE |
			    IBV_ACCESS_REMOTE_WRITE|
			    IBV_ACCESS_REMOTE_READ |
			    IBV_ACCESS_ALLOCATE_MR);
	if (!buf->mr) {
		ERROR_LOG("xio_reg_mr_ex failed\n");
		return NULL;
	}
	buf->length = length;

	return buf;
}

/*---------------------------------------------------------------------------*/
/* xio_free								     */
/*---------------------------------------------------------------------------*/
int xio_free(struct xio_buf **buf)
{
	struct xio_mr		*tmr = (*buf)->mr;
	int			retval = xio_dereg_mr(&tmr);

	free(*buf);
	*buf = NULL;

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_mr_list_init							     */
/*---------------------------------------------------------------------------*/
void xio_mr_list_init(void)
{
	INIT_LIST_HEAD(&mr_list);
}

/*---------------------------------------------------------------------------*/
/* xio_mr_list_free							     */
/*---------------------------------------------------------------------------*/
int xio_mr_list_free(void)
{
	struct xio_mr		*tmr, *next;

	list_for_each_entry_safe(tmr, next, &mr_list, mr_list_entry) {
		xio_dereg_mr(&tmr);
	}

	return 0;
}


