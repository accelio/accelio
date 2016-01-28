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
#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_transport.h"
#include "xio_protocol.h"
#include "xio_mem.h"
#include "xio_usr_transport.h"
#include "xio_mempool.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"

#ifndef HAVE_INFINIBAND_VERBS_H

/*---------------------------------------------------------------------------*/
/* xio_mem_register							     */
/*---------------------------------------------------------------------------*/
int xio_mem_register(void *addr, size_t length, struct xio_reg_mem *reg_mem)
{
	static struct xio_mr dummy_mr;

	if (!addr || !reg_mem) {
		xio_set_error(EINVAL);
		return -1;
	}

	reg_mem->addr = addr;
	reg_mem->length = length;
	reg_mem->mr = &dummy_mr;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_dereg							     */
/*---------------------------------------------------------------------------*/
int xio_mem_dereg(struct xio_reg_mem *reg_mem)
{
	reg_mem->mr = NULL;
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_alloc							     */
/*---------------------------------------------------------------------------*/
int xio_mem_alloc(size_t length, struct xio_reg_mem *reg_mem)
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

	xio_mem_register(reg_mem->addr, length, reg_mem);
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
/* xio_mem_free								     */
/*---------------------------------------------------------------------------*/
int xio_mem_free(struct xio_reg_mem *reg_mem)
{
	int			retval = 0;

	if (reg_mem->addr)
		ufree(reg_mem->addr);

	retval = xio_mem_dereg(reg_mem);

	return retval;
}

#endif /*HAVE_INFINIBAND_VERBS_H*/

/*---------------------------------------------------------------------------*/
/* xio_transport_mempool_get						     */
/*---------------------------------------------------------------------------*/
struct xio_mempool *xio_transport_mempool_get(
		struct xio_context *ctx, int reg_mr)
{
	if (ctx->mempool)
		return (struct xio_mempool *)ctx->mempool;

        /* user asked to force registration and rdma exist on machine*/
        if (ctx->register_internal_mempool && xio_get_transport("rdma"))
                reg_mr = 1;

	ctx->mempool = xio_mempool_create_prv(
			ctx->nodeid,
			(reg_mr ? XIO_MEMPOOL_FLAG_REG_MR : 0) |
			XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC);

	if (!ctx->mempool) {
		ERROR_LOG("xio_mempool_create failed (errno=%d %m)\n", errno);
		return NULL;
	}
	return (struct xio_mempool *)ctx->mempool;
}

/*---------------------------------------------------------------------------*/
/* xio_transport_state_str						     */
/*---------------------------------------------------------------------------*/
char *xio_transport_state_str(enum xio_transport_state state)
{
	switch (state) {
	case XIO_TRANSPORT_STATE_INIT:
		return "INIT";
	case XIO_TRANSPORT_STATE_LISTEN:
		return "LISTEN";
	case XIO_TRANSPORT_STATE_CONNECTING:
		return "CONNECTING";
	case XIO_TRANSPORT_STATE_CONNECTED:
		return "CONNECTED";
	case XIO_TRANSPORT_STATE_DISCONNECTED:
		return "DISCONNECTED";
	case XIO_TRANSPORT_STATE_RECONNECT:
		return "RECONNECT";
	case XIO_TRANSPORT_STATE_CLOSED:
		return "CLOSED";
	case XIO_TRANSPORT_STATE_DESTROYED:
		return "DESTROYED";
	case XIO_TRANSPORT_STATE_ERROR:
		return "ERROR";
	default:
		return "UNKNOWN";
	}

	return NULL;
};

