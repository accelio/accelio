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

#include "libxio.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_context.h"
#include "xio_task.h"
#include "xio_transport.h"
#include "xio_protocol.h"
#include "xio_mem.h"
#include "xio_usr_transport.h"
#include "xio_common.h"

/*---------------------------------------------------------------------------*/
/* xio_transport_mempool_array_init					     */
/*---------------------------------------------------------------------------*/
int xio_transport_mempool_array_init(struct xio_mempool
				     ***mempool_array,
				     int *mempool_array_len)
{
	long cpus_nr = sysconf(_SC_NPROCESSORS_CONF);
	if (cpus_nr < 0) {
		xio_set_error(errno);
		ERROR_LOG("mempool_array_init failed. (errno=%d %m)\n", errno);
		return -1;
	}


	/* free devices */
	*mempool_array_len = 0;
	*mempool_array = ucalloc(cpus_nr, sizeof(struct xio_rmda_mempool *));
	if (*mempool_array == NULL) {
		xio_set_error(errno);
		ERROR_LOG("mempool_array_init failed. (errno=%d %m)\n", errno);
		return -1;
	}
	*mempool_array_len = cpus_nr;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_transport_mempool_array_release					     */
/*---------------------------------------------------------------------------*/
void xio_transport_mempool_array_release(struct xio_mempool
						**mempool_array,
						int mempool_array_len)
{
	int i;

	for (i = 0; i < mempool_array_len; i++) {
		if (mempool_array[i]) {
			xio_mempool_destroy(mempool_array[i]);
			mempool_array[i] = NULL;
		}
	}
	ufree(mempool_array);
}

/*---------------------------------------------------------------------------*/
/* xio_transport_mempool_array_get					     */
/*---------------------------------------------------------------------------*/
struct xio_mempool *xio_transport_mempool_array_get(
		struct xio_context *ctx,
		struct xio_mempool **mempool_array,
		int mempool_array_len,
		int reg_mr)
{
	if (ctx->nodeid > mempool_array_len) {
		ERROR_LOG("xio_rdma_mempool_create failed. array overflow\n");
		return NULL;
	}
	if (mempool_array[ctx->nodeid])
		return mempool_array[ctx->nodeid];

	mempool_array[ctx->nodeid] = xio_mempool_create(
			ctx->nodeid,
			(reg_mr ? XIO_MEMPOOL_FLAG_REG_MR : 0) |
			XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC);

	if (!mempool_array[ctx->nodeid]) {
		ERROR_LOG("xio_mempool_create failed (errno=%d %m)\n", errno);
		return NULL;
	}
	return mempool_array[ctx->nodeid];
}
