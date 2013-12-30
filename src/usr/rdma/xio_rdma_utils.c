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
#include "xio_rdma_mempool.h"
#include "xio_task.h"
#include "xio_rdma_transport.h"
#include "xio_rdma_utils.h"

/*---------------------------------------------------------------------------*/
/* xio_validate_rdma_op							     */
/*---------------------------------------------------------------------------*/
int xio_validate_rdma_op(
			struct xio_sge *lsg_list, size_t lsize,
			struct xio_sge *rsg_list, size_t rsize,
			int op_size)
{
	int		l	= 0,
			r	= 0;
	uint64_t	laddr	= lsg_list[0].addr;
	uint64_t	raddr	= rsg_list[0].addr;
	uint32_t	llen	= lsg_list[0].length;
	uint32_t	rlen	= rsg_list[0].length;
	uint32_t	tot_len = 0;

	if (lsize < 1 || rsize < 1) {
		ERROR_LOG("iovec size < 1 lsize:%zd, rsize:%zd\n",
			  lsize, rsize);
		return -1;
	}

	while (1) {
		if (rlen < llen) {
			r++;
			tot_len	+= rlen;
			if (r == rsize)
				break;
			llen	-= rlen;
			laddr	+= rlen;
			raddr	= rsg_list[r].addr;
			rlen	= rsg_list[r].length;
		} else if (llen < rlen) {
			l++;
			tot_len	+= llen;
			if (l == lsize)
				break;
			rlen	-= llen;
			raddr	+= llen;
			laddr	= lsg_list[l].addr;
			llen	= lsg_list[l].length;
		} else {
			l++;
			r++;
			tot_len	+= llen;
			if ((l == lsize) || (r == rsize))
				break;

			laddr	= lsg_list[l].addr;
			llen	= lsg_list[l].length;
			raddr	= rsg_list[r].addr;
			rlen	= rsg_list[r].length;
		}
	}

	/* not enough buffers to complete */
	if (tot_len < op_size) {
		ERROR_LOG("iovec exausted\n");
		return -1;
	}

	return 0;
}

