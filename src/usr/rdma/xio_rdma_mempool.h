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
#ifndef XIO_RDMA_MEMPOOL_H
#define XIO_RDMA_MEMPOOL_H

#include <unistd.h>


struct xio_mr;
struct xio_rdma_mempool;

struct xio_rdma_mp_mem {
	void		*addr;
	size_t		length;
	struct xio_mr	*mr;
	void		*cache;
};

/* create mempool with default allocators */
struct xio_rdma_mempool *xio_rdma_mempool_create(void);

/* create mempool with NO (!) allocators */
struct xio_rdma_mempool *xio_rdma_mempool_create_ex(void);

/* add an allocator to current set (setup only) */
int xio_rdma_mempool_add_allocator(struct xio_rdma_mempool *mpool,
				   size_t size, size_t min, size_t max,
				   size_t alloc_quantum_nr);


void xio_rdma_mempool_destroy(struct xio_rdma_mempool *mpool);

int xio_rdma_mempool_alloc(struct xio_rdma_mempool *mpool,
			   size_t length, struct xio_rdma_mp_mem *mp_mem);
void xio_rdma_mempool_free(struct xio_rdma_mp_mem *mp_mem);


#endif

