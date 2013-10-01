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

#include <linux/types.h>

struct xio_rdma_mempool;

struct xio_mem_reg {
	u32  lkey;
	u32  rkey;
	u64  va;
	u64  len;
	void *mem_h;
	int  is_mr;
};

struct xio_regd_buf {
	struct xio_mem_reg	reg;		/* memory registration info  */
	void			*virt_addr;
	struct xio_device	*dev;		/* dev->ib_dev for dma_unmap */
	enum dma_data_direction direction;	/* direction for dma_unmap   */
	size_t			data_size;
};

struct xio_rdma_mp_mem {
	void		*addr;
	size_t		length;
	struct xio_mr	*mr;
	void		*cache;
};

struct xio_rdma_mem_desc {
	/* sgl for dma mapping */
	struct scatterlist	sgl[XIO_MAX_IOV];
	struct xio_rdma_mp_mem	mp_sge[XIO_MAX_IOV];
	u32			num_sge;
	unsigned int		nents;
	unsigned int		mapped;
	struct xio_regd_buf	reg_buf;
};

#define XIO_CHUNKS_SIZE_NR	4

#define XIO_16K_BLOCK_SZ	(16*1024)
#define XIO_16K_MIN_NR		128
#define XIO_16K_MAX_NR		1024
#define XIO_16K_ALLOC_NR	128

#define XIO_64K_BLOCK_SZ	(64*1024)
#define XIO_64K_MIN_NR		128
#define XIO_64K_MAX_NR		1024
#define XIO_64K_ALLOC_NR	128

#define XIO_256K_BLOCK_SZ	(256*1024)
#define XIO_256K_MIN_NR		128
#define XIO_256K_MAX_NR		1024
#define XIO_256K_ALLOC_NR	128

#define XIO_1M_BLOCK_SZ		(1024*1024)
#define XIO_1M_MIN_NR		128
#define XIO_1M_MAX_NR		1024
#define XIO_1M_ALLOC_NR		128


struct xio_rdma_mempool *xio_rdma_mempool_create(void);
void xio_rdma_mempool_destroy(struct xio_rdma_mempool *mpool);

int xio_rdma_mempool_alloc(struct xio_rdma_mempool *mpool,
			     size_t length, struct xio_rdma_mp_mem *mp_mem);

int xio_rdma_mp_sge_alloc(struct xio_rdma_mempool *mpool, xio_sge *sge,
			  u32 num_sge, xio_rdma_mem_desc *desc);

void xio_rdma_mempool_free(xio_rdma_mem_desc *desc);

#endif
