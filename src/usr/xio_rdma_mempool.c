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
#include "libxio.h"
#include "xio_common.h"
#include "xio_mem.h"
#include "xio_rdma_mempool.h"


/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
struct xio_mem_block {
	struct xio_mem_slot		*parent_slot;
	struct xio_mr			*omr;
	void				*buf;
	struct list_head		mem_block_entry;
};

struct xio_mem_region {
	struct xio_mr			*omr;
	void				*buf;
	struct list_head		mem_region_entry;
};

struct xio_mem_slot {
	struct list_head		mem_regions_list;

	struct list_head		free_blocks_list;
	struct list_head		used_blocks_list;

	size_t				mb_size;	/*memory block size */
	pthread_spinlock_t		lock;

	int				init_mb_nr;	/* initial mb
							   size */
	int				curr_mb_nr;	/* current size */
	int				max_mb_nr;	/* max allowed size */
	int				alloc_mb_nr;	/* number of items
							   per allcoation */
	int				pad;
};

struct xio_rdma_mempool {
	struct xio_mem_slot		slot[XIO_MEM_SLOTS_NR + 1];
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_mem_slot_free						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_mem_slot_free(struct xio_mem_slot *slot)
{
	struct xio_mem_region		*r, *tmp_r;


	INIT_LIST_HEAD(&slot->free_blocks_list);
	INIT_LIST_HEAD(&slot->used_blocks_list);
	list_for_each_entry_safe(r, tmp_r, &slot->mem_regions_list,
				 mem_region_entry) {
		list_del(&r->mem_region_entry);

		xio_dereg_mr(&r->omr);
		free_huge_pages(r->buf);
		free(r);
	}

	pthread_spin_destroy(&slot->lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mem_slot_resize						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_mem_slot_resize(struct xio_mem_slot *slot)
{
	char				*buf;
	struct xio_mem_region		*region;
	struct xio_mem_block		*block;
	int				nr_blocks;
	size_t				region_alloc_sz;
	size_t				data_alloc_sz;
	int				i;

	if (slot->curr_mb_nr == 0) {
		nr_blocks = min(slot->init_mb_nr, slot->max_mb_nr);
		if (nr_blocks <= 0)
			return -1;
	} else {
		nr_blocks =  slot->max_mb_nr - slot->curr_mb_nr;
		if (nr_blocks <= 0)
			return -1;
		nr_blocks = min(nr_blocks, slot->alloc_mb_nr);
	}

	region_alloc_sz = sizeof(*region) +
		nr_blocks*sizeof(struct xio_mem_block);
	buf = calloc(region_alloc_sz, sizeof(uint8_t));
	if (buf == NULL)
		return -1;

	/* region */
	region = (void *)buf;
	buf = buf + sizeof(*region);
	block = (void *)buf;

	/* region data */
	data_alloc_sz = nr_blocks*slot->mb_size;

	/* alocate the buffers and register them */
	region->buf = malloc_huge_pages(data_alloc_sz);
	if (region->buf == NULL) {
		free(buf);
		return -1;
	}

	region->omr = xio_reg_mr(region->buf, data_alloc_sz);
	if (region->omr == NULL) {
		free_huge_pages(region->buf);
		free(buf);
		return -1;
	}

	for (i = 0; i < nr_blocks; i++) {
		block->parent_slot = slot;
		block->omr	= region->omr;
		block->buf	= (char *)(region->buf) + i*slot->mb_size;
		list_add(&block->mem_block_entry, &slot->free_blocks_list);
		block++;
	}
	list_add(&region->mem_region_entry, &slot->mem_regions_list);

	slot->curr_mb_nr += nr_blocks;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_destroy						     */
/*---------------------------------------------------------------------------*/
void xio_rdma_mempool_destroy(struct xio_rdma_mempool *p)
{
	int i;

	if (!p)
		return;

	for (i = 0; i < XIO_MEM_SLOTS_NR; i++)
		xio_rdma_mem_slot_free(&p->slot[i]);

	free(p);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_create						     */
/*---------------------------------------------------------------------------*/
struct xio_rdma_mempool *xio_rdma_mempool_create(void)
{
	struct xio_rdma_mempool *p;
	int			i;
	int			ret;

	p = calloc(1, sizeof(struct xio_rdma_mempool));
	if (p == NULL)
		return NULL;

	p->slot[0].mb_size		= XIO_16K_BLOCK_SZ;
	p->slot[0].init_mb_nr		= XIO_16K_MIN_NR;
	p->slot[0].max_mb_nr		= XIO_16K_MAX_NR;
	p->slot[0].alloc_mb_nr		= XIO_16K_ALLOC_NR;

	p->slot[1].mb_size		= XIO_64K_BLOCK_SZ;
	p->slot[1].init_mb_nr		= XIO_64K_MIN_NR;
	p->slot[1].max_mb_nr		= XIO_64K_MAX_NR;
	p->slot[1].alloc_mb_nr		= XIO_64K_ALLOC_NR;

	p->slot[2].mb_size		= XIO_256K_BLOCK_SZ;
	p->slot[2].init_mb_nr		= XIO_256K_MIN_NR;
	p->slot[2].max_mb_nr		= XIO_256K_MAX_NR;
	p->slot[2].alloc_mb_nr		= XIO_256K_ALLOC_NR;

	p->slot[3].mb_size		= XIO_1M_BLOCK_SZ;
	p->slot[3].init_mb_nr		= XIO_1M_MIN_NR;
	p->slot[3].max_mb_nr		= XIO_1M_MAX_NR;
	p->slot[3].alloc_mb_nr		= XIO_1M_ALLOC_NR;

	p->slot[4].mb_size		= SIZE_MAX;

	for (i = XIO_MEM_SLOTS_NR - 1; i >= 0; i--) {
		ret = pthread_spin_init(&p->slot[i].lock,
					PTHREAD_PROCESS_PRIVATE);
		if (ret != 0)
			goto cleanup;
		INIT_LIST_HEAD(&p->slot[i].mem_regions_list);
		INIT_LIST_HEAD(&p->slot[i].free_blocks_list);
		INIT_LIST_HEAD(&p->slot[i].used_blocks_list);
		ret = xio_rdma_mem_slot_resize(&p->slot[i]);
		if (ret == -1)
			goto cleanup;
	}

	return p;
cleanup:
	xio_rdma_mempool_destroy(p);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* size2index								     */
/*---------------------------------------------------------------------------*/
static inline int size2index(struct xio_rdma_mempool *p, size_t sz)
{
	int i;

	for (i = 0; i <= XIO_MEM_SLOTS_NR; i++)
		if (sz <= p->slot[i].mb_size)
			break;

	return (i == XIO_MEM_SLOTS_NR) ? -1 : i;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_alloc						     */
/*---------------------------------------------------------------------------*/
int xio_rdma_mempool_alloc(struct xio_rdma_mempool *p, size_t length,
			   struct xio_rdma_mp_mem *mp_mem)
{
	int			index;
	struct xio_mem_slot	*slot;
	struct xio_mem_block	*block;
	int			ret = 0;

	index = size2index(p, length);
retry:
	if (index == -1) {
		errno = EINVAL;
		ret = -1;
		goto cleanup;
	}
	slot = &p->slot[index];
	pthread_spin_lock(&slot->lock);

	if (list_empty(&slot->free_blocks_list)) {
		ret = xio_rdma_mem_slot_resize(slot);
		if (ret == -1) {
			if (++index == XIO_MEM_SLOTS_NR)
				index  = -1;
			pthread_spin_unlock(&slot->lock);
			ret = 0;
			goto retry;
		}
		printf("resizing slot size:%zd\n", slot->mb_size);
	}
	block = list_first_entry(
				&slot->free_blocks_list,
				struct xio_mem_block,  mem_block_entry);


	mp_mem->addr	= block->buf;
	mp_mem->mr	= block->omr;
	mp_mem->cache	= block;
	mp_mem->length	= length;

	list_move(&block->mem_block_entry, &slot->used_blocks_list);

	pthread_spin_unlock(&slot->lock);
cleanup:
	return ret;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_free						     */
/*---------------------------------------------------------------------------*/
void xio_rdma_mempool_free(struct xio_rdma_mp_mem *mp_mem)
{
	struct xio_mem_block *block;

	if (!mp_mem)
		return;

	block = mp_mem->cache;

	pthread_spin_lock(&block->parent_slot->lock);
	list_move(&block->mem_block_entry,
		  &block->parent_slot->free_blocks_list);
	pthread_spin_unlock(&block->parent_slot->lock);
}

