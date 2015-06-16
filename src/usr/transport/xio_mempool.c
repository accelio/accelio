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
#include "xio_mem.h"
#include "xio_usr_utils.h"

/* Accelio's default mempool profile (don't expose it) */
#define XIO_MEM_SLABS_NR	4

#define _16K_BLOCK_SZ		(16 * 1024)
#define _16K_MIN_NR		0
#define _16K_MAX_NR		(1024 * 24)
#define _16K_ALLOC_NR		128

#define _64K_BLOCK_SZ		(64 * 1024)
#define _64K_MIN_NR		0
#define _64K_MAX_NR		(1024 * 24)
#define _64K_ALLOC_NR		128

#define _256K_BLOCK_SZ		(256 * 1024)
#define _256K_MIN_NR		0
#define _256K_MAX_NR		(1024 * 24)
#define _256K_ALLOC_NR		128

#define _1M_BLOCK_SZ		(1024 * 1024)
#define _1M_MIN_NR		0
#define _1M_MAX_NR		(1024 * 24)
#define _1M_ALLOC_NR		128

struct xio_mempool_config g_mempool_config = {
	XIO_MEM_SLABS_NR,
	{
		{_16K_BLOCK_SZ,  _16K_MIN_NR,  _16K_ALLOC_NR,  _16K_MAX_NR},
		{_64K_BLOCK_SZ,  _64K_MIN_NR,  _64K_ALLOC_NR,  _64K_MAX_NR},
		{_256K_BLOCK_SZ, _256K_MIN_NR, _256K_ALLOC_NR, _256K_MAX_NR},
		{_1M_BLOCK_SZ,   _1M_MIN_NR,   _1M_ALLOC_NR,   _1M_MAX_NR},
		{0,		0,	     0,		    0},
		{0,		0,	     0,		    0}
	}
};

/* #define DEBUG_MEMPOOL_MT */

/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
typedef volatile int combined_t;

struct xio_mem_block {
	struct xio_mem_slab		*parent_slab;
	struct xio_mr			*omr;
	void				*buf;
	struct xio_mem_block		*next;
	combined_t			refcnt_claim;

	volatile int			refcnt;
	struct list_head		blocks_list_entry;
};

struct xio_mem_region {
	struct xio_mr			*omr;
	void				*buf;
	struct list_head		mem_region_entry;
};

struct xio_mem_slab {
	struct xio_mempool		*pool;
	struct list_head		mem_regions_list;
	struct xio_mem_block		*free_blocks_list;
	struct list_head		blocks_list;

	size_t				mb_size;	/*memory block size */
	spinlock_t			lock;

	int				init_mb_nr;	/* initial mb
							   size */
	int				curr_mb_nr;	/* current size */
	int				max_mb_nr;	/* max allowed size */
	int				alloc_quantum_nr; /* number of items
							   per allocation */
	int				used_mb_nr;
	int				align;
	int				pad;
};

struct xio_mempool {
	uint32_t			slabs_nr; /* less sentinel */
	uint32_t			flags;
	int				nodeid;
	int				safe_mt;
	struct xio_mem_slab		*slab;
};

/* Lock free algorithm based on: Maged M. Michael & Michael L. Scott's
 * Correction of a Memory Management Method for Lock-Free Data Structures
 * of John D. Valois's Lock-Free Data Structures. Ph.D. Dissertation
 */
static inline int decrement_and_test_and_set(combined_t *ptr)
{
	int old, _new;

	do {
		old  = *ptr;
		_new = old - 2;
		if (_new == 0)
			_new = 1; /* claimed be MP */
	} while (!xio_sync_bool_compare_and_swap(ptr, old, _new));

	return (old - _new) & 1;
}

/*---------------------------------------------------------------------------*/
/* clear_lowest_bit							     */
/*---------------------------------------------------------------------------*/
static inline void clear_lowest_bit(combined_t *ptr)
{
	int old, _new;

	do {
		old = *ptr;
		_new = old - 1;
	} while (!xio_sync_bool_compare_and_swap(ptr, old, _new));
}

/*---------------------------------------------------------------------------*/
/* reclaim								     */
/*---------------------------------------------------------------------------*/
static inline void reclaim(struct xio_mem_slab *slab, struct xio_mem_block *p)
{
	struct xio_mem_block *q;

	do {
		q = slab->free_blocks_list;
		p->next = q;
	} while (!xio_sync_bool_compare_and_swap(&slab->free_blocks_list,
						 q, p));
}

/*---------------------------------------------------------------------------*/
/* release								     */
/*---------------------------------------------------------------------------*/
static inline void safe_release(struct xio_mem_slab *slab,
				struct xio_mem_block *p)
{
	if (!p)
		return;

	if (decrement_and_test_and_set(&p->refcnt_claim) == 0)
		return;

	reclaim(slab, p);
}

/*---------------------------------------------------------------------------*/
/* release								     */
/*---------------------------------------------------------------------------*/
static inline void non_safe_release(struct xio_mem_slab *slab,
				    struct xio_mem_block *p)
{
	struct xio_mem_block *q;

	if (!p)
		return;

	q = slab->free_blocks_list;
	p->next = q;
	slab->free_blocks_list = p;
}

/*---------------------------------------------------------------------------*/
/* safe_read								     */
/*---------------------------------------------------------------------------*/
static struct xio_mem_block *safe_read(struct xio_mem_slab *slab)
{
	struct xio_mem_block *q;

	while (1) {
		q = slab->free_blocks_list;
		if (!q)
			return NULL;
		xio_sync_fetch_and_add32(&q->refcnt_claim, 2);
		/* make sure q is still the head */
		if (xio_sync_bool_compare_and_swap(&slab->free_blocks_list,
						   q, q))
			return q;
		safe_release(slab, q);
	}
}

/*---------------------------------------------------------------------------*/
/* new_block								     */
/*---------------------------------------------------------------------------*/
static struct xio_mem_block *safe_new_block(struct xio_mem_slab *slab)
{
	struct xio_mem_block *p;

	while (1) {
		p = safe_read(slab);
		if (!p)
			return NULL;

		if (xio_sync_bool_compare_and_swap(&slab->free_blocks_list,
						   p, p->next)) {
			clear_lowest_bit(&p->refcnt_claim);
			return p;
		}
		safe_release(slab, p);
	}
}

/*---------------------------------------------------------------------------*/
/* new_block								     */
/*---------------------------------------------------------------------------*/
static struct xio_mem_block *non_safe_new_block(struct xio_mem_slab *slab)
{
	struct xio_mem_block *p;

	if (!slab->free_blocks_list)
		return NULL;

	p = slab->free_blocks_list;
	slab->free_blocks_list = p->next;
	p->next = NULL;

	return p;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_slab_free							     */
/*---------------------------------------------------------------------------*/
static int xio_mem_slab_free(struct xio_mem_slab *slab)
{
	struct xio_mem_region *r, *tmp_r;

	slab->free_blocks_list = NULL;

#ifdef DEBUG_MEMPOOL_MT
	if (slab->used_mb_nr)
		ERROR_LOG("buffers are still in use before free: " \
			  "pool:%p - slab[%p]: " \
			  "size:%zd, used:%d, alloced:%d, max_alloc:%d\n",
			  slab->pool, slab, slab->mb_size, slab->used_mb_nr,
			  slab->curr_mb_nr, slab->max_mb_nr);
#endif

	if (slab->curr_mb_nr) {
		list_for_each_entry_safe(r, tmp_r, &slab->mem_regions_list,
					 mem_region_entry) {
			list_del(&r->mem_region_entry);
			if (test_bits(XIO_MEMPOOL_FLAG_REG_MR,
				      &slab->pool->flags)) {
				struct xio_reg_mem   reg_mem;

				reg_mem.mr = r->omr;
				xio_mem_dereg(&reg_mem);
			}

			if (test_bits(XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC,
				      &slab->pool->flags))
				ufree_huge_pages(r->buf);
			else if (test_bits(XIO_MEMPOOL_FLAG_NUMA_ALLOC,
					   &slab->pool->flags))
				unuma_free(r->buf);
			else if (test_bits(XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC,
					   &slab->pool->flags))
				ufree(r->buf);
			ufree(r);
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_slab_resize							     */
/*---------------------------------------------------------------------------*/
static struct xio_mem_block *xio_mem_slab_resize(struct xio_mem_slab *slab,
						 int alloc)
{
	char				*buf;
	struct xio_mem_region		*region;
	struct xio_mem_block		*block;
	struct xio_mem_block		*pblock;
	struct xio_mem_block		*qblock;
	struct xio_mem_block		dummy;
	int				nr_blocks;
	size_t				region_alloc_sz;
	size_t				data_alloc_sz;
	int				i;
	size_t			aligned_sz;

	if (slab->curr_mb_nr == 0) {
		if (slab->init_mb_nr > slab->max_mb_nr)
			slab->init_mb_nr = slab->max_mb_nr;
		if (slab->init_mb_nr == 0)
			nr_blocks = min(slab->max_mb_nr,
					slab->alloc_quantum_nr);
		else
			nr_blocks = slab->init_mb_nr;
	} else {
		nr_blocks =  slab->max_mb_nr - slab->curr_mb_nr;
		nr_blocks = min(nr_blocks, slab->alloc_quantum_nr);
	}
	if (nr_blocks <= 0)
		return NULL;

	region_alloc_sz = sizeof(*region) +
		nr_blocks * sizeof(struct xio_mem_block);
	buf = (char *)ucalloc(region_alloc_sz, sizeof(uint8_t));
	if (!buf)
		return NULL;

	/* region */
	region = (struct xio_mem_region *)buf;
	buf = buf + sizeof(*region);
	block = (struct xio_mem_block *)buf;

	/* region data */
	aligned_sz = ALIGN(slab->mb_size, slab->align);
	data_alloc_sz = nr_blocks * aligned_sz;

	/* allocate the buffers and register them */
	if (test_bits(XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC,
		      &slab->pool->flags))
		region->buf = umalloc_huge_pages(data_alloc_sz);
	else if (test_bits(XIO_MEMPOOL_FLAG_NUMA_ALLOC,
			   &slab->pool->flags))
		region->buf = unuma_alloc(data_alloc_sz, slab->pool->nodeid);
	else if (test_bits(XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC,
			   &slab->pool->flags))
		region->buf = umemalign(slab->align, data_alloc_sz);

	if (!region->buf) {
		ufree(region);
		return NULL;
	}

	if (test_bits(XIO_MEMPOOL_FLAG_REG_MR, &slab->pool->flags)) {
		struct xio_reg_mem reg_mem;

		xio_mem_register(region->buf, data_alloc_sz, &reg_mem);
		region->omr = reg_mem.mr;
		if (!region->omr) {
			if (test_bits(XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC,
				      &slab->pool->flags))
				ufree_huge_pages(region->buf);
			else if (test_bits(XIO_MEMPOOL_FLAG_NUMA_ALLOC,
					   &slab->pool->flags))
				unuma_free(region->buf);
			else if (test_bits(XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC,
					   &slab->pool->flags))
				ufree(region->buf);

			ufree(region);
			return NULL;
		}
	}

	qblock = &dummy;
	pblock = block;
	for (i = 0; i < nr_blocks; i++) {
		list_add(&pblock->blocks_list_entry, &slab->blocks_list);

		pblock->parent_slab = slab;
		pblock->omr	= region->omr;
		pblock->buf	= (char *)(region->buf) + i * aligned_sz;
		pblock->refcnt_claim = 1; /* free - claimed be MP */
		qblock->next = pblock;
		qblock = pblock;
		pblock++;
	}

	/* first block given to allocator */
	if (alloc) {
		if (nr_blocks == 1)
			pblock = NULL;
		else
			pblock = block + 1;
		block->next = NULL;
		/* ref count 1, not claimed by MP */
		block->refcnt_claim = 2;
	} else {
		pblock = block;
	}
	/* Concatenate [pblock -- qblock] to free list
	 * qblock points to the last allocate block
	 */

	if (slab->pool->safe_mt) {
		do {
			qblock->next = slab->free_blocks_list;
		} while (!xio_sync_bool_compare_and_swap(
					&slab->free_blocks_list,
					qblock->next, pblock));
	} else  {
		qblock->next = slab->free_blocks_list;
		slab->free_blocks_list = pblock;
	}

	slab->curr_mb_nr += nr_blocks;

	list_add(&region->mem_region_entry, &slab->mem_regions_list);

	return block;
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_destroy							     */
/*---------------------------------------------------------------------------*/
void xio_mempool_destroy(struct xio_mempool *p)
{
	unsigned int i;

	if (!p)
		return;

	for (i = 0; i < p->slabs_nr; i++)
		xio_mem_slab_free(&p->slab[i]);

	ufree(p->slab);
	ufree(p);
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_dump							     */
/*---------------------------------------------------------------------------*/
void xio_mempool_dump(struct xio_mempool *p)
{
	unsigned int		i;
	struct xio_mem_slab	*s;

	if (!p)
		return;

	DEBUG_LOG("------------------------------------------------\n");
	for (i = 0; i < p->slabs_nr; i++) {
		s = &p->slab[i];
		DEBUG_LOG("pool:%p - slab[%d]: " \
			  "size:%zd, used:%d, alloced:%d, max_alloc:%d\n",
			  p, i, s->mb_size, s->used_mb_nr,
			  s->curr_mb_nr, s->max_mb_nr);
	}
	DEBUG_LOG("------------------------------------------------\n");
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_create							     */
/*---------------------------------------------------------------------------*/
struct xio_mempool *xio_mempool_create(int nodeid, uint32_t flags)
{
	struct xio_mempool *p;

	if (test_bits(XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC, &flags)) {
		clr_bits(XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC, &flags);
		clr_bits(XIO_MEMPOOL_FLAG_NUMA_ALLOC, &flags);
		DEBUG_LOG("mempool: using huge pages allocator\n");
	} else if (test_bits(XIO_MEMPOOL_FLAG_NUMA_ALLOC, &flags)) {
		clr_bits(XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC, &flags);
		DEBUG_LOG("mempool: using numa allocator\n");
	} else {
		set_bits(XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC, &flags);
		DEBUG_LOG("mempool: using regular allocator\n");
	}

	if (test_bits(XIO_MEMPOOL_FLAG_NUMA_ALLOC, &flags)) {
		int ret;

		if (nodeid == -1) {
			int cpu = xio_get_cpu();

			nodeid = xio_numa_node_of_cpu(cpu);
		}
		/* pin to node */
		ret = xio_numa_run_on_node(nodeid);
		if (ret)
			return NULL;
	}

	p = (struct xio_mempool *)ucalloc(1, sizeof(struct xio_mempool));
	if (!p)
		return NULL;

	p->nodeid = nodeid;
	p->flags = flags;
	p->slabs_nr = 0;
	p->safe_mt = 1;
	p->slab = NULL;

	return p;
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_create_prv						     */
/*---------------------------------------------------------------------------*/
struct xio_mempool *xio_mempool_create_prv(int nodeid, uint32_t flags)
{
	struct xio_mempool	*p;
	size_t			i;
	int			ret;

	if (g_mempool_config.slabs_nr < 1 ||
	    g_mempool_config.slabs_nr > XIO_MAX_SLABS_NR) {
		xio_set_error(EINVAL);
		return NULL;
	}

	p = xio_mempool_create(nodeid, flags);
	if (!p)
		return  NULL;

	for (i = 0; i < g_mempool_config.slabs_nr; i++) {
		ret = xio_mempool_add_slab(
			p,
			g_mempool_config.slab_cfg[i].block_sz,
			g_mempool_config.slab_cfg[i].init_blocks_nr,
			g_mempool_config.slab_cfg[i].max_blocks_nr,
			g_mempool_config.slab_cfg[i].grow_blocks_nr,
			0); /*default alignment */
		if (ret != 0)
			goto cleanup;
	}

	return p;

cleanup:
	xio_mempool_destroy(p);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* size2index								     */
/*---------------------------------------------------------------------------*/
static inline int size2index(struct xio_mempool *p, size_t sz)
{
	unsigned int		i;

	for (i = 0; i <= p->slabs_nr; i++)
		if (sz <= p->slab[i].mb_size)
			break;

	return (i == p->slabs_nr) ? -1 : (int)i;
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_alloc							     */
/*---------------------------------------------------------------------------*/
int xio_mempool_alloc(struct xio_mempool *p, size_t length,
		      struct xio_reg_mem *reg_mem)
{
	int			index;
	struct xio_mem_slab	*slab;
	struct xio_mem_block	*block;
	int			ret = 0;

	index = size2index(p, length);
retry:
	if (index == -1) {
		errno = EINVAL;
		ret = -1;
		reg_mem->addr	= NULL;
		reg_mem->mr	= NULL;
		reg_mem->priv	= NULL;
		reg_mem->length	= 0;
		goto cleanup;
	}
	slab = &p->slab[index];

	if (p->safe_mt)
		block = safe_new_block(slab);
	else
		block = non_safe_new_block(slab);
	if (!block) {
		if (p->safe_mt) {
			spin_lock(&slab->lock);
		/* we may been blocked on the spinlock while other
		 * thread resized the pool
		 */
			block = safe_new_block(slab);
		} else {
			block = non_safe_new_block(slab);
		}
		if (!block) {
			block = xio_mem_slab_resize(slab, 1);
			if (!block) {
				if (++index == (int)p->slabs_nr ||
				    test_bits(
					XIO_MEMPOOL_FLAG_USE_SMALLEST_SLAB,
					&p->flags))
					index  = -1;

				if (p->safe_mt)
					spin_unlock(&slab->lock);
				ret = 0;
				goto retry;
			}
			DEBUG_LOG("resizing slab size:%zd\n", slab->mb_size);
		}
		if (p->safe_mt)
			spin_unlock(&slab->lock);
	}

	reg_mem->addr	= block->buf;
	reg_mem->mr	= block->omr;
	reg_mem->priv	= block;
	reg_mem->length	= length;

#ifdef DEBUG_MEMPOOL_MT
	__sync_fetch_and_add(&slab->used_mb_nr, 1);
	if (__sync_fetch_and_add(&block->refcnt, 1) != 0) {
		ERROR_LOG("pool alloc failed\n");
		abort(); /* core dump - double free */
	}
#else
	slab->used_mb_nr++;
#endif

cleanup:

#ifdef DEBUG_MEMPOOL_MT
	xio_mempool_dump(p);
#endif
	return ret;
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_free							     */
/*---------------------------------------------------------------------------*/
void xio_mempool_free(struct xio_reg_mem *reg_mem)
{
	struct xio_mem_block	*block;

	if (!reg_mem || !reg_mem->priv)
		return;

	block = (struct xio_mem_block *)reg_mem->priv;

#ifdef DEBUG_MEMPOOL_MT
	if (__sync_fetch_and_sub(&block->refcnt, 1) != 1) {
		ERROR_LOG("pool: release failed");
		abort(); /* core dump - double free */
	}
	__sync_fetch_and_sub(&block->parent_slab->used_mb_nr, 1);
#else
	block->parent_slab->used_mb_nr--;
#endif

	if (block->parent_slab->pool->safe_mt)
		safe_release(block->parent_slab, block);
	else
		non_safe_release(block->parent_slab, block);
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_add_slab							     */
/*---------------------------------------------------------------------------*/
int xio_mempool_add_slab(struct xio_mempool *p,
			 size_t size, size_t min, size_t max,
			 size_t alloc_quantum_nr, int alignment)
{
	struct xio_mem_slab	*new_slab;
	struct xio_mem_block	*block;
	unsigned int ix, slab_ix, slab_shift = 0;
	int align = alignment;

	slab_ix = p->slabs_nr;
	if (p->slabs_nr) {
		for (ix = 0; ix < p->slabs_nr; ++ix) {
			if (p->slab[ix].mb_size == size) {
				xio_set_error(EEXIST);
				return -1;
			}
			if (p->slab[ix].mb_size > size) {
				slab_ix = ix;
				break;
			}
		}
	}
	if (!alignment) {
		align = g_options.xfer_buf_align;
	} else if (!is_power_of_2(alignment) ||
		   !(alignment % sizeof(void *) == 0)) {
		ERROR_LOG("invalid alignment %d\n", alignment);
		xio_set_error(EINVAL);
		return -1;
	}

	/* expand */
	new_slab = (struct xio_mem_slab *)ucalloc(p->slabs_nr + 2,
						  sizeof(struct xio_mem_slab));
	if (!new_slab) {
		xio_set_error(ENOMEM);
		return -1;
	}

	/* fill/shift slabs */
	for (ix = 0; ix < p->slabs_nr + 1; ++ix) {
		if (ix == slab_ix) {
			/* new slab */
			new_slab[ix].pool = p;
			new_slab[ix].mb_size = size;
			new_slab[ix].init_mb_nr = min;
			new_slab[ix].max_mb_nr = max;
			new_slab[ix].alloc_quantum_nr = alloc_quantum_nr;
			new_slab[ix].align = align;

			spin_lock_init(&new_slab[ix].lock);
			INIT_LIST_HEAD(&new_slab[ix].mem_regions_list);
			INIT_LIST_HEAD(&new_slab[ix].blocks_list);
			new_slab[ix].free_blocks_list = NULL;
			if (new_slab[ix].init_mb_nr) {
				(void)xio_mem_slab_resize(
					&new_slab[ix], 0);
			}
			/* src adjust */
			slab_shift = 1;
			continue;
		}
		/* shift it */
		new_slab[ix] = p->slab[ix - slab_shift];
		INIT_LIST_HEAD(&new_slab[ix].mem_regions_list);
		list_splice_init(&p->slab[ix - slab_shift].mem_regions_list,
				 &new_slab[ix].mem_regions_list);
		INIT_LIST_HEAD(&new_slab[ix].blocks_list);
		list_splice_init(&p->slab[ix - slab_shift].blocks_list,
				 &new_slab[ix].blocks_list);
		list_for_each_entry(block, &new_slab[ix].blocks_list,
				    blocks_list_entry) {
			block->parent_slab = &new_slab[ix];
		}
	}

	/* sentinel */
	new_slab[p->slabs_nr + 1].mb_size = SIZE_MAX;

	/* swap slabs */
	ufree(p->slab);
	p->slab = new_slab;

	/* adjust length */
	(p->slabs_nr)++;

	return 0;
}

