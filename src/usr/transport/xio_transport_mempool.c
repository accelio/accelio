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
#include "xio_log.h"
#include "xio_common.h"
#include "xio_mem.h"
#include "xio_usr_utils.h"

/* Accelio's default mempool profile (don't expose it) */
#define XIO_MEM_SLOTS_NR	4

#define XIO_16K_BLOCK_SZ	(16*1024)
#define XIO_16K_MIN_NR		0
#define XIO_16K_MAX_NR		(1024*24)
#define XIO_16K_ALLOC_NR	128

#define XIO_64K_BLOCK_SZ	(64*1024)
#define XIO_64K_MIN_NR		0
#define XIO_64K_MAX_NR		(1024*24)
#define XIO_64K_ALLOC_NR	128

#define XIO_256K_BLOCK_SZ	(256*1024)
#define XIO_256K_MIN_NR		0
#define XIO_256K_MAX_NR		(1024*24)
#define XIO_256K_ALLOC_NR	128

#define XIO_1M_BLOCK_SZ		(1024*1024)
#define XIO_1M_MIN_NR		0
#define XIO_1M_MAX_NR		(1024*24)
#define XIO_1M_ALLOC_NR		128

//#define DEBUG_MEMPOOL_MT

/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
typedef volatile int combined_t;

struct xio_mem_block {
	struct xio_mem_slot		*parent_slot;
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

struct xio_mem_slot {
	struct xio_mempool		*pool;
	struct list_head		mem_regions_list;
	struct xio_mem_block		*free_blocks_list;
	struct list_head		blocks_list;

	size_t				mb_size;	/*memory block size */
	pthread_spinlock_t		lock;

	int				init_mb_nr;	/* initial mb
							   size */
	int				curr_mb_nr;	/* current size */
	int				max_mb_nr;	/* max allowed size */
	int				alloc_quantum_nr; /* number of items
							   per allocation */
	int				used_mb_nr;
};

struct xio_mempool {
	uint32_t			slots_nr; /* less sentinel */
	uint32_t			flags;
	int				nodeid;
	int				safe_mt;
	struct xio_mem_slot		*slot;
};

/* Lock free algorithm based on: Maged M. Michael & Michael L. Scott's
 * Correction of a Memory Management Method for Lock-Free Data Structures
 * of John D. Valois's Lock-Free Data Structures. Ph.D. Dissertation
 */
static inline int decrement_and_test_and_set(combined_t *ptr)
{
	int old, new;

	do {
		old = *ptr;
		new = old - 2;
		if (new == 0)
			new = 1; /* claimed be MP */
	} while (!__sync_bool_compare_and_swap(ptr, old, new));

	return (old - new) & 1;
}

/*---------------------------------------------------------------------------*/
/* clear_lowest_bit							     */
/*---------------------------------------------------------------------------*/
static inline void clear_lowest_bit(combined_t *ptr)
{
	int old, new;

	do {
		old = *ptr;
		new = old - 1;
	} while (!__sync_bool_compare_and_swap(ptr, old, new));
}

/*---------------------------------------------------------------------------*/
/* reclaim								     */
/*---------------------------------------------------------------------------*/
static inline void reclaim(struct xio_mem_slot *slot, struct xio_mem_block *p)
{
	struct xio_mem_block *q;

	do {
		q = slot->free_blocks_list;
		p->next = q;
	} while (!__sync_bool_compare_and_swap(&slot->free_blocks_list, q, p));
}

/*---------------------------------------------------------------------------*/
/* release								     */
/*---------------------------------------------------------------------------*/
static inline void safe_release(struct xio_mem_slot *slot,
				struct xio_mem_block *p)
{
	if (!p)
		return;

	if (decrement_and_test_and_set(&p->refcnt_claim) == 0)
		return;

	reclaim(slot, p);
}

/*---------------------------------------------------------------------------*/
/* release								     */
/*---------------------------------------------------------------------------*/
static inline void non_safe_release(struct xio_mem_slot *slot,
				    struct xio_mem_block *p)
{
	struct xio_mem_block *q;

	if (!p)
		return;

	q = slot->free_blocks_list;
	p->next = q;
	slot->free_blocks_list = p;
}

/*---------------------------------------------------------------------------*/
/* safe_read								     */
/*---------------------------------------------------------------------------*/
static struct xio_mem_block *safe_read(struct xio_mem_slot *slot)
{
	struct xio_mem_block *q;

	while (1) {
		q = slot->free_blocks_list;
		if (q == NULL)
			return NULL;
		__sync_fetch_and_add(&q->refcnt_claim, 2);
		/* make sure q is still the head */
		if (__sync_bool_compare_and_swap(&slot->free_blocks_list, q, q))
			return q;
		else
			safe_release(slot, q);
	}
}

/*---------------------------------------------------------------------------*/
/* new_block								     */
/*---------------------------------------------------------------------------*/
static struct xio_mem_block *safe_new_block(struct xio_mem_slot *slot)
{
	struct xio_mem_block *p;

	while (1) {
		p = safe_read(slot);
		if (p == NULL)
			return NULL;

		if (__sync_bool_compare_and_swap(&slot->free_blocks_list,
						 p, p->next)) {
			clear_lowest_bit(&p->refcnt_claim);
			return p;
		} else {
			safe_release(slot, p);
		}
	}
}

/*---------------------------------------------------------------------------*/
/* new_block								     */
/*---------------------------------------------------------------------------*/
static struct xio_mem_block *non_safe_new_block(struct xio_mem_slot *slot)
{
	struct xio_mem_block *p;

	if (slot->free_blocks_list == NULL)
		return NULL;

	p = slot->free_blocks_list;
        slot->free_blocks_list = p->next;
	p->next = NULL;

	return p;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_slot_free							     */
/*---------------------------------------------------------------------------*/
static int xio_mem_slot_free(struct xio_mem_slot *slot)
{
	struct xio_mem_region *r, *tmp_r;

	slot->free_blocks_list = NULL;

#ifdef DEBUG_MEMPOOL_MT
	if (slot->used_mb_nr)
		ERROR_LOG("buffers are still in use before free: " \
			  "pool:%p - slot[%p]: " \
			  "size:%zd, used:%d, alloced:%d, max_alloc:%d\n",
			  slot->pool, slot, slot->mb_size, slot->used_mb_nr,
			  slot->curr_mb_nr, slot->max_mb_nr);
#endif

	if (slot->curr_mb_nr) {
		list_for_each_entry_safe(r, tmp_r, &slot->mem_regions_list,
					 mem_region_entry) {
			list_del(&r->mem_region_entry);
			if (slot->pool->flags & XIO_MEMPOOL_FLAG_REG_MR)
				xio_dereg_mr(&r->omr);

			if (slot->pool->flags &
					XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC)
				ufree_huge_pages(r->buf);
			else if (slot->pool->flags &
					XIO_MEMPOOL_FLAG_NUMA_ALLOC)
				unuma_free(r->buf);
			else if (slot->pool->flags &
					XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC)
				ufree(r->buf);
			ufree(r);
		}
	}

	pthread_spin_destroy(&slot->lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mem_slot_resize							     */
/*---------------------------------------------------------------------------*/
static struct xio_mem_block *xio_mem_slot_resize(struct xio_mem_slot *slot,
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

	if (slot->curr_mb_nr == 0) {
		if (slot->init_mb_nr > slot->max_mb_nr)
			slot->init_mb_nr = slot->max_mb_nr;
		if (slot->init_mb_nr == 0)
			nr_blocks = min(slot->max_mb_nr,
					slot->alloc_quantum_nr);
		else
			nr_blocks = slot->init_mb_nr;
	} else {
		nr_blocks =  slot->max_mb_nr - slot->curr_mb_nr;
		nr_blocks = min(nr_blocks, slot->alloc_quantum_nr);
	}
	if (nr_blocks <= 0)
		return NULL;

	region_alloc_sz = sizeof(*region) +
		nr_blocks*sizeof(struct xio_mem_block);
	buf = ucalloc(region_alloc_sz, sizeof(uint8_t));
	if (buf == NULL)
		return NULL;

	/* region */
	region = (void *)buf;
	buf = buf + sizeof(*region);
	block = (void *)buf;

	/* region data */
	data_alloc_sz = nr_blocks*slot->mb_size;

	/* allocate the buffers and register them */
	if (slot->pool->flags & XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC) {
		region->buf = umalloc_huge_pages(data_alloc_sz);
	} else if (slot->pool->flags & XIO_MEMPOOL_FLAG_NUMA_ALLOC) {
		region->buf = unuma_alloc(data_alloc_sz, slot->pool->nodeid);
	} else if (slot->pool->flags & XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC) {
		/*region->buf = ucalloc(data_alloc_sz, sizeof(uint8_t)); */
		region->buf = umemalign(64, data_alloc_sz);
	}

	if (region->buf == NULL) {
		ufree(region);
		return NULL;
	}

	if (slot->pool->flags & XIO_MEMPOOL_FLAG_REG_MR) {
		region->omr = xio_reg_mr(region->buf, data_alloc_sz);
		if (region->omr == NULL) {
			if (slot->pool->flags &
					XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC)
				ufree_huge_pages(region->buf);
			else if (slot->pool->flags &
					XIO_MEMPOOL_FLAG_NUMA_ALLOC)
				unuma_free(region->buf);
			else if (slot->pool->flags &
					XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC)
				ufree(region->buf);

			ufree(region);
			return NULL;
		}
	}

	qblock = &dummy;
	pblock = block;
	for (i = 0; i < nr_blocks; i++) {
		list_add(&pblock->blocks_list_entry, &slot->blocks_list);

		pblock->parent_slot = slot;
		pblock->omr	= region->omr;
		pblock->buf	= (char *)(region->buf) + i*slot->mb_size;
		pblock->refcnt_claim = 1; /* free - claimed be MP */
		qblock->next = pblock;
		qblock = pblock;
		pblock++;
	}

	/* first block given to allocator */
	if (alloc) {
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

	if (slot->pool->safe_mt) {
		do {
			qblock->next = slot->free_blocks_list;
		} while (!__sync_bool_compare_and_swap(&slot->free_blocks_list,
					qblock->next, pblock));
	} else  {
		qblock->next = slot->free_blocks_list;
		slot->free_blocks_list = pblock;
	}

	slot->curr_mb_nr += nr_blocks;

	list_add(&region->mem_region_entry, &slot->mem_regions_list);

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

	for (i = 0; i < p->slots_nr; i++)
		xio_mem_slot_free(&p->slot[i]);

	ufree(p->slot);
	ufree(p);
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_dump							     */
/*---------------------------------------------------------------------------*/
void xio_mempool_dump(struct xio_mempool *p)
{
	unsigned int		i;
	struct xio_mem_slot	*s;

	if (!p)
		return;

	DEBUG_LOG("------------------------------------------------\n");
	for (i = 0; i < p->slots_nr; i++) {
		s = &p->slot[i];
		DEBUG_LOG("pool:%p - slot[%d]: " \
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

	if (flags & XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC) {
		flags &= ~XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC;
		flags &= ~XIO_MEMPOOL_FLAG_NUMA_ALLOC;
		DEBUG_LOG("mempool: using huge pages allocator\n");
	} else if (flags & XIO_MEMPOOL_FLAG_NUMA_ALLOC) {
		flags &= ~XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC;
		flags &= ~XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC;
		DEBUG_LOG("mempool: using numa allocator\n");
	} else {
		flags &= ~XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC;
		flags &= ~XIO_MEMPOOL_FLAG_NUMA_ALLOC;
		flags |= XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC;
		DEBUG_LOG("mempool: using regular allocator\n");
	}

	if (flags & XIO_MEMPOOL_FLAG_NUMA_ALLOC) {
		int ret;
		if (nodeid == -1) {
			int cpu = xio_get_cpu();
			nodeid = numa_node_of_cpu(cpu);
		}
		/* pin to node */
		ret = numa_run_on_node(nodeid);
		if (ret)
			return NULL;
	}

	p = ucalloc(1, sizeof(struct xio_mempool));
	if (p == NULL)
		return NULL;

	p->nodeid = nodeid;
	p->flags = flags;
	p->slots_nr = 0;
	p->safe_mt = 1;
	p->slot = NULL;

	return p;
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_create_prv						     */
/*---------------------------------------------------------------------------*/
struct xio_mempool *xio_mempool_create_prv(int nodeid, uint32_t flags)
{
	struct xio_mempool	*p;
	int			i;
	int			ret;

	if (flags & XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC) {
		flags &= ~XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC;
		flags &= ~XIO_MEMPOOL_FLAG_NUMA_ALLOC;
		DEBUG_LOG("mempool: using huge pages allocator\n");
	} else if (flags & XIO_MEMPOOL_FLAG_NUMA_ALLOC) {
		flags &= ~XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC;
		flags &= ~XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC;
		DEBUG_LOG("mempool: using numa allocator\n");
	} else {
		flags &= ~XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC;
		flags &= ~XIO_MEMPOOL_FLAG_NUMA_ALLOC;
		flags |= XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC;
		DEBUG_LOG("mempool: using regular allocator\n");
	}
	if (flags & XIO_MEMPOOL_FLAG_NUMA_ALLOC) {
		int ret;
		if (nodeid == -1) {
			int cpu = xio_get_cpu();
			nodeid = numa_node_of_cpu(cpu);
		}
		/* pin to node */
		ret = numa_run_on_node(nodeid);
		if (ret)
			return NULL;
	}
	p = ucalloc(1, sizeof(struct xio_mempool));
	if (p == NULL)
		return NULL;

	p->nodeid = nodeid;
	p->flags = flags;
	p->safe_mt = 0;
	p->slots_nr = XIO_MEM_SLOTS_NR;
	p->slot = (struct xio_mem_slot *)ucalloc(p->slots_nr+1,
						 sizeof(struct xio_mem_slot));

	p->slot[0].pool			= p;
	p->slot[0].mb_size		= XIO_16K_BLOCK_SZ;
	p->slot[0].init_mb_nr		= XIO_16K_MIN_NR;
	p->slot[0].max_mb_nr		= XIO_16K_MAX_NR;
	p->slot[0].alloc_quantum_nr	= XIO_16K_ALLOC_NR;

	p->slot[1].pool			= p;
	p->slot[1].mb_size		= XIO_64K_BLOCK_SZ;
	p->slot[1].init_mb_nr		= XIO_64K_MIN_NR;
	p->slot[1].max_mb_nr		= XIO_64K_MAX_NR;
	p->slot[1].alloc_quantum_nr	= XIO_64K_ALLOC_NR;

	p->slot[2].pool			= p;
	p->slot[2].mb_size		= XIO_256K_BLOCK_SZ;
	p->slot[2].init_mb_nr		= XIO_256K_MIN_NR;
	p->slot[2].max_mb_nr		= XIO_256K_MAX_NR;
	p->slot[2].alloc_quantum_nr	= XIO_256K_ALLOC_NR;

	p->slot[3].pool			= p;
	p->slot[3].mb_size		= XIO_1M_BLOCK_SZ;
	p->slot[3].init_mb_nr		= XIO_1M_MIN_NR;
	p->slot[3].max_mb_nr		= XIO_1M_MAX_NR;
	p->slot[3].alloc_quantum_nr	= XIO_1M_ALLOC_NR;

	p->slot[4].mb_size		= SIZE_MAX;

	for (i = p->slots_nr - 1; i >= 0; i--) {
		ret = pthread_spin_init(&p->slot[i].lock,
					PTHREAD_PROCESS_PRIVATE);
		if (ret != 0)
			goto cleanup;
		INIT_LIST_HEAD(&p->slot[i].mem_regions_list);
		INIT_LIST_HEAD(&p->slot[i].blocks_list);
		p->slot[i].free_blocks_list = NULL;
		if (p->slot[i].init_mb_nr) {
			if (xio_mem_slot_resize(&p->slot[i], 0) == NULL)
				goto cleanup;
		}
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

	for (i = 0; i <= p->slots_nr; i++)
		if (sz <= p->slot[i].mb_size)
			break;

	return (i == p->slots_nr) ? -1 : (int)i;
}


/*---------------------------------------------------------------------------*/
/* xio_mempool_alloc							     */
/*---------------------------------------------------------------------------*/
int xio_mempool_alloc(struct xio_mempool *p, size_t length,
		      struct xio_mempool_obj *mp_obj)
{
	int			index;
	struct xio_mem_slot	*slot;
	struct xio_mem_block	*block;
	int			ret = 0;
#ifdef DEBUG_MEMPOOL_MT
	int			val;
#endif

	index = size2index(p, length);
retry:
	if (index == -1) {
		errno = EINVAL;
		ret = -1;
		mp_obj->addr	= NULL;
		mp_obj->mr	= NULL;
		mp_obj->cache	= NULL;
		mp_obj->length	= 0;
		goto cleanup;
	}
	slot = &p->slot[index];

	if (p->safe_mt)
		block = safe_new_block(slot);
	else
		block = non_safe_new_block(slot);
	if (!block) {
		if (p->safe_mt) {
			pthread_spin_lock(&slot->lock);
		/* we may been blocked on the spinlock while other
		 * thread resized the pool
		 */
			block = safe_new_block(slot);
		} else
			block = non_safe_new_block(slot);
		if (!block) {
			block = xio_mem_slot_resize(slot, 1);
			if (block == NULL) {
				if (++index == (int)p->slots_nr)
					index  = -1;

				if (p->safe_mt)
					pthread_spin_unlock(&slot->lock);
				ret = 0;
				goto retry;
			}
			DEBUG_LOG("resizing slot size:%zd\n", slot->mb_size);
		}
		if (p->safe_mt)
			pthread_spin_unlock(&slot->lock);
	}

	mp_obj->addr	= block->buf;
	mp_obj->mr	= block->omr;
	mp_obj->cache	= block;
	mp_obj->length	= length;

#ifdef DEBUG_MEMPOOL_MT
	__sync_fetch_and_add(&slot->used_mb_nr, 1);
	if ((val =__sync_fetch_and_add(&block->refcnt, 1)) != 0) {
		ERROR_LOG("pool alloc: refcnt:%d\n", val);
		abort(); /* core dump - double free */
	}
#else
	slot->used_mb_nr++;
#endif

cleanup:

#ifdef DEBUG_MEMPOOL_MT
	xio_mempool_dump(p);
#endif
	return ret;
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_free						     */
/*---------------------------------------------------------------------------*/
void xio_mempool_free(struct xio_mempool_obj *mp_obj)
{
	struct xio_mem_block	*block;
#ifdef DEBUG_MEMPOOL_MT
	int			val;
#endif


	if (!mp_obj || !mp_obj->cache)
		return;

	block = mp_obj->cache;

#ifdef DEBUG_MEMPOOL_MT
	if ((val = __sync_fetch_and_sub(&block->refcnt, 1)) != 1) {
		ERROR_LOG("pool: release refcnt:%d\n", val);
		abort(); /* core dump - double free */
	}
	__sync_fetch_and_sub(&block->parent_slot->used_mb_nr, 1);
#else
	block->parent_slot->used_mb_nr--;
#endif

	if (block->parent_slot->pool->safe_mt)
		safe_release(block->parent_slot, block);
	else
		non_safe_release(block->parent_slot, block);
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_add_allocator					     */
/*---------------------------------------------------------------------------*/
int xio_mempool_add_allocator(struct xio_mempool *p,
			      size_t size, size_t min, size_t max,
			      size_t alloc_quantum_nr)
{
	struct xio_mem_slot	*new_slot;
	struct xio_mem_block	*block;
	unsigned int ix, slot_ix, slot_shift = 0;

	slot_ix = p->slots_nr;
	if (p->slots_nr) {
		for (ix = 0; ix < p->slots_nr; ++ix) {
			if (p->slot[ix].mb_size == size)
				return -EEXIST;
			if (p->slot[ix].mb_size > size) {
				slot_ix = ix;
				break;
			}
		}
	}

	/* expand */
	new_slot = (struct xio_mem_slot *)ucalloc(p->slots_nr + 2,
						  sizeof(struct xio_mem_slot));
	/* fill/shift slots */
	for (ix = 0; ix < p->slots_nr + 1; ++ix) {
		if (ix == slot_ix) {
			/* new slot */
			new_slot[ix].pool = p;
			new_slot[ix].mb_size = size;
			new_slot[ix].init_mb_nr = min;
			new_slot[ix].max_mb_nr = max;
			new_slot[ix].alloc_quantum_nr = alloc_quantum_nr;

			(void) pthread_spin_init(&new_slot[ix].lock,
						 PTHREAD_PROCESS_PRIVATE);
			INIT_LIST_HEAD(&new_slot[ix].mem_regions_list);
			INIT_LIST_HEAD(&new_slot[ix].blocks_list);
			new_slot[ix].free_blocks_list = NULL;
			if (new_slot[ix].init_mb_nr) {
				(void) xio_mem_slot_resize(
					&new_slot[ix], 0);
			}
			/* src adjust */
			slot_shift = 1;
			continue;
		}
		/* shift it */
		new_slot[ix] = p->slot[ix-slot_shift];
		INIT_LIST_HEAD(&new_slot[ix].mem_regions_list);
		list_splice_init(&p->slot[ix-slot_shift].mem_regions_list,
				 &new_slot[ix].mem_regions_list);
		INIT_LIST_HEAD(&new_slot[ix].blocks_list);
		list_splice_init(&p->slot[ix-slot_shift].blocks_list,
				 &new_slot[ix].blocks_list);
		list_for_each_entry(block, &new_slot[ix].blocks_list,
				    blocks_list_entry) {
			block->parent_slot = &new_slot[ix];
		}
	}

	/* sentinel */
	new_slot[p->slots_nr+1].mb_size	= SIZE_MAX;

	/* swap slots */
	ufree(p->slot);
	p->slot = new_slot;

	/* adjust length */
	(p->slots_nr)++;

	return 0;
}

