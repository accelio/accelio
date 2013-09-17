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

#define VEC_ALLOC_SZ 128

/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
struct xio_chunk_desc {
	struct xio_chunk		*chunk;
	void				*base_addr;
	void				*end_addr;
};

struct xio_chunks_vec {
	struct xio_chunk_desc		*vec;
	int				vec_sz;
	int				chunks_nr;
};

struct xio_chunk {
	struct xio_rdma_mempool		*parent_pool;
	size_t				block_sz;
	int				nr_blocks;
	int				max_depth;

	struct xio_mr			*omr;
	void				*base_addr;
	void				*end_addr;

	/* pool of tasks */
	void				**array;
	/* LIFO */
	void				**stack;

	void				**stack_ptr;
	void				**stack_end;

	struct list_head		chunks_list_entry;
};

struct xio_chunks_list {
	struct list_head		chunks_list;

	size_t				chunk_sz;

	int				initial_nr;	/* initial chunks
							   size */
	int				curr_nr;	/* current size */
	int				max_nr;		/* max allowed size */
	int				alloc_nr;	/* number of items
							   per allcoation */
};

struct xio_rdma_mempool {
	struct xio_chunks_list		pool[XIO_CHUNKS_SIZE_NR + 1];
	struct xio_chunks_vec		*chunks_vec;
	pthread_spinlock_t		lock;
	uint32_t			pad;
};

/*---------------------------------------------------------------------------*/
/* chunk api								     */
/*---------------------------------------------------------------------------*/
static struct xio_chunk *xio_rdma_chunk_create(struct xio_rdma_mempool *p,
					       int nr_blocks, size_t block_sz);
static inline void	xio_rdma_chunk_destroy(struct xio_chunk *chunk);
static inline void	*xio_rdma_chunk_alloc(struct xio_chunk *chunk);
static inline void	xio_rdma_chunk_free(struct xio_chunk *chunk, void *mem);

/*---------------------------------------------------------------------------*/
/* chunks_vec api							     */
/*---------------------------------------------------------------------------*/
static struct xio_chunks_vec *xio_chunks_vec_create();
static inline void	xio_chunks_vec_destroy(struct xio_chunks_vec *v);
static inline void	xio_chunks_vec_resize(struct xio_chunks_vec *v);
static void		xio_chunks_vec_insert(struct xio_chunks_vec *v,
					      struct xio_chunk *chunk);
/*---------------------------------------------------------------------------*/
/* xio_chunks_vec_create						     */
/*---------------------------------------------------------------------------*/
static struct xio_chunks_vec *xio_chunks_vec_create()
{
	struct xio_chunks_vec	*v;

	v = calloc(1, sizeof(struct xio_chunks_vec));
	if (v == NULL)
		return NULL;

	v->vec = calloc(VEC_ALLOC_SZ, sizeof(struct xio_chunk_desc));
	if (v->vec == NULL)
		return NULL;
	v->vec_sz = VEC_ALLOC_SZ;
	v->chunks_nr = 0;

	return v;
}

/*---------------------------------------------------------------------------*/
/* xio_chunks_vec_destroy						     */
/*---------------------------------------------------------------------------*/
static inline void xio_chunks_vec_destroy(struct xio_chunks_vec *v)
{
	free(v->vec);
	free(v);
}

/*---------------------------------------------------------------------------*/
/* xio_chunks_vec_resize						     */
/*---------------------------------------------------------------------------*/
static inline void xio_chunks_vec_resize(struct xio_chunks_vec *v)
{
	v->vec_sz += VEC_ALLOC_SZ;
	v->vec = realloc(v->vec, v->vec_sz*sizeof(struct xio_chunk_desc));
}

/*---------------------------------------------------------------------------*/
/* xio_chunks_vec_insert						     */
/*---------------------------------------------------------------------------*/
static void xio_chunks_vec_insert(struct xio_chunks_vec *v,
			      struct xio_chunk *chunk)
{
	int c, d;
	struct xio_chunk_desc t;

	/* Insertion sort algorithm */
	if (v->chunks_nr == v->vec_sz)
		xio_chunks_vec_resize(v);


	v->vec[v->chunks_nr].chunk	= chunk;
	v->vec[v->chunks_nr].base_addr  = chunk->base_addr;
	v->vec[v->chunks_nr].end_addr	= chunk->end_addr;
	v->chunks_nr++;

	for (c = 1; c <= v->chunks_nr - 1; c++) {
		d = c;
		while (d > 0 && v->vec[d].base_addr < v->vec[d-1].base_addr) {
			t		= v->vec[d];
			v->vec[d]	= v->vec[d-1];
			v->vec[d-1]	= t;

			d--;
		}
	}
}
/*---------------------------------------------------------------------------*/
/* xio_rdma_chunk_create						     */
/*---------------------------------------------------------------------------*/
static struct xio_chunk *xio_rdma_chunk_create(
		struct xio_rdma_mempool *parent_pool,
		int nr_blocks, size_t block_sz)
{
	int				i;
	char				*buf;
	char				*data;
	struct xio_chunk		*q;
	size_t				elems_alloc_sz;


	/* pool + private data */
	size_t pool_alloc_sz = sizeof(*q) +
				2*nr_blocks*sizeof(void *);

	buf = calloc(pool_alloc_sz, sizeof(uint8_t));
	if (buf == NULL)
		return NULL;

	/* pool */
	q = (void *)buf;
	buf = buf + sizeof(*q);

	/* stack */
	q->stack = (void *)buf;
	buf = buf + nr_blocks*sizeof(void *);

	/* array */
	q->array = (void *)buf;
	buf = buf + nr_blocks*sizeof(void *);

	/* pool data */
	elems_alloc_sz = nr_blocks*block_sz;

	/* alocate the buffer and register them */
	data = malloc_huge_pages(elems_alloc_sz);
	if (data == NULL)
		return NULL;

	q->base_addr	= data;
	q->end_addr	= data + elems_alloc_sz;

	q->omr = xio_reg_mr(data, elems_alloc_sz);

	for (i = 0; i < nr_blocks; i++) {
		q->array[i]		= data;
		q->stack[i]		= q->array[i];
		data = ((char *)data) + block_sz;
	}

	q->stack_ptr	= &q->stack[0];
	q->stack_end	= &q->stack[nr_blocks];
	q->nr_blocks	= nr_blocks;
	q->block_sz	= block_sz;
	q->parent_pool	= parent_pool;

	return q;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_chunk_destroy						     */
/*---------------------------------------------------------------------------*/
static inline void xio_rdma_chunk_destroy(struct xio_chunk *q)
{
	xio_dereg_mr(&q->omr);
	if (q->nr_blocks)
		free_huge_pages(q->array[0]);
	free(q);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_chunk_alloc							     */
/*---------------------------------------------------------------------------*/
static inline void *xio_rdma_chunk_alloc(struct xio_chunk *q)
{
	int cur_depth = (q->stack_ptr - &q->stack[0]);
	if (cur_depth > q->max_depth)
		q->max_depth = cur_depth;

	return (q->stack_ptr != q->stack_end) ?
		*q->stack_ptr++ : NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_chunk_free							     */
/*---------------------------------------------------------------------------*/
static inline void xio_rdma_chunk_free(struct xio_chunk *q, void *t)
{
	assert(q->stack_ptr != q->stack);

	*--q->stack_ptr = t;
}
/*---------------------------------------------------------------------------*/
/* xio_rdma_mempol_create						     */
/*---------------------------------------------------------------------------*/
struct xio_rdma_mempool *xio_rdma_mempool_create(void)
{
	struct xio_rdma_mempool *p;
	struct xio_chunk	*q;
	int			i;
	int			ret;
	pthread_spinlock_t	lock;

	/* create alloc /free lock */
	ret = pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE);
	if (ret != 0)
		return NULL;

	p = calloc(1, sizeof(struct xio_rdma_mempool));
	if (p == NULL) {
		pthread_spin_destroy(&lock);
		return NULL;
	}

	p->chunks_vec = xio_chunks_vec_create();
	if (p->chunks_vec == NULL) {
		pthread_spin_destroy(&lock);
		free(p);
		return NULL;
	}
	p->lock				= lock;

	p->pool[0].chunk_sz		= XIO_16K_BLOCK_SZ;
	p->pool[0].initial_nr		= XIO_16K_MIN_NR;
	p->pool[0].max_nr		= XIO_16K_MAX_NR;
	p->pool[0].alloc_nr		= XIO_16K_ALLOC_NR;

	p->pool[1].chunk_sz		= XIO_64K_BLOCK_SZ;
	p->pool[1].initial_nr		= XIO_64K_MIN_NR;
	p->pool[1].max_nr		= XIO_64K_MAX_NR;
	p->pool[1].alloc_nr		= XIO_64K_ALLOC_NR;

	p->pool[2].chunk_sz		= XIO_256K_BLOCK_SZ;
	p->pool[2].initial_nr		= XIO_256K_MIN_NR;
	p->pool[2].max_nr		= XIO_256K_MAX_NR;
	p->pool[2].alloc_nr		= XIO_256K_ALLOC_NR;

	p->pool[3].chunk_sz		= XIO_1M_BLOCK_SZ;
	p->pool[3].initial_nr		= XIO_1M_MIN_NR;
	p->pool[3].max_nr		= XIO_1M_MAX_NR;
	p->pool[3].alloc_nr		= XIO_1M_ALLOC_NR;

	p->pool[4].chunk_sz		= SIZE_MAX;

	for (i = XIO_CHUNKS_SIZE_NR - 1; i >= 0; i--) {
		INIT_LIST_HEAD(&p->pool[i].chunks_list);
		q = xio_rdma_chunk_create(
				p,
				p->pool[i].initial_nr,
				p->pool[i].chunk_sz);
		if (q == NULL)
			goto cleanup;


		list_add_tail(&q->chunks_list_entry, &p->pool[i].chunks_list);
		p->pool[i].curr_nr = p->pool[i].initial_nr;
		xio_chunks_vec_insert(p->chunks_vec, q);
	}

	return p;
cleanup:
	xio_rdma_mempool_destroy(p);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_destroy						     */
/*---------------------------------------------------------------------------*/
void xio_rdma_mempool_destroy(struct xio_rdma_mempool *p)
{
	struct xio_chunks_list	*chunk_list;
	struct xio_chunk	*q, *tmp_q;
	int			i;


	if (!p)
		return;

	for (i = 0; i < XIO_CHUNKS_SIZE_NR; i++) {
		chunk_list = &p->pool[i];
		list_for_each_entry_safe(q, tmp_q, &chunk_list->chunks_list,
					 chunks_list_entry) {
			list_del(&q->chunks_list_entry);
			xio_rdma_chunk_destroy(q);
		}
	}

	xio_chunks_vec_destroy(p->chunks_vec);
	pthread_spin_destroy(&p->lock);

	free(p);
}

/*---------------------------------------------------------------------------*/
/* size2index								     */
/*---------------------------------------------------------------------------*/
static inline int size2index(struct xio_rdma_mempool *p, size_t sz)
{
	int i;

	for (i = 0; i <= XIO_CHUNKS_SIZE_NR; i++)
		if (sz <= p->pool[i].chunk_sz)
			break;

	return (i == XIO_CHUNKS_SIZE_NR) ? -1 : i;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_alloc						     */
/*---------------------------------------------------------------------------*/
int xio_rdma_mempool_alloc(struct xio_rdma_mempool *p, size_t length,
			   struct xio_rdma_mp_mem *mp_mem)
{
	int			index;
	struct xio_chunk	*q;
	struct xio_chunks_list	*chunk_list;
	void			*mem;
	int			ret;

	mp_mem->addr = NULL;
	mp_mem->mr = NULL;
	mp_mem->cache = NULL;
	mp_mem->length = 0;

	index = size2index(p, length);
	if (index == -1) {
		errno = EINVAL;
		return -1;
	}

	chunk_list = &p->pool[index];

	ret = pthread_spin_lock(&p->lock);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	list_for_each_entry(q, &chunk_list->chunks_list, chunks_list_entry) {
		mem = xio_rdma_chunk_alloc(q);
		if (mem != NULL) {
			mp_mem->addr = mem;
			mp_mem->mr = q->omr;
			mp_mem->cache = q;
			mp_mem->length = length;
			goto exit;
		}
	}
	printf("going to create new chunk for size:%zd\n",
	       chunk_list->chunk_sz);

	if ((chunk_list->curr_nr + chunk_list->alloc_nr) < chunk_list->max_nr) {
		q = xio_rdma_chunk_create(
				p,
				chunk_list->alloc_nr,
				chunk_list->chunk_sz);
		if (q == NULL)
			goto exit1;

		chunk_list->curr_nr += chunk_list->alloc_nr;

		list_add_tail(&q->chunks_list_entry, &chunk_list->chunks_list);
		xio_chunks_vec_insert(p->chunks_vec, q);

		mem = xio_rdma_chunk_alloc(q);
		if (mem != NULL) {
			mp_mem->addr = mem;
			mp_mem->mr = q->omr;
			mp_mem->cache = q;
			mp_mem->length = length;
			goto exit;
		}
	}

exit1:
	pthread_spin_unlock(&p->lock);
	errno = ENOMEM;
	return -1;
exit:
	pthread_spin_unlock(&p->lock);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_free						     */
/*---------------------------------------------------------------------------*/
void xio_rdma_mempool_free(struct xio_rdma_mp_mem *mp_mem)
{
	struct xio_chunk *q;

	if (!mp_mem)
		return;

	q = mp_mem->cache;
	if (q != NULL) {
		pthread_spin_lock(&q->parent_pool->lock);
		xio_rdma_chunk_free(q, mp_mem->addr);
		pthread_spin_unlock(&q->parent_pool->lock);
	}
}

