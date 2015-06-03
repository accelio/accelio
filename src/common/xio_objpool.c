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
#include "xio_objpool.h"
#include <xio_env_adv.h>
/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
struct xio_mem_chunk {
	struct list_head	chunk_entry;
};

struct xio_mem_obj {
	void			*obj;
	struct list_head	chain_entry;
	struct xio_objpool	*pool;
};

struct xio_objpool {
	struct list_head	free_list;	/* list of xio_mem_obj */
	struct list_head	used_list;	/* list of xio_mem_obj */
	struct list_head	chunks_list;	/* list of mem chunks */
	uint64_t		obj_size;	/* obj size */
	uint64_t		grow_nr;	/* obj to realloc in pool */
	uint64_t		total_nr;	/* total objs in pool */
};

/*---------------------------------------------------------------------------*/
/* xio_objpool_realloc							     */
/*---------------------------------------------------------------------------*/
static int xio_objpool_realloc(struct xio_objpool *p, int size, int n)
{
	struct xio_mem_obj	*obj;
	struct xio_mem_chunk	*chunk;
	size_t			alloc_sz;
	char			*buf;

	p->total_nr += n;

	alloc_sz =  sizeof(*chunk) +
			n*(sizeof(*obj) + sizeof(obj)  + size);

	buf = (char *)vzalloc(alloc_sz);
	if (!buf)
		goto err;

	chunk = (struct xio_mem_chunk *)buf;

	list_add(&chunk->chunk_entry, &p->chunks_list);

	inc_ptr(buf, sizeof(*chunk));

	obj = (struct xio_mem_obj *)buf;
	while (n--) {
		obj->obj	= sum_to_ptr((void *)obj, sizeof(*obj));
		obj->pool	= p;
		((void **)obj->obj)[0] = obj;
		inc_ptr(obj->obj, sizeof(void *));
		list_add(&obj->chain_entry, &p->free_list);
		obj = (struct xio_mem_obj *)sum_to_ptr((void *)obj->obj, size);
	}

	return 0;

err:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_objpool_realloc							     */
/*---------------------------------------------------------------------------*/
struct xio_objpool *xio_objpool_create(int size, int init_nr, int grow_nr)
{
	struct xio_objpool	*p;
	int			retval;

	p = (struct xio_objpool *)kcalloc(1, sizeof(*p), GFP_KERNEL);
	if (!p)
		return NULL;

	p->grow_nr	= grow_nr;
	p->obj_size	= size;

	INIT_LIST_HEAD(&p->free_list);
	INIT_LIST_HEAD(&p->used_list);
	INIT_LIST_HEAD(&p->chunks_list);

	retval = xio_objpool_realloc(p, size, init_nr);
	if (retval == -1)
		return NULL;

	return p;
}

/*---------------------------------------------------------------------------*/
/* xio_objpool_destroy							     */
/*---------------------------------------------------------------------------*/
void xio_objpool_destroy(struct xio_objpool *p)
{
	struct xio_mem_chunk *chunk;
	struct xio_mem_chunk *tmp_chunk;

	list_for_each_entry_safe(chunk, tmp_chunk,
				 &p->chunks_list, chunk_entry) {
		list_del(&chunk->chunk_entry);
		vfree(chunk);
	}
	kfree(p);
}

/*---------------------------------------------------------------------------*/
/* xio_objpool_alloc							     */
/*---------------------------------------------------------------------------*/
void *xio_objpool_alloc(struct xio_objpool *p)
{
	struct xio_mem_obj	*obj;
	struct xio_mem_obj	*tmp_obj;

	if (list_empty(&p->free_list) &&
	    xio_objpool_realloc(p, p->obj_size, p->grow_nr) == -1) {
		return NULL;
	}
	/* get first free item from the allocated objs */
	list_for_each_entry_safe(obj, tmp_obj, &p->free_list, chain_entry) {
		list_move(&obj->chain_entry, &p->used_list);
		return obj->obj;
	}

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_objpool_free							     */
/*---------------------------------------------------------------------------*/
void xio_objpool_free(void *o)
{
	struct xio_mem_obj *obj;

	if (!o)
		return;
	obj = (struct xio_mem_obj *)(((void **)o)[-1]);
	list_move(&obj->chain_entry, &obj->pool->free_list);
}

