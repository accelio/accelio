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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/scatterlist.h>
#include <linux/mempool.h>

#include "libxio.h"
#include <xio_os.h>
#include "xio_log.h"
#include "xio_common.h"
#include "xio_mempool.h"

/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
#ifndef SIZE_MAX
#define SIZE_MAX	(~(size_t)0)
#endif

static size_t sizes[] = {
			XIO_16K_BLOCK_SZ,
			XIO_64K_BLOCK_SZ,
			XIO_256K_BLOCK_SZ,
			XIO_1M_BLOCK_SZ,
			SIZE_MAX
			};

struct xio_chunks_list {
	struct kmem_cache *kcache;
	size_t		   block_sz;
	char name[64];	/* kmem_cache_create keeps a pointer to the pool's name
			 * Therefore the name must be valid until the pool
			 * is destroyed
			 */
};

struct xio_mempool {
	struct xio_chunks_list pool[ARRAY_SIZE(sizes)];
};

/* currently not in use - to be supported */
struct xio_mempool_config g_mempool_config = { 0 };

/*---------------------------------------------------------------------------*/
/* xio_mempool_destroy							     */
/*---------------------------------------------------------------------------*/
void xio_mempool_destroy(struct xio_mempool *p)
{
	struct xio_chunks_list *ch;
	int real_ones, i;

	if (!p)
		return;

	real_ones = ARRAY_SIZE(sizes) - 1;
	ch = p->pool;
	for (i = 0; i < real_ones; i++) {
		if (!ch->kcache)
			break;
		DEBUG_LOG("kcache(%s) freed\n", ch->name);
		kmem_cache_destroy(ch->kcache);
		ch->kcache = NULL;
		ch++;
	}

	kfree(p);
}
EXPORT_SYMBOL(xio_mempool_destroy);

/*---------------------------------------------------------------------------*/
/* xio_mempol_create							     */
/*---------------------------------------------------------------------------*/
struct xio_mempool *xio_mempool_create(void)
{
	struct xio_mempool *p;
	struct xio_chunks_list *ch;
	int real_ones, i;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		DEBUG_LOG("%s kzalloc failed\n", __func__);
		goto cleanup0;
	}

	real_ones = ARRAY_SIZE(sizes) - 1;
	ch = p->pool;
	for (i = 0; i < real_ones; i++) {
		ch->block_sz = sizes[i];
		/* The name must be valid until the pool is destroyed
		 * Use the address of the pool structure to create a unique
		 * name for the pool
		 */
		sprintf(ch->name, "xio_mempool-%zuK-%p",
			ch->block_sz/1024, p);
		ch->kcache = kmem_cache_create(ch->name,
					       ch->block_sz, PAGE_SIZE,
					       SLAB_HWCACHE_ALIGN, NULL);
		if (!ch->kcache) {
			ERROR_LOG("kcache(%s) creation failed\n", ch->name);
			goto cleanup;
		}
		DEBUG_LOG("kcache(%s) created(%p)\n", ch->name, ch->kcache);
		ch++;
	}

	DEBUG_LOG("mempool created(%p)\n", p);
	return p;

cleanup:
	xio_mempool_destroy(p);

cleanup0:
	ERROR_LOG("%s failed\n", __func__);

	return NULL;
}
EXPORT_SYMBOL(xio_mempool_create);

/*---------------------------------------------------------------------------*/
/* size2index								     */
/*---------------------------------------------------------------------------*/
static inline int size2index(struct xio_mempool *p, size_t sz)
{
	int i;

	for (i = 0; i <= XIO_CHUNKS_SIZE_NR; i++)
		if (sz <= p->pool[i].block_sz)
			break;

	return (i == XIO_CHUNKS_SIZE_NR) ? -1 : i;
}

/*---------------------------------------------------------------------------*/
/* xio__mempool_alloc							     */
/*---------------------------------------------------------------------------*/
int xio_mempool_alloc(struct xio_mempool *p, size_t length,
		      struct xio_mp_mem *mp_mem)
{
	int index;

	mp_mem->addr = NULL;
	mp_mem->cache = NULL;
	mp_mem->length = 0;

	index = size2index(p, length);
	if (index == -1) {
		xio_set_error(EINVAL);
		return -EINVAL;
	}

	mp_mem->addr = kmem_cache_alloc(p->pool[index].kcache, GFP_KERNEL);
	if (!mp_mem->addr) {
		xio_set_error(ENOMEM);
		return -ENOMEM;
	}

	mp_mem->cache = (void *)p->pool[index].kcache;
	mp_mem->length = p->pool[index].block_sz;

	return 0;
}
EXPORT_SYMBOL(xio_mempool_alloc);

int xio_mp_sge_alloc(struct xio_mempool *pool, struct xio_sge *sge,
		     u32 num_sge, struct xio_mem_desc *desc)
{
	struct xio_mp_mem *mp_sge;
	int i;

	desc->num_sge = 0;
	mp_sge = desc->mp_sge;

	for (i = 0; i < num_sge; i++) {
		if (xio_mempool_alloc(pool, sge->length, mp_sge))
			goto cleanup0;
		mp_sge++;
	}

	desc->num_sge = num_sge;
	return 0;

cleanup0:
	return -1;
}
EXPORT_SYMBOL(xio_mp_sge_alloc);

/*---------------------------------------------------------------------------*/
/* xio_mempool_free						     */
/*---------------------------------------------------------------------------*/
void xio_mempool_free_mp(struct xio_mp_mem *mp_mem)
{
	if (!mp_mem) {
		ERROR_LOG("%s mp_mem\n", __func__);
		goto cleanup0;
	}

	if (!mp_mem->cache) {
		ERROR_LOG("%s mp_mem(%p)->cache(0)\n", __func__, mp_mem);
		goto cleanup0;
	}

	if (!mp_mem->addr) {
		ERROR_LOG("%s mp_mem(%p)->addr(0)\n", __func__, mp_mem);
		goto cleanup1;
	}

	kmem_cache_free((struct kmem_cache *)mp_mem->cache, mp_mem->addr);

	mp_mem->cache = NULL;
	mp_mem->addr = NULL;

	return;

cleanup1:
	mp_mem->cache = NULL;
cleanup0:
	ERROR_LOG("%s failed\n", __func__);
}
EXPORT_SYMBOL(xio_mempool_free_mp);

void xio_mempool_free(struct xio_mem_desc *desc)
{
	int i;

	for (i = 0; i < desc->num_sge; i++) {
		if (desc->mp_sge[i].cache)
			xio_mempool_free_mp(&desc->mp_sge[i]);
	}

	desc->num_sge = 0;
}
EXPORT_SYMBOL(xio_mempool_free);
