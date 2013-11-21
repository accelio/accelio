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
#include "xio_task.h"
#include "xio_mem.h"

#define XIO_TASK_MAGIC   0x58494f5f5441534b

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_init						     */
/*---------------------------------------------------------------------------*/
struct xio_tasks_pool *xio_tasks_pool_init(int max, int pool_dd_data_sz,
					       int task_dd_data_sz,
					       void *pool_ops)
{
	int			i;
	void			*buf;
	void			*data;
	struct xio_tasks_pool	*q;
	size_t			elems_alloc_sz;


	/* pool + private data */
	size_t pool_alloc_sz = sizeof(struct xio_tasks_pool) +
				pool_dd_data_sz +
				max*sizeof(struct xio_task *);

	/* pool data */
	elems_alloc_sz = max*(sizeof(struct xio_task) + task_dd_data_sz);

	buf = malloc_huge_pages(pool_alloc_sz + elems_alloc_sz);
	if (buf == NULL) {
		xio_set_error(ENOMEM);
		return NULL;
	}
	data = buf;

	/* pool */
	q = (void *)((char *)buf + elems_alloc_sz);
	q->dd_data = (void *)((char *)q + sizeof(struct xio_tasks_pool));

	/* array */
	q->array = (void *)((char *)(q->dd_data) + pool_dd_data_sz);

	INIT_LIST_HEAD(&q->stack);

	for (i = 0; i < max; i++) {
		q->array[i]		= data;
		q->array[i]->ltid	= i;
		q->array[i]->magic	= XIO_TASK_MAGIC;
		q->array[i]->pool	= (void *)q;
		q->array[i]->dd_data	= ((char *)data) +
						sizeof(struct xio_task);
		list_add_tail(&q->array[i]->tasks_list_entry, &q->stack);
		data = ((char *)data) + sizeof(struct xio_task) +
					task_dd_data_sz;
	}
	q->max = max;
	q->nr = max;
	q->pool_ops = pool_ops;

	return q;
}

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_free						     */
/*---------------------------------------------------------------------------*/
void xio_tasks_pool_free(struct xio_tasks_pool *q)
{
	free_huge_pages(q->array[0]);
}
