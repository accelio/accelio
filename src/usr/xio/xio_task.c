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
/* xio_tasks_pool_alloc_slab						     */
/*---------------------------------------------------------------------------*/
int xio_tasks_pool_alloc_slab(struct xio_tasks_pool *q)
{
	int			alloc_nr;
	size_t			slab_alloc_sz;
	size_t			tasks_alloc_sz;
	void			*buf;
	void			*data;
	struct xio_tasks_slab	*s;
	int			retval = 0, i;
	int			tot_sz;
	int			huge_alloc = 0;

	if (q->params.start_nr < 0  || q->params.max_nr < 0 ||
	    q->params.alloc_nr < 0) {
		xio_set_error(EINVAL);
		return -1;
	}
	if (q->params.start_nr && q->curr_alloced < q->params.start_nr)
		alloc_nr = min(q->params.start_nr, q->params.max_nr);
	else
		alloc_nr = min(q->params.alloc_nr,
			       q->params.max_nr - q->curr_alloced);

	if (alloc_nr == 0)
		return 0;

	/* slab + private data */
	slab_alloc_sz = sizeof(struct xio_tasks_slab) +
			q->params.slab_dd_data_sz +
			alloc_nr*sizeof(struct xio_task *);

	/* slab data */
	tasks_alloc_sz = alloc_nr*(sizeof(struct xio_task) +
			  g_options.max_in_iovsz*sizeof(struct xio_iovec_ex) +
			  g_options.max_out_iovsz*sizeof(struct xio_iovec_ex) +
			  q->params.task_dd_data_sz);

	tot_sz = slab_alloc_sz+tasks_alloc_sz;

	if (tot_sz > 1 << 20) {
		buf = umalloc_huge_pages(tot_sz);
		huge_alloc = 1;
	} else {
		buf = ucalloc(tot_sz, 1);
	}
	if (buf == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc failed\n");
		return -1;
	}
	data = buf;

	/* slab */
	s = (void *)((char *)buf + tasks_alloc_sz);
	s->dd_data = (void *)((char *)s + sizeof(struct xio_tasks_slab));

	/* array */
	s->array = (void *)((char *)(s->dd_data) + q->params.slab_dd_data_sz);

	/* fix indexes */
	s->start_idx = q->curr_idx;
	s->end_idx = s->start_idx + alloc_nr - 1;
	q->curr_idx = s->end_idx + 1;
	s->nr = alloc_nr;
	s->huge_alloc = huge_alloc;

	if (q->params.pool_hooks.slab_pre_create)
		retval = q->params.pool_hooks.slab_pre_create(
				q->params.pool_hooks.context,
				alloc_nr,
				q->dd_data,
				s->dd_data);

	for (i = 0; i < alloc_nr; i++) {
		s->array[i]		= data;
		s->array[i]->ltid	= s->start_idx + i;
		s->array[i]->magic	= XIO_TASK_MAGIC;
		s->array[i]->pool	= (void *)q;
		s->array[i]->dd_data	= ((char *)data) +
						sizeof(struct xio_task);

		data = ((char *)data) + sizeof(struct xio_task) +
					q->params.task_dd_data_sz;

		s->array[i]->imsg.in.sgl_type		 = XIO_SGL_TYPE_IOV_PTR;
		s->array[i]->imsg.in.pdata_iov.sglist	 = data;
		s->array[i]->imsg.in.pdata_iov.max_nents = g_options.max_in_iovsz;

		data = ((char *)data) + g_options.max_in_iovsz*sizeof(struct xio_iovec_ex);

		s->array[i]->imsg.out.sgl_type		  = XIO_SGL_TYPE_IOV_PTR;
		s->array[i]->imsg.out.pdata_iov.sglist	  = data;
		s->array[i]->imsg.out.pdata_iov.max_nents = g_options.max_out_iovsz;

		data = ((char *)data) + g_options.max_out_iovsz*sizeof(struct xio_iovec_ex);

		if (q->params.pool_hooks.slab_init_task) {
			retval = q->params.pool_hooks.slab_init_task(
				q->params.pool_hooks.context,
				q->dd_data,
				s->dd_data,
				i,
				s->array[i]);
		}
		list_add_tail(&s->array[i]->tasks_list_entry, &q->stack);
	}
	q->curr_alloced += alloc_nr;
	q->curr_free += alloc_nr;

	list_add_tail(&s->slabs_list_entry, &q->slabs_list);

	if (q->params.pool_hooks.slab_post_create)
		retval = q->params.pool_hooks.slab_post_create(
				q->params.pool_hooks.context,
				q->dd_data,
				s->dd_data);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_create						     */
/*---------------------------------------------------------------------------*/
struct xio_tasks_pool *xio_tasks_pool_create(
		struct xio_tasks_pool_params *params)
{
	struct xio_tasks_pool	*q;
	char			*buf;

	/* pool */
	buf = ucalloc(sizeof(*q)+params->pool_dd_data_sz, 1);
	if (buf == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc failed\n");
		return NULL;
	}
	q		= (void *)buf;
	if (params->pool_dd_data_sz)
		q->dd_data = (void *)(q + 1);
	else
		q->dd_data = NULL;

	INIT_LIST_HEAD(&q->stack);
	INIT_LIST_HEAD(&q->slabs_list);

	memcpy(&q->params, params, sizeof(*params));

	if (q->params.pool_hooks.pool_pre_create)
		q->params.pool_hooks.pool_pre_create(
				q->params.pool_hooks.context, q, q->dd_data);


	if (q->params.start_nr != 0) {
		xio_tasks_pool_alloc_slab(q);
		if (list_empty(&q->stack)) {
			ufree(q);
			return NULL;
		}
	}
	if (q->params.pool_hooks.pool_post_create)
		q->params.pool_hooks.pool_post_create(
				q->params.pool_hooks.context, q, q->dd_data);


	return q;
}

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_destroy						     */
/*---------------------------------------------------------------------------*/
void xio_tasks_pool_destroy(struct xio_tasks_pool *q)
{
	struct xio_tasks_slab	*pslab, *next_pslab;
	int			i;

	list_for_each_entry_safe(pslab, next_pslab, &q->slabs_list,
				 slabs_list_entry) {
		list_del(&pslab->slabs_list_entry);

		if (q->params.pool_hooks.slab_uninit_task) {
			for (i = 0; i < pslab->nr; i++)
				q->params.pool_hooks.slab_uninit_task(
						q->params.pool_hooks.context,
						q->dd_data,
						pslab->dd_data,
						pslab->array[i]);
		}

		if (q->params.pool_hooks.slab_destroy)
			q->params.pool_hooks.slab_destroy(
				q->params.pool_hooks.context,
				q->dd_data,
				pslab->dd_data);

		/* the tmp tasks are returned back to pool */

		if (pslab->huge_alloc)
			ufree_huge_pages(pslab->array[0]);
		else
			ufree(pslab->array[0]);
	}

	if (q->params.pool_hooks.pool_destroy)
		q->params.pool_hooks.pool_destroy(
				q->params.pool_hooks.context,
				q, q->dd_data);

	ufree(q);
}

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_remap							     */
/*---------------------------------------------------------------------------*/
void xio_tasks_pool_remap(struct xio_tasks_pool *q, void *new_context)
{
	struct xio_tasks_slab	*pslab, *next_pslab;
	int			i, retval;

	list_for_each_entry_safe(pslab, next_pslab, &q->slabs_list,
				 slabs_list_entry) {
		if (q->params.pool_hooks.slab_post_create)
			retval = q->params.pool_hooks.slab_post_create(
					new_context,
					q->dd_data,
					pslab->dd_data);

		if (q->params.pool_hooks.slab_remap_task) {
			for (i = 0; i < pslab->nr; i++)
				q->params.pool_hooks.slab_remap_task(
						q->params.pool_hooks.context,
						new_context,
						q->dd_data,
						pslab->dd_data,
						pslab->array[i]);
		}
	}
	q->params.pool_hooks.context = new_context;
}
