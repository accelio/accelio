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
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_observer.h"
#include "xio_transport.h"

#include <linux/mm.h>
#include <linux/vmalloc.h>

#define XIO_TASK_MAGIC   0x58494f54 /* Hex of 'XIOT' */

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_alloc_slab						     */
/*---------------------------------------------------------------------------*/
int xio_tasks_pool_alloc_slab(struct xio_tasks_pool *q, void *context)
{
	int			alloc_nr;
	size_t			slab_alloc_sz;
	size_t			tasks_alloc_sz;
	void			*buf;
	void			*data;
	void			*ptr;
	struct xio_tasks_slab	*s;
	int			retval = 0, i, tot_len, initialized = 0;
	struct xio_task *task;
	struct xio_msg *msg;
	struct xio_vmsg *vmsg;
	LIST_HEAD(tmp_list);

	if ((int)q->params.start_nr < 0  || (int)q->params.max_nr < 0 ||
	    (int)q->params.alloc_nr < 0) {
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
			alloc_nr * sizeof(struct xio_task *);

	/* slab data */
	tasks_alloc_sz = alloc_nr * (sizeof(struct xio_task) +
				     q->params.task_dd_data_sz);

	tot_len = PAGE_ALIGN(slab_alloc_sz + tasks_alloc_sz);
	buf = vmalloc(tot_len);
	if (!buf) {
		xio_set_error(ENOMEM);
		return -1;
	}
	memset(buf, 0, tot_len);

	data = buf;
	ptr = buf;

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

	INIT_LIST_HEAD(&s->slabs_list_entry);

	if (q->params.pool_hooks.slab_pre_create) {
		retval = q->params.pool_hooks.slab_pre_create(
				context,
				alloc_nr,
				q->dd_data,
				s->dd_data);
		if (retval)
			goto cleanup;
	}

	for (i = 0; i < alloc_nr; i++) {
		s->array[i]	= data;
		task		= s->array[i];
		task->ltid	= s->start_idx + i;
		task->magic	= XIO_TASK_MAGIC;
		task->pool	= (void *)q;
		task->slab	= (void *)s;
		task->dd_data	= ((char *)data) + sizeof(struct xio_task);

		data = ((char *)data) + sizeof(struct xio_task) +
					q->params.task_dd_data_sz;

		msg = &task->imsg;

		vmsg = &msg->in;
		vmsg->sgl_type = XIO_SGL_TYPE_SCATTERLIST;

		if (sg_alloc_table(&vmsg->data_tbl, g_options.max_in_iovsz,
				   GFP_KERNEL)) {
			ERROR_LOG("sg_alloc_table(read_sge)\n");
			goto cleanup;
		}

		vmsg = &msg->out;
		vmsg->sgl_type = XIO_SGL_TYPE_SCATTERLIST;

		if (sg_alloc_table(&vmsg->data_tbl, g_options.max_out_iovsz,
				   GFP_KERNEL)) {
			ERROR_LOG("sg_weite_table(read_sge)\n");
			sg_free_table(&msg->in.data_tbl);
			goto cleanup;
		}

		if (q->params.pool_hooks.slab_init_task && context) {
			retval = q->params.pool_hooks.slab_init_task(
				context,
				q->dd_data,
				s->dd_data,
				i,
				s->array[i]);
			if (retval) {
				sg_free_table(&msg->out.data_tbl);
				sg_free_table(&msg->in.data_tbl);
				goto cleanup;
			}
		}
		list_add_tail(&task->tasks_list_entry, &tmp_list);
		initialized++;
	}
	q->curr_alloced += alloc_nr;

	list_add_tail(&s->slabs_list_entry, &q->slabs_list);
	preempt_disable();
	list_splice_tail(&tmp_list, &q->stack);
	preempt_enable();

	if (q->params.pool_hooks.slab_post_create && context) {
		retval = q->params.pool_hooks.slab_post_create(
				context,
				q->dd_data,
				s->dd_data);
		if (retval)
			goto cleanup;
	}

	return retval;

cleanup:
	list_del_init(&s->slabs_list_entry);

	for (i = 0; i < initialized; i++) {
		task = s->array[i];
		msg = &task->imsg;
		list_del_init(&task->tasks_list_entry);
		sg_free_table(&msg->out.data_tbl);
		sg_free_table(&msg->in.data_tbl);
	}
	vfree(ptr);

	return -1;
}
EXPORT_SYMBOL(xio_tasks_pool_alloc_slab);

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_create						     */
/*---------------------------------------------------------------------------*/
struct xio_tasks_pool *xio_tasks_pool_create(
		struct xio_tasks_pool_params *params)
{
	struct xio_tasks_pool	*q;
	char			*buf;

	/* pool */
	buf = kzalloc(sizeof(*q) + params->pool_dd_data_sz, GFP_KERNEL);
	if (!buf) {
		xio_set_error(ENOMEM);
		return NULL;
	}
	q = (void *)buf;
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

	if (q->params.start_nr) {
		xio_tasks_pool_alloc_slab(q, q->params.pool_hooks.context);
		if (list_empty(&q->stack)) {
			kfree(q);
			return NULL;
		}
	}
	if (q->params.pool_hooks.pool_post_create)
		q->params.pool_hooks.pool_post_create(
				q->params.pool_hooks.context, q, q->dd_data);

	return q;
}
EXPORT_SYMBOL(xio_tasks_pool_create);

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_destroy						     */
/*---------------------------------------------------------------------------*/
void xio_tasks_pool_destroy(struct xio_tasks_pool *q)
{
	struct xio_tasks_slab	*pslab, *next_pslab;
	struct xio_task *task;
	struct xio_msg *msg;
	unsigned int i;

	list_for_each_entry_safe(pslab, next_pslab, &q->slabs_list,
				 slabs_list_entry) {
		list_del_init(&pslab->slabs_list_entry);

		if (q->params.pool_hooks.slab_uninit_task) {
			for (i = 0; i < pslab->nr; i++) {
				task = pslab->array[i];
				msg = &task->imsg;
				list_del_init(&task->tasks_list_entry);
				sg_free_table(&msg->out.data_tbl);
				sg_free_table(&msg->in.data_tbl);

				q->params.pool_hooks.slab_uninit_task(
						pslab->array[i]->context,
						q->dd_data,
						pslab->dd_data,
						pslab->array[i]);
			}
		}

		if (q->params.pool_hooks.slab_destroy)
			q->params.pool_hooks.slab_destroy(
				q->params.pool_hooks.context,
				q->dd_data,
				pslab->dd_data);

		/* the tmp tasks are returned back to pool */
		vfree(pslab->array[0]);
	}
	if (q->params.pool_hooks.pool_destroy)
		q->params.pool_hooks.pool_destroy(
				q->params.pool_hooks.context,
				q, q->dd_data);

	kfree(q);
}
EXPORT_SYMBOL(xio_tasks_pool_destroy);

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_remap							     */
/*---------------------------------------------------------------------------*/
void xio_tasks_pool_remap(struct xio_tasks_pool *q, void *new_context)
{
	struct xio_tasks_slab	*pslab, *next_pslab;
	unsigned int		i;
	int			retval;

	if (!q)
		return;

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

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_dump_used						     */
/*---------------------------------------------------------------------------*/
void xio_tasks_pool_dump_used(struct xio_tasks_pool *q)
{
	struct xio_tasks_slab	*pslab;
	unsigned int		i;
	char			*pool_name;

	list_for_each_entry(pslab, &q->slabs_list, slabs_list_entry) {
		for (i = 0; i < pslab->nr; i++)
			if (pslab->array[i]->tlv_type != 0xdead) {
				pool_name = q->params.pool_name ?
					q->params.pool_name : "unknown";
				ERROR_LOG("pool_name:%s: in use: task:%p, " \
					  "type:0x%x\n",
					  pool_name,
					  pslab->array[i],
					  pslab->array[i]->tlv_type);
			}
	}
}

