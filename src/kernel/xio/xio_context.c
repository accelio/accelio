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

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/topology.h>

#include "libxio.h"
#include "xio_log.h"
#include <xio_os.h>
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_idr.h"
#include "xio_ev_data.h"
#include "xio_ev_loop.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"
#include "xio_mempool.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_transport.h"

#define MSGPOOL_INIT_NR	8
#define MSGPOOL_GROW_NR	64

/*---------------------------------------------------------------------------*/
/* xio_context_reg_observer						     */
/*---------------------------------------------------------------------------*/
int xio_context_reg_observer(struct xio_context *ctx,
			     struct xio_observer *observer)
{
	xio_observable_reg_observer(&ctx->observable, observer);

	return 0;
}
EXPORT_SYMBOL(xio_context_reg_observer);

/*---------------------------------------------------------------------------*/
/* xio_context_unreg_observer		                                     */
/*---------------------------------------------------------------------------*/
void xio_context_unreg_observer(struct xio_context *ctx,
				struct xio_observer *observer)
{
	xio_observable_unreg_observer(&ctx->observable, observer);
}
EXPORT_SYMBOL(xio_context_unreg_observer);

/*---------------------------------------------------------------------------*/
/* xio_ctx_create							     */
/*---------------------------------------------------------------------------*/
struct xio_context *xio_context_create(struct xio_context_params *ctx_params,
				       int polling_timeout,
				       int cpu_hint)
{
	struct xio_context		*ctx;
	struct xio_loop_ops		*loop_ops;
	struct task_struct		*worker;
	struct xio_transport		*transport;
	int				flags, cpu;

	if (!ctx_params) {
		xio_set_error(EINVAL);
		ERROR_LOG("ctx_params is NULL\n");
		goto cleanup0;

	}

	loop_ops = ctx_params->loop_ops;
	worker = ctx_params->worker;
	flags = ctx_params->flags;

	if (cpu_hint > 0 && cpu_hint >= num_online_cpus()) {
		xio_set_error(EINVAL);
		ERROR_LOG("cpu_hint(%d) >= num_online_cpus(%d)\n",
			  cpu_hint, num_online_cpus());
		goto cleanup0;
	}

	if ((flags == XIO_LOOP_USER_LOOP) &&
	    (!(loop_ops && loop_ops->add_event && loop_ops->ev_loop))) {
		xio_set_error(EINVAL);
		ERROR_LOG("loop_ops and ev_loop and ev_loop_add_event are " \
			  "mandatory with loop_ops\n");
		goto cleanup0;
	}

	xio_read_logging_level();

	/* no need to disable preemption */
	cpu = raw_smp_processor_id();

	if (cpu == -1)
		goto cleanup0;

	/* allocate new context */
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kzalloc failed\n");
		goto cleanup0;
	}

	if (cpu_hint < 0)
		cpu_hint = cpu;

	ctx->run_private = 0;
	ctx->user_context = ctx_params->user_context;
	ctx->flags = flags;
	ctx->cpuid  = cpu_hint;
	ctx->nodeid = cpu_to_node(cpu_hint);
	ctx->polling_timeout = polling_timeout;
	ctx->prealloc_xio_inline_bufs =
		!!ctx_params->prealloc_xio_inline_bufs;
	ctx->rq_depth = ctx_params->rq_depth;

	if (!ctx_params->max_conns_per_ctx)
		ctx->max_conns_per_ctx = 100;
	else
		ctx->max_conns_per_ctx =
			max(ctx_params->max_conns_per_ctx , 2);

	ctx->workqueue = xio_workqueue_create(ctx);
	if (!ctx->workqueue) {
		xio_set_error(ENOMEM);
		ERROR_LOG("xio_workqueue_init failed.\n");
		goto cleanup1;
	}
	ctx->msg_pool = xio_objpool_create(sizeof(struct xio_msg),
					   MSGPOOL_INIT_NR, MSGPOOL_GROW_NR);
	if (!ctx->msg_pool) {
		xio_set_error(ENOMEM);
		ERROR_LOG("context's msg_pool create failed. %m\n");
		goto cleanup2;
	}

	XIO_OBSERVABLE_INIT(&ctx->observable, ctx);
	INIT_LIST_HEAD(&ctx->ctx_list);

	switch (flags) {
	case XIO_LOOP_USER_LOOP:
		break;
	case XIO_LOOP_GIVEN_THREAD:
		set_cpus_allowed_ptr(worker, cpumask_of(cpu_hint));
		ctx->worker = (uint64_t)worker;
		break;
	case XIO_LOOP_TASKLET:
		break;
	case XIO_LOOP_WORKQUEUE:
		break;
	default:
		ERROR_LOG("wrong type. %u\n", flags);
		goto cleanup3;
	}

	ctx->ev_loop = xio_ev_loop_init(flags, ctx, loop_ops);
	if (!ctx->ev_loop)
		goto cleanup3;

	ctx->stats.hertz = HZ;
	/* Initialize default counters' name */
	ctx->stats.name[XIO_STAT_TX_MSG]   = kstrdup("TX_MSG", GFP_KERNEL);
	ctx->stats.name[XIO_STAT_RX_MSG]   = kstrdup("RX_MSG", GFP_KERNEL);
	ctx->stats.name[XIO_STAT_TX_BYTES] = kstrdup("TX_BYTES", GFP_KERNEL);
	ctx->stats.name[XIO_STAT_RX_BYTES] = kstrdup("RX_BYTES", GFP_KERNEL);
	ctx->stats.name[XIO_STAT_DELAY]    = kstrdup("DELAY", GFP_KERNEL);
	ctx->stats.name[XIO_STAT_APPDELAY] = kstrdup("APPDELAY", GFP_KERNEL);

	/* initialize rdma pools only */
	transport = xio_get_transport("rdma");
	if (transport && ctx->prealloc_xio_inline_bufs) {
		int retval = xio_ctx_pool_create(ctx, XIO_PROTO_RDMA,
					         XIO_CONTEXT_POOL_CLASS_INITIAL);
		if (retval) {
			ERROR_LOG("Failed to create initial pool. ctx:%p\n", ctx);
			goto cleanup2;
		}
		retval = xio_ctx_pool_create(ctx, XIO_PROTO_RDMA,
					     XIO_CONTEXT_POOL_CLASS_PRIMARY);
		if (retval) {
			ERROR_LOG("Failed to create primary pool. ctx:%p\n", ctx);
			goto cleanup2;
		}
	}
	spin_lock_init(&ctx->ctx_list_lock);

	xio_idr_add_uobj(usr_idr, ctx, "xio_context");
	return ctx;

cleanup3:
	xio_objpool_destroy(ctx->msg_pool);

cleanup2:
	xio_workqueue_destroy(ctx->workqueue);

cleanup1:
	kfree(ctx);

cleanup0:
	ERROR_LOG("xio_ctx_open failed\n");

	return NULL;
}
EXPORT_SYMBOL(xio_context_create);

/*---------------------------------------------------------------------------*/
/* xio_modify_context							     */
/*---------------------------------------------------------------------------*/
int xio_modify_context(struct xio_context *ctx,
		       struct xio_context_attr *attr,
		       int attr_mask)
{
	if (!ctx || !attr) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid parameters\n");
		return -1;
	}

	if (attr_mask & XIO_CONTEXT_ATTR_USER_CTX)
		ctx->user_context = attr->user_context;

	return 0;
}
EXPORT_SYMBOL(xio_modify_context);

/*---------------------------------------------------------------------------*/
/* xio_query_context							     */
/*---------------------------------------------------------------------------*/
int xio_query_context(struct xio_context *ctx,
		      struct xio_context_attr *attr,
		      int attr_mask)
{
	if (!ctx || !attr) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid parameters\n");
		return -1;
	}

	if (attr_mask & XIO_CONTEXT_ATTR_USER_CTX)
		attr->user_context = ctx->user_context;

	return 0;
}
EXPORT_SYMBOL(xio_query_context);

/*---------------------------------------------------------------------------*/
/* xio_ctx_tasks_pools_destroy						     */
/*---------------------------------------------------------------------------*/
static void xio_ctx_task_pools_destroy(struct xio_context *ctx)
{
	int i;

	for (i = 0; i < XIO_PROTO_LAST; i++) {
		if (ctx->initial_tasks_pool[i]) {
			xio_tasks_pool_free_tasks(ctx->initial_tasks_pool[i]);
			xio_tasks_pool_destroy(ctx->initial_tasks_pool[i]);
			ctx->initial_tasks_pool[i] = NULL;
		}
		if (ctx->primary_tasks_pool[i]) {
			xio_tasks_pool_free_tasks(ctx->primary_tasks_pool[i]);
			xio_tasks_pool_destroy(ctx->primary_tasks_pool[i]);
			ctx->primary_tasks_pool[i] = NULL;
		}
	}
}

/*---------------------------------------------------------------------------*/
/* xio_context_destroy	                                                     */
/*---------------------------------------------------------------------------*/
void xio_destroy_context_continue(struct work_struct *work)
{
	xio_work_handle_t *xio_work;
	struct xio_context *ctx;
	int i;

	xio_work = container_of(work, xio_work_handle_t, work);
	ctx = container_of(xio_work, struct xio_context, destroy_ctx_work);
	if (ctx->run_private)
		ERROR_LOG("not all observers finished! run_private=%d\n",
			  ctx->run_private);

	xio_observable_notify_all_observers(&ctx->observable,
					    XIO_CONTEXT_EVENT_POST_CLOSE, NULL);

	if (!xio_observable_is_empty(&ctx->observable))
		ERROR_LOG("context destroy: observers leak - %p\n", ctx);

	xio_observable_unreg_all_observers(&ctx->observable);

	for (i = 0; i < XIO_STAT_LAST; i++)
		kfree(ctx->stats.name[i]);

	xio_workqueue_destroy(ctx->workqueue);
	xio_objpool_destroy(ctx->msg_pool);

	/* can free only xio created loop */
	if (ctx->flags != XIO_LOOP_USER_LOOP)
		xio_ev_loop_destroy(ctx->ev_loop);

	ctx->ev_loop = NULL;

	XIO_OBSERVABLE_DESTROY(&ctx->observable);

	xio_ctx_task_pools_destroy(ctx);

	if (ctx->mempool) {
		xio_mempool_destroy(ctx->mempool);
		ctx->mempool = NULL;
	}

	kfree(ctx);
}
EXPORT_SYMBOL(xio_destroy_context_continue);

void xio_context_destroy(struct xio_context *ctx)
{
	int found;

	found = xio_idr_lookup_uobj(usr_idr, ctx);
	if (found) {
		xio_idr_remove_uobj(usr_idr, ctx);
	} else {
		ERROR_LOG("context not found:%p\n", ctx);
		xio_set_error(XIO_E_USER_OBJ_NOT_FOUND);
		return;
	}

	ctx->run_private = 0;
	xio_observable_notify_all_observers(&ctx->observable,
					    XIO_CONTEXT_EVENT_CLOSE, NULL);
	/* allow internally to run the loop for final cleanup */
	if (ctx->run_private)
		xio_context_run_loop(ctx);
	if (ctx->run_private == 0)
		xio_destroy_context_continue(&ctx->destroy_ctx_work.work);
}
EXPORT_SYMBOL(xio_context_destroy);

/*---------------------------------------------------------------------------*/
/* xio_ctx_add_delayed_work						     */
/*---------------------------------------------------------------------------*/
int xio_ctx_add_delayed_work(struct xio_context *ctx,
			     int msec_duration, void *data,
			     void (*timer_fn)(void *data),
			     xio_ctx_delayed_work_t *work)
{
	int retval;

	/* test if delayed work is pending */
	if (xio_is_delayed_work_pending(work))
		return 0;

	retval = xio_workqueue_add_delayed_work(ctx->workqueue,
						msec_duration, data,
						timer_fn, work);
	if (retval) {
		xio_set_error(retval);
		ERROR_LOG("xio_workqueue_add_delayed_work failed. err=%d\n",
			  retval);
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_del_delayed_work						     */
/*---------------------------------------------------------------------------*/
int xio_ctx_del_delayed_work(struct xio_context *ctx,
			     xio_ctx_delayed_work_t *work)
{
	int retval;

	/* test if delayed work is pending */
	if (!xio_is_delayed_work_pending(work))
		return 0;

	retval = xio_workqueue_del_delayed_work(ctx->workqueue, work);
	if (retval) {
		xio_set_error(retval);
		ERROR_LOG("workqueue_del_delayed_work failed. err=%d\n",
			  retval);
	}

	return retval;
}

int xio_context_run_loop(struct xio_context *ctx)
{
	struct xio_ev_loop *ev_loop = (struct xio_ev_loop *)ctx->ev_loop;

	return ev_loop->run(ev_loop->loop_object);
}
EXPORT_SYMBOL(xio_context_run_loop);

void xio_context_stop_loop(struct xio_context *ctx)
{
	struct xio_ev_loop *ev_loop = (struct xio_ev_loop *)ctx->ev_loop;

	ev_loop->stop(ev_loop->loop_object);
}
EXPORT_SYMBOL(xio_context_stop_loop);

int xio_context_add_event(struct xio_context *ctx, struct xio_ev_data *data)
{
	struct xio_ev_loop *ev_loop = (struct xio_ev_loop *)ctx->ev_loop;

	return ev_loop->add_event(ev_loop->loop_object, data);
}
EXPORT_SYMBOL(xio_context_add_event);

/*
 * Suspend the current handler run.
 * Note: Not protected against a race. Another thread may reactivate the event.
 */
/*---------------------------------------------------------------------------*/
/* xio_context_disable_event	                                             */
/*---------------------------------------------------------------------------*/
void xio_context_disable_event(struct xio_ev_data *data)
{
	clear_bit(XIO_EV_HANDLER_ENABLED, &data->states);
}
EXPORT_SYMBOL(xio_context_disable_event);

/*
 * Check if the event is pending.
 * Return true if the event is pending in any list.
 * Return false once the event is removed from the list in order to be executed.
 * (When inside the event handler, the event is no longer pending)
 * Note: Not protected against a race. Another thread may reactivate the event.
 */
/*---------------------------------------------------------------------------*/
/* xio_context_is_pending_event	                                             */
/*---------------------------------------------------------------------------*/
int xio_context_is_pending_event(struct xio_ev_data *data)
{
	return test_bit(XIO_EV_HANDLER_PENDING, &data->states);
}
EXPORT_SYMBOL(xio_context_is_pending_event);

int xio_context_is_loop_stopping(struct xio_context *ctx)
{
	struct xio_ev_loop *ev_loop = (struct xio_ev_loop *)ctx->ev_loop;

	return ev_loop->is_stopping(ev_loop->loop_object);
}
EXPORT_SYMBOL(xio_context_is_loop_stopping);

/*---------------------------------------------------------------------------*/
/* xio_ctx_add_work							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_add_work(struct xio_context *ctx,
		     void *data,
		     void (*function)(void *data),
		     xio_ctx_work_t *work)
{
	int retval;

	/* test if work is pending */
	if (xio_is_work_pending(work))
		return 0;

	retval = xio_workqueue_add_work(ctx->workqueue,
					data, function, work);
	if (retval) {
		xio_set_error(retval);
		ERROR_LOG("xio_workqueue_add_work failed. err=%d\n", retval);
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_set_work_destructor						     */
/*---------------------------------------------------------------------------*/
int xio_ctx_set_work_destructor(
		     struct xio_context *ctx, void *data,
		     void (*destructor)(void *data),
		     xio_ctx_work_t *work)
{
	int retval;

	/* test if work is pending */
	if (xio_is_work_pending(work))
		return 0;

	retval = xio_workqueue_set_work_destructor(
					ctx->workqueue,
					data, destructor, work);
	if (retval) {
		xio_set_error(retval);
		ERROR_LOG("xio_workqueue_set_work_destructor failed. %m\n");
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_is_work_in_handler						     */
/*---------------------------------------------------------------------------*/
int xio_ctx_is_work_in_handler(struct xio_context *ctx, xio_ctx_work_t *work)
{
	/* test if work is pending */
	if (xio_is_work_pending(work))
		return 0;

	return xio_workqueue_is_work_in_handler(ctx->workqueue, work);
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_del_work							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_del_work(struct xio_context *ctx,
		     xio_ctx_work_t *work)

{
	int retval;

	/* test if work is pending */
	if (!xio_is_work_pending(work))
		return 0;

	retval = xio_workqueue_del_work(ctx->workqueue, work);
	if (retval) {
		xio_set_error(retval);
		ERROR_LOG("xio_workqueue_del_work failed. err=%d\n", retval);
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_mempool_get							     */
/*---------------------------------------------------------------------------*/
struct xio_mempool *xio_mempool_get(struct xio_context *ctx)
{
	if (ctx->mempool)
		return ctx->mempool;

	ctx->mempool = xio_mempool_create();

	if (!ctx->mempool) {
		ERROR_LOG("xio_mempool_create failed\n");
		return NULL;
	}
	return ctx->mempool;
}
EXPORT_SYMBOL(xio_mempool_get);

/*
 * should be called only from loop context
 */
/*---------------------------------------------------------------------------*/
/* xio_context_destroy_resume	                                             */
/*---------------------------------------------------------------------------*/
void xio_context_destroy_resume(struct xio_context *ctx)
{
	if (ctx->run_private) {
		if (!--ctx->run_private) {
			switch (ctx->flags) {
			case XIO_LOOP_GIVEN_THREAD:
				xio_context_stop_loop(ctx);
				break;
			case XIO_LOOP_WORKQUEUE:
				INIT_WORK(&ctx->destroy_ctx_work.work,
					  xio_destroy_context_continue);
				schedule_work(&ctx->destroy_ctx_work.work);
				break;
			default:
				ERROR_LOG("Not supported type. %d\n", ctx->flags);
				break;
			}
		}
	}
}
EXPORT_SYMBOL(xio_context_destroy_resume);

/*---------------------------------------------------------------------------*/
/* xio_context_set_poll_completions_fn	                                     */
/*---------------------------------------------------------------------------*/
void xio_context_set_poll_completions_fn(
		struct xio_context *ctx,
		poll_completions_fn_t poll_completions_fn,
		void *poll_completions_ctx)
{
	ctx->poll_completions_ctx = poll_completions_ctx;
	ctx->poll_completions_fn =  poll_completions_fn;
}
EXPORT_SYMBOL(xio_context_set_poll_completions_fn);

/*---------------------------------------------------------------------------*/
/* xio_context_poll_completions		                                     */
/*---------------------------------------------------------------------------*/
int xio_context_poll_completions(struct xio_context *ctx, int timeout_us)
{
	if (ctx->poll_completions_fn)
		return ctx->poll_completions_fn(ctx->poll_completions_ctx,
					       timeout_us);

	return 0;
}
EXPORT_SYMBOL(xio_context_poll_completions);

/*---------------------------------------------------------------------------*/
/* xio_ctx_pool_create							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_pool_create(struct xio_context *ctx, enum xio_proto proto,
		        enum xio_context_pool_class pool_cls)
{
	struct xio_tasks_pool_ops	*pool_ops;
	struct xio_tasks_pool		**tasks_pool;
	struct xio_transport		*transport;
	struct xio_tasks_pool_params	params;
	char				pool_name[64];
	const char			*proto_str = xio_proto_str(proto);

	/* get the transport's proto */
	transport = xio_get_transport(proto_str);
	if (!transport) {
		ERROR_LOG("failed to load %s transport layer.\n", proto_str);
		ERROR_LOG("validate that your system support %s " \
			  "and the accelio's %s module is loaded\n",
			  proto_str, proto_str);
		xio_set_error(ENOPROTOOPT);
		return -1;
	}

	if (transport->get_pools_setup_ops) {
		if (!ctx->primary_pool_ops[proto] ||
		    !ctx->initial_pool_ops[proto])
			transport->get_pools_setup_ops(
					NULL,
					&ctx->initial_pool_ops[proto],
					&ctx->primary_pool_ops[proto]);
	} else {
		ERROR_LOG("transport does not implement " \
			  "\"get_pools_setup_ops\"\n");
		return -1;
	}

	switch(pool_cls) {
	case XIO_CONTEXT_POOL_CLASS_INITIAL:
		tasks_pool = &ctx->initial_tasks_pool[proto];
		pool_ops = ctx->initial_pool_ops[proto];
		sprintf(pool_name, "ctx:%p - initial_pool_%s", ctx, proto_str);

	break;
	case XIO_CONTEXT_POOL_CLASS_PRIMARY:
		tasks_pool = &ctx->primary_tasks_pool[proto];
		pool_ops = ctx->primary_pool_ops[proto];
		sprintf(pool_name, "ctx:%p - primary_pool_%s", ctx, proto_str);
	break;
	default:
		xio_set_error(EINVAL);
		ERROR_LOG("unknown pool class\n");
		return -1;
	};

	/* if already exist */
	if (*tasks_pool)
		return 0;

	if (!pool_ops)
		return -1;

	if (!pool_ops->pool_get_params ||
	    !pool_ops->slab_pre_create ||
	    !pool_ops->slab_init_task ||
	    !pool_ops->pool_post_create ||
	    !pool_ops->slab_destroy)
		return -1;

	/* get pool properties from the transport */
	memset(&params, 0, sizeof(params));

	pool_ops->pool_get_params(NULL,
				  (int *)&params.start_nr,
				  (int *)&params.max_nr,
				  (int *)&params.alloc_nr,
				  (int *)&params.pool_dd_data_sz,
				  (int *)&params.slab_dd_data_sz,
				  (int *)&params.task_dd_data_sz);
	if (ctx->prealloc_xio_inline_bufs) {
		params.start_nr = params.max_nr;
		params.alloc_nr = 0;
	}

	params.pool_hooks.slab_pre_create  =
		(int (*)(void *, int, void *, void *))
				pool_ops->slab_pre_create;
	params.pool_hooks.slab_post_create = (int (*)(void *, void *, void *))
				pool_ops->slab_post_create;
	params.pool_hooks.slab_destroy	   = (int (*)(void *, void *, void *))
				pool_ops->slab_destroy;
	params.pool_hooks.slab_init_task   =
		(int (*)(void *, void *, void *, int,  struct xio_task *))
				pool_ops->slab_init_task;
	params.pool_hooks.slab_uninit_task =
		(int (*)(void *, void *, void *, struct xio_task *))
				pool_ops->slab_uninit_task;
	params.pool_hooks.slab_remap_task =
		(int (*)(void *, void *, void *, void *, struct xio_task *))
				pool_ops->slab_remap_task;
	params.pool_hooks.pool_pre_create  = (int (*)(void *, void *, void *))
				pool_ops->pool_pre_create;
	params.pool_hooks.pool_post_create = (int (*)(void *, void *, void *))
				pool_ops->pool_post_create;
	params.pool_hooks.pool_destroy	   = (int (*)(void *, void *, void *))
				pool_ops->pool_destroy;
	params.pool_hooks.task_pre_put  = (int (*)(void *, struct xio_task *))
		pool_ops->task_pre_put;
	params.pool_hooks.task_post_get = (int (*)(void *, struct xio_task *))
		pool_ops->task_post_get;

	params.pool_name = kstrdup(pool_name, GFP_KERNEL);

	/* initialize the tasks pool */
	*tasks_pool = xio_tasks_pool_create(&params);
	if (!*tasks_pool) {
		ERROR_LOG("xio_tasks_pool_create failed\n");
		return -1;
	}

	return 0;
}


