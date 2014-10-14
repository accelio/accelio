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
#include "xio_os.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_idr.h"
#include "xio_ev_data.h"
#include "xio_ev_loop.h"
#include "xio_workqueue.h"
#include "xio_context.h"

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
struct xio_context *xio_context_create(unsigned int flags,
				       struct xio_loop_ops *loop_ops,
				       struct task_struct *worker,
				       int polling_timeout,
				       int cpu_hint)
{
	struct xio_context *ctx;
	struct dentry *xio_root;
	char name[32];
	int cpu;

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
	if (ctx == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kzalloc failed\n");
		goto cleanup0;
	}

	if (cpu_hint < 0)
		cpu_hint = cpu;

	ctx->flags = flags;
	ctx->cpuid  = cpu_hint;
	ctx->nodeid = cpu_to_node(cpu_hint);
	ctx->polling_timeout = polling_timeout;
	ctx->workqueue = xio_workqueue_create(ctx);
	if (!ctx->workqueue) {
		xio_set_error(ENOMEM);
		ERROR_LOG("xio_workqueue_init failed.\n");
		goto cleanup1;
	}

	XIO_OBSERVABLE_INIT(&ctx->observable, ctx);
	INIT_LIST_HEAD(&ctx->ctx_list);

	switch (flags) {
	case XIO_LOOP_USER_LOOP:
		break;
	case XIO_LOOP_GIVEN_THREAD:
		set_cpus_allowed_ptr(worker, cpumask_of(cpu_hint));
		ctx->worker = (uint64_t) worker;
		break;
	case XIO_LOOP_TASKLET:
		break;
	case XIO_LOOP_WORKQUEUE:
		break;
	default:
		ERROR_LOG("wrong type. %u\n", flags);
		goto cleanup2;
	}

	xio_root = xio_debugfs_root();
	if (xio_root) {
		/* More then one contexts can share the core */
		sprintf(name, "ctx-%d-%p", cpu_hint, worker);
		ctx->ctx_dentry = debugfs_create_dir(name, xio_root);
		if (!ctx->ctx_dentry) {
			ERROR_LOG("debugfs entry %s create failed\n", name);
			goto cleanup2;
		}
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

	xio_idr_add_uobj(ctx);
	return ctx;

cleanup3:
	debugfs_remove_recursive(ctx->ctx_dentry);
	ctx->ctx_dentry = NULL;

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
/* xio_context_destroy	                                                     */
/*---------------------------------------------------------------------------*/
void xio_context_destroy(struct xio_context *ctx)
{
	int i;
	int found;

	found = xio_idr_lookup_uobj(ctx);
	if (found) {
		xio_idr_remove_uobj(ctx);
	} else {
		ERROR_LOG("context not found:%p\n", ctx);
		xio_set_error(XIO_E_USER_OBJ_NOT_FOUND);
		return;
	}

	xio_observable_notify_all_observers(&ctx->observable,
					    XIO_CONTEXT_EVENT_CLOSE, NULL);
	xio_observable_unreg_all_observers(&ctx->observable);

	for (i = 0; i < XIO_STAT_LAST; i++)
		kfree(ctx->stats.name[i]);

	xio_workqueue_destroy(ctx->workqueue);

	/* can free only xio created loop */
	if (ctx->flags != XIO_LOOP_USER_LOOP)
		xio_ev_loop_destroy(ctx->ev_loop);

	ctx->ev_loop = NULL;

	debugfs_remove_recursive(ctx->ctx_dentry);
	ctx->ctx_dentry = NULL;

	XIO_OBSERVABLE_DESTROY(&ctx->observable);

	kfree(ctx);
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
		ERROR_LOG("xio_workqueue_del_delayed_work failed. err=%d\n",
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

int xio_context_is_loop_stopping(struct xio_context *ctx)
{
	struct xio_ev_loop *ev_loop = (struct xio_ev_loop *)ctx->ev_loop;
	return ev_loop->is_stopping(ev_loop->loop_object);
}

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
