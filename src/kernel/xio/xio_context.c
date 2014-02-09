/*
 * Copyright (c) 2013 Mellanox Technologies��. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies�� BSD license
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
 *      - Neither the name of the Mellanox Technologies�� nor the names of its
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
#include "xio_observer.h"
#include "xio_common.h"
#include "xio_context.h"
#include "xio_schedwork.h"
#include "xio_ev_loop.h"

/*---------------------------------------------------------------------------*/
/* xio_context_reg_observer						     */
/*---------------------------------------------------------------------------*/
int xio_context_reg_observer(struct xio_context *ctx,
			     struct xio_observer *observer)
{
	xio_observable_reg_observer(&ctx->observable, observer);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_context_unreg_observer		                                     */
/*---------------------------------------------------------------------------*/
void xio_context_unreg_observer(struct xio_context *ctx,
				struct xio_observer *observer)
{
	xio_observable_unreg_observer(&ctx->observable, observer);
}

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
		ERROR_LOG("loop_ops and ev_loop and ev_loop_add_event are mandatory with loop_ops\n");
		goto cleanup0;
	}

	xio_read_logging_level();

	cpu = get_cpu();
	put_cpu();
	if (cpu == -1)
		goto cleanup0;

	/* allocate new context */
	ctx = kzalloc(sizeof(struct xio_context), GFP_KERNEL);
	if (ctx == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kzalloc failed\n");
		goto cleanup0;
	}

	if (cpu_hint < 0) {
		cpu_hint = get_cpu();
		put_cpu();
	}

	ctx->flags = flags;
	ctx->cpuid  = cpu_hint;
	ctx->nodeid = cpu_to_node(cpu_hint);
	ctx->polling_timeout = polling_timeout;
	ctx->sched_work = xio_schedwork_init(ctx);
	if (!ctx->sched_work) {
		xio_set_error(ENOMEM);
		ERROR_LOG("xio_schedwork_init failed.\n");
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

	ctx->ev_loop = xio_ev_loop_init(flags, ctx, loop_ops);
	if (!ctx->ev_loop)
		goto cleanup2;

	ctx->stats.hertz = HZ;
	/* Init default counters' name */
	ctx->stats.name[XIO_STAT_TX_MSG]   = kstrdup("TX_MSG", GFP_KERNEL);
	ctx->stats.name[XIO_STAT_RX_MSG]   = kstrdup("RX_MSG", GFP_KERNEL);
	ctx->stats.name[XIO_STAT_TX_BYTES] = kstrdup("TX_BYTES", GFP_KERNEL);
	ctx->stats.name[XIO_STAT_RX_BYTES] = kstrdup("RX_BYTES", GFP_KERNEL);
	ctx->stats.name[XIO_STAT_DELAY]    = kstrdup("DELAY", GFP_KERNEL);
	ctx->stats.name[XIO_STAT_APPDELAY] = kstrdup("APPDELAY", GFP_KERNEL);

	return ctx;

cleanup2:
	xio_schedwork_close(ctx->sched_work);

cleanup1:
	kfree(ctx);

cleanup0:
	ERROR_LOG("xio_ctx_open ailed\n");

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_context_destroy	                                                     */
/*---------------------------------------------------------------------------*/
void xio_context_destroy(struct xio_context *ctx)
{
	int i;

	xio_observable_notify_all_observers(&ctx->observable,
					    XIO_CONTEXT_EVENT_CLOSE, NULL);
	xio_observable_unreg_all_observers(&ctx->observable);

	for (i = 0; i < XIO_STAT_LAST; i++)
		if (ctx->stats.name[i])
			kfree(ctx->stats.name[i]);

	xio_schedwork_close(ctx->sched_work);

	/* can free only xio created loop */
	if (ctx->flags != XIO_LOOP_USER_LOOP)
		xio_ev_loop_destroy(ctx->ev_loop);

	ctx->ev_loop = NULL;

	kfree(ctx);
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_timer_add							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_timer_add(struct xio_context *ctx,
		      int msec_duration, void *data,
		      void (*timer_fn)(void *data),
		      xio_ctx_timer_handle_t *handle_out)
{
	int retval;

	retval = xio_schedwork_add(ctx->sched_work,
				   msec_duration, data,
				   timer_fn, handle_out);
	if (retval) {
		xio_set_error(ENOMEM);
		ERROR_LOG("xio_schedwork_add failed.\n");
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_timer_del							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_timer_del(struct xio_context *ctx,
		      xio_ctx_timer_handle_t timer_handle)
{
	int retval;

	retval = xio_schedwork_del(ctx->sched_work, timer_handle);
	if (retval) {
		xio_set_error(ENOMEM);
		ERROR_LOG("xio_schedwork_add failed.\n");
	}

	return retval;
}

int xio_context_run_loop(struct xio_context *ctx)
{
	struct xio_ev_loop *ev_loop = (struct xio_ev_loop *)ctx->ev_loop;
	return ev_loop->run(ev_loop->loop_object);
}

void xio_context_stop_loop(struct xio_context *ctx)
{
	struct xio_ev_loop *ev_loop = (struct xio_ev_loop *)ctx->ev_loop;
	ev_loop->stop(ev_loop->loop_object);
}

int xio_context_add_event(struct xio_context *ctx, struct xio_ev_data *data)
{
	struct xio_ev_loop *ev_loop = (struct xio_ev_loop *)ctx->ev_loop;
	return ev_loop->add_event(ev_loop->loop_object, data);
}
