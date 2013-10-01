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
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/topology.h>

#include "libxio.h"
#include "xio_common.h"
#include "xio_context.h"

/* friend routins from xio_ev_loop.c */
extern void *xio_ev_loop_init(unsigned long flags, struct xio_context *ctx);
extern void xio_ev_loop_destroy(void *loop_hndl);

/*---------------------------------------------------------------------------*/
/* xio_context_add_observer						     */
/*---------------------------------------------------------------------------*/
int xio_context_add_observer(struct xio_context *ctx, void *observer,
			     notification_handler_t notify_observer)
{
	struct xio_observer_node *observer_node, *tmp_observer_node;

	list_for_each_entry_safe(observer_node, tmp_observer_node,
				 &ctx->observers_list, observers_list_entry) {
		if (observer == observer_node->observer)
			return 0;
	}

	observer_node = kzalloc(sizeof(struct xio_observer_node), GFP_KERNEL);
	if (observer_node == NULL) {
		xio_set_error(ENOMEM);
		return -1;
	}
	observer_node->observer			= observer;
	observer_node->notification_handler	= notify_observer;
	list_add(&observer_node->observers_list_entry, &ctx->observers_list);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_context_remove_observer		                                     */
/*---------------------------------------------------------------------------*/
void xio_context_remove_observer(struct xio_context *ctx, void *observer)
{
	struct xio_observer_node *observer_node, *tmp_observer_node;

	list_for_each_entry_safe(observer_node, tmp_observer_node,
				 &ctx->observers_list, observers_list_entry) {
		if (observer_node->observer == observer) {
			/* Remove the item from the tail queue. */
			list_del(&observer_node->observers_list_entry);
			kfree(observer_node);
			break;
		}
	}
}

/*---------------------------------------------------------------------------*/
/* xio_context_free_observers_list					     */
/*---------------------------------------------------------------------------*/
static void xio_context_free_observers_list(struct xio_context *ctx)
{
	struct xio_observer_node *observer_node, *tmp_observer_node;

	list_for_each_entry_safe(observer_node, tmp_observer_node,
				 &ctx->observers_list, observers_list_entry) {
		/* Remove the item from the list. */
		list_del(&observer_node->observers_list_entry);
		kfree(observer_node);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_context_notify_all						     */
/*---------------------------------------------------------------------------*/
void xio_context_notify_all(struct xio_context *ctx, int event,
				       void *event_data)
{
	struct xio_observer_node *observer_node, *tmp_observer_node;

	list_for_each_entry_safe(observer_node, tmp_observer_node,
				 &ctx->observers_list, observers_list_entry) {
		observer_node->notification_handler(observer_node->observer,
						    ctx, event, event_data);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_open								     */
/*---------------------------------------------------------------------------*/
struct xio_context *xio_ctx_open(unsigned int flags,
				 struct xio_loop_ops *loop_ops,
				 struct task_struct *worker,
				 int polling_timeout,
				 int cpu_hint)
{
	struct xio_context *ctx;
	int cpu;

	if (cpu_hint >= num_online_cpus()) {
		xio_set_error(EINVAL);
		ERROR_LOG("cpu_hint(%d) >= num_online_cpus(%d)\n",
			  cpu_hint, num_online_cpus());
		goto cleanup0;
	}

	if ((flags == XIO_LOOP_USER_LOOP) &&
	    (!(loop_ops && loop_ops->ev_loop_add_event && loop_ops->ev_loop))) {
		xio_set_error(EINVAL);
		ERROR_LOG("loop_ops and ev_loop and ev_loop_add_event are mandatory with loop_ops\n");
		goto cleanup0;
	}

	xio_read_logging_level();

	cpu = smp_processor_id();
	if (cpu == -1)
		goto cleanup0;

	/* allocate new context */
	ctx = kzalloc(sizeof(struct xio_context), GFP_KERNEL);
	if (ctx == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("calloc failed. %m\n");
		goto cleanup0;
	}

	if (cpu_hint < 0)
		cpu_hint = smp_processor_id();

	ctx->flags = flags;
	ctx->cpuid  = cpu_hint;
	ctx->nodeid = cpu_to_node(cpu_hint);
	ctx->polling_timeout = polling_timeout;

	INIT_LIST_HEAD(&ctx->observers_list);

	switch (flags) {
	case XIO_LOOP_USER_LOOP:
		ctx->ev_loop = loop_ops->ev_loop;
		memcpy(&ctx->loop_ops, loop_ops, sizeof(ctx->loop_ops));
		return ctx;
	case XIO_LOOP_GIVEN_THREAD:
		ctx->worker = (uint64_t) worker;
		break;
	case XIO_LOOP_TASKLET:
		break;
	case XIO_LOOP_WORKQUEUE:
		break;
	default:
		ERROR_LOG("wrong type. %u\n", flags);
		goto cleanup1;
	}

	ctx->ev_loop = xio_ev_loop_init(flags, ctx);
	if (!ctx->ev_loop)
		goto cleanup1;

	return ctx;

cleanup1:
	kfree(ctx);

cleanup0:
	ERROR_LOG("xio_ctx_open ailed\n");

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_close							     */
/*---------------------------------------------------------------------------*/
void xio_ctx_close(struct xio_context *ctx)
{
	xio_context_notify_all(ctx, XIO_CONTEXT_EVENT_CLOSE, NULL);
	xio_context_free_observers_list(ctx);

	/* can free olny xio created loop */
	if (ctx->flags != XIO_LOOP_USER_LOOP)
		xio_ev_loop_destroy(ctx->ev_loop);

	ctx->ev_loop = NULL;

	kfree(ctx);
}
