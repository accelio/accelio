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
#include <linux/version.h>

#include "libxio.h"
#include "xio_os.h"

#include "xio_common.h"
#include "xio_workqueue.h"
#include "xio_log.h"
#include "xio_observer.h"
#include "xio_context.h"

struct xio_workqueue {
	struct xio_context	*ctx;
	struct workqueue_struct	*workqueue;
};

/*---------------------------------------------------------------------------*/
/* xio_workqueue_create							     */
/*---------------------------------------------------------------------------*/
struct xio_workqueue *xio_workqueue_create(struct xio_context *ctx)
{
	struct xio_workqueue *workqueue;
	char queue_name[64];

	workqueue = kmalloc(sizeof(*workqueue), GFP_KERNEL);
	if (workqueue == NULL) {
		ERROR_LOG("kmalloc failed. %m\n");
		return NULL;
	}

	/* temp (also change to single thread) */
	sprintf(queue_name, "xio-scheuler-%p", ctx);
	/* check flags and bw comp */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	workqueue->workqueue = create_workqueue(queue_name);
#else
	workqueue->workqueue = alloc_workqueue(queue_name,
						WQ_MEM_RECLAIM | WQ_HIGHPRI,
						0);
#endif
	if (!workqueue->workqueue) {
		ERROR_LOG("workqueue create failed.\n");
		goto cleanup1;
	}

	workqueue->ctx = ctx;

	return workqueue;

cleanup1:
	kfree(workqueue);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_destroy						     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_destroy(struct xio_workqueue *work_queue)
{
	flush_workqueue(work_queue->workqueue);
	destroy_workqueue(work_queue->workqueue);

	kfree(work_queue);

	return 0;
}

static void xio_ev_callback(void *user_context)
{
	struct xio_work *work = user_context;

	if (!test_bit(XIO_WORK_CANCELED, &work->flags))
		work->function(work->data);
	clear_bit(XIO_WORK_PENDING, &work->flags);
}

static void xio_dwork_callback(struct work_struct *workp)
{
	struct xio_delayed_work *dw;
	struct xio_work *work;
	struct xio_ev_data *ev_data;

	dw = container_of(workp, struct xio_delayed_work, dwork.work);
	work = &dw->work;
	ev_data = &work->ev_data;
	/* Add event to event queue */

	ev_data->handler = xio_ev_callback;
	ev_data->data    = work;

	/* tell "poller mechanism" */
	if (!test_bit(XIO_WORK_CANCELED, &work->flags))
		xio_context_add_event(work->ctx, ev_data);
	else
		clear_bit(XIO_WORK_PENDING, &work->flags);
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_add_delayed_work					     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_add_delayed_work(struct xio_workqueue *workqueue,
				   int msec_duration, void *data,
				   void (*function)(void *data),
				   xio_delayed_work_handle_t *dwork)

{
	struct xio_work *work = &dwork->work;
	struct xio_context *ctx = workqueue->ctx;
	unsigned long delay_jiffies;

	if (test_and_set_bit(XIO_WORK_PENDING, &dwork->work.flags)) {
		/* work already pending */
		TRACE_LOG("work already pending.\n");
		return -1;
	}
	clear_bit(XIO_WORK_CANCELED, &dwork->work.flags);

	work->data = data;
	work->function = function;
	work->ctx = ctx;

	INIT_DELAYED_WORK(&dwork->dwork, xio_dwork_callback);

	delay_jiffies = msecs_to_jiffies(msec_duration);

	/* queue the work */
	if (!queue_delayed_work_on(ctx->cpuid, workqueue->workqueue,
				   &dwork->dwork, delay_jiffies)) {
		ERROR_LOG("work already queued?.\n");
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_del_delayed_work					     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_del_delayed_work(struct xio_workqueue *workqueue,
				   xio_delayed_work_handle_t *dwork)
{
	/* work could be already in event loop */
	set_bit(XIO_WORK_CANCELED, &dwork->work.flags);

	if (!workqueue->workqueue) {
		ERROR_LOG("No schedwork\n");
		return -1;
	}

	if (cancel_delayed_work_sync(&dwork->dwork)) {
		clear_bit(XIO_WORK_PENDING, &dwork->work.flags);
		return 0;
	}

	ERROR_LOG("Pending work wasn't found\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_add_work						     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_add_work(struct xio_workqueue *workqueue,
			   void *data,
			   void (*function)(void *data),
			   xio_work_handle_t *work)
{
	struct xio_context *ctx = workqueue->ctx;
	struct xio_ev_data *ev_data;

	if (test_and_set_bit(XIO_WORK_PENDING, &work->flags)) {
		/* work already pending in event queue */
		TRACE_LOG("work already pending.\n");
		return -1;
	}
	clear_bit(XIO_WORK_CANCELED, &work->flags);

	work->data = data;
	work->function = function;
	work->ctx = ctx;

	ev_data = &work->ev_data;

	/* Add event to event queue */
	ev_data->handler = xio_ev_callback;
	ev_data->data    = work;

	/* tell "poller mechanism" */
	xio_context_add_event(work->ctx, ev_data);

	return 0;
}
/*---------------------------------------------------------------------------*/
/* xio_workqueue_del_work						     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_del_work(struct xio_workqueue *work_queue,
			   xio_work_handle_t *work)
{
	/* work can only be marked canceled */
	set_bit(XIO_WORK_CANCELED, &work->flags);
	if (!test_bit(XIO_WORK_PENDING, &work->flags)) {
		/* work not pending */
		TRACE_LOG("work not pending.\n");
		return -1;
	}

	/* work is pending must wait for callback from event handler */
	return 0;
}
