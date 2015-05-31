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
#include <xio_os.h>

#include "xio_log.h"
#include "xio_common.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue_priv.h"
#include "xio_observer.h"
#include "xio_ev_loop.h"
#include "xio_context.h"
#include "xio_context_priv.h"

struct xio_workqueue {
	struct xio_context	*ctx;
	struct workqueue_struct	*workqueue;
	spinlock_t		lock;		/* workqueue lock */
};

/*---------------------------------------------------------------------------*/
/* xio_workqueue_create							     */
/*---------------------------------------------------------------------------*/
struct xio_workqueue *xio_workqueue_create(struct xio_context *ctx)
{
	struct xio_workqueue *workqueue;
	char queue_name[64];

	workqueue = kmalloc(sizeof(*workqueue), GFP_KERNEL);
	if (!workqueue) {
		ERROR_LOG("kmalloc failed.\n");
		return NULL;
	}

	/* temporary (also change to single thread) */
	sprintf(queue_name, "xio-scheduler-%p", ctx);
	/* check flags and backward  compatibility */
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
	spin_lock_init(&workqueue->lock);

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
	int deleted = 0;
	struct xio_uwork *uwork = user_context;
	int try_destroy = 0;

	set_bit(XIO_WORK_RUNNING, &uwork->flags);
	if (test_bit(XIO_WORK_CANCELED, &uwork->flags)) {
		clear_bit(XIO_WORK_PENDING, &uwork->flags);
	} else {
		void (*function)(void *data);
		void *data;
		/* Must clear pending before calling the function
		 * in case the function deletes the work or the
		 * enclosing structure. Note that since the function
		 * can reuse the work structure after clearing the
		 * pending flag then we must use temporary variables
		 */
		function = uwork->function;
		data = uwork->data;
		/* Set running before clearing pending */
		clear_bit(XIO_WORK_PENDING, &uwork->flags);
		uwork->deleted = &deleted;
		set_bit(XIO_WORK_IN_HANDLER, &uwork->flags);
		function(data);
		if (deleted)
			return;
		clear_bit(XIO_WORK_IN_HANDLER, &uwork->flags);
		try_destroy = !!uwork->destructor;
	}
	clear_bit(XIO_WORK_RUNNING, &uwork->flags);
	complete(&uwork->complete);
	if (try_destroy)
		uwork->destructor(uwork->destructor_data);
}

static void xio_uwork_add_event(struct xio_uwork *uwork)
{
	struct xio_ev_data *ev_data;

	if (test_bit(XIO_WORK_CANCELED, &uwork->flags)) {
		clear_bit(XIO_WORK_PENDING, &uwork->flags);
		return;
	}

	/* This routine is called on context core */

	ev_data = &uwork->ev_data;
	ev_data->handler = xio_ev_callback;
	ev_data->data    = uwork;

	xio_context_add_event(uwork->ctx, ev_data);
}

static void xio_dwork_callback(struct work_struct *workp)
{
	struct xio_delayed_work *dwork;
	struct xio_uwork *uwork;

	dwork = container_of(workp, struct xio_delayed_work, dwork.work);
	uwork = &dwork->uwork;

	xio_uwork_add_event(uwork);
}

static void xio_work_callback(struct work_struct *workp)
{
	struct xio_work *work;
	struct xio_uwork *uwork;

	work = container_of(workp, struct xio_work, work);
	uwork = &work->uwork;

	xio_uwork_add_event(uwork);
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_del_uwork2						     */
/*---------------------------------------------------------------------------*/
static int xio_workqueue_del_uwork2(struct xio_workqueue *workqueue,
				    struct xio_uwork *uwork)
{
	/* Work is in event loop queue or running, can wait for its completion
	 * only if on other workers context
	 */

	if (workqueue->ctx == uwork->ctx) {
		if (test_bit(XIO_WORK_IN_HANDLER, &uwork->flags)) {
			/* simple self cancellation detected
			 * it doesn't detect loop cancellation
			 */
			TRACE_LOG("self cancellation.\n");
			clear_bit(XIO_WORK_IN_HANDLER, &uwork->flags);
			clear_bit(XIO_WORK_RUNNING, &uwork->flags);
			*uwork->deleted = 1;
		} else {
			/* It is O.K. to arm a work and then to cancel it but
			 * waiting for it will create a lockout situation.
			 * that is this context needs to block until completion
			 * is signaled from this context.
			 * since the work was marked canceled in phase 1 it
			 * is guaranteed not to run in the future.
			 */
			/*
			 * TODO We might have an issue in case the
			 * xio_ev_callback event was already added to the loop,
			 * and meanwhile the work was/will be freed from another
			 * event in this context.
			 * In this case, we need to remove xio_ev_callback event
			 * from the loop here, but we do not support this right
			 * now...
			 * The best solution for now is to add event for freeing
			 * the work, after canceling the work.
			 * Need to make sure to do this in each of the objects
			 * containing a work, e.g. nexus, connection, ...
			 */
			xio_context_disable_event(&uwork->ev_data);
		}
		return 0;
	}

	/* work may be on event handler */
	/* TODO: tasklet version? */
	if (in_atomic()) {
		ERROR_LOG("Can't wait for cancellation in atomic context.\n");
		return -1;
	}

	wait_for_completion(&uwork->complete);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_del_uwork1						     */
/*---------------------------------------------------------------------------*/
static int xio_workqueue_del_uwork1(struct xio_workqueue *workqueue,
				    struct xio_uwork *uwork)
{
	int ret;

	if (!test_bit(XIO_WORK_INITIALIZED, &uwork->flags)) {
		ERROR_LOG("work not initialized.\n");
		return -1;
	}

	if (!workqueue->workqueue) {
		ERROR_LOG("No work-queue\n");
		return -1;
	}

	if (test_and_set_bit(XIO_WORK_CANCELED, &uwork->flags)) {
		/* Already canceled */
		return 0;
	}

	if (test_bit(XIO_WORK_RUNNING, &uwork->flags)) {
		/* In xio_ev_callback go directly to phase 2 */
		TRACE_LOG("phase1 -> phase2.\n");
		ret = xio_workqueue_del_uwork2(workqueue, uwork);
		return ret;
	}

	if (!test_bit(XIO_WORK_PENDING, &uwork->flags)) {
		/* work not pending (run done) */
		TRACE_LOG("work not pending.\n");
		return 0;
	}

	/* need to cancel the work */
	return 1;
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_del_delayed_work					     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_del_delayed_work(struct xio_workqueue *workqueue,
				   xio_delayed_work_handle_t *dwork)
{
	struct xio_uwork *uwork = &dwork->uwork;
	int ret;

	ret = xio_workqueue_del_uwork1(workqueue, uwork);
	if (ret <= 0)
		return ret;

	/* need to cancel the work */
	if (cancel_delayed_work_sync(&dwork->dwork)) {
		clear_bit(XIO_WORK_PENDING, &uwork->flags);
		return 0;
	}

	ret = xio_workqueue_del_uwork2(workqueue, uwork);

	return ret;
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_del_work						     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_del_work(struct xio_workqueue *workqueue,
			   xio_work_handle_t *work)
{
	struct xio_uwork *uwork = &work->uwork;
	int ret;

	ret = xio_workqueue_del_uwork1(workqueue, uwork);
	if (ret <= 0)
		return ret;

	/* need to cancel the work */
	if (cancel_work_sync(&work->work)) {
		clear_bit(XIO_WORK_PENDING, &uwork->flags);
		return 0;
	}

	ret = xio_workqueue_del_uwork2(workqueue, uwork);

	return ret;
}

static int xio_init_uwork(struct xio_context *ctx,
			  struct xio_uwork *uwork,
			  void *data,
			  void (*function)(void *data))
{
	if (test_and_set_bit(XIO_WORK_PENDING, &uwork->flags)) {
		/* work already pending */
		TRACE_LOG("work already pending.\n");
		return -1;
	}
	clear_bit(XIO_WORK_CANCELED, &uwork->flags);

	if (test_and_set_bit(XIO_WORK_INITIALIZED, &uwork->flags)) {
		/* re-arm completion */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
		INIT_COMPLETION(uwork->complete);
#else
		reinit_completion(&uwork->complete);
#endif
	} else {
		init_completion(&uwork->complete);
	}

	uwork->data = data;
	uwork->function = function;
	uwork->ctx = ctx;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_add_delayed_work					     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_add_delayed_work(struct xio_workqueue *workqueue,
				   int msec_duration, void *data,
				   void (*function)(void *data),
				   xio_delayed_work_handle_t *dwork)

{
	struct xio_uwork *uwork = &dwork->uwork;
	struct xio_context *ctx = workqueue->ctx;
	unsigned long delay_jiffies;

	if (xio_init_uwork(ctx, uwork, data, function) < 0) {
		ERROR_LOG("initialization of work failed.\n");
		return -1;
	}

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
/* xio_workqueue_add_work						     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_add_work(struct xio_workqueue *workqueue,
			   void *data,
			   void (*function)(void *data),
			   xio_work_handle_t *work)
{
	struct xio_uwork *uwork = &work->uwork;
	struct xio_context *ctx = workqueue->ctx;

	if (xio_init_uwork(ctx, uwork, data, function) < 0) {
		ERROR_LOG("initialization of work failed.\n");
		return -1;
	}

	INIT_WORK(&work->work, xio_work_callback);

	/* queue the work */
	if (!queue_work_on(ctx->cpuid, workqueue->workqueue, &work->work)) {
		ERROR_LOG("work already queued?.\n");
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_set_work_destructor					     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_set_work_destructor(struct xio_workqueue *work_queue,
				      void *data,
				      void (*destructor)(void *data),
				      xio_work_handle_t *work)
{
	struct xio_uwork *uwork = &work->uwork;

	uwork->destructor	= destructor;
	uwork->destructor_data	= data;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_workqueue_is_work_in_hanlder					     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_is_work_in_handler(struct xio_workqueue *work_queue,
				     xio_work_handle_t *work)
{
	struct xio_uwork *uwork = &work->uwork;

	return test_bit(XIO_WORK_IN_HANDLER, &uwork->flags);
}

