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
#include "xio_schedwork.h"
#include "xio_log.h"
#include "xio_observer.h"
#include "xio_context.h"

struct xio_schedwork {
	struct xio_context	*ctx;
	struct workqueue_struct	*workqueue;
};

struct xio_delayed_work {
	struct	delayed_work	dwork;
	struct xio_context	*ctx;
	void			(*timer_fn)(void *data);
	void			*data;
	struct xio_ev_data	ev_data;
};


/*---------------------------------------------------------------------------*/
/* xio_schedwork_init							     */
/*---------------------------------------------------------------------------*/
struct xio_schedwork *xio_schedwork_init(struct xio_context *ctx)
{
	struct xio_schedwork *sched_work;
	char queue_name[64];

	sched_work = kmalloc(sizeof(*sched_work), GFP_KERNEL);
	if (sched_work == NULL) {
		ERROR_LOG("kmalloc failed. %m\n");
		return NULL;
	}

	/* temp (also change to single thread) */
	sprintf(queue_name, "xio-scheuler-%p", ctx);
	/* check flags and bw comp */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	sched_work->workqueue = create_workqueue(queue_name);
#else
	sched_work->workqueue = alloc_workqueue(queue_name,
						WQ_MEM_RECLAIM | WQ_HIGHPRI,
						0);
#endif
	if (!sched_work->workqueue) {
		ERROR_LOG("workqueue create failed.\n");
		goto cleanup1;
	}

	sched_work->ctx = ctx;

	return sched_work;

cleanup1:
	kfree(sched_work);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_schedwork_close							     */
/*---------------------------------------------------------------------------*/
int xio_schedwork_close(struct xio_schedwork *sched_work)
{
	flush_workqueue(sched_work->workqueue);
	destroy_workqueue(sched_work->workqueue);

	kfree(sched_work);

	return 0;
}

static void xio_ev_callback(void *user_context)
{
	struct xio_delayed_work *xdwork = user_context;

	xdwork->timer_fn(xdwork->data);

	kfree(xdwork);
}

static void xio_work_callback(struct work_struct *work)
{
	struct xio_delayed_work *xdwork;
	struct xio_ev_data *ev_data;

	xdwork = container_of(work, struct xio_delayed_work, dwork.work);

	ev_data = &xdwork->ev_data;
	/* Add event to event queue */

	ev_data->handler = xio_ev_callback;
	ev_data->data    = xdwork;

	/* tell "poller mechanism" */
	xio_context_add_event(xdwork->ctx, ev_data);
}

/*---------------------------------------------------------------------------*/
/* xio_schedwork_add							     */
/*---------------------------------------------------------------------------*/
int xio_schedwork_add(struct xio_schedwork *sched_work,
		      int msec_duration, void *data,
		      void (*timer_fn)(void *data),
		      xio_schedwork_handle_t *handle_out)
{
	struct xio_delayed_work *xdwork;
	struct xio_context *ctx = sched_work->ctx;
	unsigned long delay_jiffies;

	xdwork = kmalloc(sizeof(*xdwork), GFP_KERNEL);
	if (!xdwork) {
		ERROR_LOG("kmalloc failed.\n");
		return -1;
	}

	xdwork->data = data;
	xdwork->timer_fn = timer_fn;
	xdwork->ctx = ctx;

	INIT_DELAYED_WORK(&xdwork->dwork, xio_work_callback);

	delay_jiffies = msecs_to_jiffies(msec_duration);

	/* queue the work */
	if (!queue_delayed_work_on(ctx->cpuid, sched_work->workqueue,
	                           &xdwork->dwork, delay_jiffies)) {
		ERROR_LOG("work already queued?.\n");
		return -1;
	}

	/* for cancellation */
	*handle_out = xdwork;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_schedwork_del							     */
/*---------------------------------------------------------------------------*/
int xio_schedwork_del(struct xio_schedwork *sched_work, void* handle)
{
	struct xio_delayed_work *xdwork;

	if (!sched_work->workqueue) {
		ERROR_LOG("No schedwork\n");
		return -1;
	}

	xdwork = (struct xio_delayed_work *) handle;

	if (cancel_delayed_work_sync(&xdwork->dwork)) {
		kfree(xdwork);
		return 0;
	}

	ERROR_LOG("Pending work wasn't found\n");
	return -1;
}

