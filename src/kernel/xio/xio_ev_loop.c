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

#include <xio_os.h>
#include "libxio.h"
#include "xio_log.h"
#include "xio_observer.h"
#include "xio_common.h"
#include "xio_ev_data.h"
#include "xio_ev_loop.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"

static void xio_append_ordered(struct llist_node *first,
			       struct llist_node *last,
			       struct xio_ev_loop *loop)
{
	if (loop->first)
		loop->last->next = first;
	else
		loop->first = first;
	loop->last = last;
}

/*---------------------------------------------------------------------------*/
/* forward declarations	of private API					     */
/*---------------------------------------------------------------------------*/

static int priv_ev_loop_run(void *loop_hndl);
static void priv_ev_loop_stop(void *loop_hndl);
static int priv_ev_is_loop_stopping(void *loop_hndl);

static void priv_ev_loop_run_tasklet(unsigned long data);
static void priv_ev_loop_run_work(struct work_struct *work);

static void priv_ev_loop_stop_thread(void *loop_hndl);

static int priv_ev_add_thread(void *loop_hndl, struct xio_ev_data *event);
static int priv_ev_add_tasklet(void *loop_hndl, struct xio_ev_data *event);
static int priv_ev_add_workqueue(void *loop_hndl, struct xio_ev_data *event);

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_init							     */
/*---------------------------------------------------------------------------*/
void *xio_ev_loop_init(unsigned long flags, struct xio_context *ctx,
		       struct xio_loop_ops *loop_ops)
{
	struct xio_ev_loop *loop;
	char queue_name[64];

	loop = kzalloc(sizeof(*loop), GFP_KERNEL);
	if (!loop) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kmalloc failed. %m\n");
		goto cleanup0;
	}

	set_bit(XIO_EV_LOOP_STOP, &loop->states);
	init_completion(&loop->complete);

	init_llist_head(&loop->ev_llist);
	loop->first = NULL;
	loop->last = NULL;

	/* use default implementation */
	loop->run  = priv_ev_loop_run;
	loop->stop = priv_ev_loop_stop;
	loop->is_stopping = priv_ev_is_loop_stopping;
	loop->loop_object = loop;

	switch (flags) {
	case XIO_LOOP_USER_LOOP:
		/* override with user provided routines and object */
		loop->run  = loop_ops->run;
		loop->stop = loop_ops->stop;
		loop->add_event = loop_ops->add_event;
		loop->loop_object = loop_ops->ev_loop;
		break;
	case XIO_LOOP_GIVEN_THREAD:
		loop->stop = priv_ev_loop_stop_thread;
		loop->add_event = priv_ev_add_thread;
		init_waitqueue_head(&loop->wait);
		break;
	case XIO_LOOP_TASKLET:
		loop->add_event = priv_ev_add_tasklet;
		tasklet_init(&loop->tasklet, priv_ev_loop_run_tasklet,
			     (unsigned long)loop);
		break;
	case XIO_LOOP_WORKQUEUE:
		/* temporary (also change to single thread) */
		sprintf(queue_name, "xio-%p", loop);
		/* check flags and backward  compatibility */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		loop->workqueue = create_workqueue(queue_name);
#else
		loop->workqueue = alloc_workqueue(queue_name,
						  WQ_MEM_RECLAIM | WQ_HIGHPRI,
						  0);
#endif
		if (!loop->workqueue) {
			ERROR_LOG("workqueue create failed.\n");
			goto cleanup1;
		}
		loop->add_event = priv_ev_add_workqueue;
		break;
	default:
		ERROR_LOG("wrong type. %lu\n", flags);
		goto cleanup1;
	}

	loop->flags = flags;
	loop->ctx = ctx;

	return loop;

cleanup1:
	clear_bit(XIO_EV_LOOP_STOP, &loop->states);
	kfree(loop);
cleanup0:
	ERROR_LOG("event loop creation failed.\n");
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_destroy							     */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_destroy(void *loop_hndl)
{
	struct xio_ev_loop *loop = (struct xio_ev_loop *)loop_hndl;

	if (!loop)
		return;

	if (test_bit(XIO_EV_LOOP_IN_HANDLER, &loop->states)) {
		ERROR_LOG("Can't destroy the loop from within handlers.\n");
		return;
	}

	if (test_and_set_bit(XIO_EV_LOOP_DOWN, &loop->states)) {
		ERROR_LOG("Down already in progress.\n");
		return;
	}

	set_bit(XIO_EV_LOOP_STOP, &loop->states);

	/* TODO: Clean all unhandled events !!!! */

	switch (loop->flags) {
	case XIO_LOOP_GIVEN_THREAD:
		if (!test_and_set_bit(XIO_EV_LOOP_WAKE, &loop->states))
			wake_up_interruptible(&loop->wait);
		if (test_bit(XIO_EV_LOOP_ACTIVE, &loop->states)) {
			TRACE_LOG("loop: wait_for_completion");
			wait_for_completion(&loop->complete);
		}
		break;
	case XIO_LOOP_TASKLET:
		tasklet_kill(&loop->tasklet);
		break;
	case XIO_LOOP_WORKQUEUE:
		flush_workqueue(loop->workqueue);
		destroy_workqueue(loop->workqueue);
		break;
	default:
		break;
	}

	kfree(loop);
}

/*---------------------------------------------------------------------------*/
/* priv_ev_add_thread							     */
/*---------------------------------------------------------------------------*/
static int priv_ev_add_thread(void *loop_hndl, struct xio_ev_data *event)
{
	struct xio_ev_loop *loop = (struct xio_ev_loop *)loop_hndl;

	/* don't add events */
	if (test_bit(XIO_EV_LOOP_DOWN, &loop->states))
		return 0;

	set_bit(XIO_EV_HANDLER_ENABLED, &event->states);
	if (!test_and_set_bit(XIO_EV_HANDLER_PENDING, &event->states))
		llist_add(&event->ev_llist, &loop->ev_llist);

	/* don't wake up */
	if (test_bit(XIO_EV_LOOP_STOP, &loop->states))
		return 0;

	if (!test_and_set_bit(XIO_EV_LOOP_WAKE, &loop->states))
		wake_up_interruptible(&loop->wait);

	return 0;
}

static void priv_ipi(void *loop_hndl)
{
	struct xio_ev_loop *loop = (struct xio_ev_loop *)loop_hndl;

	/* CSD can be reused */
	clear_bit(XIO_EV_LOOP_SCHED, &loop->states);

	/* don't wake up */
	if (test_bit(XIO_EV_LOOP_STOP, &loop->states))
		return;

	tasklet_schedule(&loop->tasklet);
}

/*---------------------------------------------------------------------------*/
/* priv_kick_tasklet							     */
/*---------------------------------------------------------------------------*/
static void priv_kick_tasklet(void *loop_hndl)
{
	struct xio_ev_loop *loop = (struct xio_ev_loop *)loop_hndl;
	int cpu;

	/* If EQ related interrupt was not assigned to the requested core,
	 * or if a event from another context is sent (e.g. module down event)
	 * and since tasklet runs on the core that schedule it IPI must be used
	 */
	cpu = get_cpu();
	if (likely(loop->ctx->cpuid == cpu)) {
		tasklet_schedule(&loop->tasklet);
		put_cpu();
		return;
	}
	put_cpu();

	/* check if CSD in use */
	if (test_and_set_bit(XIO_EV_LOOP_SCHED, &loop->states))
		return;

	/* can't use __smp_call_function_single it is GPL exported */
	smp_call_function_single(loop->ctx->cpuid, priv_ipi, loop_hndl, 0);
}

/*---------------------------------------------------------------------------*/
/* priv_ev_add_tasklet							     */
/*---------------------------------------------------------------------------*/
static int priv_ev_add_tasklet(void *loop_hndl, struct xio_ev_data *event)
{
	struct xio_ev_loop *loop = (struct xio_ev_loop *)loop_hndl;

	/* don't add events */
	if (test_bit(XIO_EV_LOOP_DOWN, &loop->states))
		return 0;

	set_bit(XIO_EV_HANDLER_ENABLED, &event->states);
	if (!test_and_set_bit(XIO_EV_HANDLER_PENDING, &event->states))
		llist_add(&event->ev_llist, &loop->ev_llist);

	/* don't wake up */
	if (test_bit(XIO_EV_LOOP_STOP, &loop->states))
		return 0;

	priv_kick_tasklet(loop_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* priv_ev_add_workqueue						     */
/*---------------------------------------------------------------------------*/
static int priv_ev_add_workqueue(void *loop_hndl, struct xio_ev_data *event)
{
	struct xio_ev_loop *loop = (struct xio_ev_loop *)loop_hndl;

	/* don't add events */
	if (test_bit(XIO_EV_LOOP_DOWN, &loop->states))
		return 0;

	set_bit(XIO_EV_HANDLER_ENABLED, &event->states);
	if (test_and_set_bit(XIO_EV_HANDLER_PENDING, &event->states))
		return 0;

	if (test_bit(XIO_EV_LOOP_STOP, &loop->states)) {
		/* delayed put in link list until resume */
		llist_add(&event->ev_llist, &loop->ev_llist);
		return 0;
	}

	INIT_WORK(&event->work, priv_ev_loop_run_work);
	queue_work_on(loop->ctx->cpuid, loop->workqueue, &event->work);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* priv_ev_loop_run_thread						     */
/*---------------------------------------------------------------------------*/
static void priv_ev_loop_run_thread(struct xio_ev_loop *loop)
{
	struct xio_ev_data	*tev;
	struct llist_node	*last, *first;
	struct llist_node	*node;
	unsigned long		start_time = jiffies;

	if (test_bit(XIO_EV_LOOP_IN_HANDLER, &loop->states)) {
		/* If a callback i.e. "tev->handler" stopped the loop,
		 * and then restart it by calling run than we must exit
		 */
		TRACE_LOG("call loop run while in handler\n");
		return;
	}

	set_bit(XIO_EV_LOOP_ACTIVE, &loop->states);
	if (test_bit(XIO_EV_LOOP_DOWN, &loop->states)) {
		complete(&loop->complete);
		clear_bit(XIO_EV_LOOP_ACTIVE, &loop->states);
		return;
	}

	/* loop can stopped and restarted, thus old events can be pending in
	 * order in the (first - last) list or new events (in reverse order)
	 * are queued in ev_llsits
	 */
	if (loop->first || !llist_empty(&loop->ev_llist)) {
		if (test_and_set_bit(XIO_EV_LOOP_WAKE, &loop->states))
			goto retry_wait; /* race detected */
		else
			goto retry_dont_wait; /* was one wake-up was called */
	}

retry_wait:

	wait_event_interruptible(loop->wait,
				 test_bit(XIO_EV_LOOP_WAKE, &loop->states));

	if (unlikely(test_bit(XIO_EV_LOOP_STOP, &loop->states)))
		goto stopped;

retry_dont_wait:

	while ((last = llist_del_all(&loop->ev_llist)) != NULL) {
		first = llist_reverse_order(last);
		xio_append_ordered(first, last, loop);
		node = loop->first;
		while (node) {
			tev = llist_entry(node, struct xio_ev_data, ev_llist);
			node = llist_next(node);
			loop->first = node;
			set_bit(XIO_EV_LOOP_IN_HANDLER, &loop->states);
			clear_bit(XIO_EV_HANDLER_PENDING, &tev->states);
			if (time_after(jiffies, start_time)) {
				/* schedule(); todo need to understand better */
				start_time = jiffies;
			}
			if (test_bit(XIO_EV_HANDLER_ENABLED, &tev->states))
				tev->handler(tev->data);
			clear_bit(XIO_EV_LOOP_IN_HANDLER, &loop->states);
		}
		loop->last = NULL;
		if (unlikely(test_bit(XIO_EV_LOOP_STOP, &loop->states)))
			goto stopped;
	}

	/* All events were processed prepare to wait */

	if (unlikely(test_bit(XIO_EV_LOOP_STOP, &loop->states)))
		goto stopped;

	/* "race point" */
	clear_bit(XIO_EV_LOOP_WAKE, &loop->states);

	/* if a new entry was added while we were at "race point"
	 * an event was added and loop was resumed,
	 * than wait event might block forever as condition is false
	 */
	if (llist_empty(&loop->ev_llist))
		goto retry_wait;

	if (test_and_set_bit(XIO_EV_LOOP_WAKE, &loop->states))
		goto retry_wait; /* bit is set add_event did set it  */
	else
		goto retry_dont_wait; /* add_event will not call wake up */

stopped:
	clear_bit(XIO_EV_LOOP_WAKE, &loop->states);
	if (test_bit(XIO_EV_LOOP_DOWN, &loop->states))
		complete(&loop->complete);
	clear_bit(XIO_EV_LOOP_ACTIVE, &loop->states);
}

/*---------------------------------------------------------------------------*/
/* priv_ev_loop_run_tasklet						     */
/*---------------------------------------------------------------------------*/
static void priv_ev_loop_run_tasklet(unsigned long data)
{
	struct xio_ev_loop *loop = (struct xio_ev_loop *)data;
	struct xio_ev_data	*tev;
	struct llist_node	*last, *first;
	struct llist_node	*node;

	while ((last = llist_del_all(&loop->ev_llist)) != NULL) {
		first = llist_reverse_order(last);
		xio_append_ordered(first, last, loop);
		node = loop->first;
		while (node) {
			if (unlikely(test_bit(XIO_EV_LOOP_STOP, &loop->states)))
				return;
			tev = llist_entry(node, struct xio_ev_data, ev_llist);
			node = llist_next(node);
			loop->first = node;
			set_bit(XIO_EV_LOOP_IN_HANDLER, &loop->states);
			clear_bit(XIO_EV_HANDLER_PENDING, &tev->states);
			if (test_bit(XIO_EV_HANDLER_ENABLED, &tev->states))
				tev->handler(tev->data);
			clear_bit(XIO_EV_LOOP_IN_HANDLER, &loop->states);
		}
		loop->last = NULL;
	}
}

/*---------------------------------------------------------------------------*/
/* priv_ev_loop_run_work						     */
/*---------------------------------------------------------------------------*/
static void priv_ev_loop_run_work(struct work_struct *work)
{
	struct xio_ev_data *tev = container_of(work, struct xio_ev_data, work);

	/*  CURRENTLY CAN'T MARK IN LOOP */
	clear_bit(XIO_EV_HANDLER_PENDING, &tev->states);
	if (test_bit(XIO_EV_HANDLER_ENABLED, &tev->states))
		tev->handler(tev->data);
}

/*---------------------------------------------------------------------------*/
/* priv_ev_loop_run							     */
/*---------------------------------------------------------------------------*/
int priv_ev_loop_run(void *loop_hndl)
{
	struct xio_ev_loop	*loop = loop_hndl;
	struct xio_ev_data	*tev;
	struct llist_node	*last, *first;
	struct llist_node	*node;
	int cpu;

	clear_bit(XIO_EV_LOOP_STOP, &loop->states);

	switch (loop->flags) {
	case XIO_LOOP_GIVEN_THREAD:
		if (unlikely(loop->ctx->worker != (uint64_t)get_current())) {
			ERROR_LOG("worker kthread(%p) is not current(%p).\n",
				  (void *)loop->ctx->worker, get_current());
			goto cleanup0;
		}
		/* no need to disable preemption */
		cpu = raw_smp_processor_id();
		if (loop->ctx->cpuid != cpu) {
			TRACE_LOG("worker on core(%d) scheduled to(%d).\n",
				  cpu, loop->ctx->cpuid);
			set_cpus_allowed_ptr(get_current(),
					     cpumask_of(loop->ctx->cpuid));
		}
		priv_ev_loop_run_thread(loop);
		return 0;
	case XIO_LOOP_TASKLET:
		/* were events added to list while in STOP state ? */
		if (!llist_empty(&loop->ev_llist))
			priv_kick_tasklet(loop_hndl);
		return 0;
	case XIO_LOOP_WORKQUEUE:
		/* were events added to list while in STOP state ? */
		while ((last = llist_del_all(&loop->ev_llist)) != NULL) {
			first = llist_reverse_order(last);
			xio_append_ordered(first, last, loop);
			node = loop->first;
			while (node) {
				tev = llist_entry(node, struct xio_ev_data,
						  ev_llist);
				node = llist_next(node);
				loop->first = node;
				INIT_WORK(&tev->work, priv_ev_loop_run_work);
				queue_work_on(loop->ctx->cpuid, loop->workqueue,
					      &tev->work);
			}
			loop->last = NULL;
		}
		return 0;
	default:
		/* undo */
		set_bit(XIO_EV_LOOP_STOP, &loop->states);
		return -1;
	}

cleanup0:
	set_bit(XIO_EV_LOOP_STOP, &loop->states);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* priv_ev_loop_stop							     */
/*---------------------------------------------------------------------------*/
void priv_ev_loop_stop(void *loop_hndl)
{
	struct xio_ev_loop *loop = loop_hndl;

	if (!loop)
		return;

	set_bit(XIO_EV_LOOP_STOP, &loop->states);
}

/*---------------------------------------------------------------------------*/
/* priv_ev_loop_stop							     */
/*---------------------------------------------------------------------------*/
void priv_ev_loop_stop_thread(void *loop_hndl)
{
	struct xio_ev_loop *loop = loop_hndl;

	if (!loop)
		return;

	set_bit(XIO_EV_LOOP_STOP, &loop->states);
	if (!test_and_set_bit(XIO_EV_LOOP_WAKE, &loop->states))
		wake_up_interruptible(&loop->wait);
}

/*---------------------------------------------------------------------------*/
/* priv_ev_is_loop_stopping						     */
/*---------------------------------------------------------------------------*/
int priv_ev_is_loop_stopping(void *loop_hndl)
{
	struct xio_ev_loop *loop = loop_hndl;

	if (!loop)
		return 0;

	return test_bit(XIO_EV_LOOP_STOP, &loop->states);
}
