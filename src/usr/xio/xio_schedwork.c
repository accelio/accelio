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

#include "xio_schedwork.h"
#include "xio_log.h"
#include "xio_observer.h"
#include "xio_context.h"
#include "xio_timers_list.h"



struct xio_schedwork {
	struct xio_context		*ctx;
	struct xio_timers_list		timers_list;
	int				timer_fd;
	int				armed_timer;
};

#define NSEC_PER_SEC    1000000000L

/**
 * set_normalized_timespec - set timespec sec and nsec parts and
 * normalize
 *
 * @ts:         pointer to timespec variable to be set
 * @sec:        seconds to set
 * @nsec:       nanoseconds to set
 *
 * Set seconds and nanoseconds field of a timespec variable and
 * normalize to the timespec storage format
 *
 * Note: The tv_nsec part is always in the range of
 *      0 <= tv_nsec < NSEC_PER_SEC
 * For negative values only the tv_sec field is negative !
 */
static void set_normalized_timespec(struct timespec *ts,
				    time_t sec, int64_t nsec)
{
	while (nsec >= XIO_NS_IN_SEC) {
		nsec -= XIO_NS_IN_SEC;
		++sec;
	}
	while (nsec < 0) {
		nsec += XIO_NS_IN_SEC;
		--sec;
	}
	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}

/*---------------------------------------------------------------------------*/
/* xio_schedwork_rearm							     */
/*---------------------------------------------------------------------------*/
static int xio_schedwork_rearm(struct xio_schedwork *sched_work)
{
	struct itimerspec new_t = { {0, 0}, {0, 0} };
	int		  err;
	int64_t		  ns_to_expire;

	ns_to_expire =
		xio_timerlist_ns_duration_to_expire(
			&sched_work->timers_list);

	if (ns_to_expire == -1 && !sched_work->armed_timer)
		return 0;

	if (ns_to_expire == -1) {
		new_t.it_value.tv_nsec = 0;
	} else if (ns_to_expire < 1) {
		new_t.it_value.tv_nsec = 1;
	} else {
		set_normalized_timespec(&new_t.it_value,
					0, ns_to_expire);
	}

	/* rearm the timer */
	err = timerfd_settime(sched_work->timer_fd, 0, &new_t, NULL);
	if (err < 0) {
		ERROR_LOG("timerfd_settime failed. %m\n");
		return -1;
	}

	if (ns_to_expire == -1)
		sched_work->armed_timer = 0;
	else
		sched_work->armed_timer = 1;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_timed_action_handler						     */
/*---------------------------------------------------------------------------*/
static void xio_timed_action_handler(int fd, int events, void *user_context)
{
	struct xio_schedwork	*sched_work = user_context;
	int64_t			exp;
	ssize_t			s;

	/* consume the timer data in fd */
	s = read(sched_work->timer_fd, &exp, sizeof(exp));
	if (s < 0) {
		if (errno != EAGAIN)
			ERROR_LOG("failed to read from timerfd, %m\n");
		return;
	}
	if (s != sizeof(uint64_t)) {
		ERROR_LOG("failed to read from timerfd, %m\n");
		return;
	}
	sched_work->armed_timer = 0;

	xio_timers_list_expire(&sched_work->timers_list);

	xio_schedwork_rearm(sched_work);
}

/*---------------------------------------------------------------------------*/
/* xio_schedwork_init							     */
/*---------------------------------------------------------------------------*/
struct xio_schedwork *xio_schedwork_init(struct xio_context *ctx)
{
	struct xio_schedwork	*sched_work;
	int			retval;

	sched_work = ucalloc(1, sizeof(*sched_work));
	if (sched_work == NULL) {
		ERROR_LOG("ucalloc failed. %m\n");
		return NULL;
	}

	xio_timers_list_init(&sched_work->timers_list);
	sched_work->ctx = ctx;

	sched_work->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (sched_work->timer_fd < 0) {
		ERROR_LOG("timerfd_create failed. %m\n");
		ufree(sched_work);
		return NULL;
	}

	/* add to epoll */
	retval = xio_context_add_ev_handler(
			ctx,
			sched_work->timer_fd,
			XIO_POLLIN,
			xio_timed_action_handler,
			sched_work);
	if (retval) {
		ERROR_LOG("ev_loop_add_cb failed. %m\n");
		close(sched_work->timer_fd);
		ufree(sched_work);
		return NULL;
	}

	return sched_work;
}

/*---------------------------------------------------------------------------*/
/* xio_schedwork_close							     */
/*---------------------------------------------------------------------------*/
int xio_schedwork_close(struct xio_schedwork *sched_work)
{
	int retval;

	retval = xio_context_del_ev_handler(
			sched_work->ctx,
			sched_work->timer_fd);
	if (retval)
		ERROR_LOG("ev_loop_del_cb failed. %m\n");

	xio_timers_list_close(&sched_work->timers_list);
	retval = xio_schedwork_rearm(sched_work);
	if (retval)
		ERROR_LOG("xio_schedwork_rearm failed. %m\n");

	close(sched_work->timer_fd);
	ufree(sched_work);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_schedwork_add							     */
/*---------------------------------------------------------------------------*/
int xio_schedwork_add(struct xio_schedwork *sched_work,
		      int msec_duration, void *data,
		      void (*timer_fn)(void *data),
		      xio_schedwork_handle_t *handle_out)
{
	int	retval;

	xio_timers_list_add_duration(
			&sched_work->timers_list,
			timer_fn, data,
			((uint64_t)msec_duration) * 1000000ULL,
			handle_out);

	/* rearm the timer */
	retval = xio_schedwork_rearm(sched_work);
	if (retval)
		ERROR_LOG("xio_schedwork_rearm failed. %m\n");


	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_schedwork_del							     */
/*---------------------------------------------------------------------------*/
int xio_schedwork_del(struct xio_schedwork *sched_work,
		      xio_schedwork_handle_t timer_handle)
{
	int	retval;

	xio_timers_list_del(
			&sched_work->timers_list,
			timer_handle);

	/* rearm the timer */
	retval = xio_schedwork_rearm(sched_work);
	if (retval)
		ERROR_LOG("xio_schedwork_rearm failed. %m\n");


	return retval;
}

