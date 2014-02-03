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
#ifndef XIO_TIMERS_LIST_H
#define XIO_TIMERS_LIST_H

#include "xio_os.h"


#define XIO_MS_IN_SEC   1000ULL
#define XIO_US_IN_SEC   1000000ULL
#define XIO_NS_IN_SEC   1000000000ULL
#define XIO_US_IN_MSEC  1000ULL
#define XIO_NS_IN_MSEC  1000000ULL
#define XIO_NS_IN_USEC  1000ULL

#define xio_timer_handle_t void *


struct xio_timers_list {
	struct list_head		timer_head;
	struct list_head		*timer_iter;
};

struct xio_timers_list_timer {
	struct list_head		list;
	uint64_t			expire_time;
	int				is_absolute_timer;
	int				pad;
	void				(*timer_fn)(void *data);
	void				*data;
	xio_timer_handle_t		handle_addr;
};

/*---------------------------------------------------------------------------*/
/* xio_timers_list_init							     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_init(struct xio_timers_list *timers_list)
{
	INIT_LIST_HEAD(&timers_list->timer_head);
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_ns_from_epoch					     */
/*---------------------------------------------------------------------------*/
static inline uint64_t xio_timers_list_ns_from_epoch(void)
{
	uint64_t	ns_from_epoch;
	struct timeval	time_from_epoch;

	gettimeofday(&time_from_epoch, 0);

	ns_from_epoch = ((time_from_epoch.tv_sec * XIO_NS_IN_SEC) +
			 (time_from_epoch.tv_usec * XIO_NS_IN_USEC));

	return ns_from_epoch;
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_ns_current_get					     */
/*---------------------------------------------------------------------------*/
static inline uint64_t xio_timers_list_ns_current_get(void)
{
	uint64_t	ns_monotonic;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	ns_monotonic = (ts.tv_sec*XIO_NS_IN_SEC) + (uint64_t)ts.tv_nsec;
	return ns_monotonic;
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_ns_monotonic_freq					     */
/*---------------------------------------------------------------------------*/
static inline uint64_t xio_timers_list_ns_monotonic_freq(void)
{
	uint64_t	ns_monotonic_freq;
	struct timespec ts;

	clock_getres(CLOCK_MONOTONIC, &ts);

	ns_monotonic_freq = XIO_NS_IN_SEC/((ts.tv_sec * XIO_NS_IN_SEC) +
			    ts.tv_nsec);

	return ns_monotonic_freq;
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_add							     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_add(struct xio_timers_list *timers_list,
				       struct xio_timers_list_timer *timer)
{
	struct list_head		*timer_list = NULL;
	struct xio_timers_list_timer	*timer_from_list;
	int				found = 0;

	for (timer_list = timers_list->timer_head.next;
	     timer_list != &timers_list->timer_head;
	     timer_list = timer_list->next) {
		timer_from_list = list_entry(timer_list,
					     struct xio_timers_list_timer,
					     list);

		if (timer_from_list->expire_time > timer->expire_time) {
			list_add(&timer->list, timer_list->prev);
			found = 1;
			break; /* for timer iteration */
		}
	}
	if (found == 0)
		list_add(&timer->list, timers_list->timer_head.prev);
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_add_absolute						     */
/*---------------------------------------------------------------------------*/
static inline int xio_timers_list_add_absolute(
			struct xio_timers_list *timers_list,
			void (*timer_fn) (void *data),
			void *data,
			uint64_t ns_from_epoch,
			xio_timer_handle_t *handle)
{
	struct xio_timers_list_timer *timer;

	timer = (struct xio_timers_list_timer *)ucalloc(1,
					sizeof(struct xio_timers_list_timer));
	if (timer == 0) {
		errno = ENOMEM;
		return -1;
	}

	timer->expire_time		= ns_from_epoch;
	timer->is_absolute_timer	= 1;
	timer->data			= data;
	timer->timer_fn			= timer_fn;
	timer->handle_addr		= handle;
	xio_timers_list_add(timers_list, timer);

	*handle = timer;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_add_duration						     */
/*---------------------------------------------------------------------------*/
static inline int xio_timers_list_add_duration(
			struct xio_timers_list *timers_list,
			void (*timer_fn) (void *data),
			void *data,
			uint64_t ns_duration,
			xio_timer_handle_t *handle)
{
	struct xio_timers_list_timer *timer;

	timer = (struct xio_timers_list_timer *)ucalloc(1,
					sizeof(struct xio_timers_list_timer));
	if (timer == 0) {
		errno = ENOMEM;
		return -1;
	}

	timer->expire_time	 = xio_timers_list_ns_current_get() +
				   ns_duration;
	timer->is_absolute_timer = 0;
	timer->data		 = data;
	timer->timer_fn		 = timer_fn;
	timer->handle_addr	 = handle;

	xio_timers_list_add(timers_list, timer);

	*handle = timer;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_del							     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_del(struct xio_timers_list *timers_list,
				       xio_timer_handle_t timer_handle)
{
	struct xio_timers_list_timer *timer =
				(struct xio_timers_list_timer *)timer_handle;

	memset(timer->handle_addr, 0, sizeof(struct xio_timers_list_timer *));
	/*
	 * If the next timer after the currently expiring timer because
	 * xio_timers_list_del is called from a timer handler, get to the next
	 * timer
	 */
	if (timers_list->timer_iter == &timer->list)
		timers_list->timer_iter = timers_list->timer_iter->next;

	list_del_init(&timer->list);
	ufree(timer);
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_close						     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_close(struct xio_timers_list *timers_list)
{
	struct xio_timers_list_timer	*timer_list, *next_timer_list;

	list_for_each_entry_safe(timer_list, next_timer_list,
				 &timers_list->timer_head,
				 list) {
		xio_timers_list_del(timers_list, timer_list);
	}
}
/*---------------------------------------------------------------------------*/
/* xio_timers_list_expire_time						     */
/*---------------------------------------------------------------------------*/
static inline uint64_t xio_timers_list_expire_time(
			struct xio_timers_list *timers_list,
			xio_timer_handle_t timer_handle)
{
	struct xio_timers_list_timer *timer =
			(struct xio_timers_list_timer *)timer_handle;

	return timer->expire_time;
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_pre_dispatch						     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_pre_dispatch(
			struct xio_timers_list *timers_list,
			xio_timer_handle_t timer_handle)
{
	struct xio_timers_list_timer *timer =
			(struct xio_timers_list_timer *)timer_handle;

	memset(timer->handle_addr, 0, sizeof(struct timerlist_timer *));
	list_del_init(&timer->list);
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_post_dispatch					     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_post_dispatch(
			struct xio_timers_list *timers_list,
			xio_timer_handle_t timer_handle)
{
	struct xio_timers_list_timer *timer =
			(struct xio_timers_list_timer *)timer_handle;

	ufree(timer);
}

/*
 * returns the number of msec until the next timer will expire for
 * use with epoll
 */
/*---------------------------------------------------------------------------*/
/* xio_timers_list_ns_duration_to_expire				     */
/*---------------------------------------------------------------------------*/
static inline uint64_t xio_timerlist_ns_duration_to_expire(
			struct xio_timers_list *timers_list)
{
	struct xio_timers_list_timer	*timer_from_list;
	uint64_t			current_time;
	uint64_t			ns_duration_to_expire;
	static uint64_t			hz = -1;

	/*
	 * empty list, no expire
	 */
	if (timers_list->timer_head.next == &timers_list->timer_head)
		return -1;

	if (hz == -1)
		hz = xio_timers_list_ns_monotonic_freq();

	timer_from_list = list_entry(timers_list->timer_head.next,
		struct xio_timers_list_timer, list);

	if (timer_from_list->is_absolute_timer)
		current_time = xio_timers_list_ns_from_epoch();
	else
		current_time = xio_timers_list_ns_current_get();

	/*
	 * timer at head of list is expired, zero ns required
	 */
	if (timer_from_list->expire_time < current_time)
		return 0;

	ns_duration_to_expire =
		(timer_from_list->expire_time - current_time);

	return ns_duration_to_expire;
}

/*
 * Expires any timers that should be expired
 */
/*---------------------------------------------------------------------------*/
/* xio_timers_list_expire						     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_expire(struct xio_timers_list *timers_list)
{
	struct xio_timers_list_timer	*timer_from_list;
	uint64_t			current_time_from_epoch;
	uint64_t			current_monotonic_time;
	uint64_t			current_time;

	current_monotonic_time	= xio_timers_list_ns_current_get();
	current_time		= xio_timers_list_ns_from_epoch();
	current_time_from_epoch = current_time;

	for (timers_list->timer_iter = timers_list->timer_head.next;
		timers_list->timer_iter != &timers_list->timer_head;) {
		timer_from_list = list_entry(timers_list->timer_iter,
			struct xio_timers_list_timer, list);

		current_time = (timer_from_list->is_absolute_timer ?
				current_time_from_epoch :
				current_monotonic_time);

		if (timer_from_list->expire_time < current_time) {
			timers_list->timer_iter =
					timers_list->timer_iter->next;

			xio_timers_list_pre_dispatch(timers_list,
						     timer_from_list);

			timer_from_list->timer_fn(timer_from_list->data);

			xio_timers_list_post_dispatch(timers_list,
						      timer_from_list);
		} else {
			break; /* for timer iteration */
		}
	}
	timers_list->timer_iter = 0;
}

#endif /* XIO_TIMERS_LIST_H */

