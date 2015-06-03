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

#define XIO_MS_IN_SEC   1000ULL
#define XIO_US_IN_SEC   1000000ULL
#define XIO_NS_IN_SEC   1000000000ULL
#define XIO_US_IN_MSEC  1000ULL
#define XIO_NS_IN_MSEC  1000000ULL
#define XIO_NS_IN_USEC  1000ULL
#define SAFE_LIST

#define xio_timer_handle_t void *

struct xio_timers_list {
	struct list_head		timers_head;
#ifdef SAFE_LIST
	spinlock_t			lock; /* timer list lock */
	int				pad;
#endif
};

enum timers_list_rc {
	TIMERS_LIST_RC_ERROR			= -1,
	TIMERS_LIST_RC_OK			=  0,
	TIMERS_LIST_RC_EMPTY			=  1,
	TIMERS_LIST_RC_BECAME_FIRST_ENTRY	=  2,
	TIMERS_LIST_RC_NOT_EMPTY		=  3,
};

static inline void xio_timers_list_lock(struct xio_timers_list *timers_list)
{
#ifdef SAFE_LIST
	spin_lock(&timers_list->lock);
#endif
}

static inline void xio_timers_list_unlock(struct xio_timers_list *timers_list)
{
#ifdef SAFE_LIST
	spin_unlock(&timers_list->lock);
#endif
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_ns_current_get					     */
/*---------------------------------------------------------------------------*/
static inline uint64_t xio_timers_list_ns_current_get(void)
{
	uint64_t	ns_monotonic;
	struct timespec ts;

	xio_clock_gettime(&ts);

	ns_monotonic = (ts.tv_sec*XIO_NS_IN_SEC) + (uint64_t)ts.tv_nsec;

	return ns_monotonic;
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_init							     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_init(struct xio_timers_list *timers_list)
{
	INIT_LIST_HEAD(&timers_list->timers_head);
#ifdef SAFE_LIST
	spin_lock_init(&timers_list->lock);
#endif
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_add							     */
/*---------------------------------------------------------------------------*/
static inline enum timers_list_rc xio_timers_list_add(
				       struct xio_timers_list *timers_list,
				       struct xio_timers_list_entry *tentry)
{
	struct list_head		*timer_list;
	struct xio_timers_list_entry	*tentry_from_list;
	int				found = 0;
	enum timers_list_rc		retval = TIMERS_LIST_RC_OK;

	list_for_each(timer_list, &timers_list->timers_head) {
		tentry_from_list = list_entry(timer_list,
					      struct xio_timers_list_entry,
					      entry);

		if (time_before64(tentry->expires,
				  tentry_from_list->expires)) {
			list_add_tail(&tentry->entry, &tentry_from_list->entry);
			found = 1;
			break; /* for timer iteration */
		}
	}
	if (found == 0)
		list_add_tail(&tentry->entry, &timers_list->timers_head);

	if (list_first_entry(&timers_list->timers_head,
			     struct xio_timers_list_entry, entry) == tentry)
		retval = TIMERS_LIST_RC_BECAME_FIRST_ENTRY;

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_add_duration						     */
/*---------------------------------------------------------------------------*/
static inline enum timers_list_rc xio_timers_list_add_duration(
			struct xio_timers_list *timers_list,
			uint64_t ns_duration,
			struct xio_timers_list_entry *tentry)
{
	tentry->expires			=
		(xio_timers_list_ns_current_get() + ns_duration);

	return xio_timers_list_add(timers_list, tentry);
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_del							     */
/*---------------------------------------------------------------------------*/
static inline enum timers_list_rc xio_timers_list_del(
				       struct xio_timers_list *timers_list,
				       struct xio_timers_list_entry *tentry)
{
	enum timers_list_rc	      retval = TIMERS_LIST_RC_OK;

	if (list_empty(&timers_list->timers_head)) {
		retval = TIMERS_LIST_RC_EMPTY;
		goto unlock;
	}

	list_del_init(&tentry->entry);

	if (list_empty(&timers_list->timers_head))
		retval = TIMERS_LIST_RC_EMPTY;
	else
		retval = TIMERS_LIST_RC_NOT_EMPTY;
unlock:
	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_close						     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_close(struct xio_timers_list *timers_list)
{
	struct xio_timers_list_entry	*tentry;

	xio_timers_list_lock(timers_list);
	while (!list_empty(&timers_list->timers_head)) {
		tentry = list_first_entry(
			&timers_list->timers_head,
			struct xio_timers_list_entry, entry);
		list_del_init(&tentry->entry);
	}
	xio_timers_list_unlock(timers_list);
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_expires						     */
/*---------------------------------------------------------------------------*/
static inline uint64_t xio_timers_list_expires(
			struct xio_timers_list *timers_list,
			struct xio_timers_list_entry *tentry)
{
	return tentry->expires;
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_pre_dispatch						     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_pre_dispatch(
			struct xio_timers_list *timers_list,
			struct xio_timers_list_entry *tentry)
{
	list_del_init(&tentry->entry);
}

/*---------------------------------------------------------------------------*/
/* xio_timers_list_post_dispatch					     */
/*---------------------------------------------------------------------------*/
static inline void xio_timers_list_post_dispatch(
			struct xio_timers_list *timers_list,
			struct xio_timers_list_entry *tentry)
{
}

/*
 * returns the number of msec until the next timer will expire for
 * use with epoll
 */
/*---------------------------------------------------------------------------*/
/* xio_timers_list_ns_duration_to_expire				     */
/*---------------------------------------------------------------------------*/
static inline int64_t xio_timerlist_ns_duration_to_expire(
			struct xio_timers_list *timers_list)
{
	struct xio_timers_list_entry	*tentry;
	int64_t				current_time;
	int64_t				ns_duration_to_expire;

	/*
	 * empty list, no expire
	 */
	if (list_empty(&timers_list->timers_head))
		return -1;

	tentry = list_first_entry(
			&timers_list->timers_head,
			struct xio_timers_list_entry, entry);

	current_time = xio_timers_list_ns_current_get();

	/*
	 * timer at head of list is expired, zero ns required
	 */
	if (time_after64(current_time, tentry->expires))
		return 0;

	ns_duration_to_expire = (tentry->expires - current_time);

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
	struct xio_timers_list_entry	*tentry;
	uint64_t			current_time;
	xio_delayed_work_handle_t	*dwork;
	xio_work_handle_t		*work;

	xio_timers_list_lock(timers_list);
	while (!list_empty(&timers_list->timers_head)) {
		tentry = list_first_entry(&timers_list->timers_head,
					  struct xio_timers_list_entry, entry);

		current_time = xio_timers_list_ns_current_get();

		if (time_before_eq64(tentry->expires, current_time)) {
			xio_timers_list_pre_dispatch(timers_list,
						     tentry);

			xio_timers_list_unlock(timers_list);
			dwork = container_of(tentry,
					     xio_delayed_work_handle_t,
					     timer);
			work = &dwork->work;
			work->flags &= ~XIO_WORK_PENDING;

			work->function(work->data);

			xio_timers_list_post_dispatch(timers_list,
						      tentry);
			xio_timers_list_lock(timers_list);
		} else {
			break; /* for timer iteration */
		}
	}
	xio_timers_list_unlock(timers_list);
}

static inline int xio_timers_list_is_empty(struct xio_timers_list *timers_list)
{
	return list_empty(&timers_list->timers_head);
}

#endif /* XIO_TIMERS_LIST_H */

