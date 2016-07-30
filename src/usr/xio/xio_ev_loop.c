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
#include <sys/eventfd.h>
#include <sys/epoll.h>

#include <xio_os.h>
#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "get_clock.h"
#include "xio_ev_data.h"
#include "xio_ev_loop.h"

#define MAX_DELETED_EVENTS	1024

/*---------------------------------------------------------------------------*/
/* structs                                                                   */
/*---------------------------------------------------------------------------*/
struct xio_ev_loop {
	int				efd;
	/* flags */
	volatile uint32_t		in_dispatch:1;
	volatile uint32_t		stop_loop:1;
	volatile uint32_t		wakeup_armed:1;
	volatile uint32_t		pad:29;

	int				wakeup_event;
	int				deleted_events_nr;
	struct list_head		poll_events_list;
	struct list_head		events_list;
	struct xio_ev_data		*deleted_events[MAX_DELETED_EVENTS];
};

/*---------------------------------------------------------------------------*/
/* epoll_to_xio_poll_events                                                  */
/*---------------------------------------------------------------------------*/
static inline uint32_t epoll_to_xio_poll_events(uint32_t epoll_events)
{
	uint32_t xio_events = 0;

	if (epoll_events & EPOLLIN)
		xio_events |= XIO_POLLIN;
	if (epoll_events & EPOLLOUT)
		xio_events |= XIO_POLLOUT;
	if (epoll_events & EPOLLRDHUP)
		xio_events |= XIO_POLLRDHUP;
	if (epoll_events & EPOLLET)
		xio_events |= XIO_POLLET;
	if (epoll_events & EPOLLONESHOT)
		xio_events |= XIO_ONESHOT;
	if (epoll_events & EPOLLHUP)
		xio_events |= XIO_POLLHUP;
	if (epoll_events & EPOLLERR)
		xio_events |= XIO_POLLERR;

	return xio_events;
}

/*---------------------------------------------------------------------------*/
/* xio_to_epoll_poll_events                                                  */
/*---------------------------------------------------------------------------*/
static inline uint32_t xio_to_epoll_poll_events(uint32_t xio_events)
{
	uint32_t epoll_events = 0;

	if (xio_events & XIO_POLLIN)
		epoll_events |= EPOLLIN;
	if (xio_events & XIO_POLLOUT)
		epoll_events |= EPOLLOUT;
	if (xio_events & XIO_POLLRDHUP)
		epoll_events |= EPOLLRDHUP;
	if (xio_events & XIO_POLLET)
		epoll_events |= EPOLLET;
	if (xio_events & XIO_ONESHOT)
		epoll_events |= EPOLLONESHOT;
	if (xio_events & XIO_POLLHUP)
		epoll_events |= EPOLLHUP;
	if (xio_events & XIO_POLLERR)
		epoll_events |= EPOLLERR;

	return epoll_events;
}

/*---------------------------------------------------------------------------*/
/* xio_event_add                                                           */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_add(void *loop_hndl, int fd, int events,
		    xio_ev_handler_t handler, void *data)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop *)loop_hndl;
	struct epoll_event	ev;
	struct xio_ev_data	*tev = NULL;
	int			err;

	memset(&ev, 0, sizeof(ev));
	ev.events = xio_to_epoll_poll_events(events);

	if (fd != loop->wakeup_event) {
		tev = (struct xio_ev_data *)ucalloc(1, sizeof(*tev));
		if (!tev) {
			xio_set_error(errno);
			ERROR_LOG("calloc failed, %m\n");
			return -1;
		}
		tev->data	= data;
		tev->ev_handler	= handler;
		tev->fd		= fd;

		list_add(&tev->events_list_entry, &loop->poll_events_list);
	}

	ev.data.ptr = tev;
	err = epoll_ctl(loop->efd, EPOLL_CTL_ADD, fd, &ev);
	if (err) {
		if (fd != loop->wakeup_event)
			list_del(&tev->events_list_entry);
		xio_set_error(errno);
		if (errno != EEXIST)
			ERROR_LOG("epoll_ctl failed fd:%d,  %m\n", fd);
		else
			DEBUG_LOG("epoll_ctl already exists fd:%d,  %m\n", fd);
		ufree(tev);
	}

	return err;
}

/*---------------------------------------------------------------------------*/
/* xio_event_lookup							     */
/*---------------------------------------------------------------------------*/
static struct xio_ev_data *xio_event_lookup(void *loop_hndl, int fd)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop *)loop_hndl;
	struct xio_ev_data	*tev;

	list_for_each_entry(tev, &loop->poll_events_list, events_list_entry) {
		if (tev->fd == fd)
			return tev;
	}
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_del							     */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_del(void *loop_hndl, int fd)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop *)loop_hndl;
	struct xio_ev_data	*tev;
	int ret;

	if (fd != loop->wakeup_event) {
		tev = xio_event_lookup(loop, fd);
		if (!tev) {
			xio_set_error(ENOENT);
			ERROR_LOG("event lookup failed. fd:%d\n", fd);
			return -1;
		}
		list_del(&tev->events_list_entry);
		if (loop->deleted_events_nr < MAX_DELETED_EVENTS) {
			loop->deleted_events[loop->deleted_events_nr] = tev;
			loop->deleted_events_nr++;
		} else {
			ERROR_LOG("failed to delete event\n");
		}
	}

	ret = epoll_ctl(loop->efd, EPOLL_CTL_DEL, fd, NULL);
	if (ret < 0) {
		xio_set_error(errno);
		ERROR_LOG("epoll_ctl failed. %m\n");
	}

	return ret;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_modify							     */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_modify(void *loop_hndl, int fd, int events)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop *)loop_hndl;
	struct epoll_event	ev;
	struct xio_ev_data	*tev = NULL;
	int			retval;

	if (fd != loop->wakeup_event) {
		tev = xio_event_lookup(loop, fd);
		if (!tev) {
			xio_set_error(ENOENT);
			ERROR_LOG("event lookup failed. fd:%d\n", fd);
			return -1;
		}
	}

	memset(&ev, 0, sizeof(ev));
	ev.events	= xio_to_epoll_poll_events(events);
	ev.data.ptr	= tev;

	retval = epoll_ctl(loop->efd, EPOLL_CTL_MOD, fd, &ev);
	if (retval != 0) {
		xio_set_error(errno);
		ERROR_LOG("epoll_ctl failed. efd:%d, fd:%d %m\n",
			  loop->efd, fd);
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_create							     */
/*---------------------------------------------------------------------------*/
void *xio_ev_loop_create()
{
	struct xio_ev_loop	*loop;
	int			retval;
	eventfd_t		val = 1;

	loop = (struct xio_ev_loop *)ucalloc(1, sizeof(struct xio_ev_loop));
	if (!loop) {
		xio_set_error(errno);
		ERROR_LOG("calloc failed. %m\n");
		return NULL;
	}

	INIT_LIST_HEAD(&loop->poll_events_list);
	INIT_LIST_HEAD(&loop->events_list);

	loop->stop_loop		= 0;
	loop->wakeup_armed	= 0;
	loop->deleted_events_nr = 0;
	loop->efd		= epoll_create1(EPOLL_CLOEXEC);
	if (loop->efd == -1) {
		xio_set_error(errno);
		ERROR_LOG("epoll_create failed. %m\n");
		goto cleanup;
	}

	/* prepare the wakeup eventfd */
	loop->wakeup_event	= eventfd(0, EFD_NONBLOCK);
	if (loop->wakeup_event == -1) {
		xio_set_error(errno);
		ERROR_LOG("eventfd failed. %m\n");
		goto cleanup1;
	}
	/* ADD & SET the wakeup fd and once application wants to arm
	 * just MODify the already prepared eventfd to the epoll */
	xio_ev_loop_add(loop, loop->wakeup_event, 0, NULL, NULL);
	retval = eventfd_write(loop->wakeup_event, val);
	if (retval != 0)
		goto cleanup2;

	return loop;

cleanup2:
	close(loop->wakeup_event);
cleanup1:
	close(loop->efd);
cleanup:
	ufree(loop);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_init_event						     */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_init_event(struct xio_ev_data *evt,
			    xio_event_handler_t event_handler, void *data)
{
	evt->handler = event_handler;
	evt->scheduled = 0;
	evt->data = data;
	INIT_LIST_HEAD(&evt->events_list_entry);
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_add_event						     */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_add_event(void *_loop, struct xio_ev_data *evt)
{
	struct xio_ev_loop *loop = (struct xio_ev_loop *)_loop;

	if (!evt->scheduled) {
		evt->scheduled = 1;
		list_add_tail(&evt->events_list_entry,
			      &loop->events_list);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_remove_event						     */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_remove_event(struct xio_ev_data *evt)
{
	if (evt->scheduled) {
		evt->scheduled = 0;
		list_del_init(&evt->events_list_entry);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_is_pending_event						     */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_is_pending_event(struct xio_ev_data *evt)
{
	return evt->scheduled;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_exec_scheduled						     */
/*---------------------------------------------------------------------------*/
static int xio_ev_loop_exec_scheduled(struct xio_ev_loop *loop)
{
	struct list_head	*last_sched;
	struct list_head	*events_list_entry;
	struct xio_ev_data	*tev, *tevn;
	xio_event_handler_t	event_handler;
	void			*event_data;
	int work_remains = 0;

	if (!list_empty(&loop->events_list)) {
		/* execute only work scheduled till now */
		last_sched = loop->events_list.prev;
		list_for_each_entry_safe(tev, tevn, &loop->events_list,
					 events_list_entry) {
			xio_ev_loop_remove_event(tev);
			/* copy the relevant fields tev can be freed in
			 * callback
			 */
			event_handler		= tev->handler;
			event_data		= tev->data;
			events_list_entry	= &tev->events_list_entry;
			event_handler(event_data);
			if (events_list_entry == last_sched)
				break;
		}
		if (!list_empty(&loop->events_list))
			work_remains = 1;
	}
	return work_remains;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_deleted_event_lookup					     */
/*---------------------------------------------------------------------------*/
static inline int xio_ev_loop_deleted_event_lookup(struct xio_ev_loop *loop,
						   struct xio_ev_data *tev)
{
	int j;

	for (j = 0; j < loop->deleted_events_nr; j++) {
		if (loop->deleted_events[j] == tev)
			return 1;
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_run_helper                                                    */
/*---------------------------------------------------------------------------*/
static inline int xio_ev_loop_run_helper(void *loop_hndl, int timeout)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop *)loop_hndl;
	int			nevent = 0, i, found = 0;
	struct epoll_event	events[1024];
	struct xio_ev_data	*tev;
	int			work_remains;
	int			tmout;
	int			wait_time = timeout;
	uint32_t		out_events;
	cycles_t		start_cycle  = 0;

	if (timeout != -1)
		start_cycle = get_cycles();

retry:
	work_remains = xio_ev_loop_exec_scheduled(loop);
	tmout = work_remains ? 0 : timeout;

	/* free deleted event handlers */
	if (unlikely(loop->deleted_events_nr))
		while (loop->deleted_events_nr)
			ufree(loop->deleted_events[--loop->deleted_events_nr]);

	nevent = epoll_wait(loop->efd, events, ARRAY_SIZE(events), tmout);
	if (unlikely(nevent < 0)) {
		if (errno != EINTR) {
			xio_set_error(errno);
			ERROR_LOG("epoll_wait failed. %m\n");
			return -1;
		}
		goto retry;
	} else if (nevent > 0) {
		/* save the epoll modify in "stop" while dispatching handlers */
		loop->in_dispatch = 1;
		for (i = 0; i < nevent; i++) {
			tev = (struct xio_ev_data *)events[i].data.ptr;
			if (likely(tev)) {
				/* look for deleted event handlers */
				if (unlikely(loop->deleted_events_nr)) {
					found =
					  xio_ev_loop_deleted_event_lookup(
								   loop, tev);
					if (found)
						break;

					continue;
				}
				out_events =
					epoll_to_xio_poll_events(
							events[i].events);
				/* (fd != loop->wakeup_event) */
				tev->ev_handler(tev->fd, out_events,
						tev->data);
			} else {
				/* wakeup event auto-removed from epoll
				 * due to ONESHOT
				 * */

				/* check wakeup is armed to prevent false
				 * wake ups
				 * */
				if (loop->wakeup_armed == 1) {
					loop->wakeup_armed = 0;
					loop->stop_loop = 1;
				}
			}
		}
		loop->in_dispatch = 0;
	} else {
		/* timed out */
		if (tmout || timeout == 0)
			loop->stop_loop = 1;
		/* TODO: timeout should be updated by the elapsed
		 * duration of each loop
		 * */
	}
	/* calculate the remaining timeout */
	if (timeout != -1 && !loop->stop_loop) {
		int time_passed = (int)((get_cycles() -
				start_cycle)/(1000*g_mhz) + 0.5);
		if (time_passed >= wait_time)
			loop->stop_loop = 1;
		else
			timeout = wait_time - time_passed;
	}

	if (likely(loop->stop_loop == 0)) {
		goto retry;
	} else {
		/* drain events before returning */
		while (!list_empty(&loop->events_list))
			xio_ev_loop_exec_scheduled(loop);

		/* free deleted event handlers */
		while (loop->deleted_events_nr)
			ufree(loop->deleted_events[--loop->deleted_events_nr]);
	}

	loop->stop_loop = 0;
	loop->wakeup_armed = 0;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_run_timeout						     */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_run_timeout(void *loop_hndl, int timeout_msec)
{
	return xio_ev_loop_run_helper(loop_hndl, timeout_msec);
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_run                                                           */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_run(void *loop_hndl)
{
	return xio_ev_loop_run_helper(loop_hndl, -1 /* block indefinitely */);
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_stop							     */
/*---------------------------------------------------------------------------*/
inline void xio_ev_loop_stop(void *loop_hndl)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop *)loop_hndl;

	if (!loop || loop->efd == -1)
		return;

	if (loop->stop_loop == 1)
		return; /* loop is already marked for stopping (and also
			   armed for wakeup from blocking) */
	loop->stop_loop = 1;

	if (loop->in_dispatch || loop->wakeup_armed == 1)
		return; /* wakeup is still armed, probably left loop in previous
			   cycle due to other reasons (timeout, events) */
	loop->wakeup_armed = 1;
	xio_ev_loop_modify(loop, loop->wakeup_event,
			   XIO_POLLIN | XIO_ONESHOT);
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_destroy                                                       */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_destroy(void *loop_hndl)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop *)loop_hndl;
	struct xio_ev_data	*tev, *tmp_tev;

	if (!loop)
		return;

	/* mark loop as stopped */
	loop->stop_loop = 1;
	list_for_each_entry_safe(tev, tmp_tev, &loop->poll_events_list,
				 events_list_entry) {
		xio_ev_loop_del(loop, tev->fd);
	}

	list_for_each_entry_safe(tev, tmp_tev, &loop->events_list,
				 events_list_entry) {
		xio_ev_loop_remove_event(tev);
	}

	/* free deleted event handlers */
	while (loop->deleted_events_nr)
		ufree(loop->deleted_events[--loop->deleted_events_nr]);

	xio_ev_loop_del(loop, loop->wakeup_event);

	close(loop->efd);
	loop->efd = -1;

	close(loop->wakeup_event);
	loop->wakeup_event = -1;

	ufree(loop);
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_poll_wait					             */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_poll_wait(void *loop_hndl, int timeout_ms)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop *)loop_hndl;

	loop->stop_loop = 1;
	return xio_ev_loop_run_helper(loop, timeout_ms);
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_get_poll_fd                                               */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_get_poll_fd(void *loop_hndl)
{
	struct xio_ev_loop  *loop = (struct xio_ev_loop *)loop_hndl;

	if (!loop_hndl) {
		xio_set_error(EINVAL);
		return -1;
	}
	return loop->efd;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_is_stopping						     */
/*---------------------------------------------------------------------------*/
inline int xio_ev_loop_is_stopping(void *loop_hndl)
{
	return loop_hndl ? ((struct xio_ev_loop	*)loop_hndl)->stop_loop : 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_reset_stop						     */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_reset_stop(void *loop_hndl)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop *)loop_hndl;

	loop->stop_loop = 0;
	loop->wakeup_armed = 0;
}

