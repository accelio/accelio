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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>

#include <libxio.h>
#include "xio_common.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/*---------------------------------------------------------------------------*/
/* structs                                                                   */
/*---------------------------------------------------------------------------*/
struct xio_ev_data {
	xio_ev_handler_t		handler;
	void				*data;
	int				fd;
	int				reserved;
	struct list_head		events_list_entry;
};

struct xio_ev_loop {
	int				efd;
	int				stop_loop;
	int				wakeup_event;
	int				wait;

	struct list_head		events_list;
};

/*---------------------------------------------------------------------------*/
/* xio_event_add                                                           */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_add(void *loop_hndl, int fd, int events,
		xio_ev_handler_t handler, void *data)
{
	struct xio_ev_loop	*loop = loop_hndl;
	struct epoll_event	ev;
	struct xio_ev_data	*tev;
	int			err;

	tev = calloc(1, sizeof(*tev));
	if (!tev) {
		xio_set_error(errno);
		ERROR_LOG("calloc failed, %m\n");
		return -1;
	}
	tev->data	= data;
	tev->handler	= handler;
	tev->fd		= fd;

	memset(&ev, 0, sizeof(ev));
	if (events & XIO_POLLIN)
		ev.events |= EPOLLIN;
	if (events & XIO_POLLOUT)
		ev.events |= EPOLLOUT;
	/* default is edge triggered */
	if (!(events & XIO_POLLLT))
		ev.events |= EPOLLET;

	ev.data.ptr = tev;
	err = epoll_ctl(loop->efd, EPOLL_CTL_ADD, fd, &ev);
	if (err) {
		xio_set_error(errno);
		ERROR_LOG("epoll_ctl failed fd:%d,  %m\n", fd);
		free(tev);
	} else {
		list_add(&tev->events_list_entry, &loop->events_list);
	}

	return err;
}

/*---------------------------------------------------------------------------*/
/* xio_event_lookup							     */
/*---------------------------------------------------------------------------*/
static struct xio_ev_data *xio_event_lookup(void *loop_hndl, int fd)
{
	struct xio_ev_loop	*loop = loop_hndl;
	struct xio_ev_data	*tev;

	list_for_each_entry(tev, &loop->events_list, events_list_entry) {
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
	struct xio_ev_loop	*loop = loop_hndl;
	struct xio_ev_data	*tev;
	int ret;

	tev = xio_event_lookup(loop, fd);
	if (!tev) {
		xio_set_error(ENOENT);
		ERROR_LOG("event lookup failed. fd:%d\n", fd);
		return -1;
	}

	ret = epoll_ctl(loop->efd, EPOLL_CTL_DEL, fd, NULL);
	if (ret < 0) {
		xio_set_error(errno);
		ERROR_LOG("epoll_ctl failed. %m\n");
	}
	list_del(&tev->events_list_entry);
	free(tev);

	return ret;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_modify							     */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_modify(void *loop_hndl, int fd, int events)
{
	struct xio_ev_loop	*loop = loop_hndl;
	struct epoll_event	ev;
	struct xio_ev_data	*tev;
	int			retval;

	tev = xio_event_lookup(loop, fd);
	if (!tev) {
		xio_set_error(ENOENT);
		ERROR_LOG("event lookup failed. fd:%d\n", fd);
		return -1;
	}

	memset(&ev, 0, sizeof(ev));
	if (events == XIO_POLLIN)
		ev.events = EPOLLIN;
	else if (events == XIO_POLLOUT)
		ev.events = EPOLLOUT;
	ev.data.ptr = tev;

	retval = epoll_ctl(loop->efd, EPOLL_CTL_MOD, fd, &ev);
	if (retval != 0) {
		xio_set_error(errno);
		ERROR_LOG("epoll_ctl failed. %m\n");
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_init							     */
/*---------------------------------------------------------------------------*/
void *xio_ev_loop_init()
{
	struct xio_ev_loop	*loop;
	int			retval;

	loop = calloc(1, sizeof(struct xio_ev_loop));
	if (loop == NULL) {
		xio_set_error(errno);
		ERROR_LOG("calloc failed. %m\n");
		return  NULL;
	}

	INIT_LIST_HEAD(&loop->events_list);

	loop->stop_loop		= 0;
	loop->efd		= epoll_create(4096);
	if (loop->efd == -1) {
		xio_set_error(errno);
		ERROR_LOG("epoll_create failed. %m\n");
		goto cleanup;
	}

	loop->wakeup_event	= eventfd(0, EFD_NONBLOCK);
	if (loop->wakeup_event == -1) {
		xio_set_error(errno);
		ERROR_LOG("eventfd failed. %m\n");
		goto cleanup1;
	}

	retval = xio_ev_loop_add(loop, loop->wakeup_event,
				 EPOLLIN|XIO_POLLLT,
				 NULL, NULL);
	if (retval != 0)
		goto cleanup2;

	return loop;

cleanup2:
	close(loop->wakeup_event);
cleanup1:
	close(loop->efd);
cleanup:
	free(loop);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_run_helper                                                    */
/*---------------------------------------------------------------------------*/
inline int xio_ev_loop_run_helper(void *loop_hndl, int timeout)
{
	struct xio_ev_loop	*loop = loop_hndl;
	int			nevent = 0, i;
	struct epoll_event	events[1024];
	struct xio_ev_data	*tev;
	int			retval;
	eventfd_t		val;

retry:
	loop->wait = 1;
	nevent = epoll_wait(loop->efd, events, ARRAY_SIZE(events), timeout);
	loop->wait = 0;
	if (nevent < 0) {
		if (errno != EINTR) {
			xio_set_error(errno);
			ERROR_LOG("epoll_wait failed. %m\n");
			return -1;
		} else {
			goto retry;
		}
	} else if (likely(nevent)) {
		for (i = 0; i < nevent; i++) {
			tev = (struct xio_ev_data *)events[i].data.ptr;
			if (likely(tev->fd != loop->wakeup_event)) {
					tev->handler(tev->fd, events[i].events,
					     tev->data);
			} else {
				/* drain the pipe */
				retval = eventfd_read(loop->wakeup_event,
						      &val);
				if (retval != 0)
					ERROR_LOG("reading from eventfd " \
						  " failed. %m\n");
			}
		}
	} else {
		/* timed out */
		loop->stop_loop = 1;
		/* TODO: timeout should be updated by the elapsed duration of
		 * each loop */
	}
	if (likely(loop->stop_loop == 0))
		goto retry;

	loop->stop_loop = 0;
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_run_timeout                                              */
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
/* xio_ev_loop_stop                                                        */
/*---------------------------------------------------------------------------*/
inline void xio_ev_loop_stop(void *loop_hndl)
{
	struct xio_ev_loop	*loop = loop_hndl;
	eventfd_t		val = 1;

	if (loop == NULL)
		return;

	loop->stop_loop = 1;

	if (loop->wait == 1)
		eventfd_write(loop->wakeup_event, val);
}

/*---------------------------------------------------------------------------*/
/* svc_loop_destroy                                                          */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_destroy(void **loop_hndl)
{
	struct xio_ev_loop **loop = (struct xio_ev_loop **)loop_hndl;
	struct xio_ev_data	*tev, *tmp_tev;

	if (*loop == NULL)
		return;

	list_for_each_entry_safe(tev, tmp_tev, &(*loop)->events_list,
				 events_list_entry) {
		xio_ev_loop_del((*loop), tev->fd);
	}

	close((*loop)->efd);
	close((*loop)->wakeup_event);
	free((*loop));
	*loop = NULL;
}

