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
#ifndef WIN32 // Avner TODO - move to OS layer
#include <unistd.h>
#include <sys/select.h>
#else
#include <Winsock2.h>
#include <io.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <libxio.h>
#include <xio_env.h>
#include <xio_mem.h>
#include <xio_log.h>
#include "xio_common.h"
#include "xio_ev_data.h"
#include "xio_ev_loop.h"
#include "xio_common.h"
#include "get_clock.h"

#define MAX_DELETED_EVENTS	1024

static HANDLE create_io_completion_port();
/*---------------------------------------------------------------------------*/
/* structs                                                                   */
/*---------------------------------------------------------------------------*/
struct xio_ev_loop {
	HANDLE			cpl_port; // the completion port
//	fd_set              readfds,  save_rfds;
//	fd_set              writefds, save_wfds;
	int			in_dispatch;
	int			stop_loop;
	volatile int		wakeup_armed;
//	socket_t		wakeup_fd[2];
//	uint64_t		wakeup_temp;
	int			deleted_events_nr;
	struct xio_ev_data *	deleted_events[MAX_DELETED_EVENTS];
	struct list_head	poll_events_list; // TODO: allow it to contain multiple instances of same fd
	struct list_head	events_list;
};

/*---------------------------------------------------------------------------*/
/* xio_event_add                                                           */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_add(void *loop_hndl, int fd, int events,
		    xio_ev_handler_t handler, void *data)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop *)loop_hndl;
	struct xio_ev_data	*tev = NULL;

	tev = (struct xio_ev_data *)ucalloc(1, sizeof(*tev));
	if (!tev) {
		xio_set_error(errno);
		ERROR_LOG("calloc failed, %m\n");
		return -1;
	}
	tev->data	= data;
	tev->handler	= handler;
	tev->fd		= fd;
	tev->reserved = events; // maintain 'events' for select support of ONESHOT // TODO events

	if (CreateIoCompletionPort((HANDLE)fd, loop->cpl_port,
		(ULONG_PTR)&tev, 0) != loop->cpl_port)
	{
		int err = WSAGetLastError();
		xio_set_error(err);
		ERROR_LOG("CreateIoCompletionPort failed, %m\n");
		return -1;
	}

	list_add(&tev->events_list_entry, &loop->poll_events_list);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_event_lookup							     */
/*---------------------------------------------------------------------------*/
static struct xio_ev_data *xio_event_lookup(void *loop_hndl, int fd)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop	*)loop_hndl;
	struct xio_ev_data	*tev;

	list_for_each_entry(tev, &loop->poll_events_list, events_list_entry) {
		if (tev->fd == fd)
			return tev;  // TODO: support multiple occurances
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

	// TODO: remove fd from our iocp handle - if possible??
	// TODO: what about a possible current running select?
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_modify							     */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_modify(void *loop_hndl, int fd, int events)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop	*)loop_hndl;
	struct xio_ev_data	*tev = NULL;

	tev = xio_event_lookup(loop, fd);
	if (!tev) {
		xio_set_error(ENOENT);
		ERROR_LOG("event lookup failed. fd:%d\n", fd);
		return -1;
	}
	tev->reserved = events; // maintain 'events' for select support of ONESHOT // TODO events

	// TODO: remove fd from our iocp handle - if possible??
	// TODO: what about a possible current running select?
#if 0
	if (events & (XIO_POLLIN|XIO_POLLRDHUP) ) { // best effort for reading peer hup
		FD_SET(fd, &loop->save_rfds);
	}
	if (events & XIO_POLLOUT) {
		FD_SET(fd, &loop->save_wfds);
	}
#endif
	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_ev_loop_create							     */
/*---------------------------------------------------------------------------*/
void *xio_ev_loop_create()
{
	struct xio_ev_loop *loop;

	loop = (struct xio_ev_loop *)ucalloc(1, sizeof(struct xio_ev_loop));
	if (loop == NULL) {
		xio_set_error(errno);
		ERROR_LOG("calloc failed. %m\n");
		return NULL;
	}

	INIT_LIST_HEAD(&loop->poll_events_list);
	INIT_LIST_HEAD(&loop->events_list);

	loop->stop_loop		= 0;
	loop->wakeup_armed = 0;
	loop->deleted_events_nr = 0;
	loop->cpl_port = create_io_completion_port();
	if (!loop->cpl_port)
	{
		int err = WSAGetLastError();
		xio_set_error(err);
		ERROR_LOG("CreateIoCompletionPort failed. %m\n");
		ufree(loop);
		return NULL;
	}

	return loop;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_init_event						     */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_init_event(struct xio_ev_data *evt,
			    xio_event_handler_t event_handler, void *data)
{
	evt->event_handler = event_handler;
	evt->scheduled = 0;
	evt->data = data;
	INIT_LIST_HEAD(&evt->events_list_entry);
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_add_event						     */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_add_event(void *_loop, struct xio_ev_data *evt)
{
	struct xio_ev_loop *loop = (struct xio_ev_loop	*)_loop;

	if (!evt->scheduled) {
		evt->scheduled = 1;
		list_add_tail(&evt->events_list_entry,
			      &loop->events_list);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_remove_event						     */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_remove_event(void *loop, struct xio_ev_data *evt)
{
	if (evt->scheduled) {
		evt->scheduled = 0;
		list_del_init(&evt->events_list_entry);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_exec_scheduled						     */
/*---------------------------------------------------------------------------*/
static int xio_ev_loop_exec_scheduled(struct xio_ev_loop *loop)
{
	struct list_head *last_sched;
	struct xio_ev_data *tev, *tevn;
	int work_remains = 0;

	if (!list_empty(&loop->events_list)) {
		/* execute only work scheduled till now */
		last_sched = loop->events_list.prev;
		list_for_each_entry_safe(tev, tevn, &loop->events_list,
			events_list_entry) {
			xio_ev_loop_remove_event(loop, tev);
			tev->event_handler(tev->data);
			if (&tev->events_list_entry == last_sched)
				break;
		}
		if (!list_empty(&loop->events_list))
			work_remains = 1;
	}
	return work_remains;
}

// Create a string with last error message
char * get_last_error_str(int error, char *buffer, int buflen)
{
#ifdef WIN32 // Avner TODO - move to OS layer
	if (error)
	{
		DWORD   dwLastError = error;
//		TCHAR   lpBuffer[256] = _T("?");
		if (dwLastError != 0)    // Don't want to see a "operation done successfully" error ;-)
			FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM,                 // It´s a system error
			NULL,                                      // No string to be formatted needed
			dwLastError,                               // Hey Windows: Please explain this error!
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),  // Do it in the standard language
			buffer,              // Put the message here
			buflen - 1,                     // Number of bytes to store the message
			NULL);
		buffer[buflen - 1] = '\0';
/*
		LPVOID lpMsgBuf;
		DWORD bufLen = FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpMsgBuf,
			0, NULL);
		if (bufLen)
		{
			LPCSTR lpMsgStr = (LPCSTR)lpMsgBuf;
			char *result;
			result = strdup(lpMsgStr);
			LocalFree(lpMsgBuf);
			return result;
		}
//*/
	}
#endif
	return NULL;
}

// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
#if 0
static WSAOVERLAPPED* new_overlapped(void)
{
	return (WSAOVERLAPPED*)ucalloc(1, sizeof(WSAOVERLAPPED));
}
#endif
// -----------------------------------------------------------------------------

static HANDLE create_io_completion_port()
{
	return CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
}

// -----------------------------------------------------------------------------

static BOOL get_completion_status(struct xio_ev_loop *loop, DWORD* length, struct xio_ev_data** tev,
	WSAOVERLAPPED** ovl_res, int milliseconds)
{

	OVERLAPPED_ENTRY entries[1024];
	ULONG numEntriesRemoved;


	BOOL resultOk;
	*ovl_res = NULL;
	*tev = NULL;
	if (milliseconds == -1) milliseconds = INFINITE;

	resultOk = GetQueuedCompletionStatus(loop->cpl_port, length, (PULONG_PTR)tev,
		ovl_res, milliseconds);
	resultOk = GetQueuedCompletionStatusEx(loop->cpl_port, entries, sizeof(entries) / sizeof(entries[0]), &numEntriesRemoved, milliseconds, TRUE);

	if (!resultOk)
	{
		DWORD err = GetLastError();
		if (err == ERROR_ABANDONED_WAIT_0) // TODO cleanup
			printf("* error %d getting completion port status!!!\n", err);
		else
			; // log timeout

	}

	if (!*tev || !*ovl_res)
	{
		printf("* don't know what to do, aborting!!!\n");
		exit(1);
	}

	return resultOk;
}


/*---------------------------------------------------------------------------*/
/* xio_ev_loop_run_helper_select                                                    */
/*---------------------------------------------------------------------------*/
static inline int xio_ev_loop_run_helper_iocp(void *loop_hndl, int timeout)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop	*)loop_hndl;
	int			i, j, found = 0;

	OVERLAPPED_ENTRY entries[1024];
	ULONG nevent = 0;

	struct xio_ev_data	*tev;
	int			work_remains;
	int			tmout;
	int			wait_time = timeout;
	cycles_t		start_cycle = 0;
//	struct timeval		tval, *ptval;

	DWORD length;
	BOOL resultOk;
	WSAOVERLAPPED* ovl_res;

	if (timeout != -1)
		start_cycle = get_cycles();
retry:
	work_remains = xio_ev_loop_exec_scheduled(loop);
	tmout = work_remains ? 0 : timeout;
	if (tmout == -1) tmout = INFINITE;

	/* free deleted event handlers */
	if (unlikely(loop->deleted_events_nr))
		while (loop->deleted_events_nr)
			ufree(loop->deleted_events[--loop->deleted_events_nr]);
#if 0
	memcpy(&loop->readfds, &loop->save_rfds, sizeof(fd_set));
	memcpy(&loop->writefds, &loop->save_wfds, sizeof(fd_set));
	num_found = 0;
#endif
	resultOk = GetQueuedCompletionStatusEx(loop->cpl_port, entries, sizeof(entries) / sizeof(entries[0]), &nevent, tmout, TRUE);

	if (unlikely(!resultOk && GetLastError() != WAIT_TIMEOUT)) {
		int last_error;
		char buffer[256];
		last_error = GetLastError();
		get_last_error_str(last_error, buffer, sizeof(buffer));
		ERROR_LOG("select failed. last_error=%d err_str=%s (errno=%d %s)\n", last_error, buffer, last_error, strerror(last_error));
		xio_set_error(last_error);
		return -1;
	}
	else if (resultOk) {
		/* save the epoll modify in "stop" while dispatching handlers */
		loop->in_dispatch = 1;
		for (i = 0; i < nevent; i++) {
			length = entries[i].dwNumberOfBytesTransferred;
			tev = (struct xio_ev_data *)entries[i].lpCompletionKey;
			ovl_res = entries[i].lpOverlapped;

			if (likely(length || tev || ovl_res)) {
//			if (likely(tev != NULL)) {
				/* look for deleted event handlers */
				if (unlikely(loop->deleted_events_nr)) {
					for (j = 0; j < loop->deleted_events_nr;
						j++) {
						if (loop->deleted_events[j] ==
							tev) {
							found = 1;
							break;
						}
					}
					if (found) {
						found = 0;
						continue;
					}
				}
				uint32_t out_events = 0; // TODO
//				out_events = epoll_to_xio_poll_events(events[i].events);
				/* (fd != loop->wakeup_event) */
				tev->handler(tev->fd, out_events,
					tev->data);
			}
			else {
				/* wakeup event auto-removed from epoll
				* due to ONESHOT
				TODO: this assumption is not valid with IOCP -
				however, it seems to be safe without it
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
	}
#if 0
	else if (nevent > 0) {

		// check wakeup is armed to prevent false wakeups
		if (loop->wakeup_fd[0] == tev->fd){
			uint64_t val;
			num_found++;
			loop->stop_loop = 1;
			xio_read(loop->wakeup_fd[0], &val, sizeof(val)); // consume it - TODO
		}

		/* loop on list of events/fds */
		list_for_each_entry_safe(tev, tmp_tev, &loop->poll_events_list, events_list_entry) {
				int num = 0;
			int out_events = 0;

			if (num_found >= nevent)
				break;

			if (FD_ISSET(tev->fd, &loop->readfds)) {
				num++;
				out_events |= XIO_POLLIN;
			}
			if (FD_ISSET(tev->fd, &loop->writefds)) {
				num++;
				out_events |= XIO_POLLOUT;
			}
			if (num) {
				num_found += num;
				if (tev->reserved & XIO_ONESHOT) {
					FD_CLR(tev->fd, &loop->save_rfds);
					FD_CLR(tev->fd, &loop->save_wfds);
				}
				/* look for deleted event handlers */
				if (unlikely(loop->deleted_events_nr)) {
					for (j = 0; j < loop->deleted_events_nr;
							j++) {
						if (loop->deleted_events[j] ==
								tev) {
							found = 1;
							break;
						}
					}
					if (found) {
						found = 0;
						continue;
					}
				}

				tev->handler(tev->fd, out_events,	tev->data);
			}
		}
	}
#endif
	else {
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

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_run_helper                                                    */
/*---------------------------------------------------------------------------*/
static inline int xio_ev_loop_run_helper(void *loop_hndl, int timeout)
{
	return xio_ev_loop_run_helper_iocp(loop_hndl, timeout);
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
void xio_ev_loop_stop(void *loop_hndl)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop	*)loop_hndl;
	uint64_t val = 1;
	if (loop == NULL)
		return;

	if (loop->stop_loop == 1)
		return; /* loop is already marked for stopping (and also
			   armed for wakeup from blocking) */
	loop->stop_loop = 1;

	if (loop->in_dispatch || loop->wakeup_armed == 1)
		return; /* wakeup is still armed, probably left loop in previous
			cycle due to other reasons (timeout, events) */
	loop->wakeup_armed = 1;
	BOOL ret = PostQueuedCompletionStatus(loop->cpl_port, 0, NULL, NULL); //wakeup ev-loop
	if (!ret) {
		int err = GetLastError();
		xio_set_error(err);
		WARN_LOG("failed to PostQueuedCompletionStatus; err=%d\n", err);
		// avner: is this WARN or error?
	}

#if 0
/* avner TODO: consider...
	if (is_self_thread || loop->wakeup_armed == 1)
		return;  // wakeup is still armed, probably left loop in previous
			     // cycle due to other reasons (timeout, events)
//*/
	if (loop->in_dispatch)
		return;

	if (sizeof(val) == xio_write(loop->wakeup_fd[1], &val, sizeof(val))) {
		xio_set_error(errno);
		WARN_LOG("failed to write int to wakeup_fd[1]:%d\n", loop->wakeup_fd[1]);
		// avner: is this WARN or error?
	}
#endif
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_destroy                                                       */
/*---------------------------------------------------------------------------*/
void xio_ev_loop_destroy(void **loop_hndl)
{
	struct xio_ev_loop *loop = *(struct xio_ev_loop **)loop_hndl;
	struct xio_ev_data	*tev, *tmp_tev;

	if (loop == NULL)
		return;

	list_for_each_entry_safe(tev, tmp_tev, &loop->poll_events_list,
		events_list_entry) {
		xio_ev_loop_del(loop, tev->fd);
	}

	list_for_each_entry_safe(tev, tmp_tev, &loop->events_list,
		events_list_entry) {
		xio_ev_loop_remove_event(loop, tev);
	}
#if 0
	xio_ev_loop_del(loop, loop->wakeup_fd[0]);

	closesocket(loop->wakeup_fd[0]);
	closesocket(loop->wakeup_fd[1]);
#endif
	if (loop->cpl_port) CloseHandle(loop->cpl_port);

	ufree(loop);
	loop = NULL;
}


/*---------------------------------------------------------------------------*/
/* xio_ev_loop_poll_wait                                                     */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_poll_wait(void *loop_hndl, int timeout_ms)
{
	struct xio_ev_loop      *loop = (struct xio_ev_loop *)loop_hndl;

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
	return (int)loop->cpl_port;
}

#if 0
/*---------------------------------------------------------------------------*/
/* xio_ev_loop_handler							     */
/*---------------------------------------------------------------------------*/
static void xio_ev_loop_handler(int fd, int events, void *data)
{
	struct xio_ev_loop	*loop = (struct xio_ev_loop	*)data;

	loop->stop_loop = 1;
	xio_ev_loop_run_helper(loop, 0);
}

/*---------------------------------------------------------------------------*/
/* xio_ev_loop_get_poll_params                                               */
/*---------------------------------------------------------------------------*/
int xio_ev_loop_get_poll_params(void *loop_hndl,
				struct xio_poll_params *poll_params)
{
	if (!loop_hndl || !poll_params) {
		xio_set_error(EINVAL);
		return -1;
	}

	poll_params->fd		= -1;
	poll_params->events	= XIO_POLLIN;
	poll_params->handler	= xio_ev_loop_handler;
	poll_params->data	= loop_hndl;

	//avner TODO: consider support select

	return 0;
}
#endif

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

