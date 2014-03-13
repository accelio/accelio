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
#ifndef XIO_EV_LOOP_H
#define XIO_EV_LOOP_H

#include "xio_common.h"
#include "xio_ev_data.h"

/*---------------------------------------------------------------------------*/
/* XIO default event loop API						     */
/*									     */
/* NoTE: xio provides default muxer implementation around epoll.	     */
/* users are encouraged to utilize their own implementations and provides    */
/* appropriate services to xio via the xio's context open interface	     */
/*---------------------------------------------------------------------------*/
/**
 * initializes event loop handle
 *
 * @returns event loop handle or NULL upon error
 */
void *xio_ev_loop_create(void);

/**
 * xio_ev_loop_run - event loop main loop
 *
 * @param[in] loop	Pointer to the event dispatcher
 *
 * @returns success (0), or a (negative) error value
 */
int xio_ev_loop_run(void *loop);

/**
 * event loop main loop with limited blocking duration
 *
 * @param[in] loop_hndl		Pointer to event loop
 * @param[in] timeout_msec	The timeout argument specifies the minimum
 *				number of milliseconds that xio_ev_loop_run
 *				will block before exiting
 *
 * @returns success (0), or a (negative) error value
 */
int xio_ev_loop_run_timeout(void *loop_hndl, int timeout_msec);

/**
 * stop a running event loop main loop
 *
 * @param[in] loop		Pointer to event loop
 * @param[in] is_self_thread	lighter stop if called from within ev_loop
 *				callbacks
 */
void xio_ev_loop_stop(void *loop, int is_self_thread);

/**
 * destroy the event loop
 *
 * @param[in] loop		Pointer to event loop
 */
void xio_ev_loop_destroy(void **loop);

/**
 * add event handlers on dispatcher
 *
 * @param[in] loop	the dispatcher context
 * @param[in] fd	the file descriptor
 * @param[in] events	the event signaled as defined in
 *			enum xio_ev_loop_events
 * @param[in] handler	event handler that handles the event
 * @param[in] data	user private data
 *
 * @returns	success (0), or a (negative) error value
 */
int xio_ev_loop_add(void *loop,
		    int fd, int events,
		    xio_ev_handler_t handler,
		    void *data);

/**
 * delete event handlers from dispatcher
 *
 * @param[in] loop	the dispatcher context
 * @param[in] fd	the file descriptor
 *
 * @returns	success (0), or a (negative) error value
 */
int xio_ev_loop_del(void *loop, int fd);

/**
 * get loop poll parameters to assign to external dispatcher
 *
 * @param[in] loop	  the dispatcher context
 * @param[in] poll_params Structure with polling parameters
 *			  to be added to external dispatcher
 *
 * @returns success (0), or a (negative) error value
 */
int xio_ev_loop_get_poll_params(void *loop,
				struct xio_poll_params *poll_params);

/**
 * initialize event job
 *
 * @param[in] evt	  the scheduled event data
 * @param[in] sched_handler callback function to call when event
 *			  is scheduled
 * @param[in] data	  user private data to pass to callback
 *
 * @returns none
 */
void xio_ev_loop_init_event(struct xio_ev_data *evt,
			    xio_event_handler_t event_handler,
			    void *data);

/**
 * add event job to scheduled events queue
 *
 * @param[in] loop	  the dispatcher context
 * @param[in] evt	  the scheduled event data
 *
 * @returns none
 */
void xio_ev_loop_add_event(void *loop,
			   struct xio_ev_data *evt);

/**
 * remove event from events queue
 *
 * @param[in] loop	  the dispatcher context
 * @param[in] evt	  the scheduled event data
 *
 * @returns none
 */
void xio_ev_loop_remove_event(void *loop,
			      struct xio_ev_data *evt);

#endif

