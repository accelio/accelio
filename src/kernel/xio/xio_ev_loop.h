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

/*---------------------------------------------------------------------------*/
/* defines								     */
/*---------------------------------------------------------------------------*/

#define XIO_EV_LOOP_WAKE	BIT(0)
#define XIO_EV_LOOP_STOP	BIT(1)
#define XIO_EV_LOOP_DOWN	BIT(2)
#define XIO_EV_LOOP_SCHED	BIT(3)
#define XIO_EV_LOOP_IN_HANDLER	BIT(4)
#define XIO_EV_LOOP_ACTIVE	BIT(5)

#define XIO_EV_HANDLER_PENDING	BIT(0)
#define XIO_EV_HANDLER_ENABLED	BIT(1)

/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/

struct xio_ev_loop {
	struct xio_context *ctx;
	void *loop_object;
	int  (*run)(void *loop_hndl);
	void (*stop)(void *loop_hndl);
	int (*is_stopping)(void *loop_hndl);
	int  (*add_event)(void *loop_hndl, struct xio_ev_data *data);
	unsigned long	flags;

	volatile unsigned long	states;
	union {
		wait_queue_head_t wait;
		struct tasklet_struct tasklet;
		struct workqueue_struct *workqueue;
	};
	/* for thread, tasklet and for stopped workqueue  */
	struct llist_head ev_llist;
	struct llist_node *first;
	struct llist_node *last;
	struct completion complete;
};

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
void *xio_ev_loop_init(unsigned long flags, struct xio_context *ctx,
		       struct xio_loop_ops *loop);

/**
 * destroy the event loop
 *
 * @param[in] loop_hndl		Handle to event loop
 */
void xio_ev_loop_destroy(void *loop);

#endif

