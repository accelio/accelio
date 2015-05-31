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
#ifndef XIO_WORKQUEUE_H
#define XIO_WORKQUEUE_H

#include "xio_workqueue_priv.h"

/* opaque type */
struct xio_workqueue;
struct xio_context;

/*---------------------------------------------------------------------------*/
/* xio_workqueue_create							     */
/*---------------------------------------------------------------------------*/
struct xio_workqueue *xio_workqueue_create(struct xio_context *ctx);

/*---------------------------------------------------------------------------*/
/* xio_workqueue_destroy						     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_destroy(struct xio_workqueue *work_queue);

/*---------------------------------------------------------------------------*/
/* xio_workqueue_add_delayed_work					     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_add_delayed_work(struct xio_workqueue *work_queue,
				   int msec_duration, void *data,
				   void (*function)(void *data),
				   xio_delayed_work_handle_t *work);

/*---------------------------------------------------------------------------*/
/* xio_workqueue_del_delayed_work					     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_del_delayed_work(struct xio_workqueue *work_queue,
				   xio_delayed_work_handle_t *work);

/*---------------------------------------------------------------------------*/
/* xio_workqueue_add_work						     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_add_work(struct xio_workqueue *work_queue,
			   void *data,
			   void (*function)(void *data),
			   xio_work_handle_t *work);

/*---------------------------------------------------------------------------*/
/* xio_workqueue_del_work						     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_del_work(struct xio_workqueue *work_queue,
			   xio_work_handle_t *work);

/*---------------------------------------------------------------------------*/
/* xio_workqueue_set_work_destructor					     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_set_work_destructor(struct xio_workqueue *work_queue,
				     void *data,
				     void (*destructor)(void *data),
				     xio_work_handle_t *work);

/*---------------------------------------------------------------------------*/
/* xio_workqueue_is_work_in_handler					     */
/*---------------------------------------------------------------------------*/
int xio_workqueue_is_work_in_handler(struct xio_workqueue *work_queue,
				     xio_work_handle_t *work);

#endif /* XIO_WORKQUEUE_H */

