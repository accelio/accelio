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
#ifndef XIO_OBSERVER_H
#define XIO_OBSERVER_H

/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
typedef int (*notify_fn_t)(void *observer_impl,
			   void *observable_impl,
			   int event, void *event_data);

/*---------------------------------------------------------------------------*/
/* xio_observer								     */
/*---------------------------------------------------------------------------*/
struct xio_observer {
	void			*impl;
	notify_fn_t		notify;
};

#define XIO_OBSERVER_INIT(name, obj, notify_fn) \
	{ (name)->impl = obj; (name)->notify = notify_fn; }

#define XIO_OBSERVER_DESTROY(name) \
	{ (name)->impl = NULL; (name)->notify = NULL; }

/*---------------------------------------------------------------------------*/
/* xio_observer_node							     */
/*---------------------------------------------------------------------------*/
struct xio_observer_node {
	struct xio_observer	*observer;
	struct list_head	observers_list_node;
};

/*---------------------------------------------------------------------------*/
/* xio_observerable							     */
/*---------------------------------------------------------------------------*/
struct xio_observable {
	void			*impl;
	struct list_head	observers_list;
	struct xio_observer_node *observer_node; /* for one observer */
};

struct xio_observer_event{
	struct xio_observer	*observer;
	struct xio_observable *observable;
	void *event_data;
	int event;
	int pad;
};

#define XIO_OBSERVABLE_INIT(name, obj) \
	{ (name)->impl = obj; INIT_LIST_HEAD(&(name)->observers_list); \
	  (name)->observer_node = NULL; }

#define XIO_OBSERVABLE_DESTROY(name) \
	{ (name)->impl = NULL; INIT_LIST_HEAD(&(name)->observers_list); \
	  (name)->observer_node = NULL; }

/*---------------------------------------------------------------------------*/
/* xio_observable_reg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_observable_reg_observer(struct xio_observable *observable,
				 struct xio_observer *observer);

/*---------------------------------------------------------------------------*/
/* xio_observable_unreg_observer					     */
/*---------------------------------------------------------------------------*/
void xio_observable_unreg_observer(struct xio_observable *observable,
				   struct xio_observer *observer);

/*---------------------------------------------------------------------------*/
/* xio_observable_notify_observer					     */
/*---------------------------------------------------------------------------*/
void xio_observable_notify_observer(struct xio_observable *observable,
				    struct xio_observer *observer,
				    int event, void *event_data);

/*---------------------------------------------------------------------------*/
/* xio_observable_notify_all_observers					     */
/*---------------------------------------------------------------------------*/
void xio_observable_notify_all_observers(struct xio_observable *observable,
					 int event, void *event_data);

/*---------------------------------------------------------------------------*/
/* xio_observable_notify_any_observer					     */
/*---------------------------------------------------------------------------*/
void xio_observable_notify_any_observer(struct xio_observable *observable,
					int event, void *event_data);

/*---------------------------------------------------------------------------*/
/* xio_observable_unreg_all_observers					     */
/*---------------------------------------------------------------------------*/
void xio_observable_unreg_all_observers(struct xio_observable *observable);

/*---------------------------------------------------------------------------*/
/* xio_observable_is_empty						     */
/*---------------------------------------------------------------------------*/
static inline int xio_observable_is_empty(struct xio_observable *observable)
{
	return list_empty(&observable->observers_list);
}

#endif /* XIO_OBSERVER_H */
