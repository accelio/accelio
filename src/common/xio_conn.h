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
#ifndef XIO_CONN_H
#define XIO_CONN_H

#include "xio_hash.h"
#include "xio_context.h"
#include "xio_transport.h"
#include "sys/hashtable.h"

/*---------------------------------------------------------------------------*/
/* defines	                                                             */
/*---------------------------------------------------------------------------*/
#define XIO_CONN_CLOSE_TIMEOUT	60000

/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
struct xio_conn;

/*---------------------------------------------------------------------------*/
/* enum									     */
/*---------------------------------------------------------------------------*/
enum xio_conn_event {
	XIO_CONN_EVENT_NEW_CONNECTION,
	XIO_CONN_EVENT_ESTABLISHED,
	XIO_CONN_EVENT_DISCONNECTED,
	XIO_CONN_EVENT_CLOSED,
	XIO_CONN_EVENT_REFUSED,
	XIO_CONN_EVENT_NEW_MESSAGE,
	XIO_CONN_EVENT_SEND_COMPLETION,
	XIO_CONN_EVENT_ASSIGN_IN_BUF,
	XIO_CONN_EVENT_CANCEL_REQUEST,
	XIO_CONN_EVENT_CANCEL_RESPONSE,
	XIO_CONN_EVENT_ERROR,
	XIO_CONN_EVENT_MESSAGE_ERROR
};

enum xio_conn_state {
	XIO_CONN_STATE_INIT,
	XIO_CONN_STATE_OPEN,
	XIO_CONN_STATE_LISTEN,
	XIO_CONN_STATE_CONNECTING,
	XIO_CONN_STATE_CONNECTED,
	XIO_CONN_STATE_REJECTED,
	XIO_CONN_STATE_CLOSED,
	XIO_CONN_STATE_DISCONNECTED,

};

/*---------------------------------------------------------------------------*/
/* structs	                                                             */
/*---------------------------------------------------------------------------*/
union xio_conn_event_data {
	struct {
		struct xio_task		*task;
		enum xio_wc_op		op;
		int			pad;
	} msg;
	struct {
		struct xio_task		*task;
		int			is_assigned;
		int			pad;
	} assign_in_buf;
	struct {
		struct xio_task		*task;
		enum xio_status		reason;
		int			pad;
	} msg_error;
	struct {
		struct xio_conn		*child_conn;
	} new_connection;
	struct {
		enum xio_status		reason;
	} error;
	struct {
		struct xio_task		*task;
		enum xio_status		result;
		int			pad;
		void			*ulp_msg;
		size_t			ulp_msg_sz;
	} cancel;
};


/**
 * Connection data type
 */
struct xio_conn {
	struct xio_transport		*transport;
	struct xio_transport_base	*transport_hndl;

	struct xio_tasks_pool		*primary_tasks_pool;
	struct xio_tasks_pool_ops	*primary_pool_ops;

	struct xio_tasks_pool		*initial_tasks_pool;
	struct xio_tasks_pool_ops	*initial_pool_ops;
	struct xio_observer		*server_observer;
	struct xio_observer		trans_observer;
	struct xio_observer		ctx_observer;
	struct xio_observable		observable;
	struct kref			kref;

	int				cid;
	enum xio_conn_state		state;
	int				is_first_req;
	int				is_listener;
	int				pad;
	xio_ctx_timer_handle_t		close_time_hndl;

	struct list_head		observers_htbl;

	HT_ENTRY(xio_conn, xio_key_int32) conns_htbl;
};

/*---------------------------------------------------------------------------*/
/* xio_conn_close							     */
/*---------------------------------------------------------------------------*/
void xio_conn_close(struct xio_conn *conn, struct xio_observer *observer);

/*---------------------------------------------------------------------------*/
/* xio_conn_open							     */
/*---------------------------------------------------------------------------*/
struct xio_conn *xio_conn_open(struct xio_context *ctx,
			       const char *portal_uri,
			       struct xio_observer *observer,
			       uint32_t oid);

/*---------------------------------------------------------------------------*/
/* xio_conn_connect							     */
/*---------------------------------------------------------------------------*/
int xio_conn_connect(struct xio_conn *conn, const char *portal_uri,
		     struct xio_observer *observer,
		     const char *out_if);

/*---------------------------------------------------------------------------*/
/* xio_conn_listen							     */
/*---------------------------------------------------------------------------*/
int xio_conn_listen(struct xio_conn *conn, const char *portal_uri,
		    uint16_t *src_port, int backlog);

/*---------------------------------------------------------------------------*/
/* xio_conn_accept							     */
/*---------------------------------------------------------------------------*/
int xio_conn_accept(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_handler_init							     */
/*---------------------------------------------------------------------------*/
int xio_conn_reject(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_conn_poll							     */
/*---------------------------------------------------------------------------*/
int xio_conn_poll(struct xio_conn *conn,
		  long min_nr, long nr, struct timespec *timeout);

/*---------------------------------------------------------------------------*/
/* xio_conn_send							     */
/*---------------------------------------------------------------------------*/
int xio_conn_send(struct xio_conn *conn, struct xio_task *task);

/*---------------------------------------------------------------------------*/
/* xio_conn_cancel_req							     */
/*---------------------------------------------------------------------------*/
int xio_conn_cancel_req(struct xio_conn *conn,
			struct xio_msg *req, uint64_t stag,
			void *ulp_msg, size_t ulp_msg_sz);
/*---------------------------------------------------------------------------*/
/* xio_conn_cancel_rsp							     */
/*---------------------------------------------------------------------------*/
int xio_conn_cancel_rsp(struct xio_conn *conn,
			struct xio_task *task, enum xio_status result,
			void *ulp_msg, size_t ulp_msg_sz);

/*---------------------------------------------------------------------------*/
/* xio_conn_set_opt							     */
/*---------------------------------------------------------------------------*/
int xio_conn_set_opt(struct xio_conn *conn, int optname,
		     const void *optval, int optlen);

/*---------------------------------------------------------------------------*/
/* xio_conn_get_opt							     */
/*---------------------------------------------------------------------------*/
int xio_conn_get_opt(struct xio_conn *conn, int optname,
		     void *optval, int *optlen);

/*---------------------------------------------------------------------------*/
/* xio_conn_get_primary_task						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_conn_get_primary_task(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_conn_primary_free_tasks						     */
/*---------------------------------------------------------------------------*/
int xio_conn_primary_free_tasks(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_conn_add_server_observer						     */
/*---------------------------------------------------------------------------*/
static inline void xio_conn_set_server_observer(struct xio_conn *conn,
					       struct xio_observer *observer)
{
	conn->server_observer = observer;
}
/*---------------------------------------------------------------------------*/
/* xio_conn_reg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_conn_reg_observer(struct xio_conn *conn,
			   struct xio_observer *observer,
			   uint32_t oid);

/*---------------------------------------------------------------------------*/
/* xio_conn_unreg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_conn_unreg_observer(struct xio_conn *conn,
			     struct xio_observer *observer);

/*---------------------------------------------------------------------------*/
/* xio_conn_observer_lookup						     */
/*---------------------------------------------------------------------------*/
struct xio_observer *xio_conn_observer_lookup(struct xio_conn *conn,
					      uint32_t id);

/*---------------------------------------------------------------------------*/
/* xio_conn_notify_observer						     */
/*---------------------------------------------------------------------------*/
static inline void xio_conn_notify_observer(struct xio_conn *conn,
			      struct xio_observer *observer,
			      int event, void *event_data)
{
	xio_observable_notify_observer(&conn->observable, observer,
				       event, event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_get_src_addr						     */
/*---------------------------------------------------------------------------*/
int xio_conn_get_src_addr(struct xio_conn *conn,
			  struct sockaddr_storage *sa, socklen_t len);

/*---------------------------------------------------------------------------*/
/* xio_conn_get_validators_cls						     */
/*---------------------------------------------------------------------------*/
static inline
struct xio_transport_msg_validators_cls *xio_conn_get_validators_cls(
						struct xio_conn *conn)
{
	return &conn->transport->validators_cls;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_get_proto							     */
/*---------------------------------------------------------------------------*/
static inline int xio_conn_get_proto(struct xio_conn *conn)
{
	return conn->transport_hndl->proto;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_addref							     */
/*---------------------------------------------------------------------------*/
static inline void xio_conn_addref(struct xio_conn *conn)
{

	if (conn->close_time_hndl) {
		kref_init(&conn->kref);
		xio_ctx_timer_del(conn->transport_hndl->ctx,
				conn->close_time_hndl);
		conn->close_time_hndl = NULL;
	} else {
		kref_get(&conn->kref);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_get_server							     */
/*---------------------------------------------------------------------------*/
static inline struct xio_server *xio_conn_get_server(struct xio_conn *conn)
{
	return conn->server_observer->impl;
}

#endif /*XIO_CONNECTION_H */

