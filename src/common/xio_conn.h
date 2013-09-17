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
#include "xio_transport.h"
#include "sys/hashtable.h"

/*---------------------------------------------------------------------------*/
/* defines	                                                             */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
struct xio_conn;

/*---------------------------------------------------------------------------*/
/* enum									     */
/*---------------------------------------------------------------------------*/
enum xio_conn_event {
	XIO_CONNECTION_NEW_CONNECTION,
	XIO_CONNECTION_ESTABLISHED,
	XIO_CONNECTION_DISCONNECTED,
	XIO_CONNECTION_CLOSED,
	XIO_CONNECTION_REFUSED,
	XIO_CONNECTION_NEW_MESSAGE,
	XIO_CONNECTION_SEND_COMPLETION,
	XIO_CONNECTION_ASSIGN_IN_BUF,
	XIO_CONNECTION_ERROR,
};

/*---------------------------------------------------------------------------*/
/* structs	                                                             */
/*---------------------------------------------------------------------------*/
union xio_conn_event_data {
	struct {
		struct xio_conn		*child_conn;
	} new_connection;
	struct {
		enum xio_status		reason;
	} error;
	struct {
		struct xio_task		*task;
		enum xio_wc_op		op;
		int			pad;
	} msg;
	struct {
		struct xio_task	*task;
		int		 is_assigned;
		int		 pad;
	} assign_in_buf;

};


struct xio_tasks_pool_ops {
	void	(*pool_get_params)(struct xio_transport_base *transport_hndl,
				int *pool_len, int *pool_dd_sz,
				int *task_dd_size);
	int	(*pool_alloc)(struct xio_transport_base *trans_hndl,
				int max, void *pool_dd_data);
	int	(*pool_free)(struct xio_transport_base *trans_hndl,
				void *pool_dd_data);
	int	(*pool_init_item)(struct xio_transport_base *trans_hndl,
				void *pool_dd_data, struct xio_task *task);
	int	(*pool_run)(struct xio_transport_base *trans_hndl);

	int	(*pre_put)(struct xio_transport_base *trans_hndl,
			struct xio_task *task);
	int	(*post_get)(struct xio_transport_base *trans_hndl,
			struct xio_task *task);
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

	int				refcnt;
	int				cid;
	int				is_first_msg;
	int				pad;

	HT_ENTRY(xio_conn, xio_key_int32) conns_htbl;

	/* list of sessions using this connection */
	struct list_head		observers_list;
};

/*---------------------------------------------------------------------------*/
/* xio_conn_close							     */
/*---------------------------------------------------------------------------*/
void xio_conn_close(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_conn_open							     */
/*---------------------------------------------------------------------------*/
struct xio_conn *xio_conn_open(struct xio_context *ctx,
		const char *portal_uri, void  *observer,
		notification_handler_t	notification_handler);

/*---------------------------------------------------------------------------*/
/* xio_conn_connect							     */
/*---------------------------------------------------------------------------*/
int xio_conn_connect(struct xio_conn *conn, const char *portal_uri);

/*---------------------------------------------------------------------------*/
/* xio_conn_listen							     */
/*---------------------------------------------------------------------------*/
int xio_conn_listen(struct xio_conn *conn, const char *portal_uri,
		    uint16_t *src_port);

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
int xio_conn_poll(struct xio_conn *conn, struct timespec *timeout);

/*---------------------------------------------------------------------------*/
/* xio_conn_send							     */
/*---------------------------------------------------------------------------*/
int xio_conn_send(struct xio_conn *conn, struct xio_task *task);

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
/* xio_conn_get_initial_task						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_conn_get_initial_task(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_conn_put_task							     */
/*---------------------------------------------------------------------------*/
void xio_conn_put_task(struct xio_conn *conn, struct xio_task *task);

/*---------------------------------------------------------------------------*/
/* xio_conn_get_primary_task						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_conn_get_primary_task(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_conn_primary_free_tasks						     */
/*---------------------------------------------------------------------------*/
int xio_conn_primary_free_tasks(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* trmda_conn_task_lookup						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_conn_task_lookup(struct xio_conn *conn, int id);

/*---------------------------------------------------------------------------*/
/* xio_conn_add_observer						     */
/*---------------------------------------------------------------------------*/
int xio_conn_add_observer(struct xio_conn *conn, void *observer,
			    notification_handler_t notify_observer);

/*---------------------------------------------------------------------------*/
/* xio_conn_remove_observer						     */
/*---------------------------------------------------------------------------*/
void xio_conn_remove_observer(struct xio_conn *conn, void *observer);


/*---------------------------------------------------------------------------*/
/* xio_conn_notify_observer						     */
/*---------------------------------------------------------------------------*/
void xio_conn_notify_observer(struct xio_conn *conn, void *observer,
			   int event,
			   void *event_data);

/*---------------------------------------------------------------------------*/
/* xio_conn_set_pools_ops						     */
/*---------------------------------------------------------------------------*/
void xio_conn_set_pools_ops(struct xio_conn *conn,
		struct xio_tasks_pool_ops *initial_pool_ops,
		struct xio_tasks_pool_ops *primary_pool_ops);

/*---------------------------------------------------------------------------*/
/* xio_conn_get_src_addr						     */
/*---------------------------------------------------------------------------*/
int xio_conn_get_src_addr(struct xio_conn *conn,
			  struct sockaddr_storage *sa, socklen_t len);

/*---------------------------------------------------------------------------*/
/* xio_conn_get_trans_cls						     */
/*---------------------------------------------------------------------------*/
static inline struct xio_transport_cls *xio_conn_get_trans_cls(
				struct xio_conn *conn)
{
	return &conn->transport->trans_cls;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_get_proto							     */
/*---------------------------------------------------------------------------*/
static inline int xio_conn_get_proto(struct xio_conn *conn)
{
	return conn->transport_hndl->proto;
}

#endif /*XIO_CONNECTION_H */

