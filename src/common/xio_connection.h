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
#ifndef XIO_CONNECTION_H
#define XIO_CONNECTION_H

#include "xio_msg_list.h"


enum xio_connection_state {
		CONNECTION_STATE_INIT,
		CONNECTION_STATE_ONLINE,
		CONNECTION_STATE_CLOSE,		/* user close */
		CONNECTION_STATE_DISCONNECT,	/* peer close */
		CONNECTION_STATE_CLOSED,
};


struct xio_connection {
	struct xio_conn			*conn;
	struct xio_session		*session;
	struct xio_context		*ctx;	/* connection context */
	struct xio_session_ops		ses_ops;
	/* server's session may have multiple connections each has
	 * private data assignd by bind
	 */
	void				*cb_user_context;

	int				conn_idx;
	int				state;
	uint32_t			pad;
	int32_t				send_req_toggle;

	struct xio_msg_list		reqs_msgq;
	struct xio_msg_list		rsps_msgq;
	struct xio_msg_list		one_way_msg_pool;
	struct xio_msg			*msg_array;

	struct list_head		io_tasks_list;
	struct list_head		post_io_tasks_list;
	struct list_head		pre_send_list;
	struct list_head		connections_list_entry;
};

struct xio_connection *xio_connection_init(
		struct xio_session *session,
		struct xio_context *ctx, int conn_idx,
		void *cb_user_context);

int xio_connection_conn_close(struct xio_connection *connection);
int xio_connection_close(struct xio_connection *connection);

static inline void xio_connection_set(
			struct xio_connection *connection,
			struct xio_conn *conn)
{
	connection->conn = conn;
}

static inline void xio_connection_set_ops(
		struct xio_connection *connection,
		struct xio_session_ops *ses_ops)
{
	memcpy(&connection->ses_ops, ses_ops, sizeof(*ses_ops));
}

int xio_connection_send(struct xio_connection *conn,
			  struct xio_msg *msg);

int xio_connection_xmit_msgs(struct xio_connection *conn);

void xio_connection_queue_io_task(struct xio_connection *connection,
				    struct xio_task *task);

static inline void xio_connection_set_state(
				struct xio_connection *conn,
				enum xio_connection_state state)
{
	conn->state = state;
}

int xio_connection_ack_ow_req(struct xio_connection *conn,
			      struct xio_msg *msg);

int xio_connection_release_ow_rsp(struct xio_connection *conn,
				  struct xio_msg *msg);

void xio_release_response_task(struct xio_task *task);



#endif /*XIO_CONNECTION_H */

