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
#include "xio_os.h"
#include "xio_common.h"
#include "libxio.h"
#include "xio_protocol.h"
#include "xio_observer.h"
#include "xio_transport.h"
#include "xio_task.h"
#include "xio_context.h"
#include "xio_session.h"
#include "xio_conn.h"
#include "xio_connection.h"


struct xio_server {
	struct xio_conn			*listener;
	struct xio_observer		observer;
	char				*uri;
	struct xio_context		*ctx;
	struct xio_session_ops		ops;
	uint32_t			session_flags;
	uint32_t			pad;
	void				*cb_private_data;
};

static int xio_on_conn_event(void *observer, void *notifier, int event,
			void *event_data);

/*---------------------------------------------------------------------------*/
/* xio_on_new_conn							     */
/*---------------------------------------------------------------------------*/
static int xio_on_new_conn(struct xio_server *server,
			   struct xio_conn *conn,
			   union xio_conn_event_data *event_data)
{
	int		retval;

	/* set the server as observer */
	xio_conn_set_server_observer(event_data->new_connection.child_conn,
				     &server->observer);

	retval = xio_conn_accept(event_data->new_connection.child_conn);
	if (retval != 0) {
		ERROR_LOG("failed to accept connection\n");
		return -1;
	}

	return 0;
}

/* first message after new connection are going trough the server */
static int xio_on_new_message(struct xio_server *server,
			      struct xio_conn *conn,
			      int event,
			      union xio_conn_event_data *event_data)
{
	struct xio_session		*session;
	struct xio_connection		*connection;

	struct xio_session_attr attr = {
		&server->ops,
		NULL,
		0
	};

	/* read the first message  type */
	uint32_t tlv_type = xio_read_tlv_type(&event_data->msg.task->mbuf);

	if (tlv_type == XIO_SESSION_SETUP_REQ) {
		/* create new session */
		session = xio_session_init(
				XIO_SESSION_SERVER,
				&attr,
				server->uri,
				0,
				server->session_flags,
				server->cb_private_data);

		if (session == NULL) {
			ERROR_LOG("server [new session]: failed " \
				"  allocating session failed\n");
			return -1;
		}
		DEBUG_LOG("server [new session]: server:%p, " \
			  "session:%p, conn:%p ,session_id:%d\n",
			  server, session, conn, session->session_id);

		/* get transport class routines */
		session->trans_cls = xio_conn_get_trans_cls(conn);

		connection =
			xio_session_alloc_connection(session,
						     server->ctx, 0,
						     server->cb_private_data);
		if (!connection) {
			ERROR_LOG("server failed to allocate new connection\n");
			goto cleanup;
		}
		connection = xio_session_assign_conn(session, conn);
		if (!connection) {
			ERROR_LOG("server failed to assign new connection\n");
			goto cleanup1;
		}

		xio_connection_set_state(connection, CONNECTION_STATE_ONLINE);
	} else if (tlv_type == XIO_CONNECTION_HELLO_REQ) {
		struct xio_task	*task = event_data->msg.task;

		/* find the old session */
		session = xio_find_session(event_data->msg.task);
		if (session == NULL) {
			ERROR_LOG("server [new connection]: failed " \
				  "session not found\n");
			return -1;
		}
		task->session = session;

		DEBUG_LOG("server [new connection]: server:%p, " \
			  "session:%p, conn:%p, session_id:%d\n",
			   server, session, conn, session->session_id);

		connection = xio_session_alloc_connection(task->session,
						  server->ctx, 0,
						  server->cb_private_data);

		connection = xio_session_assign_conn(task->session, conn);

		/* copy the server attributes to the connection */
		xio_connection_set_ops(connection, &server->ops);

		task->connection = connection;

		xio_connection_set_state(connection, CONNECTION_STATE_ONLINE);
	} else {
		ERROR_LOG("server unexpected message\n");
	}

	/* route the message to the session */
	xio_conn_notify_observer(conn, &session->observer, event, event_data);

	return 0;

cleanup1:
	xio_session_free_connection(connection);

cleanup:
	xio_session_close(session);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_on_conn_event				                             */
/*---------------------------------------------------------------------------*/
static int xio_on_conn_event(void *observer, void *notifier, int event,
			void *event_data)
{
	struct xio_server	*server = observer;
	struct xio_conn	*conn	= notifier;
	int			retval  = 0;

	switch (event) {
	case XIO_CONNECTION_NEW_MESSAGE:
	case XIO_CONNECTION_ASSIGN_IN_BUF:
		TRACE_LOG("server: [notification] - new message. " \
			 "server:%p, conn:%p\n", observer, notifier);

		xio_on_new_message(server, conn, event, event_data);
		break;
	case XIO_CONNECTION_NEW_CONNECTION:
		DEBUG_LOG("server: [notification] - new connection. " \
			 "server:%p, conn:%p\n", observer, notifier);
		xio_on_new_conn(server, conn, event_data);
		break;

	case XIO_CONNECTION_DISCONNECTED:
	case XIO_CONNECTION_CLOSED:
	case XIO_CONNECTION_ESTABLISHED:
		break;

	case XIO_CONNECTION_ERROR:
		ERROR_LOG("session: [notification] - connection error. " \
			  "session:%p, conn:%p\n", observer, notifier);
		break;
	default:
		ERROR_LOG("server: [notification] - unexpected event :%d. " \
			  "server:%p, conn:%p\n", event, observer, notifier);
	};

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_bind								     */
/*---------------------------------------------------------------------------*/
struct xio_server *xio_bind(struct xio_context *ctx,
				struct xio_session_ops *ops,
				const char *uri,
				uint16_t *src_port,
				uint32_t session_flags,
				void *cb_private_data)
{
	struct xio_server	*server;
	int			retval;
	int			backlog = 0;

	if ((ctx == NULL) || (ops == NULL) || (uri == NULL)) {
		ERROR_LOG("invalid parameters ctx:%p, ops:%p, uri:%p\n",
			  ctx, ops, uri);
		xio_set_error(EINVAL);
		return NULL;
	}

	TRACE_LOG("bind to %s\n", uri);

	/* create the server */
	server = kcalloc(1, sizeof(struct xio_server), GFP_KERNEL);
	if (server == NULL) {
		xio_set_error(ENOMEM);
		return NULL;
	}

	/* fill server data*/
	server->ctx = ctx;
	server->cb_private_data	= cb_private_data;
	server->uri = kstrdup(uri, GFP_KERNEL);

	server->session_flags = session_flags;
	memcpy(&server->ops, ops, sizeof(*ops));

	XIO_OBSERVER_INIT(&server->observer, server, xio_on_conn_event);

	server->listener = xio_conn_open(ctx, uri, NULL, 0);
	if (server->listener == NULL) {
		ERROR_LOG("failed to create connection\n");
		goto cleanup;
	}

	xio_conn_set_server_observer(server->listener,
				     &server->observer);

	retval = xio_conn_listen(server->listener,
				 uri, src_port, backlog);
	if (retval != 0) {
		ERROR_LOG("connection listen failed\n");
		goto cleanup1;
	}

	return server;

cleanup1:
	xio_conn_close(server->listener, NULL);
cleanup:
	kfree(server->uri);
	kfree(server);

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_unbind								     */
/*---------------------------------------------------------------------------*/
int xio_unbind(struct xio_server *server)
{
	int retval = 0;

	xio_conn_close(server->listener, NULL);
	kfree(server->uri);
	kfree(server);

	return retval;
}


