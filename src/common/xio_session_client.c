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
#include "libxio.h"
#include "xio_common.h"
#include "xio_protocol.h"
#include "xio_observer.h"
#include "xio_task.h"
#include "xio_context.h"
#include "xio_transport.h"
#include "xio_sessions_store.h"
#include "xio_hash.h"
#include "xio_session.h"
#include "xio_conn.h"
#include "xio_connection.h"
#include "xio_session_priv.h"

/*---------------------------------------------------------------------------*/
/* xio_session_write_setup_req						     */
/*---------------------------------------------------------------------------*/
struct xio_msg *xio_session_write_setup_req(struct xio_session *session)
{
	struct xio_msg		*msg;
	void			*buf;
	uint8_t			*ptr;
	uint16_t		len;


	/* allocate message */
	buf = kcalloc(SETUP_BUFFER_LEN + sizeof(struct xio_msg),
		      sizeof(uint8_t), GFP_KERNEL);
	if (buf == NULL) {
		ERROR_LOG("message allocation failed\n");
		xio_set_error(ENOMEM);
		return NULL;
	}

	/* fill the message */
	msg = buf;
	msg->out.header.iov_base = msg + 1;
	msg->out.header.iov_len = 0;
	msg->out.data_iovlen = 0;

	ptr = msg->out.header.iov_base;
	len = 0;

	/* serialize message on the buffer */
	len = xio_write_uint32(session->session_id , 0, ptr);
	ptr  = ptr + len;

	/* uri length */
	len = xio_write_uint16((uint16_t)session->uri_len , 0, ptr);
	ptr  = ptr + len;

	/* private length */
	len = xio_write_uint16((uint16_t)(session->user_context_len),
				  0, ptr);
	ptr  = ptr + len;

	if (session->uri_len) {
		len = xio_write_array((uint8_t *)session->uri,
					session->uri_len, 0, ptr);
		ptr  = ptr + len;
	}
	if (session->user_context_len) {
		len = xio_write_array(session->user_context,
					session->user_context_len,
					  0, ptr);
		ptr  = ptr + len;
	}
	msg->out.header.iov_len = ptr - (uint8_t *)msg->out.header.iov_base;

	if (msg->out.header.iov_len > SETUP_BUFFER_LEN)  {
		ERROR_LOG("primary task pool is empty\n");
		xio_set_error(XIO_E_MSG_SIZE);
		kfree(buf);
		return NULL;
	}

	return msg;
}

/*---------------------------------------------------------------------------*/
/* xio_on_connection_hello_rsp_recv			                     */
/*---------------------------------------------------------------------------*/
int xio_on_connection_hello_rsp_recv(struct xio_connection *connection,
				     struct xio_task *task)
{
	xio_connection_release_hello(connection, task->sender_task->omsg);
	/* recycle the task */
	xio_tasks_pool_put(task->sender_task);
	task->sender_task = NULL;
	xio_tasks_pool_put(task);

	xio_connection_xmit_msgs(connection);

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_session_accept_connection					     */
/*---------------------------------------------------------------------------*/
int xio_session_accept_connection(struct xio_session *session)
{
	struct xio_connection	*connection, *tmp_connection;
	struct xio_conn		*conn;
	int			retval = 0;
	char			*portal;

	list_for_each_entry_safe(connection, tmp_connection,
				 &session->connections_list,
				 connections_list_entry) {
		if (connection->conn == NULL) {
			if (connection->conn_idx == 0) {
				portal = session->portals_array[
						session->last_opened_portal++];
				if (session->last_opened_portal ==
				    session->portals_array_len)
					session->last_opened_portal = 0;
			} else {
				int pid = (connection->conn_idx %
					   session->portals_array_len);
				portal = session->portals_array[pid];
			}
			conn = xio_conn_open(connection->ctx, portal,
					     &session->observer,
					     session->session_id);

			if (conn == NULL) {
				ERROR_LOG("failed to open connection to %s\n",
					  portal);
				retval = -1;
				break;
			}
			connection = xio_session_assign_conn(session, conn);
			if (connection == NULL) {
				ERROR_LOG("failed to assign connection\n");
				retval = -1;
				break;
			}
			DEBUG_LOG("reconnecting to %s\n", portal);
			retval = xio_conn_connect(conn, portal,
						  &session->observer, NULL);
			if (retval != 0) {
				ERROR_LOG("connection connect failed\n");
				retval = -1;
				break;
			}
		}
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_session_redirect_connection					     */
/*---------------------------------------------------------------------------*/
int xio_session_redirect_connection(struct xio_session *session)
{
	struct xio_conn		*conn, *tmp_conn;
	int			retval;
	char			*service;

	service = session->services_array[session->last_opened_service++];
	if (session->last_opened_service == session->services_array_len)
		session->last_opened_service = 0;

	conn = xio_conn_open(session->lead_connection->ctx, service, NULL, 0);
	if (conn == NULL) {
		ERROR_LOG("failed to open connection to %s\n",
			  service);
		return -1;
	}
	/* initialize the redirected connection */
	tmp_conn = session->lead_connection->conn;
	session->redir_connection = session->lead_connection;
	xio_connection_set_conn(session->redir_connection, conn);

	TRACE_LOG("connection redirected to %s\n", service);
	retval = xio_conn_connect(conn, service, &session->observer, NULL);
	if (retval != 0) {
		ERROR_LOG("connection connect failed\n");
		goto cleanup;
	}

	/* prep the lead connection for close */
	session->lead_connection = xio_connection_init(session,
			session->lead_connection->ctx,
			session->lead_connection->conn_idx,
			session->lead_connection->cb_user_context);
	xio_connection_set_conn(session->lead_connection, tmp_conn);

	return 0;

cleanup:
	xio_conn_close(conn, &session->observer);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_on_connection_rejected			                             */
/*---------------------------------------------------------------------------*/
int xio_on_connection_rejected(struct xio_session *session,
			       struct xio_connection *connection)
{
	/* notify the upper layer */
	struct xio_session_event_data  ev_data = {
		.event =		XIO_SESSION_REJECT_EVENT,
		.reason =		session->reject_reason,
		.private_data =		session->new_ses_rsp.user_context,
		.private_data_len =	session->new_ses_rsp.user_context_len
	};

	/* also send disconnect to connections that do no have conn */
	while (!list_empty(&session->connections_list)) {
		connection = list_first_entry(&session->connections_list,
				struct xio_connection,
				connections_list_entry);
		ev_data.conn =  connection;
		ev_data.conn_user_context =
			(connection) ? connection->cb_user_context : NULL;

		if (session->ses_ops.on_session_event)
			session->ses_ops.on_session_event(
					session, &ev_data,
					session->cb_user_context);
		connection->state = XIO_CONNECTION_STATE_DISCONNECTED;
		xio_session_disconnect(session, connection);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_read_setup_rsp							     */
/*---------------------------------------------------------------------------*/
int xio_read_setup_rsp(struct xio_connection *connection,
		       struct xio_task *task,
		       uint16_t *action)
{
	struct xio_msg			*msg = &task->imsg;
	struct xio_session_hdr		hdr;
	struct xio_session		*session = connection->session;
	struct xio_new_session_rsp	*rsp = &session->new_ses_rsp;
	uint8_t				*ptr;
	uint16_t			len;
	int				i = 0;
	uint16_t			str_len;

	/* read session header */
	if (xio_session_read_header(task, &hdr) != 0)
		return -1;
	task->imsg.sn = hdr.serial_num;

	/* free the outgoing message */
	kfree(task->sender_task->omsg);
	task->sender_task->omsg = NULL;

	/* read the message */
	ptr = msg->in.header.iov_base;

	/* read the payload */
	len = xio_read_uint32(&session->peer_session_id , 0, ptr);
	ptr  = ptr + len;

	len = xio_read_uint16(action, 0, ptr);
	ptr = ptr + len;

	switch (*action) {
	case XIO_ACTION_ACCEPT:
		len = xio_read_uint16(&session->portals_array_len, 0, ptr);
		ptr = ptr + len;

		len = xio_read_uint16(&rsp->user_context_len, 0, ptr);
		ptr = ptr + len;

		if (session->portals_array_len) {
			session->portals_array = kcalloc(
					session->portals_array_len,
				       sizeof(char *), GFP_KERNEL);
			if (session->portals_array == NULL) {
				ERROR_LOG("allocation failed\n");
				xio_set_error(ENOMEM);
				return -1;
			}
			for (i = 0; i < session->portals_array_len; i++) {
				len = xio_read_uint16(&str_len, 0, ptr);
				ptr = ptr + len;

				session->portals_array[i] =
					kstrndup((char *)ptr, str_len,
						 GFP_KERNEL);
				session->portals_array[i][str_len] = 0;
				ptr = ptr + str_len;
			}

		} else {
			session->portals_array = NULL;
		}

		if (session->new_ses_rsp.user_context_len) {
			rsp->user_context = kcalloc(rsp->user_context_len,
					sizeof(uint8_t), GFP_KERNEL);
			if (rsp->user_context == NULL) {
				ERROR_LOG("allocation failed\n");
				xio_set_error(ENOMEM);
				return -1;
			}

			len = xio_read_array(rsp->user_context,
					rsp->user_context_len, 0, ptr);
			ptr = ptr + len;
		} else {
			rsp->user_context = NULL;
		}
		break;
	case XIO_ACTION_REDIRECT:
		len = xio_read_uint16(&session->services_array_len, 0, ptr);
		ptr = ptr + len;

		len = xio_read_uint16(&rsp->user_context_len, 0, ptr);
		ptr = ptr + len;

		if (session->services_array_len) {
			session->services_array = kcalloc(
					session->services_array_len,
					sizeof(char *), GFP_KERNEL);
			if (session->services_array == NULL) {
				ERROR_LOG("allocation failed\n");
				xio_set_error(ENOMEM);
				return -1;
			}

			for (i = 0; i < session->services_array_len; i++) {
				len = xio_read_uint16(&str_len, 0, ptr);
				ptr = ptr + len;

				session->services_array[i] =
					kstrndup((char *)ptr, str_len,
						 GFP_KERNEL);
				session->services_array[i][str_len] = 0;
				ptr = ptr + str_len;
			}

		} else {
			session->services_array = NULL;
		}
		break;

	case XIO_ACTION_REJECT:
		len = xio_read_uint32(&session->reject_reason , 0, ptr);
		ptr  = ptr + len;

		len = xio_read_uint16(&rsp->user_context_len, 0, ptr);
		ptr = ptr + len;

		if (session->new_ses_rsp.user_context_len) {
			rsp->user_context = kcalloc(rsp->user_context_len,
					sizeof(uint8_t), GFP_KERNEL);
			if (rsp->user_context == NULL) {
				ERROR_LOG("allocation failed\n");
				xio_set_error(ENOMEM);
				return -1;
			}

			len = xio_read_array(rsp->user_context,
					rsp->user_context_len, 0, ptr);
			ptr = ptr + len;
		} else {
			rsp->user_context = NULL;
		}
		break;
	default:
		break;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_prep_portal							     */
/*---------------------------------------------------------------------------*/
static int xio_prep_portal(struct xio_connection *connection)
{
	struct xio_session *session = connection->session;
	char portal[64];

	/* extract portal from uri */
	if (xio_uri_get_portal(session->uri, portal, sizeof(portal)) != 0) {
		xio_set_error(EADDRNOTAVAIL);
		ERROR_LOG("parsing uri failed. uri: %s\n", session->uri);
		return -1;
	}
	session->portals_array = kcalloc(
			1,
			sizeof(char *), GFP_KERNEL);
	if (session->portals_array == NULL) {
		ERROR_LOG("allocation failed\n");
		xio_set_error(ENOMEM);
		return -1;
	}
	session->portals_array_len = 1;
	session->portals_array[0] = kstrdup(portal, GFP_KERNEL);

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_on_setup_rsp_recv			                             */
/*---------------------------------------------------------------------------*/
int xio_on_setup_rsp_recv(struct xio_connection *connection,
			  struct xio_task *task)
{
	uint16_t			action = 0;
	struct xio_session		*session = connection->session;
	struct xio_new_session_rsp	*rsp = &session->new_ses_rsp;
	int				retval = 0;
	struct xio_connection		*tmp_connection;

	retval = xio_read_setup_rsp(connection, task, &action);

	/* the tx task is returend back to pool */
	xio_tasks_pool_put(task->sender_task);
	task->sender_task = NULL;

	xio_tasks_pool_put(task);
	DEBUG_LOG("task recycled\n");

	if (retval != 0) {
		ERROR_LOG("failed to read setup response\n");
		return -1;
	}

	switch (action) {
	case XIO_ACTION_ACCEPT:
		if (session->portals_array == NULL)  {
			xio_prep_portal(connection);

			/* insert the connection into list */
			xio_session_assign_conn(session, connection->conn);
			session->lead_connection = NULL;
			session->redir_connection = NULL;
			session->disable_teardown = 0;

			/* now try to send */
			xio_connection_set_state(connection,
						 XIO_CONNECTION_STATE_ONLINE);

			if (session->connections_nr > 1) {
				session->state = XIO_SESSION_STATE_ACCEPTED;

				/* open new connections */
				retval = xio_session_accept_connection(session);
				if (retval != 0) {
					ERROR_LOG(
						"failed to accept connection\n");
					return -1;
				}
			} else {
				session->state = XIO_SESSION_STATE_ONLINE;
				TRACE_LOG(
				     "session state is now ONLINE. session:%p\n",
				     session);

				/* notify the upper layer */
				if (session->ses_ops.on_session_established)
					session->ses_ops.on_session_established(
						session, rsp,
						session->cb_user_context);

				kfree(rsp->user_context);
				rsp->user_context = NULL;
			}
			/* start connection transmission */
			xio_connection_xmit_msgs(connection);

			return 0;
		} else { /* reconnect to peer other session */
			TRACE_LOG("session state is now ACCEPT. session:%p\n",
				  session);

			/* clone temporary connection */
			tmp_connection = xio_connection_init(
				session,
				session->lead_connection->ctx,
				session->lead_connection->conn_idx,
				session->lead_connection->cb_user_context);

			xio_connection_set_conn(tmp_connection,
						connection->conn);
			connection->conn = NULL;
			session->lead_connection = tmp_connection;

			/* close the lead/redirected connection */
			/* temporay disable teardown */
			session->disable_teardown = 1;
			xio_disconnect_initial_connection(
					session->lead_connection);


			/* temporary disable teardown - on cached conns close
			 * callback may jump immidatly and since there are no
			 * connections. teardown may notified
			 */
			session->state = XIO_SESSION_STATE_ACCEPTED;
			/* open new connections */
			retval = xio_session_accept_connection(session);
			if (retval != 0) {
				ERROR_LOG("failed to accept connection\n");
				return -1;
			}
			TRACE_LOG("sending fin request. session:%p, " \
				  "connection:%p\n",
				  session->lead_connection->session,
				  session->lead_connection);

			return 0;
		}
		break;
	case XIO_ACTION_REDIRECT:
		TRACE_LOG("session state is now REDIRECT. session:%p\n",
			  session);

		session->state = XIO_SESSION_STATE_REDIRECTED;

		/* open new connections */
		retval = xio_session_redirect_connection(session);
		if (retval != 0) {
			ERROR_LOG("failed to redirect connection\n");
			return -1;
		}
		/* close the lead connection */
		session->disable_teardown = 1;
		xio_disconnect_initial_connection(
				session->lead_connection);
		return 0;
		break;
	case XIO_ACTION_REJECT:
		session->state = XIO_SESSION_STATE_REJECTED;

		session->lead_connection = NULL;

		TRACE_LOG("session state is now REJECT. session:%p\n",
			  session);

		retval = xio_on_connection_rejected(session, connection);
		if (retval != 0)
			ERROR_LOG("failed to reject connection\n");

		kfree(rsp->user_context);
		rsp->user_context = NULL;

		return retval;

		break;
	}

	return -1;
}


/*---------------------------------------------------------------------------*/
/* xio_on_conn_refused							     */
/*---------------------------------------------------------------------------*/
int xio_on_conn_refused(struct xio_session *session,
			struct xio_conn *conn,
			union xio_conn_event_data *event_data)
{
	struct xio_connection *connection;

	/* enable the teardown */
	session->disable_teardown  = 0;
	session->lead_connection = NULL;
	session->redir_connection = NULL;

	if ((session->state == XIO_SESSION_STATE_CONNECT) ||
	    (session->state == XIO_SESSION_STATE_REDIRECTED)) {
		session->state = XIO_SESSION_STATE_REFUSED;

		while (!list_empty(&session->connections_list)) {
			connection = list_first_entry(
				&session->connections_list,
				struct xio_connection,
				connections_list_entry);
			connection->state =
				XIO_CONNECTION_STATE_DISCONNECTED;
			xio_session_notify_connection_refused(
					session,
					connection,
					XIO_E_CONNECT_ERROR);
			xio_session_disconnect(session, connection);
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_client_conn_established					     */
/*---------------------------------------------------------------------------*/
int xio_on_client_conn_established(struct xio_session *session,
				   struct xio_conn *conn,
				   union xio_conn_event_data *event_data)
{
	int				retval = 0;
	int				is_last = 1;
	struct xio_connection		*connection;
	struct xio_msg			*msg;
	struct xio_session_event_data	ev_data = {
		.event	=	XIO_SESSION_ERROR_EVENT,
		.reason =	XIO_E_SESSION_REFUSED
	};

	switch (session->state) {
	case XIO_SESSION_STATE_CONNECT:
		msg = xio_session_write_setup_req(session);
		if (msg == NULL) {
			ERROR_LOG("setup request creation failed\n");
			return -1;
		}

		msg->type = XIO_SESSION_SETUP_REQ;
		retval = xio_connection_send(session->lead_connection,
				msg);
		if (retval) {
			TRACE_LOG("failed to send session "\
					"setup request\n");
			ev_data.conn =  session->lead_connection;
			ev_data.conn_user_context =
				session->lead_connection->cb_user_context;
			if (session->ses_ops.on_session_event)
				session->ses_ops.on_session_event(
						session, &ev_data,
						session->cb_user_context);
		}

		break;
	case XIO_SESSION_STATE_REDIRECTED:
		msg = xio_session_write_setup_req(session);
		if (msg == NULL) {
			ERROR_LOG("setup request creation failed\n");
			return -1;
		}
		session->state = XIO_SESSION_STATE_CONNECT;

		msg->type      = XIO_SESSION_SETUP_REQ;

		retval = xio_connection_send(session->redir_connection,
				msg);
		if (retval) {
			TRACE_LOG("failed to send session setup request\n");
			ev_data.conn =  session->redir_connection;
			ev_data.conn_user_context =
				session->redir_connection->cb_user_context;
			if (session->ses_ops.on_session_event)
				session->ses_ops.on_session_event(
						session, &ev_data,
						session->cb_user_context);
		}
		break;
	case XIO_SESSION_STATE_ACCEPTED:
		connection = xio_session_find_connection(session, conn);
		if (connection == NULL) {
			ERROR_LOG("failed to find connection session:%p," \
				  "conn:%p\n", session, conn);
			return -1;
		}
		session->disable_teardown = 0;

		/* introduce the connection to the session */
		xio_connection_send_hello_req(connection);

		/* set the new connection to online */
		xio_connection_set_state(connection,
					 XIO_CONNECTION_STATE_ONLINE);

		/* is this the last to accept */
		list_for_each_entry(connection,
				    &session->connections_list,
				    connections_list_entry) {
			if (connection->state != XIO_CONNECTION_STATE_ONLINE) {
				is_last = 0;
				break;
			}
		}
		if (is_last) {
			session->state = XIO_SESSION_STATE_ONLINE;
			TRACE_LOG("session state is now ONLINE. session:%p\n",
				  session);
			if (session->ses_ops.on_session_established)
				session->ses_ops.on_session_established(
						session, &session->new_ses_rsp,
						session->cb_user_context);

			kfree(session->new_ses_rsp.user_context);
		}
		break;
	case XIO_SESSION_STATE_ONLINE:
		connection = xio_session_find_connection(session, conn);
		if (connection == NULL)  {
			ERROR_LOG("failed to find connection\n");
			return -1;
		}
		DEBUG_LOG("connection established: " \
			  "connection:%p, session:%p, conn:%p\n",
			   connection, connection->session,
			   connection->conn);
		/* now try to send */
		xio_connection_set_state(connection,
					 XIO_CONNECTION_STATE_ONLINE);
		xio_connection_xmit_msgs(connection);
		break;
	default:
		break;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_conn_event_client						     */
/*---------------------------------------------------------------------------*/
int xio_on_conn_event_client(void *observer, void *sender, int event,
			     void *event_data)
{
	struct xio_session	*session = observer;
	struct xio_conn	*conn	= sender;
	int			retval  = 0;


	switch (event) {
	case XIO_CONN_EVENT_NEW_MESSAGE:
/*
		TRACE_LOG("session: [notification] - new message. " \
			 "session:%p, conn:%p\n", observer, sender);

*/		xio_on_new_message(session, conn, event_data);
		break;
	case XIO_CONN_EVENT_SEND_COMPLETION:
/*		TRACE_LOG("session: [notification] - send_completion. " \
			 "session:%p, conn:%p\n", observer, sender);
*/
		xio_on_send_completion(session, conn, event_data);
		break;
	case XIO_CONN_EVENT_ASSIGN_IN_BUF:
/*		TRACE_LOG("session: [notification] - assign in buf. " \
			 "session:%p, conn:%p\n", observer, sender);
*/
		xio_on_assign_in_buf(session, conn, event_data);
		break;
	case XIO_CONN_EVENT_CANCEL_REQUEST:
		DEBUG_LOG("session: [notification] - cancel request. " \
			 "session:%p, conn:%p\n", observer, sender);
		xio_on_cancel_request(session, conn, event_data);
		break;
	case XIO_CONN_EVENT_CANCEL_RESPONSE:
		DEBUG_LOG("session: [notification] - cancel response. " \
			 "session:%p, conn:%p\n", observer, sender);
		xio_on_cancel_response(session, conn, event_data);
		break;
	case XIO_CONN_EVENT_ESTABLISHED:
		DEBUG_LOG("session: [notification] - conn established. " \
			 "session:%p, conn:%p\n", observer, sender);
		xio_on_client_conn_established(session, conn, event_data);
		break;
	case XIO_CONN_EVENT_DISCONNECTED:
		DEBUG_LOG("session: [notification] - conn disconnected" \
			 " session:%p, conn:%p\n", observer, sender);
		xio_on_conn_disconnected(session, conn, event_data);
		break;
	case XIO_CONN_EVENT_CLOSED:
		DEBUG_LOG("session: [notification] - conn closed. " \
			 "session:%p, conn:%p\n", observer, sender);
		xio_on_conn_closed(session, conn, event_data);
		break;
	case XIO_CONN_EVENT_REFUSED:
		DEBUG_LOG("session: [notification] - conn refused. " \
			 "session:%p, conn:%p\n", observer, sender);
		xio_on_conn_refused(session, conn, event_data);
		break;
	case XIO_CONN_EVENT_ERROR:
		DEBUG_LOG("session: [notification] - conn error. " \
			 "session:%p, conn:%p\n", observer, sender);
		xio_on_conn_error(session, conn, event_data);
		break;
	case XIO_CONN_EVENT_MESSAGE_ERROR:
		DEBUG_LOG("session: [notification] - conn message error. " \
			 "session:%p, conn:%p\n", observer, sender);
		xio_on_conn_message_error(session, conn, event_data);
		break;
	default:
		DEBUG_LOG("session: [notification] - unexpected event. " \
			 "event:%d, session:%p, conn:%p\n",
			 event, observer, sender);
		xio_on_conn_error(session, conn, event_data);
		break;
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_connect								     */
/*---------------------------------------------------------------------------*/
struct xio_connection *xio_connect(struct xio_session  *session,
				       struct xio_context  *ctx,
				       uint32_t conn_idx,
				       const char *out_if,
				       void *conn_user_context)
{
	struct xio_session	*psession = NULL;
	struct xio_connection	*connection = NULL, *tmp_connection;
	int			retval;

	if ((ctx == NULL) || (session == NULL)) {
		ERROR_LOG("invalid parameters ctx:%p, session:%p\n",
			  ctx, session);
		xio_set_error(EINVAL);
		return NULL;
	}
	/* lookup for session in store */
	psession = xio_sessions_store_lookup(session->session_id);
	if (psession == NULL) {
		ERROR_LOG("failed to find session\n");
		xio_set_error(EINVAL);
		return NULL;
	}

	mutex_lock(&session->lock);

	/* only one connection per context allowed */
	connection = xio_session_find_connection_by_ctx(session, ctx);
	if (connection != NULL) {
		ERROR_LOG("context:%p, already assigned connection:%p\n",
			  ctx, connection);
		goto cleanup;
	}
	if (session->state == XIO_SESSION_STATE_INIT) {
		char portal[64];
		struct xio_conn	*conn;
		/* extract portal from uri */
		if (xio_uri_get_portal(session->uri, portal,
				       sizeof(portal)) != 0) {
			xio_set_error(EADDRNOTAVAIL);
			ERROR_LOG("parsing uri failed. uri: %s\n",
				  session->uri);
			goto cleanup;
		}
		conn = xio_conn_open(ctx, portal, &session->observer,
						  session->session_id);
		if (conn == NULL) {
			ERROR_LOG("failed to create connection\n");
			goto cleanup;
		}
		/* initialize the lead connection */
		session->lead_connection = xio_session_alloc_connection(
				session, ctx,
				conn_idx,
				conn_user_context);
		session->lead_connection->conn = conn;

		connection  = session->lead_connection;

		/* get transport class routines */
		session->validators_cls = xio_conn_get_validators_cls(conn);

		session->state = XIO_SESSION_STATE_CONNECT;

		retval = xio_conn_connect(conn, portal,
					  &session->observer, out_if);
		if (retval != 0) {
			ERROR_LOG("connection connect failed\n");
			session->state = XIO_SESSION_STATE_INIT;
			goto cleanup;
		}
	} else if ((session->state == XIO_SESSION_STATE_CONNECT) ||
		   (session->state == XIO_SESSION_STATE_REDIRECTED)) {
		connection  = xio_session_alloc_connection(session,
						     ctx, conn_idx,
						     conn_user_context);
	} else if (session->state == XIO_SESSION_STATE_ONLINE ||
		   session->state == XIO_SESSION_STATE_ACCEPTED) {
		struct xio_conn *conn;
		char *portal;
		if (conn_idx == 0) {
			portal = session->portals_array[
					session->last_opened_portal++];
			if (session->last_opened_portal ==
			    session->portals_array_len)
					session->last_opened_portal = 0;
		} else {
			int pid = (conn_idx % session->portals_array_len);
			portal = session->portals_array[pid];
		}
		connection  = xio_session_alloc_connection(session, ctx,
						     conn_idx,
						     conn_user_context);
		conn = xio_conn_open(ctx, portal, &session->observer,
				     session->session_id);
		if (conn == NULL) {
			ERROR_LOG("failed to open connection\n");
			goto cleanup;
		}
		tmp_connection = xio_session_assign_conn(session, conn);
		if (tmp_connection != connection) {
			ERROR_LOG("failed to open connection conn:%p, %p %p\n",
				  conn, tmp_connection, connection);
			goto cleanup;
		}
		DEBUG_LOG("reconnecting to %s, ctx:%p\n", portal, ctx);
		retval = xio_conn_connect(conn, portal,
					  &session->observer, out_if);
		if (retval != 0) {
			ERROR_LOG("connection connect failed\n");
			goto cleanup;
		}
		connection = tmp_connection;
		if (session->state == XIO_SESSION_STATE_ONLINE)
			xio_connection_send_hello_req(connection);
	}
	mutex_unlock(&session->lock);

	return connection;

cleanup:
	mutex_unlock(&session->lock);

	return NULL;
}

