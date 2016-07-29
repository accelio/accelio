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

#include <sys/hashtable.h>
#include <xio_os.h>
#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "xio_protocol.h"
#include "xio_observer.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_transport.h"
#include "xio_sessions_cache.h"
#include "xio_idr.h"
#include "xio_hash.h"
#include "xio_msg_list.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"
#include "xio_nexus.h"
#include "xio_session.h"
#include "xio_connection.h"
#include "xio_session_priv.h"
#include <xio_env_adv.h>

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
	if (unlikely(!buf)) {
		ERROR_LOG("message allocation failed\n");
		xio_set_error(ENOMEM);
		return NULL;
	}

	/* fill the message */
	msg = (struct xio_msg *)buf;
	buf = sum_to_ptr(buf, sizeof(*msg));
	msg->out.header.iov_base = buf;
	msg->out.header.iov_len = 0;
	msg->out.sgl_type = XIO_SGL_TYPE_IOV_PTR;
	msg->in.sgl_type = XIO_SGL_TYPE_IOV_PTR;
	/* All other in/out parameters are zero because of kcalloc anyway */

	msg->type = (enum xio_msg_type)XIO_SESSION_SETUP_REQ;

	ptr = (uint8_t *)msg->out.header.iov_base;
	len = 0;

	/* serialize message on the buffer */
	len = xio_write_uint32(session->session_id, 0, ptr);
	ptr  = ptr + len;

	/* tx queue depth bytes*/
	len = xio_write_uint64(session->snd_queue_depth_bytes, 0, ptr);
	ptr  = ptr + len;

	/* rx queue depth bytes*/
	len = xio_write_uint64(session->rcv_queue_depth_bytes, 0, ptr);
	ptr  = ptr + len;

	/* tx queue depth msgs*/
	len = xio_write_uint16((uint16_t)session->snd_queue_depth_msgs,
			       0, ptr);
	ptr  = ptr + len;

	/* rx queue depth msgs*/
	len = xio_write_uint16((uint16_t)session->rcv_queue_depth_msgs,
			       0, ptr);
	ptr  = ptr + len;

	/* uri length */
	len = xio_write_uint16((uint16_t)session->uri_len, 0, ptr);
	ptr  = ptr + len;

	/* private length */
	len = xio_write_uint16((uint16_t)(session->hs_private_data_len),
			       0, ptr);
	ptr  = ptr + len;

	if (session->uri_len) {
		len = xio_write_array((uint8_t *)session->uri,
				      session->uri_len, 0, ptr);
		ptr  = ptr + len;
	}
	if (session->hs_private_data_len) {
		len = xio_write_array((const uint8_t *)session->hs_private_data,
				      session->hs_private_data_len,
				      0, ptr);
		ptr  = ptr + len;
	}
	msg->out.header.iov_len = ptr - (uint8_t *)msg->out.header.iov_base;

	if (msg->out.header.iov_len > SETUP_BUFFER_LEN)  {
		ERROR_LOG("primary task pool is empty\n");
		xio_set_error(XIO_E_MSG_SIZE);
		kfree(msg);
		return NULL;
	}

	return msg;
}

/*---------------------------------------------------------------------------*/
/* xio_session_accept_connections					     */
/*---------------------------------------------------------------------------*/
int xio_session_accept_connections(struct xio_session *session)
{
	struct xio_connection	*connection, *tmp_connection;
	struct xio_nexus	*nexus;
	int			retval = 0;
	char			*portal;

	list_for_each_entry_safe(connection, tmp_connection,
				 &session->connections_list,
				 connections_list_entry) {
		if (!connection->nexus) {
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
			nexus = xio_nexus_open(connection->ctx, portal,
					       &session->observer,
					       session->session_id,
					       connection->nexus_attr_mask,
					       &connection->nexus_attr);

			if (unlikely(!nexus)) {
				ERROR_LOG("failed to open connection to %s\n",
					  portal);
				retval = -1;
				break;
			}
			connection = xio_session_assign_nexus(session, nexus);
			if (unlikely(!connection)) {
				ERROR_LOG("failed to assign connection\n");
				retval = -1;
				break;
			}
			connection->cd_bit = 0;
			DEBUG_LOG("reconnecting to %s. connection:%p, " \
				  "nexus:%p\n",
				  portal, connection, nexus);
			retval = xio_nexus_connect(nexus, portal,
						   &session->observer, NULL);
			if (unlikely(retval != 0)) {
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
	struct xio_nexus		*nexus, *tmp_nexus;
	int			retval;
	char			*service;

	service = session->services_array[session->last_opened_service++];
	if (session->last_opened_service == session->services_array_len)
		session->last_opened_service = 0;

	nexus = xio_nexus_open(session->lead_connection->ctx, service,
			       NULL, 0,
			       session->lead_connection->nexus_attr_mask,
			       &session->lead_connection->nexus_attr);
	if (unlikely(!nexus)) {
		ERROR_LOG("failed to open connection to %s\n",
			  service);
		return -1;
	}
	/* initialize the redirected connection */
	tmp_nexus = session->lead_connection->nexus;
	session->redir_connection = session->lead_connection;
	session->redir_connection->cd_bit = 0;
	xio_connection_set_nexus(session->redir_connection, nexus);

	ERROR_LOG("connection redirected to %s\n", service);
	retval = xio_nexus_connect(nexus, service, &session->observer, NULL);
	if (unlikely(retval != 0)) {
		ERROR_LOG("connection connect failed\n");
		goto cleanup;
	}

	kfree(session->uri);
	session->uri = kstrdup(service, GFP_KERNEL);

	/* prep the lead connection for close */
	session->lead_connection = xio_connection_create(
			session,
			session->lead_connection->ctx,
			session->lead_connection->conn_idx,
			session->lead_connection->cb_user_context);
	xio_connection_set_nexus(session->lead_connection, tmp_nexus);

	return 0;

cleanup:
	xio_nexus_close(nexus, &session->observer);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_on_session_rejected			                             */
/*---------------------------------------------------------------------------*/
int xio_on_session_rejected(struct xio_session *session)
{
	struct xio_connection *pconnection, *tmp_connection;

	/* also send disconnect to connections that do no have nexus */
	list_for_each_entry_safe(pconnection, tmp_connection,
				 &session->connections_list,
				 connections_list_entry) {
		session->disable_teardown   = 0;
		pconnection->disable_notify = 0;
		pconnection->close_reason = XIO_E_SESSION_REJECTED;
		if (pconnection->nexus)
			xio_disconnect_initial_connection(pconnection);
		else
			xio_connection_disconnected(pconnection);
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
	xio_session_read_header(task, &hdr);
#ifdef XIO_SESSION_DEBUG
	connection->peer_connection = hdr.connection;
	connection->peer_session = hdr.session;
#endif
	task->imsg.sn = hdr.serial_num;

	/* free the outgoing message */
	kfree(task->sender_task->omsg);
	task->sender_task->omsg = NULL;

	/* read the message */
	ptr = (uint8_t *)msg->in.header.iov_base;

	/* read the payload */
	len = xio_read_uint32(&session->peer_session_id, 0, ptr);
	ptr  = ptr + len;

	len = xio_read_uint16(action, 0, ptr);
	ptr = ptr + len;

	switch (*action) {
	case XIO_ACTION_ACCEPT:
		/* read the peer tx queue depth bytes */
		len = xio_read_uint64(&session->peer_snd_queue_depth_bytes,
				      0, ptr);
		ptr = ptr + len;

		/* read the peer rx queue depth bytes */
		len = xio_read_uint64(&session->peer_rcv_queue_depth_bytes,
				      0, ptr);
		ptr = ptr + len;

		/* read the peer tx queue depth msgs */
		len = xio_read_uint16(&session->peer_snd_queue_depth_msgs,
				      0, ptr);
		ptr = ptr + len;

		/* read the peer rx queue depth msgs */
		len = xio_read_uint16(&session->peer_rcv_queue_depth_msgs,
				      0, ptr);
		ptr = ptr + len;

		len = xio_read_uint16(&session->portals_array_len, 0, ptr);
		ptr = ptr + len;

		len = xio_read_uint16(&rsp->private_data_len, 0, ptr);
		ptr = ptr + len;

		if (session->portals_array_len) {
			session->portals_array = (char **)kcalloc(
					session->portals_array_len,
				       sizeof(char *), GFP_KERNEL);
			if (unlikely(!session->portals_array)) {
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

		if (session->new_ses_rsp.private_data_len) {
			rsp->private_data = kcalloc(rsp->private_data_len,
					sizeof(uint8_t), GFP_KERNEL);
			if (unlikely(!rsp->private_data)) {
				ERROR_LOG("allocation failed\n");
				xio_set_error(ENOMEM);
				return -1;
			}

			len = xio_read_array((uint8_t *)rsp->private_data,
					     rsp->private_data_len, 0, ptr);
			ptr = ptr + len;
		} else {
			rsp->private_data = NULL;
		}
		break;
	case XIO_ACTION_REDIRECT:
		len = xio_read_uint16(&session->services_array_len, 0, ptr);
		ptr = ptr + len;

		len = xio_read_uint16(&rsp->private_data_len, 0, ptr);
		ptr = ptr + len;

		if (session->services_array_len) {
			session->services_array = (char **)kcalloc(
					session->services_array_len,
					sizeof(char *), GFP_KERNEL);
			if (unlikely(!session->services_array)) {
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
		len = xio_read_uint32(&session->reject_reason, 0, ptr);
		ptr  = ptr + len;

		len = xio_read_uint16(&rsp->private_data_len, 0, ptr);
		ptr = ptr + len;

		if (session->new_ses_rsp.private_data_len) {
			rsp->private_data = kcalloc(
						rsp->private_data_len,
						sizeof(uint8_t), GFP_KERNEL);
			if (unlikely(!rsp->private_data)) {
				ERROR_LOG("allocation failed\n");
				xio_set_error(ENOMEM);
				return -1;
			}

			len = xio_read_array((uint8_t *)rsp->private_data,
					     rsp->private_data_len, 0, ptr);
			ptr = ptr + len;
		} else {
			rsp->private_data = NULL;
		}
		break;
	default:
		break;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_session_fill_portals_array					     */
/*---------------------------------------------------------------------------*/
static int xio_session_fill_portals_array(struct xio_session *session)
{
	char portal[64];

	/* extract portal from uri */
	if (xio_uri_get_portal(session->uri, portal, sizeof(portal)) != 0) {
		xio_set_error(EADDRNOTAVAIL);
		ERROR_LOG("parsing uri failed. uri: %s\n", session->uri);
		return -1;
	}
	session->portals_array = (char **)kcalloc(
			1,
			sizeof(char *), GFP_KERNEL);
	if (unlikely(!session->portals_array)) {
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
	int				retval = 0, fill_portals = 0;
	struct xio_connection		*tmp_connection;

	retval = xio_read_setup_rsp(connection, task, &action);

	/* the tx task is returend back to pool */
	xio_tasks_pool_put(task->sender_task);
	task->sender_task = NULL;

	xio_tasks_pool_put(task);
	DEBUG_LOG("task recycled\n");

	if (unlikely(retval != 0)) {
		ERROR_LOG("failed to read setup response\n");
		return -1;
	}

	switch (action) {
	case XIO_ACTION_ACCEPT:
		if (!session->portals_array)  {
			xio_session_fill_portals_array(session);
			fill_portals = 1;
		}
		session->state = XIO_SESSION_STATE_ONLINE;
		TRACE_LOG("session state is now ONLINE. session:%p\n", session);
		/* notify the upper layer */
		if (session->ses_ops.on_session_established) {
#ifdef XIO_THREAD_SAFE_DEBUG
			xio_ctx_debug_thread_unlock(connection->ctx);
#endif
			session->ses_ops.on_session_established(
					session, rsp,
					session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
			xio_ctx_debug_thread_lock(connection->ctx);
#endif
		}

		kfree(rsp->private_data);
		rsp->private_data = NULL;

		if (fill_portals)  {
			xio_on_connection_hello_rsp_recv(connection, NULL);
			/* insert the connection into list */
			xio_session_assign_nexus(session, connection->nexus);
			session->lead_connection = NULL;
			session->redir_connection = NULL;
			session->disable_teardown = 0;

			if (session->connections_nr > 1) {
				/* open new connections */
				retval = xio_session_accept_connections(
								session);
				if (unlikely(retval != 0)) {
					ERROR_LOG(
					    "failed to accept connection\n");
					return -1;
				}
			}
		} else { /* reconnect to peer other session */
			TRACE_LOG("session state is now ACCEPT. session:%p\n",
				  session);

			/* clone temporary connection */
			tmp_connection = xio_connection_create(
				session,
				session->lead_connection->ctx,
				session->lead_connection->conn_idx,
				session->lead_connection->cb_user_context);

			xio_connection_set_nexus(tmp_connection,
						 connection->nexus);
			connection->nexus = NULL;
			session->lead_connection = tmp_connection;

			/* close the lead/redirected connection */
			/* temporary disable teardown */
			session->disable_teardown = 1;
			session->lead_connection->disable_notify = 1;
			session->lead_connection->state	=
					XIO_CONNECTION_STATE_ONLINE;

			/* temporary account it as user object */
			xio_idr_add_uobj(usr_idr, session->lead_connection,
					 "xio_connection");
			xio_disconnect_initial_connection(
						session->lead_connection);

			/* open new connections */
			retval = xio_session_accept_connections(session);
			if (unlikely(retval != 0)) {
				ERROR_LOG("failed to accept connection\n");
				return -1;
			}
		}
		return 0;
	case XIO_ACTION_REDIRECT:
		TRACE_LOG("session state is now REDIRECT. session:%p\n",
			  session);

		session->state = XIO_SESSION_STATE_REDIRECTED;

		/* open new connections */
		retval = xio_session_redirect_connection(session);
		if (unlikely(retval != 0)) {
			ERROR_LOG("failed to redirect connection\n");
			return -1;
		}

		/* close the lead connection */
		session->disable_teardown = 1;
		session->lead_connection->disable_notify = 1;
		session->lead_connection->state	= XIO_CONNECTION_STATE_ONLINE;
		xio_disconnect_initial_connection(session->lead_connection);

		return 0;
	case XIO_ACTION_REJECT:
		xio_connection_set_state(connection,
					 XIO_CONNECTION_STATE_ESTABLISHED);
		xio_session_notify_connection_established(session,
							  connection);

		session->state = XIO_SESSION_STATE_REJECTED;
		session->disable_teardown = 0;
		session->lead_connection = NULL;

		TRACE_LOG("session state is now REJECT. session:%p\n",
			  session);

		retval = xio_on_session_rejected(session);
		if (unlikely(retval != 0))
			ERROR_LOG("failed to reject session\n");

		kfree(rsp->private_data);
		rsp->private_data = NULL;

		return retval;
	}

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_on_nexus_refused							     */
/*---------------------------------------------------------------------------*/
int xio_on_nexus_refused(struct xio_session *session,
			 struct xio_nexus *nexus,
			 union xio_nexus_event_data *event_data)
{
	struct xio_connection *connection, *next_connection;

	/* enable the teardown */
	session->disable_teardown  = 0;

	switch (session->state) {
	case XIO_SESSION_STATE_CONNECT:
	case XIO_SESSION_STATE_REDIRECTED:
		session->state = XIO_SESSION_STATE_REFUSED;
		list_for_each_entry_safe(
				connection, next_connection,
				&session->connections_list,
				connections_list_entry) {
			xio_connection_refused(connection);
		}
		break;
	default:
		connection = xio_session_find_connection(session, nexus);
		if (connection)
			xio_connection_refused(connection);
		break;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_client_nexus_established					     */
/*---------------------------------------------------------------------------*/
int xio_on_client_nexus_established(struct xio_session *session,
				    struct xio_nexus *nexus,
				    union xio_nexus_event_data *event_data)
{
	int				retval = 0;
	struct xio_connection		*connection;
	struct xio_msg			*msg;
	struct xio_session_event_data	ev_data = {
		.conn = NULL,
		.conn_user_context = NULL,
		.event = XIO_SESSION_ERROR_EVENT,
		.private_data = NULL,
		.private_data_len = 0,
		.reason = XIO_E_SESSION_REFUSED,
	};

	switch (session->state) {
	case XIO_SESSION_STATE_CONNECT:
		msg = xio_session_write_setup_req(session);
		if (unlikely(!msg)) {
			ERROR_LOG("setup request creation failed\n");
			return -1;
		}

		retval = xio_connection_send(session->lead_connection,
					     msg);
		if (retval && retval != -EAGAIN) {
			TRACE_LOG("failed to send session "\
					"setup request\n");
			ev_data.conn =  session->lead_connection;
			ev_data.conn_user_context =
				session->lead_connection->cb_user_context;
			if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_unlock(session->lead_connection->ctx);
#endif
				session->ses_ops.on_session_event(
						session, &ev_data,
						session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_lock(session->lead_connection->ctx);
#endif
			}
		}

		break;
	case XIO_SESSION_STATE_REDIRECTED:
		msg = xio_session_write_setup_req(session);
		if (unlikely(!msg)) {
			ERROR_LOG("setup request creation failed\n");
			return -1;
		}
		session->state = XIO_SESSION_STATE_CONNECT;

		retval = xio_connection_send(session->redir_connection,
					     msg);
		if (retval && retval != -EAGAIN) {
			TRACE_LOG("failed to send session setup request\n");
			ev_data.conn =  session->redir_connection;
			ev_data.conn_user_context =
				session->redir_connection->cb_user_context;
			if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_unlock(session->redir_connection->ctx);
#endif
				session->ses_ops.on_session_event(
						session, &ev_data,
						session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_lock(session->redir_connection->ctx);
#endif
			}

		}
		break;
	case XIO_SESSION_STATE_ONLINE:
	case XIO_SESSION_STATE_ACCEPTED:
		connection = xio_session_find_connection(session, nexus);
		if (unlikely(!connection)) {
			ERROR_LOG("failed to find connection session:%p," \
				  "nexus:%p\n", session, nexus);
			return -1;
		}
		session->disable_teardown = 0;
		if (connection->state == XIO_CONNECTION_STATE_INIT) {
			/* introduce the connection to the session */
			xio_connection_send_hello_req(connection);
		} else {
			xio_connection_set_state(connection,
						 XIO_CONNECTION_STATE_ONLINE);
			xio_connection_keepalive_start(connection);
			xio_connection_xmit_msgs(connection);
		}
		break;
	default:
		break;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_client_on_nexus_event						     */
/*---------------------------------------------------------------------------*/
int xio_client_on_nexus_event(void *observer, void *sender, int event,
			      void *_event_data)
{
	struct xio_session	*session = (struct xio_session *)observer;
	struct xio_nexus	*nexus	= (struct xio_nexus *)sender;
	union xio_nexus_event_data *event_data =
			(union xio_nexus_event_data *)_event_data;

	switch (event) {
	case XIO_NEXUS_EVENT_NEW_MESSAGE:
/*
		TRACE_LOG("session: [notification] - new message. " \
			 "session:%p, nexus:%p\n", observer, sender);

*/		xio_on_new_message(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_SEND_COMPLETION:
/*		TRACE_LOG("session: [notification] - send_completion. " \
			 "session:%p, nexus:%p\n", observer, sender);
*/
		xio_on_send_completion(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_DIRECT_RDMA_COMPLETION:
		xio_on_rdma_direct_comp(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_ASSIGN_IN_BUF:
/*		TRACE_LOG("session: [notification] - assign in buf. " \
			 "session:%p, nexus:%p\n", observer, sender);
*/
		xio_on_assign_in_buf(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_CANCEL_REQUEST:
		DEBUG_LOG("session: [notification] - cancel request. " \
			 "session:%p, nexus:%p\n", observer, sender);
		xio_on_cancel_request(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_CANCEL_RESPONSE:
		DEBUG_LOG("session: [notification] - cancel response. " \
			 "session:%p, nexus:%p\n", observer, sender);
		xio_on_cancel_response(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_ESTABLISHED:
		DEBUG_LOG("session: [notification] - nexus established. " \
			 "session:%p, nexus:%p\n", observer, sender);
		xio_on_client_nexus_established(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_DISCONNECTED:
		DEBUG_LOG("session: [notification] - nexus disconnected" \
			 " session:%p, nexus:%p\n", observer, sender);
		xio_on_nexus_disconnected(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_RECONNECTING:
		DEBUG_LOG("session: [notification] - connection reconnecting" \
			 " session:%p, nexus:%p\n", observer, sender);
		xio_on_nexus_reconnecting(session, nexus);
		break;
	case XIO_NEXUS_EVENT_RECONNECTED:
		DEBUG_LOG("session: [notification] - connection reconnected" \
			 " session:%p, nexus:%p\n", observer, sender);
		xio_on_nexus_reconnected(session, nexus);
		break;
	case XIO_NEXUS_EVENT_CLOSED:
		DEBUG_LOG("session: [notification] - nexus closed. " \
			 "session:%p, nexus:%p\n", observer, sender);
		xio_on_nexus_closed(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_REFUSED:
		DEBUG_LOG("session: [notification] - nexus refused. " \
			 "session:%p, nexus:%p\n", observer, sender);
		xio_on_nexus_refused(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_ERROR:
		DEBUG_LOG("session: [notification] - nexus error. " \
			 "session:%p, nexus:%p\n", observer, sender);
		xio_on_nexus_error(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_MESSAGE_ERROR:
		DEBUG_LOG("session: [notification] - nexus message error. " \
			 "session:%p, nexus:%p\n", observer, sender);
		xio_on_nexus_message_error(session, nexus, event_data);
		break;
	default:
		DEBUG_LOG("session: [notification] - unexpected event. " \
			 "event:%d, session:%p, nexus:%p\n",
			 event, observer, sender);
		xio_on_nexus_error(session, nexus, event_data);
		break;
	}

	return 0;
}

static inline void xio_session_refuse_connection(void *conn)
{
	struct xio_connection *connection = (struct xio_connection *)conn;

	xio_connection_refused(connection);
}

static void xio_connect_timeout(void *data)
{
	struct xio_connection *connection = (struct xio_connection *)data;

	xio_connection_force_disconnect(connection, XIO_E_TIMEOUT);
}

/*---------------------------------------------------------------------------*/
/* xio_connect								     */
/*---------------------------------------------------------------------------*/
struct xio_connection *xio_connect(struct xio_connection_params *cparams)
{
	struct xio_session	*session;
	struct xio_context	*ctx;
	struct xio_session	*psession = NULL;
	struct xio_connection	*connection = NULL, *tmp_connection;
	struct xio_nexus	*nexus = NULL;
	int			retval;
	int			attr_mask = 0;
	struct			xio_nexus_init_attr *pattr = NULL;
	struct			xio_nexus_init_attr  attr;

	if (!cparams) {
		ERROR_LOG("invalid parameter\n");
		xio_set_error(EINVAL);
		return NULL;
	}

	if (!cparams->ctx || !cparams->session) {
		ERROR_LOG("invalid parameters ctx:%p, session:%p\n",
			  cparams->ctx, cparams->session);
		xio_set_error(EINVAL);
		return NULL;
	}
	ctx	= cparams->ctx;
	session = cparams->session;
	if (cparams->enable_tos) {
		attr.tos	= cparams->tos;
		attr_mask	= XIO_NEXUS_ATTR_TOS;
		pattr		= &attr;
	}

	/* lookup for session in cache */
	psession = xio_sessions_cache_lookup(session->session_id);
	if (!psession) {
		ERROR_LOG("failed to find session\n");
		xio_set_error(EINVAL);
		return NULL;
	}

	mutex_lock(&session->lock);

	/* only one connection per context allowed */
	connection = xio_session_find_connection_by_ctx(session, ctx);
	if (connection) {
		ERROR_LOG("context:%p, already assigned connection:%p\n",
			  ctx, connection);
		goto cleanup2;
	}
	if (session->state == XIO_SESSION_STATE_INIT) {
		char portal[64];
		/* extract portal from uri */
		if (xio_uri_get_portal(session->uri, portal,
				       sizeof(portal)) != 0) {
			xio_set_error(EADDRNOTAVAIL);
			ERROR_LOG("parsing uri failed. uri: %s\n",
				  session->uri);
			goto cleanup;
		}
		nexus = xio_nexus_open(ctx, portal, &session->observer,
				       session->session_id,
				       attr_mask, pattr);
		if (!nexus) {
			ERROR_LOG("failed to create connection\n");
			goto cleanup;
		}
		/* initialize the lead connection */
		session->lead_connection = xio_session_alloc_connection(
				session, ctx,
				cparams->conn_idx,
				cparams->conn_user_context);
		session->lead_connection->nexus = nexus;

		connection  = session->lead_connection;

		/* get transport class routines */
		session->validators_cls = xio_nexus_get_validators_cls(nexus);

		session->state = XIO_SESSION_STATE_CONNECT;

		retval = xio_nexus_connect(nexus, portal,
					   &session->observer,
					   cparams->out_addr);
		if (retval != 0) {
			ERROR_LOG("connection connect failed\n");
			session->state = XIO_SESSION_STATE_INIT;
			goto cleanup;
		}
	} else if ((session->state == XIO_SESSION_STATE_CONNECT) ||
		   (session->state == XIO_SESSION_STATE_REDIRECTED)) {
		connection  = xio_session_alloc_connection(
				session, ctx,
				cparams->conn_idx,
				cparams->conn_user_context);
		if (session->state == XIO_SESSION_STATE_REFUSED ||
		    session->state == XIO_SESSION_STATE_REJECTED) {
			xio_idr_add_uobj(usr_idr, connection, "xio_connection");
			mutex_unlock(&session->lock);
			retval = xio_ctx_add_work(
					connection->ctx,
					connection,
					xio_session_refuse_connection,
					&connection->fin_work);
			if (retval != 0)
				ERROR_LOG("xio_ctx_timer_add failed.\n");

			return connection;
		} else if (session->state == XIO_SESSION_STATE_CLOSING ||
			   session->state == XIO_SESSION_STATE_CLOSED) {
			DEBUG_LOG("refusing connection %p - " \
				  "session is closing\n", connection);
			goto cleanup;
		}
	} else if (session->state == XIO_SESSION_STATE_ONLINE ||
		   session->state == XIO_SESSION_STATE_ACCEPTED) {
		struct xio_nexus *nexus;
		char *portal;

		if (cparams->conn_idx == 0) {
			portal = session->portals_array[
					session->last_opened_portal++];
			if (session->last_opened_portal ==
			    session->portals_array_len)
					session->last_opened_portal = 0;
		} else {
			int pid =
				(cparams->conn_idx %
				 session->portals_array_len);

			portal = session->portals_array[pid];
		}
		connection  = xio_session_alloc_connection(
				session, ctx,
				cparams->conn_idx,
				cparams->conn_user_context);

		nexus = xio_nexus_open(ctx, portal, &session->observer,
				       session->session_id,
				       attr_mask, pattr);
		if (!nexus) {
			ERROR_LOG("failed to open connection\n");
			goto cleanup;
		}
		tmp_connection = xio_session_assign_nexus(session, nexus);
		if (tmp_connection != connection) {
			ERROR_LOG("failed to open connection nexus:%p, %p %p\n",
				  nexus, tmp_connection, connection);
			goto cleanup;
		}
		retval = xio_nexus_connect(nexus, portal,
					   &session->observer,
					   cparams->out_addr);
		if (retval != 0) {
			ERROR_LOG("connection connect failed\n");
			goto cleanup;
		}
	} else if (session->state == XIO_SESSION_STATE_REFUSED ||
		    session->state == XIO_SESSION_STATE_REJECTED ||
		    session->state == XIO_SESSION_STATE_CLOSING ||
		    session->state == XIO_SESSION_STATE_CLOSED) {
		goto cleanup2;
	}

	xio_idr_add_uobj(usr_idr, connection, "xio_connection");

	if (cparams->enable_tos) {
		connection->nexus_attr_mask = attr_mask;
		connection->nexus_attr	    = attr;
	}
	if (cparams->connect_timeout_secs) {
		int  connect_timeout = cparams->connect_timeout_secs * 1000;
		retval = xio_ctx_add_delayed_work(
						  connection->ctx,
						  connect_timeout,
						  connection,
						  xio_connect_timeout,
						  &connection->connect_work);
		if (unlikely(retval)) {
			ERROR_LOG("xio_ctx_delayed_work failed. rc:%d\n", retval);
			/* not critical - do not exit */
		}
	}

	if (cparams->disconnect_timeout_secs) {
                if (cparams->disconnect_timeout_secs < XIO_MIN_CONNECTION_TIMEOUT)
                        connection->disconnect_timeout = XIO_MIN_CONNECTION_TIMEOUT;
                else
                        connection->disconnect_timeout = cparams->disconnect_timeout_secs * 1000;
	} else {
                connection->disconnect_timeout = XIO_DEF_CONNECTION_TIMEOUT;
        }

	mutex_unlock(&session->lock);

	DEBUG_LOG("xio_connect: session:%p, connection:%p, " \
		  "ctx:%p, nexus:%p\n",
		  session, connection, ctx,
		  ((connection) ? connection->nexus : NULL));

	return connection;

cleanup:
	if (nexus)
		xio_nexus_close(nexus, &session->observer);

	if (connection)
		xio_session_free_connection(connection);

cleanup2:
	mutex_unlock(&session->lock);

	return NULL;
}
EXPORT_SYMBOL(xio_connect);
