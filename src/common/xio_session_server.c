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
/* xio_on_setup_req_recv			                             */
/*---------------------------------------------------------------------------*/
int xio_on_setup_req_recv(struct xio_connection *connection,
			  struct xio_task *task)
{
	struct xio_msg			*msg = &task->imsg;
	struct xio_new_session_req	req;
	uint8_t				*ptr;
	uint16_t			len;
	struct xio_session_hdr		hdr;
	struct xio_session		*session = connection->session;
	int				retval;
	struct xio_session_event_data  error_event = {
		.conn = NULL,
		.conn_user_context = NULL,
		.event = XIO_SESSION_ERROR_EVENT,
		.reason = XIO_E_SUCCESS,
		.private_data = NULL,
		.private_data_len = 0,
	};

	/* read session header */
	xio_session_read_header(task, &hdr);
#ifdef XIO_SESSION_DEBUG
	connection->peer_connection = hdr.connection;
	connection->peer_session = hdr.session;
#endif
	task->imsg.sn = hdr.serial_num;
	task->connection = connection;
	task->session = session;
	connection->session->setup_req = msg;
	connection->session->connection_srv_first = connection;

	/* read the header */
	ptr = (uint8_t *)msg->in.header.iov_base;

	memset(&req, 0, sizeof(req));

	/* session id */
	len = xio_read_uint32(&session->peer_session_id, 0, ptr);
	ptr  = ptr + len;

	/* queue depth bytes */
	len = xio_read_uint64(&session->peer_snd_queue_depth_bytes, 0, ptr);
	ptr = ptr + len;

	len = xio_read_uint64(&session->peer_rcv_queue_depth_bytes, 0, ptr);
	ptr = ptr + len;

	/* queue depth msgs */
	len = xio_read_uint16((uint16_t *)&session->peer_snd_queue_depth_msgs,
			      0, ptr);
	ptr = ptr + len;

	len = xio_read_uint16((uint16_t *)&session->peer_rcv_queue_depth_msgs,
			      0, ptr);
	ptr = ptr + len;

	/* uri length */
	len = xio_read_uint16(&req.uri_len, 0, ptr);
	ptr = ptr + len;

	/* private length */
	len = xio_read_uint16(&req.private_data_len, 0, ptr);
	ptr = ptr + len;

	if (req.uri_len) {
		req.uri =
		  (char *)kcalloc(req.uri_len, sizeof(char), GFP_KERNEL);
		if (unlikely(!req.uri)) {
			xio_set_error(ENOMEM);
			ERROR_LOG("uri allocation failed. len:%d\n",
				  req.uri_len);
			goto cleanup1;
		}

		len = xio_read_array((uint8_t *)req.uri,
				     req.uri_len, 0, ptr);
		ptr = ptr + len;
	}
	if (req.private_data_len) {
		req.private_data = kcalloc(req.private_data_len,
					   sizeof(uint8_t), GFP_KERNEL);
		if (unlikely(!req.private_data)) {
			xio_set_error(ENOMEM);
			ERROR_LOG("private data allocation failed. len:%d\n",
				  req.private_data_len);
			goto cleanup2;
		}
		len = xio_read_array((uint8_t *)req.private_data,
				     req.private_data_len,
				     0, ptr);
		ptr = ptr + len;
	}

	req.proto = (enum xio_proto)xio_nexus_get_proto(connection->nexus);
	xio_nexus_get_peer_addr(connection->nexus,
				&req.src_addr, sizeof(req.src_addr));

	/* cache the task in io queue*/
	xio_connection_queue_io_task(connection, task);

	/* notify the upper layer */
	if (connection->ses_ops.on_new_session) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		retval = connection->ses_ops.on_new_session(
					session, &req,
					connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
		if (retval)
			goto cleanup2;
	} else {
		retval = xio_accept(session, NULL, 0, NULL, 0);
		if (retval) {
			ERROR_LOG("failed to auto accept session. session:%p\n",
				  session);
			goto cleanup2;
		}
	}

	/* Don't move session state to ONLINE. In case of multiple portals
	 * the accept moves the state to ACCEPTED until the first "HELLO"
	 * message arrives. Note that the "upper layer" may call redirect or
	 * reject.
	 */

	xio_session_notify_new_connection(session, connection);

	kfree(req.private_data);
	kfree(req.uri);

	return 0;

cleanup2:
	kfree(req.private_data);

cleanup1:
	kfree(req.uri);

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		error_event.reason = (enum xio_status)xio_errno();
		session->ses_ops.on_session_event(
				session, &error_event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_session_write_accept_rsp						     */
/*---------------------------------------------------------------------------*/
struct xio_msg *xio_session_write_accept_rsp(struct xio_session *session,
					     uint16_t action,
					     const char **portals_array,
					     uint16_t portals_array_len,
					     void *user_context,
					     uint16_t user_context_len)
{
	struct xio_msg		*msg;
	uint8_t			*buf;
	uint8_t			*ptr;
	uint16_t		len, i, str_len, tot_len;

	/* calculate length */
	tot_len = 5*sizeof(uint16_t) + sizeof(uint32_t) + 2*sizeof(uint64_t);
	for (i = 0; i < portals_array_len; i++)
		tot_len += strlen(portals_array[i]) + sizeof(uint16_t);
	tot_len += user_context_len;

	if (tot_len > SETUP_BUFFER_LEN)  {
		ERROR_LOG("buffer is too small\n");
		xio_set_error(EMSGSIZE);
		return NULL;
	}

	/* allocate message */
	buf = (uint8_t *)kcalloc(SETUP_BUFFER_LEN + sizeof(struct xio_msg),
		      sizeof(uint8_t), GFP_KERNEL);
	if (unlikely(!buf)) {
		ERROR_LOG("message allocation failed\n");
		xio_set_error(ENOMEM);
		return NULL;
	}

	/* fill the message */
	msg = (struct xio_msg *)buf;
	msg->out.header.iov_base = buf + sizeof(struct xio_msg);
	msg->out.header.iov_len = 0;

	ptr = (uint8_t *)msg->out.header.iov_base;
	len = 0;

	/* serialize message into the buffer */

	/* session_id */
	len = xio_write_uint32(session->session_id, 0, ptr);
	ptr  = ptr + len;

	/* action */
	len = xio_write_uint16(action, 0, ptr);
	ptr  = ptr + len;

	if (action == XIO_ACTION_ACCEPT) {
		/* tx queue depth bytes */
		len = xio_write_uint64(session->snd_queue_depth_bytes, 0, ptr);
		ptr  = ptr + len;

		/* rx queue depth bytes */
		len = xio_write_uint64(session->rcv_queue_depth_bytes, 0, ptr);
		ptr  = ptr + len;

		/* tx queue depth msgs */
		len = xio_write_uint16(session->snd_queue_depth_msgs, 0, ptr);
		ptr  = ptr + len;

		/* rx queue depth msgs */
		len = xio_write_uint16(session->rcv_queue_depth_msgs, 0, ptr);
		ptr  = ptr + len;
	}

	/* portals_array_len */
	len = xio_write_uint16(portals_array_len, 0, ptr);
	ptr  = ptr + len;

	/* user_context_len */
	len = xio_write_uint16(user_context_len, 0, ptr);
	ptr  = ptr + len;

	for (i = 0; i < portals_array_len; i++) {
		str_len = strlen(portals_array[i]);

		len = xio_write_uint16(str_len, 0, ptr);
		ptr  = ptr + len;

		len = xio_write_array((uint8_t *)portals_array[i],
				      str_len, 0, ptr);
		ptr  = ptr + len;
	}

	if (user_context_len) {
		len = xio_write_array((const uint8_t *)user_context,
				      user_context_len,
				      0, ptr);
		ptr  = ptr + len;
	}

	msg->out.header.iov_len = ptr - (uint8_t *)msg->out.header.iov_base;

	if (msg->out.header.iov_len != tot_len) {
		ERROR_LOG("calculated length %d != actual length %zd\n",
			  tot_len, msg->out.header.iov_len);
	}

	return msg;
}

/*---------------------------------------------------------------------------*/
/* xio_session_write_reject_rsp						     */
/*---------------------------------------------------------------------------*/
struct xio_msg *xio_session_write_reject_rsp(struct xio_session *session,
					     enum xio_status reason,
					     void *user_context,
					     uint16_t user_context_len)
{
	struct xio_msg	*msg;
	uint8_t			*buf;
	uint8_t			*ptr;
	uint16_t		len,  tot_len;
	uint16_t		action = XIO_ACTION_REJECT;

	/* calclate length */
	tot_len = 2*sizeof(uint16_t) + 2*sizeof(uint32_t);
	tot_len += user_context_len;

	if (tot_len > SETUP_BUFFER_LEN)  {
		ERROR_LOG("buffer is too small\n");
		xio_set_error(EMSGSIZE);
		return NULL;
	}

	/* allocate message */
	buf = (uint8_t *)kcalloc(SETUP_BUFFER_LEN + sizeof(struct xio_msg),
		      sizeof(uint8_t), GFP_KERNEL);
	if (!buf) {
		ERROR_LOG("message allocation failed\n");
		xio_set_error(ENOMEM);
		return NULL;
	}

	/* fill the message */
	msg = (struct xio_msg *)buf;
	msg->out.header.iov_base = buf + sizeof(struct xio_msg);
	msg->out.header.iov_len = 0;

	ptr = (uint8_t *)msg->out.header.iov_base;
	len = 0;

	/* serialize message into the buffer */

	/* session_id */
	len = xio_write_uint32(session->session_id, 0, ptr);
	ptr  = ptr + len;

	/* action */
	len = xio_write_uint16(action, 0, ptr);
	ptr  = ptr + len;

	/* reason */
	len = xio_write_uint32(reason, 0, ptr);
	ptr  = ptr + len;

	/* user_context_len */
	len = xio_write_uint16(user_context_len, 0, ptr);
	ptr  = ptr + len;

	if (user_context_len) {
		len = xio_write_array((const uint8_t *)user_context,
				      user_context_len,
				      0, ptr);
		ptr  = ptr + len;
	}

	msg->out.header.iov_len = ptr - (uint8_t *)msg->out.header.iov_base;

	if (msg->out.header.iov_len != tot_len) {
		ERROR_LOG("calculated length %d != actual length %zd\n",
			  tot_len, msg->out.header.iov_len);
	}

	return msg;
}

/*---------------------------------------------------------------------------*/
/* xio_accept								     */
/*---------------------------------------------------------------------------*/
int xio_accept(struct xio_session *session,
	       const char **portals_array,
	       size_t portals_array_len,
	       void *user_context,
	       size_t user_context_len)
{
	int			retval = 0;
	struct xio_msg		*msg;
	struct xio_task		*task;

	msg = xio_session_write_accept_rsp(session,
					   XIO_ACTION_ACCEPT,
					   portals_array,
					   portals_array_len,
					   user_context,
					   user_context_len);
	if (!msg) {
		ERROR_LOG("setup request creation failed\n");
		return -1;
	}

	msg->request	= session->setup_req;
	msg->type	= (enum xio_msg_type)XIO_SESSION_SETUP_RSP;

	task = container_of(msg->request,
			    struct xio_task, imsg);

	if (portals_array_len != 0) {
		/* server side state is changed to ACCEPT, will be move to
		 * ONLINE state when first "hello" message arrives
		 */
		session->state = XIO_SESSION_STATE_ACCEPTED;
		/* temporary disable teardown */
		session->disable_teardown = 1;
		TRACE_LOG("session state is now ACCEPT. session:%p\n",
			  session);
	} else {
		/* initialize credits */
		task->connection->peer_credits_msgs =
					session->peer_rcv_queue_depth_msgs;
		task->connection->credits_msgs	= 0;
		task->connection->peer_credits_bytes =
					session->peer_rcv_queue_depth_bytes;
		task->connection->credits_bytes	= 0;

		/* server side state is changed to ONLINE, immediately  */
		session->state = XIO_SESSION_STATE_ONLINE;
		TRACE_LOG("session state changed to ONLINE. session:%p\n",
			  session);
	}
	retval = xio_connection_send(task->connection, msg);
	if (retval && retval != -EAGAIN) {
		ERROR_LOG("failed to send message. errno:%d\n", -retval);
		xio_set_error(-retval);
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL(xio_accept);

/*---------------------------------------------------------------------------*/
/* xio_redirect								     */
/*---------------------------------------------------------------------------*/
int xio_redirect(struct xio_session *session,
		 const char **portals_array,
		 size_t portals_array_len)
{
	int			retval = 0;
	struct xio_msg		*msg;
	struct xio_task		*task;

	if (portals_array_len == 0 || !portals_array) {
		xio_set_error(EINVAL);
		ERROR_LOG("portals array for redirect is mandatory\n");
		return -1;
	}

	msg = xio_session_write_accept_rsp(session,
					   XIO_ACTION_REDIRECT,
					   portals_array,
					   portals_array_len,
					   NULL,
					   0);
	if (unlikely(!msg)) {
		ERROR_LOG("setup request creation failed\n");
		return -1;
	}
	if (portals_array_len != 0) {
		/* server side state is changed to ACCEPT */
		session->state = XIO_SESSION_STATE_REDIRECTED;
		TRACE_LOG("session state is now REDIRECTED. session:%p\n",
			  session);
	}
	msg->request = session->setup_req;
	msg->type    = (enum xio_msg_type)XIO_SESSION_SETUP_RSP;

	task = container_of(msg->request,
			    struct xio_task, imsg);

	retval = xio_connection_send(task->connection, msg);
	if (retval && retval != -EAGAIN) {
		ERROR_LOG("failed to send message errno:%d\n", -retval);
		xio_set_error(-retval);
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL(xio_redirect);

/*---------------------------------------------------------------------------*/
/* xio_reject								     */
/*---------------------------------------------------------------------------*/
int xio_reject(struct xio_session *session,
	       enum xio_status reason,
	       void *user_context,
	       size_t user_context_len)
{
	int			retval = 0;
	struct xio_msg		*msg;
	struct xio_task		*task;

	msg = xio_session_write_reject_rsp(session, reason, user_context,
					   user_context_len);
	if (!msg) {
		ERROR_LOG("setup request creation failed\n");
		return -1;
	}
	/* server side state is changed to REJECTED */
	session->state = XIO_SESSION_STATE_REJECTED;
	TRACE_LOG("session state is now REJECT. session:%p\n",
		  session);

	msg->request = session->setup_req;
	msg->type    = (enum xio_msg_type)XIO_SESSION_SETUP_RSP;

	task = container_of(msg->request,
			    struct xio_task, imsg);

	task->connection->close_reason = XIO_E_SESSION_REJECTED;

	retval = xio_connection_send(task->connection, msg);
	if (retval && retval != -EAGAIN) {
		ERROR_LOG("failed to send message. errno:%d\n", -retval);
		xio_set_error(-retval);
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL(xio_reject);

/*---------------------------------------------------------------------------*/
/* xio_on_setup_rsp_send_comp			                             */
/*---------------------------------------------------------------------------*/
int xio_on_setup_rsp_send_comp(struct xio_connection *connection,
			       struct xio_task *task)
{
	TRACE_LOG("got session setup response comp. session:%p, " \
		  "connection:%p\n",
		  connection->session, connection);

	kfree(task->omsg);

	/* recycle the task */
	xio_tasks_pool_put(task);

	/* time to set new callback */
	DEBUG_LOG("task recycled\n");

	switch (connection->session->state) {
	case XIO_SESSION_STATE_ACCEPTED:
	case XIO_SESSION_STATE_REJECTED:
	case XIO_SESSION_STATE_REDIRECTED:
		xio_disconnect_initial_connection(connection);
		break;
	default:
		/* try to transmit now */
		xio_connection_xmit_msgs(connection);
		break;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_server_nexus_established					     */
/*---------------------------------------------------------------------------*/
int xio_on_server_nexus_established(struct xio_session *session,
				    struct xio_nexus *nexus,
				    union xio_nexus_event_data *event_data)
{
	struct xio_connection *connection = xio_session_find_connection(session, nexus);
	connection->restarted = 1;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_server_on_nexus_event						     */
/*---------------------------------------------------------------------------*/
int xio_server_on_nexus_event(void *observer, void *sender, int event,
			      void *_event_data)
{
	struct xio_session	*session = (struct xio_session *)observer;
	struct xio_nexus	*nexus	= (struct xio_nexus *)sender;
	int			retval  = 0;
	union xio_nexus_event_data *event_data = (union xio_nexus_event_data *)
							_event_data;

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
		DEBUG_LOG("session: [notification] - connection established. " \
			 "session:%p, nexus:%p\n", observer, sender);
		xio_on_server_nexus_established(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_DISCONNECTED:
		DEBUG_LOG("session: [notification] - connection disconnected" \
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
		DEBUG_LOG("session: [notification] - connection closed. " \
			 "session:%p, nexus:%p\n", observer, sender);
		xio_on_nexus_closed(session, nexus, event_data);
		break;
	case XIO_NEXUS_EVENT_ERROR:
		DEBUG_LOG("session: [notification] - connection error. " \
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

	return retval;
}
