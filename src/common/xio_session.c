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
#include "xio_sessions_cache.h"
#include "xio_hash.h"
#include "xio_nexus.h"
#include "xio_session.h"
#include "xio_connection.h"
#include "xio_session_priv.h"

/*---------------------------------------------------------------------------*/
/* forward declarations							     */
/*---------------------------------------------------------------------------*/
static int xio_on_req_recv(struct xio_connection *connection,
				  struct xio_task *task);
static int xio_on_rsp_recv(struct xio_connection *nexusetion,
				  struct xio_task *task);
static int xio_on_ow_req_send_comp(struct xio_connection *connection,
				  struct xio_task *task);
static int xio_on_rsp_send_comp(struct xio_connection *connection,
				  struct xio_task *task);
/*---------------------------------------------------------------------------*/
/* xio_session_alloc_connection						     */
/*---------------------------------------------------------------------------*/
struct xio_connection *xio_session_alloc_connection(
		struct xio_session *session,
		struct xio_context *ctx,
		uint32_t connection_idx,
		void	*connection_user_context)
{
	struct xio_connection		*connection;

	/* allocate and initialize connection */
	connection = xio_connection_init(session, ctx,
					 connection_idx, connection_user_context);
	if (connection == NULL) {
		ERROR_LOG("failed to initialize connection. " \
			  "seesion:%p, ctx:%p, connection_idx:%d\n",
			  session, ctx, connection_idx);
		return NULL;
	}
	/* add the connection  to the session's connections list */
	spin_lock(&session->connections_list_lock);
	list_add_tail(&connection->connections_list_entry,
		      &session->connections_list);
	session->connections_nr++;
	spin_unlock(&session->connections_list_lock);

	return connection;
}

/*---------------------------------------------------------------------------*/
/* xio_session_free_connection						     */
/*---------------------------------------------------------------------------*/
int xio_session_free_connection(struct xio_connection *connection)
{
	int retval;

	spin_lock(&connection->session->connections_list_lock);
	connection->session->connections_nr--;
	list_del(&connection->connections_list_entry);
	spin_unlock(&connection->session->connections_list_lock);

	retval = xio_connection_close(connection);
	if (retval != 0) {
		ERROR_LOG("failed to close connection");
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_session_assign_nexus						     */
/*---------------------------------------------------------------------------*/
struct xio_connection *xio_session_assign_nexus(
		struct xio_session *session,
		struct xio_nexus *nexus)
{
	struct xio_connection		*connection;

	spin_lock(&session->connections_list_lock);
	/* find free slot */
	list_for_each_entry(connection, &session->connections_list,
			    connections_list_entry) {
		if ((connection->ctx == nexus->transport_hndl->ctx)  &&
		    ((connection->nexus == NULL) ||
		     (connection->nexus == nexus))) {
			/* remove old observer if exist */
			spin_unlock(&session->connections_list_lock);
			xio_connection_set_nexus(connection, nexus);
			return connection;
		}
	}
	spin_unlock(&session->connections_list_lock);

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_session_find_connection						     */
/*---------------------------------------------------------------------------*/
struct xio_connection *xio_session_find_connection(
		struct xio_session *session,
		struct xio_nexus *nexus)
{
	struct xio_connection		*connection;
	struct xio_context		*ctx = nexus->transport_hndl->ctx;

	list_for_each_entry(connection, &ctx->ctx_list, ctx_list_entry) {
		if (connection->nexus == nexus &&
		    connection->session == session)
			return connection;
	}

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_session_find_connection_by_ctx					     */
/*---------------------------------------------------------------------------*/
struct xio_connection *xio_session_find_connection_by_ctx(
		struct xio_session *session,
		struct xio_context *ctx)
{
	struct xio_connection		*connection;

	list_for_each_entry(connection, &ctx->ctx_list, ctx_list_entry) {
		if (connection->session == session)
			return connection;
	}
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_find_session							     */
/*---------------------------------------------------------------------------*/
struct xio_session *xio_find_session(struct xio_task *task)
{
	struct xio_session_hdr	*tmp_hdr;
	struct xio_observer	*observer;
	struct xio_session	*session;
	uint32_t		dest_session_id;

	xio_mbuf_push(&task->mbuf);

	/* set start of the session header */
	tmp_hdr = xio_mbuf_set_session_hdr(&task->mbuf);

	xio_mbuf_pop(&task->mbuf);

	dest_session_id = ntohl(tmp_hdr->dest_session_id);

	observer = xio_nexus_observer_lookup(task->nexus, dest_session_id);
	if (observer != NULL &&  observer->impl)
		return observer->impl;

	/* fall back to cache - this is should only happen when new connection
	 * message arrive to a portal on the server - just for the first
	 * message
	 */
	session = xio_sessions_cache_lookup(dest_session_id);
	if (session == NULL)
		ERROR_LOG("failed to find session\n");

	return session;
}

/*---------------------------------------------------------------------------*/
/* xio_session_write_header						     */
/*---------------------------------------------------------------------------*/
void xio_session_write_header(struct xio_task *task,
			     struct xio_session_hdr *hdr)
{
	struct xio_session_hdr *tmp_hdr;

	/* set start of the session header */
	tmp_hdr = xio_mbuf_set_session_hdr(&task->mbuf);

	/* fill header */
	PACK_LVAL(hdr, tmp_hdr,  dest_session_id);
	PACK_LLVAL(hdr, tmp_hdr, serial_num);
	PACK_LVAL(hdr, tmp_hdr, flags);
	PACK_LVAL(hdr, tmp_hdr, receipt_result);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_session_hdr));
}

/*---------------------------------------------------------------------------*/
/* xio_session_read_header						     */
/*---------------------------------------------------------------------------*/
void xio_session_read_header(struct xio_task *task,
			    struct xio_session_hdr *hdr)
{
	struct xio_session_hdr *tmp_hdr;

	/* set start of the session header */
	tmp_hdr = xio_mbuf_set_session_hdr(&task->mbuf);

	/* fill request */
	UNPACK_LLVAL(tmp_hdr, hdr, serial_num);
	UNPACK_LVAL(tmp_hdr, hdr, dest_session_id);
	UNPACK_LVAL(tmp_hdr, hdr, flags);
	UNPACK_LVAL(tmp_hdr, hdr, receipt_result);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_session_hdr));
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_teardown						     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_teardown(struct xio_session *session, int reason)
{
	struct xio_session_event_data  event = {
		.event = XIO_SESSION_TEARDOWN_EVENT,
		.reason = reason
	};
	if (session->ses_ops.on_session_event)
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_rejected						     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_rejected(struct xio_session *session)
{
	/* notify the upper layer */
	struct xio_session_event_data  ev_data = {
		.event =		XIO_SESSION_REJECT_EVENT,
		.reason =		session->reject_reason,
		.private_data =		session->new_ses_rsp.user_context,
		.private_data_len =	session->new_ses_rsp.user_context_len
	};

	if (session->ses_ops.on_session_event)
		session->ses_ops.on_session_event(
				session, &ev_data,
				session->cb_user_context);
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_new_connection					     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_new_connection(struct xio_session *session,
				       struct xio_connection *connection)
{
	struct xio_session_event_data  event = {
		.conn			= connection,
		.conn_user_context	= connection->cb_user_context,
		.event			= XIO_SESSION_NEW_CONNECTION_EVENT,
		.reason			= XIO_E_SUCCESS,
	};

	if (session->ses_ops.on_session_event)
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_established				     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_established(struct xio_session *session,
				       struct xio_connection *connection)
{
	struct xio_session_event_data  event = {
		.conn		   = connection,
		.conn_user_context = connection->cb_user_context,
		.event		   = XIO_SESSION_CONNECTION_ESTABLISHED_EVENT,
		.reason		   = XIO_E_SUCCESS,
	};

	if (session->ses_ops.on_session_event)
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
}


/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_closed					     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_closed(struct xio_session *session,
					  struct xio_connection *connection)
{
	struct xio_session_event_data  event = {
		.event = XIO_SESSION_CONNECTION_CLOSED_EVENT,
		.reason = connection->close_reason,
		.conn = connection,
		.conn_user_context = connection->cb_user_context
	};
	if (session->ses_ops.on_session_event)
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_disconnected				     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_disconnected(struct xio_session *session,
					  struct xio_connection *connection,
					  enum xio_status reason)
{
	struct xio_session_event_data  event = {
		.event = XIO_SESSION_CONNECTION_DISCONNECTED_EVENT,
		.reason = reason,
		.conn = connection,
		.conn_user_context = connection->cb_user_context
	};

	if (session->ses_ops.on_session_event)
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_refused				     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_refused(struct xio_session *session,
					  struct xio_connection *connection,
					  enum xio_status reason)
{
	struct xio_session_event_data  event = {
		.event = XIO_SESSION_CONNECTION_REFUSED_EVENT,
		.reason = reason,
		.conn = connection,
		.conn_user_context = connection->cb_user_context
	};

	if (session->ses_ops.on_session_event)
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_teardown				     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_teardown(struct xio_session *session,
					  struct xio_connection *connection)
{
	struct xio_session_event_data  event = {
		.event = XIO_SESSION_CONNECTION_TEARDOWN_EVENT,
		.reason = connection->close_reason,
		.conn = connection,
		.conn_user_context = connection->cb_user_context
	};

	if (session->ses_ops.on_session_event)
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_error					     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_error(struct xio_session *session,
					  struct xio_connection *connection,
					  enum xio_status reason)
{
	struct xio_session_event_data  event = {
		.event = XIO_SESSION_CONNECTION_ERROR_EVENT,
		.reason = reason,
		.conn = connection,
		.conn_user_context = connection->cb_user_context
	};

	if (session->ses_ops.on_session_event)
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
}
/*---------------------------------------------------------------------------*/
/* xio_session_pre_teardown						     */
/*---------------------------------------------------------------------------*/
static void xio_session_pre_teardown(struct xio_session *session)
{
	int i;

	/* unregister session from context */
	xio_sessions_cache_remove(session->session_id);
	for (i = 0; i < session->services_array_len; i++)
		kfree(session->services_array[i]);
	for (i = 0; i < session->portals_array_len; i++)
		kfree(session->portals_array[i]);
	kfree(session->services_array);
	kfree(session->portals_array);
	kfree(session->user_context);
	kfree(session->uri);
	session->state = XIO_SESSION_STATE_CLOSED;
}

/*---------------------------------------------------------------------------*/
/* xio_session_post_teardown						     */
/*---------------------------------------------------------------------------*/
void xio_session_post_teardown(struct xio_session *session)
{
	if (session->state == XIO_SESSION_STATE_CLOSED) {
		TRACE_LOG("session %p released\n", session);
		mutex_destroy(&session->lock);
		kfree(session);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_on_fin_req_send_comp				                     */
/*---------------------------------------------------------------------------*/
int xio_on_fin_req_send_comp(struct xio_connection *connection,
			struct xio_task *task)
{
	TRACE_LOG("got fin request send completion. session:%p, " \
		  "connection:%p\n",
		  connection->session, connection);

	return 0;
}

void xio_close_time_wait(void *data)
{
	struct xio_connection *connection = data;

	DEBUG_LOG("connection %p state change: current_state:%s, " \
		  "next_state:%s\n",
		  connection,
		  xio_connection_state_str(connection->state),
		  xio_connection_state_str(XIO_CONNECTION_STATE_CLOSED));

	connection->state = XIO_CONNECTION_STATE_CLOSED;

	/* flush all messages from in flight message queue to in queue */
	xio_connection_flush_msgs(connection);

	/* flush all messages back to user */
	xio_connection_notify_msgs_flush(connection);

	if (!connection->disable_notify)
		xio_session_notify_connection_teardown(connection->session,
						       connection);
	else
		xio_connection_destroy(connection);
}

void xio_handle_last_ack(void *data)
{
	struct xio_connection *connection = data;

	DEBUG_LOG("connection %p state change: current_state:%s, " \
		  "next_state:%s\n",
		  connection,
		  xio_connection_state_str(connection->state),
		  xio_connection_state_str(XIO_CONNECTION_STATE_CLOSED));

	connection->state = XIO_CONNECTION_STATE_CLOSED;

	xio_connection_destroy(connection);
}
/*---------------------------------------------------------------------------*/
/* xio_on_fin_rsp_recv				                             */
/*---------------------------------------------------------------------------*/
int xio_on_fin_rsp_recv(struct xio_connection *connection,
			struct xio_task *task)
{
	struct xio_transition	*transition;

	DEBUG_LOG("got fin response. session:%p, connection:%p\n",
		  connection->session, connection);

	/* cancel the timer */
	if (xio_is_delayed_work_pending(&connection->fin_timeout_work))
		xio_ctx_del_delayed_work(connection->ctx,
					&connection->fin_timeout_work);

	xio_connection_release_fin(connection, task->sender_task->omsg);

	/* recycle the task */
	xio_tasks_pool_put(task->sender_task);
	task->sender_task = NULL;
	xio_tasks_pool_put(task);

	transition = xio_connection_next_transit(connection->state, 1 /*ack*/);

	if (!transition->valid) {
		ERROR_LOG("invalid transition. session:%p, connection:%p, " \
			  "state:%d\n",
			  connection->session, connection, connection->state);
		return -1;
	}
	if (connection->state == XIO_CONNECTION_STATE_LAST_ACK) {
		xio_handle_last_ack(connection);
		return 0;
	}

	DEBUG_LOG("connection %p state change: current_state:%s, " \
		  "next_state:%s\n",
		  connection,
		  xio_connection_state_str(connection->state),
		  xio_connection_state_str(transition->next_state));

	connection->state = transition->next_state;

	if (connection->state == XIO_CONNECTION_STATE_TIME_WAIT) {
		int retval = xio_ctx_add_delayed_work(
				connection->ctx,
				2, connection,
				xio_close_time_wait,
				&connection->fin_delayed_work);
		if (retval != 0) {
			ERROR_LOG("xio_ctx_timer_add failed.\n");
			return retval;
		}
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_fin_req_recv				                             */
/*---------------------------------------------------------------------------*/
int xio_on_fin_req_recv(struct xio_connection *connection,
			struct xio_task *task)
{
	struct xio_transition	*transition;

	DEBUG_LOG("fin request received. session:%p, connection:%p\n",
		  connection->session, connection);

	transition = xio_connection_next_transit(connection->state, 0 /*fin*/);

	if (!transition->valid) {
		ERROR_LOG("invalid transition. session:%p, connection:%p\n",
			  connection->session, connection);
		return -1;
	}
	if (transition->send_flags & SEND_ACK)
		xio_send_fin_ack(connection, task);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_fin_rsp_send_comp						     */
/*---------------------------------------------------------------------------*/
int xio_on_fin_rsp_send_comp(struct xio_connection *connection,
			     struct xio_task *task)
{
	struct xio_transition	*transition;

	int			retval;

	DEBUG_LOG("fin response send completion received. "  \
		  "session:%p, connection:%p\n",
		  connection->session, connection);

	xio_connection_release_fin(connection, task->omsg);
	xio_tasks_pool_put(task);

	transition = xio_connection_next_transit(connection->state, 0 /*fin*/);

	DEBUG_LOG("connection %p state change: current_state:%s, " \
		  "next_state:%s\n",
		  connection,
		  xio_connection_state_str(connection->state),
		  xio_connection_state_str(transition->next_state));

	connection->state = transition->next_state;

	/* transition from online to close_wait - notify the application */
	if (connection->state == XIO_CONNECTION_STATE_CLOSE_WAIT) {
		if (!connection->disable_notify)
			xio_session_notify_connection_closed(
					connection->session,
					connection);

		/* flush all messages from in flight message
		 * queue to in queue */
		xio_connection_flush_msgs(connection);

		/* flush all messages back to user */
		xio_connection_notify_msgs_flush(connection);

		if (!connection->disable_notify)
			xio_session_notify_connection_teardown(
					connection->session,
					connection);
		else
			xio_connection_destroy(connection);
	}

	if (connection->state == XIO_CONNECTION_STATE_TIME_WAIT) {
		retval = xio_ctx_add_delayed_work(
				connection->ctx,
				2, connection,
				xio_close_time_wait,
				&connection->fin_delayed_work);
		if (retval != 0) {
			ERROR_LOG("xio_ctx_timer_add failed.\n");
			return retval;
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_req_recv				                             */
/*---------------------------------------------------------------------------*/
static int xio_on_req_recv(struct xio_connection *connection,
		struct xio_task *task)
{
	struct xio_session_hdr	hdr;
	struct xio_msg		*msg = &task->imsg;
	struct xio_statistics *stats = &connection->ctx->stats;
	struct xio_vmsg *vmsg = &msg->in;

	/* read session header */
	xio_session_read_header(task, &hdr);

	msg->sn		= hdr.serial_num;
	msg->flags	= hdr.flags;
	msg->next	= NULL;
	task->connection = connection;

	xio_connection_queue_io_task(connection, task);

	task->state = XIO_TASK_STATE_DELIVERED;

	/* add reference count to protect against release in callback */
	/* add ref to task avoiding race when user call release or send
	 * completion
	 */
	if (hdr.flags & XIO_MSG_FLAG_REQUEST_READ_RECEIPT)
		xio_task_addref(task);

	msg->timestamp = get_cycles();
	xio_stat_inc(stats, XIO_STAT_RX_MSG);
	xio_stat_add(stats, XIO_STAT_RX_BYTES,
		     vmsg->header.iov_len +
		     xio_iovex_length(vmsg->pdata_iov, vmsg->data_iovlen));

	xio_msg_cp_ptr2vec(&msg->in);
	xio_msg_cp_ptr2vec(&msg->out);

	/* notify the upper layer */
	if (connection->ses_ops.on_msg)
		connection->ses_ops.on_msg(
				connection->session, msg,
				msg->more_in_batch,
				connection->cb_user_context);

	if (hdr.flags & XIO_MSG_FLAG_REQUEST_READ_RECEIPT) {
		if (task->state == XIO_TASK_STATE_DELIVERED) {
			xio_connection_send_read_receipt(connection, msg);
		} else {
			/* free the ref added in this function */
			xio_tasks_pool_put(task);
		}
	}

	/* now try to send */
	xio_connection_xmit_msgs(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_rsp_recv				                             */
/*---------------------------------------------------------------------------*/
static int xio_on_rsp_recv(struct xio_connection *connection,
			   struct xio_task *task)
{
	struct xio_session_hdr	hdr;
	struct xio_msg		*msg = &task->imsg;
	struct xio_msg		*omsg;
	struct xio_task		*sender_task = task->sender_task;
	struct xio_statistics *stats = &connection->ctx->stats;

	if (connection->state != XIO_CONNECTION_STATE_ONLINE) {
		DEBUG_LOG("responses received while connection is offline\n");
		/* for various reasons, responses can arrive while connection
		 * is already offline
		 * just remove the message and release the response
		 */
		xio_connection_remove_in_flight(connection, sender_task->omsg);
		xio_release_response_task(task);
		goto xmit;
	}

	/* read session header */
	xio_session_read_header(task, &hdr);

	msg->sn = hdr.serial_num;

	omsg		= sender_task->omsg;
	omsg->next	= NULL;

	xio_stat_add(stats, XIO_STAT_DELAY,
		     get_cycles() - omsg->timestamp);
	xio_stat_inc(stats, XIO_STAT_RX_MSG);

	task->connection = connection;

	/* remove only if not response with "read receipt" */
	if (!((hdr.flags &
	    (XIO_MSG_RSP_FLAG_FIRST | XIO_MSG_RSP_FLAG_LAST)) ==
	     XIO_MSG_RSP_FLAG_FIRST)) {
		xio_connection_remove_in_flight(connection, omsg);
	} else {
		if (task->tlv_type == XIO_ONE_WAY_RSP) {
			if (hdr.flags & XIO_MSG_RSP_FLAG_FIRST)
				xio_connection_remove_in_flight(connection, omsg);
			connection->in_flight_sends_budget++;
		} else {
			connection->in_flight_reqs_budget++;
		}
	}

	omsg->type = task->tlv_type;

	/* cache the task in io queue */
	xio_connection_queue_io_task(connection, task);

	/* remove the message from in flight queue */

	if (task->tlv_type == XIO_ONE_WAY_RSP) {
		/* one way message with "read receipt" */
		if (!(hdr.flags & XIO_MSG_RSP_FLAG_FIRST))
			ERROR_LOG("protocol requires first flag to be set. " \
				  "flags:0x%x\n", hdr.flags);

		omsg->sn	  = msg->sn; /* one way do have response */
		omsg->receipt_res = hdr.receipt_result;
		if (connection->ses_ops.on_msg_delivered)
			connection->ses_ops.on_msg_delivered(
				    connection->session,
				    omsg,
				    task->imsg.more_in_batch,
				    connection->cb_user_context);
		sender_task->omsg = NULL;
		xio_release_response_task(task);
	} else {
		if (hdr.flags & XIO_MSG_RSP_FLAG_FIRST) {
			if (connection->ses_ops.on_msg_delivered) {
				omsg->receipt_res = hdr.receipt_result;
				omsg->sn	  = hdr.serial_num;
				connection->ses_ops.on_msg_delivered(
						connection->session,
						omsg,
						task->imsg.more_in_batch,
						connection->cb_user_context);
			}
			/* standalone receipt */
			if ((hdr.flags &
			    (XIO_MSG_RSP_FLAG_FIRST | XIO_MSG_RSP_FLAG_LAST)) ==
					XIO_MSG_RSP_FLAG_FIRST) {

				/* after receipt delivered reproduce the
				 * original "in" side  */
				memcpy(&omsg->in, &sender_task->in_receipt,
				       sizeof(omsg->in));

				/* recycle the receipt */
				xio_tasks_pool_put(task);
			}
		}
		if (hdr.flags & XIO_MSG_RSP_FLAG_LAST) {
			struct xio_vmsg *vmsg = &msg->in;
			xio_stat_add(stats, XIO_STAT_RX_BYTES,
				     vmsg->header.iov_len +
				     xio_iovex_length(vmsg->pdata_iov,
						      vmsg->data_iovlen));
			xio_msg_cp_ptr2vec(&msg->in);
			xio_msg_cp_ptr2vec(&msg->out);

			omsg->request	= msg;
			if (connection->ses_ops.on_msg)
				connection->ses_ops.on_msg(
					connection->session,
					omsg,
					task->imsg.more_in_batch,
					connection->cb_user_context);
		}
	}

xmit:
	/* now try to send */
	xio_connection_xmit_msgs(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_rsp_send_comp				                             */
/*---------------------------------------------------------------------------*/
static int xio_on_rsp_send_comp(
		struct xio_connection *connection,
		struct xio_task *task)
{

	if (connection->is_flushed) {
		xio_tasks_pool_put(task);
		goto xmit;
	}

	/* remove the message from in flight queue */
	xio_connection_remove_in_flight(connection, task->omsg);

	/*
	 * completion of receipt
	 */
	if ((task->omsg_flags &
	    (XIO_MSG_RSP_FLAG_FIRST | XIO_MSG_RSP_FLAG_LAST)) ==
	     XIO_MSG_RSP_FLAG_FIRST) {
		xio_connection_release_read_receipt(connection, task->omsg);
		xio_release_response_task(task);
	} else {
		/* send completion notification only to responder to
		 * release responses
		 */
		if (connection->ses_ops.on_msg_send_complete) {
			connection->ses_ops.on_msg_send_complete(
					connection->session, task->omsg,
					connection->cb_user_context);
		}
		/* recycle the task */
		xio_tasks_pool_put(task);
	}

xmit:
	/* now try to send */
	xio_connection_xmit_msgs(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_ow_req_send_comp				                     */
/*---------------------------------------------------------------------------*/
static int xio_on_ow_req_send_comp(
		struct xio_connection *connection,
		struct xio_task *task)
{
	if (connection->is_flushed) {
		xio_tasks_pool_put(task);
		goto xmit;
	}

	/* recycle the task */
	if (!(task->omsg_flags & XIO_MSG_FLAG_REQUEST_READ_RECEIPT)) {
		struct xio_statistics *stats = &connection->ctx->stats;
		struct xio_msg *omsg = task->omsg;
		xio_stat_add(stats, XIO_STAT_DELAY,
			     get_cycles() - omsg->timestamp);

		xio_connection_remove_in_flight(connection, task->omsg);

		/* send completion notification to
		 * release request
		 */
		if (connection->ses_ops.on_ow_msg_send_complete) {
			connection->ses_ops.on_ow_msg_send_complete(
					connection->session, task->omsg,
					connection->cb_user_context);
		}
		xio_tasks_pool_put(task);
	}

xmit:
	/* now try to send */
	xio_connection_xmit_msgs(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_nexus_disconnected			                             */
/*---------------------------------------------------------------------------*/
int xio_on_nexus_disconnected(struct xio_session *session,
			     struct xio_nexus *nexus,
			     union xio_nexus_event_data *event_data)
{
	struct xio_connection *connection;

	if (session->lead_connection &&
	    session->lead_connection->nexus == nexus) {
		connection = session->lead_connection;
		connection->close_reason = XIO_E_SESSION_DISCONECTED;
	} else if (session->redir_connection &&
		   session->redir_connection->nexus == nexus) {
		connection = session->redir_connection;
		connection->close_reason = XIO_E_SESSION_DISCONECTED;
	} else {
		spin_lock(&session->connections_list_lock);
		connection = xio_session_find_connection(session, nexus);
		spin_unlock(&session->connections_list_lock);
		connection->close_reason = XIO_E_SESSION_DISCONECTED;
		xio_connection_disconnected(connection);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_nexus_reconnected			                             */
/*---------------------------------------------------------------------------*/
int xio_on_nexus_reconnected(struct xio_session *session,
			    struct xio_nexus *nexus)
{
	struct xio_connection		*connection;

	if (session->lead_connection && session->lead_connection->nexus == nexus)
		connection = session->lead_connection;
	else
		connection = xio_session_find_connection(session, nexus);

	if (connection)
		xio_connection_restart(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_nexus_closed							     */
/*---------------------------------------------------------------------------*/
int xio_on_nexus_closed(struct xio_session *session,
		       struct xio_nexus *nexus,
		       union xio_nexus_event_data *event_data)
{
	TRACE_LOG("session:%p - nexus:%p close complete\n", session, nexus);

	/* no more notifications */
	xio_nexus_unreg_observer(nexus, &session->observer);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_nexus_message_error						     */
/*---------------------------------------------------------------------------*/
int xio_on_nexus_message_error(struct xio_session *session,
			      struct xio_nexus *nexus,
			      union xio_nexus_event_data *event_data)
{
	struct xio_task *task = event_data->msg_error.task;

	xio_connection_remove_msg_from_queue(task->connection, task->omsg);

	if (task->session->ses_ops.on_msg_error)
		task->session->ses_ops.on_msg_error(
				task->session,
				event_data->msg_error.reason,
				task->omsg,
				task->connection->cb_user_context);

	if (IS_REQUEST(task->tlv_type))
		xio_tasks_pool_put(task);
	else
		xio_connection_queue_io_task(task->connection, task);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_nexus_error							     */
/*---------------------------------------------------------------------------*/
int xio_on_nexus_error(struct xio_session *session,
		      struct xio_nexus *nexus,
		      union xio_nexus_event_data *event_data)
{
	struct xio_connection *connection =
				xio_session_find_connection(session, nexus);

	/* disable the teardown */
	session->disable_teardown = 0;
	session->lead_connection  = NULL;
	session->redir_connection = NULL;

	switch (session->state) {
	case XIO_SESSION_STATE_CONNECT:
	case XIO_SESSION_STATE_REDIRECTED:
		session->state = XIO_SESSION_STATE_REFUSED;
		while (!list_empty(&session->connections_list)) {
			connection = list_first_entry(
					&session->connections_list,
					struct xio_connection,
					connections_list_entry);
			xio_connection_error_event(connection,
						   event_data->error.reason);
		}
		break;
	default:
		xio_connection_error_event(connection,
					   event_data->error.reason);
		break;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_new_message							     */
/*---------------------------------------------------------------------------*/
int xio_on_new_message(struct xio_session *session,
		       struct xio_nexus *nexus,
		       union xio_nexus_event_data *event_data)
{
	struct xio_task		*task  = event_data->msg.task;
	struct xio_connection	*connection = NULL;
	int			retval = -1;
	int			tlv_type;



	if (task->sender_task) {
		session = task->sender_task->session;
		connection = task->sender_task->connection;
	}

	if (session == NULL) {
		session = xio_find_session(task);
		if (session == NULL) {
			ERROR_LOG("failed to find session\n");
			xio_tasks_pool_put(task);
			return -1;
		}
	}

	if (connection == NULL) {
		connection = xio_session_find_connection(session, nexus);
		if (connection == NULL) {
			/* leading connection is refused */
			if (session->lead_connection &&
			    session->lead_connection->nexus == nexus) {
				connection = session->lead_connection;
			} else if (session->redir_connection &&
				   session->redir_connection->nexus == nexus) {
				/* redirected connection is refused */
				connection = session->redir_connection;
			} else {
				ERROR_LOG("failed to find connection\n");
				xio_tasks_pool_put(task);
				return -1;
			}
		}
	}

	tlv_type		= task->tlv_type;
	task->session		= session;
	task->connection	= connection;

	switch (tlv_type) {
	case XIO_MSG_REQ:
	case XIO_ONE_WAY_REQ:
		retval = xio_on_req_recv(connection, task);
		break;
	case XIO_MSG_RSP:
	case XIO_ONE_WAY_RSP:
		retval = xio_on_rsp_recv(connection, task);
		break;
	case XIO_FIN_REQ:
		retval = xio_on_fin_req_recv(connection, task);
		break;
	case XIO_FIN_RSP:
		retval = xio_on_fin_rsp_recv(connection, task);
		break;
	case XIO_SESSION_SETUP_REQ:
		retval = xio_on_setup_req_recv(connection, task);
		break;
	case XIO_SESSION_SETUP_RSP:
		retval = xio_on_setup_rsp_recv(connection, task);
		break;
	case XIO_CONNECTION_HELLO_REQ:
		retval = xio_on_connection_hello_req_recv(connection, task);
		break;
	case XIO_CONNECTION_HELLO_RSP:
		retval = xio_on_connection_hello_rsp_recv(connection, task);
		break;
	default:
		retval = -1;
		break;
	}

	if (retval != 0)
		ERROR_LOG("receiving new message failed. type:0x%x\n",
			  tlv_type);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_send_completion						     */
/*---------------------------------------------------------------------------*/
int xio_on_send_completion(struct xio_session *session,
			   struct xio_nexus *nexus,
			   union xio_nexus_event_data *event_data)
{
	struct xio_task	*task  = event_data->msg.task;
	struct xio_connection	*connection;
	int			retval = -1;

	connection = task->connection;

	switch (task->tlv_type) {
	case XIO_MSG_REQ:
	case XIO_SESSION_SETUP_REQ:
		retval = 0;
		break;
	case XIO_MSG_RSP:
	case XIO_ONE_WAY_RSP:
		retval = xio_on_rsp_send_comp(connection, task);
		break;
	case XIO_ONE_WAY_REQ:
		retval = xio_on_ow_req_send_comp(connection, task);
		break;
	case XIO_FIN_REQ:
		retval = xio_on_fin_req_send_comp(connection, task);
		break;
	case XIO_FIN_RSP:
		retval = xio_on_fin_rsp_send_comp(connection, task);
		break;
	case XIO_SESSION_SETUP_RSP:
		retval = xio_on_setup_rsp_send_comp(connection, task);
		break;
	case XIO_CONNECTION_HELLO_REQ:
		retval = 0;
		break;
	case XIO_CONNECTION_HELLO_RSP:
		retval = xio_on_connection_hello_rsp_send_comp(connection,
							       task);
		break;
	default:
		break;
	}

	if (retval != 0)
		ERROR_LOG("message send completion failed. type:0x%x\n",
			  task->tlv_type);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_assign_in_buf							     */
/*---------------------------------------------------------------------------*/
int xio_on_assign_in_buf(struct xio_session *session,
			 struct xio_nexus *nexus,
			 union xio_nexus_event_data *event_data)
{
	struct xio_task	*task  = event_data->assign_in_buf.task;
	struct xio_connection	*connection;

	if (session == NULL)
		session = xio_find_session(task);

	connection = xio_session_find_connection(session, nexus);
	if (connection == NULL) {
		connection = xio_session_assign_nexus(session, nexus);
		if (connection == NULL) {
			ERROR_LOG("failed to find connection :%p. " \
				  "dropping message:%d\n", nexus,
				  event_data->msg.op);
			return -1;
		}
	}

	if (connection->ses_ops.assign_data_in_buf) {
		xio_msg_cp_ptr2vec(&task->imsg.in);
		connection->ses_ops.assign_data_in_buf(&task->imsg,
					connection->cb_user_context);
		event_data->assign_in_buf.is_assigned = 1;
		/* copy the task message to pointer */
		xio_msg_cp_vec2ptr(&task->imsg.in);
		return 0;
	}
	event_data->assign_in_buf.is_assigned = 0;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_cancel_request						     */
/*---------------------------------------------------------------------------*/
int xio_on_cancel_request(struct xio_session *sess,
			  struct xio_nexus *nexus,
			  union xio_nexus_event_data *event_data)
{
	struct xio_session_cancel_hdr	hdr;
	struct xio_msg			*req = NULL;
	struct xio_session_cancel_hdr	*tmp_hdr;
	struct xio_session		*session;
	struct xio_connection		*connection;
	struct xio_task			*task;
	struct xio_observer		*observer;


	tmp_hdr			 = event_data->cancel.ulp_msg;
	hdr.sn			 = ntohll(tmp_hdr->sn);
	hdr.responder_session_id = ntohl(tmp_hdr->responder_session_id);

	observer = xio_nexus_observer_lookup(nexus, hdr.responder_session_id);
	if (observer == NULL) {
		ERROR_LOG("failed to find session\n");
		return -1;
	}

	session = observer->impl;

	connection = xio_session_find_connection(session, nexus);
	if (connection == NULL) {
		ERROR_LOG("failed to find session\n");
		return -1;
	}

	/* lookup for task in io list */
	task = xio_connection_find_io_task(connection, hdr.sn);
	if (task) {
		if (connection->ses_ops.on_cancel_request) {
			connection->ses_ops.on_cancel_request(
				connection->session,
				&task->imsg,
				connection->cb_user_context);
			return 0;
		} else {
			WARN_LOG("cancel is not supported on responder\n");
		}
	}
	TRACE_LOG("message to cancel not found %llu\n", hdr.sn);

	req = kcalloc(1, sizeof(*req), GFP_KERNEL);
	if (req == NULL) {
		ERROR_LOG("req allocation failed\n");
		return -1;
	}

	req->sn	= hdr.sn;
	xio_connection_send_cancel_response(connection, req, NULL,
					    XIO_E_MSG_NOT_FOUND);
	kfree(req);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_cancel_response						     */
/*---------------------------------------------------------------------------*/
int xio_on_cancel_response(struct xio_session *sess,
			   struct xio_nexus *nexus,
			   union xio_nexus_event_data *event_data)
{
	struct xio_session_cancel_hdr	hdr;
	struct xio_session_cancel_hdr	*tmp_hdr;
	struct xio_observer		*observer;
	struct xio_session		*session;
	struct xio_connection		*connection;
	struct xio_msg			*msg = NULL;
	struct xio_msg			*pmsg;

	if (!event_data) {
		xio_set_error(EINVAL);
		ERROR_LOG("null event_data\n");
		return -1;
	}

	if (event_data->cancel.task == NULL) {
		tmp_hdr			 = event_data->cancel.ulp_msg;
		hdr.sn			 = ntohll(tmp_hdr->sn);
		hdr.requester_session_id = ntohl(tmp_hdr->requester_session_id);

		observer = xio_nexus_observer_lookup(nexus,
						    hdr.requester_session_id);
		if (observer == NULL) {
			ERROR_LOG("failed to find session\n");
			return -1;
		}
		session = observer->impl;

		/* large object - allocate it */
		msg		= kcalloc(1, sizeof(*msg), GFP_KERNEL);
		if (msg == NULL) {
			ERROR_LOG("msg allocation failed\n");
			return -1;
		}

		pmsg		= msg;		/* fake a message */
		msg->sn		= hdr.sn;
		msg->status	= 0;
	} else {
		session		= event_data->cancel.task->session;
		pmsg		= event_data->cancel.task->omsg;
		hdr.sn		= pmsg->sn;
	}

	connection = xio_session_find_connection(session, nexus);
	if (connection == NULL) {
		ERROR_LOG("failed to find session\n");
		if (msg)
			kfree(msg);
		return -1;
	}

	/* need to release the last reference since answer is not expected */
	if (event_data->cancel.result == XIO_E_MSG_CANCELED &&
	    event_data->cancel.task)
		xio_tasks_pool_put(event_data->cancel.task);

	if (connection->ses_ops.on_cancel)
		connection->ses_ops.on_cancel(
				session,
				pmsg,
				event_data->cancel.result,
				connection->cb_user_context);
	else
		ERROR_LOG("cancel is not supported\n");

	if (msg)
		kfree(msg);

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_session_init			                                     */
/*---------------------------------------------------------------------------*/
struct xio_session *xio_session_init(
		enum xio_session_type type,
		struct xio_session_attr *attr,
		const char *uri,
		uint32_t initial_sn,
		uint32_t flags,
		void *cb_user_context)
{
	struct xio_session	*session = NULL;
	int			retval;
	int			uri_len = strlen(uri);


	/* extract portal from uri */
	/* create the session */
	session = kcalloc(1, sizeof(struct xio_session), GFP_KERNEL);
	if (session == NULL) {
		ERROR_LOG("failed to create session\n");
		xio_set_error(ENOMEM);
		return NULL;
	}

	XIO_OBSERVER_INIT(&session->observer, session,
			  (type == XIO_SESSION_SERVER) ?
					xio_server_on_nexus_event :
					xio_client_on_nexus_event);

	INIT_LIST_HEAD(&session->connections_list);

	session->user_context_len = attr->user_context_len;

	/* copy private data if exist */
	if (session->user_context_len) {
		session->user_context = kmalloc(attr->user_context_len,
						GFP_KERNEL);
		if (session->user_context == NULL) {
			xio_set_error(ENOMEM);
			goto cleanup;
		}
		memcpy(session->user_context, attr->user_context,
		       session->user_context_len);
	}
	mutex_init(&session->lock);
	spin_lock_init(&session->connections_list_lock);

	/* fill session data*/
	session->type			= type;
	session->cb_user_context	= cb_user_context;

	session->trans_sn		= initial_sn;
	session->state			= XIO_SESSION_STATE_INIT;
	session->session_flags		= flags;

	memcpy(&session->ses_ops, attr->ses_ops,
	       sizeof(*attr->ses_ops));


	session->uri_len = uri_len;
	session->uri = kstrdup(uri, GFP_KERNEL);
	if (session->uri == NULL) {
		xio_set_error(ENOMEM);
		goto cleanup2;
	}

	/* add the session to storage */
	retval = xio_sessions_cache_add(session, &session->session_id);
	if (retval != 0) {
		ERROR_LOG("adding session to sessions cache failed :%p\n",
			  session);
		goto cleanup3;
	}
	return session;

cleanup3:
	kfree(session->uri);
cleanup2:
	kfree(session->user_context);
cleanup:
	kfree(session);

	return NULL;
}


/*---------------------------------------------------------------------------*/
/* xio_session_destroy							     */
/*---------------------------------------------------------------------------*/
int xio_session_destroy(struct xio_session *session)
{
	if (session == NULL)
		return 0;

	TRACE_LOG("session destroy:%p\n", session);
	session->state = XIO_SESSION_STATE_CLOSING;
	if (list_empty(&session->connections_list)) {
		xio_session_pre_teardown(session);
		if (!session->in_notify)
			xio_session_post_teardown(session);
	} else {
		xio_set_error(EBUSY);
		ERROR_LOG("xio_session_close failed: " \
			  "connections are still open\n");
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_session_create			                                     */
/*---------------------------------------------------------------------------*/
struct xio_session *xio_session_create(
		enum xio_session_type type,
		struct xio_session_attr *attr,
		const char *uri,
		uint32_t initial_sn,
		uint32_t flags,
		void *cb_user_context)
{
	struct xio_session	*session = NULL;

	/* input validation */
	if (attr == NULL || uri == NULL) {
		xio_set_error(EINVAL);
		ERROR_LOG("xio_session_open: invalid parameter\n");
		return NULL;
	}

	session = xio_session_init(type, attr, uri,
				     initial_sn, flags, cb_user_context);

	if (session == NULL) {
		ERROR_LOG("failed to open session\n");
		return NULL;
	}
	return session;
}

/*---------------------------------------------------------------------------*/
/* xio_session_assign_ops						     */
/*---------------------------------------------------------------------------*/
void xio_session_assign_ops(struct xio_session *session,
		struct xio_session_ops *ops)
{
	memcpy(&session->ses_ops, ops, sizeof(*ops));
}

/*---------------------------------------------------------------------------*/
/* xio_session_event_str						     */
/*---------------------------------------------------------------------------*/
const char *xio_session_event_str(enum xio_session_event event)
{
	switch (event) {
	case XIO_SESSION_REJECT_EVENT:
		return "session reject";
	case XIO_SESSION_TEARDOWN_EVENT:
		return "session teardown";
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		return "new connection";
	case XIO_SESSION_CONNECTION_ESTABLISHED_EVENT:
		return "connection established";
	case XIO_SESSION_CONNECTION_CLOSED_EVENT:
		return "connection closed";
	case XIO_SESSION_CONNECTION_DISCONNECTED_EVENT:
		return "connection disconnected";
	case XIO_SESSION_CONNECTION_REFUSED_EVENT:
		return "connection refused";
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		return "connection teardown";
	case XIO_SESSION_CONNECTION_ERROR_EVENT:
		return "connection error";
	case XIO_SESSION_ERROR_EVENT:
		return "session error";
	};
	return "unknown session event";
}

/*---------------------------------------------------------------------------*/
/* xio_query_session							     */
/*---------------------------------------------------------------------------*/
int xio_query_session(struct xio_session *session,
		      struct xio_session_attr *attr,
		      int attr_mask)
{
	if (!session || !attr) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid parameters\n");
		return -1;
	}
	if (attr_mask & XIO_SESSION_ATTR_USER_CTX)
		attr->user_context = session->user_context;

	if (attr_mask & XIO_SESSION_ATTR_SES_OPS)
		attr->ses_ops = &session->ses_ops;

	if (attr_mask & XIO_SESSION_ATTR_URI)
		attr->uri = session->uri;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_modify_session							     */
/*---------------------------------------------------------------------------*/
int xio_modify_session(struct xio_session *session,
		       struct xio_session_attr *attr,
		       int attr_mask)
{
	if (!session || !attr) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid parameters\n");
		return -1;
	}

	if (attr_mask & XIO_SESSION_ATTR_USER_CTX)
		session->user_context = attr->user_context;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_get_connection							     */
/*---------------------------------------------------------------------------*/
struct xio_connection *xio_get_connection(
		struct xio_session *session,
		struct xio_context *ctx)
{
	ERROR_LOG("%s function have been deprecated. "			\
		  "That means it have been replaced by new function or" \
		  "is no longer supported, and may be removed"		\
		  "from future versions. "				\
		  "All code that uses the functions should"		\
		  "be converted to use its replacement if one exists.\n",
		  __func__);
	return  xio_session_find_connection_by_ctx(session, ctx);
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_cancel						     */
/*---------------------------------------------------------------------------*/
int xio_session_notify_cancel(struct xio_connection *connection,
			      struct xio_msg *req, enum xio_status result)
{
	/* notify the upper layer */
	if (connection->ses_ops.on_cancel)
		connection->ses_ops.on_cancel(
				connection->session, req,
				result,
				connection->cb_user_context);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_msg_error						     */
/*---------------------------------------------------------------------------*/
int xio_session_notify_msg_error(struct xio_connection *connection,
				 struct xio_msg *msg, enum xio_status result)
{
	/* notify the upper layer */
	if (connection->ses_ops.on_msg_error)
		connection->ses_ops.on_msg_error(
				connection->session,
				result, msg,
				connection->cb_user_context);

	return 0;
}

