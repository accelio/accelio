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
#include "xio_hash.h"
#include "xio_sg_table.h"
#include "xio_idr.h"
#include "xio_msg_list.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"
#include "xio_nexus.h"
#include "xio_connection.h"
#include "xio_sessions_cache.h"
#include "xio_session.h"
#include "xio_session_priv.h"
#include <xio_env_adv.h>

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
	connection = xio_connection_create(session, ctx, connection_idx,
					   connection_user_context);
	if (!connection) {
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
		    (!connection->nexus ||
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

	spin_lock(&session->connections_list_lock);
	list_for_each_entry(connection, &session->connections_list,
				connections_list_entry) {
		if (connection->ctx == ctx) {
			spin_unlock(&session->connections_list_lock);
			return connection;
		}
	}
	spin_unlock(&session->connections_list_lock);

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
	tmp_hdr = (struct xio_session_hdr *)
			xio_mbuf_set_session_hdr(&task->mbuf);

	xio_mbuf_pop(&task->mbuf);

	dest_session_id = ntohl(tmp_hdr->dest_session_id);

	observer = xio_nexus_observer_lookup(task->nexus, dest_session_id);
	if (observer &&  observer->impl)
		return (struct xio_session *)observer->impl;

	/* fall back to cache - this is should only happen when new connection
	 * message arrive to a portal on the server - just for the first
	 * message
	 */
	session = xio_sessions_cache_lookup(dest_session_id);
	if (!session)
		ERROR_LOG("failed to find session %d\n", dest_session_id);

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
	tmp_hdr =
	     (struct xio_session_hdr *)xio_mbuf_set_session_hdr(&task->mbuf);

	/* fill header */
	PACK_LVAL(hdr, tmp_hdr,  dest_session_id);
	PACK_LVAL(hdr, tmp_hdr, flags);
	PACK_LLVAL(hdr, tmp_hdr, serial_num);
	PACK_SVAL(hdr, tmp_hdr, sn);
	PACK_SVAL(hdr, tmp_hdr, ack_sn);
	PACK_SVAL(hdr, tmp_hdr, credits_msgs);
	PACK_LVAL(hdr, tmp_hdr, receipt_result);
	PACK_LLVAL(hdr, tmp_hdr, credits_bytes);
#ifdef XIO_SESSION_DEBUG
	PACK_LLVAL(hdr, tmp_hdr, connection);
	PACK_LLVAL(hdr, tmp_hdr, session);
#endif

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
	tmp_hdr = (struct xio_session_hdr *)
			xio_mbuf_set_session_hdr(&task->mbuf);

	/* fill request */
	UNPACK_LVAL(tmp_hdr, hdr, dest_session_id);
	UNPACK_LVAL(tmp_hdr, hdr, flags);
	UNPACK_LLVAL(tmp_hdr, hdr, serial_num);
	UNPACK_SVAL(tmp_hdr, hdr, sn);
	UNPACK_SVAL(tmp_hdr, hdr, ack_sn);
	UNPACK_SVAL(tmp_hdr, hdr, credits_msgs);
	UNPACK_LVAL(tmp_hdr, hdr, receipt_result);
	UNPACK_LLVAL(tmp_hdr, hdr, credits_bytes);
#ifdef XIO_SESSION_DEBUG
	UNPACK_LLVAL(tmp_hdr, hdr, connection);
	UNPACK_LLVAL(tmp_hdr, hdr, session);
#endif

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_session_hdr));
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_teardown						     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_teardown(struct xio_session *session, int reason)
{
	struct xio_session_event_data  event = {
		.conn = NULL,
		.conn_user_context = NULL,
		.event = XIO_SESSION_TEARDOWN_EVENT,
		.reason = (enum xio_status)reason,
		.private_data = NULL,
		.private_data_len = 0,
	};

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(session->teardown_work_ctx);
#endif
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(session->teardown_work_ctx);
#endif
	}
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_new_connection					     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_new_connection(struct xio_session *session,
				       struct xio_connection *connection)
{
	struct xio_session_event_data  event = {
		.conn = connection,
		.conn_user_context = connection->cb_user_context,
		.event = XIO_SESSION_NEW_CONNECTION_EVENT,
		.reason = XIO_E_SUCCESS,
		.private_data = NULL,
		.private_data_len = 0,
	};

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_established				     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_established(
		struct xio_session *session,
		struct xio_connection *connection)
{
	struct xio_session_event_data  event = {
		.conn = connection,
		.conn_user_context = connection->cb_user_context,
		.event = XIO_SESSION_CONNECTION_ESTABLISHED_EVENT,
		.reason = XIO_E_SUCCESS,
		.private_data = NULL,
		.private_data_len = 0,
	};

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		xio_ctx_del_delayed_work(connection->ctx,
					 &connection->connect_work);
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_closed					     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_closed(struct xio_session *session,
					  struct xio_connection *connection)
{
	struct xio_session_event_data  event = {
		.conn = connection,
		.conn_user_context = connection->cb_user_context,
		.event = XIO_SESSION_CONNECTION_CLOSED_EVENT,
		.reason = (enum xio_status)connection->close_reason,
		.private_data = NULL,
		.private_data_len = 0,
	};

	if (connection->cd_bit)
		return;

	connection->cd_bit = 1;

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
                xio_ctx_del_delayed_work(connection->ctx,
				         &connection->connect_work);
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_disconnected				     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_disconnected(
		struct xio_session *session,
		struct xio_connection *connection,
		enum xio_status reason)
{
	struct xio_session_event_data  event = {
		.conn = connection,
		.conn_user_context = connection->cb_user_context,
		.event = XIO_SESSION_CONNECTION_DISCONNECTED_EVENT,
		.private_data = NULL,
		.private_data_len = 0,
		.reason = reason,
	};

	if (connection->cd_bit)
		return;

	connection->cd_bit = 1;

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		xio_ctx_del_delayed_work(connection->ctx,
					 &connection->connect_work);

		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_refused				     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_refused(struct xio_session *session,
					   struct xio_connection *connection,
					   enum xio_status reason)
{
	struct xio_session_event_data  event = {
		.conn = connection,
		.conn_user_context = connection->cb_user_context,
		.event = XIO_SESSION_CONNECTION_REFUSED_EVENT,
		.reason = reason,
		.private_data = NULL,
		.private_data_len = 0,
	};

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
                xio_ctx_del_delayed_work(connection->ctx,
                                         &connection->connect_work);

		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_teardown				     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_teardown(struct xio_session *session,
					    struct xio_connection *connection)
{
	struct xio_session_event_data  event = {
		.conn = connection,
		.conn_user_context = connection->cb_user_context,
		.event = XIO_SESSION_CONNECTION_TEARDOWN_EVENT,
		.reason = (enum xio_status)connection->close_reason,
		.private_data = NULL,
		.private_data_len = 0,
	};

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_connection_error					     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_connection_error(struct xio_session *session,
					 struct xio_connection *connection,
					 enum xio_status reason)
{
	struct xio_session_event_data  event = {
		.conn = connection,
		.conn_user_context = connection->cb_user_context,
		.event = XIO_SESSION_CONNECTION_ERROR_EVENT,
		.reason = reason,
		.private_data = NULL,
		.private_data_len = 0,
	};

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
                xio_ctx_del_delayed_work(connection->ctx,
                                         &connection->connect_work);

		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_reconnecting										     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_reconnecting(struct xio_session *session,
		  struct xio_connection *connection)
{
	struct xio_session_event_data  event = {
		.conn = connection,
		.conn_user_context = connection->cb_user_context,
		.event = XIO_SESSION_CONNECTION_RECONNECTING_EVENT,
		.reason = (enum xio_status)connection->close_reason,
		.private_data = NULL,
		.private_data_len = 0,
	};

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_reconnected										     */
/*---------------------------------------------------------------------------*/
void xio_session_notify_reconnected(struct xio_session *session,
		  struct xio_connection *connection)
{
	struct xio_session_event_data  event = {
		.conn = connection,
		.conn_user_context = connection->cb_user_context,
		.event = XIO_SESSION_CONNECTION_RECONNECTED_EVENT,
		.reason = XIO_E_SUCCESS,
		.private_data = NULL,
		.private_data_len = 0,
	};

	if (session->ses_ops.on_session_event) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		session->ses_ops.on_session_event(
				session, &event,
				session->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
}

/*---------------------------------------------------------------------------*/
/* xio_on_req_recv				                             */
/*---------------------------------------------------------------------------*/
static int xio_on_req_recv(struct xio_connection *connection,
			   struct xio_task *task)
{
	struct xio_session_hdr	hdr;
	struct xio_msg		*msg = &task->imsg;
#ifdef XIO_CFLAG_STAT_COUNTERS
	struct xio_statistics *stats = &connection->ctx->stats;
	struct xio_vmsg *vmsg = &msg->in;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;

	sgtbl		= xio_sg_table_get(&msg->in);
	sgtbl_ops	= (struct xio_sg_table_ops *)
				xio_sg_table_ops_get(msg->in.sgl_type);
#endif

	/* read session header */
	xio_session_read_header(task, &hdr);

	if (connection->req_exp_sn == hdr.sn) {
		connection->req_exp_sn++;
		connection->req_ack_sn = hdr.sn;
		if (connection->enable_flow_control) {
			connection->peer_credits_msgs += hdr.credits_msgs;
			connection->peer_credits_bytes += hdr.credits_bytes;
		}
		connection->restarted = 0;
	} else {
		if (unlikely(connection->restarted)) {
			connection->req_exp_sn = hdr.sn + 1;
			connection->restarted = 0;
		} else {
			ERROR_LOG("ERROR: sn expected:%d, sn arrived:%d\n",
				  connection->req_exp_sn, hdr.sn);
		}
	}
	/*
	DEBUG_LOG("[%s] sn:%d, exp:%d, ack:%d, credits:%d, peer_credits:%d\n",
		  __func__,
		  connection->req_sn, connection->req_exp_sn,
		  connection->req_ack_sn,
		  connection->credits_msgs, connection->peer_credits_msgs);
	*/
#ifdef XIO_SESSION_DEBUG
	connection->peer_connection = hdr.connection;
	connection->peer_session = hdr.session;
#endif
	msg->sn		= hdr.serial_num;
	msg->flags	= 0;
	msg->next	= NULL;

	if (test_bits(XIO_MSG_FLAG_LAST_IN_BATCH, &task->imsg_flags))
		set_bits(XIO_MSG_FLAG_LAST_IN_BATCH, &msg->flags);

	xio_connection_queue_io_task(connection, task);

	task->state = XIO_TASK_STATE_DELIVERED;

	/* add reference count to protect against release in callback */
	/* add ref to task avoiding race when user call release or send
	 * completion
	 */
	if (hdr.flags & XIO_MSG_FLAG_REQUEST_READ_RECEIPT)
		xio_task_addref(task);

#ifdef XIO_CFLAG_STAT_COUNTERS
	msg->timestamp = get_cycles();
	xio_stat_inc(stats, XIO_STAT_RX_MSG);
	xio_stat_add(stats, XIO_STAT_RX_BYTES,
		     vmsg->header.iov_len + tbl_length(sgtbl_ops, sgtbl));
#endif
	if (test_bits(XIO_MSG_FLAG_EX_IMM_READ_RECEIPT, &hdr.flags)) {
		xio_task_addref(task);
		/* send receipt before calling the callback */
		xio_connection_send_read_receipt(connection, msg);
	}

	/* notify the upper layer */
	if (task->status) {
		xio_session_notify_msg_error(connection, msg,
					     (enum xio_status)task->status,
					     XIO_MSG_DIRECTION_IN);
		task->status = 0;
	} else {
		/* check for repeated msgs */
		/* repeated msgs will not be delivered to the application since they were already delivered */
		if (connection->latest_delivered < msg->sn || connection->latest_delivered == 0) {
#ifdef XIO_THREAD_SAFE_DEBUG
			xio_ctx_debug_thread_unlock(connection->ctx);
#endif
			connection->ses_ops.on_msg(
					connection->session, msg,
					task->last_in_rxq,
					connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
			xio_ctx_debug_thread_lock(connection->ctx);
#endif
			connection->latest_delivered = msg->sn;
		}
	}

	if (hdr.flags & XIO_MSG_FLAG_REQUEST_READ_RECEIPT) {
		if (task->state == XIO_TASK_STATE_DELIVERED) {
			xio_connection_send_read_receipt(connection, msg);
		} else {
			/* free the ref added in this function */
			xio_tasks_pool_put(task);
		}
	}

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
	int			standalone_receipt = 0;
#ifdef XIO_CFLAG_STAT_COUNTERS
	struct xio_statistics	*stats = &connection->ctx->stats;
#endif

	if ((connection->state != XIO_CONNECTION_STATE_ONLINE) &&
	    (connection->state != XIO_CONNECTION_STATE_FIN_WAIT_1)) {
		DEBUG_LOG("responses received while connection is offline\n");
		/* for various reasons, responses can arrive while connection
		 * is already offline
		 * release the response, and let it be flushed via "flush"
		 * mechanism
		 */
		xio_release_response_task(task);
		goto exit;
	}

	/* read session header */
	xio_session_read_header(task, &hdr);

	/* standalone receipt */
	if (xio_app_receipt_request(&hdr) ==
	    XIO_MSG_FLAG_EX_RECEIPT_FIRST)
		standalone_receipt = 1;

	/* update receive + send window */
	if (connection->rsp_exp_sn == hdr.sn) {
		connection->rsp_exp_sn++;
		connection->rsp_ack_sn = hdr.sn;
		connection->restarted  = 0;
		if (connection->enable_flow_control) {
			connection->peer_credits_msgs += hdr.credits_msgs;
			connection->peer_credits_bytes += hdr.credits_bytes;
		}
	} else {
		if (unlikely(connection->restarted)) {
			connection->rsp_exp_sn = hdr.sn + 1;
			connection->restarted = 0;
		} else {
			ERROR_LOG("ERROR: expected sn:%d, arrived sn:%d\n",
				  connection->rsp_exp_sn, hdr.sn);
		}
	}
	/*
	DEBUG_LOG("[%s] sn:%d, exp:%d, ack:%d, credits:%d, peer_credits:%d\n",
		  __func__,
		  connection->rsp_sn, connection->rsp_exp_sn,
		  connection->rsp_ack_sn,
		  connection->credits_msgs, connection->peer_credits_msgs);
	*/
#ifdef XIO_SESSION_DEBUG
	connection->peer_connection = hdr.connection;
	connection->peer_session = hdr.session;
#endif

	msg->sn = hdr.serial_num;

	omsg		= sender_task->omsg;

#ifdef XIO_CFLAG_STAT_COUNTERS
	xio_stat_add(stats, XIO_STAT_DELAY,
		     get_cycles() - omsg->timestamp);
	xio_stat_inc(stats, XIO_STAT_RX_MSG);
#endif
	omsg->next	= NULL;

	xio_clear_ex_flags(&omsg->flags);

	task->connection = connection;
	task->session = connection->session;

	/* remove only if not response with "read receipt" */
	if (!standalone_receipt) {
		xio_connection_remove_in_flight(connection, omsg);
	} else {
		if (task->tlv_type == XIO_ONE_WAY_RSP)
			if (xio_app_receipt_first_request(&hdr))
				xio_connection_remove_in_flight(connection,
								omsg);
	}

	omsg->type = (enum xio_msg_type)task->tlv_type;

	/* cache the task in io queue */
	xio_connection_queue_io_task(connection, task);

	/* remove the message from in flight queue */

	if (task->tlv_type == XIO_ONE_WAY_RSP) {
		/* one way message with "read receipt" */
		if (!xio_app_receipt_first_request(&hdr))
			ERROR_LOG("protocol requires first flag to be set. " \
				  "flags:0x%x\n", hdr.flags);

		if (connection->enable_flow_control) {
			struct xio_sg_table_ops	*sgtbl_ops;
			void			*sgtbl;

			sgtbl		= xio_sg_table_get(&omsg->out);
			sgtbl_ops	= (struct xio_sg_table_ops *)
				xio_sg_table_ops_get(omsg->out.sgl_type);

			connection->tx_queued_msgs--;
			connection->tx_bytes -=
				(omsg->out.header.iov_len +
					 tbl_length(sgtbl_ops, sgtbl));
		}

		omsg->sn	  = msg->sn; /* one way do have response */
		omsg->receipt_res = (enum xio_receipt_result)hdr.receipt_result;

		if (omsg->flags &
		    XIO_MSG_FLAG_REQUEST_READ_RECEIPT) {
			if (connection->ses_ops.on_msg_delivered) {
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_unlock(connection->ctx);
#endif
				connection->ses_ops.on_msg_delivered(
						connection->session,
						omsg,
						task->last_in_rxq,
						connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_lock(connection->ctx);
#endif
			}
		} else {
			if (connection->ses_ops.on_ow_msg_send_complete) {
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_unlock(connection->ctx);
#endif
				connection->ses_ops.on_ow_msg_send_complete(
					connection->session, omsg,
					connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_lock(connection->ctx);
#endif
			}
		}
		sender_task->omsg = NULL;
		xio_release_response_task(task);
	} else {
		if (xio_app_receipt_first_request(&hdr)) {
			if (connection->ses_ops.on_msg_delivered) {
				omsg->receipt_res =
				    (enum xio_receipt_result)hdr.receipt_result;
				omsg->sn	  = hdr.serial_num;
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_unlock(connection->ctx);
#endif
				connection->ses_ops.on_msg_delivered(
						connection->session,
						omsg,
						task->last_in_rxq,
						connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_lock(connection->ctx);
#endif
			}
			/* standalone receipt */
			if (standalone_receipt) {
				/* after receipt delivered reproduce the
				 * original "in" side  */
				memcpy(&omsg->in, &sender_task->in_receipt,
				       sizeof(omsg->in));

				/* recycle the receipt */
				xio_tasks_pool_put(task);
			}
		}
		if (xio_app_receipt_last_request(&hdr)) {
#ifdef XIO_CFLAG_STAT_COUNTERS
			struct xio_vmsg *vmsg = &msg->in;
			struct xio_sg_table_ops	*sgtbl_ops;
			void			*sgtbl;

			sgtbl		= xio_sg_table_get(&msg->in);
			sgtbl_ops	= (struct xio_sg_table_ops *)
					xio_sg_table_ops_get(msg->in.sgl_type);
			xio_stat_add(stats, XIO_STAT_RX_BYTES,
				     vmsg->header.iov_len +
				     tbl_length(sgtbl_ops, sgtbl));
#endif
			omsg->request	= msg;
			if (task->status) {
				xio_session_notify_msg_error(
					connection, omsg,
					(enum xio_status)task->status,
					XIO_MSG_DIRECTION_IN);
				task->status = 0;
			} else {
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_unlock(connection->ctx);
#endif
				/*if (connection->ses_ops.on_msg) */
					connection->ses_ops.on_msg(
						connection->session,
						omsg,
						task->last_in_rxq,
						connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
				xio_ctx_debug_thread_lock(connection->ctx);
#endif
			}
		}
	}

exit:
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
		goto exit;
	}

	/* remove the message from in flight queue */
	xio_connection_remove_in_flight(connection, task->omsg);

	/*
	 * completion of receipt
	 */
	if ((task->omsg_flags &
	    (XIO_MSG_FLAG_EX_RECEIPT_FIRST | XIO_MSG_FLAG_EX_RECEIPT_LAST)) ==
	     XIO_MSG_FLAG_EX_RECEIPT_FIRST) {
		xio_connection_release_read_receipt(connection, task->omsg);
		xio_release_response_task(task);
	} else {
		/* send completion notification only to responder to
		 * release responses
		 */
		xio_clear_ex_flags(&task->omsg->flags);
		if (connection->ses_ops.on_msg_send_complete) {
#ifdef XIO_THREAD_SAFE_DEBUG
			xio_ctx_debug_thread_unlock(connection->ctx);
#endif
			connection->ses_ops.on_msg_send_complete(
					connection->session, task->omsg,
					connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
			xio_ctx_debug_thread_lock(connection->ctx);
#endif
		}
		/* recycle the task */
		xio_tasks_pool_put(task);
	}

exit:
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_credits_ack_recv						     */
/*---------------------------------------------------------------------------*/
int xio_on_credits_ack_recv(struct xio_connection *connection,
			    struct xio_task *task)
{
	struct xio_session_hdr	hdr;

	if (connection->enable_flow_control == 0)
		return 0;

	/* read session header */
	xio_session_read_header(task, &hdr);

	if (connection->req_exp_sn == hdr.sn) {
		connection->req_exp_sn++;
		connection->req_ack_sn = hdr.sn;
		connection->peer_credits_msgs += hdr.credits_msgs;
		connection->peer_credits_bytes += hdr.credits_bytes;
	} else {
		ERROR_LOG("ERROR: sn expected:%d, sn arrived:%d\n",
			  connection->req_exp_sn, hdr.sn);
	}
	connection->credits_msgs++;
	xio_tasks_pool_put(task);
	/*
	DEBUG_LOG("[%s] sn:%d, exp:%d, ack:%d, credits:%d, peer_credits:%d\n",
	       __func__,
	       connection->sn, connection->exp_sn, connection->ack_sn,
	       connection->credits_msgs, connection->peer_credits_msgs);
	*/
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_ow_req_send_comp				                     */
/*---------------------------------------------------------------------------*/
static int xio_on_ow_req_send_comp(
		struct xio_connection *connection,
		struct xio_task *task)
{
#ifdef XIO_CFLAG_STAT_COUNTERS
	struct xio_statistics	*stats = &connection->ctx->stats;
#endif
	struct xio_msg		*omsg = task->omsg;

	if (connection->is_flushed) {
		xio_tasks_pool_put(task);
		goto exit;
	}

	if (!omsg || omsg->flags & XIO_MSG_FLAG_REQUEST_READ_RECEIPT ||
	    task->omsg_flags & XIO_MSG_FLAG_REQUEST_READ_RECEIPT ||
	    task->omsg->flags & XIO_MSG_FLAG_EX_IMM_READ_RECEIPT)
		return 0;
#ifdef XIO_CFLAG_STAT_COUNTERS
	xio_stat_add(stats, XIO_STAT_DELAY,
		     get_cycles() - omsg->timestamp);
	xio_stat_inc(stats, XIO_STAT_RX_MSG); /* need to replace with
					       * TX_COMP
					       */
#endif
	xio_connection_remove_in_flight(connection, omsg);
	omsg->flags = task->omsg_flags;
	xio_clear_ex_flags(&omsg->flags);

	if (connection->enable_flow_control) {
		struct xio_sg_table_ops	*sgtbl_ops;
		void			*sgtbl;

		sgtbl		= xio_sg_table_get(&omsg->out);
		sgtbl_ops	= (struct xio_sg_table_ops *)
				xio_sg_table_ops_get(omsg->out.sgl_type);

		connection->tx_queued_msgs--;
		connection->tx_bytes -=
			(omsg->out.header.iov_len +
			 tbl_length(sgtbl_ops, sgtbl));
	}

	/* send completion notification to
	 * release request
	 */
	if (connection->ses_ops.on_ow_msg_send_complete) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		connection->ses_ops.on_ow_msg_send_complete(
				connection->session, omsg,
				connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
	xio_tasks_pool_put(task);

exit:
	return 0;
}

int xio_on_rdma_direct_comp(struct xio_session *session,
			    struct xio_nexus *nexus,
			    union xio_nexus_event_data *event_data)
{
	struct xio_task	*task  = event_data->msg.task;
	struct xio_msg *omsg = task->omsg;
	struct xio_connection *connection = task->connection;

	if (unlikely(task->tlv_type != XIO_MSG_TYPE_RDMA)) {
		ERROR_LOG("Unexpected message type %u\n",
			  task->tlv_type);
		return 0;
	}

	if (connection->is_flushed) {
		xio_tasks_pool_put(task);
		goto xmit;
	}

	if (!omsg)
		return 0;

	xio_connection_remove_in_flight(connection, omsg);
	omsg->flags = task->omsg_flags;
	connection->tx_queued_msgs--;

	if (connection->ses_ops.on_rdma_direct_complete) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		connection->ses_ops.on_rdma_direct_complete(
				connection->session, omsg,
				connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}
	xio_tasks_pool_put(task);

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

	DEBUG_LOG("xio_session_on_nexus_disconnected. session:%p, nexus:%p\n",
		  session, nexus);

	if (session->lead_connection &&
	    session->lead_connection->nexus == nexus) {
		connection = session->lead_connection;
		connection->close_reason = XIO_E_SESSION_DISCONNECTED;
		xio_connection_disconnected(connection);
	} else if (session->redir_connection &&
		   session->redir_connection->nexus == nexus) {
		connection = session->redir_connection;
		connection->close_reason = XIO_E_SESSION_DISCONNECTED;
		xio_connection_disconnected(connection);
	} else {
		spin_lock(&session->connections_list_lock);
		connection = xio_session_find_connection(session, nexus);
		spin_unlock(&session->connections_list_lock);
		connection->close_reason = XIO_E_SESSION_DISCONNECTED;

		/* disconnection arrive during active closing phase */
		if (connection->state != XIO_CONNECTION_STATE_CLOSED) {
			kref_init(&connection->kref);
			xio_connection_disconnected(connection);
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_nexus_reconnecting		                             */
/*---------------------------------------------------------------------------*/
int xio_on_nexus_reconnecting(struct xio_session *session,
			     struct xio_nexus *nexus)
{
	struct xio_connection		*connection;

	if (session->lead_connection &&
	    session->lead_connection->nexus == nexus)
		connection = session->lead_connection;
	else
		connection = xio_session_find_connection(session, nexus);

	if (connection)
		xio_connection_reconnect(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_nexus_reconnected			                             */
/*---------------------------------------------------------------------------*/
int xio_on_nexus_reconnected(struct xio_session *session,
			     struct xio_nexus *nexus)
{
	struct xio_connection		*connection;

	if (session->lead_connection &&
	    session->lead_connection->nexus == nexus)
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
	struct xio_connection		*connection;

	TRACE_LOG("session:%p - nexus:%p close complete\n", session, nexus);

	/* no more notifications */
	xio_nexus_unreg_observer(nexus, &session->observer);

	if (session->lead_connection &&
	    session->lead_connection->nexus == nexus)
		connection = session->lead_connection;
	else
		connection = xio_session_find_connection(session, nexus);
	if (connection)
		connection->nexus = NULL;

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
	xio_connection_queue_io_task(task->connection, task);

	if (task->session->ses_ops.on_msg_error && IS_APPLICATION_MSG(task->tlv_type)) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(task->connection->ctx);
#endif
		task->session->ses_ops.on_msg_error(
				task->session,
				event_data->msg_error.reason,
				event_data->msg_error.direction,
				task->omsg,
				task->connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(task->connection->ctx);
#endif
	}

	if (IS_REQUEST(task->tlv_type) || task->tlv_type == XIO_MSG_TYPE_RDMA)
		xio_tasks_pool_put(task);
	else
		xio_release_response_task(task);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_nexus_error							     */
/*---------------------------------------------------------------------------*/
int xio_on_nexus_error(struct xio_session *session, struct xio_nexus *nexus,
		       union xio_nexus_event_data *event_data)
{
	struct xio_connection *connection, *next_connection;

	/* disable the teardown */
	session->disable_teardown = 0;

	switch (session->state) {
	case XIO_SESSION_STATE_CONNECT:
	case XIO_SESSION_STATE_REDIRECTED:
		session->state = XIO_SESSION_STATE_REFUSED;
		list_for_each_entry_safe(
				connection, next_connection,
				&session->connections_list,
				connections_list_entry) {
			xio_connection_error_event(connection,
						   event_data->error.reason);
		}

		break;
	default:
		connection = xio_session_find_connection(session, nexus);
		xio_connection_error_event(connection,
					   event_data->error.reason);
		break;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_new_message							     */
/*---------------------------------------------------------------------------*/
int xio_on_new_message(struct xio_session *s,
		       struct xio_nexus *nexus,
		       union xio_nexus_event_data *event_data)
{
	struct xio_task		*task  = event_data->msg.task;
	struct xio_connection	*connection = NULL;
	struct xio_session	*session = s;
	int			retval = -1;
	int			xmit = 0;

	if (task->sender_task) {
		session = task->sender_task->session;
		connection = task->sender_task->connection;
	}

	if (!session) {
		session = xio_find_session(task);
		if (!session) {
			ERROR_LOG("failed to find session\n");
			xio_tasks_pool_put(task);
			return -1;
		}
	}

	if (!connection) {
		connection = xio_session_find_connection(session, nexus);
		if (!connection) {
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

	task->session		= session;
	task->connection	= connection;

	switch (task->tlv_type) {
	case XIO_MSG_REQ:
	case XIO_ONE_WAY_REQ:
		retval = xio_on_req_recv(connection, task);
		xmit = 1;
		break;
	case XIO_MSG_RSP:
	case XIO_ONE_WAY_RSP:
		retval = xio_on_rsp_recv(connection, task);
		xmit = 1;
		break;
	case XIO_ACK_REQ:
		retval = xio_on_credits_ack_recv(connection, task);
		xmit = 1;
		break;
	case XIO_FIN_REQ:
		retval = xio_on_fin_req_recv(connection, task);
		break;
	case XIO_FIN_RSP:
		retval = xio_on_fin_ack_recv(connection, task);
		break;
	case XIO_SESSION_SETUP_REQ:
		retval = xio_on_setup_req_recv(connection, task);
		xmit = 1;
		break;
	case XIO_SESSION_SETUP_RSP:
		retval = xio_on_setup_rsp_recv(connection, task);
		xmit = 1;
		break;
	case XIO_CONNECTION_HELLO_REQ:
		retval = xio_on_connection_hello_req_recv(connection, task);
		xmit = 1;
		break;
	case XIO_CONNECTION_HELLO_RSP:
		retval = xio_on_connection_hello_rsp_recv(connection, task);
		xmit = 1;
		break;
	case XIO_CONNECTION_KA_REQ:
		retval = xio_on_connection_ka_req_recv(connection, task);
		break;
	case XIO_CONNECTION_KA_RSP:
		retval = xio_on_connection_ka_rsp_recv(connection, task);
		break;
	default:
		retval = -1;
		break;
	}

	/* now try to send */
	if (xmit)
		xio_connection_xmit_msgs(connection);

	if (retval != 0)
		ERROR_LOG("receiving new message failed. type:0x%x\n",
			  task->tlv_type);

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
	int			xmit = 0;

	connection = task->connection;

	switch (task->tlv_type) {
	case XIO_MSG_REQ:
	case XIO_SESSION_SETUP_REQ:
		retval = 0;
		break;
	case XIO_MSG_RSP:
	case XIO_ONE_WAY_RSP:
		retval = xio_on_rsp_send_comp(connection, task);
		xmit = 1;
		break;
	case XIO_ONE_WAY_REQ:
		retval = xio_on_ow_req_send_comp(connection, task);
		xmit = 1;
		break;
	case XIO_ACK_REQ:
		retval = xio_on_credits_ack_send_comp(connection, task);
		xmit = 1;
		break;
	case XIO_FIN_REQ:
		retval = xio_on_fin_req_send_comp(connection, task);
		break;
	case XIO_FIN_RSP:
		retval = xio_on_fin_ack_send_comp(connection, task);
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
		xmit = 1;
		break;
	case XIO_CONNECTION_KA_REQ:
		retval = 0;
		break;
	case XIO_CONNECTION_KA_RSP:
		retval = xio_on_connection_ka_rsp_send_comp(connection,
							    task);
		break;
	default:
		break;
	}
	/* now try to send */
	if (xmit)
		xio_connection_xmit_msgs(connection);

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
	int retval;

	if (!session)
		session = xio_find_session(task);

	connection = xio_session_find_connection(session, nexus);
	if (!connection) {
		connection = xio_session_assign_nexus(session, nexus);
		if (!connection) {
			ERROR_LOG("failed to find connection :%p. " \
				  "dropping message:%d\n", nexus,
				  event_data->msg.op);
			return -1;
		}
	}

	if (connection->ses_ops.assign_data_in_buf) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		retval = connection->ses_ops.assign_data_in_buf(
					&task->imsg,
					connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
		event_data->assign_in_buf.is_assigned = (retval == 0);
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

	tmp_hdr			 = (struct xio_session_cancel_hdr *)
					event_data->cancel.ulp_msg;
	hdr.sn			 = ntohll(tmp_hdr->sn);
	hdr.responder_session_id = ntohl(tmp_hdr->responder_session_id);

	observer = xio_nexus_observer_lookup(nexus, hdr.responder_session_id);
	if (!observer) {
		ERROR_LOG("failed to find session\n");
		return -1;
	}

	session = (struct xio_session *)observer->impl;

	connection = xio_session_find_connection(session, nexus);
	if (!connection) {
		ERROR_LOG("failed to find session\n");
		return -1;
	}

	/* lookup for task in io list */
	task = xio_connection_find_io_task(connection, hdr.sn);
	if (task) {
		if (connection->ses_ops.on_cancel_request) {
#ifdef XIO_THREAD_SAFE_DEBUG
			xio_ctx_debug_thread_unlock(connection->ctx);
#endif
			connection->ses_ops.on_cancel_request(
				connection->session,
				&task->imsg,
				connection->cb_user_context);
			return 0;
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
		}
		WARN_LOG("cancel is not supported on responder\n");
	}
	TRACE_LOG("message to cancel not found %llu\n", hdr.sn);

	req = (struct xio_msg *)kcalloc(1, sizeof(*req), GFP_KERNEL);
	if (!req) {
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

	if (!event_data->cancel.task) {
		tmp_hdr			 = (struct xio_session_cancel_hdr *)
						event_data->cancel.ulp_msg;
		hdr.sn			 = ntohll(tmp_hdr->sn);
		hdr.requester_session_id = ntohl(tmp_hdr->requester_session_id);

		observer = xio_nexus_observer_lookup(nexus,
						     hdr.requester_session_id);
		if (!observer) {
			ERROR_LOG("failed to find session\n");
			return -1;
		}
		session = (struct xio_session *)observer->impl;

		/* large object - allocate it */
		msg = (struct xio_msg *)kcalloc(1, sizeof(*msg), GFP_KERNEL);
		if (!msg) {
			ERROR_LOG("msg allocation failed\n");
			return -1;
		}

		pmsg		= msg;		/* fake a message */
		msg->sn		= hdr.sn;
	} else {
		session		= event_data->cancel.task->session;
		pmsg		= event_data->cancel.task->omsg;
		hdr.sn		= pmsg->sn;
	}

	connection = xio_session_find_connection(session, nexus);
	if (!connection) {
		ERROR_LOG("failed to find session\n");
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

	kfree(msg);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_session_create			                                     */
/*---------------------------------------------------------------------------*/
struct xio_session *xio_session_create(struct xio_session_params *params)
{
	struct xio_session	*session = NULL;
	int			retval;
	int			uri_len = 0;

	/* input validation */
	if (!params || !params->uri) {
		xio_set_error(EINVAL);
		ERROR_LOG("xio_session_open: invalid parameter\n");
		return NULL;
	}
	uri_len = strlen(params->uri);

	/* extract portal from uri */
	/* create the session */
	session = (struct xio_session *)
			kcalloc(1, sizeof(struct xio_session), GFP_KERNEL);
	if (!session) {
		ERROR_LOG("failed to create session\n");
		xio_set_error(ENOMEM);
		return NULL;
	}

	XIO_OBSERVER_INIT(&session->observer, session,
			  (params->type == XIO_SESSION_SERVER) ?
					xio_server_on_nexus_event :
					xio_client_on_nexus_event);

	INIT_LIST_HEAD(&session->connections_list);

	session->hs_private_data_len = params->private_data_len;

	/* copy private data if exist */
	if (session->hs_private_data_len) {
		session->hs_private_data = kmalloc(session->hs_private_data_len,
						GFP_KERNEL);
		if (!session->hs_private_data) {
			xio_set_error(ENOMEM);
			goto cleanup;
		}
		memcpy(session->hs_private_data, params->private_data,
		       session->hs_private_data_len);
	}
	mutex_init(&session->lock);
	spin_lock_init(&session->connections_list_lock);

	/* fill session data*/
	session->type			= params->type;
	session->cb_user_context	= params->user_context;

	session->trans_sn		= params->initial_sn;
	session->state			= XIO_SESSION_STATE_INIT;
	session->snd_queue_depth_msgs	= g_options.snd_queue_depth_msgs;
	session->rcv_queue_depth_msgs	= g_options.rcv_queue_depth_msgs;
	session->snd_queue_depth_bytes	= g_options.snd_queue_depth_bytes;
	session->rcv_queue_depth_bytes	= g_options.rcv_queue_depth_bytes;
	session->connection_srv_first	= NULL;

	memcpy(&session->ses_ops, params->ses_ops,
	       sizeof(*params->ses_ops));

	session->uri_len = uri_len;
	session->uri = kstrdup(params->uri, GFP_KERNEL);
	if (!session->uri) {
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
	xio_idr_add_uobj(usr_idr, session, "xio_session");

	return session;

cleanup3:
	kfree(session->uri);
cleanup2:
	kfree(session->hs_private_data);
cleanup:
	kfree(session);

	ERROR_LOG("session creation failed\n");

	return NULL;
}
EXPORT_SYMBOL(xio_session_create);

/*---------------------------------------------------------------------------*/
/* xio_session_post_destroy						     */
/*---------------------------------------------------------------------------*/
void xio_session_post_destroy(void *_session)
{
	int found;
	int i;
	struct xio_session *session = (struct xio_session *)_session;


	if (session->teardown_work_ctx) {
		xio_context_unreg_observer(session->teardown_work_ctx,
					   &session->ctx_observer);
		xio_ctx_del_work(session->teardown_work_ctx,
				 &session->teardown_work);
	}

	if (!list_empty(&session->connections_list)) {
		xio_set_error(EBUSY);
		ERROR_LOG("xio_session_destroy failed: " \
			  "connections are still open\n");
		return;
	}

	found = xio_idr_lookup_uobj(usr_idr, session);
	if (found) {
		xio_idr_remove_uobj(usr_idr, session);
	} else {
		ERROR_LOG("session not found:%p\n", session);
		xio_set_error(XIO_E_USER_OBJ_NOT_FOUND);
		return;
	}

	TRACE_LOG("session destroy:%p\n", session);

	session->state = XIO_SESSION_STATE_CLOSED;

	/* unregister session from context */
	xio_sessions_cache_remove(session->session_id);
	for (i = 0; i < session->services_array_len; i++)
		kfree(session->services_array[i]);
	for (i = 0; i < session->portals_array_len; i++)
		kfree(session->portals_array[i]);
	kfree(session->services_array);
	kfree(session->portals_array);
	kfree(session->hs_private_data);
	kfree(session->uri);
	XIO_OBSERVER_DESTROY(&session->observer);
	XIO_OBSERVER_DESTROY(&session->ctx_observer);

	mutex_destroy(&session->lock);
	kfree(session);

	return;
}

/*---------------------------------------------------------------------------*/
/* xio_session_destroy							     */
/*---------------------------------------------------------------------------*/
int xio_session_destroy(struct xio_session *session)
{
	if (!session)
		return 0;

#ifdef XIO_THREAD_SAFE_DEBUG
	if (session->teardown_work_ctx)
		/* not locking if the session did not contain active conn */
		xio_ctx_debug_thread_lock(session->teardown_work_ctx);
#endif

	TRACE_LOG("xio_post_destroy_session seesion:%p\n", session);

	if (session->teardown_work_ctx &&
	    xio_ctx_is_work_in_handler(session->teardown_work_ctx,
				       &session->teardown_work)) {
		xio_context_unreg_observer(session->teardown_work_ctx,
					   &session->ctx_observer);

		xio_ctx_set_work_destructor(
		     session->teardown_work_ctx, session,
		     xio_session_post_destroy,
		     &session->teardown_work);
	} else {
		xio_session_post_destroy(session);
	}
#ifdef XIO_THREAD_SAFE_DEBUG
	if (session->teardown_work_ctx)
		xio_ctx_debug_thread_unlock(session->teardown_work_ctx);
#endif

	return 0;
}
EXPORT_SYMBOL(xio_session_destroy);

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
	case XIO_SESSION_CONNECTION_RECONNECTING_EVENT:
		return "connection reconnecting";
	case XIO_SESSION_CONNECTION_RECONNECTED_EVENT:
		return "connection reconnected";
	};
	return "unknown session event";
}
EXPORT_SYMBOL(xio_session_event_str);

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
		attr->user_context = session->cb_user_context;

	if (attr_mask & XIO_SESSION_ATTR_SES_OPS)
		attr->ses_ops = &session->ses_ops;

	if (attr_mask & XIO_SESSION_ATTR_URI)
		attr->uri = session->uri;

	return 0;
}
EXPORT_SYMBOL(xio_query_session);

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
		session->cb_user_context = attr->user_context;

	return 0;
}
EXPORT_SYMBOL(xio_modify_session);

/*---------------------------------------------------------------------------*/
/* xio_get_connection							     */
/*---------------------------------------------------------------------------*/
struct xio_connection *xio_get_connection(struct xio_session *session,
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
	if (connection->ses_ops.on_cancel) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		connection->ses_ops.on_cancel(
				connection->session, req,
				result,
				connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_session_notify_msg_error						     */
/*---------------------------------------------------------------------------*/
int xio_session_notify_msg_error(struct xio_connection *connection,
				 struct xio_msg *msg, enum xio_status result,
				 enum xio_msg_direction direction)
{
	/* notify the upper layer */
	if (connection->ses_ops.on_msg_error && IS_APPLICATION_MSG(msg->type)) {
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_unlock(connection->ctx);
#endif
		connection->ses_ops.on_msg_error(
				connection->session,
				result, direction, msg,
				connection->cb_user_context);
#ifdef XIO_THREAD_SAFE_DEBUG
		xio_ctx_debug_thread_lock(connection->ctx);
#endif
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_session_on_context_event						     */
/*---------------------------------------------------------------------------*/
static int xio_session_on_context_event(void *observer, void *sender, int event,
				void *event_data)
{
	struct xio_session *session = (struct xio_session *)observer;

	if (event == XIO_CONTEXT_EVENT_CLOSE) {
		TRACE_LOG("context: [close] ctx:%p\n", sender);

		xio_context_unreg_observer(session->teardown_work_ctx,
					   &session->ctx_observer);
		/* clean the context so that upon session destroy do not
		 * do not handle workqueue
		 */
		xio_ctx_del_work(session->teardown_work_ctx,
				 &session->teardown_work);

		session->teardown_work_ctx = NULL;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_session_pre_teardown						     */
/*---------------------------------------------------------------------------*/
static void xio_session_pre_teardown(void *_session)
{
	struct xio_session	*session = (struct xio_session *)_session;
	int			destroy_session = 0;
	int			reason;

	switch (session->state) {
	case XIO_SESSION_STATE_REJECTED:
		reason = XIO_E_SESSION_REJECTED;
		break;
	case XIO_SESSION_STATE_ACCEPTED:
		if (session->type == XIO_SESSION_SERVER)
			reason = XIO_E_SESSION_DISCONNECTED;
		else
			reason = XIO_E_SESSION_REFUSED;
		break;
	default:
		reason = session->teardown_reason;
		break;
	}
	mutex_lock(&session->lock);

	spin_lock(&session->connections_list_lock);
	destroy_session = ((session->connections_nr == 0) &&
			   !session->lead_connection &&
			   !session->redir_connection);

	spin_unlock(&session->connections_list_lock);

		/* last chance to teardown */
	if (destroy_session) {
		/* remove the session from cache */
		xio_sessions_cache_remove(session->session_id);
		mutex_unlock(&session->lock);
		session->state = XIO_SESSION_STATE_CLOSING;
		session->teardown_reason = reason;

		/* start listen to context events  - context can be destroyed
		 * while session still alive */
		xio_context_unreg_observer(session->teardown_work_ctx,
                                           &session->ctx_observer);

		XIO_OBSERVER_INIT(&session->ctx_observer, session,
				  xio_session_on_context_event);
		xio_context_reg_observer(session->teardown_work_ctx,
					 &session->ctx_observer);

		xio_session_notify_teardown(session, session->teardown_reason);
	} else {
		mutex_unlock(&session->lock);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_session_init_teardown						     */
/*---------------------------------------------------------------------------*/
void xio_session_init_teardown(struct xio_session *session,
			       struct xio_context *ctx,
			       int close_reason)
{
		session->teardown_reason = close_reason;
		session->teardown_work_ctx = ctx;

		xio_ctx_add_work(
				ctx,
				session,
				xio_session_pre_teardown,
				&session->teardown_work);
}

