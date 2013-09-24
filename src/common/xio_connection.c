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
#include "xio_task.h"
#include "xio_msg_list.h"
#include "xio_conn.h"
#include "xio_connection.h"
#include "xio_session.h"

#define MSG_POOL_SZ	1024


/*---------------------------------------------------------------------------*/
/* xio_init_ow_msg_pool							     */
/*---------------------------------------------------------------------------*/
static int xio_init_ow_msg_pool(struct xio_connection *conn)
{
	int i;

	conn->msg_array = kcalloc(MSG_POOL_SZ, sizeof(struct xio_msg),
				  GFP_KERNEL);
	xio_msg_list_init(&conn->one_way_msg_pool);
	for (i = 0; i < MSG_POOL_SZ; i++)
		xio_msg_list_insert_head(&conn->one_way_msg_pool,
					 &conn->msg_array[i]);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_free_ow_msg_pool							     */
/*---------------------------------------------------------------------------*/
static int xio_free_ow_msg_pool(struct xio_connection *conn)
{
	xio_msg_list_init(&conn->one_way_msg_pool);
	kfree(conn->msg_array);
	conn->msg_array = NULL;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_connection_init							     */
/*---------------------------------------------------------------------------*/
struct xio_connection *xio_connection_init(struct xio_session *session,
					       struct xio_context *ctx,
					       int conn_idx,
					       void *cb_user_context)
{
		struct xio_connection *connection;

		if ((ctx == NULL) || (session == NULL)) {
			xio_set_error(EINVAL);
			return NULL;
		}

		connection = kcalloc(1, sizeof(*connection), GFP_KERNEL);
		if (connection == NULL) {
			xio_set_error(ENOMEM);
			return NULL;
		}

		connection->session	= session;
		connection->conn	= NULL;
		connection->ctx		= ctx;
		connection->conn_idx	= conn_idx;
		connection->cb_user_context = cb_user_context;
		memcpy(&connection->ses_ops, &session->ses_ops,
		       sizeof(session->ses_ops));

		INIT_LIST_HEAD(&connection->io_tasks_list);
		INIT_LIST_HEAD(&connection->post_io_tasks_list);
		INIT_LIST_HEAD(&connection->pre_send_list);

		xio_msg_list_init(&connection->reqs_msgq);
		xio_msg_list_init(&connection->rsps_msgq);
		xio_init_ow_msg_pool(connection);

		return connection;
}

/*---------------------------------------------------------------------------*/
/* xio_connection_send							     */
/*---------------------------------------------------------------------------*/
int xio_connection_send(struct xio_connection *conn,
			  struct xio_msg *msg)
{
	int			retval = 0;
	struct xio_task		*task = NULL;
	struct xio_task		*req_task = NULL;
	struct xio_session_hdr	hdr;
	int			is_req = 0;


	if (msg->type == XIO_ONE_WAY_RSP) {
		task = xio_conn_get_primary_task(conn->conn);
		if (task == NULL) {
			ERROR_LOG("tasks pool is empty\n");
			xio_set_error(ENOMEM);
			return -1;
		}
		req_task = container_of(msg->request, struct xio_task, imsg);
		if (req_task == NULL) {
			ERROR_LOG("response with id %"PRIu64" is unknown." \
				  " - connection:%p, session:%p, conn:%p\n",
				  msg->request->sn, conn, conn->session,
				  conn->conn);
			xio_set_error(EINVAL);
			xio_conn_put_task(conn->conn, task);
			return -1;
		}
		list_move_tail(&task->tasks_list_entry, &conn->pre_send_list);
		task->sender_task = req_task;
		task->omsg	  = msg;
		hdr.serial_num	  = msg->request->sn;
		task->rtid	  = req_task->rtid;
		is_req = 1;
	} else {
		if ((msg->type == XIO_MSG_TYPE_REQ) ||
		    (msg->type == XIO_SESSION_SETUP_REQ) ||
		    (msg->type == XIO_ONE_WAY_REQ)) {
			task = xio_conn_get_primary_task(conn->conn);
			if (task == NULL) {
				ERROR_LOG("tasks pool is empty\n");
				xio_set_error(ENOMEM);
				return -1;
			}
			task->omsg	= msg;
			hdr.serial_num	= task->omsg->sn;
			is_req = 1;
			list_move_tail(&task->tasks_list_entry,
				       &conn->pre_send_list);
		} else {
			task = container_of(msg->request,
					    struct xio_task, imsg);
			if (task == NULL) {
				ERROR_LOG("response with id %"PRIu64""   \
					  "is unknown. - connection:%p," \
					  "session:%p, conn:%p\n",
					  msg->request->sn, conn,
					  conn->session, conn->conn);
				xio_set_error(EINVAL);
				return -1;
			}
			list_move_tail(&task->tasks_list_entry,
				       &conn->pre_send_list);

			hdr.serial_num	= msg->request->sn;
		}
	}

	/* reset the task mbuf */
	xio_mbuf_reset(&task->mbuf);

	/* set the the mbuf to begining of tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		goto cleanup;


	task->tlv_type		= msg->type;
	task->session		= conn->session;
	task->conn		= conn->conn;
	task->omsg		= msg;


	/* write session header */
	hdr.dest_session_id = conn->session->peer_session_id;
	if (xio_session_write_header(task, &hdr) != 0)
		goto cleanup;

	/* send it */
	retval = xio_conn_send(conn->conn, task);
	if (retval != 0) {
		if (xio_errno() != EAGAIN)
			ERROR_LOG("xio_conn_send failed\n");
		goto cleanup;
	}

	return 0;

cleanup:
	if (is_req)
		xio_conn_put_task(conn->conn, task);
	else
		list_move(&task->tasks_list_entry, &conn->io_tasks_list);


	return -1;
}
/*---------------------------------------------------------------------------*/
/* xio_connection_flush							     */
/*---------------------------------------------------------------------------*/
static int xio_connection_flush(struct xio_connection *conn)
{
	struct xio_msg		*msg;
	struct xio_task		*task = NULL;

	while (!xio_msg_list_empty(&conn->rsps_msgq)) {
		msg = xio_msg_list_first(&conn->rsps_msgq);
		xio_msg_list_remove(&conn->rsps_msgq, msg);
		task = container_of(msg->request, struct xio_task, imsg);
			/* after send success release it */
		if (task->sender_task) {
			/* the tx task is returend back to pool */
			xio_conn_put_task(task->sender_task->conn,
					  task->sender_task);
			task->sender_task = NULL;
		}
		xio_conn_put_task(task->conn, task);

		if (msg->type == XIO_ONE_WAY_RSP)
			xio_msg_list_insert_tail(&conn->one_way_msg_pool, msg);
	}
	while (!xio_msg_list_empty(&conn->reqs_msgq)) {
		msg = xio_msg_list_first(&conn->reqs_msgq);
		xio_msg_list_remove(&conn->reqs_msgq, msg);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_connection_xmit							     */
/*---------------------------------------------------------------------------*/
static int xio_connection_xmit(struct xio_connection *conn)
{
	struct xio_msg *msg;
	int    retval = 0;
	int    retry_cnt = 0;
	struct xio_msg_list *msg_lists[] = {
		&conn->reqs_msgq,
		&conn->rsps_msgq
	};
	struct xio_msg_list *msgq;

	while (retry_cnt < 2) {
		msgq = msg_lists[conn->send_req_toggle];
		conn->send_req_toggle = 1 - conn->send_req_toggle;
		if (!xio_msg_list_empty(msgq)) {
			msg = xio_msg_list_first(msgq);
			xio_msg_list_remove(msgq, msg);
			retval = xio_connection_send(conn, msg);
			if (retval) {
				if (EAGAIN != xio_errno())
					break;
				/* if user requested not to queue messages */
				if (xio_session_not_queueing(conn->session))
					break;
				xio_msg_list_insert_head(msgq, msg);
				retval = 0;
				retry_cnt++;
			} else {
				retry_cnt = 0;
			}
		} else {
			retry_cnt++;
		}
	}

	if (retval != 0)
		ERROR_LOG("failed to send message - %s\n",
			  xio_strerror(xio_errno()));

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_send_request							     */
/*---------------------------------------------------------------------------*/
int xio_send_request(struct xio_connection *conn,
				  struct xio_msg *msg)
{
	int		valid;

	valid = xio_session_is_valid_in_req(conn->session, msg);
	if (!valid) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid in message\n");
		return -1;
	}
	valid = xio_session_is_valid_out_msg(conn->session, msg);
	if (!valid) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid out message\n");
		return -1;
	}
	if (xio_session_not_queueing(conn->session) &&
	    (conn->state != CONNECTION_STATE_ONLINE)) {
		xio_set_error(EAGAIN);
		return -1;
	}

	msg->sn = xio_session_get_sn(conn->session);
	msg->type = XIO_MSG_TYPE_REQ;

	xio_msg_list_insert_tail(&conn->reqs_msgq, msg);

	/* do not xmit until connection is assigned */
	if (conn->state == CONNECTION_STATE_ONLINE)
		return xio_connection_xmit(conn);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_send_response							     */
/*---------------------------------------------------------------------------*/
int xio_send_response(struct xio_msg *msg)
{
	struct xio_task *task = container_of(msg->request,
					     struct xio_task, imsg);
	struct xio_connection *conn = task->connection;

	int valid = xio_session_is_valid_out_msg(conn->session, msg);
	if (!valid) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid out message\n");
		return -1;
	}

	if (xio_session_not_queueing(conn->session) &&
	    (conn->state != CONNECTION_STATE_ONLINE)) {
		xio_set_error(EAGAIN);
		return -1;
	}

	msg->type = XIO_MSG_TYPE_RSP;
	xio_msg_list_insert_tail(&conn->rsps_msgq, msg);

	/* do not xmit until connection is assigned */
	if (conn->state == CONNECTION_STATE_ONLINE)
		return xio_connection_xmit(conn);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_ack_msg								     */
/*---------------------------------------------------------------------------*/
int xio_connection_ack_ow_req(struct xio_connection *conn,
			      struct xio_msg *msg)
{
	struct xio_msg *rsp;
	struct xio_task *task;


	if (xio_msg_list_empty(&conn->one_way_msg_pool)) {
		xio_set_error(ENOMEM);
		ERROR_LOG("one way msg pool is empty\n");
		return -1;
	}
	task = container_of(msg, struct xio_task, imsg);
	if (task == NULL) {
		xio_set_error(EINVAL);
		ERROR_LOG("request not found\n");
		return -1;
	}
	if (task->ack_ow)
		task->ack_ow = 0;
	else
		return 0;

	/* add ref to task avoiding race when user call release or send
	 * completion
	 */
	xio_task_addref(task);

	rsp = xio_msg_list_first(&conn->one_way_msg_pool);
	xio_msg_list_remove(&conn->one_way_msg_pool, rsp);

	rsp->type = XIO_ONE_WAY_RSP;
	rsp->request = msg;

	rsp->out.header.iov_len = 0;
	rsp->out.data_iovlen = 0;

	xio_msg_list_insert_tail(&conn->rsps_msgq, rsp);

	/* do not xmit until connection is assigned */
	if (conn->state == CONNECTION_STATE_ONLINE)
		return xio_connection_xmit(conn);

	return 0;
}

int xio_connection_release_ow_rsp(struct xio_connection *conn,
				  struct xio_msg *msg)
{
	xio_msg_list_insert_head(&conn->one_way_msg_pool, msg);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_send_msg								     */
/*---------------------------------------------------------------------------*/
int xio_send_msg(struct xio_connection *conn,
		struct xio_msg *msg)
{
	int		valid;

	valid = xio_session_is_valid_out_msg(conn->session, msg);
	if (!valid) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid out message\n");
		return -1;
	}

	if (xio_session_not_queueing(conn->session) &&
	    (conn->state != CONNECTION_STATE_ONLINE)) {
		xio_set_error(EAGAIN);
		return -1;
	}

	msg->sn = xio_session_get_sn(conn->session);
	msg->type = XIO_ONE_WAY_REQ;

	/* reset the in side of the message */
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	msg->in.data_iovlen = 0;

	xio_msg_list_insert_tail(&conn->reqs_msgq, msg);

	/* do not xmit until connection is assigned */
	if (conn->state == CONNECTION_STATE_ONLINE)
		return xio_connection_xmit(conn);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_connection_xmit_msgs						     */
/*---------------------------------------------------------------------------*/
int xio_connection_xmit_msgs(struct xio_connection *conn)
{
	if (conn->state == CONNECTION_STATE_ONLINE) {
		return xio_connection_xmit(conn);
	} else if (xio_session_not_queueing(conn->session)) {
		xio_set_error(EAGAIN);
		return -1;
	}

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_connection_conn_close						     */
/*---------------------------------------------------------------------------*/
int xio_connection_conn_close(struct xio_connection *connection)
{
	struct xio_task *ptask, *pnext_task;

	xio_connection_flush(connection);

	if (!list_empty(&connection->post_io_tasks_list)) {
		TRACE_LOG("post_io_list not empty!\n");
		list_for_each_entry_safe(ptask, pnext_task,
					 &connection->post_io_tasks_list,
					 tasks_list_entry) {
			TRACE_LOG("post_io_list: task %p, refcnt:%d, " \
				  "type 0x%x ltid:%d\n",
				  ptask, ptask->refcnt,
				  ptask->tlv_type, ptask->ltid);
			xio_conn_put_task(connection->conn, ptask);
		}
	}

	if (!list_empty(&connection->pre_send_list)) {
		TRACE_LOG("pre_send_list not empty!\n");
		list_for_each_entry_safe(ptask, pnext_task,
					 &connection->pre_send_list,
					 tasks_list_entry) {
			TRACE_LOG("pre_send_list: task %p, refcnt:%d, " \
				  "type 0x%x ltid:%d\n",
				  ptask, ptask->refcnt,
				  ptask->tlv_type, ptask->ltid);
			if (ptask->sender_task) {
				/* the tx task is returend back to pool */
				xio_conn_put_task(ptask->sender_task->conn,
						  ptask->sender_task);
				ptask->sender_task = NULL;
			}
			xio_conn_put_task(ptask->conn, ptask);
		}
	}

	if (!list_empty(&connection->io_tasks_list)) {
		TRACE_LOG("io_tasks_list not empty!\n");
		list_for_each_entry_safe(ptask, pnext_task,
					 &connection->io_tasks_list,
					 tasks_list_entry) {
			TRACE_LOG("io_tasks_list: task %p, refcnt:%d, " \
				  "type 0x%x ltid:%d\n",
				  ptask, ptask->refcnt,
				  ptask->tlv_type, ptask->ltid);
		}
	}

	/* inventory */
	xio_conn_primary_free_tasks(connection->conn);

	return 0;
}
/*---------------------------------------------------------------------------*/
/* xio_connection_close							     */
/*---------------------------------------------------------------------------*/
int xio_connection_close(struct xio_connection *connection)
{
	if (connection->conn)
		xio_connection_conn_close(connection);

	xio_free_ow_msg_pool(connection);
	kfree(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_connection_queue_io_task						     */
/*---------------------------------------------------------------------------*/
void xio_connection_queue_io_task(struct xio_connection *connection,
				    struct xio_task *task)
{
	list_move_tail(&task->tasks_list_entry, &connection->io_tasks_list);
}

/*---------------------------------------------------------------------------*/
/* xio_release_response_task						     */
/*---------------------------------------------------------------------------*/
void xio_release_response_task(struct xio_task *task)
{
	/* the tx task is returend back to pool */
	if (task->sender_task) {
		xio_conn_put_task(task->sender_task->conn, task->sender_task);
		task->sender_task = NULL;
	}

	/* the rx task is returend back to pool */
	xio_conn_put_task(task->conn, task);
}

/*---------------------------------------------------------------------------*/
/* xio_release_response							     */
/*---------------------------------------------------------------------------*/
int xio_release_response(struct xio_msg *msg)
{
	struct xio_task		*task;
	struct xio_connection	*conn;

	task = container_of(msg->request, struct xio_task, imsg);
	if (task == NULL) {
		xio_set_error(EINVAL);
		ERROR_LOG("request not found\n");
		return -1;
	}
	conn = task->connection;
	list_move_tail(&task->tasks_list_entry, &conn->post_io_tasks_list);


	if (task->tlv_type != XIO_MSG_RSP) {
		xio_set_error(EINVAL);
		return -1;
	}
	/* reset the in */
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	msg->in.data_iovlen = 0;


	xio_release_response_task(task);

	xio_connection_xmit_msgs(conn);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_release_msg							     */
/*---------------------------------------------------------------------------*/
int xio_release_msg(struct xio_msg *msg)
{
	struct xio_task		*task;
	struct xio_connection	*conn;

	task = container_of(msg, struct xio_task, imsg);
	if (task == NULL) {
		xio_set_error(EINVAL);
		ERROR_LOG("request not found\n");
		return -1;
	}
	conn = task->connection;
	list_move_tail(&task->tasks_list_entry, &conn->post_io_tasks_list);


	if (task->tlv_type != XIO_ONE_WAY_REQ) {
		ERROR_LOG("xio_release_msg failed. invalid type, 0x%d\n",
			  task->tlv_type);
		xio_set_error(EINVAL);
		return -1;
	}

	/* the rx task is returend back to pool */
	xio_conn_put_task(task->conn, task);

	xio_connection_xmit_msgs(conn);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_disconnect							     */
/*---------------------------------------------------------------------------*/
int xio_disconnect(struct xio_connection *conn)
{
	conn->state = CONNECTION_STATE_CLOSE;
	xio_session_disconnect(conn->session, conn);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_poll_completions							     */
/*---------------------------------------------------------------------------*/
int xio_poll_completions(struct xio_connection *conn,
				       struct timespec *timeout)
{
	if (conn->conn)
		return xio_conn_poll(conn->conn, timeout);
	else
		return 0;
}


