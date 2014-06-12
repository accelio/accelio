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
#include "xio_hash.h"
#include "xio_observer.h"
#include "xio_context.h"
#include "xio_task.h"
#include "xio_transport.h"
#include "xio_conns_store.h"
#include "xio_conn.h"
#include "xio_session.h"


/*---------------------------------------------------------------------------*/
/* private structures							     */
/*---------------------------------------------------------------------------*/
struct xio_observers_htbl_node {
	struct xio_observer	*observer;
	uint32_t		id;
	uint32_t		pad;
	struct list_head	observers_htbl_node;

};

static int xio_msecs[] = {60000, 30000, 15000, 0};

#define XIO_SERVER_GRACE_PERIOD 1000
#define XIO_SERVER_TIMEOUT (60000 + 30000 + 15000 + XIO_SERVER_GRACE_PERIOD)

/*---------------------------------------------------------------------------*/
/* forward declarations							     */
/*---------------------------------------------------------------------------*/
static int xio_conn_primary_pool_create(struct xio_conn *conn);
static int xio_conn_primary_pool_recreate(struct xio_conn *conn);
static int xio_on_transport_event(void *observer, void *sender, int event,
				  void *event_data);
static void xio_on_conn_closed(struct xio_conn *conn,
			       union xio_transport_event_data *event_data);
static int xio_conn_flush_tx_queue(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_conn_server_reconnect		                                     */
/*---------------------------------------------------------------------------*/
static int xio_conn_server_reconnect(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_conn_client_reconnect						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_client_reconnect(struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_conn_client_reconnect_timeout					     */
/*---------------------------------------------------------------------------*/
static void xio_conn_client_reconnect_failed(void *data);

static void xio_conn_cancel_dwork(struct xio_conn *conn)
{
	if (xio_is_delayed_work_pending(&conn->close_time_hndl)) {
		xio_ctx_del_delayed_work(conn->transport_hndl->ctx,
					 &conn->close_time_hndl);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_free_conn							     */
/*---------------------------------------------------------------------------*/
static inline void xio_conn_free_conn(struct xio_conn *conn)
{
	if (!conn)
		return;

	kfree(conn->portal_uri);
	conn->portal_uri = NULL;

	kfree(conn->out_if_addr);
	conn->out_if_addr = NULL;

	kfree(conn);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_init_observers_htbl						     */
/*---------------------------------------------------------------------------*/
static inline void xio_conn_init_observers_htbl(struct xio_conn *conn)
{
	INIT_LIST_HEAD(&conn->observers_htbl);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_free_observers_htbl						     */
/*---------------------------------------------------------------------------*/
static void xio_conn_free_observers_htbl(struct xio_conn *conn)
{
	struct xio_observers_htbl_node	*node, *next_node;

	list_for_each_entry_safe(node, next_node,
				 &conn->observers_htbl,
				 observers_htbl_node) {
		list_del(&node->observers_htbl_node);
		kfree(node);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_hash_observer						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_hash_observer(struct xio_conn *conn,
				  struct xio_observer *observer,
				  uint32_t id)
{
	struct xio_observers_htbl_node	*node;

	node = kcalloc(1, sizeof(*node), GFP_KERNEL);
	if (!node) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcalloc failed. %m\n");
		return -1;
	}
	node->observer	= observer;
	node->id	= id;

	list_add_tail(&node->observers_htbl_node,
		      &conn->observers_htbl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_unhash_observer						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_unhash_observer(struct xio_conn *conn,
				    struct xio_observer *observer)
{
	struct xio_observers_htbl_node	*node, *next_node;

	list_for_each_entry_safe(node, next_node,
				 &conn->observers_htbl,
				 observers_htbl_node) {
		if (node->observer == observer) {
			list_del(&node->observers_htbl_node);
			kfree(node);
			return 0;
		}
	}

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_observer_lookup						     */
/*---------------------------------------------------------------------------*/
struct xio_observer *xio_conn_observer_lookup(struct xio_conn *conn,
					      uint32_t id)
{
	struct xio_observers_htbl_node	*node;

	list_for_each_entry(node,
			    &conn->observers_htbl,
			    observers_htbl_node) {
		if (node->id == id)
			return node->observer;
	}

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_reg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_conn_reg_observer(struct xio_conn *conn,
			   struct xio_observer *observer,
			   uint32_t oid)
{
	xio_observable_reg_observer(&conn->observable, observer);
	xio_conn_hash_observer(conn, observer, oid);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_unreg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_conn_unreg_observer(struct xio_conn *conn,
			     struct xio_observer *observer)
{
	xio_conn_unhash_observer(conn, observer);
	xio_observable_unreg_observer(&conn->observable, observer);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_get_primary_task						     */
/*---------------------------------------------------------------------------*/
inline struct xio_task *xio_conn_get_primary_task(struct xio_conn *conn)
{
	return  xio_tasks_pool_get(conn->primary_tasks_pool);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_task_lookup							     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_conn_task_lookup(void *conn, int id)
{
	return xio_tasks_pool_lookup(
			((struct xio_conn *)conn)->primary_tasks_pool, id);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_primary_free_tasks						     */
/*---------------------------------------------------------------------------*/
inline int xio_conn_primary_free_tasks(struct xio_conn *conn)
{
	return xio_tasks_pool_free_tasks(conn->primary_tasks_pool);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_notify_server		                                     */
/*---------------------------------------------------------------------------*/
static void xio_conn_notify_server(struct xio_conn *conn,
		int event, void *event_data)
{
	if (conn->server_observer)
		xio_observable_notify_observer(&conn->observable,
					       conn->server_observer,
					       event, event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_write_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_write_setup_req(struct xio_task *task,
		struct xio_conn_setup_req *req)
{
	struct xio_conn_setup_req *tmp_req;

	 /* reset the whole mbuf before building a message */
	 xio_mbuf_reset(&task->mbuf);

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return -1;

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

	tmp_req = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* fill request */
	PACK_SVAL(req, tmp_req, version);
	PACK_SVAL(req, tmp_req, flags);
	PACK_LVAL(req, tmp_req, cid);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_conn_setup_req));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_read_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_read_setup_req(struct xio_task *task,
		struct xio_conn_setup_req *req)
{
	struct xio_conn_setup_req *tmp_req;

	 /* reset the whole mbuf before building a message */
	 xio_mbuf_reset(&task->mbuf);

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return -1;

	tmp_req = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* fill request */
	UNPACK_SVAL(tmp_req, req, version);
	UNPACK_SVAL(tmp_req, req, flags);
	UNPACK_LVAL(tmp_req, req, cid);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_conn_setup_req));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_write_setup_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_write_setup_rsp(struct xio_task *task,
		struct xio_conn_setup_rsp *rsp)
{
	struct xio_conn_setup_rsp *tmp_rsp;

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return -1;

	tmp_rsp = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* fill request */
	PACK_LVAL(rsp, tmp_rsp, cid);
	PACK_LVAL(rsp, tmp_rsp, status);
	PACK_SVAL(rsp, tmp_rsp, version);
	PACK_SVAL(rsp, tmp_rsp, flags);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_conn_setup_rsp));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_read_setup_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_read_setup_rsp(struct xio_task *task,
		struct xio_conn_setup_rsp *rsp)
{
	struct xio_conn_setup_rsp *tmp_rsp;

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return -1;

	tmp_rsp = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* fill request */
	UNPACK_LVAL(tmp_rsp, rsp, cid);
	UNPACK_LVAL(tmp_rsp, rsp, status);
	UNPACK_SVAL(tmp_rsp, rsp, version);
	UNPACK_SVAL(tmp_rsp, rsp, flags);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_conn_setup_rsp));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_send_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_send_setup_req(struct xio_conn *conn)
{
	struct xio_task	*task;
	struct xio_conn_setup_req req = {0};
	int    retval = 0;

	TRACE_LOG("send setup request\n");

	if (conn->transport->send == NULL) {
		ERROR_LOG("transport does not implement \"send\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}

	task =  xio_tasks_pool_get(conn->initial_tasks_pool);
	if (task == NULL) {
		ERROR_LOG("initial task pool is empty\n");
		return -1;
	}
	task->tlv_type = XIO_CONN_SETUP_REQ;

	req.version = XIO_VERSION;
	retval = xio_conn_write_setup_req(task, &req);
	if (retval)
		goto cleanup;


	/* always add it to the top */
	list_add(&task->tasks_list_entry, &conn->tx_queue);
	retval = conn->transport->send(conn->transport_hndl, task);
	if (retval != 0) {
		ERROR_LOG("send setup request failed\n");
		xio_tasks_pool_put(task);
		return -1;
	}

	return 0;

cleanup:
	xio_tasks_pool_put(task);
	xio_set_error(XIO_E_MSG_INVALID);
	ERROR_LOG("receiving setup request failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_swap						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_swap(struct xio_conn *old, struct xio_conn *new)
{
	struct xio_transport		*transport;

	if (old->transport != new->transport) {
		ERROR_LOG("can't swap not the same transport\n");
		return -1;
	}

	transport = old->transport;

	if (!transport->dup2) {
		ERROR_LOG("transport doesn't support dup2\n");
		return -ENOSYS;
	}

	/* SWAP observers */
	/* disconnect observers */
	xio_observable_unreg_observer(
			&new->transport_hndl->observable,
			&new->trans_observer);

	xio_observable_unreg_observer(
			&old->transport_hndl->observable,
			&old->trans_observer);

	/* reconnect observers (swapped) */
	xio_observable_reg_observer(
			&new->transport_hndl->observable,
			&old->trans_observer);

	xio_observable_reg_observer(
			&old->transport_hndl->observable,
			&new->trans_observer);

	xio_tasks_pool_remap(old->primary_tasks_pool, new->transport_hndl);
	/* make old_conn->transport_hndl copy of new_conn->transport_hndl
	 * old_conn->trasport_hndl will be closed, note that observers were
	 * swapped
	 */
	if (transport->dup2(new->transport_hndl, &old->transport_hndl)) {
		ERROR_LOG("dup2 transport failed\n");
		return -1;
	}

	/* silently close new_conn */
	xio_conn_close(new, NULL);

	/* TODO what about messages held by the application */

	/* be ready to receive messages */
	if (xio_conn_primary_pool_recreate(old)) {
		ERROR_LOG("recreate primary pool failed\n");
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_on_recv_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_on_recv_setup_req(struct xio_conn *new_conn,
				      struct xio_task *task)
{
	struct xio_conn_setup_req req;
	struct xio_conn_setup_rsp rsp;
	struct xio_conn *conn;
	uint32_t status = 0;
	uint32_t cid;
	int      retval = 0;
	uint16_t flags = 0;

	TRACE_LOG("receiving setup request\n");
	retval = xio_conn_read_setup_req(task, &req);
	if (retval != 0)
		goto cleanup;

	/* verify version */
	if (req.version != XIO_VERSION) {
		ERROR_LOG("client invalid version.cver:0x%x, sver::0x%x\n",
			  req.version, XIO_VERSION);
		xio_set_error(XIO_E_INVALID_VERSION);
		return -1;
	}

	/* by default conn is the new conn */
	conn = new_conn;
	if (req.flags & XIO_RECONNECT) {
		struct xio_conn *dis_conn;
		/* Server side reconnect strategy, use new transport with the
		 * old connection
		 */
		cid = req.cid;
		dis_conn = xio_conns_store_lookup(cid);
		if (dis_conn) {
			/* stop timer */
			xio_conn_cancel_dwork(dis_conn);
			retval = xio_conn_swap(dis_conn, new_conn);
			if (retval != 0) {
				ERROR_LOG("swap conn failed\n");
				return -1;
			}
			/* retransmission will start after setup response is
			 * transmitted - xio_conn_on_send_setup_rsp_comp
			 */
		} else {
			flags = XIO_CID;
			status = -1;
		}
	} else {
		cid = conn->cid;
		/* time to prepare the primary pool */
		retval = xio_conn_primary_pool_create(conn);
		if (retval != 0) {
			ERROR_LOG("create primary pool failed\n");
			return -1;
		}
	}

	/* reset mbuf */
	xio_mbuf_reset(&task->mbuf);

	/* write response */
	task->tlv_type	= XIO_CONN_SETUP_RSP;

	rsp.cid		= cid;
	rsp.status	= status;
	rsp.version	= XIO_VERSION;
	rsp.flags	= flags;

	TRACE_LOG("send setup response\n");

	retval = xio_conn_write_setup_rsp(task, &rsp);
	if (retval != 0)
		goto cleanup;

	/* send it */
	list_move(&task->tasks_list_entry, &conn->tx_queue);
	retval = conn->transport->send(conn->transport_hndl, task);
	if (retval != 0) {
		ERROR_LOG("send setup respone failed\n");
		return -1;
	}

	return 0;

cleanup:
	xio_set_error(XIO_E_MSG_INVALID);
	ERROR_LOG("receiving setup request failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_on_recv_setup_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_on_recv_setup_rsp(struct xio_conn *conn,
				      struct xio_task *task)
{
	struct xio_conn_setup_rsp	rsp;
	int				retval;

	TRACE_LOG("receiving setup response\n");
	retval = xio_conn_read_setup_rsp(task, &rsp);
	if (retval != 0)
		goto cleanup;

	if (rsp.status) {
		xio_set_error(rsp.status);
		ERROR_LOG("remote peer reported status %d - [%s]\n",
			  rsp.status, xio_strerror(rsp.status));
		if (rsp.flags & XIO_CID) {
			/* reconnection is impossible since remote
			 * CID was not found on server side
			 */
			/* Stop timer */
			xio_conn_cancel_dwork(conn);
			/* Kill conn */
			conn->state = XIO_CONN_STATE_DISCONNECTED;
			TRACE_LOG("conn state changed to disconnected\n");
			xio_observable_notify_all_observers(&conn->observable,
							    XIO_CONN_EVENT_DISCONNECTED,
							    NULL);
		}
		return -1;
	}
	if (rsp.version != XIO_VERSION) {
		xio_set_error(XIO_E_INVALID_VERSION);
		ERROR_LOG("client invalid version.cver:0x%x, sver::0x%x\n",
			  XIO_VERSION, rsp.version);
		return -1;
	}

	/* recycle the tasks */
	xio_tasks_pool_put(task->sender_task);
	task->sender_task = NULL;
	xio_tasks_pool_put(task);

	if (conn->state != XIO_CONN_STATE_RECONNECT) {
		/* create the primary */
		retval = xio_conn_primary_pool_create(conn);
		if (retval != 0) {
			ERROR_LOG("create primary pool failed\n");
			return -1;
		}
		conn->state = XIO_CONN_STATE_CONNECTED;

		xio_observable_notify_all_observers(&conn->observable,
						    XIO_CONN_EVENT_ESTABLISHED,
						    NULL);
		/* remember server cid for reconnect */
		conn->server_cid = rsp.cid;
	} else {
		/* Stop reconnect timer */
		xio_conn_cancel_dwork(conn);

		/* ignore close event on transport_hndl (part of dup2) */
		xio_observable_unreg_observer(&conn->transport_hndl->observable,
					      &conn->trans_observer);

		/* conn is an observer of the new transport (see open API)
		 * no need to register
		 */
		xio_tasks_pool_remap(conn->primary_tasks_pool,
				     conn->new_transport_hndl);
		/* make conn->transport_hndl copy of conn->new_transport_hndl
		 * old conn->trasport_hndl will be closed
		 */
		if (conn->transport->dup2(conn->new_transport_hndl,
					  &conn->transport_hndl)) {
			ERROR_LOG("dup2 transport failed\n");
			return -1;
		}

		/* new_transport_hndl was "duplicated" on transport_hndl
		 * thus we need to consume one reference count
		 */
		conn->transport->close(conn->new_transport_hndl);
		conn->new_transport_hndl = NULL;

		/* TODO: what about messages held by the application */
		/* be ready to receive messages */
		retval = xio_conn_primary_pool_recreate(conn);
		if (retval != 0) {
			ERROR_LOG("recreate primary pool failed\n");
			return -1;
		}
		conn->state = XIO_CONN_STATE_CONNECTED;

		/* Tell session to re-initiate transmission */
		xio_observable_notify_all_observers(&conn->observable,
						    XIO_CONN_EVENT_RECONNECTED,
						    NULL);
	}

	return 0;
cleanup:
	xio_set_error(XIO_E_MSG_INVALID);
	ERROR_LOG("receiving setup request failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_on_send_setup_rsp_comp					     */
/*---------------------------------------------------------------------------*/
static int xio_conn_on_send_setup_rsp_comp(struct xio_conn *conn,
					   struct xio_task *task)
{
	enum xio_conn_event conn_event;

	if (conn->state == XIO_CONN_STATE_RECONNECT)
		/* Tell session to re-initiate transmission */
		conn_event = XIO_CONN_EVENT_RECONNECTED;
	else
		conn_event = XIO_CONN_EVENT_ESTABLISHED;

	/* Set new state */
	conn->state = XIO_CONN_STATE_CONNECTED;
	xio_observable_notify_all_observers(&conn->observable,
					    conn_event,
					    NULL);

	/* recycle the task */
	xio_tasks_pool_put(task);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_on_recv_req							     */
/*---------------------------------------------------------------------------*/
static int xio_conn_on_recv_req(struct xio_conn *conn,
				struct xio_task *task)
{
	union xio_conn_event_data conn_event_data;

	task->conn = conn;
	conn_event_data.msg.task = task;
	conn_event_data.msg.op = XIO_WC_OP_RECV;


	if (!conn->transport_hndl->is_client) {
		if (task->tlv_type == XIO_SESSION_SETUP_REQ) {
			/* add reference count to opened connection that new
			 * session is join in */
			if (!conn->is_first_req)
				xio_conn_addref(conn);
			else
				conn->is_first_req = 0;

			/* always route "hello" to server */
			xio_conn_notify_server(
					conn,
					XIO_CONN_EVENT_NEW_MESSAGE,
					&conn_event_data);
			return 0;
		} else if (task->tlv_type == XIO_CONNECTION_HELLO_REQ) {
			if (!conn->is_first_req)
				xio_conn_addref(conn);
			else
				conn->is_first_req = 0;

			/* always route "hello" to server */
			xio_conn_notify_server(
					conn,
					XIO_CONN_EVENT_NEW_MESSAGE,
					&conn_event_data);
			return 0;
		}
	}

	/* route the message to any of observer */
	xio_observable_notify_any_observer(
			&conn->observable,
			XIO_CONN_EVENT_NEW_MESSAGE,
			&conn_event_data);

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_conn_on_recv_rsp							     */
/*---------------------------------------------------------------------------*/
static int xio_conn_on_recv_rsp(struct xio_conn *conn,
				struct xio_task *task)
{
	union xio_conn_event_data conn_event_data;

	task->conn = conn;
	conn_event_data.msg.task = task;
	conn_event_data.msg.op = XIO_WC_OP_RECV;

	if (likely(task->sender_task)) {
		/* route the response to the sender session */
		xio_observable_notify_observer(
				&conn->observable,
				&task->sender_task->session->observer,
				XIO_CONN_EVENT_NEW_MESSAGE,
				&conn_event_data);
	} else {
		/* route the message to any of observer */
		xio_observable_notify_any_observer(
			&conn->observable,
			XIO_CONN_EVENT_NEW_MESSAGE,
			&conn_event_data);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_on_send_msg_comp						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_on_send_msg_comp(struct xio_conn *conn,
				  struct xio_task *task)
{
	union xio_conn_event_data conn_event_data;

	conn_event_data.msg.task	= task;
	conn_event_data.msg.op		= XIO_WC_OP_SEND;


	xio_observable_notify_observer(
			&conn->observable,
			&task->session->observer,
			XIO_CONN_EVENT_SEND_COMPLETION,
			&conn_event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_initial_pool_create						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_initial_pool_create(struct xio_conn *conn)
{
	int				alloc_nr;
	int				start_nr;
	int				max_nr;
	int				task_dd_sz;
	int				slab_dd_sz;
	struct xio_tasks_pool_cls	pool_cls;
	struct xio_tasks_pool_params	params;

	if (conn->initial_pool_ops == NULL)
		return -1;

	if ((conn->initial_pool_ops->pool_get_params == NULL) ||
	    (conn->initial_pool_ops->slab_pre_create == NULL) ||
	    (conn->initial_pool_ops->slab_init_task == NULL) ||
	    (conn->initial_pool_ops->pool_post_create == NULL) ||
	    (conn->initial_pool_ops->slab_destroy == NULL))
		return -1;

	/* get pool properties from the transport */
	conn->initial_pool_ops->pool_get_params(conn->transport_hndl,
						&start_nr,
						&max_nr,
						&alloc_nr,
						&slab_dd_sz,
						&task_dd_sz);

	memset(&params, 0, sizeof(params));

	params.start_nr			   = start_nr;
	params.max_nr			   = max_nr;
	params.alloc_nr			   = alloc_nr;
	params.slab_dd_data_sz		   = slab_dd_sz;
	params.task_dd_data_sz		   = task_dd_sz;
	params.pool_hooks.context	   = conn->transport_hndl;
	params.pool_hooks.slab_pre_create  =
		(void *)conn->initial_pool_ops->slab_pre_create;
	params.pool_hooks.slab_post_create =
		(void *)conn->initial_pool_ops->slab_post_create;
	params.pool_hooks.slab_destroy	   =
		(void *)conn->initial_pool_ops->slab_destroy;
	params.pool_hooks.slab_init_task   =
		(void *)conn->initial_pool_ops->slab_init_task;
	params.pool_hooks.slab_uninit_task =
		(void *)conn->initial_pool_ops->slab_uninit_task;
	params.pool_hooks.slab_remap_task =
		(void *)conn->initial_pool_ops->slab_remap_task;
	params.pool_hooks.pool_pre_create  =
		(void *)conn->initial_pool_ops->pool_pre_create;
	params.pool_hooks.pool_post_create =
		(void *)conn->initial_pool_ops->pool_post_create;
	params.pool_hooks.pool_destroy	   =
		(void *)conn->initial_pool_ops->pool_destroy;
	params.pool_hooks.task_pre_put	   =
		(void *)conn->initial_pool_ops->task_pre_put;
	params.pool_hooks.task_post_get	   =
		(void *)conn->initial_pool_ops->task_post_get;

	/* set pool helpers to the transport */
	if (conn->transport->set_pools_cls) {
		pool_cls.pool		= NULL;
		pool_cls.task_get	= (void *)xio_tasks_pool_get;
		pool_cls.task_lookup	= (void *)xio_tasks_pool_lookup;
		pool_cls.task_put	= (void *)xio_tasks_pool_put;

		conn->transport->set_pools_cls(conn->transport_hndl,
					       &pool_cls,
					       NULL);
	}

	/* initialize the tasks pool */
	conn->initial_tasks_pool = xio_tasks_pool_create(&params);
	if (conn->initial_tasks_pool == NULL) {
		ERROR_LOG("xio_tasks_pool_create failed\n");
		goto cleanup;
	}

	return 0;

cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_initial_pool_free						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_initial_pool_free(struct xio_conn *conn)
{
	if (!conn->primary_tasks_pool)
		return -1;

	xio_tasks_pool_destroy(conn->initial_tasks_pool);

	return  0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_initial_pool_create						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_primary_pool_create(struct xio_conn *conn)
{
	int				alloc_nr;
	int				start_nr;
	int				max_nr;
	int				task_dd_sz;
	int				slab_dd_sz;
	struct xio_tasks_pool_cls	pool_cls;
	struct xio_tasks_pool_params	params;

	if (conn->primary_pool_ops == NULL)
		return -1;

	if ((conn->primary_pool_ops->pool_get_params == NULL) ||
	    (conn->primary_pool_ops->slab_pre_create == NULL) ||
	    (conn->primary_pool_ops->slab_init_task == NULL) ||
	    (conn->primary_pool_ops->pool_post_create == NULL) ||
	    (conn->primary_pool_ops->slab_destroy	== NULL))
		return -1;

	/* get pool properties from the transport */
	conn->primary_pool_ops->pool_get_params(conn->transport_hndl,
						&start_nr,
						&max_nr,
						&alloc_nr,
						&slab_dd_sz,
						&task_dd_sz);

	memset(&params, 0, sizeof(params));

	params.start_nr			   = start_nr;
	params.max_nr			   = max_nr;
	params.alloc_nr			   = alloc_nr;
	params.slab_dd_data_sz		   = slab_dd_sz;
	params.task_dd_data_sz		   = task_dd_sz;
	params.pool_hooks.context	   = conn->transport_hndl;
	params.pool_hooks.slab_pre_create  =
		(void *)conn->primary_pool_ops->slab_pre_create;
	params.pool_hooks.slab_post_create =
		(void *)conn->primary_pool_ops->slab_post_create;
	params.pool_hooks.slab_destroy	   =
		(void *)conn->primary_pool_ops->slab_destroy;
	params.pool_hooks.slab_init_task   =
		(void *)conn->primary_pool_ops->slab_init_task;
	params.pool_hooks.slab_uninit_task =
		(void *)conn->primary_pool_ops->slab_uninit_task;
	params.pool_hooks.slab_remap_task =
		(void *)conn->primary_pool_ops->slab_remap_task;
	params.pool_hooks.pool_pre_create =
		(void *)conn->primary_pool_ops->pool_pre_create;
	params.pool_hooks.pool_post_create =
		(void *)conn->primary_pool_ops->pool_post_create;
	params.pool_hooks.pool_destroy =
		(void *)conn->primary_pool_ops->pool_destroy;
	params.pool_hooks.task_pre_put	   =
		(void *)conn->primary_pool_ops->task_pre_put;
	params.pool_hooks.task_post_get	   =
		(void *)conn->primary_pool_ops->task_post_get;

	/* set pool helpers to the transport */
	if (conn->transport->set_pools_cls) {
		pool_cls.pool		= NULL;
		pool_cls.task_get	= (void *)xio_tasks_pool_get;
		pool_cls.task_lookup	= (void *)xio_tasks_pool_lookup;
		pool_cls.task_put	= xio_tasks_pool_put;

		conn->transport->set_pools_cls(conn->transport_hndl,
					       NULL,
					       &pool_cls);
	}

	/* initialize the tasks pool */
	conn->primary_tasks_pool = xio_tasks_pool_create(&params);
	if (conn->primary_tasks_pool == NULL) {
		ERROR_LOG("xio_tasks_pool_create failed\n");
		goto cleanup;
	}

	return 0;

cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_primary_pool_recreate					     */
/*---------------------------------------------------------------------------*/
static int xio_conn_primary_pool_recreate(struct xio_conn *conn)
{
	if (conn->primary_pool_ops == NULL)
		return -1;

	if (conn->primary_tasks_pool == NULL)
		return -1;

	/* Equivalent to old xio_rdma_primary_pool_run,
	 * will call xio_rdma_rearm_rq
	 */
	if (conn->primary_pool_ops->pool_post_create)
		conn->primary_pool_ops->pool_post_create(
				conn->transport_hndl,
				conn->primary_tasks_pool,
				conn->primary_tasks_pool->dd_data);


	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_primary_pool_destroy					     */
/*---------------------------------------------------------------------------*/
static int xio_conn_primary_pool_destroy(struct xio_conn *conn)
{
	if (!conn->primary_tasks_pool)
		return -1;

	xio_tasks_pool_destroy(conn->primary_tasks_pool);
	return  0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_release_cb							     */
/*---------------------------------------------------------------------------*/
static void xio_conn_release_cb(void *data)
{
	struct xio_conn *conn = data;

	TRACE_LOG("physical connection close. conn:%p rdma_hndl:%p\n",
		  conn, conn->transport_hndl);

	if (!conn->is_listener)
		xio_conns_store_remove(conn->cid);

	if (conn->state != XIO_CONN_STATE_DISCONNECTED) {
		conn->state = XIO_CONN_STATE_CLOSED;
		TRACE_LOG("conn state changed to closed\n");
	}

	/* now it is zero */
	if (conn->transport->close)
		conn->transport->close(conn->transport_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_release							     */
/*---------------------------------------------------------------------------*/
static void xio_conn_release(void *data)
{
	struct xio_conn *conn = data;

	TRACE_LOG("physical connection close. conn:%p rdma_hndl:%p\n",
		  conn, conn->transport_hndl);

	if (xio_is_delayed_work_pending(&conn->close_time_hndl)) {
		xio_ctx_del_delayed_work(conn->transport_hndl->ctx,
					 &conn->close_time_hndl);
	}

	xio_conn_release_cb(data);
}

/*---------------------------------------------------------------------------*/
/* xio_on_context_close							     */
/*---------------------------------------------------------------------------*/
static void xio_on_context_close(struct xio_conn *conn,
				 struct xio_context *ctx)
{
	TRACE_LOG("xio_on_context_close. conn:%p, ctx:%p\n", conn, ctx);

	/* remove the conn from table */
	xio_conns_store_remove(conn->cid);

	if (xio_is_delayed_work_pending(&conn->close_time_hndl)) {
		xio_ctx_del_delayed_work(ctx,
					 &conn->close_time_hndl);
	}

	/* shut down the context and its dependent without waiting */
	if (conn->transport->context_shutdown)
		conn->transport->context_shutdown(conn->transport_hndl, ctx);

	/* at that stage the conn->transport_hndl no longer exist */
	conn->transport_hndl = NULL;

	/* close the connection */
	xio_on_conn_closed(conn, NULL);
}

/*---------------------------------------------------------------------------*/
/* xio_on_context_event							     */
/*---------------------------------------------------------------------------*/
static int xio_on_context_event(void *observer,
			    void *sender, int event, void *event_data)
{
	TRACE_LOG("xio_on_context_event\n");
	if (event == XIO_CONTEXT_EVENT_CLOSE) {
		TRACE_LOG("context: [close] ctx:%p\n", sender);
		xio_on_context_close(observer, sender);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_create							     */
/*---------------------------------------------------------------------------*/
struct xio_conn *xio_conn_create(struct xio_conn *parent_conn,
				 struct xio_transport_base *transport_hndl)
{
	struct xio_conn		*conn;
	int			retval;


	if (parent_conn->transport_hndl->is_client)
		return NULL;

	/* allocate connection */
	conn = kcalloc(1, sizeof(struct xio_conn), GFP_KERNEL);
	if (!conn) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcalloc failed. %m\n");
		return NULL;
	}

	XIO_OBSERVER_INIT(&conn->trans_observer, conn,
			  xio_on_transport_event);

	XIO_OBSERVABLE_INIT(&conn->observable, conn);

	xio_conn_init_observers_htbl(conn);

	/* start listen to context events */
	XIO_OBSERVER_INIT(&conn->ctx_observer, conn,
			  xio_on_context_event);

	INIT_LIST_HEAD(&conn->tx_queue);

	xio_context_reg_observer(transport_hndl->ctx, &conn->ctx_observer);


	/* add the connection to temporary list */
	conn->transport_hndl		= transport_hndl;
	conn->transport			= parent_conn->transport;
	kref_init(&conn->kref);
	conn->state			= XIO_CONN_STATE_OPEN;
	conn->is_first_req		= 1;

	xio_conns_store_add(conn, &conn->cid);

	/* add  the new connection as observer to transport */
	xio_transport_reg_observer(conn->transport_hndl,
				   &conn->trans_observer);

	if (conn->transport->get_pools_setup_ops) {
		conn->transport->get_pools_setup_ops(conn->transport_hndl,
						     &conn->initial_pool_ops,
						     &conn->primary_pool_ops);
	} else {
		ERROR_LOG("transport does not implement \"add_observer\"\n");
		goto cleanup;
	}

	retval = xio_conn_initial_pool_create(conn);
	if (retval != 0) {
		ERROR_LOG("failed to setup initial pool\n");
		goto cleanup;
	}

	TRACE_LOG("conn: [new] ptr:%p, transport_hndl:%p\n", conn,
		  conn->transport_hndl);

	return conn;

cleanup:
	xio_on_conn_closed(conn, NULL);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_on_message_error							     */
/*---------------------------------------------------------------------------*/
static void xio_on_message_error(struct xio_conn *conn,
				 union xio_transport_event_data *event_data)
{
	union xio_conn_event_data	conn_event_data;

	conn_event_data.msg_error.reason =  event_data->msg_error.reason;
	conn_event_data.msg_error.task	=  event_data->msg_error.task;

	xio_observable_notify_any_observer(&conn->observable,
					   XIO_CONN_EVENT_MESSAGE_ERROR,
					   &conn_event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_on_new_connection		                                     */
/*---------------------------------------------------------------------------*/
static void xio_on_new_connection(struct xio_conn *conn,
				  union xio_transport_event_data *event_data)
{
	union xio_conn_event_data	conn_event_data;
	struct xio_conn			*child_conn;

	child_conn = xio_conn_create(
			conn,
			event_data->new_connection.child_trans_hndl);

	conn_event_data.new_connection.child_conn = child_conn;
	if (child_conn == NULL) {
		ERROR_LOG("failed to create child connection\n");
		goto exit;
	}

	/* notify of new child to server */
	xio_conn_notify_server(
			conn,
			XIO_CONN_EVENT_NEW_CONNECTION,
			&conn_event_data);

	return;
exit:
	xio_conn_notify_server(
			conn,
			XIO_CONN_EVENT_ERROR,
			&conn_event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_on_conn_closed							     */
/*---------------------------------------------------------------------------*/
static void xio_on_conn_closed(struct xio_conn *conn,
			       union xio_transport_event_data *
			       event_data)
{
	TRACE_LOG("conn:%p - close complete\n", conn);

	if (conn->transport_hndl)
		xio_transport_unreg_observer(conn->transport_hndl,
					     &conn->trans_observer);

	xio_conn_free_observers_htbl(conn);
	xio_observable_unreg_all_observers(&conn->observable);

	if (xio_is_delayed_work_pending(&conn->close_time_hndl)) {
		if (conn->transport_hndl)
			xio_ctx_del_delayed_work(
					conn->transport_hndl->ctx,
					&conn->close_time_hndl);
	}
	xio_conn_flush_tx_queue(conn);

	xio_conn_initial_pool_free(conn);

	xio_conn_primary_free_tasks(conn);
	xio_conn_primary_pool_destroy(conn);

	xio_conns_store_remove(conn->cid);

	if (conn->transport_hndl)
		xio_context_unreg_observer(conn->transport_hndl->ctx,
					   &conn->ctx_observer);

	xio_conn_free_conn(conn);
}


/*---------------------------------------------------------------------------*/
/* xio_on_transport_error		                                     */
/*---------------------------------------------------------------------------*/
static void xio_on_transport_error(struct xio_conn *conn,
				   union xio_transport_event_data *event_data)
{
	union xio_conn_event_data conn_event_data;

	conn_event_data.error.reason =  event_data->error.reason;

	xio_observable_notify_all_observers(&conn->observable,
					    XIO_CONN_EVENT_ERROR,
					    &conn_event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_on_connection_established		                             */
/*---------------------------------------------------------------------------*/
static void xio_on_connection_established(struct xio_conn *conn,
				    union xio_transport_event_data *
				    event_data)
{
	if (!conn->transport_hndl->is_client)
		return;

	xio_conn_initial_pool_create(conn);

	xio_conn_send_setup_req(conn);
}

/*---------------------------------------------------------------------------*/
/* xio_on_connection_disconnected		                             */
/*---------------------------------------------------------------------------*/
static void xio_on_connection_disconnected(struct xio_conn *conn,
					   union xio_transport_event_data *
					   event_data)
{
	int ret;
	int enable_reconnect = 0;

	/* Try to reconnect */
	if (enable_reconnect) {
		if (conn->transport_hndl->is_client)
			ret = xio_conn_client_reconnect(conn);
		else
			ret = xio_conn_server_reconnect(conn);

		if (!ret) {
			TRACE_LOG("reconnect attempt conn:%p\n", conn);
			return;
		}
	}

	/* Can't reconnect */

	conn->state = XIO_CONN_STATE_DISCONNECTED;
	TRACE_LOG("conn state changed to disconnected conn:%p\n", conn);

	if (!xio_observable_is_empty(&conn->observable)) {
		xio_observable_notify_all_observers(
				&conn->observable,
				XIO_CONN_EVENT_DISCONNECTED,
				&event_data);
	} else {
		xio_conn_release(conn);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_on_new_message				                             */
/*---------------------------------------------------------------------------*/
static int xio_on_new_message(struct xio_conn *conn,
				    union xio_transport_event_data
				    *event_data)
{
	int	retval = -1;
	struct xio_task	*task = event_data->msg.task;

	switch (task->tlv_type) {
	case XIO_CONN_SETUP_RSP:
		retval = xio_conn_on_recv_setup_rsp(conn, task);
		break;
	case XIO_CONN_SETUP_REQ:
		retval = xio_conn_on_recv_setup_req(conn, task);
		break;

	default:
		if (IS_REQUEST(task->tlv_type))
			retval = xio_conn_on_recv_req(conn, task);
		else
			retval = xio_conn_on_recv_rsp(conn, task);
		break;
	};

	if (retval != 0) {
		ERROR_LOG("failed to handle message. " \
			  "conn:%p tlv_type:%d op:%d\n",
			  conn, task->tlv_type, event_data->msg.op);
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_on_send_completion				                     */
/*---------------------------------------------------------------------------*/
static int xio_on_send_completion(struct xio_conn *conn,
				    union xio_transport_event_data
				    *event_data)
{
	int	retval = -1;
	struct xio_task	*task = event_data->msg.task;

	switch (task->tlv_type) {
	case XIO_CONN_SETUP_RSP:
		retval = xio_conn_on_send_setup_rsp_comp(conn, task);
		break;
	case XIO_CONN_SETUP_REQ:
		retval = 0;
		break;
	default:
		retval  = xio_conn_on_send_msg_comp(conn, task);
		break;
	};

	if (retval != 0) {
		ERROR_LOG("failed to handle message. " \
			  "conn:%p tlv_type:%d op:%d\n",
			  conn, task->tlv_type, event_data->msg.op);
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_on_assign_in_buf							     */
/*---------------------------------------------------------------------------*/
static int xio_on_assign_in_buf(struct xio_conn *conn,
				union xio_transport_event_data
				*event_data)
{
	int				retval = 0;
	struct xio_task			*task = event_data->msg.task;
	union xio_conn_event_data	conn_event_data;

	conn_event_data.assign_in_buf.task = event_data->msg.task;
	task->conn = conn;

	xio_observable_notify_any_observer(
			&conn->observable,
			XIO_CONN_EVENT_ASSIGN_IN_BUF,
			&conn_event_data);

	event_data->assign_in_buf.is_assigned =
		conn_event_data.assign_in_buf.is_assigned;

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_on_cancel_request						     */
/*---------------------------------------------------------------------------*/
static int xio_on_cancel_request(struct xio_conn *conn,
				 union xio_transport_event_data
				 *event_data)
{
	union xio_conn_event_data conn_event_data = {
		.cancel.ulp_msg		= event_data->cancel.ulp_msg,
		.cancel.ulp_msg_sz	= event_data->cancel.ulp_msg_sz,
		.cancel.task		= event_data->cancel.task,
		.cancel.result		= event_data->cancel.result,
	};

	/* route the message to any of the sessions */
	xio_observable_notify_any_observer(
			&conn->observable,
			XIO_CONN_EVENT_CANCEL_REQUEST,
			&conn_event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_assign_in_buf							     */
/*---------------------------------------------------------------------------*/
static int xio_on_cancel_response(struct xio_conn *conn,
				  union xio_transport_event_data
				  *event_data)
{
	union xio_conn_event_data conn_event_data = {
		.cancel.ulp_msg		= event_data->cancel.ulp_msg,
		.cancel.ulp_msg_sz	= event_data->cancel.ulp_msg_sz,
		.cancel.task		= event_data->cancel.task,
		.cancel.result		= event_data->cancel.result,
	};

	/* route the message to any of the sessions */
	xio_observable_notify_any_observer(
			&conn->observable,
			XIO_CONN_EVENT_CANCEL_RESPONSE,
			&conn_event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_on_transport_event		                                     */
/*---------------------------------------------------------------------------*/
static int xio_on_transport_event(void *observer, void *sender, int event,
				  void *event_data)
{
	struct xio_conn		*conn = observer;
	union xio_transport_event_data *ev_data = event_data;


	switch (event) {
	case XIO_TRANSPORT_NEW_MESSAGE:
/*
		TRACE_LOG("conn: [notification] - new message. " \
			 "conn:%p, transport:%p\n", observer, sender);
*/
		xio_on_new_message(conn, ev_data);
		break;
	case XIO_TRANSPORT_SEND_COMPLETION:
/*
		TRACE_LOG("conn: [notification] - send completion. " \
			 "conn:%p, transport:%p\n", observer, sender);
*/
		xio_on_send_completion(conn, ev_data);
		break;
	case XIO_TRANSPORT_ASSIGN_IN_BUF:
/*
		DEBUG_LOG("conn: [notification] - assign in buffer. " \
			 "conn:%p, transport:%p\n", observer, sender);
*/
		xio_on_assign_in_buf(conn, ev_data);
		break;
	case XIO_TRANSPORT_MESSAGE_ERROR:
		DEBUG_LOG("conn: [notification] - message error. " \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_message_error(conn, ev_data);
		break;
	case XIO_TRANSPORT_CANCEL_REQUEST:
		DEBUG_LOG("conn: [notification] - cancel request. " \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_cancel_request(conn, ev_data);
		break;
	case XIO_TRANSPORT_CANCEL_RESPONSE:
		DEBUG_LOG("conn: [notification] - cancel respnose. " \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_cancel_response(conn, ev_data);
		break;
	case XIO_TRANSPORT_NEW_CONNECTION:
		DEBUG_LOG("conn: [notification] - new transport. " \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_new_connection(conn, ev_data);
		break;
	case XIO_TRANSPORT_ESTABLISHED:
		DEBUG_LOG("conn: [notification] - transport established. " \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_connection_established(conn, ev_data);
		break;
	case XIO_TRANSPORT_DISCONNECTED:
		DEBUG_LOG("conn: [notification] - transport disconnected. "  \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_connection_disconnected(conn, ev_data);
		break;
	case XIO_TRANSPORT_CLOSED:
		DEBUG_LOG("conn: [notification] - transport closed. "  \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_conn_closed(conn, ev_data);
		break;
	case XIO_TRANSPORT_REFUSED:
		DEBUG_LOG("conn: [notification] - transport refused. " \
			 "conn:%p, transport:%p\n", observer, sender);
		if (conn->state == XIO_CONN_STATE_RECONNECT) {
			xio_conn_client_reconnect_failed(conn);
		} else {
			conn->state = XIO_CONN_STATE_DISCONNECTED;
			TRACE_LOG("conn state changed to disconnected\n");
			xio_observable_notify_all_observers(&conn->observable,
							    XIO_CONN_EVENT_REFUSED,
							    &event_data);
		}
		break;
	case XIO_TRANSPORT_ERROR:
		DEBUG_LOG("conn: [notification] - transport error. " \
			 "conn:%p, transport:%p\n", observer, sender);
		if (conn->state == XIO_CONN_STATE_RECONNECT)
			xio_conn_client_reconnect_failed(conn);
		else
			xio_on_transport_error(conn, ev_data);
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_open		                                             */
/*---------------------------------------------------------------------------*/
struct xio_conn *xio_conn_open(
		struct xio_context *ctx,
		const char *portal_uri,
		struct xio_observer  *observer,
		uint32_t oid)
{
	struct xio_transport		*transport;
	struct xio_conn			*conn;
	char				proto[8];


	/* look for opened connection */
	conn = xio_conns_store_find(ctx, portal_uri);
	if (conn != NULL) {
		if (observer) {
			xio_observable_reg_observer(&conn->observable,
						    observer);
			xio_conn_hash_observer(conn, observer, oid);
		}
		if (xio_is_delayed_work_pending(&conn->close_time_hndl)) {
			xio_ctx_del_delayed_work(ctx,
						 &conn->close_time_hndl);
			kref_init(&conn->kref);
		} else {
			xio_conn_addref(conn);
		}

		TRACE_LOG("conn: [addref] conn:%p, refcnt:%d\n", conn,
			  atomic_read(&conn->kref.refcount));

		return conn;
	}

	/* extract portal from uri */
	if (xio_uri_get_proto(portal_uri, proto, sizeof(proto)) != 0) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("parsing uri failed. uri: %s\n", portal_uri);
		return NULL;
	}
	/* get the transport's proto */
	transport = xio_get_transport(proto);
	if (transport == NULL) {
		ERROR_LOG("invalid protocol. proto: %s\n", proto);
		xio_set_error(XIO_E_ADDR_ERROR);
		return NULL;
	}

	if (transport->open == NULL) {
		ERROR_LOG("transport %s does not implement \"open\"\n",
			  proto);
		xio_set_error(ENOSYS);
		return NULL;
	}
	/* allocate connection */
	conn = kcalloc(1, sizeof(struct xio_conn), GFP_KERNEL);
	if (conn == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcalloc failed. %m\n");
		return NULL;
	}

	XIO_OBSERVER_INIT(&conn->trans_observer, conn, xio_on_transport_event);
	XIO_OBSERVABLE_INIT(&conn->observable, conn);
	INIT_LIST_HEAD(&conn->tx_queue);

	xio_conn_init_observers_htbl(conn);

	if (observer) {
		xio_observable_reg_observer(&conn->observable, observer);
		xio_conn_hash_observer(conn, observer, oid);
	}

	/* start listen to context events */
	XIO_OBSERVER_INIT(&conn->ctx_observer, conn,
			  xio_on_context_event);

	xio_context_reg_observer(ctx, &conn->ctx_observer);

	conn->transport_hndl = transport->open(transport, ctx,
					       &conn->trans_observer);
	if (conn->transport_hndl == NULL) {
		ERROR_LOG("transport open failed\n");
		goto cleanup;
	}
	conn->transport	= transport;
	kref_init(&conn->kref);
	conn->state = XIO_CONN_STATE_OPEN;

	if (conn->transport->get_pools_setup_ops) {
		conn->transport->get_pools_setup_ops(conn->transport_hndl,
						     &conn->initial_pool_ops,
						     &conn->primary_pool_ops);
	} else {
		ERROR_LOG("transport does not implement \"add_observer\"\n");
		goto cleanup;
	}

	xio_conns_store_add(conn, &conn->cid);

	TRACE_LOG("conn: [new] conn:%p, transport_hndl:%p\n", conn,
		  conn->transport_hndl);

	return conn;
cleanup:
	xio_on_conn_closed(conn, NULL);

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_reconnect		                                             */
/* client side reconnection						     */
/*---------------------------------------------------------------------------*/
int xio_conn_reconnect(struct xio_conn *conn)
{
	struct xio_transport *transport;
	struct xio_context *ctx;
	int retval;

	if (conn->state != XIO_CONN_STATE_RECONNECT) {
		xio_set_error(XIO_E_STATE);
		ERROR_LOG("reconnect not permitted in current state(%d)\n",
			  conn->state);
		return -1;
	}

	transport = conn->transport;
	ctx = conn->transport_hndl->ctx;

	conn->new_transport_hndl = transport->open(conn->transport, ctx,
						   &conn->trans_observer);

	if (conn->new_transport_hndl == NULL) {
		ERROR_LOG("transport open failed\n");
		return -1;
	}

	retval = transport->connect(conn->new_transport_hndl,
				    conn->portal_uri,
				    conn->out_if_addr);

	if (retval != 0) {
		/* ignore close notification */
		xio_observable_unreg_observer(
				&conn->new_transport_hndl->observable,
				&conn->trans_observer);

		transport->close(conn->new_transport_hndl);
		conn->new_transport_hndl = NULL;
		ERROR_LOG("transport reconnect failed\n");
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_connect		                                             */
/*---------------------------------------------------------------------------*/
int xio_conn_connect(struct xio_conn *conn,
		     const char	*portal_uri,
		     struct xio_observer *observer,
		     const char	*out_if)
{
	int retval;

	if (conn->transport->connect == NULL) {
		ERROR_LOG("transport does not implement \"connect\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}

	switch (conn->state) {
	case XIO_CONN_STATE_OPEN:
		/* for reconnect */
		conn->portal_uri = kstrdup(portal_uri, GFP_KERNEL);
		if (!conn->portal_uri) {
			ERROR_LOG("memory alloc failed\n");
			xio_set_error(ENOMEM);
			goto cleanup1;
		}
		if (out_if) {
			conn->out_if_addr  = kstrdup(out_if, GFP_KERNEL);
			if (!conn->out_if_addr) {
				ERROR_LOG("memory alloc failed\n");
				xio_set_error(ENOMEM);
				goto cleanup2;
			}
		}
		retval = conn->transport->connect(conn->transport_hndl,
						  portal_uri,
						  out_if);
		if (retval != 0) {
			ERROR_LOG("transport connect failed\n");
			goto cleanup3;
		}
		conn->state = XIO_CONN_STATE_CONNECTING;
		break;
	case XIO_CONN_STATE_CONNECTED:
		xio_conn_notify_observer(conn, observer,
					 XIO_CONN_EVENT_ESTABLISHED,
					 NULL);
		break;
	default:
		break;
	}

	return 0;

cleanup3:
	kfree(conn->out_if_addr);
	conn->out_if_addr = NULL;
cleanup2:
	kfree(conn->portal_uri);
	conn->portal_uri = NULL;
cleanup1:
	ERROR_LOG("transport connect failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_listen			                                     */
/*---------------------------------------------------------------------------*/
int xio_conn_listen(struct xio_conn *conn, const char *portal_uri,
		    uint16_t *src_port, int backlog)
{
	int retval;

	if (conn->transport->listen == NULL) {
		ERROR_LOG("transport does not implement \"listen\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}
	if (conn->state == XIO_CONN_STATE_OPEN) {
		/* do not hold the listener connection in storage */
		xio_conns_store_remove(conn->cid);
		retval = conn->transport->listen(conn->transport_hndl,
						 portal_uri, src_port,
						 backlog);
		if (retval != 0) {
			DEBUG_LOG("transport listen failed. uri:[%s]\n",
				  portal_uri);
			return -1;
		}
		conn->state = XIO_CONN_STATE_LISTEN;
		conn->is_listener = 1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_accept			                                     */
/*---------------------------------------------------------------------------*/
int xio_conn_accept(struct xio_conn *conn)
{
	int retval;

	if (conn->transport->accept == NULL) {
		ERROR_LOG("transport does not implement \"accept\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}
	if (conn->state == XIO_CONN_STATE_OPEN) {
		retval = conn->transport->accept(conn->transport_hndl);
		if (retval != 0) {
			ERROR_LOG("transport accept failed.\n");
			return -1;
		}
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_reject			                                     */
/*---------------------------------------------------------------------------*/
int xio_conn_reject(struct xio_conn *conn)
{
	int retval;

	if (conn->transport->reject == NULL) {
		ERROR_LOG("transport does not implement \"reject\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}
	if (conn->state == XIO_CONN_STATE_OPEN) {
		retval = conn->transport->reject(conn->transport_hndl);
		if (retval != 0) {
			ERROR_LOG("transport reject failed.\n");
			return -1;
		}
	}
	return 0;
}
/*---------------------------------------------------------------------------*/
/* xio_conn_delayed_close		                                     */
/*---------------------------------------------------------------------------*/
static void xio_conn_delayed_close(struct kref *kref)
{
	struct xio_conn *conn = container_of(kref,
					     struct xio_conn,
					     kref);
	int		retval;

	TRACE_LOG("xio_conn_deleyed close. conn:%p, state:%d\n",
		  conn, conn->state);

	switch (conn->state) {
	case XIO_CONN_STATE_LISTEN:
		/* the listener conn, called from xio_unbind */
	case XIO_CONN_STATE_DISCONNECTED:
		xio_conn_release(conn);
		break;
	default:
		retval = xio_ctx_add_delayed_work(
				conn->transport_hndl->ctx,
				XIO_CONN_CLOSE_TIMEOUT, conn,
				xio_conn_release_cb,
				&conn->close_time_hndl);
		if (retval)
			ERROR_LOG("xio_conn_delayed_close failed\n");
		break;
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_close		                                             */
/*---------------------------------------------------------------------------*/
void xio_conn_close(struct xio_conn *conn, struct xio_observer *observer)
{
	TRACE_LOG("conn: [putref] ptr:%p, refcnt:%d\n", conn,
		  atomic_read(&conn->kref.refcount));

	if (observer) {
		xio_conn_notify_observer(
				conn, observer,
				XIO_CONN_EVENT_CLOSED, NULL);

		xio_conn_unhash_observer(conn, observer);
		xio_conn_unreg_observer(conn, observer);
	}
	kref_put(&conn->kref, xio_conn_delayed_close);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_flush_tx_queue						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_flush_tx_queue(struct xio_conn *conn)
{
	struct xio_task *ptask, *next_ptask;

	list_for_each_entry_safe(ptask, next_ptask, &conn->tx_queue,
				 tasks_list_entry) {
		TRACE_LOG("flushing task %p type 0x%x\n",
			  ptask, ptask->tlv_type);
		if (ptask->sender_task) {
			xio_tasks_pool_put(ptask->sender_task);
			ptask->sender_task = NULL;
		}
		xio_tasks_pool_put(ptask);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_xmit							     */
/*---------------------------------------------------------------------------*/
static int xio_conn_xmit(struct xio_conn *conn)
{
	int		retval;
	struct xio_task *task;

	if (!conn->transport) {
		ERROR_LOG("transport not initialized\n");
		return -1;
	}
	if (!conn->transport->send)
		return 0;

	while (1) {

		if (list_empty(&conn->tx_queue))
			break;

		task = list_first_entry(&conn->tx_queue,
					struct xio_task,  tasks_list_entry);
		retval = conn->transport->send(conn->transport_hndl, task);
		if (retval != 0) {
			union xio_conn_event_data conn_event_data;

			if (xio_errno() == EAGAIN)
				return 0;

			ERROR_LOG("transport send failed err:%d\n",
				  xio_errno());
			conn_event_data.msg_error.reason = xio_errno();
			conn_event_data.msg_error.task	= task;

			xio_observable_notify_any_observer(
					&conn->observable,
					XIO_CONN_EVENT_MESSAGE_ERROR,
					&conn_event_data);
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_send							     */
/*---------------------------------------------------------------------------*/
int xio_conn_send(struct xio_conn *conn, struct xio_task *task)
{
	int		retval;

	if (!conn->transport) {
		ERROR_LOG("transport not initialized\n");
		return -1;
	}
	if (!conn->transport->send)
		return 0;

	/* push to end of the queue */
	list_move_tail(&task->tasks_list_entry, &conn->tx_queue);

	/* xmit it to the transport */
	retval = xio_conn_xmit(conn);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_poll							     */
/*---------------------------------------------------------------------------*/
int xio_conn_poll(struct xio_conn *conn, long min_nr, long nr,
		  struct timespec *timeout)
{
	int	retval = 0;

	if (conn->transport->poll) {
		retval = conn->transport->poll(conn->transport_hndl,
					       min_nr, nr, timeout);
		if (retval < 0) {
			ERROR_LOG("transport poll failed\n");
			return -1;
		}
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_set_opt							     */
/*---------------------------------------------------------------------------*/
int xio_conn_set_opt(struct xio_conn *conn, int optname,
		       const void *optval, int optlen)
{
	if (conn->transport->set_opt)
		return conn->transport->set_opt(conn->transport_hndl,
				optname, optval, optlen);

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_get_opt							     */
/*---------------------------------------------------------------------------*/
int xio_conn_get_opt(struct xio_conn *conn, int optname,
		       void *optval, int *optlen)
{
	if (conn->transport->get_opt)
		return conn->transport->get_opt(conn->transport_hndl,
				optname, optval, optlen);

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_get_src_addr						     */
/*---------------------------------------------------------------------------*/
int xio_conn_get_src_addr(struct xio_conn *conn,
			  struct sockaddr_storage *sa, socklen_t len)
{
	memcpy(sa, &conn->transport_hndl->peer_addr, len);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_cancel_req							     */
/*---------------------------------------------------------------------------*/
int xio_conn_cancel_req(struct xio_conn *conn,
			struct xio_msg *req, uint64_t stag,
			void *ulp_msg, size_t ulp_msg_sz)
{
	if (conn->transport->cancel_req)
		return conn->transport->cancel_req(conn->transport_hndl,
						   req, stag,
						   ulp_msg, ulp_msg_sz);

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_cancel_rsp							     */
/*---------------------------------------------------------------------------*/
int xio_conn_cancel_rsp(struct xio_conn *conn,
			struct xio_task *task, enum xio_status result,
			void *ulp_msg, size_t ulp_msg_sz)
{
	if (conn->transport->cancel_req)
		return conn->transport->cancel_rsp(conn->transport_hndl,
						   task, result,
						   ulp_msg, ulp_msg_sz);
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_server_reconnect_timeout					     */
/*---------------------------------------------------------------------------*/
static void xio_conn_server_reconnect_timeout(void *data)
{
	struct xio_conn *conn = data;

	/* No reconnect within timeout */
	conn->state = XIO_CONN_STATE_DISCONNECTED;
	TRACE_LOG("conn state changed to disconnected\n");
	xio_observable_notify_all_observers(&conn->observable,
					    XIO_CONN_EVENT_DISCONNECTED,
					    NULL);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_server_reconnect		                                     */
/*---------------------------------------------------------------------------*/
static int xio_conn_server_reconnect(struct xio_conn *conn)
{
	int		retval;

	if (conn->state != XIO_CONN_STATE_CONNECTED)
		return -1;

	xio_conn_state_set(conn, XIO_CONN_STATE_RECONNECT);

	/* Just wait and see if some client tries to reconnect */
	retval = xio_ctx_add_delayed_work(conn->transport_hndl->ctx,
					  XIO_SERVER_TIMEOUT, conn,
					  xio_conn_server_reconnect_timeout,
					  &conn->close_time_hndl);
	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_client_reconnect_timeout					     */
/*---------------------------------------------------------------------------*/
static void xio_conn_client_reconnect_timeout(void *data)
{
	struct xio_conn *conn = data;
	int retval;

	/* Try to reconnect after the waiting period */
	retval = xio_conn_reconnect(conn);
	if (!retval) {
		TRACE_LOG("reconnect succeed\n");
		return;
	}

	if (conn->reconnect_retries) {
		conn->reconnect_retries--;
		retval = xio_ctx_add_delayed_work(conn->transport_hndl->ctx,
					   xio_msecs[conn->reconnect_retries],
					   conn,
					   xio_conn_client_reconnect_timeout,
					   &conn->close_time_hndl);
	} else {
		/* retries number exceeded */
		conn->state = XIO_CONN_STATE_DISCONNECTED;
		TRACE_LOG("conn state changed to disconnected\n");
		xio_observable_notify_all_observers(&conn->observable,
						    XIO_CONN_EVENT_DISCONNECTED,
						    NULL);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_client_reconnect_failed					     */
/*---------------------------------------------------------------------------*/
static void xio_conn_client_reconnect_failed(void *data)
{
	struct xio_conn *conn = data;
	int retval;

	/* Failed to reconnect (connect was called) */
	if (conn->reconnect_retries) {
		conn->reconnect_retries--;
		retval = xio_ctx_add_delayed_work(conn->transport_hndl->ctx,
					   xio_msecs[conn->reconnect_retries],
					   conn,
					   xio_conn_client_reconnect_timeout,
					   &conn->close_time_hndl);
		if (retval)
			ERROR_LOG("adding delayed work failed\n");
	} else {
		/* retries number exceeded */
		conn->state = XIO_CONN_STATE_DISCONNECTED;
		TRACE_LOG("conn state changed to disconnected\n");
		xio_observable_notify_all_observers(&conn->observable,
						    XIO_CONN_EVENT_DISCONNECTED,
						    NULL);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_client_reconnect						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_client_reconnect(struct xio_conn *conn)
{
	/* With client we do an exponential back-off first delay is 0 */
	int		retval;

	if (conn->state != XIO_CONN_STATE_CONNECTED)
		return -1;

	if (conn->transport->dup2 == NULL)
		return -1;

	xio_conn_state_set(conn, XIO_CONN_STATE_RECONNECT);

	/* All portal_uri and out_if were saved in the conn
	 * observer is not used in this flow
	 */

	/* Three retries but vector start from 0 */
	conn->reconnect_retries = 3;
	/* Try to reconnect immediately
	 * Note connect may succeed but we may get a reject */
	retval = xio_conn_reconnect(conn);
	if (!retval)
		return 0;


	conn->reconnect_retries = 2;
	retval = xio_ctx_add_delayed_work(conn->transport_hndl->ctx,
					  xio_msecs[conn->reconnect_retries],
					  conn,
					  xio_conn_client_reconnect_timeout,
					  &conn->close_time_hndl);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_update_task							     */
/*---------------------------------------------------------------------------*/
int xio_conn_update_task(struct xio_conn *conn, struct xio_task *task)
{
	/* transport may not need to update tasks */
	if (conn->transport->update_task == NULL)
		return 0;

	if (conn->transport->update_task(conn->transport_hndl, task))
		return -1;

	return 0;
}
