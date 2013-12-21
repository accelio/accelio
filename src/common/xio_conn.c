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
/* private structs							     */
/*---------------------------------------------------------------------------*/
struct xio_observers_htbl_node {
	struct xio_observer	*observer;
	uint32_t		id;
	uint32_t		pad;
	struct list_head	observers_htbl_node;

};

/*---------------------------------------------------------------------------*/
/* forward declarations							     */
/*---------------------------------------------------------------------------*/
static int xio_conn_primary_pool_setup(struct xio_conn *conn);
static int xio_on_transport_event(void *observer, void *sender, int event,
				  void *event_data);
static void xio_on_conn_closed(struct xio_conn *conn,
			       union xio_transport_event_data *event_data);


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
	static struct xio_observers_htbl_node *last_node /*= NULL */;

	if (last_node && last_node->id == id)
		return last_node->observer;

	list_for_each_entry(node,
			    &conn->observers_htbl,
			    observers_htbl_node) {
		if (node->id == id) {
			last_node = node;
			return node->observer;
		}
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
/* xio_pre_put_task							     */
/*---------------------------------------------------------------------------*/
static void xio_pre_put_task(struct xio_task *task)
{
	task->imsg.user_context		= 0;
	task->imsg.in.header.iov_base	= NULL;
	task->imsg.in.header.iov_len	= 0;
	task->imsg.in.data_iovlen	= 0;
	task->imsg.flags		= 0;
	task->omsg			= NULL;
	task->tlv_type			= 0xdead;
	task->sender_task		= NULL;
	task->omsg_flags		= 0;
	task->state			= XIO_TASK_STATE_INIT;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_put_task							     */
/*---------------------------------------------------------------------------*/
static inline void xio_conn_put_task(struct kref *kref)
{
	struct xio_task *task = container_of(kref, struct xio_task, kref);
	struct xio_tasks_pool *pool;
	struct xio_tasks_pool_ops *pool_ops;

	assert(task->pool);

	pool = (struct xio_tasks_pool *)task->pool;

	assert(pool->pool_ops);

	pool_ops = (struct xio_tasks_pool_ops *)pool->pool_ops;

	if (pool_ops->pre_put)
		pool_ops->pre_put(task->conn->transport_hndl, task);

	xio_pre_put_task(task);

	pool->nr++;
	list_move(&task->tasks_list_entry, &pool->stack);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_get_initial_task						     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_conn_get_initial_task(void *pool_provider)
{
	struct xio_conn *conn = pool_provider;

	struct xio_task *task =  xio_tasks_pool_get(conn->initial_tasks_pool);

	if (conn->initial_pool_ops->post_get)
		conn->initial_pool_ops->post_get(conn->transport_hndl,
						task);

	return task;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_get_primary_task						     */
/*---------------------------------------------------------------------------*/
inline struct xio_task *xio_conn_get_primary_task(struct xio_conn *conn)
{
	struct xio_task *task =  xio_tasks_pool_get(conn->primary_tasks_pool);

	if (task == NULL)
		return NULL;

	if (conn->primary_pool_ops->post_get)
		conn->primary_pool_ops->post_get(conn->transport_hndl,
						 task);
	return task;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_primary_task_alloc						     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_conn_primary_task_alloc(void *conn)
{
	return xio_conn_get_primary_task((struct xio_conn *)conn);
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

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return -1;

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

	tmp_req = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* fill request */
	PACK_SVAL(req, tmp_req, version);

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

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return -1;

	tmp_req = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* fill request */
	UNPACK_SVAL(tmp_req, req, version);

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
	PACK_SVAL(rsp, tmp_rsp, cid);
	PACK_LVAL(rsp, tmp_rsp, status);
	PACK_SVAL(rsp, tmp_rsp, version);

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
	UNPACK_SVAL(tmp_rsp, rsp, cid);
	UNPACK_LVAL(tmp_rsp, rsp, status);
	UNPACK_SVAL(tmp_rsp, rsp, version);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_conn_setup_rsp));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_send_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_send_setup_req(struct xio_conn *conn)
{
	int			retval = 0;
	struct xio_task	*task;
	struct xio_conn_setup_req req;


	if (conn->transport->send == NULL) {
		ERROR_LOG("transport does not implement \"send\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}

	task = xio_conn_get_initial_task(conn);
	if (task == NULL) {
		ERROR_LOG("initial task pool is empty\n");
		return -1;
	}
	task->tlv_type = XIO_CONN_SETUP_REQ;

	req.version = XIO_VERSION;
	retval = xio_conn_write_setup_req(task, &req);
	if (retval)
		goto cleanup;


	/* send it */
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
/* xio_conn_on_recv_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_on_recv_setup_req(struct xio_conn *conn,
					struct xio_task *task)
{
	int			retval = 0;
	struct xio_conn_setup_req req;
	struct xio_conn_setup_rsp rsp;

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

	/* time to prepare the primary pool */
	retval = xio_conn_primary_pool_setup(conn);
	if (retval != 0) {
		ERROR_LOG("setup primary pool failed\n");
		return -1;
	}

	/* reset mbuf */
	xio_mbuf_reset(&task->mbuf);

	/* write response */
	task->tlv_type	= XIO_CONN_SETUP_RSP;

	rsp.cid		= conn->cid;
	rsp.status	= 0;
	rsp.version	= XIO_VERSION;

	retval = xio_conn_write_setup_rsp(task, &rsp);
	if (retval != 0)
		goto cleanup;

	/* send it */
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

	TRACE_LOG("receiving setup respnse\n");
	retval = xio_conn_read_setup_rsp(task, &rsp);
	if (retval != 0)
		goto cleanup;

	if (rsp.status) {
		xio_set_error(rsp.status);
		ERROR_LOG("remote peer reported status %d - [%s]\n",
			  rsp.status, xio_strerror(rsp.status));
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

	/* create the primary */
	retval = xio_conn_primary_pool_setup(conn);
	if (retval != 0) {
		ERROR_LOG("setup primary pool failed\n");
		return -1;
	}
	conn->state = XIO_CONN_STATE_CONNECTED;

	xio_observable_notify_all_observers(&conn->observable,
					    XIO_CONN_EVENT_ESTABLISHED, NULL);

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
	conn->state = XIO_CONN_STATE_CONNECTED;
	xio_observable_notify_all_observers(&conn->observable,
					    XIO_CONN_EVENT_ESTABLISHED, NULL);
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
			if (!conn->is_first_setup_req)
				xio_conn_addref(conn);
			else
				conn->is_first_setup_req = 0;

			/* always route "hello" to server */
			xio_conn_notify_server(
					conn,
					XIO_CONN_EVENT_NEW_MESSAGE,
					&conn_event_data);
			return 0;
		} else if (task->tlv_type == XIO_CONNECTION_HELLO_REQ) {
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
/* xio_conn_initial_pool_setup						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_initial_pool_setup(struct xio_conn *conn)
{
	int i;
	int num_tasks;
	int task_dd_sz;
	int pool_dd_sz;
	int retval;
	struct xio_tasks_pool_cls  pool_cls;

	if (conn->initial_pool_ops == NULL)
		return -1;

	if ((conn->initial_pool_ops->pool_get_params == NULL) ||
	    (conn->initial_pool_ops->pool_alloc == NULL) ||
	    (conn->initial_pool_ops->pool_init_item == NULL) ||
	    (conn->initial_pool_ops->pool_run == NULL) ||
	    (conn->initial_pool_ops->pool_free == NULL))
		return -1;

	/* get pool properties from the transport */
	conn->initial_pool_ops->pool_get_params(
				conn->transport_hndl,
				&num_tasks, &pool_dd_sz,
				&task_dd_sz);

	/* initialize the tasks pool */
	conn->initial_tasks_pool = xio_tasks_pool_init(
			num_tasks, pool_dd_sz, task_dd_sz,
				conn->initial_pool_ops);
	if (conn->initial_tasks_pool == NULL) {
		ERROR_LOG("xio_ tasks_pool_init failed\n");
		goto cleanup0;
	}

	/* allocate the pool */
	retval = conn->initial_pool_ops->pool_alloc(
				conn->transport_hndl,
				conn->initial_tasks_pool->max,
				conn->initial_tasks_pool->dd_data);
	if (retval != 0) {
		ERROR_LOG("initial_pool_alloc failed\n");
		goto cleanup1;
	}

	for (i = 0; i < conn->initial_tasks_pool->max; i++) {
		/* initialize each pool's item */
		retval = conn->initial_pool_ops->pool_init_item(
				conn->transport_hndl,
				conn->initial_tasks_pool->dd_data,
				conn->initial_tasks_pool->array[i]);
		if (retval != 0) {
			ERROR_LOG("initial_pool_init_item failed\n");
			goto cleanup;
		}
		conn->initial_tasks_pool->array[i]->release = xio_conn_put_task;
		conn->initial_tasks_pool->array[i]->conn = conn;
	}

	pool_cls.pool	     = conn;
	pool_cls.task_alloc  = xio_conn_get_initial_task;
	pool_cls.task_lookup = NULL;
	pool_cls.task_free   = xio_tasks_pool_put;

	if (conn->transport->set_pools_cls)
		conn->transport->set_pools_cls(conn->transport_hndl,
					       &pool_cls,
					       NULL);
	/* pool is ready for use */
	retval = conn->initial_pool_ops->pool_run(conn->transport_hndl);
	if (retval != 0) {
		ERROR_LOG("initial_pool_init failed\n");
		goto cleanup;
	}

	return 0;

cleanup:
	/* pool_free was checked above and it is not NULL */
	conn->initial_pool_ops->pool_free(conn->transport_hndl,
					  conn->initial_tasks_pool->dd_data);
cleanup1:
	xio_tasks_pool_free(conn->initial_tasks_pool);

cleanup0:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_initial_pool_free						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_initial_pool_free(struct xio_conn *conn)
{
	int retval = 0;

	if (conn->initial_tasks_pool == NULL)
		return 0;

	if (conn->initial_pool_ops->pool_free) {
		retval = conn->initial_pool_ops->pool_free(conn->transport_hndl,
					   conn->initial_tasks_pool->dd_data);
		if (retval != 0)
			ERROR_LOG("releasing initial pool failed\n");
	}
	xio_tasks_pool_free(conn->initial_tasks_pool);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_primary_pool_setup					     */
/*---------------------------------------------------------------------------*/
static int xio_conn_primary_pool_setup(struct xio_conn *conn)
{
	int i, retval;
	int num_tasks;
	int task_dd_sz;
	int pool_dd_sz;
	struct xio_tasks_pool_cls  pool_cls;

	if (conn->initial_pool_ops == NULL)
		return -1;

	if ((conn->primary_pool_ops->pool_get_params == NULL) ||
	    (conn->primary_pool_ops->pool_alloc == NULL) ||
	    (conn->primary_pool_ops->pool_init_item == NULL) ||
	    (conn->primary_pool_ops->pool_run == NULL) ||
	    (conn->primary_pool_ops->pool_free	== NULL))
		return -1;

	/* get pool properties from the transport */
	conn->primary_pool_ops->pool_get_params(conn->transport_hndl,
						 &num_tasks,
						 &pool_dd_sz,
						 &task_dd_sz);

	/* initialize the tasks pool */
	conn->primary_tasks_pool = xio_tasks_pool_init(
			num_tasks, pool_dd_sz, task_dd_sz,
			conn->primary_pool_ops);
	if (conn->primary_tasks_pool == NULL) {
		ERROR_LOG("xio_ tasks_pool_init failed\n");
		goto cleanup0;
	}

	/* allocate the pool */
	retval = conn->primary_pool_ops->pool_alloc(
				conn->transport_hndl,
				conn->primary_tasks_pool->max,
				conn->primary_tasks_pool->dd_data);

	if (retval != 0) {
		ERROR_LOG("primary_pool_alloc failed\n");
		goto cleanup1;
	}

	for (i = 0; i < conn->primary_tasks_pool->max; i++) {
		/* initialize each pool's item */
		retval = conn->primary_pool_ops->pool_init_item(
				conn->transport_hndl,
				conn->primary_tasks_pool->dd_data,
				conn->primary_tasks_pool->array[i]);
		if (retval != 0) {
			ERROR_LOG("primary_pool_init_item failed\n");
			goto cleanup;
		}
		conn->primary_tasks_pool->array[i]->release = xio_conn_put_task;
		conn->primary_tasks_pool->array[i]->conn = conn;
	}
	pool_cls.pool	     = conn;
	pool_cls.task_alloc  = xio_conn_primary_task_alloc;
	pool_cls.task_lookup = xio_conn_task_lookup;
	pool_cls.task_free   = xio_tasks_pool_put;

	if (conn->transport->set_pools_cls)
		conn->transport->set_pools_cls(conn->transport_hndl,
					       NULL,
					       &pool_cls);

	/* pool is ready for use */
	retval = conn->primary_pool_ops->pool_run(conn->transport_hndl);
	if (retval != 0) {
		ERROR_LOG("primary_pool_init failed\n");
		goto cleanup;
	}
	return 0;

cleanup:
	/* pool_free was checked above and it is not NULL */
	conn->primary_pool_ops->pool_free(conn->transport_hndl,
					  conn->primary_tasks_pool->dd_data);

cleanup1:
	xio_tasks_pool_free(conn->primary_tasks_pool);

cleanup0:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_primary_pool_free						     */
/*---------------------------------------------------------------------------*/
static int xio_conn_primary_pool_free(struct xio_conn *conn)
{
	int retval = 0;

	if (conn->primary_tasks_pool == NULL)
		return 0;

	if (conn->primary_pool_ops->pool_free) {
		retval = conn->primary_pool_ops->pool_free(conn->transport_hndl,
					   conn->primary_tasks_pool->dd_data);
		if (retval != 0)
			ERROR_LOG("releasing initial pool failed\n");
	}
	xio_tasks_pool_free(conn->primary_tasks_pool);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_release		                                             */
/*---------------------------------------------------------------------------*/
static void xio_conn_release(void *data)
{
	struct xio_conn *conn = data;

	TRACE_LOG("physical connection close. conn:%p\n", conn);

	if (conn->state != XIO_CONN_STATE_DISCONNECTED) {
		conn->state = XIO_CONN_STATE_CLOSED;
		TRACE_LOG("conn state changed to closed\n");
	}

	/* now it is zero */
	if (conn->transport->close)
		conn->transport->close(conn->transport_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_on_context_close							     */
/*---------------------------------------------------------------------------*/
static void xio_on_context_close(struct xio_conn *conn,
				 struct xio_context *ctx)
{
	TRACE_LOG("xio_on_context_close. conn:%p, ctx:%p\n", conn, ctx);

	/* shut down the context and its decendent without waiting */
	if (conn->transport->context_shutdown)
		conn->transport->context_shutdown(conn->transport, ctx);

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
/* xio_conn_create		                                             */
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

	xio_context_reg_observer(transport_hndl->ctx, &conn->ctx_observer);


	/* add the conection to temporary list */
	conn->transport_hndl		= transport_hndl;
	conn->transport			= parent_conn->transport;
	kref_init(&conn->kref);
	conn->state			= XIO_CONN_STATE_OPEN;
	conn->is_first_setup_req	= 1;

	xio_conns_store_add(conn, &conn->cid);

	/* add  the new cnnnection as oberver to transport */
	if (conn->transport->reg_observer) {
		conn->transport->reg_observer(conn->transport_hndl,
					      &conn->trans_observer);
	} else {
		ERROR_LOG("transport does not implement \"add_observer\"\n");
		return NULL;
	}

	if (conn->transport->get_pools_setup_ops) {
		conn->transport->get_pools_setup_ops(conn->transport_hndl,
						     &conn->initial_pool_ops,
						     &conn->primary_pool_ops);
	} else {
		ERROR_LOG("transport does not implement \"add_observer\"\n");
		return NULL;
	}

	retval = xio_conn_initial_pool_setup(conn);
	if (retval != 0) {
		ERROR_LOG("failed to setup initial pool\n");
		goto cleanup;
	}

	TRACE_LOG("conn: [new] ptr:%p, transport_hndl:%p\n", conn,
		  conn->transport_hndl);

	return conn;

cleanup:
	kfree(conn);
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
	if (child_conn == NULL) {
		ERROR_LOG("failed to create child connection\n");
		goto exit;
	}

	/* notify of new child to server */
	conn_event_data.new_connection.child_conn = child_conn;

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

	xio_conn_reject(child_conn);
	xio_conn_close(child_conn, NULL);
}

/*---------------------------------------------------------------------------*/
/* xio_on_conn_closed							     */
/*---------------------------------------------------------------------------*/
static void xio_on_conn_closed(struct xio_conn *conn,
			       union xio_transport_event_data *
			       event_data)
{
	TRACE_LOG("conn:%p - close complete\n", conn);

	if (conn->transport->unreg_observer && conn->transport_hndl) {
		conn->transport->unreg_observer(conn->transport_hndl,
						&conn->trans_observer);
	}
	xio_conn_free_observers_htbl(conn);
	xio_observable_unreg_all_observers(&conn->observable);

	xio_conns_store_remove(conn->cid);

	xio_conn_initial_pool_free(conn);

	xio_conn_primary_free_tasks(conn);
	xio_conn_primary_pool_free(conn);

	if (conn->transport_hndl)
		xio_context_unreg_observer(conn->transport_hndl->ctx,
					   &conn->ctx_observer);

	kfree(conn);
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

	xio_conn_initial_pool_setup(conn);

	xio_conn_send_setup_req(conn);
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
		DEBUG_LOG("conn: [notification] - assign in buffer. " \
			 "conn:%p, transport:%p\n", observer, sender);
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
		conn->state = XIO_CONN_STATE_DISCONNECTED;
		TRACE_LOG("conn state changed to disconnected\n");
		xio_observable_notify_all_observers(&conn->observable,
						    XIO_CONN_EVENT_DISCONNECTED,
						    &event_data);
		break;
	case XIO_TRANSPORT_CLOSED:
		DEBUG_LOG("conn: [notification] - transport closed. "  \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_conn_closed(conn, ev_data);
		break;
	case XIO_TRANSPORT_REFUSED:
		DEBUG_LOG("conn: [notification] - transport refused. " \
			 "conn:%p, transport:%p\n", observer, sender);
		conn->state = XIO_CONN_STATE_DISCONNECTED;
		TRACE_LOG("conn state changed to disconnected\n");
		xio_observable_notify_all_observers(&conn->observable,
						    XIO_CONN_EVENT_REFUSED,
						    &event_data);
		break;
	case XIO_TRANSPORT_ERROR:
		DEBUG_LOG("conn: [notification] - transport error. " \
			 "conn:%p, transport:%p\n", observer, sender);
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

		if (conn->close_time_hndl) {
			kref_init(&conn->kref);
			xio_ctx_timer_del(conn->transport_hndl->ctx,
					  conn->close_time_hndl);
			conn->close_time_hndl = NULL;
		} else {
			kref_get(&conn->kref);
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
		kfree(conn);
		return NULL;
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
		return NULL;
	}

	xio_conns_store_add(conn, &conn->cid);

	TRACE_LOG("conn: [new] conn:%p, transport_hndl:%p\n", conn,
		  conn->transport_hndl);

	return conn;
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
	if (conn->state == XIO_CONN_STATE_OPEN) {
		retval = conn->transport->connect(conn->transport_hndl,
						  portal_uri,
						  out_if);
		if (retval != 0) {
			ERROR_LOG("transport connect failed\n");
			return -1;
		}
		conn->state = XIO_CONN_STATE_CONNECTING;
	} else {
		if (conn->state ==  XIO_CONN_STATE_CONNECTED)
			xio_conn_notify_observer(
					conn, observer,
					XIO_CONN_EVENT_ESTABLISHED,
					NULL);
	}

	return 0;
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

	if (conn->state != XIO_CONN_STATE_DISCONNECTED) {
		retval = xio_ctx_timer_add(
				conn->transport_hndl->ctx,
				XIO_CONN_CLOSE_TIMEOUT, conn,
				xio_conn_release,
				&conn->close_time_hndl);
		if (retval)
			ERROR_LOG("xio_conn_delayed_close failed\n");
	} else {
		xio_conn_release(conn);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_close		                                             */
/*---------------------------------------------------------------------------*/
void xio_conn_close(struct xio_conn *conn, struct xio_observer *observer)
{
	TRACE_LOG("conn: [putref] ptr:%p, refcnt:%d\n", conn,
		  atomic_read(&conn->kref.refcount));

	kref_put(&conn->kref, xio_conn_delayed_close);

	if (observer) {
		xio_conn_notify_observer(
				conn, observer,
				XIO_CONN_EVENT_CLOSED, NULL);

		xio_conn_unhash_observer(conn, observer);
		xio_conn_unreg_observer(conn, observer);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_send							     */
/*---------------------------------------------------------------------------*/
int xio_conn_send(struct xio_conn *conn, struct xio_task *task)
{
	int	retval;

	if (conn->transport->send) {
		retval = conn->transport->send(conn->transport_hndl, task);
		if (retval != 0) {
			if (xio_errno() != EAGAIN) {
				union xio_conn_event_data conn_event_data;

				ERROR_LOG("transport send failed\n");
				conn_event_data.msg_error.reason = xio_errno();
				conn_event_data.msg_error.task	= task;

				xio_observable_notify_any_observer(
					   &conn->observable,
					   XIO_CONN_EVENT_MESSAGE_ERROR,
					   &conn_event_data);

				xio_set_error(ENOMSG);
			}
			return -1;
		}
	}

	return 0;
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


