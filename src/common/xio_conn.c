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
#include "xio_context.h"
#include "xio_task.h"
#include "xio_transport.h"
#include "xio_conns_store.h"
#include "xio_conn.h"
#include "xio_session.h"

/*---------------------------------------------------------------------------*/
/* forward declarations							     */
/*---------------------------------------------------------------------------*/
static int xio_conn_primary_pool_setup(struct xio_conn *conn);

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
	task->omsg_flags		= 0;
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
inline struct xio_task *xio_conn_get_initial_task(struct xio_conn *conn)
{
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
/* xio_conn_task_lookup						     */
/*---------------------------------------------------------------------------*/
inline struct xio_task *xio_conn_task_lookup(struct xio_conn *conn,
						 int id)
{
	return xio_tasks_pool_lookup(conn->primary_tasks_pool, id);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_primary_free_tasks					     */
/*---------------------------------------------------------------------------*/
inline int xio_conn_primary_free_tasks(struct xio_conn *conn)
{
	return xio_tasks_pool_free_tasks(conn->primary_tasks_pool);
}

/*---------------------------------------------------------------------------*/
/* xio_conn_add_observer						     */
/*---------------------------------------------------------------------------*/
int xio_conn_add_observer(struct xio_conn *conn, void *observer,
				   notification_handler_t notify_observer)
{
	struct xio_observer_node *observer_node, *tmp_observer_node;

	list_for_each_entry_safe(observer_node, tmp_observer_node,
				 &conn->observers_list, observers_list_entry) {
		if (observer == observer_node->observer)
			return 0;
	}

	observer_node = kcalloc(1, sizeof(struct xio_observer_node),
				GFP_KERNEL);
	if (observer_node == NULL) {
		xio_set_error(ENOMEM);
		return -1;
	}
	observer_node->observer			= observer;
	observer_node->notification_handler	= notify_observer;
	list_add(&observer_node->observers_list_entry, &conn->observers_list);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_remove_observer		                                     */
/*---------------------------------------------------------------------------*/
void xio_conn_remove_observer(struct xio_conn *conn, void *observer)
{
	struct xio_observer_node *observer_node, *tmp_observer_node;

	list_for_each_entry_safe(observer_node, tmp_observer_node,
				 &conn->observers_list, observers_list_entry) {
		if (observer_node->observer == observer) {
			/* Remove the item from the tail queue. */
			list_del(&observer_node->observers_list_entry);
			kfree(observer_node);
			break;
		}
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_free_observers_list		                             */
/*---------------------------------------------------------------------------*/
static void xio_conn_free_observers_list(struct xio_conn *conn)
{
	struct xio_observer_node *observer_node, *tmp_observer_node;

	list_for_each_entry_safe(observer_node, tmp_observer_node,
				 &conn->observers_list, observers_list_entry) {
		/* Remove the item from the list. */
		list_del(&observer_node->observers_list_entry);
		kfree(observer_node);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_notify_alls		                                     */
/*---------------------------------------------------------------------------*/
void xio_conn_notify_all(struct xio_conn *conn, int event,
				       void *event_data)
{
	struct xio_observer_node *observer_node, *tmp_observer_node;

	list_for_each_entry_safe(observer_node, tmp_observer_node,
				 &conn->observers_list, observers_list_entry) {
		observer_node->notification_handler(observer_node->observer,
						    conn, event, event_data);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_notify_any		                                     */
/*---------------------------------------------------------------------------*/
static void xio_conn_notify_any(struct xio_conn *conn,
		int event, void *event_data)
{
	struct xio_observer_node *observer_node, *tmp_observer_node;

	list_for_each_entry_safe(observer_node, tmp_observer_node,
				 &conn->observers_list, observers_list_entry) {
		if (observer_node->observer != NULL) {
			observer_node->notification_handler(
					NULL,
					conn, event, event_data);
			break;
		}
	}
}

/*---------------------------------------------------------------------------*/
/* xio_conn_notify_any		                                     */
/*---------------------------------------------------------------------------*/
void xio_conn_notify_observer(struct xio_conn *conn,
		void *observer,
		int event, void *event_data)
{
	struct xio_observer_node *observer_node, *tmp_observer_node;

	list_for_each_entry_safe(observer_node, tmp_observer_node,
				 &conn->observers_list, observers_list_entry) {
		if (observer_node->observer == observer) {
			observer_node->notification_handler(
					observer_node->observer,
					conn, event, event_data);
			break;
		}
	}
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
	if (atomic_read(&conn->refcnt) != 1)
		return 0;

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
	uint32_t		status = 0;
	struct xio_conn_setup_req req;
	struct xio_conn_setup_rsp rsp;



	retval = xio_conn_read_setup_req(task, &req);
	if (retval != 0)
		goto cleanup;

	/* verify version */
	if (req.version != XIO_VERSION) {
		ERROR_LOG("client invalid version.cver:0x%x, sver::0x%x\n",
			  req.version, XIO_VERSION);
		status = XIO_E_INVALID_VERSION;
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
	task->tlv_type = XIO_CONN_SETUP_RSP;

	rsp.cid		= conn->cid;
	rsp.status	= 0;
	rsp.version	= XIO_VERSION;

	retval = xio_conn_write_setup_rsp(task, &rsp);
	if (retval != 0)
		goto cleanup;

	/* remove it from io_tasks list */
	list_del_init(&task->tasks_list_entry);
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
	struct	 xio_conn_setup_rsp rsp;
	int	 retval;

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
	xio_conn_notify_all(conn, XIO_CONNECTION_ESTABLISHED, NULL);

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
	/* recycle the task */
	xio_tasks_pool_put(task);

	xio_conn_notify_all(conn, XIO_CONNECTION_ESTABLISHED, NULL);
	return 0;
}
/*---------------------------------------------------------------------------*/
/* xio_conn_on_recv_msg							     */
/*---------------------------------------------------------------------------*/
static int xio_conn_on_recv_msg(struct xio_conn *conn,
				  struct xio_task *task)
{
	struct xio_observer_node	*observer_node;
	union xio_conn_event_data conn_event_data = {
		.msg.task	= task,
		.msg.op		= XIO_WC_OP_RECV
	};
	task->conn = conn;

	if (!conn->transport_hndl->is_client) {
		if (unlikely(conn->is_first_msg)) {
			/* route the message to first observer (the server) */
			conn->is_first_msg = 0;
			observer_node = list_first_entry(
				&conn->observers_list,
				struct xio_observer_node,
				observers_list_entry);

			xio_conn_notify_observer(
					conn,
					observer_node->observer,
					XIO_CONNECTION_NEW_MESSAGE,
					&conn_event_data);
			return 0;
		}
	}
	if (task->sender_task) {
		/* route the response to the sender session */
		xio_conn_notify_observer(
				conn,
				task->sender_task->session,
				XIO_CONNECTION_NEW_MESSAGE,
				&conn_event_data);
	} else {
		/* route the message to any of the sessions */
		xio_conn_notify_any(
				conn,
				XIO_CONNECTION_NEW_MESSAGE,
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
	union xio_conn_event_data conn_event_data = {
		.msg.task	= task,
		.msg.op		= XIO_WC_OP_SEND
	};

	xio_conn_notify_observer(
			conn, task->session,
			XIO_CONNECTION_SEND_COMPLETION,
			&conn_event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_on_set_pools_ops						     */
/*---------------------------------------------------------------------------*/
inline void xio_conn_set_pools_ops(struct xio_conn *conn,
		struct xio_tasks_pool_ops *initial_pool_ops,
		struct xio_tasks_pool_ops *primary_pool_ops)
{
	conn->initial_pool_ops = initial_pool_ops;
	conn->primary_pool_ops = primary_pool_ops;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_initial_pool_setup					     */
/*---------------------------------------------------------------------------*/
static int xio_conn_initial_pool_setup(struct xio_conn *conn)
{
	int i;
	int num_tasks;
	int task_dd_sz;
	int pool_dd_sz;
	int retval;

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
		goto cleanup;
	}

	/* allocate the pool */
	retval = conn->initial_pool_ops->pool_alloc(
				conn->transport_hndl,
				conn->initial_tasks_pool->max,
				conn->initial_tasks_pool->dd_data);
	if (retval != 0) {
		ERROR_LOG("initial_pool_alloc failed\n");
		goto cleanup;
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
	}

	/* pool is ready for use */
	retval = conn->initial_pool_ops->pool_run(conn->transport_hndl);
	if (retval != 0) {
		ERROR_LOG("initial_pool_init failed\n");
		goto cleanup;
	}

	return 0;

cleanup:
	conn->initial_pool_ops->pool_free(conn->transport_hndl,
					  conn->initial_tasks_pool->dd_data);
	if (conn->initial_tasks_pool)
		xio_tasks_pool_free(conn->initial_tasks_pool);

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
		goto cleanup;
	}

	/* allocate the pool */
	retval = conn->primary_pool_ops->pool_alloc(
				conn->transport_hndl,
				conn->primary_tasks_pool->max,
				conn->primary_tasks_pool->dd_data);

	if (retval != 0) {
		ERROR_LOG("primary_pool_alloc failed\n");
		goto cleanup;
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
	}

	/* pool is ready for use */
	retval = conn->primary_pool_ops->pool_run(conn->transport_hndl);
	if (retval != 0) {
		ERROR_LOG("primary_pool_init failed\n");
		goto cleanup;
	}
	return 0;

cleanup:
	conn->primary_pool_ops->pool_free(conn->transport_hndl,
			conn->primary_tasks_pool->dd_data);

	if (conn->primary_tasks_pool)
		xio_tasks_pool_free(conn->primary_tasks_pool);

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
/* xio_conn_create		                                             */
/*---------------------------------------------------------------------------*/
struct xio_conn *xio_conn_create(
		struct xio_conn *parent_conn,
		struct xio_transport_base *transport_hndl)
{
	struct xio_conn	*conn;
	int			retval;


	if (parent_conn->transport_hndl->is_client)
		return NULL;

	/* allocate connection */
	conn = kcalloc(1, sizeof(struct xio_conn), GFP_KERNEL);
	if (conn == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcalloc failed. %m\n");
		return NULL;
	}

	/* add the conection to temporary list */
	conn->transport_hndl	= transport_hndl;
	conn->transport		= parent_conn->transport;
	conn->initial_pool_ops	= parent_conn->initial_pool_ops;
	conn->primary_pool_ops	= parent_conn->primary_pool_ops;
	atomic_set(&conn->refcnt, 1);
	conn->is_first_msg	= 1;

	INIT_LIST_HEAD(&conn->observers_list);

	xio_conns_store_add(conn, &conn->cid);

	/* add  the new cnnnection as oberver to transport */
	if (conn->transport->add_observer) {
		conn->transport->add_observer(conn->transport_hndl, conn);
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
/* xio_on_new_connection		                                     */
/*---------------------------------------------------------------------------*/
static void xio_on_new_connection(struct xio_conn *conn,
				    union xio_transport_event_data *
				    event_data)
{
	union xio_conn_event_data	conn_event_data;
	struct xio_conn		*child_conn;

	child_conn = xio_conn_create(
			conn,
			event_data->new_connection.child_trans_hndl);
	if (child_conn == NULL) {
		ERROR_LOG("failed to create child connection\n");
		goto exit;
	}

	/* notify of new child to session */
	conn_event_data.new_connection.child_conn = child_conn;

	xio_conn_notify_all(conn, XIO_CONNECTION_NEW_CONNECTION,
			    &conn_event_data);
	return;
exit:
	xio_conn_reject(child_conn);
	xio_conn_close(child_conn);

	xio_conn_notify_all(conn, XIO_CONNECTION_ERROR,
			    &conn_event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_on_connection_closed		                                     */
/*---------------------------------------------------------------------------*/
static void xio_on_connection_closed(struct xio_conn *conn,
				    union xio_transport_event_data *
				    event_data)
{
	TRACE_LOG("conn:%d - close complete\n", conn->cid);
	xio_conn_notify_all(conn, XIO_CONNECTION_CLOSED, NULL);

	xio_conn_free_observers_list(conn);
	xio_conns_store_remove(conn->cid);

	xio_conn_initial_pool_free(conn);
	xio_conn_primary_pool_free(conn);

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

	xio_conn_notify_all(conn, XIO_CONNECTION_ERROR,
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


	if (unlikely(IS_CONN_SETUP(task->tlv_type))) {
		if (task->tlv_type == XIO_CONN_SETUP_RSP)
			retval = xio_conn_on_recv_setup_rsp(conn, task);
		else
			retval = xio_conn_on_recv_setup_req(conn, task);
	} else {
		retval = xio_conn_on_recv_msg(conn, task);
	}

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

	if (unlikely(task->tlv_type == XIO_CONN_SETUP_RSP))
		retval = xio_conn_on_send_setup_rsp_comp(conn, task);
	else
		retval  = xio_conn_on_send_msg_comp(conn, task);

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
	struct xio_observer_node	*observer_node;
	int				retval = 0;
	struct xio_task			*task = event_data->msg.task;

	union xio_conn_event_data conn_event_data = {
		.assign_in_buf.task		= task,
	};
	task->conn = conn;

	if (!conn->transport_hndl->is_client) {
		if (unlikely(conn->is_first_msg)) {
			/* route the message to first observer (the server) */
			conn->is_first_msg = 0;
			observer_node = list_first_entry(
					&conn->observers_list,
					struct xio_observer_node,
					observers_list_entry);

			xio_conn_notify_observer(
					conn,
					observer_node->observer,
					XIO_CONNECTION_ASSIGN_IN_BUF,
					&conn_event_data);

			event_data->assign_in_buf.is_assigned =
				conn_event_data.assign_in_buf.is_assigned;
		}
	}
	/* route the message to any of the sessions */
	xio_conn_notify_any(
			conn,
			XIO_CONNECTION_ASSIGN_IN_BUF,
			&conn_event_data);
	event_data->assign_in_buf.is_assigned =
		conn_event_data.assign_in_buf.is_assigned;



	return retval;
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
		INFO_LOG("conn: [notification] - new message. " \
			 "conn:%p, transport:%p\n", observer, sender);
*/
		xio_on_new_message(conn, ev_data);
		break;
	case XIO_TRANSPORT_SEND_COMPLETION:
/*
		INFO_LOG("conn: [notification] - send completion. " \
			 "conn:%p, transport:%p\n", observer, sender);
*/
		xio_on_send_completion(conn, ev_data);
		break;
	case XIO_TRANSPORT_ASSIGN_IN_BUF:
		INFO_LOG("conn: [notification] - assign in buffer. " \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_assign_in_buf(conn, ev_data);
		break;
	case XIO_TRANSPORT_NEW_CONNECTION:
		INFO_LOG("conn: [notification] - new transport. " \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_new_connection(conn, ev_data);
		break;
	case XIO_TRANSPORT_ESTABLISHED:
		INFO_LOG("conn: [notification] - transport established. " \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_connection_established(conn, ev_data);
		break;
	case XIO_TRANSPORT_DISCONNECTED:
		INFO_LOG("conn: [notification] - transport disconnected. "  \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_conn_notify_all(conn, XIO_CONNECTION_DISCONNECTED,
				    event_data);
		break;
	case XIO_TRANSPORT_CLOSED:
		INFO_LOG("conn: [notification] - transport closed. "  \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_on_connection_closed(conn, ev_data);
		break;
	case XIO_TRANSPORT_REFUSED:
		INFO_LOG("conn: [notification] - transport refused. " \
			 "conn:%p, transport:%p\n", observer, sender);
		xio_conn_notify_all(conn,  XIO_CONNECTION_REFUSED,
				    event_data);
		break;
	case XIO_TRANSPORT_ERROR:
		INFO_LOG("conn: [notification] - transport error. " \
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
		const char *portal_uri, void  *observer,
		notification_handler_t notify_observer)
{
	struct xio_transport		*transport;
	struct xio_conn			*conn;
	char				proto[8];
	int				retval;


	/* look for opened connection */
	conn = xio_conns_store_find(ctx, portal_uri);
	if (conn != NULL) {
		if (observer) {
			retval = xio_conn_add_observer(conn, observer,
					notify_observer);
			if (retval != 0) {
				ERROR_LOG("connection observer addition " \
					 "failed.\n");
				kfree(conn);
				return NULL;
			}
		}
		atomic_inc(&conn->refcnt);
		ERROR_LOG("conn: [addref] ptr:%p, refcnt:%d\n", conn,
			  atomic_read(&conn->refcnt));
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

	conn->transport_hndl = transport->open(transport, ctx, conn,
					       xio_on_transport_event);
	if (conn->transport_hndl == NULL) {
		ERROR_LOG("transport open failed\n");
		kfree(conn);
		return NULL;
	}
	conn->transport		= transport;
	atomic_set(&conn->refcnt, 1);

	xio_conns_store_add(conn, &conn->cid);

	INIT_LIST_HEAD(&conn->observers_list);

	if (observer) {
		retval = xio_conn_add_observer(conn, observer,
						 notify_observer);
		if (retval != 0) {
			ERROR_LOG("connection observer addition failed.\n");
			conn->transport->close(conn->transport_hndl);
			kfree(conn);
			return NULL;
		}
	}

	TRACE_LOG("conn: [new] id:%d, transport_hndl:%p\n", conn->cid,
		  conn->transport_hndl);

	return conn;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_connect		                                             */
/*---------------------------------------------------------------------------*/
int xio_conn_connect(struct xio_conn *conn,
		const char *portal_uri)
{
	int retval;

	if (conn->transport->connect == NULL) {
		ERROR_LOG("transport does not implement \"connect\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}
	if (atomic_read(&conn->refcnt) == 1) {
		retval = conn->transport->connect(conn->transport_hndl,
						  portal_uri);
		if (retval != 0) {
			ERROR_LOG("transport connect failed\n");
			return -1;
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_listen			                                     */
/*---------------------------------------------------------------------------*/
int xio_conn_listen(struct xio_conn *conn, const char *portal_uri,
		    uint16_t *src_port)
{
	int retval;

	if (conn->transport->listen == NULL) {
		ERROR_LOG("transport does not implement \"listen\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}
	if (atomic_read(&conn->refcnt) == 1) {
		retval = conn->transport->listen(conn->transport_hndl,
						 portal_uri, src_port);
		if (retval != 0) {
			ERROR_LOG("transport listen failed. uri:[%s]\n",
				  portal_uri);
			return -1;
		}
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
	if (atomic_read(&conn->refcnt) == 1) {
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
	if (atomic_read(&conn->refcnt) == 1) {
		retval = conn->transport->reject(conn->transport_hndl);
		if (retval != 0) {
			ERROR_LOG("transport reject failed.\n");
			return -1;
		}
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_close		                                             */
/*---------------------------------------------------------------------------*/
void xio_conn_close(struct xio_conn *conn)
{
	int was = __atomic_add_unless(&conn->refcnt, -1, 0);

	/* was allready 0 */
	if (!was)
		return;

	if (was == 1) {
		/* now it is zero */
		if (conn->transport->close)
			conn->transport->close(conn->transport_hndl);
	} else {
		/* not yet zero */
		xio_conn_notify_all(conn, XIO_CONNECTION_CLOSED, NULL);
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
			if (xio_errno() != EAGAIN)
				ERROR_LOG("transport send failed\n");
			return -1;
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conn_poll							     */
/*---------------------------------------------------------------------------*/
int xio_conn_poll(struct xio_conn *conn,  struct timespec *timeout)
{
	int	retval = 0;

	if (conn->transport->poll) {
		retval = conn->transport->poll(conn->transport_hndl, timeout);
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



