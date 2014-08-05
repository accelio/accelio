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
#include "xio_nexus_cache.h"
#include "xio_nexus.h"
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
static int xio_nexus_primary_pool_create(struct xio_nexus *nexus);
static int xio_nexus_primary_pool_recreate(struct xio_nexus *nexus);
static int xio_nexus_on_transport_event(void *observer, void *sender,
					int event, void *event_data);
static void xio_nexus_on_transport_closed(struct xio_nexus *nexus,
					  union xio_transport_event_data
					  *event_data);
static int xio_nexus_flush_tx_queue(struct xio_nexus *nexus);
static int xio_nexus_destroy(struct xio_nexus *nexus);

/*---------------------------------------------------------------------------*/
/* xio_nexus_server_reconnect		                                     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_server_reconnect(struct xio_nexus *nexus);

/*---------------------------------------------------------------------------*/
/* xio_nexus_client_reconnect						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_client_reconnect(struct xio_nexus *nexus);

/*---------------------------------------------------------------------------*/
/* xio_nexus_client_reconnect_timeout					     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_client_reconnect_failed(void *data);

static void xio_nexus_cancel_dwork(struct xio_nexus *nexus)
{
	if (xio_is_delayed_work_pending(&nexus->close_time_hndl)) {
		xio_ctx_del_delayed_work(nexus->transport_hndl->ctx,
					 &nexus->close_time_hndl);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_init_observers_htbl					     */
/*---------------------------------------------------------------------------*/
static inline void xio_nexus_init_observers_htbl(struct xio_nexus *nexus)
{
	INIT_LIST_HEAD(&nexus->observers_htbl);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_free_observers_htbl					     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_free_observers_htbl(struct xio_nexus *nexus)
{
	struct xio_observers_htbl_node	*node, *next_node;

	list_for_each_entry_safe(node, next_node,
				 &nexus->observers_htbl,
				 observers_htbl_node) {
		list_del(&node->observers_htbl_node);
		kfree(node);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_hash_observer						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_hash_observer(struct xio_nexus *nexus,
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
		      &nexus->observers_htbl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_delete_observer						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_delete_observer(struct xio_nexus *nexus,
				     struct xio_observer *observer)
{
	struct xio_observers_htbl_node	*node, *next_node;

	list_for_each_entry_safe(node, next_node,
				 &nexus->observers_htbl,
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
/* xio_nexus_observer_lookup						     */
/*---------------------------------------------------------------------------*/
struct xio_observer *xio_nexus_observer_lookup(struct xio_nexus *nexus,
					       uint32_t id)
{
	struct xio_observers_htbl_node	*node;

	list_for_each_entry(node,
			    &nexus->observers_htbl,
			    observers_htbl_node) {
		if (node->id == id)
			return node->observer;
	}

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_reg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_nexus_reg_observer(struct xio_nexus *nexus,
			    struct xio_observer *observer,
			    uint32_t oid)
{
	xio_observable_reg_observer(&nexus->observable, observer);
	xio_nexus_hash_observer(nexus, observer, oid);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_unreg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_nexus_unreg_observer(struct xio_nexus *nexus,
			      struct xio_observer *observer)
{
	xio_nexus_delete_observer(nexus, observer);
	xio_observable_unreg_observer(&nexus->observable, observer);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_get_primary_task						     */
/*---------------------------------------------------------------------------*/
inline struct xio_task *xio_nexus_get_primary_task(struct xio_nexus *nexus)
{
	return  xio_tasks_pool_get(nexus->primary_tasks_pool);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_task_lookup						     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_nexus_task_lookup(void *nexus, int id)
{
	return xio_tasks_pool_lookup(
			((struct xio_nexus *)nexus)->primary_tasks_pool, id);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_primary_free_tasks						     */
/*---------------------------------------------------------------------------*/
inline int xio_nexus_primary_free_tasks(struct xio_nexus *nexus)
{
	return xio_tasks_pool_free_tasks(nexus->primary_tasks_pool);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_notify_server		                                     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_notify_server(struct xio_nexus *nexus, int event,
				    void *event_data)
{
	if (nexus->server_observer)
		xio_observable_notify_observer(&nexus->observable,
					       nexus->server_observer,
					       event, event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_write_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_write_setup_req(struct xio_task *task,
				     struct xio_nexus_setup_req *req)
{
	struct xio_nexus_setup_req *tmp_req;

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

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_nexus_setup_req));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_read_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_read_setup_req(struct xio_task *task,
				    struct xio_nexus_setup_req *req)
{
	struct xio_nexus_setup_req *tmp_req;

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

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_nexus_setup_req));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_write_setup_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_write_setup_rsp(struct xio_task *task,
				     struct xio_nexus_setup_rsp *rsp)
{
	struct xio_nexus_setup_rsp *tmp_rsp;

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return -1;

	tmp_rsp = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* fill request */
	PACK_LVAL(rsp, tmp_rsp, cid);
	PACK_LVAL(rsp, tmp_rsp, status);
	PACK_SVAL(rsp, tmp_rsp, version);
	PACK_SVAL(rsp, tmp_rsp, flags);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_nexus_setup_rsp));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_read_setup_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_read_setup_rsp(struct xio_task *task,
				    struct xio_nexus_setup_rsp *rsp)
{
	struct xio_nexus_setup_rsp *tmp_rsp;

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return -1;

	tmp_rsp = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* fill request */
	UNPACK_LVAL(tmp_rsp, rsp, cid);
	UNPACK_LVAL(tmp_rsp, rsp, status);
	UNPACK_SVAL(tmp_rsp, rsp, version);
	UNPACK_SVAL(tmp_rsp, rsp, flags);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_nexus_setup_rsp));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_send_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_send_setup_req(struct xio_nexus *nexus)
{
	struct xio_task	*task;
	struct xio_nexus_setup_req req = {0};
	struct xio_transport_base *trans_hndl;
	int    retval = 0;

	TRACE_LOG("send setup request\n");

	if (nexus->transport->send == NULL) {
		ERROR_LOG("transport does not implement \"send\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}

	task =  xio_tasks_pool_get(nexus->initial_tasks_pool);
	if (task == NULL) {
		ERROR_LOG("initial task pool is empty\n");
		return -1;
	}
	task->tlv_type = XIO_NEXUS_SETUP_REQ;

	req.version = XIO_VERSION;

	/* when reconnecting before the dup2 send is done via new handle */
	if (nexus->state == XIO_NEXUS_STATE_RECONNECT) {
		req.flags = XIO_RECONNECT;
		req.cid = nexus->server_cid;
		trans_hndl = nexus->new_transport_hndl;
	} else {
		req.flags = 0;
		req.cid = 0;
		trans_hndl = nexus->transport_hndl;
	}

	retval = xio_nexus_write_setup_req(task, &req);
	if (retval)
		goto cleanup;


	/* always add it to the top */
	list_add(&task->tasks_list_entry, &nexus->tx_queue);


	if (!trans_hndl) {
		ERROR_LOG("null transport handle state=%d\n", nexus->state);
		xio_tasks_pool_put(task);
		return -1;
	}

	retval = nexus->transport->send(trans_hndl, task);
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
/* xio_nexus_swap							     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_swap(struct xio_nexus *old, struct xio_nexus *new)
{
	struct xio_transport		*transport;
	struct xio_tasks_pool		*initial_tasks_pool;

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

	/* Swap the initial pool as the setup request arrived on the a task
	 * from the initial pool and should be answered using the same task
	 */
	initial_tasks_pool = old->initial_tasks_pool;
	old->initial_tasks_pool = new->initial_tasks_pool;
	new->initial_tasks_pool = initial_tasks_pool;

	xio_tasks_pool_remap(old->primary_tasks_pool, new->transport_hndl);
	/* make old_nexus->transport_hndl copy of new_nexus->transport_hndl
	 * old_nexus->trasport_hndl will be closed, note that observers were
	 * swapped
	 */
	if (transport->dup2(new->transport_hndl, &old->transport_hndl)) {
		ERROR_LOG("dup2 transport failed\n");
		return -1;
	}

	/* silently close new_nexus */
	xio_nexus_close(new, NULL);

	/* TODO what about messages held by the application */

	/* be ready to receive messages */
	if (xio_nexus_primary_pool_recreate(old)) {
		ERROR_LOG("recreate primary pool failed\n");
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_recv_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_recv_setup_req(struct xio_nexus *new_nexus,
				       struct xio_task *task)
{
	struct xio_nexus_setup_req req;
	struct xio_nexus_setup_rsp rsp;
	struct xio_nexus *nexus;
	uint32_t status = 0;
	uint32_t cid;
	int      retval = 0;
	uint16_t flags = 0;

	TRACE_LOG("receiving setup request\n");
	retval = xio_nexus_read_setup_req(task, &req);
	if (retval != 0)
		goto cleanup;

	/* verify version */
	if (req.version != XIO_VERSION) {
		ERROR_LOG("client invalid version.cver:0x%x, sver::0x%x\n",
			  req.version, XIO_VERSION);
		xio_set_error(XIO_E_INVALID_VERSION);
		return -1;
	}

	/* by default nexus is the new nexus */
	nexus = new_nexus;
	if (req.flags & XIO_RECONNECT) {
		struct xio_nexus *dis_nexus;
		/* Server side reconnect strategy, use new transport with the
		 * old nexus
		 */
		cid = req.cid;
		flags = XIO_RECONNECT;
		dis_nexus = xio_nexus_cache_lookup(cid);
		if (dis_nexus) {
			/* stop timer */
			xio_nexus_cancel_dwork(dis_nexus);
			retval = xio_nexus_swap(dis_nexus, new_nexus);
			if (retval != 0) {
				ERROR_LOG("swap nexus failed\n");
				return -1;
			}
			/* retransmission will start after setup response is
			 * transmitted - xio_nexus_on_send_setup_rsp_comp
			 */
			nexus = dis_nexus;
		} else {
			flags = XIO_CID;
			status = -1;
		}
	} else {
		cid = nexus->cid;
		/* time to prepare the primary pool */
		retval = xio_nexus_primary_pool_create(nexus);
		if (retval != 0) {
			ERROR_LOG("create primary pool failed\n");
			status = ENOMEM;
			goto send_response;
		}
	}

send_response:
	/* reset mbuf */
	xio_mbuf_reset(&task->mbuf);

	/* write response */
	task->tlv_type	= XIO_NEXUS_SETUP_RSP;

	rsp.cid		= cid;
	rsp.status	= status;
	rsp.version	= XIO_VERSION;
	rsp.flags	= flags;

	TRACE_LOG("send setup response\n");

	retval = xio_nexus_write_setup_rsp(task, &rsp);
	if (retval != 0)
		goto cleanup;

	/* send it */
	list_move(&task->tasks_list_entry, &nexus->tx_queue);
	retval = nexus->transport->send(nexus->transport_hndl, task);
	if (retval != 0) {
		ERROR_LOG("send setup response failed\n");
		return -1;
	}

cleanup:
	xio_set_error(XIO_E_MSG_INVALID);
	ERROR_LOG("receiving setup request failed\n");

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_recv_setup_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_recv_setup_rsp(struct xio_nexus *nexus,
				       struct xio_task *task)
{
	struct xio_nexus_setup_rsp	rsp;
	int				retval;

	TRACE_LOG("receiving setup response\n");
	retval = xio_nexus_read_setup_rsp(task, &rsp);
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
			xio_nexus_cancel_dwork(nexus);
			/* Kill nexus */
			nexus->state = XIO_NEXUS_STATE_DISCONNECTED;
			TRACE_LOG("nexus state changed to disconnected\n");
			xio_observable_notify_all_observers(
					&nexus->observable,
					XIO_NEXUS_EVENT_DISCONNECTED,
					NULL);
		} else {
			union xio_nexus_event_data nexus_event_data;

			nexus_event_data.error.reason =  XIO_E_CONNECT_ERROR;
			xio_observable_notify_all_observers(
					&nexus->observable,
					XIO_NEXUS_EVENT_ERROR,
					&nexus_event_data);
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

	if (nexus->state != XIO_NEXUS_STATE_RECONNECT) {
		/* create the primary */
		retval = xio_nexus_primary_pool_create(nexus);
		if (retval != 0) {
			ERROR_LOG("create primary pool failed\n");
			return -1;
		}
		nexus->state = XIO_NEXUS_STATE_CONNECTED;

		xio_observable_notify_all_observers(&nexus->observable,
						    XIO_NEXUS_EVENT_ESTABLISHED,
						    NULL);
		/* remember server cid for reconnect */
		nexus->server_cid = rsp.cid;
	} else {
		/* Stop reconnect timer */
		xio_nexus_cancel_dwork(nexus);

		/* ignore close event on transport_hndl (part of dup2) */
		xio_observable_unreg_observer(
				&nexus->transport_hndl->observable,
				&nexus->trans_observer);

		/* nexus is an observer of the new transport (see open API)
		 * no need to register
		 */
		xio_tasks_pool_remap(nexus->primary_tasks_pool,
				     nexus->new_transport_hndl);
		/* make nexus->transport_hndl copy of nexus->new_transport_hndl
		 * old nexus->trasport_hndl will be closed
		 */
		if (nexus->transport->dup2(nexus->new_transport_hndl,
					   &nexus->transport_hndl)) {
			ERROR_LOG("dup2 transport failed\n");
			return -1;
		}

		/* new_transport_hndl was "duplicated" on transport_hndl
		 * thus we need to consume one reference count
		 */
		nexus->transport->close(nexus->new_transport_hndl);
		nexus->new_transport_hndl = NULL;

		/* TODO: what about messages held by the application */
		/* be ready to receive messages */
		retval = xio_nexus_primary_pool_recreate(nexus);
		if (retval != 0) {
			ERROR_LOG("recreate primary pool failed\n");
			return -1;
		}
		nexus->state = XIO_NEXUS_STATE_CONNECTED;

		/* Tell session to re-initiate transmission */
		xio_observable_notify_all_observers(&nexus->observable,
						    XIO_NEXUS_EVENT_RECONNECTED,
						    NULL);
	}

	return 0;
cleanup:
	xio_set_error(XIO_E_MSG_INVALID);
	ERROR_LOG("receiving setup request failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_send_setup_rsp_comp					     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_send_setup_rsp_comp(struct xio_nexus *nexus,
					    struct xio_task *task)
{
	enum xio_nexus_event nexus_event;

	if (nexus->state == XIO_NEXUS_STATE_RECONNECT)
		/* Tell session to re-initiate transmission */
		nexus_event = XIO_NEXUS_EVENT_RECONNECTED;
	else
		nexus_event = XIO_NEXUS_EVENT_ESTABLISHED;

	/* Set new state */
	nexus->state = XIO_NEXUS_STATE_CONNECTED;
	xio_observable_notify_all_observers(&nexus->observable,
					    nexus_event,
					    NULL);

	/* recycle the task */
	xio_tasks_pool_put(task);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_recv_req						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_recv_req(struct xio_nexus *nexus,
				 struct xio_task *task)
{
	union xio_nexus_event_data nexus_event_data;

	task->nexus = nexus;
	nexus_event_data.msg.task = task;
	nexus_event_data.msg.op = XIO_WC_OP_RECV;


	if (!nexus->transport_hndl->is_client) {
		if (task->tlv_type == XIO_SESSION_SETUP_REQ) {
			/* add reference count to opened nexus that new
			 * session is join in */
			if (!nexus->is_first_req)
				xio_nexus_addref(nexus);
			else
				nexus->is_first_req = 0;

			/* always route "hello" to server */
			xio_nexus_notify_server(
					nexus,
					XIO_NEXUS_EVENT_NEW_MESSAGE,
					&nexus_event_data);
			return 0;
		} else if (task->tlv_type == XIO_CONNECTION_HELLO_REQ) {
			if (!nexus->is_first_req)
				xio_nexus_addref(nexus);
			else
				nexus->is_first_req = 0;

			/* always route "hello" to server */
			xio_nexus_notify_server(
					nexus,
					XIO_NEXUS_EVENT_NEW_MESSAGE,
					&nexus_event_data);
			return 0;
		}
	}

	/* route the message to any of observer */
	xio_observable_notify_any_observer(
			&nexus->observable,
			XIO_NEXUS_EVENT_NEW_MESSAGE,
			&nexus_event_data);

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_nexus_on_recv_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_recv_rsp(struct xio_nexus *nexus,
				 struct xio_task *task)
{
	union xio_nexus_event_data nexus_event_data;

	task->nexus = nexus;
	nexus_event_data.msg.task = task;
	nexus_event_data.msg.op = XIO_WC_OP_RECV;

	if (likely(task->sender_task)) {
		/* route the response to the sender session */
		xio_observable_notify_observer(
				&nexus->observable,
				&task->sender_task->session->observer,
				XIO_NEXUS_EVENT_NEW_MESSAGE,
				&nexus_event_data);
	} else {
		/* route the message to any of observer */
		xio_observable_notify_any_observer(
			&nexus->observable,
			XIO_NEXUS_EVENT_NEW_MESSAGE,
			&nexus_event_data);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_send_msg_comp						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_send_msg_comp(struct xio_nexus *nexus,
				      struct xio_task *task)
{
	union xio_nexus_event_data nexus_event_data;

	nexus_event_data.msg.task	= task;
	nexus_event_data.msg.op		= XIO_WC_OP_SEND;


	xio_observable_notify_observer(
			&nexus->observable,
			&task->session->observer,
			XIO_NEXUS_EVENT_SEND_COMPLETION,
			&nexus_event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_initial_pool_create					     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_initial_pool_create(struct xio_nexus *nexus)
{
	int				alloc_nr;
	int				start_nr;
	int				max_nr;
	int				task_dd_sz;
	int				slab_dd_sz;
	int				pool_dd_sz;
	struct xio_tasks_pool_cls	pool_cls;
	struct xio_tasks_pool_params	params;
	struct xio_transport_base	*transport_hndl;

	if (nexus->initial_pool_ops == NULL)
		return -1;

	if ((nexus->initial_pool_ops->pool_get_params == NULL) ||
	    (nexus->initial_pool_ops->slab_pre_create == NULL) ||
	    (nexus->initial_pool_ops->slab_init_task == NULL) ||
	    (nexus->initial_pool_ops->pool_post_create == NULL) ||
	    (nexus->initial_pool_ops->slab_destroy == NULL))
		return -1;

	if (nexus->state == XIO_NEXUS_STATE_RECONNECT)
		transport_hndl = nexus->new_transport_hndl;
	else
		transport_hndl = nexus->transport_hndl;

	/* get pool properties from the transport */
	nexus->initial_pool_ops->pool_get_params(transport_hndl,
						 &start_nr,
						 &max_nr,
						 &alloc_nr,
						 &pool_dd_sz,
						 &slab_dd_sz,
						 &task_dd_sz);

	memset(&params, 0, sizeof(params));

	params.start_nr			   = start_nr;
	params.max_nr			   = max_nr;
	params.alloc_nr			   = alloc_nr;
	params.pool_dd_data_sz		   = pool_dd_sz;
	params.slab_dd_data_sz		   = slab_dd_sz;
	params.task_dd_data_sz		   = task_dd_sz;
	params.pool_hooks.context	   = transport_hndl;
	params.pool_hooks.slab_pre_create  =
		(void *)nexus->initial_pool_ops->slab_pre_create;
	params.pool_hooks.slab_post_create =
		(void *)nexus->initial_pool_ops->slab_post_create;
	params.pool_hooks.slab_destroy	   =
		(void *)nexus->initial_pool_ops->slab_destroy;
	params.pool_hooks.slab_init_task   =
		(void *)nexus->initial_pool_ops->slab_init_task;
	params.pool_hooks.slab_uninit_task =
		(void *)nexus->initial_pool_ops->slab_uninit_task;
	params.pool_hooks.slab_remap_task =
		(void *)nexus->initial_pool_ops->slab_remap_task;
	params.pool_hooks.pool_pre_create  =
		(void *)nexus->initial_pool_ops->pool_pre_create;
	params.pool_hooks.pool_post_create =
		(void *)nexus->initial_pool_ops->pool_post_create;
	params.pool_hooks.pool_destroy	   =
		(void *)nexus->initial_pool_ops->pool_destroy;
	params.pool_hooks.task_pre_put	   =
		(void *)nexus->initial_pool_ops->task_pre_put;
	params.pool_hooks.task_post_get	   =
		(void *)nexus->initial_pool_ops->task_post_get;

	/* set pool helpers to the transport */
	if (nexus->transport->set_pools_cls) {
		pool_cls.pool		= NULL;
		pool_cls.task_get	= (void *)xio_tasks_pool_get;
		pool_cls.task_lookup	= (void *)xio_tasks_pool_lookup;
		pool_cls.task_put	= (void *)xio_tasks_pool_put;

		nexus->transport->set_pools_cls(transport_hndl,
						&pool_cls, NULL);
	}

	/* initialize the tasks pool */
	nexus->initial_tasks_pool = xio_tasks_pool_create(&params);
	if (nexus->initial_tasks_pool == NULL) {
		ERROR_LOG("xio_tasks_pool_create failed\n");
		goto cleanup;
	}

	return 0;

cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_initial_pool_free						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_initial_pool_free(struct xio_nexus *nexus)
{
	if (!nexus->primary_tasks_pool)
		return -1;

	xio_tasks_pool_destroy(nexus->initial_tasks_pool);

	return  0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_initial_pool_create					     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_primary_pool_create(struct xio_nexus *nexus)
{
	int				alloc_nr;
	int				start_nr;
	int				max_nr;
	int				task_dd_sz;
	int				slab_dd_sz;
	int				pool_dd_sz;
	struct xio_tasks_pool_cls	pool_cls;
	struct xio_tasks_pool_params	params;

	if (nexus->primary_pool_ops == NULL)
		return -1;

	if ((nexus->primary_pool_ops->pool_get_params == NULL) ||
	    (nexus->primary_pool_ops->slab_pre_create == NULL) ||
	    (nexus->primary_pool_ops->slab_init_task == NULL) ||
	    (nexus->primary_pool_ops->pool_post_create == NULL) ||
	    (nexus->primary_pool_ops->slab_destroy	== NULL))
		return -1;

	/* get pool properties from the transport */
	nexus->primary_pool_ops->pool_get_params(nexus->transport_hndl,
						&start_nr,
						&max_nr,
						&alloc_nr,
						&pool_dd_sz,
						&slab_dd_sz,
						&task_dd_sz);

	memset(&params, 0, sizeof(params));

	params.start_nr			   = start_nr;
	params.max_nr			   = max_nr;
	params.alloc_nr			   = alloc_nr;
	params.pool_dd_data_sz		   = pool_dd_sz;
	params.slab_dd_data_sz		   = slab_dd_sz;
	params.task_dd_data_sz		   = task_dd_sz;
	params.pool_hooks.context	   = nexus->transport_hndl;
	params.pool_hooks.slab_pre_create  =
		(void *)nexus->primary_pool_ops->slab_pre_create;
	params.pool_hooks.slab_post_create =
		(void *)nexus->primary_pool_ops->slab_post_create;
	params.pool_hooks.slab_destroy	   =
		(void *)nexus->primary_pool_ops->slab_destroy;
	params.pool_hooks.slab_init_task   =
		(void *)nexus->primary_pool_ops->slab_init_task;
	params.pool_hooks.slab_uninit_task =
		(void *)nexus->primary_pool_ops->slab_uninit_task;
	params.pool_hooks.slab_remap_task =
		(void *)nexus->primary_pool_ops->slab_remap_task;
	params.pool_hooks.pool_pre_create =
		(void *)nexus->primary_pool_ops->pool_pre_create;
	params.pool_hooks.pool_post_create =
		(void *)nexus->primary_pool_ops->pool_post_create;
	params.pool_hooks.pool_destroy =
		(void *)nexus->primary_pool_ops->pool_destroy;
	params.pool_hooks.task_pre_put	   =
		(void *)nexus->primary_pool_ops->task_pre_put;
	params.pool_hooks.task_post_get	   =
		(void *)nexus->primary_pool_ops->task_post_get;

	/* set pool helpers to the transport */
	if (nexus->transport->set_pools_cls) {
		pool_cls.pool		= NULL;
		pool_cls.task_get	= (void *)xio_tasks_pool_get;
		pool_cls.task_lookup	= (void *)xio_tasks_pool_lookup;
		pool_cls.task_put	= xio_tasks_pool_put;

		nexus->transport->set_pools_cls(nexus->transport_hndl,
					       NULL,
					       &pool_cls);
	}

	/* initialize the tasks pool */
	nexus->primary_tasks_pool = xio_tasks_pool_create(&params);
	if (nexus->primary_tasks_pool == NULL) {
		ERROR_LOG("xio_tasks_pool_create failed\n");
		goto cleanup;
	}

	return 0;

cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_primary_pool_recreate					     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_primary_pool_recreate(struct xio_nexus *nexus)
{
	struct xio_tasks_pool_cls	pool_cls;

	if (nexus->primary_pool_ops == NULL)
		return -1;

	if (nexus->primary_tasks_pool == NULL)
		return -1;

	/* set pool helpers to the transport */
	if (nexus->transport->set_pools_cls) {
		pool_cls.pool		= NULL;
		pool_cls.task_get	= (void *)xio_tasks_pool_get;
		pool_cls.task_lookup	= (void *)xio_tasks_pool_lookup;
		pool_cls.task_put	= xio_tasks_pool_put;

		nexus->transport->set_pools_cls(nexus->transport_hndl,
					       NULL,
					       &pool_cls);
	}
	/* Equivalent to old xio_rdma_primary_pool_run,
	 * will call xio_rdma_rearm_rq
	 */
	if (nexus->primary_pool_ops->pool_post_create)
		nexus->primary_pool_ops->pool_post_create(
				nexus->transport_hndl,
				nexus->primary_tasks_pool,
				nexus->primary_tasks_pool->dd_data);


	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_primary_pool_destroy					     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_primary_pool_destroy(struct xio_nexus *nexus)
{
	if (!nexus->primary_tasks_pool)
		return -1;

	xio_tasks_pool_destroy(nexus->primary_tasks_pool);
	return  0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_release_cb							     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_release_cb(void *data)
{
	struct xio_nexus *nexus = data;

	TRACE_LOG("physical nexus close. nexus:%p rdma_hndl:%p\n",
		  nexus, nexus->transport_hndl);

	if (!nexus->is_listener)
		xio_nexus_cache_remove(nexus->cid);

	if (nexus->state != XIO_NEXUS_STATE_DISCONNECTED) {
		nexus->state = XIO_NEXUS_STATE_CLOSED;
		TRACE_LOG("nexus state changed to closed\n");
	}

	/* now it is zero */
	if (nexus->transport->close)
		nexus->transport->close(nexus->transport_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_release							     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_release(void *data)
{
	struct xio_nexus *nexus = data;

	TRACE_LOG("physical nexus close. nexus:%p rdma_hndl:%p\n",
		  nexus, nexus->transport_hndl);

	if (xio_is_delayed_work_pending(&nexus->close_time_hndl)) {
		xio_ctx_del_delayed_work(nexus->transport_hndl->ctx,
					 &nexus->close_time_hndl);
	}

	xio_nexus_release_cb(data);
}

/*---------------------------------------------------------------------------*/
/* xio_on_context_close							     */
/*---------------------------------------------------------------------------*/
static void xio_on_context_close(struct xio_nexus *nexus,
				 struct xio_context *ctx)
{
	TRACE_LOG("xio_on_context_close. nexus:%p, ctx:%p\n", nexus, ctx);

	/* remove the nexus from table */
	xio_nexus_cache_remove(nexus->cid);

	if (xio_is_delayed_work_pending(&nexus->close_time_hndl)) {
		xio_ctx_del_delayed_work(ctx,
					 &nexus->close_time_hndl);
	}

	/* shut down the context and its dependent without waiting */
	if (nexus->transport->context_shutdown)
		nexus->transport->context_shutdown(nexus->transport_hndl, ctx);

	/* at that stage the nexus->transport_hndl no longer exist */
	nexus->transport_hndl = NULL;

	/* close the nexus */
	xio_nexus_destroy(nexus);
}

/*---------------------------------------------------------------------------*/
/* xio_on_context_event							     */
/*---------------------------------------------------------------------------*/
static int xio_on_context_event(void *observer, void *sender, int event,
				void *event_data)
{
	TRACE_LOG("xio_on_context_event\n");
	if (event == XIO_CONTEXT_EVENT_CLOSE) {
		TRACE_LOG("context: [close] ctx:%p\n", sender);
		xio_on_context_close(observer, sender);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_create							     */
/*---------------------------------------------------------------------------*/
struct xio_nexus *xio_nexus_create(struct xio_nexus *parent_nexus,
				   struct xio_transport_base *transport_hndl)
{
	struct xio_nexus		*nexus;
	int			retval;


	if (parent_nexus->transport_hndl->is_client)
		return NULL;

	/* allocate nexus */
	nexus = kcalloc(1, sizeof(struct xio_nexus), GFP_KERNEL);
	if (!nexus) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcalloc failed. %m\n");
		return NULL;
	}

	XIO_OBSERVER_INIT(&nexus->trans_observer, nexus,
			  xio_nexus_on_transport_event);

	XIO_OBSERVABLE_INIT(&nexus->observable, nexus);

	xio_nexus_init_observers_htbl(nexus);

	/* start listen to context events */
	XIO_OBSERVER_INIT(&nexus->ctx_observer, nexus,
			  xio_on_context_event);

	INIT_LIST_HEAD(&nexus->tx_queue);

	xio_context_reg_observer(transport_hndl->ctx, &nexus->ctx_observer);


	/* add the nexus to temporary list */
	nexus->transport_hndl		= transport_hndl;
	nexus->transport			= parent_nexus->transport;
	kref_init(&nexus->kref);
	nexus->state			= XIO_NEXUS_STATE_OPEN;
	nexus->is_first_req		= 1;

	xio_nexus_cache_add(nexus, &nexus->cid);

	/* add  the new nexus as observer to transport */
	xio_transport_reg_observer(nexus->transport_hndl,
				   &nexus->trans_observer);

	if (nexus->transport->get_pools_setup_ops) {
		nexus->transport->get_pools_setup_ops(nexus->transport_hndl,
						     &nexus->initial_pool_ops,
						     &nexus->primary_pool_ops);
	} else {
		ERROR_LOG("transport does not implement \"add_observer\"\n");
		goto cleanup;
	}

	retval = xio_nexus_initial_pool_create(nexus);
	if (retval != 0) {
		ERROR_LOG("failed to setup initial pool\n");
		goto cleanup;
	}

	TRACE_LOG("nexus: [new] ptr:%p, transport_hndl:%p\n", nexus,
		  nexus->transport_hndl);

	return nexus;

cleanup:
	xio_nexus_destroy(nexus);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_message_error						     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_on_message_error(struct xio_nexus *nexus,
				       union xio_transport_event_data
				       *event_data)
{
	union xio_nexus_event_data	nexus_event_data;

	nexus_event_data.msg_error.reason =  event_data->msg_error.reason;
	nexus_event_data.msg_error.task	=  event_data->msg_error.task;

	xio_observable_notify_any_observer(&nexus->observable,
					   XIO_NEXUS_EVENT_MESSAGE_ERROR,
					   &nexus_event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_new_transport						     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_on_new_transport(struct xio_nexus *nexus,
				       union xio_transport_event_data
				       *event_data)
{
	union xio_nexus_event_data	nexus_event_data;
	struct xio_nexus			*child_nexus;

	child_nexus = xio_nexus_create(
			nexus,
			event_data->new_connection.child_trans_hndl);

	nexus_event_data.new_nexus.child_nexus = child_nexus;
	if (child_nexus == NULL) {
		ERROR_LOG("failed to create child nexus\n");
		goto exit;
	}

	/* notify of new child to server */
	xio_nexus_notify_server(
			nexus,
			XIO_NEXUS_EVENT_NEW_CONNECTION,
			&nexus_event_data);

	return;
exit:
	xio_nexus_notify_server(
			nexus,
			XIO_NEXUS_EVENT_ERROR,
			&nexus_event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_transport_closed					     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_on_transport_closed(struct xio_nexus *nexus,
					  union xio_transport_event_data
					  *event_data)
{
	xio_nexus_destroy(nexus);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_transport_error		                                     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_on_transport_error(struct xio_nexus *nexus,
					 union xio_transport_event_data
					 *event_data)
{
	union xio_nexus_event_data nexus_event_data;

	nexus_event_data.error.reason =  event_data->error.reason;

	xio_observable_notify_all_observers(&nexus->observable,
					    XIO_NEXUS_EVENT_ERROR,
					    &nexus_event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_transport_established					     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_on_transport_established(struct xio_nexus *nexus,
					       union xio_transport_event_data
					       *event_data)
{
	if (!nexus->transport_hndl->is_client)
		return;

	xio_nexus_initial_pool_create(nexus);

	xio_nexus_send_setup_req(nexus);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_transport_disconnected				             */
/*---------------------------------------------------------------------------*/
static void xio_nexus_on_transport_disconnected(struct xio_nexus *nexus,
						union xio_transport_event_data
						*event_data)
{
	int ret;

	/* cancel old timers */
	if (xio_is_delayed_work_pending(&nexus->close_time_hndl))
		xio_ctx_del_delayed_work(nexus->transport_hndl->ctx,
					 &nexus->close_time_hndl);

	/* Try to reconnect */
	if (g_options.reconnect) {
			if (nexus->transport_hndl->is_client)
			ret = xio_nexus_client_reconnect(nexus);
		else
			ret = xio_nexus_server_reconnect(nexus);

		if (!ret) {
			TRACE_LOG("reconnect attempt nexus:%p\n", nexus);
			return;
		} else {
			ERROR_LOG("can't reconnect nexus:%p\n", nexus);
		}
	}

	/* Can't reconnect */

	nexus->state = XIO_NEXUS_STATE_DISCONNECTED;
	TRACE_LOG("nexus state changed to disconnected nexus:%p\n", nexus);

	if (!xio_observable_is_empty(&nexus->observable)) {
		xio_observable_notify_all_observers(
				&nexus->observable,
				XIO_NEXUS_EVENT_DISCONNECTED,
				&event_data);
	} else {
		xio_nexus_release(nexus);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_new_message				                     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_new_message(struct xio_nexus *nexus,
				    union xio_transport_event_data *event_data)
{
	int	retval = -1;
	struct xio_task	*task = event_data->msg.task;

	switch (task->tlv_type) {
	case XIO_NEXUS_SETUP_RSP:
		retval = xio_nexus_on_recv_setup_rsp(nexus, task);
		break;
	case XIO_NEXUS_SETUP_REQ:
		retval = xio_nexus_on_recv_setup_req(nexus, task);
		break;

	default:
		if (IS_REQUEST(task->tlv_type))
			retval = xio_nexus_on_recv_req(nexus, task);
		else
			retval = xio_nexus_on_recv_rsp(nexus, task);
		break;
	};

	if (retval != 0) {
		ERROR_LOG("failed to handle message. " \
			  "nexus:%p tlv_type:%d op:%d\n",
			  nexus, task->tlv_type, event_data->msg.op);
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_send_completion				                     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_send_completion(struct xio_nexus *nexus,
					union xio_transport_event_data
					*event_data)
{
	int	retval = -1;
	struct xio_task	*task = event_data->msg.task;

	switch (task->tlv_type) {
	case XIO_NEXUS_SETUP_RSP:
		retval = xio_nexus_on_send_setup_rsp_comp(nexus, task);
		break;
	case XIO_NEXUS_SETUP_REQ:
		retval = 0;
		break;
	default:
		retval  = xio_nexus_on_send_msg_comp(nexus, task);
		break;
	};

	if (retval != 0) {
		ERROR_LOG("failed to handle message. " \
			  "nexus:%p tlv_type:%d op:%d\n",
			  nexus, task->tlv_type, event_data->msg.op);
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_assign_in_buf						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_assign_in_buf(struct xio_nexus *nexus,
				      union xio_transport_event_data
				      *event_data)
{
	int				retval = 0;
	struct xio_task			*task = event_data->msg.task;
	union xio_nexus_event_data	nexus_event_data;

	nexus_event_data.assign_in_buf.task = event_data->msg.task;
	task->nexus = nexus;

	xio_observable_notify_any_observer(
			&nexus->observable,
			XIO_NEXUS_EVENT_ASSIGN_IN_BUF,
			&nexus_event_data);

	event_data->assign_in_buf.is_assigned =
		nexus_event_data.assign_in_buf.is_assigned;

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_cancel_request						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_cancel_request(struct xio_nexus *nexus,
				       union xio_transport_event_data
				       *event_data)
{
	union xio_nexus_event_data nexus_event_data = {
		.cancel.ulp_msg		= event_data->cancel.ulp_msg,
		.cancel.ulp_msg_sz	= event_data->cancel.ulp_msg_sz,
		.cancel.task		= event_data->cancel.task,
		.cancel.result		= event_data->cancel.result,
	};

	/* route the message to any of the sessions */
	xio_observable_notify_any_observer(
			&nexus->observable,
			XIO_NEXUS_EVENT_CANCEL_REQUEST,
			&nexus_event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_assign_in_buf						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_cancel_response(struct xio_nexus *nexus,
					union xio_transport_event_data
					*event_data)
{
	union xio_nexus_event_data nexus_event_data = {
		.cancel.ulp_msg		= event_data->cancel.ulp_msg,
		.cancel.ulp_msg_sz	= event_data->cancel.ulp_msg_sz,
		.cancel.task		= event_data->cancel.task,
		.cancel.result		= event_data->cancel.result,
	};

	/* route the message to any of the sessions */
	xio_observable_notify_any_observer(
			&nexus->observable,
			XIO_NEXUS_EVENT_CANCEL_RESPONSE,
			&nexus_event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_on_transport_event		                                     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_on_transport_event(void *observer, void *sender,
					int event, void *event_data)
{
	struct xio_nexus		*nexus = observer;
	union xio_transport_event_data *ev_data = event_data;


	switch (event) {
	case XIO_TRANSPORT_NEW_MESSAGE:
/*
		TRACE_LOG("nexus: [notification] - new message. " \
			 "nexus:%p, transport:%p\n", observer, sender);
*/
		xio_nexus_on_new_message(nexus, ev_data);
		break;
	case XIO_TRANSPORT_SEND_COMPLETION:
/*
		TRACE_LOG("nexus: [notification] - send completion. " \
			 "nexus:%p, transport:%p\n", observer, sender);
*/
		xio_nexus_on_send_completion(nexus, ev_data);
		break;
	case XIO_TRANSPORT_ASSIGN_IN_BUF:
/*
		DEBUG_LOG("nexus: [notification] - assign in buffer. " \
			 "nexus:%p, transport:%p\n", observer, sender);
*/
		xio_nexus_on_assign_in_buf(nexus, ev_data);
		break;
	case XIO_TRANSPORT_MESSAGE_ERROR:
		DEBUG_LOG("nexus: [notification] - message error. " \
			 "nexus:%p, transport:%p\n", observer, sender);
		xio_nexus_on_message_error(nexus, ev_data);
		break;
	case XIO_TRANSPORT_CANCEL_REQUEST:
		DEBUG_LOG("nexus: [notification] - cancel request. " \
			 "nexus:%p, transport:%p\n", observer, sender);
		xio_nexus_on_cancel_request(nexus, ev_data);
		break;
	case XIO_TRANSPORT_CANCEL_RESPONSE:
		DEBUG_LOG("nexus: [notification] - cancel respnose. " \
			 "nexus:%p, transport:%p\n", observer, sender);
		xio_nexus_on_cancel_response(nexus, ev_data);
		break;
	case XIO_TRANSPORT_NEW_CONNECTION:
		DEBUG_LOG("nexus: [notification] - new transport. " \
			 "nexus:%p, transport:%p\n", observer, sender);
		xio_nexus_on_new_transport(nexus, ev_data);
		break;
	case XIO_TRANSPORT_ESTABLISHED:
		DEBUG_LOG("nexus: [notification] - transport established. " \
			 "nexus:%p, transport:%p\n", observer, sender);
		xio_nexus_on_transport_established(nexus, ev_data);
		break;
	case XIO_TRANSPORT_DISCONNECTED:
		DEBUG_LOG("nexus: [notification] - transport disconnected. "  \
			 "nexus:%p, transport:%p\n", observer, sender);
		xio_nexus_on_transport_disconnected(nexus, ev_data);
		break;
	case XIO_TRANSPORT_CLOSED:
		DEBUG_LOG("nexus: [notification] - transport closed. "  \
			 "nexus:%p, transport:%p\n", observer, sender);
		xio_nexus_on_transport_closed(nexus, ev_data);
		break;
	case XIO_TRANSPORT_REFUSED:
		DEBUG_LOG("nexus: [notification] - transport refused. " \
			 "nexus:%p, transport:%p\n", observer, sender);
		if (nexus->state == XIO_NEXUS_STATE_RECONNECT) {
			xio_nexus_client_reconnect_failed(nexus);
		} else {
			nexus->state = XIO_NEXUS_STATE_DISCONNECTED;
			TRACE_LOG("nexus state changed to disconnected\n");
			xio_observable_notify_all_observers(
					&nexus->observable,
					XIO_NEXUS_EVENT_REFUSED,
					&event_data);
		}
		break;
	case XIO_TRANSPORT_ERROR:
		DEBUG_LOG("nexus: [notification] - transport error. " \
			 "nexus:%p, transport:%p\n", observer, sender);
		if (nexus->state == XIO_NEXUS_STATE_RECONNECT)
			xio_nexus_client_reconnect_failed(nexus);
		else
			xio_nexus_on_transport_error(nexus, ev_data);
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_destroy		                                             */
/*---------------------------------------------------------------------------*/
static int xio_nexus_destroy(struct xio_nexus *nexus)
{
	TRACE_LOG("nexus:%p - close complete\n", nexus);

	if (nexus->transport_hndl)
		xio_transport_unreg_observer(nexus->transport_hndl,
					     &nexus->trans_observer);

	xio_nexus_free_observers_htbl(nexus);
	xio_observable_unreg_all_observers(&nexus->observable);

	if (xio_is_delayed_work_pending(&nexus->close_time_hndl)) {
		if (nexus->transport_hndl)
			xio_ctx_del_delayed_work(
					nexus->transport_hndl->ctx,
					&nexus->close_time_hndl);
	}
	xio_nexus_flush_tx_queue(nexus);

	xio_nexus_initial_pool_free(nexus);

	xio_nexus_primary_free_tasks(nexus);
	xio_nexus_primary_pool_destroy(nexus);

	xio_nexus_cache_remove(nexus->cid);

	if (nexus->transport_hndl)
		xio_context_unreg_observer(nexus->transport_hndl->ctx,
					   &nexus->ctx_observer);

	kfree(nexus->portal_uri);
	nexus->portal_uri = NULL;

	kfree(nexus->out_if_addr);
	nexus->out_if_addr = NULL;

	kfree(nexus);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_open		                                             */
/*---------------------------------------------------------------------------*/
struct xio_nexus *xio_nexus_open(struct xio_context *ctx,
				 const char *portal_uri,
				 struct xio_observer  *observer, uint32_t oid)
{
	struct xio_transport		*transport;
	struct xio_nexus			*nexus;
	char				proto[8];


	/* look for opened nexus */
	nexus = xio_nexus_cache_find(ctx, portal_uri);
	if (nexus != NULL) {
		if (observer) {
			xio_observable_reg_observer(&nexus->observable,
						    observer);
			xio_nexus_hash_observer(nexus, observer, oid);
		}
		if (xio_is_delayed_work_pending(&nexus->close_time_hndl)) {
			xio_ctx_del_delayed_work(ctx,
						 &nexus->close_time_hndl);
			kref_init(&nexus->kref);
		} else {
			xio_nexus_addref(nexus);
		}

		TRACE_LOG("nexus: [addref] nexus:%p, refcnt:%d\n", nexus,
			  atomic_read(&nexus->kref.refcount));

		return nexus;
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
	/* allocate nexus */
	nexus = kcalloc(1, sizeof(struct xio_nexus), GFP_KERNEL);
	if (nexus == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcalloc failed. %m\n");
		return NULL;
	}

	XIO_OBSERVER_INIT(&nexus->trans_observer, nexus,
			  xio_nexus_on_transport_event);
	XIO_OBSERVABLE_INIT(&nexus->observable, nexus);
	INIT_LIST_HEAD(&nexus->tx_queue);

	xio_nexus_init_observers_htbl(nexus);

	if (observer) {
		xio_observable_reg_observer(&nexus->observable, observer);
		xio_nexus_hash_observer(nexus, observer, oid);
	}

	/* start listen to context events */
	XIO_OBSERVER_INIT(&nexus->ctx_observer, nexus,
			  xio_on_context_event);

	xio_context_reg_observer(ctx, &nexus->ctx_observer);

	nexus->transport_hndl = transport->open(transport, ctx,
					       &nexus->trans_observer);
	if (nexus->transport_hndl == NULL) {
		ERROR_LOG("transport open failed\n");
		goto cleanup;
	}
	nexus->transport	= transport;
	kref_init(&nexus->kref);
	nexus->state = XIO_NEXUS_STATE_OPEN;

	if (nexus->transport->get_pools_setup_ops) {
		nexus->transport->get_pools_setup_ops(nexus->transport_hndl,
						      &nexus->initial_pool_ops,
						      &nexus->primary_pool_ops);
	} else {
		ERROR_LOG("transport does not implement \"add_observer\"\n");
		goto cleanup;
	}

	xio_nexus_cache_add(nexus, &nexus->cid);

	TRACE_LOG("nexus: [new] nexus:%p, transport_hndl:%p\n", nexus,
		  nexus->transport_hndl);

	return nexus;
cleanup:
	xio_nexus_destroy(nexus);

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_reconnect		                                             */
/* client side reconnection						     */
/*---------------------------------------------------------------------------*/
int xio_nexus_reconnect(struct xio_nexus *nexus)
{
	struct xio_transport *transport;
	struct xio_context *ctx;
	int retval;

	if (nexus->state != XIO_NEXUS_STATE_RECONNECT) {
		xio_set_error(XIO_E_STATE);
		ERROR_LOG("reconnect not permitted in current state(%d)\n",
			  nexus->state);
		return -1;
	}

	transport = nexus->transport;
	ctx = nexus->transport_hndl->ctx;

	nexus->new_transport_hndl = transport->open(nexus->transport, ctx,
						   &nexus->trans_observer);

	if (nexus->new_transport_hndl == NULL) {
		ERROR_LOG("transport open failed\n");
		return -1;
	}

	retval = transport->connect(nexus->new_transport_hndl,
				    nexus->portal_uri,
				    nexus->out_if_addr);

	if (retval != 0) {
		/* ignore close notification */
		xio_observable_unreg_observer(
				&nexus->new_transport_hndl->observable,
				&nexus->trans_observer);

		transport->close(nexus->new_transport_hndl);
		nexus->new_transport_hndl = NULL;
		ERROR_LOG("transport reconnect failed\n");
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_connect		                                             */
/*---------------------------------------------------------------------------*/
int xio_nexus_connect(struct xio_nexus *nexus, const char *portal_uri,
		      struct xio_observer *observer, const char *out_if)
{
	int retval;

	if (nexus->transport->connect == NULL) {
		ERROR_LOG("transport does not implement \"connect\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}

	switch (nexus->state) {
	case XIO_NEXUS_STATE_OPEN:
		/* for reconnect */
		nexus->portal_uri = kstrdup(portal_uri, GFP_KERNEL);
		if (!nexus->portal_uri) {
			ERROR_LOG("memory alloc failed\n");
			xio_set_error(ENOMEM);
			goto cleanup1;
		}
		if (out_if) {
			nexus->out_if_addr  = kstrdup(out_if, GFP_KERNEL);
			if (!nexus->out_if_addr) {
				ERROR_LOG("memory alloc failed\n");
				xio_set_error(ENOMEM);
				goto cleanup2;
			}
		}
		retval = nexus->transport->connect(nexus->transport_hndl,
						  portal_uri,
						  out_if);
		if (retval != 0) {
			ERROR_LOG("transport connect failed\n");
			goto cleanup3;
		}
		nexus->state = XIO_NEXUS_STATE_CONNECTING;
		break;
	case XIO_NEXUS_STATE_CONNECTED:
		xio_nexus_notify_observer(nexus, observer,
					  XIO_NEXUS_EVENT_ESTABLISHED,
					  NULL);
		break;
	default:
		break;
	}

	return 0;

cleanup3:
	kfree(nexus->out_if_addr);
	nexus->out_if_addr = NULL;
cleanup2:
	kfree(nexus->portal_uri);
	nexus->portal_uri = NULL;
cleanup1:
	ERROR_LOG("transport connect failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_listen			                                     */
/*---------------------------------------------------------------------------*/
int xio_nexus_listen(struct xio_nexus *nexus, const char *portal_uri,
		     uint16_t *src_port, int backlog)
{
	int retval;

	if (nexus->transport->listen == NULL) {
		ERROR_LOG("transport does not implement \"listen\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}
	if (nexus->state == XIO_NEXUS_STATE_OPEN) {
		/* do not hold the listener nexus in storage */
		xio_nexus_cache_remove(nexus->cid);
		retval = nexus->transport->listen(nexus->transport_hndl,
						 portal_uri, src_port,
						 backlog);
		if (retval != 0) {
			DEBUG_LOG("transport listen failed. uri:[%s]\n",
				  portal_uri);
			return -1;
		}
		nexus->state = XIO_NEXUS_STATE_LISTEN;
		nexus->is_listener = 1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_accept			                                     */
/*---------------------------------------------------------------------------*/
int xio_nexus_accept(struct xio_nexus *nexus)
{
	int retval;

	if (nexus->transport->accept == NULL) {
		ERROR_LOG("transport does not implement \"accept\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}
	if (nexus->state == XIO_NEXUS_STATE_OPEN) {
		retval = nexus->transport->accept(nexus->transport_hndl);
		if (retval != 0) {
			ERROR_LOG("transport accept failed.\n");
			return -1;
		}
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_reject			                                     */
/*---------------------------------------------------------------------------*/
int xio_nexus_reject(struct xio_nexus *nexus)
{
	int retval;

	if (nexus->transport->reject == NULL) {
		ERROR_LOG("transport does not implement \"reject\"\n");
		xio_set_error(ENOSYS);
		return -1;
	}
	if (nexus->state == XIO_NEXUS_STATE_OPEN) {
		retval = nexus->transport->reject(nexus->transport_hndl);
		if (retval != 0) {
			ERROR_LOG("transport reject failed.\n");
			return -1;
		}
	}
	return 0;
}
/*---------------------------------------------------------------------------*/
/* xio_nexus_delayed_close		                                     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_delayed_close(struct kref *kref)
{
	struct xio_nexus *nexus = container_of(kref,
					     struct xio_nexus,
					     kref);
	int		retval;

	TRACE_LOG("xio_nexus_deleyed close. nexus:%p, state:%d\n",
		  nexus, nexus->state);

	switch (nexus->state) {
	case XIO_NEXUS_STATE_LISTEN:
		/* the listener nexus, called from xio_unbind */
	case XIO_NEXUS_STATE_DISCONNECTED:
		xio_nexus_release(nexus);
		break;
	default:
		retval = xio_ctx_add_delayed_work(
				nexus->transport_hndl->ctx,
				XIO_NEXUS_CLOSE_TIMEOUT, nexus,
				xio_nexus_release_cb,
				&nexus->close_time_hndl);
		if (retval)
			ERROR_LOG("xio_nexus_delayed_close failed\n");
		break;
	}
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_close		                                             */
/*---------------------------------------------------------------------------*/
void xio_nexus_close(struct xio_nexus *nexus, struct xio_observer *observer)
{
	TRACE_LOG("nexus: [putref] ptr:%p, refcnt:%d\n", nexus,
		  atomic_read(&nexus->kref.refcount));

	if (observer) {
		xio_nexus_notify_observer(
				nexus, observer,
				XIO_NEXUS_EVENT_CLOSED, NULL);
		xio_nexus_unreg_observer(nexus, observer);
	}
	kref_put(&nexus->kref, xio_nexus_delayed_close);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_flush_tx_queue						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_flush_tx_queue(struct xio_nexus *nexus)
{
	struct xio_task *ptask, *next_ptask;

	list_for_each_entry_safe(ptask, next_ptask, &nexus->tx_queue,
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
/* xio_nexus_xmit							     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_xmit(struct xio_nexus *nexus)
{
	int		retval;
	struct xio_task *task;

	if (!nexus->transport) {
		ERROR_LOG("transport not initialized\n");
		return -1;
	}
	if (!nexus->transport->send)
		return 0;

	while (1) {
		if (list_empty(&nexus->tx_queue))
			break;

		task = list_first_entry(&nexus->tx_queue,
					struct xio_task,  tasks_list_entry);
		retval = nexus->transport->send(nexus->transport_hndl, task);
		if (retval != 0) {
			union xio_nexus_event_data nexus_event_data;

			if (xio_errno() == EAGAIN)
				return 0;

			ERROR_LOG("transport send failed err:%d\n",
				  xio_errno());
			nexus_event_data.msg_error.reason = xio_errno();
			nexus_event_data.msg_error.task	= task;

			xio_observable_notify_any_observer(
					&nexus->observable,
					XIO_NEXUS_EVENT_MESSAGE_ERROR,
					&nexus_event_data);
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_send							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_send(struct xio_nexus *nexus, struct xio_task *task)
{
	int		retval;

	if (!nexus->transport) {
		ERROR_LOG("transport not initialized\n");
		return -1;
	}
	if (!nexus->transport->send)
		return 0;

	/* push to end of the queue */
	list_move_tail(&task->tasks_list_entry, &nexus->tx_queue);

	/* xmit it to the transport */
	retval = xio_nexus_xmit(nexus);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_poll							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_poll(struct xio_nexus *nexus, long min_nr, long nr,
		   struct timespec *timeout)
{
	int	retval = 0;

	if (nexus->transport->poll) {
		retval = nexus->transport->poll(nexus->transport_hndl,
					       min_nr, nr, timeout);
		if (retval < 0) {
			ERROR_LOG("transport poll failed\n");
			return -1;
		}
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_set_opt							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_set_opt(struct xio_nexus *nexus, int optname, const void *optval,
		      int optlen)
{
	if (nexus->transport->set_opt)
		return nexus->transport->set_opt(nexus->transport_hndl,
				optname, optval, optlen);

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_get_opt							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_get_opt(struct xio_nexus *nexus, int optname, void *optval,
		      int *optlen)
{
	if (nexus->transport->get_opt)
		return nexus->transport->get_opt(nexus->transport_hndl,
				optname, optval, optlen);

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_get_peer_addr						     */
/*---------------------------------------------------------------------------*/
int xio_nexus_get_peer_addr(struct xio_nexus *nexus,
			    struct sockaddr_storage *sa, socklen_t len)
{
	memcpy(sa, &nexus->transport_hndl->peer_addr, len);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_get_local_addr						     */
/*---------------------------------------------------------------------------*/
int xio_nexus_get_local_addr(struct xio_nexus *nexus,
			     struct sockaddr_storage *sa, socklen_t len)
{
	memcpy(sa, &nexus->transport_hndl->local_addr, len);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_cancel_req							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_cancel_req(struct xio_nexus *nexus, struct xio_msg *req,
			 uint64_t stag, void *ulp_msg, size_t ulp_msg_sz)
{
	if (nexus->transport->cancel_req)
		return nexus->transport->cancel_req(nexus->transport_hndl,
						   req, stag,
						   ulp_msg, ulp_msg_sz);

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_cancel_rsp							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_cancel_rsp(struct xio_nexus *nexus, struct xio_task *task,
			 enum xio_status result, void *ulp_msg,
			 size_t ulp_msg_sz)
{
	if (nexus->transport->cancel_req)
		return nexus->transport->cancel_rsp(nexus->transport_hndl,
						   task, result,
						   ulp_msg, ulp_msg_sz);
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_server_reconnect_timeout					     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_server_reconnect_timeout(void *data)
{
	struct xio_nexus *nexus = data;

	/* No reconnect within timeout */
	nexus->state = XIO_NEXUS_STATE_DISCONNECTED;
	TRACE_LOG("nexus state changed to disconnected\n");
	xio_observable_notify_all_observers(&nexus->observable,
					    XIO_NEXUS_EVENT_DISCONNECTED,
					    NULL);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_server_reconnect		                                     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_server_reconnect(struct xio_nexus *nexus)
{
	int		retval;

	if (nexus->state != XIO_NEXUS_STATE_CONNECTED)
		return -1;

	xio_nexus_state_set(nexus, XIO_NEXUS_STATE_RECONNECT);

	/* Just wait and see if some client tries to reconnect */
	retval = xio_ctx_add_delayed_work(nexus->transport_hndl->ctx,
					  XIO_SERVER_TIMEOUT, nexus,
					  xio_nexus_server_reconnect_timeout,
					  &nexus->close_time_hndl);
	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_client_reconnect_timeout					     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_client_reconnect_timeout(void *data)
{
	struct xio_nexus *nexus = data;
	int retval;

	ERROR_LOG("%s\n", __func__);
	/* Try to reconnect after the waiting period */
	retval = xio_nexus_reconnect(nexus);
	if (!retval) {
		TRACE_LOG("reconnect succeed\n");
		return;
	}

	if (nexus->reconnect_retries) {
		nexus->reconnect_retries--;
		retval = xio_ctx_add_delayed_work(
				nexus->transport_hndl->ctx,
				xio_msecs[nexus->reconnect_retries],
				nexus,
				xio_nexus_client_reconnect_timeout,
				&nexus->close_time_hndl);
	} else {
		/* retries number exceeded */
		nexus->state = XIO_NEXUS_STATE_DISCONNECTED;
		TRACE_LOG("nexus state changed to disconnected\n");
		xio_observable_notify_all_observers(
				&nexus->observable,
				XIO_NEXUS_EVENT_DISCONNECTED,
				NULL);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_client_reconnect_failed					     */
/*---------------------------------------------------------------------------*/
static void xio_nexus_client_reconnect_failed(void *data)
{
	struct xio_nexus *nexus = data;
	int retval;

	/* Failed to reconnect (connect was called) */
	if (nexus->reconnect_retries) {
		nexus->reconnect_retries--;
		retval = xio_ctx_add_delayed_work(
				nexus->transport_hndl->ctx,
				xio_msecs[nexus->reconnect_retries],
				nexus,
				xio_nexus_client_reconnect_timeout,
				&nexus->close_time_hndl);
		if (retval)
			ERROR_LOG("adding delayed work failed\n");
	} else {
		/* retries number exceeded */
		nexus->state = XIO_NEXUS_STATE_DISCONNECTED;
		TRACE_LOG("nexus state changed to disconnected\n");
		xio_observable_notify_all_observers(
				&nexus->observable,
				XIO_NEXUS_EVENT_DISCONNECTED,
				NULL);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_client_reconnect						     */
/*---------------------------------------------------------------------------*/
static int xio_nexus_client_reconnect(struct xio_nexus *nexus)
{
	/* With client we do an exponential back-off first delay is 0 */
	int		retval;

	if (nexus->state != XIO_NEXUS_STATE_CONNECTED)
		return -1;

	if (nexus->transport->dup2 == NULL)
		return -1;

	xio_nexus_state_set(nexus, XIO_NEXUS_STATE_RECONNECT);

	/* All portal_uri and out_if were saved in the nexus
	 * observer is not used in this flow
	 */

	/* Three retries but vector start from 0 */
	nexus->reconnect_retries = 3;
	/* Try to reconnect immediately
	 * Note connect may succeed but we may get a reject */
	retval = xio_nexus_reconnect(nexus);
	if (!retval)
		return 0;

	nexus->reconnect_retries = 2;
	retval = xio_ctx_add_delayed_work(nexus->transport_hndl->ctx,
					  xio_msecs[nexus->reconnect_retries],
					  nexus,
					  xio_nexus_client_reconnect_timeout,
					  &nexus->close_time_hndl);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_update_task						     */
/*---------------------------------------------------------------------------*/
int xio_nexus_update_task(struct xio_nexus *nexus, struct xio_task *task)
{
	/* transport may not need to update tasks */
	if (nexus->transport->update_task == NULL)
		return 0;

	if (nexus->transport->update_task(nexus->transport_hndl, task))
		return -1;

	return 0;
}
