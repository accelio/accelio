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
#ifndef XIO_NEXUS_H
#define XIO_NEXUS_H

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
struct xio_nexus;

/*---------------------------------------------------------------------------*/
/* enum									     */
/*---------------------------------------------------------------------------*/
enum xio_nexus_event {
	XIO_NEXUS_EVENT_NEW_CONNECTION,
	XIO_NEXUS_EVENT_ESTABLISHED,
	XIO_NEXUS_EVENT_DISCONNECTED,
	XIO_NEXUS_EVENT_RECONNECTING,
	XIO_NEXUS_EVENT_RECONNECTED,
	XIO_NEXUS_EVENT_CLOSED,
	XIO_NEXUS_EVENT_REFUSED,
	XIO_NEXUS_EVENT_NEW_MESSAGE,
	XIO_NEXUS_EVENT_SEND_COMPLETION,
	XIO_NEXUS_EVENT_ASSIGN_IN_BUF,
	XIO_NEXUS_EVENT_CANCEL_REQUEST,
	XIO_NEXUS_EVENT_CANCEL_RESPONSE,
	XIO_NEXUS_EVENT_ERROR,
	XIO_NEXUS_EVENT_MESSAGE_ERROR,
	XIO_NEXUS_EVENT_DIRECT_RDMA_COMPLETION,
};

enum xio_nexus_state {
	XIO_NEXUS_STATE_INIT,
	XIO_NEXUS_STATE_OPEN,
	XIO_NEXUS_STATE_LISTEN,
	XIO_NEXUS_STATE_CONNECTING,
	XIO_NEXUS_STATE_CONNECTED,
	XIO_NEXUS_STATE_REJECTED,
	XIO_NEXUS_STATE_CLOSED,
	XIO_NEXUS_STATE_DISCONNECTED,
	XIO_NEXUS_STATE_RECONNECT,
	XIO_NEXUS_STATE_ERROR
};

enum xio_nexus_attr_mask {
	XIO_NEXUS_ATTR_TOS			= 1 << 0
};

/*---------------------------------------------------------------------------*/
/* structs	                                                             */
/*---------------------------------------------------------------------------*/
union xio_nexus_event_data {
	struct {
		struct xio_task		*task;
		enum xio_wc_op		op;
		int			pad;
	} msg;
	struct {
		struct xio_task		*task;
		int			is_assigned;
		int			pad;
	} assign_in_buf;
	struct {
		struct xio_task		*task;
		enum xio_status		reason;
		enum xio_msg_direction	direction;
	} msg_error;
	struct {
		struct xio_nexus	*child_nexus;
	} new_nexus;
	struct {
		enum xio_status		reason;
		enum xio_msg_direction	direction;
	} error;
	struct {
		struct xio_task		*task;
		enum xio_status		result;
		int			pad;
		void			*ulp_msg;
		size_t			ulp_msg_sz;
	} cancel;
};

struct xio_nexus_attr {
	uint8_t			tos;	 /**< type of service RFC 2474 */
	uint8_t			pad[3];
};

struct xio_nexus_init_attr {
	uint8_t			tos;	 /**< type of service RFC 2474 */
	uint8_t			pad[3];
};

/**
 * Connection data type
 */
struct xio_nexus {
	struct xio_transport		*transport;
	struct xio_transport_base	*transport_hndl;

	struct xio_tasks_pool		*primary_tasks_pool;
	struct xio_tasks_pool		*initial_tasks_pool;

	struct xio_observer		trans_observer;
	struct xio_observer		ctx_observer;
	struct xio_observer		srv_observer;
	struct xio_observable		observable;
	struct kref			kref;

	int				cid;
	enum xio_nexus_state		state;
	short				is_first_req;
	short				reconnect_retries;
	int				is_listener;
	int				srq_enabled;
	xio_delayed_work_handle_t	close_time_hndl;

	struct list_head		observers_htbl;
	struct list_head		tx_queue;
	struct xio_server		*server;

	/* Client side for reconnect */
	int				server_cid;
	int				server_cid_pad;
	struct xio_transport_base	*new_transport_hndl;
	char				*portal_uri;
	char				*out_if_addr;
	uint32_t			trans_attr_mask;
	struct xio_transport_init_attr	trans_attr;
	struct xio_ev_data		destroy_event;
	struct xio_ev_data		trans_error_event;
	spinlock_t			nexus_obs_lock;
	int 				pad2;
	struct mutex			lock_connect;      /* lock nexus connect */

	HT_ENTRY(xio_nexus, xio_key_int32) nexus_htbl;
};

/*---------------------------------------------------------------------------*/
/* xio_nexus_close							     */
/*---------------------------------------------------------------------------*/
void xio_nexus_close(struct xio_nexus *nexus, struct xio_observer *observer);

/*---------------------------------------------------------------------------*/
/* xio_nexus_open							     */
/*---------------------------------------------------------------------------*/
struct xio_nexus *xio_nexus_open(struct xio_context *ctx,
				 const char *portal_uri,
				 struct xio_observer *observer,
				 uint32_t oid,
				 uint32_t attr_mask,
				 struct xio_nexus_init_attr *init_attr);

/*---------------------------------------------------------------------------*/
/* xio_nexus_connect							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_connect(struct xio_nexus *nexus, const char *portal_uri,
		      struct xio_observer *observer,
		      const char *out_if);

/*---------------------------------------------------------------------------*/
/* xio_nexus_listen							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_listen(struct xio_nexus *nexus, const char *portal_uri,
		     uint16_t *src_port, int backlog);

/*---------------------------------------------------------------------------*/
/* xio_nexus_accept							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_accept(struct xio_nexus *nexus);

/*---------------------------------------------------------------------------*/
/* xio_handler_init							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_reject(struct xio_nexus *nexus);

/*---------------------------------------------------------------------------*/
/* xio_nexus_poll							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_poll(struct xio_nexus *nexus,
		   long min_nr, long nr, struct timespec *timeout);

/*---------------------------------------------------------------------------*/
/* xio_nexus_send							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_send(struct xio_nexus *nexus, struct xio_task *task);

/*---------------------------------------------------------------------------*/
/* xio_nexus_cancel_req							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_cancel_req(struct xio_nexus *nexus,
			 struct xio_msg *req, uint64_t stag,
			 void *ulp_msg, size_t ulp_msg_sz);
/*---------------------------------------------------------------------------*/
/* xio_nexus_cancel_rsp							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_cancel_rsp(struct xio_nexus *nexus,
			 struct xio_task *task, enum xio_status result,
			 void *ulp_msg, size_t ulp_msg_sz);

/*---------------------------------------------------------------------------*/
/* xio_nexus_set_opt							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_set_opt(struct xio_nexus *nexus, int optname,
		      const void *optval, int optlen);

/*---------------------------------------------------------------------------*/
/* xio_nexus_get_opt							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_get_opt(struct xio_nexus *nexus, int optname,
		      void *optval, int *optlen);

/*---------------------------------------------------------------------------*/
/* xio_nexus_get_primary_task						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_nexus_get_primary_task(struct xio_nexus *nexus);

/*---------------------------------------------------------------------------*/
/* xio_nexus_primary_free_tasks						     */
/*---------------------------------------------------------------------------*/
int xio_nexus_primary_free_tasks(struct xio_nexus *nexus);

/*---------------------------------------------------------------------------*/
/* xio_nexus_set_server							     */
/*---------------------------------------------------------------------------*/
void xio_nexus_set_server(struct xio_nexus *nexus, struct xio_server *server);

/*---------------------------------------------------------------------------*/
/* xio_nexus_reg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_nexus_reg_observer(struct xio_nexus *nexus,
			    struct xio_observer *observer,
			    uint32_t oid);

/*---------------------------------------------------------------------------*/
/* xio_nexus_unreg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_nexus_unreg_observer(struct xio_nexus *nexus,
			      struct xio_observer *observer);

/*---------------------------------------------------------------------------*/
/* xio_nexus_observer_lookup						     */
/*---------------------------------------------------------------------------*/
struct xio_observer *xio_nexus_observer_lookup(struct xio_nexus *nexus,
					       uint32_t id);

/*---------------------------------------------------------------------------*/
/* xio_nexus_notify_observer						     */
/*---------------------------------------------------------------------------*/
static inline void xio_nexus_notify_observer(
			      struct xio_nexus *nexus,
			      struct xio_observer *observer,
			      int event, void *event_data)
{
	xio_observable_notify_observer(&nexus->observable, observer,
				       event, event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_get_peer_addr						     */
/*---------------------------------------------------------------------------*/
int xio_nexus_get_peer_addr(struct xio_nexus *nexus,
			    struct sockaddr_storage *sa, socklen_t len);

/*---------------------------------------------------------------------------*/
/* xio_nexus_get_local_addr						     */
/*---------------------------------------------------------------------------*/
int xio_nexus_get_local_addr(struct xio_nexus *nexus,
			     struct sockaddr_storage *sa, socklen_t len);

/*---------------------------------------------------------------------------*/
/* xio_nexus_get_validators_cls						     */
/*---------------------------------------------------------------------------*/
static inline
struct xio_transport_msg_validators_cls *xio_nexus_get_validators_cls(
						struct xio_nexus *nexus)
{
	return &nexus->transport->validators_cls;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_get_proto							     */
/*---------------------------------------------------------------------------*/
static inline int xio_nexus_get_proto(struct xio_nexus *nexus)
{
	return nexus->transport_hndl->proto;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_addref							     */
/*---------------------------------------------------------------------------*/
static inline void xio_nexus_addref(struct xio_nexus *nexus)
{
	if (xio_is_delayed_work_pending(&nexus->close_time_hndl)) {
		kref_init(&nexus->kref);
		xio_ctx_del_delayed_work(nexus->transport_hndl->ctx,
					 &nexus->close_time_hndl);
	} else {
		kref_get(&nexus->kref);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_state_get							     */
/*---------------------------------------------------------------------------*/
static inline enum xio_nexus_state xio_nexus_state_get(struct xio_nexus *nexus)
{
	return nexus->state;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_state_set							     */
/*---------------------------------------------------------------------------*/
static inline void xio_nexus_state_set(struct xio_nexus *nexus,
				       enum xio_nexus_state state)
{
	nexus->state = state;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_update_task						     */
/*---------------------------------------------------------------------------*/
int xio_nexus_update_task(struct xio_nexus *nexus, struct xio_task *task);

/*---------------------------------------------------------------------------*/
/* xio_nexus_update_rkey						     */
/*---------------------------------------------------------------------------*/
int xio_nexus_update_rkey(struct xio_nexus *nexus,
			  uint32_t *rkey);

/*---------------------------------------------------------------------------*/
/* xio_nexus_modify							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_modify(struct xio_nexus *nexus,
		     struct xio_nexus_attr *attr,
		     int attr_mask);

/*---------------------------------------------------------------------------*/
/* xio_nexus_query							     */
/*---------------------------------------------------------------------------*/
int xio_nexus_query(struct xio_nexus *nexus,
		    struct xio_nexus_attr *attr,
		    int attr_mask);

#ifdef __cplusplus
}
#endif

#endif /*XIO_NEXUS_H */
