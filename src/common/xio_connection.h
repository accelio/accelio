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
#ifndef XIO_CONNECTION_H
#define XIO_CONNECTION_H

enum xio_connection_state {
		XIO_CONNECTION_STATE_INIT,
		XIO_CONNECTION_STATE_ESTABLISHED,
		XIO_CONNECTION_STATE_ONLINE,
		XIO_CONNECTION_STATE_FIN_WAIT_1,	/* tcp state machine */
		XIO_CONNECTION_STATE_FIN_WAIT_2,	/* tcp state machine */
		XIO_CONNECTION_STATE_CLOSING,		/* tcp state machine */
		XIO_CONNECTION_STATE_TIME_WAIT,		/* tcp state machine */
		XIO_CONNECTION_STATE_CLOSE_WAIT,	/* tcp state machine */
		XIO_CONNECTION_STATE_LAST_ACK,		/* tcp state machine */
		XIO_CONNECTION_STATE_CLOSED,		/* user close */
		XIO_CONNECTION_STATE_DISCONNECTED,	/* disconnect */
		XIO_CONNECTION_STATE_ERROR,		/* error */
		XIO_CONNECTION_STATE_INVALID
};

#define		SEND_ACK	0x0001
#define		SEND_FIN	0x0002

#define         XIO_MIN_CONNECTION_TIMEOUT	1000
#define         XIO_DEF_CONNECTION_TIMEOUT	300000

struct xio_transition {
	int				valid;
	enum xio_connection_state	next_state;
	int				send_flags;
};

struct xio_ka {
	xio_delayed_work_handle_t	timer;
	int				probes;
	int				req_sent;
	int				timedout;
	int				pad;
};

struct xio_connection {
	struct xio_ka			ka;
	struct xio_nexus		*nexus;
	struct xio_session		*session;
	struct xio_context		*ctx;	/* connection context */
	struct xio_session_ops		ses_ops;

	/* server's session may have multiple connections each has
	 * private data assigned by bind
	 */
	uint16_t			enable_flow_control;
	uint16_t			req_sn;
	uint16_t			req_exp_sn;
	uint16_t			req_ack_sn;

	uint16_t			rsp_sn;
	uint16_t			rsp_exp_sn;
	uint16_t			rsp_ack_sn;
	uint16_t			credits_msgs;

	uint16_t			peer_credits_msgs;
	uint16_t			rx_queue_watermark_msgs;
	uint16_t			conn_idx;
	uint16_t			state;

	uint16_t			fin_req_timeout;
	uint16_t			disable_notify;
	uint16_t			disconnecting;
	uint16_t			restarted;

	uint64_t			latest_delivered;

	uint16_t			is_flushed;
	uint16_t			send_req_toggle;
	uint16_t			cd_bit;  /*close disconnect bit */
	uint16_t			fin_request_flushed;

	uint32_t			close_reason;
	int32_t				tx_queued_msgs;
	struct kref			kref;
	uint32_t			disconnect_timeout;

	struct xio_msg_list		reqs_msgq;
	struct xio_msg_list		rsps_msgq;
	struct xio_msg_list		in_flight_reqs_msgq;
	struct xio_msg_list		in_flight_rsps_msgq;

	xio_work_handle_t		hello_work;
	xio_work_handle_t		fin_work;
	xio_delayed_work_handle_t	fin_delayed_work;
	xio_delayed_work_handle_t	fin_timeout_work;

	struct list_head		managed_rkey_list;
	struct list_head		io_tasks_list;
	struct list_head		post_io_tasks_list;
	struct list_head		pre_send_list;
	struct list_head		connections_list_entry;
	struct list_head		ctx_list_entry;
	void				*cb_user_context;

	size_t				tx_bytes;
	uint64_t			credits_bytes;
	uint64_t			peer_credits_bytes;
	uint64_t			rx_queue_watermark_bytes;

	uint32_t			nexus_attr_mask;
	struct xio_nexus_init_attr	nexus_attr;

	xio_work_handle_t		teardown_work;
	xio_delayed_work_handle_t	connect_work;

#ifdef XIO_SESSION_DEBUG
	uint64_t			peer_connection;
	uint64_t			peer_session;
#endif
};

struct xio_connection *xio_connection_create(
		struct xio_session *session,
		struct xio_context *ctx, int conn_idx,
		void *cb_user_context);

int xio_connection_close(struct xio_connection *connection);

static inline void xio_connection_set(
			struct xio_connection *connection,
			struct xio_nexus *nexus)
{
	connection->nexus = nexus;
}

static inline void xio_connection_set_ops(
		struct xio_connection *connection,
		struct xio_session_ops *ses_ops)
{
	memcpy(&connection->ses_ops, ses_ops, sizeof(*ses_ops));
}

int xio_connection_send(struct xio_connection *connection,
			struct xio_msg *msg);

int xio_connection_xmit_msgs(struct xio_connection *connection);

void xio_connection_queue_io_task(struct xio_connection *connection,
				  struct xio_task *task);

struct xio_task *xio_connection_find_io_task(struct xio_connection *connection,
					     uint64_t msg_sn);

static inline void xio_connection_set_state(
				struct xio_connection *connection,
				enum xio_connection_state state)
{
	connection->state = state;
}

struct xio_transition *xio_connection_next_transit(
					enum xio_connection_state state,
					int fin_ack);

int xio_connection_send_read_receipt(struct xio_connection *connection,
				     struct xio_msg *msg);

int xio_connection_release_read_receipt(struct xio_connection *connection,
					struct xio_msg *msg);

void xio_release_response_task(struct xio_task *task);

int xio_send_fin_ack(struct xio_connection *connection,
		     struct xio_task *task);

int xio_disconnect_initial_connection(
		struct xio_connection *connection);

int xio_connection_disconnected(struct xio_connection *connection);

int xio_connection_refused(struct xio_connection *connection);

int xio_connection_error_event(struct xio_connection *connection,
			       enum xio_status reason);

int xio_connection_remove_in_flight(struct xio_connection *connection,
				    struct xio_msg *msg);

int xio_connection_remove_msg_from_queue(struct xio_connection *connection,
					 struct xio_msg *msg);

int xio_connection_send_cancel_response(
		struct xio_connection *connection,
		struct xio_msg *msg,
		struct xio_task *task,
		enum xio_status result);

int xio_connection_send_hello_req(struct xio_connection *connection);

int xio_connection_send_hello_rsp(struct xio_connection *connection,
				  struct xio_task *task);

char *xio_connection_state_str(enum xio_connection_state state);

int xio_connection_reconnect(struct xio_connection *connection);

int xio_connection_restart(struct xio_connection *connection);

int xio_on_fin_req_send_comp(struct xio_connection *connection,
			     struct xio_task *task);

int xio_on_fin_ack_send_comp(struct xio_connection *connection,
			     struct xio_task *task);

int xio_on_fin_req_recv(struct xio_connection *connection,
			struct xio_task *task);

int xio_on_fin_ack_recv(struct xio_connection *connection,
			struct xio_task *task);

int xio_on_connection_hello_req_recv(struct xio_connection *connection,
				     struct xio_task *task);

int xio_on_connection_hello_rsp_send_comp(struct xio_connection *connection,
					  struct xio_task *task);
int xio_on_connection_hello_rsp_recv(struct xio_connection *connection,
				     struct xio_task *task);

int xio_send_credits_ack(struct xio_connection *connection);

int xio_on_credits_ack_send_comp(struct xio_connection *connection,
				 struct xio_task *task);

int xio_on_credits_ack_recv(struct xio_connection *connection,
			    struct xio_task *task);

const struct xio_transport_base *xio_req_to_transport_base(
	const struct xio_msg *req);

int xio_connection_ioctl(struct xio_connection *connection, int con_optname,
			 void *optval, int *optlen);

int xio_on_connection_ka_req_recv(struct xio_connection *connection,
				  struct xio_task *task);

int xio_on_connection_ka_rsp_send_comp(struct xio_connection *connection,
				       struct xio_task *task);

int xio_on_connection_ka_rsp_recv(struct xio_connection *connection,
				  struct xio_task *task);

void xio_connection_keepalive_start(void *_connection);

int xio_connection_force_disconnect(struct xio_connection *connection,
                                    enum xio_status reason);

#endif /*XIO_CONNECTION_H */
