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
#ifndef XIO_SESSION_H
#define XIO_SESSION_H

/*---------------------------------------------------------------------------*/
/* forward declarations			                                     */
/*---------------------------------------------------------------------------*/
struct xio_session;

/*---------------------------------------------------------------------------*/
/* enums				                                     */
/*---------------------------------------------------------------------------*/
enum xio_session_state {
	XIO_SESSION_STATE_INIT,
	XIO_SESSION_STATE_CONNECT,
	XIO_SESSION_STATE_ONLINE,
	XIO_SESSION_STATE_REDIRECTED,
	XIO_SESSION_STATE_ACCEPTED,
	XIO_SESSION_STATE_REJECTED,
	XIO_SESSION_STATE_REFUSED,
	XIO_SESSION_STATE_CLOSING,
	XIO_SESSION_STATE_CLOSED,
};

/*---------------------------------------------------------------------------*/
/* structures				                                     */
/*---------------------------------------------------------------------------*/
struct xio_session {
	struct xio_transport_msg_validators_cls	*validators_cls;
	struct xio_session_ops		ses_ops;

	uint64_t			trans_sn; /* transaction sn */
	uint32_t			session_id;
	uint32_t			peer_session_id;
	uint32_t			connections_nr;
	uint16_t			snd_queue_depth_msgs;
	uint16_t			rcv_queue_depth_msgs;
	uint16_t			peer_snd_queue_depth_msgs;
	uint16_t			peer_rcv_queue_depth_msgs;
	uint16_t			pad[2];
	uint64_t			snd_queue_depth_bytes;
	uint64_t			rcv_queue_depth_bytes;
	uint64_t			peer_snd_queue_depth_bytes;
	uint64_t			peer_rcv_queue_depth_bytes;
	struct list_head		sessions_list_entry;
	struct list_head		connections_list;

	HT_ENTRY(xio_session, xio_key_int32) sessions_htbl;

	struct xio_msg			*setup_req;
	struct xio_observer		observer;
	struct xio_observer		ctx_observer;

	enum xio_session_type		type;

	volatile enum xio_session_state	state;

	struct xio_new_session_rsp	new_ses_rsp;
	char				*uri;
	char				**portals_array;
	char				**services_array;

	/*
	 *  References a user-controlled data buffer. The contents of
	 *  the buffer are copied and transparently passed to the remote side
	 *  as part of the communication request.  Maybe NULL if private_data
	 *  is not required.
	 */
	void				*hs_private_data;
	void				*cb_user_context;

	/*
	 * Specifies  the  size  of  the user-controlled data buffer.
	 */
	uint16_t			hs_private_data_len;
	uint16_t			uri_len;
	uint16_t			portals_array_len;
	uint16_t			services_array_len;
	uint16_t			last_opened_portal;
	uint16_t			last_opened_service;

	uint32_t			teardown_reason;
	uint32_t			reject_reason;
	uint32_t			pad1;
	struct mutex                    lock;	   /* lock open connection */
	spinlock_t                      connections_list_lock;
	int				disable_teardown;
	struct xio_connection		*lead_connection;
	struct xio_connection		*redir_connection;
	/* server: represents the leading connection on server side */
	struct xio_connection           *connection_srv_first;
	struct xio_context		*teardown_work_ctx;
	xio_work_handle_t		teardown_work;

};

/*---------------------------------------------------------------------------*/
/* functions								     */
/*---------------------------------------------------------------------------*/
void xio_session_write_header(
		struct xio_task *task,
		struct xio_session_hdr *hdr);

static inline uint64_t xio_session_get_sn(
		struct xio_session *session)
{
	return xio_sync_fetch_and_add64(&session->trans_sn, 1);
}

struct xio_session *xio_find_session(
		struct xio_task *task);

struct xio_connection *xio_session_find_connection(
		struct xio_session *session,
		struct xio_nexus *nexus);

struct xio_connection *xio_session_alloc_connection(
		struct xio_session *session,
		struct xio_context *ctx,
		uint32_t connection_idx,
		void	 *connection_user_context);

int xio_session_free_connection(
		struct xio_connection *connection);

struct xio_connection  *xio_session_assign_nexus(
		struct xio_session *session,
		struct xio_nexus *nexus);

void xio_session_assign_ops(
		struct xio_session *session,
		struct xio_session_ops *ops);

struct xio_connection *xio_server_create_accepted_connection(
		struct xio_session *session,
		struct xio_nexus *nexus);

int xio_session_reconnect(
		struct xio_session  *session,
		struct xio_connection  *connection);

/*---------------------------------------------------------------------------*/
/* xio_session_is_valid_in_req						     */
/*---------------------------------------------------------------------------*/
static inline int xio_session_is_valid_in_req(struct xio_session *session,
					      struct xio_msg *msg)
{
	return session->validators_cls->is_valid_in_req(msg);
}

/*---------------------------------------------------------------------------*/
/* xio_session_is_valid_out_msg						     */
/*---------------------------------------------------------------------------*/
static inline int xio_session_is_valid_out_msg(struct xio_session *session,
					       struct xio_msg *msg)
{
	return session->validators_cls->is_valid_out_msg(msg);
}

int xio_session_notify_cancel(struct xio_connection *connection,
			      struct xio_msg *req, enum xio_status result);

void xio_session_notify_new_connection(struct xio_session *session,
				       struct xio_connection *connection);

void xio_session_notify_connection_established(
					struct xio_session *session,
					struct xio_connection *connection);

void xio_session_notify_connection_closed(
					struct xio_session *session,
					struct xio_connection *connection);

void xio_session_notify_connection_disconnected(
					struct xio_session *session,
					struct xio_connection *connection,
					enum xio_status reason);

void xio_session_notify_connection_refused(
					struct xio_session *session,
					struct xio_connection *connection,
					enum xio_status reason);

void xio_session_notify_connection_error(
					struct xio_session *session,
					struct xio_connection *connection,
					enum xio_status reason);

void xio_session_notify_connection_teardown(
					struct xio_session *session,
					struct xio_connection *connection);

int xio_session_notify_msg_error(struct xio_connection *connection,
				 struct xio_msg *msg, enum xio_status result,
				 enum xio_msg_direction direction);

void xio_session_notify_teardown(struct xio_session *session, int reason);

void xio_session_notify_rejected(struct xio_session *session);

void xio_session_notify_reconnecting(
					struct xio_session *session,
					struct xio_connection *connection);

void xio_session_notify_reconnected(
					struct xio_session *session,
					struct xio_connection *connection);

void xio_session_init_teardown(struct xio_session *session,
			       struct xio_context *ctx, int close_reason);

#endif /*XIO_SESSION_H */

