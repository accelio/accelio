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

#include "xio_hash.h"
#include "sys/hashtable.h"

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
	XIO_SESSION_STATE_CLOSING,
	XIO_SESSION_STATE_CLOSED,
};

/*---------------------------------------------------------------------------*/
/* structures				                                     */
/*---------------------------------------------------------------------------*/
struct xio_conn_node {
	struct xio_conn			*conn;
	struct list_head		connections_list_entry;
};

struct xio_portal_node {
	char				*portal;
	struct list_head		portals_list_entry;
};

struct xio_session {
	uint64_t			trans_sn; /* transaction sn */
	uint32_t			session_id;
	uint32_t			peer_session_id;
	uint32_t			session_flags;
	uint32_t			connections_nr;

	struct list_head		sessions_list_entry;
	struct list_head		connections_list;
	HT_ENTRY(xio_session, xio_key_int32) sessions_htbl;

	struct xio_session_ops		ses_ops;
	struct xio_transport_msg_validators_cls	*validators_cls;
	struct xio_msg			*setup_req;
	struct xio_observer		observer;

	enum xio_session_type		type;
	volatile enum xio_session_state	state;

	struct xio_new_session_rsp	new_ses_rsp;
	char				*uri;
	char				**portals_array;
	char				**services_array;

	void				*user_context;
	void				*cb_user_context;

	uint16_t			user_context_len;
	uint16_t			uri_len;
	uint16_t			portals_array_len;
	uint16_t			services_array_len;
	uint16_t			last_opened_portal;
	uint16_t			last_opened_service;

	uint32_t			reject_reason;
	struct mutex                    lock;	   /* lock open connection */
	spinlock_t                      connections_list_lock;
	int				disable_teardown;
	struct xio_connection		*lead_connection;
	struct xio_connection		*redir_connection;
};

/*---------------------------------------------------------------------------*/
/* functions								     */
/*---------------------------------------------------------------------------*/
struct xio_session *xio_session_create(
		struct xio_session *parent_session,
		struct xio_conn *conn);

struct xio_session *xio_session_init(
		enum xio_session_type type,
		struct xio_session_attr *attr,
		const char *uri,
		uint32_t initial_sn,
		uint32_t flags,
		void *cb_user_context);

int xio_session_write_header(
		struct xio_task *task,
		struct xio_session_hdr *hdr);

static inline uint64_t xio_session_get_sn(
		struct xio_session *session)
{
	return __sync_fetch_and_add(&session->trans_sn, 1);
}

int xio_session_disconnect(
		struct xio_session  *session,
		struct xio_connection  *connection);

struct xio_session *xio_find_session(
		struct xio_task *task);

struct xio_connection *xio_session_find_connection(
		struct xio_session *session,
		struct xio_conn *conn);

struct xio_connection *xio_session_alloc_connection(
		struct xio_session *session,
		struct xio_context *ctx,
		uint32_t conn_idx,
		void *conn_user_context);

int xio_session_free_connection(
		struct xio_connection *connection);

struct xio_connection  *xio_session_assign_conn(
		struct xio_session *session,
		struct xio_conn *conn);

void xio_session_assign_ops(
		struct xio_session *session,
		struct xio_session_ops *ops);

struct xio_connection *xio_server_create_accepted_connection(
		struct xio_session *session,
		struct xio_conn *conn);

/*---------------------------------------------------------------------------*/
/* xio_session_is_valid_in_req						     */
/*---------------------------------------------------------------------------*/
static inline int xio_session_is_valid_in_req(struct xio_session *session,
					   struct xio_msg *msg)
{
	if (session->validators_cls->is_valid_in_req)
		return session->validators_cls->is_valid_in_req(msg);

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_session_is_valid_out_msg						     */
/*---------------------------------------------------------------------------*/
static inline int xio_session_is_valid_out_msg(struct xio_session *session,
					    struct xio_msg *msg)
{
	if (session->validators_cls->is_valid_out_msg)
		return session->validators_cls->is_valid_out_msg(msg);

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

static inline int xio_session_not_queueing(struct xio_session *session)
{
	return session->session_flags & XIO_SESSION_FLAG_DONTQUEUE;
}

int xio_session_notify_cancel(struct xio_connection *connection,
			      struct xio_msg *req, enum xio_status result);

void xio_session_notify_new_connection(struct xio_session *session,
				       struct xio_connection *connection);

int xio_session_notify_msg_error(struct xio_connection *connection,
			         struct xio_msg *msg, enum xio_status result);

#endif /*XIO_SESSION_H */

