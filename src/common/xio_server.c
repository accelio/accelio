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
#include "xio_observer.h"
#include "xio_hash.h"
#include "xio_transport.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_idr.h"
#include "xio_msg_list.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"
#include "xio_session.h"
#include "xio_nexus.h"
#include "xio_connection.h"
#include "xio_server.h"
#include <xio_env_adv.h>

static int xio_on_nexus_event(void *observer, void *notifier, int event,
			      void *event_data);
static void xio_server_destroy(struct kref *kref);

/*---------------------------------------------------------------------------*/
/* xio_server_reg_observer						     */
/*---------------------------------------------------------------------------*/
int xio_server_reg_observer(struct xio_server *server,
			    struct xio_observer *observer)
{
	kref_get(&server->kref);
	xio_observable_reg_observer(&server->nexus_observable, observer);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_server_unreg_observer		                                     */
/*---------------------------------------------------------------------------*/
void xio_server_unreg_observer(struct xio_server *server,
			       struct xio_observer *observer)
{
	xio_observable_unreg_observer(&server->nexus_observable, observer);
	kref_put(&server->kref, xio_server_destroy);
}

/*---------------------------------------------------------------------------*/
/* xio_on_new_nexus							     */
/*---------------------------------------------------------------------------*/
static int xio_on_new_nexus(struct xio_server *server,
			    struct xio_nexus *nexus,
			    union xio_nexus_event_data *event_data)
{
	int		retval;

	/* set the server as observer */
	retval = xio_nexus_accept(event_data->new_nexus.child_nexus);
	if (retval != 0) {
		ERROR_LOG("failed to accept connection\n");
		return -1;
	}

	return 0;
}

/* first message after new connection are going trough the server */
static int xio_on_new_message(struct xio_server *server,
			      struct xio_nexus *nexus,
			      int event,
			      union xio_nexus_event_data *event_data)
{
	struct xio_session		*session = NULL;
	struct xio_connection		*connection = NULL;
	struct xio_connection		*connection1 = NULL;
	struct xio_task			*task;
	uint32_t			tlv_type;
	struct xio_session_params	params;
	int				locked = 0;

	if (!server || !nexus || !event_data || !event_data->msg.task) {
		ERROR_LOG("server [new session]: failed " \
			  "invalid parameter\n");
		return -1;
	}
	if (nexus->state == XIO_NEXUS_STATE_CLOSED) {
		ERROR_LOG("got a request for server %p but the corresponding nexus %p is closing\n",
				server, nexus);
		return -1;
	}

	task			= event_data->msg.task;

	params.type		= XIO_SESSION_SERVER;
	params.initial_sn	= 0;
	params.ses_ops		= &server->ops;
	params.uri		= server->uri;
	params.private_data	= NULL;
	params.private_data_len = 0;
	params.user_context	= server->cb_private_data;

	/* read the first message  type */
	tlv_type = xio_read_tlv_type(&event_data->msg.task->mbuf);

	if (tlv_type == XIO_SESSION_SETUP_REQ) {
		/* create new session */
		session = xio_session_create(&params);
		if (!session) {
			ERROR_LOG("server [new session]: failed " \
				"  allocating session failed\n");
			return -1;
		}
		DEBUG_LOG("server [new session]: server:%p, " \
			  "session:%p, nexus:%p ,session_id:%d\n",
			  server, session, nexus, session->session_id);

		/* get transport class routines */
		session->validators_cls = xio_nexus_get_validators_cls(nexus);

		connection =
			xio_session_alloc_connection(session,
						     server->ctx, 0,
						     server->cb_private_data);
		if (!connection) {
			ERROR_LOG("server failed to allocate new connection\n");
			goto cleanup;
		}
		connection1 = xio_session_assign_nexus(session, nexus);
		if (!connection1) {
			ERROR_LOG("server failed to assign new connection\n");
			goto cleanup1;
		}
		connection = connection1;

		xio_idr_add_uobj(usr_idr, session, "xio_session");
		xio_idr_add_uobj(usr_idr, connection, "xio_connection");
		xio_connection_set_state(connection,
					 XIO_CONNECTION_STATE_ONLINE);

		xio_connection_keepalive_start(connection);

		task->session		= session;
		task->connection	= connection;
	} else if (tlv_type == XIO_CONNECTION_HELLO_REQ) {
		struct xio_session *session1;
		/* find the old session without lock */
		session = xio_find_session(event_data->msg.task);
		if (!session) {
			ERROR_LOG("server [new connection]: failed " \
				  "session not found. server:%p\n",
				  server);
			xio_nexus_close(nexus, NULL);
			return -1;
		}
		/* lock it and retry find */
		mutex_lock(&session->lock);
		/* session before destruction - try to lock before continue */
		session1 = xio_find_session(event_data->msg.task);
		if (!session1) {
			ERROR_LOG("server [new connection]: failed " \
				  "session not found. server:%p\n",
				  server);
			xio_nexus_close(nexus, NULL);
			mutex_unlock(&session->lock);
			return -1;
		}
		locked = 1;
		task->session = session;

		DEBUG_LOG("server [new connection]: server:%p, " \
			  "session:%p, nexus:%p, session_id:%d\n",
			   server, session, nexus, session->session_id);

		connection = xio_session_alloc_connection(
				task->session,
				server->ctx, 0,
				server->cb_private_data);

		if (!connection) {
			ERROR_LOG("server failed to allocate new connection\n");
			goto cleanup;
		}
		connection1 = xio_session_assign_nexus(task->session, nexus);
		if (!connection1) {
			ERROR_LOG("server failed to assign new connection\n");
			goto cleanup1;
		}
		connection = connection1;

		/* copy the server attributes to the connection */
		xio_connection_set_ops(connection, &server->ops);

		task->connection = connection;

		/* This in a multiple-portal situation */
		session->state = XIO_SESSION_STATE_ONLINE;
		xio_connection_set_state(connection,
					 XIO_CONNECTION_STATE_ONLINE);

		xio_connection_keepalive_start(connection);

		xio_idr_add_uobj(usr_idr, connection, "xio_connection");
	} else {
		ERROR_LOG("server unexpected message\n");
		return -1;
	}

	/* route the message to the session */
	if (session)
		xio_nexus_notify_observer(nexus, &session->observer,
					  event, event_data);
	if (locked)
		mutex_unlock(&session->lock);

	return 0;

cleanup1:
	if (connection)
		xio_session_free_connection(connection);

cleanup:
	if (session)
		xio_session_destroy(session);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_on_nexus_event				                             */
/*---------------------------------------------------------------------------*/
static int xio_on_nexus_event(void *observer, void *notifier, int event,
			      void *event_data)
{
	struct xio_server	*server = (struct xio_server *)observer;
	struct xio_nexus	*nexus	= (struct xio_nexus *)notifier;
	int			retval  = 0;

	switch (event) {
	case XIO_NEXUS_EVENT_NEW_MESSAGE:
	case XIO_NEXUS_EVENT_ASSIGN_IN_BUF:
		TRACE_LOG("server: [notification] - new message. " \
			  "server:%p, nexus:%p\n", observer, notifier);

		xio_on_new_message(server, nexus, event,
				   (union xio_nexus_event_data *)event_data);
		break;
	case XIO_NEXUS_EVENT_NEW_CONNECTION:
		DEBUG_LOG("server: [notification] - new connection. " \
			  "server:%p, nexus:%p\n", observer, notifier);
		xio_on_new_nexus(server, nexus,
				 (union xio_nexus_event_data *)event_data);
		break;

	case XIO_NEXUS_EVENT_DISCONNECTED:
	case XIO_NEXUS_EVENT_CLOSED:
	case XIO_NEXUS_EVENT_ESTABLISHED:
		break;

	case XIO_NEXUS_EVENT_ERROR:
		ERROR_LOG("server: [notification] - connection error. " \
			  "server:%p, nexus:%p\n", observer, notifier);
		break;
	default:
		ERROR_LOG("server: [notification] - unexpected event :%d. " \
			  "server:%p, nexus:%p\n", event, observer, notifier);
		break;
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_bind								     */
/*---------------------------------------------------------------------------*/
struct xio_server *xio_bind(struct xio_context *ctx,
			    struct xio_session_ops *ops,
			    const char *uri,
			    uint16_t *src_port,
			    uint32_t session_flags,
			    void *cb_private_data)
{
	struct xio_server	*server;
	int			retval;
	int			backlog = 0; /* setting to 0 will use the transport default */

	if (!ctx  || !ops || !uri) {
		ERROR_LOG("invalid parameters ctx:%p, ops:%p, uri:%p\n",
			  ctx, ops, uri);
		xio_set_error(EINVAL);
		return NULL;
	}

	TRACE_LOG("bind to %s\n", uri);

	/* create the server */
	server = (struct xio_server *)
			kcalloc(1, sizeof(struct xio_server), GFP_KERNEL);
	if (!server) {
		xio_set_error(ENOMEM);
		return NULL;
	}
	kref_init(&server->kref);

	/* fill server data*/
	server->ctx = ctx;
	server->cb_private_data	= cb_private_data;
	server->uri = kstrdup(uri, GFP_KERNEL);

	server->session_flags = session_flags;
	memcpy(&server->ops, ops, sizeof(*ops));

	XIO_OBSERVER_INIT(&server->observer, server, xio_on_nexus_event);

	XIO_OBSERVABLE_INIT(&server->nexus_observable, server);

	server->listener = xio_nexus_open(ctx, uri, NULL, 0, 0, NULL);
	if (!server->listener) {
		ERROR_LOG("failed to create connection\n");
		goto cleanup;
	}
	retval = xio_nexus_listen(server->listener,
				  uri, src_port, backlog);
	if (retval != 0) {
		ERROR_LOG("connection listen failed\n");
		goto cleanup1;
	}
	xio_nexus_set_server(server->listener, server);
	xio_idr_add_uobj(usr_idr, server, "xio_server");

	return server;

cleanup1:
	xio_nexus_close(server->listener, NULL);
cleanup:
	kfree(server->uri);
	kfree(server);

	return NULL;
}
EXPORT_SYMBOL(xio_bind);

/*---------------------------------------------------------------------------*/
/* xio_server_destroy							     */
/*---------------------------------------------------------------------------*/
static void xio_server_destroy(struct kref *kref)
{
	struct xio_server *server = container_of(kref,
						 struct xio_server, kref);

	DEBUG_LOG("xio_server_destroy - server:%p\n", server);
	xio_observable_unreg_all_observers(&server->nexus_observable);

	xio_nexus_close(server->listener, NULL);

	XIO_OBSERVER_DESTROY(&server->observer);
	XIO_OBSERVABLE_DESTROY(&server->nexus_observable);

	kfree(server->uri);
	kfree(server);
}

/*---------------------------------------------------------------------------*/
/* xio_unbind								     */
/*---------------------------------------------------------------------------*/
int xio_unbind(struct xio_server *server)
{
	int retval = 0;
	int found;

	if (!server)
		return -1;

	found = xio_idr_lookup_uobj(usr_idr, server);
	if (found) {
		xio_idr_remove_uobj(usr_idr, server);
	} else {
		ERROR_LOG("server not found:%p\n", server);
		xio_set_error(XIO_E_USER_OBJ_NOT_FOUND);
		return -1;
	}
	/* notify all observers that the server wishes to exit */
	xio_observable_notify_all_observers(&server->nexus_observable,
					    XIO_SERVER_EVENT_CLOSE, NULL);

	kref_put(&server->kref, xio_server_destroy);

	return retval;
}
EXPORT_SYMBOL(xio_unbind);
