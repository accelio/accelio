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
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sched.h>

#include "libxio.h"
#include "obj_pool.h"
#include "reg_utils.h"

#define PRINT_COUNTER		400000
#define TEST_DISCONNECT		1

struct  connection_entry {
	struct xio_connection		*connection;
	struct thread_data		*tdata;
	uint64_t			nsent;
	uint64_t			nrecv;
	int				disconnected;
	int				cid;
	struct session_entry		*session_entry;
	TAILQ_ENTRY(connection_entry)	conns_list_entry;
};

struct session_entry {
	struct xio_session		*session;
	TAILQ_HEAD(, connection_entry)	conns_list;
	TAILQ_ENTRY(session_entry)	sessions_list_entry;
};

struct thread_data {
	int				affinity;
	int				pad;
	struct client_data		*client_data;
	struct xio_context		*ctx;
	struct obj_pool			*req_pool;
	struct obj_pool			*out_iobuf_pool;
	struct obj_pool			*in_iobuf_pool;
	pthread_t			thread_id;
};

/* private session data */
struct client_data {
	int				threads_num;
	int				queue_depth;
	int				client_dlen;
	int				server_dlen;
	int				disconnect_nr;
	int				nsent;
	int				nrecv;
	pthread_spinlock_t		lock;
	pthread_barrier_t		barr;
	struct thread_data		*tdata;
	TAILQ_HEAD(, session_entry)	sessions_list;
};

static void out_iobuf_obj_init(void *user_context, void *obj)
{
	struct xio_buf		**iobuf	= obj;
	struct thread_data	*tdata	= user_context;

	*iobuf = xio_alloc(tdata->client_data->client_dlen);
}

static void in_iobuf_obj_init(void *user_context, void *obj)
{
	struct xio_buf		**iobuf	= obj;
	struct thread_data	*tdata	= user_context;

	*iobuf = xio_alloc(tdata->client_data->server_dlen);
}

static void iobuf_obj_free(void *user_context, void *obj)
{
	struct xio_buf		**iobuf	= obj;

	xio_free(iobuf);
}

static void msg_obj_init(void *user_context, void *obj)
{
	struct xio_msg		*req	= obj;
	struct xio_buf		**out_iobuf;
	struct xio_buf		**in_iobuf;
	struct thread_data	*tdata	= user_context;

	if (tdata->client_data->client_dlen) {
		out_iobuf = obj_pool_get(tdata->out_iobuf_pool);
		req->out.data_iov[0].iov_base	  = (*out_iobuf)->addr;
		req->out.data_iov[0].iov_len	  = (*out_iobuf)->length;
		req->out.data_iov[0].mr		  = (*out_iobuf)->mr;
		req->out.data_iov[0].user_context = out_iobuf;
		req->out.data_iovlen		  = 1;
	} else {
		req->out.data_iov[0].iov_base	  = NULL;
		req->out.data_iov[0].iov_len	  = 0;
		req->out.data_iov[0].mr		  = NULL;
		req->out.data_iov[0].user_context = NULL;
		req->out.data_iovlen		  = 0;
	}

	if (tdata->client_data->server_dlen > 8000) {
		in_iobuf = obj_pool_get(tdata->in_iobuf_pool);

		req->in.data_iov[0].iov_base	  = (*in_iobuf)->addr;
		req->in.data_iov[0].iov_len	  = (*in_iobuf)->length;
		req->in.data_iov[0].mr		  = (*in_iobuf)->mr;
		req->in.data_iov[0].user_context  = in_iobuf;
		req->in.data_iovlen		  = 1;
	} else {
		req->in.data_iov[0].iov_base	  = NULL;
		req->in.data_iov[0].iov_len	  = 0;
		req->in.data_iov[0].mr		  = NULL;
		req->in.data_iov[0].user_context  = NULL;
		req->in.data_iovlen		  = 0;
	}

	req->in.header.iov_len		  = 0;
	req->out.header.iov_len		  = 0;
}

/*---------------------------------------------------------------------------*/
/* worker_thread							     */
/*---------------------------------------------------------------------------*/
static void *worker_thread(void *data)
{
	struct thread_data	*tdata = data;
	struct xio_msg		*req;
	cpu_set_t		cpuset;
	int			i;
	int			qdepth_per_thread;
	struct session_entry	*session_entry;
	struct connection_entry *connection_entry;


	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	qdepth_per_thread =
	    tdata->client_data->queue_depth/tdata->client_data->threads_num;
	if (!qdepth_per_thread)
		qdepth_per_thread = 1;

	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, 0);

	/* get session entry */
	connection_entry = calloc(1, sizeof(*connection_entry));
	connection_entry->tdata	= tdata;


	pthread_spin_lock(&tdata->client_data->lock);
	session_entry = TAILQ_FIRST(&tdata->client_data->sessions_list);
	TAILQ_INSERT_TAIL(&session_entry->conns_list,
			  connection_entry, conns_list_entry);
	pthread_spin_unlock(&tdata->client_data->lock);

	connection_entry->session_entry = session_entry;

	/* connect the session  */
	connection_entry->connection = xio_connect(session_entry->session,
						   tdata->ctx,
						   connection_entry->cid,
						   NULL, connection_entry);

	if (tdata->client_data->client_dlen)
		tdata->out_iobuf_pool = obj_pool_init(
				qdepth_per_thread,
				sizeof(struct xio_buf *),
				tdata, out_iobuf_obj_init);

	if (tdata->client_data->server_dlen)
		tdata->in_iobuf_pool = obj_pool_init(
				qdepth_per_thread,
				sizeof(struct xio_buf *),
				tdata, in_iobuf_obj_init);

	tdata->req_pool = obj_pool_init(qdepth_per_thread,
					sizeof(struct xio_msg),
					tdata, msg_obj_init);

	/* send first messages */
	pthread_spin_lock(&tdata->client_data->lock);
	for (i = 0; i < qdepth_per_thread; i++) {
		if (tdata->client_data->nsent <
		    tdata->client_data->disconnect_nr) {
			req = obj_pool_get(tdata->req_pool);
			xio_send_request(connection_entry->connection, req);
			connection_entry->nsent++;
			tdata->client_data->nsent++;
		}
	}
	pthread_spin_unlock(&tdata->client_data->lock);

	/* sync threads */
	pthread_barrier_wait(&tdata->client_data->barr);

	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

	/* normal exit phase */
	DEBUG("exit signaled\n");

	obj_pool_free(tdata->req_pool, NULL, NULL);
	if (tdata->client_data->client_dlen)
		obj_pool_free(tdata->out_iobuf_pool, NULL, iobuf_obj_free);
	if (tdata->client_data->server_dlen)
		obj_pool_free(tdata->in_iobuf_pool, NULL, iobuf_obj_free);

	/* free the context */
	xio_context_destroy(tdata->ctx);

	DEBUG("thread exit\n");

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* on_connection_teardown						     */
/*---------------------------------------------------------------------------*/
static int on_connection_teardown(struct xio_session *session,
				  struct xio_connection *connection,
				  void *cb_user_context)
{
	struct client_data *client_data = cb_user_context;
	struct session_entry *session_entry;
	struct connection_entry *connection_entry, *tmp_connection_entry;
	int			found = 0;

	pthread_spin_lock(&client_data->lock);
	TAILQ_FOREACH(session_entry, &client_data->sessions_list,
		      sessions_list_entry) {
		if (session_entry->session == session) {
			TAILQ_FOREACH_SAFE(connection_entry,
					   tmp_connection_entry,
					   &session_entry->conns_list,
					   conns_list_entry) {
				if (connection_entry->connection ==
				    connection) {
					TAILQ_REMOVE(&session_entry->conns_list,
						     connection_entry,
						     conns_list_entry);
					free(connection_entry);
					found = 1;
					break;
				}
			}
			break;
		}
	}
	pthread_spin_unlock(&client_data->lock);

	if (found)
		xio_connection_destroy(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_teardown							     */
/*---------------------------------------------------------------------------*/
static int on_session_teardown(struct xio_session *session,
			       void *cb_user_context)
{
	struct client_data *client_data = cb_user_context;
	struct session_entry *session_entry;


	pthread_spin_lock(&client_data->lock);
	TAILQ_FOREACH(session_entry, &client_data->sessions_list,
		      sessions_list_entry) {
		if (session_entry->session == session) {
			free(session_entry);
			xio_session_destroy(session);
			break;
		}
	}
	pthread_spin_unlock(&client_data->lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
		struct xio_session_event_data *event_data,
		void *cb_user_context)
{
	struct client_data *client_data = cb_user_context;
	int			i;

	DEBUG("client session event: %s. session:%p, connection:%p, " \
	      "reason: %s\n",
	      xio_session_event_str(event_data->event),
	      session, event_data->conn,
	      xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		on_connection_teardown(session, event_data->conn,
				       cb_user_context);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		on_session_teardown(session, cb_user_context);
		for (i = 0; i < client_data->threads_num; i++)
			xio_context_stop_loop(client_data->tdata[i].ctx, 0);
		break;
	default:
		break;
	};

	/* normal exit phase */
	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_msg_error								     */
/*---------------------------------------------------------------------------*/
static int on_msg_error(struct xio_session *session,
		enum xio_status error, struct xio_msg  *req,
		void *cb_user_context)
{
	struct connection_entry	*conn_entry	= cb_user_context;
	struct thread_data	*tdata		= conn_entry->tdata;
	struct xio_buf	**out_iobuf	= req->out.data_iov[0].user_context;
	struct xio_buf	**in_iobuf	= req->in.data_iov[0].user_context;

	req->in.data_iov[0].user_context = NULL;
	req->out.data_iov[0].user_context = NULL;
	obj_pool_put(tdata->req_pool, req);
	if (out_iobuf)
		obj_pool_put(tdata->out_iobuf_pool, out_iobuf);
	if (in_iobuf)
		obj_pool_put(tdata->in_iobuf_pool, in_iobuf);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_response								     */
/*---------------------------------------------------------------------------*/
static int on_response(struct xio_session *session,
			struct xio_msg *rsp,
			int more_in_batch,
			void *cb_user_context)
{
	struct connection_entry	*conn_entry	= cb_user_context;
	struct thread_data	*tdata		= conn_entry->tdata;
#if  TEST_DISCONNECT
	struct session_entry	*session_entry	= conn_entry->session_entry;
	struct connection_entry *connection_entry;
#endif
	struct xio_buf		**in_iobuf;

	/* acknowledge xio that response is no longer needed */
	xio_release_response(rsp);

#if  TEST_DISCONNECT
	pthread_spin_lock(&tdata->client_data->lock);
	tdata->client_data->nrecv++;
	conn_entry->nrecv++;
	if (tdata->client_data->nrecv == tdata->client_data->disconnect_nr) {
		TAILQ_FOREACH(connection_entry,
			      &session_entry->conns_list,
			      conns_list_entry) {
			if (!connection_entry->disconnected)  {
				DEBUG("client disconnect. session:%p, " \
				      "connection:%p\n",
				      session, connection_entry->connection);
				connection_entry->disconnected = 1;
				xio_disconnect(connection_entry->connection);
			}
		}
	}
	if (tdata->client_data->nsent >= tdata->client_data->disconnect_nr) {
		struct xio_buf	**out_iobuf = rsp->out.data_iov[0].user_context;
		struct xio_buf	**in_iobuf = rsp->in.data_iov[0].user_context;
		rsp->in.data_iov[0].user_context = NULL;
		rsp->out.data_iov[0].user_context = NULL;
		obj_pool_put(tdata->req_pool, rsp);
		if (out_iobuf)
			obj_pool_put(tdata->out_iobuf_pool, out_iobuf);
		if (in_iobuf)
			obj_pool_put(tdata->in_iobuf_pool, in_iobuf);

		pthread_spin_unlock(&tdata->client_data->lock);
		return 0;
	}
	pthread_spin_unlock(&tdata->client_data->lock);
#endif

	/* resend the message */
	if (tdata->client_data->server_dlen &&
	    rsp->in.data_iov[0].user_context) {
		in_iobuf = rsp->in.data_iov[0].user_context;

		rsp->in.data_iov[0].iov_base	= (*in_iobuf)->addr;
		rsp->in.data_iov[0].iov_len	= (*in_iobuf)->length;
		rsp->in.data_iov[0].mr		= (*in_iobuf)->mr;
		rsp->in.data_iovlen		= 1;
	} else {
		rsp->in.data_iov[0].iov_base	= NULL;
		rsp->in.data_iov[0].iov_len	= 0;
		rsp->in.data_iov[0].mr		= NULL;
		rsp->in.data_iovlen		= 0;
	}

	rsp->in.header.iov_len			= 0;

	xio_send_request(conn_entry->connection, rsp);
	pthread_spin_lock(&tdata->client_data->lock);
	conn_entry->nsent++;
	tdata->client_data->nsent++;
	pthread_spin_unlock(&tdata->client_data->lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_established						     */
/*---------------------------------------------------------------------------*/
static int on_session_established(struct xio_session *session,
			struct xio_new_session_rsp *rsp,
			void *cb_user_context)
{
	DEBUG("client session event: session established. session:%p\n",
	      session);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  on_session_established,
	.on_msg				=  on_response,
	.on_msg_error			=  on_msg_error,
};

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int client_main(int argc, char *argv[])
{
	int			i;
	char			url[256];
	struct client_data	client_data;
	int			queue_depth		= atoi(argv[3]);
	uint16_t		client_threads_num	= atoi(argv[4]);
	/*uint16_t		server_threads_num	= atoi(argv[5]);*/
	int			client_dlen		= atoi(argv[6]);
	int			server_dlen		= atoi(argv[7]);
	int			client_disconnect_nr	= atoi(argv[8]);
	/*int			server_disconnect_nr	= atoi(argv[9]);*/
	struct session_entry    *session_entry;

	/* client session attributes */
	struct xio_session_attr attr = {
		&ses_ops, /* callbacks structure */
		NULL,	  /* no need to pass the server private data */
		0
	};

	memset(&client_data, 0, sizeof(client_data));

	client_data.tdata = calloc(client_threads_num,
				    sizeof(*client_data.tdata));
	if (!client_data.tdata)
		return -1;

	client_data.threads_num = client_threads_num;
	client_data.client_dlen = client_dlen;
	client_data.server_dlen = server_dlen;
	client_data.queue_depth = queue_depth;
	client_data.disconnect_nr = client_disconnect_nr;

	xio_init();

	TAILQ_INIT(&client_data.sessions_list);
	pthread_spin_init(&client_data.lock, PTHREAD_PROCESS_PRIVATE);

	session_entry = calloc(1, sizeof(*session_entry));
	TAILQ_INIT(&session_entry->conns_list);

	/* create url to connect to */
	sprintf(url, "rdma://%s:%s", argv[1], argv[2]);
	session_entry->session = xio_session_create(XIO_SESSION_CLIENT,
						&attr, url,
						0, 0, &client_data);

	if (session_entry->session  == NULL) {
		free(session_entry);
		goto cleanup;
	}

	TAILQ_INSERT_TAIL(&client_data.sessions_list,
			  session_entry, sessions_list_entry);

	/* initialize thread synchronization barrier */
	pthread_barrier_init(&client_data.barr, NULL,
			     client_data.threads_num);

	/* spawn threads to handle connection */
	for (i = 0; i < client_data.threads_num; i++) {
		client_data.tdata[i].client_data	= &client_data;
		client_data.tdata[i].affinity		= i;

		pthread_create(&client_data.tdata[i].thread_id, NULL,
			       worker_thread, &client_data.tdata[i]);
	}

	/* join the threads */
	for (i = 0; i < client_data.threads_num; i++)
		pthread_join(client_data.tdata[i].thread_id, NULL);

	free(client_data.tdata);

cleanup:
	xio_shutdown();

	DEBUG("client: goodbye and good riddance\n");

	return 0;
}

