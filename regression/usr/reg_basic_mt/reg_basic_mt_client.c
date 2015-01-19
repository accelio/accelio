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
	struct obj_pool			*out_reg_mem_pool;
	struct obj_pool			*in_reg_mem_pool;
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
	int				nerror;
	int				pad;
	pthread_spinlock_t		lock;
	pthread_barrier_t		barr;
	struct thread_data		*tdata;
	TAILQ_HEAD(, session_entry)	sessions_list;
};

/*---------------------------------------------------------------------------*/
/* obt_reg_mem_init							     */
/*---------------------------------------------------------------------------*/
static void out_reg_mem_init(void *user_context, void *obj)
{
	struct xio_reg_mem	*reg_mem = (struct xio_reg_mem *)obj;
	struct thread_data	*tdata	= (struct thread_data *)user_context;

	xio_mem_alloc(tdata->client_data->client_dlen, reg_mem);
}

/*---------------------------------------------------------------------------*/
/* in_reg_mem_init							     */
/*---------------------------------------------------------------------------*/
static void in_reg_mem_init(void *user_context, void *obj)
{
	struct xio_reg_mem	*reg_mem = (struct xio_reg_mem *)obj;
	struct thread_data	*tdata	= (struct thread_data *)user_context;

	xio_mem_alloc(tdata->client_data->server_dlen, reg_mem);
}

/*---------------------------------------------------------------------------*/
/* reg_mem_free							     */
/*---------------------------------------------------------------------------*/
static void reg_mem_free(void *user_context, void *obj)
{
	struct xio_reg_mem	*reg_mem = (struct xio_reg_mem *)obj;

	xio_mem_free(reg_mem);
}

/*---------------------------------------------------------------------------*/
/* msg_obj_init								     */
/*---------------------------------------------------------------------------*/
static void msg_obj_init(void *user_context, void *obj)
{
	struct xio_msg		*req	= (struct xio_msg *)obj;
	struct xio_reg_mem	*out_reg_mem;
	struct xio_reg_mem	*in_reg_mem;
	struct xio_iovec_ex	*sglist;
	struct thread_data	*tdata	= (struct thread_data *)user_context;

	sglist = vmsg_sglist(&req->out);
	if (tdata->client_data->client_dlen) {
		out_reg_mem =
			(struct xio_reg_mem *)obj_pool_get(tdata->out_reg_mem_pool);
		sglist[0].iov_base	= out_reg_mem->addr;
		sglist[0].iov_len	= out_reg_mem->length;
		sglist[0].mr		= out_reg_mem->mr;
		sglist[0].user_context	= out_reg_mem;
		vmsg_sglist_set_nents(&req->out, 1);
	} else {
		sglist[0].iov_base	= NULL;
		sglist[0].iov_len	= 0;
		sglist[0].mr		= NULL;
		sglist[0].user_context	= NULL;
		vmsg_sglist_set_nents(&req->out, 0);
	}

	sglist = vmsg_sglist(&req->in);
	if (tdata->client_data->server_dlen > 8000) {
		in_reg_mem =
			(struct xio_reg_mem *)obj_pool_get(tdata->in_reg_mem_pool);

		sglist[0].iov_base	= in_reg_mem->addr;
		sglist[0].iov_len	= in_reg_mem->length;
		sglist[0].mr		= in_reg_mem->mr;
		sglist[0].user_context  = in_reg_mem;
		vmsg_sglist_set_nents(&req->in, 1);
	} else {
		sglist[0].iov_base	= NULL;
		sglist[0].iov_len	= 0;
		sglist[0].mr		= NULL;
		sglist[0].user_context  = NULL;
		vmsg_sglist_set_nents(&req->in, 0);
	}

	req->in.header.iov_len		  = 0;
	req->out.header.iov_len		  = 0;
}

/*---------------------------------------------------------------------------*/
/* msg_obj_free								     */
/*---------------------------------------------------------------------------*/
static void msg_obj_free(void *user_context, void *obj)
{
	struct xio_msg		*req	= (struct xio_msg *)obj;
	struct xio_iovec_ex	*sglist;
	struct thread_data	*tdata	= (struct thread_data *)user_context;

	sglist = vmsg_sglist(&req->out);
	if (sglist[0].user_context) {
		struct xio_reg_mem *out_reg_mem =
			(struct xio_reg_mem *)sglist[0].user_context;
		obj_pool_put(tdata->out_reg_mem_pool, out_reg_mem);
		sglist[0].user_context= NULL;
	}
	sglist = vmsg_sglist(&req->in);
	if (sglist[0].user_context) {
		struct xio_reg_mem *in_reg_mem =
			(struct xio_reg_mem *)sglist[0].user_context;
		obj_pool_put(tdata->in_reg_mem_pool, in_reg_mem);
		sglist[0].user_context= NULL;
	}
}

/*---------------------------------------------------------------------------*/
/* worker_thread							     */
/*---------------------------------------------------------------------------*/
static void *worker_thread(void *data)
{
	struct thread_data	*tdata = (struct thread_data *)data;
	struct xio_msg		*req;
	cpu_set_t		cpuset;
	int			i;
	int			qdepth_per_thread;
	struct session_entry	*session_entry;
	struct connection_entry *connection_entry;
	struct xio_connection_params	cparams;


	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	qdepth_per_thread =
	    tdata->client_data->queue_depth/tdata->client_data->threads_num;
	if (!qdepth_per_thread)
		qdepth_per_thread = 1;

	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, 0, tdata->affinity);

	/* get session entry */
	connection_entry = (struct connection_entry *)
					calloc(1, sizeof(*connection_entry));
	connection_entry->tdata	= tdata;


	pthread_spin_lock(&tdata->client_data->lock);
	session_entry = TAILQ_FIRST(&tdata->client_data->sessions_list);
	TAILQ_INSERT_TAIL(&session_entry->conns_list,
			  connection_entry, conns_list_entry);
	pthread_spin_unlock(&tdata->client_data->lock);

	connection_entry->session_entry = session_entry;

	memset(&cparams, 0, sizeof(cparams));
	cparams.session			= session_entry->session;
	cparams.ctx			= tdata->ctx;
	cparams.conn_idx		= connection_entry->cid;
	cparams.conn_user_context	= connection_entry;

	/* connect the session  */
	connection_entry->connection = xio_connect(&cparams);

	if (tdata->client_data->client_dlen)
		tdata->out_reg_mem_pool = obj_pool_init(
				qdepth_per_thread,
				sizeof(struct xio_reg_mem),
				tdata, out_reg_mem_init);

	if (tdata->client_data->server_dlen)
		tdata->in_reg_mem_pool = obj_pool_init(
				qdepth_per_thread,
				sizeof(struct xio_reg_mem),
				tdata, in_reg_mem_init);

	tdata->req_pool = obj_pool_init(qdepth_per_thread,
					sizeof(struct xio_msg),
					tdata, msg_obj_init);

	/* send first messages */
	pthread_spin_lock(&tdata->client_data->lock);
	for (i = 0; i < qdepth_per_thread; i++) {
		if (tdata->client_data->nsent <
		    tdata->client_data->disconnect_nr) {
			req = (struct xio_msg *)obj_pool_get(tdata->req_pool);
			xio_send_request(connection_entry->connection, req);
			tdata->client_data->nsent++;
		}
	}
	pthread_spin_unlock(&tdata->client_data->lock);

	/* sync threads */
	pthread_barrier_wait(&tdata->client_data->barr);

	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

	/* normal exit phase */
	DEBUG("client exit signaled\n");

	/* free the context */
	xio_context_destroy(tdata->ctx);

	obj_pool_free(tdata->req_pool, tdata, msg_obj_free);
	if (tdata->client_data->client_dlen)
		obj_pool_free(tdata->out_reg_mem_pool, NULL, reg_mem_free);
	if (tdata->client_data->server_dlen)
		obj_pool_free(tdata->in_reg_mem_pool, NULL, reg_mem_free);

	DEBUG("client thread exit\n");

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* on_connection_teardown						     */
/*---------------------------------------------------------------------------*/
static int on_connection_teardown(struct xio_session *session,
				  struct xio_connection *connection,
				  void *cb_user_context)
{
	struct client_data *client_data = (struct client_data *)cb_user_context;
	struct session_entry *session_entry;
	struct connection_entry *connection_entry, *tmp_connection_entry;

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
					break;
				}
			}
			break;
		}
	}
	pthread_spin_unlock(&client_data->lock);

	xio_connection_destroy(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_teardown							     */
/*---------------------------------------------------------------------------*/
static int on_session_teardown(struct xio_session *session,
			       void *cb_user_context)
{
	struct client_data *client_data = (struct client_data *)cb_user_context;
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
	DEBUG("client: sent:%d, recv:%d, flushed:%d\n",
	      client_data->nsent, client_data->nrecv, client_data->nerror);

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
	struct client_data *client_data = (struct client_data *)cb_user_context;
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
			xio_context_stop_loop(client_data->tdata[i].ctx);
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
			enum xio_status error,
			enum xio_msg_direction direction,
			struct xio_msg  *req,
			void *cb_user_context)
{
	struct connection_entry	*conn_entry	=
				(struct connection_entry *)cb_user_context;
	struct thread_data	*tdata		= conn_entry->tdata;

	if (direction == XIO_MSG_DIRECTION_OUT) {
		DEBUG("**** [%p] message %lu failed. reason: %s\n",
		       session, req->sn, xio_strerror(error));
	} else {
		xio_release_response(req);
		DEBUG("**** [%p] message %lu failed. reason: %s\n",
		       session, req->request->sn, xio_strerror(error));
	}
	obj_pool_put(tdata->req_pool, req);

	pthread_spin_lock(&tdata->client_data->lock);
	tdata->client_data->nerror++;
	pthread_spin_unlock(&tdata->client_data->lock);


	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_response								     */
/*---------------------------------------------------------------------------*/
static int on_response(struct xio_session *session,
		       struct xio_msg *rsp,
		       int last_in_rxq,
		       void *cb_user_context)
{
	struct connection_entry	*conn_entry	=
				(struct connection_entry *)cb_user_context;
	struct thread_data	*tdata		= conn_entry->tdata;
#if  TEST_DISCONNECT
	struct session_entry	*session_entry	= conn_entry->session_entry;
	struct connection_entry *connection_entry;
#endif
	struct xio_reg_mem	*in_reg_mem;
	struct xio_iovec_ex	*isglist = vmsg_sglist(&rsp->in);

	/* acknowledge xio that response is no longer needed */
	xio_release_response(rsp);

#if  TEST_DISCONNECT
	pthread_spin_lock(&tdata->client_data->lock);
	tdata->client_data->nrecv++;
	if (tdata->client_data->nrecv == tdata->client_data->disconnect_nr) {
		TAILQ_FOREACH(connection_entry,
			      &session_entry->conns_list,
			      conns_list_entry) {
				DEBUG("client disconnect. session:%p, " \
				      "connection:%p\n",
				      session, connection_entry->connection);
				connection_entry->disconnected = 1;
				xio_disconnect(connection_entry->connection);
		}
	}
	if (tdata->client_data->nsent >= tdata->client_data->disconnect_nr) {
		obj_pool_put(tdata->req_pool, rsp);
		pthread_spin_unlock(&tdata->client_data->lock);
		return 0;
	}
	pthread_spin_unlock(&tdata->client_data->lock);
#endif

	/* resend the message */
	if (tdata->client_data->server_dlen &&
	    isglist[0].user_context) {
		in_reg_mem = (struct xio_reg_mem *)isglist[0].user_context;

		isglist[0].iov_base	= in_reg_mem->addr;
		isglist[0].iov_len	= in_reg_mem->length;
		isglist[0].mr		= in_reg_mem->mr;
		vmsg_sglist_set_nents(&rsp->in, 1);
	} else {
		isglist[0].iov_base	= NULL;
		isglist[0].iov_len	= 0;
		isglist[0].mr		= NULL;
		vmsg_sglist_set_nents(&rsp->in, 0);
	}

	rsp->in.header.iov_len			= 0;

	xio_send_request(conn_entry->connection, rsp);
	pthread_spin_lock(&tdata->client_data->lock);
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
	struct xio_session_params params;


	memset(&client_data, 0, sizeof(client_data));
	memset(&params, 0, sizeof(params));

	client_data.tdata = (struct thread_data *)calloc(client_threads_num,
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

	session_entry =
		(struct session_entry *)calloc(1, sizeof(*session_entry));
	TAILQ_INIT(&session_entry->conns_list);

	/* create url to connect to */
	sprintf(url, "rdma://%s:%s", argv[1], argv[2]);
	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.user_context	= &client_data;
	params.uri		= url;

	session_entry->session = xio_session_create(&params);
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

