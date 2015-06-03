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

#include "libxio.h"
#include "obj_pool.h"
#include "reg_utils.h"
#include <sys/queue.h>

#define PRINT_COUNTER		1000000
#define TEST_DISCONNECT		1
#define EXTRA_QDEPTH		128


struct portals_vec {
	int				vec_len;
	int				pad;
	const char			**vec;
};

struct  connection_entry {
	struct xio_connection		*connection;
	TAILQ_ENTRY(connection_entry)	conns_list_entry;
};

struct session_entry {
	struct xio_session		*session;
	volatile int			disconnected;
	int				pad;
	TAILQ_HEAD(, connection_entry)	conns_list;
	TAILQ_ENTRY(session_entry)	sessions_list_entry;
};

struct thread_data {
	char				portal[64];
	int				affinity;
	int				pad;
	struct obj_pool			*rsp_pool;
	struct obj_pool			*in_reg_mem_pool;
	struct obj_pool			*out_reg_mem_pool;
	struct xio_context		*ctx;
	struct server_data		*server_data;
	pthread_t			thread_id;
};

/* server private data */
struct server_data {
	struct xio_context		*ctx;
	int				threads_num;
	int				queue_depth;
	int				client_dlen;
	int				server_dlen;
	int				disconnect_nr;
	volatile int			ncomp;
	volatile int			nsent;
	volatile int			nerror;
	int				pad;
	pthread_spinlock_t		lock;
	TAILQ_HEAD(, session_entry)	sessions_list;
	pthread_barrier_t		barr;
	struct thread_data		*tdata;
};

/*---------------------------------------------------------------------------*/
/* portals_get								     */
/*---------------------------------------------------------------------------*/
static struct portals_vec *portals_get(struct server_data *server_data,
				       const char *uri, void *user_context)
{
	/* fill portals array and return it. */
	int			i;
	struct portals_vec	*portals =
			(struct portals_vec *)calloc(1, sizeof(*portals));

	portals->vec = (const char **)
			calloc(server_data->threads_num, sizeof(*portals->vec));
	for (i = 0; i < server_data->threads_num; i++) {
		portals->vec[i] = strdup(server_data->tdata[i].portal);
		portals->vec_len++;
	}

	return portals;
}

/*---------------------------------------------------------------------------*/
/* portals_free								     */
/*---------------------------------------------------------------------------*/
static void portals_free(struct portals_vec *portals)
{
	int			i;
	for (i = 0; i < portals->vec_len; i++)
		free((char *)(portals->vec[i]));

	free(portals->vec);
	free(portals);
}

/*---------------------------------------------------------------------------*/
/* out_reg_mem_init							     */
/*---------------------------------------------------------------------------*/
static void out_reg_mem_init(void *user_context, void *obj)
{
	struct xio_reg_mem	*reg_mem = (struct xio_reg_mem *)obj;
	struct thread_data	*tdata	= (struct thread_data *)user_context;

	xio_mem_alloc(tdata->server_data->server_dlen, reg_mem);
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
static void in_reg_mem_init(void *user_context, void *obj)
{
	struct xio_reg_mem	*reg_mem = (struct xio_reg_mem *)obj;
	struct thread_data	*tdata	= (struct thread_data *)user_context;

	xio_mem_alloc(tdata->server_data->client_dlen, reg_mem);
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
static void reg_mem_free(void *user_context, void *obj)
{
	struct xio_reg_mem	*reg_mem = (struct xio_reg_mem *)obj;

	xio_mem_free(reg_mem);
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
static void msg_obj_init(void *user_context, void *obj)
{
	struct xio_msg *rsp = (struct xio_msg *)obj;

	rsp->out.header.iov_len		= 0;
	rsp->in.header.iov_len		= 0;
	vmsg_sglist_set_nents(&rsp->in, 0);
	vmsg_sglist_set_nents(&rsp->out, 0);
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session,
		      struct xio_msg *req,
		      int last_in_rxq,
		      void *cb_user_context)
{
	struct thread_data	*tdata  = (struct thread_data *)cb_user_context;
	struct xio_iovec_ex	*sglist = vmsg_sglist(&req->in);
	struct xio_reg_mem	*reg_mem = (struct xio_reg_mem *)sglist[0].user_context;
	struct xio_msg		*rsp;

	/* process request */
	if (reg_mem && vmsg_sglist_nents(&req->in)) {
		obj_pool_put(tdata->in_reg_mem_pool, reg_mem);
		sglist[0].user_context = NULL;
	}

	rsp = (struct xio_msg *)obj_pool_get(tdata->rsp_pool);

	/* attach request to response */
	rsp->request = req;

	rsp->in.header.iov_len	= 0;
	vmsg_sglist_set_nents(&rsp->in, 0);
//
	sglist = vmsg_sglist(&rsp->out);
	if (tdata->server_data->server_dlen) {
		reg_mem = (struct xio_reg_mem *)obj_pool_get(tdata->out_reg_mem_pool);

		sglist[0].iov_base	= reg_mem->addr;
		sglist[0].iov_len	=
				tdata->server_data->server_dlen;
		sglist[0].mr		= reg_mem->mr;
		sglist[0].user_context = reg_mem;
		vmsg_sglist_set_nents(&rsp->out, 1);
	} else {
		vmsg_sglist_set_nents(&rsp->out, 0);
	}
	rsp->out.header.iov_len	= 0;

	xio_send_response(rsp);

	pthread_spin_lock(&tdata->server_data->lock);
	tdata->server_data->nsent++;
	pthread_spin_unlock(&tdata->server_data->lock);


	return 0;
}

/*---------------------------------------------------------------------------*/
/* assign_data_in_buf							     */
/*---------------------------------------------------------------------------*/
int assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	struct thread_data	*tdata = (struct thread_data *)cb_user_context;
	struct xio_iovec_ex	*sglist = vmsg_sglist(&msg->in);
	struct xio_reg_mem	*reg_mem;

	reg_mem = (struct xio_reg_mem *)obj_pool_get(tdata->in_reg_mem_pool);

	vmsg_sglist_set_nents(&msg->in, 1);
	sglist[0].iov_base	= reg_mem->addr;
	sglist[0].iov_len	= reg_mem->length;
	sglist[0].mr		= reg_mem->mr;
	sglist[0].user_context	= reg_mem;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_send_rsp_complete							     */
/*---------------------------------------------------------------------------*/
static int on_send_rsp_complete(struct xio_session *session,
				struct xio_msg *rsp,
				void *cb_prv_data)
{
	struct thread_data	*tdata = (struct thread_data *)cb_prv_data;
	struct xio_iovec_ex	*sglist = vmsg_sglist(&rsp->out);

	if (tdata->server_data->server_dlen) {
		obj_pool_put(tdata->out_reg_mem_pool,
			     sglist[0].user_context);

		sglist[0].iov_base	= NULL;
		sglist[0].iov_len	= 0;
		sglist[0].mr		= NULL;
		sglist[0].user_context	= NULL;
	}
	vmsg_sglist_set_nents(&rsp->out, 0);

	/* can be safely freed */
	obj_pool_put(tdata->rsp_pool, rsp);

	pthread_spin_lock(&tdata->server_data->lock);
	tdata->server_data->ncomp++;

#if  TEST_DISCONNECT
	if (tdata->server_data->ncomp == tdata->server_data->disconnect_nr) {
		struct session_entry *session_entry,
				     *tmp_session_entry;
		struct connection_entry *connection_entry,
					*tmp_connection_entry;

		TAILQ_FOREACH_SAFE(session_entry, tmp_session_entry,
				   &tdata->server_data->sessions_list,
				   sessions_list_entry) {
			if ((session_entry->session == session) &&
			    (session_entry->disconnected == 0)) {
				session_entry->disconnected = 1;
				TAILQ_FOREACH_SAFE(connection_entry,
						   tmp_connection_entry,
						   &session_entry->conns_list,
						   conns_list_entry) {
						DEBUG(
						  "server disconnect. " \
						  "session:%p, connection:%p\n",
						  session,
						  connection_entry->connection);
						xio_disconnect(
						  connection_entry->connection);
				}
				break;
			}
		}
	}
#endif
	pthread_spin_unlock(&tdata->server_data->lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_msg_error								     */
/*---------------------------------------------------------------------------*/
static int on_msg_error(struct xio_session *session,
			enum xio_status error,
			enum xio_msg_direction direction,
			struct xio_msg  *rsp,
			void *cb_user_context)
{
	struct thread_data	*tdata = (struct thread_data *)cb_user_context;
	struct xio_iovec_ex	*sglist = vmsg_sglist(&rsp->out);

	if (tdata->server_data->server_dlen) {
		obj_pool_put(tdata->out_reg_mem_pool,
			     sglist[0].user_context);

		sglist[0].iov_base		= NULL;
		sglist[0].iov_len		= 0;
		sglist[0].mr			= NULL;
		sglist[0].user_context		= NULL;
	}
	vmsg_sglist_set_nents(&rsp->out, 0);

	obj_pool_put(tdata->rsp_pool, rsp);

	pthread_spin_lock(&tdata->server_data->lock);
	tdata->server_data->nerror++;
	pthread_spin_unlock(&tdata->server_data->lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops  portal_server_ops = {
	.on_session_event		=  NULL,
	.on_new_session			=  NULL,
	.on_msg_send_complete		=  on_send_rsp_complete,
	.on_msg				=  on_request,
	.on_msg_error			=  on_msg_error,
	.assign_data_in_buf		=  assign_data_in_buf
};

/*---------------------------------------------------------------------------*/
/* portal_server_cb							     */
/*---------------------------------------------------------------------------*/
static void *portal_server_cb(void *data)
{
	struct thread_data	*tdata = (struct thread_data *)data;
	cpu_set_t		cpuset;
	struct xio_server	*server;

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);


	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, 0, tdata->affinity);

	if (tdata->server_data->server_dlen)
		tdata->out_reg_mem_pool = obj_pool_init(
				tdata->server_data->queue_depth + EXTRA_QDEPTH,
				sizeof(struct xio_reg_mem),
				tdata, out_reg_mem_init);

	if (tdata->server_data->client_dlen)
		tdata->in_reg_mem_pool = obj_pool_init(
				tdata->server_data->queue_depth + EXTRA_QDEPTH,
				sizeof(struct xio_reg_mem),
				tdata, in_reg_mem_init);

	tdata->rsp_pool = obj_pool_init(
			tdata->server_data->queue_depth + EXTRA_QDEPTH,
			sizeof(struct xio_msg),
			tdata, msg_obj_init);


	/* bind a listener server to a portal/url */
	DEBUG("thread [%d] - listen:%s\n", tdata->affinity, tdata->portal);
	server = xio_bind(tdata->ctx, &portal_server_ops, tdata->portal,
			  NULL, 0, tdata);
	if (server == NULL)
		goto cleanup;

	pthread_barrier_wait(&tdata->server_data->barr);

	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

	/* normal exit phase */
	DEBUG("server exit signaled\n");

	/* detach the server */
	xio_unbind(server);

cleanup:
	/* free the context */
	xio_context_destroy(tdata->ctx);

	obj_pool_free(tdata->rsp_pool, NULL, NULL);
	if (tdata->server_data->client_dlen)
		obj_pool_free(tdata->in_reg_mem_pool, NULL, reg_mem_free);
	if (tdata->server_data->server_dlen)
		obj_pool_free(tdata->out_reg_mem_pool, NULL, reg_mem_free);


	DEBUG("portal thread [%d] exit\n", tdata->affinity);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* on_new_connection							     */
/*---------------------------------------------------------------------------*/
static int on_new_connection(struct xio_session *session,
			     struct xio_connection *connection,
			     void *cb_user_context)
{
	struct server_data *server_data = (struct server_data *)cb_user_context;
	struct session_entry	*session_entry;
	struct connection_entry *connection_entry;

	pthread_spin_lock(&server_data->lock);
	TAILQ_FOREACH(session_entry, &server_data->sessions_list,
		      sessions_list_entry) {
		if (session_entry->session == session) {
			if (session_entry->disconnected == 1) {
				xio_disconnect(connection);
				break;
			}
		connection_entry = (struct connection_entry *)
					calloc(1, sizeof(*connection_entry));
			if (connection_entry == NULL)
				return -1;
			connection_entry->connection = connection;
			TAILQ_INSERT_TAIL(&session_entry->conns_list,
					  connection_entry, conns_list_entry);
			break;
		}
	}
	pthread_spin_unlock(&server_data->lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_connection_teardown						     */
/*---------------------------------------------------------------------------*/
static int on_connection_teardown(struct xio_session *session,
				  struct xio_connection *connection,
				  void *cb_user_context)
{
	struct server_data *server_data = (struct server_data *)cb_user_context;
	struct session_entry *session_entry;
	struct connection_entry *connection_entry, *tmp_connection_entry;

	pthread_spin_lock(&server_data->lock);
	TAILQ_FOREACH(session_entry, &server_data->sessions_list,
		      sessions_list_entry) {
		if (session_entry->session == session) {
			TAILQ_FOREACH_SAFE(
					connection_entry,
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
	pthread_spin_unlock(&server_data->lock);

	xio_connection_destroy(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_teardown							     */
/*---------------------------------------------------------------------------*/
static int on_session_teardown(struct xio_session *session,
			       void *cb_user_context)
{
	struct server_data *server_data = (struct server_data *)cb_user_context;
	struct session_entry *session_entry;


	pthread_spin_lock(&server_data->lock);
	TAILQ_FOREACH(session_entry, &server_data->sessions_list,
		      sessions_list_entry) {
		if (session_entry->session == session) {
			free(session_entry);
			xio_session_destroy(session);
			break;
		}
	}
	DEBUG("server: sent:%d, comp:%d, flushed:%d\n",
	      server_data->nsent, server_data->ncomp, server_data->nerror);
	pthread_spin_unlock(&server_data->lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct server_data *server_data = (struct server_data *)cb_user_context;
	int		   i;

	DEBUG("server session event: %s. session:%p, " \
	      "connection:%p, reason: %s\n",
	      xio_session_event_str(event_data->event),
	      session, event_data->conn,
	      xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		on_new_connection(session, event_data->conn, cb_user_context);
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		on_connection_teardown(session, event_data->conn,
				       cb_user_context);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		on_session_teardown(session, cb_user_context);
		for (i = 0; i < server_data->threads_num; i++)
			xio_context_stop_loop(server_data->tdata[i].ctx);
		xio_context_stop_loop(server_data->ctx);
		break;
	default:
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_new_session							     */
/*---------------------------------------------------------------------------*/
static int on_new_session(struct xio_session *session,
			  struct xio_new_session_req *req,
			  void *cb_user_context)
{
	struct portals_vec *portals;
	struct server_data *server_data = (struct server_data *)cb_user_context;
	struct session_entry *session_entry;

	DEBUG("server new session event. session:%p\n", session);

	portals = portals_get(server_data, req->uri, req->private_data);

	session_entry = (struct session_entry *)calloc(1, sizeof(*session_entry));
	TAILQ_INIT(&session_entry->conns_list);
	session_entry->session = session;

	pthread_spin_lock(&server_data->lock);
	TAILQ_INSERT_TAIL(&server_data->sessions_list,
			  session_entry, sessions_list_entry);
	pthread_spin_unlock(&server_data->lock);
	/* automatic accept the request */
	xio_accept(session, portals->vec, portals->vec_len, NULL, 0);

	portals_free(portals);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops  server_ops = {
	.on_session_event		=  on_session_event,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  NULL,
	.on_msg_error			=  NULL
};

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int server_main(int argc, char *argv[])
{
	struct xio_server	*server;	/* server portal */
	struct server_data	*server_data;
	char			url[256];
	int			i;
	uint16_t		port			= atoi(argv[2]);
	int			queue_depth		= atoi(argv[3]);
	/*uint16_t		client_threads_num	= atoi(argv[4]);*/
	uint16_t		server_threads_num	= atoi(argv[5]);
	int			client_dlen		= atoi(argv[6]);
	int			server_dlen		= atoi(argv[7]);
	/*int			client_disconnect_nr	= atoi(argv[8]);*/
	int			server_disconnect_nr	= atoi(argv[9]);


	server_data = (struct server_data *)calloc(1, sizeof(*server_data));
	if (!server_data)
		return -1;

	server_data->tdata = (struct thread_data *)calloc(server_threads_num,
				    sizeof(*server_data->tdata));
	if (!server_data->tdata)
		goto cleanup;

	server_data->threads_num = server_threads_num;
	server_data->queue_depth = queue_depth;
	server_data->client_dlen = client_dlen;
	server_data->server_dlen = server_dlen;
	server_data->disconnect_nr = server_disconnect_nr;

	xio_init();

	/* create thread context for the client */
	server_data->ctx	= xio_context_create(NULL, 0, -1);

	TAILQ_INIT(&server_data->sessions_list);
	pthread_spin_init(&server_data->lock, PTHREAD_PROCESS_PRIVATE);

	/* create url to connect to */
	sprintf(url, "rdma://%s:%d", argv[1], port);
	/* bind a listener server to a portal/url */
	server = xio_bind(server_data->ctx, &server_ops,
			  url, NULL, 0, server_data);
	if (server == NULL)
		goto cleanup1;

	/* initialize thread synchronization barrier */
	pthread_barrier_init(&server_data->barr, NULL,
			     server_data->threads_num + 1);

	/* spawn portals */
	for (i = 0; i < server_data->threads_num; i++) {
		server_data->tdata[i].server_data	= server_data;
		server_data->tdata[i].affinity		= i+1;
		port += 1;

		sprintf(server_data->tdata[i].portal, "rdma://%s:%d",
			argv[1], port);

		pthread_create(&server_data->tdata[i].thread_id, NULL,
			       portal_server_cb, &server_data->tdata[i]);
	}

	pthread_barrier_wait(&server_data->barr);

	xio_context_run_loop(server_data->ctx, XIO_INFINITE);

	/* normal exit phase */
	DEBUG("server exit signaled\n");

	/* join the threads */
	for (i = 0; i < server_data->threads_num; i++)
		pthread_join(server_data->tdata[i].thread_id, NULL);

	/* free the server */
	xio_unbind(server);

cleanup1:
	/* free the context */

	xio_context_destroy(server_data->ctx);

	xio_shutdown();

	pthread_spin_destroy(&server_data->lock);

	free(server_data->tdata);
cleanup:
	free(server_data);

	DEBUG("server: goodbye and good riddance\n");

	return 0;
}

