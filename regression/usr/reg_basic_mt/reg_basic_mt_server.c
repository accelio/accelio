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

#define PRINT_COUNTER		1000000
#define TEST_DISCONNECT		0
#define DISCONNECT_NR		6000000
#define EXTRA_QDEPTH		64

struct portals_vec {
	int			vec_len;
	int			pad;
	const char		**vec;
};

struct thread_data {
	char			portal[64];
	int			affinity;
	int			cnt;
	int			nsent;
	int			pad;
	struct obj_pool		*rsp_pool;
	struct obj_pool		*in_iobuf_pool;
	struct obj_pool		*out_iobuf_pool;
	struct xio_context	*ctx;
	struct server_data	*server_data;
	pthread_t		thread_id;
};


/* server private data */
struct server_data {
	struct xio_context	*ctx;
	int			threads_num;
	int			queue_depth;
	int			client_dlen;
	int			server_dlen;
	struct thread_data	*tdata;
};

static struct portals_vec *portals_get(struct server_data *server_data,
				const char *uri, void *user_context)
{
	/* fill portals array and return it. */
	int			i;
	struct portals_vec	*portals = calloc(1, sizeof(*portals));

	portals->vec = calloc(server_data->threads_num, sizeof(*portals->vec));
	for (i = 0; i < server_data->threads_num; i++) {
		portals->vec[i] = strdup(server_data->tdata[i].portal);
		portals->vec_len++;
	}

	return portals;
}

static void portals_free(struct portals_vec *portals)
{
	int			i;
	for (i = 0; i < portals->vec_len; i++)
		free((char *)(portals->vec[i]));

	free(portals->vec);
	free(portals);
}

static void out_iobuf_obj_init(void *user_context, void *obj)
{
	struct xio_buf		**iobuf	= obj;
	struct thread_data	*tdata	= user_context;

	*iobuf = xio_alloc(tdata->server_data->server_dlen);
}

static void in_iobuf_obj_init(void *user_context, void *obj)
{
	struct xio_buf		**iobuf	= obj;
	struct thread_data	*tdata	= user_context;

	*iobuf = xio_alloc(tdata->server_data->client_dlen);
}

static void iobuf_obj_free(void *user_context, void *obj)
{
	struct xio_buf		**iobuf	= obj;

	xio_free(iobuf);
}

static void msg_obj_init(void *user_context, void *obj)
{
	struct xio_msg		*rsp	= obj;
	struct xio_buf		**iobuf;
	struct thread_data	*tdata	= user_context;

	if (tdata->server_data->server_dlen) {
		iobuf = obj_pool_get(tdata->out_iobuf_pool);

		rsp->out.data_iov[0].iov_base	= (*iobuf)->addr;
		rsp->out.data_iov[0].iov_len	= (*iobuf)->length;
		rsp->out.data_iov[0].mr		= (*iobuf)->mr;
		rsp->out.data_iov[0].user_context = iobuf;
		rsp->out.data_iovlen		= 1;
	} else {
		rsp->out.data_iov[0].iov_base	= NULL;
		rsp->out.data_iov[0].iov_len	= 0;
		rsp->out.data_iov[0].mr		= NULL;
		rsp->out.data_iov[0].user_context = NULL;
		rsp->out.data_iovlen		= 1;
	}
	rsp->out.header.iov_len		= 0;
	rsp->in.data_iovlen		= 0;
	rsp->in.header.iov_len		= 0;
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session,
			struct xio_msg *req,
			int more_in_batch,
			void *cb_user_context)
{
	struct thread_data	*tdata  = cb_user_context;
	struct xio_buf		**iobuf = req->in.data_iov[0].user_context;
	struct xio_msg		*rsp;

	/* process request */
	if (iobuf && req->in.data_iovlen) {
		obj_pool_put(tdata->in_iobuf_pool, iobuf);
		req->in.data_iov[0].user_context = NULL;
	}
	rsp = obj_pool_get(tdata->rsp_pool);

	/* attach request to response */
	rsp->request = req;

	rsp->in.header.iov_len		= 0;
	rsp->in.data_iovlen		= 0;
	rsp->out.header.iov_len		= 0;
	rsp->out.data_iov[0].iov_len	= tdata->server_data->server_dlen;
	rsp->out.data_iovlen		=
				tdata->server_data->server_dlen ? 1 : 0;


	xio_send_response(rsp);
	tdata->nsent++;

#if  TEST_DISCONNECT
	if (tdata->nsent == DISCONNECT_NR) {
		struct xio_connection *connection =
			xio_get_connection(session, tdata->ctx);
		DEBUG("client disconnect. session:%p, connection:%p\n",
		      session, connection);
		xio_disconnect(connection);
		return 0;
	}
#endif

	return 0;
}

/*---------------------------------------------------------------------------*/
/* assign_data_in_buf							     */
/*---------------------------------------------------------------------------*/
int assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	struct thread_data	*tdata = cb_user_context;
	struct xio_buf		**iobuf;


	iobuf = obj_pool_get(tdata->in_iobuf_pool);

	msg->in.data_iovlen = 1;

	msg->in.data_iov[0].iov_base	= (*iobuf)->addr;
	msg->in.data_iov[0].iov_len	= (*iobuf)->length;
	msg->in.data_iov[0].mr		= (*iobuf)->mr;
	msg->in.data_iov[0].user_context = iobuf;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_send_rsp_complete						     */
/*---------------------------------------------------------------------------*/
static int on_send_rsp_complete(struct xio_session *session,
			struct xio_msg *rsp,
			void *cb_prv_data)
{
	struct thread_data	*tdata = cb_prv_data;

	/* can be safely freed */
	obj_pool_put(tdata->rsp_pool, rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_msg_error								     */
/*---------------------------------------------------------------------------*/
int on_msg_error(struct xio_session *session,
		enum xio_status error, struct xio_msg  *msg,
		void *cb_prv_data)
{
	struct thread_data	*tdata = cb_prv_data;

	obj_pool_put(tdata->rsp_pool, msg);

	return 0;
}

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
/* worker thread callback						     */
/*---------------------------------------------------------------------------*/
static void *portal_server_cb(void *data)
{
	struct thread_data	*tdata = data;
	cpu_set_t		cpuset;
	struct xio_server	*server;

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);


	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, 0);

	if (tdata->server_data->server_dlen)
		tdata->out_iobuf_pool = obj_pool_init(
				tdata->server_data->queue_depth + EXTRA_QDEPTH,
				sizeof(struct xio_buf *),
				tdata, out_iobuf_obj_init);

	if (tdata->server_data->client_dlen)
		tdata->in_iobuf_pool = obj_pool_init(
				tdata->server_data->queue_depth,
				sizeof(struct xio_buf *),
				tdata, in_iobuf_obj_init);

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

	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

	/* normal exit phase */
	DEBUG("exit signaled\n");

	/* detach the server */
	xio_unbind(server);

	obj_pool_free(tdata->rsp_pool, NULL, NULL);
	if (tdata->server_data->client_dlen)
		obj_pool_free(tdata->in_iobuf_pool, NULL, iobuf_obj_free);
	if (tdata->server_data->server_dlen)
		obj_pool_free(tdata->out_iobuf_pool, NULL, iobuf_obj_free);

cleanup:
	/* free the context */
	xio_context_destroy(tdata->ctx);

	DEBUG("thread exit\n");
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
		struct xio_session_event_data *event_data,
		void *cb_user_context)
{
	struct server_data *server_data = cb_user_context;
	int		   i;

	DEBUG("server session event: %s. session:%p, " \
	      "connection:%p, reason: %s\n",
	      xio_session_event_str(event_data->event),
	      session, event_data->conn,
	      xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		for (i = 0; i < server_data->threads_num; i++)
			xio_context_stop_loop(server_data->tdata[i].ctx, 0);
		xio_context_stop_loop(server_data->ctx, 0);
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
	struct server_data *server_data = cb_user_context;

	portals = portals_get(server_data, req->uri, req->user_context);

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
	uint16_t		port		= atoi(argv[2]);
	uint16_t		threads_num	= atoi(argv[3]);
	int			queue_depth     = atoi(argv[4]);
	int			client_dlen     = atoll(argv[5]);
	int			server_dlen     = atoll(argv[6]);


	server_data = calloc(1, sizeof(*server_data));
	if (!server_data)
		return -1;

	server_data->tdata = calloc(threads_num, sizeof(*server_data->tdata));
	if (!server_data->tdata)
		return -1;

	server_data->threads_num = threads_num;
	server_data->queue_depth = queue_depth;
	server_data->client_dlen = client_dlen;
	server_data->server_dlen = server_dlen;

	xio_init();

	/* create thread context for the client */
	server_data->ctx	= xio_context_create(NULL, 0);

	/* create url to connect to */
	sprintf(url, "rdma://%s:%d", argv[1], port);
	/* bind a listener server to a portal/url */
	server = xio_bind(server_data->ctx, &server_ops,
			  url, NULL, 0, server_data);
	if (server == NULL)
		goto cleanup;

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
	xio_context_run_loop(server_data->ctx, XIO_INFINITE);

	/* normal exit phase */
	DEBUG("exit signaled\n");

	/* join the threads */
	for (i = 0; i < server_data->threads_num; i++)
		pthread_join(server_data->tdata[i].thread_id, NULL);

	/* free the server */
	xio_unbind(server);
cleanup:
	/* free the context */
	xio_context_destroy(server_data->ctx);

	xio_shutdown();


	free(server_data->tdata);
	free(server_data);

	DEBUG("server: goodbye and good riddance\n");

	return 0;
}

