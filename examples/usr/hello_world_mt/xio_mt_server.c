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

#define MAX_THREADS		4
#define QUEUE_DEPTH		512
#define PRINT_COUNTER		1000000
#define DISCONNECT_NR		2000000

int test_disconnect;

struct portals_vec {
	int			vec_len;
	int			pad;
	const char		*vec[MAX_THREADS];
};

struct thread_data {
	char			portal[64];
	int			affinity;
	int			cnt;
	int			nsent;
	int			pad;
	struct xio_msg		rsp[QUEUE_DEPTH];
	struct xio_context	*ctx;
	struct xio_connection	*connection;
	pthread_t		thread_id;
};

/* server private data */
struct server_data {
	struct xio_context	*ctx;
	struct thread_data	tdata[MAX_THREADS];
};

static struct portals_vec *portals_get(struct server_data *server_data,
				       const char *uri, void *user_context)
{
	/* fill portals array and return it. */
	int			i;
	struct portals_vec	*portals = (struct portals_vec *)
						calloc(1, sizeof(*portals));
	for (i = 0; i < MAX_THREADS; i++) {
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

	free(portals);
}

/*---------------------------------------------------------------------------*/
/* process_request							     */
/*---------------------------------------------------------------------------*/
static void process_request(struct thread_data *tdata,
			    struct xio_msg *req)
{
	if (++tdata->cnt == PRINT_COUNTER) {
		printf("thread [%d] tid:%p - message: [%lu] - %s\n",
		       tdata->affinity,
		       (void *)pthread_self(),
		       (req->sn + 1), (char *)req->in.header.iov_base);
		tdata->cnt = 0;
	}
	req->in.header.iov_base	  = NULL;
	req->in.header.iov_len	  = 0;
	vmsg_sglist_set_nents(&req->in, 0);
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session,
		      struct xio_msg *req,
		      int last_in_rxq,
		      void *cb_user_context)
{
	struct thread_data	*tdata = (struct thread_data *)cb_user_context;
	int i = req->sn % QUEUE_DEPTH;

	/* process request */
	process_request(tdata, req);

	/* attach request to response */
	tdata->rsp[i].request = req;

	xio_send_response(&tdata->rsp[i]);
	tdata->nsent++;

	if (test_disconnect) {
		if (tdata->nsent == DISCONNECT_NR && tdata->connection) {
			xio_disconnect(tdata->connection);
			return 0;
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops  portal_server_ops = {
	.on_session_event		=  NULL,
	.on_new_session			=  NULL,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  on_request,
	.on_msg_error			=  NULL
};

/*---------------------------------------------------------------------------*/
/* worker thread callback						     */
/*---------------------------------------------------------------------------*/
static void *portal_server_cb(void *data)
{
	struct thread_data	*tdata = (struct thread_data *)data;
	cpu_set_t		cpuset;
	struct xio_server	*server;
	char			str[128];
	int			i;

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);


	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, 0, tdata->affinity);

	/* bind a listener server to a portal/url */
	printf("thread [%d] - listen:%s\n", tdata->affinity, tdata->portal);
	server = xio_bind(tdata->ctx, &portal_server_ops, tdata->portal,
			  NULL, 0, tdata);
	if (server == NULL)
		goto cleanup;

	sprintf(str, "hello world header response from thread %d",
		tdata->affinity);
	/* create "hello world" message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		tdata->rsp[i].out.header.iov_base = strdup(str);
		tdata->rsp[i].out.header.iov_len =
			strlen((const char *)
				tdata->rsp[i].out.header.iov_base) + 1;
	}

	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	/* detach the server */
	xio_unbind(server);

	/* free the message */
	for (i = 0; i < QUEUE_DEPTH; i++)
		free(tdata->rsp[i].out.header.iov_base);

cleanup:
	/* free the context */
	xio_context_destroy(tdata->ctx);

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct server_data *server_data = (struct server_data *)cb_user_context;
	struct thread_data *tdata;
	int		   i;


	tdata = (event_data->conn_user_context == server_data) ?
		NULL : (struct thread_data *)event_data->conn_user_context;

	printf("session event: %s. session:%p, connection:%p, reason: %s\n",
	       xio_session_event_str(event_data->event),
	       session, event_data->conn,
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		if (tdata)
			tdata->connection = event_data->conn;
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		if (tdata)
			tdata->connection = NULL;
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		for (i = 0; i < MAX_THREADS; i++)
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

	portals = portals_get(server_data, req->uri, req->private_data);

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
int main(int argc, char *argv[])
{
	struct xio_server	*server;	/* server portal */
	struct server_data	*server_data;
	char			url[256];
	int			i;
	uint16_t		port = atoi(argv[2]);

	if (argc < 3) {
		printf("Usage: %s <host> <port> <transport:optional>\
				<finite run:optional>\n", argv[0]);
		exit(1);
	}

	server_data = (struct server_data *)calloc(1, sizeof(*server_data));
	if (!server_data)
		return -1;

	xio_init();

	/* create thread context for the client */
	server_data->ctx	= xio_context_create(NULL, 0, -1);

	/* create url to connect to */
	if (argc > 3)
		sprintf(url, "%s://%s:%d", argv[3], argv[1], port);
	else
		sprintf(url, "rdma://%s:%d", argv[1], port);

	if (argc > 4)
		test_disconnect = atoi(argv[4]);
	else
		test_disconnect = 1;

	/* bind a listener server to a portal/url */
	server = xio_bind(server_data->ctx, &server_ops,
			  url, NULL, 0, server_data);
	if (server == NULL)
		goto cleanup;


	/* spawn portals */
	for (i = 0; i < MAX_THREADS; i++) {
		server_data->tdata[i].affinity = i+1;
		port += 1;
		if (argc > 3)
			sprintf(server_data->tdata[i].portal, "%s://%s:%d",
				argv[3], argv[1], port);
		else
			sprintf(server_data->tdata[i].portal, "rdma://%s:%d",
				argv[1], port);
		pthread_create(&server_data->tdata[i].thread_id, NULL,
			       portal_server_cb, &server_data->tdata[i]);
	}

	xio_context_run_loop(server_data->ctx, XIO_INFINITE);

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	/* join the threads */
	for (i = 0; i < MAX_THREADS; i++)
		pthread_join(server_data->tdata[i].thread_id, NULL);

	/* free the server */
	xio_unbind(server);
cleanup:
	/* free the context */
	xio_context_destroy(server_data->ctx);

	xio_shutdown();

	free(server_data);

	return 0;
}

