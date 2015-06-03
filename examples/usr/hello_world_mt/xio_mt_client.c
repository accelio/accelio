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

#define MAX_THREADS		4
#define PRINT_COUNTER		400000
#define DISCONNECT_NR		3000000

int test_disconnect;

struct thread_data {
	int			cid;
	int			affinity;
	uint64_t		cnt;
	uint64_t		nsent;
	uint64_t		nrecv;
	struct xio_session	*session;
	struct xio_connection	*conn;
	struct xio_context	*ctx;
	struct xio_msg		req;
	pthread_t		thread_id;
};


/* private session data */
struct session_data {
	struct xio_session	*session;
	struct thread_data	tdata[MAX_THREADS];
};

/*---------------------------------------------------------------------------*/
/* worker_thread							     */
/*---------------------------------------------------------------------------*/
static void *worker_thread(void *data)
{
	struct thread_data		*tdata = (struct thread_data *)data;
	struct xio_connection_params	cparams;
	cpu_set_t			cpuset;
	char				str[128];

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, 0, tdata->affinity);

	memset(&cparams, 0, sizeof(cparams));
	cparams.session			= tdata->session;
	cparams.ctx			= tdata->ctx;
	cparams.conn_idx		= tdata->cid;
	cparams.conn_user_context	= tdata;

	/* connect the session  */
	tdata->conn = xio_connect(&cparams);

	/* create "hello world" message */
	memset(&tdata->req, 0, sizeof(tdata->req));
	sprintf(str, "hello world header request from thread %d",
		tdata->affinity);
	tdata->req.out.header.iov_base = strdup(str);
	tdata->req.out.header.iov_len =
		strlen((const char *)tdata->req.out.header.iov_base) + 1;

	/* send first message */
	xio_send_request(tdata->conn, &tdata->req);
	tdata->nsent++;

	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	free(tdata->req.out.header.iov_base);

	/* free the context */
	xio_context_destroy(tdata->ctx);

	fprintf(stdout, "thread exit\n");
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct thread_data  *tdata,
			     struct xio_msg *rsp)
{
	if (++tdata->cnt == PRINT_COUNTER) {
		((char *)(rsp->in.header.iov_base))[rsp->in.header.iov_len] = 0;
		printf("thread [%d] - tid:%p  - message: [%lu] - %s\n",
		       tdata->affinity,
		      (void *)pthread_self(),
		       (rsp->request->sn + 1), (char *)rsp->in.header.iov_base);
		tdata->cnt = 0;
	}
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct session_data *session_data = (struct session_data *)
						cb_user_context;
	int			i;

	printf("%s. reason: %s\n",
	       xio_session_event_str(event_data->event),
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		for (i = 0; i < MAX_THREADS; i++)
			if (session_data->tdata[i].ctx)
				xio_context_stop_loop(session_data->tdata[i].ctx);
		break;
	default:
		break;
	};

	/* normal exit phase */
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
	struct thread_data  *tdata = (struct thread_data *)cb_user_context;

	tdata->nrecv++;

	/* process the incoming message */
	process_response(tdata, rsp);

	/* acknowlege xio that response is no longer needed */
	xio_release_response(rsp);

	if (test_disconnect) {
		if (tdata->nrecv == DISCONNECT_NR) {
			xio_disconnect(tdata->conn);
			return 0;
		}
	}

	if (tdata->nsent == DISCONNECT_NR)
		return 0;

	tdata->req.in.header.iov_base	  = NULL;
	tdata->req.in.header.iov_len	  = 0;
	vmsg_sglist_set_nents(&tdata->req.in, 0);

	/* resend the message */
	xio_send_request(tdata->conn, &tdata->req);
	tdata->nsent++;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  NULL,
	.on_msg				=  on_response,
	.on_msg_error			=  NULL
};

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	int			i;
	char			url[256];
	struct session_data	session_data;
	struct xio_session_params params;


	if (argc < 3) {
		printf("Usage: %s <host> <port> <transport:optional>\
				<finite run:optional>\n", argv[0]);
		exit(1);
	}
	memset(&session_data, 0, sizeof(session_data));
	memset(&params, 0, sizeof(params));

	xio_init();

	/* create url to connect to */
	if (argc > 3)
		sprintf(url, "%s://%s:%s", argv[3], argv[1], argv[2]);
	else
		sprintf(url, "rdma://%s:%s", argv[1], argv[2]);

	if (argc > 4)
		test_disconnect = atoi(argv[4]);
	else
		test_disconnect = 1;

	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.user_context	= &session_data;
	params.uri		= url;

	session_data.session = xio_session_create(&params);
	if (session_data.session == NULL)
		goto cleanup;

	/* spawn threads to handle connection */
	for (i = 0; i < MAX_THREADS; i++) {
		session_data.tdata[i].affinity	= i+1;
		session_data.tdata[i].cid	= i+1;
		session_data.tdata[i].cnt	= 0;
		/* all threads are working on the same session */
		session_data.tdata[i].session	= session_data.session;
		pthread_create(&session_data.tdata[i].thread_id, NULL,
			       worker_thread, &session_data.tdata[i]);
	}

	/* join the threads */
	for (i = 0; i < MAX_THREADS; i++)
		pthread_join(session_data.tdata[i].thread_id, NULL);

	/* close the session */
	xio_session_destroy(session_data.session);

cleanup:
	xio_shutdown();

	return 0;
}

