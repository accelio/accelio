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
#define TEST_DISCONNECT		1
#define DISCONNECT_NR		3000000


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
	struct thread_data	*tdata = data;
	cpu_set_t		cpuset;
	char			str[128];

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, 0, tdata->affinity);

	/* connect the session  */
	tdata->conn = xio_connect(tdata->session, tdata->ctx,
				  tdata->cid, NULL, tdata);

	/* create "hello world" message */
	memset(&tdata->req, 0, sizeof(tdata->req));
	sprintf(str, "hello world header request from thread %d",
		tdata->affinity);
	tdata->req.out.header.iov_base = strdup(str);
	tdata->req.out.header.iov_len =
		strlen(tdata->req.out.header.iov_base);

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
		printf("thread [%d] - tid:%p  - message: [%"PRIu64"] - %s\n",
		       tdata->affinity,
		      (void *)pthread_self(),
		       (rsp->request->sn + 1), (char *)rsp->in.header.iov_base);
		tdata->cnt = 0;
	}
	rsp->in.header.iov_base	  = NULL;
	rsp->in.header.iov_len	  = 0;
	rsp->in.data_iovlen	  = 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
		struct xio_session_event_data *event_data,
		void *cb_user_context)
{
	struct session_data *session_data = cb_user_context;
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
			xio_context_stop_loop(session_data->tdata[i].ctx, 0);
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
			int more_in_batch,
			void *cb_user_context)
{
	struct thread_data  *tdata = cb_user_context;

	tdata->nrecv++;

	/* process the incoming message */
	process_response(tdata, rsp);

	/* acknowlege xio that response is no longer needed */
	xio_release_response(rsp);

#if  TEST_DISCONNECT
	if (tdata->nrecv == DISCONNECT_NR) {
		xio_disconnect(tdata->conn);
		return 0;
	}

	if (tdata->nsent == DISCONNECT_NR)
		return 0;
#endif


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

	/* client session attributes */
	struct xio_session_attr attr = {
		&ses_ops, /* callbacks structure */
		NULL,	  /* no need to pass the server private data */
		0
	};

	xio_init();

	memset(&session_data, 0, sizeof(session_data));
	/* create url to connect to */
	sprintf(url, "rdma://%s:%s", argv[1], argv[2]);
	session_data.session = xio_session_create(XIO_SESSION_CLIENT,
						&attr, url,
						0, 0, &session_data);

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

