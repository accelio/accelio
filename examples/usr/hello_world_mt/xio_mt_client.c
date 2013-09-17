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
#define HW_PRINT_COUNTER	400000

struct hw_thread_data {
	int			cid;
	int			affinity;
	uint64_t		cnt;
	struct xio_session	*session;
	struct xio_connection	*conn;
	struct xio_context	*ctx;
	struct xio_msg		req;
	void			*loop;
	pthread_t		thread_id;
};


/* private session data */
struct hw_session_data {
	struct xio_session	*session;
	struct hw_thread_data	tdata[MAX_THREADS];
};

static void *hw_worker_thread(void *data)
{
	struct hw_thread_data	*tdata = data;
	cpu_set_t		cpuset;
	char			str[128];

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	/* open default event loop */
	tdata->loop = xio_ev_loop_init();

	/* create thread context for the client */
	tdata->ctx = xio_ctx_open(NULL, tdata->loop, 0);

	/* connect the session  */
	tdata->conn = xio_connect(tdata->session, tdata->ctx,
				  tdata->cid, tdata);

	/* create "hello world" message */
	memset(&tdata->req, 0, sizeof(tdata->req));
	sprintf(str,"hello world header request from thread %d",
		tdata->affinity);
	tdata->req.out.header.iov_base = strdup(str);
	tdata->req.out.header.iov_len =
		strlen(tdata->req.out.header.iov_base);

	/* send first message */
	xio_send_request(tdata->conn, &tdata->req);

	/* the default xio supplied main loop */
	xio_ev_loop_run(tdata->loop);

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	/* free the context */
	xio_ctx_close(tdata->ctx);

	/* destroy the default loop */
	xio_ev_loop_destroy(&tdata->loop);

	fprintf(stdout, "thread exit\n");
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct hw_thread_data  *tdata,
			     struct xio_msg *rsp)
{
	if (++tdata->cnt == HW_PRINT_COUNTER) {
		((char *)(rsp->in.header.iov_base))[rsp->in.header.iov_len] = 0;
		printf("thread [%d] - tid:%p  - message: [%"PRIu64"] - %s\n",
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
	struct hw_session_data *session_data = cb_user_context;
	int			i;

	printf("%s. reason: %s\n",
	       xio_session_event_str(event_data->event),
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_REJECT_EVENT:
	case XIO_SESSION_CONNECTION_DISCONNECTED_EVENT:
		xio_disconnect(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		for (i = 0; i < MAX_THREADS; i++)
			xio_ev_loop_stop(session_data->tdata[i].loop);
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
	struct hw_thread_data  *tdata = cb_user_context;

	/* process the incoming message */
	process_response(tdata, rsp);

	/* acknowlege xio that response is no longer needed */
	xio_release_response(rsp);

	/* resend the message */
	xio_send_request(tdata->conn, &tdata->req);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops ses_ops = {
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
	struct hw_session_data	session_data;

	/* client session attributes */
	struct xio_session_attr attr = {
		&ses_ops, /* callbacks structure */
		NULL,	  /* no need to pass the server private data */
		0
	};

	memset(&session_data, 0, sizeof(session_data));
	/* create url to connect to */
	sprintf(url, "rdma://%s:%s", argv[1], argv[2]);
	session_data.session = xio_session_open(XIO_SESSION_REQ,
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
			       hw_worker_thread, &session_data.tdata[i]);
	}

	/* join the threads */
	for (i = 0; i < MAX_THREADS; i++)
		pthread_join(session_data.tdata[i].thread_id, NULL);

	/* close the session */
	xio_session_close(session_data.session);

cleanup:


	return 0;
}

