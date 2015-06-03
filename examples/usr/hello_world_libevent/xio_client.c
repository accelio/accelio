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
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <event2/event.h>		/* libevent header (libevent-devel) */
#include <event2/event_struct.h>	/* libevent header (libevent-devel) */

#include "libxio.h"

#define QUEUE_DEPTH		512
#define PRINT_COUNTER		4000000
#define DISCONNECT_NR		20000000

int test_disconnect;

/* private session data */
struct session_data {
	struct xio_context	*ctx;
	struct xio_connection	*conn;
	struct event_base	*evbase;
	uint64_t		cnt;
	uint64_t		nsent;
	uint64_t		nrecv;
	uint64_t		pad;
	struct xio_msg		req[QUEUE_DEPTH];
};

static inline void timeout_cb(evutil_socket_t fd, short event, void *arg)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_nsec /= 1000000;
	printf("[%lu.%lu] - timeout_cb called\n", ts.tv_sec, ts.tv_nsec);
}

static inline void xio_event_handler(int fd, short event, void *arg)
{
	struct xio_context  *ctx = (struct xio_context *)arg;

	xio_context_poll_wait(ctx, 0);
}

/*---------------------------------------------------------------------------*/
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct session_data *session_data,
			     struct xio_msg *rsp)
{
	if (++session_data->cnt == PRINT_COUNTER) {
		((char *)(rsp->in.header.iov_base))[rsp->in.header.iov_len] = 0;
		printf("message: [%lu] - %s\n",
		       (rsp->request->sn + 1), (char *)rsp->in.header.iov_base);
		session_data->cnt = 0;
	}
	rsp->in.header.iov_base	  = NULL;
	rsp->in.header.iov_len	  = 0;
	vmsg_sglist_set_nents(&rsp->in, 0);
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct session_data *session_data =
		(struct session_data *)cb_user_context;

	printf("session event: %s. reason: %s\n",
	       xio_session_event_str(event_data->event),
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		event_base_loopbreak(session_data->evbase);
		break;
	default:
		break;
	};

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
	struct session_data *session_data =
			(struct session_data *)cb_user_context;
	int i = rsp->request->sn % QUEUE_DEPTH;

	session_data->nrecv++;
	/* process the incoming message */
	process_response(session_data, rsp);

	/* acknowledge xio that response is no longer needed */
	xio_release_response(rsp);

	if (test_disconnect) {
		if (session_data->nrecv == DISCONNECT_NR) {
			xio_disconnect(session_data->conn);
			printf("disconnect\n");
		}
		if (session_data->nrecv >= DISCONNECT_NR)
			return 0;
	}

	/* resend the message */
	xio_send_request(session_data->conn, &session_data->req[i]);
	session_data->nsent++;

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
	struct xio_session	*session;
	char			url[256];
	struct session_data	session_data;
	int			i = 0;
	struct event		timeout;
	struct event		xio_event;
	struct timeval		tv;
	int			xio_fd;
	struct xio_session_params params;
	struct xio_connection_params cparams;

	if (argc < 3) {
		printf("Usage: %s <host> <port> <transport:optional>\
				<finite run:optional>\n", argv[0]);
		exit(1);
	}
	memset(&session_data, 0, sizeof(session_data));
	memset(&params, 0, sizeof(params));
	memset(&cparams, 0, sizeof(cparams));


	/* initialize library */
	xio_init();

	/* create thread context for the client */
	session_data.ctx = xio_context_create(NULL, 0, -1);

	/* get poll parameters for libevent */
	xio_fd = xio_context_get_poll_fd(session_data.ctx);

	/* create url to connect to */
	if (argc > 3)
		sprintf(url, "%s://%s:%s", argv[3], argv[1], argv[2]);
	else
		sprintf(url, "rdma://%s:%s", argv[1], argv[2]);

	if (argc > 4)
		test_disconnect = atoi(argv[4]);
	else
		test_disconnect = 0;

	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.user_context	= &session_data;
	params.uri		= url;

	session = xio_session_create(&params);
	cparams.session			= session;
	cparams.ctx			= session_data.ctx;
	cparams.conn_user_context	= &session_data;

	/* connect the session  */
	session_data.conn = xio_connect(&cparams);

	/* create "hello world" message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		memset(&session_data.req[i], 0, sizeof(session_data.req[i]));
		/* header */
		session_data.req[i].out.header.iov_base =
			strdup("hello world header request");
		session_data.req[i].out.header.iov_len = 1 +
			strlen((char *)session_data.req[i].out.header.iov_base);
		/* iovec[0]*/
		session_data.req[i].out.sgl_type	   = XIO_SGL_TYPE_IOV;
		session_data.req[i].out.data_iov.max_nents = XIO_IOVLEN;

		session_data.req[i].out.data_iov.sglist[0].iov_base =
			strdup("hello world iovec request");
		session_data.req[i].out.data_iov.sglist[0].iov_len = 1 + strlen(
			(const char *)
			   session_data.req[i].out.data_iov.sglist[0].iov_base);
		session_data.req[i].out.data_iov.nents = 1;
	}
	/* send first message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		xio_send_request(session_data.conn, &session_data.req[i]);
		session_data.nsent++;
	}

	/* Initialize the event library */
	session_data.evbase = event_base_new();

	/* Initialize one timer event */
	event_assign(&timeout, session_data.evbase, -1,
		     EV_PERSIST, timeout_cb, (void *)&timeout);

	evutil_timerclear(&tv);
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	event_add(&timeout, &tv);

	event_assign(&xio_event, session_data.evbase, xio_fd,
		     EV_READ|EV_PERSIST, xio_event_handler,
		     session_data.ctx);

	/* Add it to the active events, without a timeout */
	event_add(&xio_event, NULL);

	event_base_dispatch(session_data.evbase);

	fprintf(stdout, "exit signaled\n");

	event_base_free(session_data.evbase);

	/* free the message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		free(session_data.req[i].out.header.iov_base);
		free(session_data.req[i].out.data_iov.sglist[0].iov_base);
	}

	/* free the context */
	xio_context_destroy(session_data.ctx);

	xio_shutdown();

	printf("good bye\n");
	return 0;
}

