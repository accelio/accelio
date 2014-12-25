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
#include <errno.h>

#include "libxio.h"

#define QUEUE_DEPTH		512
#define PRINT_COUNTER		4000000
#define DISCONNECT_NR		2000000

int test_disconnect;

/* server private data */
struct server_data {
	struct xio_context	*ctx;
	struct xio_connection	*connection;
	uint64_t		nsent;
	uint64_t		cnt;
	struct xio_msg		rsp[QUEUE_DEPTH];	/* global message */
};

/*---------------------------------------------------------------------------*/
/* process_request							     */
/*---------------------------------------------------------------------------*/
static void process_request(struct server_data *server_data,
			    struct xio_msg *req)
{
	struct xio_iovec_ex	*sglist = vmsg_sglist(&req->in);
	char			*str;
	int			nents = vmsg_sglist_nents(&req->in);
	int			len, i;
	char			tmp;

	/* note all data is packed together so in order to print each
	 * part on its own NULL character is temporarily stuffed
	 * before the print and the original character is restored after
	 * the printf
	 */
	if (++server_data->cnt == PRINT_COUNTER) {
		str = (char *)req->in.header.iov_base;
		len = req->in.header.iov_len;
		if (str) {
			if (((unsigned) len) > 64)
				len = 64;
			tmp = str[len];
			str[len] = '\0';
			printf("message header : [%lu] - %s\n",
			       (req->sn + 1), str);
			str[len] = tmp;
		}
		for (i = 0; i < nents; i++) {
			str = (char *)sglist[i].iov_base;
			len = sglist[i].iov_len;
			if (str) {
				if (((unsigned) len) > 64)
					len = 64;
				tmp = str[len];
				str[len] = '\0';
				printf("message data: [%lu][%d][%d] - %s\n",
				       (req->sn + 1), i, len, str);
				str[len] = tmp;
			}
		}
		server_data->cnt = 0;
	}
	req->in.header.iov_base	  = NULL;
	req->in.header.iov_len	  = 0;
	vmsg_sglist_set_nents(&req->in, 0);
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct server_data *server_data =
		(struct server_data *)cb_user_context;

	printf("session event: %s. session:%p, connection:%p, reason: %s\n",
	       xio_session_event_str(event_data->event),
	       session, event_data->conn,
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		server_data->connection = event_data->conn;
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		server_data->connection = NULL;
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		xio_context_stop_loop(server_data->ctx);  /* exit */
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
	struct server_data *server_data =
		(struct server_data *)cb_user_context;

	/* automatically accept the request */
	printf("new session event. session:%p\n", session);

	if (server_data->connection == NULL)
		xio_accept(session, NULL, 0, NULL, 0);
	else
		xio_reject(session, (enum xio_status)EISCONN, NULL, 0);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session,
		      struct xio_msg *req,
		      int last_in_rxq,
		      void *cb_user_context)
{
	struct server_data *server_data =
		(struct server_data *)cb_user_context;
	int i = req->sn % QUEUE_DEPTH;

	/* process request */
	process_request(server_data, req);

	/* attach request to response */
	server_data->rsp[i].request = req;

	xio_send_response(&server_data->rsp[i]);
	server_data->nsent++;

	if (test_disconnect) {
		if (server_data->nsent == DISCONNECT_NR) {
			xio_disconnect(server_data->connection);
			return 0;
		}
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops  server_ops = {
	.on_session_event		=  on_session_event,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  on_request,
	.on_msg_error			=  NULL
};

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct xio_server	*server;	/* server portal */
	struct server_data	server_data;
	char			url[256];
	int			i;

	if (argc < 3) {
		printf("Usage: %s <host> <port> <transport:optional>\
				<finite run:optional>\n", argv[0]);
		exit(1);
	}

	/* initialize library */
	xio_init();

		/* create "hello world" message */
	memset(&server_data, 0, sizeof(server_data));
	for (i = 0; i < QUEUE_DEPTH; i++) {
		server_data.rsp[i].out.header.iov_base =
			strdup("hello world header response");
		server_data.rsp[i].out.header.iov_len =
			strlen((const char *)
			       server_data.rsp[i].out.header.iov_base) + 1;
	}

	/* create thread context for the client */
	server_data.ctx	= xio_context_create(NULL, 0, -1);


	/* create url to connect to */
	if (argc > 3)
		sprintf(url, "%s://%s:%s", argv[3], argv[1], argv[2]);
	else
		sprintf(url, "rdma://%s:%s", argv[1], argv[2]);

	if (argc > 4)
		test_disconnect = atoi(argv[4]);
	else
		test_disconnect = 0;

	/* bind a listener server to a portal/url */
	server = xio_bind(server_data.ctx, &server_ops,
			  url, NULL, 0, &server_data);
	if (server) {
		printf("listen to %s\n", url);
		xio_context_run_loop(server_data.ctx, XIO_INFINITE);

		/* normal exit phase */
		fprintf(stdout, "exit signaled\n");

		/* free the server */
		xio_unbind(server);
	}

	/* free the message */
	for (i = 0; i < QUEUE_DEPTH; i++)
		free(server_data.rsp[i].out.header.iov_base);

	/* free the context */
	xio_context_destroy(server_data.ctx);

	xio_shutdown();

	return 0;
}


