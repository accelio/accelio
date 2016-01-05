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
#define DISCONNECT_NR		(2 * PRINT_COUNTER)

int test_disconnect;
int queue_depth;

/* private session data */
struct session_data {
	struct xio_context	*ctx;
	struct xio_connection	*conn;
	uint64_t		cnt;
	uint64_t		nsent;
	uint64_t		nrecv;
	uint64_t		pad;
	struct xio_msg		req_ring[QUEUE_DEPTH];
};

/*---------------------------------------------------------------------------*/
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct session_data *session_data,
			     struct xio_msg *rsp)
{
	if (++session_data->cnt == PRINT_COUNTER) {
		struct xio_iovec_ex	*isglist = vmsg_sglist(&rsp->in);
		int			inents = vmsg_sglist_nents(&rsp->in);

		printf("message: [%llu] - %s\n",
		       (unsigned long long)(rsp->request->sn + 1),
		       (char *)rsp->in.header.iov_base);
		printf("message: [%llu] - %s\n",
		       (unsigned long long)(rsp->request->sn + 1),
		       (char *)(inents > 0 ? isglist[0].iov_base : NULL));
		session_data->cnt = 0;
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

	printf("session event: %s. reason: %s\n",
	       xio_session_event_str(event_data->event),
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		xio_context_stop_loop(session_data->ctx);  /* exit */
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
	struct session_data *session_data = (struct session_data *)
						cb_user_context;
	struct xio_msg	    *req = rsp;

	session_data->nrecv++;
	/* process the incoming message */
	process_response(session_data, rsp);

	/* acknowledge xio that response is no longer needed */
	xio_release_response(rsp);

	if (test_disconnect) {
		if (session_data->nrecv == DISCONNECT_NR) {
			xio_disconnect(session_data->conn);
			return 0;
		}
		if (session_data->nsent == DISCONNECT_NR)
			return 0;
	}
	req->in.header.iov_base	  = NULL;
	req->in.header.iov_len	  = 0;
	vmsg_sglist_set_nents(&req->in, 0);

	/* resend the message */
	xio_send_request(session_data->conn, req);
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
	struct xio_session		*session;
	char				url[256];
	struct session_data		session_data;
	int				i = 0, opt, optlen;
	struct xio_session_params	params;
	struct xio_connection_params	cparams;
	struct xio_msg			*req;
	struct xio_reg_mem      	xbuf;
        int 				msg_size = 0;
        int 				max_msg_size = 0;
        uint8_t 			*data = NULL;

	if (argc < 3) {
		printf("Usage: %s <host> <port> <transport:optional>" \
		       "<finite run:optional> <msg size:optional>\n", argv[0]);
		exit(1);
	}
	if (argc > 4)
		test_disconnect = atoi(argv[4]);
	else
		test_disconnect = 0;
	if (argc > 5)
		msg_size = atoi(argv[5]);

	memset(&session_data, 0, sizeof(session_data));
	memset(&params, 0, sizeof(params));
	memset(&cparams, 0, sizeof(cparams));

	/* initialize library */
	xio_init();

	/* get minimal queue depth */
	xio_get_opt(NULL, XIO_OPTLEVEL_ACCELIO,
		    XIO_OPTNAME_SND_QUEUE_DEPTH_MSGS,
		    &opt, &optlen);
	queue_depth = QUEUE_DEPTH > opt ? opt : QUEUE_DEPTH;

        /* get max msg size */
	/* this size distinguishes between big and small msgs, where for small msgs rdma_post_send/rdma_post_recv
	are called as opposed to to big msgs where rdma_write/rdma_read are called */
        xio_get_opt(NULL, XIO_OPTLEVEL_ACCELIO,
                    XIO_OPTNAME_MAX_INLINE_XIO_DATA,
                    &opt, &optlen);
        max_msg_size = opt;

	/* create thread context for the client */
	session_data.ctx = xio_context_create(NULL, 0, -1);

	/* create url to connect to */
	if (argc > 3)
		sprintf(url, "%s://%s:%s", argv[3], argv[1], argv[2]);
	else
		sprintf(url, "rdma://%s:%s", argv[1], argv[2]);

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
	req = session_data.req_ring;
	for (i = 0; i < queue_depth; i++) {
		/* header */
		req->out.header.iov_base =
			strdup("hello world header request");
		req->out.header.iov_len =
			strlen((const char *)
				req->out.header.iov_base) + 1;
		/* iovec[0]*/
		req->in.sgl_type		  = XIO_SGL_TYPE_IOV;
		req->in.data_iov.max_nents = XIO_IOVLEN;

		req->out.sgl_type	   = XIO_SGL_TYPE_IOV;
		req->out.data_iov.max_nents = XIO_IOVLEN;

		/* data */
		if (msg_size < max_msg_size) { /* small msgs */
			req->out.data_iov.sglist[0].iov_base =
				strdup("hello world data request");
		} else { /* big msgs */
			if (data == NULL) {
				printf("allocating xio memory...\n");
				xio_mem_alloc(msg_size, &xbuf);
				data = (uint8_t *)xbuf.addr;
				memset(data, 0, msg_size);
				sprintf((char *)data, "hello world data request");
			}
			req->out.data_iov.sglist[0].mr = xbuf.mr;
			req->out.data_iov.sglist[0].iov_base = data;
		}

                req->out.data_iov.sglist[0].iov_len =
                        strlen((const char *)
                          req->out.data_iov.sglist[0].iov_base)
                           + 1;

		req->out.data_iov.nents = 1;

		req++;
	}
	/* send first message */
	req = session_data.req_ring;
	for (i = 0; i < queue_depth; i++) {
		xio_send_request(session_data.conn, req);
		session_data.nsent++;
		req++;
	}

	/* event dispatcher is now running */
	xio_context_run_loop(session_data.ctx, XIO_INFINITE);

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	/* free the message */
	req = session_data.req_ring;
	for (i = 0; i < queue_depth; i++) {
		free(req->out.header.iov_base);
		if (msg_size < max_msg_size) free(req->out.data_iov.sglist[0].iov_base);
		req++;
	}
	if (xbuf.addr) {
		printf("freeing xio memory...\n");
                xio_mem_free(&xbuf);
                xbuf.addr = NULL;
        }

	/* free the context */
	xio_context_destroy(session_data.ctx);

	xio_shutdown();

	printf("good bye\n");
	return 0;
}

