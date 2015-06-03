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
 *
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

#define QUEUE_DEPTH		30
#define PRINT_COUNTER		10000
#define DISCONNECT_NR		(2*PRINT_COUNTER)
#define	MSG_DATA_LEN		1024
#define	MAX_NENTS		(XIO_MAX_IOV - 1)
#define	GATHER			1

int test_disconnect;
int gather = GATHER;

/* server private data */
struct server_data {
	struct xio_context	*ctx;
	struct xio_connection	*connection;
	uint64_t		nsent;
	uint64_t		cnt;
	struct xio_msg		rsp[QUEUE_DEPTH];	/* global message */
	struct xio_reg_mem	xbuf;
	struct xio_reg_mem	in_xbuf;
	uint8_t			*buf;
	uint8_t			*hdr;
	size_t			hdrlen;
	uint8_t			*data;
	size_t			datalen;
};

/*---------------------------------------------------------------------------*/
/* msg_vec_init								     */
/*---------------------------------------------------------------------------*/
static int msg_vec_init(struct server_data *sdata,
			int imax_nents, int omax_nents)
{
	int			i, len;
	struct	xio_msg		*msg;
	uint8_t			*buf;


	len = QUEUE_DEPTH*(imax_nents + omax_nents);

	buf = (uint8_t *)calloc(len, sizeof(struct xio_iovec_ex));
	if (!buf)
		return -1;

	/* save the memory */
	sdata->buf	= buf;

	for (i = 0; i < QUEUE_DEPTH; i++) {
		msg = &sdata->rsp[i];
		if (imax_nents) {
			msg->in.sgl_type		= XIO_SGL_TYPE_IOV_PTR;
			msg->in.pdata_iov.max_nents	= imax_nents;
			msg->in.pdata_iov.sglist	=
						(struct xio_iovec_ex *)buf;

			buf = buf + imax_nents*sizeof(struct xio_iovec_ex);
		}
		if (omax_nents) {
			msg->out.sgl_type		= XIO_SGL_TYPE_IOV_PTR;
			msg->out.pdata_iov.max_nents	= omax_nents;
			msg->out.pdata_iov.sglist	=
						(struct xio_iovec_ex *)buf;

			buf = buf + omax_nents*sizeof(struct xio_iovec_ex);
		}
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* msg_prep_for_send							     */
/*---------------------------------------------------------------------------*/
static void msg_prep_for_send(struct server_data *sdata, struct xio_msg *msg)
{
	struct xio_vmsg		*pmsg = &msg->out;
	struct xio_iovec_ex	*sglist = vmsg_sglist(pmsg);
	size_t			i;

	if (sdata->hdr == NULL) {
		sdata->hdr	= (uint8_t *)strdup("hello world response header");
		sdata->hdrlen	= strlen((char *)sdata->hdr) + 1;
	}
	if (sdata->data == NULL) {
		uint8_t *data;
		xio_mem_alloc(MSG_DATA_LEN, &sdata->xbuf);
		data = (uint8_t *)sdata->xbuf.addr;
		memset(data, 0, MSG_DATA_LEN);

		sprintf((char *)data, "hello world response data");

		/* still send MSG_DATA_LEN bytes */
		sdata->data	= data;
		sdata->datalen	= MSG_DATA_LEN;
	}

	/* don't do the memcpy */
	pmsg->header.iov_len		= sdata->hdrlen;
	pmsg->header.iov_base		= sdata->hdr;

	vmsg_sglist_set_nents(pmsg, pmsg->pdata_iov.max_nents);
	for (i = 0; i < pmsg->pdata_iov.max_nents; i++) {
		sglist[i].iov_base	= sdata->data;
		sglist[i].iov_len	= sdata->datalen;
		sglist[i].mr		= sdata->xbuf.mr;
	}
}

/*---------------------------------------------------------------------------*/
/* msg_resources_destroy						     */
/*---------------------------------------------------------------------------*/
static void msg_resources_destroy(struct server_data *sdata)
{
	if (sdata->xbuf.addr) {
		xio_mem_free(&sdata->xbuf);
		sdata->xbuf.addr = NULL;
		sdata->data = NULL;
	}

	if (sdata->in_xbuf.addr) {
		xio_mem_free(&sdata->in_xbuf);
		sdata->in_xbuf.addr = NULL;
	}

	if (sdata->buf) {
		free(sdata->buf);
		sdata->buf = NULL;
	}
	if (sdata->hdr) {
		free(sdata->hdr);
		sdata->hdr = NULL;
	}

}


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
				printf("message data: [%lu][%d][%zd] - %s\n",
				       (req->sn + 1), i, sglist[i].iov_len, str);
				str[len] = tmp;
			}
		}
		server_data->cnt = 0;
	}
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct server_data *server_data = (struct server_data *)cb_user_context;

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
	struct server_data *server_data = (struct server_data *)cb_user_context;

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
	struct server_data *server_data = (struct server_data *)cb_user_context;
	int i = req->sn % QUEUE_DEPTH;

	/* process request */
	process_request(server_data, req);

	/* prep in for send */
	req->in.header.iov_base	  = NULL;
	req->in.header.iov_len	  = 0;
	vmsg_sglist_set_nents(&req->in, 0);

	msg_prep_for_send(server_data, &server_data->rsp[i]);

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
/* assign_data_in_buf							     */
/*---------------------------------------------------------------------------*/
static int assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	struct server_data	*sdata =
					(struct server_data *)cb_user_context;
	struct xio_iovec_ex	*sglist = vmsg_sglist(&msg->in);
	int			nents = vmsg_sglist_nents(&msg->in);
	int			i;

	/* gather into one buffer */
	if (gather) {
		if (sdata->in_xbuf.addr == NULL)
			xio_mem_alloc(MAX_NENTS*MSG_DATA_LEN,
				      &sdata->in_xbuf);

		vmsg_sglist_set_nents(&msg->in, 1);
		sglist[0].iov_base	= sdata->in_xbuf.addr;
		sglist[0].iov_len	= MAX_NENTS*MSG_DATA_LEN;
		sglist[0].mr		= sdata->in_xbuf.mr;

	} else {
		if (sdata->in_xbuf.addr == NULL)
			xio_mem_alloc(MSG_DATA_LEN, &sdata->in_xbuf);

		for (i = 0; i < nents; i++) {
			sglist[i].iov_base	= sdata->in_xbuf.addr;
			sglist[i].mr		= sdata->in_xbuf.mr;
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_msg_error								     */
/*---------------------------------------------------------------------------*/
static int on_msg_error(struct xio_session *session,
			enum xio_status error,
			enum xio_msg_direction direction,
			struct xio_msg  *msg,
			void *cb_user_context)
{
	struct server_data *sdata = (struct server_data *)cb_user_context;

	if (direction == XIO_MSG_DIRECTION_OUT) {
		printf("**** [%p] message %lu failed. reason: %s\n",
		       session, msg->sn, xio_strerror(error));
	} else {
		xio_release_response(msg);
		printf("**** [%p] message %lu failed. reason: %s\n",
		       session, msg->request->sn, xio_strerror(error));
	}

	switch (error) {
	case XIO_E_MSG_FLUSHED:
		break;
	default:
		xio_disconnect(sdata->connection);
		break;
	};

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
	.on_msg_error			=  on_msg_error,
	.assign_data_in_buf		=  assign_data_in_buf
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
	int			xopt = MAX_NENTS;

	if (argc < 3) {
		printf("Usage: %s <host> <port> <transport:optional>\
				<finite run:optional>\n", argv[0]);
		exit(1);
	}
	memset(&server_data, 0, sizeof(server_data));

	/* initialize library */
	xio_init();

	/* set accelio max message vector used */
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_IN_IOVLEN,
		    &xopt, sizeof(int));
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_OUT_IOVLEN,
		    &xopt, sizeof(int));

	msg_vec_init(&server_data, xopt, xopt);

	/* create thread context for the client */
	server_data.ctx	= xio_context_create(NULL, 0, -1);

	/* create "hello world" message */
	for (i = 0; i < QUEUE_DEPTH; i++)
		msg_prep_for_send(&server_data, &server_data.rsp[i]);

	/* create url to connect to */
	if (argc > 3)
		sprintf(url, "%s://%s:%s", argv[3], argv[1], argv[2]);
	else
		sprintf(url, "rdma://%s:%s", argv[1], argv[2]);

	if (argc > 4)
		test_disconnect = atoi(argv[4]);
	else
		test_disconnect = 0;

	gather = GATHER;

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

	/* free the context */
	xio_context_destroy(server_data.ctx);

	/* free the message */
	msg_resources_destroy(&server_data);

	xio_shutdown();

	return 0;
}


