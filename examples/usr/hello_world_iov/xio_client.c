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

#include "libxio.h"

#define QUEUE_DEPTH		30
#define PRINT_COUNTER		10000
#define DISCONNECT_NR		(2*PRINT_COUNTER)
#define	MSG_DATA_LEN		1024
#define	MAX_NENTS		(XIO_MAX_IOV - 1)


int test_disconnect;

/* private session data */
struct session_data {
	struct xio_context	*ctx;
	struct xio_connection	*conn;
	uint64_t		cnt;
	uint64_t		nsent;
	uint64_t		nrecv;
	uint64_t		pad;
	struct xio_msg		req[QUEUE_DEPTH];
	struct xio_reg_mem	xbuf;
	struct xio_reg_mem	in_xbuf;
	uint8_t			*buf;
	uint8_t			*hdr;
	size_t			hdrlen;
	uint8_t			*idata;
	size_t			idatalen;
	uint8_t			*odata;
	size_t			odatalen;
};

/*---------------------------------------------------------------------------*/
/* msg_vec_init								     */
/*---------------------------------------------------------------------------*/
static int msg_vec_init(struct session_data *sdata,
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
		msg = &sdata->req[i];
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
static void msg_prep_for_send(struct session_data *sdata, struct xio_msg *msg)
{
	struct xio_vmsg		*pomsg = &msg->out;
	struct xio_iovec_ex	*osglist = vmsg_sglist(pomsg);
	struct xio_vmsg		*pimsg = &msg->in;
	struct xio_iovec_ex	*isglist = vmsg_sglist(pimsg);
	size_t			i;

	if (sdata->hdr == NULL) {
		sdata->hdr	= (uint8_t *)strdup("hello world request header");
		sdata->hdrlen	= strlen((char *)sdata->hdr) + 1;
	}
	if (sdata->odata == NULL) {
		uint8_t *data;
		xio_mem_alloc(MSG_DATA_LEN, &sdata->xbuf);
		data = (uint8_t *)sdata->xbuf.addr;
		memset(data, 0, MSG_DATA_LEN);

		sprintf((char *)data, "hello world request data");

		/* still send MSG_DATA_LEN bytes */
		sdata->odata	= data;
		sdata->odatalen	= MSG_DATA_LEN;
	}
	if (sdata->idata == NULL) {
		uint8_t *data;
		xio_mem_alloc(MSG_DATA_LEN, &sdata->in_xbuf);
		data = (uint8_t *)sdata->in_xbuf.addr;

		memset(data, 0, MSG_DATA_LEN);

		/* still send MSG_DATA_LEN bytes */
		sdata->idata	= data;
		sdata->idatalen	= MSG_DATA_LEN;
	}

	/* don't do the memcpy */
	pomsg->header.iov_len		= sdata->hdrlen;
	pomsg->header.iov_base		= sdata->hdr;

	vmsg_sglist_set_nents(pomsg, pomsg->pdata_iov.max_nents);
	for (i = 0; i < pomsg->pdata_iov.max_nents; i++) {
		osglist[i].iov_base	= sdata->odata;
		osglist[i].iov_len	= sdata->odatalen;
		osglist[i].mr		= sdata->xbuf.mr;
	}

	/* prepare for response */
	vmsg_sglist_set_nents(pimsg, pimsg->pdata_iov.max_nents);
	for (i = 0; i < pimsg->pdata_iov.max_nents; i++) {
		isglist[i].iov_base	= sdata->idata;
		isglist[i].iov_len	= sdata->idatalen;
		isglist[i].mr		= sdata->in_xbuf.mr;
	}
}

/*---------------------------------------------------------------------------*/
/* msg_resources_destroy						     */
/*---------------------------------------------------------------------------*/
static void msg_resources_destroy(struct session_data *sdata)
{
	if (sdata->xbuf.addr) {
		xio_mem_free(&sdata->xbuf);
		sdata->xbuf.addr = NULL;
		sdata->odata = NULL;
	}
	if (sdata->in_xbuf.addr) {
		xio_mem_free(&sdata->in_xbuf);
		sdata->in_xbuf.addr = NULL;
		sdata->idata = NULL;
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
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct session_data *session_data,
			    struct xio_msg *rsp)
{
	struct xio_iovec_ex	*sglist = vmsg_sglist(&rsp->request->in);
	char			*str;
	int			nents = vmsg_sglist_nents(&rsp->request->in);
	int			len, i;
	char			tmp;


	/* note all data is packed together so in order to print each
	 * part on its own NULL character is temporarily stuffed
	 * before the print and the original character is restored after
	 * the printf
	 */
	if (++session_data->cnt == PRINT_COUNTER) {
		str = (char *)rsp->request->in.header.iov_base;
		len = rsp->request->in.header.iov_len;
		if (str) {
			if (((unsigned) len) > 64)
				len = 64;
			tmp = str[len];
			str[len] = '\0';
			printf("message header : [%lu] - %s\n",
			       (rsp->request->sn + 1), str);
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
				       (rsp->request->sn + 1), i, sglist[i].iov_len, str);
				str[len] = tmp;
			}
		}
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
	struct xio_vmsg		*pmsg = &rsp->in;
	struct session_data	*session_data = (struct session_data *)
						cb_user_context;
	int i = rsp->request->sn % QUEUE_DEPTH;

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

	/* clean the "in" size of the message */
	pmsg->header.iov_len		= 0;
	pmsg->header.iov_base		= NULL;
//	vmsg_sglist_set_nents(pmsg, 0);

	msg_prep_for_send(session_data, &session_data->req[i]);

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
	struct xio_session		*session;
	char				url[256];
	struct session_data		session_data;
	int				i = 0;
	struct xio_session_params	params;
	struct xio_connection_params	cparams;
	int				xopt = MAX_NENTS;

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

	/* set accelio max message vector used */
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_IN_IOVLEN,
		    &xopt, sizeof(int));
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_OUT_IOVLEN,
		    &xopt, sizeof(int));

	msg_vec_init(&session_data, xopt, xopt);

	/* create thread context for the client */
	session_data.ctx = xio_context_create(NULL, 0, -1);


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
	for (i = 0; i < QUEUE_DEPTH; i++)
		msg_prep_for_send(&session_data, &session_data.req[i]);

	/* send first message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		xio_send_request(session_data.conn, &session_data.req[i]);
		session_data.nsent++;
	}

	/* event dispatcher is now running */
	xio_context_run_loop(session_data.ctx, XIO_INFINITE);

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	/* free the context */
	xio_context_destroy(session_data.ctx);

	/* free the message */
	msg_resources_destroy(&session_data);

	xio_shutdown();

	printf("good bye\n");
	return 0;
}

