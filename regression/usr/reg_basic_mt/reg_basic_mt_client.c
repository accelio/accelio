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
#include "obj_pool.h"
#include "reg_utils.h"

#define PRINT_COUNTER		400000
#define TEST_DISCONNECT		1
#define DISCONNECT_NR		10000

struct thread_data {
	int			cid;
	int			affinity;
	uint64_t		cnt;
	uint64_t		nsent;
	uint64_t		nrecv;
	struct session_data	*session_data;
	struct xio_connection	*conn;
	struct xio_context	*ctx;
	struct obj_pool		*req_pool;
	struct obj_pool		*out_iobuf_pool;
	struct obj_pool		*in_iobuf_pool;
	pthread_t		thread_id;
};


/* private session data */
struct session_data {
	struct xio_session	*session;
	int			threads_num;
	int			queue_depth;
	int			client_dlen;
	int			server_dlen;
	struct thread_data	*tdata;
};

static void out_iobuf_obj_init(void *user_context, void *obj)
{
	struct xio_buf		**iobuf	= obj;
	struct thread_data	*tdata	= user_context;

	*iobuf = xio_alloc(tdata->session_data->client_dlen);
}

static void in_iobuf_obj_init(void *user_context, void *obj)
{
	struct xio_buf		**iobuf	= obj;
	struct thread_data	*tdata	= user_context;

	*iobuf = xio_alloc(tdata->session_data->server_dlen);
}

static void iobuf_obj_free(void *user_context, void *obj)
{
	struct xio_buf		**iobuf	= obj;

	xio_free(iobuf);
}

static void msg_obj_init(void *user_context, void *obj)
{
	struct xio_msg		*req	= obj;
	struct xio_buf		**out_iobuf;
	struct xio_buf		**in_iobuf;
	struct thread_data	*tdata	= user_context;

	if (tdata->session_data->client_dlen) {
		out_iobuf = obj_pool_get(tdata->out_iobuf_pool);
		req->out.data_iov[0].iov_base	  = (*out_iobuf)->addr;
		req->out.data_iov[0].iov_len	  = (*out_iobuf)->length;
		req->out.data_iov[0].mr		  = (*out_iobuf)->mr;
		req->out.data_iov[0].user_context = out_iobuf;
		req->out.data_iovlen		  = 1;
	} else {
		req->out.data_iov[0].iov_base	  = NULL;
		req->out.data_iov[0].iov_len	  = 0;
		req->out.data_iov[0].mr		  = NULL;
		req->out.data_iov[0].user_context = NULL;
		req->out.data_iovlen		  = 0;
	}

	if (tdata->session_data->server_dlen > 8000) {
		in_iobuf = obj_pool_get(tdata->in_iobuf_pool);

		req->in.data_iov[0].iov_base	  = (*in_iobuf)->addr;
		req->in.data_iov[0].iov_len	  = (*in_iobuf)->length;
		req->in.data_iov[0].mr		  = (*in_iobuf)->mr;
		req->in.data_iov[0].user_context  = in_iobuf;
		req->in.data_iovlen		  = 1;
	} else {
		req->in.data_iov[0].iov_base	  = NULL;
		req->in.data_iov[0].iov_len	  = 0;
		req->in.data_iov[0].mr		  = NULL;
		req->in.data_iov[0].user_context  = NULL;
		req->in.data_iovlen		  = 0;
	}

	req->in.header.iov_len		  = 0;
	req->out.header.iov_len		  = 0;
}


/*---------------------------------------------------------------------------*/
/* worker_thread							     */
/*---------------------------------------------------------------------------*/
static void *worker_thread(void *data)
{
	struct thread_data	*tdata = data;
	struct xio_msg		*req;
	cpu_set_t		cpuset;
	int			i;

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, 0);

	/* connect the session  */
	tdata->conn = xio_connect(tdata->session_data->session, tdata->ctx,
				  tdata->cid, NULL, tdata);

	if (tdata->session_data->client_dlen)
		tdata->out_iobuf_pool = obj_pool_init(
				tdata->session_data->queue_depth,
				sizeof(struct xio_buf *),
				tdata, out_iobuf_obj_init);

	if (tdata->session_data->server_dlen)
		tdata->in_iobuf_pool = obj_pool_init(
				tdata->session_data->queue_depth,
				sizeof(struct xio_buf *),
				tdata, in_iobuf_obj_init);

	tdata->req_pool = obj_pool_init(tdata->session_data->queue_depth,
					sizeof(struct xio_msg),
					tdata, msg_obj_init);

	/* send first messages */
	for (i = 0; i < tdata->session_data->queue_depth; i++) {
		req = obj_pool_get(tdata->req_pool);
		xio_send_request(tdata->conn, req);
		tdata->nsent++;
	}
	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

	/* normal exit phase */
	DEBUG("exit signaled\n");

	obj_pool_free(tdata->req_pool, NULL, NULL);
	if (tdata->session_data->client_dlen)
		obj_pool_free(tdata->out_iobuf_pool, NULL, iobuf_obj_free);
	if (tdata->session_data->server_dlen)
		obj_pool_free(tdata->in_iobuf_pool, NULL, iobuf_obj_free);

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
	struct session_data *session_data = cb_user_context;
	int			i;

	DEBUG("client session event: %s. session:%p, connection:%p, " \
	      "reason: %s\n",
	      xio_session_event_str(event_data->event),
	      session, event_data->conn,
	      xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		for (i = 0; i < session_data->threads_num; i++)
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
	struct xio_buf		**in_iobuf;
	tdata->nrecv++;

	/* acknowlege xio that response is no longer needed */
	xio_release_response(rsp);

#if  TEST_DISCONNECT
	if (tdata->nrecv == DISCONNECT_NR) {
		DEBUG("client disconnect. session:%p, connection:%p\n",
		      session, tdata->conn);
		xio_disconnect(tdata->conn);
		return 0;
	}

	if (tdata->nsent == DISCONNECT_NR) {
		struct xio_buf	**out_iobuf = rsp->out.data_iov[0].user_context;
		struct xio_buf	**in_iobuf = rsp->in.data_iov[0].user_context;
		rsp->in.data_iov[0].user_context = NULL;
		rsp->out.data_iov[0].user_context = NULL;
		obj_pool_put(tdata->req_pool, rsp);
		if (out_iobuf)
			obj_pool_put(tdata->out_iobuf_pool, out_iobuf);
		if (in_iobuf)
			obj_pool_put(tdata->in_iobuf_pool, in_iobuf);

		return 0;
	}
#endif

	/* resend the message */
	if (tdata->session_data->server_dlen &&
	    rsp->in.data_iov[0].user_context) {
		in_iobuf = rsp->in.data_iov[0].user_context;

		rsp->in.data_iov[0].iov_base	= (*in_iobuf)->addr;
		rsp->in.data_iov[0].iov_len	= (*in_iobuf)->length;
		rsp->in.data_iov[0].mr		= (*in_iobuf)->mr;
		rsp->in.data_iovlen		= 1;
	} else {
		rsp->in.data_iov[0].iov_base	= NULL;
		rsp->in.data_iov[0].iov_len	= 0;
		rsp->in.data_iov[0].mr		= NULL;
		rsp->in.data_iovlen		= 0;
	}

	rsp->in.header.iov_len			= 0;

	xio_send_request(tdata->conn, rsp);
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
int client_main(int argc, char *argv[])
{
	int			i;
	char			url[256];
	struct session_data	session_data;
	uint16_t		threads_num	= atoi(argv[3]);
	int			queue_depth     = atoi(argv[4]);
	int			client_dlen	= atoi(argv[5]);
	int			server_dlen	= atoi(argv[6]);

	/* client session attributes */
	struct xio_session_attr attr = {
		&ses_ops, /* callbacks structure */
		NULL,	  /* no need to pass the server private data */
		0
	};

	memset(&session_data, 0, sizeof(session_data));

	session_data.tdata = calloc(threads_num, sizeof(*session_data.tdata));
	if (!session_data.tdata)
		return -1;

	session_data.threads_num = threads_num;
	session_data.client_dlen = client_dlen;
	session_data.server_dlen = server_dlen;
	session_data.queue_depth = queue_depth;

	xio_init();

	/* create url to connect to */
	sprintf(url, "rdma://%s:%s", argv[1], argv[2]);
	session_data.session = xio_session_create(XIO_SESSION_CLIENT,
						&attr, url,
						0, 0, &session_data);

	if (session_data.session == NULL)
		goto cleanup;

	/* spawn threads to handle connection */
	for (i = 0; i < session_data.threads_num; i++) {
		session_data.tdata[i].session_data	= &session_data;
		session_data.tdata[i].affinity		= i;
		session_data.tdata[i].cid		= i;
		session_data.tdata[i].cnt		= 0;

		pthread_create(&session_data.tdata[i].thread_id, NULL,
			       worker_thread, &session_data.tdata[i]);
	}

	/* join the threads */
	for (i = 0; i < session_data.threads_num; i++)
		pthread_join(session_data.tdata[i].thread_id, NULL);

	/* close the session */
	xio_session_destroy(session_data.session);

	free(session_data.tdata);
cleanup:
	xio_shutdown();

	DEBUG("client: goodbye and good riddance\n");

	return 0;
}

