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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif
#include <linux/completion.h>

#include "libxio.h"

MODULE_AUTHOR("Eyal Solomon, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO hello client " \
		   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

static char *xio_argv[] = {"xio_client_example", 0, 0, 0, "rdma"};

module_param_named(ip, xio_argv[1], charp, 0);
MODULE_PARM_DESC(ip, "IP of NIC to send request to");

module_param_named(port, xio_argv[2], charp, 0);
MODULE_PARM_DESC(port, "Port to send request to");

module_param_named(data_len, xio_argv[3], charp, 0);
MODULE_PARM_DESC(data_len, "Msg data len of the request default 22");

module_param_named(transport, xio_argv[4], charp, 0);
MODULE_PARM_DESC(transport, "Transport protocol to send request with");

static struct task_struct *xio_main_th;
static struct completion cleanup_complete;

#define QUEUE_DEPTH		512
#define HW_PRINT_COUNTER	4000000

/* private session data */
struct session_data {
	struct xio_context	*ctx;
	void			*loop;
	struct xio_session	*session;
	struct xio_connection	*connection;
	struct xio_msg		req[QUEUE_DEPTH];
};

static struct session_data *g_session_data;
atomic_t module_state;

#define SG_TBL_LEN 64
/*---------------------------------------------------------------------------*/
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct xio_msg *rsp)
{
	static uint64_t cnt;
	struct scatterlist      *sgl = rsp->in.data_tbl.sgl;
	struct xio_vmsg *omsg;
	char *str;
	int len, i;
	char tmp;


	if (++cnt == HW_PRINT_COUNTER) {
		pr_info("message: [%llu] - %s\n", (rsp->request->sn + 1),
			(char *)rsp->in.header.iov_base);
		omsg = &rsp->in;
		for (i = 0; i < vmsg_sglist_nents(omsg); i++) {
			str = (char *)sg_virt(sgl);
			len = sgl->length;
			if (str) {
				if (((unsigned)len) > 64)
					len = 64;
				tmp = str[len];
				str[len] = '\0';
				pr_info("message data: [%llu][%d][%d] - %s\n",
					 (rsp->request->sn + 1), i, len, str);
				str[len] = tmp;
			}
			sgl = sg_next(sgl);
		}
		cnt = 0;
	}

	/* Client didn't allocate this memory */
	rsp->in.header.iov_base = NULL;
	rsp->in.header.iov_len  = 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct session_data *session_data = cb_user_context;

	pr_info("session event: %s. reason: %s\n",
		xio_session_event_str(event_data->event),
		xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		session_data->connection = NULL;
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		session_data->session = NULL;
		xio_session_destroy(session);
		xio_context_stop_loop(session_data->ctx); /* exit */
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
	struct session_data *session_data = cb_user_context;
	struct xio_msg	    *req = rsp;

	/* process the incoming message */
	process_response(rsp);

	/* acknowledge xio that response is no longer needed */
	xio_release_response(rsp);

	/* resend the message */
	xio_send_request(session_data->connection, req);

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

static void xio_module_down(void *data)
{
	struct session_data *session_data;
	struct xio_session *session;
	struct xio_connection *connection;

	session_data = (struct session_data *)data;

	if (!session_data->session)
		goto stop_loop_now;

	if (!session_data->connection)
		goto destroy_session;

	connection = session_data->connection;
	session_data->connection = NULL;
	xio_disconnect(connection);

	return;

destroy_session:
	/* in multi thread version on need to user reference count */
	session = session_data->session;
	session_data->session = NULL;
	xio_session_destroy(session);

stop_loop_now:
	/* No session -> no XIO_SESSION_TEARDOWN_EVENT */
	xio_context_stop_loop(session_data->ctx); /* exit */
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
static int xio_client_main(void *data)
{
	char **argv = (char **)data;

	struct xio_session	*session;
	struct xio_session_params params;
	struct xio_context_params ctx_params;
	struct xio_connection_params cparams;
	char			url[256];
	struct xio_context	*ctx;
	struct session_data	*session_data;
	int			i = 0;
	unsigned long		data_len = 0, size = 0;
	char			*buf = NULL;
	const char		*hdr = "hello world iovec request";
	const char		*msg = "hello world iovec request";

	atomic_add(2, &module_state);

	session_data = vzalloc(sizeof(*session_data));
	if (!session_data) {
		/*pr_err("session_data alloc failed\n");*/
		return 0;
	}

	/* create thread context for the client */
	memset(&ctx_params, 0, sizeof(ctx_params));
	ctx_params.flags = XIO_LOOP_GIVEN_THREAD;
	ctx_params.worker = current;

	ctx = xio_context_create(&ctx_params, 0, -1);
	if (!ctx) {
		vfree(session_data);
		pr_err("context open filed\n");
		return 0;
	}

	session_data->ctx = ctx;

	/* create url to connect to */
	sprintf(url, "%s://%s:%s", argv[4], argv[1], argv[2]);

	memset(&params, 0, sizeof(params));
	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.user_context	= session_data;
	params.uri		= url;

	session = xio_session_create(&params);

	memset(&cparams, 0, sizeof(cparams));
	cparams.session			= session;
	cparams.ctx			= ctx;
	cparams.conn_user_context	= session_data;

	/* connect the session  */
	session_data->session = session;
	session_data->connection = xio_connect(&cparams);

	/* create "hello world" message */

	if (argv[3] != NULL && kstrtoul(argv[3], 0, &data_len)) { /* check, convert and assign data_len */
		data_len = strlen(msg);
	}
	for (i = 0; i < QUEUE_DEPTH; i++) {
		struct xio_vmsg *omsg, *imsg;

		omsg = &session_data->req[i].out;
		xio_reinit_msg(&session_data->req[i]);

		/* header */
		session_data->req[i].out.header.iov_base = kstrdup(hdr,
								   GFP_KERNEL);
		session_data->req[i].out.header.iov_len = strlen(hdr) + 1;
		/* iovec[0]*/
		sg_alloc_table(&omsg->data_tbl, SG_TBL_LEN, GFP_KERNEL);

		/* currently only one entry */
		xio_init_vmsg(omsg, 1);     /* one entry (max_nents) */
		if (data_len < strlen(msg)) {
			buf = kstrndup(msg, data_len, GFP_KERNEL);
			size = strlen((const char *) buf) + 1;
		} else {
			pr_info("allocating xio memory...\n");
			buf = kmalloc(data_len, GFP_KERNEL);
			memcpy(buf, "hello world iovec request", 26);
			size  = data_len;
		}
		sg_init_one(omsg->data_tbl.sgl, buf, size);
		/* orig_nents is 1 */
		vmsg_sglist_set_nents(omsg,1);

		imsg = &session_data->req[i].in;
		xio_init_vmsg(imsg, 4);  /* one entry (max_nents) */
	}

	/* send first message */
	for (i = 0; i < QUEUE_DEPTH; i++)
		xio_send_request(session_data->connection,
				 &session_data->req[i]);

	g_session_data = session_data;

	/* the default xio supplied main loop */
	if (atomic_add_unless(&module_state, 4, 0x83))
		xio_context_run_loop(ctx);
	atomic_sub(4, &module_state);

	/* normal exit phase */
	pr_info("exit signaled\n");

	/* free the message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		kfree(session_data->req[i].out.header.iov_base);
		/* Currently need to release only one entry */
		kfree(sg_virt(session_data->req[i].out.data_tbl.sgl));
		sg_free_table(&session_data->req[i].out.data_tbl);
		xio_fini_vmsg(&session_data->req[i].out);
		xio_fini_vmsg(&session_data->req[i].in);
	}

	/* free the context */
	xio_context_destroy(ctx);

	vfree(session_data);

	pr_info("good bye\n");

	complete_and_exit(&cleanup_complete, 0);

	return 0;
}

static int __init xio_hello_init_module(void)
{
	int iov_len = SG_TBL_LEN;

	if (!(xio_argv[1] && xio_argv[2])) {
		pr_err("NO IP or port were given\n");
		return -EINVAL;
	}

	atomic_set(&module_state, 1);
	init_completion(&cleanup_complete);

	/* set accelio max message vector used */
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_IN_IOVLEN,
		    &iov_len, sizeof(int));
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_OUT_IOVLEN,
		    &iov_len, sizeof(int));

	xio_main_th = kthread_run(xio_client_main, xio_argv,
				  "xio-hello-client");
	if (IS_ERR(xio_main_th)) {
		complete(&cleanup_complete);
		return PTR_ERR(xio_main_th);
	}

	return 0;
}

static void __exit xio_hello_cleanup_module(void)
{
	struct xio_ev_data down_event;
	int state;

	state = atomic_add_return(0x80, &module_state);

	if (state & 4) {
		/* thread is running, loop is still running */
		memset(&down_event, 0, sizeof(down_event));
		down_event.handler = xio_module_down;
		down_event.data = (void *)g_session_data;
		xio_context_add_event(g_session_data->ctx, &down_event);
	}

	/* wait fot thread to terminate */
	if (state & 2)
		wait_for_completion(&cleanup_complete);
}

module_init(xio_hello_init_module);
module_exit(xio_hello_cleanup_module);
