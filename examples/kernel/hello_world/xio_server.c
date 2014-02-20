/*
 * Copyright (c) 2013 Mellanox Technologies��. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies�� BSD license
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
 *      - Neither the name of the Mellanox Technologies�� nor the names of its
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
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif
#include <linux/completion.h>

#include "libxio.h"

MODULE_AUTHOR("Eyal Solomon, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO hello server "
	   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

static char *xio_argv[] = {"xio_hello_server", 0, 0};

module_param_named(ip, xio_argv[1], charp, 0);
MODULE_PARM_DESC(ip, "IP of NIC to receice request from");

module_param_named(port, xio_argv[2], charp, 0);
MODULE_PARM_DESC(port, "Port to receive request from");

static struct task_struct *xio_main_th;
static struct completion cleanup_complete;

#define QUEUE_DEPTH		512
#define PRINT_COUNTER		4000000

/* server private data */
struct server_data {
	struct xio_context	*ctx;
	struct xio_session	*session;
	uint64_t		cnt;
	struct xio_msg	rsp[QUEUE_DEPTH];	/* global message */
};

static struct server_data *g_server_data = 0;
atomic_t module_state;

/*---------------------------------------------------------------------------*/
/* process_request							     */
/*---------------------------------------------------------------------------*/
static void process_request(struct xio_msg *req)
{
	char *str, tmp;
	int len, i;

	/* note all data is packed together so in order to print each
	 * part on its own NULL character is temporarily stuffed
	 * before the print and the original character is restored after
	 * the printf
	 */
	if (++g_server_data->cnt == PRINT_COUNTER) {
		str = (char *) req->in.header.iov_base;
		len = req->in.header.iov_len;
		if (str) {
			if (((unsigned) len) > 64)
				len = 64;
			tmp = str[len];
			str[len] = '\0';
			printk("message header : [%llu] - %s\n",
			       (req->sn + 1), str);
			str[len] = tmp;

		}
		for (i = 0; i < req->in.data_iovlen; i++) {
			str = (char *) req->in.data_iov[i].iov_base;
			len = req->in.data_iov[i].iov_len;
			if (str) {
				if (((unsigned) len) > 64)
					len = 64;
				tmp = str[len];
				str[len] = '\0';
				printk("message data: [%llu][%d][%d] - %s\n",
				       (req->sn + 1), i, len, str);
				str[len] = tmp;
			}

		}
		g_server_data->cnt = 0;
	}
	req->in.header.iov_base	  = NULL;
	req->in.header.iov_len	  = 0;
	req->in.data_iovlen	  = 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
		struct xio_session_event_data *event_data,
		void *cb_user_context)
{
	struct server_data *server_data = cb_user_context;

	printk("session event: %s. reason: %s\n",
	       xio_session_event_str(event_data->event),
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		server_data->session = NULL;
		xio_session_destroy(session);
		if (atomic_read(&module_state) & 0x80)
			xio_context_stop_loop(server_data->ctx); /* exit */
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
	struct server_data *server_data = cb_user_context;

	server_data->session = session;

	/* Automatically accept the request */
	xio_accept(session, NULL, 0, NULL, 0);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session,
			struct xio_msg *req,
			int more_in_batch,
			void *cb_user_context)
{
	struct server_data *server_data = cb_user_context;
	int i = req->sn % QUEUE_DEPTH;

	/* process request */
	process_request(req);

	/* attach request to response */
	server_data->rsp[i].request = req;

	xio_send_response(&server_data->rsp[i]);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops server_ops = {
	.on_session_event		=  on_session_event,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  on_request,
	.on_msg_error			=  NULL
};

static void xio_module_down(void *data)
{
	struct server_data *server_data;
	struct xio_connection *connection;
	struct xio_session *session;

	server_data = (struct server_data *) data;
	if (!server_data->session)
		goto stop_loop_now;

	connection = xio_get_connection(server_data->session, server_data->ctx);
	if (!connection)
		goto destroy_session;

	xio_connection_destroy(connection);
	return;

destroy_session:
	/* in multi thread version on need to user reference count */
	session = server_data->session;
	server_data->session = NULL;
	xio_session_destroy(session);

stop_loop_now:
	/* No session -> no XIO_SESSION_TEARDOWN_EVENT */
	xio_context_stop_loop(server_data->ctx); /* exit */
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
static int xio_server_main(void *data)
{
	char **argv = (char **) data;
	struct xio_server	*server;	/* server portal */
	struct server_data	*server_data;
	char			url[256];
	struct xio_context	*ctx;
	int			i;

	atomic_add(2, &module_state);

	server_data = kzalloc(sizeof(*server_data), GFP_KERNEL);
	if (!server_data) {
		printk("server_data alloc failed\n");
		return 0;
	}

	/* create thread context for the server */
	ctx = xio_context_create(XIO_LOOP_GIVEN_THREAD, NULL, current, 0, -1);
	if (!ctx) {
		kfree(server_data);
		printk("context open filed\n");
		return 0;
	}
	server_data->ctx = ctx;

	/* create "hello world" message */
	for (i = 0; i <QUEUE_DEPTH; i++) {
		server_data->rsp[i].out.header.iov_base =
			kstrdup("hello world header response", GFP_KERNEL);
		server_data->rsp[i].out.header.iov_len =
			strlen(server_data->rsp[i].out.header.iov_base);
	}

	/* create url to connect to */
	sprintf(url, "rdma://%s:%s", argv[1], argv[2]);
	/* bind a listener server to a portal/url */
	server = xio_bind(ctx, &server_ops, url, NULL, 0, server_data);
	if (server) {
		printk("listen to %s\n", url);

		g_server_data = server_data;
		if (atomic_add_unless(&module_state, 4, 0x83))
			xio_context_run_loop(ctx);

		/* normal exit phase */
		printk("exit signaled\n");

		/* free the server */
		xio_unbind(server);
	}

	/* free the message */
	for (i = 0; i < QUEUE_DEPTH; i++)
		kfree(server_data->rsp[i].out.header.iov_base);

	/* free the context */
	xio_context_destroy(ctx);

	kfree(server_data);

	complete_and_exit(&cleanup_complete, 0);

	return 0;
}

static int __init xio_hello_init_module(void)
{
	if (!(xio_argv[1] && xio_argv[2])) {
		printk("NO IP or port were given\n");
		return -EINVAL;
	}

	atomic_set(&module_state, 1);
	init_completion(&cleanup_complete);

	xio_main_th = kthread_run(xio_server_main, xio_argv, "xio-hello-server");
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
		down_event.data = (void *) g_server_data;
		xio_context_add_event(g_server_data->ctx, &down_event);
	}

	/* wait for thread to terminate */
	if (state & 2)
		wait_for_completion(&cleanup_complete);
}

module_init(xio_hello_init_module);
module_exit(xio_hello_cleanup_module);
