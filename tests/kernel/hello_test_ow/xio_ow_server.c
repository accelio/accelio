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
#include <linux/version.h>
#include <linux/inet.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif
#include <linux/completion.h>
#include <linux/scatterlist.h>

#include "libxio.h"
#include "xio_msg.h"
#include "xio_test_utils.h"

#define MAX_POOL_SIZE		512
#define PRINT_COUNTER		4000000

#define XIO_DEF_ADDRESS		"127.0.0.1"
#define XIO_DEF_PORT		2061
#define XIO_DEF_TRANSPORT	"rdma"
#define XIO_DEF_HEADER_SIZE	32
#define XIO_DEF_DATA_SIZE	32
#define XIO_DEF_IOV_LEN		1
#define	XIO_DEF_CPU		1
#define XIO_TEST_VERSION	"1.0.0"
#define XIO_READ_BUF_LEN	(1024 * 1024)

/* will disconnect after DISCONNECT_FACTOR*print counter msgs */
#define DISCONNECT_FACTOR	3

#define SG_TBL_LEN		256

MODULE_AUTHOR("Eyal Solomon, Or Kehati, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO one way server " \
		   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

static char *xio_argv[] = {"xio_ow_server", 0, 0, 0, 0, 0, 0, 0, 0, 0};

module_param_named(ip, xio_argv[1], charp, 0);
MODULE_PARM_DESC(ip, "IP of NIC to send request to");

module_param_named(port, xio_argv[2], charp, 0);
MODULE_PARM_DESC(port, "Port to send request to");

module_param_named(transport, xio_argv[3], charp, 0);
MODULE_PARM_DESC(transport, "Transport type (rdma/tcp)");

module_param_named(header_len, xio_argv[4], charp, 0);
MODULE_PARM_DESC(header_len, "Header length of the message");

module_param_named(data_len, xio_argv[5], charp, 0);
MODULE_PARM_DESC(data_len, "Data length of the message");

module_param_named(iov_len, xio_argv[6], charp, 0);
MODULE_PARM_DESC(iov_len, "Data length of the message vector");

module_param_named(finite_run, xio_argv[7], charp, 0);
MODULE_PARM_DESC(finite_run, "0 for infinite run, 1 for infinite run");

module_param_named(cpu, xio_argv[8], charp, 0);
MODULE_PARM_DESC(cpu, "Cpu mask");

static struct task_struct *xio_main_th;
static struct completion cleanup_complete;
atomic_t module_state;

struct xio_test_config {
	char		server_addr[32];
	uint16_t	server_port;
	char		transport[16];
	uint64_t	cpu_mask;
	uint32_t	hdr_len;
	uint32_t	data_len;
	uint32_t	iov_len;
	uint32_t	finite_run;
	uint32_t	padding;
};

struct test_params {
	struct xio_connection	*connection;
	struct xio_context	*ctx;
	struct xio_session	*session;
	void			*xbuf;
	uint64_t		nsent;
	uint64_t		nrecv;
	uint16_t		finite_run;
	uint16_t		padding[3];
	uint64_t		disconnect_nr;
	int cpu;
};

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static struct xio_test_config  test_config = {
	XIO_DEF_ADDRESS,
	XIO_DEF_PORT,
	XIO_DEF_TRANSPORT,
	XIO_DEF_CPU,
	XIO_DEF_HEADER_SIZE,
	XIO_DEF_DATA_SIZE,
	XIO_DEF_IOV_LEN,
	0
};

struct test_params		g_test_params;

/*---------------------------------------------------------------------------*/
/* process_request							     */
/*---------------------------------------------------------------------------*/
static void process_request(struct xio_msg *msg)
{
	static int cnt;

	if (!msg) {
		cnt = 0;
		return;
	}
	if (++cnt == PRINT_COUNTER) {
		struct scatterlist *sgl = msg->in.data_tbl.sgl;

		pr_info("**** message [%llu] %s - %s\n",
			(msg->sn + 1),
			(char *)msg->in.header.iov_base,
			(char *)sg_virt(sgl));
		cnt = 0;
	}
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct xio_connection_attr	conn_attr;
	struct test_params		*test_params = cb_user_context;

	pr_info("session event: %s. session:%p, connection:%p, reason: %s\n",
		xio_session_event_str(event_data->event),
		session, event_data->conn,
		xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		/* assign connection private data */
		conn_attr.user_context = cb_user_context;
		xio_modify_connection(event_data->conn, &conn_attr,
				      XIO_CONNECTION_ATTR_USER_CTX);
		if (!test_params->connection)
			test_params->connection = event_data->conn;
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		if (event_data->reason != XIO_E_SESSION_REJECTED) {
			pr_info("last recv:%llu\n",
				test_params->nrecv);
			test_params->connection = NULL;
		}
		xio_connection_destroy(event_data->conn);
		test_params->connection = NULL;
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		test_params->session = NULL;
		xio_session_destroy(session);
		if (event_data->reason != XIO_E_SESSION_REJECTED) {
			if (atomic_read(&module_state) & 0x80)
				xio_context_stop_loop(
						test_params->ctx); /* exit */
		}
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
	struct test_params *test_params = cb_user_context;
	char ip[INET6_ADDRSTRLEN + 1];

	pr_info("**** [%p] on_new_session :%s:%d\n", session,
		get_ip((struct sockaddr *)&req->src_addr, ip),
		get_port((struct sockaddr *)&req->src_addr));

	test_params->session = session;

	if (!test_params->connection)
		xio_accept(session, NULL, 0, NULL, 0);
	else
		xio_reject(session, EISCONN, NULL, 0);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_request								     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session,
		      struct xio_msg *req,
		      int last_in_rxq,
		      void *cb_user_context)
{
	struct test_params *test_params = cb_user_context;

	test_params->nrecv++;

	/* process request */
	process_request(req);

	xio_release_msg(req);
	if (test_params->finite_run &&
	    test_params->nrecv == test_params->disconnect_nr) {
		xio_disconnect(test_params->connection);
		return 0;
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
	pr_info("**** [%p] message [%llu] failed. reason: %s\n",
		session, msg->request->sn, xio_strerror(error));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* assign_data_in_buf							     */
/*---------------------------------------------------------------------------*/
static int assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	struct test_params	*test_params = cb_user_context;
	struct scatterlist	*sgl = msg->in.data_tbl.sgl;
	int			nents = msg->in.data_tbl.nents;
	int i;

	if (!test_params->xbuf)
		test_params->xbuf = kzalloc(XIO_READ_BUF_LEN, GFP_KERNEL);

	for (i = 0; i < nents; i++) {
		sg_set_buf(sgl, test_params->xbuf, XIO_READ_BUF_LEN);
		sgl = sg_next(sgl);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops server_ops = {
	.on_session_event		=  on_session_event,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  on_request,
	.on_msg_error			=  on_msg_error,
	.assign_data_in_buf		=  assign_data_in_buf
};

/*---------------------------------------------------------------------------*/
/* usage                                                                     */
/*---------------------------------------------------------------------------*/
static void usage(const char *argv0)
{
	pr_info("Usage:\n");
	pr_info("  %s ip=<ip> [OPTIONS]" \
		"\t\t\tStart a server and wait for connection\n", argv0);
	pr_info("\n");
	pr_info("Options:\n");

	pr_info("\tip=<ip> ");
	pr_info("\t\tConnect to ip <ip>\n");

	pr_info("\tport=<port> ");
	pr_info("\t\tConnect to port <port> (default %d)\n",
		XIO_DEF_PORT);

	pr_info("\ttransport=<type> ");
	pr_info("\t\tUse rdma/tcp as transport <type> (default %s)\n",
		XIO_DEF_TRANSPORT);

	pr_info("\theader_len=<number> ");
	pr_info("\t\tSet the header length of the message to <number> bytes " \
			"(default %d)\n", XIO_DEF_HEADER_SIZE);

	pr_info("\tdata_len=<length> ");
	pr_info("\t\tSet the data length of the message to <number> bytes " \
			"(default %d)\n", XIO_DEF_DATA_SIZE);

	pr_info("\tiov_len=<length> ");
	pr_info("\t\tSet the data length of the message vector" \
			"(default %d)\n", XIO_DEF_IOV_LEN);

	pr_info("\tcpu=<cpu num> ");
	pr_info("\t\tSet cpu mask to bind the process to specific cpu\n");
}

/*---------------------------------------------------------------------------*/
/* parse_cmdline							     */
/*---------------------------------------------------------------------------*/
int parse_cmdline(struct xio_test_config *test_config, char **argv)
{
	uint32_t tmp = 0;

	if (!argv[1]) {
		usage(argv[0]);
		pr_err("NO IP was given\n");
		return -1;
	}

	sprintf(test_config->server_addr, "%s", argv[1]);

	if (argv[2]) {
		if (kstrtouint(argv[2], 0, &tmp))
			pr_err("parse error\n");
		test_config->server_port = (uint16_t)tmp;
	}

	if (argv[3])
		sprintf(test_config->transport, "%s", argv[3]);

	if (argv[4])
		if (kstrtouint(argv[4], 0, &test_config->hdr_len))
			pr_err("parse error\n");

	if (argv[5])
		if (kstrtouint(argv[5], 0, &test_config->data_len))
			pr_err("parse error\n");

	if (argv[6]) {
		if (kstrtouint(argv[6], 0, &test_config->iov_len))
			pr_err("parse error\n");
		if (test_config->iov_len > SG_TBL_LEN) {
			pr_err("iov_len (%d) > %d\n",
			       test_config->iov_len, SG_TBL_LEN);
			return -1;
		}
	}
	if (argv[7])
		if (kstrtouint(argv[7], 0, &test_config->finite_run))
			pr_err("parse error\n");

	if (argv[8]) {
		if (kstrtoull(argv[8], 16, &test_config->cpu_mask))
			pr_err("parse error\n");
	}

	return 0;
}

/*************************************************************
* Function: print_test_config
*-------------------------------------------------------------
* Description: print the test configuration
*************************************************************/
static void print_test_config(
		const struct xio_test_config *test_config_p)
{
	pr_info(" =============================================\n");
	pr_info(" Server Address	: %s\n", test_config_p->server_addr);
	pr_info(" Server Port		: %u\n", test_config_p->server_port);
	pr_info(" Transport		: %s\n", test_config_p->transport);
	pr_info(" Header Length		: %u\n", test_config_p->hdr_len);
	pr_info(" Data Length		: %u\n", test_config_p->data_len);
	pr_info(" Vector Length		: %u\n", test_config_p->iov_len);
	pr_info(" CPU Mask		: 0x%llx\n", test_config_p->cpu_mask);
	pr_info(" =============================================\n");
}

static void xio_module_down(void *data)
{
	struct test_params *params;
	struct xio_session *session;
	struct xio_connection *connection;

	params = (struct test_params *)data;

	if (!params->session)
		goto stop_loop_now;

	if (!params->connection)
		goto destroy_session;

	connection = params->connection;
	params->connection = NULL;
	xio_disconnect(connection);

	return;

destroy_session:
	/* in multi thread version on need to user reference count */
	session = params->session;
	params->session = NULL;
	xio_session_destroy(session);

stop_loop_now:
	/* No session -> no XIO_SESSION_TEARDOWN_EVENT */
	xio_context_stop_loop(params->ctx); /* exit */
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
static int xio_server_main(void *data)
{
	struct xio_server		*server;
	struct xio_context_params	ctx_params;
	char				url[256];

	atomic_add(2, &module_state);

	print_test_config(&test_config);

	g_test_params.finite_run = test_config.finite_run;
	g_test_params.disconnect_nr = PRINT_COUNTER * DISCONNECT_FACTOR;

	memset(&ctx_params, 0, sizeof(ctx_params));
	ctx_params.flags = XIO_LOOP_GIVEN_THREAD;
	ctx_params.worker = current;

	g_test_params.ctx = xio_context_create(&ctx_params,
					       0, g_test_params.cpu);
	if (!g_test_params.ctx) {
		int error = xio_errno();

		pr_err("context creation failed. reason %d - (%s)\n",
		       error, xio_strerror(error));
		goto cleanup;
	}

	sprintf(url, "%s://%s:%d",
		test_config.transport,
		test_config.server_addr,
		test_config.server_port);

	server = xio_bind(g_test_params.ctx, &server_ops,
			  url, NULL, 0, &g_test_params);
	if (server) {
		pr_info("listen to %s\n", url);

		if (atomic_add_unless(&module_state, 4, 0x83))
			xio_context_run_loop(g_test_params.ctx);
		atomic_sub(4, &module_state);

		/* normal exit phase */
		pr_info("exit signaled\n");

		/* free the server */
		xio_unbind(server);
	} else {
		pr_err("**** Error - xio_bind failed - %s. " \
		       "Did you load a transport module?\n",
		       xio_strerror(xio_errno()));
		/*xio_assert(0);*/
	}

	xio_context_destroy(g_test_params.ctx);

	kfree(g_test_params.xbuf);
	g_test_params.xbuf = NULL;

cleanup:

	complete_and_exit(&cleanup_complete, 0);

	return 0;
}

static int __init xio_hello_init_module(void)
{
	int iov_len = SG_TBL_LEN;

	if (parse_cmdline(&test_config, xio_argv))
		return -EINVAL;

	atomic_set(&module_state, 1);
	init_completion(&cleanup_complete);

	/* set accelio max message vector used */
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_IN_IOVLEN,
		    &iov_len, sizeof(int));
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_OUT_IOVLEN,
		    &iov_len, sizeof(int));

	xio_main_th = kthread_create(xio_server_main, xio_argv,
				     "xio-hello-server");
	if (IS_ERR(xio_main_th)) {
		complete(&cleanup_complete);
		return PTR_ERR(xio_main_th);
	}

	if (test_config.cpu_mask) {
		g_test_params.cpu = __ffs64(test_config.cpu_mask);
		pr_info("cpu is %d\n", g_test_params.cpu);
		kthread_bind(xio_main_th, g_test_params.cpu);
	}

	wake_up_process(xio_main_th);

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
		down_event.data = (void *)&g_test_params;
		xio_context_add_event(g_test_params.ctx,
				      &down_event);
	}

	/* wait for thread to terminate */
	if (state & 2)
		wait_for_completion(&cleanup_complete);
}

module_init(xio_hello_init_module);
module_exit(xio_hello_cleanup_module);
