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
#include <linux/bitops.h>
#include <linux/version.h>
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

#define MAX_HEADER_SIZE		32
#define MAX_DATA_SIZE		32
#define PRINT_COUNTER		100000
#define XIO_DEF_ADDRESS		"127.0.0.1"
#define XIO_DEF_PORT		2061
#define XIO_DEF_TRANSPORT	"rdma"
#define XIO_DEF_HEADER_SIZE	32
#define XIO_DEF_DATA_SIZE	32
#define XIO_DEF_CPU		-1
#define XIO_TEST_VERSION	"1.0.0"
#define MAX_POOL_SIZE		2048
#define ONE_MB			BIT(20)
#define POLLING_TIMEOUT		500
#define DISCONNECT_FACTOR	3

#define SG_TBL_LEN		64

MODULE_AUTHOR("Eyal Solomon, Or Kehati, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO lat client " \
		   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

static char *xio_argv[] = {"xio_lat_client", 0, 0, 0, 0, 0, 0, 0};

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

module_param_named(finite_run, xio_argv[6], charp, 0);
MODULE_PARM_DESC(finite_run, "0 for infinite run, 1 for infinite run");

module_param_named(cpu, xio_argv[7], charp, 0);
MODULE_PARM_DESC(cpu, "Cpu mask");

/*
 * Important: If running client & server on same machine, use "cpu"
 * parameter to run on different cpus.
 */

static struct task_struct *xio_main_th;
static struct completion cleanup_complete;
atomic_t module_state;

struct xio_test_config {
	char			server_addr[32];
	uint16_t		server_port;
	char			transport[16];
	uint64_t		cpu_mask;
	uint32_t		hdr_len;
	uint32_t		data_len;
	uint32_t		conn_idx;
	uint16_t		finite_run;
	uint16_t		padding[3];
};

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static struct msg_pool		*pool;
static uint64_t			print_counter;
static struct xio_connection	*g_connection;
struct xio_session		*g_session;
static struct xio_context	*ctx;
static uint64_t			nrecv;
static uint64_t			disconnect_nr;
static struct msg_params	msg_params;
int cpu;

static struct xio_test_config  test_config = {
	XIO_DEF_ADDRESS,
	XIO_DEF_PORT,
	XIO_DEF_TRANSPORT,
	XIO_DEF_CPU,
	XIO_DEF_HEADER_SIZE,
	XIO_DEF_DATA_SIZE
};

/*---------------------------------------------------------------------------*/
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct xio_msg *rsp)
{
	struct scatterlist	*in_sgl, *out_sgl;
	static uint64_t		cnt;
	static int		first_time = 1;
	static uint64_t		start_time;
	static size_t		txlen, rxlen;

	if (first_time) {
		size_t			data_len = 0;
		int			i;

		out_sgl = rsp->out.data_tbl.sgl;
		for (i = 0; i < rsp->out.data_tbl.nents; i++) {
			data_len += out_sgl->length;
			out_sgl = sg_next(out_sgl);
		}

		txlen = rsp->out.header.iov_len + data_len;

		data_len = 0;
		in_sgl = rsp->in.data_tbl.sgl;
		for (i = 0; i < rsp->in.data_tbl.nents; i++) {
			data_len += in_sgl->length;
			in_sgl = sg_next(in_sgl);
		}

		rxlen = rsp->in.header.iov_len + data_len;

		start_time = get_cpu_usecs();
		first_time = 0;

		disconnect_nr = print_counter * DISCONNECT_FACTOR;
	}
	if (++cnt == print_counter) {
		char		timeb[40];

		uint64_t delta = get_cpu_usecs() - start_time;
		uint64_t pps = (cnt * USECS_IN_SEC) / delta;

		uint64_t txbw = pps * txlen / ONE_MB;
		uint64_t rxbw = pps * rxlen / ONE_MB;
		uint64_t lat = 1000000 / pps;

		pr_info("transactions per second: %llu, lat: %llu us, " \
			"bandwidth: TX %llu MB/s, RX: %llu MB/s, length: " \
			"TX: %zd B, RX: %zd B\n",
		       pps, lat, txbw, rxbw,
		       txlen, rxlen);
		get_time(timeb, 40);

		/*
		in_sgl = rsp->in.data_tbl.sgl;
		pr_info("**** [%s] - message [%llu] %s - %s\n",
		       timeb, (rsp->request->sn + 1),
		       (char *)rsp->in.header.iov_base,
		       (char *)(rsp->in.data_tbl.nents > 0 ?
				sg_virt(in_sgl) : NULL));
		*/
		cnt = 0;
		start_time = get_cpu_usecs();
	}
}

/*---------------------------------------------------------------------------*/
/* on_connection_established						     */
/*---------------------------------------------------------------------------*/
static int on_connection_established(struct xio_connection *conn)
{
	struct xio_msg			*msg;

	pr_info("**** starting ...\n");

	/* create transaction */
	msg = msg_pool_get(pool);
	if (!msg)
		return 0;

	/* get pointers to internal buffers */
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	msg->in.data_tbl.nents = 0;

	/*
	   sglist = vmsg_sglist(&msg->in);
	   sglist[0].iov_base = NULL;
	   sglist[0].iov_len  = ONE_MB;
	   sglist[0].mr = NULL;
	   vmsg_sglist_set_nents(&msg->in, 1);
	   */

	/* recycle the message and fill new request */
	msg_build_out_sgl(&msg_params, msg, test_config.hdr_len, 1,
		  test_config.data_len);

	/* try to send it */
	if (xio_send_request(conn, msg) == -1) {
		pr_info("**** sent %d messages\n", 1);
		if (xio_errno() != EAGAIN)
			pr_info("**** [%p] Error - xio_send_msg " \
					"failed. %s\n",
					conn,
					xio_strerror(xio_errno()));
		msg_pool_put(pool, msg);
		xio_assert(0);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	pr_info("session event: %s. reason: %s\n",
		xio_session_event_str(event_data->event),
		xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_ESTABLISHED_EVENT:
		on_connection_established(event_data->conn);
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_REJECT_EVENT:
	case XIO_SESSION_TEARDOWN_EVENT:
		g_session = NULL;
		xio_session_destroy(session);
		xio_context_stop_loop(ctx);  /* exit */
		if (pool) {
			msg_pool_free(pool);
			pool = NULL;
		}
		break;
	default:
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_established						     */
/*---------------------------------------------------------------------------*/
static int on_session_established(struct xio_session *session,
				  struct xio_new_session_rsp *rsp,
				  void *cb_user_context)
{
	pr_info("**** [%p] session established\n", session);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_response								     */
/*---------------------------------------------------------------------------*/
static int on_response(struct xio_session *session,
		       struct xio_msg *msg,
		       int last_in_rxq,
		       void *cb_user_context)
{
	/* struct scatterlist	*sgl; */

	process_response(msg);

	/* message is no longer needed */
	xio_release_response(msg);

	nrecv++;

	msg_pool_put(pool, msg);

	if (test_config.finite_run) {
		if (nrecv ==  disconnect_nr) {
			xio_disconnect(g_connection);
			return 0;
		}

		if (nrecv > disconnect_nr)
			return 0;
	}

	/* reset message */
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	msg->in.data_tbl.nents = 0;

	/*
	sgl = msg->in.data_tbl.sgl;
	xio_tbl_set_nents(&msg->in.data_tbl, test_config.in_iov_len);
	sg_set_buf(sgl, NULL, ONE_MB);
	*/

	msg->sn = 0;

	/* recycle the message and fill new request */
	msg_build_out_sgl(&msg_params, msg,
		  test_config.hdr_len,
		  1, test_config.data_len);

	/* try to send it */
	if (xio_send_request(g_connection, msg) == -1) {
		if (xio_errno() != EAGAIN)
			pr_err("**** [%p] Error - xio_send_msg " \
					"failed %s\n",
					session,
					xio_strerror(xio_errno()));
		msg_pool_put(pool, msg);
		/* xio_assert(0); */
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
		session, msg->sn, xio_strerror(error));

	msg_pool_put(pool, msg);

	switch (error) {
	case XIO_E_MSG_FLUSHED:
		break;
	default:
		xio_disconnect(g_connection);
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  on_session_established,
	.on_msg				=  on_response,
	.on_msg_error			=  on_msg_error
};

/*---------------------------------------------------------------------------*/
/* usage                                                                     */
/*---------------------------------------------------------------------------*/
static void usage(const char *argv0)
{
	pr_info("Usage:\n");
	pr_info("  %s ip=<ip> [OPTIONS] <host>\tConnect to server at <host>\n",
		argv0);
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

	pr_info("\tfinite_run=<finite-run> ");
	pr_info("\t\t0 for infinite run, 1 for infinite run" \
			"(default 0)\n");

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
		tmp = 0;
		if (kstrtouint(argv[6], 0, &tmp))
			pr_err("parse error\n");
		test_config->finite_run = (uint16_t)tmp;
	}

	if (argv[7]) {
		if (kstrtoull(argv[7], 16, &test_config->cpu_mask))
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
	pr_info(" Server Address		: %s\n", test_config_p->server_addr);
	pr_info(" Server Port		: %u\n", test_config_p->server_port);
	pr_info(" Transport		: %s\n", test_config_p->transport);
	pr_info(" Header Length		: %u\n", test_config_p->hdr_len);
	pr_info(" Data Length		: %u\n", test_config_p->data_len);
	pr_info(" Connection Index	: %u\n", test_config_p->conn_idx);
	pr_info(" CPU Mask		: 0x%llx\n", test_config_p->cpu_mask);
	pr_info(" Finite run		: %x\n", test_config_p->finite_run);
	pr_info(" =============================================\n");
}

static void xio_module_down(void *data)
{
	struct xio_session *tmp_session;
	struct xio_connection *tmp_connection;

	if (!g_session)
		goto stop_loop_now;

	if (!g_connection)
		goto destroy_session;

	tmp_connection = g_connection;
	g_connection = NULL;
	xio_disconnect(tmp_connection);

	return;

destroy_session:
	/* in multi thread version on need to user reference count */
	tmp_session = g_session;
	g_session = NULL;
	xio_session_destroy(tmp_session);

stop_loop_now:
	/* No session -> no XIO_SESSION_TEARDOWN_EVENT */
	xio_context_stop_loop(ctx); /* exit */
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
static int xio_client_main(void *data)
{
	char				url[256];
	struct xio_session_params	params;
	struct xio_context_params	ctx_params;
	struct xio_connection_params	cparams;
	int				error;
	int				retval = 0;

	atomic_add(2, &module_state);

	print_counter = PRINT_COUNTER;

	print_test_config(&test_config);

	memset(&params, 0, sizeof(params));
	memset(&cparams, 0, sizeof(cparams));

	/* prepare buffers for this test */
	if (msg_api_init(&msg_params,
			 test_config.hdr_len, test_config.data_len, 0) != 0) {
		pr_err("msg_api_init failed\n");
		return -1;
	}

	pool = msg_pool_alloc(MAX_POOL_SIZE, 1, 1);
	if (!pool) {
		pr_err("msg_pool_alloc failed\n");
		goto cleanup;
	}

	/* create thread context for the server */
	memset(&ctx_params, 0, sizeof(ctx_params));
	ctx_params.flags = XIO_LOOP_GIVEN_THREAD;
	ctx_params.worker = current;

	ctx = xio_context_create(&ctx_params,
				 POLLING_TIMEOUT, cpu);
	if (!ctx) {
		pr_err("context open failed\n");
		goto cleanup;
	}

	sprintf(url, "%s://%s:%d",
		test_config.transport,
		test_config.server_addr,
		test_config.server_port);

	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.uri		= url;

	g_session = xio_session_create(&params);
	if (!g_session)
		pr_err("session creation failed\n");

	cparams.session			= g_session;
	cparams.ctx			= ctx;
	cparams.conn_idx		= test_config.conn_idx;

	/* connect the session  */
	g_connection = xio_connect(&cparams);

	/* the default xio supplied main loop */
	if (atomic_add_unless(&module_state, 4, 0x83))
		retval = xio_context_run_loop(ctx);
	atomic_sub(4, &module_state);

	if (retval != 0) {
		error = xio_errno();
		pr_err("running event loop failed. reason %d - (%s)\n",
		       error, xio_strerror(error));
		xio_assert(retval == 0);
	}

	/* normal exit phase */
	pr_info("exit signaled\n");

	xio_context_destroy(ctx);

	msg_pool_free(pool);

cleanup:
	msg_api_free(&msg_params);

	pr_info("exit complete\n");

	complete_and_exit(&cleanup_complete, 0);

	return 0;
}

static int __init xio_lat_init_module(void)
{
	int opt = 1;

	if (parse_cmdline(&test_config, xio_argv))
		return -EINVAL;

	atomic_set(&module_state, 1);
	init_completion(&cleanup_complete);

	/* disable nagle algorithm for tcp */
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_TCP, XIO_OPTNAME_TCP_NO_DELAY,
		    &opt, sizeof(int));

	xio_main_th = kthread_create(xio_client_main, xio_argv,
				     "xio-hello-client");
	if (IS_ERR(xio_main_th)) {
		complete(&cleanup_complete);
		return PTR_ERR(xio_main_th);
	}

	if (test_config.cpu_mask) {
		cpu = __ffs64(test_config.cpu_mask);
		pr_info("cpu is %d\n", cpu);
		kthread_bind(xio_main_th, cpu);
	}

	wake_up_process(xio_main_th);

	return 0;
}

static void __exit xio_lat_cleanup_module(void)
{
	struct xio_ev_data down_event;
	int state;

	state = atomic_add_return(0x80, &module_state);

	if (state & 4) {
		/* thread is running, loop is still running */
		memset(&down_event, 0, sizeof(down_event));
		down_event.handler = xio_module_down;
		down_event.data = NULL;
		xio_context_add_event(ctx, &down_event);
	}

	/* wait fot thread to terminate */
	if (state & 2)
		wait_for_completion(&cleanup_complete);
}

module_init(xio_lat_init_module);
module_exit(xio_lat_cleanup_module);
