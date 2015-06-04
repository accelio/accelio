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
#define PRINT_COUNTER		4000000
#define XIO_DEF_ADDRESS		"127.0.0.1"
#define XIO_DEF_PORT		2061
#define XIO_DEF_TRANSPORT	"rdma"
#define XIO_DEF_HEADER_SIZE	32
#define XIO_DEF_DATA_SIZE	32
#define XIO_DEF_CPU		-1
#define XIO_DEF_IN_IOV_LEN	0
#define XIO_DEF_OUT_IOV_LEN	1
#define XIO_DEF_CONN_IDX	0
#define XIO_TEST_VERSION	"1.0.0"
#define MAX_OUTSTANDING_REQS	50
/* will disconnect after DISCONNECT_FACTOR*print counter msgs */
#define DISCONNECT_FACTOR	3
#define	CHAIN_MESSAGES		0

#define MAX_POOL_SIZE		MAX_OUTSTANDING_REQS
#define ONE_MB			BIT(20)

#define SG_TBL_LEN		256

MODULE_AUTHOR("Eyal Solomon, Or Kehati, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO hello client " \
		   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

static char *xio_argv[] = {"xio_hello_client", 0, 0, 0, 0, 0, 0, 0, 0, 0};

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

module_param_named(out_iov_len, xio_argv[6], charp, 0);
MODULE_PARM_DESC(out_iov_len, "Data length of the out message vector");

module_param_named(in_iov_len, xio_argv[7], charp, 0);
MODULE_PARM_DESC(in_iov_len, "Data length of the in message vecto");

module_param_named(finite_run, xio_argv[8], charp, 0);
MODULE_PARM_DESC(finite_run, "0 for infinite run, 1 for infinite run");

module_param_named(cpu, xio_argv[9], charp, 0);
MODULE_PARM_DESC(cpu, "Bind to specific cpu");

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
	uint32_t		in_iov_len;
	uint32_t		out_iov_len;
	uint32_t		conn_idx;
	uint16_t		finite_run;
	uint16_t		padding[3];
};

struct test_stat {
	uint64_t		cnt;
	uint64_t		start_time;
	uint64_t		print_counter;
	int			first_time;
	int			pad;
	size_t			rxlen;
	size_t			txlen;
};

struct chain_list {
	struct xio_msg		*head;
	struct xio_msg		*tail;
	int			sz;
	int			pad;
};

struct test_params {
	struct msg_pool		*pool;
	struct xio_connection	*connection;
	struct xio_context	*ctx;
	struct xio_session	*session;
	struct chain_list	chain;
	struct test_stat	stat;
	struct msg_params	msg_params;
	uint64_t		nsent;
	uint64_t		nrecv;
	uint16_t		finite_run;
	uint16_t		padding;
	uint32_t		iov_sz;
	uint64_t		disconnect_nr;
	int			cpu;
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
	XIO_DEF_IN_IOV_LEN,
	XIO_DEF_OUT_IOV_LEN,
	XIO_DEF_CONN_IDX
};

struct test_params		g_test_params;

/*---------------------------------------------------------------------------*/
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct test_params *test_params,
			     struct xio_msg *rsp)
{
	struct scatterlist	*in_sgl, *out_sgl;

	if (test_params->stat.first_time) {
		size_t			data_len = 0;
		int			i;

		out_sgl = rsp->out.data_tbl.sgl;
		for (i = 0; i < rsp->out.data_tbl.nents; i++) {
			data_len += out_sgl->length;
			out_sgl = sg_next(out_sgl);
		}

		test_params->stat.txlen = rsp->out.header.iov_len + data_len;

		data_len = 0;
		in_sgl = rsp->in.data_tbl.sgl;
		for (i = 0; i < rsp->in.data_tbl.nents; i++) {
			data_len += in_sgl->length;
			in_sgl = sg_next(in_sgl);
		}

		test_params->stat.rxlen = rsp->in.header.iov_len + data_len;

		test_params->stat.start_time = get_cpu_usecs();
		test_params->stat.first_time = 0;

		data_len = test_params->stat.txlen > test_params->stat.rxlen ?
			   test_params->stat.txlen : test_params->stat.rxlen;
		data_len = data_len / 1024;
		test_params->stat.print_counter = (data_len ?
				 PRINT_COUNTER / data_len : PRINT_COUNTER);
		if (test_params->stat.print_counter < 1000)
			test_params->stat.print_counter = 1000;
		test_params->disconnect_nr =
			test_params->stat.print_counter * DISCONNECT_FACTOR;
	}
	if (++test_params->stat.cnt == test_params->stat.print_counter) {
		char		timeb[40];

		uint64_t delta = get_cpu_usecs() - test_params->stat.start_time;
		uint64_t pps = (test_params->stat.cnt * USECS_IN_SEC) / delta;
		uint64_t txbw = pps * test_params->stat.txlen / ONE_MB;
		uint64_t rxbw = pps * test_params->stat.rxlen / ONE_MB;

		pr_info("transactions per second: %llu, bandwidth: " \
		       "TX %llu MB/s, RX: %llu MB/s, length: TX: %zd B, RX: %zd B\n",
		       pps, txbw,  rxbw,
		       test_params->stat.txlen, test_params->stat.rxlen);
		get_time(timeb, 40);

		in_sgl = rsp->in.data_tbl.sgl;
		pr_info("**** [%s] - message [%llu] %s - %s\n",
			timeb, (rsp->request->sn + 1),
			(char *)rsp->in.header.iov_base,
			(char *)(rsp->in.data_tbl.nents > 0 ?
				 sg_virt(in_sgl) : NULL));

		test_params->stat.cnt = 0;
		test_params->stat.start_time = get_cpu_usecs();
	}
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct test_params *test_params = cb_user_context;

	pr_info("session event: %s. reason: %s\n",
		xio_session_event_str(event_data->event),
		xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		pr_info("nsent:%llu, nrecv:%llu, " \
		       "delta:%llu\n",
		       test_params->nsent, test_params->nrecv,
		       test_params->nsent - test_params->nrecv);

		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_REJECT_EVENT:
	case XIO_SESSION_TEARDOWN_EVENT:
		test_params->session = NULL;
		xio_session_destroy(session);
		xio_context_stop_loop(test_params->ctx);  /* exit */
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
/* on_msg_delivered							     */
/*---------------------------------------------------------------------------*/
static int on_msg_delivered(struct xio_session *session,
			    struct xio_msg *msg,
			    int last_in_rxq,
			    void *cb_user_context)
{
	/*
	pr_info("**** on message delivered\n");
	*/

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
	struct test_params	*test_params = cb_user_context;
	struct scatterlist	*sgl;
	static int		chain_messages = CHAIN_MESSAGES;
	size_t			j;

	test_params->nrecv++;

	process_response(test_params, msg);

	/* message is no longer needed */
	xio_release_response(msg);

	msg_pool_put(test_params->pool, msg);

	if (test_params->finite_run) {
		if (test_params->nrecv ==  test_params->disconnect_nr) {
			xio_disconnect(test_params->connection);
			return 0;
		}

		if (test_params->nsent == test_params->disconnect_nr)
			return 0;
	}

	/* peek message from the pool */
	msg = msg_pool_get(test_params->pool);
	if (!msg) {
		pr_err("pool is empty\n");
		return 0;
	}
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;

	sgl = msg->in.data_tbl.sgl;
	xio_tbl_set_nents(&msg->in.data_tbl, test_config.in_iov_len);

	for (j = 0; j < test_config.in_iov_len; j++) {
		sg_set_buf(sgl, NULL, test_params->iov_sz);
		sgl = sg_next(sgl);
	}

	msg->sn = 0;

	/* assign buffers to the message */
	msg_build_out_sgl(&test_params->msg_params, msg,
		  test_config.hdr_len,
		  test_config.out_iov_len, test_config.data_len);

	if (chain_messages) {
		msg->next = NULL;
		if (!test_params->chain.head) {
			test_params->chain.head = msg;
			test_params->chain.tail = test_params->chain.head;
		} else {
			test_params->chain.tail->next = msg;
			test_params->chain.tail = test_params->chain.tail->next;
		}
		if (++test_params->chain.sz == MAX_OUTSTANDING_REQS) {
			if (xio_send_request(test_params->connection,
					     test_params->chain.head) == -1) {
				if (xio_errno() != EAGAIN)
					pr_err("**** [%p] Error - "\
					       "xio_send_request " \
					       "failed %s\n",
					       session,
					       xio_strerror(xio_errno()));
				msg_pool_put(test_params->pool, msg);
				xio_assert(xio_errno() == EAGAIN);
			}
			test_params->nsent += test_params->chain.sz;
			test_params->chain.head = NULL;
			test_params->chain.sz = 0;
		}
	} else {
		/* try to send it */
		/*msg->flags = XIO_MSG_FLAG_REQUEST_READ_RECEIPT; */
		if (xio_send_request(test_params->connection, msg) == -1) {
			if (xio_errno() != EAGAIN)
				pr_err("**** [%p] Error - xio_send_request " \
						"failed %s\n",
						session,
						xio_strerror(xio_errno()));
			msg_pool_put(test_params->pool, msg);
			/* xio_assert(xio_errno() == EAGAIN); */
		}
		test_params->nsent++;
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
	struct test_params *test_params = cb_user_context;

	if (direction == XIO_MSG_DIRECTION_OUT) {
		pr_info("**** [%p] message %llu failed. reason: %s\n",
			session, msg->sn, xio_strerror(error));
	} else {
		xio_release_response(msg);
		pr_info("**** [%p] message %llu failed. reason: %s\n",
			session, msg->request->sn, xio_strerror(error));
	}

	msg_pool_put(test_params->pool, msg);

	switch (error) {
	case XIO_E_MSG_FLUSHED:
		break;
	default:
		xio_disconnect(test_params->connection);
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
	.on_msg_delivered		=  on_msg_delivered,
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

	pr_info("\tout_iov_len=<length> ");
	pr_info("\t\tSet the data length of the out message vector" \
			"(default %d)\n", XIO_DEF_OUT_IOV_LEN);

	pr_info("\tin_iov_len=<length> ");
	pr_info("\t\tSet the data length of the message vector" \
			"(default %d)\n", XIO_DEF_IN_IOV_LEN);

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
		if (kstrtouint(argv[6], 0, &test_config->out_iov_len))
			pr_err("parse error\n");
		if (test_config->out_iov_len > SG_TBL_LEN) {
			pr_err("out_iov_len (%d) > %d\n",
			       test_config->out_iov_len, SG_TBL_LEN);
			return -1;
		}
	}

	if (argv[7]) {
		if (kstrtouint(argv[7], 0, &test_config->in_iov_len))
			pr_err("parse error\n");
		if (test_config->in_iov_len > SG_TBL_LEN) {
			pr_err("in_iov_len (%d) > %d\n",
			       test_config->in_iov_len, SG_TBL_LEN);
			return -1;
		}
	}

	if (argv[8]) {
		tmp = 0;
		if (kstrtouint(argv[8], 0, &tmp))
			pr_err("parse error\n");
		test_config->finite_run = (uint16_t)tmp;
	}

	if (argv[9]) {
		if (kstrtoull(argv[9], 16, &test_config->cpu_mask))
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
	pr_info(" Out Vector Length	: %u\n", test_config_p->out_iov_len);
	pr_info(" In Vector Length	: %u\n", test_config_p->in_iov_len);
	pr_info(" Connection Index	: %u\n", test_config_p->conn_idx);
	pr_info(" CPU Mask		: 0x%llx\n", test_config_p->cpu_mask);
	pr_info(" Finite run		: %x\n", test_config_p->finite_run);
	pr_info(" =============================================\n");
}

/*---------------------------------------------------------------------------*/
/* send_one_by_one							     */
/*---------------------------------------------------------------------------*/
int send_one_by_one(struct test_params *test_params)
{
	struct scatterlist	*sgl;
	struct xio_msg		*msg;
	int			i;
	size_t			j;

	for (i = 0; i < MAX_OUTSTANDING_REQS; i++) {
		/* create transaction */
		msg = msg_pool_get(test_params->pool);
		if (!msg)
			break;

		/* get pointers to internal buffers */
		msg->in.header.iov_base = NULL;
		msg->in.header.iov_len = 0;

		sgl = msg->in.data_tbl.sgl;
		xio_tbl_set_nents(&msg->in.data_tbl, test_config.in_iov_len);

		for (j = 0; j < test_config.in_iov_len; j++) {
			sg_set_buf(sgl, NULL, g_test_params.iov_sz);
			sgl = sg_next(sgl);
		}

		/* assign buffers to the message */
		msg_build_out_sgl(&test_params->msg_params, msg,
			  test_config.hdr_len,
			  test_config.out_iov_len, test_config.data_len);

		/* try to send it */
		if (xio_send_request(test_params->connection, msg) == -1) {
			pr_info("**** sent %d messages\n", i);
			if (xio_errno() != EAGAIN)
				pr_info("**** connection:%p - " \
					"Error - xio_send_request " \
					"failed. %s\n",
					test_params->connection,
					xio_strerror(xio_errno()));
			msg_pool_put(test_params->pool, msg);
			return -1;
		}
		test_params->nsent++;
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* send_chained								     */
/*---------------------------------------------------------------------------*/
int send_chained(struct test_params *test_params)
{
	struct scatterlist	*sgl;
	struct xio_msg		*msg, *head = NULL, *tail = NULL;
	int			i;
	size_t			j;
	int			nsent = 0;

	for (i = 0; i < MAX_OUTSTANDING_REQS; i++) {
		/* create transaction */
		msg = msg_pool_get(test_params->pool);
		if (!msg)
			break;

		/* get pointers to internal buffers */
		msg->in.header.iov_base = NULL;
		msg->in.header.iov_len = 0;

		sgl = msg->in.data_tbl.sgl;
		xio_tbl_set_nents(&msg->in.data_tbl, test_config.in_iov_len);

		for (j = 0; j < test_config.in_iov_len; j++) {
			sg_set_buf(sgl, NULL, g_test_params.iov_sz);
			sgl = sg_next(sgl);
		}

		/* assign buffers to the message */
		msg_build_out_sgl(&test_params->msg_params, msg,
			  test_config.hdr_len,
			  test_config.out_iov_len, test_config.data_len);

		msg->next = NULL;

		/* append the message */
		if (!head) {
			head = msg;
			tail = head;
		} else {
			tail->next = msg;
			tail = tail->next;
		}

		nsent++;
	}

	/* try to send it */
	if (xio_send_request(test_params->connection, head) == -1) {
		pr_info("**** sent %d messages\n", i);
		if (xio_errno() != EAGAIN)
			pr_err("**** connection:%p - " \
					"Error - xio_send_request " \
					"failed. %s\n",
					test_params->connection,
					xio_strerror(xio_errno()));
		msg_pool_put(test_params->pool, msg);
		return -1;
	}

	test_params->nsent += nsent;

	return 0;
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
static int xio_client_main(void *data)
{
	char				url[256];
	struct xio_session_params	params;
	struct xio_connection_params	cparams;
	int				error;
	int				retval;
	struct xio_context_params	ctx_params;
	static int			chain_messages = CHAIN_MESSAGES;

	atomic_add(2, &module_state);

	print_test_config(&test_config);

	memset(&params, 0, sizeof(params));
	memset(&cparams, 0, sizeof(cparams));
	g_test_params.stat.first_time = 1;
	g_test_params.finite_run = test_config.finite_run;

	/* prepare buffers for this test */
	if (msg_api_init(&g_test_params.msg_params,
			 test_config.hdr_len, test_config.data_len, 0) != 0) {
		pr_err("msg_api_init failed\n");
		return -1;
	}

	g_test_params.pool = msg_pool_alloc(MAX_POOL_SIZE,
					  test_config.in_iov_len,
					  test_config.out_iov_len);
	/* accelio kernel can support up to 256 pages so only ONE_MB is
	 * allowed */
	g_test_params.iov_sz = (test_config.in_iov_len) ?
		ONE_MB / test_config.in_iov_len : 0;
	if (!g_test_params.pool) {
		pr_err("msg_pool_alloc failed\n");
		goto cleanup;
	}

	/* create thread context for the client */
	memset(&ctx_params, 0, sizeof(ctx_params));
	ctx_params.flags = XIO_LOOP_GIVEN_THREAD;
	ctx_params.worker = current;


	g_test_params.ctx = xio_context_create(&ctx_params,
					       0, g_test_params.cpu);
	if (!g_test_params.ctx) {
		pr_err("context open failed\n");
		goto cleanup;
	}

	sprintf(url, "%s://%s:%d",
		test_config.transport,
		test_config.server_addr,
		test_config.server_port);

	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.user_context	= &g_test_params;
	params.uri		= url;

	g_test_params.session = xio_session_create(&params);
	if (!g_test_params.session)
		pr_err("session creation failed\n");

	cparams.session			= g_test_params.session;
	cparams.ctx			= g_test_params.ctx;
	cparams.conn_idx		= test_config.conn_idx;
	cparams.conn_user_context	= &g_test_params;

	/* connect the session  */
	g_test_params.connection = xio_connect(&cparams);

	pr_info("**** starting ...\n");

	if (chain_messages)
		retval = send_chained(&g_test_params);
	else
		retval = send_one_by_one(&g_test_params);

	xio_assert(retval == 0);

	/* the default xio supplied main loop */
	if (atomic_add_unless(&module_state, 4, 0x83))
		retval = xio_context_run_loop(g_test_params.ctx);
	atomic_sub(4, &module_state);

	if (retval != 0) {
		error = xio_errno();
		pr_err("running event loop failed. reason %d - (%s)\n",
		       error, xio_strerror(error));
		xio_assert(retval == 0);
	}

	/* normal exit phase */
	pr_info("exit signaled\n");

	xio_context_destroy(g_test_params.ctx);

	msg_pool_free(g_test_params.pool);

cleanup:
	msg_api_free(&g_test_params.msg_params);

	pr_info("exit complete\n");

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

	xio_main_th = kthread_create(xio_client_main, xio_argv,
				     "xio-hello-client");
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
		xio_context_add_event(g_test_params.ctx, &down_event);
	}

	/* wait fot thread to terminate */
	if (state & 2)
		wait_for_completion(&cleanup_complete);
}

module_init(xio_hello_init_module);
module_exit(xio_hello_cleanup_module);
