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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

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
#define XIO_DEF_CPU		0
#define XIO_TEST_VERSION	"1.0.0"
#define MAX_OUTSTANDING_REQS	50
#define DISCONNECT_FACTOR	3
#define MAX_POOL_SIZE		MAX_OUTSTANDING_REQS
#define ONE_MB			(1 << 20)
#define XIO_READ_BUF_LEN	ONE_MB


struct xio_test_config {
	char			server_addr[32];
	uint16_t		server_port;
	char			transport[16];
	uint16_t		cpu;
	uint32_t		hdr_len;
	uint32_t		data_len;
	uint32_t		conn_idx;
	uint16_t		finite_run;
	uint16_t		padding[3];
};

struct ow_test_stat {
	uint64_t		cnt;
	uint64_t		start_time;
	uint64_t		print_counter;
	int			first_time;
	int			pad;
	size_t			xlen;
};

struct ow_test_params {
	struct msg_pool		*pool;
	struct xio_reg_mem	reg_mem;
	struct xio_connection	*conn;
	struct xio_context	*ctx;
	struct ow_test_stat	rx_stat;
	struct ow_test_stat	tx_stat;
	struct msg_params	msg_params;
	unsigned int		nsent;
	unsigned int		ndelivered;
	uint16_t		finite_run;
	uint16_t		padding[3];
	uint64_t		disconnect_nr;
};

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static struct xio_test_config  test_config = {
	.server_addr = XIO_DEF_ADDRESS,
	.server_port = XIO_DEF_PORT,
	.transport = XIO_DEF_TRANSPORT,
	.cpu = XIO_DEF_CPU,
	.hdr_len = XIO_DEF_HEADER_SIZE,
	.data_len = XIO_DEF_DATA_SIZE,
	.conn_idx = 0,
	.finite_run = 0,
	.padding = { 0 },
};

/*---------------------------------------------------------------------------*/
/* process_rx_message							     */
/*---------------------------------------------------------------------------*/
static void process_rx_message(struct ow_test_params *ow_params,
			       struct xio_msg *msg)
{
	struct xio_iovec_ex	*isglist = vmsg_sglist(&msg->in);
	int			inents = vmsg_sglist_nents(&msg->in);


	if (ow_params->rx_stat.first_time) {
		size_t	data_len = 0;
		int	i;

		data_len = 0;
		for (i = 0; i < inents; i++)
			data_len += isglist[i].iov_len;

		ow_params->rx_stat.xlen = msg->in.header.iov_len + data_len;

		ow_params->rx_stat.start_time = get_cpu_usecs();
		ow_params->rx_stat.first_time = 0;

		data_len = ow_params->rx_stat.xlen/1024;
		ow_params->rx_stat.print_counter = data_len ?
			PRINT_COUNTER/data_len : PRINT_COUNTER;
		if (ow_params->rx_stat.print_counter < 1000)
			ow_params->rx_stat.print_counter = 1000;
	}
	if (++ow_params->rx_stat.cnt == ow_params->rx_stat.print_counter) {
		char		timeb[40];

		uint64_t delta =
			get_cpu_usecs() - ow_params->rx_stat.start_time;
		uint64_t pps = (ow_params->rx_stat.cnt*USECS_IN_SEC)/delta;

		double rxbw = (1.0*pps*ow_params->rx_stat.xlen/ONE_MB);

		printf("transactions per second: %lu, bandwidth: " \
		       "RX: %.2f MB/s, RX: %zd B\n",
		       pps, rxbw, ow_params->rx_stat.xlen);
		get_time(timeb, 40);
		printf("**** [%s] - message [%lu] %s - %s\n",
		       timeb, (msg->sn + 1),
		       (char *)msg->in.header.iov_base,
		       (char *)(inents > 0 ? isglist[0].iov_base : NULL));
		ow_params->rx_stat.cnt = 0;
		ow_params->rx_stat.start_time = get_cpu_usecs();
	}
}


/*---------------------------------------------------------------------------*/
/* process_message							     */
/*---------------------------------------------------------------------------*/
static void process_tx_message(struct ow_test_params *ow_params,
			       struct xio_msg *msg)
{
	struct xio_iovec_ex	*osglist = vmsg_sglist(&msg->out);
	int			onents = vmsg_sglist_nents(&msg->out);

	if (ow_params->tx_stat.first_time) {
		size_t	data_len = 0;
		int	i;

		for (i = 0; i < onents; i++)
			data_len += osglist[i].iov_len;

		ow_params->tx_stat.xlen = msg->out.header.iov_len + data_len;

		ow_params->tx_stat.start_time = get_cpu_usecs();
		ow_params->tx_stat.first_time = 0;

		data_len = ow_params->tx_stat.xlen/1024;
		ow_params->tx_stat.print_counter = data_len ?
			PRINT_COUNTER/data_len : PRINT_COUNTER;
		if (ow_params->tx_stat.print_counter < 1000)
			ow_params->tx_stat.print_counter = 1000;
		ow_params->disconnect_nr =
			ow_params->tx_stat.print_counter * DISCONNECT_FACTOR;
	}
	if (++ow_params->tx_stat.cnt == ow_params->tx_stat.print_counter) {
		char		timeb[40];

		uint64_t delta =
			get_cpu_usecs() - ow_params->tx_stat.start_time;
		uint64_t pps = (ow_params->tx_stat.cnt*USECS_IN_SEC)/delta;

		double txbw = (1.0*pps*ow_params->tx_stat.xlen/ONE_MB);

		printf("transactions per second: %lu, bandwidth: " \
		       "TX %.2f MB/s,length: TX: %zd B\n",
		       pps, txbw, ow_params->tx_stat.xlen);
		get_time(timeb, 40);
		printf("**** [%s] - message [%lu] %s - %s\n",
		       timeb, (msg->sn + 1),
		       (char *)msg->out.header.iov_base,
		       (char *)(onents > 0 ? osglist[0].iov_base : NULL));
		ow_params->tx_stat.cnt = 0;
		ow_params->tx_stat.start_time = get_cpu_usecs();
	}
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct ow_test_params *ow_params =
				(struct ow_test_params *)cb_user_context;

	printf("session event: %s. reason: %s\n",
	       xio_session_event_str(event_data->event),
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_context_stop_loop(ow_params->ctx);  /* exit */
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
	printf("**** [%p] session established\n", session);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_message_delivered							     */
/*---------------------------------------------------------------------------*/
static int on_message_delivered(struct xio_session *session,
				struct xio_msg *msg,
				int last_in_rxq,
				void *cb_user_context)
{
	struct ow_test_params *ow_params =
				(struct ow_test_params *)cb_user_context;
	struct xio_msg *new_msg;

	process_tx_message(ow_params, msg);
	ow_params->ndelivered++;

	/* can be safely returned to pool */
	msg_pool_put(ow_params->pool, msg);

	if (ow_params->finite_run) {
		if (ow_params->ndelivered == ow_params->disconnect_nr) {
			xio_disconnect(ow_params->conn);
			return 0;
		}

		if (ow_params->nsent == ow_params->disconnect_nr)
			return 0;
	}

	/* peek message from the pool */
	new_msg = msg_pool_get(ow_params->pool);
	if (new_msg == NULL) {
		printf("pool is empty\n");
		return 0;
	}

	/* assign buffers to the message */
	msg_build_out_sgl(&ow_params->msg_params, new_msg,
		  test_config.hdr_len,
		  1, test_config.data_len);

	/*
	 * ask for receipt since we need to put the message back
	 * to pool
	 */
	 new_msg->flags = XIO_MSG_FLAG_REQUEST_READ_RECEIPT;

	/* send it */
	if (xio_send_msg(ow_params->conn, new_msg) == -1) {
		if (xio_errno() != EAGAIN)
			printf("**** [%p] Error - xio_send_msg " \
					"failed. %s\n",
					session,
					xio_strerror(xio_errno()));
		msg_pool_put(ow_params->pool, new_msg);
		xio_assert(0);
	}
	ow_params->nsent++;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_server_message							     */
/*---------------------------------------------------------------------------*/
static int on_server_message(struct xio_session *session,
			     struct xio_msg *msg,
			     int last_in_rxq,
			     void *cb_user_context)
{
	struct ow_test_params *ow_params =
				(struct ow_test_params *)cb_user_context;

	/* server send message */

	/* process the incoming message */
	process_rx_message(ow_params, msg);

	/* message is no longer needed */
	xio_release_msg(msg);

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
	struct ow_test_params *ow_params =
				(struct ow_test_params *)cb_user_context;

	printf("**** [%p] message [%lu] failed. reason: %s\n",
	       session, msg->sn, xio_strerror(error));

	msg_pool_put(ow_params->pool, msg);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* assign_data_in_buf							     */
/*---------------------------------------------------------------------------*/
static int assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	struct xio_iovec_ex	*sglist = vmsg_sglist(&msg->in);
	struct ow_test_params	*ow_params =
				(struct ow_test_params *)cb_user_context;

	vmsg_sglist_set_nents(&msg->in, 1);
	if (ow_params->reg_mem.addr == NULL)
		xio_mem_alloc(XIO_READ_BUF_LEN, &ow_params->reg_mem);

	sglist[0].iov_base = ow_params->reg_mem.addr;
	sglist[0].mr = ow_params->reg_mem.mr;
	sglist[0].iov_len = XIO_READ_BUF_LEN;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  on_session_established,
	.on_msg				=  on_server_message,
	.on_msg_send_complete		=  NULL,
	.on_msg_delivered		=  on_message_delivered,
	.on_msg_error			=  on_msg_error,
	.assign_data_in_buf		=  assign_data_in_buf
};

/*---------------------------------------------------------------------------*/
/* usage                                                                     */
/*---------------------------------------------------------------------------*/
static void usage(const char *argv0, int status)
{
	printf("Usage:\n");
	printf("  %s [OPTIONS] <host>\tConnect to server at <host>\n", argv0);
	printf("\n");
	printf("Options:\n");

	printf("\t-c, --cpu=<cpu num> ");
	printf("\t\tBind the process to specific cpu (default 0)\n");

	printf("\t-p, --port=<port> ");
	printf("\t\tConnect to port <port> (default %d)\n",
	       XIO_DEF_PORT);

	printf("\t-r, --transport=<type> ");
	printf("\t\tUse rdma/tcp as transport <type> (default %s)\n",
	       XIO_DEF_TRANSPORT);

	printf("\t-n, --header-len=<number> ");
	printf("\tSet the header length of the message to <number> bytes " \
			"(default %d)\n", XIO_DEF_HEADER_SIZE);

	printf("\t-w, --data-len=<length> ");
	printf("\tSet the data length of the message to <number> bytes " \
			"(default %d)\n", XIO_DEF_DATA_SIZE);

	printf("\t-f, --finite-run=<finite-run> ");
	printf("\t0 for infinite run, 1 for infinite run" \
			"(default 0)\n");

	printf("\t-v, --version ");
	printf("\t\t\tPrint the version and exit\n");

	printf("\t-h, --help ");
	printf("\t\t\tDisplay this help and exit\n");

	exit(status);
}

/*---------------------------------------------------------------------------*/
/* parse_cmdline							     */
/*---------------------------------------------------------------------------*/
int parse_cmdline(struct xio_test_config *test_config, int argc, char **argv)
{
	while (1) {
		int c;

		static struct option const long_options[] = {
			{ .name = "cpu",	.has_arg = 1, .val = 'c'},
			{ .name = "port",	.has_arg = 1, .val = 'p'},
			{ .name = "transport",	.has_arg = 1, .val = 'r'},
			{ .name = "header-len",	.has_arg = 1, .val = 'n'},
			{ .name = "data-len",	.has_arg = 1, .val = 'w'},
			{ .name = "index",	.has_arg = 1, .val = 'i'},
			{ .name = "finite-run",	.has_arg = 1, .val = 'f'},
			{ .name = "version",	.has_arg = 0, .val = 'v'},
			{ .name = "help",	.has_arg = 0, .val = 'h'},
			{0, 0, 0, 0},
		};

		static char *short_options = "c:p:r:n:w:i:f:vh";
		optopt = 0;
		opterr = 0;

		c = getopt_long(argc, argv, short_options,
				long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			test_config->cpu =
				(uint16_t)strtol(optarg, NULL, 0);
			break;
		case 'p':
			test_config->server_port =
				(uint16_t)strtol(optarg, NULL, 0);
			break;
		case 'r':
			strcpy(test_config->transport, optarg);
			break;
		case 'n':
			test_config->hdr_len =
				(uint32_t)strtol(optarg, NULL, 0);
		break;
		case 'w':
			test_config->data_len =
				(uint32_t)strtol(optarg, NULL, 0);
			break;
		case 'i':
			test_config->conn_idx =
				(uint32_t)strtol(optarg, NULL, 0);
			break;
		case 'f':
			test_config->finite_run =
					(uint16_t)strtol(optarg, NULL, 0);
			break;
		case 'v':
			printf("version: %s\n", XIO_TEST_VERSION);
			exit(0);
			break;
		case 'h':
			usage(argv[0], 0);
			break;
		default:
			fprintf(stderr, " invalid command or flag.\n");
			fprintf(stderr,
				" please check command line and run again.\n\n");
			usage(argv[0], -1);
			xio_assert(0);
		}
	}
	if (optind == argc - 1) {
		strcpy(test_config->server_addr, argv[optind]);
	} else if (optind < argc) {
		fprintf(stderr,
			" Invalid Command line.Please check command rerun\n");
		exit(-1);
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
	printf(" =============================================\n");
	printf(" Server Address		: %s\n", test_config_p->server_addr);
	printf(" Server Port		: %u\n", test_config_p->server_port);
	printf(" Transport		: %s\n", test_config_p->transport);
	printf(" Header Length		: %u\n", test_config_p->hdr_len);
	printf(" Data Length		: %u\n", test_config_p->data_len);
	printf(" Connection Index	: %u\n", test_config_p->conn_idx);
	printf(" CPU Affinity		: %x\n", test_config_p->cpu);
	printf(" Finite run		: %x\n", test_config_p->finite_run);
	printf(" =============================================\n");
}
/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct xio_session	*session;
	struct ow_test_params	ow_params;
	int			error;
	int			retval;
	char			url[256];
	struct xio_msg		*msg;
	int			i = 0;
	struct xio_session_params params;
	struct xio_connection_params cparams;

	/* parse the command line */
	if (parse_cmdline(&test_config, argc, argv) != 0)
		return -1;

	/* print the input */
	print_test_config(&test_config);

	/* bind proccess to cpu */
	set_cpu_affinity(test_config.cpu);

	xio_init();

	memset(&ow_params, 0, sizeof(ow_params));
	memset(&params, 0, sizeof(params));
	memset(&cparams, 0, sizeof(cparams));
	ow_params.rx_stat.first_time = 1;
	ow_params.tx_stat.first_time = 1;
	ow_params.finite_run = test_config.finite_run;

	/* prepare buffers for this test */
	if (msg_api_init(&ow_params.msg_params,
			 test_config.hdr_len, test_config.data_len, 0) != 0)
		return -1;

	ow_params.pool = msg_pool_alloc(MAX_POOL_SIZE, 1, 1);
	if (ow_params.pool == NULL)
		goto cleanup;


	/* open xio context and assign a loop */
	ow_params.ctx = xio_context_create(NULL, 0, test_config.cpu);
	if (ow_params.ctx == NULL) {
		error = xio_errno();
		fprintf(stderr, "context creation failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_assert(ow_params.ctx != NULL);
	}

	/* create a url and open session */
	sprintf(url, "%s://%s:%d",
		test_config.transport,
		test_config.server_addr,
		test_config.server_port);

	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.user_context	= &ow_params;
	params.uri		= url;

	session = xio_session_create(&params);
	if (session == NULL) {
		error = xio_errno();
		fprintf(stderr, "session creation failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_assert(session != NULL);
	}
	/* connect the session  */
	cparams.session			= session;
	cparams.ctx			= ow_params.ctx;
	cparams.conn_idx		= test_config.conn_idx;
	cparams.conn_user_context	= &ow_params;

	ow_params.conn = xio_connect(&cparams);
	if (ow_params.conn == NULL) {
		error = xio_errno();
		fprintf(stderr, "connection creation failed. " \
			"reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_assert(ow_params.conn != NULL);
	}

	printf("**** starting ...\n");
	for (i = 0; i < MAX_OUTSTANDING_REQS; i++) {
		/* pick message from the pool */
		msg = msg_pool_get(ow_params.pool);
		if (msg == NULL)
			break;

		/* assign buffers to the message */
		msg_build_out_sgl(&ow_params.msg_params, msg,
			  test_config.hdr_len,
			  1, test_config.data_len);

		/* ask for read receipt since the message needed to be
		 * recycled to the pool */
		msg->flags = XIO_MSG_FLAG_REQUEST_READ_RECEIPT;

		/* send the message */
		if (xio_send_msg(ow_params.conn, msg) == -1) {
			printf("**** sent %d messages\n", i);
			if (xio_errno() != EAGAIN)
				printf("**** [%p] Error - xio_send_msg " \
				       "failed. %s\n",
					session,
					xio_strerror(xio_errno()));
			msg_pool_put(ow_params.pool, msg);
			return 0;
		}
		ow_params.nsent++;
	}

	/* the default xio supplied main loop */
	retval = xio_context_run_loop(ow_params.ctx, XIO_INFINITE);
	if (retval != 0) {
		error = xio_errno();
		fprintf(stderr, "running event loop failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_assert(retval == 0);
	}

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	retval = xio_session_destroy(session);
	if (retval != 0) {
		error = xio_errno();
		fprintf(stderr, "session close failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_assert(retval == 0);
	}

	xio_context_destroy(ow_params.ctx);

	if (ow_params.pool)
		msg_pool_free(ow_params.pool);

	if (ow_params.reg_mem.addr)
		xio_mem_free(&ow_params.reg_mem);

cleanup:
	msg_api_free(&ow_params.msg_params);

	xio_shutdown();

	fprintf(stdout, "exit complete\n");

	return 0;
}

