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
#define __GNU_SOURCE
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
/* will disconnect after DISCONNECT_FACTOR*print counter msgs */
#define DISCONNECT_FACTOR	3
#define ASK_FOR_RECEIPT		0


#define MAX_POOL_SIZE		MAX_OUTSTANDING_REQS
#define ONE_MB			(1 << 20)

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

struct test_stat {
	uint64_t		cnt;
	uint64_t		start_time;
	uint64_t		print_counter;
	int			first_time;
	int			pad;
	size_t			rxlen;
	size_t			txlen;
};

struct test_params {
	struct msg_pool		*pool;
	struct xio_connection	*connection;
	struct xio_context	*ctx;
	struct test_stat	stat;
	struct msg_params	msg_params;
	uint64_t		nsent;
	uint64_t		ncomp;
	uint64_t		ndelivered;
	int			ask_for_receipt;
	uint16_t		finite_run;
	uint16_t		closed;
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
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_message(struct test_params *test_params,
			    struct xio_msg *msg)
{
	struct xio_iovec_ex	*osglist = vmsg_sglist(&msg->out);
	int			onents = vmsg_sglist_nents(&msg->out);

	if (test_params->stat.first_time) {
		size_t	data_len = 0;
		int	i;

for (i = 0; i < onents; i++)
			data_len += osglist[i].iov_len;

		test_params->stat.txlen = msg->out.header.iov_len + data_len;

		test_params->stat.start_time = get_cpu_usecs();
		test_params->stat.first_time = 0;

		data_len = test_params->stat.txlen/1024;
		test_params->stat.print_counter = (data_len ?
				 PRINT_COUNTER/data_len : PRINT_COUNTER);
		if (test_params->stat.print_counter < 1000)
			test_params->stat.print_counter = 1000;
		test_params->disconnect_nr =
			test_params->stat.print_counter * DISCONNECT_FACTOR;
	}
	if (++test_params->stat.cnt == test_params->stat.print_counter) {
		uint64_t delta = get_cpu_usecs() - test_params->stat.start_time;
		uint64_t pps = (test_params->stat.cnt*USECS_IN_SEC)/delta;

		double txbw = (1.0*pps*test_params->stat.txlen/ONE_MB);

		printf("transactions per second: %lu, bandwidth: " \
		       "TX %.2f MB/s, length: TX: %zd B\n",
		       pps, txbw,
		       test_params->stat.txlen);

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
	struct test_params *test_params = (struct test_params *)cb_user_context;

	printf("session event: %s. reason: %s\n",
	       xio_session_event_str(event_data->event),
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_CLOSED_EVENT:
	case XIO_SESSION_CONNECTION_DISCONNECTED_EVENT:
		test_params->closed = 1;
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		printf("nsent:%lu, ncomp:%lu, " \
		       "delta:%lu\n",
		       test_params->nsent, test_params->ncomp,
		       test_params->nsent-test_params->ncomp);

		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_REJECT_EVENT:
	case XIO_SESSION_TEARDOWN_EVENT:
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
	printf("**** [%p] session established\n", session);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_msg_delivered							     */
/*---------------------------------------------------------------------------*/
static int on_msg_delivered(struct xio_session *session, struct xio_msg *msg,
			    int last_in_rxq, void *cb_user_context)
{
	struct test_params *test_params = (struct test_params *)cb_user_context;
	test_params->ndelivered++;

	process_message(test_params, msg);

	/* can be safely freed */
	msg_pool_put(test_params->pool, msg);

	if (test_params->finite_run) {
		if ((test_params->ncomp+test_params->ndelivered) >
		       test_params->disconnect_nr)
			return 0;
		if ((test_params->ncomp + test_params->ndelivered) ==
		     test_params->disconnect_nr) {
			xio_disconnect(test_params->connection);
			return 0;
		}
	}
	if (test_params->closed)
		return 0;


	/* peek message from the pool */
	msg = msg_pool_get(test_params->pool);
	if (msg == NULL) {
		printf("pool is empty\n");
		return 0;
	}

	/* reset message */
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len	= 0;
	msg->in.data_iov.nents	= 0;

	/* assign buffers to the message */
	msg_build_out_sgl(&test_params->msg_params, msg,
		  test_config.hdr_len,
		  1, test_config.data_len);

	/* try to send it */
	if (test_params->ask_for_receipt)
		msg->flags = XIO_MSG_FLAG_REQUEST_READ_RECEIPT;
	else
		msg->flags = 0;


	if (xio_send_msg(test_params->connection, msg) == -1) {
		if (xio_errno() != EAGAIN)
			printf("**** [%p] Error - xio_send_request " \
					"failed %s\n",
					session,
					xio_strerror(xio_errno()));
		msg_pool_put(test_params->pool, msg);
		xio_assert(0);
	}
	test_params->nsent++;


	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_msg_send_complete							     */
/*---------------------------------------------------------------------------*/
static int on_msg_send_complete(struct xio_session *session,
				struct xio_msg *msg,
				void *cb_user_context)
{
	struct test_params *test_params = (struct test_params *)cb_user_context;
	process_message(test_params, msg);

	test_params->ncomp++;

	/* can be safely freed */
	msg_pool_put(test_params->pool, msg);

	if (test_params->finite_run) {
		if ((test_params->ncomp+test_params->ndelivered) >
		       test_params->disconnect_nr)
			return 0;
		if ((test_params->ncomp + test_params->ndelivered) ==
		     test_params->disconnect_nr) {
			xio_disconnect(test_params->connection);
			return 0;
		}
	}

	if (test_params->closed)
		return 0;

	/* peek message from the pool */
	msg = msg_pool_get(test_params->pool);
	if (msg == NULL) {
		printf("pool is empty\n");
		return 0;
	}

	/* reset message */
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len	= 0;
	msg->in.data_iov.nents	= 0;

	/* assign buffers to the message */
	msg_build_out_sgl(&test_params->msg_params, msg,
		  test_config.hdr_len,
		  1, test_config.data_len);

	/* try to send it */
	if (test_params->ask_for_receipt)
		msg->flags = XIO_MSG_FLAG_REQUEST_READ_RECEIPT;
	else
		msg->flags = 0;



	if (xio_send_msg(test_params->connection, msg) == -1) {
		if (xio_errno() != EAGAIN)
			printf("**** [%p] Error - xio_send_request " \
					"failed %s\n",
					session,
					xio_strerror(xio_errno()));
		msg_pool_put(test_params->pool, msg);
		xio_assert(0);
	}
	test_params->nsent++;

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
	struct test_params *test_params = (struct test_params *)cb_user_context;

	printf("**** [%p] message [%lu] failed. reason: %s\n",
	       session, msg->sn, xio_strerror(error));

	msg_pool_put(test_params->pool, msg);

	return 0;
}
/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  on_session_established,
	.on_msg_delivered		=  on_msg_delivered,
	.on_msg				=  NULL,
	.on_msg_error			=  on_msg_error,
	.on_ow_msg_send_complete	=  on_msg_send_complete
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
	optind = 0;
	opterr = 0;


	while (1) {
		int c;

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
			exit(-1);
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
	struct test_params	test_params;
	int			error;
	int			retval;
	char			url[256];
	struct xio_msg		*msg;
	int			i = 0;
	struct xio_session_params params;
	struct xio_connection_params cparams;

	if (parse_cmdline(&test_config, argc, argv) != 0)
		return -1;

	print_test_config(&test_config);

	set_cpu_affinity(test_config.cpu);

	xio_init();

	memset(&test_params, 0, sizeof(struct test_params));
	memset(&params, 0, sizeof(params));
	memset(&cparams, 0, sizeof(cparams));
	test_params.stat.first_time = 1;
	test_params.ask_for_receipt = ASK_FOR_RECEIPT;
	test_params.finite_run = test_config.finite_run;

	/* prepare buffers for this test */
	if (msg_api_init(&test_params.msg_params,
			 test_config.hdr_len, test_config.data_len, 0) != 0)
		return -1;

	test_params.pool = msg_pool_alloc(MAX_POOL_SIZE, 0, 1);
	if (test_params.pool == NULL)
		goto cleanup;

	test_params.ctx = xio_context_create(NULL, 0, test_config.cpu);
	if (test_params.ctx == NULL) {
		error = xio_errno();
		fprintf(stderr, "context creation failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_assert(test_params.ctx != NULL);
	}

	sprintf(url, "%s://%s:%d",
		test_config.transport,
		test_config.server_addr,
		test_config.server_port);

	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.user_context	= &test_params;
	params.uri		= url;

	session = xio_session_create(&params);
	if (session == NULL) {
		error = xio_errno();
		fprintf(stderr, "session creation failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_assert(session != NULL);
	}

	cparams.session			= session;
	cparams.ctx			= test_params.ctx;
	cparams.conn_idx		= test_config.conn_idx;
	cparams.conn_user_context	= &test_params;

	/* connect the session  */
	test_params.connection = xio_connect(&cparams);

	printf("**** starting ...\n");
	for (i = 0; i < MAX_OUTSTANDING_REQS; i++) {
		/* create transaction */
		msg = msg_pool_get(test_params.pool);
		if (msg == NULL)
			break;

		/* get pointers to internal buffers */
		msg->in.header.iov_base = NULL;
		msg->in.header.iov_len	= 0;
		vmsg_sglist_set_nents(&msg->in, 0);

		/* assign buffers to the message */
		msg_build_out_sgl(&test_params.msg_params, msg,
			  test_config.hdr_len,
			  1, test_config.data_len);

		/* try to send it */
		if (test_params.ask_for_receipt)
			msg->flags = XIO_MSG_FLAG_REQUEST_READ_RECEIPT;
		else
			msg->flags = 0;


		if (xio_send_msg(test_params.connection, msg) == -1) {
			printf("**** sent %d messages\n", i);
			if (xio_errno() != EAGAIN)
				printf("**** [%p] Error - xio_send_request " \
				       "failed. %s\n",
					session,
					xio_strerror(xio_errno()));
			msg_pool_put(test_params.pool, msg);
			xio_assert(0);
		}
		test_params.nsent++;
	}

	/* the default xio supplied main loop */
	retval = xio_context_run_loop(test_params.ctx, XIO_INFINITE);
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

	xio_context_destroy(test_params.ctx);

	if (test_params.pool)
		msg_pool_free(test_params.pool);
cleanup:
	msg_api_free(&test_params.msg_params);

	xio_shutdown();

	fprintf(stdout, "exit complete\n");

	return 0;
}

