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
#define PRINT_COUNTER		100000
#define XIO_DEF_ADDRESS		"127.0.0.1"
#define XIO_DEF_PORT		2061
#define XIO_DEF_TRANSPORT	"rdma"
#define XIO_DEF_HEADER_SIZE	32
#define XIO_DEF_DATA_SIZE	32
#define XIO_DEF_CPU		0
#define XIO_TEST_VERSION	"1.0.0"

#define MAX_POOL_SIZE		2048
#define ONE_MB			(1 << 20)
#define POLLING_TIMEOUT		25
#define DISCONNECT_FACTOR	3

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

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static struct msg_pool		*pool;
static uint64_t			print_counter;
static struct xio_connection	*conn;
static struct xio_context	*ctx;
static uint64_t nrecv;
static uint64_t			disconnect_nr;
static struct msg_params	msg_params;

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
static void process_response(struct xio_msg *rsp)
{
	struct xio_iovec_ex	*isglist = vmsg_sglist(&rsp->in);
	int			inents = vmsg_sglist_nents(&rsp->in);
	static uint64_t		cnt;
	static int		first_time = 1;
	static uint64_t		start_time;
	static size_t		txlen, rxlen;

	if (first_time) {
		struct xio_iovec_ex	*osglist = vmsg_sglist(&rsp->out);
		int			onents = vmsg_sglist_nents(&rsp->out);
		size_t			data_len = 0;
		int			i;

		for (i = 0; i < onents; i++)
			data_len += osglist[i].iov_len;

		txlen = rsp->out.header.iov_len + data_len;

		data_len = 0;
		for (i = 0; i < inents; i++)
			data_len += isglist[i].iov_len;

		rxlen = rsp->in.header.iov_len + data_len;

		start_time = get_cpu_usecs();
		first_time = 0;
		disconnect_nr = print_counter * DISCONNECT_FACTOR;
	}

	if (++cnt == print_counter) {
		char		timeb[40];

		uint64_t delta = get_cpu_usecs() - start_time;
		uint64_t pps = (cnt*USECS_IN_SEC)/delta;

		double txbw = (1.0*pps*txlen/ONE_MB);
		double rxbw = (1.0*pps*rxlen/ONE_MB);
		double lat = (1000000.0/pps);

		printf("transactions per second: %lu, lat: %.2f us, bandwidth: " \
		       "TX %.2f MB/s, RX: %.2f MB/s, length: TX: %zd B, RX: %zd B\n",
		       pps, lat, txbw, rxbw, txlen, rxlen);
		get_time(timeb, 40);
		/*
		printf("**** [%s] - message [%lu] %s - %s\n",
		       timeb, (rsp->request->sn + 1),
		       (char *)rsp->in.header.iov_base,
		       (char *)(inents > 0 ? isglist[0].iov_base : NULL));
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

	printf("**** starting ...\n");

	/* create transaction */
	msg = msg_pool_get(pool);
	if (msg == NULL)
		return 0;

	/* get pointers to internal buffers */
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	vmsg_sglist_set_nents(&msg->in, 0);

	/*
	   sglist = vmsg_sglist(&msg->in);
	   sglist[0].iov_base = NULL;
	   sglist[0].iov_len  = ONE_MB;
	   sglist[0].mr = NULL;
	   vmsg_sglist_set_nents(&msg->in, 1);
	   */

	/* recycle the message and fill new request */
	msg_build_out_sgl(&msg_params, msg,
			test_config.hdr_len,
			1, test_config.data_len);

	/* try to send it */
	if (xio_send_request(conn, msg) == -1) {
		printf("**** sent %d messages\n", 1);
		if (xio_errno() != EAGAIN)
			printf("**** [%p] Error - xio_send_msg " \
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
	printf("session event: %s. reason: %s\n",
	       xio_session_event_str(event_data->event),
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_ESTABLISHED_EVENT:
		on_connection_established(event_data->conn);
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
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
	printf("**** [%p] session established\n", session);

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
	/*struct xio_iovec_ex	*sglist; */

	process_response(msg);

	/* message is no longer needed */
	xio_release_response(msg);

	nrecv++;

	if (test_config.finite_run) {
		if (nrecv == disconnect_nr) {
			xio_disconnect(conn);
			return 0;
		}
		if (nrecv > disconnect_nr)
			return 0;
	}

	/* reset message */
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	vmsg_sglist_set_nents(&msg->in, 0);

	/*
	sglist = vmsg_sglist(&msg->in);
	sglist[0].iov_base = NULL;
	sglist[0].iov_len  = ONE_MB;
	sglist[0].mr = NULL;
	vmsg_sglist_set_nents(&msg->in, 1);
	*/
	msg->sn = 0;

	/* recycle the message and fill new request */
	msg_build_out_sgl(&msg_params, msg,
			test_config.hdr_len,
			1, test_config.data_len);

	/* try to send it */
	if (xio_send_request(conn, msg) == -1) {
		if (xio_errno() != EAGAIN)
			printf("**** [%p] Error - xio_send_msg " \
					"failed %s\n",
					session,
					xio_strerror(xio_errno()));
		msg_pool_put(pool, msg);
		xio_assert(0);
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
	printf("**** [%p] message [%lu] failed. reason: %s\n",
	       session, msg->sn, xio_strerror(error));

	msg_pool_put(pool, msg);

	switch (error) {
	case XIO_E_MSG_FLUSHED:
		break;
	default:
		xio_assert(0);
		break;
	};

	return 0;
}
/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  on_session_established,
	.on_msg				=  on_response,
	.on_msg_error			=  on_msg_error
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
			{ .name = "finite_run",	.has_arg = 1, .val = 'i'},
			{ .name = "version",	.has_arg = 0, .val = 'v'},
			{ .name = "help",	.has_arg = 0, .val = 'h'},
			{0, 0, 0, 0},
		};

		static char *short_options = "c:p:r:n:w:f:i:vh";

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
	struct xio_session		*session;
	int				error;
	int				retval;
	char				url[256];
	/*struct xio_iovec_ex		*sglist; */
	int				opt;
	struct xio_session_params	params;
	struct xio_connection_params	cparams;

	xio_init();
	if (parse_cmdline(&test_config, argc, argv) != 0)
		return -1;

	print_counter = PRINT_COUNTER;

	print_test_config(&test_config);

	set_cpu_affinity(test_config.cpu);

	/* disable nagle algorithm for tcp */
	opt = 1;
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_TCP, XIO_OPTNAME_TCP_NO_DELAY,
		    &opt, sizeof(int));

	ctx = xio_context_create(NULL, POLLING_TIMEOUT, test_config.cpu);
	if (ctx == NULL) {
		error = xio_errno();
		fprintf(stderr, "context creation failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_assert(ctx != NULL);
	}

	if (msg_api_init(&msg_params,
			 test_config.hdr_len, test_config.data_len, 0) != 0)
		return -1;

	sprintf(url, "%s://%s:%d",
		test_config.transport,
		test_config.server_addr,
		test_config.server_port);

	memset(&params, 0, sizeof(params));
	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.uri		= url;

	session = xio_session_create(&params);
	if (session == NULL) {
		error = xio_errno();
		fprintf(stderr, "session creation failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_assert(session != NULL);
	}
	pool = msg_pool_alloc(MAX_POOL_SIZE, 1, 1);

	/* connect the session  */
	memset(&cparams, 0, sizeof(cparams));
	cparams.session		= session;
	cparams.ctx		= ctx;
	cparams.conn_idx	= test_config.conn_idx;

	conn = xio_connect(&cparams);

	/* the default xio supplied main loop */
	retval = xio_context_run_loop(ctx, XIO_INFINITE);
	if (retval != 0) {
		error = xio_errno();
		fprintf(stderr, "running event loop failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_context_destroy(ctx);
		xio_assert(retval == 0);
	}

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");


	retval = xio_session_destroy(session);
	if (retval != 0) {
		error = xio_errno();
		fprintf(stderr, "session close failed. reason %d - (%s)\n",
			error, xio_strerror(error));
	}

	xio_context_destroy(ctx);

	fprintf(stdout, "exit complete\n");

	return 0;
}

