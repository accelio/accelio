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
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>

#include "libxio.h"
#include "xio_msg.h"
#include "xio_test_utils.h"

#define MAX_POOL_SIZE		2048

#define XIO_DEF_ADDRESS		"127.0.0.1"
#define XIO_DEF_PORT		2061
#define XIO_DEF_TRANSPORT	"rdma"
#define XIO_DEF_HEADER_SIZE	32
#define XIO_DEF_DATA_SIZE	32
#define XIO_DEF_CPU		0
#define XIO_TEST_VERSION	"1.0.0"
#define XIO_READ_BUF_LEN	(1024*1024)
#define POLLING_TIMEOUT		25
#define PRINT_COUNTER		4000000

struct xio_test_config {
	char			server_addr[32];
	uint16_t		server_port;
	char			transport[16];
	uint16_t		cpu;
	uint32_t		hdr_len;
	uint32_t		data_len;
	uint16_t		finite_run;
	uint16_t		padding;
};

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static struct msg_pool		*pool;
static struct xio_context	*ctx;
static struct xio_reg_mem	reg_mem;
static struct msg_params	msg_params;


static struct xio_test_config  test_config = {
	.server_addr = XIO_DEF_ADDRESS,
	.server_port = XIO_DEF_PORT,
	.transport = XIO_DEF_TRANSPORT,
	.cpu = XIO_DEF_CPU,
	.hdr_len = XIO_DEF_HEADER_SIZE,
	.data_len = XIO_DEF_DATA_SIZE,
	.finite_run = 0,
	.padding = 0,
};

/*---------------------------------------------------------------------------*/
/* process_request							     */
/*---------------------------------------------------------------------------*/
static void process_request(struct xio_msg *msg)
{
	static int cnt;

	if (msg == NULL) {
		cnt = 0;
		return;
	}
	if (++cnt == PRINT_COUNTER) {
		struct xio_iovec_ex *sglist = vmsg_sglist(&msg->in);

		printf("**** message [%lu] %s - %s\n",
		       (msg->sn+1),
		       (char *)msg->in.header.iov_base,
		       (char *)sglist[0].iov_base);
		cnt = 0;
	}
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_prv_data)
{
	printf("session event: %s. session:%p, connection:%p, reason: %s\n",
	       xio_session_event_str(event_data->event),
	       session, event_data->conn,
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		process_request(NULL);
		xio_session_destroy(session);
		if (test_config.finite_run)
			xio_context_stop_loop(ctx); /* exit */
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
			  void *cb_prv_data)
{
	printf("**** [%p] on_new_session :%s:%d\n", session,
	       get_ip((struct sockaddr *)&req->src_addr),
	       get_port((struct sockaddr *)&req->src_addr));

	xio_accept(session, NULL, 0, NULL, 0);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_request								     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session, struct xio_msg *req,
		      int last_in_rxq, void *cb_prv_data)
{
	struct xio_msg	*rsp;

	/* process request */
	process_request(req);

	/* alloc transaction */
	rsp	= msg_pool_get(pool);

	rsp->request		= req;

	/* fill response */
	msg_build_out_sgl(&msg_params, rsp,
		  test_config.hdr_len,
		  1, test_config.data_len);

	if (xio_send_response(rsp) == -1) {
		printf("**** [%p] Error - xio_send_msg failed. %s\n",
		       session, xio_strerror(xio_errno()));
		msg_pool_put(pool, req);
		xio_assert(0);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_send_response_complete						     */
/*---------------------------------------------------------------------------*/
static int on_send_response_complete(struct xio_session *session,
				     struct xio_msg *msg,
				     void *cb_prv_data)
{
	/* can be safely freed */
	msg_pool_put(pool, msg);

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
	case XIO_E_MSG_DISCARDED:
	case XIO_E_MSG_FLUSHED:
		break;
	default:
		/* need to send response here */
		xio_assert(0);
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* assign_data_in_buf							     */
/*---------------------------------------------------------------------------*/
int assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	struct xio_iovec_ex	*sglist = vmsg_sglist(&msg->in);

	vmsg_sglist_set_nents(&msg->in, 1);
	if (reg_mem.addr == NULL)
		xio_mem_alloc(XIO_READ_BUF_LEN, &reg_mem);

	sglist[0].iov_base = reg_mem.addr;
	sglist[0].mr =	reg_mem.mr;
	sglist[0].iov_len = XIO_READ_BUF_LEN;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops server_ops = {
	.on_session_event		=  on_session_event,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  on_send_response_complete,
	.on_msg				=  on_request,
	.on_msg_error			=  on_msg_error,
	.assign_data_in_buf		=  assign_data_in_buf
};

/*---------------------------------------------------------------------------*/
/* usage                                                                     */
/*---------------------------------------------------------------------------*/
static void usage(const char *argv0, int status)
{
	printf("Usage:\n");
	printf("  %s [OPTIONS]\t\t\tStart a server and wait for connection\n",
	       argv0);
	printf("\n");
	printf("Options:\n");

	printf("\t-c, --cpu=<cpu num> ");
	printf("\t\tBind the process to specific cpu (default 0)\n");

	printf("\t-p, --port=<port> ");
	printf("\t\tListen on port <port> (default %d)\n",
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
			{ .name = "core",	.has_arg = 1, .val = 'c'},
			{ .name = "port",	.has_arg = 1, .val = 'p'},
			{ .name = "transport",	.has_arg = 1, .val = 'r'},
			{ .name = "header-len",	.has_arg = 1, .val = 'n'},
			{ .name = "data-len",	.has_arg = 1, .val = 'w'},
			{ .name = "finite",	.has_arg = 1, .val = 'f'},
			{ .name = "version",	.has_arg = 0, .val = 'v'},
			{ .name = "help",	.has_arg = 0, .val = 'h'},
			{0, 0, 0, 0},
		};

		static char *short_options = "c:p:r:n:w:f:svh";

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
		case 'f':
			test_config->finite_run =
					(uint32_t)strtol(optarg, NULL, 0);
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
	printf(" CPU Affinity		: %x\n", test_config_p->cpu);
	printf(" Finite run		: %u\n", test_config_p->finite_run);
	printf(" =============================================\n");
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct xio_server	*server;
	char			url[256];
	int			opt;

	xio_init();
	if (parse_cmdline(&test_config, argc, argv) != 0)
		return -1;

	memset(&reg_mem, 0, sizeof reg_mem);
	print_test_config(&test_config);

	set_cpu_affinity(test_config.cpu);

	opt = 1;
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_TCP, XIO_OPTNAME_TCP_NO_DELAY,
		    &opt, sizeof(int));

	ctx	= xio_context_create(NULL, POLLING_TIMEOUT, test_config.cpu);

	if (msg_api_init(&msg_params,
			 test_config.hdr_len, test_config.data_len, 1) != 0)
		return -1;

	pool = msg_pool_alloc(MAX_POOL_SIZE, 0, 1);

	sprintf(url, "%s://%s:%d",
		test_config.transport,
		test_config.server_addr,
		test_config.server_port);

	server = xio_bind(ctx, &server_ops, url, NULL, 0, NULL);
	if (server) {
		printf("listen to %s\n", url);
		xio_context_run_loop(ctx, XIO_INFINITE);

		/* normal exit phase */
		fprintf(stdout, "exit signaled\n");

		/* free the server */
		xio_unbind(server);
	} else {
		printf("**** Error - xio_bind failed. %s\n",
		       xio_strerror(xio_errno()));
		xio_context_destroy(ctx);
		xio_assert(0);
	}

	if (pool)
		msg_pool_free(pool);
	pool = NULL;

	if (reg_mem.addr)
		xio_mem_free(&reg_mem);

	xio_context_destroy(ctx);

	return 0;
}

