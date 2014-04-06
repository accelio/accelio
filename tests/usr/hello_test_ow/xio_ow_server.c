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
#include <sched.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libxio.h"
#include "xio_msg.h"

#define MAX_POOL_SIZE		6000
#define PRINT_COUNTER		4000000

#define XIO_DEF_ADDRESS		"127.0.0.1"
#define XIO_DEF_PORT		2061
#define XIO_DEF_HEADER_SIZE	32
#define XIO_DEF_DATA_SIZE	32
#define XIO_DEF_CPU		0
#define XIO_TEST_VERSION	"1.0.0"
#define XIO_READ_BUF_LEN	(1024*1024)
#define TEST_DISCONNECT		0
#define DISCONNECT_NR		12000000

struct xio_test_config {
	char		server_addr[32];
	uint16_t	server_port;
	uint16_t	cpu;
	uint32_t	hdr_len;
	uint32_t	data_len;
};

struct test_params {
	struct msg_pool		*pool;
	struct xio_connection	*connection;
	struct xio_context	*ctx;
	char			*buf;
	struct xio_mr		*mr;
	struct msg_params	msg_params;
	uint64_t		nsent;
	uint64_t		nrecv;
};

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static struct xio_test_config  test_config = {
	XIO_DEF_ADDRESS,
	XIO_DEF_PORT,
	XIO_DEF_CPU,
	XIO_DEF_HEADER_SIZE,
	XIO_DEF_DATA_SIZE
};

/*
 * Set CPU affinity to one core.
 */
static void set_cpu_affinity(int cpu)
{
	cpu_set_t coremask;		/* core affinity mask */

	CPU_ZERO(&coremask);
	CPU_SET(cpu, &coremask);
	if (sched_setaffinity(0, sizeof(cpu_set_t), &coremask) != 0)
		fprintf(stderr, "Unable to set affinity. %m\n");
}

/*---------------------------------------------------------------------------*/
/* get_ip								     */
/*---------------------------------------------------------------------------*/
static inline char *get_ip(const struct sockaddr *ip)
{
	if (ip->sa_family == AF_INET) {
		static char addr[INET_ADDRSTRLEN];
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		return (char *)inet_ntop(AF_INET, &(v4->sin_addr),
					 addr, INET_ADDRSTRLEN);
	}
	if (ip->sa_family == AF_INET6) {
		static char addr[INET6_ADDRSTRLEN];
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ip;
		return (char *)inet_ntop(AF_INET6, &(v6->sin6_addr),
					 addr, INET6_ADDRSTRLEN);
	}
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* get_port								     */
/*---------------------------------------------------------------------------*/
static inline uint16_t get_port(const struct sockaddr *ip)
{
	if (ip->sa_family == AF_INET) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		return ntohs(v4->sin_port);
	}
	if (ip->sa_family == AF_INET6) {
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ip;
		return ntohs(v6->sin6_port);
	}
	return 0;
}


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
		printf("**** message [%"PRIu64"] %s - %s\n",
		       (msg->sn+1),
		       (char *)msg->in.header.iov_base,
		       (char *)msg->in.data_iov[0].iov_base);
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
	struct xio_connection_params cparams;
	struct test_params *test_params = cb_user_context;

	printf("session event: %s. session:%p, connection:%p, reason: %s\n",
	       xio_session_event_str(event_data->event),
	       session, event_data->conn,
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		/* assign connection private data */
		cparams.user_context = cb_user_context;
		xio_set_connection_params(event_data->conn, &cparams);
		break;
	case XIO_SESSION_REJECT_EVENT:
		xio_disconnect(event_data->conn);
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		printf("last recv:%"PRIu64"\n",
		       test_params->nrecv);

		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		xio_context_stop_loop(test_params->ctx, 0);
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

	printf("**** [%p] on_new_session :%s:%d\n", session,
	       get_ip((struct sockaddr *)&req->src_addr),
	       get_port((struct sockaddr *)&req->src_addr));

	xio_accept(session, NULL, 0, NULL, 0);

	if (test_params->connection == NULL)
		test_params->connection = xio_get_connection(session,
							     test_params->ctx);


	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_request								     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session,
			struct xio_msg *req,
			int more_in_batch,
			void *cb_user_context)
{
	struct test_params *test_params = cb_user_context;

	test_params->nrecv++;

	if (req->status)
		printf("**** request completed with error. [%s]\n",
		       xio_strerror(req->status));

	/* process request */
	process_request(req);

	xio_release_msg(req);

#if  TEST_DISCONNECT
	if (test_params->nrecv == DISCONNECT_NR) {
		xio_disconnect(test_params->connection);
		return 0;
	}
#endif

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_msg_error								     */
/*---------------------------------------------------------------------------*/
static int on_msg_error(struct xio_session *session,
		enum xio_status error, struct xio_msg  *msg,
		void *cb_user_context)
{
	struct test_params *test_params = cb_user_context;

	printf("**** [%p] message [%"PRIu64"] failed. reason: %s\n",
	       session, msg->request->sn, xio_strerror(error));

//	test_params->nrecv++;
	msg_pool_put(test_params->pool, msg);

	return 0;
}

static int assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	struct test_params *test_params = cb_user_context;
	msg->in.data_iovlen = 1;

	if (test_params->mr == NULL) {
		msg->in.data_iov[0].iov_base = calloc(XIO_READ_BUF_LEN, 1);
		msg->in.data_iov[0].iov_len = XIO_READ_BUF_LEN;
		msg->in.data_iov[0].mr =
			xio_reg_mr(msg->in.data_iov[0].iov_base,
				   msg->in.data_iov[0].iov_len);
		test_params->buf = msg->in.data_iov[0].iov_base;
		test_params->mr = msg->in.data_iov[0].mr;
	} else {
		msg->in.data_iov[0].iov_base = test_params->buf;
		msg->in.data_iov[0].iov_len = XIO_READ_BUF_LEN;
		msg->in.data_iov[0].mr = test_params->mr;
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

	printf("\t-n, --header-len=<number> ");
	printf("\tSet the header length of the message to <number> bytes " \
			"(default %d)\n", XIO_DEF_HEADER_SIZE);

	printf("\t-w, --data-len=<length> ");
	printf("\tSet the data length of the message to <number> bytes " \
			"(default %d)\n", XIO_DEF_DATA_SIZE);

	printf("\t-v, --version ");
	printf("\t\t\tPrint the version and exit\n");

	printf("\t-h, --help ");
	printf("\t\t\tDisplay this help and exit\n");

	exit(status);
}

/*---------------------------------------------------------------------------*/
/* parse_cmdline							     */
/*---------------------------------------------------------------------------*/
int parse_cmdline(struct xio_test_config *test_config,
		int argc, char **argv)
{
	while (1) {
		int c;

		static struct option const long_options[] = {
			{ .name = "core",	.has_arg = 1, .val = 'c'},
			{ .name = "port",	.has_arg = 1, .val = 'p'},
			{ .name = "header-len",	.has_arg = 1, .val = 'n'},
			{ .name = "data-len",	.has_arg = 1, .val = 'w'},
			{ .name = "version",	.has_arg = 0, .val = 'v'},
			{ .name = "help",	.has_arg = 0, .val = 'h'},
			{0, 0, 0, 0},
		};

		static char *short_options = "c:p:n:w:svh";

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
		case 'n':
			test_config->hdr_len =
				(uint32_t)strtol(optarg, NULL, 0);
		break;
		case 'w':
			test_config->data_len =
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
			break;
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
	printf(" Header Length		: %u\n", test_config_p->hdr_len);
	printf(" Data Length		: %u\n", test_config_p->data_len);
	printf(" CPU Affinity		: %x\n", test_config_p->cpu);
	printf(" =============================================\n");
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct xio_server	*server;
	struct test_params	test_params;
	char			url[256];

	if (parse_cmdline(&test_config, argc, argv) != 0)
		return -1;

	print_test_config(&test_config);

	set_cpu_affinity(test_config.cpu);

	xio_init();

	memset(&test_params, 0, sizeof(struct test_params));

	/* prepare buffers for this test */
	if (msg_api_init(&test_params.msg_params,
			 test_config.hdr_len, test_config.data_len, 0) != 0)
		return -1;

	test_params.pool = msg_pool_alloc(MAX_POOL_SIZE, 0, 0, 0, 0);
	if (test_params.pool == NULL)
		goto cleanup;

	test_params.ctx = xio_context_create(NULL, 0, test_config.cpu);
	if (test_params.ctx == NULL) {
		int error = xio_errno();
		fprintf(stderr, "context creation failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		goto exit1;
	}

	sprintf(url, "rdma://%s:%d", test_config.server_addr,
		test_config.server_port);

	server = xio_bind(test_params.ctx, &server_ops, url, NULL, 0, &test_params);
	if (server) {
		printf("listen to %s\n", url);
		xio_context_run_loop(test_params.ctx, XIO_INFINITE);

		/* normal exit phase */
		fprintf(stdout, "exit signaled\n");

		/* free the server */
		xio_unbind(server);
	}

	xio_context_destroy(test_params.ctx);

exit1:
	if (test_params.pool)
		msg_pool_free(test_params.pool);

	if (test_params.mr) {
		xio_dereg_mr(&test_params.mr);
		test_params.mr = NULL;
	}

	if (test_params.buf) {
		free(test_params.buf);
		test_params.buf = NULL;
	}
cleanup:
	msg_api_free(&test_params.msg_params);

	xio_shutdown();

	return 0;
}

