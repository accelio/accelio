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

#define MAX_POOL_SIZE		512

#define XIO_DEF_ADDRESS		"127.0.0.1"
#define XIO_DEF_PORT		2061
#define XIO_DEF_HEADER_SIZE	32
#define XIO_DEF_DATA_SIZE	32
#define XIO_DEF_CPU		0
#define XIO_TEST_VERSION	"1.0.0"
#define XIO_READ_BUF_LEN	(1024*1024)


struct xio_test_config {
	char		server_addr[32];
	uint16_t	server_port;
	uint16_t	cpu;
	uint32_t	hdr_len;
	uint32_t	data_len;
};
#define PRINT_COUNTER	4000000


/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static void			*loop;
static struct msg_pool		*pool;
static uint64_t			last_sent;
static uint64_t			last_comp;


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
void set_cpu_affinity(int cpu)
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
		void *cb_prv_data)
{
	printf("session event: %s. session:%p, connection:%p, reason: %s\n",
	       xio_session_event_str(event_data->event),
	       session, event_data->conn,
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		/* assign connection private data */
		event_data->conn_user_context = cb_prv_data;
		break;
	case XIO_SESSION_CONNECTION_CLOSED_EVENT:
		printf("last sent:%lu, last comp:%lu, delta:%lu\n",
		       last_sent,  last_comp, last_sent-last_comp);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		process_request(NULL);
		xio_session_close(session);
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
static int on_request(struct xio_session *session,
			struct xio_msg *req,
			int more_in_batch,
			void *cb_prv_data)
{
	struct xio_msg	*rsp;

	if (req->status)
		printf("**** request completed with error. [%s]\n",
		       xio_strerror(req->status));


	/* process request */
	process_request(req);

	/* alloc transaction */
	rsp	= msg_pool_get(pool);

	rsp->request		= req;
	rsp->more_in_batch	= 0;

	/* fill response */
	msg_write(rsp, "hello world response header", test_config.hdr_len,
		  "hello world response data", test_config.data_len);

	if (xio_send_response(rsp) == -1) {
		printf("**** [%p] Error - xio_send_msg failed. %s\n",
		       session, xio_strerror(xio_errno()));
		msg_pool_put(pool, req);
	}
	last_sent = req->sn;


	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_send_response_complete						     */
/*---------------------------------------------------------------------------*/
static int on_send_response_complete(struct xio_session *session,
			struct xio_msg *msg,
			void *cb_prv_data)
{
	last_comp = msg->request->sn;

	/* can be safely freed */
	msg_pool_put(pool, msg);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_msg_error								     */
/*---------------------------------------------------------------------------*/
int on_msg_error(struct xio_session *session,
		enum xio_status error, struct xio_msg  *msg,
		void *cb_private_data)
{
	printf("**** [%p] message [%"PRIu64"] failed. reason: %s\n",
	       session, msg->request->sn, xio_strerror(error));

	msg_pool_put(pool, msg);

	return 0;
}

int assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	static int first_time = 1;
	static char *buf = NULL;
	static struct xio_mr *mr = NULL;

	msg->in.data_iovlen = 1;

	if (first_time) {
		msg->in.data_iov[0].iov_base = calloc(XIO_READ_BUF_LEN, 1);
		msg->in.data_iov[0].iov_len = XIO_READ_BUF_LEN;
		msg->in.data_iov[0].mr =
			xio_reg_mr(msg->in.data_iov[0].iov_base,
				   msg->in.data_iov[0].iov_len);
		buf = msg->in.data_iov[0].iov_base;
		mr = msg->in.data_iov[0].mr;
		first_time = 0;
	} else {
		msg->in.data_iov[0].iov_base = buf;
		msg->in.data_iov[0].iov_len = XIO_READ_BUF_LEN;
		msg->in.data_iov[0].mr = mr;
	}

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
	char			url[256];
	struct xio_context	*ctx;

	if (parse_cmdline(&test_config, argc, argv) != 0)
		return -1;

	print_test_config(&test_config);

	set_cpu_affinity(test_config.cpu);

	xio_init();

	loop	= xio_ev_loop_init();
	ctx	= xio_ctx_open(NULL, loop, 0);

	if (msg_api_init(test_config.hdr_len, test_config.data_len, 1) != 0)
		return -1;

	pool = msg_pool_alloc(MAX_POOL_SIZE,
			      test_config.hdr_len, test_config.data_len,
			      0, 0);


	sprintf(url, "rdma://%s:%d", test_config.server_addr,
		test_config.server_port);

	server = xio_bind(ctx, &server_ops, url, NULL, 0, NULL);
	if (server) {
		printf("listen to %s\n", url);
		xio_ev_loop_run(loop);

		/* normal exit phase */
		fprintf(stdout, "exit signaled\n");

		/* free the server */
		xio_unbind(server);
	}

	if (pool)
		msg_pool_free(pool);
	pool = NULL;

	xio_ctx_close(ctx);
	xio_ev_loop_destroy(&loop);

	return 0;
}

