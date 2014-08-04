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
#include <pthread.h>

#include "libxio.h"
#include "xio_msg.h"
#include "xio_test_utils.h"
#include "xio_intf.h"

#define MAX_POOL_SIZE		512

#define XIO_DEF_ADDRESS		"127.0.0.1"
#define XIO_DEF_PORT		2061
#define XIO_DEF_TRANSPORT	"rdma"
#define XIO_DEF_HEADER_SIZE	32
#define XIO_DEF_DATA_SIZE	32
#define XIO_DEF_CPU		0
#define XIO_DEF_POLL		0
#define XIO_TEST_VERSION	"1.0.0"
#define XIO_READ_BUF_LEN	(1024*1024)
#define PRINT_COUNTER		4000000
#define MAX_THREADS		6

struct xio_test_config {
	char		server_addr[32];
	uint16_t	server_port;
	char		transport[16];
	uint16_t	cpu;
	uint32_t	hdr_len;
	uint32_t	data_len;
	int		poll_timeout;
};

struct portals_vec {
	int			vec_len;
	int			pad;
	const char		*vec[MAX_THREADS];
};

struct thread_stat_data {
	uint64_t print_counter;
	uint64_t cnt;
	uint64_t start_time;
	size_t	 txlen;
	size_t	 rxlen;
	int	 first_time;
	int	 pad;
};

struct  thread_data {
	struct thread_stat_data	stat;
	struct xio_context	*ctx;
	struct msg_pool		*pool;
	void			*loop;
	struct xio_buf		*xbuf;
	char			portal[64];
	int			affinity;
	int			cnt;
	pthread_t		thread_id;
};

/* server private data */
struct server_data {
	void			*ctx;
	int			tdata_nr;
	int			pad;
	struct thread_data	*tdata;
};

static struct msg_params msg_prms;

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
	XIO_DEF_POLL
};

static struct portals_vec *portals_get(struct server_data *server_data,
				       const char *uri, void *user_context)
{
	/* fill portals array and return it. */
	int			i;
	struct portals_vec	*portals = calloc(1, sizeof(*portals));
	for (i = 0; i < MAX_THREADS; i++) {
		portals->vec[i] = strdup(server_data->tdata[i].portal);
		portals->vec_len++;
	}

	return portals;
}

static void portals_free(struct portals_vec *portals)
{
	int			i;
	for (i = 0; i < portals->vec_len; i++)
		free((char *)(portals->vec[i]));

	free(portals);
}

/*---------------------------------------------------------------------------*/
/* process_request							     */
/*---------------------------------------------------------------------------*/
static void process_request(struct thread_data *tdata, struct xio_msg *msg)
{
	if (msg == NULL) {
		tdata->stat.cnt = 0;
		return;
	}

	if (++tdata->stat.cnt == PRINT_COUNTER) {
		struct xio_iovec_ex *sglist = vmsg_sglist(&msg->in);

		printf("thread [%d] - message [%lu] %s - %s\n",
		       tdata->affinity,
		       (msg->sn+1),
		       (char *)msg->in.header.iov_base,
		       (char *)sglist[0].iov_base);
		tdata->stat.cnt = 0;
	}
}

/*---------------------------------------------------------------------------*/
/* on_request								     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session, struct xio_msg *req,
		      int more_in_batch, void *cb_prv_data)
{
	struct xio_msg		*rsp;
	struct thread_data	*tdata = cb_prv_data;

	if (req->status) {
		printf("**** request completed with error. [%s]\n",
		       xio_strerror(req->status));
		xio_assert(req->status == 0);
	}

	/* process request */
	process_request(tdata, req);

	/* alloc transaction */
	rsp	= msg_pool_get(tdata->pool);

	rsp->request		= req;
	rsp->more_in_batch	= 0;

	/* fill response */
	msg_write(&msg_prms, rsp,
		  test_config.hdr_len,
		  1, test_config.data_len);

	if (xio_send_response(rsp) == -1) {
		printf("**** [%p] Error - xio_send_msg failed. %s\n",
		       session, xio_strerror(xio_errno()));
		msg_pool_put(tdata->pool, req);
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
	struct thread_data	*tdata = cb_prv_data;

	/* can be safely freed */
	msg_pool_put(tdata->pool, msg);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_msg_error								     */
/*---------------------------------------------------------------------------*/
int on_msg_error(struct xio_session *session,
		 enum xio_status error, struct xio_msg  *msg,
		 void *cb_prv_data)
{
	struct thread_data	*tdata = cb_prv_data;

	printf("**** [%p] message [%lu] failed. reason: %s\n",
	       session, msg->request->sn, xio_strerror(error));

	msg_pool_put(tdata->pool, msg);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* assign_data_in_buf							     */
/*---------------------------------------------------------------------------*/
int assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	struct thread_data	*tdata = cb_user_context;
	struct xio_iovec_ex	*sglist = vmsg_sglist(&msg->in);

	vmsg_sglist_set_nents(&msg->in, 1);
	if (tdata->xbuf == NULL)
		tdata->xbuf = xio_alloc(XIO_READ_BUF_LEN);

	sglist[0].iov_base = tdata->xbuf->addr;
	sglist[0].mr = tdata->xbuf->mr;
	sglist[0].iov_len = XIO_READ_BUF_LEN;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops  portal_server_ops = {
	.on_session_event		=  NULL,
	.on_new_session			=  NULL,
	.on_msg_send_complete		=  on_send_response_complete,
	.on_msg				=  on_request,
	.on_msg_error			=  on_msg_error,
	.assign_data_in_buf		=  assign_data_in_buf
};

/*---------------------------------------------------------------------------*/
/* worker thread callback						     */
/*---------------------------------------------------------------------------*/
static void *portal_server_cb(void *data)
{
	struct thread_data	*tdata = data;
	cpu_set_t		cpuset;
	struct xio_server	*server;
	int			retval = 0;

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	/* prepare data for the cuurent thread */
	tdata->pool = msg_pool_alloc(MAX_POOL_SIZE, 0, 1);

	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, test_config.poll_timeout,
					tdata->affinity);

	/* bind a listener server to a portal/url */
	printf("thread [%d] - listen:%s\n", tdata->affinity, tdata->portal);
	server = xio_bind(tdata->ctx, &portal_server_ops, tdata->portal,
			  NULL, 0, tdata);
	if (server == NULL) {
		printf("**** Error - xio_bind failed. %s\n",
		       xio_strerror(xio_errno()));
		xio_assert(0);
		goto cleanup;
	}

	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

	/* normal exit phase */
	fprintf(stdout, "thread [%d] - exit signaled\n", tdata->affinity);

	/* detach the server */
	xio_unbind(server);

	if (tdata->pool)
		msg_pool_free(tdata->pool);

	if (tdata->xbuf)
		xio_free(&tdata->xbuf);

cleanup:
	/* free the context */
	xio_context_destroy(tdata->ctx);

	pthread_exit(&retval);
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct server_data *server_data = cb_user_context;
	int		   i;

	printf("session event: %s. session:%p, connection:%p, reason: %s\n",
	       xio_session_event_str(event_data->event),
	       session, event_data->conn,
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		for (i = 0; i < server_data->tdata_nr; i++) {
			process_request(&server_data->tdata[i], NULL);
			xio_context_stop_loop(server_data->tdata[i].ctx, 0);
		}
		xio_context_stop_loop(server_data->ctx, 0);
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
	struct portals_vec *portals;
	struct server_data *server_data = cb_user_context;

	printf("**** [%p] on_new_session :%s:%d\n", session,
	       get_ip((struct sockaddr *)&req->src_addr),
	       get_port((struct sockaddr *)&req->src_addr));

	portals = portals_get(server_data, req->uri, req->private_data);

	/* automatic accept the request */
	xio_accept(session, portals->vec, portals->vec_len, NULL, 0);

	portals_free(portals);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops server_ops = {
	.on_session_event		=  on_session_event,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  NULL,
	.on_msg_error			=  NULL,
	.assign_data_in_buf		=  NULL
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

	printf("\t-t, --timeout=<number> ");
	printf("\tSet polling timeout in microseconds " \
			"(default %d)\n", XIO_DEF_POLL);

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
			{ .name = "timeout",	.has_arg = 0, .val = 't'},
			{ .name = "version",	.has_arg = 0, .val = 'v'},
			{ .name = "help",	.has_arg = 0, .val = 'h'},
			{0, 0, 0, 0},
		};

		static char *short_options = "c:p:r:n:w:t:svh";

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
		case 't':
			test_config->poll_timeout =
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
	printf(" CPU Affinity		: %x\n", test_config_p->cpu);
	printf(" Poll Timeout		: %d\n", test_config_p->poll_timeout);
	printf(" =============================================\n");
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct xio_server	*server;	/* server portal */
	struct server_data	server_data;
	char			url[256];
	int			i;
	uint16_t		port;
	int			max_cpus;
	uint64_t		cpusmask;
	int			cpusnr;
	int			cpu;



	memset(&server_data, 0, sizeof(server_data));

	server_data.tdata = calloc(MAX_THREADS, sizeof(struct thread_data));
	if (!server_data.tdata)
		return -1;
	server_data.tdata_nr = MAX_THREADS;

	max_cpus = sysconf(_SC_NPROCESSORS_ONLN);

	if (parse_cmdline(&test_config, argc, argv) != 0)
		return -1;

	print_test_config(&test_config);
	i = intf_best_cpus(test_config.server_addr, &cpusmask, &cpusnr);
	if (i == 0) {
		if (!cpusmask_test_bit(test_config.cpu, &cpusmask)) {
			printf("warning: cpu %d is not best cpu for %s\n",
			       test_config.cpu, test_config.server_addr);
			printf("best cpus [%d] %s\n", cpusnr,
			       intf_cpusmask_str(cpusmask, cpusnr, url));
		}
	}

	set_cpu_affinity(test_config.cpu);

	if (msg_api_init(&msg_prms,
			 test_config.hdr_len, test_config.data_len, 1) != 0)
		return -1;

	/* create thread context for the client */
	server_data.ctx = xio_context_create(NULL, test_config.poll_timeout,
					     test_config.cpu);

	/* create url to connect to */
	sprintf(url, "%s://%s:%d",
		test_config.transport,
		test_config.server_addr,
		test_config.server_port);

	/* bind a listener server to a portal/url */
	server = xio_bind(server_data.ctx, &server_ops, url,
			  NULL, 0, &server_data);
	if (server == NULL)
		goto cleanup;

	/* spawn portals */
	port = test_config.server_port;
	for (i = 0, cpu = 0; i < MAX_THREADS; i++, cpu++) {
		while (1) {
			if (cpusmask_test_bit(cpu, &cpusmask))
				break;
			if (++cpu == max_cpus)
				cpu = 0;
		}
		server_data.tdata[i].affinity = cpu;
		port++;
		sprintf(server_data.tdata[i].portal, "%s://%s:%d",
			test_config.transport,
			test_config.server_addr, port);
		pthread_create(&server_data.tdata[i].thread_id, NULL,
			       portal_server_cb, &server_data.tdata[i]);
	}

	xio_context_run_loop(server_data.ctx, XIO_INFINITE);

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	/* join the threads */
	for (i = 0; i < MAX_THREADS; i++)
		pthread_join(server_data.tdata[i].thread_id, NULL);

	/* free the server */
	xio_unbind(server);
cleanup:
	/* free the context */
	xio_context_destroy(server_data.ctx);

	free(server_data.tdata);

	msg_api_free(&msg_prms);

	return 0;
}

