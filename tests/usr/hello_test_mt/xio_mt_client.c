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
#include <pthread.h>

#include "libxio.h"
#include "xio_msg.h"
#include "xio_intf.h"
#include "xio_test_utils.h"

#define MAX_HEADER_SIZE		32
#define MAX_DATA_SIZE		32
#define PRINT_COUNTER		6000000
#define XIO_DEF_ADDRESS		"127.0.0.1"
#define XIO_DEF_PORT		2061
#define XIO_DEF_TRANSPORT	"rdma"
#define XIO_DEF_HEADER_SIZE	32
#define XIO_DEF_DATA_SIZE	32
#define XIO_DEF_CPU		0
#define XIO_DEF_POLL		0
#define XIO_TEST_VERSION	"1.0.0"
#define MAX_OUTSTANDING_REQS	50

#define MAX_POOL_SIZE		MAX_OUTSTANDING_REQS
#define ONE_MB			(1 << 20)
#define MAX_THREADS		4
#define DISCONNECT_FACTOR	3
#define HCA_NAME		"ib0"

struct xio_test_config {
	char			server_addr[32];
	uint16_t		server_port;
	char			transport[16];
	uint16_t		cpu;
	uint32_t		hdr_len;
	uint32_t		data_len;
	uint32_t		conn_idx;
	int			poll_timeout;
	uint16_t		finite_run;
	uint16_t		padding;
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

struct thread_data {
	struct thread_stat_data stat;
	int			cid;
	int			affinity;
	struct xio_session	*session;
	struct xio_connection	*conn;
	struct xio_context	*ctx;
	struct msg_pool		*pool;
	pthread_t		thread_id;
	uint64_t		disconnect_nr;
	uint64_t		nrecv;
	uint64_t		nsent;
	uint16_t		finite_run;
	uint16_t		padding;
	int			exit_code;
};

/* private session data */
struct session_data {
	struct xio_session	*session;
	struct thread_data	tdata[MAX_THREADS];
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
	.conn_idx = XIO_DEF_POLL,
	.poll_timeout = 0,
	.finite_run = 0,
	.padding = 0,
};

static struct msg_params msg_params;

/*---------------------------------------------------------------------------*/
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct thread_data	*tdata, struct xio_msg *rsp)
{
	struct xio_iovec_ex	*isglist = vmsg_sglist(&rsp->in);
	int			inents = vmsg_sglist_nents(&rsp->in);

	if (tdata->stat.first_time) {
		struct xio_iovec_ex	*osglist = vmsg_sglist(&rsp->out);
		int			onents = vmsg_sglist_nents(&rsp->out);
		size_t			data_len = 0;
		int			i;

		for (i = 0; i < onents; i++)
			data_len += osglist[i].iov_len;

		tdata->stat.txlen = rsp->out.header.iov_len + data_len;

		data_len = 0;
		for (i = 0; i < inents; i++)
			data_len += isglist[i].iov_len;

		tdata->stat.rxlen = rsp->in.header.iov_len + data_len;

		tdata->stat.start_time = get_cpu_usecs();
		tdata->stat.first_time = 0;

		data_len = tdata->stat.txlen > tdata->stat.rxlen ?
			   tdata->stat.txlen : tdata->stat.rxlen;
		data_len = data_len/1024;
		tdata->stat.print_counter = (data_len ?
					     PRINT_COUNTER/data_len :
					     PRINT_COUNTER);
		tdata->stat.print_counter /=  MAX_THREADS;
		if (tdata->stat.print_counter <  1000)
			tdata->stat.print_counter = 1000;
		tdata->disconnect_nr =
			tdata->stat.print_counter * DISCONNECT_FACTOR;
	}
	if (++tdata->stat.cnt == tdata->stat.print_counter) {
		char		timeb[40];

		uint64_t delta = get_cpu_usecs() - tdata->stat.start_time;
		uint64_t pps = (tdata->stat.cnt*USECS_IN_SEC)/delta;

		double txbw = (1.0*pps*tdata->stat.txlen/ONE_MB);
		double rxbw = (1.0*pps*tdata->stat.rxlen/ONE_MB);

		printf("transactions per second: %lu, bandwidth: " \
		       "TX %.2f MB/s, RX: %.2f MB/s, length: TX: %zd B, " \
		       "RX: %zd B\n",
		       pps, txbw, rxbw, tdata->stat.txlen, tdata->stat.rxlen);
		get_time(timeb, 40);
		printf("[%s] thread [%d] - tid:%p  - message [%lu] " \
		       "%s - %s\n",
		       timeb,
		       tdata->affinity,
		       (void *)pthread_self(),
		       (rsp->request->sn + 1),
		       (char *)rsp->in.header.iov_base,
		       (char *)(inents > 0 ? isglist[0].iov_base : NULL));
		tdata->stat.cnt = 0;
		tdata->stat.start_time = get_cpu_usecs();
	}
}

static void *worker_thread(void *data)
{
	struct thread_data		*tdata = (struct thread_data *)data;
	cpu_set_t			cpuset;
	struct xio_connection_params	cparams;
	struct xio_msg			*msg;
	struct xio_iovec_ex		*sglist;
	int				i;

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	/* prepare data for the cuurent thread */
	tdata->pool = msg_pool_alloc(MAX_POOL_SIZE, 1, 1);
	if (tdata->pool == NULL) {
		fprintf(stderr, "failed to alloc pool\n");
		tdata->exit_code = -1;
		return NULL;
	}

	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, test_config.poll_timeout,
					tdata->affinity);

	memset(&cparams, 0, sizeof(cparams));
	cparams.session			= tdata->session;
	cparams.ctx			= tdata->ctx;
	cparams.conn_idx		= tdata->cid;
	cparams.conn_user_context	= tdata;

	/* connect the session  */
	tdata->conn = xio_connect(&cparams);
	if (tdata->conn == NULL) {
		tdata->exit_code = -1;
		goto exit;
	}

	for (i = 0;  i < MAX_OUTSTANDING_REQS; i++) {
		/* create transaction */
		msg = msg_pool_get(tdata->pool);
		if (msg == NULL) {
			/* on error - disconnect */
			tdata->exit_code = -1;
			xio_disconnect(tdata->conn);
			break;
		}

		/* get pointers to internal buffers */
		msg->in.header.iov_base = NULL;
		msg->in.header.iov_len = 0;

		sglist = vmsg_sglist(&msg->in);
		vmsg_sglist_set_nents(&msg->in, 1);

		/* tell accelio to use  1MB buffer from its internal pool */
		sglist[0].iov_base = NULL;
		sglist[0].iov_len  = ONE_MB;
		sglist[0].mr = NULL;

		/* create "hello world" message */
		msg_build_out_sgl(&msg_params, msg,
			  test_config.hdr_len,
			  1, test_config.data_len);

		/* send first message */
		if (xio_send_request(tdata->conn, msg) == -1) {
			printf("**** sent %d messages\n", i);
			if (xio_errno() != EAGAIN)
				printf("**** [%p] Error - xio_send_request " \
				       "failed. %s\n",
					tdata->session,
					xio_strerror(xio_errno()));
			msg_pool_put(tdata->pool, msg);
			tdata->nsent++;
			/* on error - disconnect */
			tdata->exit_code = -1;
			xio_disconnect(tdata->conn);
			break;
		}
	}

	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

exit:
	/* normal exit phase */
	fprintf(stdout, "thread[%d]: exit signaled\n", tdata->affinity);

	if (tdata->pool)
		msg_pool_free(tdata->pool);

	/* free the context */
	xio_context_destroy(tdata->ctx);

	if (tdata->exit_code)
		fprintf(stdout, "thread exit - failure\n");
	else
		fprintf(stdout, "thread exit - success\n");

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct session_data *session_data =
					(struct session_data *)cb_user_context;
	int		    i;

	printf("session event: %s. reason: %s\n",
	       xio_session_event_str(event_data->event),
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_ERROR_EVENT:
		break;
	case XIO_SESSION_CONNECTION_CLOSED_EVENT:
	case XIO_SESSION_CONNECTION_DISCONNECTED_EVENT:
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_REJECT_EVENT:
	case XIO_SESSION_TEARDOWN_EVENT:
		for (i = 0; i < MAX_THREADS; i++) {
			struct thread_data *tdata = &session_data->tdata[i];
			if (tdata->exit_code == 0 && tdata->ctx)
				xio_context_stop_loop(tdata->ctx);
		}
		break;
	default:
		break;
	};

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
	struct thread_data  *tdata = (struct thread_data *)cb_user_context;
	struct xio_iovec_ex *sglist;

	tdata->nrecv++;

	process_response(tdata, msg);

	/* message is no longer needed */
	xio_release_response(msg);

	if (tdata->finite_run) {
		if (tdata->nrecv ==  tdata->disconnect_nr) {
			xio_disconnect(tdata->conn);
			return 0;
		}
		if (tdata->nsent == tdata->disconnect_nr) {
			printf("already sent more that needed\n");
			return 0;
		}
	}

	/* reset message */
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;

	sglist = vmsg_sglist(&msg->in);
	vmsg_sglist_set_nents(&msg->in, 1);

	/* tell accelio to use  1MB buffer from its internal pool */
	sglist[0].iov_base = NULL;
	sglist[0].iov_len  = ONE_MB;
	sglist[0].mr = NULL;

	msg->sn = 0;

	/* recycle the message and fill new request */
	msg_build_out_sgl(&msg_params, msg,
		  test_config.hdr_len,
		  1, test_config.data_len);

	if (xio_send_request(tdata->conn, msg) == -1) {
		if (xio_errno() != EAGAIN)
			printf("**** [%p] Error - xio_send_request " \
					"failed %s\n",
					session,
					xio_strerror(xio_errno()));
		msg_pool_put(tdata->pool, msg);
		tdata->nsent++;
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
	struct thread_data  *tdata = (struct thread_data *)cb_user_context;

	if (direction == XIO_MSG_DIRECTION_OUT) {
		printf("**** [%p] message %lu failed. reason: %s\n",
		       session, msg->sn, xio_strerror(error));
	} else {
		xio_release_response(msg);
		printf("**** [%p] message %lu failed. reason: %s\n",
		       session, msg->request->sn, xio_strerror(error));
	}

	msg_pool_put(tdata->pool, msg);

	switch (error) {
	case XIO_E_MSG_FLUSHED:
		break;
	default:
		xio_disconnect(tdata->conn);
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
/* callbacks								     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  on_session_established,
	.on_msg_delivered		=  NULL,
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

	printf("\t-t, --timeout=<number> ");
	printf("\tSet polling timeout in microseconds " \
			"(default %d)\n", XIO_DEF_POLL);

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
			{ .name = "timeout",	.has_arg = 1, .val = 't'},
			{ .name = "finite",	.has_arg = 1, .val = 'f'},
			{ .name = "version",	.has_arg = 0, .val = 'v'},
			{ .name = "help",	.has_arg = 0, .val = 'h'},
			{0, 0, 0, 0},
		};

		static char *short_options = "c:p:r:n:w:i:t:f:vh";

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
					(uint32_t)strtol(optarg, NULL, 0);
			break;
		case 'v':
			printf("version: %s\n", XIO_TEST_VERSION);
			exit(0);
			break;
		case 'h':
			usage(argv[0], 0);
			break;
		case 't':
			test_config->poll_timeout =
				(uint32_t)strtol(optarg, NULL, 0);
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
	printf(" Poll timeout		: %d\n", test_config_p->poll_timeout);
	printf(" CPU Affinity		: %x\n", test_config_p->cpu);
	printf(" Finite run		: %u\n", test_config_p->finite_run);
	printf(" =============================================\n");
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct session_data	sess_data;
	char			url[256];
	int			i = 0;
	int			max_cpus;
	uint64_t		cpusmask = 0;
	int			cpusnr;
	int			cpu;
	int			exit_code = 0;
	struct xio_session_params params;

	xio_init();
	if (parse_cmdline(&test_config, argc, argv) != 0)
		return -1;

	print_test_config(&test_config);

	i = intf_name_best_cpus(HCA_NAME, &cpusmask, &cpusnr);
	if (i == 0) {
		if (!cpusmask_test_bit(test_config.cpu, &cpusmask)) {
			printf("warning: cpu %d is not best cpu for %s\n",
			       test_config.cpu, HCA_NAME);
			printf("best cpus [%d] %s\n", cpusnr,
			       intf_cpusmask_str(cpusmask, cpusnr, url));
		}
	}

	set_cpu_affinity(test_config.cpu);

	memset(&sess_data, 0, sizeof(sess_data));
	memset(&params, 0, sizeof(params));
	max_cpus = sysconf(_SC_NPROCESSORS_ONLN);

	/* prepare buffers for this test */
	if (msg_api_init(&msg_params,
			 test_config.hdr_len, test_config.data_len, 0) != 0)
		return -1;

	sprintf(url, "%s://%s:%d",
		test_config.transport,
		test_config.server_addr,
		test_config.server_port);

	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.user_context	= &sess_data;
	params.uri		= url;

	sess_data.session = xio_session_create(&params);
	if (sess_data.session == NULL) {
		int error = xio_errno();
		fprintf(stderr, "session creation failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		exit_code = -1;
		goto exit;
	}

	/* spawn threads to handle connection */
	for (i = 0, cpu = 0; i < MAX_THREADS; i++, cpu++) {
		while (cpusmask) {
			if (cpusmask_test_bit(cpu, &cpusmask))
				break;
			if (++cpu == max_cpus)
				cpu = 0;
		}
		sess_data.tdata[i].affinity		= cpu;
		sess_data.tdata[i].cid			= i+1;
		sess_data.tdata[i].stat.first_time	= 1;
		sess_data.tdata[i].stat.print_counter	= PRINT_COUNTER;
		sess_data.tdata[i].finite_run = test_config.finite_run;

		/* all threads are working on the same session */
		sess_data.tdata[i].session	= sess_data.session;
		pthread_create(&sess_data.tdata[i].thread_id, NULL,
			       worker_thread, &sess_data.tdata[i]);
	}

	/* join the threads */
	for (i = 0; i < MAX_THREADS; i++) {
		pthread_join(sess_data.tdata[i].thread_id, NULL);
		if (sess_data.tdata[i].exit_code != 0)
			exit_code = -1;
	}


	fprintf(stdout, "joined all threads\n");

	/* close the session */
	xio_session_destroy(sess_data.session);

exit:
	msg_api_free(&msg_params);

	return exit_code;
}
