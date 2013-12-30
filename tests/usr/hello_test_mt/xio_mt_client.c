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
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>

#include "libxio.h"
#include "xio_msg.h"

#define MAX_HEADER_SIZE		32
#define MAX_DATA_SIZE		32
#define PRINT_COUNTER		6000000
#define XIO_DEF_ADDRESS		"127.0.0.1"
#define XIO_DEF_PORT		2061
#define XIO_DEF_HEADER_SIZE	32
#define XIO_DEF_DATA_SIZE	32
#define XIO_DEF_CPU		0
#define XIO_DEF_POLL		0
#define XIO_TEST_VERSION	"1.0.0"

#define MAX_POOL_SIZE		400
#define USECS_IN_SEC		1000000
#define NSECS_IN_USEC		1000
#define ONE_MB			(1 << 20)
#define MAX_THREADS		4

struct xio_test_config {
	char			server_addr[32];
	uint16_t		server_port;
	uint16_t		cpu;
	uint32_t		hdr_len;
	uint32_t		data_len;
	uint32_t		conn_idx;
	int			poll_timeout;
};

struct thread_stat_data {
	uint64_t print_counter;
	uint64_t cnt ;
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
	void			*loop;
	struct msg_pool		*pool;
	pthread_t		thread_id;
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
	XIO_DEF_ADDRESS,
	XIO_DEF_PORT,
	XIO_DEF_CPU,
	XIO_DEF_HEADER_SIZE,
	XIO_DEF_DATA_SIZE,
	XIO_DEF_POLL
};

/**
 * Convert a timespec to a microsecond value.
 * @e NOTE: There is a loss of precision in the conversion.
 *
 * @param time_spec The timespec to convert.
 * @return The number of microseconds specified by the timespec.
 */
static inline
unsigned long long timespec_to_usecs(struct timespec *time_spec)
{
	unsigned long long retval = 0;

	retval  = time_spec->tv_sec * USECS_IN_SEC;
	retval += time_spec->tv_nsec / NSECS_IN_USEC;

	return retval;
}

static inline unsigned long long get_cpu_usecs()
{
	struct timespec ts = {0, 0};
	clock_gettime(CLOCK_MONOTONIC, &ts);

	return  timespec_to_usecs(&ts);
}

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
/* get_time								     */
/*---------------------------------------------------------------------------*/
void get_time(char *time, int len)
{
	struct timeval tv;
	struct tm      t;
	int	       n;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &t);
	/* Format the date and time,
	   down to a single second. */
	n = snprintf(time, len,
		  "%04d/%02d/%02d-%02d:%02d:%02d.%05ld",
		   t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
		   t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec);
	time[n] = 0;
}

/*---------------------------------------------------------------------------*/
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct thread_data	*tdata, struct xio_msg *rsp)
{
	if (tdata->stat.first_time) {
		size_t	data_len = 0;
		int	i;

		for (i = 0; i < rsp->out.data_iovlen; i++)
			data_len += rsp->out.data_iov[i].iov_len;

		tdata->stat.txlen = rsp->out.header.iov_len + data_len;

		data_len = 0;
		for (i = 0; i < rsp->in.data_iovlen; i++)
			data_len += rsp->in.data_iov[i].iov_len;

		tdata->stat.rxlen = rsp->in.header.iov_len + data_len;

		tdata->stat.start_time = get_cpu_usecs();
		tdata->stat.first_time = 0;

		data_len = tdata->stat.txlen > tdata->stat.rxlen ?
			   tdata->stat.txlen : tdata->stat.rxlen;
		data_len = data_len/1024;
		tdata->stat.print_counter = (data_len ? PRINT_COUNTER/data_len : PRINT_COUNTER);
		tdata->stat.print_counter /=  MAX_THREADS;
	}
	if (++tdata->stat.cnt == tdata->stat.print_counter) {
		char		timeb[40];

		uint64_t delta = get_cpu_usecs() - tdata->stat.start_time;
		uint64_t pps = (tdata->stat.cnt*USECS_IN_SEC)/delta;

		double txbw = (1.0*pps*tdata->stat.txlen/ONE_MB);
		double rxbw = (1.0*pps*tdata->stat.rxlen/ONE_MB);

		printf("transactions per second: %"PRIu64", bandwidth: " \
		       "TX %.2f MB/s, RX: %.2f MB/s, length: TX: %zd B, RX: %zd B\n",
		       pps, txbw, rxbw, tdata->stat.txlen, tdata->stat.rxlen);
		get_time(timeb, 40);
		printf("[%s] thread [%d] - tid:%p  - message [%"PRIu64"] %s - %s\n",
		       timeb,
		       tdata->affinity,
		       (void *)pthread_self(),
		       (rsp->request->sn + 1),
		       (char *)rsp->in.header.iov_base,
		       (char *)rsp->in.data_iov[0].iov_base);
		tdata->stat.cnt = 0;
		tdata->stat.start_time = get_cpu_usecs();
	}
}

static void *worker_thread(void *data)
{
	struct thread_data	*tdata = data;
	cpu_set_t		cpuset;
	struct xio_msg		*msg;
	int			i;

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	/* prepare data for the cuurent thread */
	tdata->pool = msg_pool_alloc(MAX_POOL_SIZE,
				     test_config.hdr_len, test_config.data_len,
				     0, 0);

	/* open default event loop */
	tdata->loop = xio_ev_loop_init();


	/* create thread context for the client */
	tdata->ctx = xio_ctx_open(NULL, tdata->loop, test_config.poll_timeout);

	/* connect the session  */
	tdata->conn = xio_connect(tdata->session, tdata->ctx,
				  tdata->cid, NULL, tdata);

	for (i = 0;  i < 150; i++) {
		/* create transaction */
		msg = msg_pool_get(tdata->pool);
		if (msg == NULL)
			break;

		/* get pointers to internal buffers */
		msg->in.header.iov_base = NULL;
		msg->in.header.iov_len = 0;
		msg->in.data_iovlen = 0;
		msg->in.data_iov[0].iov_base = NULL;
		msg->in.data_iov[0].iov_len  = ONE_MB;
		msg->in.data_iov[0].mr = NULL;

		/* create "hello world" message */
		msg_write(msg, NULL,
			  test_config.hdr_len, NULL, test_config.data_len);

		/* send first message */
		if (xio_send_request(tdata->conn, msg) == -1) {
			printf("**** sent %d messages\n", i);
			if (xio_errno() != EAGAIN)
				printf("**** [%p] Error - xio_send_request " \
				       "failed. %s\n",
					tdata->session,
					xio_strerror(xio_errno()));
			msg_pool_put(tdata->pool, msg);
			return 0;
		}
	}

	/* the default xio supplied main loop */
	xio_ev_loop_run(tdata->loop);

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	if (tdata->pool)
		msg_pool_free(tdata->pool);

	/* free the context */
	xio_ctx_close(tdata->ctx);

	/* destroy the default loop */
	xio_ev_loop_destroy(&tdata->loop);

	fprintf(stdout, "thread exit\n");
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
		struct xio_session_event_data *event_data,
		void *cb_user_context)
{
	struct session_data *session_data = cb_user_context;
	int		    i;

	printf("session event: %s. reason: %s\n",
	       xio_session_event_str(event_data->event),
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_REJECT_EVENT:
	case XIO_SESSION_CONNECTION_DISCONNECTED_EVENT:
		xio_disconnect(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		for (i = 0; i < MAX_THREADS; i++)
			xio_ev_loop_stop(session_data->tdata[i].loop, 0);
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
			int more_in_batch,
			void *cb_user_context)
{
	struct thread_data  *tdata = cb_user_context;

	process_response(tdata, msg);

	if (msg->status)
		printf("**** message completed with error. [%s]\n",
		       xio_strerror(msg->status));

	/* message is no longer needed */
	xio_release_response(msg);

	/* reset message */
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	msg->in.data_iovlen = 0;
	msg->in.data_iov[0].iov_base = NULL;
	msg->in.data_iov[0].iov_len  = ONE_MB;
	msg->in.data_iov[0].mr = NULL;

	msg->sn = 0;
	msg->more_in_batch = 0;

	/* recycle the message and fill new request */
	msg_write(msg, NULL, test_config.hdr_len,
		       NULL, test_config.data_len);

	if (xio_send_request(tdata->conn, msg) == -1) {
		if (xio_errno() != EAGAIN)
			printf("**** [%p] Error - xio_send_request " \
					"failed %s\n",
					session,
					xio_strerror(xio_errno()));
		msg_pool_put(tdata->pool, msg);
		return 0;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_msg_error								     */
/*---------------------------------------------------------------------------*/
int on_msg_error(struct xio_session *session,
		enum xio_status error, struct xio_msg  *msg,
		void *cb_user_context)
{
	struct thread_data  *tdata = cb_user_context;

	printf("**** [%p] message [%"PRIu64"] failed. reason: %s\n",
	       session, msg->request->sn, xio_strerror(error));

	msg_pool_put(tdata->pool, msg);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  NULL,
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
int parse_cmdline(struct xio_test_config *test_config,
		int argc, char **argv)
{
	while (1) {
		int c;

		static struct option const long_options[] = {
			{ .name = "cpu",	.has_arg = 1, .val = 'c'},
			{ .name = "port",	.has_arg = 1, .val = 'p'},
			{ .name = "header-len",	.has_arg = 1, .val = 'n'},
			{ .name = "data-len",	.has_arg = 1, .val = 'w'},
			{ .name = "index",	.has_arg = 1, .val = 'i'},
			{ .name = "timeout",	.has_arg = 1, .val = 't'},
			{ .name = "version",	.has_arg = 0, .val = 'v'},
			{ .name = "help",	.has_arg = 0, .val = 'h'},
			{0, 0, 0, 0},
		};

		static char *short_options = "c:p:n:w:i:t:vh";

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
		case 'i':
			test_config->conn_idx =
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
	printf(" Connection Index	: %u\n", test_config_p->conn_idx);
	printf(" Poll timeout		: %d\n", test_config_p->poll_timeout);
	printf(" CPU Affinity		: %x\n", test_config_p->cpu);
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

	/* client session attributes */
	struct xio_session_attr attr = {
		&ses_ops,
		NULL,
		0
	};

	if (parse_cmdline(&test_config, argc, argv) != 0)
		return -1;

	print_test_config(&test_config);

	set_cpu_affinity(test_config.cpu);

	memset(&sess_data, 0, sizeof(sess_data));
	max_cpus = sysconf(_SC_NPROCESSORS_ONLN);


	if (msg_api_init(test_config.hdr_len, test_config.data_len, 0) != 0)
		return -1;

	sprintf(url, "rdma://%s:%d", test_config.server_addr,
		test_config.server_port);
	sess_data.session = xio_session_open(XIO_SESSION_CLIENT,
				   &attr, url, 0, 0, &sess_data);
	if (sess_data.session == NULL) {
		int error = xio_errno();
		fprintf(stderr, "session creation failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		goto cleanup;
	}

	/* spawn threads to handle connection */
	for (i = 0; i < MAX_THREADS; i++) {
		sess_data.tdata[i].affinity		=
				((test_config.cpu + i + 1) % max_cpus);
		sess_data.tdata[i].cid			= i+1;
		sess_data.tdata[i].stat.first_time	= 1;
		sess_data.tdata[i].stat.print_counter	= PRINT_COUNTER;

		/* all threads are working on the same session */
		sess_data.tdata[i].session	= sess_data.session;
		pthread_create(&sess_data.tdata[i].thread_id, NULL,
			       worker_thread, &sess_data.tdata[i]);
	}

	/* join the threads */
	for (i = 0; i < MAX_THREADS; i++)
		pthread_join(sess_data.tdata[i].thread_id, NULL);

	/* close the session */
	xio_session_close(sess_data.session);

cleanup:

	return 0;
}
