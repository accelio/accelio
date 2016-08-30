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
#include "get_clock.h"
#include "xio_perftest_parameters.h"
#include "xio_perftest_communication.h"
#include "xio_perftest_resources.h"
#include "xio_perftest.h"

#define USECS_IN_SEC		1000000
#define NSECS_IN_USEC		1000
#define ONE_MB			(1 << 20)

struct thread_stat_data {
	volatile uint64_t	scnt;
	volatile uint64_t	ccnt;
	volatile uint64_t	tot_rtt;
	volatile uint64_t	max_rtt;
	volatile uint64_t	min_rtt;
};

struct thread_data {
	struct thread_stat_data stat;
	struct session_data    *sdata;
	struct msg_pool		*pool;
	struct xio_reg_mem	reg_mem;
	struct xio_session	*session;
	struct xio_connection	*conn;
	struct xio_context	*ctx;
	struct perf_parameters	*user_param;
	uint64_t		data_len;
	int			tx_nr;
	int			rx_nr;
	int			cid;
	int			affinity;
	int			disconnect;
	int			do_stat;
	pthread_t		thread_id;
};

/* private session data */
struct session_data {
	uint64_t		tps;
	double			avg_lat_us;
	double			min_lat_us;
	double			max_lat_us;
	double			avg_bw;
	int			abort;
	int			hs_connected;
	struct xio_session	*session;
	struct thread_data	*tdata;
};

struct  test_vec {
	uint32_t		hdr_len;
	uint32_t		data_len;
};

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static uint32_t	threads_iter;
static uint64_t	hdr_len;
static uint64_t	data_len;
static FILE	*fd = NULL;
static double	g_mhz;

/*---------------------------------------------------------------------------*/
/* statistics_thread_cb							     */
/*---------------------------------------------------------------------------*/
static void *statistics_thread_cb(void *data)
{
	uint64_t		start_time;
	uint64_t		tx_len = hdr_len + data_len;
	double			delta;
	uint64_t		scnt_start = 0;
	uint64_t		scnt_end = 0;
	uint64_t		rtt_start = 0;
	uint64_t		rtt_end = 0;
	uint64_t		min_rtt = -1;
	uint64_t		max_rtt = 0;
	struct session_data	*sess_data = (struct session_data *)data;
	cpu_set_t		cpuset;
	unsigned int		i;

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);

	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

	/* makes it hot */
	sleep(1);

	for (i = 0; i < threads_iter; i++) {
		scnt_start += sess_data->tdata[i].stat.scnt;
		rtt_start += sess_data->tdata[i].stat.tot_rtt;
		sess_data->tdata[i].stat.min_rtt  = -1;
		sess_data->tdata[i].stat.max_rtt  = 0;
	}

	/* test period */
	/* start collecting statistics data */
	start_time = get_cycles();
	for (i = 0; i < threads_iter; i++)
		sess_data->tdata[i].do_stat = 1;

	sleep(2);
	/* stop collecting statistics data */
	for (i = 0; i < threads_iter; i++)
		sess_data->tdata[i].do_stat = 0;

	delta = (get_cycles() - start_time)/g_mhz;

	for (i = 0; i < threads_iter; i++) {
		scnt_end += sess_data->tdata[i].stat.scnt;
		rtt_end += sess_data->tdata[i].stat.tot_rtt;
		if (min_rtt > sess_data->tdata[i].stat.min_rtt)
			min_rtt = sess_data->tdata[i].stat.min_rtt;
		if (max_rtt < sess_data->tdata[i].stat.min_rtt)
			max_rtt = sess_data->tdata[i].stat.max_rtt;
	}
	if ( scnt_end != scnt_start) {
		sess_data->avg_lat_us = (rtt_end - rtt_start)/g_mhz;
		sess_data->avg_lat_us /= (scnt_end - scnt_start);

		sess_data->min_lat_us = min_rtt/g_mhz;
		sess_data->max_lat_us = max_rtt/g_mhz;

		sess_data->tps    = ((scnt_end - scnt_start)*USECS_IN_SEC)/delta;
		sess_data->avg_bw = (1.0*sess_data->tps*tx_len/ONE_MB);
	}

	for (i = 0; i < threads_iter; i++)
		sess_data->tdata[i].disconnect = 1;

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* worker_thread							     */
/*---------------------------------------------------------------------------*/
static void *worker_thread(void *data)
{
	struct thread_data		*tdata = (struct thread_data *)data;
	struct xio_connection_params	cparams;
	struct xio_iovec_ex		*sglist;
	cpu_set_t			cpuset;
	struct xio_msg			*msg;
	unsigned int			i;

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	/* prepare data for the cuurent thread */
	tdata->pool = msg_pool_alloc(tdata->user_param->queue_depth);

	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, tdata->user_param->poll_timeout,
					tdata->affinity);

	memset(&cparams, 0, sizeof(cparams));
	cparams.session			= tdata->session;
	cparams.ctx			= tdata->ctx;
	cparams.conn_idx		= tdata->cid;
	cparams.conn_user_context	= tdata;

	/* connect the session  */
	tdata->conn = xio_connect(&cparams);

	if (tdata->data_len)
		xio_mem_alloc(tdata->data_len, &tdata->reg_mem);

	for (i = 0;  i < tdata->user_param->queue_depth; i++) {
		/* create transaction */
		msg = msg_pool_get(tdata->pool);
		if (msg == NULL)
			break;

		/* get pointers to internal buffers */
		msg->in.header.iov_len = 0;

		sglist = vmsg_sglist(&msg->in);
		vmsg_sglist_set_nents(&msg->in, 0);

		msg->out.header.iov_len = 0;
		sglist = vmsg_sglist(&msg->out);
		if (tdata->data_len) {
			vmsg_sglist_set_nents(&msg->out, 1);
			sglist[0].iov_base	= tdata->reg_mem.addr;
			sglist[0].iov_len	= tdata->reg_mem.length;
			sglist[0].mr		= tdata->reg_mem.mr;
		} else {
			vmsg_sglist_set_nents(&msg->out, 0);
		}
		msg->user_context = (void *)get_cycles();
		/* send first message */
		if (xio_send_request(tdata->conn, msg) == -1) {
			if (xio_errno() != EAGAIN)
				printf("**** [%p] Error - xio_send_request " \
				       "failed. %s\n",
					tdata->session,
					xio_strerror(xio_errno()));
			msg_pool_put(tdata->pool, msg);
			return 0;
		}
		if (tdata->do_stat)
			tdata->stat.scnt++;
		tdata->tx_nr++;
	}

	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

	/* normal exit phase */

	if (tdata->pool)
		msg_pool_free(tdata->pool);

	if (tdata->reg_mem.addr)
		xio_mem_free(&tdata->reg_mem);


	/* free the context */
	xio_context_destroy(tdata->ctx);

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
	unsigned int	    i;


	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_ERROR_EVENT:
	case XIO_SESSION_CONNECTION_REFUSED_EVENT:
	case XIO_SESSION_REJECT_EVENT:
	case XIO_SESSION_CONNECTION_DISCONNECTED_EVENT:
		fprintf(stderr, "%s. reason: %s\n",
			xio_session_event_str(event_data->event),
			xio_strerror(event_data->reason));

		for (i = 0; i < threads_iter; i++) {
			session_data->tdata[i].disconnect = 1;
			session_data->abort = 1;
		}
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		for (i = 0; i < threads_iter; i++)
			xio_context_stop_loop(session_data->tdata[i].ctx);
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

	cycles_t rtt = (get_cycles()-(cycles_t)msg->user_context);

	if (tdata->do_stat) {
		if (rtt > tdata->stat.max_rtt)
			tdata->stat.max_rtt = rtt;
		if (rtt < tdata->stat.min_rtt)
			tdata->stat.min_rtt = rtt;
		tdata->stat.tot_rtt += rtt;
		tdata->stat.ccnt++;
	}

	tdata->rx_nr++;

	/* message is no longer needed */
	xio_release_response(msg);

	if (tdata->disconnect) {
		if (tdata->rx_nr == tdata->tx_nr)
			xio_disconnect(tdata->conn);
		else
			msg_pool_put(tdata->pool, msg);
		return 0;
	}

	/* reset message */
	msg->in.header.iov_len = 0;
	vmsg_sglist_set_nents(&msg->in, 0);

	msg->user_context = (void *)get_cycles();
	if (xio_send_request(tdata->conn, msg) == -1) {
		if (xio_errno() != EAGAIN)
			printf("**** [%p] Error - xio_send_request " \
					"failed %s\n",
					session,
					xio_strerror(xio_errno()));
		msg_pool_put(tdata->pool, msg);
		return 0;
	}
	if (tdata->do_stat)
		tdata->stat.scnt++;

	tdata->tx_nr++;

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

	msg_pool_put(tdata->pool, msg);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  NULL,
	.on_msg_delivered		=  NULL,
	.on_msg				=  on_response,
	.on_msg_error			=  on_msg_error
};

/*---------------------------------------------------------------------------*/
/* run_client_test							     */
/*---------------------------------------------------------------------------*/
int run_client_test(struct perf_parameters *user_param)
{
	struct session_data	sess_data;
	struct perf_comm	*comm;
	struct thread_data	*tdata;
	char			str[512];
	char			url[256];
	unsigned int		i = 0;
	int			cpu;
	int			max_cpus;
	int			cpusnr;
	uint64_t		cpusmask = 0;
	pthread_t		statistics_thread_id;
	struct perf_command	command;
	int			size_log2;
	int			max_size_log2 = 24;
	struct xio_session_params params;


	xio_init();

	if (user_param->output_file) {
                fd = fopen(user_param->output_file, "w");
                if (fd == NULL) {
                        fprintf(stderr, "file open failed. %s\n",
                                user_param->output_file);
                        goto cleanup1;
                }
                fprintf(fd, "size, threads, tps, bw[Mbps], lat[usec]\n");
                fflush(fd);
        }

	g_mhz		= get_cpu_mhz(0);
	max_cpus	= sysconf(_SC_NPROCESSORS_ONLN);
	threads_iter    = user_param->start_thread;
	size_log2	= 0;

	tdata = (struct thread_data *)
			calloc(user_param->threads_num, sizeof(*tdata));
	if (tdata == NULL) {
		fprintf(stderr, "malloc failed.\n");
		goto cleanup1;
	}

	comm = create_comm_struct(user_param);
	if (establish_connection(comm)) {
		fprintf(stderr, "failed to establish connection\n");
		goto cleanup2;
	}

	i = intf_name_best_cpus(user_param->intf_name, &cpusmask, &cpusnr);
	if (i == 0) {
		printf("best cpus [%d] %s\n", cpusnr,
		       intf_cpusmask_str(cpusmask, cpusnr, str));
	}

	printf("%s", RESULT_FMT);
	printf("%s", RESULT_LINE);


	while (threads_iter <= user_param->threads_num)  {
		data_len	= (uint64_t)1 << size_log2;

		memset(&sess_data, 0, sizeof(sess_data));
		memset(tdata, 0, user_param->threads_num*sizeof(*tdata));
		memset(&params, 0, sizeof(params));
		sess_data.tdata = tdata;

		command.test_param.machine_type	= user_param->machine_type;
		command.test_param.test_type	= user_param->test_type;
		command.test_param.verb		= user_param->verb;
		command.test_param.data_len	= data_len;
		command.command			= GetTestParams;

		ctx_write_data(comm, &command, sizeof(command));

		sprintf(url, "%s://%s:%d",
			user_param->transport,
			user_param->server_addr,
			user_param->server_port);

		params.type		= XIO_SESSION_CLIENT;
		params.ses_ops		= &ses_ops;
		params.user_context	= &sess_data;
		params.uri		= url;

		sess_data.session = xio_session_create(&params);
		if (sess_data.session == NULL) {
			int error = xio_errno();
			fprintf(stderr,
				"session creation failed. reason %d - (%s)\n",
				error, xio_strerror(error));
			goto cleanup;
		}

		pthread_create(&statistics_thread_id, NULL,
			       statistics_thread_cb, &sess_data);

		/* spawn threads to handle connection */
		for (i = 0, cpu = 0; i < threads_iter; i++, cpu++) {
			while (cpusmask) {
				if (cpusmask_test_bit(cpu, &cpusmask))
					break;
				if (++cpu == max_cpus)
					cpu = 0;
			}
			sess_data.tdata[i].affinity		= cpu;
			sess_data.tdata[i].cid			= 0;
			sess_data.tdata[i].sdata		= &sess_data;
			sess_data.tdata[i].user_param		= user_param;
			sess_data.tdata[i].data_len		= data_len;

			/* all threads are working on the same session */
			sess_data.tdata[i].session	= sess_data.session;
			pthread_create(&sess_data.tdata[i].thread_id, NULL,
				       worker_thread, &sess_data.tdata[i]);
		}

		pthread_join(statistics_thread_id, NULL);

		/* join the threads */
		for (i = 0; i < threads_iter; i++)
			pthread_join(sess_data.tdata[i].thread_id, NULL);

		/* close the session */
		xio_session_destroy(sess_data.session);

		if (sess_data.abort) {
			fprintf(stderr, "program aborted\n");
			goto cleanup;
		}

		/* send result to server */
		command.results.bytes		= data_len;
		command.results.threads		= threads_iter;
		command.results.tps		= sess_data.tps;
		command.results.avg_bw		= sess_data.avg_bw;
		command.results.avg_lat		= sess_data.avg_lat_us;
		command.results.min_lat		= sess_data.min_lat_us;
		command.results.max_lat		= sess_data.max_lat_us;
		command.command			= GetTestResults;

		/* sync point */
		ctx_write_data(comm, &command, sizeof(command));

		printf(REPORT_FMT,
		       data_len,
		       threads_iter,
		       sess_data.tps,
		       sess_data.avg_bw,
		       sess_data.avg_lat_us,
		       sess_data.min_lat_us,
		       sess_data.max_lat_us);
		if (fd)
			fprintf(fd, "%lu, %d, %lu, %.2lf, %.2lf\n",
				data_len,
				threads_iter,
				sess_data.tps,
				sess_data.avg_bw,
				sess_data.avg_lat_us);
		fflush(fd);

		/* sync point */
		ctx_read_data(comm, NULL, 0, NULL);

		if (++size_log2 < max_size_log2)
			continue;

		threads_iter++;
		size_log2 = 0;
	}

	printf("%s", RESULT_LINE);

cleanup:
	ctx_hand_shake(comm);

cleanup2:
	ctx_close_connection(comm);

	destroy_comm_struct(comm);

	free(tdata);

cleanup1:
	if (fd)
                fclose(fd);
	
	xio_shutdown();

	return 0;
}
