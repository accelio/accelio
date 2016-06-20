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
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libxio.h"
#include "xio_msg.h"
#include "xio_perftest_communication.h"
#include "xio_perftest_resources.h"
#include "xio_perftest_parameters.h"


struct  thread_data {
	struct perf_parameters	*user_param;
	struct msg_pool		*pool;
	struct xio_context	*ctx;
	struct xio_reg_mem	in_reg_mem;
	int			affinity;
	int			portal_index;
	pthread_t		thread_id;
};

/* server private data */
struct server_data {
	struct perf_parameters	*user_param;
	struct perf_comm	*comm;
	struct test_parameters  rem_test_param;
	struct test_parameters	my_test_param;
	struct xio_context	*ctx;
	int			tdata_nr;
	int			running;
	struct thread_data	*tdata;
	pthread_t		thread_id;
};

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
/* on_request								     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session,
			struct xio_msg *req,
			int last_in_rxq,
			void *cb_prv_data)
{
	struct xio_msg		*rsp;
	struct thread_data	*tdata = (struct thread_data *)cb_prv_data;

	/* alloc transaction */
	rsp	= msg_pool_get(tdata->pool);

	/* fill response */
	rsp->request		= req;
	rsp->in.header.iov_len	= 0;
	rsp->out.header.iov_len = 0;
	vmsg_sglist_set_nents(&rsp->in, 0);

	if (tdata->user_param->verb == READ)
		vmsg_sglist_set_nents(&rsp->out, 0);

	if (xio_send_response(rsp) == -1) {
		printf("**** [%p] Error - xio_send_msg failed. %s\n",
		       session, xio_strerror(xio_errno()));
		msg_pool_put(tdata->pool, req);
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
	struct thread_data	*tdata = (struct thread_data *)cb_prv_data;

	/* can be safely freed */
	msg_pool_put(tdata->pool, msg);

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
	struct thread_data	*tdata = (struct thread_data *)cb_user_context;

	msg_pool_put(tdata->pool, msg);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* assign_data_in_buf							     */
/*---------------------------------------------------------------------------*/
static int assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	struct thread_data	*tdata = (struct thread_data *)cb_user_context;
	struct xio_iovec_ex	*sglist = vmsg_sglist(&msg->in);
	int			retval = 0;

	if (!tdata->in_reg_mem.addr) {
		retval = xio_mem_alloc(sglist[0].iov_len, &tdata->in_reg_mem);
	} else if (tdata->in_reg_mem.length < sglist[0].iov_len) {
		xio_mem_free(&tdata->in_reg_mem);
		retval = xio_mem_alloc(sglist[0].iov_len, &tdata->in_reg_mem);
	}

	if (!retval){
		vmsg_sglist_set_nents(&msg->in, 1);

		sglist[0].iov_base	= tdata->in_reg_mem.addr;
		sglist[0].iov_len	= tdata->in_reg_mem.length;
		sglist[0].mr		= tdata->in_reg_mem.mr;
	} else {
		printf("**** Error - assign_data_in_buf failed with xio_msg:\
			%p and context: %p.\n", msg, cb_user_context);
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops  portal_server_ops = {
	.on_session_event		=  NULL,
	.on_new_session			=  NULL,
	.on_msg_send_complete		=  on_send_response_complete,
	.on_msg				=  on_request,
	.on_msg_error			=  on_msg_error,
	.assign_data_in_buf		=  assign_data_in_buf
};

/*---------------------------------------------------------------------------*/
/* portal_server_cb							     */
/*---------------------------------------------------------------------------*/
static void *portal_server_cb(void *data)
{
	struct thread_data	*tdata = (struct thread_data *)data;
	cpu_set_t		cpuset;
	struct xio_server	*server;
	int			retval = 0;

	/* set affinity to thread */

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(tdata->thread_id, sizeof(cpu_set_t), &cpuset);

	/* prepare data for the current thread */
	tdata->pool = msg_pool_alloc(tdata->user_param->queue_depth + 1024);

	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, tdata->user_param->poll_timeout,
					tdata->affinity);

	/* bind a listener server to a portal/url */
	server = xio_bind(tdata->ctx, &portal_server_ops,
			  tdata->user_param->portals_arr[tdata->portal_index],
			  NULL, 0, tdata);
	if (server == NULL)
		goto cleanup;

	/* the default xio supplied main loop */
	xio_context_run_loop(tdata->ctx, XIO_INFINITE);

	/* detach the server */
	xio_unbind(server);

	if (tdata->pool)
		msg_pool_free(tdata->pool);

	if (tdata->in_reg_mem.addr)
		xio_mem_free(&tdata->in_reg_mem);

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
	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
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
	struct server_data *server_data = (struct server_data *)cb_user_context;

	/* automatic accept the request */
	xio_accept(session,
		   (const char **)server_data->user_param->portals_arr,
		   server_data->user_param->portals_arr_len,
		   NULL, 0);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops server_ops = {
	.on_session_event		=  on_session_event,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  NULL,
	.on_msg_error			=  NULL,
	.assign_data_in_buf		=  NULL
};

/*---------------------------------------------------------------------------*/
/* balancer_server_cb							     */
/*---------------------------------------------------------------------------*/
static void *balancer_server_cb(void *data)
{
	struct xio_server	*server;	/* server portal */
	struct server_data	*server_data = (struct server_data *)data;
	char			url[256];
	int			retval = 0;

	/* create thread context for the client */
	server_data->ctx = xio_context_create(NULL,
				server_data->user_param->poll_timeout, -1);

	/* create url to connect to */
	sprintf(url, "%s://*:%d",
		server_data->user_param->transport,
		server_data->user_param->server_port);

	/* bind a listener server to a portal/url */
	server = xio_bind(server_data->ctx, &server_ops, url,
			  NULL, 0, server_data);
	if (server == NULL)
		goto cleanup;

	server_data->running = 1;
	xio_context_run_loop(server_data->ctx, XIO_INFINITE);

	/* free the server */
	xio_unbind(server);
cleanup:
	/* free the context */
	xio_context_destroy(server_data->ctx);

	pthread_exit(&retval);
}


/*---------------------------------------------------------------------------*/
/* on_test_results							     */
/*---------------------------------------------------------------------------*/
static void on_test_results(struct test_results *results)
{
	printf(REPORT_FMT,
	       (uint64_t)results->bytes,
	       results->threads,
	       results->tps,
	       results->avg_bw,
	       results->avg_lat,
	       results->min_lat,
	       results->max_lat);
}

/*---------------------------------------------------------------------------*/
/* run_server_test							     */
/*---------------------------------------------------------------------------*/
int run_server_test(struct perf_parameters *user_param)
{
	char			str[512];
	struct server_data	server_data;
	struct perf_command	command;
	unsigned int		i;
	int			len, retval;
	unsigned int		max_cpus;
	uint64_t		cpusmask = 0;
	int			cpusnr;
	unsigned int		cpu;

	xio_init();

	max_cpus = sysconf(_SC_NPROCESSORS_ONLN);

	i = intf_name_best_cpus(user_param->intf_name, &cpusmask, &cpusnr);
	if (i == 0) {
		printf("best cpus [%d] %s\n", cpusnr,
		       intf_cpusmask_str(cpusmask, cpusnr, str));
	}

	server_data.my_test_param.machine_type	= user_param->machine_type;
	server_data.my_test_param.test_type	= user_param->test_type;
	server_data.my_test_param.verb		= user_param->verb;
	server_data.my_test_param.data_len	= 0;


	server_data.tdata = (struct thread_data *)
		calloc(user_param->threads_num, sizeof(*server_data.tdata));

	/* spawn portals */
	for (i = 0, cpu = 0; i < user_param->threads_num; i++, cpu++) {
		while (cpusmask) {
			if (cpusmask_test_bit(cpu, &cpusmask))
				break;
			if (++cpu == max_cpus)
				cpu = 0;
		}
		server_data.tdata[i].affinity = cpu;

		server_data.tdata[i].portal_index =
					(i % user_param->portals_arr_len);
		server_data.tdata[i].user_param = user_param;

		pthread_create(&server_data.tdata[i].thread_id, NULL,
			       portal_server_cb, &server_data.tdata[i]);
	}

	server_data.user_param = user_param;
	pthread_create(&server_data.thread_id, NULL,
		       balancer_server_cb, &server_data);

	server_data.comm = create_comm_struct(user_param);
	if (establish_connection(server_data.comm)) {
		fprintf(stderr, "failed to establish connection\n");
		goto cleanup;
	}


	printf("%s", RESULT_FMT);
	printf("%s", RESULT_LINE);

	while (1) {
		/* sync test parameters */
		retval = ctx_read_data(server_data.comm, &command,
				       sizeof(command), &len);
		if (retval) {	/* disconnection */
			fprintf(stderr, "program aborted\n");
			break;
		}

		if (len == 0) { /* handshake */
			ctx_write_data(server_data.comm, NULL, 0);
			break;
		}
		switch (command.command) {
		case GetTestResults:
			on_test_results(&command.results);
			ctx_write_data(server_data.comm, NULL, 0);
			break;
		case  GetTestParams:
			break;
		default:
			fprintf(stderr, "unknown command %d\n", len);
			exit(0);
			break;
		};
	}
	if (retval == 0)
		printf("%s", RESULT_LINE);

	/* normal exit phase */
	ctx_close_connection(server_data.comm);

cleanup:
	for (i = 0; i < user_param->threads_num; i++)
		xio_context_stop_loop(server_data.tdata[i].ctx);

	destroy_comm_struct(server_data.comm);

	/* join the threads */
	for (i = 0; i < user_param->threads_num; i++)
		pthread_join(server_data.tdata[i].thread_id, NULL);

	if (server_data.running)
		xio_context_stop_loop(server_data.ctx);

	pthread_join(server_data.thread_id, NULL);

	free(server_data.tdata);

	xio_shutdown();

	return 0;
}
