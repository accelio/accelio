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
#ifndef XIO_PERFTEST_PARAMETERS_H
#define XIO_PERFTEST_PARAMETERS_H

/* The type of the test */
typedef enum { LAT , BW } TestType;

/* The type of the machine ( server or client actually). */
typedef enum { SERVER , CLIENT , UNCHOSEN} MachineType;

/* verb operation */
typedef enum { READ, WRITE} Verb;



#define LAT_QUEUE_DEPTH			1
#define BW_QUEUE_DEPTH			50

#define CLIENT_BW_POLL_TIMEOUT		0
#define SERVER_BW_POLL_TIMEOUT		25
#define SERVER_LAT_POLL_TIMEOUT		100
#define CLIENT_LAT_POLL_TIMEOUT		100


#define XIO_DEF_PORT			2061
#define XIO_DEF_CPU			0
#define XIO_DEF_START_THREAD		1

#define XIO_DEF_TRANSPORT		"rdma"

#define XIO_DEF_INTERFACE		"ib0"

#if defined(TEST_LAT)
#define XIO_TEST_TYPE			LAT
#define XIO_DEF_QUEUE_DEPTH		LAT_QUEUE_DEPTH
#define XIO_DEF_POLL_TIMEOUT		100
#elif defined(TEST_BW)
#define XIO_TEST_TYPE			BW
#define XIO_DEF_QUEUE_DEPTH		BW_QUEUE_DEPTH
#define XIO_DEF_POLL_TIMEOUT		0
#endif

#if defined(VERB_READ)
#define XIO_VERB			READ
#elif defined(VERB_WRITE)
#define XIO_VERB			WRITE
#endif

#define XIO_DEF_THREADS_NUM		0
#define XIO_PERF_VERSION		"1.0.0"

#define RESULT_LINE "----------------------------------------------------------------------------------------------------------------------\n"

/* The format of the results */
#define RESULT_FMT		" #bytes     #threads   #TPS       BW average[MBps]   Latency average[usecs]   Latency low[usecs]   Latency peak[usecs]\n"
/* Result print format */
#define REPORT_FMT		" %-7lu     %-2d         %-9.2lu	  %-9.2lf     %-9.2lf                  %-9.2lf              %-9.2lf\n"


struct perf_parameters {
	uint16_t		server_port;
	uint16_t		cpu;
	uint32_t		start_thread;
	uint32_t		queue_depth;
	uint32_t		poll_timeout;
	uint32_t		threads_num;
	uint32_t		portals_arr_len;
	uint32_t		pad;
	TestType		test_type;
	MachineType		machine_type;
	Verb			verb;
	char			*output_file;
	char			*transport;
	char			**portals_arr;
	char			*server_addr;
	char			*intf_name;
};


/*---------------------------------------------------------------------------*/
/* usage                                                                     */
/*---------------------------------------------------------------------------*/
void usage(const char *argv0, int status);

/*---------------------------------------------------------------------------*/
/* parse_cmdline							     */
/*---------------------------------------------------------------------------*/
int parse_cmdline(struct perf_parameters *perf_parameters,
		  int argc, char **argv);

/*---------------------------------------------------------------------------*/
/* print_test_info							     */
/*---------------------------------------------------------------------------*/
void print_test_info(const struct perf_parameters *perf_parameters_p);


/*---------------------------------------------------------------------------*/
/* destroy_perf_params							     */
/*---------------------------------------------------------------------------*/
void destroy_perf_params(struct perf_parameters *user_param);

#endif /* XIO_PERFTEST_PARAMETERS_H */

