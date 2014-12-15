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
#include <string.h>
#include <inttypes.h>
#include <sched.h>
#include "libxio.h"
#include "xio_perftest_parameters.h"
#include "xio_perftest.h"
#include "get_clock.h"

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
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct perf_parameters	user_param;
	int optval;


	if (parse_cmdline(&user_param, argc, argv) != 0)
		return -1;

	print_test_info(&user_param);

	set_cpu_affinity(user_param.cpu);

	/* run as root */
	if (user_param.test_type == LAT) {
		optval = 1;
		xio_set_opt(NULL,
			    XIO_OPTLEVEL_RDMA,
			    XIO_OPTNAME_ENABLE_DMA_LATENCY,
			    &optval, sizeof(optval));
	}

	/* disable nagle algorithm for tcp */
	optval = 1;
	xio_set_opt(NULL,
			XIO_OPTLEVEL_TCP, XIO_OPTNAME_TCP_NO_DELAY,
			&optval, sizeof(optval));

	if (user_param.machine_type == CLIENT)
		run_client_test(&user_param);

	if (user_param.machine_type == SERVER)
		run_server_test(&user_param);

	/* run as root */
	if (user_param.test_type == LAT) {
		optval = 0;
		xio_set_opt(NULL,
			    XIO_OPTLEVEL_RDMA,
			    XIO_OPTNAME_ENABLE_DMA_LATENCY,
			    &optval, sizeof(optval));
	}

	destroy_perf_params(&user_param);

	return 0;
}
