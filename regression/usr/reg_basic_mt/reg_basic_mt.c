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
#include <pthread.h>
#include "reg_utils.h"

extern int client_main(int argc, const char *argv[]);
extern int server_main(int argc, const char *argv[]);

char  REG_DEBUG = 0;

struct params {
	int		argc;
	int		pad;
	const char	**argv;
};

struct program_vars {
	char		client_threads_num[8];
	char		server_threads_num[8];
	char		client_dlen[8];
	char		server_dlen[8];
	char		queue_depth[8];
	char		client_disconnect_nr[8];
	char		server_disconnect_nr[8];
	unsigned long	seed;
	unsigned long	test_num;
};


static void *client_thread(void *data)
{
	struct params *params	= (struct params *)data;
	client_main(params->argc, params->argv);
	return NULL;
}

static void *server_thread(void *data)
{
	struct params *params	= (struct params *)data;
	server_main(params->argc, params->argv);
	return NULL;
}

void rand_params(struct program_vars *vars)
{
	int var;
	int max_dlen;
	int max_qdepth;
	int client_threads_num;
	int cpus;

	time((time_t *)&vars->seed);

	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (cpus > 16)
		cpus = 16;

	/*
	vars->test_num = 0;
	vars->seed = 1424589915;
	*/
	srandom(vars->seed);

	do {
		var = random() % cpus;
	} while (var == 0);
	sprintf(vars->server_threads_num, "%d", var);

	/* threads number [1,24] */
	do {
		var = random() % cpus;
	} while (var == 0);
	client_threads_num = var;
	sprintf(vars->client_threads_num, "%d", client_threads_num);

	max_qdepth = (client_threads_num > 2) ? 100 : 300;

	/* queue_depth [1,300] */
	do {
		var = random() % max_qdepth;
	} while (var == 0);
	sprintf(vars->queue_depth, "%d", var);

	if (vars->test_num % 2)
		max_dlen = (client_threads_num > 3) ? 262144 : 524288;
	else
		max_dlen = 10000;

	/* client_dlen [0,1048576] */
	var = random() % max_dlen;
	sprintf(vars->client_dlen, "%d", var);

	/* server_dlen [0,1048576] */
	var = random() % max_dlen;
	sprintf(vars->server_dlen, "%d", var);

	/* client_disconnect_nr [1, 25000] */
	do {
		var = random() % 25000;
	} while (var == 0);
	sprintf(vars->client_disconnect_nr, "%d", var);

	/* server_disconnect_nr [1, 25000] */
	do {
		var = random() % 25000;
	} while (var == 0);
	sprintf(vars->server_disconnect_nr, "%d", var);
}

int main(int argc, char *argv[])
{
	static const char *argvv[11] = { 0 };
	int max_iterations = atoi(argv[3]);

	struct params params  = {
		.argc = argc,
		.argv = argvv
	};
	pthread_t stid, ctid;
	struct	 program_vars vars;

	if (argc == 1)
		return 0;

	vars.test_num = 0;

start:
	rand_params(&vars);
	argvv[0] = argv[0];
	argvv[1] = argv[1];	/* address */
	argvv[2] = argv[2];	/* port */
	argvv[3] = vars.queue_depth;
	argvv[4] = vars.client_threads_num;
	argvv[5] = vars.server_threads_num;
	argvv[6] = vars.client_dlen;
	argvv[7] = vars.server_dlen;
	argvv[8] = vars.client_disconnect_nr;
	argvv[9] = vars.server_disconnect_nr;


	fprintf(stderr, "seed:%lu, queue_depth:%s, client threads:%s, " \
			"server threads:%s, client_dlen:%s, "		\
			"server_dlen:%s, client_disc_nr:%s, "		\
			"server_disc_nr:%s [start]\n",
			vars.seed,
			vars.queue_depth,
			vars.client_threads_num,
			vars.server_threads_num,
			vars.client_dlen,
			vars.server_dlen,
			vars.client_disconnect_nr,
			vars.server_disconnect_nr);

	pthread_create(&stid, NULL, server_thread, &params);
	pthread_create(&ctid, NULL, client_thread, &params);

	pthread_join(stid, NULL);
	pthread_join(ctid, NULL);

	fprintf(stderr, "seed:%lu, queue_depth:%s, client threads:%s, " \
			"server threads:%s, client_dlen:%s, "		\
			"server_dlen:%s, client_disc_nr:%s, "		\
			"server_disc_nr:%s [pass]\n",
			vars.seed,
			vars.queue_depth,
			vars.client_threads_num,
			vars.server_threads_num,
			vars.client_dlen,
			vars.server_dlen,
			vars.client_disconnect_nr,
			vars.server_disconnect_nr);

	vars.test_num++;

	if (!max_iterations || (int)vars.test_num != max_iterations)
		goto start;

	return 0;
}

