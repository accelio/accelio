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
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <getopt.h>
#include "xio_perftest_parameters.h"




#define test_type_str(type) (((type) == BW) ? "BW" : "LAT")

/*---------------------------------------------------------------------------*/
/* isnumeric								     */
/*---------------------------------------------------------------------------*/
static int isnumeric(char *str)
{
	char *p = str;

	while (*p) {
		if (!isdigit(*p))
			return 0;
		p++;
	}
	return 1;
}

/*---------------------------------------------------------------------------*/
/* tokenize_host_port							     */
/*---------------------------------------------------------------------------*/
static int tokenize_host_port(char *token, char *host, uint16_t *port)
{
	char *p = strstr(token, ":");
	int len;

	if (p == NULL)
		return -1;

	if (!isnumeric(p+1))
		return -1;

	/* host */
	len = p-token;
	strncpy(host, token, len);
	host[len] = 0;

	/* port */
	*port = (uint16_t)strtol(p+1, NULL, 0);

	return 0;
}

/* parses "host:port;host:port;..." string */
/*---------------------------------------------------------------------------*/
/* portals_arg_to_urls							     */
/*---------------------------------------------------------------------------*/
static char **portals_arg_to_urls(char *transport,
				  char *portals_arg, uint32_t *urls_vec_len)
{
	char		*token;
	char		delim[] = ";";
	char		*str;
	char		host[256];
	char		url[1024];
	char		*array[1024];
	char		**vec = NULL;
	uint16_t	port;
	int		n = 0, i;


	str = strdup(portals_arg);

	/* get the first token */
	token = strtok(str, delim);

	/* walk through other tokens */
	while (token != NULL && n < 1024) {
		if (tokenize_host_port(token, host, &port))
			goto cleanup;
		sprintf(url, "%s://%s:%d", transport, host, port);
		array[n] = strdup(url);
		n++;

		token = strtok(NULL, delim);
	}
	if (n > 0) {
		vec = (char **)calloc(n+1, sizeof(*vec));
		if (vec == NULL)
			goto cleanup;
		for (i = 0; i < n; i++)
			vec[i] = array[i];

		*urls_vec_len = n;
	}

cleanup:
	free(str);

	return vec;
}

/*---------------------------------------------------------------------------*/
/* usage                                                                     */
/*---------------------------------------------------------------------------*/
void usage(const char *argv0, int status)
{
	printf("Usage:\n");
	printf("  %s [OPTIONS] <host>\tConnect to server at <host>\n",
	       basename(argv0));
	printf("\n");
	printf("Options:\n");

	printf("\t-c, --cpu=<cpu num> ");
	printf("\t\t\t\tBind the process to specific cpu (default %d)\n",
	       XIO_DEF_CPU);

	printf("\t-p, --port=<port> ");
	printf("\t\t\t\tConnect to port <port> (default %d)\n",
	       XIO_DEF_PORT);

	printf("\t-n, --threads_number=<length> ");
	printf("\t\t\tSet the maximum number of threads in test " \
			"(default %d)\n", XIO_DEF_THREADS_NUM);

	printf("\t-r, --transport=<type>");
	printf("\t\t\t\tSet the transport type to rdma/tcp (default rdma)\n");

	printf("\t-i, --interface=<name>");
	printf("\t\t\t\tSet the interface name (default %s)\n",
	       XIO_DEF_INTERFACE);

	printf("\t-w, --portals={\"addr:port,addr:port,...\"}");
	printf("\tSet address and port of each portal in server\n");

	printf("\t-t, --poll_timeout=<number> ");
	printf("\t\t\tSet polling timeout in microseconds " \
			"(default %d)\n", XIO_DEF_POLL_TIMEOUT);

	printf("\t-q, --queue_depth=<number> ");
	printf("\t\t\tSet the number of messages to send " \
	       "(default %d)\n", XIO_DEF_QUEUE_DEPTH);

	printf("\t-s, --start_thread=<thread num> ");
	printf("\t\t\t\tSet the start number of thread (default %d)\n",
	       XIO_DEF_START_THREAD);


	printf("\t-v, --version ");
	printf("\t\t\t\t\tPrint the version and exit\n");

	printf("\t-h, --help ");
	printf("\t\t\t\t\tDisplay this help and exit\n");

	exit(status);
}

/*---------------------------------------------------------------------------*/
/* force_dependencies							     */
/*---------------------------------------------------------------------------*/
static int force_dependencies(struct perf_parameters *user_param)
{
	if (user_param->test_type == LAT) {
		user_param->queue_depth = LAT_QUEUE_DEPTH;
		if (user_param->poll_timeout == XIO_DEF_POLL_TIMEOUT) {
			if (user_param->machine_type == SERVER)
				user_param->poll_timeout =
					SERVER_LAT_POLL_TIMEOUT;
			else
				user_param->poll_timeout =
					CLIENT_LAT_POLL_TIMEOUT;
		}
	}
	if (user_param->test_type == BW) {
		if (user_param->poll_timeout == XIO_DEF_POLL_TIMEOUT) {
			if (user_param->machine_type == SERVER)
				user_param->poll_timeout =
					SERVER_BW_POLL_TIMEOUT;
			else
				user_param->poll_timeout =
					CLIENT_BW_POLL_TIMEOUT;
		}
	}
	if (user_param->machine_type == SERVER) {
		if (user_param->portals_arr == NULL) {
			printf("portals argument is mandatory on server\n");
			return -1;
		}
	}
	if (user_param->threads_num  < 1) {
		printf("threads number is mandatory - recommended cores " \
		       "per numa\n");
		return -1;
	}



	return 0;
}

/*---------------------------------------------------------------------------*/
/* init_perf_params							     */
/*---------------------------------------------------------------------------*/
static void init_perf_params(struct perf_parameters *user_param)
{
	user_param->server_port		= XIO_DEF_PORT;
	user_param->cpu			= XIO_DEF_CPU;
	user_param->start_thread	= XIO_DEF_START_THREAD;
	user_param->queue_depth		= XIO_DEF_QUEUE_DEPTH;
	user_param->poll_timeout	= XIO_DEF_POLL_TIMEOUT;
	user_param->threads_num		= XIO_DEF_THREADS_NUM;
	user_param->test_type		= XIO_TEST_TYPE;
	user_param->verb		= XIO_VERB;
	user_param->machine_type	= SERVER;
	user_param->output_file		= NULL;
	user_param->transport		= NULL;
	user_param->portals_arr		= NULL;
	user_param->portals_arr_len     = 0;
	user_param->server_addr		= NULL;
	user_param->intf_name		= NULL;
}

/*---------------------------------------------------------------------------*/
/* destroy_perf_params							     */
/*---------------------------------------------------------------------------*/
void destroy_perf_params(struct perf_parameters *user_param)
{
	if (user_param->transport) {
		free(user_param->transport);
		user_param->transport = NULL;
	}

	if (user_param->portals_arr) {
		unsigned int i;
		for (i = 0; i < user_param->portals_arr_len; i++)
			free(user_param->portals_arr[i]);
		free(user_param->portals_arr);
		user_param->portals_arr = NULL;
	}
	if (user_param->intf_name) {
		free(user_param->intf_name);
		user_param->intf_name = NULL;
	}

	if (user_param->server_addr) {
		free(user_param->server_addr);
		user_param->server_addr = NULL;
	}

	if (user_param->output_file) {
		free(user_param->output_file);
		user_param->output_file = NULL;
	}
}

/*---------------------------------------------------------------------------*/
/* parse_cmdline							     */
/*---------------------------------------------------------------------------*/
int parse_cmdline(struct perf_parameters *user_param,
		  int argc, char **argv)
{
	int	max_cpus;
	char	*portals = NULL;
	long	l;

	if (!user_param)
		return -1;

	init_perf_params(user_param);

	while (1) {
		int c;

		static struct option const long_options[] = {
			{ .name = "cpu",	 .has_arg = 1, .val = 'c'},
			{ .name = "interface",	 .has_arg = 1, .val = 'i'},
			{ .name = "port",	 .has_arg = 1, .val = 'p'},
			{ .name = "threads",	 .has_arg = 1, .val = 'n'},
			{ .name = "transport",	 .has_arg = 1, .val = 'r'},
			{ .name = "portals",	 .has_arg = 1, .val = 'w'},
			{ .name = "poll_time",   .has_arg = 1, .val = 't'},
			{ .name = "queue_depth", .has_arg = 1, .val = 'q'},
			{ .name = "output_file", .has_arg = 1, .val = 'o'},
			{ .name = "start_thread",.has_arg = 1, .val = 's'},
			{ .name = "version",	 .has_arg = 0, .val = 'v'},
			{ .name = "help",	 .has_arg = 0, .val = 'h'},
			{0, 0, 0, 0},
		};

		static char *short_options = "c:i:p:n:r:w:t:q:o:s:vh";

		c = getopt_long(argc, argv, short_options,
				long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			if (!optarg)
				goto invalid_cmdline;
			errno = 0;
			l = strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "strtol failed :%m\n");
				goto invalid_cmdline;
			}
			user_param->cpu = (uint16_t)l;
			break;
		case 'p':
			if (!optarg)
				goto invalid_cmdline;

			errno = 0;
			l = strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "strtol failed :%m\n");
				goto invalid_cmdline;
			}
			user_param->server_port = (uint16_t)l;
			break;
		case 'n':
			if (!optarg)
				goto invalid_cmdline;

			errno = 0;
			l = strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "strtol failed :%m\n");
				goto invalid_cmdline;
			}
			user_param->threads_num = (uint32_t)l;
			max_cpus = sysconf(_SC_NPROCESSORS_ONLN);
			if ((int)user_param->threads_num > max_cpus) {
				fprintf(stderr, "more threads then cpus\n");
				goto invalid_cmdline;
			}
			break;
		case 'r':
			if (!optarg)
				goto invalid_cmdline;

			if (optarg && !user_param->transport) {
				user_param->transport = strdup(optarg);
				if (!user_param->transport)
					goto invalid_cmdline;
			}
			break;
		case 'w':
			if (optarg && !portals && !user_param->portals_arr) {
				portals = strdup(optarg);
				if (!portals)
					goto invalid_cmdline;
			} else
				goto invalid_cmdline;
			break;
		case 't':
			if (!optarg)
				goto invalid_cmdline;
			errno = 0;
			l = strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "strtol failed :%m\n");
				goto invalid_cmdline;
			}
			user_param->poll_timeout = (uint32_t)l;
			break;
		case 'q':
			if (!optarg)
				goto invalid_cmdline;
			errno = 0;
			l = strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "strtol failed :%m\n");
				goto invalid_cmdline;
			}
			user_param->queue_depth = (uint32_t)l;
			break;
		case 'o':
			if (optarg && !user_param->output_file) {
				user_param->output_file = strdup(optarg);
				if (!user_param->output_file)
					goto invalid_cmdline;

			} else
				goto invalid_cmdline;

		break;
		case 'i':
			if (optarg && !user_param->intf_name) {
				user_param->intf_name = strdup(optarg);
				if (!user_param->intf_name)
					goto invalid_cmdline;
			} else
				goto invalid_cmdline;

		break;
		case 's':
			if (!optarg)
				goto invalid_cmdline;
			errno = 0;
			l = strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "strtol failed :%m\n");
				goto invalid_cmdline;
			}
			user_param->start_thread = l;
			break;
		case 'v':
			printf("version: %s\n", XIO_PERF_VERSION);
			exit(0);
			break;
		case 'h':
			usage(argv[0], 0);
			break;
		break;
		default:
			fprintf(stderr, " invalid command or flag.\n");
			goto invalid_cmdline;
			break;
		}
	}
	if (optind == argc - 1) {
		if (argv[optind] && !user_param->server_addr) {
			user_param->server_addr = strdup(argv[optind]);
			if (!user_param->server_addr)
				goto invalid_cmdline;
			user_param->machine_type = CLIENT;
		}
	} else if (optind < argc) {
		goto invalid_cmdline;
	}

	if (!user_param->transport) {
		user_param->transport = strdup(XIO_DEF_TRANSPORT);
	}
	if (!user_param->intf_name) {
		user_param->intf_name = strdup(XIO_DEF_INTERFACE);
	}
	if (user_param->start_thread > user_param->threads_num)
		user_param->start_thread = user_param->threads_num;


	if (portals && !user_param->portals_arr) {
		user_param->portals_arr =
				portals_arg_to_urls(
						user_param->transport,
						portals,
						&user_param->portals_arr_len);
		if (!user_param->portals_arr || !*user_param->portals_arr) {
			fprintf(stderr, "failed to parse portals\n");
			goto invalid_cmdline;
		}
	}

	if (force_dependencies(user_param))
		goto invalid_cmdline;

	if (portals) {
		free(portals);
		portals = NULL;
	}

	return 0;

invalid_cmdline:
	if (portals)
		free(portals);

	destroy_perf_params(user_param);
	fprintf(stderr,
		"Invalid Command line. Please check command rerun\n");
	usage(argv[0], -1);
	exit(-1);
}

/*************************************************************
* Function: print_test_info
*-------------------------------------------------------------
* Description: print the test configuration
*************************************************************/
void print_test_info(const struct perf_parameters *user_param)
{
	printf(" =============================================\n");
	if (user_param->server_addr)
		printf(" Server Address		: %s\n",
		       user_param->server_addr);
	if (user_param->intf_name)
		printf(" Local Interface	: %s\n",
		       user_param->intf_name);
		printf(" Server Port		: %d\n",
	       user_param->server_port);
	printf(" Transport Type		: %s\n",
	       user_param->transport);
	printf(" Test Type		: %s\n",
	       test_type_str(user_param->test_type));
	printf(" Queue Depth		: %d\n",
	       user_param->queue_depth);
	printf(" Threads		: %d\n",
	       user_param->threads_num);
	printf(" Start Thread		: %d\n",
	       user_param->start_thread);
	printf(" Poll timeout		: %d\n",
	       user_param->poll_timeout);
	if (user_param->output_file)
		printf(" Output file		: %s\n",
		       user_param->output_file);
	printf(" CPU Affinity		: %x\n",
	       user_param->cpu);
	printf(" =============================================\n");
}

