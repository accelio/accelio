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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <fcntl.h>
#include "get_clock.h"

#include "libraio.h"


#define IODEPTH	1024
#define ONE_MB	(1 << 20)


#define min(a, b) (((a) > (b)) ? (b) : (a))

/* Divide and round up */
#define div_and_round_up(value, div) \
	(((value % div) != 0) ? (value / div + 1) : (value / div))


static char		*file_path;
static char		*server_addr;
static char		*transport;
static uint16_t		server_port;
static int		block_size;
static int		loops;

struct raio_pool {
	void		**stack_ptr;
	void		**stack_end;

	/* pool of tasks */
	void		**array;
	/* LIFO */
	void		**stack;

	/* max number of elements */
	int		max;
	int		pad;
};


static inline void *raio_pool_get(struct raio_pool *q)
{
	return (q->stack_ptr != q->stack_end) ?
		*q->stack_ptr++ : NULL;
}

static inline void raio_pool_put(struct raio_pool *q, void *t)
{
	*--q->stack_ptr = t;
}

struct raio_pool *raio_pool_init(int max, size_t size)
{
	int			i;
	char			*buf;
	char			*data;
	struct raio_pool	*q;
	size_t			elems_alloc_sz;


	/* pool + private data */
	size_t pool_alloc_sz = sizeof(struct raio_pool) +
				2*max*sizeof(void *);

	if (max < 1)
		return NULL;

	buf = (char *)calloc(pool_alloc_sz, sizeof(uint8_t));
	if (buf == NULL)
		return NULL;

	/* pool */
	q = (struct raio_pool *)buf;
	buf = buf + sizeof(struct raio_pool);

	/* stack */
	q->stack = (void **)buf;
	buf = buf + max*sizeof(void *);

	/* array */
	q->array = (void **)buf;
	buf = buf + max*sizeof(void *);

	/* pool data */
	elems_alloc_sz = max*size;

	data = (char *)calloc(elems_alloc_sz, sizeof(uint8_t));
	if (data == NULL) {
		free(q);
		return NULL;
	}

	for (i = 0; i < max; i++) {
		q->array[i]		= data;
		q->stack[i]		= q->array[i];
		data = ((char *)data) + size;
	}

	q->stack_ptr = q->stack;
	q->stack_end = (q->stack_ptr + max);
	q->max = max;

	return q;
}
void raio_pool_free(struct raio_pool *q)
{
	free(q->array[0]);
	free(q);
}

/*---------------------------------------------------------------------------*/
/* usage                                                                     */
/*---------------------------------------------------------------------------*/
static void usage(const char *app) {
	printf("Usage:\n");
	printf("\t%s [OPTIONS] - raio simple file client\n", basename((char *)app));
	printf("options:\n");
	printf("\t--addr, -a <addr>       : server ip address\n");
	printf("\t--port, -p <port>       : server port\n");
	printf("\t--file-path, -f <path>  : file path\n");
	printf("\t--block-size, -b <size> : block size in bytes\n");
	printf("\t--loops, -l <num>       : num of run loops\n");
	printf("\t--transport, -t <name>  : rdma,tcp (default: rdma)\n");
	printf("\t--help, -h              : print this message and exit\n");
	exit(0);
}
static void free_cmdline_params(void)
{
	if (file_path) {
		free(file_path);
		file_path = NULL;
	}
	if (server_addr) {
		free(server_addr);
		server_addr = NULL;
	}
	if (transport) {
		free(transport);
		transport = NULL;
	}
}

/*---------------------------------------------------------------------------*/
/* parse_cmdline							     */
/*---------------------------------------------------------------------------*/
int parse_cmdline(int argc, char **argv)
{
	static struct option const long_options[] = {
		{ .name = "addr",	.has_arg = 1, .val = 'a'},
		{ .name = "port",	.has_arg = 1, .val = 'p'},
		{ .name = "transport",	.has_arg = 1, .val = 't'},
		{ .name = "file-path",	.has_arg = 1, .val = 'f'},
		{ .name = "block-size",	.has_arg = 1, .val = 'b'},
		{ .name = "loops",	.has_arg = 1, .val = 'l'},
		{ .name = "help",	.has_arg = 0, .val = 'h'},
		{0, 0, 0, 0},
	};
	optind = 0;
	opterr = 0;
	server_addr = NULL;
	file_path = NULL;
	transport = NULL;

	while (1) {
		int c;

		static char *short_options = "a:p:t:f:b:l:h";

		c = getopt_long(argc, argv, short_options,
				long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			if (server_addr == NULL)
				server_addr = strdup(optarg);
			if (server_addr == NULL)
				goto cleanup;
			break;
		case 'p':
			server_port =
				(uint16_t)strtol(optarg, NULL, 0);
			break;
		case 't':
			if (transport == NULL)
				transport = strdup(optarg);
			if (transport == NULL)
				goto cleanup;
			break;
		case 'f':
			if (file_path == NULL)
				file_path = strdup(optarg);
			if (file_path == NULL)
				goto cleanup;
			break;
		case 'b':
			block_size = strtol(optarg, NULL, 0);
			break;
		case 'l':
			loops = strtol(optarg, NULL, 0);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		default:
			fprintf(stderr, " invalid command or flag.\n");
			goto cleanup;
			break;
		}
	}
	if (argc == 1)
		usage(argv[0]);
	if (optind < argc)
		goto cleanup;

	return 0;

cleanup:
	free_cmdline_params();
	fprintf(stderr,
		"Invalid Command line. Please check command rerun\n");
	usage(argv[0]);
	exit(-1);
}

/*
 #define WRITE_FILE
*/
int main(int argc, char *argv[])
{
	struct sockaddr_in	servaddr;
	struct stat64		stbuf;
	int			retval;
	raio_context_t		io_ctx;
	struct raio_iocb	**piocb;
	struct raio_pool	*iocb_pool;
	struct raio_event	events[IODEPTH];
	int			i, j;
	int			flags;
	uint64_t		offset = 0;
	int			tot_num;
	int			tot_submitted;
	int			tot_completed = 0;
	int			ncomplete;
	int			nsubmit;
	int			npending;
	int			nqueued;
	int			loop;
	int			fd;
	cycles_t		start_time = 0;
	cycles_t		end_time = 0;
	double			mhz;
	double			usec, size, rate, pps;
#ifdef WRITE_FILE
	int			fdw;
	char *			file = "/tmp/copy";
#endif

	file_path = NULL;
	transport = NULL;
	server_addr = NULL;
	server_port = 0;
	block_size = 0;
	loops = 0;

	parse_cmdline(argc, argv);
	if ((server_addr == NULL) || (server_port == 0) ||
	    (loops == 0) || (file_path == NULL) || (block_size == 0)) {
		fprintf(stderr, " invalid command or flag.\n");
		fprintf(stderr,
			" please check command line and run again.\n\n");
		usage(argv[0]);
	}
	if (transport == NULL)
		transport = strdup("rdma");
	else if (strcmp(transport, "rdma") && strcmp(transport, "tcp")) {
		fprintf(stderr, " invalid transport\n");
		fprintf(stderr,
			" please check command line and run again.\n\n");
		usage(argv[0]);
	}

	/* get clock cycles */
	mhz = get_cpu_mhz(0);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(server_addr);
	servaddr.sin_port = htons(server_port);

#ifdef WRITE_FILE
	fdw = open(file, O_TRUNC|O_WRONLY|O_CREAT|O_SYNC, 0666);
	if (fdw < 0)
		printf("open for write failed %m\n");
#endif

	fd = raio_start(transport, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if (fd == -1) {
		fprintf(stderr, "raio_start failed %s://%s:%d %m\n",
			transport, server_addr, server_port);
		return -1;
	}

	retval = raio_setup(fd, IODEPTH, &io_ctx);
	if (retval == -1) {
		fprintf(stderr, "raio_setup failed - fd:%d %m\n", fd);
		goto stop;
	}

	flags = O_RDONLY | O_LARGEFILE /*| O_DIRECT*/;
	retval = raio_open(fd, file_path, flags);
	if (retval == -1) {
		fprintf(stderr, "raio_open failed %s flags:%x %m\n",
			file_path, flags);
		goto stop;
	}

	/* get the file size */
	retval = raio_fstat(fd, &stbuf);
	if (retval == -1) {
		fprintf(stderr, "raio_fstat failed - fd:%d %m\n", fd);
		goto close_file;
	}

	/* calculate how many iterations are needed */
	tot_num = div_and_round_up(stbuf.st_size, block_size);
	if (tot_num == 0) {
		fprintf(stderr, "invalid file size %ld %d\n",
			(unsigned long)stbuf.st_size, block_size);
		goto close_file;
	}

	/* initialize iocb pool */
	iocb_pool = raio_pool_init(IODEPTH, sizeof(struct raio_iocb));

	/* allocate array for holding pointers */
	piocb = (struct raio_iocb **)calloc(IODEPTH, sizeof(struct raio_iocb *));

	printf("reading started ");
	fflush(stdout);

	for (loop = 0; loop < loops; loop++) {
		offset = 0;
		tot_submitted =  0;
		tot_completed = 0;
		ncomplete = 0;
		npending = 0;
		nqueued = 0;
		nsubmit = 0;

		printf(".");
		fflush(stdout);
		if (loop == loops/2)
			start_time = get_cycles();

		do {
			if (tot_submitted < tot_num) {
				for (i = nqueued; i < IODEPTH; i++) {
					if ((uint64_t)stbuf.st_size <= offset)
						break;
					piocb[i] = (struct raio_iocb *)
						       raio_pool_get(iocb_pool);
					if (piocb[i])  {
						raio_prep_pread(piocb[i], fd,
								NULL,
								block_size,
								offset, NULL);
						offset += block_size;
						nqueued++;
					} else {
						break;
					}
				}
				nsubmit = min(nqueued, IODEPTH-npending);
				if (nsubmit) {
					nsubmit = raio_submit(io_ctx,
							      nsubmit , piocb);
					if (nsubmit <= 0) {
						fprintf(
						  stderr,
						  "\nraio_submit failed: " \
						  "fd:%d %s\n", fd,
						   strerror(-nsubmit));
						goto cleanup;
					}
					tot_submitted  += nsubmit;
					npending += nsubmit;

					for (i = nsubmit, j = 0; i < nqueued;
					     j++, i++)
						piocb[j] = piocb[i];
					nqueued -= nsubmit;
				}
			}
			while (npending > 0) {
				ncomplete = raio_getevents(io_ctx, 1, 1,
							   events, NULL);
				if (ncomplete < 0) {
					fprintf(stderr,
						"\nraio_getevents failed - fd:%d %s\n",
						fd, strerror(-ncomplete));
					goto cleanup;
				}
				if (ncomplete) {
					npending -= ncomplete;
					tot_completed += ncomplete;
					for (i = 0; i < ncomplete; i++) {
#ifdef WRITE_FILE
						lseek(fdw,
						      events[i].obj->u.c.offset,
						      SEEK_SET);
						retval =
						  write(
						     fdw,
						     events[i].obj->u.c.buf,
						     events[i].obj->u.c.nbytes);

#endif
						raio_pool_put(iocb_pool,
							      events[i].obj);
					}
					retval = raio_release(io_ctx,
							      ncomplete,
							      events);
					if (retval == -1) {
						fprintf(stderr,
							"\nraio_release failed: fd:%d %m\n",
							fd);
						goto cleanup;
					}
				}
				if (ncomplete == 0)
					break;
			}
		} while  (tot_completed < tot_num);

		if (loop == loops/2)
			end_time = get_cycles();
	}
	printf("\nreading completed\n");

	usec = (end_time - start_time)/mhz;

	size = 1.0*stbuf.st_size/ONE_MB;
	rate = (1.0*size*ONE_MB)/usec;
	pps = (1.0*tot_num*ONE_MB)/usec;
	printf("done [%d/%d] time: %.2f msecs, size: %.2f MB, " \
			"rate: %.2f MBps, pps: %.0f, block size: %d B\n",
			tot_completed, tot_num, usec/1000,
			size, rate, pps, block_size);

#ifdef WRITE_FILE
	close(fdw);
#endif


cleanup:
	retval = raio_destroy(io_ctx);
	if (retval == -1) {
		fprintf(stderr, "raio_destroy failed - fd:%d %m\n", fd);
		return -1;
	}
	raio_pool_free(iocb_pool);
	free(piocb);

close_file:

	retval = raio_close(fd);
	if (retval == -1) {
		fprintf(stderr, "raio_close failed - fd:%d %m\n", fd);
		return -1;
	}

stop:
	raio_stop(fd);
	free_cmdline_params();

	printf("good bye\n");

	return 0;
}

