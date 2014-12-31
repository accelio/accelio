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
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>

#include "libxio.h"

#define QUEUE_DEPTH		512
#define PRINT_COUNTER		4000000
#define PIDFILE_LOCATION	"/var/run/xiosrvd.pid"
#define logerr(fmt, ...) \
	logit(LOG_ERR, fmt ": %s", ##__VA_ARGS__, strerror(errno))


/* server private data */
struct server_data {
	struct xio_context	*ctx;
	struct xio_connection	*connection;
	uint64_t		nsent;
	uint64_t		cnt;
	struct xio_msg		rsp[QUEUE_DEPTH];	/* global message */
};

/* Do we have to finish? */
volatile int exit_flag;

/* Do we have to reload the configuration? */
volatile int reload_flag;

/* If true, messages go to syslog, otherwise to stderr */
static int use_syslog;

/* Path of the pid file */
static char *pid_file = PIDFILE_LOCATION;

/* If true, don't fork to the background */
static int nofork_flag;

/* If true, enable debug mode */
static int debug_flag;

static struct server_data server_data;

/*---------------------------------------------------------------------------*/
/* logit								     */
/*---------------------------------------------------------------------------*/
void logit(int level, const char *fmt, ...)
{
	va_list ap;
	char *msg;
	int  ret;

	va_start(ap, fmt);
	if (use_syslog) {
		vsyslog(level, fmt, ap);
	} else {
		ret = vasprintf(&msg, fmt, ap);
		if (ret) {
			printf("%s\n", msg);
			free(msg);
		}
	}
	va_end(ap);
}

/*---------------------------------------------------------------------------*/
/* process_request							     */
/*---------------------------------------------------------------------------*/
static void process_request(struct server_data *server_data,
			    struct xio_msg *req)
{
	struct xio_iovec_ex	*sglist = vmsg_sglist(&req->in);
	char			*str;
	int			nents = vmsg_sglist_nents(&req->in);
	int			len, i;
	char			tmp;

	/* note all data is packed together so in order to print each
	 * part on its own NULL character is temporarily stuffed
	 * before the print and the original character is restored after
	 * the printf
	 */
	if (++server_data->cnt == PRINT_COUNTER) {
		str = (char *)req->in.header.iov_base;
		len = req->in.header.iov_len;
		if (str) {
			if (((unsigned) len) > 64)
				len = 64;
			tmp = str[len];
			str[len] = '\0';
			logit(LOG_INFO, "message header : [%lu] - %s",
			      (req->sn + 1), str);
			str[len] = tmp;
		}
		for (i = 0; i < nents; i++) {
			str = (char *)sglist[i].iov_base;
			len = sglist[i].iov_len;
			if (str) {
				if (((unsigned)len) > 64)
					len = 64;
				tmp = str[len];
				str[len] = '\0';
				logit(LOG_INFO, "message data: " \
				      "[%lu][%d][%d] - %s",
				      (req->sn + 1), i, len, str);
				str[len] = tmp;
			}
		}
		server_data->cnt = 0;
	}
	req->in.header.iov_base	  = NULL;
	req->in.header.iov_len	  = 0;
	vmsg_sglist_set_nents(&req->in, 0);
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct server_data *server_data = (struct server_data *)cb_user_context;

	printf("session event: %s. session:%p, connection:%p, reason: %s\n",
	       xio_session_event_str(event_data->event),
	       session, event_data->conn,
	       xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		server_data->connection = event_data->conn;
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		server_data->connection = NULL;
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		xio_context_stop_loop(server_data->ctx);  /* exit */
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

	/* automatically accept the request */
	printf("new session event. session:%p\n", session);

	if (server_data->connection == NULL)
		xio_accept(session, NULL, 0, NULL, 0);
	else
		xio_reject(session, (enum xio_status)EISCONN , NULL, 0);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session,
		      struct xio_msg *req,
		      int last_in_rxq,
		      void *cb_user_context)
{
	struct server_data *server_data = (struct server_data *)cb_user_context;
	int i = req->sn % QUEUE_DEPTH;

	/* process request */
	process_request(server_data, req);

	/* attach request to response */
	server_data->rsp[i].request = req;

	xio_send_response(&server_data->rsp[i]);
	server_data->nsent++;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops  server_ops = {
	.on_session_event		=  on_session_event,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  on_request,
	.on_msg_error			=  NULL
};

/*---------------------------------------------------------------------------*/
/* signal_handler							     */
/*---------------------------------------------------------------------------*/
static void signal_handler(int sig)
{
	if (sig == SIGHUP)
		reload_flag = 1;
	else
		exit_flag = 1;

	if (server_data.connection)
		xio_disconnect(server_data.connection);
	else
		xio_context_stop_loop(server_data.ctx);  /* exit */
}


static struct option longopts[] = {
	{ "addr",	required_argument,	NULL, 'a' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "transport",	required_argument,	NULL, 'r' },
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "nofork",	no_argument,		NULL, 'n' },
	{ "version",	no_argument,		NULL, 'V' },
	{ NULL }
};

/*---------------------------------------------------------------------------*/
/* usage								     */
/*---------------------------------------------------------------------------*/
static void usage(const char *prog, int error)
{
	printf("Usage: %s [options]\n", prog);
	printf("Valid options:\n");
	printf("\t-a address, --addr ipaddress	" \
	       "Use the specified ip address\n");
	printf("\t-p port, --port port	Use the specified port\n");
	printf("\t-r transport, --trans transport Transport type (rdma/tcp)\n");
	printf("\t-h, --help		This help text\n");
	printf("\t-d, --debug		Debug mode: don't fork, " \
	       "log traffic to stdout\n");
	printf("\t-n, --nofork		Don't fork to the background\n");
	printf("\t-V, --version		Print the version number and exit\n");
	exit(error);
}

/*---------------------------------------------------------------------------*/
/* create_pidfile							     */
/*---------------------------------------------------------------------------*/
static int create_pidfile(const char *pidfile)
{
	FILE *file = NULL;
	int fd, pid, rc = 0;

	/* open the file and associate a stream with it */
	fd = open(pidfile, O_RDWR|O_CREAT, 0644);
	if (fd != -1)
		file = fdopen(fd, "r+");

	if (fd == -1 || file == NULL) {
		logit(LOG_ERR, "open failed, pidfile=%s, errno=%s",
		      pidfile, strerror(errno));
		return -1;
	}

	/* Lock the file */
	if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
		logit(LOG_ERR, "flock failed, pidfile=%s, errno=%s",
		      pidfile, strerror(errno));
		fclose(file);
		return -1;
	}

	pid = getpid();
	if (!fprintf(file, "%d\n", pid)) {
		logit(LOG_ERR, "fprintf failed, pidfile=%s, errno=%s",
		      pidfile, strerror(errno));
		fclose(file);
		return -1;
	}
	fflush(file);

	if (flock(fd, LOCK_UN) == -1) {
		logit(LOG_ERR, "flock failed, pidfile=%s, errno=%s",
		      pidfile, strerror(errno));
		fclose(file);
		return -1;
	}
	fclose(file);

	return rc;
}

/*---------------------------------------------------------------------------*/
/* remove_pidfile							     */
/*---------------------------------------------------------------------------*/
static inline void remove_pidfile(void)
{
	unlink(pid_file);
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *const argv[])
{
	struct xio_server	*server;	/* server portal */
	char			url[256];
	int			i;
	struct sigaction	sa;
	int			c;
	char			*addr = NULL;
	char			*port = NULL;
	char			*trans = NULL;

	while (1) {
		c = getopt_long(argc, argv, "a:p:r:hdnV", longopts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			addr = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 'r':
			trans = optarg;
			break;
		case 'h':
			usage(argv[0], 0);
		case 'd':
			debug_flag++;
			nofork_flag++;
			break;
		case 'n':
			nofork_flag++;
			break;
		case 'V':
			printf("%s\n", PACKAGE_STRING);
			exit(0);
			break;
		default:
			usage(argv[0], 1);
			break;
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGPIPE, &sa, NULL);


	if (!nofork_flag && daemon(0, 0)) {
		logerr("daemon() failed");
		exit(1);
	}

	if (!debug_flag) {
		openlog("xiosrvd", LOG_PID, LOG_DAEMON);
		use_syslog = 1;
	}

	/* Create the process PID file */
	if (create_pidfile(pid_file) != 0)
		exit(EXIT_FAILURE);

	/* initialize library */
	xio_init();

		/* create "hello world" message */
	memset(&server_data, 0, sizeof(server_data));
	for (i = 0; i < QUEUE_DEPTH; i++) {
		server_data.rsp[i].out.header.iov_base =
			strdup("hello world header response");
		server_data.rsp[i].out.header.iov_len =
			strlen((const char *)
				server_data.rsp[i].out.header.iov_base) + 1;
	}

	/* create thread context for the client */
	server_data.ctx	= xio_context_create(NULL, 0, -1);


	/* create url to connect to */
	if (trans)
		sprintf(url, "%s://%s:%s", trans, addr, port);
	else
		sprintf(url, "rdma://%s:%s", addr, port);
reload:
	/* bind a listener server to a portal/url */
	server = xio_bind(server_data.ctx, &server_ops,
			  url, NULL, 0, &server_data);
	if (server) {
		logit(LOG_INFO, "listen to %s", url);
		xio_context_run_loop(server_data.ctx, XIO_INFINITE);

		/* free the server */
		xio_unbind(server);

		if (reload_flag) {
			reload_flag = 0;
			goto reload;
		}
		/* normal exit phase */
		logit(LOG_INFO, "exit signaled");
	}

	/* free the message */
	for (i = 0; i < QUEUE_DEPTH; i++)
		free(server_data.rsp[i].out.header.iov_base);


	/* free the context */
	xio_context_destroy(server_data.ctx);

	xio_shutdown();

	remove_pidfile();

	if (use_syslog)
		closelog();

	return 0;
}
