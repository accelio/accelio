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
#define PIDFILE_LOCATION	"/var/run/xioclntd.pid"
#define logerr(fmt, ...) \
	logit(LOG_ERR, fmt ": %s", ##__VA_ARGS__, strerror(errno))


/* private session data */
struct session_data {
	struct xio_context	*ctx;
	struct xio_connection	*conn;
	uint64_t		cnt;
	uint64_t		nsent;
	uint64_t		nrecv;
	uint64_t		pad;
	struct xio_msg		req[QUEUE_DEPTH];
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

static int reconnect_flag;

static struct session_data session_data;

/*---------------------------------------------------------------------------*/
/* logit								     */
/*---------------------------------------------------------------------------*/
static void logit(int level, const char *fmt, ...)
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
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct session_data *session_data,
			     struct xio_msg *rsp)
{
	if (++session_data->cnt == PRINT_COUNTER) {
		((char *)(rsp->in.header.iov_base))[rsp->in.header.iov_len] = 0;
		logit(LOG_INFO, "message: [%lu] - %s\n",
		      (rsp->request->sn + 1), (char *)rsp->in.header.iov_base);
		session_data->cnt = 0;
	}
	rsp->in.header.iov_base	  = NULL;
	rsp->in.header.iov_len	  = 0;
	vmsg_sglist_set_nents(&rsp->in, 0);
}
/*---------------------------------------------------------------------------*/
/* on_connection_established						     */
/*---------------------------------------------------------------------------*/
static void on_connection_established(struct xio_connection *connection,
				      struct session_data *session_data)
{
	int i = 0;
	/* send first message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		xio_send_request(connection, &session_data->req[i]);
		session_data->nsent++;
	}
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct session_data *session_data = (struct session_data *)
						cb_user_context;

	logit(LOG_INFO, "session event: %s. reason: %s\n",
	      xio_session_event_str(event_data->event),
	      xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_DISCONNECTED_EVENT:
	case XIO_SESSION_CONNECTION_REFUSED_EVENT:
		reconnect_flag = 1;
		break;
	case XIO_SESSION_CONNECTION_ESTABLISHED_EVENT:
		on_connection_established(event_data->conn, session_data);
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		session_data->conn = NULL;
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		xio_context_stop_loop(session_data->ctx);  /* exit */
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
		       struct xio_msg *rsp,
		       int last_in_rxq,
		       void *cb_user_context)
{
	struct session_data *session_data = (struct session_data *)
						cb_user_context;
	int i = rsp->request->sn % QUEUE_DEPTH;

	session_data->nrecv++;
	/* process the incoming message */
	process_response(session_data, rsp);

	/* acknowledge xio that response is no longer needed */
	xio_release_response(rsp);

	if (reconnect_flag || reload_flag)
		return 0;

	/* resend the message */
	xio_send_request(session_data->conn, &session_data->req[i]);
	session_data->nsent++;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  NULL,
	.on_msg				=  on_response,
	.on_msg_error			=  NULL,
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

	if (session_data.conn)
		xio_disconnect(session_data.conn);
	else
		xio_context_stop_loop(session_data.ctx);  /* exit */
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
	printf("\t-r transport, --trans transport	" \
	       "Transport type (rdma/tcp)\n");
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
static void remove_pidfile(void)
{
	unlink(pid_file);
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *const argv[])
{
	struct xio_session	*session;
	char			url[256];
	int			i;
	struct sigaction	sa;
	int			c;
	char			*addr = NULL;
	char			*port = NULL;
	char			*trans = NULL;
	struct xio_session_params params;
	struct xio_connection_params cparams;

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
		openlog("xioclntd", LOG_PID, LOG_DAEMON);
		use_syslog = 1;
	}

	/* Create the process PID file */
	if (create_pidfile(pid_file) != 0)
		exit(EXIT_FAILURE);

	memset(&session_data, 0, sizeof(session_data));
	memset(&params, 0, sizeof(params));
	memset(&cparams, 0, sizeof(cparams));

	/* initialize library */
	xio_init();

	/* create "hello world" message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		memset(&session_data.req[i], 0, sizeof(session_data.req[i]));
		/* header */
		session_data.req[i].out.header.iov_base =
			strdup("hello world header request");
		session_data.req[i].out.header.iov_len =
			strlen((const char *)
				session_data.req[i].out.header.iov_base) + 1;
		/* iovec[0]*/
		session_data.req[i].out.sgl_type	   = XIO_SGL_TYPE_IOV;
		session_data.req[i].out.data_iov.max_nents = XIO_IOVLEN;

		session_data.req[i].out.data_iov.sglist[0].iov_base =
			strdup("hello world iovec request");

		session_data.req[i].out.data_iov.sglist[0].iov_len =
			strlen((const char *)
				session_data.req[i].out.data_iov.sglist[0].iov_base) + 1;

		session_data.req[i].out.data_iov.nents = 1;
	}
	/* create thread context for the client */
	session_data.ctx = xio_context_create(NULL, 0, -1);

	/* create url to connect to */
	if (trans)
		sprintf(url, "%s://%s:%s", trans, addr, port);
	else
		sprintf(url, "rdma://%s:%s", addr, port);

	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.user_context	= &session_data;
	params.uri		= url;


reconnect:
	session = xio_session_create(&params);

	cparams.session			= session;
	cparams.ctx			= session_data.ctx;
	cparams.conn_user_context	= &session_data;

	/* connect the session  */
	session_data.conn = xio_connect(&cparams);

	/* event dispatcher is now running */
	xio_context_run_loop(session_data.ctx, XIO_INFINITE);

	if (reconnect_flag || reload_flag) {
		session_data.cnt = 0;
		if (reconnect_flag)
			sleep(1);
		reload_flag = 0;
		reconnect_flag = 0;
		goto reconnect;
	}

	/* normal exit phase */
	logit(LOG_INFO, "exit signaled\n");

	/* free the message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		free(session_data.req[i].out.header.iov_base);
		free(session_data.req[i].out.data_iov.sglist[0].iov_base);
	}

	/* free the context */
	xio_context_destroy(session_data.ctx);

	xio_shutdown();

	remove_pidfile();

	if (use_syslog)
		closelog();

	return 0;
}
