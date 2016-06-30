/* Copyright (c) 2013 Mellanox Technologies®. All rights reserved.
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
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/queue.h>
#include "bitset.h"
#include "libxio.h"
#include "raio_handlers.h"
#include <arpa/inet.h>

/*---------------------------------------------------------------------------*/
/* preprocessor macros							     */
/*---------------------------------------------------------------------------*/
#define POLLING_TIME_USEC	70

#ifndef TAILQ_FOREACH_SAFE
#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST(head);					\
	     (var) && ((tvar) = TAILQ_NEXT(var, field), 1);		\
	     (var) = (tvar))
#endif

#ifndef SLIST_FOREACH_SAFE
#define	SLIST_FOREACH_SAFE(var, head, field, tvar)			 \
	for ((var) = SLIST_FIRST((head));				 \
			(var) && ((tvar) = SLIST_NEXT((var), field), 1); \
			(var) = (tvar))
#endif

/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
struct portals_vec {
	int				vec_len;
	int				pad;
	const char			**vec;
};

struct raio_thread_data {
	struct raio_server_data		*server_data;
	char				portal[64];
	int				affinity;
	int				id;
	struct xio_msg			rsp;
	struct xio_context		*ctx;

	SLIST_HEAD(, raio_connection_data)	conns_list;

	int				disconnected;
	int				pad;
};

struct  raio_connection_data {
	struct xio_connection			*connection;
	int					disconnected;
	int					pad;

	void					*dd_data;

	struct raio_thread_data			*tdata;
	struct raio_session_data		*sdata;

	/* for thread  */
	SLIST_ENTRY(raio_connection_data)	thr_conns_list_entry;

	/* for session  */
	SLIST_ENTRY(raio_connection_data)	ses_conns_list_entry;
};

struct raio_session_data {
	struct	xio_session			*session;
	struct  xio_connection			*fe_conn;

	void					*dd_data;
	struct raio_server_data			*server_data;

	SLIST_HEAD(, raio_connection_data)	conns_list;
	SLIST_ENTRY(raio_session_data)		sessions_list_entry;
};

/* server private data */
struct raio_server_data {
	struct xio_context			*ctx;
	int					tot_sessions;
	int					finite_run;
	int					extra_perf;
	int					pad;

	SLIST_HEAD(, raio_session_data)		sessions_list;

	pthread_t				*thread_id;
	struct raio_thread_data			*tdata;
};

static char		*server_addr;
static char		*transport;
static int		finite_run;
static uint16_t		server_port;
static char		*cpumask;
static int		extra_perf;
static int		MAX_THREADS;

/*---------------------------------------------------------------------------*/
/* portals_get								     */
/*---------------------------------------------------------------------------*/
static struct portals_vec *portals_get(struct raio_server_data *server_data,
				       const char *uri, void *user_context)
{
	/* fill portals array and return it. */
	int			i, j;
	struct portals_vec *portals =
		(struct portals_vec *)calloc(1, sizeof(*portals));

	portals->vec = (const char **)calloc(MAX_THREADS, sizeof(char*));

	for (i = 0; i < MAX_THREADS; i++) {
		j = (server_data->tot_sessions + i) % MAX_THREADS;
		portals->vec[i] = strdup(server_data->tdata[j].portal);
		portals->vec_len++;
	}
	server_data->tot_sessions++;

	return portals;
}

/*---------------------------------------------------------------------------*/
/* portals_free								     */
/*---------------------------------------------------------------------------*/
static void portals_free(struct portals_vec *portals)
{
	int			i;

	for (i = 0; i < portals->vec_len; i++)
		free((char *)(portals->vec[i]));

	free(portals->vec);
	free(portals);
}

/*---------------------------------------------------------------------------*/
/* on_response_comp							     */
/*---------------------------------------------------------------------------*/
static int on_response_comp(struct xio_session *session,
			    struct xio_msg *rsp,
			    void *cb_user_context)
{
	struct raio_connection_data	*cdata =
		(struct raio_connection_data *)cb_user_context;

	raio_handler_on_rsp_comp(
			cdata->sdata->dd_data,
			cdata->dd_data,
			rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_session_disconnect						     */
/*---------------------------------------------------------------------------*/
static void raio_session_disconnect(struct raio_session_data *session_data)
{
	struct raio_connection_data	*connection_entry,
					*tmp_connection_entry;

	SLIST_FOREACH_SAFE(connection_entry, &session_data->conns_list,
			   ses_conns_list_entry,
			   tmp_connection_entry) {
		if (!connection_entry->disconnected) {
			connection_entry->disconnected = 1;
			xio_disconnect(connection_entry->connection);
		}
	}
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
static int on_request(struct xio_session *session, struct xio_msg *req,
		      int last_in_rxq, void *cb_user_context)
{
	struct raio_connection_data	*cdata =
		(struct raio_connection_data *)cb_user_context;
	int				disconnect;

	disconnect = raio_handler_on_req(
			cdata->sdata->dd_data,
			cdata->dd_data,
			last_in_rxq,
			req);
	if (disconnect)
		raio_session_disconnect(cdata->sdata);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops  portal_server_ops = {
	.on_session_event		=  NULL,
	.on_new_session			=  NULL,
	.on_msg_send_complete		=  on_response_comp,
	.on_msg				=  on_request,
	.on_msg_error			=  NULL
};

/*---------------------------------------------------------------------------*/
/* worker thread callback						     */
/*---------------------------------------------------------------------------*/
static void *portal_server_cb(void *data)
{
	struct raio_thread_data	*tdata = (struct raio_thread_data *)data;
	cpu_set_t		cpuset;
	pthread_t		thread;
	struct xio_server	*server;
	unsigned int polling_tmo = POLLING_TIME_USEC;

	if (tdata->server_data->extra_perf)
		polling_tmo = 0;

	/* set affinity to thread */
	thread = pthread_self();

	CPU_ZERO(&cpuset);
	CPU_SET(tdata->affinity, &cpuset);

	pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);

	/* create thread context for the client */
	tdata->ctx = xio_context_create(NULL, polling_tmo,
					tdata->affinity);

	/* bind a listener server to a portal/url */
	server = xio_bind(tdata->ctx, &portal_server_ops, tdata->portal,
			  NULL, 0, tdata);
	if (!server) {
		fprintf(stderr, "failed to bind server\n");
		goto cleanup;
	}

	if (tdata->server_data->extra_perf) {
		struct raio_connection_data *cdata;
		unsigned int i = 0;

		while (!tdata->disconnected) {
			xio_context_poll_completions(tdata->ctx, 0);
			SLIST_FOREACH(cdata, &tdata->conns_list,
					thr_conns_list_entry) {
				raio_handler_bs_poll(
					cdata->sdata->dd_data,
					cdata->dd_data);
			}

			if (++i % 500 == 0)
				xio_context_poll_wait(tdata->ctx, 0);
		}
	} else {
		/* the default xio supplied main loop */
		xio_context_run_loop(tdata->ctx, XIO_INFINITE);
	}

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	/* detach the server */
	xio_unbind(server);

cleanup:
	/* free the context */
	xio_context_destroy(tdata->ctx);

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* on_new_connection							     */
/*---------------------------------------------------------------------------*/
static int on_new_connection(struct xio_session *session,
			     struct xio_connection *connection,
			     struct raio_session_data *session_entry,
			     struct raio_thread_data *tdata)
{
	struct raio_connection_data	*connection_entry;
	struct xio_connection_attr	attr;

	connection_entry = (struct raio_connection_data *)
				calloc(1, sizeof(*connection_entry));
	if (!connection_entry)
		return -1;
	connection_entry->connection = connection;
	connection_entry->sdata	     = session_entry;
	connection_entry->tdata	     = tdata;

	connection_entry->dd_data =
		raio_handler_get_portal_data(
				session_entry->dd_data,
				tdata->id);

	attr.user_context = connection_entry;
	xio_modify_connection(connection, &attr,
			      XIO_CONNECTION_ATTR_USER_CTX);
	SLIST_INSERT_HEAD(&tdata->conns_list,
			  connection_entry,
			  thr_conns_list_entry);

	SLIST_INSERT_HEAD(&session_entry->conns_list,
			  connection_entry,
			  ses_conns_list_entry);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_connection_teardown						     */
/*---------------------------------------------------------------------------*/
static int on_connection_teardown(struct xio_session *session,
				  struct xio_connection *connection,
				  void *cb_user_context)
{
	struct raio_connection_data	*cdata =
		(struct raio_connection_data *)cb_user_context;

	SLIST_REMOVE(&cdata->tdata->conns_list,
		     cdata,
		     raio_connection_data,
		     thr_conns_list_entry);
	SLIST_REMOVE(&cdata->sdata->conns_list,
		     cdata,
		     raio_connection_data,
		     ses_conns_list_entry);

	free(cdata);
	xio_connection_destroy(connection);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct raio_session_data *session_data =
				(struct raio_session_data *)cb_user_context;
	struct raio_server_data	*server_data = session_data->server_data;
	struct raio_thread_data	*tdata;
	int			i;

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		tdata =
		  (struct raio_thread_data *)event_data->conn_user_context;
		if (session_data->fe_conn)
			on_new_connection(session, event_data->conn,
					  session_data, tdata);
		else
			session_data->fe_conn = event_data->conn;
		break;
	case XIO_SESSION_CONNECTION_ERROR_EVENT:
		xio_disconnect(event_data->conn);
		break;
	case XIO_SESSION_CONNECTION_DISCONNECTED_EVENT:
	case XIO_SESSION_CONNECTION_CLOSED_EVENT:
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		for (i = 0; i < MAX_THREADS; i++) {
			void *pd = raio_handler_get_portal_data(
					session_data->dd_data,
					server_data->tdata[i].id);
			raio_handler_free_portal_data(pd);
		}

		raio_handler_free_session_data(
				session_data->dd_data);
		SLIST_REMOVE(&server_data->sessions_list,
			     session_data,
			     raio_session_data,
			     sessions_list_entry);
		free(session_data);

		xio_session_destroy(session);

		if (server_data->finite_run) {
			for (i = 0; i < MAX_THREADS; i++) {
				xio_context_stop_loop(
						server_data->tdata[i].ctx);
				server_data->tdata[i].disconnected = 1;
			}
			xio_context_stop_loop(server_data->ctx);
		}
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		if (session_data->fe_conn != event_data->conn)
			on_connection_teardown(session, event_data->conn,
					       event_data->conn_user_context);
		else
			xio_connection_destroy(session_data->fe_conn);
		break;
	default:
		printf("unexpected session event: session:%p, %s. reason: %s\n",
		       session,
		       xio_session_event_str(event_data->event),
		       xio_strerror(event_data->reason));
		break;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_new_session							     */
/*---------------------------------------------------------------------------*/
static int on_new_session(struct xio_session *session,
			  struct xio_new_session_req *req,
			  void *cb_user_context)
{
	struct portals_vec *portals;
	struct raio_server_data *server_data = (struct raio_server_data *)
								cb_user_context;
	struct raio_session_data *session_data;
	struct xio_session_attr	attr;
	int			i;

	portals = portals_get(server_data, req->uri, req->private_data);

	/* alloc and initialize */
	session_data = (struct raio_session_data *)
				calloc(1, sizeof(*session_data));
	session_data->session = session;
	session_data->server_data = server_data;
	session_data->dd_data = raio_handler_init_session_data(MAX_THREADS);

	for (i = 0; i < MAX_THREADS; i++) {
		raio_handler_init_portal_data(
			session_data->dd_data,
			server_data->tdata[i].id,
			server_data->tdata[i].ctx);
	}

	attr.user_context = session_data;
	xio_modify_session(session, &attr,
			   XIO_SESSION_ATTR_USER_CTX);

	SLIST_INSERT_HEAD(&server_data->sessions_list,
			  session_data, sessions_list_entry);

	/* automatic accept the request */
	xio_accept(session, portals->vec, portals->vec_len, NULL, 0);

	portals_free(portals);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops  server_ops = {
	.on_session_event		=  on_session_event,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  NULL,
	.on_msg_error			=  NULL
};

/*---------------------------------------------------------------------------*/
/* usage                                                                     */
/*---------------------------------------------------------------------------*/
static void usage(const char *app)
{
	printf("Usage:\n");
	printf("\t%s [OPTIONS] - raio file server\n", basename((char *)app));
	printf("options:\n");
	printf("\t--addr, -a <addr>      : server ip address\n");
	printf("\t--port, -p <port>      : server port\n");
	printf("\t--cpumask, -c <cpumask>: cpumask\n");
	printf("\t--finite, -f           : finite run (default: infinite)\n");
	printf("\t--transport, -t <name> : rdma,tcp (default: rdma)\n");
	printf("\t--extra-perf, -e       : extra performance at expence\n");
	printf("\t                         of CPU usage (default: false)\n");
	printf("\t--threads, -n <num>    : number of threads (default: 6)\n");
	printf("\t--help, -h             : print this message and exit\n");
	exit(0);
}

static void free_cmdline_params(void)
{
	if (server_addr) {
		free(server_addr);
		server_addr = NULL;
	}
	if (transport) {
		free(transport);
		transport = NULL;
	}
	if (cpumask) {
		free(cpumask);
		cpumask = NULL;
	}

}

/*---------------------------------------------------------------------------*/
/* parse_cmdline                                                             */
/*---------------------------------------------------------------------------*/
int parse_cmdline(int argc, char **argv)
{
	static struct option const long_options[] = {
		{ .name = "addr", .has_arg = 1, .val = 'a'},
		{ .name = "port", .has_arg = 1, .val = 'p'},
		{ .name = "cpumask", .has_arg = 1, .val = 'c'},
		{ .name = "transport", .has_arg = 1, .val = 't'},
		{ .name = "finite", .has_arg = 1, .val = 'f'},
		{ .name = "extra-perf", .has_arg = 1, .val = 'e'},
		{ .name = "threads", .has_arg = 1, .val = 'n'},
		{ .name = "help", .has_arg = 0, .val = 'h'},
		{0, 0, 0, 0},
	};
	static char *short_options = "a:p:c:t:f:h:e:n:";
	int c;

	server_addr = NULL;
	transport = NULL;
	server_port = 0;
	cpumask = NULL;
	finite_run = 0;
	extra_perf = 0;
	MAX_THREADS = 6;

	optind = 0;
	opterr = 0;

	while (1) {
		c = getopt_long(argc, argv, short_options,
				long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			if (!server_addr)
				server_addr = strdup(optarg);
			if (!server_addr)
				goto cleanup;
			break;
		case 'p':
			server_port =
				(uint16_t)strtol(optarg, NULL, 0);
			break;
		case 'c':
			if (cpumask) {
				free(cpumask);
				cpumask = NULL;
			}
			cpumask = strdup(optarg);
			if (!cpumask)
                                goto cleanup;
			break;
		case 't':
			if (!transport)
				transport = strdup(optarg);
			if (!transport)
				goto cleanup;
			break;
		case 'f':
			finite_run =
				(uint16_t)strtol(optarg, NULL, 0);
			break;
		case 'e':
			extra_perf =
				(uint16_t) strtol(optarg, NULL, 0);
			break;
		case 'n':
			MAX_THREADS =
				(uint16_t) strtol(optarg, NULL, 0);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		default:
			fprintf(stderr, "\nError:\n\tInvalid param: %s\n",
				argv[optind - 1]);
			goto cleanup;
			break;
		}
	}
	if (argc == 1)
		goto cleanup;
	if (optind < argc) {
		fprintf(stderr, "\nError:\n\tInvalid param: %s\n",
			argv[optind]);
		goto cleanup;
	}

	return 0;

cleanup:
	free_cmdline_params();
	fprintf(stderr,	"Failed to parse command line params.\n\n");
	usage(argv[0]);
	exit(-1);
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct xio_server	*server;	/* server portal */
	struct raio_server_data	server_data;
	char			url[256];
	int			i;
	int			curr_cpu;
	int			max_cpus;
	int			opt;
        bitset                  *b = NULL, *bdup = NULL;

	parse_cmdline(argc, argv);
	if (!server_addr || server_port == 0) {
		fprintf(stderr, "Error:\n\tno server address and/or port\n");
		usage(argv[0]);
	}
	if (!transport) {
		transport = strdup("rdma");
	} else if (strcmp(transport, "rdma") && strcmp(transport, "tcp")) {
		fprintf(stderr, "Error:\n\tinvalid transport name: %s\n",
			transport);
		usage(argv[0]);
	}
	xio_init();

	opt = 0;
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_IN_IOVLEN,
		    &opt, sizeof(int));
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_OUT_IOVLEN,
		    &opt, sizeof(int));

	opt = 2048;
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_SND_QUEUE_DEPTH_MSGS,
		    &opt, sizeof(int));
	opt = 2048;
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_RCV_QUEUE_DEPTH_MSGS,
		    &opt, sizeof(int));

	opt = 512;
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_INLINE_XIO_DATA_ALIGN,
		    &opt, sizeof(int));

	opt = 512;
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_XFER_BUF_ALIGN,
		    &opt, sizeof(int));

	opt = 0;
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_ENABLE_KEEPALIVE,
		    &opt, sizeof(int));

	memset(&server_data, 0, sizeof(server_data));

        curr_cpu = sched_getcpu();
	max_cpus = sysconf(_SC_NPROCESSORS_ONLN);

        if (cpumask) {
                b = str_to_bitset(cpumask, NULL);
                if (!b) {
                        fprintf(stderr, "failed to parse cpumask\n");
                        goto cleanup;
                }
                bdup = bitset_dup(b);
                if (!bdup) {
                        fprintf(stderr, "failed to duplicate bitset\n");
                        goto cleanup;
                }
        }
	server_data.finite_run = finite_run;
	server_data.extra_perf = extra_perf;
	SLIST_INIT(&server_data.sessions_list);

	/* create thread context for the client */
	server_data.ctx	= xio_context_create(NULL, 0, curr_cpu);

	/* create url to connect to */
	sprintf(url, "%s://%s:%d", transport, server_addr, server_port);

	/* bind a listener server to a portal/url */
	server = xio_bind(server_data.ctx, &server_ops,
			  url, NULL, 0, &server_data);
	if (!server) {
		fprintf(stderr, "failed to bind server\n");
		goto cleanup;
	}

	server_data.tdata = (struct raio_thread_data *)
				calloc(MAX_THREADS, sizeof(struct raio_thread_data));
	server_data.thread_id = (pthread_t *)
				calloc(MAX_THREADS, sizeof(pthread_t));
	/* spawn portals */
	for (i = 0; i < MAX_THREADS; i++) {
		server_data.tdata[i].server_data = &server_data;
		server_data.tdata[i].id = i;
                if (b) {
                        int cpu = bitset_firstset(b);
                        server_data.tdata[i].affinity = cpu;

                        bitset_unset(b, cpu);

                        if (bitset_isempty(b))
                                bitset_copy(b, bdup);
                } else {
                        server_data.tdata[i].affinity =
                                (curr_cpu + i) % max_cpus;
                }
		printf("[%d] affinity:%d/%d\n", i,
		       server_data.tdata[i].affinity, max_cpus);
		server_port++;
		sprintf(server_data.tdata[i].portal, "%s://%s:%d",
			transport, server_addr, server_port);
		pthread_create(&server_data.thread_id[i], NULL,
			       portal_server_cb, &server_data.tdata[i]);
	}
	xio_context_run_loop(server_data.ctx, XIO_INFINITE);

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");

	/* join the threads */
	for (i = 0; i < MAX_THREADS; i++)
		pthread_join(server_data.thread_id[i], NULL);

	free(server_data.thread_id);
	free(server_data.tdata);
	/* free the server */
	xio_unbind(server);
cleanup:
	/* free the context */
	xio_context_destroy(server_data.ctx);

	xio_shutdown();

        if (b)
                bitset_free(b);

        if (bdup)
                bitset_free(bdup);

	free_cmdline_params();

	return 0;
}

