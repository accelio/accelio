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
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/eventfd.h>


#include "libxio.h"
#include "raio_command.h"
#include "raio_buffer.h"
#include "raio_utils.h"
#include "libraio.h"
#include "msg_pool.h"

/*---------------------------------------------------------------------------*/
/* preprocessor defines							     */
/*---------------------------------------------------------------------------*/
#define MAX_MSG_LEN		512
#define RAIO_MAX_NR		2048
#define USECS_IN_SEC		1000000
#define NSECS_IN_USEC		1000
#define NSECS_IN_SEC		1000000000

#define uint64_from_ptr(p)	(uint64_t)(uintptr_t)(p)
#define ptr_from_int64(p)	(void *)(unsigned long)(p)

#ifdef VISIBILITY
#define __RAIO_PUBLIC __attribute__((visibility("default")))
#else
#define __RAIO_PUBLIC
#endif



/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
struct raio_session_data;
struct raio_thread_data;

struct raio_mr {
	struct xio_mr			*omr;
};

struct raio_io_u {
	struct raio_iocb		*iocb;
	struct raio_session_data	*ses_data;
	struct xio_msg			req;
	struct xio_msg			*rsp;
	int				res;
	int				res2;

	char				req_hdr[MAX_MSG_LEN];

	TAILQ_ENTRY(raio_io_u)		io_u_list;
};

struct raio_context  {
	struct raio_session_data	*session_data;

	struct raio_io_u		*io_us_free;
	int				io_u_queued_nr;
	int				io_u_completed_nr;
	int				io_u_free_nr;
	int				pad;

	TAILQ_HEAD(, raio_io_u)		io_u_free_list;
	TAILQ_HEAD(, raio_io_u)		io_u_completed_list;
	TAILQ_HEAD(, raio_io_u)		io_u_queued_list;
};

/* private session data */
struct raio_session_data {
	struct xio_session		*session;
	int				fd;
	int				key;
	int				sd_errno;
	int				maxevents;
	int				npending;
	int				max_nr;
	int				min_nr;
	int				disconnected;
	struct raio_answer		ans;
	struct xio_msg			*cmd_rsp;
	struct xio_msg			cmd_req;
	struct xio_connection		*conn;

	struct xio_context		*ctx;
	raio_context_t			io_ctx;

	LIST_ENTRY(raio_session_data)   rsd_siblings;
};

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static LIST_HEAD(, raio_session_data) rsd_list =
	LIST_HEAD_INITIALIZER(rsd_list);
static pthread_spinlock_t rsd_lock;


/*---------------------------------------------------------------------------*/
/* rsd_module_init							     */
/*---------------------------------------------------------------------------*/
__attribute__((constructor)) void raio_module_init(void)
{
	pthread_spin_init(&rsd_lock, PTHREAD_PROCESS_PRIVATE);
}

/*---------------------------------------------------------------------------*/
/* rsd_module_exit							     */
/*---------------------------------------------------------------------------*/
__attribute__((destructor)) void raio_module_exit(void)
{
	pthread_spin_destroy(&rsd_lock);
}

/*---------------------------------------------------------------------------*/
/* rsd_list_add								     */
/*---------------------------------------------------------------------------*/
int rsd_list_add(struct raio_session_data *rsd)
{
	static int key = 10;

	pthread_spin_lock(&rsd_lock);
	rsd->key = key++;

	LIST_INSERT_HEAD(&rsd_list, rsd, rsd_siblings);
	pthread_spin_unlock(&rsd_lock);

	return rsd->key;
}

/*---------------------------------------------------------------------------*/
/* rsd_list_remove							     */
/*---------------------------------------------------------------------------*/
int rsd_list_remove(struct raio_session_data *rsd)
{
	pthread_spin_lock(&rsd_lock);
	LIST_REMOVE(rsd, rsd_siblings);
	pthread_spin_unlock(&rsd_lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* rsd_list_find							     */
/*---------------------------------------------------------------------------*/
struct raio_session_data *rsd_list_find(int key)
{
	struct raio_session_data *rsd;

	pthread_spin_lock(&rsd_lock);
	LIST_FOREACH(rsd, &rsd_list, rsd_siblings) {
		if (rsd->key == key) {
			pthread_spin_unlock(&rsd_lock);
			return rsd;
		}
	}
	pthread_spin_unlock(&rsd_lock);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* fill_timespec							     */
/*---------------------------------------------------------------------------*/
static int fill_timespec(struct timespec *ts)
{
	if (!clock_gettime(CLOCK_MONOTONIC, ts))
		return 0;

	perror("clock_gettime");
	return 1;
}

/*---------------------------------------------------------------------------*/
/* ts_utime_since_now							     */
/*---------------------------------------------------------------------------*/
static unsigned long long ts_utime_since_now(struct timespec *t)
{
	long long sec, nsec;
	struct timespec now;

	if (fill_timespec(&now))
		return 0;

	sec = now.tv_sec - t->tv_sec;
	nsec = now.tv_nsec - t->tv_nsec;
	if (sec > 0 && nsec < 0) {
		sec--;
		nsec += NSECS_IN_SEC;
	}

	sec *= USECS_IN_SEC;
	nsec /= NSECS_IN_USEC;
	return sec + nsec;
}

/*---------------------------------------------------------------------------*/
/* get_ip								     */
/*---------------------------------------------------------------------------*/
static inline char *get_ip(const struct sockaddr *ip)
{
	if (ip->sa_family == AF_INET) {
		static char addr[INET_ADDRSTRLEN];
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		return (char *)inet_ntop(AF_INET, &(v4->sin_addr),
					 addr, INET_ADDRSTRLEN);
	}
	if (ip->sa_family == AF_INET6) {
		static char addr[INET6_ADDRSTRLEN];
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ip;
		return (char *)inet_ntop(AF_INET6, &(v6->sin6_addr),
					 addr, INET6_ADDRSTRLEN);
	}
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* get_port								     */
/*---------------------------------------------------------------------------*/
static inline uint16_t get_port(const struct sockaddr *ip)
{
	if (ip->sa_family == AF_INET) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
		return ntohs(v4->sin_port);
	}
	if (ip->sa_family == AF_INET6) {
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ip;
		return ntohs(v6->sin6_port);
	}
	return 0;
}
/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
		struct xio_session_event_data *event_data,
		void *cb_user_context)
{
	struct raio_session_data  *session_data = cb_user_context;

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_CLOSED_EVENT:
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		session_data->disconnected = 1;
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_context_stop_loop(session_data->ctx, 0);  /* exit */
		break;
	default:
		printf("libraio: unexpected session event: %s. reason: %s\n",
		       xio_session_event_str(event_data->event),
		       xio_strerror(event_data->reason));
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_submit_answer							     */
/*---------------------------------------------------------------------------*/
static void on_submit_answer(struct xio_msg *rsp)
{
	struct raio_io_u	*io_u;

	io_u = rsp->user_context;

	io_u->rsp = rsp;

	unpack_u32((uint32_t *)&io_u->res2,
	unpack_u32((uint32_t *)&io_u->res,
	unpack_u32((uint32_t *)&io_u->ses_data->ans.ret_errno,
	unpack_u32((uint32_t *)&io_u->ses_data->ans.ret,
	unpack_u32(&io_u->ses_data->ans.data_len,
	unpack_u32(&io_u->ses_data->ans.command,
		   io_u->rsp->in.header.iov_base))))));

	TAILQ_INSERT_TAIL(&io_u->ses_data->io_ctx->io_u_completed_list,
			  io_u, io_u_list);
	io_u->ses_data->io_ctx->io_u_completed_nr++;

	/* this for getevent call */
	if (io_u->ses_data->min_nr != 0) {
		if (io_u->ses_data->io_ctx->io_u_completed_nr >=
		    io_u->ses_data->min_nr)
			xio_context_stop_loop(io_u->ses_data->ctx, 0);
	}
}

/*---------------------------------------------------------------------------*/
/* on_response								     */
/*---------------------------------------------------------------------------*/
static int on_response(struct xio_session *session,
			struct xio_msg *rsp,
			int more_in_batch,
			void *cb_user_context)
{
	struct raio_session_data  *session_data = cb_user_context;
	uint32_t		  command;

	unpack_u32(&command,
		   rsp->in.header.iov_base);

	switch (command) {
	case RAIO_CMD_IO_SUBMIT:
		on_submit_answer(rsp);
		break;
	case RAIO_CMD_OPEN:
	case RAIO_CMD_FSTAT:
	case RAIO_CMD_CLOSE:
	case RAIO_CMD_IO_SETUP:
	case RAIO_CMD_IO_DESTROY:
		/* break the loop */
		session_data->cmd_rsp = rsp;
		xio_context_stop_loop(session_data->ctx, 0);
		break;
	default:
		printf("libraio: unknown answer %d\n", command);
		break;
	};
	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  NULL,
	.on_msg				=  on_response,
	.on_msg_error			=  NULL
};

/*---------------------------------------------------------------------------*/
/* raio_open								     */
/*---------------------------------------------------------------------------*/
__RAIO_PUBLIC int raio_open(const struct sockaddr *addr, socklen_t addrlen,
	      const char *pathname, int flags)

{
	int				retval;
	char				url[256];
	struct raio_session_data	*session_data;
	int				raio_err = 0;
	int				fd;

	/* client session attributes */
	struct xio_session_attr attr = {
		&ses_ops, /* callbacks structure */
		NULL,	  /* no need to pass the server private data */
		0
	};

	xio_init();

	session_data = calloc(1, sizeof(*session_data));

	session_data->cmd_req.out.header.iov_base =
		calloc(MAX_MSG_LEN, sizeof(char));
	session_data->cmd_req.out.header.iov_len =
		MAX_MSG_LEN;
	session_data->cmd_req.out.data_iovlen = 0;


	/* create thread context for the client */
	session_data->ctx = xio_context_create(NULL, 0, -1);

	/* create url to connect to */
	sprintf(url, "rdma://%s:%d",
		get_ip(addr), get_port(addr));
	session_data->session = xio_session_create(XIO_SESSION_CLIENT,
						 &attr, url,
						 0, 0, session_data);
	if (session_data->session == NULL)
		goto cleanup;

	/* connect the session  */
	session_data->conn = xio_connect(session_data->session,
					 session_data->ctx, 0,
					 NULL,
					 session_data);
	if (session_data->conn == NULL)
		goto cleanup1;

	msg_reset(&session_data->cmd_req);
	pack_open_command(pathname, flags,
			  session_data->cmd_req.out.header.iov_base,
			  &session_data->cmd_req.out.header.iov_len);

	xio_send_request(session_data->conn, &session_data->cmd_req);

	/* the default xio supplied main loop */
	xio_context_run_loop(session_data->ctx, XIO_INFINITE);

	if (session_data->disconnected) {
		retval = -1;
		raio_err = ECONNREFUSED;
		goto cleanup1;
	}

	retval = unpack_open_answer(
			session_data->cmd_rsp->in.header.iov_base,
			session_data->cmd_rsp->in.header.iov_len,
			&session_data->fd);

	/* acknowlege xio that response is no longer needed */
	xio_release_response(session_data->cmd_rsp);

	if (retval == -1) {
		raio_err = errno;
		xio_disconnect(session_data->conn);
		goto cleanup1;
	}

	errno = 0;
	fd = rsd_list_add(session_data);


	return fd;

cleanup1:
	if (session_data->session) {
		if (!session_data->disconnected) {
			xio_context_run_loop(session_data->ctx, XIO_INFINITE);
			xio_session_destroy(session_data->session);
		} else {
		     xio_session_destroy(session_data->session);
		}
		session_data->session = NULL;
	}
cleanup:
	/* free the context */
	xio_context_destroy(session_data->ctx);

	errno = raio_err;

	printf("libraio: raio_open failed. %m\n");

	return -1;
}

/*---------------------------------------------------------------------------*/
/* raio_close								     */
/*---------------------------------------------------------------------------*/
__RAIO_PUBLIC int raio_close(int fd)
{
	int				retval = -1;
	int				raio_err = 0;

	struct raio_session_data *session_data = rsd_list_find(fd);
	if (session_data == NULL) {
		errno = EINVAL;
		return -1;
	}


	if (session_data->disconnected) {
		retval  = 0;
		goto cleanup;
	}

	msg_reset(&session_data->cmd_req);
	pack_close_command(
			session_data->fd,
			session_data->cmd_req.out.header.iov_base,
			&session_data->cmd_req.out.header.iov_len);

	xio_send_request(session_data->conn, &session_data->cmd_req);

	/* the default xio supplied main loop */
	xio_context_run_loop(session_data->ctx, XIO_INFINITE);

	retval = unpack_close_answer(
			session_data->cmd_rsp->in.header.iov_base,
			session_data->cmd_rsp->in.header.iov_len);
	if (retval == -1) {
		raio_err = errno;
		printf("libraio: raio_close failed: %m\n");
	}

	/* acknowlege xio that response is no longer needed */
	xio_release_response(session_data->cmd_rsp);

cleanup:
	rsd_list_remove(session_data);

	if (!session_data->disconnected) {
		xio_disconnect(session_data->conn);
		xio_context_run_loop(session_data->ctx, XIO_INFINITE);
		xio_session_destroy(session_data->session);
	}
	/* free the context */
	xio_context_destroy(session_data->ctx);

	xio_shutdown();

	free(session_data);

	errno = raio_err;
	return retval;
}

/*---------------------------------------------------------------------------*/
/* raio_fstat								     */
/*---------------------------------------------------------------------------*/
__RAIO_PUBLIC int raio_fstat(int fd, struct stat64 *stbuf)
{
	int				retval;

	struct raio_session_data *session_data = rsd_list_find(fd);
	if (session_data == NULL) {
		errno = EINVAL;
		return -1;
	}

	msg_reset(&session_data->cmd_req);
	pack_fstat_command(
			session_data->fd,
			session_data->cmd_req.out.header.iov_base,
			&session_data->cmd_req.out.header.iov_len);

	xio_send_request(session_data->conn, &session_data->cmd_req);

	/* the default xio supplied main loop */
	xio_context_run_loop(session_data->ctx, XIO_INFINITE);

	if (session_data->disconnected) {
		errno  = ECONNRESET;
		return -1;
	}

	retval = unpack_fstat_answer(
			session_data->cmd_rsp->in.header.iov_base,
			session_data->cmd_rsp->in.header.iov_len,
			stbuf);
	if (retval == -1)
		retval = errno;

	/* acknowlege xio that response is no longer needed */
	xio_release_response(session_data->cmd_rsp);

	if (retval) {
		errno = retval;
		return -1;
	}

	errno = 0;
	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_setup								     */
/*---------------------------------------------------------------------------*/
__RAIO_PUBLIC int raio_setup(int fd, int maxevents, raio_context_t *ctxp)
{
	int				i;
	raio_context_t			ctx;
	int				retval;

	struct raio_session_data *session_data = rsd_list_find(fd);
	if (session_data == NULL) {
		errno = EINVAL;
		return -1;
	}
	session_data->maxevents = maxevents;

	msg_reset(&session_data->cmd_req);
	pack_setup_command(
			session_data->fd,
			session_data->maxevents,
			session_data->cmd_req.out.header.iov_base,
			&session_data->cmd_req.out.header.iov_len);

	session_data->cmd_req.out.data_iovlen = 0;

	/* send first message */
	xio_send_request(session_data->conn, &session_data->cmd_req);

	xio_context_run_loop(session_data->ctx, XIO_INFINITE);

	if (session_data->disconnected)
		return -ECONNRESET;

	retval = unpack_setup_answer(
			session_data->cmd_rsp->in.header.iov_base,
			session_data->cmd_rsp->in.header.iov_len);

	if (retval == -1)
		retval = errno;

	/* acknowlege xio that response is no longer needed */
	xio_release_response(session_data->cmd_rsp);

	if (retval)
		return -retval;

	session_data->io_ctx = calloc(1, sizeof(*session_data->io_ctx));

	ctx = session_data->io_ctx;
	ctx->io_us_free = calloc(2*session_data->maxevents,
				 sizeof(struct raio_io_u));
	ctx->io_u_free_nr = 2*session_data->maxevents;

	TAILQ_INIT(&ctx->io_u_free_list);
	TAILQ_INIT(&ctx->io_u_queued_list);
	TAILQ_INIT(&ctx->io_u_completed_list);

	/* register each io_u in the free list */
	for (i = 0; i < ctx->io_u_free_nr; i++) {
		ctx->io_us_free[i].req.out.header.iov_base =
			ctx->io_us_free[i].req_hdr;
		ctx->io_us_free[i].req.out.header.iov_len =
			MAX_MSG_LEN;
		TAILQ_INSERT_TAIL(&ctx->io_u_free_list,
				  &ctx->io_us_free[i], io_u_list);
	}
	session_data->io_ctx->session_data = session_data;
	*ctxp = session_data->io_ctx;
	session_data->npending  = 0;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_destroy								     */
/*---------------------------------------------------------------------------*/
__RAIO_PUBLIC int raio_destroy(raio_context_t ctx)
{
	struct raio_session_data *session_data;
	int			 retval  = 0;

	session_data = ctx->session_data;

	if (session_data->disconnected)
		goto cleanup;


	msg_reset(&session_data->cmd_req);
	pack_destroy_command(
			session_data->fd,
			session_data->cmd_req.out.header.iov_base,
			&session_data->cmd_req.out.header.iov_len);

	xio_send_request(session_data->conn, &session_data->cmd_req);

	xio_context_run_loop(session_data->ctx, XIO_INFINITE);
	if (session_data->disconnected) {
		errno =  ECONNRESET;
		retval = -1;
		goto cleanup;
	}


	/* don't check answer just clean */

	/* acknowlege xio that response is no longer needed */
	xio_release_response(session_data->cmd_rsp);

cleanup:
	free(ctx->io_us_free);
	free(ctx);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* raio_submit								     */
/*---------------------------------------------------------------------------*/
__RAIO_PUBLIC int raio_submit(raio_context_t ctx,
			      long nr, struct raio_iocb *ios[])
{
	struct raio_session_data	*session_data;
	struct raio_io_u		*io_u;
	int				i;

	if (!ctx || (nr < 0))
		return -EINVAL;

	session_data = ctx->session_data;

	if (session_data->npending == session_data->maxevents)
		return -EINVAL;

	if ((session_data->npending  + nr) > session_data->maxevents)
		nr = session_data->maxevents - session_data->npending;

	if ((session_data->npending  + nr) > RAIO_MAX_NR)
		nr = RAIO_MAX_NR - session_data->npending;

	if (nr > RAIO_MAX_NR)
		nr = RAIO_MAX_NR;


	for (i = 0; i < nr; i++) {
		io_u = TAILQ_FIRST(&ctx->io_u_free_list);
		if (!io_u) {
			printf("libraio: io_u_free_list is empty\n");
			return -1;
		}

		TAILQ_REMOVE(&ctx->io_u_free_list, io_u, io_u_list);
		ctx->io_u_free_nr--;
		msg_reset(&io_u->req);

		/* replace the shadowed fd with the real one */
		ios[i]->raio_fildes = session_data->fd;
		pack_submit_command(
				ios[i],
				(i == (nr - 1)),
				io_u->req.out.header.iov_base,
				&io_u->req.out.header.iov_len);
		if (ios[i]->raio_lio_opcode == RAIO_CMD_PWRITE) {
			io_u->req.out.data_iov[0].iov_base = ios[i]->u.c.buf;
			io_u->req.out.data_iov[0].iov_len = ios[i]->u.c.nbytes;
			if (ios[i]->u.c.mr)
				io_u->req.out.data_iov[0].mr =
					ios[i]->u.c.mr->omr;
			else
				io_u->req.out.data_iov[0].mr = NULL;
			io_u->req.in.data_iovlen  = 0;
			io_u->req.out.data_iovlen = 1;
		} else {
			io_u->req.in.data_iov[0].iov_base = ios[i]->u.c.buf;
			io_u->req.in.data_iov[0].iov_len = ios[i]->u.c.nbytes;
			if (ios[i]->u.c.mr)
				io_u->req.in.data_iov[0].mr =
					ios[i]->u.c.mr->omr;
			else
				io_u->req.in.data_iov[0].mr = NULL;
			io_u->req.in.data_iovlen  = 1;
			io_u->req.out.data_iovlen = 0;
		}
		io_u->req.user_context = io_u;
		io_u->iocb = ios[i];
		io_u->ses_data = session_data;
		xio_send_request(session_data->conn, &io_u->req);
	}
	session_data->npending += nr;

	/* trigger event that packets are ready */
	for (i = 0; i < nr; i++) {
		if (io_u->iocb->u.c.flags & (1 << 0)) {
			eventfd_write(io_u->iocb->u.c.resfd,
				      (eventfd_t)nr);
		}
	}

	return nr;
}

/*
#define POLL_COMPLETIONS 1
*/
/*---------------------------------------------------------------------------*/
/* rsd_getevents							     */
/*---------------------------------------------------------------------------*/
__RAIO_PUBLIC int raio_getevents(raio_context_t ctx, long min_nr, long nr,
		   struct raio_event *events, struct timespec *t)
{
	struct raio_session_data	*session_data;
	struct raio_io_u		*io_u;
	struct timespec			start;
	int				i, r;
	int				have_timeout = 0;
	int				actual_nr;

	session_data = ctx->session_data;

	if ((session_data->npending == 0) &&
	    (ctx->io_u_completed_nr == 0))
		return 0;

	if ((min_nr < 0) || (nr < min_nr))
		return -EINVAL;

	if (min_nr > session_data->npending)
		min_nr = session_data->npending;

	if (t)  {
		if ((t->tv_sec != 0) || (t->tv_nsec != 0)) {
			if (!fill_timespec(&start))
				have_timeout = 1;
		}
	}

	r = 0;

restart:
	if ((ctx->io_u_completed_nr <  min_nr) ||
	    (ctx->io_u_completed_nr == 0))  {
#ifdef POLL_COMPLETIONS
		session_data->min_nr = 0;
		xio_poll_completions(session_data->conn,
				     (min_nr ? min_nr : 1),
				     nr , NULL);
#else
		session_data->min_nr  = (min_nr ? min_nr : 1);
		xio_context_run_loop(session_data->ctx, XIO_INFINITE);
		if (session_data->disconnected)
			return -ECONNRESET;
#endif
	}
	actual_nr = ((nr < ctx->io_u_completed_nr) ?
		     nr : ctx->io_u_completed_nr);

	for (i = 0; i < actual_nr; i++) {
		io_u = TAILQ_FIRST(&ctx->io_u_completed_list);
		if (io_u == NULL)
			break;
		TAILQ_REMOVE(&ctx->io_u_completed_list, io_u, io_u_list);
		ctx->io_u_completed_nr--;

		io_u->iocb->raio_fildes	= session_data->key;
		io_u->iocb->u.c.buf	= io_u->rsp->in.data_iov[0].iov_base;

		events[i].data		= io_u->iocb->data;
		events[i].obj		= io_u->iocb;
		events[i].res		= io_u->res;
		events[i].res2		= io_u->res2;
		events[i].handle	= uint64_from_ptr(io_u);

		TAILQ_INSERT_TAIL(&ctx->io_u_queued_list, io_u, io_u_list);
		ctx->io_u_queued_nr++;
		r++;
	}
	session_data->npending -= r;

	if (r >= min_nr)
		return r;

	if (have_timeout) {
		unsigned long long usec;

		usec = (t->tv_sec * USECS_IN_SEC) +
		       (t->tv_nsec / NSECS_IN_USEC);
		if (ts_utime_since_now(&start) > usec)
			return r;
	}
	goto restart;
}

/*---------------------------------------------------------------------------*/
/* raio_release								     */
/*---------------------------------------------------------------------------*/
__RAIO_PUBLIC int raio_release(raio_context_t ctx, long nr,
				struct raio_event *events)
{
	int				i;
	struct raio_io_u		*io_u;

	for (i = 0; i < nr; i++) {
		io_u = ptr_from_int64(events[i].handle);
		if (io_u == NULL)
			continue;
		TAILQ_REMOVE(&ctx->io_u_queued_list, io_u, io_u_list);
		ctx->io_u_queued_nr--;
		xio_release_response(io_u->rsp);
		TAILQ_INSERT_TAIL(&ctx->io_u_free_list, io_u, io_u_list);
		ctx->io_u_free_nr++;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_reg_mr								     */
/*---------------------------------------------------------------------------*/
__RAIO_PUBLIC int raio_reg_mr(raio_context_t ctx, void *buf,
			      size_t len, raio_mr_t *mr)
{
	*mr = malloc(sizeof(struct raio_mr));
	if (*mr == NULL) {
		printf("libraio: malloc failed. %m\n");
		return -1;
	}
	(*mr)->omr = xio_reg_mr(buf, len);
	if ((*mr)->omr == NULL) {
		printf("libraio: failed to register mr. %m\n");
		free(*mr);
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_dereg_mr							     */
/*---------------------------------------------------------------------------*/
__RAIO_PUBLIC int raio_dereg_mr(raio_context_t ctx, raio_mr_t mr)
{
	int retval = xio_dereg_mr(&mr->omr);

	if (retval == -1)
		printf("libraio: failed to deregister mr. %m\n");
	free(mr);

	return retval;
}

