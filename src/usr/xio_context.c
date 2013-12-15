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
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*#include <asm/types.h> */
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/netlink.h>

#include "xio_os.h"
#include "libxio.h"
#include "xio_observer.h"
#include "xio_common.h"
#include "xio_context.h"
#include "xio_schedwork.h"
#include "get_clock.h"


/*---------------------------------------------------------------------------*/
/* xio_context_add_observer						     */
/*---------------------------------------------------------------------------*/
int xio_context_reg_observer(struct xio_context *ctx,
			     struct xio_observer *observer)
{
	xio_observable_reg_observer(&ctx->observable, observer);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_context_remove_observer		                                     */
/*---------------------------------------------------------------------------*/
void xio_context_unreg_observer(struct xio_context *ctx,
				struct xio_observer *observer)
{
	xio_observable_unreg_observer(&ctx->observable, observer);
}

void xio_stats_handler(int fd, int events, void *data)
{
	struct xio_context *ctx = (struct xio_context *)data;
	unsigned char buf[NLMSG_SPACE(1024)];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct msghdr msg;
	struct iovec iov;
	struct sockaddr_nl dest_addr;
	uint64_t now = get_cycles();
	char *ptr;
	int i;

	/* read netlink message */
	iov.iov_base = (void *)nlh;
	/* max size for receive */
	iov.iov_len = NLMSG_SPACE(1024);
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	recvmsg(fd, &msg, 0);

	ptr = (char *)NLMSG_DATA(nlh);

	switch (nlh->nlmsg_type - NLMSG_MIN_TYPE) {
	case 0: /* Format */
		/* counting will start now */
		memset(&ctx->stats.counter, 0,
		       XIO_STAT_LAST * sizeof(uint64_t));
		/* First the cycles' hertz (assumed to be fixed) */
		memcpy(ptr, &ctx->stats.hertz, sizeof(ctx->stats.hertz));
		ptr += sizeof(ctx->stats.hertz);
		memcpy(ptr, &now, sizeof(now));
		ptr += sizeof(now);
		/* Counters' name */
		for (i = 0; i < XIO_STAT_LAST; i++) {
			if (!ctx->stats.name[i])
				continue;
			strcpy(ptr, ctx->stats.name[i]);
			/* keep the '\0' */
			ptr += strlen(ptr) + 1;
		}
		/* but not the last '\0' */
		ptr--;
		break;
	case 1: /* Statistics */
		/* Fisrt the timestamp in cycles */
		memcpy(ptr, &now, sizeof(now));
		ptr += sizeof(now);
		/* for each named counter counter */
		for (i = 0; i < XIO_STAT_LAST; i++) {
			if (!ctx->stats.name[i])
				continue;
			memcpy((void *)ptr, &ctx->stats.counter[i],
			       sizeof(uint64_t));
			ptr += sizeof(uint64_t);
		}
		break;
	default: /* Not yet implemented */
		ERROR_LOG("Unsupported message type(%d)\n", nlh->nlmsg_type);
		return;
	}

	/* header is in the buffer */
	nlh->nlmsg_len = ptr - (char *)buf;
	iov.iov_len = nlh->nlmsg_len;

	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 1;
	/* don't modify type */

	/* Send unicst */
	dest_addr.nl_groups = 0;
	/* send response */
	sendmsg(fd, &msg, 0);
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_open                                                              */
/*---------------------------------------------------------------------------*/
struct xio_context *xio_ctx_open(struct xio_loop_ops *loop_ops,
		void *ev_loop,
		int polling_timeout)
{
	struct xio_context		*ctx = NULL;
	int				cpu;
	struct sockaddr_nl		nladdr;
	int				fd;
	socklen_t			addr_len;

	xio_read_logging_level();

	cpu = sched_getcpu();
	if (cpu == -1)
		return NULL;

	/* allocate new context */
	ctx = calloc(1, sizeof(struct xio_context));
	if (ctx == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("calloc failed. %m\n");
		return NULL;
	}

	if (loop_ops == NULL)  {
		/* use default implementation */
		ctx->loop_ops.ev_loop_add_cb = xio_ev_loop_add;
		ctx->loop_ops.ev_loop_del_cb = xio_ev_loop_del;
	} else {
		ctx->loop_ops.ev_loop_add_cb = loop_ops->ev_loop_add_cb;
		ctx->loop_ops.ev_loop_del_cb = loop_ops->ev_loop_del_cb;
	}
	ctx->ev_loop = ev_loop;

	ctx->cpuid		= cpu;
	ctx->nodeid		= xio_get_nodeid(cpu);
	ctx->polling_timeout	= polling_timeout;

	ctx->worker = (uint64_t) pthread_self();

	XIO_OBSERVABLE_INIT(&ctx->observable, ctx);

	ctx->sched_work = xio_schedwork_init(ctx);
	if (!ctx->sched_work) {
		xio_set_error(errno);
		ERROR_LOG("schedwork_init failed. %m\n");
		goto cleanup1;
	}

	/* only root can bind netlink socket */
	if (geteuid() != 0) {
		DEBUG_LOG("statistics monitoring disabled. " \
			  "not priviliged user\n");
		return ctx;
	}

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (fd < 0) {
		xio_set_error(errno);
		ERROR_LOG("socket failed. %m\n");
		goto cleanup1;
	}

	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pad = 0;

	/* Listen to both UC and MC
	 * By default the monitoring program send MC request but if
	 * a thread starts after the monitor program than it will miss
	 * the request for the format. When the monitoring progarm receives
	 * statistics from a thread that it doesn't have its format it will
	 * send a UC request directly to it
	 *
	 */
	nladdr.nl_pid	 = 0;
	nladdr.nl_groups = 1;

	if (bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr))) {
		xio_set_error(errno);
		ERROR_LOG("bind failed. %m\n");
		goto cleanup2;
	}

	addr_len = sizeof(nladdr);
	if (getsockname(fd, (struct sockaddr *)&nladdr, &addr_len)) {
		xio_set_error(errno);
		ERROR_LOG("getsockname failed. %m\n");
		goto cleanup2;
	}

	if (addr_len != sizeof(nladdr)) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid addr_len\n");
		goto cleanup2;
	}
	if (nladdr.nl_family != AF_NETLINK) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid nl_family\n");
		goto cleanup2;
	}


	DEBUG_LOG("netlink socket bind to port %u\n",
		  nladdr.nl_pid);

	ctx->loop_ops.ev_loop_add_cb(ev_loop, fd, XIO_POLLIN,
				     xio_stats_handler, ctx);

	ctx->stats.hertz = get_cpu_mhz(0) * 1000000.0 + 0.5;
	/* Init default counters' name */
	ctx->stats.name[XIO_STAT_TX_MSG] = strdup("TX_MSG");
	ctx->stats.name[XIO_STAT_RX_MSG] = strdup("RX_MSG");
	ctx->stats.name[XIO_STAT_TX_BYTES] = strdup("TX_BYTES");
	ctx->stats.name[XIO_STAT_RX_BYTES] = strdup("RX_BYTES");
	ctx->stats.name[XIO_STAT_DELAY] = strdup("DELAY");
	ctx->stats.name[XIO_STAT_APPDELAY] = strdup("APPDELAY");

	ctx->netlink_sock = (void *)(unsigned long) fd;

	return ctx;

cleanup2:
	close(fd);
cleanup1:
	free(ctx);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_close	                                                     */
/*---------------------------------------------------------------------------*/
void xio_ctx_close(struct xio_context *ctx)
{
	int i;

	xio_observable_notify_all_observers(&ctx->observable,
					    XIO_CONTEXT_EVENT_CLOSE, NULL);
	xio_observable_unreg_all_observers(&ctx->observable);

	if (ctx->netlink_sock) {
		int fd = (int)(long) ctx->netlink_sock;
		ctx->loop_ops.ev_loop_del_cb(ctx->ev_loop, fd);
		close(fd);
		ctx->netlink_sock = NULL;
	}

	for (i = 0; i < XIO_STAT_LAST; i++)
		if (ctx->stats.name[i])
			free(ctx->stats.name[i]);

	xio_schedwork_close(ctx->sched_work);

	free(ctx);
	ctx = NULL;
}
/*---------------------------------------------------------------------------*/
/* xio_ctx_timer_add							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_timer_add(struct xio_context *ctx,
		      int msec_duration, void *data,
		      void (*timer_fn)(void *data),
		      xio_ctx_timer_handle_t *handle_out)
{
	int retval;

	retval = xio_schedwork_add(ctx->sched_work,
				   msec_duration, data,
				   timer_fn, handle_out);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("xio_schedwork_add failed. %m\n");
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_timer_del							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_timer_del(struct xio_context *ctx,
		      xio_ctx_timer_handle_t timer_handle)
{
	int retval;

	retval = xio_schedwork_del(ctx->sched_work, timer_handle);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("xio_schedwork_add failed. %m\n");
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_add_counter							     */
/*---------------------------------------------------------------------------*/
int xio_add_counter(struct xio_context *ctx, char *name)
{
	int i;

	for (i = XIO_STAT_USER_FIRST; i < XIO_STAT_LAST; i++) {
		if (!ctx->stats.name[i]) {
			ctx->stats.name[i] = strdup(name);
			if (!ctx->stats.name[i]) {
				perror("malloc");
				return -1;
			}
			ctx->stats.counter[i] = 0;
			return i;
		}
	}

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_del_counter							     */
/*---------------------------------------------------------------------------*/

int xio_del_counter(struct xio_context *ctx, int counter)
{
	if (counter < XIO_STAT_USER_FIRST || counter >= XIO_STAT_LAST) {
		fprintf(stderr, "counter(%d) out of range\n", counter);
		return -1;
	}

	/* free the name and mark as free for reuse */
	free(ctx->stats.name[counter]);
	ctx->stats.name[counter] = NULL;

	return 0;
}
