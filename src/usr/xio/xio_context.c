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

#include <xio_os.h>
#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "get_clock.h"
#include "xio_ev_data.h"
#include "xio_ev_loop.h"
#include "xio_idr.h"
#include "xio_workqueue.h"
#include "xio_timers_list.h"
#include "xio_context.h"
#include "xio_usr_utils.h"

/*---------------------------------------------------------------------------*/
/* xio_context_reg_observer						     */
/*---------------------------------------------------------------------------*/
int xio_context_reg_observer(struct xio_context *ctx,
			     struct xio_observer *observer)
{
	xio_observable_reg_observer(&ctx->observable, observer);

	return 0;
}
EXPORT_SYMBOL(xio_context_reg_observer);

/*---------------------------------------------------------------------------*/
/* xio_context_unreg_observer		                                     */
/*---------------------------------------------------------------------------*/
void xio_context_unreg_observer(struct xio_context *ctx,
				struct xio_observer *observer)
{
	xio_observable_unreg_observer(&ctx->observable, observer);
}
EXPORT_SYMBOL(xio_context_unreg_observer);

/*---------------------------------------------------------------------------*/
/* xio_stats_handler							     */
/*---------------------------------------------------------------------------*/
static void xio_stats_handler(int fd, int events, void *data)
{
	struct xio_context *ctx = (struct xio_context *)data;
	unsigned char buf[NLMSG_SPACE(1024)];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct msghdr msg;
	struct iovec iov;
	struct sockaddr_nl dest_addr;
	uint64_t now = get_cycles();
	ssize_t ret;
	char *ptr;
	int i;

	/* read netlink message */
	iov.iov_base = (void *)nlh;
	/* max size for receive */
	iov.iov_len = NLMSG_SPACE(1024);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	ret = recvmsg(fd, &msg, 0);
	if (ret <= 0)
		return;

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
	ret = sendmsg(fd, &msg, 0);
	if (ret <= 0)
		return;
}

/*---------------------------------------------------------------------------*/
/* xio_pin_to_cpu - pin to specific cpu					     */
/*---------------------------------------------------------------------------*/
static int xio_pin_to_cpu(int cpu)
{
	int		ncpus = numa_num_task_cpus();
	int		ret;
	cpu_set_t	cs;

	if (ncpus > CPU_SETSIZE)
		return -1;

	CPU_ZERO(&cs);
	CPU_SET(cpu, &cs);
	if (CPU_COUNT(&cs) == 1)
		return 0;

	ret = sched_setaffinity(0, sizeof(cs), &cs);
	if (ret) {
		xio_set_error(errno);
		ERROR_LOG("sched_setaffinity failed. %m\n");
		return -1;
	}
	/* guaranteed to take effect immediately */
	sched_yield();

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_pin_to_node - pin to the numa node of the cpu			     */
/*---------------------------------------------------------------------------*/
static int xio_pin_to_node(int cpu)
{
	int node = numa_node_of_cpu(cpu);
	/* pin to node */
	int ret = numa_run_on_node(node);
	if (ret)
		return -1;

	/* is numa_run_on_node() guaranteed to take effect immediately? */
	sched_yield();

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_context_create                                                        */
/*---------------------------------------------------------------------------*/
struct xio_context *xio_context_create(struct xio_context_attr *ctx_attr,
				       int polling_timeout_us, int cpu_hint)
{
	struct xio_context		*ctx = NULL;
	int				cpu;
	struct sockaddr_nl		nladdr;
	int				fd;
	socklen_t			addr_len;

	xio_read_logging_level();

	if (cpu_hint == -1) {
		cpu = xio_get_cpu();
		if (cpu == -1) {
			xio_set_error(errno);
			return NULL;
		}
	} else {
		cpu = cpu_hint;
	}
	/*pin the process to cpu */
	xio_pin_to_cpu(cpu);
	/* pin to the numa node of the cpu */
	if (0)
		xio_pin_to_node(cpu);


	/* allocate new context */
	ctx = (struct xio_context *)ucalloc(1, sizeof(struct xio_context));
	if (ctx == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("calloc failed. %m\n");
		return NULL;
	}
	ctx->ev_loop		= xio_ev_loop_create();

	ctx->cpuid		= cpu;
	ctx->nodeid		= numa_node_of_cpu(cpu);
	ctx->polling_timeout	= polling_timeout_us;
	ctx->worker		= (uint64_t) pthread_self();

	if (ctx_attr)
		ctx->user_context = ctx_attr->user_context;

	XIO_OBSERVABLE_INIT(&ctx->observable, ctx);
	INIT_LIST_HEAD(&ctx->ctx_list);

	ctx->workqueue = xio_workqueue_create(ctx);
	if (!ctx->workqueue) {
		xio_set_error(errno);
		ERROR_LOG("schedwork_queue_init failed. %m\n");
		goto cleanup1;
	}

	/* only root can bind netlink socket */
	if (geteuid() != 0) {
		DEBUG_LOG("statistics monitoring disabled. " \
			  "not privileged user\n");
		goto exit;
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
	 * the request for the format. When the monitoring program receives
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

	xio_ev_loop_add(ctx->ev_loop, fd, XIO_POLLIN,
			xio_stats_handler, ctx);

	ctx->stats.hertz = g_mhz * 1000000.0 + 0.5;
	/* Init default counters' name */
	ctx->stats.name[XIO_STAT_TX_MSG] = strdup("TX_MSG");
	ctx->stats.name[XIO_STAT_RX_MSG] = strdup("RX_MSG");
	ctx->stats.name[XIO_STAT_TX_BYTES] = strdup("TX_BYTES");
	ctx->stats.name[XIO_STAT_RX_BYTES] = strdup("RX_BYTES");
	ctx->stats.name[XIO_STAT_DELAY] = strdup("DELAY");
	ctx->stats.name[XIO_STAT_APPDELAY] = strdup("APPDELAY");

	ctx->netlink_sock = (void *)(unsigned long) fd;

exit:
	xio_idr_add_uobj(usr_idr, ctx, "xio_context");
	return ctx;

cleanup2:
	close(fd);
cleanup1:
	ufree(ctx);
	return NULL;
}
EXPORT_SYMBOL(xio_context_create);

/*---------------------------------------------------------------------------*/
/* xio_context_destroy	                                                     */
/*---------------------------------------------------------------------------*/
void xio_context_destroy(struct xio_context *ctx)
{
	int i;
	int found;

	if (ctx == NULL)
		return;


	found = xio_idr_lookup_uobj(usr_idr, ctx);
	if (found) {
		xio_idr_remove_uobj(usr_idr, ctx);
	} else {
		ERROR_LOG("context not found:%p\n", ctx);
		xio_set_error(XIO_E_USER_OBJ_NOT_FOUND);
		return;
	}
	ctx->run_private = 0;
	xio_observable_notify_all_observers(&ctx->observable,
					    XIO_CONTEXT_EVENT_CLOSE, NULL);

	/* allow internally to run the loop for final cleanup */
	if (ctx->run_private)
		xio_context_run_loop(ctx, 5000);

	xio_observable_unreg_all_observers(&ctx->observable);

	if (ctx->netlink_sock) {
		int fd = (int)(long) ctx->netlink_sock;
		xio_ev_loop_del(ctx->ev_loop, fd);
		close(fd);
		ctx->netlink_sock = NULL;
	}
	for (i = 0; i < XIO_STAT_LAST; i++)
		if (ctx->stats.name[i])
			free(ctx->stats.name[i]);

	xio_workqueue_destroy(ctx->workqueue);

	if (ctx->mempool) {
		xio_mempool_destroy((struct xio_mempool *)ctx->mempool);
		ctx->mempool = NULL;
	}

	xio_ev_loop_destroy(&ctx->ev_loop);

	XIO_OBSERVABLE_DESTROY(&ctx->observable);
	ufree(ctx);
}
EXPORT_SYMBOL(xio_context_destroy);

/*---------------------------------------------------------------------------*/
/* xio_ctx_add_delayed_work						     */
/*---------------------------------------------------------------------------*/
int xio_ctx_add_delayed_work(struct xio_context *ctx,
			     int msec_duration, void *data,
			     void (*timer_fn)(void *data),
			     xio_ctx_delayed_work_t *work)
{
	int retval;

	/* test if delayed work is pending */
	if (xio_is_delayed_work_pending(work))
		return 0;

	retval = xio_workqueue_add_delayed_work(ctx->workqueue,
						msec_duration, data,
						timer_fn, work);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("xio_workqueue_add_delayed_work failed. %m\n");
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_del_delayed_work						     */
/*---------------------------------------------------------------------------*/
int xio_ctx_del_delayed_work(struct xio_context *ctx,
			     xio_ctx_delayed_work_t *work)
{
	int retval;

	/* test if delayed work is pending */
	if (!xio_is_delayed_work_pending(work))
		return 0;

	retval = xio_workqueue_del_delayed_work(ctx->workqueue, work);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("xio_workqueue_del_delayed_work failed. %m\n");
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
				ERROR_LOG("stddup failed. %m");
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
		ERROR_LOG("counter(%d) out of range\n", counter);
		return -1;
	}

	/* free the name and mark as free for reuse */
	free(ctx->stats.name[counter]);
	ctx->stats.name[counter] = NULL;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_modify_context							     */
/*---------------------------------------------------------------------------*/
int xio_modify_context(struct xio_context *ctx,
		       struct xio_context_attr *attr,
		       int attr_mask)
{
	if (!ctx || !attr) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid parameters\n");
		return -1;
	}

	if (attr_mask & XIO_CONTEXT_ATTR_USER_CTX)
		ctx->user_context = attr->user_context;

	return 0;
}
EXPORT_SYMBOL(xio_modify_context);

/*---------------------------------------------------------------------------*/
/* xio_query_context							     */
/*---------------------------------------------------------------------------*/
int xio_query_context(struct xio_context *ctx,
		      struct xio_context_attr *attr,
		      int attr_mask)
{
	if (!ctx || !attr) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid parameters\n");
		return -1;
	}

	if (attr_mask & XIO_CONTEXT_ATTR_USER_CTX)
		attr->user_context = ctx->user_context;

	return 0;
}
EXPORT_SYMBOL(xio_query_context);

/*---------------------------------------------------------------------------*/
/* xio_context_get_poll_params						     */
/*---------------------------------------------------------------------------*/
int xio_context_get_poll_params(struct xio_context *ctx,
				struct xio_poll_params *poll_params)
{
	return xio_ev_loop_get_poll_params(ctx->ev_loop, poll_params);
}

/*---------------------------------------------------------------------------*/
/* xio_context_add_ev_handler						     */
/*---------------------------------------------------------------------------*/
int xio_context_add_ev_handler(struct xio_context *ctx,
			       int fd, int events,
			       xio_ev_handler_t handler,
			       void *data)
{
	return xio_ev_loop_add(ctx->ev_loop,
			       fd, events, handler, data);
}
EXPORT_SYMBOL(xio_context_add_ev_handler);

/*---------------------------------------------------------------------------*/
/* xio_context_modify_ev_handler					     */
/*---------------------------------------------------------------------------*/
int xio_context_modify_ev_handler(struct xio_context *ctx,
				  int fd, int events)
{
	return xio_ev_loop_modify(ctx->ev_loop, fd, events);
}

/*---------------------------------------------------------------------------*/
/* xio_context_del_ev_handler						     */
/*---------------------------------------------------------------------------*/
int xio_context_del_ev_handler(struct xio_context *ctx,
			       int fd)
{
	return xio_ev_loop_del(ctx->ev_loop, fd);
}

/*---------------------------------------------------------------------------*/
/* xio_context_run_loop							     */
/*---------------------------------------------------------------------------*/
int xio_context_run_loop(struct xio_context *ctx, int timeout_ms)
{
	if (timeout_ms == -1)
		return	xio_ev_loop_run(ctx->ev_loop);
	else
		return	xio_ev_loop_run_timeout(ctx->ev_loop, timeout_ms);
}
EXPORT_SYMBOL(xio_context_run_loop);

/*---------------------------------------------------------------------------*/
/* xio_context_stop_loop						     */
/*---------------------------------------------------------------------------*/
inline void xio_context_stop_loop(struct xio_context *ctx, int is_self_thread)
{
	xio_ev_loop_stop(ctx->ev_loop, is_self_thread);
}
EXPORT_SYMBOL(xio_context_stop_loop);

/*---------------------------------------------------------------------------*/
/* xio_context_is_loop_stopping						     */
/*---------------------------------------------------------------------------*/
inline int xio_context_is_loop_stopping(struct xio_context *ctx)
{
	return xio_ev_loop_is_stopping(ctx->ev_loop);
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_add_work							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_add_work(struct xio_context *ctx,
		     void *data,
		     void (*function)(void *data),
		     xio_ctx_work_t *work)
{
	int retval;

	/* test if work is pending */
	if (xio_is_work_pending(work))
		return 0;

	retval = xio_workqueue_add_work(ctx->workqueue,
					data, function, work);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("xio_workqueue_add_work failed. %m\n");
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_del_work							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_del_work(struct xio_context *ctx,
		     xio_ctx_work_t *work)

{
	int retval;

	/* test if work is pending */
	if (!xio_is_work_pending(work))
		return 0;

	retval = xio_workqueue_del_work(ctx->workqueue, work);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("xio_workqueue_del_work failed. %m\n");
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_init_event							     */
/*---------------------------------------------------------------------------*/
void xio_ctx_init_event(
		xio_ctx_event_t *evt,
		void (*event_handler)(void *data),
		void *data)
{
	xio_ev_loop_init_event(evt, event_handler, data);
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_add_event							     */
/*---------------------------------------------------------------------------*/
void xio_ctx_add_event(struct xio_context *ctx, xio_ctx_event_t *evt)
{
	xio_ev_loop_add_event(ctx->ev_loop, evt);
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_remove_event							     */
/*---------------------------------------------------------------------------*/
void xio_ctx_remove_event(struct xio_context *ctx, xio_ctx_event_t *evt)
{
	xio_ev_loop_remove_event(ctx->ev_loop, evt);
}

