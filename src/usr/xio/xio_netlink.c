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
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_timers_list.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_context.h"

#define XIO_NETLINK_MCAST_GRP_ID 4

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
/* xio_netlink								     */
/*---------------------------------------------------------------------------*/
int xio_netlink(struct xio_context *ctx)
{
	struct sockaddr_nl		nladdr;
	int				fd;
	socklen_t			addr_len;

	/* only root can bind netlink socket */
	if (geteuid() != 0) {
		DEBUG_LOG("statistics monitoring disabled. " \
			"not privileged user\n");
		return 0;
	}

	fd = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (fd < 0) {
		xio_set_error(errno);
		ERROR_LOG("socket failed. %m\n");
		return -1;
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
	nladdr.nl_pid = 0;
	nladdr.nl_groups = XIO_NETLINK_MCAST_GRP_ID;

	if (bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr))) {
		/*
		 * I suspect that accelio is broken on kernel 3.19 due
		 * to the following patch:
		 * https://patchwork.ozlabs.org/patch/429350/
		 */
		if (errno == ENOENT) {
			WARN_LOG("netlink bind failed. %m\n");
			close(fd);
			return 0;
		}
		xio_set_error(errno);
		ERROR_LOG("netlink bind failed. %m\n");
		goto cleanup;
	}

	addr_len = sizeof(nladdr);
	if (getsockname(fd, (struct sockaddr *)&nladdr, &addr_len)) {
		xio_set_error(errno);
		ERROR_LOG("getsockname failed. %m\n");
		goto cleanup;
	}

	if (addr_len != sizeof(nladdr)) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid addr_len\n");
		goto cleanup;
	}
	if (nladdr.nl_family != AF_NETLINK) {
		xio_set_error(EINVAL);
		ERROR_LOG("invalid nl_family\n");
		goto cleanup;
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

	ctx->netlink_sock = (void *)(unsigned long)fd;
	return 0;

cleanup:
	close(fd);
	return -1;
}

