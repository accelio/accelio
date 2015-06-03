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
#include <xio_os.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <ib_cm.h>

#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_transport.h"
#include "xio_usr_transport.h"
#include "xio_mempool.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_rdma_utils.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"
#include "xio_rdma_transport.h"

/*---------------------------------------------------------------------------*/
/* xio_validate_rdma_op							     */
/*---------------------------------------------------------------------------*/
int xio_validate_rdma_op(
			struct xio_sge *lsg_list, size_t lsize,
			struct xio_sge *rsg_list, size_t rsize,
			int op_size,
			int max_sge,
			int *tasks_used)
{
	unsigned int	l	= 0,
			r	= 0;
	uint64_t	laddr	= lsg_list[0].addr;
	uint64_t	raddr	= rsg_list[0].addr;
	uint32_t	llen	= lsg_list[0].length;
	uint32_t	rlen	= rsg_list[0].length;
	int32_t		tot_len = 0;
	int		k = 0;

	if (lsize < 1 || rsize < 1) {
		ERROR_LOG("iovec size < 1 lsize:%zd, rsize:%zd\n",
			  lsize, rsize);
		*tasks_used = 0;
		return -1;
	}

	/* At least one task */
	*tasks_used = 1;

	while (1) {
		if (rlen < llen) {
			r++;
			tot_len	+= rlen;
			if (r == rsize)
				break;
			llen	-= rlen;
			laddr	+= rlen;
			raddr	= rsg_list[r].addr;
			rlen	= rsg_list[r].length;
			(*tasks_used)++;
			k = 0;
		} else if (llen < rlen) {
			l++;
			tot_len	+= llen;
			if (l == lsize)
				break;
			k++;
			if (k == max_sge - 1) {
				/* reached last index */
				(*tasks_used)++;
				k = 0;
			}
			rlen	-= llen;
			raddr	+= llen;
			laddr	= lsg_list[l].addr;
			llen	= lsg_list[l].length;
		} else {
			l++;
			r++;
			tot_len	+= llen;
			if ((l == lsize) || (r == rsize))
				break;
			laddr	= lsg_list[l].addr;
			llen	= lsg_list[l].length;
			raddr	= rsg_list[r].addr;
			rlen	= rsg_list[r].length;
			(*tasks_used)++;
			k = 0;
		}
	}

	/* not enough buffers to complete */
	if (tot_len < op_size) {
		*tasks_used = 0;
		ERROR_LOG("iovec exhausted\n");
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_cm_rej_reason_str					             */
/*---------------------------------------------------------------------------*/
const char *xio_cm_rej_reason_str(int reason)
{
	switch (reason) {
	case IB_CM_REJ_NO_QP:
		return "No QP";
	case IB_CM_REJ_NO_EEC:
		return "No EEC";
	case IB_CM_REJ_NO_RESOURCES:
		return "No Resources";
	case IB_CM_REJ_TIMEOUT:
		return "Timeout";
	case IB_CM_REJ_UNSUPPORTED:
		return "Unsupported";
	case IB_CM_REJ_INVALID_COMM_ID:
		return "Invalid COMM ID";
	case IB_CM_REJ_INVALID_COMM_INSTANCE:
		return "Invalid COMM Instance";
	case IB_CM_REJ_INVALID_SERVICE_ID:
		return "Invalid Service ID";
	case IB_CM_REJ_INVALID_TRANSPORT_TYPE:
		return "Invalid Transport Type";
	case IB_CM_REJ_STALE_CONN:
		return "Stale Connection";
	case IB_CM_REJ_RDC_NOT_EXIST:
		return "RDC not exist";
	case IB_CM_REJ_INVALID_GID:
		return "Invalid GID";
	case IB_CM_REJ_INVALID_LID:
		return "Invalid LID";
	case IB_CM_REJ_INVALID_SL:
		return "Invalid SL";
	case IB_CM_REJ_INVALID_TRAFFIC_CLASS:
		return "Invalid Traffic Class";
	case IB_CM_REJ_INVALID_HOP_LIMIT:
		return "Invalid HOP Limit";
	case IB_CM_REJ_INVALID_PACKET_RATE:
		return "Invalid Packet Rate";
	case IB_CM_REJ_INVALID_ALT_GID:
		return "Invalid Alt GID";
	case IB_CM_REJ_INVALID_ALT_LID:
		return "Invalid Alt LID";
	case IB_CM_REJ_INVALID_ALT_SL:
		return "Invalid Alt SL";
	case IB_CM_REJ_INVALID_ALT_TRAFFIC_CLASS:
		return "Invalid Alt Traffic Class";
	case IB_CM_REJ_INVALID_ALT_HOP_LIMIT:
		return "Invalid Alt HOP Limit";
	case IB_CM_REJ_INVALID_ALT_PACKET_RATE:
		return "Invalid Alt Packet Rate";
	case IB_CM_REJ_PORT_CM_REDIRECT:
		return "Invalid Alt Packet Rate";
	case IB_CM_REJ_PORT_REDIRECT:
		return "Port Redirect";
	case IB_CM_REJ_INVALID_MTU:
		return "Invalid MTU";
	case IB_CM_REJ_INSUFFICIENT_RESP_RESOURCES:
		return "Invalid Response Resources";
	case IB_CM_REJ_CONSUMER_DEFINED:
		return "Consumer Defined";
	case IB_CM_REJ_INVALID_RNR_RETRY:
		return "Invalid RNR Retry";
	case IB_CM_REJ_DUPLICATE_LOCAL_COMM_ID:
		return "Duplicate Local Comm ID";
	case IB_CM_REJ_INVALID_CLASS_VERSION:
		return "Invalid Class Version";
	case IB_CM_REJ_INVALID_FLOW_LABEL:
		return "Invalid Flow Label";
	case IB_CM_REJ_INVALID_ALT_FLOW_LABEL:
		return "Invalid Alt Flow Label";
	default:
		return "Unknown error";
	};
}

void xio_validate_ulimit_memlock(void)
{
	struct rlimit		mlock_limit;

	if (getrlimit(RLIMIT_MEMLOCK, &mlock_limit)) {
		ERROR_LOG("getrlimit call failed. (errno=%d %m)\n", errno);
		return;
	}
	if (mlock_limit.rlim_cur != RLIM_INFINITY) {
		WARN_LOG("Verify that Max Locked Memory (ulimit -l) " \
			 "setting is on unlimited (current is %ld)\n",
			 mlock_limit.rlim_cur);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mr_lookup							     */
/*---------------------------------------------------------------------------*/
struct ibv_mr *xio_rdma_mr_lookup(const struct xio_mr *tmr,
				  const struct xio_device *dev)
{
	struct xio_mr_elem *tmr_elem;
	const struct list_head *dm_list = &tmr->dm_list;

	list_for_each_entry(tmr_elem, dm_list, dm_list_entry) {
		if (dev == tmr_elem->dev)
			return tmr_elem->mr;
	}
	return NULL;
}
