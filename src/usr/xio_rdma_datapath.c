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
#include "xio_os.h"
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include "libxio.h"
#include "xio_common.h"
#include "xio_context.h"
#include "xio_task.h"
#include "xio_transport.h"
#include "xio_conn.h"
#include "xio_protocol.h"
#include "get_clock.h"
#include "xio_mem.h"
#include "xio_rdma_mempool.h"
#include "xio_rdma_transport.h"


/*---------------------------------------------------------------------------*/
/* externals								     */
/*---------------------------------------------------------------------------*/
extern double g_mhz;
extern struct xio_rdma_options	rdma_options;

/*---------------------------------------------------------------------------*/
/* forward declarations							     */
/*---------------------------------------------------------------------------*/
static void xio_prep_rdma_rd_send_req(
		struct xio_task *task,
		struct xio_rdma_transport *rdma_hndl,
		int signaled);
static int xio_rdma_on_recv_req(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task);
static int xio_rdma_on_recv_rsp(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task);
static int xio_rdma_on_setup_msg(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task);
static int xio_rdma_on_rsp_send_comp(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task);
static int xio_rdma_on_req_send_comp(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task);
static int xio_rdma_on_recv_nop(struct xio_rdma_transport *rdma_hndl,
				struct xio_task *task);
static int xio_rdma_send_nop(struct xio_rdma_transport *rdma_hndl);


/*---------------------------------------------------------------------------*/
/* xio_rdma_mr_lookup							     */
/*---------------------------------------------------------------------------*/
static inline struct ibv_mr *xio_rdma_mr_lookup(struct xio_mr *tmr,
				    struct xio_device *dev)
{
	struct xio_mr_elem *tmr_elem;

	list_for_each_entry(tmr_elem, &tmr->dm_list, dm_list_entry) {
		if (dev == tmr_elem->dev)
			return tmr_elem->mr;
	}
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_post_recv							     */
/*---------------------------------------------------------------------------*/
int xio_post_recv(struct xio_rdma_transport *rdma_hndl,
			   struct xio_task *task, int num_recv_bufs)
{
	struct ibv_recv_wr	*bad_wr	= NULL;
	int			retval, nr_posted;
	struct xio_rdma_task *rdma_task =
				(struct xio_rdma_task *)task->dd_data;

	retval = ibv_post_recv(rdma_hndl->qp, &rdma_task->rxd.recv_wr, &bad_wr);
	if (likely(!retval)) {
		nr_posted = num_recv_bufs;
	} else {
		struct ibv_recv_wr *wr;
			nr_posted = 0;
		for (wr = &rdma_task->rxd.recv_wr; wr != bad_wr; wr = wr->next)
			nr_posted++;

		xio_set_error(retval);
		ERROR_LOG("ibv_post_recv failed. (errno=%d %s)\n",
			  retval, strerror(retval));
	}
	rdma_hndl->rqe_avail += nr_posted;

	/* credit updates */
	rdma_hndl->credits += nr_posted;

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_post_send                                                           */
/*---------------------------------------------------------------------------*/
static int xio_post_send(struct xio_rdma_transport *rdma_hndl,
			   struct xio_work_req *xio_send,
			   int num_send_reqs)
{
	struct ibv_send_wr	*bad_wr;
	int			retval, nr_posted;


	TRACE_LOG("num_sge:%d, len1:%d, len2:%d, send_flags:%d\n",
		  xio_send->send_wr.num_sge,
		  xio_send->send_wr.sg_list[0].length,
		  xio_send->send_wr.sg_list[1].length,
		  xio_send->send_wr.send_flags);

	retval = ibv_post_send(rdma_hndl->qp, &xio_send->send_wr, &bad_wr);
	if (likely(!retval)) {
		nr_posted = num_send_reqs;
	} else {
		struct ibv_send_wr *wr;

		nr_posted = 0;
		for (wr = &xio_send->send_wr; wr != bad_wr; wr = wr->next)
			nr_posted++;

		xio_set_error(retval);

		ERROR_LOG("ibv_post_send failed. (errno=%d %s)  posted:%d/%d " \
			  "sge_sz:%d, sqe_avail:%d\n", retval, strerror(retval),
			  nr_posted, num_send_reqs, xio_send->send_wr.num_sge,
			  rdma_hndl->sqe_avail);
	}
	rdma_hndl->sqe_avail -= nr_posted;

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_sn							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_write_sn(struct xio_task *task,
			     uint16_t sn, uint16_t ack_sn, uint16_t credits)
{
	uint16_t *psn;

	/* save the current place */
	xio_mbuf_push(&task->mbuf);
	/* goto to the first tlv */
	xio_mbuf_reset(&task->mbuf);
	/* goto the first transport header*/
	xio_mbuf_set_trans_hdr(&task->mbuf);

	/* jump over the first uint16_t */
	xio_mbuf_inc(&task->mbuf, sizeof(uint16_t));

	/* and set serial number */
	psn = xio_mbuf_get_curr_ptr(&task->mbuf);
	*psn = htons(sn);

	xio_mbuf_inc(&task->mbuf, sizeof(uint16_t));

	/* and set ack serial number */
	psn = xio_mbuf_get_curr_ptr(&task->mbuf);
	*psn = htons(ack_sn);

	xio_mbuf_inc(&task->mbuf, sizeof(uint16_t));

	/* and set credits */
	psn = xio_mbuf_get_curr_ptr(&task->mbuf);
	*psn = htons(credits);

	/* pop to the original place */
	xio_mbuf_pop(&task->mbuf);

	return 0;
}

static inline uint16_t tx_window_sz(struct xio_rdma_transport *rdma_hndl)
{
	return rdma_hndl->max_sn - rdma_hndl->sn;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_xmit							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_xmit(struct xio_rdma_transport *rdma_hndl)
{
	struct xio_task		*task = NULL;
	struct xio_rdma_task	*rdma_task = NULL;
	struct xio_rdma_task	*prev_rdma_task = NULL;
	struct xio_work_req	*first_wr = NULL;
	struct xio_work_req	*curr_wr = NULL;
	uint16_t		tx_window;
	uint16_t		window;
	uint16_t		retval;
	uint16_t		req_nr = 0;

	tx_window = tx_window_sz(rdma_hndl);
	window = min(rdma_hndl->peer_credits, tx_window);
	window = min(window, rdma_hndl->sqe_avail);

	TRACE_LOG("XMIT: tx_window:%d, peer_credits:%d, sqe_avail:%d\n",
		  tx_window,
		  rdma_hndl->peer_credits,
		  rdma_hndl->sqe_avail);

	if (window == 0) {
		xio_set_error(EAGAIN);
		return -1;
	}

	/* if "ready to send queue" is not empty */
	while (rdma_hndl->tx_ready_tasks_num) {
		task = list_first_entry(
				&rdma_hndl->tx_ready_list,
				struct xio_task,  tasks_list_entry);

		rdma_task = task->dd_data;
		if (rdma_task->ib_op == XIO_IB_RDMA_WRITE) {
			if (req_nr >= (window - 1))
				break;

			/* prepare it for rdma wr and concatenate the send
			 * wr to it */
			rdma_task->rdmad.send_wr.next = &rdma_task->txd.send_wr;
			rdma_task->rdmad.send_wr.send_flags = IBV_SEND_SIGNALED;

			curr_wr = &rdma_task->rdmad;
			req_nr++;
		} else {
			if (req_nr >= window)
				break;
			curr_wr = &rdma_task->txd;
		}
		xio_rdma_write_sn(task, rdma_hndl->sn, rdma_hndl->ack_sn,
				  rdma_hndl->credits);
		rdma_task->sn = rdma_hndl->sn;
		rdma_hndl->sn++;
		rdma_hndl->sim_peer_credits += rdma_hndl->credits;
		rdma_hndl->credits = 0;
		rdma_hndl->peer_credits--;

		if (prev_rdma_task == NULL)
			first_wr = curr_wr;
		else
			prev_rdma_task->txd.send_wr.next = &curr_wr->send_wr;

		prev_rdma_task = rdma_task;
		req_nr++;
		rdma_hndl->tx_ready_tasks_num--;
		if (IS_REQUEST(task->tlv_type))
			rdma_hndl->reqs_in_flight_nr++;
		else
			rdma_hndl->rsps_in_flight_nr++;
		list_move_tail(&task->tasks_list_entry,
			       &rdma_hndl->in_flight_list);
	}
	if (req_nr) {
		prev_rdma_task->txd.send_wr.next = NULL;
		if (tx_window_sz(rdma_hndl) < 1 ||
		    rdma_hndl->sqe_avail < req_nr + 1)
			prev_rdma_task->txd.send_wr.send_flags |=
				IBV_SEND_SIGNALED;
		retval = xio_post_send(rdma_hndl, first_wr, req_nr);
		if (retval != 0) {
			ERROR_LOG("xio_post_send failed");
			return -1;
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_xmit_rdma_rd							     */
/*---------------------------------------------------------------------------*/
static void xio_xmit_rdma_rd(struct xio_rdma_transport *rdma_hndl)
{
	struct xio_task		*task = NULL;
	struct xio_rdma_task	*rdma_task = NULL;
	struct xio_rdma_task	*prev_rdma_task = NULL;
	struct xio_work_req	*first_wr = NULL;
	int num_reqs = 0;
	int err;

	while (!list_empty(&rdma_hndl->rdma_rd_list) &&
	       rdma_hndl->sqe_avail > num_reqs) {
		task = list_first_entry(
				&rdma_hndl->rdma_rd_list,
				struct xio_task,  tasks_list_entry);
		list_move_tail(&task->tasks_list_entry,
			       &rdma_hndl->rdma_rd_in_flight_list);
		rdma_task = task->dd_data;

		/* prepare it for rdma read */
		xio_prep_rdma_rd_send_req(task, rdma_hndl, 1);
		if (first_wr == NULL)
			first_wr = &rdma_task->rdmad;
		else
			prev_rdma_task->rdmad.send_wr.next =
						&rdma_task->rdmad.send_wr;
		prev_rdma_task = rdma_task;
		num_reqs++;
	}
	rdma_hndl->kick_rdma_rd = 0;
	if (prev_rdma_task) {
		prev_rdma_task->rdmad.send_wr.next = NULL;
		rdma_hndl->rdma_in_flight += num_reqs;
		/* submit the chain of rdma-rd requests, start from the first */
		err = xio_post_send(rdma_hndl, first_wr, num_reqs);
		/* ToDo: error handling */
	} else if (!list_empty(&rdma_hndl->rdma_rd_list)) {
		rdma_hndl->kick_rdma_rd = 1;
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_rearm_rq							     */
/*---------------------------------------------------------------------------*/
int xio_rdma_rearm_rq(struct xio_rdma_transport *rdma_hndl)
{
	struct xio_task		*first_task = NULL;
	struct xio_task		*task = NULL;
	struct xio_task		*prev_task = NULL;
	struct xio_rdma_task	*rdma_task = NULL;
	struct xio_rdma_task	*prev_rdma_task = NULL;
	int			num_to_post;
	int			i;

	num_to_post = rdma_hndl->actual_rq_depth - rdma_hndl->rqe_avail;
	for (i = 0; i < num_to_post; i++) {
		/* get ready to receive message */
		task = xio_conn_get_primary_task(rdma_hndl->base.observer);
		if (task == 0) {
			ERROR_LOG("primary task pool is empty\n");
			return -1;
		}
		rdma_task = task->dd_data;
		if (first_task == NULL)
			first_task = task;
		else
			prev_rdma_task->rxd.recv_wr.next =
						&rdma_task->rxd.recv_wr;

		prev_task = task;
		prev_rdma_task = rdma_task;
		rdma_task->ib_op = XIO_IB_RECV;
		list_add_tail(&task->tasks_list_entry, &rdma_hndl->rx_list);
	}
	if (prev_task) {
		prev_rdma_task->rxd.recv_wr.next = NULL;
		xio_post_recv(rdma_hndl, first_task, num_to_post);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_rx_error_handler						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_rx_error_handler(struct xio_rdma_transport *rdma_hndl,
	      struct xio_task *task)
{
	/* remove the task from rx list */
	xio_tasks_pool_put(task);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_tx_error_handler						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_tx_error_handler(struct xio_rdma_transport *rdma_hndl,
	      struct xio_task *task)
{
	/* remove the task from in-flight list */
	xio_tasks_pool_put(task);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_rd_error_handler						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_rd_error_handler(struct xio_rdma_transport *rdma_hndl,
	      struct xio_task *task)
{
	/* remove the task from rdma rd in-flight list */
	xio_tasks_pool_put(task);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_wr_error_handler						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_wr_error_handler(struct xio_rdma_transport *rdma_hndl,
	      struct xio_task *task)
{
	struct xio_rdma_task  *rdma_task = task->dd_data;

	/* wait for the concatenated "send" */
	rdma_task->ib_op = XIO_IB_SEND;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_handle_wc_error                                                       */
/*---------------------------------------------------------------------------*/
static void xio_handle_task_error(struct xio_task *task)
{
	struct xio_rdma_task            *rdma_task = task->dd_data;
	struct xio_rdma_transport       *rdma_hndl = rdma_task->rdma_hndl;

	switch (rdma_task->ib_op) {
	case XIO_IB_RECV:
		/* this should be the Flush, no task has been created yet */
		xio_rdma_rx_error_handler(rdma_hndl, task);
		break;
	case XIO_IB_SEND:
		/* the task should be completed now */
		xio_rdma_tx_error_handler(rdma_hndl, task);
		break;
	case XIO_IB_RDMA_READ:
		xio_rdma_rd_error_handler(rdma_hndl, task);
		break;
	case XIO_IB_RDMA_WRITE:
		xio_rdma_wr_error_handler(rdma_hndl, task);
		break;
	default:
		ERROR_LOG("unknown opcode: task:%p, type:0x%x, " \
			  "magic:0x%"PRIx64", ib_op:0x%x\n",
			  task, task->tlv_type,
			  task->magic, rdma_task->ib_op);
		break;
	}
}

/*---------------------------------------------------------------------------*/
/* xio_handle_wc_error                                                       */
/*---------------------------------------------------------------------------*/
static void xio_handle_wc_error(struct ibv_wc *wc)
{
	struct xio_task			*task = ptr_from_int64(wc->wr_id);
	struct xio_rdma_task            *rdma_task = task->dd_data;
	struct xio_rdma_transport       *rdma_hndl = rdma_task->rdma_hndl;

	if (wc->status == IBV_WC_WR_FLUSH_ERR) {
		TRACE_LOG("conn:%p, rdma_task:%p, task:%p, " \
			  "wr_id:0x%"PRIx64", " \
			  "err:%s, vendor_err:0x%x, " \
			   "ib_op:%x\n",
			   rdma_hndl, rdma_task, task,
			   wc->wr_id,
			   ibv_wc_status_str(wc->status),
			   wc->vendor_err,
			   rdma_task->ib_op);
	} else  {
		ERROR_LOG("conn:%p, rdma_task:%p, task:%p, "  \
			  "wr_id:0x%"PRIx64", " \
			  "err:%s, vendor_err:0x%x," \
			  "ib_op:0x%x\n",
			  rdma_hndl, rdma_task, task,
			  wc->wr_id,
			  ibv_wc_status_str(wc->status),
			  wc->vendor_err,
			  rdma_task->ib_op);

		ERROR_LOG("byte_len=%u, immdata=%u, qp_num=0x%x, src_qp=%u\n",
			  wc->byte_len, wc->imm_data, wc->qp_num, wc->src_qp);
	}
	xio_handle_task_error(task);

	/* temporary  */
	if (wc->status != IBV_WC_WR_FLUSH_ERR) {
		ERROR_LOG("program abort\n");
		exit(0);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_idle_handler						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_idle_handler(struct xio_rdma_transport *rdma_hndl)
{
	if (rdma_hndl->tx_ready_tasks_num)
		return 0;

	if (rdma_hndl->state != XIO_STATE_CONNECTED)
		return 0;

	/* send nop if no message is queued */
	if (!(rdma_hndl->peer_credits && rdma_hndl->credits &&
	      rdma_hndl->sqe_avail &&
	      rdma_hndl->sim_peer_credits < MAX_RECV_WR))
		return 0;

	TRACE_LOG("peer_credits:%d, credits:%d sim_peer_credits:%d\n",
		  rdma_hndl->peer_credits, rdma_hndl->credits,
		  rdma_hndl->sim_peer_credits);

	xio_rdma_send_nop(rdma_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_rx_handler							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_rx_handler(struct xio_rdma_transport *rdma_hndl,
	      struct xio_task *task, int has_more)
{
	int			retval;
	struct xio_rdma_task	*rdma_task = task->dd_data;
	int			must_send = 0;

	rdma_hndl->rqe_avail--;
	rdma_hndl->sim_peer_credits--;

	/* rearm the receive queue  */
	if ((rdma_hndl->state == XIO_STATE_CONNECTED) &&
	    (rdma_hndl->rqe_avail <= rdma_hndl->rq_depth + 1))
		xio_rdma_rearm_rq(rdma_hndl);

	retval = xio_mbuf_read_first_tlv(&task->mbuf);

	task->tlv_type = xio_mbuf_tlv_type(&task->mbuf);
	list_move_tail(&task->tasks_list_entry, &rdma_hndl->io_list);

	rdma_task->more_in_batch = has_more;

	/* call recv completion  */
	switch (task->tlv_type) {
	case XIO_CREDIT_NOP:
		xio_rdma_on_recv_nop(rdma_hndl, task);
		break;
	case XIO_CONN_SETUP_REQ:
	case XIO_CONN_SETUP_RSP:
		xio_rdma_on_setup_msg(rdma_hndl, task);
		break;
	default:
		if (IS_REQUEST(task->tlv_type))
			xio_rdma_on_recv_req(rdma_hndl, task);
		else if (IS_RESPONSE(task->tlv_type))
			xio_rdma_on_recv_rsp(rdma_hndl, task);
		else
			ERROR_LOG("unknown message type:0x%x\n",
				  task->tlv_type);
		break;
	}

	if (rdma_hndl->state != XIO_STATE_CONNECTED)
		return retval;

	/* transmit ready packets */
	if (rdma_hndl->tx_ready_tasks_num) {
		must_send = (tx_window_sz(rdma_hndl) >= SEND_TRESHOLD);
		must_send |= (has_more == 0);
	}
	/* resource are now available and rdma rd  requests are pending kick
	 * them
	 */
	if (rdma_hndl->kick_rdma_rd)
		xio_xmit_rdma_rd(rdma_hndl);


	if (must_send)
		xio_rdma_xmit(rdma_hndl);

	return retval;
}


/*---------------------------------------------------------------------------*/
/* xio_rdma_tx_comp_handler						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_tx_comp_handler(struct xio_rdma_transport *rdma_hndl,
	      struct xio_task *task)
{
	struct xio_task		*ptask, *next_ptask;
	struct xio_rdma_task	*rdma_task;
	int			found = 0;
	int			removed = 0;

	list_for_each_entry_safe(ptask, next_ptask, &rdma_hndl->in_flight_list,
				 tasks_list_entry) {
		list_move_tail(&ptask->tasks_list_entry,
			       &rdma_hndl->tx_comp_list);
		removed++;
		rdma_task = ptask->dd_data;

		rdma_hndl->sqe_avail++;
		/* rdma wr utilizes two wqe but appears only once in the
		 * in flight list
		 */
		if (rdma_task->ib_op == XIO_IB_RDMA_WRITE)
			rdma_hndl->sqe_avail++;

		if (IS_REQUEST(ptask->tlv_type)) {
			rdma_hndl->max_sn++;
			rdma_hndl->reqs_in_flight_nr--;
			xio_rdma_on_req_send_comp(rdma_hndl, ptask);
			xio_tasks_pool_put(ptask);
		} else if (IS_RESPONSE(ptask->tlv_type)) {
			rdma_hndl->max_sn++;
			rdma_hndl->rsps_in_flight_nr--;
			xio_rdma_on_rsp_send_comp(rdma_hndl, ptask);
		} else if (IS_NOP(ptask->tlv_type)) {
			rdma_hndl->rsps_in_flight_nr--;
			xio_tasks_pool_put(ptask);
		} else {
			ERROR_LOG("unexpected task %p type:0x%x id:%d " \
				  "magic:0x%"PRIx64"\n",
				  ptask, rdma_task->ib_op,
				  ptask->ltid, ptask->magic);
			continue;
		}
		if (ptask == task) {
			found  = 1;
			break;
		}
	}
	/* resource are now available and rdma rd  requests are pending kick
	 * them
	 */
	if (rdma_hndl->kick_rdma_rd)
		xio_xmit_rdma_rd(rdma_hndl);


	if (rdma_hndl->tx_ready_tasks_num)
		xio_rdma_xmit(rdma_hndl);


	if (!found && removed)
		ERROR_LOG("not found but removed %d type:0x%x\n",
			  removed, task->tlv_type);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_rd_comp_handler						     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_rd_comp_handler(
		struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task)
{
	union xio_transport_event_data	event_data;

	rdma_hndl->rdma_in_flight--;
	rdma_hndl->sqe_avail++;
	list_move_tail(&task->tasks_list_entry, &rdma_hndl->io_list);

	xio_xmit_rdma_rd(rdma_hndl);

	/* fill notification event */
	event_data.msg.op		= XIO_WC_OP_RECV;
	event_data.msg.task		= task;

	xio_rdma_notify_observer(rdma_hndl,
				 XIO_TRANSPORT_NEW_MESSAGE, &event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_wr_comp_handler						     */
/*---------------------------------------------------------------------------*/
static inline void xio_rdma_wr_comp_handler(
		struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task)
{
}

/*---------------------------------------------------------------------------*/
/* xio_handle_wc							     */
/*---------------------------------------------------------------------------*/
static inline void xio_handle_wc(struct ibv_wc *wc, int has_more)
{
	struct xio_task			*task = ptr_from_int64(wc->wr_id);
	struct xio_rdma_task		*rdma_task = task->dd_data;
	struct xio_rdma_transport	*rdma_hndl = rdma_task->rdma_hndl;

	TRACE_LOG("received opcode :%s [%x]\n",
		  ibv_wc_opcode_str(wc->opcode), wc->opcode);

	switch (wc->opcode) {
	case IBV_WC_RECV:
		xio_rdma_rx_handler(rdma_hndl, task, has_more);
		break;
	case IBV_WC_SEND:
		xio_rdma_tx_comp_handler(rdma_hndl, task);
		break;
	case IBV_WC_RDMA_READ:
		xio_rdma_rd_comp_handler(rdma_hndl, task);
		break;
	case IBV_WC_RDMA_WRITE:
		xio_rdma_wr_comp_handler(rdma_hndl, task);
		break;
	default:
		ERROR_LOG("unknown opcode :%s [%x]\n",
			  ibv_wc_opcode_str(wc->opcode), wc->opcode);
		break;
	}
}



/*---------------------------------------------------------------------------*/
/* xio_cq_event_handler							     */
/*---------------------------------------------------------------------------*/
static int xio_cq_event_handler(struct xio_cq *tcq, int timeout_us)
{
	int				retval;
	int				i;
	int				num_delayed_arm = 0;
	cycles_t			timeout = timeout_us*g_mhz;
	cycles_t			start_time;
	int				req_notify = 0;
	int				last_recv = -1;


retry:
	while (1) {
		retval = ibv_poll_cq(tcq->cq, tcq->wc_array_len, tcq->wc_array);
		if (likely(retval > 0)) {
			num_delayed_arm = 0;
			req_notify = 0;
			for (i = retval; i > 0; i--) {
				if (tcq->wc_array[i-1].opcode == IBV_WC_RECV) {
					last_recv = i-1;
					break;
				}
			}
			for (i = 0; i < retval; i++) {
				if (tcq->wc_array[i].status == IBV_WC_SUCCESS)
					xio_handle_wc(&tcq->wc_array[i],
						      (i != last_recv));
				else
					xio_handle_wc_error(
							&tcq->wc_array[i]);
			}
		} else if (retval == 0) {
			if (timeout_us == 0)
				break;
			/* wait timeout before going out */
			if (num_delayed_arm == 0) {
				start_time = get_cycles();
			} else {
				if (get_cycles() - start_time > timeout)
					break;
			}
			num_delayed_arm++;
		} else {
			ERROR_LOG("ibv_poll_cq failed. (errno=%d %m)\n", errno);
			break;
		}
	}

	if (req_notify == 0) {
		retval = ibv_req_notify_cq(tcq->cq, 0);
		if (unlikely(retval))
			ERROR_LOG("ibv_req_notify_cq failed. (errno=%d %m)\n",
				  errno);
		req_notify = 1;
		goto retry;
	}

	return 0;
}



/*---------------------------------------------------------------------------*/
/* xio_rdma_poll							     */
/*---------------------------------------------------------------------------*/
int xio_rdma_poll(struct xio_transport_base *transport,
			 struct timespec *ts_timeout)
{
	int			retval;
	int			i;
	struct xio_rdma_transport *rdma_hndl;
	struct xio_cq		*tcq;
	int			last_recv = -1;
	int			nr = 8;
	int			nr_comp = 0;
	cycles_t		timeout;
	cycles_t		start_time;

	rdma_hndl  = (struct xio_rdma_transport *)transport;
	tcq = rdma_hndl->tcq;

	if (ts_timeout == NULL) {
		xio_set_error(EINVAL);
		return -1;
	}

	timeout = timespec_to_usecs(ts_timeout)*g_mhz;
	if (timeout == 0)
		return 0;

	start_time = get_cycles();

	while (1) {
		retval = ibv_poll_cq(tcq->cq, nr, tcq->wc_array);
		if (likely(retval > 0)) {
			for (i = retval; i > 0; i--) {
				if (tcq->wc_array[i-1].opcode == IBV_WC_RECV) {
					last_recv = i-1;
					break;
				}
			}
			for (i = 0; i < retval; i++) {
				if (rdma_hndl->tcq->wc_array[i].status ==
				    IBV_WC_SUCCESS)
					xio_handle_wc(&tcq->wc_array[i],
						      (i != last_recv));
				else
					xio_handle_wc_error(&tcq->wc_array[i]);
			}
			nr_comp += retval;
			if ((get_cycles() - start_time) >= timeout)
				break;
		} else if (retval == 0) {
			if ((get_cycles() - start_time) >= timeout)
				break;
		} else {
			ERROR_LOG("ibv_poll_cq failed. (errno=%d %m)\n", errno);
			xio_set_error(errno);
			return -1;
		}
	}

	retval = ibv_req_notify_cq(tcq->cq, 0);
	if (unlikely(retval)) {
		errno = retval;
		xio_set_error(errno);
		ERROR_LOG("ibv_req_notify_cq failed. (errno=%d %m)\n",
			  errno);
		return -1;
	}

	return nr_comp;
}

/*---------------------------------------------------------------------------*/
/* xio_data_ev_handler							     */
/*---------------------------------------------------------------------------*/
void xio_data_ev_handler(int fd, int events, void *user_context)
{
	void				*cq_context;
	struct ibv_cq			*cq;
	struct xio_cq			*tcq = user_context;
	struct xio_rdma_transport	*rdma_hndl;
	int				retval;

	retval = ibv_get_cq_event(tcq->channel, &cq, &cq_context);
	if (unlikely(retval != 0)) {
		ERROR_LOG("ibv_get_cq_event failed. (retval=%d %m)\n", errno);
		retval = ibv_req_notify_cq(cq, 0);
		if (retval != 0)
			ERROR_LOG("ibv_req_notify_cq failed. (errno=%d %m)\n",
				  errno);
		return;
	}

	/* accumulate number of cq events that need to
	 * be acked, and periodically ack them
	 */
	if (++tcq->cq_events_that_need_ack == UINT_MAX) {
		ibv_ack_cq_events(tcq->cq, UINT_MAX);
		tcq->cq_events_that_need_ack = 0;
	}

	xio_cq_event_handler(tcq, tcq->ctx->polling_timeout);

	list_for_each_entry(rdma_hndl, &tcq->trans_list, trans_list_entry) {
		xio_rdma_idle_handler(rdma_hndl);
	}

	return;
}

/*---------------------------------------------------------------------------*/
/* xio_prep_rdma_rd_send_req						     */
/*---------------------------------------------------------------------------*/
static void xio_prep_rdma_rd_send_req(
		struct xio_task *task,
		struct xio_rdma_transport *rdma_hndl,
		int signaled)
{
	struct xio_rdma_task	*rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	struct ibv_mr		*mr;
	struct xio_work_req	*rdmad = &rdma_task->rdmad;
	int			i;

	rdma_task->ib_op = XIO_IB_RDMA_READ;

	for (i = 0; i < task->imsg.in.data_iovlen; i++) {
		rdmad->sge[i].addr		=
			uint64_from_ptr(task->imsg.in.data_iov[i].iov_base);
		rdmad->sge[i].length	= task->imsg.in.data_iov[i].iov_len;

		mr = xio_rdma_mr_lookup(task->imsg.in.data_iov[i].mr,
					rdma_hndl->tcq->dev);
		rdmad->sge[i].lkey	= mr->lkey;
	}
	rdmad->send_wr.num_sge		= task->imsg.in.data_iovlen;
	rdmad->send_wr.wr_id		= uint64_from_ptr(task);
	rdmad->send_wr.next		= NULL;
	rdmad->send_wr.opcode		= IBV_WR_RDMA_READ;
	rdmad->send_wr.send_flags	= (signaled ? IBV_SEND_SIGNALED : 0);

	rdmad->send_wr.wr.rdma.remote_addr = rdma_task->req_write_sge[0].addr;
	rdmad->send_wr.wr.rdma.rkey	   = rdma_task->req_write_sge[0].stag;
}

/*---------------------------------------------------------------------------*/
/* xio_prep_rdma_wr_send_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_prep_rdma_wr_send_rsp(
		struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task)
{
	struct xio_rdma_task	*rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	struct ibv_mr		*mr;
	struct xio_work_req	*rdmad = &rdma_task->rdmad;
	int			i, retval = 0;

	/* user provided mr */
	if (task->omsg->out.data_iov[0].mr) {
		for (i = 0; i < task->omsg->out.data_iovlen; i++) {
			rdmad->sge[i].addr =
			uint64_from_ptr(task->omsg->out.data_iov[i].iov_base);
			rdmad->sge[i].length =
				task->omsg->out.data_iov[i].iov_len;
			mr = xio_rdma_mr_lookup(task->omsg->out.data_iov[i].mr,
					rdma_hndl->tcq->dev);
			rdmad->sge[i].lkey		= mr->lkey;
		}
		rdmad->send_wr.num_sge		= i;
	} else {
		if (rdma_hndl->rdma_mempool == NULL) {
			xio_set_error(XIO_E_NO_BUFS);
			ERROR_LOG(
					"message /read/write failed - " \
					"library's memory pool disabled\n");
			goto cleanup;
		}
		/* user did not provide mr - take buffers from pool
		 * and do copy */
		for (i = 0; i < task->omsg->out.data_iovlen; i++) {
			retval = xio_rdma_mempool_alloc(
					rdma_hndl->rdma_mempool,
					task->omsg->out.data_iov[i].iov_len,
					&rdma_task->write_sge[i]);
			if (retval) {
				rdma_task->write_num_sge = i;
				xio_set_error(ENOMEM);
				ERROR_LOG("mempool is empty for %zd bytes\n",
					  task->omsg->out.data_iov[i].iov_len);
				goto cleanup;
			}

			rdma_task->write_sge[i].length =
				task->omsg->out.data_iov[i].iov_len;

			mr = xio_rdma_mr_lookup(rdma_task->write_sge[i].mr,
						rdma_hndl->tcq->dev);

			/* copy the data to the buffer */
			memcpy(rdma_task->write_sge[i].addr,
			       task->omsg->out.data_iov[i].iov_base,
			       task->omsg->out.data_iov[i].iov_len);

			rdmad->sge[i].addr =
				uint64_from_ptr(rdma_task->write_sge[i].addr);
			rdmad->sge[i].length = rdma_task->write_sge[i].length;
			rdmad->sge[i].lkey = mr->lkey;
		}
		rdmad->send_wr.num_sge	= i;
		rdma_task->write_num_sge = i;
	}

	rdmad->send_wr.wr_id		   = uint64_from_ptr(task);
	rdmad->send_wr.opcode		   = IBV_WR_RDMA_WRITE;
	rdmad->send_wr.wr.rdma.remote_addr = rdma_task->req_read_sge[0].addr;
	rdmad->send_wr.wr.rdma.rkey	   = rdma_task->req_read_sge[0].stag;

	return 0;

cleanup:
	for (i = 0; i < rdma_task->write_num_sge; i++)
		xio_rdma_mempool_free(&rdma_task->write_sge[i]);

	rdma_task->write_num_sge = 0;
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_req_header						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_write_req_header(struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task, struct xio_req_hdr *req_hdr)
{
	struct xio_req_hdr		*tmp_req_hdr;
	static struct xio_req_hdr	zero_req_hdr;
	static int			first_time = 1;

	/* point to trasport header */
	xio_mbuf_set_trans_hdr(&task->mbuf);
	tmp_req_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	if (first_time) {
		memset(&zero_req_hdr, 0, sizeof(zero_req_hdr));
		first_time = 0;
	}
	*tmp_req_hdr = zero_req_hdr;

	/* pack relevant values */
	PACK_SVAL(req_hdr, tmp_req_hdr, req_hdr_len);
	PACK_SVAL(req_hdr, tmp_req_hdr, tid);
	tmp_req_hdr->opcode = req_hdr->opcode;
	tmp_req_hdr->flags  = req_hdr->flags;
	PACK_SVAL(req_hdr, tmp_req_hdr, ulp_hdr_len);
	PACK_SVAL(req_hdr, tmp_req_hdr, ulp_pad_len);
	PACK_LLVAL(req_hdr, tmp_req_hdr, ulp_imm_len);
	PACK_LLVAL(req_hdr, tmp_req_hdr, read_va);
	PACK_LVAL(req_hdr, tmp_req_hdr, read_stag);
	PACK_LVAL(req_hdr, tmp_req_hdr, read_len);
	PACK_LLVAL(req_hdr, tmp_req_hdr, write_va);
	PACK_LVAL(req_hdr, tmp_req_hdr, write_stag);
	PACK_LVAL(req_hdr, tmp_req_hdr, write_len);

#ifdef EYAL_TODO
	print_hex_dump_bytes("post_send: ", DUMP_PREFIX_ADDRESS,
			     task->mbuf.curr,
			     64);
#endif
	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_req_hdr));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_read_req_header						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_read_req_header(struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task,
		struct xio_req_hdr *req_hdr)
{
	static struct xio_req_hdr	zero_req_hdr;
	struct xio_req_hdr		*tmp_req_hdr;
	static int			first_time = 1;
	struct xio_rdma_task	*rdma_task =
		(struct xio_rdma_task *)task->dd_data;


	/* point to trasport header */
	xio_mbuf_set_trans_hdr(&task->mbuf);
	tmp_req_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	if (first_time) {
		memset(&zero_req_hdr, 0, sizeof(zero_req_hdr));
		first_time = 0;
	}
	*req_hdr = zero_req_hdr;

	UNPACK_SVAL(tmp_req_hdr, req_hdr, req_hdr_len);

	if (req_hdr->req_hdr_len != sizeof(struct xio_req_hdr)) {
		ERROR_LOG(
		"header length's read failed. arrived:%d  expected:%zd\n",
		req_hdr->req_hdr_len, sizeof(struct xio_req_hdr));
		return -1;
	}
	UNPACK_SVAL(tmp_req_hdr, req_hdr, sn);
	UNPACK_SVAL(tmp_req_hdr, req_hdr, credits);
	UNPACK_SVAL(tmp_req_hdr, req_hdr, tid);
	req_hdr->opcode = tmp_req_hdr->opcode;
	UNPACK_SVAL(tmp_req_hdr, req_hdr, ulp_hdr_len);
	UNPACK_SVAL(tmp_req_hdr, req_hdr, ulp_pad_len);
	UNPACK_LLVAL(tmp_req_hdr, req_hdr, ulp_imm_len);
	UNPACK_LLVAL(tmp_req_hdr, req_hdr, read_va);
	UNPACK_LVAL(tmp_req_hdr, req_hdr, read_stag);
	UNPACK_LVAL(tmp_req_hdr, req_hdr, read_len);
	UNPACK_LLVAL(tmp_req_hdr, req_hdr, write_va);
	UNPACK_LVAL(tmp_req_hdr, req_hdr, write_stag);
	UNPACK_LVAL(tmp_req_hdr, req_hdr, write_len);

	/* params for RDMA_WRITE */
	if (req_hdr->read_va && req_hdr->read_len && req_hdr->read_stag) {
		rdma_task->req_read_sge[0].addr	= req_hdr->read_va;
		rdma_task->req_read_sge[0].length = req_hdr->read_len;
		rdma_task->req_read_sge[0].stag	= req_hdr->read_stag;
		rdma_task->req_read_num_sge	= 1;
	} else {
		rdma_task->req_read_num_sge	= 0;
	}

	/* params for RDMA_READ */
	if (req_hdr->write_va && req_hdr->write_len && req_hdr->write_stag) {
		rdma_task->req_write_sge[0].addr = req_hdr->write_va;
		rdma_task->req_write_sge[0].length = req_hdr->write_len;
		rdma_task->req_write_sge[0].stag = req_hdr->write_stag;
		rdma_task->req_write_num_sge	= 1;
	} else {
		rdma_task->req_write_num_sge	= 0;
	}

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_req_hdr));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_rsp_header						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_write_rsp_header(struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task, struct xio_rsp_hdr *rsp_hdr)
{
	struct xio_rsp_hdr		*tmp_rsp_hdr;
	static struct xio_rsp_hdr	zero_rsp_hdr;
	static int			first_time = 1;

	/* point to trasport header */
	xio_mbuf_set_trans_hdr(&task->mbuf);
	tmp_rsp_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	if (first_time) {
		memset(&zero_rsp_hdr, 0, sizeof(zero_rsp_hdr));
		first_time = 0;
	}
	*tmp_rsp_hdr = zero_rsp_hdr;

	/* pack relevant values */
	PACK_SVAL(rsp_hdr, tmp_rsp_hdr, rsp_hdr_len);
	PACK_SVAL(rsp_hdr, tmp_rsp_hdr, tid);
	tmp_rsp_hdr->opcode = rsp_hdr->opcode;
	PACK_SVAL(rsp_hdr, tmp_rsp_hdr, ulp_hdr_len);
	PACK_SVAL(rsp_hdr, tmp_rsp_hdr, ulp_pad_len);
	PACK_LLVAL(rsp_hdr, tmp_rsp_hdr, ulp_imm_len);
	PACK_LVAL(rsp_hdr, tmp_rsp_hdr, status);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_rsp_hdr));
#ifdef EYAL_TODO
	print_hex_dump_bytes("post_send: ", DUMP_PREFIX_ADDRESS,
			     task->mbuf.tlv.head, 64);
#endif
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_read_rsp_header						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_read_rsp_header(struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task, struct xio_rsp_hdr *rsp_hdr)
{
	static struct xio_rsp_hdr	zero_rsp_hdr;
	struct xio_rsp_hdr		*tmp_rsp_hdr;
	static int			first_time = 1;

	/* point to trasport header */
	xio_mbuf_set_trans_hdr(&task->mbuf);
	tmp_rsp_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	if (first_time) {
		memset(&zero_rsp_hdr, 0, sizeof(zero_rsp_hdr));
		first_time = 0;
	}
	*rsp_hdr = zero_rsp_hdr;


	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, rsp_hdr_len);

	if (rsp_hdr->rsp_hdr_len != sizeof(struct xio_rsp_hdr)) {
		ERROR_LOG(
		"header length's read failed. arrived:%d expected:%zd\n",
		  rsp_hdr->rsp_hdr_len, sizeof(struct xio_rsp_hdr));
		return -1;
	}

	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, sn);
	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, credits);
	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, tid);
	rsp_hdr->opcode = tmp_rsp_hdr->opcode;
	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, ulp_hdr_len);
	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, ulp_pad_len);
	UNPACK_LLVAL(tmp_rsp_hdr, rsp_hdr, ulp_imm_len);
	UNPACK_LVAL(tmp_rsp_hdr, rsp_hdr, status);

	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_rsp_hdr));

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_header						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_write_header(
		struct xio_rdma_transport *rdma_hndl,
		struct xio_task	*task, uint16_t ulp_hdr_len,
		uint16_t ulp_pad_len, uint64_t ulp_imm_len,
		uint32_t status)
{
	struct xio_rdma_task	*rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	struct ibv_mr		*mr;

	struct xio_req_hdr	req_hdr;
	struct xio_rsp_hdr	rsp_hdr;

	/* write the headers */
	if (IS_REQUEST(task->tlv_type)) {
		/* fill request header */
		req_hdr.req_hdr_len	= sizeof(req_hdr);
		req_hdr.tid		= task->ltid;
		req_hdr.opcode		= rdma_task->ib_op;
		req_hdr.flags		= 0;
		req_hdr.ulp_hdr_len	= ulp_hdr_len;
		req_hdr.ulp_pad_len	= ulp_pad_len;
		req_hdr.ulp_imm_len	= ulp_imm_len;

		if (rdma_task->read_num_sge > 0) {
			req_hdr.read_va		=
				uint64_from_ptr(rdma_task->read_sge[0].addr);

			if (rdma_task->read_sge[0].mr) {
				mr = xio_rdma_mr_lookup(
						rdma_task->read_sge[0].mr,
						rdma_hndl->tcq->dev);
				if (!mr)
					goto cleanup;

				req_hdr.read_stag	= mr->rkey;
			} else  {
				req_hdr.read_stag	= 0;
			}
			req_hdr.read_len	= rdma_task->read_sge[0].length;
		} else {
			req_hdr.read_va		= 0;
			req_hdr.read_len	= 0;
			req_hdr.read_stag	= 0;
		}
		if (rdma_task->write_num_sge > 0) {
			req_hdr.write_va	=
				uint64_from_ptr(rdma_task->write_sge[0].addr);

			if (rdma_task->write_sge[0].mr) {
				mr = xio_rdma_mr_lookup(
						rdma_task->write_sge[0].mr,
						rdma_hndl->tcq->dev);
				if (!mr)
					goto cleanup;
				req_hdr.write_stag	= mr->rkey;
			} else {
				req_hdr.write_stag	= 0;
			}
			req_hdr.write_len = rdma_task->write_sge[0].length;
		} else {
			req_hdr.write_va   = 0;
			req_hdr.write_len  = 0;
			req_hdr.write_stag = 0;
		}

		if (xio_rdma_write_req_header(rdma_hndl, task, &req_hdr) != 0)
			goto cleanup;
	} else if (IS_RESPONSE(task->tlv_type)) {
		/* fill response header */
		rsp_hdr.rsp_hdr_len	= sizeof(rsp_hdr);
		rsp_hdr.tid		= task->rtid;
		rsp_hdr.opcode		= rdma_task->ib_op;
		rsp_hdr.flags		= 0;
		rsp_hdr.ulp_hdr_len	= ulp_hdr_len;
		rsp_hdr.ulp_pad_len	= ulp_pad_len;
		rsp_hdr.ulp_imm_len	= ulp_imm_len;
		rsp_hdr.status		= status;
		if (xio_rdma_write_rsp_header(rdma_hndl, task, &rsp_hdr) != 0)
			goto cleanup;
	} else {
		ERROR_LOG("unknown message type\n");
	}

	/* write the payload header */
	if (ulp_hdr_len) {
		if (xio_mbuf_write_array(
		    &task->mbuf,
		    task->omsg->out.header.iov_base,
		    task->omsg->out.header.iov_len) != 0)
			goto cleanup;
	}

	/* write the pad between header and data */
	if (ulp_pad_len)
		xio_mbuf_inc(&task->mbuf, ulp_pad_len);

	return 0;

cleanup:
	xio_set_error(XIO_E_MSG_SIZE);
	ERROR_LOG("xio_rdma_send_msg failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_send_data						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_write_send_data(
		struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task)
{
	struct xio_rdma_task	*rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	size_t			i;
	struct ibv_mr		*mr;

	/* user provided mr */
	if (task->omsg->out.data_iov[0].mr) {
		struct ibv_sge	*sge = &rdma_task->txd.sge[1];
		struct xio_iovec_ex *iov =
			&task->omsg->out.data_iov[0];
		for (i = 0; i < task->omsg->out.data_iovlen; i++)  {
			if (iov->mr == NULL) {
				ERROR_LOG("failed to find mr on iov\n");
				goto cleanup;
			}

			/* get the crresopnding key of the
			 * outgoing adapter */
			mr = xio_rdma_mr_lookup(iov->mr,
					rdma_hndl->tcq->dev);
			if (mr == NULL) {
				ERROR_LOG("failed to find memory " \
						"handle\n");
				goto cleanup;
			}
			/* copy the iovec */
			/* send it on registered memory */
			sge->addr    = uint64_from_ptr(iov->iov_base);
			sge->length  = (uint32_t)iov->iov_len;
			sge->lkey    = mr->lkey;
			iov++;
			sge++;
		}
		rdma_task->txd.send_wr.num_sge =
			task->omsg->out.data_iovlen + 1;
	} else {
		/* copy to internal buffer */
		for (i = 0; i < task->omsg->out.data_iovlen; i++) {
			/* copy the data into internal buffer */
			if (xio_mbuf_write_array(
				&task->mbuf,
				task->omsg->out.data_iov[i].iov_base,
				task->omsg->out.data_iov[i].iov_len) != 0)
				goto cleanup;
		}
		rdma_task->txd.send_wr.num_sge = 1;
	}

	return 0;

cleanup:
	xio_set_error(XIO_E_MSG_SIZE);
	ERROR_LOG("xio_rdma_send_msg failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_task_put							     */
/*---------------------------------------------------------------------------*/
int xio_rdma_task_put(
		struct xio_transport_base *trans_hndl,
		struct xio_task *task)
{
	struct xio_rdma_task	*rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	int	i;

	/* recycle RDMA  buffers back to pool */

	/* put buffers back to pool */
	for (i = 0; i < rdma_task->read_num_sge; i++) {
		if (rdma_task->read_sge[i].cache) {
			xio_rdma_mempool_free(&rdma_task->read_sge[i]);
			rdma_task->read_sge[i].cache = NULL;
		}
	}
	rdma_task->read_num_sge = 0;

	for (i = 0; i < rdma_task->write_num_sge; i++) {
		if (rdma_task->write_sge[i].cache) {
			xio_rdma_mempool_free(&rdma_task->write_sge[i]);
			rdma_task->write_sge[i].cache = NULL;
		}
	}
	rdma_task->write_num_sge = 0;

	rdma_task->txd.send_wr.num_sge = 1;
	rdma_task->ib_op = XIO_IB_NULL;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_prep_req_out_data						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_prep_req_out_data(
		struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task)
{
	struct xio_rdma_task	*rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	struct xio_vmsg		*vmsg = &task->omsg->out;
	uint64_t		xio_hdr_len;
	uint64_t		ulp_out_hdr_len;
	uint64_t		ulp_pad_len = 0;
	uint64_t		ulp_out_imm_len;
	size_t			retval;
	int			i;
	int			data_alignment = DEF_DATA_ALIGNMENT;

	/* check for multiple iovecs for RDMA */
	if (vmsg->data_iovlen > 1) {
		ERROR_LOG("iovec with len > 1 is not supported\n");
		return -1;
	}

	/* calculate headers */
	ulp_out_hdr_len	= vmsg->header.iov_len;
	ulp_out_imm_len	= xio_iovex_length(vmsg->data_iov,
					   vmsg->data_iovlen);

	xio_hdr_len = xio_mbuf_get_curr_offset(&task->mbuf);
	xio_hdr_len += sizeof(struct xio_req_hdr);

	if (rdma_hndl->max_send_buf_sz	 < (xio_hdr_len + ulp_out_hdr_len)) {
		ERROR_LOG("header size %zd exceeds the max header allowed %d\n",
			  ulp_out_imm_len, rdma_hndl->max_send_buf_sz);
		return -1;
	}

	/* the data is outgoing via SEND */
	if ((ulp_out_hdr_len + ulp_out_imm_len +
	    OMX_MAX_HDR_SZ) < rdma_hndl->max_send_buf_sz) {
		if (data_alignment && ulp_out_imm_len) {
			uint16_t hdr_len = xio_hdr_len + ulp_out_hdr_len;
			ulp_pad_len = ALIGN(hdr_len, data_alignment) - hdr_len;
		}
		rdma_task->ib_op = XIO_IB_SEND;
		/* user has small request - no rdma operation expected */
		rdma_task->write_num_sge = 0;

		/* write xio header to the buffer */
		retval = xio_rdma_write_header(
				rdma_hndl, task,
				ulp_out_hdr_len, ulp_pad_len, ulp_out_imm_len,
				XIO_E_SUCCESS);
		if (retval)
			return -1;

		/* if there is data, set it to buffer or directly to the sge */
		if (ulp_out_imm_len) {
			retval = xio_rdma_write_send_data(rdma_hndl, task);
			if (retval)
				return -1;
		}
	} else {
		/* the data is outgoing via SEND but the peer will do
		 * RDMA_READ */

		rdma_task->ib_op = XIO_IB_RDMA_READ;
		/* user provided mr */
		if (task->omsg->out.data_iov[0].mr) {
			for (i = 0; i < vmsg->data_iovlen; i++) {
				rdma_task->write_sge[i].addr =
					vmsg->data_iov[i].iov_base;
				rdma_task->write_sge[i].cache = NULL;
				rdma_task->write_sge[i].mr =
					task->omsg->out.data_iov[i].mr;

				rdma_task->write_sge[i].length =
					vmsg->data_iov[i].iov_len;
			}
		} else {
			if (rdma_hndl->rdma_mempool == NULL) {
				xio_set_error(XIO_E_NO_BUFS);
				ERROR_LOG(
					"message /read/write failed - " \
					"library's memory pool disabled\n");
				goto cleanup;
			}

			/* user did not provide mr - take buffers from pool
			 * and do copy */
			for (i = 0; i < vmsg->data_iovlen; i++) {
				retval = xio_rdma_mempool_alloc(
						rdma_hndl->rdma_mempool,
						vmsg->data_iov[i].iov_len,
						&rdma_task->write_sge[i]);
				if (retval) {
					rdma_task->write_num_sge = i;
					xio_set_error(ENOMEM);
					ERROR_LOG(
					"mempool is empty for %zd bytes\n",
					vmsg->data_iov[i].iov_len);
					goto cleanup;
				}

				rdma_task->write_sge[i].length =
					vmsg->data_iov[i].iov_len;

				/* copy the data to the buffer */
				memcpy(rdma_task->write_sge[i].addr,
				       vmsg->data_iov[i].iov_base,
				       vmsg->data_iov[i].iov_len);
			}
		}
		rdma_task->write_num_sge = vmsg->data_iovlen;

		/* write xio header to the buffer */
		retval = xio_rdma_write_header(
				rdma_hndl, task,
				ulp_out_hdr_len, 0, 0, XIO_E_SUCCESS);

		if (retval) {
			ERROR_LOG("Failed to write header\n");
			goto cleanup;
		}
	}

	return 0;

cleanup:
	for (i = 0; i < rdma_task->write_num_sge; i++)
		xio_rdma_mempool_free(&rdma_task->write_sge[i]);

	rdma_task->write_num_sge = 0;

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_prep_req_in_data						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_prep_req_in_data(
		struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task)
{
	struct xio_rdma_task		*rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	size_t				hdr_len;
	size_t				data_len;
	struct xio_vmsg			*vmsg = &task->omsg->in;
	int				i, retval;


	/* check for multiple iovecs for RDMA */
	if (vmsg->data_iovlen > 1) {
		ERROR_LOG("iovec with len > 1 is not supported\n");
		return -1;
	}

	data_len  = xio_iovex_length(vmsg->data_iov, vmsg->data_iovlen);
	hdr_len  = vmsg->header.iov_len;

	if (data_len + hdr_len + OMX_MAX_HDR_SZ < rdma_hndl->max_send_buf_sz) {
		/* user has small response - no rdma operation expected */
		rdma_task->read_num_sge = 0;
	} else  {
		/* user provided buffers with length for RDMA WRITE */
		/* user provided mr */
		if (vmsg->data_iov[0].mr)  {
			for (i = 0; i < vmsg->data_iovlen; i++) {
				rdma_task->read_sge[i].addr =
					vmsg->data_iov[i].iov_base;
				rdma_task->read_sge[i].cache = NULL;
				rdma_task->read_sge[i].mr =
					vmsg->data_iov[i].mr;

				rdma_task->read_sge[i].length =
					vmsg->data_iov[i].iov_len;
			}
		} else  {
			if (rdma_hndl->rdma_mempool == NULL) {
				xio_set_error(XIO_E_NO_BUFS);
				ERROR_LOG(
					"message /read/write failed - " \
					"library's memory pool disabled\n");
				goto cleanup;
			}

			/* user did not provide mr */
			for (i = 0; i < vmsg->data_iovlen; i++) {
				retval = xio_rdma_mempool_alloc(
						rdma_hndl->rdma_mempool,
						vmsg->data_iov[i].iov_len,
						&rdma_task->read_sge[i]);

				if (retval) {
					rdma_task->read_num_sge = i;
					xio_set_error(ENOMEM);
					ERROR_LOG(
					"mempool is empty for %zd bytes\n",
					vmsg->data_iov[i].iov_len);
					goto cleanup;
				}
				rdma_task->read_sge[i].length =
					vmsg->data_iov[i].iov_len;
			}
		}
		rdma_task->read_num_sge = vmsg->data_iovlen;
	}

	return 0;

cleanup:
	for (i = 0; i < rdma_task->read_num_sge; i++)
		xio_rdma_mempool_free(&rdma_task->read_sge[i]);

	rdma_task->read_num_sge = 0;

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_send_req							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_send_req(struct xio_rdma_transport *rdma_hndl,
	struct xio_task *task)
{
	struct xio_rdma_task	*rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	uint64_t		payload;
	size_t			retval;
	int			i;
	int			must_send = 0;
	size_t			sge_len;


	if (rdma_hndl->reqs_in_flight_nr + rdma_hndl->rsps_in_flight_nr >=
	    rdma_hndl->max_tx_ready_tasks_num) {
		xio_set_error(EAGAIN);
		return -1;
	}

	if (rdma_hndl->reqs_in_flight_nr >=
			rdma_hndl->max_tx_ready_tasks_num - 1) {
		xio_set_error(EAGAIN);
		return -1;
	}
	/* tx ready is full - refuse request */
	if (rdma_hndl->tx_ready_tasks_num >=
			rdma_hndl->max_tx_ready_tasks_num) {
		xio_set_error(EAGAIN);
		return -1;
	}

	/* prepare buffer for RDMA response  */
	retval = xio_rdma_prep_req_in_data(rdma_hndl, task);
	if (retval != 0) {
		ERROR_LOG("rdma_prep_req_in_data failed\n");
		return -1;
	}

	/* prepare the out message  */
	retval = xio_rdma_prep_req_out_data(rdma_hndl, task);
	if (retval != 0) {
		ERROR_LOG("rdma_prep_req_out_data failed\n");
		return -1;
	}

	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* add tlv */
	if (xio_mbuf_write_tlv(&task->mbuf, task->tlv_type, payload) != 0) {
		ERROR_LOG("write tlv failed\n");
		return -1;
	}

	/* set the length */
	rdma_task->txd.sge[0].length = xio_mbuf_get_curr_offset(&task->mbuf);

	/* validate header */
	if (XIO_TLV_LEN + payload != rdma_task->txd.sge[0].length) {
		ERROR_LOG("header validation failed\n");
		return -1;
	}
	xio_task_addref(task);

	/* check for inline */
	rdma_task->txd.send_wr.send_flags = 0;

	sge_len = 0;
	for (i = 0; i < rdma_task->txd.send_wr.num_sge; i++)
		sge_len += rdma_task->txd.sge[i].length;

	if (sge_len < MAX_INLINE_DATA)
		rdma_task->txd.send_wr.send_flags |= IBV_SEND_INLINE;

	if (++rdma_hndl->req_sig_cnt >= HARD_CQ_MOD || task->force_signal) {
		/* avoid race between send completion and response arrival */
		rdma_task->txd.send_wr.send_flags |= IBV_SEND_SIGNALED;
		rdma_hndl->req_sig_cnt = 0;
	}

	rdma_task->ib_op = XIO_IB_SEND;

	list_move_tail(&task->tasks_list_entry, &rdma_hndl->tx_ready_list);

	rdma_hndl->tx_ready_tasks_num++;

	/* transmit only if  available */
	if (task->omsg->more_in_batch == 0) {
		must_send = 1;
	} else {
		if (tx_window_sz(rdma_hndl) >= SEND_TRESHOLD)
			must_send = 1;
	}
	/* resource are now available and rdma rd  requests are pending kick
	 * them
	 */
	if (rdma_hndl->kick_rdma_rd)
		xio_xmit_rdma_rd(rdma_hndl);


	if (must_send)
		xio_rdma_xmit(rdma_hndl);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_send_rsp							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_send_rsp(struct xio_rdma_transport *rdma_hndl,
	struct xio_task *task)
{
	struct xio_rdma_task	*rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	struct xio_rsp_hdr	rsp_hdr;
	uint64_t		payload;
	uint64_t		xio_hdr_len;
	uint64_t		ulp_hdr_len;
	uint64_t		ulp_pad_len = 0;
	uint64_t		ulp_imm_len;
	size_t			retval;
	int			i;
	int			data_alignment = DEF_DATA_ALIGNMENT;
	size_t			sge_len;
	int			must_send = 0;

	if (rdma_hndl->reqs_in_flight_nr + rdma_hndl->rsps_in_flight_nr >=
	    rdma_hndl->max_tx_ready_tasks_num) {
		xio_set_error(EAGAIN);
		return -1;
	}

	if (rdma_hndl->rsps_in_flight_nr >=
			2*rdma_hndl->max_tx_ready_tasks_num - 1) {
		xio_set_error(EAGAIN);
		return -1;
	}
	/* tx ready is full - refuse request */
	if (rdma_hndl->tx_ready_tasks_num >=
			rdma_hndl->max_tx_ready_tasks_num) {
		xio_set_error(EAGAIN);
		return -1;
	}

	/* calculate headers */
	ulp_hdr_len	= task->omsg->out.header.iov_len;
	ulp_imm_len	= xio_iovex_length(task->omsg->out.data_iov,
					   task->omsg->out.data_iovlen);
	xio_hdr_len = xio_mbuf_get_curr_offset(&task->mbuf);
	xio_hdr_len += sizeof(rsp_hdr);

	if (rdma_hndl->max_send_buf_sz	 < (xio_hdr_len + ulp_hdr_len)) {
		ERROR_LOG("header size %zd exceeds the max header allowed %d\n",
			  ulp_imm_len, rdma_hndl->max_send_buf_sz);
		goto cleanup;
	}
	/* the data is outgoing via SEND */
	if ((xio_hdr_len + ulp_hdr_len + data_alignment +
	    ulp_imm_len) < rdma_hndl->max_send_buf_sz) {
		if (data_alignment && ulp_imm_len) {
			uint16_t hdr_len = xio_hdr_len + ulp_hdr_len;
			ulp_pad_len = ALIGN(hdr_len, data_alignment) - hdr_len;
		}
		rdma_task->ib_op = XIO_IB_SEND;
		/* write xio header to the buffer */
		retval = xio_rdma_write_header(
				rdma_hndl, task,
				ulp_hdr_len, ulp_pad_len, ulp_imm_len,
				XIO_E_SUCCESS);
		if (retval)
			goto cleanup;

		/* if there is data, set it to buffer or directly to the sge */
		if (ulp_imm_len) {
			retval = xio_rdma_write_send_data(rdma_hndl, task);
			if (retval)
				goto cleanup;
		} else {
			/* no data at all */
			task->omsg->out.data_iov[0].iov_base	= NULL;
			task->omsg->out.data_iovlen		= 0;
		}
	} else {
		if (rdma_task->req_read_sge[0].addr &&
		    rdma_task->req_read_sge[0].length &&
		    rdma_task->req_read_sge[0].stag) {
			/* the data is sent via RDMA_WRITE */
			rdma_task->ib_op = XIO_IB_RDMA_WRITE;

			/* prepare rdma write */
			xio_prep_rdma_wr_send_rsp(rdma_hndl, task);

			/* and the header is sent via SEND */
			/* write xio header to the buffer */
			retval = xio_rdma_write_header(
					rdma_hndl, task,
					ulp_hdr_len, 0, ulp_imm_len,
					XIO_E_SUCCESS);
		} else {
			ERROR_LOG("partial completion of request due " \
				  "to missing, response buffer\n");

			/* the client did not provide buffer for response */
			retval = xio_rdma_write_header(
					rdma_hndl, task,
					ulp_hdr_len, 0, 0,
					XIO_E_PARTIAL_MSG);
		}
	}

	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* add tlv */
	if (xio_mbuf_write_tlv(&task->mbuf, task->tlv_type, payload) != 0)
		goto cleanup;

	/* set the length */
	rdma_task->txd.sge[0].length = xio_mbuf_get_curr_offset(&task->mbuf);

	/* validate header */
	if (XIO_TLV_LEN + payload != rdma_task->txd.sge[0].length) {
		ERROR_LOG("header validation failed\n");
		goto cleanup;
	}

	rdma_task->txd.send_wr.send_flags = 0;

	/* check for inline */
	if (rdma_task->ib_op == XIO_IB_SEND) {
		sge_len = 0;
		for (i = 0; i < rdma_task->txd.send_wr.num_sge; i++)
			sge_len += rdma_task->txd.sge[i].length;

		if (sge_len < MAX_INLINE_DATA)
			rdma_task->txd.send_wr.send_flags |= IBV_SEND_INLINE;
	}

	if (++rdma_hndl->rsp_sig_cnt >= SOFT_CQ_MOD || task->force_signal) {
		rdma_task->txd.send_wr.send_flags |= IBV_SEND_SIGNALED;
		rdma_hndl->rsp_sig_cnt = 0;
	}

	list_move_tail(&task->tasks_list_entry, &rdma_hndl->tx_ready_list);
	rdma_hndl->tx_ready_tasks_num++;

	/* transmit only if  available */
	if (task->omsg->more_in_batch == 0) {
		must_send = 1;

	} else {
		if (tx_window_sz(rdma_hndl) >= SEND_TRESHOLD)
			must_send = 1;
	}
	/* resource are now available and rdma rd  requests are pending kick
	 * them
	 */
	if (rdma_hndl->kick_rdma_rd)
		xio_xmit_rdma_rd(rdma_hndl);


	if (must_send)
		xio_rdma_xmit(rdma_hndl);

	return retval;

cleanup:
	xio_set_error(XIO_E_MSG_SIZE);
	ERROR_LOG("xio_rdma_send_msg failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_rsp_send_comp						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_rsp_send_comp(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task)
{
	union xio_transport_event_data event_data;

	event_data.msg.op	= XIO_WC_OP_SEND;
	event_data.msg.task	= task;

	xio_rdma_notify_observer(rdma_hndl,
				 XIO_TRANSPORT_SEND_COMPLETION, &event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_req_send_comp						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_req_send_comp(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task)
{
	union xio_transport_event_data event_data;

	event_data.msg.op	= XIO_WC_OP_SEND;
	event_data.msg.task	= task;

	xio_rdma_notify_observer(rdma_hndl,
				 XIO_TRANSPORT_SEND_COMPLETION, &event_data);

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_rdma_on_recv_rsp							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_recv_rsp(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task)
{
	int			retval = 0;
	union xio_transport_event_data event_data;
	struct xio_conn		*conn = rdma_hndl->base.observer;
	struct xio_rsp_hdr	rsp_hdr;
	struct xio_msg		*imsg;
	struct xio_msg		*omsg;
	size_t			datalen;
	void			*ulp_hdr;
	struct xio_rdma_task	*rdma_task = task->dd_data;
	struct xio_rdma_task	*rdma_sender_task = task->dd_data;
	int			i;

	/* read the response header */
	retval = xio_rdma_read_rsp_header(rdma_hndl, task, &rsp_hdr);
	if (retval != 0) {
		xio_set_error(XIO_E_MSG_INVALID);
		goto cleanup;
	}
	/* update receive + send window */
	if (rdma_hndl->exp_sn == rsp_hdr.sn) {
		rdma_hndl->exp_sn++;
		rdma_hndl->ack_sn = rsp_hdr.sn;
		rdma_hndl->peer_credits += rsp_hdr.credits;
	} else {
		ERROR_LOG("ERROR: expected sn:%d, arrived sn:%d\n",
			  rdma_hndl->exp_sn, rsp_hdr.sn);
	}

	task->imsg.more_in_batch = rdma_task->more_in_batch;

	/* find the sender task */
	task->sender_task =
		xio_conn_task_lookup(conn, rsp_hdr.tid);

	rdma_sender_task = task->sender_task->dd_data;

	omsg = task->sender_task->omsg;
	imsg = &task->imsg;

	ulp_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);
	/* msg from received message */
	if (rsp_hdr.ulp_hdr_len) {
		imsg->in.header.iov_base	= ulp_hdr;
		imsg->in.header.iov_len		= rsp_hdr.ulp_hdr_len;
	} else {
		imsg->in.header.iov_base	= NULL;
		imsg->in.header.iov_len		= 0;
	}

	omsg->status = rsp_hdr.status;
	omsg->type =  task->tlv_type;

	/* handle the headers */
	if (omsg->in.header.iov_base) {
		/* copy header to user buffers */
		size_t hdr_len = 0;
		if (imsg->in.header.iov_len > omsg->in.header.iov_len)  {
			hdr_len = imsg->in.header.iov_len;
			omsg->status = XIO_E_MSG_SIZE;
		} else {
			hdr_len = omsg->in.header.iov_len;
			omsg->status = XIO_E_SUCCESS;
		}
		if (hdr_len)
			memcpy(omsg->in.header.iov_base,
			       imsg->in.header.iov_base,
			       hdr_len);

		omsg->in.header.iov_len = hdr_len;
	} else {
		/* no copy - just pointers */
		memclonev(&omsg->in.header, NULL, &imsg->in.header, 1);
	}

	switch (rsp_hdr.opcode) {
	case XIO_IB_SEND:
		/* if data arrived, set the pointers */
		if (rsp_hdr.ulp_imm_len) {
			imsg->in.data_iov[0].iov_base	= ulp_hdr +
				imsg->in.header.iov_len + rsp_hdr.ulp_pad_len;
			imsg->in.data_iov[0].iov_len	= rsp_hdr.ulp_imm_len;
			imsg->in.data_iovlen		= 1;
		} else {
			imsg->in.data_iov[0].iov_base	= NULL;
			imsg->in.data_iov[0].iov_len	= 0;
			imsg->in.data_iovlen		= 0;
		}
		if (omsg->in.data_iovlen) {
			/* deep copy */
			if (imsg->in.data_iovlen) {
				size_t idata_len  = xio_iovex_length(
					imsg->in.data_iov,
					imsg->in.data_iovlen);
				size_t odata_len  = xio_iovex_length(
					omsg->in.data_iov,
					omsg->in.data_iovlen);

				if (idata_len > odata_len) {
					omsg->status = XIO_E_MSG_SIZE;
					goto partial_msg;
				} else {
					omsg->status = XIO_E_SUCCESS;
				}
				if (omsg->in.data_iov[0].iov_base)  {
					/* user porvided buffer so do copy */
					datalen = memcpyv(
					  (struct xio_iovec *)omsg->in.data_iov,
					  omsg->in.data_iovlen, 0,
					  (struct xio_iovec *)imsg->in.data_iov,
					  imsg->in.data_iovlen, 0);

					omsg->in.data_iovlen =
						imsg->in.data_iovlen;
				} else {
					/* use provided only length - set user
					 * pointers */
					memclonev(
					  (struct xio_iovec *)omsg->in.data_iov,
					  (int *)&omsg->in.data_iovlen,
					  (struct xio_iovec *)imsg->in.data_iov,
					  imsg->in.data_iovlen);
				}
			} else {
				omsg->in.data_iovlen = imsg->in.data_iovlen;
			}
		} else {
			memclonev((struct xio_iovec *)omsg->in.data_iov,
				  (int *)&omsg->in.data_iovlen,
				  (struct xio_iovec *)imsg->in.data_iov,
				  imsg->in.data_iovlen);
		}
		break;
	case XIO_IB_RDMA_WRITE:
		imsg->in.data_iov[0].iov_base	=
			ptr_from_int64(rdma_sender_task->read_sge[0].addr);
		imsg->in.data_iov[0].iov_len	= rsp_hdr.ulp_imm_len;
		imsg->in.data_iovlen		= 1;

		/* user provided mr */
		if (omsg->in.data_iov[0].mr)  {
			/* data was copied directly to user buffer */
			/* need to update the buffer length */
			omsg->in.data_iov[0].iov_len =
				imsg->in.data_iov[0].iov_len;
		} else  {
			/* user provided buffer but not mr */
			/* deep copy */

			if (omsg->in.data_iov[0].iov_base)  {
				datalen = memcpyv(
					(struct xio_iovec *)omsg->in.data_iov,
					omsg->in.data_iovlen, 0,
					(struct xio_iovec *)imsg->in.data_iov,
					imsg->in.data_iovlen, 0);
				omsg->in.data_iovlen = imsg->in.data_iovlen;

				/* put buffers back to pool */
				for (i = 0; i < rdma_sender_task->read_num_sge;
						i++) {
					xio_rdma_mempool_free(
						&rdma_sender_task->read_sge[i]);
					rdma_sender_task->read_sge[i].cache = 0;
				}
				rdma_sender_task->read_num_sge = 0;
			} else {
				/* use provided only length - set user
				 * pointers */
				memclonev((struct xio_iovec *)omsg->in.data_iov,
					  (int *)&omsg->in.data_iovlen,
					  (struct xio_iovec *)imsg->in.data_iov,
					  imsg->in.data_iovlen);
			}
		}
		break;
	default:
		ERROR_LOG("unexpected opcode\n");
		break;
	}

partial_msg:
	/* fill notification event */
	event_data.msg.op	= XIO_WC_OP_RECV;
	event_data.msg.task	= task;

	/* notify the upper layer of received message */
	xio_rdma_notify_observer(rdma_hndl,
				 XIO_TRANSPORT_NEW_MESSAGE, &event_data);
	return 0;

cleanup:
	retval = xio_errno();
	ERROR_LOG("xio_rdma_on_recv_rsp failed. (errno=%d %s)\n",
		  retval, xio_strerror(retval));
	xio_rdma_notify_observer_error(rdma_hndl, retval);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_notify_assign_in_buf					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_assign_in_buf(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task, int *is_assigned)
{
	union xio_transport_event_data event_data = {
			.assign_in_buf.task	   = task,
			.assign_in_buf.is_assigned = 0
	};

	xio_rdma_notify_observer(rdma_hndl,
				 XIO_TRANSPORT_ASSIGN_IN_BUF, &event_data);

	*is_assigned = event_data.assign_in_buf.is_assigned;
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_sched_rdma_rd_req						     */
/*---------------------------------------------------------------------------*/
static int xio_sched_rdma_rd_req(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task)
{
	struct xio_rdma_task *rdma_task =
				(struct xio_rdma_task *)task->dd_data;
	int			i, retval;
	int			user_assign_flag = 0;

	/* server side get buffer from pool and do rdma read */

	/* needed buffer to do rdma read. there are two options:	   */
	/* option 1: user provides call back that fills application memory */
	/* option 2: use internal buffer pool				   */

	/* hint the upper layer of sizes */
	for (i = 0;  i < rdma_task->req_write_num_sge; i++) {
		task->imsg.in.data_iov[i].iov_base  = NULL;
		task->imsg.in.data_iov[i].iov_len  =
					rdma_task->req_write_sge[i].length;
	}
	task->imsg.in.data_iovlen = rdma_task->req_write_num_sge;

	xio_rdma_assign_in_buf(rdma_hndl, task, &user_assign_flag);

	if (user_assign_flag) {
		/* if user does not have buffers ignore */
		if (task->imsg.in.data_iovlen == 0) {
			WARN_LOG("application has not provided buffers\n");
			WARN_LOG("rdma read is ignored\n");
			task->imsg.status = XIO_E_PARTIAL_MSG;
			return -1;
		}
		if (task->imsg.in.data_iov[0].mr == NULL) {
			WARN_LOG("application has not provided mr\n");
			WARN_LOG("rdma read is ignored\n");
			task->imsg.status = EINVAL;
			return -1;
		}
		if (rdma_task->req_write_num_sge != task->imsg.in.data_iovlen) {
			WARN_LOG("application provided invalid iovec length\n");
			WARN_LOG("rdma read is ignored\n");
			task->imsg.status = EINVAL;
			return -1;
		}

		for (i = 0;  i < rdma_task->req_write_num_sge; i++) {
			rdma_task->read_sge[i].cache = NULL;
			task->imsg.in.data_iov[i].iov_len  =
				min(task->imsg.in.data_iov[i].iov_len,
				    rdma_task->req_write_sge[i].length);
		}
	} else {
		if (rdma_hndl->rdma_mempool == NULL) {
				xio_set_error(XIO_E_NO_BUFS);
				ERROR_LOG(
					"message /read/write failed - " \
					"library's memory pool disabled\n");
				goto cleanup;
		}

		for (i = 0;  i < rdma_task->req_write_num_sge; i++) {
			retval = xio_rdma_mempool_alloc(
					rdma_hndl->rdma_mempool,
					rdma_task->req_write_sge[i].length,
					&rdma_task->read_sge[i]);

			if (retval) {
				rdma_task->read_num_sge = i;
				ERROR_LOG("mempool is empty for %zd bytes\n",
					  rdma_task->read_sge[i].length);

				task->imsg.status = ENOMEM;
				goto cleanup;
			}
			rdma_task->read_sge[i].length =
				rdma_task->req_write_sge[i].length;

			task->imsg.in.data_iov[i].iov_base =
					rdma_task->read_sge[i].addr;
			task->imsg.in.data_iov[i].iov_len  =
					rdma_task->read_sge[i].length;
			task->imsg.in.data_iov[i].mr =
					rdma_task->read_sge[i].mr;
		}
		task->imsg.in.data_iovlen = rdma_task->req_write_num_sge;
		rdma_task->read_num_sge = rdma_task->req_write_num_sge;
	}

	list_move_tail(&task->tasks_list_entry, &rdma_hndl->rdma_rd_list);
	xio_xmit_rdma_rd(rdma_hndl);

	return 0;
cleanup:
	for (i = 0; i < rdma_task->read_num_sge; i++)
		xio_rdma_mempool_free(&rdma_task->read_sge[i]);

	rdma_task->read_num_sge = 0;
	return -1;
}


/*---------------------------------------------------------------------------*/
/* xio_rdma_on_recv_req							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_recv_req(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task)
{
	int			retval = 0;
	struct xio_rdma_task	*rdma_task =
				(struct xio_rdma_task *)task->dd_data;
	union xio_transport_event_data event_data;
	struct xio_req_hdr	req_hdr;
	struct xio_msg		*imsg;
	void			*ulp_hdr;

	/* read header */
	retval = xio_rdma_read_req_header(rdma_hndl, task, &req_hdr);
	if (retval != 0) {
		xio_set_error(XIO_E_MSG_INVALID);
		goto cleanup;
	}

	if (rdma_hndl->exp_sn == req_hdr.sn) {
		rdma_hndl->exp_sn++;
		rdma_hndl->ack_sn = req_hdr.sn;
		rdma_hndl->peer_credits += req_hdr.credits;
	} else {
		ERROR_LOG("ERROR: sn expected:%d, sn arrived:%d\n",
			  rdma_hndl->exp_sn, req_hdr.sn);
	}

	/* save originator identifier */
	task->rtid		= req_hdr.tid;
	task->imsg.more_in_batch = rdma_task->more_in_batch;

	imsg = &task->imsg;
	ulp_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	imsg->type = task->tlv_type;
	imsg->in.header.iov_len	= req_hdr.ulp_hdr_len;

	if (req_hdr.ulp_hdr_len)
		imsg->in.header.iov_base	= ulp_hdr;
	else
		imsg->in.header.iov_base	= NULL;

	switch (req_hdr.opcode) {
	case XIO_IB_SEND:
		if (req_hdr.ulp_imm_len) {
			/* incoming data via SEND */
			/* if data arrived, set the pointers */
			imsg->in.data_iov[0].iov_len	= req_hdr.ulp_imm_len;
			imsg->in.data_iov[0].iov_base	= ulp_hdr +
				imsg->in.header.iov_len +
				req_hdr.ulp_pad_len;
			imsg->in.data_iovlen		= 1;
		} else {
			/* no data at all */
			imsg->in.data_iov[0].iov_base	= NULL;
			imsg->in.data_iovlen		= 0;
		}
		break;
	case XIO_IB_RDMA_READ:
		/* schedule request for RDMA READ. in case of error
		 * don't schedule the rdma read operation */
		TRACE_LOG("scheduling rdma read\n");
		retval = xio_sched_rdma_rd_req(rdma_hndl, task);
		if (retval == 0)
			return 0;
		break;
	default:
		ERROR_LOG("unexpected opcode\n");
		break;
	};

	/* fill notification event */
	event_data.msg.op	= XIO_WC_OP_RECV;
	event_data.msg.task	= task;

	xio_rdma_notify_observer(rdma_hndl,
				 XIO_TRANSPORT_NEW_MESSAGE, &event_data);

	return 0;

cleanup:
	retval = xio_errno();
	ERROR_LOG("xio_rdma_on_recv_req failed. (errno=%d %s)\n", retval,
		  xio_strerror(retval));
	xio_rdma_notify_observer_error(rdma_hndl, retval);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_setup_msg						     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_write_setup_msg(struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task, struct xio_rdma_setup_msg *msg)
{
	struct xio_rdma_setup_msg	*tmp_msg;

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

	/* jump after connection setup header */
	if (rdma_hndl->base.is_client)
		xio_mbuf_inc(&task->mbuf,
			     sizeof(struct xio_conn_setup_req));
	else
		xio_mbuf_inc(&task->mbuf,
			     sizeof(struct xio_conn_setup_rsp));

	tmp_msg = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* pack relevant values */
	PACK_LLVAL(msg, tmp_msg, buffer_sz);
	PACK_SVAL(msg, tmp_msg, sq_depth);
	PACK_SVAL(msg, tmp_msg, rq_depth);
	PACK_SVAL(msg, tmp_msg, credits);

#ifdef EYAL_TODO
	print_hex_dump_bytes("post_send: ", DUMP_PREFIX_ADDRESS,
			     task->mbuf.tlv.head,
			     64);
#endif
	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_rdma_setup_msg));
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_read_setup_msg						     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_read_setup_msg(struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task, struct xio_rdma_setup_msg *msg)
{
	struct xio_rdma_setup_msg	*tmp_msg;

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

	/* jump after connection setup header */
	if (rdma_hndl->base.is_client)
		xio_mbuf_inc(&task->mbuf,
			     sizeof(struct xio_conn_setup_rsp));
	else
		xio_mbuf_inc(&task->mbuf,
			     sizeof(struct xio_conn_setup_req));

	tmp_msg = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* pack relevant values */
	UNPACK_LLVAL(tmp_msg, msg, buffer_sz);
	UNPACK_SVAL(tmp_msg, msg, sq_depth);
	UNPACK_SVAL(tmp_msg, msg, rq_depth);
	UNPACK_SVAL(tmp_msg, msg, credits);

#ifdef EYAL_TODO
	print_hex_dump_bytes("post_send: ", DUMP_PREFIX_ADDRESS,
			     task->mbuf.curr,
			     64);
#endif
	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_rdma_setup_msg));
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_send_setup_msg						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_send_setup_msg(struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task)
{
	uint16_t payload;
	struct xio_rdma_task	*rdma_task =
		(struct xio_rdma_task *)task->dd_data;

	if (rdma_hndl->base.is_client) {
		struct xio_rdma_setup_msg  req;
		req.buffer_sz		= rdma_hndl->max_send_buf_sz;
		req.sq_depth		= rdma_hndl->sq_depth;
		req.rq_depth		= rdma_hndl->rq_depth;
		req.credits		= 0;
		xio_rdma_write_setup_msg(rdma_hndl, task, &req);
	} else {
		rdma_hndl->sim_peer_credits += rdma_hndl->credits;

		rdma_hndl->setup_rsp.credits = rdma_hndl->credits;
		xio_rdma_write_setup_msg(rdma_hndl,
					 task, &rdma_hndl->setup_rsp);
		rdma_hndl->credits = 0;
	}
	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* add tlv */
	if (xio_mbuf_write_tlv(&task->mbuf, task->tlv_type, payload) != 0)
		return  -1;

	/* set the length */
	rdma_task->txd.sge[0].length = xio_mbuf_data_length(&task->mbuf);
	rdma_task->ib_op	= XIO_IB_SEND;

	if (task->tlv_type == XIO_CONN_SETUP_REQ) {
		rdma_hndl->reqs_in_flight_nr++;
		xio_task_addref(task);
	} else {
		rdma_hndl->rsps_in_flight_nr++;
	}

	list_add_tail(&task->tasks_list_entry, &rdma_hndl->in_flight_list);

	rdma_hndl->peer_credits--;
	xio_post_send(rdma_hndl, &rdma_task->txd, 1);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_setup_msg						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_setup_msg(struct xio_rdma_transport *rdma_hndl,
			    struct xio_task *task)
{
	union xio_transport_event_data event_data;
	struct xio_rdma_setup_msg *rsp  = &rdma_hndl->setup_rsp;

	if (rdma_hndl->base.is_client) {
		struct xio_task *sender_task = list_first_entry(
				&rdma_hndl->in_flight_list,
				struct xio_task,  tasks_list_entry);

		/* remove the task from in_flight_list */
		rdma_hndl->reqs_in_flight_nr--;
		task->sender_task = sender_task;
		xio_rdma_read_setup_msg(rdma_hndl, task, rsp);
		/* get the initial credits */
		rdma_hndl->peer_credits += rsp->credits;
	} else {
		struct xio_rdma_setup_msg req;

		xio_rdma_read_setup_msg(rdma_hndl, task, &req);

		/* current implementation is symatric */
		rsp->buffer_sz	= rdma_hndl->max_send_buf_sz;
		rsp->sq_depth	= min(req.sq_depth, rdma_hndl->rq_depth);
		rsp->rq_depth	= min(req.rq_depth, rdma_hndl->sq_depth);
	}

	/* save the values */
	rdma_hndl->rq_depth		= rsp->rq_depth;
	rdma_hndl->actual_rq_depth	= rdma_hndl->rq_depth + EXTRA_RQE;
	rdma_hndl->sq_depth		= rsp->sq_depth;
	rdma_hndl->membuf_sz		= rsp->buffer_sz;

	/* initialize send window */
	rdma_hndl->sn = 0;
	rdma_hndl->ack_sn = ~0;
	rdma_hndl->credits = 0;
	rdma_hndl->max_sn = rdma_hndl->sq_depth;

	/* initialize receive window */
	rdma_hndl->exp_sn = 0;
	rdma_hndl->max_exp_sn = 0;

	/* now we can calculate  primary pool size */
	xio_rdma_calc_pool_size(rdma_hndl);

	rdma_hndl->state = XIO_STATE_CONNECTED;

	/* fill notification event */
	event_data.msg.op	= XIO_WC_OP_RECV;
	event_data.msg.task	= task;

	xio_rdma_notify_observer(rdma_hndl,
				 XIO_TRANSPORT_NEW_MESSAGE, &event_data);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_nop							     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_write_nop(struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task, struct xio_nop_hdr *nop)
{
	struct  xio_nop_hdr *tmp_nop;
	uint64_t	payload;
	uint64_t	offset;

	xio_mbuf_reset(&task->mbuf);

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return;

	offset = xio_mbuf_get_curr_offset(&task->mbuf);
	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

	payload = xio_mbuf_tlv_payload_len(&task->mbuf);
	offset = xio_mbuf_get_curr_offset(&task->mbuf);

	/* get the pointer */
	tmp_nop = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* pack relevant values */
	PACK_SVAL(nop, tmp_nop, hdr_len);
	PACK_SVAL(nop, tmp_nop, sn);
	PACK_SVAL(nop, tmp_nop, ack_sn);
	PACK_SVAL(nop, tmp_nop, credits);
	tmp_nop->opcode = nop->opcode;
	tmp_nop->flags = nop->flags;

#ifdef EYAL_TODO
	print_hex_dump_bytes("write_nop: ", DUMP_PREFIX_ADDRESS,
			     task->mbuf.tlv.head,
			     64);
#endif
	xio_mbuf_inc(&task->mbuf, sizeof(*nop));
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_send_nop							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_send_nop(struct xio_rdma_transport *rdma_hndl)
{
	uint64_t		payload;
	struct xio_task		*task;
	struct xio_rdma_task	*rdma_task;
	struct  xio_nop_hdr	nop = {
		.hdr_len	= sizeof(nop),
		.sn		= rdma_hndl->sn,
		.ack_sn		= rdma_hndl->ack_sn,
		.credits	= rdma_hndl->credits,
		.opcode		= 0,
		.flags		= 0,
	};

	TRACE_LOG("SEND_NOP\n");

	task = xio_conn_get_primary_task(rdma_hndl->base.observer);
	if (!task) {
		ERROR_LOG("primary task pool is empty\n");
		return -1;
	}

	task->tlv_type	= XIO_CREDIT_NOP;
	rdma_task	= (struct xio_rdma_task *)task->dd_data;

	/* write the message */
	xio_rdma_write_nop(rdma_hndl, task, &nop);
	rdma_hndl->sim_peer_credits += rdma_hndl->credits;
	rdma_hndl->credits = 0;

	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* add tlv */
	if (xio_mbuf_write_tlv(&task->mbuf, task->tlv_type, payload) != 0)
		return  -1;

	/* set the length */
	rdma_task->txd.sge[0].length	= xio_mbuf_data_length(&task->mbuf);
	rdma_task->txd.send_wr.send_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;
	rdma_task->txd.send_wr.next	= NULL;
	rdma_task->ib_op		= XIO_IB_SEND;
	rdma_task->txd.send_wr.num_sge	= 1;

	rdma_hndl->rsps_in_flight_nr++;
	list_add_tail(&task->tasks_list_entry, &rdma_hndl->in_flight_list);

	rdma_hndl->peer_credits--;
	xio_post_send(rdma_hndl, &rdma_task->txd, 1);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_read_nop							     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_read_nop(struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task, struct xio_nop_hdr *nop)
{
	struct  xio_nop_hdr *tmp_nop;

	/* goto to the first tlv */
	xio_mbuf_reset(&task->mbuf);

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

	/* get the pointer */
	tmp_nop = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* pack relevant values */
	UNPACK_SVAL(tmp_nop, nop, hdr_len);
	UNPACK_SVAL(tmp_nop, nop, sn);
	UNPACK_SVAL(tmp_nop, nop, ack_sn);
	UNPACK_SVAL(tmp_nop, nop, credits);
	nop->opcode = tmp_nop->opcode;
	nop->flags = tmp_nop->flags;

#ifdef EYAL_TODO
	print_hex_dump_bytes("post_send: ", DUMP_PREFIX_ADDRESS,
			     task->mbuf.tlv.head,
			     64);
#endif
	xio_mbuf_inc(&task->mbuf, sizeof(*nop));
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_recv_nop							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_recv_nop(struct xio_rdma_transport *rdma_hndl,
				struct xio_task *task)
{
	struct xio_nop_hdr	nop;

	TRACE_LOG("RECV_NOP\n");
	xio_rdma_read_nop(rdma_hndl, task, &nop);

	if (rdma_hndl->exp_sn == nop.sn)
		rdma_hndl->peer_credits += nop.credits;
	else
		ERROR_LOG("ERROR: sn expected:%d, sn arrived:%d\n",
			  rdma_hndl->exp_sn, nop.sn);

	/* the rx task is returend back to pool */
	xio_tasks_pool_put(task);

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_rdma_send							     */
/*---------------------------------------------------------------------------*/
int xio_rdma_send(struct xio_transport_base *transport,
		struct xio_task *task)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	int	retval = -1;

	switch (task->tlv_type) {
	case XIO_CONN_SETUP_REQ:
	case XIO_CONN_SETUP_RSP:
		retval = xio_rdma_send_setup_msg(rdma_hndl, task);
		break;
	default:
		if (IS_REQUEST(task->tlv_type))
			retval = xio_rdma_send_req(rdma_hndl, task);
		else if (IS_RESPONSE(task->tlv_type))
			retval = xio_rdma_send_rsp(rdma_hndl, task);
		else
			ERROR_LOG("unknown message type:0x%x\n",
				  task->tlv_type);
		break;
	}

	return retval;
}
