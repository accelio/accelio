/*
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

#include <linux/types.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include "libxio.h"
#include <xio_os.h>
#include "xio_log.h"
#include "xio_observer.h"
#include "xio_common.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_ktransport.h"
#include "xio_transport.h"
#include "xio_protocol.h"
#include "xio_mem.h"
#include "xio_mempool.h"
#include "xio_rdma_transport.h"
#include "xio_rdma_utils.h"
#include "xio_sg_table.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_context.h"

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
/* forward declarations							     */
/*---------------------------------------------------------------------------*/
static void xio_prep_rdma_wr_send_req(
		struct xio_task *task,
		struct xio_rdma_transport *rdma_hndl,
		struct xio_work_req *next_wr,
		int signaled);
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
static int xio_rdma_on_req_send_comp(struct xio_rdma_transport *rdma_hndl,
				     struct xio_task *task);
static int xio_rdma_on_rsp_send_comp(struct xio_rdma_transport *rdma_hndl,
				     struct xio_task *task);
static int xio_rdma_on_direct_rdma_comp(struct xio_rdma_transport *rdma_hndl,
					struct xio_task *task,
					enum xio_wc_op op);
static int xio_rdma_on_recv_nop(struct xio_rdma_transport *rdma_hndl,
				struct xio_task *task);
static int xio_rdma_send_nop(struct xio_rdma_transport *rdma_hndl);
static int xio_rdma_on_recv_cancel_req(struct xio_rdma_transport *rdma_hndl,
				       struct xio_task *task);
static int xio_rdma_on_recv_cancel_rsp(struct xio_rdma_transport *rdma_hndl,
				       struct xio_task *task);
static int xio_sched_rdma_rd(struct xio_rdma_transport *rdma_hndl,
			     struct xio_task *task);
static int xio_sched_rdma_wr_req(struct xio_rdma_transport *rdma_hndl,
				 struct xio_task *task);
void xio_cq_data_callback_cont(struct ib_cq *cq, void *cq_context);
static int xio_rdma_send_rdma_read_ack(struct xio_rdma_transport *rdma_hndl,
				       int rtid);
static int xio_rdma_on_recv_rdma_read_ack(struct xio_rdma_transport *rdma_hndl,
					  struct xio_task *task);
static int xio_sched_rdma_rd(struct xio_rdma_transport *rdma_hndl,
			     struct xio_task *task);
static int xio_rdma_post_recv_rsp(struct xio_task *task);
/*---------------------------------------------------------------------------*/
/* xio_post_recv							     */
/*---------------------------------------------------------------------------*/
int xio_post_recv(struct xio_rdma_transport *rdma_hndl,
		  struct xio_task *task, int num_recv_bufs)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct ib_recv_wr	*bad_wr	= NULL;
	int			retval, nr_posted;

	retval = ib_post_recv(rdma_hndl->qp, &rdma_task->rxd.recv_wr, &bad_wr);
	if (likely(!retval)) {
		nr_posted = num_recv_bufs;
	} else {
		struct ib_recv_wr *wr;
			nr_posted = 0;
		for (wr = &rdma_task->rxd.recv_wr; wr != bad_wr; wr = wr->next)
			nr_posted++;

		xio_set_error(retval);
		ERROR_LOG("ib_post_recv failed. (errno=%d %s)\n",
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
	struct ib_send_wr	*bad_wr, *wr;
	int			retval, nr_posted;

	/*
	for (wr = &xio_send->send_wr; wr != NULL; wr = wr->next)
		ERROR_LOG("wr_id:0x%llx, num_sge:%d, addr:0x%llx, len1:%d, " \
			  "addr:0x%llx, len2:%d, send_flags:%d\n",
				wr->wr_id,
				wr->num_sge,
				wr->sg_list[0].addr,
				wr->sg_list[0].length,
				wr->sg_list[1].addr,
				wr->sg_list[1].length,
				wr->send_flags);
	*/

	retval = ib_post_send(rdma_hndl->qp, &xio_send->send_wr, &bad_wr);
	if (likely(!retval)) {
		nr_posted = num_send_reqs;
	} else {
		nr_posted = 0;
		for (wr = &xio_send->send_wr; wr != bad_wr; wr = wr->next)
			nr_posted++;

		xio_set_error(retval);

		ERROR_LOG("ib_post_send failed. (errno=%d %s)  posted:%d/%d " \
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

	/* jump over the first uint32_t */
	xio_mbuf_inc(&task->mbuf, sizeof(uint32_t));

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
	struct xio_task		*task = NULL, *task1, *task2;
	struct xio_rdma_task	*rdma_task = NULL;
	struct xio_rdma_task	*prev_rdma_task = NULL;
	struct xio_work_req	*first_wr = NULL;
	struct xio_work_req	*curr_wr = NULL;
	struct xio_work_req	*last_wr = NULL;
	struct xio_work_req	*prev_wr = &rdma_hndl->dummy_wr;
	uint16_t		tx_window;
	uint16_t		window = 0;
	uint16_t		retval;
	uint16_t		req_nr = 0;

	tx_window = tx_window_sz(rdma_hndl);
	/* save one credit for nop */
	if (rdma_hndl->peer_credits > 1) {
		uint16_t peer_credits = rdma_hndl->peer_credits - 1;

		window = min(peer_credits, tx_window);
		window = min(window, ((uint16_t)rdma_hndl->sqe_avail));
	}
	/*
	TRACE_LOG("XMIT: tx_window:%d, peer_credits:%d, sqe_avail:%d\n",
		  tx_window,
		  rdma_hndl->peer_credits,
		  rdma_hndl->sqe_avail);
	*/
	if (window == 0) {
		xio_set_error(EAGAIN);
		return -1;
	}

	/* if "ready to send queue" is not empty */
	while (rdma_hndl->tx_ready_tasks_num) {
		task = list_first_entry(&rdma_hndl->tx_ready_list,
					struct xio_task,  tasks_list_entry);

		rdma_task = task->dd_data;

		/* prefetch next buffer */
		if (rdma_hndl->tx_ready_tasks_num > 2) {
			task1 = list_first_entry/*_or_null*/(
					&task->tasks_list_entry,
					struct xio_task,  tasks_list_entry);
			if (task1) {
				xio_prefetch(task1->mbuf.buf.head);
				task2 = list_first_entry/*_or_null*/(
						&task1->tasks_list_entry,
						struct xio_task,
						tasks_list_entry);
				if (task2)
					xio_prefetch(task2->mbuf.buf.head);
			}
		}

		/* phantom task */
		if (rdma_task->phantom_idx) {
			if (req_nr >= window)
				break;
			curr_wr = &rdma_task->rdmad;

			prev_wr->send_wr.next	= &curr_wr->send_wr;

			prev_rdma_task		= rdma_task;
			prev_wr			= curr_wr;
			req_nr++;
			rdma_hndl->tx_ready_tasks_num--;

			rdma_task->txd.send_wr.send_flags &= ~IB_SEND_SIGNALED;

			if (rdma_task->out_ib_op == XIO_IB_RDMA_WRITE  ||
			    rdma_task->out_ib_op == XIO_IB_RDMA_WRITE_DIRECT) {
				/*
				if (xio_map_txmad_work_req(rdma_hndl->dev,
							   curr_wr))
					ERROR_LOG("DMA map to device failed\n");
				*/
				xio_prep_rdma_wr_send_req(task, rdma_hndl,
							  NULL /*no next*/,
							  0 /* signaled */);
			}

			if (rdma_task->out_ib_op == XIO_IB_RDMA_READ_DIRECT) {
				xio_prep_rdma_rd_send_req(task, rdma_hndl,
							  0 /* signaled */);
			}

			list_move_tail(&task->tasks_list_entry,
				       &rdma_hndl->in_flight_list);
			continue;
		}
		if (rdma_task->out_ib_op == XIO_IB_RDMA_WRITE) {
			if (req_nr >= (window - 1))
				break;

			/* prepare it for rdma wr and concatenate the send
			 * wr to it */
			xio_prep_rdma_wr_send_req(task, rdma_hndl,
						  &rdma_task->txd, 1);

			rdma_task->rdmad.send_wr.next = &rdma_task->txd.send_wr;
			rdma_task->txd.send_wr.send_flags |= IB_SEND_SIGNALED;

			/* prev wr will be linked to the RDMA */
			curr_wr = &rdma_task->rdmad;
			last_wr = &rdma_task->txd;

			req_nr++;
		} else if (rdma_task->out_ib_op == XIO_IB_RDMA_WRITE_DIRECT) {
			if (req_nr >= window)
				break;
			xio_prep_rdma_wr_send_req(task, rdma_hndl,
						  NULL /*no next*/,
						  1 /* signaled */);
			curr_wr = &rdma_task->rdmad;
			last_wr = curr_wr;
		} else if (rdma_task->out_ib_op == XIO_IB_RDMA_READ_DIRECT) {
			if (req_nr >= window)
				break;
			xio_prep_rdma_rd_send_req(task, rdma_hndl,
						  1 /* signaled */);
			curr_wr = &rdma_task->rdmad;
			last_wr = curr_wr;
		} else {
			if (req_nr >= window)
				break;
			/* prev wr will be linked to the send */
			curr_wr = &rdma_task->txd;
			last_wr = curr_wr;
		}
		if (rdma_task->out_ib_op != XIO_IB_RDMA_WRITE_DIRECT &&
		    rdma_task->out_ib_op != XIO_IB_RDMA_READ_DIRECT) {
			xio_rdma_write_sn(task, rdma_hndl->sn,
					  rdma_hndl->ack_sn,
					  rdma_hndl->credits);
			rdma_task->sn = rdma_hndl->sn;

			/* set the length of the header */
			rdma_task->txd.sgt.sgl[0].length =
				xio_mbuf_data_length(&task->mbuf);

			/* Map the send */
			if (unlikely(xio_map_tx_work_req(rdma_hndl->dev,
						&rdma_task->txd))) {
				ERROR_LOG("DMA map to device failed\n");
				return -1;
			}
			rdma_task->txd.send_wr.num_sge = rdma_task->txd.mapped;

			rdma_hndl->sn++;
			rdma_hndl->sim_peer_credits += rdma_hndl->credits;
			rdma_hndl->credits = 0;
			rdma_hndl->peer_credits--;
		}
		if (IS_REQUEST(task->tlv_type) ||
		    task->tlv_type == XIO_MSG_TYPE_RDMA)
			rdma_hndl->reqs_in_flight_nr++;
		else if (IS_RESPONSE(task->tlv_type))
			rdma_hndl->rsps_in_flight_nr++;
		else
			ERROR_LOG("Unexpected tlv_type %u\n", task->tlv_type);

		prev_wr->send_wr.next = &curr_wr->send_wr;
		prev_wr = last_wr;

		prev_rdma_task = rdma_task;
		req_nr++;
		rdma_hndl->tx_ready_tasks_num--;
		list_move_tail(&task->tasks_list_entry,
			       &rdma_hndl->in_flight_list);
	}

	if (req_nr) {
		first_wr = container_of(rdma_hndl->dummy_wr.send_wr.next,
					struct xio_work_req, send_wr);
		prev_rdma_task->txd.send_wr.next = NULL;
		if (tx_window_sz(rdma_hndl) < 1 ||
		    rdma_hndl->sqe_avail < req_nr + 1)
			prev_rdma_task->txd.send_wr.send_flags |=
						IB_SEND_SIGNALED;
		retval = xio_post_send(rdma_hndl, first_wr, req_nr);
		if (unlikely(retval != 0)) {
			ERROR_LOG("xio_post_send failed\n");
			return -1;
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_xmit_rdma_rd							     */
/*---------------------------------------------------------------------------*/
static int xio_xmit_rdma_rd_(struct xio_rdma_transport *rdma_hndl,
			     struct list_head *rdma_rd_list,
			     struct list_head *rdma_rd_in_flight_list,
			     int *rdma_rd_in_flight,
			     int *kick_rdma_rd)
{
	struct xio_task		*task = NULL;
	struct xio_rdma_task	*rdma_task = NULL;
	struct xio_work_req	*first_wr = NULL;
	struct xio_work_req	*prev_wr = &rdma_hndl->dummy_wr;
	struct xio_work_req	*curr_wr = NULL;
	int num_reqs = 0;
	int err;

	if (list_empty(rdma_rd_list) ||
	    rdma_hndl->sqe_avail == 0)
		goto exit;

	do {
		task = list_first_entry(
				rdma_rd_list,
				struct xio_task,  tasks_list_entry);
		list_move_tail(&task->tasks_list_entry,
			       rdma_rd_in_flight_list);
		rdma_task = task->dd_data;

		/* pending "sends" that were delayed for rdma read completion
		 *  are moved to wait in the in_flight list
		 *   because of the need to keep order
		 */
		if (rdma_task->out_ib_op == XIO_IB_RECV) {
			(*rdma_rd_in_flight)++;
			continue;
		}

		BUG_ON(rdma_task->out_ib_op != XIO_IB_RDMA_READ);
		/* prepare it for rdma read */
		xio_prep_rdma_rd_send_req(task, rdma_hndl, 1);

		curr_wr = &rdma_task->rdmad;
		prev_wr->send_wr.next = &curr_wr->send_wr;
		prev_wr = &rdma_task->rdmad;

		num_reqs++;
	} while (!list_empty(rdma_rd_list) &&
		 rdma_hndl->sqe_avail > num_reqs);

	rdma_hndl->kick_rdma_rd_req = 0;
	if (num_reqs) {
		first_wr = container_of(rdma_hndl->dummy_wr.send_wr.next,
					struct xio_work_req, send_wr);
		prev_wr->send_wr.next = NULL;
		(*rdma_rd_in_flight) += num_reqs;
		/* submit the chain of rdma-rd requests, start from the first */
		err = xio_post_send(rdma_hndl, first_wr, num_reqs);
		if (unlikely(err))
			ERROR_LOG("xio_post_send failed\n");

		/* ToDo: error handling */
	}
exit:
	*kick_rdma_rd = !list_empty(rdma_rd_list);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_xmit_rdma_rd_req							     */
/*---------------------------------------------------------------------------*/
static inline int xio_xmit_rdma_rd_req(struct xio_rdma_transport *rdma_hndl)
{
	return xio_xmit_rdma_rd_(rdma_hndl,
				 &rdma_hndl->rdma_rd_req_list,
				 &rdma_hndl->rdma_rd_req_in_flight_list,
				 &rdma_hndl->rdma_rd_req_in_flight,
				 &rdma_hndl->kick_rdma_rd_req);
}

/*---------------------------------------------------------------------------*/
/* xio_xmit_rdma_rd_rsp							     */
/*---------------------------------------------------------------------------*/
static inline int xio_xmit_rdma_rd_rsp(struct xio_rdma_transport *rdma_hndl)
{
	return xio_xmit_rdma_rd_(rdma_hndl,
				 &rdma_hndl->rdma_rd_rsp_list,
				 &rdma_hndl->rdma_rd_rsp_in_flight_list,
				 &rdma_hndl->rdma_rd_rsp_in_flight,
				 &rdma_hndl->kick_rdma_rd_rsp);
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
	struct xio_work_req	*rxd;

	num_to_post = rdma_hndl->actual_rq_depth - rdma_hndl->rqe_avail;
	for (i = 0; i < num_to_post; i++) {
		/* get ready to receive message */
		task = xio_rdma_primary_task_alloc(rdma_hndl);
		if (unlikely(task == 0)) {
			ERROR_LOG("primary tasks pool is empty\n");
			return -1;
		}
		rdma_task = task->dd_data;
		/* map the receive address for dma
		 * Note other sge fields don't change
		 */

		rxd = &rdma_task->rxd;
		if (unlikely(xio_map_rx_work_req(rdma_hndl->dev, rxd))) {
			ERROR_LOG("DMA map from device failed\n");
			return -1;
		}
		rxd->recv_wr.num_sge = rxd->mapped;

		if (!first_task)
			first_task = task;
		else
			prev_rdma_task->rxd.recv_wr.next =
						&rdma_task->rxd.recv_wr;

		prev_task = task;
		prev_rdma_task = rdma_task;
		rdma_task->out_ib_op = XIO_IB_RECV;
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
	XIO_TO_RDMA_TASK(task, rdma_task);

	/* unmap dma */
	xio_unmap_rx_work_req(rdma_hndl->dev, &rdma_task->rxd);

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
	XIO_TO_RDMA_TASK(task, rdma_task);

	/* unmap dma */
	xio_unmap_tx_work_req(rdma_hndl->dev, &rdma_task->txd);

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
	XIO_TO_RDMA_TASK(task, rdma_task);

	if (rdma_task->out_ib_op == XIO_IB_RDMA_WRITE_DIRECT)
		return 0;

	/* wait for the concatenated "send" */
	rdma_task->out_ib_op = XIO_IB_SEND;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_handle_task_error                                                     */
/*---------------------------------------------------------------------------*/
static void xio_handle_task_error(struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	XIO_TO_RDMA_HNDL(task, rdma_hndl);

	switch (rdma_task->out_ib_op) {
	case XIO_IB_RECV:
		/* this should be the Flush, no task has been created yet */
		xio_rdma_rx_error_handler(rdma_hndl, task);
		break;
	case XIO_IB_SEND:
		/* the task should be completed now */
		xio_rdma_tx_error_handler(rdma_hndl, task);
		break;
	case XIO_IB_RDMA_READ:
	case XIO_IB_RDMA_READ_DIRECT:
		xio_rdma_rd_error_handler(rdma_hndl, task);
		break;
	case XIO_IB_RDMA_WRITE:
	case XIO_IB_RDMA_WRITE_DIRECT:
		xio_rdma_wr_error_handler(rdma_hndl, task);
		break;
	default:
		ERROR_LOG("unknown out_ib_op: task:%p, type:0x%x, " \
			  "magic:0x%x, out_ib_op:0x%x\n",
			  task, task->tlv_type,
			  task->magic, rdma_task->out_ib_op);
		break;
	}
}

/*---------------------------------------------------------------------------*/
/* xio_handle_wc_error							     */
/*---------------------------------------------------------------------------*/
static void xio_handle_wc_error(struct ib_wc *wc)
{
	struct xio_task			*task = NULL;
	struct xio_rdma_task		*rdma_task = NULL;
	struct xio_rdma_transport	*rdma_hndl = NULL;
	int				retval;

	task = (struct xio_task *)ptr_from_int64(wc->wr_id);
	if (task && task->dd_data == ptr_from_int64(XIO_BEACON_WRID)) {
		rdma_hndl = container_of(task,
					 struct xio_rdma_transport,
					 beacon_task);
		rdma_hndl->beacon_sent = 0;
		TRACE_LOG("beacon rdma_hndl:%p\n", rdma_hndl);
		kref_put(&rdma_hndl->base.kref, xio_rdma_close_cb);
		return;
	} else if (task && task->dd_data == ptr_from_int64(XIO_FRWR_LI_WRID)) {
		ERROR_LOG("frwr are not signaled rdma_hndl:%p\n", rdma_hndl);
		return;
	}

	if (wc->wr_id) {
		task = ptr_from_int64(wc->wr_id);
		rdma_task = (struct xio_rdma_task *)task->dd_data;
		rdma_hndl = (struct xio_rdma_transport *)task->context;
		rdma_hndl->sqe_avail += rdma_task->sqe_used;
		rdma_task->sqe_used = 0;
	} else {
		task = NULL;
	}

	if (wc->status == IB_WC_WR_FLUSH_ERR) {
		TRACE_LOG("rdma_hndl:%p, rdma_task:%p, task:%p, " \
			  "wr_id:0x%llx, " \
			  "err:%s, vendor_err:0x%x\n",
			   rdma_hndl, rdma_task, task,
			   wc->wr_id,
			   xio_ib_wc_status_str(wc->status),
			   wc->vendor_err);
	} else  {
		if (rdma_hndl)
			ERROR_LOG("[%s] - state:%d, rdma_hndl:%p, " \
				  "rdma_task:%p, task:%p, " \
				  "wr_id:0x%llx, " \
				  "err:%s, vendor_err:0x%x\n",
				  rdma_hndl->base.is_client ?
				  "client" : "server",
				  rdma_hndl->state,
				  rdma_hndl, rdma_task, task,
				  wc->wr_id,
				  xio_ib_wc_status_str(wc->status),
				  wc->vendor_err);
		else
			ERROR_LOG("wr_id:0x%llx, err:%s, vendor_err:0x%x\n",
				  wc->wr_id,
				  xio_ib_wc_status_str(wc->status),
				  wc->vendor_err);

		ERROR_LOG("byte_len=%u, immdata=%u, qp=%p, " \
			  "qp_num=0x%x, src_qp=0x%x\n",
			  wc->byte_len, ntohl(wc->ex.imm_data),
			  wc->qp, wc->qp ? wc->qp->qp_num : 0xdeadbeaf,
			  wc->src_qp);
	}
	if (task && rdma_task)
		xio_handle_task_error(task);

	/* temporary  */
	if (wc->status != IB_WC_WR_FLUSH_ERR) {
		if (rdma_hndl) {
			ERROR_LOG("cq error reported. calling " \
				  "rdma_disconnect. rdma_hndl:%p\n",
				  rdma_hndl);
			retval = rdma_disconnect(rdma_hndl->cm_id);
			if (retval)
				ERROR_LOG("rdma_hndl:%p rdma_disconnect" \
					  "failed, %d\n", rdma_hndl, retval);
		} else {
			/* TODO: handle each error specifically */
			ERROR_LOG("ASSERT: program abort\n");
			BUG();
		}
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_idle_handler						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_idle_handler(struct xio_rdma_transport *rdma_hndl)
{
	if (rdma_hndl->state != XIO_TRANSPORT_STATE_CONNECTED ||
	    !rdma_hndl->primary_pool_cls.task_lookup)
		return 0;

	/* Does the local have resources to send message?  */
	if (!rdma_hndl->sqe_avail)
		return 0;

	/* Try to do some useful work, want to spend time before calling the
	 * pool, this increase the chance that more messages will arrive
	 * and request notify will not be necessary
	 */

	if (rdma_hndl->kick_rdma_rd_req)
		xio_xmit_rdma_rd_req(rdma_hndl);

	if (rdma_hndl->kick_rdma_rd_rsp)
		xio_xmit_rdma_rd_rsp(rdma_hndl);

	/* Does the local have resources to send message?
	 * xio_xmit_rdma_rd may consumed the sqe_avail
	 */
	if (!rdma_hndl->sqe_avail)
		return 0;

	/* Can the peer receive messages? */
	if (!rdma_hndl->peer_credits)
		return 0;

	/* If we have real messages to send there is no need for
	 * a special NOP message as credits are piggybacked
	 */
	if (rdma_hndl->tx_ready_tasks_num) {
		xio_rdma_xmit(rdma_hndl);
		return 0;
	}

	/* Send NOP if messages are not queued */

	/* Does the peer have already maximum credits? */
	if (rdma_hndl->sim_peer_credits >= MAX_RECV_WR)
		return 0;

	/* Does the local have any credits to send? */
	if (!rdma_hndl->credits)
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
			       struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_task		*task1, *task2;
	int			must_send = 0;
	struct xio_work_req	*rxd = &rdma_task->rxd;
	struct list_head	*task_prev;
	int			retval;

	/* prefetch next buffer */
	if (likely(task->tasks_list_entry.next !=
		   task->tasks_list_entry.prev)) {
		task1 = list_entry(task->tasks_list_entry.next,
				   struct xio_task,  tasks_list_entry);
		task_prev = task->tasks_list_entry.prev;
		xio_prefetch(task1->mbuf.buf.head);
	} else {
		task1 = NULL;
		task_prev = NULL;
	}

	rdma_hndl->rqe_avail--;
	rdma_hndl->sim_peer_credits--;

	/* unmap dma */
	xio_unmap_rx_work_req(rdma_hndl->dev, rxd);
	if (rdma_task->read_mem_desc.nents && rdma_task->read_mem_desc.mapped)
		xio_unmap_desc(rdma_hndl, &rdma_task->read_mem_desc,
			       DMA_FROM_DEVICE);

	if (rdma_task->write_mem_desc.nents && rdma_task->write_mem_desc.mapped)
		xio_unmap_desc(rdma_hndl, &rdma_task->write_mem_desc,
			       DMA_TO_DEVICE);

	/* rearm the receive queue  */
	/*
	if ((rdma_hndl->state == XIO_TRANSPORT_STATE_CONNECTED) &&
	    (rdma_hndl->rqe_avail <= rdma_hndl->rq_depth + 1))
		xio_rdma_rearm_rq(rdma_hndl);
	*/
	retval = xio_mbuf_read_first_tlv(&task->mbuf);

	task->tlv_type = xio_mbuf_tlv_type(&task->mbuf);

	list_move_tail(&task->tasks_list_entry, &rdma_hndl->io_list);

	/* call recv completion  */
	switch (task->tlv_type) {
	case XIO_CREDIT_NOP:
		xio_rdma_on_recv_nop(rdma_hndl, task);
		if (rdma_hndl->rqe_avail <= rdma_hndl->rq_depth + 1)
			xio_rdma_rearm_rq(rdma_hndl);
		must_send = 1;
		break;
	case XIO_RDMA_READ_ACK:
		xio_rdma_on_recv_rdma_read_ack(rdma_hndl, task);
		if (rdma_hndl->rqe_avail <= rdma_hndl->rq_depth + 1)
			xio_rdma_rearm_rq(rdma_hndl);
		must_send = 1;
		break;
	case XIO_NEXUS_SETUP_REQ:
	case XIO_NEXUS_SETUP_RSP:
		xio_rdma_on_setup_msg(rdma_hndl, task);
		break;
	case XIO_CANCEL_REQ:
		xio_rdma_on_recv_cancel_req(rdma_hndl, task);
		break;
	case XIO_CANCEL_RSP:
		xio_rdma_on_recv_cancel_rsp(rdma_hndl, task);
		break;
	default:
		/* rearm the receive queue  */
		if (rdma_hndl->rqe_avail <= rdma_hndl->rq_depth + 1)
			xio_rdma_rearm_rq(rdma_hndl);
		if (IS_REQUEST(task->tlv_type))
			xio_rdma_on_recv_req(rdma_hndl, task);
		else if (IS_RESPONSE(task->tlv_type))
			xio_rdma_on_recv_rsp(rdma_hndl, task);
		else
			ERROR_LOG("unknown message type:0x%x\n",
				  task->tlv_type);
		break;
	}
	/*
	if (rdma_hndl->state != XIO_TRANSPORT_STATE_CONNECTED)
		return retval;
	*/
	/* transmit ready packets */
	if (!must_send && rdma_hndl->tx_ready_tasks_num)
		must_send = (tx_window_sz(rdma_hndl) >= SEND_THRESHOLD);
	/* resource are now available and rdma rd  requests are pending kick
	 * them
	 */
	if (rdma_hndl->kick_rdma_rd_req)
		xio_xmit_rdma_rd_req(rdma_hndl);

	if (rdma_hndl->kick_rdma_rd_rsp)
		xio_xmit_rdma_rd_rsp(rdma_hndl);

	if (must_send)
		xio_rdma_xmit(rdma_hndl);

	/* prefetch next buffer */
	if  (task1) {
		if (task1->tasks_list_entry.next != task_prev) {
			task2 = list_entry(task1->tasks_list_entry.next,
					   struct xio_task, tasks_list_entry);
			xio_prefetch(task2);
		}
	}

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
	struct xio_work_req	*txd, *rdmad;

	/* If we got a completion, it means all the previous tasks should've
	   been sent by now - due to ordering */
	list_for_each_entry_safe(ptask, next_ptask, &rdma_hndl->in_flight_list,
				 tasks_list_entry) {
		list_move_tail(&ptask->tasks_list_entry,
			       &rdma_hndl->tx_comp_list);
		removed++;
		rdma_task = ptask->dd_data;

		txd = &rdma_task->txd;

		/* unmap dma */
		xio_unmap_tx_work_req(rdma_hndl->dev, txd);

		rdma_hndl->sqe_avail++;
		rdma_hndl->sqe_avail += rdma_task->sqe_used;
		rdma_task->sqe_used = 0;

		/* phantom task  */
		if (rdma_task->phantom_idx) {
			xio_tasks_pool_put(ptask);
			continue;
		}

		/* rdma wr utilizes two wqe but appears only once in the
		 * in flight list
		 */
		if (rdma_task->out_ib_op == XIO_IB_RDMA_WRITE)
			rdma_hndl->sqe_avail++;

		if (IS_RDMA_RD_ACK(ptask->tlv_type)) {
			rdma_hndl->rsps_in_flight_nr--;
			xio_tasks_pool_put(ptask);
		} else if (IS_REQUEST(ptask->tlv_type)) {
			rdma_hndl->max_sn++;
			rdma_hndl->reqs_in_flight_nr--;
			xio_rdma_on_req_send_comp(rdma_hndl, ptask);
			xio_tasks_pool_put(ptask);
		} else if (IS_RESPONSE(ptask->tlv_type)) {
			rdmad = &rdma_task->rdmad;
			/* unmap dma */
			/* Need to handle FMR/FRWR */
			if (rdma_task->out_ib_op == XIO_IB_RDMA_WRITE)
				xio_unmap_txmad_work_req(rdma_hndl->dev, rdmad);
			else
				xio_unmap_rxmad_work_req(rdma_hndl->dev, rdmad);

			if (rdma_task->read_mem_desc.nents &&
			    rdma_task->read_mem_desc.mapped)
				xio_unmap_desc(rdma_hndl,
					       &rdma_task->read_mem_desc,
					       DMA_FROM_DEVICE);

			if (rdma_task->write_mem_desc.nents &&
			    rdma_task->write_mem_desc.mapped)
				xio_unmap_desc(rdma_hndl,
					       &rdma_task->write_mem_desc,
					       DMA_TO_DEVICE);

			rdma_hndl->max_sn++;
			rdma_hndl->rsps_in_flight_nr--;
			xio_rdma_on_rsp_send_comp(rdma_hndl, ptask);
		} else if (IS_NOP(ptask->tlv_type)) {
			rdma_hndl->rsps_in_flight_nr--;
			xio_tasks_pool_put(ptask);
		} else if (ptask->tlv_type == XIO_MSG_TYPE_RDMA) {
			rdma_hndl->reqs_in_flight_nr--;
			rdmad = &rdma_task->rdmad;
			if (rdma_task->out_ib_op == XIO_IB_RDMA_WRITE_DIRECT) {
				xio_unmap_txmad_work_req(rdma_hndl->dev, rdmad);
				xio_rdma_on_direct_rdma_comp(
						rdma_hndl, ptask,
						XIO_WC_OP_RDMA_WRITE);
				xio_tasks_pool_put(ptask);
			}
		} else {
			ERROR_LOG("unexpected task %p tlv %u type:0x%x id:%d " \
				  "magic:0x%x\n",
				  ptask, ptask->tlv_type, rdma_task->out_ib_op,
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
	if (rdma_hndl->kick_rdma_rd_req)
		xio_xmit_rdma_rd_req(rdma_hndl);

	if (rdma_hndl->kick_rdma_rd_rsp)
		xio_xmit_rdma_rd_rsp(rdma_hndl);

	if (rdma_hndl->tx_ready_tasks_num)
		xio_rdma_xmit(rdma_hndl);

	if (!found && removed)
		ERROR_LOG("not found but removed %d type:0x%x\n",
			  removed, task->tlv_type);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* unmap_rdma_rd_task							     */
/*---------------------------------------------------------------------------*/
static void unmap_rdma_rd_task(struct xio_rdma_transport *rdma_hndl,
			       struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	if (rdma_task->rdmad.mapped)
		xio_unmap_rxmad_work_req(rdma_hndl->dev,
					 &rdma_task->rdmad);

	if (rdma_task->read_mem_desc.nents &&
	    rdma_task->read_mem_desc.mapped)
		xio_unmap_desc(rdma_hndl, &rdma_task->read_mem_desc,
			       DMA_FROM_DEVICE);

	if (rdma_task->write_mem_desc.nents &&
	    rdma_task->write_mem_desc.mapped)
		xio_unmap_desc(rdma_hndl, &rdma_task->write_mem_desc,
			       DMA_TO_DEVICE);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_rd_req_comp_handler						     */
/*---------------------------------------------------------------------------*/
static void xio_direct_rdma_rd_comp_handler(
		struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);

	rdma_hndl->sqe_avail++;
	rdma_hndl->sqe_avail += rdma_task->sqe_used;
	rdma_task->sqe_used = 0;

	if (rdma_task->phantom_idx == 0) {
		rdma_hndl->reqs_in_flight_nr--;
		xio_rdma_on_direct_rdma_comp(rdma_hndl, task,
					     XIO_WC_OP_RDMA_READ);

		unmap_rdma_rd_task(rdma_hndl, task);
	} else {
		xio_tasks_pool_put(task);
		xio_xmit_rdma_rd_req(rdma_hndl);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_rd_req_comp_handler						     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_rd_req_comp_handler(struct xio_rdma_transport *rdma_hndl,
					 struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	union xio_transport_event_data event_data;
	struct xio_transport_base	*transport =
					(struct xio_transport_base *)rdma_hndl;

	rdma_hndl->rdma_rd_req_in_flight--;

	rdma_hndl->sqe_avail++;
	rdma_hndl->sqe_avail += rdma_task->sqe_used;
	rdma_task->sqe_used = 0;

	if (rdma_task->phantom_idx == 0) {
		if (task->state == XIO_TASK_STATE_CANCEL_PENDING) {
			TRACE_LOG("[%d] - **** message is canceled\n",
				  rdma_task->sn);
			xio_rdma_cancel_rsp(transport, task, XIO_E_MSG_CANCELED,
					    NULL, 0);
			xio_tasks_pool_put(task);
			xio_xmit_rdma_rd_req(rdma_hndl);
			if (rdma_task->rdmad.mapped)
				xio_unmap_rxmad_work_req(rdma_hndl->dev,
							 &rdma_task->rdmad);
			return;
		}

		list_move_tail(&task->tasks_list_entry, &rdma_hndl->io_list);

		xio_xmit_rdma_rd_req(rdma_hndl);

		unmap_rdma_rd_task(rdma_hndl, task);

		/* fill notification event */
		event_data.msg.op	= XIO_WC_OP_RECV;
		event_data.msg.task	= task;

		xio_transport_notify_observer(&rdma_hndl->base,
					      XIO_TRANSPORT_EVENT_NEW_MESSAGE,
					      &event_data);

		while (rdma_hndl->rdma_rd_req_in_flight) {
			task = list_first_entry(
					&rdma_hndl->rdma_rd_req_in_flight_list,
					struct xio_task,  tasks_list_entry);

			rdma_task = task->dd_data;

			if (rdma_task->out_ib_op != XIO_IB_RECV)
				break;

			/* tasks that arrived in Send/Receive while pending
			 * "RDMA READ" tasks were in flight was fenced.
			 */
			rdma_hndl->rdma_rd_req_in_flight--;
			list_move_tail(&task->tasks_list_entry,
				       &rdma_hndl->io_list);
			event_data.msg.op	= XIO_WC_OP_RECV;
			event_data.msg.task	= task;

			xio_transport_notify_observer(
					&rdma_hndl->base,
					XIO_TRANSPORT_EVENT_NEW_MESSAGE,
					&event_data);
		}
	} else {
		xio_tasks_pool_put(task);
		xio_xmit_rdma_rd_req(rdma_hndl);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_rd_rsp_comp_handler						     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_rd_rsp_comp_handler(struct xio_rdma_transport *rdma_hndl,
					 struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	union xio_transport_event_data event_data;
	struct xio_transport_base	*transport =
					(struct xio_transport_base *)rdma_hndl;

	rdma_hndl->rdma_rd_rsp_in_flight--;

	rdma_hndl->sqe_avail++;
	rdma_hndl->sqe_avail += rdma_task->sqe_used;
	rdma_task->sqe_used = 0;

	if (rdma_task->phantom_idx == 0) {
		if (task->state == XIO_TASK_STATE_CANCEL_PENDING) {
			TRACE_LOG("[%d] - **** message is canceled\n",
				  rdma_task->sn);
			xio_rdma_cancel_rsp(transport, task, XIO_E_MSG_CANCELED,
					    NULL, 0);
			xio_tasks_pool_put(task);
			xio_xmit_rdma_rd_rsp(rdma_hndl);
			if (rdma_task->rdmad.mapped)
				xio_unmap_rxmad_work_req(rdma_hndl->dev,
							 &rdma_task->rdmad);
			return;
		}

		list_move_tail(&task->tasks_list_entry, &rdma_hndl->io_list);

		/* notify the peer that it can free resources */
		xio_rdma_send_rdma_read_ack(rdma_hndl, task->rtid);

		xio_xmit_rdma_rd_rsp(rdma_hndl);

		unmap_rdma_rd_task(rdma_hndl, task);

		/* copy from task->in to sender_task->in */
		xio_rdma_post_recv_rsp(task);

		/* fill notification event */
		event_data.msg.op	= XIO_WC_OP_RECV;
		event_data.msg.task	= task;

		xio_transport_notify_observer(&rdma_hndl->base,
					      XIO_TRANSPORT_EVENT_NEW_MESSAGE,
					      &event_data);

		while (rdma_hndl->rdma_rd_rsp_in_flight) {
			task = list_first_entry(
					&rdma_hndl->rdma_rd_rsp_in_flight_list,
					struct xio_task,  tasks_list_entry);

			rdma_task = task->dd_data;

			if (rdma_task->out_ib_op != XIO_IB_RECV)
				break;

			/* tasks that arrived in Send/Receive while pending
			 * "RDMA READ" tasks were in flight was fenced.
			 */
			rdma_hndl->rdma_rd_rsp_in_flight--;
			list_move_tail(&task->tasks_list_entry,
				       &rdma_hndl->io_list);
			event_data.msg.op	= XIO_WC_OP_RECV;
			event_data.msg.task	= task;

			xio_transport_notify_observer(
					&rdma_hndl->base,
					XIO_TRANSPORT_EVENT_NEW_MESSAGE,
					&event_data);
		}
	} else {
		xio_tasks_pool_put(task);
		xio_xmit_rdma_rd_rsp(rdma_hndl);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_handle_wc							     */
/*---------------------------------------------------------------------------*/
static inline void xio_handle_wc(struct ib_wc *wc, int last_in_rxq)
{
	struct xio_task		*task = ptr_from_int64(wc->wr_id);
	int			opcode = wc->opcode;

	XIO_TO_RDMA_HNDL(task, rdma_hndl);

	/*
	TRACE_LOG("received opcode :%s byte_len [%u]\n",
		  xio_ib_wc_opcode_str(wc->opcode), wc->byte_len);
	*/

	switch (opcode) {
	case IB_WC_RECV:
		task->last_in_rxq = last_in_rxq;
		xio_rdma_rx_handler(rdma_hndl, task);
		break;
	case IB_WC_SEND:
	case IB_WC_RDMA_WRITE:
		if (opcode == IB_WC_SEND ||
		    (opcode == IB_WC_RDMA_WRITE &&
		     task->tlv_type == XIO_MSG_TYPE_RDMA))
			xio_rdma_tx_comp_handler(rdma_hndl, task);
		break;
	case IB_WC_RDMA_READ:
		task->last_in_rxq = last_in_rxq;
		if (IS_REQUEST(task->tlv_type))
			xio_rdma_rd_req_comp_handler(rdma_hndl, task);
		else if (IS_RESPONSE(task->tlv_type))
			xio_rdma_rd_rsp_comp_handler(rdma_hndl, task);
		else if (task->tlv_type == XIO_MSG_TYPE_RDMA)
			xio_direct_rdma_rd_comp_handler(rdma_hndl, task);
		else
			ERROR_LOG("Unexpected tlv_type %u\n", task->tlv_type);
		break;
	case IB_WC_LOCAL_INV:
	case IB_WC_FAST_REG_MR:
		break;
	default:
		ERROR_LOG("unknown opcode :%s [0x%x]\n",
			  xio_ib_wc_opcode_str(wc->opcode), wc->opcode);
		break;
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_poll_completions						     */
/*---------------------------------------------------------------------------*/
void xio_rdma_poll_completions(struct xio_cq *tcq, int timeout_us)
{
	int			retval;
	int			i;
	struct xio_task		*task;
	int			last_in_rxq = -1;
	int			tlv_type;
	unsigned long		timeout;
	unsigned long		start_time;
	struct ib_wc		*wc;
	struct xio_rdma_task	*rdma_task;

	timeout = usecs_to_jiffies(timeout_us);

	start_time = jiffies;

	while (1) {
		retval = ib_poll_cq(tcq->cq, tcq->wc_array_len, tcq->wc_array);
		if (likely(retval > 0)) {
			wc = &tcq->wc_array[retval - 1];
			for (i = retval - 1; i >= 0; i--) {
				if (((wc->opcode == IB_WC_RECV || wc->opcode == IB_WC_RDMA_READ)) &&
				    wc->status == IB_WC_SUCCESS) {
					task = (struct xio_task *)
						ptr_from_int64(wc->wr_id);
					rdma_task = (struct xio_rdma_task *)task->dd_data;
					if (!rdma_task->phantom_idx) {
						tlv_type = xio_mbuf_read_type(
								&task->mbuf);
						if (IS_APPLICATION_MSG(tlv_type)) {
							last_in_rxq = i;
							break;
						}
					}
				}
				wc--;
			}
			wc = &tcq->wc_array[0];
			for (i = 0; i < retval; i++) {
				if (likely(wc->status == IB_WC_SUCCESS))
					xio_handle_wc(wc,
						      (last_in_rxq == i));
				else
					xio_handle_wc_error(wc);
				wc++;
			}
			if (time_is_before_eq_jiffies(start_time + timeout))
				break;
			if (xio_context_is_loop_stopping(tcq->ctx))
				break;
		} else if (retval == 0) {
			if (time_is_before_eq_jiffies(start_time + timeout))
				break;
		} else {
			ERROR_LOG("ib_poll_cq failed. (ret=%d %m)\n", retval);
			xio_set_error(-retval);
			return;
		}
	}

	retval = ib_req_notify_cq(tcq->cq, IB_CQ_NEXT_COMP);
	if (unlikely(retval)) {
		/* didn't request IB_CQ_REPORT_MISSED_EVENTS so can't be > 0 */
		xio_set_error(-retval);
		ERROR_LOG("ib_req_notify_cq failed. (ret=%d)\n", retval);
		return;
	}
	tcq->num_delayed_arm = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_cq_event_handler							     */
/*---------------------------------------------------------------------------*/
static int xio_cq_event_handler(struct xio_cq *tcq)
{
	struct xio_task *task;
	unsigned long	start_time;
	u32		budget = MAX_POLL_WC;
	int		poll_nr, polled;
	int		retval, tlv_type;
	int		i, last_in_rxq = -1;
	struct ib_wc	*wc;
	struct xio_rdma_task *rdma_task;

	start_time = jiffies;

retry:
	while (budget) {
		poll_nr = min(budget, tcq->wc_array_len);
		for (i = 0; i < poll_nr; i++) {
			/* don't hold spinlock_irqsave for long */
			retval = ib_poll_cq(tcq->cq, 1, &tcq->wc_array[i]);
			if (unlikely(retval <= 0))
				break;
		}
		polled = i;
		budget -= i;
		tcq->wqes += i;

		wc = &tcq->wc_array[polled - 1];
		for (i = polled - 1; i >= 0; i--) {
			if ((wc->opcode == IB_WC_RECV || wc->opcode == IB_WC_RDMA_READ) &&
			     wc->status == IB_WC_SUCCESS) {
				task = (struct xio_task *)
					ptr_from_int64(wc->wr_id);
				rdma_task = (struct xio_rdma_task *)task->dd_data;
				if (!rdma_task->phantom_idx) {
					tlv_type = xio_mbuf_read_type(&task->mbuf);
					if (IS_APPLICATION_MSG(tlv_type)) {
						last_in_rxq = i;
						break;
					}
				}
			}
			wc--;
		}
		/* process work completions */
		wc = &tcq->wc_array[0];
		for (i = 0; i < polled; i++) {
			if (wc->status == IB_WC_SUCCESS)
				xio_handle_wc(wc,
					      (last_in_rxq == i));
			else
				xio_handle_wc_error(wc);
			wc++;
		}
		/* an error or no more work completions */
		if (polled != poll_nr)
			break;

		if (time_after(jiffies, start_time)) {
			/* time slice exhausted, reschedule */
			xio_cq_data_callback_cont(tcq->cq, tcq);
			return 0;
		}
	}

	/* If we got anything, return quickly, and come again later */
	if (likely(budget != MAX_POLL_WC)) {
		/* budget was consumed, reschedule */
		xio_cq_data_callback_cont(tcq->cq, tcq);
		return 0;
	}

	if (unlikely(tcq->polling_started == 0 && tcq->ctx->polling_timeout)) {
		getnstimeofday(&tcq->polling_end_time);
		timespec_add_ns(&tcq->polling_end_time,
				tcq->ctx->polling_timeout * NSECS_IN_USEC);
		tcq->polling_started = 1;
	}

	/* If loop was terminated before the budget was consumed
	 * need to re-arm the CQ
	 */
	tcq->num_delayed_arm++;
	if (tcq->num_delayed_arm < MAX_NUM_DELAYED_ARM) {
		/* Let other activities to do some work
		 * with the hope that events will arrive and
		 * no interrupt triggering will be required.
		 * Kind of busy wait
		 */
		xio_cq_data_callback_cont(tcq->cq, tcq);
		return 0;
	}

	if (likely(tcq->polling_started)) {
		struct timespec ts;

		getnstimeofday(&ts);
		if (tcq->polling_end_time.tv_sec > ts.tv_sec ||
		    tcq->polling_end_time.tv_nsec > ts.tv_nsec) {
			xio_cq_data_callback_cont(tcq->cq, tcq);
			return 0;
		}
		tcq->polling_started = 0;
	}

	tcq->num_delayed_arm = 0;

	/* retries limit reached */
	retval = ib_req_notify_cq(tcq->cq,
				  IB_CQ_NEXT_COMP |
				  IB_CQ_REPORT_MISSED_EVENTS);
	if (likely(!retval))
		return 0;

	/* if driver supports IB_CQ_REPORT_MISSED_EVENTS
	 * note budget is not yet consumed
	 */
	if (retval > 0)
		goto retry;

	ERROR_LOG("ib_req_notify_cq failed. (err=%d)\n",
		  retval);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_data_handler							     */
/*---------------------------------------------------------------------------*/
void xio_data_handler(void *user_context)
{
	struct xio_cq *tcq = (struct xio_cq *)user_context;
	struct xio_rdma_transport *rdma_hndl;

	xio_cq_event_handler(tcq);

	list_for_each_entry(rdma_hndl, &tcq->trans_list, trans_list_entry) {
		xio_rdma_idle_handler(rdma_hndl);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_cq_data_callback_cont (completion)				     */
/*---------------------------------------------------------------------------*/
void xio_cq_data_callback_cont(struct ib_cq *cq, void *cq_context)
{
	struct xio_cq *tcq = (struct xio_cq *)cq_context;

	tcq->scheds++;
	/* do it in init time */
	tcq->event_data.handler = xio_data_handler;
	tcq->event_data.data    = cq_context;
	/* tell "poller mechanism" */
	xio_context_add_event(tcq->ctx, &tcq->event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_cq_data_callback (completion)					     */
/*---------------------------------------------------------------------------*/
void xio_cq_data_callback(struct ib_cq *cq, void *cq_context)
{
	struct xio_cq *tcq = (struct xio_cq *)cq_context;

	tcq->events++;
	/* do it in init time */
	tcq->event_data.handler = xio_data_handler;
	tcq->event_data.data    = cq_context;
	/* tell "poller mechanism" */
	xio_context_add_event(tcq->ctx, &tcq->event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_prep_rdma_rd_send_req						     */
/*---------------------------------------------------------------------------*/
static void xio_prep_rdma_rd_send_req(struct xio_task *task,
				      struct xio_rdma_transport *rdma_hndl,
				      int signaled)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_work_req	*rdmad = &rdma_task->rdmad;

	if (unlikely(!rdmad->nents)) {
		ERROR_LOG("ZERO nents %s\n", __func__);
		return;
	}

	if (unlikely(xio_map_rxmad_work_req(rdma_hndl->dev, rdmad))) {
		ERROR_LOG("DMA map from device failed\n");
		return;
	}

	rdmad->send_wr.num_sge		= rdmad->mapped;
	rdmad->send_wr.wr_id		= uint64_from_ptr(task);
	rdmad->send_wr.next		= NULL;
	rdmad->send_wr.opcode		= IB_WR_RDMA_READ;
	rdmad->send_wr.send_flags	= (signaled ? IB_SEND_SIGNALED : 0);

	/* remote_addr and rkey were set in xio_prep_rdma_op */
}

/*---------------------------------------------------------------------------*/
/* xio_prep_rdma_wr_send_req						     */
/*---------------------------------------------------------------------------*/
static void xio_prep_rdma_wr_send_req(struct xio_task *task,
				      struct xio_rdma_transport *rdma_hndl,
				      struct xio_work_req *next_wr,
				      int signaled)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_device	*dev = rdma_hndl->dev;
	struct xio_work_req	*rdmad = &rdma_task->rdmad;

	if (unlikely(!rdmad->nents)) {
		ERROR_LOG("ZERO nents %s\n", __func__);
		return;
	}

	if (unlikely(xio_map_txmad_work_req(dev, rdmad))) {
		ERROR_LOG("DMA map to device failed\n");
		return;
	}

	rdmad->send_wr.num_sge		= rdmad->mapped;
	rdmad->send_wr.wr_id		= uint64_from_ptr(task);
	rdmad->send_wr.next		= (next_wr ? &next_wr->send_wr : NULL);
	rdmad->send_wr.opcode		= IB_WR_RDMA_WRITE;
	rdmad->send_wr.send_flags	|= (signaled ? IB_SEND_SIGNALED : 0);

	/* remote_addr and rkey were set in xio_prep_rdma_op */
}

/*---------------------------------------------------------------------------*/
/* xio_prep_rdma_op							     */
/*---------------------------------------------------------------------------*/
static int xio_prep_rdma_op(struct xio_task *task,
			    struct xio_rdma_transport *rdma_hndl,
			    enum xio_ib_op_code  xio_out_ib_op,
			    enum ib_wr_opcode   opcode,
			    struct xio_vmsg *vmsg,
			    struct xio_sge *rsg_list, size_t rsize,
			    size_t *out_rsize,
			    uint32_t op_size,
			    int	max_sge,
			    int signaled,
			    struct list_head *target_list,
			    int tasks_number)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_task		*tmp_task;
	int task_idx;

	struct xio_rdma_task	*tmp_rdma_task;
	struct xio_work_req	*rdmad = &rdma_task->rdmad;
	struct xio_task		*ptask, *next_ptask;
	struct scatterlist *sg = NULL;
	struct scatterlist *liov;
	struct sg_table *sgtbl;
	size_t lsize;
	uint64_t laddr;
	uint64_t raddr;
	uint64_t raddr_base;
	uint32_t llen;
	uint32_t rlen;
	uint32_t rkey;
	uint32_t tot_len = 0;
	uint32_t int_len = 0;
	uint32_t rint_len = 0;
	int l = 0, r = 0, k = 0;
	LIST_HEAD(tmp_list);

	sgtbl = &vmsg->data_tbl;

	lsize = sgtbl->nents;
	liov  = sgtbl->sgl;

	r = 0;
	rlen  = rsg_list[r].length;
	raddr = rsg_list[r].addr;
	raddr_base = raddr;
	rkey  = rsg_list[r].stag;

	l = 0;
	laddr = uint64_from_ptr(sg_virt(liov));
	llen  = liov->length;
	/* lkey will be set just after mapping when the ib_sge will be set */

	k = 0;

	if (unlikely(lsize < 1 || rsize < 1)) {
		ERROR_LOG("iovec size < 1 lsize:%zud, rsize:%zud\n",
			  lsize, rsize);
		return -1;
	}

	task_idx = tasks_number - 1;

	if (task_idx == 0) {
		tmp_task = task;
	} else {
		/* take new task */
		tmp_task =
			xio_tasks_pool_get(
				rdma_hndl->phantom_tasks_pool, rdma_hndl);
		if (unlikely(!tmp_task)) {
			ERROR_LOG("phantom tasks pool is empty\n");
			return -1;
		}
	}
	tmp_rdma_task = (struct xio_rdma_task *)tmp_task->dd_data;
	rdmad = &tmp_rdma_task->rdmad;
	sg = rdmad->sgt.sgl;
	/*sg_init_table(sg, XIO_MAX_IOV);*/

	while (1) {
		if (rlen < llen) {
			/* .num_sge will come from rdmad->mapped */
			rdmad->send_wr.wr_id		=
					uint64_from_ptr(tmp_task);
			rdmad->send_wr.next		= NULL;
			rdmad->send_wr.opcode		= opcode;
			rdmad->send_wr.send_flags	=
					(signaled ? IB_SEND_SIGNALED : 0);
			rdmad->send_wr.wr.rdma.remote_addr = raddr_base;
			rdmad->send_wr.wr.rdma.rkey	   = rkey;

			/* Address is not yet mapped */
			sg_set_page(sg, virt_to_page(laddr),
				    rlen, offset_in_page(laddr));
			sg_mark_end(sg);
			rdmad->last_sg = sg;
			rdmad->sgt.nents = k + 1;
			rdmad->nents			= k + 1;
			k				= 0;

			tot_len				+= rlen;
			int_len				+= rlen;
			tmp_rdma_task->out_ib_op		= xio_out_ib_op;
			tmp_rdma_task->phantom_idx	= task_idx;

			/* close the task */
			list_move_tail(&tmp_task->tasks_list_entry, &tmp_list);
			/* advance the remote index */
			r++;
			if (r == rsize) {
				liov->length = int_len;
				int_len = 0;
				l++;
				break;
			}
			task_idx--;
			/* Is this the last task */
			if (task_idx) {
				/* take new task */
				tmp_task =
					xio_tasks_pool_get(
						rdma_hndl->phantom_tasks_pool,
						rdma_hndl);
				if (unlikely(!tmp_task)) {
					ERROR_LOG(
					      "phantom tasks pool is empty\n");
					goto cleanup;
				}
			} else {
				tmp_task = task;
			}

			tmp_rdma_task =
				(struct xio_rdma_task *)tmp_task->dd_data;
			rdmad = &tmp_rdma_task->rdmad;
			sg = rdmad->sgt.sgl;
			/* sg_init_table(sg, XIO_MAX_IOV); */

			llen	-= rlen;
			laddr	+= rlen;
			raddr	= rsg_list[r].addr;
			rlen	= rsg_list[r].length;
			rkey	= rsg_list[r].stag;
			raddr_base = raddr;
		} else if (llen < rlen) {
			/* Address is not yet mapped */
			sg_set_page(sg, virt_to_page(laddr),
				    llen, offset_in_page(laddr));
			tot_len			+= llen;
			int_len			+= llen;
			rint_len		+= llen;

			liov->length = int_len;
			int_len = 0;
			/* advance the local index */
			l++;
			k++;
			if (l == lsize || k == max_sge - 1) {
				/* .num_sge will come from rdmad->mapped */
				rdmad->send_wr.wr_id		   =
						uint64_from_ptr(tmp_task);
				rdmad->send_wr.next		   = NULL;
				rdmad->send_wr.opcode		   = opcode;
				rdmad->send_wr.send_flags	=
					   (signaled ? IB_SEND_SIGNALED : 0);
				rdmad->send_wr.wr.rdma.remote_addr = raddr_base;
				rdmad->send_wr.wr.rdma.rkey = rkey;
				tmp_rdma_task->out_ib_op = xio_out_ib_op;
				tmp_rdma_task->phantom_idx = task_idx;

				sg_mark_end(sg);
				rdmad->last_sg = sg;
				rdmad->sgt.nents = k;
				rdmad->nents = k;

				/* close the task */
				list_move_tail(&tmp_task->tasks_list_entry,
					       &tmp_list);

				if (l == lsize) {
					rsg_list[r].length = rint_len;
					rint_len = 0;
					r++;
					break;
				}

				/* if we are here then k == max_sge - 1 */

				task_idx--;
				/* Is this the last task */
				if (task_idx) {
					/* take new task */
					tmp_task =
						xio_tasks_pool_get(
						rdma_hndl->phantom_tasks_pool,
						rdma_hndl);
					if (unlikely(!tmp_task)) {
						ERROR_LOG(
						"phantom tasks pool is empty\n");
						goto cleanup;
					}
				} else {
					tmp_task = task;
				}

				tmp_rdma_task =
				  (struct xio_rdma_task *)tmp_task->dd_data;
				rdmad = &tmp_rdma_task->rdmad;
				k = 0;
				sg = rdmad->sgt.sgl;
				/* sg_init_table(sg, XIO_MAX_IOV); */
			} else {
				sg = sg_next(sg);
			}
			liov = sg_next(liov);
			rlen	-= llen;
			raddr	+= llen;
			laddr = uint64_from_ptr(sg_virt(liov));
			llen  = liov->length;
		} else {
			/* .num_sge will come from rdmad->mapped */
			rdmad->send_wr.wr_id = uint64_from_ptr(tmp_task);
			rdmad->send_wr.next		= NULL;
			rdmad->send_wr.opcode		= opcode;
			rdmad->send_wr.send_flags	=
					(signaled ? IB_SEND_SIGNALED : 0);
			rdmad->send_wr.wr.rdma.remote_addr = raddr_base;
			rdmad->send_wr.wr.rdma.rkey	   = rkey;

			/* Address is not yet mapped */
			sg_set_page(sg, virt_to_page(laddr),
				    llen, offset_in_page(laddr));
			sg_mark_end(sg);
			rdmad->last_sg = sg;
			rdmad->sgt.nents = k + 1;
			rdmad->nents = k + 1;
			k = 0;

			tot_len			       += llen;
			int_len			       += llen;
			rint_len		       += llen;
			tmp_rdma_task->out_ib_op		= xio_out_ib_op;
			tmp_rdma_task->phantom_idx	= task_idx;

			/* close the task */
			list_move_tail(&tmp_task->tasks_list_entry,
				       &tmp_list);

			liov->length = int_len;
			int_len = 0;
			rsg_list[r].length = rint_len;
			rint_len = 0;
			/* advance the remote and local indices */
			r++;
			l++;
			if ((l == lsize) || (r == rsize))
				break;
			liov = sg_next(liov);

			task_idx--;
			/* Is this the last task */
			if (task_idx) {
				/* take new task */
				tmp_task =
					xio_tasks_pool_get(
						rdma_hndl->phantom_tasks_pool,
						rdma_hndl);
				if (unlikely(!tmp_task)) {
					ERROR_LOG(
					       "phantom tasks pool is empty\n");
					goto cleanup;
				}
			} else {
				tmp_task = task;
			}
			tmp_rdma_task =
				(struct xio_rdma_task *)tmp_task->dd_data;
			rdmad = &tmp_rdma_task->rdmad;
			sg = rdmad->sgt.sgl;
			/* sg_init_table(sg, XIO_MAX_IOV); */

			laddr = uint64_from_ptr(sg_virt(liov));
			llen  = liov->length;

			raddr	= rsg_list[r].addr;
			rlen	= rsg_list[r].length;
			rkey	= rsg_list[r].stag;
			raddr_base = raddr;
		}
	}
	sgtbl->nents = l;
	sg_mark_end(liov);
	*out_rsize = r;

	if (tot_len < op_size) {
		ERROR_LOG("iovec exhausted\n");
		goto cleanup;
	}

	list_splice_tail(&tmp_list, target_list);

	return 0;
cleanup:

	/* list does not contain the original task */
	list_for_each_entry_safe(ptask, next_ptask, &tmp_list,
				 tasks_list_entry) {
		/* the tmp tasks are returned back to pool */
		xio_tasks_pool_put(ptask);
	}

	return -1;
}

/*---------------------------------------------------------------------------*/
/* verify_req_send_limits						     */
/*---------------------------------------------------------------------------*/
static int verify_req_send_limits(const struct xio_rdma_transport *rdma_hndl)
{
	if (rdma_hndl->reqs_in_flight_nr + rdma_hndl->rsps_in_flight_nr >
	    rdma_hndl->max_tx_ready_tasks_num) {
		DEBUG_LOG("over limits reqs_in_flight_nr=%u, "\
			  "rsps_in_flight_nr=%u, max_tx_ready_tasks_num=%u\n",
			  rdma_hndl->reqs_in_flight_nr,
			  rdma_hndl->rsps_in_flight_nr,
			  rdma_hndl->max_tx_ready_tasks_num);
		xio_set_error(EAGAIN);
		return -1;
	}

	if (rdma_hndl->reqs_in_flight_nr >=
			rdma_hndl->max_tx_ready_tasks_num - 1) {
		DEBUG_LOG("over limits reqs_in_flight_nr=%u, " \
			  "max_tx_ready_tasks_num=%u\n",
			  rdma_hndl->reqs_in_flight_nr,
			  rdma_hndl->max_tx_ready_tasks_num);

		xio_set_error(EAGAIN);
		return -1;
	}
	/* tx ready is full - refuse request */
	if (rdma_hndl->tx_ready_tasks_num >=
			rdma_hndl->max_tx_ready_tasks_num) {
		DEBUG_LOG("over limits tx_ready_tasks_num=%u, "\
			  "max_tx_ready_tasks_num=%u\n",
			  rdma_hndl->tx_ready_tasks_num,
			  rdma_hndl->max_tx_ready_tasks_num);
		xio_set_error(EAGAIN);
		return -1;
	}
	if (rdma_hndl->sqe_avail < 2) {
		DEBUG_LOG("rdma_hndl=%p, no sqe_avail=%d\n",
			  rdma_hndl, rdma_hndl->sqe_avail);
		xio_set_error(EAGAIN);
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* verify_rsp_send_limits						     */
/*---------------------------------------------------------------------------*/
static int verify_rsp_send_limits(const struct xio_rdma_transport *rdma_hndl)
{
	if (rdma_hndl->reqs_in_flight_nr + rdma_hndl->rsps_in_flight_nr >
	    rdma_hndl->max_tx_ready_tasks_num) {
		DEBUG_LOG("over limits reqs_in_flight_nr=%u, "\
			  "rsps_in_flight_nr=%u, max_tx_ready_tasks_num=%u\n",
			  rdma_hndl->reqs_in_flight_nr,
			  rdma_hndl->rsps_in_flight_nr,
			  rdma_hndl->max_tx_ready_tasks_num);
		xio_set_error(EAGAIN);
		return -1;
	}

	if (rdma_hndl->rsps_in_flight_nr >=
			rdma_hndl->max_tx_ready_tasks_num - 1) {
		DEBUG_LOG("over limits rsps_in_flight_nr=%u, " \
			  "max_tx_ready_tasks_num=%u\n",
			  rdma_hndl->rsps_in_flight_nr,
			  rdma_hndl->max_tx_ready_tasks_num);

		xio_set_error(EAGAIN);
		return -1;
	}
	/* tx ready is full - refuse request */
	if (rdma_hndl->tx_ready_tasks_num >=
			rdma_hndl->max_tx_ready_tasks_num) {
		DEBUG_LOG("over limits tx_ready_tasks_num=%u, "\
			  "max_tx_ready_tasks_num=%u\n",
			  rdma_hndl->tx_ready_tasks_num,
			  rdma_hndl->max_tx_ready_tasks_num);
		xio_set_error(EAGAIN);
		return -1;
	}
	if (rdma_hndl->sqe_avail < 2) {
		DEBUG_LOG("rdma_hndl=%p, no sqe_avail=%d\n",
			  rdma_hndl, rdma_hndl->sqe_avail);
		xio_set_error(EAGAIN);
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* kick_send_and_read							     */
/*---------------------------------------------------------------------------*/
static int kick_send_and_read(struct xio_rdma_transport *rdma_hndl,
			      struct xio_task *task,
			      int must_send)
{
	int retval = 0;

	/* transmit only if available */
	if (test_bits(XIO_MSG_FLAG_LAST_IN_BATCH, &task->omsg->flags) ||
	    task->is_control) {
		must_send = 1;
	} else {
		if (tx_window_sz(rdma_hndl) >= SEND_THRESHOLD)
			must_send = 1;
	}

	/* resource are now available and rdma rd  requests are pending kick
	 * them
	 */
	if (rdma_hndl->kick_rdma_rd_req) {
		retval = xio_xmit_rdma_rd_req(rdma_hndl);
		if (retval) {
			retval = xio_errno();
			if (retval != EAGAIN) {
				ERROR_LOG("xio_xmit_rdma_rd failed. %s\n",
					  xio_strerror(retval));
				return -1;
			}
			retval = 0;
		}
	}
	if (rdma_hndl->kick_rdma_rd_rsp) {
		retval = xio_xmit_rdma_rd_rsp(rdma_hndl);
		if (retval) {
			retval = xio_errno();
			if (retval != EAGAIN) {
				ERROR_LOG("xio_xmit_rdma_rd_rsp failed. %s\n",
					  xio_strerror(retval));
				return -1;
			}
			retval = 0;
		}
	}
	if (must_send) {
		retval = xio_rdma_xmit(rdma_hndl);
		if (retval) {
			retval = xio_errno();
			if (retval != EAGAIN) {
				ERROR_LOG("xio_xmit_rdma failed. %s\n",
					  xio_strerror(retval));
				return -1;
			}
			retval = 0;
		}
	}
	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_perform_direct_rdma						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_perform_direct_rdma(struct xio_rdma_transport *rdma_hndl,
					struct xio_task *task)
{
	enum xio_ib_op_code	out_ib_opcode;
	enum ib_wr_opcode	wr_opcode;
	size_t			llen;
	size_t			rsg_out_list_len = 0;
	int			retval = 0;
	int			tasks_used = 0;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;

	if (unlikely(verify_req_send_limits(rdma_hndl)))
		return -1;

	sgtbl		= xio_sg_table_get(&task->omsg->out);
	sgtbl_ops	= xio_sg_table_ops_get(task->omsg->out.sgl_type);

	llen = tbl_length(sgtbl_ops, sgtbl);

	if (unlikely(task->omsg->rdma.length < llen)) {
		ERROR_LOG("peer provided too small iovec\n");
		task->status = XIO_E_REM_USER_BUF_OVERFLOW;
		return -1;
	}

	retval = xio_validate_rdma_op(
		&task->omsg->out,
		task->omsg->rdma.rsg_list,
		task->omsg->rdma.nents,
		llen,
		rdma_hndl->max_sge,
		&tasks_used);
	if (unlikely(retval)) {
		ERROR_LOG("failed to validate input scatter lists\n");
		task->status = XIO_E_MSG_INVALID;
		return -1;
	}
	out_ib_opcode = task->omsg->rdma.is_read ? XIO_IB_RDMA_READ_DIRECT :
		XIO_IB_RDMA_WRITE_DIRECT;
	wr_opcode = task->omsg->rdma.is_read ? IB_WR_RDMA_READ :
		IB_WR_RDMA_WRITE;

	retval = xio_prep_rdma_op(task, rdma_hndl,
				  out_ib_opcode,
				  wr_opcode,
				  &task->omsg->out,
				  task->omsg->rdma.rsg_list,
				  task->omsg->rdma.nents,
				  &rsg_out_list_len,
				  llen,
				  rdma_hndl->max_sge,
				  0,
				  &rdma_hndl->tx_ready_list, tasks_used);
	if (unlikely(retval)) {
		ERROR_LOG("failed to allocate tasks\n");
		task->status = XIO_E_NO_BUFS;
		return -1;
	}

	rdma_hndl->tx_ready_tasks_num += tasks_used;

	return kick_send_and_read(rdma_hndl, task, 0 /* must_send  */);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_req_header						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_write_req_header(struct xio_rdma_transport *rdma_hndl,
				     struct xio_task *task,
				     struct xio_rdma_req_hdr *req_hdr)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_rdma_req_hdr		*tmp_req_hdr;
	struct xio_sge			*tmp_sge;
	struct xio_sge			sge;
	size_t				hdr_len;
	uint32_t			i;
	struct ib_device		*ib_dev = rdma_hndl->dev->ib_dev;
	struct ib_mr			*mr = rdma_hndl->dev->mr; /* Need fix
								    for
								    FMR/FRWR */
	uint16_t			in_num_sge, out_num_sge;
	struct xio_sg_table_ops		*sgtbl_ops;
	void				*sgtbl;
	void				*sg;

	sgtbl		= xio_sg_table_get(&task->omsg->in);
	sgtbl_ops	= xio_sg_table_ops_get(task->omsg->in.sgl_type);

	/* point to transport header */
	xio_mbuf_set_trans_hdr(&task->mbuf);
	tmp_req_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* pack relevant values */
	tmp_req_hdr->version  = req_hdr->version;
	tmp_req_hdr->flags    = req_hdr->flags;
	PACK_SVAL(req_hdr, tmp_req_hdr, req_hdr_len);
	/* sn		shall be coded later */
	/* ack_sn	shall be coded later */
	/* credits	shall be coded later */
	PACK_LVAL(req_hdr, tmp_req_hdr, ltid);
	tmp_req_hdr->in_ib_op	   = req_hdr->in_ib_op;
	tmp_req_hdr->out_ib_op	   = req_hdr->out_ib_op;
	/* In case of FMR/FRWR the remote side will get one element */
	if (rdma_task->read_mem_desc.mem_reg.mem_h)
		in_num_sge = 1;
	else
		in_num_sge  = req_hdr->in_num_sge;

	if (rdma_task->write_mem_desc.mem_reg.mem_h)
		out_num_sge = 1;
	else
		out_num_sge = req_hdr->out_num_sge;

	tmp_req_hdr->in_num_sge = htons(in_num_sge);
	tmp_req_hdr->out_num_sge = htons(out_num_sge);
	PACK_SVAL(req_hdr, tmp_req_hdr, ulp_hdr_len);
	PACK_SVAL(req_hdr, tmp_req_hdr, ulp_pad_len);
	/*remain_data_len is not used		*/
	PACK_LLVAL(req_hdr, tmp_req_hdr, ulp_imm_len);

	tmp_sge = (void *)((uint8_t *)tmp_req_hdr +
			   sizeof(struct xio_rdma_req_hdr));

	/* IN: requester expect small input written via send */
	sg = sge_first(sgtbl_ops, sgtbl);
	if (req_hdr->in_ib_op == XIO_IB_SEND) {
		for (i = 0;  i < req_hdr->in_num_sge; i++) {
			sge.addr = 0;
			sge.length = sge_length(sgtbl_ops, sg);
			sge.stag = 0;
			PACK_LLVAL(&sge, tmp_sge, addr);
			PACK_LVAL(&sge, tmp_sge, length);
			PACK_LVAL(&sge, tmp_sge, stag);
			tmp_sge++;
		}
	}
	/* IN: requester expect big input written rdma write */
	if (req_hdr->in_ib_op == XIO_IB_RDMA_WRITE) {
		if (rdma_task->read_mem_desc.mem_reg.mem_h) {
			/* FMR/FRWR case */
			sge.addr = rdma_task->read_mem_desc.mem_reg.va;
			sge.length = rdma_task->read_mem_desc.mem_reg.len;
			sge.stag = rdma_task->read_mem_desc.mem_reg.rkey;
			PACK_LLVAL(&sge, tmp_sge, addr);
			PACK_LVAL(&sge, tmp_sge, length);
			PACK_LVAL(&sge, tmp_sge, stag);
			tmp_sge++;
		} else {
			sg = rdma_task->read_mem_desc.sgt.sgl;
			for (i = 0;  i < req_hdr->in_num_sge; i++) {
				sge.addr = ib_sg_dma_address(ib_dev, sg);
				sge.length = ib_sg_dma_len(ib_dev, sg);
				sge.stag = mr->rkey;
				PACK_LLVAL(&sge, tmp_sge, addr);
				PACK_LVAL(&sge, tmp_sge, length);
				PACK_LVAL(&sge, tmp_sge, stag);
				tmp_sge++;
				sg = sg_next(sg);
			}
		}
	}
	/* OUT: requester want to write data via rdma read */
	if (req_hdr->out_ib_op == XIO_IB_RDMA_READ) {
		if (rdma_task->write_mem_desc.mem_reg.mem_h) {
			/* FMR/FRWR case */
			sge.addr = rdma_task->write_mem_desc.mem_reg.va;
			sge.length = rdma_task->write_mem_desc.mem_reg.len;
			sge.stag = rdma_task->write_mem_desc.mem_reg.rkey;
			PACK_LLVAL(&sge, tmp_sge, addr);
			PACK_LVAL(&sge, tmp_sge, length);
			PACK_LVAL(&sge, tmp_sge, stag);
			tmp_sge++;
		} else {
			sg = rdma_task->write_mem_desc.sgt.sgl;
			for (i = 0;  i < req_hdr->out_num_sge; i++) {
				sge.addr = ib_sg_dma_address(ib_dev, sg);
				sge.length = ib_sg_dma_len(ib_dev, sg);
				sge.stag = mr->rkey;
				PACK_LLVAL(&sge, tmp_sge, addr);
				PACK_LVAL(&sge, tmp_sge, length);
				PACK_LVAL(&sge, tmp_sge, stag);
				tmp_sge++;
				sg = sg_next(sg);
			}
		}
	}
	if (req_hdr->out_ib_op == XIO_IB_SEND) {
		for (i = 0;  i < req_hdr->out_num_sge; i++) {
			sge.addr = 0;
			sge.length = sge_length(sgtbl_ops, sg);
			sge.stag = 0;
			PACK_LLVAL(&sge, tmp_sge, addr);
			PACK_LVAL(&sge, tmp_sge, length);
			PACK_LVAL(&sge, tmp_sge, stag);
			tmp_sge++;
			sg = sge_next(sgtbl_ops, sgtbl, sg);
		}
	}

	hdr_len	= sizeof(struct xio_rdma_req_hdr);
	hdr_len += sizeof(struct xio_sge) * (in_num_sge +
					     out_num_sge);

#ifdef EYAL_TODO
	print_hex_dump_bytes("post_send: ", DUMP_PREFIX_ADDRESS,
			     task->mbuf.curr,
			     64);
#endif
	xio_mbuf_inc(&task->mbuf, hdr_len);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_read_req_header						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_read_req_header(struct xio_rdma_transport *rdma_hndl,
				    struct xio_task *task,
				    struct xio_rdma_req_hdr *req_hdr)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_rdma_req_hdr		*tmp_req_hdr;
	struct xio_sge			*tmp_sge;
	size_t				hdr_len;
	int				i;

	/* point to transport header */
	xio_mbuf_set_trans_hdr(&task->mbuf);
	tmp_req_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	req_hdr->version  = tmp_req_hdr->version;
	req_hdr->flags    = tmp_req_hdr->flags;
	UNPACK_SVAL(tmp_req_hdr, req_hdr, req_hdr_len);

	if (unlikely(req_hdr->req_hdr_len != sizeof(struct xio_rdma_req_hdr))) {
		ERROR_LOG(
		"header length's read failed. arrived:%d  expected:%zud\n",
		req_hdr->req_hdr_len, sizeof(struct xio_rdma_req_hdr));
		return -1;
	}
	UNPACK_SVAL(tmp_req_hdr, req_hdr, sn);
	UNPACK_SVAL(tmp_req_hdr, req_hdr, credits);
	UNPACK_LVAL(tmp_req_hdr, req_hdr, ltid);
	req_hdr->out_ib_op		= tmp_req_hdr->out_ib_op;
	UNPACK_SVAL(tmp_req_hdr, req_hdr, in_num_sge);
	UNPACK_SVAL(tmp_req_hdr, req_hdr, out_num_sge);
	UNPACK_SVAL(tmp_req_hdr, req_hdr, ulp_hdr_len);
	UNPACK_SVAL(tmp_req_hdr, req_hdr, ulp_pad_len);

	/* remain_data_len not in use */
	UNPACK_LLVAL(tmp_req_hdr, req_hdr, ulp_imm_len);

	tmp_sge = (void *)((uint8_t *)tmp_req_hdr +
			   sizeof(struct xio_rdma_req_hdr));

	rdma_task->sn = req_hdr->sn;

	/* params for SEND/RDMA_WRITE */
	for (i = 0; i < req_hdr->in_num_sge; i++) {
		UNPACK_LLVAL(tmp_sge, &rdma_task->req_in_sge[i], addr);
		UNPACK_LVAL(tmp_sge, &rdma_task->req_in_sge[i], length);
		UNPACK_LVAL(tmp_sge, &rdma_task->req_in_sge[i], stag);
		tmp_sge++;
	}
	rdma_task->req_in_num_sge = req_hdr->in_num_sge;

	/* params for SEND/RDMA_READ */
	for (i = 0; i < req_hdr->out_num_sge; i++) {
		UNPACK_LLVAL(tmp_sge, &rdma_task->req_out_sge[i], addr);
		UNPACK_LVAL(tmp_sge, &rdma_task->req_out_sge[i], length);
		UNPACK_LVAL(tmp_sge, &rdma_task->req_out_sge[i], stag);
		tmp_sge++;
	}
	rdma_task->req_out_num_sge = req_hdr->out_num_sge;

	hdr_len	= sizeof(struct xio_rdma_req_hdr);
	hdr_len += sizeof(struct xio_sge) * (req_hdr->in_num_sge +
					     req_hdr->out_num_sge);

	xio_mbuf_inc(&task->mbuf, hdr_len);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_rsp_header						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_write_rsp_header(struct xio_rdma_transport *rdma_hndl,
				     struct xio_task *task,
				     struct xio_rdma_rsp_hdr *rsp_hdr)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_sge			sge;
	struct xio_rdma_rsp_hdr		*tmp_rsp_hdr;
	struct xio_sge			*tmp_sge;
	struct ib_device		*ib_dev = rdma_hndl->dev->ib_dev;
	/* Need fix for FMR/FRWR */
	struct ib_mr			*mr = rdma_hndl->dev->mr;
	void				*sg;
	size_t				hdr_len;
	uint32_t			*wr_len;
	int				i;

	/* point to transport header */
	xio_mbuf_set_trans_hdr(&task->mbuf);
	tmp_rsp_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* pack relevant values */
	tmp_rsp_hdr->version  = rsp_hdr->version;
	tmp_rsp_hdr->flags    = rsp_hdr->flags;
	PACK_SVAL(rsp_hdr, tmp_rsp_hdr, rsp_hdr_len);
	/* sn		shall be coded later */
	/* ack_sn	shall be coded later */
	/* credits	shall be coded later */
	PACK_LVAL(rsp_hdr, tmp_rsp_hdr, rtid);
	tmp_rsp_hdr->out_ib_op = rsp_hdr->out_ib_op;
	PACK_LVAL(rsp_hdr, tmp_rsp_hdr, status);
	PACK_SVAL(rsp_hdr, tmp_rsp_hdr, out_num_sge);
	PACK_LVAL(rsp_hdr, tmp_rsp_hdr, ltid);
	PACK_SVAL(rsp_hdr, tmp_rsp_hdr, ulp_hdr_len);
	PACK_SVAL(rsp_hdr, tmp_rsp_hdr, ulp_pad_len);
	/* remain_data_len not in use */
	PACK_LLVAL(rsp_hdr, tmp_rsp_hdr, ulp_imm_len);

	hdr_len	= sizeof(struct xio_rdma_rsp_hdr);

	/* OUT: responder want to write data via rdma write */
	if (rsp_hdr->out_ib_op == XIO_IB_RDMA_WRITE) {
		wr_len = (uint32_t *)((uint8_t *)tmp_rsp_hdr +
				sizeof(struct xio_rdma_rsp_hdr));

		/* params for RDMA WRITE */
		for (i = 0;  i < rsp_hdr->out_num_sge; i++) {
			*wr_len = htonl(rdma_task->rsp_out_sge[i].length);
			wr_len++;
		}
		hdr_len += sizeof(uint32_t) * rsp_hdr->out_num_sge;
	}
	if (rsp_hdr->out_ib_op == XIO_IB_RDMA_READ) {
		tmp_sge = (struct xio_sge *)((uint8_t *)tmp_rsp_hdr + hdr_len);

		/* OUT: requester want to write data via rdma read */
		if (rdma_task->write_mem_desc.mem_reg.mem_h) {
			/* FMR/FRWR case */
			sge.addr = rdma_task->write_mem_desc.mem_reg.va;
			sge.length = rdma_task->write_mem_desc.mem_reg.len;
			sge.stag = rdma_task->write_mem_desc.mem_reg.rkey;
			PACK_LLVAL(&sge, tmp_sge, addr);
			PACK_LVAL(&sge, tmp_sge, length);
			PACK_LVAL(&sge, tmp_sge, stag);
			tmp_sge++;
			hdr_len += sizeof(struct xio_sge);
		} else {
			sg = rdma_task->write_mem_desc.sgt.sgl;
			for (i = 0;  i < rsp_hdr->out_num_sge; i++) {
				sge.addr = ib_sg_dma_address(ib_dev, sg);
				sge.length = ib_sg_dma_len(ib_dev, sg);
				sge.stag = mr->rkey;
				PACK_LLVAL(&sge, tmp_sge, addr);
				PACK_LVAL(&sge, tmp_sge, length);
				PACK_LVAL(&sge, tmp_sge, stag);
				tmp_sge++;
				sg = sg_next(sg);
			}
			hdr_len +=
				sizeof(struct xio_sge) * rsp_hdr->out_num_sge;
		}
	}

	xio_mbuf_inc(&task->mbuf, hdr_len);

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
				    struct xio_task *task,
				    struct xio_rdma_rsp_hdr *rsp_hdr)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_rdma_rsp_hdr		*tmp_rsp_hdr;
	struct xio_sge			*tmp_sge;
	size_t				hdr_len;
	uint32_t			*wr_len;
	int				i;

	/* point to transport header */
	xio_mbuf_set_trans_hdr(&task->mbuf);
	tmp_rsp_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	rsp_hdr->version  = tmp_rsp_hdr->version;
	rsp_hdr->flags    = tmp_rsp_hdr->flags;
	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, rsp_hdr_len);

	if (unlikely(rsp_hdr->rsp_hdr_len != sizeof(struct xio_rdma_rsp_hdr))) {
		ERROR_LOG(
		"header length's read failed. arrived:%d expected:%zu\n",
		  rsp_hdr->rsp_hdr_len, sizeof(struct xio_rdma_rsp_hdr));
		return -1;
	}
	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, sn);
	/* ack_sn not used */
	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, credits);
	UNPACK_LVAL(tmp_rsp_hdr, rsp_hdr, rtid);
	rsp_hdr->out_ib_op = tmp_rsp_hdr->out_ib_op;
	UNPACK_LVAL(tmp_rsp_hdr, rsp_hdr, status);
	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, out_num_sge);
	UNPACK_LVAL(tmp_rsp_hdr, rsp_hdr, ltid);
	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, ulp_hdr_len);
	UNPACK_SVAL(tmp_rsp_hdr, rsp_hdr, ulp_pad_len);
	/* remain_data_len not in use */
	UNPACK_LLVAL(tmp_rsp_hdr, rsp_hdr, ulp_imm_len);

	hdr_len	= sizeof(struct xio_rdma_rsp_hdr);
	if (rsp_hdr->out_ib_op == XIO_IB_RDMA_WRITE) {
		wr_len = (uint32_t  *)((uint8_t *)tmp_rsp_hdr +
				sizeof(struct xio_rdma_rsp_hdr));

		/* params for RDMA WRITE */
		for (i = 0;  i < rsp_hdr->out_num_sge; i++) {
			rdma_task->rsp_out_sge[i].length = ntohl(*wr_len);
			wr_len++;
		}
		rdma_task->rsp_out_num_sge = rsp_hdr->out_num_sge;

		hdr_len += sizeof(uint32_t) * rsp_hdr->out_num_sge;
	}
	if (rsp_hdr->out_ib_op == XIO_IB_RDMA_READ) {
		tmp_sge = (struct xio_sge *)((uint8_t *)tmp_rsp_hdr +
					     sizeof(struct xio_rdma_rsp_hdr));

		/* params for RDMA_READ */
		for (i = 0;  i < rsp_hdr->out_num_sge; i++) {
			UNPACK_LLVAL(tmp_sge, &rdma_task->req_out_sge[i],
				     addr);
			UNPACK_LVAL(tmp_sge, &rdma_task->req_out_sge[i],
				    length);
			UNPACK_LVAL(tmp_sge, &rdma_task->req_out_sge[i],
				    stag);
			tmp_sge++;
		}
		rdma_task->req_out_num_sge	= i;
		hdr_len += sizeof(struct xio_sge) * rsp_hdr->out_num_sge;
	}

	xio_mbuf_inc(&task->mbuf, hdr_len);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_prep_req_header						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_prep_req_header(struct xio_rdma_transport *rdma_hndl,
				    struct xio_task	*task,
				    uint16_t ulp_hdr_len,
				    uint16_t ulp_pad_len,
				    uint64_t ulp_imm_len,
				    uint32_t status)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_rdma_req_hdr	req_hdr;

	if (unlikely(!IS_REQUEST(task->tlv_type))) {
		ERROR_LOG("unknown message type %u\n", task->tlv_type);
		return -1;
	}

	/* write the headers */

	/* fill request header */
	req_hdr.version		= XIO_REQ_HEADER_VERSION;
	req_hdr.req_hdr_len	= sizeof(req_hdr);
	req_hdr.ltid		= task->ltid;
	req_hdr.in_ib_op	= rdma_task->in_ib_op;
	req_hdr.out_ib_op	= rdma_task->out_ib_op;
	req_hdr.flags		= 0;

	if (test_bits(XIO_MSG_FLAG_PEER_WRITE_RSP, &task->omsg_flags))
		set_bits(XIO_MSG_FLAG_PEER_WRITE_RSP, &req_hdr.flags);
	else if (test_bits(XIO_MSG_FLAG_LAST_IN_BATCH, &task->omsg_flags))
		set_bits(XIO_MSG_FLAG_LAST_IN_BATCH, &req_hdr.flags);

	req_hdr.ulp_hdr_len	= ulp_hdr_len;
	req_hdr.ulp_pad_len	= ulp_pad_len;
	req_hdr.ulp_imm_len	= ulp_imm_len;
	req_hdr.in_num_sge	= rdma_task->req_in_num_sge;
	req_hdr.out_num_sge	= rdma_task->req_out_num_sge;

	if (rdma_task->in_ib_op != XIO_IB_SEND &&
	    rdma_task->req_in_num_sge > 0) {
		unsigned int sqe_used = 0;

		if (xio_map_desc(rdma_hndl, &rdma_task->read_mem_desc,
				 DMA_FROM_DEVICE, &sqe_used))
			goto cleanup0;
		rdma_task->sqe_used += sqe_used;
	}
	if (rdma_task->out_ib_op != XIO_IB_SEND &&
	    rdma_task->req_out_num_sge > 0) {
		unsigned int sqe_used = 0;

		if (xio_map_desc(rdma_hndl, &rdma_task->write_mem_desc,
				 DMA_TO_DEVICE, &sqe_used))
			goto cleanup1;
		rdma_task->sqe_used += sqe_used;
	}

	if (xio_rdma_write_req_header(rdma_hndl, task, &req_hdr) != 0)
		goto cleanup2;

	/* write the payload header */
	if (ulp_hdr_len) {
		if (xio_mbuf_write_array(
		    &task->mbuf,
		    task->omsg->out.header.iov_base,
		    task->omsg->out.header.iov_len) != 0)
			goto cleanup2;
	}

	/* write the pad between header and data */
	if (ulp_pad_len)
		xio_mbuf_inc(&task->mbuf, ulp_pad_len);

	return 0;

cleanup2:
	if (rdma_task->out_ib_op != XIO_IB_SEND &&
	    rdma_task->req_out_num_sge > 0) {
		xio_unmap_desc(rdma_hndl,
			       &rdma_task->write_mem_desc,
			       DMA_TO_DEVICE);
	}

cleanup1:
	if (rdma_task->in_ib_op != XIO_IB_SEND &&
	    rdma_task->req_in_num_sge > 0) {
		xio_unmap_desc(rdma_hndl,
			       &rdma_task->read_mem_desc,
			       DMA_FROM_DEVICE);
	}

cleanup0:
	xio_set_error(XIO_E_MSG_SIZE);
	ERROR_LOG("xio_rdma_write_req_header failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_prep_rsp_header						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_prep_rsp_header(struct xio_rdma_transport *rdma_hndl,
				    struct xio_task *task,
				    uint16_t ulp_hdr_len,
				    uint16_t ulp_pad_len,
				    uint64_t ulp_imm_len,
				    uint32_t status)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_rdma_rsp_hdr	rsp_hdr;
	uint64_t		xio_hdr_len;

	if (unlikely(!IS_RESPONSE(task->tlv_type))) {
		ERROR_LOG("unknown message type\n");
		return -1;
	}

	/* fill response header */
	rsp_hdr.version		= XIO_RSP_HEADER_VERSION;
	rsp_hdr.rsp_hdr_len	= sizeof(rsp_hdr);
	rsp_hdr.rtid		= task->rtid;
	rsp_hdr.ltid		= task->ltid;
	rsp_hdr.out_ib_op		= rdma_task->out_ib_op;
	rsp_hdr.flags		= XIO_HEADER_FLAG_NONE;
	if (rdma_task->out_ib_op == XIO_IB_RDMA_READ)
		rsp_hdr.out_num_sge	= rdma_task->req_out_num_sge;
	else
		rsp_hdr.out_num_sge	= rdma_task->rsp_out_num_sge;
	rsp_hdr.ulp_hdr_len	= ulp_hdr_len;
	rsp_hdr.ulp_pad_len	= ulp_pad_len;
	rsp_hdr.ulp_imm_len	= ulp_imm_len;
	rsp_hdr.status		= status;

	if (xio_rdma_write_rsp_header(rdma_hndl, task, &rsp_hdr) != 0)
		goto cleanup;

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

	/* reinit header sgl to proper size (size was updated )*/
	xio_hdr_len = xio_mbuf_get_curr_offset(&task->mbuf);
	xio_reinit_header(rdma_task, xio_hdr_len);

	return 0;

cleanup:
	xio_set_error(XIO_E_MSG_SIZE);
	ERROR_LOG("xio_rdma_write_rsp_header failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_send_data						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_write_send_data(struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);

	if (xio_vmsg_to_tx_sgt(&task->omsg->out,
			       &rdma_task->txd.sgt,
			       &rdma_task->txd.nents)) {
		xio_set_error(XIO_E_MSG_SIZE);
		ERROR_LOG("xio_vmsg_to_sgt failed\n");
		goto cleanup;
	}

	/* No need to add one for the header (internal) */
	/* rdma_task->txd.nents++; */

	return 0;

cleanup:
	xio_set_error(XIO_E_MSG_SIZE);
	ERROR_LOG("xio_rdma_send_msg failed\n");
	return -1;
}

/* up until testing the feature */
#undef HAVE_RDMA_READ_RSP

/*---------------------------------------------------------------------------*/
/* xio_rdma_prep_rsp_out_data						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_prep_rsp_out_data(
		struct xio_rdma_transport *rdma_hndl,
		struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_rdma_rsp_hdr	rsp_hdr;
	struct xio_sg_table_ops	*sgtbl_ops;
	struct xio_vmsg		*vmsg = &task->omsg->out;
	void			*sgtbl;
	size_t			retval;
	uint64_t		xio_hdr_len;
	uint64_t		ulp_imm_len;
	uint16_t		ulp_hdr_len;
	uint16_t		ulp_pad_len = 0;
	int			enforce_write_rsp;

	sgtbl		= xio_sg_table_get(vmsg);
	sgtbl_ops	= (struct xio_sg_table_ops *)
				xio_sg_table_ops_get(vmsg->sgl_type);

	/* calculate headers */
	ulp_hdr_len = task->omsg->out.header.iov_len;
	ulp_imm_len = tbl_length(sgtbl_ops, sgtbl);

	xio_hdr_len = xio_mbuf_get_curr_offset(&task->mbuf);
	xio_hdr_len += sizeof(rsp_hdr);
	xio_hdr_len += rdma_task->req_in_num_sge * sizeof(struct xio_sge);

	if (g_poptions->inline_xio_data_align && ulp_imm_len) {
		uint16_t hdr_len = xio_hdr_len + ulp_hdr_len;

		ulp_pad_len = ALIGN(hdr_len,
				    g_poptions->inline_xio_data_align) -
			      hdr_len;
	}

	enforce_write_rsp = (task->imsg_flags &&
			   (task->imsg_flags &
			    XIO_HEADER_FLAG_PEER_WRITE_RSP));
	/*
	if (rdma_hndl->max_inline_buf_sz < xio_hdr_len + ulp_hdr_len) {
		ERROR_LOG("header size %u exceeds max header %zu\n",
			  ulp_hdr_len,
			  rdma_hndl->max_inline_buf_sz - (size_t)xio_hdr_len);
		xio_set_error(XIO_E_MSG_SIZE);
		goto cleanup;
	}
	*/

	/* initialize the txd */
	rdma_task->txd.send_wr.num_sge = 1;

	/* Small data is outgoing via SEND unless the requester explicitly
	 * insisted on RDMA operation and provided resources.
	 * One sge is reserved for the header
	 */
	if ((ulp_imm_len == 0) ||
	    (!enforce_write_rsp &&
	     (tbl_nents(sgtbl_ops, sgtbl) <=
	      (size_t)(rdma_hndl->max_sge - 1)) &&
	     ((xio_hdr_len + ulp_hdr_len + ulp_pad_len + ulp_imm_len) <
	      (uint64_t)rdma_hndl->max_inline_buf_sz))) {
		rdma_task->out_ib_op = XIO_IB_SEND;
		/* write xio header to the buffer */
		retval = xio_rdma_prep_rsp_header(
				rdma_hndl, task,
				ulp_hdr_len, ulp_pad_len, ulp_imm_len,
				XIO_E_SUCCESS);
		if (retval)
			goto cleanup;

		/* if there is data, set it to buffer or directly to the sge */
		if (ulp_imm_len) {
			retval = xio_rdma_write_send_data(task);
			if (retval)
				goto cleanup;
		} else {
			/* no data at all */
			tbl_set_nents(sgtbl_ops, sgtbl, 0);
			rdma_task->txd.nents = 1;
		}
	} else {
		if (rdma_task->req_in_sge[0].addr &&
		    rdma_task->req_in_sge[0].length &&
		    rdma_task->req_in_sge[0].stag) {
			/* the data is sent via RDMA_WRITE */

			/* prepare rdma write */
			xio_sched_rdma_wr_req(rdma_hndl, task);

			/* and the header is sent via SEND */
			/* write xio header to the buffer */
			retval = xio_rdma_prep_rsp_header(
					rdma_hndl, task,
					ulp_hdr_len, 0, ulp_imm_len,
					XIO_E_SUCCESS);
		} else {
			/* EYAL - the case were requester send request but
			 * does not provide buffer for response. responder
			 * tries to send via rdma_write but fail. it converts
			 * the response to rdma_read. responder handle
			 * rdma_read and finally send ack to release resources
			 */
#ifndef HAVE_RDMA_READ_RSP
			DEBUG_LOG("partial completion of request due " \
				  "to missing, response buffer\n");

			rdma_task->out_ib_op = XIO_IB_SEND;

			/* the client did not provide buffer for response */
			retval = xio_rdma_prep_rsp_header(
					rdma_hndl, task,
					ulp_hdr_len, 0, 0,
					XIO_E_RSP_BUF_SIZE_MISMATCH);

			tbl_set_nents(sgtbl_ops, sgtbl, 0);
#else
			/* the data is outgoing via SEND but the peer will do
			 * RDMA_READ */

			/* Only header header in the SEND */
			rdma_task->txd.nents = 1;

			rdma_task->out_ib_op = XIO_IB_RDMA_READ;

			/* user must provided buffers with length for
			 * RDMA READ */
			if (xio_vmsg_to_sgt(
				vmsg,
				&rdma_task->write_mem_desc.sgt,
				&rdma_task->write_mem_desc.nents) < 0) {
				ERROR_LOG("xio_vmsg_to_sgt failed\n");
				goto cleanup1;
			}
			rdma_task->req_out_num_sge =
					rdma_task->write_mem_desc.nents;
			rdma_task->sqe_used	 = 0;

			/* write XIO header to the buffer */
			retval = xio_rdma_prep_req_header(rdma_hndl, task,
							  ulp_hdr_len, 0, 0,
							  XIO_E_SUCCESS);

			if (retval) {
				ERROR_LOG("Failed to write header\n");
				goto cleanup1;
			}

			/* reinit header sgl to proper size
			 * (size was updated )*/
			xio_hdr_len = xio_mbuf_get_curr_offset(&task->mbuf);
			xio_reinit_header(rdma_task, xio_hdr_len);
#endif
		}
	}

	return 0;
#ifdef HAVE_RDMA_READ_RSP
cleanup1:
	xio_mempool_free(&rdma_task->write_mem_desc);
	rdma_task->req_out_num_sge = 0;
	return -1;
#endif

cleanup:
	xio_set_error(XIO_E_MSG_SIZE);
	ERROR_LOG("xio_rdma_send_msg failed\n");
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_prep_req_out_data						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_prep_req_out_data(struct xio_rdma_transport *rdma_hndl,
				      struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_vmsg		*vmsg = &task->omsg->out;
	uint64_t		xio_hdr_len;
	uint64_t		xio_max_hdr_len;
	uint64_t		ulp_hdr_len;
	uint64_t		ulp_pad_len = 0;
	uint64_t		ulp_imm_len;
	size_t			retval;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	int			tx_by_sr;
	uint32_t		nents;

	sgtbl		= xio_sg_table_get(&task->omsg->out);
	sgtbl_ops	= xio_sg_table_ops_get(task->omsg->out.sgl_type);
	nents		= tbl_nents(sgtbl_ops, sgtbl);

	/* calculate headers */
	ulp_hdr_len	= vmsg->header.iov_len;
	ulp_imm_len	= tbl_length(sgtbl_ops, sgtbl);

	xio_hdr_len = xio_mbuf_get_curr_offset(&task->mbuf);
	xio_hdr_len += sizeof(struct xio_rdma_req_hdr);
	xio_hdr_len += sizeof(struct xio_sge) * rdma_task->req_in_num_sge;
	xio_max_hdr_len = xio_hdr_len + sizeof(struct xio_sge) * nents;

	/*
	if (rdma_hndl->max_inline_buf_sz < (xio_hdr_len + ulp_hdr_len)) {
		ERROR_LOG("header size %llu exceeds max header %llu\n",
			  ulp_imm_len, rdma_hndl->max_inline_buf_sz -
			  xio_hdr_len);
		return -1;
	}
	*/

	if (g_poptions->inline_xio_data_align && ulp_imm_len) {
		uint16_t hdr_len = xio_hdr_len + ulp_hdr_len;

		ulp_pad_len = ALIGN(hdr_len,
				    g_poptions->inline_xio_data_align) -
			      hdr_len;
	}

	/* initialize the txd */
	rdma_task->txd.send_wr.num_sge = 1;

	if (test_bits(XIO_MSG_FLAG_PEER_READ_REQ, &task->omsg_flags) && nents)
		tx_by_sr = 0;
	else
		/* test for using send/receive or rdma_read */
		tx_by_sr = (nents  <= (rdma_hndl->max_sge - 1) &&
			    ((ulp_hdr_len + ulp_pad_len +
			      ulp_imm_len + xio_max_hdr_len) <=
			     rdma_hndl->max_inline_buf_sz) &&
			    (((int)(ulp_imm_len) <=
			      xio_get_options()->max_inline_xio_data) ||
			     ulp_imm_len == 0));

	/* the data is outgoing via SEND */
	if (tx_by_sr) {
		rdma_task->out_ib_op = XIO_IB_SEND;
		/* user has small request - no rdma operation expected */
		rdma_task->req_out_num_sge = 0;
		rdma_task->sqe_used	 = 0;

		/* write xio header to the buffer */
		retval = xio_rdma_prep_req_header(
				rdma_hndl, task,
				ulp_hdr_len, ulp_pad_len, ulp_imm_len,
				XIO_E_SUCCESS);
		if (retval)
			return -1;

		/* reinit header sgl to proper size (size was updated )*/
		xio_hdr_len = xio_mbuf_get_curr_offset(&task->mbuf);
		xio_reinit_header(rdma_task, xio_hdr_len);

		/* if there is data, set it to buffer or directly to the sge */
		if (ulp_imm_len) {
			retval = xio_rdma_write_send_data(task);
			if (retval)
				return -1;
		} else {
			/* Only header */
			rdma_task->txd.nents = 1;
		}
	} else {
		/* the data is outgoing via SEND but the peer will do
		 * RDMA_READ
		 */
		/* Only header header in the SEND */
		rdma_task->txd.nents = 1;

		rdma_task->out_ib_op = XIO_IB_RDMA_READ;

		/* user must provided buffers with length for RDMA READ */
		if (xio_vmsg_to_sgt(vmsg, &rdma_task->write_mem_desc.sgt,
				    &rdma_task->write_mem_desc.nents) < 0) {
			ERROR_LOG("xio_vmsg_to_sgt failed\n");
			goto cleanup;
		}
		rdma_task->req_out_num_sge = rdma_task->write_mem_desc.nents;
		rdma_task->sqe_used	 = 0;

		/* write XIO header to the buffer */
		retval = xio_rdma_prep_req_header(rdma_hndl, task,
						  ulp_hdr_len, 0, 0,
						  XIO_E_SUCCESS);

		if (unlikely(retval)) {
			ERROR_LOG("Failed to write header\n");
			goto cleanup;
		}

		/* reinit header sgl to proper size (size was updated )*/
		xio_hdr_len = xio_mbuf_get_curr_offset(&task->mbuf);
		xio_reinit_header(rdma_task, xio_hdr_len);
	}

	return 0;

cleanup:
	xio_mempool_free(&rdma_task->write_mem_desc);
	rdma_task->req_out_num_sge = 0;

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_prep_req_in_data						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_prep_req_in_data(struct xio_rdma_transport *rdma_hndl,
				     struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	size_t				hdr_len;
	size_t				xio_hdr_len;
	size_t				data_len;
	struct xio_vmsg			*vmsg = &task->omsg->in;
	struct xio_sg_table_ops		*sgtbl_ops;
	void				*sgtbl;
	void				*sg;
	int				enforce_write_rsp;
	int				nents;
	int				retval;
	unsigned int			i;

	sgtbl		= xio_sg_table_get(&task->omsg->in);
	sgtbl_ops	= xio_sg_table_ops_get(task->omsg->in.sgl_type);
	nents		= tbl_nents(sgtbl_ops, sgtbl);

	if (nents == 0) {
		rdma_task->in_ib_op = XIO_IB_SEND;
		rdma_task->req_in_num_sge = 0;
		return 0;
	}
	data_len = tbl_length(sgtbl_ops, sgtbl);
	hdr_len  = vmsg->header.iov_len;
	if (hdr_len && hdr_len >= rdma_hndl->peer_max_header) {
		ERROR_LOG("hdr_len=%zd is bigger than peer_max_reader=%d\n",
				hdr_len, rdma_hndl->peer_max_header);
		return -1;
	}

	/* before working on the out - current place after the session header */
	xio_hdr_len = xio_mbuf_get_curr_offset(&task->mbuf);
	xio_hdr_len += sizeof(struct xio_rdma_rsp_hdr);
	xio_hdr_len += sizeof(struct xio_sge) * nents;

	/* requester may insist on RDMA for small buffers to eliminate copy
	 * from receive buffers to user buffers
	 */
	enforce_write_rsp = task->omsg_flags & XIO_MSG_FLAG_PEER_WRITE_RSP;
	if (!(enforce_write_rsp) &&
	    data_len + hdr_len + xio_hdr_len < rdma_hndl->max_inline_buf_sz) {
		/* user has small response - no rdma operation expected */
		rdma_task->in_ib_op = XIO_IB_SEND;
		rdma_task->req_in_num_sge = (data_len) ? nents : 0;
	} else  {
		rdma_task->in_ib_op = XIO_IB_RDMA_WRITE;
		/* user must provided buffers with length for RDMA WRITE */
		if (xio_vmsg_to_sgt(vmsg, &rdma_task->read_mem_desc.sgt,
				    &rdma_task->read_mem_desc.nents) < 0) {
			ERROR_LOG("xio_vmsg_to_sgt failed\n");
			goto cleanup;
		}

		sg = sge_first(sgtbl_ops, sgtbl);
		if (!sge_addr(sgtbl_ops, sg)) {
			if (unlikely(!rdma_hndl->rdma_mempool)) {
				xio_set_error(XIO_E_NO_BUFS);
				ERROR_LOG(
					"message /read/write failed - " \
					"library's memory pool disabled\n");
				goto cleanup;
			}

			/* user did not provide buffers */
			for_each_sge(sgtbl, sgtbl_ops, sg, i) {
				retval = xio_mempool_alloc(
					rdma_hndl->rdma_mempool,
					sge_length(sgtbl_ops, sg),
					&rdma_task->read_mem_desc.mp_sge[i]);

				if (unlikely(retval)) {
					rdma_task->req_in_num_sge = i;
					rdma_task->read_mem_desc.num_sge = i;
					xio_set_error(ENOMEM);
					ERROR_LOG(
					"mempool is empty for %zd bytes\n",
					sge_length(sgtbl_ops, sg));
					goto cleanup;
				}
				sge_set_addr(
				   sgtbl_ops, sg,
				   rdma_task->read_mem_desc.mp_sge[i].addr);
			}
			rdma_task->read_mem_desc.num_sge = nents;
		}
		rdma_task->req_in_num_sge = rdma_task->read_mem_desc.nents;
	}
	/*
	if (rdma_task->req_in_num_sge > rdma_hndl->peer_max_out_iovsz) {
		ERROR_LOG("request in iovlen %d is bigger then peer " \
			  "max out iovlen %d\n",
			   rdma_task->req_in_num_sge,
			   rdma_hndl->peer_max_out_iovsz);
		goto cleanup;
	}
	*/
	return 0;

cleanup:
	xio_mempool_free(&rdma_task->read_mem_desc);
	rdma_task->req_in_num_sge = 0;
	xio_set_error(EMSGSIZE);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_send_req							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_send_req(struct xio_rdma_transport *rdma_hndl,
			     struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct scatterlist *sg;
	uint64_t		payload;
	size_t			retval;
	int			i;
	int			must_send = 0;
	size_t			sge_len;

	if (verify_req_send_limits(rdma_hndl))
		return -1;

	/* prepare buffer for RDMA response  */
	retval = xio_rdma_prep_req_in_data(rdma_hndl, task);
	if (unlikely(retval != 0)) {
		ERROR_LOG("rdma_prep_req_in_data failed\n");
		return -1;
	}

	/* prepare the out message  */
	retval = xio_rdma_prep_req_out_data(rdma_hndl, task);
	if (unlikely(retval != 0)) {
		ERROR_LOG("rdma_prep_req_out_data failed\n");
		return -1;
	}
	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* add tlv */
	if (unlikely(xio_mbuf_write_tlv(&task->mbuf, task->tlv_type, payload) != 0)) {
		ERROR_LOG("write tlv failed\n");
		xio_set_error(EOVERFLOW);
		return -1;
	}

	/* xio_rdma_prep_req_out_data sets txd.nents */
	/* set the length */
	rdma_task->txd.sgt.sgl[0].length =
		xio_mbuf_get_curr_offset(&task->mbuf);

	/* validate header */
	if (unlikely(XIO_TLV_LEN + payload != rdma_task->txd.sgt.sgl[0].length)) {
		ERROR_LOG("header validation failed\n");
		return -1;
	}
	xio_task_addref(task);

	/* check for inline */
	rdma_task->txd.send_wr.send_flags = 0;

	sge_len = 0;
	sg = rdma_task->txd.sgt.sgl;
	for (i = 0; i < rdma_task->txd.send_wr.num_sge; i++) {
		sge_len += sg->length;
		sg = sg_next(sg);
	}

	if (sge_len < rdma_hndl->max_inline_data)
		rdma_task->txd.send_wr.send_flags |= IB_SEND_INLINE;

	if (IS_FIN(task->tlv_type)) {
		rdma_task->txd.send_wr.send_flags |= IB_SEND_FENCE;
		must_send = 1;
	}

	if (unlikely(++rdma_hndl->req_sig_cnt >= HARD_CQ_MOD ||
		     task->is_control ||
		     task->omsg->flags & XIO_MSG_FLAG_IMM_SEND_COMP)) {
		/* avoid race between send completion and response arrival */
		rdma_task->txd.send_wr.send_flags |= IB_SEND_SIGNALED;
		rdma_hndl->req_sig_cnt = 0;
	}

	rdma_task->out_ib_op = XIO_IB_SEND;

	list_move_tail(&task->tasks_list_entry, &rdma_hndl->tx_ready_list);

	rdma_hndl->tx_ready_tasks_num++;

	return kick_send_and_read(rdma_hndl, task, must_send);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_send_rsp							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_send_rsp(struct xio_rdma_transport *rdma_hndl,
			     struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_work_req	*txd;
	struct scatterlist	*sg;
	size_t			retval;
	size_t			sge_len;
	uint64_t		payload;
	int			i;
	int			must_send = 0;

	if (unlikely(verify_rsp_send_limits(rdma_hndl)))
		return -1;

	/* prepare the out message  */
	retval = xio_rdma_prep_rsp_out_data(rdma_hndl, task);
	if (unlikely(retval != 0)) {
		ERROR_LOG("rdma_prep_req_out_data failed\n");
		goto cleanup;
	}

	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* add tlv */
	if (xio_mbuf_write_tlv(&task->mbuf, task->tlv_type, payload) != 0)
		goto cleanup;

	txd = &rdma_task->txd;

	/* set the length of the header */
	txd->sgt.sgl[0].length = xio_mbuf_get_curr_offset(&task->mbuf);

	/* validate header */
	if (unlikely(XIO_TLV_LEN + payload != txd->sgt.sgl[0].length)) {
		ERROR_LOG("header validation failed\n");
		goto cleanup;
	}

	txd->send_wr.send_flags = 0;

	/* check for inline */
	if (rdma_task->out_ib_op == XIO_IB_SEND ||
	    rdma_task->out_ib_op == XIO_IB_RDMA_READ)   {
		sge_len = 0;
		sg = txd->sgt.sgl;
		for (i = 0; i < txd->send_wr.num_sge; i++) {
			sge_len += sg->length;
			sg = sg_next(sg);
		}

		if (sge_len < rdma_hndl->max_inline_data)
			txd->send_wr.send_flags |= IB_SEND_INLINE;

		list_move_tail(&task->tasks_list_entry,
			       &rdma_hndl->tx_ready_list);
		rdma_hndl->tx_ready_tasks_num++;
	}

	if (IS_FIN(task->tlv_type)) {
		txd->send_wr.send_flags |= IB_SEND_FENCE;
		must_send = 1;
	}

	if (++rdma_hndl->rsp_sig_cnt >= SOFT_CQ_MOD ||
	    task->is_control ||
	    task->omsg->flags & XIO_MSG_FLAG_IMM_SEND_COMP) {
		txd->send_wr.send_flags |= IB_SEND_SIGNALED;
		rdma_hndl->rsp_sig_cnt = 0;
	}
	if (rdma_task->out_ib_op == XIO_IB_RDMA_READ)
		xio_task_addref(task);

	return kick_send_and_read(rdma_hndl, task, must_send);
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
	XIO_TO_RDMA_TASK(task, rdma_task);
	union xio_transport_event_data event_data;

	if (rdma_task->out_ib_op == XIO_IB_RDMA_READ) {
		xio_tasks_pool_put(task);
		return 0;
	}
	if (IS_CANCEL(task->tlv_type))
		return 0;

	event_data.msg.op	= XIO_WC_OP_SEND;
	event_data.msg.task	= task;

	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_EVENT_SEND_COMPLETION,
				      &event_data);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_req_send_comp						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_req_send_comp(struct xio_rdma_transport *rdma_hndl,
				     struct xio_task *task)
{
	union xio_transport_event_data event_data;

	if (IS_CANCEL(task->tlv_type))
		return 0;

	event_data.msg.op	= XIO_WC_OP_SEND;
	event_data.msg.task	= task;

	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_EVENT_SEND_COMPLETION,
				      &event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_direct_rdma_comp						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_direct_rdma_comp(struct xio_rdma_transport *rdma_hndl,
					struct xio_task *task,
					enum xio_wc_op op)
{
	union xio_transport_event_data event_data;

	event_data.msg.op = op;
	event_data.msg.task = task;
	xio_transport_notify_observer(
		&rdma_hndl->base,
		XIO_TRANSPORT_EVENT_DIRECT_RDMA_COMPLETION,
		&event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_post_recv_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_post_recv_rsp(struct xio_task *task)
{
	struct xio_msg		*imsg;
	struct xio_msg		*omsg;
	struct xio_sg_table_ops	*isgtbl_ops;
	void			*isgtbl;
	struct xio_sg_table_ops	*osgtbl_ops;
	void			*osgtbl;

	omsg		= task->sender_task->omsg;
	imsg		= &task->imsg;
	isgtbl		= xio_sg_table_get(&imsg->in);
	isgtbl_ops	= (struct xio_sg_table_ops *)
				xio_sg_table_ops_get(imsg->in.sgl_type);
	osgtbl		= xio_sg_table_get(&omsg->in);
	osgtbl_ops	= (struct xio_sg_table_ops *)
				xio_sg_table_ops_get(omsg->in.sgl_type);

	tbl_clone(osgtbl_ops, osgtbl, isgtbl_ops, isgtbl);

	/* also set bits */
	if (test_bits(XIO_MSG_HINT_ASSIGNED_DATA_IN_BUF, &imsg->hints))
		set_bits(XIO_MSG_HINT_ASSIGNED_DATA_IN_BUF, &omsg->hints);
	else
		clr_bits(XIO_MSG_HINT_ASSIGNED_DATA_IN_BUF, &omsg->hints);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_recv_rsp							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_recv_rsp(struct xio_rdma_transport *rdma_hndl,
				struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	XIO_TO_RDMA_TASK(task, rdma_sender_task);
	int			retval = 0, i;
	union xio_transport_event_data event_data;
	struct xio_rdma_rsp_hdr	rsp_hdr;
	struct xio_msg		*imsg;
	struct xio_msg		*omsg;
	void			*ulp_hdr;
	struct xio_sg_table_ops	*isgtbl_ops;
	void			*isgtbl;
	struct xio_sg_table_ops	*osgtbl_ops;
	void			*osgtbl;
	void			*sg;
	struct scatterlist	*sgl;

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
	/* read the sn */
	rdma_task->sn = rsp_hdr.sn;

	/* find the sender task */
	task->sender_task = xio_rdma_primary_task_lookup(rdma_hndl,
							 rsp_hdr.rtid);

	task->rtid	 = rsp_hdr.ltid;
	rdma_sender_task = task->sender_task->dd_data;
	/* mark the sender task as arrived */
	task->sender_task->state = XIO_TASK_STATE_RESPONSE_RECV;

	xio_unmap_tx_work_req(rdma_hndl->dev, &rdma_sender_task->txd);

	if (rdma_sender_task->read_mem_desc.nents &&
	    rdma_sender_task->read_mem_desc.mapped)
		xio_unmap_desc(rdma_hndl, &rdma_sender_task->read_mem_desc,
			       DMA_FROM_DEVICE);
	if (rdma_sender_task->write_mem_desc.nents &&
	    rdma_sender_task->write_mem_desc.mapped)
		xio_unmap_desc(rdma_hndl, &rdma_sender_task->write_mem_desc,
			       DMA_TO_DEVICE);

	omsg		= task->sender_task->omsg;
	imsg		= &task->imsg;
	isgtbl		= xio_sg_table_get(&imsg->in);
	isgtbl_ops	= xio_sg_table_ops_get(imsg->in.sgl_type);
	osgtbl		= xio_sg_table_get(&omsg->in);
	osgtbl_ops	= xio_sg_table_ops_get(omsg->in.sgl_type);

	clr_bits(XIO_MSG_HINT_ASSIGNED_DATA_IN_BUF, &imsg->hints);

	ulp_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);
	/* msg from received message */
	if (rsp_hdr.ulp_hdr_len) {
		imsg->in.header.iov_base = ulp_hdr;
		imsg->in.header.iov_len  = rsp_hdr.ulp_hdr_len;
	} else {
		imsg->in.header.iov_base = NULL;
		imsg->in.header.iov_len  = 0;
	}

	task->status = rsp_hdr.status;

	if (omsg->in.header.iov_base) {
		/* copy header to user buffers */
		size_t hdr_len = 0;

		if (imsg->in.header.iov_len > omsg->in.header.iov_len)  {
			hdr_len = imsg->in.header.iov_len;
			task->status = XIO_E_MSG_SIZE;
		} else {
			hdr_len = omsg->in.header.iov_len;
			task->status = XIO_E_SUCCESS;
		}
		if (hdr_len && imsg->in.header.iov_base)
			memcpy(omsg->in.header.iov_base,
			       imsg->in.header.iov_base,
			       hdr_len);
		else
			*((char *)omsg->in.header.iov_base) = 0;

		omsg->in.header.iov_len = hdr_len;
	} else {
		/* no copy - just pointers */
		memclonev(&omsg->in.header, 1, &imsg->in.header, 1);
	}

	/* if data arrived, set the pointers */
	switch (rsp_hdr.out_ib_op) {
	case XIO_IB_SEND:
		/* This is a completion of RDMA READ can free
		 * DMA mapping of send buffer (future FMR/FRWR)
		 */
		xio_unmap_desc(rdma_hndl,
			       &rdma_sender_task->write_mem_desc,
			       DMA_TO_DEVICE);
		if (rsp_hdr.ulp_imm_len) {
			tbl_set_nents(isgtbl_ops, isgtbl, 1);
			sg = sge_first(isgtbl_ops, isgtbl);
			sge_set_addr(isgtbl_ops, sg,
				     (ulp_hdr + imsg->in.header.iov_len +
				     rsp_hdr.ulp_pad_len));
			sge_set_length(isgtbl_ops, sg,
				       rsp_hdr.ulp_imm_len);
		} else {
			tbl_set_nents(isgtbl_ops, isgtbl, 0);
		}
		if (tbl_nents(osgtbl_ops, osgtbl)) {
			/* deep copy */
			if (tbl_nents(isgtbl_ops, isgtbl)) {
				size_t idata_len  =
					tbl_length(isgtbl_ops, isgtbl);
				size_t odata_len  =
					tbl_length(osgtbl_ops, osgtbl);

				if (idata_len > odata_len) {
					task->status = XIO_E_MSG_SIZE;
					xio_reset_desc(
					 &rdma_sender_task->write_mem_desc);
					goto partial_msg;
				} else {
					task->status = XIO_E_SUCCESS;
				}
				sg = sge_first(osgtbl_ops, osgtbl);
				if (sge_addr(osgtbl_ops, sg))  {
					/* user provided buffer so do copy */
					tbl_copy(osgtbl_ops, osgtbl,
						 isgtbl_ops, isgtbl);
				} else {
					/* use provided only length - set user
					 * pointers */
					tbl_clone(osgtbl_ops, osgtbl,
						  isgtbl_ops, isgtbl);
				}
			} else {
				tbl_set_nents(osgtbl_ops, osgtbl,
					      tbl_nents(isgtbl_ops, isgtbl));
			}
		} else {
			tbl_clone(osgtbl_ops, osgtbl,
				  isgtbl_ops, isgtbl);
		}
		xio_reset_desc(&rdma_sender_task->write_mem_desc);
		break;
	case XIO_IB_RDMA_WRITE:
		/* This is a completion of RDMA WRITE can free
		 * DMA mapping of read buffer (future FMR/FRWR)
		 */
		xio_unmap_desc(rdma_hndl,
			       &rdma_sender_task->read_mem_desc,
			       DMA_FROM_DEVICE);
		if (rdma_task->rsp_out_num_sge >
		    rdma_sender_task->req_in_num_sge) {
			ERROR_LOG("local in data_iovec is too small %d < %d\n",
				  rdma_sender_task->req_in_num_sge,
				  rdma_task->rsp_out_num_sge);
			xio_reset_desc(&rdma_sender_task->read_mem_desc);
			goto partial_msg;
		}
		tbl_set_nents(isgtbl_ops, isgtbl,
			      rdma_task->rsp_out_num_sge);

		sg = sge_first(isgtbl_ops, isgtbl);
		sgl = rdma_sender_task->read_mem_desc.sgt.sgl;
		for (i = 0; i < rdma_task->rsp_out_num_sge; i++) {
			sge_set_addr(isgtbl_ops, sg, sg_virt(sgl));
			sge_set_length(isgtbl_ops, sg,
				       rdma_task->rsp_out_sge[i].length);
			sg = sge_next(isgtbl_ops, isgtbl, sg);
			sgl = sg_next(sgl);
		}
		if (tbl_nents(osgtbl_ops, osgtbl)) {
			sg = sge_first(osgtbl_ops, osgtbl);
			if (sge_addr(osgtbl_ops, sg)) {
				void *isg;
				struct xio_mp_mem *mp_sge;

				mp_sge =
				  &rdma_sender_task->read_mem_desc.mp_sge[0];
				/* user provided buffer */
				if (!mp_sge->cache) {
					/* user buffers were aligned no
					 * bounce buffer data was copied
					 * directly to user buffer need
					 * to update the buffer length
					 */
					for_each_sge(isgtbl,
						     isgtbl_ops, isg, i) {
						sge_set_length(
							osgtbl_ops, sg,
							sge_length(
								isgtbl_ops,
								isg));
						sg = sge_next(osgtbl_ops,
							      osgtbl, sg);
					}
					tbl_set_nents(osgtbl_ops, osgtbl,
						      tbl_nents(isgtbl_ops,
								isgtbl));
					/* also read_mem_desc.sgt must follow
					 * the same nents => but we are about
					 * to reset the desc
					rdma_sender_task->read_mem_desc.sgt.nents =
					      tbl_nents(isgtbl_ops, isgtbl);
					*/
				} else {
					/* Bounce buffer */
					tbl_copy(osgtbl_ops, osgtbl,
						 isgtbl_ops, isgtbl);
					/* put bounce buffer back to pool */
					xio_mempool_free(
						&rdma_sender_task->read_mem_desc);
					rdma_sender_task->req_in_num_sge = 0;
				}
			} else {
				/* use provided only length - set user
				 * pointers */
				tbl_clone(osgtbl_ops, osgtbl,
					  isgtbl_ops, isgtbl);
			}
		} else {
			ERROR_LOG("empty out message\n");
		}
		xio_reset_desc(&rdma_sender_task->read_mem_desc);
		break;
	case XIO_IB_RDMA_READ:
		/* schedule request for RDMA READ. in case of error
		 * don't schedule the rdma read operation */
		/*TRACE_LOG("scheduling rdma read\n");*/
		retval = xio_sched_rdma_rd(rdma_hndl, task);
		if (retval == 0)
			return 0;
		ERROR_LOG("scheduling rdma read failed\n");
		break;
	default:
		ERROR_LOG("%s unexpected op 0x%x\n", __func__,
			  rsp_hdr.out_ib_op);
		break;
	}
	/* must delay the send due to pending rdma read responses
	 * if not user will get out of order messages - need fence
	 */
	if (!list_empty(&rdma_hndl->rdma_rd_rsp_list)) {
		list_move_tail(&task->tasks_list_entry,
			       &rdma_hndl->rdma_rd_rsp_list);
		rdma_hndl->kick_rdma_rd_rsp = 1;
		return 0;
	}
	if (rdma_hndl->rdma_rd_rsp_in_flight) {
		rdma_hndl->rdma_rd_rsp_in_flight++;
		list_move_tail(&task->tasks_list_entry,
			       &rdma_hndl->rdma_rd_rsp_in_flight_list);
		return 0;
	}

partial_msg:
	/* fill notification event */
	event_data.msg.op	= XIO_WC_OP_RECV;
	event_data.msg.task	= task;

	/* notify the upper layer of received message */
	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_EVENT_NEW_MESSAGE,
				      &event_data);
	return 0;

cleanup:
	retval = xio_errno();
	ERROR_LOG("xio_rdma_on_recv_rsp failed. (errno=%d %s)\n",
		  retval, xio_strerror(retval));
	xio_transport_notify_observer_error(&rdma_hndl->base, retval);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_sched_rdma_rd						     */
/*---------------------------------------------------------------------------*/
static int xio_sched_rdma_rd(struct xio_rdma_transport *rdma_hndl,
			     struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	int			i, retval;
	int			user_assign_flag = 0;
	size_t			rlen = 0, llen = 0;
	size_t			rsg_out_list_len = 0;
	int			tasks_used = 0;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sg;
	struct list_head	*rdma_rd_list;

	/* peer get buffer from pool and do rdma read */

	/* needed buffer to do rdma read. there are two options:	   */
	/* option 1: user provides call back that fills application memory */
	/* option 2: use internal buffer pool				   */

	/* hint the upper layer of sizes */
	sgtbl		= xio_sg_table_get(&task->imsg.in);
	sgtbl_ops	= xio_sg_table_ops_get(task->imsg.in.sgl_type);
	tbl_set_nents(sgtbl_ops, sgtbl, rdma_task->req_out_num_sge);
	for_each_sge(sgtbl, sgtbl_ops, sg, i) {
		sge_set_addr(sgtbl_ops, sg, NULL);
		sge_set_length(sgtbl_ops, sg,
			       rdma_task->req_out_sge[i].length);
		rlen += rdma_task->req_out_sge[i].length;
		rdma_task->read_mem_desc.mp_sge[i].cache = NULL;
	}

	sgtbl		= xio_sg_table_get(&task->imsg.out);
	sgtbl_ops	= xio_sg_table_ops_get(task->imsg.out.sgl_type);
	if (rdma_task->req_in_num_sge) {
		tbl_set_nents(sgtbl_ops, sgtbl, rdma_task->req_in_num_sge);
		for_each_sge(sgtbl, sgtbl_ops, sg, i) {
			sge_set_addr(sgtbl_ops, sg, NULL);
			sge_set_length(sgtbl_ops, sg,
				       rdma_task->req_in_sge[i].length);
			rdma_task->write_mem_desc.mp_sge[i].cache = NULL;
		}
	} else {
		tbl_set_nents(sgtbl_ops, sgtbl, 0);
	}
	sgtbl		= xio_sg_table_get(&task->imsg.in);
	sgtbl_ops	= xio_sg_table_ops_get(task->imsg.in.sgl_type);

	xio_transport_assign_in_buf(&rdma_hndl->base, task, &user_assign_flag);

	if (user_assign_flag) {
		/* if user does not have buffers ignore */
		if (tbl_nents(sgtbl_ops, sgtbl) == 0) {
			WARN_LOG("application has not provided buffers\n");
			WARN_LOG("rdma read is ignored\n");
			task->status = XIO_E_NO_USER_BUFS;
			return -1;
		}
		for_each_sge(sgtbl, sgtbl_ops, sg, i) {
			/* not required since the application can change
			 * number of SG entries as part of
			 * assign_data_in_buf() callback and this SG count
			 * might not match with rdma_task->req_out_num_sge.
			 */
			/*
			 rdma_task->read_mem_desc.mp_sge[i].cache = NULL;
			*/
			if (!sge_addr(sgtbl_ops, sg)) {
				ERROR_LOG("application has provided " \
					  "null address\n");
				ERROR_LOG("rdma read is ignored\n");
				task->status = XIO_E_NO_USER_BUFS;
				return -1;
			}
			llen += sge_length(sgtbl_ops, sg);
		}
		if (rlen  > llen) {
			ERROR_LOG("application provided too small iovec\n");
			ERROR_LOG("remote peer want to write %zd bytes while " \
				  "local peer provided buffer size %zd bytes\n",
				  rlen, llen);
			ERROR_LOG("rdma read is ignored\n");
			task->status = XIO_E_USER_BUF_OVERFLOW;
			return -1;
		}
		set_bits(XIO_MSG_HINT_ASSIGNED_DATA_IN_BUF, &task->imsg.hints);
	} else {
		retval = xio_mp_sge_alloc(rdma_hndl->rdma_mempool,
					  rdma_task->req_out_sge,
					  rdma_task->req_out_num_sge,
					  &rdma_task->read_mem_desc);
		if (unlikely(retval)) {
			ERROR_LOG("mempool alloc failed\n");
			task->status = ENOMEM;
			goto cleanup;
		}

		tbl_set_nents(sgtbl_ops, sgtbl, rdma_task->req_out_num_sge);
		for_each_sge(sgtbl, sgtbl_ops, sg, i) {
			rdma_task->read_mem_desc.mp_sge[i].length =
				rdma_task->req_out_sge[i].length;

			sge_set_addr(sgtbl_ops, sg,
				     rdma_task->read_mem_desc.mp_sge[i].addr);
			sge_set_length(
				sgtbl_ops, sg,
				rdma_task->read_mem_desc.mp_sge[i].length);
			llen += rdma_task->read_mem_desc.mp_sge[i].length;
		}
		rdma_task->req_in_num_sge = rdma_task->req_out_num_sge;
	}

	retval = xio_validate_rdma_op(&task->imsg.in,
				      rdma_task->req_out_sge,
				      rdma_task->req_out_num_sge,
				      min(rlen, llen),
				      rdma_hndl->max_sge,
				      &tasks_used);
	if (retval) {
		ERROR_LOG("failed to validate input iovecs, " \
			  "rlen=%zu, llen=%zu\n", rlen, llen);
		ERROR_LOG("rdma read is ignored\n");
		task->status = XIO_E_MSG_INVALID;
		return -1;
	}
	if (!task->sender_task)
		rdma_rd_list		= &rdma_hndl->rdma_rd_req_list;
	else
		rdma_rd_list		= &rdma_hndl->rdma_rd_rsp_list;

	retval = xio_prep_rdma_op(task, rdma_hndl,
				  XIO_IB_RDMA_READ,
				  IB_WR_RDMA_READ,
				  &task->imsg.in,
				  rdma_task->req_out_sge,
				  rdma_task->req_out_num_sge,
				  &rsg_out_list_len,
				  min(rlen, llen),
				  rdma_hndl->max_sge,
				  1,
				  rdma_rd_list, tasks_used);
	if (unlikely(retval)) {
		ERROR_LOG("failed to allocate tasks\n");
		ERROR_LOG("rdma read is ignored\n");
		task->status = XIO_E_WRITE_FAILED;
		return -1;
	}

	if (!task->sender_task)
		xio_xmit_rdma_rd_req(rdma_hndl);
	else
		xio_xmit_rdma_rd_rsp(rdma_hndl);

	return 0;
cleanup:
	rdma_task->req_in_num_sge = 0;
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_set_rsp_out_sge							     */
/*---------------------------------------------------------------------------*/
static inline void xio_set_rsp_out_sge(struct xio_task *task,
				       struct xio_sge *rsg_list,
				       size_t rsize)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	unsigned int	i;

	for (i = 0; i < rsize; i++)
		rdma_task->rsp_out_sge[i].length = rsg_list[i].length;

	rdma_task->rsp_out_num_sge = rsize;
}

/*---------------------------------------------------------------------------*/
/* xio_sched_rdma_wr_req						     */
/*---------------------------------------------------------------------------*/
static int xio_sched_rdma_wr_req(struct xio_rdma_transport *rdma_hndl,
				 struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	int		i, retval = 0;
	size_t		rlen = 0, llen = 0;
	size_t		rsg_out_list_len = 0;
	int		tasks_used = 0;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;

	sgtbl		= xio_sg_table_get(&task->omsg->out);
	sgtbl_ops	= xio_sg_table_ops_get(task->omsg->out.sgl_type);

	llen = tbl_length(sgtbl_ops, sgtbl);

	for (i = 0;  i < rdma_task->req_in_num_sge; i++)
		rlen += rdma_task->req_in_sge[i].length;

	if (unlikely(rlen < llen)) {
		ERROR_LOG("peer provided too small iovec\n");
		ERROR_LOG("rdma write is ignored\n");
		task->status = XIO_E_REM_USER_BUF_OVERFLOW;
		goto cleanup;
	}
	retval = xio_validate_rdma_op(&task->omsg->out,
				      rdma_task->req_in_sge,
				      rdma_task->req_in_num_sge,
				      min(rlen, llen),
				      rdma_hndl->max_sge,
				      &tasks_used);
	if (unlikely(retval)) {
		ERROR_LOG("failed to invalidate input iovecs\n");
		ERROR_LOG("rdma write is ignored\n");
		task->status = XIO_E_MSG_INVALID;
		goto cleanup;
	}

	retval = xio_prep_rdma_op(task, rdma_hndl,
				  XIO_IB_RDMA_WRITE,
				  IB_WR_RDMA_WRITE,
				  &task->omsg->out,
				  rdma_task->req_in_sge,
				  rdma_task->req_in_num_sge,
				  &rsg_out_list_len,
				  min(rlen, llen),
				  rdma_hndl->max_sge,
				  0,
				  &rdma_hndl->tx_ready_list, tasks_used);
	if (unlikely(retval)) {
		ERROR_LOG("failed to allocate tasks\n");
		ERROR_LOG("rdma write is ignored\n");
		task->status = XIO_E_READ_FAILED;
		goto cleanup;
	}
	/* prepare response to peer */
	xio_set_rsp_out_sge(task, rdma_task->req_in_sge, rsg_out_list_len);

	/* xio_prep_rdma_op used splice to transfer "tasks_used"  to
	 * tx_ready_list
	 */
	rdma_hndl->tx_ready_tasks_num += tasks_used;
	return 0;
cleanup:
	rdma_task->req_out_num_sge = 0;
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_recv_req							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_recv_req(struct xio_rdma_transport *rdma_hndl,
				struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	int			retval = 0;
	union xio_transport_event_data event_data;
	struct xio_rdma_req_hdr	req_hdr;
	struct xio_msg		*imsg;
	void			*ulp_hdr;
	int			i;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sg;

	/* read header */
	retval = xio_rdma_read_req_header(rdma_hndl, task, &req_hdr);
	if (unlikely(retval)) {
		xio_set_error(XIO_E_MSG_INVALID);
		goto cleanup;
	}

	if (rdma_hndl->exp_sn == req_hdr.sn) {
		rdma_hndl->exp_sn++;
		rdma_hndl->ack_sn = req_hdr.sn;
		rdma_hndl->peer_credits += req_hdr.credits;
	} else {
		ERROR_LOG("ERROR: sn expected:%d, sn arrived:%d" \
			  " out_ib_op:%u %u %u\n",
			  rdma_hndl->exp_sn, req_hdr.sn,
			  req_hdr.out_ib_op,
			  req_hdr.in_num_sge, req_hdr.out_num_sge);
	}

	/* save originator identifier */
	task->imsg_flags	= req_hdr.flags;
	task->rtid		= req_hdr.ltid;

	imsg		= &task->imsg;
	sgtbl		= xio_sg_table_get(&imsg->out);
	sgtbl_ops	= xio_sg_table_ops_get(imsg->out.sgl_type);

	ulp_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	imsg->type = task->tlv_type;
	imsg->in.header.iov_len	= req_hdr.ulp_hdr_len;

	clr_bits(XIO_MSG_HINT_ASSIGNED_DATA_IN_BUF, &imsg->hints);

	if (req_hdr.ulp_hdr_len)
		imsg->in.header.iov_base	= ulp_hdr;
	else
		imsg->in.header.iov_base	= NULL;

	/* hint upper layer about expected response */
	if (rdma_task->req_in_num_sge) {
		tbl_set_nents(sgtbl_ops, sgtbl, rdma_task->req_in_num_sge);
		for_each_sge(sgtbl, sgtbl_ops, sg, i) {
			sge_set_addr(sgtbl_ops, sg, NULL);
			sge_set_length(sgtbl_ops, sg,
				       rdma_task->req_in_sge[i].length);
		}
	} else {
		tbl_set_nents(sgtbl_ops, sgtbl, 0);
	}

	switch (req_hdr.out_ib_op) {
	case XIO_IB_SEND:
		sgtbl		= xio_sg_table_get(&imsg->in);
		sgtbl_ops	= xio_sg_table_ops_get(imsg->in.sgl_type);

		if (req_hdr.ulp_imm_len) {
			/* incoming data via SEND */
			/* if data arrived, set the pointers */
			tbl_set_nents(sgtbl_ops, sgtbl, 1);
			sg = sge_first(sgtbl_ops, sgtbl);
			sge_set_addr(sgtbl_ops, sg,
				     (ulp_hdr + imsg->in.header.iov_len +
				     req_hdr.ulp_pad_len));
			sge_set_length(sgtbl_ops, sg, req_hdr.ulp_imm_len);
		} else {
			/* no data at all */
			tbl_set_nents(sgtbl_ops, sgtbl, 0);
		}
		break;
	case XIO_IB_RDMA_READ:
		/* schedule request for RDMA READ. in case of error
		 * don't schedule the rdma read operation */
		/* TRACE_LOG("scheduling rdma read\n"); */
		retval = xio_sched_rdma_rd(rdma_hndl, task);
		if (retval == 0)
			return 0;
		ERROR_LOG("scheduling rdma read failed\n");
		break;
	default:
		ERROR_LOG("unexpected out_ib_op\n");
		xio_set_error(XIO_E_MSG_INVALID);
		task->status = XIO_E_MSG_INVALID;
		break;
	}

	/* must delay the send due to pending rdma read requests
	 * if not user will get out of order messages - need fence
	 */
	if (!list_empty(&rdma_hndl->rdma_rd_req_list)) {
		list_move_tail(&task->tasks_list_entry,
			       &rdma_hndl->rdma_rd_req_list);
		rdma_hndl->kick_rdma_rd_req = 1;
		return 0;
	}
	if (rdma_hndl->rdma_rd_req_in_flight) {
		rdma_hndl->rdma_rd_req_in_flight++;
		list_move_tail(&task->tasks_list_entry,
			       &rdma_hndl->rdma_rd_req_in_flight_list);
		return 0;
	}
	/* fill notification event */
	event_data.msg.op	= XIO_WC_OP_RECV;
	event_data.msg.task	= task;

	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_EVENT_NEW_MESSAGE,
				      &event_data);

	return 0;

cleanup:
	retval = xio_errno();
	ERROR_LOG("xio_rdma_on_recv_req failed. (errno=%d %s)\n", retval,
		  xio_strerror(retval));
	xio_transport_notify_observer_error(&rdma_hndl->base, retval);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_setup_msg						     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_write_setup_msg(struct xio_rdma_transport *rdma_hndl,
				     struct xio_task *task,
				     struct xio_rdma_setup_msg *msg)
{
	struct xio_rdma_setup_msg *tmp_msg;
	struct xio_rkey_tbl_pack *ptbl;
	struct xio_rkey_tbl *tbl;
	int i;

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

	/* jump after connection setup header */
	if (rdma_hndl->base.is_client)
		xio_mbuf_inc(&task->mbuf,
			     sizeof(struct xio_nexus_setup_req));
	else
		xio_mbuf_inc(&task->mbuf,
			     sizeof(struct xio_nexus_setup_rsp));

	tmp_msg = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* pack relevant values */
	PACK_LLVAL(msg, tmp_msg, buffer_sz);
	PACK_SVAL(msg, tmp_msg, sq_depth);
	PACK_SVAL(msg, tmp_msg, rq_depth);
	PACK_SVAL(msg, tmp_msg, credits);
	PACK_LVAL(msg, tmp_msg, max_in_iovsz);
	PACK_LVAL(msg, tmp_msg, max_out_iovsz);
	PACK_SVAL(msg, tmp_msg, rkey_tbl_size);
	PACK_LVAL(msg, tmp_msg, max_header_len);

#ifdef EYAL_TODO
	print_hex_dump_bytes("post_send: ", DUMP_PREFIX_ADDRESS,
			     task->mbuf.tlv.head,
			     64);
#endif
	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_rdma_setup_msg));

	if (!msg->rkey_tbl_size)
		return;

	tbl = rdma_hndl->rkey_tbl;
	ptbl = xio_mbuf_get_curr_ptr(&task->mbuf);
	for (i = 0; i < rdma_hndl->rkey_tbl_size; i++) {
		PACK_LVAL(tbl, ptbl, old_rkey);
		PACK_LVAL(tbl, ptbl, new_rkey);
		tbl++;
		xio_mbuf_inc(&task->mbuf, sizeof(struct xio_rkey_tbl_pack));
		ptbl = xio_mbuf_get_curr_ptr(&task->mbuf);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_read_setup_msg						     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_read_setup_msg(struct xio_rdma_transport *rdma_hndl,
				    struct xio_task *task,
				    struct xio_rdma_setup_msg *msg)
{
	struct xio_rdma_setup_msg *tmp_msg;
	struct xio_rkey_tbl_pack *ptbl;
	struct xio_rkey_tbl *tbl;
	int i;

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

	/* jump after connection setup header */
	if (rdma_hndl->base.is_client)
		xio_mbuf_inc(&task->mbuf,
			     sizeof(struct xio_nexus_setup_rsp));
	else
		xio_mbuf_inc(&task->mbuf,
			     sizeof(struct xio_nexus_setup_req));

	tmp_msg = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* pack relevant values */
	UNPACK_LLVAL(tmp_msg, msg, buffer_sz);
	UNPACK_SVAL(tmp_msg, msg, sq_depth);
	UNPACK_SVAL(tmp_msg, msg, rq_depth);
	UNPACK_SVAL(tmp_msg, msg, credits);
	UNPACK_LVAL(tmp_msg, msg, max_in_iovsz);
	UNPACK_LVAL(tmp_msg, msg, max_out_iovsz);
	UNPACK_SVAL(tmp_msg, msg, rkey_tbl_size);
	UNPACK_LVAL(tmp_msg, msg, max_header_len);

#ifdef EYAL_TODO
	print_hex_dump_bytes("post_send: ", DUMP_PREFIX_ADDRESS,
			     task->mbuf.curr,
			     64);
#endif
	xio_mbuf_inc(&task->mbuf, sizeof(struct xio_rdma_setup_msg));

	if (!msg->rkey_tbl_size)
		return;

	rdma_hndl->peer_rkey_tbl = kcalloc(msg->rkey_tbl_size, sizeof(*tbl),
				   GFP_KERNEL);
	if (!rdma_hndl->peer_rkey_tbl) {
		ERROR_LOG("calloc failed. (errno=%m)\n");
		xio_strerror(ENOMEM);
		msg->rkey_tbl_size = -1;
		return;
	}

	tbl = rdma_hndl->peer_rkey_tbl;
	ptbl = xio_mbuf_get_curr_ptr(&task->mbuf);
	for (i = 0; i < msg->rkey_tbl_size; i++) {
		UNPACK_LVAL(ptbl, tbl, old_rkey);
		UNPACK_LVAL(ptbl, tbl, new_rkey);
		tbl++;
		xio_mbuf_inc(&task->mbuf, sizeof(struct xio_rkey_tbl_pack));
		ptbl = xio_mbuf_get_curr_ptr(&task->mbuf);
	}
	rdma_hndl->peer_rkey_tbl_size = msg->rkey_tbl_size;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_send_setup_req						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_send_setup_req(struct xio_rdma_transport *rdma_hndl,
				   struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	uint16_t payload;
	struct xio_rdma_setup_msg  req;

	req.buffer_sz           = xio_rdma_get_inline_buffer_size();
	req.sq_depth		= rdma_hndl->sq_depth;
	req.rq_depth		= rdma_hndl->rq_depth;
	req.credits		= 0;
	req.max_in_iovsz	= rdma_options.max_in_iovsz;
	req.max_out_iovsz	= rdma_options.max_out_iovsz;
	req.rkey_tbl_size	= rdma_hndl->rkey_tbl_size;
	req.max_header_len	= g_poptions->max_inline_xio_hdr;

	xio_rdma_write_setup_msg(rdma_hndl, task, &req);

	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* add tlv */
	if (xio_mbuf_write_tlv(&task->mbuf, task->tlv_type, payload) != 0)
		return  -1;

	/* Only header */
	rdma_task->txd.nents = 1;
	rdma_task->txd.sgt.nents = 1;
	/* set the length */
	rdma_task->txd.sgt.sgl[0].length = xio_mbuf_data_length(&task->mbuf);

	rdma_task->txd.send_wr.send_flags = IB_SEND_SIGNALED;
	if (rdma_task->txd.sgt.sgl[0].length < rdma_hndl->max_inline_data)
		rdma_task->txd.send_wr.send_flags |= IB_SEND_INLINE;

	rdma_task->txd.send_wr.next	= NULL;
	rdma_task->out_ib_op		= XIO_IB_SEND;

	/* Map the send */
	if (xio_map_tx_work_req(rdma_hndl->dev, &rdma_task->txd)) {
		ERROR_LOG("DMA map to device failed\n");
		return -1;
	}
	rdma_task->txd.send_wr.num_sge = rdma_task->txd.mapped;

	xio_task_addref(task);
	rdma_hndl->reqs_in_flight_nr++;

	list_move_tail(&task->tasks_list_entry, &rdma_hndl->in_flight_list);

	rdma_hndl->peer_credits--;

	/* set the lkey prior to sending */
	rdma_task->txd.send_wr.sg_list[0].lkey = rdma_hndl->dev->mr->lkey;

	/* send the setup request */
	xio_post_send(rdma_hndl, &rdma_task->txd, 1);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_send_setup_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_send_setup_rsp(struct xio_rdma_transport *rdma_hndl,
				   struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	uint16_t payload;

	rdma_hndl->sim_peer_credits   += rdma_hndl->credits;
	rdma_hndl->setup_rsp.credits   = rdma_hndl->credits;
	rdma_hndl->setup_rsp.buffer_sz = g_poptions->max_inline_xio_hdr +
					    g_poptions->max_inline_xio_data +
					    xio_mbuf_get_curr_offset(&task->mbuf);
	rdma_hndl->setup_rsp.max_header_len = g_poptions->max_inline_xio_hdr;

	xio_rdma_write_setup_msg(rdma_hndl, task, &rdma_hndl->setup_rsp);

	rdma_hndl->credits = 0;
	rdma_hndl->setup_rsp.max_in_iovsz	= rdma_options.max_in_iovsz;
	rdma_hndl->setup_rsp.max_out_iovsz	= rdma_options.max_out_iovsz;

	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* add tlv */
	if (xio_mbuf_write_tlv(&task->mbuf, task->tlv_type, payload) != 0)
		return  -1;

	/* Only header */
	rdma_task->txd.nents = 1;
	/* set the length */
	rdma_task->txd.sgt.sgl[0].length = xio_mbuf_data_length(&task->mbuf);

	rdma_task->txd.send_wr.send_flags = IB_SEND_SIGNALED;
	if (rdma_task->txd.sgt.sgl[0].length < rdma_hndl->max_inline_data)
		rdma_task->txd.send_wr.send_flags |= IB_SEND_INLINE;

	rdma_task->txd.send_wr.next	= NULL;
	rdma_task->out_ib_op		= XIO_IB_SEND;

	/* Map the send */
	if (unlikely(xio_map_tx_work_req(rdma_hndl->dev, &rdma_task->txd))) {
		ERROR_LOG("DMA map to device failed\n");
		return -1;
	}
	rdma_task->txd.send_wr.num_sge = rdma_task->txd.mapped;

	rdma_hndl->rsps_in_flight_nr++;

	list_move(&task->tasks_list_entry, &rdma_hndl->in_flight_list);

	rdma_hndl->peer_credits--;

        /* set the lkey prior to sending */
        rdma_task->txd.send_wr.sg_list[0].lkey = rdma_hndl->dev->mr->lkey;

        /* send the setup request */
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
	u64 local_buf_size;

	if (rdma_hndl->base.is_client) {
		struct xio_task *sender_task = NULL;

		if (!list_empty(&rdma_hndl->in_flight_list))
			sender_task = list_first_entry(
					&rdma_hndl->in_flight_list,
					struct xio_task,  tasks_list_entry);
		else if (!list_empty(&rdma_hndl->tx_comp_list))
			sender_task = list_first_entry(
					&rdma_hndl->tx_comp_list,
					struct xio_task,  tasks_list_entry);
		else
			ERROR_LOG("could not find sender task\n");

		task->sender_task = sender_task;
		if (sender_task && sender_task->dd_data) {
			struct xio_rdma_task *rdma_sender_task;

			rdma_sender_task = task->sender_task->dd_data;
			xio_unmap_tx_work_req(rdma_hndl->dev,
					      &rdma_sender_task->txd);
		}
		xio_rdma_read_setup_msg(rdma_hndl, task, rsp);
		/* get the initial credits */
		rdma_hndl->peer_credits += rsp->credits;
	} else {
		struct xio_rdma_setup_msg req;

		xio_rdma_read_setup_msg(rdma_hndl, task, &req);

		/* current implementation is symmetric */
		local_buf_size          = xio_rdma_get_inline_buffer_size();
		rsp->buffer_sz		= min(req.buffer_sz, local_buf_size);
		rsp->sq_depth		= max((int)req.sq_depth, rdma_hndl->rq_depth);
		rsp->rq_depth		= max((int)req.rq_depth, rdma_hndl->sq_depth);
		rsp->max_in_iovsz	= req.max_in_iovsz;
		rsp->max_out_iovsz	= req.max_out_iovsz;
		rsp->max_header_len	= req.max_header_len;
	}

	/* save the values */
	rdma_hndl->rq_depth		= rsp->rq_depth;
	rdma_hndl->actual_rq_depth	= rdma_hndl->rq_depth + EXTRA_RQE;
	rdma_hndl->sq_depth		= rsp->sq_depth;
	rdma_hndl->membuf_sz		= rsp->buffer_sz;
	rdma_hndl->max_inline_buf_sz	= rsp->buffer_sz;
	rdma_hndl->peer_max_in_iovsz	= rsp->max_in_iovsz;
	rdma_hndl->peer_max_out_iovsz	= rsp->max_out_iovsz;
	rdma_hndl->peer_max_header	= rsp->max_header_len;

	/* initialize send window */
	rdma_hndl->sn = 0;
	rdma_hndl->ack_sn = ~0;
	rdma_hndl->credits = 0;
	rdma_hndl->max_sn = rdma_hndl->sq_depth;

	/* initialize receive window */
	rdma_hndl->exp_sn = 0;
	rdma_hndl->max_exp_sn = 0;

	rdma_hndl->max_tx_ready_tasks_num = rdma_hndl->sq_depth;
	rdma_hndl->num_tasks = rdma_hndl->base.ctx->max_conns_per_ctx *
			(rdma_hndl->sq_depth + rdma_hndl->actual_rq_depth);

	/* fill notification event */
	event_data.msg.op	= XIO_WC_OP_RECV;
	event_data.msg.task	= task;

	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_EVENT_NEW_MESSAGE,
				      &event_data);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_write_rdma_read_ack_hdr						     */
/*---------------------------------------------------------------------------*/
static void xio_write_rdma_read_ack_hdr(struct xio_rdma_transport *rdma_hndl,
					struct xio_task *task,
					struct xio_rdma_read_ack_hdr *rra)
{
	struct xio_rdma_read_ack_hdr *tmp_rra;

	xio_mbuf_reset(&task->mbuf);

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return;

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

	/* get the pointer */
	tmp_rra = (struct xio_rdma_read_ack_hdr *)
					xio_mbuf_get_curr_ptr(&task->mbuf);

	/* pack relevant values */
	PACK_SVAL(rra, tmp_rra, hdr_len);
	PACK_LVAL(rra, tmp_rra, rtid);

	xio_mbuf_inc(&task->mbuf, sizeof(*rra));
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_send_rdma_read_ack						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_send_rdma_read_ack(struct xio_rdma_transport *rdma_hndl,
				       int rtid)
{
	uint64_t			payload;
	struct xio_task			*task;
	struct xio_rdma_task		*rdma_task;
	struct xio_rdma_read_ack_hdr	rra = {
		.hdr_len	= sizeof(rra),
		.rtid		= rtid,
	};

	task = xio_rdma_primary_task_alloc(rdma_hndl);
	if (unlikely(!task)) {
		ERROR_LOG("primary tasks pool is empty\n");
		return -1;
	}
	task->omsg = NULL;

	task->tlv_type	= XIO_RDMA_READ_ACK;
	rdma_task	= (struct xio_rdma_task *)task->dd_data;

	/* write the message */
	xio_write_rdma_read_ack_hdr(rdma_hndl, task, &rra);

	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* add tlv */
	if (xio_mbuf_write_tlv(&task->mbuf, task->tlv_type, payload) != 0)
		return  -1;

	/* set the length */
	rdma_task->txd.sge[0].length	= xio_mbuf_data_length(&task->mbuf);
	rdma_task->txd.send_wr.send_flags = 0;
	if (rdma_task->txd.sge[0].length < (size_t)rdma_hndl->max_inline_data)
		rdma_task->txd.send_wr.send_flags |= IB_SEND_INLINE;

	rdma_task->txd.send_wr.next	= NULL;
	rdma_task->out_ib_op		= XIO_IB_SEND;
	rdma_task->txd.send_wr.num_sge	= 1;

	rdma_hndl->rsps_in_flight_nr++;
	list_add_tail(&task->tasks_list_entry, &rdma_hndl->in_flight_list);

	rdma_hndl->peer_credits--;
	xio_post_send(rdma_hndl, &rdma_task->txd, 1);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_read_rdma_read_ack_hdr						     */
/*---------------------------------------------------------------------------*/
static void xio_read_rdma_read_ack_hdr(struct xio_rdma_transport *rdma_hndl,
				       struct xio_task *task,
				       struct xio_rdma_read_ack_hdr *rra)
{
	struct xio_rdma_read_ack_hdr *tmp_rra;

	/* goto to the first tlv */
	xio_mbuf_reset(&task->mbuf);

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

	/* get the pointer */
	tmp_rra = (struct xio_rdma_read_ack_hdr *)
					xio_mbuf_get_curr_ptr(&task->mbuf);

	/* pack relevant values */
	UNPACK_SVAL(tmp_rra, rra, hdr_len);
	UNPACK_LVAL(tmp_rra, rra, rtid);

	xio_mbuf_inc(&task->mbuf, sizeof(*rra));
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_recv_rdma_read_ack					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_recv_rdma_read_ack(struct xio_rdma_transport *rdma_hndl,
					  struct xio_task *task)
{
	struct xio_rdma_read_ack_hdr	rra;
	union xio_transport_event_data	event_data;
	struct xio_task			*req_task;

	xio_read_rdma_read_ack_hdr(rdma_hndl, task, &rra);

	/* the rx task is returned back to pool */
	xio_tasks_pool_put(task);

	/* find the sender task */
	req_task = xio_rdma_primary_task_lookup(rdma_hndl, rra.rtid);

	event_data.msg.op	= XIO_WC_OP_SEND;
	event_data.msg.task	= req_task;

	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_EVENT_SEND_COMPLETION,
				      &event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_write_nop							     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_write_nop(struct xio_rdma_transport *rdma_hndl,
			       struct xio_task *task,
			       struct xio_nop_hdr *nop)
{
	struct  xio_nop_hdr *tmp_nop;

	xio_mbuf_reset(&task->mbuf);

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return;

	/* set the mbuf after tlv header */
	xio_mbuf_set_val_start(&task->mbuf);

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

	task = xio_rdma_primary_task_alloc(rdma_hndl);
	if (unlikely(!task)) {
		ERROR_LOG("primary tasks pool is empty\n");
		return -1;
	}

	task->omsg = NULL;

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

	rdma_task->txd.send_wr.next	= NULL;
	rdma_task->out_ib_op		= XIO_IB_SEND;

	rdma_task->txd.nents = 1;
	rdma_task->txd.sgt.nents = 1;
	/* set the length */
	rdma_task->txd.sgt.sgl[0].length = xio_mbuf_data_length(&task->mbuf);

	rdma_task->txd.send_wr.send_flags = IB_SEND_SIGNALED;
	if (rdma_task->txd.sgt.sgl[0].length < rdma_hndl->max_inline_data)
		rdma_task->txd.send_wr.send_flags |= IB_SEND_INLINE;

	/* Map the send */
	if (unlikely(xio_map_tx_work_req(rdma_hndl->dev, &rdma_task->txd))) {
		ERROR_LOG("DMA map to device failed\n");
		return -1;
	}

	rdma_task->txd.send_wr.num_sge = rdma_task->txd.mapped;

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
			      struct xio_task *task,
			      struct xio_nop_hdr *nop)
{
	struct xio_nop_hdr *tmp_nop;

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

	/* the rx task is returned back to pool */
	xio_tasks_pool_put(task);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_send_cancel							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_send_cancel(struct xio_rdma_transport *rdma_hndl,
				uint32_t tlv_type,
				struct xio_rdma_cancel_hdr *cancel_hdr,
				void *ulp_msg, size_t ulp_msg_sz)
{
	uint64_t		payload;
	uint16_t		ulp_hdr_len;
	int			retval;
	struct xio_task		*task;
	struct xio_rdma_task	*rdma_task;
	void			*buff;

	task = xio_rdma_primary_task_alloc(rdma_hndl);
	if (unlikely(!task)) {
		ERROR_LOG("primary tasks pool is empty\n");
		return -1;
	}
	xio_mbuf_reset(&task->mbuf);

	/* set start of the tlv */
	if (xio_mbuf_tlv_start(&task->mbuf) != 0)
		return -1;

	task->tlv_type			= tlv_type;
	rdma_task			= (struct xio_rdma_task *)task->dd_data;
	rdma_task->out_ib_op		= XIO_IB_SEND;
	rdma_task->req_out_num_sge	= 0;
	rdma_task->req_in_num_sge	= 0;
	rdma_task->sqe_used		= 0;

	ulp_hdr_len = sizeof(*cancel_hdr) + sizeof(uint16_t) + ulp_msg_sz;
	rdma_hndl->dummy_msg.out.header.iov_base =
		kzalloc(ulp_hdr_len, GFP_KERNEL);
	rdma_hndl->dummy_msg.out.header.iov_len = ulp_hdr_len;

	/* write the message */
	/* get the pointer */
	buff = rdma_hndl->dummy_msg.out.header.iov_base;

	/* pack relevant values */
	buff += xio_write_uint16(cancel_hdr->hdr_len, 0, buff);
	buff += xio_write_uint16(cancel_hdr->sn, 0, buff);
	buff += xio_write_uint32(cancel_hdr->result, 0, buff);
	buff += xio_write_uint16((uint16_t)(ulp_msg_sz), 0, buff);
	buff += xio_write_array(ulp_msg, ulp_msg_sz, 0, buff);

	task->omsg = &rdma_hndl->dummy_msg;

	/* write xio header to the buffer */
	retval = xio_rdma_prep_req_header(rdma_hndl, task,
					  ulp_hdr_len, 0, 0,
					  XIO_E_SUCCESS);
	if (unlikely(retval))
		return -1;

	payload = xio_mbuf_tlv_payload_len(&task->mbuf);

	/* add tlv */
	if (xio_mbuf_write_tlv(&task->mbuf, task->tlv_type, payload) != 0)
		return  -1;

	task->omsg = NULL;
	kfree(rdma_hndl->dummy_msg.out.header.iov_base);

	rdma_task->txd.nents = 1;

	/* set the length */
	rdma_task->txd.sgt.nents = 1;
	rdma_task->txd.sgt.sgl[0].length = xio_mbuf_data_length(&task->mbuf);

	rdma_task->txd.send_wr.send_flags = IB_SEND_SIGNALED;
	if (rdma_task->txd.sgt.sgl[0].length < rdma_hndl->max_inline_data)
		rdma_task->txd.send_wr.send_flags |= IB_SEND_INLINE;

	rdma_task->txd.send_wr.next = NULL;

	/* Map the send */
	if (unlikely(xio_map_tx_work_req(rdma_hndl->dev, &rdma_task->txd))) {
		ERROR_LOG("DMA map to device failed\n");
		return -1;
	}
	rdma_task->txd.send_wr.num_sge = rdma_task->txd.mapped;

	rdma_hndl->tx_ready_tasks_num++;
	list_move_tail(&task->tasks_list_entry, &rdma_hndl->tx_ready_list);

	xio_rdma_xmit(rdma_hndl);

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
	int retval = -1;

	switch (task->tlv_type) {
	case XIO_NEXUS_SETUP_REQ:
		retval = xio_rdma_send_setup_req(rdma_hndl, task);
		break;
	case XIO_NEXUS_SETUP_RSP:
		retval = xio_rdma_send_setup_rsp(rdma_hndl, task);
		break;
	case XIO_MSG_TYPE_RDMA:
		retval = xio_rdma_perform_direct_rdma(
			(struct xio_rdma_transport *)rdma_hndl, task);
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

/*---------------------------------------------------------------------------*/
/* xio_rdma_cancel_req_handler						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_cancel_req_handler(struct xio_rdma_transport *rdma_hndl,
				       struct xio_rdma_cancel_hdr *cancel_hdr,
				       void *ulp_msg, size_t ulp_msg_sz)
{
	union xio_transport_event_data	event_data;
	struct xio_task			*ptask, *next_ptask;
	struct xio_rdma_task		*rdma_task;
	int				found = 0;

	/* start by looking for the task rdma_rd  */
	list_for_each_entry_safe(ptask, next_ptask,
				 &rdma_hndl->rdma_rd_req_list,
				 tasks_list_entry) {
		rdma_task = ptask->dd_data;
		if (rdma_task->phantom_idx == 0 &&
		    rdma_task->sn == cancel_hdr->sn) {
			TRACE_LOG("[%d] - message found on rdma_rd_req_list\n",
				  cancel_hdr->sn);
			ptask->state = XIO_TASK_STATE_CANCEL_PENDING;
			found = 1;
			break;
		}
	}

	if (!found) {
		list_for_each_entry_safe(ptask, next_ptask,
					 &rdma_hndl->rdma_rd_req_in_flight_list,
					 tasks_list_entry) {
			rdma_task = ptask->dd_data;
			if (rdma_task->phantom_idx == 0 &&
			    rdma_task->sn == cancel_hdr->sn) {
				TRACE_LOG("[%d] - message found on " \
					  "rdma_rd_req_in_flight_list\n",
					  cancel_hdr->sn);
				ptask->state = XIO_TASK_STATE_CANCEL_PENDING;
				found = 1;
				break;
			}
		}
	}

	if (!found) {
		TRACE_LOG("[%d] - was not found\n", cancel_hdr->sn);
		/* fill notification event */
		event_data.cancel.ulp_msg	   =  ulp_msg;
		event_data.cancel.ulp_msg_sz	   =  ulp_msg_sz;
		event_data.cancel.task		   =  NULL;
		event_data.cancel.result	   =  0;

		xio_transport_notify_observer(
				&rdma_hndl->base,
				XIO_TRANSPORT_EVENT_CANCEL_REQUEST,
				&event_data);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_cancel_req_handler						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_cancel_rsp_handler(struct xio_rdma_transport *rdma_hndl,
				       struct xio_rdma_cancel_hdr *cancel_hdr,
				       void *ulp_msg, size_t ulp_msg_sz)
{
	union xio_transport_event_data	event_data;
	struct xio_task			*ptask, *next_ptask;
	struct xio_rdma_task		*rdma_task;
	struct xio_task			*task_to_cancel = NULL;

	if ((cancel_hdr->result ==  XIO_E_MSG_CANCELED) ||
	    (cancel_hdr->result ==  XIO_E_MSG_CANCEL_FAILED)) {
		/* look in the in_flight */
		list_for_each_entry_safe(ptask, next_ptask,
					 &rdma_hndl->in_flight_list,
				tasks_list_entry) {
			rdma_task = ptask->dd_data;
			if (rdma_task->sn == cancel_hdr->sn) {
				task_to_cancel = ptask;
				break;
			}
		}
		if (!task_to_cancel) {
			/* look in the tx_comp */
			list_for_each_entry_safe(ptask, next_ptask,
						 &rdma_hndl->tx_comp_list,
					tasks_list_entry) {
				rdma_task = ptask->dd_data;
				if (rdma_task->sn == cancel_hdr->sn) {
					task_to_cancel = ptask;
					break;
				}
			}
		}

		if (!task_to_cancel)  {
			ERROR_LOG("[%d] - Failed to found canceled message\n",
				  cancel_hdr->sn);
			/* fill notification event */
			event_data.cancel.ulp_msg	=  ulp_msg;
			event_data.cancel.ulp_msg_sz	=  ulp_msg_sz;
			event_data.cancel.task		=  NULL;
			event_data.cancel.result	=  XIO_E_MSG_NOT_FOUND;

			xio_transport_notify_observer(
					&rdma_hndl->base,
					XIO_TRANSPORT_EVENT_CANCEL_RESPONSE,
					&event_data);
			return 0;
		}
	}

	/* fill notification event */
	event_data.cancel.ulp_msg	   =  ulp_msg;
	event_data.cancel.ulp_msg_sz	   =  ulp_msg_sz;
	event_data.cancel.task		   =  task_to_cancel;
	event_data.cancel.result	   =  cancel_hdr->result;

	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_EVENT_CANCEL_RESPONSE,
				      &event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_recv_cancel_rsp						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_recv_cancel_rsp(struct xio_rdma_transport *rdma_hndl,
				       struct xio_task *task)
{
	int			retval = 0;
	struct xio_rdma_rsp_hdr	rsp_hdr;
	struct xio_msg		*imsg;
	void			*ulp_hdr;
	void			*buff;
	uint16_t		ulp_msg_sz;
	struct xio_rdma_task	*rdma_task = task->dd_data;
	struct xio_rdma_cancel_hdr cancel_hdr;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sg;

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
	/* read the sn */
	rdma_task->sn = rsp_hdr.sn;

	imsg		= &task->imsg;
	sgtbl		= xio_sg_table_get(&imsg->in);
	sgtbl_ops	= xio_sg_table_ops_get(imsg->in.sgl_type);
	sg		= sge_first(sgtbl_ops, sgtbl);

	ulp_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	imsg->type = task->tlv_type;
	imsg->in.header.iov_len		= rsp_hdr.ulp_hdr_len;
	imsg->in.header.iov_base	= ulp_hdr;
	sge_set_addr(sgtbl_ops, sg, NULL);
	tbl_set_nents(sgtbl_ops, sgtbl, 0);

	buff = imsg->in.header.iov_base;
	buff += xio_read_uint16(&cancel_hdr.hdr_len, 0, buff);
	buff += xio_read_uint16(&cancel_hdr.sn, 0, buff);
	buff += xio_read_uint32(&cancel_hdr.result, 0, buff);
	buff += xio_read_uint16(&ulp_msg_sz, 0, buff);

	xio_rdma_cancel_rsp_handler(rdma_hndl, &cancel_hdr,
				    buff, ulp_msg_sz);
	/* return the the cancel response task to pool */
	xio_tasks_pool_put(task);

	return 0;
cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_on_recv_cancel_req						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_on_recv_cancel_req(struct xio_rdma_transport *rdma_hndl,
				       struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	int			retval = 0;
	struct xio_rdma_cancel_hdr cancel_hdr;
	struct xio_rdma_req_hdr	req_hdr;
	struct xio_msg		*imsg;
	void			*ulp_hdr;
	void			*buff;
	uint16_t		ulp_msg_sz;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sg;

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

	/* read the sn */
	rdma_task->sn = req_hdr.sn;

	imsg		= &task->imsg;
	sgtbl		= xio_sg_table_get(&imsg->in);
	sgtbl_ops	= xio_sg_table_ops_get(imsg->in.sgl_type);
	sg		= sge_first(sgtbl_ops, sgtbl);

	ulp_hdr = xio_mbuf_get_curr_ptr(&task->mbuf);

	/* set header pointers */
	imsg->type = task->tlv_type;
	imsg->in.header.iov_len		= req_hdr.ulp_hdr_len;
	imsg->in.header.iov_base	= ulp_hdr;
	sge_set_addr(sgtbl_ops, sg, NULL);
	tbl_set_nents(sgtbl_ops, sgtbl, 0);

	buff = imsg->in.header.iov_base;
	buff += xio_read_uint16(&cancel_hdr.hdr_len, 0, buff);
	buff += xio_read_uint16(&cancel_hdr.sn, 0, buff);
	buff += xio_read_uint32(&cancel_hdr.result, 0, buff);
	buff += xio_read_uint16(&ulp_msg_sz, 0, buff);

	xio_rdma_cancel_req_handler(rdma_hndl, &cancel_hdr,
				    buff, ulp_msg_sz);
	/* return the the cancel request task to pool */
	xio_tasks_pool_put(task);

	return 0;

cleanup:
	retval = xio_errno();
	ERROR_LOG("xio_rdma_on_recv_req failed. (errno=%d %s)\n", retval,
		  xio_strerror(retval));
	xio_transport_notify_observer_error(&rdma_hndl->base, retval);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_cancel_req							     */
/*---------------------------------------------------------------------------*/
int xio_rdma_cancel_req(struct xio_transport_base *transport,
			struct xio_msg *req, uint64_t stag,
			void *ulp_msg, size_t ulp_msg_sz)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	struct xio_task			*ptask, *next_ptask;
	union xio_transport_event_data	event_data;
	struct xio_rdma_task		*rdma_task;
	struct  xio_rdma_cancel_hdr	cancel_hdr = {
		.hdr_len	= sizeof(cancel_hdr),
		.result		= 0
	};

	/* look in the tx_ready */
	list_for_each_entry_safe(ptask, next_ptask, &rdma_hndl->tx_ready_list,
				 tasks_list_entry) {
		if (ptask->omsg &&
		    (ptask->omsg->sn == req->sn) &&
		    (ptask->stag == stag)) {
			TRACE_LOG("[%llu] - message found on tx_ready_list\n",
				  req->sn);

			/* return decrease ref count from task */
			xio_tasks_pool_put(ptask);
			rdma_hndl->tx_ready_tasks_num--;
			list_move_tail(&ptask->tasks_list_entry,
				       &rdma_hndl->tx_comp_list);

			/* fill notification event */
			event_data.cancel.ulp_msg	=  ulp_msg;
			event_data.cancel.ulp_msg_sz	=  ulp_msg_sz;
			event_data.cancel.task		=  ptask;
			event_data.cancel.result	=  XIO_E_MSG_CANCELED;

			xio_transport_notify_observer(
					&rdma_hndl->base,
					XIO_TRANSPORT_EVENT_CANCEL_RESPONSE,
					&event_data);
			return 0;
		}
	}
	/* look in the in_flight */
	list_for_each_entry_safe(ptask, next_ptask, &rdma_hndl->in_flight_list,
				 tasks_list_entry) {
		if (ptask->omsg &&
		    (ptask->omsg->sn == req->sn) &&
		    (ptask->stag == stag) &&
		    (ptask->state != XIO_TASK_STATE_RESPONSE_RECV)) {
			TRACE_LOG("[%llu] - message found on in_flight_list\n",
				  req->sn);

			rdma_task	= ptask->dd_data;
			cancel_hdr.sn	= rdma_task->sn;

			xio_rdma_send_cancel(rdma_hndl, XIO_CANCEL_REQ,
					     &cancel_hdr,
					     ulp_msg, ulp_msg_sz);
			return 0;
		}
	}
	/* look in the tx_comp */
	list_for_each_entry_safe(ptask, next_ptask, &rdma_hndl->tx_comp_list,
				 tasks_list_entry) {
		if (ptask->omsg &&
		    (ptask->omsg->sn == req->sn) &&
		    (ptask->stag == stag) &&
		    (ptask->state != XIO_TASK_STATE_RESPONSE_RECV)) {
			TRACE_LOG("[%llu] - message found on tx_comp_list\n",
				  req->sn);
			rdma_task	= ptask->dd_data;
			cancel_hdr.sn	= rdma_task->sn;

			xio_rdma_send_cancel(rdma_hndl, XIO_CANCEL_REQ,
					     &cancel_hdr,
					     ulp_msg, ulp_msg_sz);
			return 0;
		}
	}
	TRACE_LOG("[%llu] - message not found on tx path\n", req->sn);

	/* fill notification event */
	event_data.cancel.ulp_msg	   =  ulp_msg;
	event_data.cancel.ulp_msg_sz	   =  ulp_msg_sz;
	event_data.cancel.task		   =  NULL;
	event_data.cancel.result	   =  XIO_E_MSG_NOT_FOUND;

	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_EVENT_CANCEL_RESPONSE,
				      &event_data);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_cancel_rsp							     */
/*---------------------------------------------------------------------------*/
int xio_rdma_cancel_rsp(struct xio_transport_base *transport,
			struct xio_task *task, enum xio_status result,
			void *ulp_msg, size_t ulp_msg_sz)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	struct xio_rdma_task	*rdma_task;

	struct  xio_rdma_cancel_hdr cancel_hdr = {
		.hdr_len	= sizeof(cancel_hdr),
		.result		= result,
	};

	if (task) {
		rdma_task = task->dd_data;
		cancel_hdr.sn = rdma_task->sn;
	} else {
		cancel_hdr.sn = 0;
	}

	/* fill dummy transport header since was handled by upper layer
	 */
	return xio_rdma_send_cancel(rdma_hndl, XIO_CANCEL_RSP,
				    &cancel_hdr, ulp_msg, ulp_msg_sz);
}
