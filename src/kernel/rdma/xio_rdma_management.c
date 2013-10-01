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
#include <linux/kernel.h>
#include <linux/module.h>

#include <rdma/rdma_cma.h>

#include "libxio.h"
#include "xio_common.h"
#include "xio_context.h"
#include "xio_task.h"
#include "xio_transport.h"
#include "xio_conn.h"
#include "xio_protocol.h"
#include "xio_mem.h"
#include "xio_rdma_mempool.h"
#include "xio_rdma_transport.h"

MODULE_AUTHOR("Eyal Solomon, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO library "
	   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static struct xio_rdma_mempool		*mempool;
static struct xio_rdma_mempool		**mempool_array;
static int				mempool_array_len;

/*---------------------------------------------------------------------------*/
/* forward declaration							     */
/*---------------------------------------------------------------------------*/
static struct xio_transport_base *xio_rdma_open(
		struct xio_transport *transport,
		struct xio_context *ctx,
		void  *observer,
		notification_handler_t notif_cb);

static void xio_rdma_close(struct xio_transport_base *transport);

static void xio_cq_event_callback(struct ib_event *cause, void *context)
{
	ERR_LOG("got cq event %d ctx(%p)\n", cause->event, context);
}

/*---------------------------------------------------------------------------*/
/* xio_cq_create							     */
/*---------------------------------------------------------------------------*/
static struct xio_cq *xio_cq_init(struct xio_device *dev,
				  struct xio_context *ctx)
{
	struct xio_cq	*tcq;
	int		comp_vec = 0;
	int		num_cores = num_online_cpus();
	u32		alloc_sz;
	int		retval;

	/* If two session were created with the same context and
	 * the address resovled on the same davice than the smae
	 * CQ is used
	 */
	read_lock_bh(&dev->cq_lock);
 	list_for_each_entry(tcq, &dev->cq_list, cq_list) {
		if (tcq->ctx == ctx) {
			atomic_inc(&tcq->refcnt);
			read_unlock_bh(&dev->cq_lock);
			return tcq;
		}
	}
	read_unlock_bh(&dev->cq_lock);

	if (ctx->cpuid < 0 || ctx->cpuid >= num_cores)
		cpu = smp_processor_id();
	else
		cpu = ctx->cpuid;

	cpu = cpu % dev->cqs_used;

	tcq = kzalloc(sizeof(struct xio_cq), GFP_KERNEL);
	if (!tcq) {
		ERROR_LOG("xio_cq_init kzalloc failed\n");
		goto cleanup0;
	}

	alloc_sz = min(dev->device_attr.max_cqe, CQE_ALLOC_SIZE);
	tcq->max_cqe  = dev->device_attr.max_cqe;
	tcq->cq_depth	= tcq->alloc_sz;
	tcq->cqe_avail	= tcq->alloc_sz;
	atomic_set(&tcq->refcnt, 1);

	tcq->dev	= dev;
	tcq->max_cqe	= dev->device_attr.max_cqe;
	tcq->alloc_sz	= alloc_sz;
	tcq->cq_depth	= alloc_sz;
	tcq->cqe_avail	= alloc_sz;

	/* xio_rdma_poll doesn't support separate tx & rx poll
	 * so we use only one cq fro RX and TX
	 */

	tcq->cq = ib_create_cq(dev->ib_dev,
			       xio_cq_data_callback,
			       xio_cq_event_callback,
			       (void *)tcq,
			       alloc_sz, cpu);
	if (IS_ERR(tcq->cq)) {
		ERROR_LOG("ib_create_cq err(%d)\n", ERR_PTR(tcq->cq));
		goto cleanup1;
	}

	/* we don't expect missed events (if supported) so it is an error */
	if (ib_req_notify_cq(tcq->cq,
			     IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS)) {
		ERROR_LOG("ib_req_notify_cq\n");
		goto cleanup2;
	}

	INIT_LIST_HEAD(&tcq->trans_list);

	write_lock_bh(&dev->cq_lock);
	list_add(&tcq->cq_list, dev->cq_list);
	write_unlock_bh(&dev->cq_lock);

	/* set the tcq rdma_hndl to be a context observer */
	xio_context_add_observer(ctx, tcq, xio_on_context_event);

	return tcq;

cleanup2:
	ib_destroy_cq(tcq->rxq);
cleanup1:
	kfree(tcq);
cleanup0:
	ERROR_LOG("xio_cq_init failed\n");
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_cq_release							     */
/*---------------------------------------------------------------------------*/
static void xio_cq_release(struct xio_cq *tcq)
{
	int retval;

	write_lock_bh(&dev->cq_lock);
	list_del_init(&tcq->cq_list_entry);
	write_unlock_bh(&dev->cq_lock);

	/*the event loop may be release by the time this fuction is called */
	retval = ib_destroy_cq(tcq->cq);
	if (retval)
		ERROR_LOG("ibv_destroy_cq failed. (errno=%d %m)\n", retval);


	kfree(tcq->wc_array);
	kfree(tcq);
}

/*---------------------------------------------------------------------------*/
/* xio_dev_event_handler						     */
/*---------------------------------------------------------------------------*/
static void xio_dev_event_handler(struct ib_event_handler *handler,
				struct ib_event *event)
{
	ERR_LOG("async event %d on device %s port %d\n", event->event,
		event->device->name, event->element.port_num);
}

/*---------------------------------------------------------------------------*/
/* xio_device_init							     */
/*---------------------------------------------------------------------------*/
static struct xio_device *xio_device_init(struct ib_device *ib_dev, int port)
{
	struct xio_device	*dev;
	int			retval;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL) {
		xio_set_error(errno);
		ERROR_LOG("malloc failed. (errno=%d %m)\n", errno);
		goto cleanup0;
	}

	retval = ib_query_device(ib_dev, &dev->device_attr);
	if (retval < 0) {
		ERROR_LOG("ibv_query_device failed. (errno=%d %m)\n", errno);
		goto cleanup1;
	}

#if 0
	/* Assign function handles  - based on FMR support */
	if (ib_dev->alloc_fmr && ib_dev->dealloc_fmr &&
	    ib_dev->map_phys_fmr && ib_dev->unmap_fmr) {
		INFO_LOG("FMR supported, using FMR for registration\n");
		dev->alloc_rdma_reg_res = xio_create_fmr_pool;
		dev->free_rdma_reg_res = xio_free_fmr_pool;
		dev->reg_rdma_mem = xio_reg_rdma_mem_fmr;
		dev->unreg_rdma_mem = xio_unreg_mem_fmr;
	} else if (dev->dev_attr.device_cap_flags &
		   IB_DEVICE_MEM_MGT_EXTENSIONS) {
		INFO_LOG("FRWR supported, using FRWR for registration\n");
		dev->alloc_rdma_reg_res = xio_create_frwr_pool;
		dev->free_rdma_reg_res = xio_free_frwr_pool;
		dev->reg_rdma_mem = xio_reg_rdma_mem_frwr;
		dev->unreg_rdma_mem = xio_unreg_mem_frwr;
	} else {
		ERROR_LOG("IB device does not support FMRs nor FRWRs, can't register memory\n");
		goto cleanup1;
	}
#endif

	dev->ib_dev = ib_dev;
	dev->port_num = port;

	dev->pd = ib_alloc_pd(ib_dev);
	if (dev->pd == NULL) {
		xio_set_error(errno);
		ERROR_LOG("ibv_alloc_pd failed. (errno=%d %m)\n", errno);
		goto cleanup1;
	}

	dev->mr = ib_get_dma_mr(dev->pd,
				IB_ACCESS_LOCAL_WRITE |
				IB_ACCESS_REMOTE_WRITE |
				IB_ACCESS_REMOTE_READ);
	if (IS_ERR(dev->mr)) {
		xio_set_error(errno);
		ERROR_LOG("ib_get_dma_mr failed. (errno=%d %m)\n", errno);
		goto cleanup2;
	}


	rwlock_init(&dev->cq_lock);
	INIT_LIST_HEAD(&dev->cq_list);
	num_cores = num_online_cpus();
	num_cores = roundup_pow_of_two(num_cores);
	dev->cqs_used = min(num_cores, dev->device_attr.num_comp_vectors);

	TRACE_LOG("rdma device: [new] %p\n", dev);

	INIT_IB_EVENT_HANDLER(&dev->event_handler, dev->ib_dev,
			      xio_dev_event_handler);

	if (ib_register_event_handler(&dev->event_handler))
		goto cleanup3;

	return dev;

cleanup3:
	ib_dereg_mr(dev->mr);
cleanup2:
	ibv_dealloc_pd(dev->pd);
cleanup1:
	kfree(dev);
cleanup0:
	ERROR_LOG("rdma device: [new] failed\n");
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_device_release							     */
/*---------------------------------------------------------------------------*/
static void xio_device_release(struct xio_device *dev)
{
	int			retval;
	struct xio_cq		*tcq, *next;

	TRACE_LOG("rdma device: [close] dev:%p\n", dev);

	(void)ib_unregister_event_handler(&device->event_handler);

	list_for_each_entry_safe(tcq, next, &dev->cq_list, cq_list_entry) {
		xio_cq_release(tcq);
	}

	if (xio_dev->fmr_pool)
		ib_destroy_fmr_pool(xio_dev->fmr_pool);

	ib_dereg_mr(dev->mr);
	ib_dealloc_pd(dev->pd);

	kfree(dev);
}

/*---------------------------------------------------------------------------*/
/* xio_rmda_mempool_array_init						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_mempool_array_init()
{
	/* kernel mempool is numa based */
	mempool_array = &mempool;
	mempool_array_len = 1;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_array_release					     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_mempool_array_release()
{
	/* kernel mempool is numa based */

	mempool_array = NULL;
	if (mempool)
		xio_rdma_mempool_destroy(mempool);
	mempool = NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_array_get						     */
/*---------------------------------------------------------------------------*/
static struct xio_rdma_mempool *xio_rdma_mempool_array_get(
						struct xio_context *ctx)
{
	/* kernel mempool is numa based */
	if (mempool)
		return mempool;

	mempool = xio_rdma_mempool_create();
	if (mempool) {
		ERROR_LOG("xio_rdma_mempool_create failed\m");
		return NULL;
	}
	return mempool;
}

/*---------------------------------------------------------------------------*/
/* xio_on_context_close							     */
/*---------------------------------------------------------------------------*/
static void xio_on_context_close(void *observer,
				 struct xio_context *ctx)
{
	struct xio_cq *tcq = (struct xio_cq *) observer;

	xio_context_remove_observer(ctx, observer);

	xio_cq_release(tcq);
}

/*---------------------------------------------------------------------------*/
/* xio_on_context_event							     */
/*---------------------------------------------------------------------------*/
static int xio_on_context_event(void *observer, void *sender,
				int event, void *event_data)
{
	if (event == XIO_CONTEXT_EVENT_CLOSE) {
		TRACE_LOG("context: [close] ctx:%p\n", sender);
		xio_on_context_close(observer, sender);
	}

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_cq_alloc_slots							     */
/*---------------------------------------------------------------------------*/
static int xio_cq_alloc_slots(struct xio_cq *tcq, int cqe_num)
{
	if (cqe_num < tcq->cqe_avail) {
		tcq->cqe_avail -= cqe_num;
		return 0;
	} else if (tcq->cq_depth + tcq->alloc_sz < tcq->max_cqe) {
		int retval = ib_resize_cq(tcq->cq,
					  tcq->cq_depth + tcq->alloc_sz);
		if (retval != 0) {
			ERROR_LOG("ibv_resize_cq failed. %m\n");
			return -1;
		}
		tcq->cq_depth  += tcq->alloc_sz;
		tcq->cqe_avail += tcq->alloc_sz;
		tcq->cqe_avail -= cqe_num;
		return 0;
	} else {
		ERROR_LOG("cq overflow reached\n");
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_cq_free_slots							     */
/*---------------------------------------------------------------------------*/
static int xio_cq_free_slots(struct xio_cq *tcq, int cqe_num)
{
	if (tcq->cqe_avail + cqe_num <= tcq->cq_depth) {
		tcq->cqe_avail += cqe_num;
		return 0;
	}
	ERROR_LOG("cq allocation error");

	return 0;
}

static void xio_qp_event_handler(struct ib_event *cause, void *context)
{
	ERR_LOG("got qp event %d\n",cause->event);
}

/*---------------------------------------------------------------------------*/
/* xio_setup_qp                                                              */
/*---------------------------------------------------------------------------*/
static int xio_setup_qp(struct xio_rdma_transport *rdma_hndl)
{
	struct xio_device		*dev;
	struct ib_qp_init_attr		qp_attr;
	int				dev_found = 0;
	int				retval = 0;
	struct	xio_cq			*tcq;

	/* Shold be set by now */
	dev = rdma_hndl->dev;
	if (!dev) {
		ERROR_LOG("failed to find device\n");
		return -1;
	}

	tcq = xio_cq_init(dev, rdma_hndl->base.ctx);
	if (tcq == NULL) {
		ERROR_LOG("cq initialization failed\n");
		return -1;
	}

	retval = xio_cq_alloc_slots(tcq, MAX_CQE_PER_QP);
	if (retval != 0) {
		ERROR_LOG("cq full capacity reached\n");
		return -1;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));

	qp_attr.event_handler		= xio_qp_event_handler;
	qp_attr.qp_context		= rdma_hndl;
	qp_attr.qp_type			= IBV_QPT_RC;
	qp_attr.send_cq			= tcq->cq;
	qp_attr.recv_cq			= tcq->cq;
	qp_attr.cap.max_send_wr		= MAX_SEND_WR;
	qp_attr.cap.max_recv_wr		= MAX_RECV_WR + EXTRA_RQE;
	qp_attr.cap.max_inline_data	= MAX_INLINE_DATA;
	qp_attr.cap.max_send_sge	= MAX_SGE;
	qp_attr.cap.max_recv_sge	= MAX_SGE;

	/* only generate completion queue entries if requested */
	qp_attr.sq_sig_all		= 0;

	retval = rdma_create_qp(rdma_hndl->cm_id, dev->pd, &qp_attr);
	if (retval) {
		xio_set_error(errno);
		xio_cq_free_slots(tcq, MAX_CQE_PER_QP);
		ERROR_LOG("rdma_create_qp failed. (errno=%d %m)\n", errno);
		return -1;
	}
	rdma_hndl->dev		= dev;
	rdma_hndl->tcq		= tcq;
	rdma_hndl->qp		= rdma_hndl->cm_id->qp;
	rdma_hndl->sqe_avail	= MAX_SEND_WR;

	list_add(&rdma_hndl->trans_list, &tcq->trans_list);

	TRACE_LOG("rdma qp: [new] handle:%p, qp:0x%x\n", rdma_hndl,
		  rdma_hndl->qp->qp_num);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_release_qp							     */
/*---------------------------------------------------------------------------*/
static void xio_release_qp(struct xio_rdma_transport *rdma_hndl)
{
	if (rdma_hndl->qp) {
		TRACE_LOG("rdma qp: [close] handle:%p, qp:0x%x\n", rdma_hndl,
			  rdma_hndl->qp->qp_num);
		xio_cq_free_slots(rdma_hndl->tcq, MAX_CQE_PER_QP);
		list_del(&rdma_hndl->trans_list);
		rdma_destroy_qp(rdma_hndl->cm_id);
		rdma_hndl->qp	= NULL;
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rxd_init								     */
/*---------------------------------------------------------------------------*/
static void xio_rxd_init(struct xio_work_req *rxd,
			   struct xio_task *task,
			   void *buf, unsigned size,
			   struct ib_mr *srmr)
{
	struct page *page,
	unsigned int offset;

	/* This address need to be dma mapped */
	rxd->sge[0].addr	= uint64_from_ptr(buf);
	rxd->sge[0].length	= size;
	rxd->sge[0].lkey	= srmr->lkey;

	rxd->recv_wr.wr_id	= uint64_from_ptr(task);
	rxd->recv_wr.sg_list	= rxd->sge;
	rxd->recv_wr.num_sge	= 1;
	rxd->recv_wr.next	= NULL;

	sg_init_table(rxd->sgl, XIO_MAX_IOV + 1);

	page = virt_to_page(buf);
	offset = buf - page_to_virt(page);
	sg_set_page(rxd->sgl, page, size, offset);
	rxd->nents  = 1;
	rxd->mapped = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_txd_init								     */
/*---------------------------------------------------------------------------*/
static void xio_txd_init(struct xio_work_req *txd,
			  struct xio_task *task,
			  void *buf, unsigned size,
			  struct ib_mr *srmr)
{
	struct page *page,
	unsigned int offset;

	/* This address need to be dma mapped */
	txd->sge[0].addr	= uint64_from_ptr(buf);
	txd->sge[0].length	= size;
	txd->sge[0].lkey	= srmr->lkey;

	txd->send_wr.wr_id	= uint64_from_ptr(task);
	txd->send_wr.next	= NULL;
	txd->send_wr.sg_list	= txd->sge;
	txd->send_wr.num_sge	= 1;
	txd->send_wr.opcode	= IBV_WR_SEND;

	sg_init_table(txd->sgl, XIO_MAX_IOV + 1);

	page = virt_to_page(buf);
	offset = buf - page_to_virt(page);
	sg_set_page(txd->sgl, page, size, offset);
	txd->nents  = 1;
	txd->mapped = 0;

	/*txd->send_wr.send_flags = IBV_SEND_SIGNALED; */
}

/*---------------------------------------------------------------------------*/
/* xio_rdmad_init							     */
/*---------------------------------------------------------------------------*/
static void xio_rdmad_init(struct xio_work_req *rdmad,
			   struct xio_task *task)
{
	rdmad->send_wr.wr_id = uint64_from_ptr(task);
	rdmad->send_wr.sg_list = rdmad->sge;
	rdmad->send_wr.num_sge = 1;
	rdmad->send_wr.next = NULL;
	rdmad->send_wr.send_flags = IBV_SEND_SIGNALED;

	sg_init_table(rdmad->sgl, XIO_MAX_IOV + 1);

	rdmad->nents  = 1;
	rdmad->mapped = 0;

	/* to be set before posting:
	   rdmad->xio_ib_op, rdmad->send_wr.opcode
	   rdmad->sge.addr, rdmad->sge.length
	   rdmad->send_wr.wr.rdma.(remote_addr,rkey) */
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_task_init							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_task_init(struct xio_task *task,
				 struct xio_rdma_transport *rdma_hndl,
				 void *buf,
				 unsigned long size,
				 struct ibv_mr *srmr)
{
	struct xio_rdma_task *rdma_task =
		(struct xio_rdma_task *)task->dd_data;

	rdma_task->rdma_hndl = rdma_hndl;
	rdma_task->buf = buf;

	xio_rxd_init(&rdma_task->rxd, task, buf, size, srmr);
	xio_txd_init(&rdma_task->txd, task, buf, size, srmr);
	xio_rdmad_init(&rdma_task->rdmad, task);

	/* initialize the mbuf */
	xio_mbuf_init(&task->mbuf, buf, size, 0);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_flush_task_list						     */
/*---------------------------------------------------------------------------*/
int xio_rdma_flush_task_list(struct xio_rdma_transport *rdma_hndl,
				    struct list_head *list)
{
	struct xio_task *ptask, *next_ptask;

	list_for_each_entry_safe(ptask, next_ptask, list,
				 tasks_list_entry) {
		TRACE_LOG("flushing task %p type 0x%x, refcnt:%d\n",
			  ptask, ptask->tlv_type, ptask->refcnt);
		if (ptask->sender_task) {
			xio_conn_put_task(rdma_hndl->base.observer,
					  ptask->sender_task);
			ptask->sender_task = NULL;
		}
		xio_conn_put_task(rdma_hndl->base.observer, ptask);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_calc_pool_size						     */
/*---------------------------------------------------------------------------*/
void xio_rdma_calc_pool_size(struct xio_rdma_transport *rdma_hndl)
{
	/* four queues are invloved:
	 * tx_ready_queue, recv_queue, sent_queue, io_submit_queue,
	 * also note that client holds the sent and recv tasks
	 * simultanousely */

	rdma_hndl->num_tasks = 8*(rdma_hndl->sq_depth +
				  rdma_hndl->actual_rq_depth);
	rdma_hndl->alloc_sz  = rdma_hndl->num_tasks*rdma_hndl->membuf_sz;

	TRACE_LOG("pool size:  alloc_sz:%zd, num_tasks:%d, buf_sz:%zd\n",
		  rdma_hndl->alloc_sz,
		  rdma_hndl->num_tasks,
		  rdma_hndl->membuf_sz);
}


/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_alloc						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_initial_pool_alloc(
		struct xio_transport_base *transport_hndl,
		int max, void *pool_dd_data)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;

	rdma_pool->buf_size = CONN_SETUP_BUF_SIZE;
	rdma_pool->data_pool = kcalloc(max, rdma_pool->buf_size, GFP_KERNEL);
	if (rdma_pool->data_pool == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcalloc conn_setup_data_pool %dX%d failed\n",
			  max, rdma_pool->buf_size);
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_run						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_initial_pool_run(
		struct xio_transport_base *transport_hndl)
{
	struct xio_task *task;
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	struct xio_rdma_task *rdma_task;
	int	retval;

	task = xio_conn_get_initial_task(rdma_hndl->base.observer);
	if (task == NULL) {
		ERROR_LOG("failed to get task\n");
	} else {
		DEBUG_LOG("post_recv conn_setup rx task:%p\n", task);
		retval = xio_post_recv(rdma_hndl, task, 1);
		if (retval)
			ERROR_LOG("xio_post_recv failed\n");

		/* assuming that both sides posted one recv wr for initial
		 * negotiation
		 */
		rdma_hndl->peer_credits	= 1;
		rdma_hndl->sim_peer_credits = 1;
		rdma_task = (struct xio_rdma_task *)task->dd_data;

		rdma_task->ib_op	= XIO_IB_RECV;
		list_add_tail(&task->tasks_list_entry, &rdma_hndl->rx_list);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_free						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_initial_pool_free(
		struct xio_transport_base *transport_hndl, void *pool_dd_data)
{
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;

	kfree(rdma_pool->data_pool);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_init_task					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_pool_unnit_task(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, struct xio_task *task)
{
	sg_free_table(&rdma_task->read_sge.table);
	sg_free_table(&rdma_task->write_sge.table);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_init_task					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_initial_pool_init_task(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, struct xio_task *task)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;
	void *buf = rdma_pool->data_pool + (task->ltid*rdma_pool->buf_size);

	return xio_rdma_task_init(task,
				  rdma_hndl,
				  buf,
				  rdma_pool->buf_size,
				  rdma_hndl->dev->mr);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_get_params					     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_initial_pool_get_params(
		struct xio_transport_base *transport_hndl,
		int *pool_len, int *pool_dd_sz, int *task_dd_sz)
{
	*pool_len = NUM_CONN_SETUP_TASKS;
	*pool_dd_sz = sizeof(struct xio_rdma_tasks_pool);
	*task_dd_sz = sizeof(struct xio_rdma_task);
}

static struct xio_tasks_pool_ops initial_tasks_pool_ops = {
	.pool_get_params	= xio_rdma_initial_pool_get_params,
	.pool_alloc		= xio_rdma_initial_pool_alloc,
	.pool_free		= xio_rdma_initial_pool_free,
	.pool_init_item		= xio_rdma_initial_pool_init_task,
	.pool_uninit_item	= xio_rdma_pool_uninit_task,
	.pool_run		= xio_rdma_initial_pool_run
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_alloc						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_primary_pool_alloc(
		struct xio_transport_base *transport_hndl,
		int max, void *pool_dd_data)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;

	rdma_pool->buf_size = rdma_hndl->membuf_sz;
#ifdef EYAL_TODO
	rdma_pool->data_mr = xio_rdma_alloc_mr(rdma_hndl->tcq->dev,
						 rdma_hndl->alloc_sz);
	if (rdma_pool->data_mr != NULL)
		rdma_pool->data_pool = rdma_pool->data_mr->addr;
	else
#endif
	{
		rdma_pool->data_pool = malloc_huge_pages(rdma_hndl->alloc_sz);
		if (!rdma_pool->data_pool) {
			xio_set_error(ENOMEM);
			ERROR_LOG("malloc rdma pool sz:%zu failed\n",
				  rdma_hndl->alloc_sz);
			return -1;
		}

		/* One pool of registered memory per PD */
		rdma_pool->data_mr = ibv_reg_mr(rdma_hndl->tcq->dev->pd,
				rdma_pool->data_pool,
				rdma_hndl->alloc_sz,
				IBV_ACCESS_LOCAL_WRITE);
		if (!rdma_pool->data_mr) {
			xio_set_error(errno);
			free_huge_pages(rdma_pool->data_pool);
			ERROR_LOG("ibv_reg_mr failed, %m\n");
			return -1;
		}
	}
	DEBUG_LOG("pool buf:%p, mr:%p lkey:0x%x\n",
		  rdma_pool->data_pool, rdma_pool->data_mr,
		  rdma_pool->data_mr->lkey);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_run						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_primary_pool_run(
		struct xio_transport_base *transport_hndl)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;

	xio_rdma_rearm_rq(rdma_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_free						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_primary_pool_free(
		struct xio_transport_base *transport_hndl, void *pool_dd_data)
{
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;

	ibv_dereg_mr(rdma_pool->data_mr);
	free_huge_pages(rdma_pool->data_pool);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_init_task					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_primary_pool_init_task(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, struct xio_task *task)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;
	void *buf = rdma_pool->data_pool + (task->ltid*rdma_pool->buf_size);

	struct xio_rdma_task *rdma_task = (struct xio_rdma_task *)task->dd_data;
	rdma_task->ib_op = 0x200;

	return xio_rdma_task_init(task,
				  rdma_hndl,
				  buf,
				  rdma_pool->buf_size,
				  rdma_hndl->dev->mr);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_get_params					     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_primary_pool_get_params(
		struct xio_transport_base *transport_hndl, int *pool_len,
		int *pool_dd_sz, int *task_dd_sz)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;

	*pool_len = rdma_hndl->num_tasks;
	*pool_dd_sz = sizeof(struct xio_rdma_tasks_pool);
	*task_dd_sz = sizeof(struct xio_rdma_task);
}

static struct xio_tasks_pool_ops   primary_tasks_pool_ops = {
	.pool_get_params	= xio_rdma_primary_pool_get_params,
	.pool_alloc		= xio_rdma_primary_pool_alloc,
	.pool_free		= xio_rdma_primary_pool_free,
	.pool_init_item		= xio_rdma_primary_pool_init_task,
	.pool_uninit_item	= xio_rdma_pool_uninit_task,
	.pool_run		= xio_rdma_primary_pool_run,
	.pre_put		= xio_rdma_task_put,
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_close_complete		                                     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_close_complete(struct xio_transport_base *transport)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;

	TRACE_LOG("rdma transport: [close_comp] handle:%p, qp:%p\n",
		  rdma_hndl, rdma_hndl->qp);

	xio_release_qp(rdma_hndl);
	if (rdma_hndl->cm_id)
		rdma_destroy_id(rdma_hndl->cm_id);

	kfree(rdma_hndl->base.portal_uri);

	kfree(rdma_hndl);
}

/*---------------------------------------------------------------------------*/
/* on_cm_addr_resolved	                                                     */
/*---------------------------------------------------------------------------*/
static void on_cm_addr_resolved(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	int				retval = 0;

	retval = rdma_resolve_route(rdma_hndl->cm_id, ROUTE_RESOLVE_TIMEOUT);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("rdma_resolve_route failed. (errno=%d %m)\n", errno);
		xio_rdma_notify_observer_error(rdma_hndl, xio_errno());
	}
}

/*---------------------------------------------------------------------------*/
/* on_cm_route_resolved (client)					     */
/*---------------------------------------------------------------------------*/
static void on_cm_route_resolved(struct rdma_cm_id *cma_id,
				 struct rdma_cm_event *ev,
				 struct xio_rdma_transport *rdma_hndl)
{
	int				retval = 0;
	struct rdma_conn_param		cm_params = {
		.initiator_depth		= 1,
		.responder_resources		= 1,
		.rnr_retry_count		= 0, /* 7 - infinite retry */
		.retry_count			= 0
	};
	struct xio_device *xio_dev;

	/* Find the device on which the connection was established */
	xio_devs = ib_get_client_data(cma_id->device, &xio_client);
	if (!(xio_devs && xio_devs[cma_id->port_num])) {
		ERROR_LOG("device(%s) port(%d) not registerd\n",
			  ib_get_device_name(cma_id->device),
			  cma_id->port_num);
		xio_set_error(ENODEV);
		goto notify_err1;
	}

	rdma_hndl->dev = xio_devs[cma_id->port_num];

	retval = xio_setup_qp(rdma_hndl);
	if (retval != 0) {
		ERROR_LOG("internal logic error in create_endpoint\n");
		goto notify_err1;
	}

	/*
	 * When choosing the responder resources for a ULP, it is usually
	 * best to use the maximum value of the HCA.  If the other side is
	 * not going to use RDMA read, then it should zero out the
	 * initiator_depth in the REP, which will zero out the local
	 * responder_resources when we program the QP. Generally, the
	 * initiator_depth should be either set to 0 or
	 * min(max_qp_rd_atom, max_send_wr).  Use 0 if RDMA read is
	 * never going to be sent from this side.
	 */
	cm_params.responder_resources =
		rdma_hndl->tcq->dev->device_attr.max_qp_rd_atom;
	cm_params.initiator_depth =
		rdma_hndl->tcq->dev->device_attr.max_qp_init_rd_atom;

	/* connect to peer */
	retval = rdma_connect(rdma_hndl->cm_id, &cm_params);
	if (retval != 0) {
		xio_set_error(ENOMEM);

		ERROR_LOG("rdma_connect failed. (errno=%d %m)\n", errno);
		goto notify_err2;
	}
	rdma_hndl->client_responder_resources = cm_params.responder_resources;
	rdma_hndl->client_initiator_depth = cm_params.initiator_depth;


	return;

notify_err2:
	xio_release_qp(rdma_hndl);
notify_err1:
	xio_rdma_notify_observer_error(rdma_hndl, xio_errno());
}

/*---------------------------------------------------------------------------*/
/* on_cm_connect_request (server)					     */
/*---------------------------------------------------------------------------*/
static void  on_cm_connect_request(struct rdma_cm_id *cma_id,
				   struct rdma_cm_event *ev,
				   struct xio_rdma_transport *parent_hndl)
{
	struct xio_rdma_transport *child_hndl;
	union xio_transport_event_data event_data;
	int	retval = 0;

	struct xio_device **xio_devs;

	/* Find the device on which the connection was established */
	xio_devs = ib_get_client_data(cma_id->device, &xio_client);
	if (!(xio_devs && xio_devs[cma_id->port_num])) {
		ERROR_LOG("device(%s) port(%d) not registerd\n",
			  ib_get_device_name(cma_id->device),
			  cma_id->port_num);
		xio_set_error(ENODEV);
		goto notify_err1;
	}

	rdma_hndl->dev = xio_devs[cma_id->port_num];

	child_hndl = (struct xio_rdma_transport *)xio_rdma_open(
		parent_hndl->transport,
		parent_hndl->base.ctx,
		NULL,
		parent_hndl->base.notify_observer);
	if (child_hndl == NULL) {
		ERROR_LOG("failed to open rdma transport\n");
		goto notify_err1;
	}

	child_hndl->dev		= xio_dev;
	child_hndl->cm_id	= cma_id;
	child_hndl->qp		= cma_id->qp;
	child_hndl->tcq		= parent_hndl->tcq;
	/* Can we set it ? is it a new cm_id */
	cma_id->context		= child_hndl;
	child_hndl->client_initiator_depth =
		ev->param.conn.initiator_depth;
	child_hndl->client_responder_resources =
		ev->param.conn.responder_resources;

	/* initiator is dst, target is src */
	memcpy(&child_hndl->base.peer_addr,
	       &child_hndl->cm_id->route.addr.dst_addr,
	       sizeof(child_hndl->base.peer_addr));
	child_hndl->base.proto = XIO_PROTO_RDMA;

	retval = xio_setup_qp(child_hndl);
	if (retval != 0) {
		ERROR_LOG("failed to setup qp\n");
		goto notify_err2;
	}
	/* set pools operations */
	xio_conn_set_pools_ops(parent_hndl->base.observer,
			       &initial_tasks_pool_ops,
			       &primary_tasks_pool_ops);

	event_data.new_connection.child_trans_hndl =
		(struct xio_transport_base *)child_hndl;
	xio_rdma_notify_observer(parent_hndl,
				 XIO_TRANSPORT_NEW_CONNECTION,
				 &event_data);

	return;

notify_err2:
	xio_rdma_close((struct xio_transport_base *)child_hndl);

notify_err1:
	xio_rdma_notify_observer_error(parent_hndl, xio_errno());
}

/*---------------------------------------------------------------------------*/
/* on_cm_rejected							     */
/*---------------------------------------------------------------------------*/
static void  on_cm_rejected(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	xio_rdma_notify_observer(rdma_hndl, XIO_TRANSPORT_REJECTED, NULL);
}

/*---------------------------------------------------------------------------*/
/* on_cm_established						             */
/*---------------------------------------------------------------------------*/
static void  on_cm_established(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	/* set pools operations  */
	xio_conn_set_pools_ops(rdma_hndl->base.observer,
			       &initial_tasks_pool_ops,
			       &primary_tasks_pool_ops);

	xio_rdma_notify_observer(rdma_hndl, XIO_TRANSPORT_ESTABLISHED,
				 NULL);
}

/*---------------------------------------------------------------------------*/
/* on_cm_disconnected							     */
/*---------------------------------------------------------------------------*/
static void  on_cm_disconnected(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	TRACE_LOG("on_cm_disconnected\n");
	if (rdma_hndl->state == XIO_STATE_CONNECTED)  {
		rdma_hndl->state = XIO_STATE_DISCONNECTED;
		DEBUG_LOG("on_cm_disconnected: state is now disconnected\n");
		int retval = rdma_disconnect(rdma_hndl->cm_id);
		if (retval)
			ERROR_LOG("conn:%p rdma_disconnect failed, %m\n",
				  rdma_hndl);
	}
}

/*
 * Handle RDMA_CM_EVENT_TIMEWAIT_EXIT which is expected to be the last
 * event during the lifecycle of a connection, when it had been shut down
 * and the network has cleared from the remaining in-flight messages.
*/
/*---------------------------------------------------------------------------*/
/* on_cm_timedwait_exit							     */
/*---------------------------------------------------------------------------*/
static void on_cm_timewait_exit(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	TRACE_LOG("on_cm_timedwait_exit\n");

	if (!list_empty(&rdma_hndl->in_flight_list)) {
		TRACE_LOG("in_flight_list not empty!\n");
		xio_rdma_flush_task_list(rdma_hndl, &rdma_hndl->in_flight_list);
		/* for task that attched to senders with ref coount = 2 */
		xio_rdma_flush_task_list(rdma_hndl, &rdma_hndl->in_flight_list);
	}

	if (!list_empty(&rdma_hndl->rdma_rd_in_flight_list)) {
		TRACE_LOG("rdma_rd_in_flight_list not empty!\n");
		xio_rdma_flush_task_list(rdma_hndl,
					 &rdma_hndl->rdma_rd_in_flight_list);
	}

	if (!list_empty(&rdma_hndl->rdma_rd_list)) {
		TRACE_LOG("rdma_rd_list not empty!\n");
		xio_rdma_flush_task_list(rdma_hndl, &rdma_hndl->rdma_rd_list);
	}

	if (!list_empty(&rdma_hndl->tx_comp_list)) {
		TRACE_LOG("tx_comp_list not empty!\n");
		xio_rdma_flush_task_list(rdma_hndl, &rdma_hndl->tx_comp_list);
	}
	if (!list_empty(&rdma_hndl->io_list)) {
		TRACE_LOG("io_list not empty!\n");
		xio_rdma_flush_task_list(rdma_hndl, &rdma_hndl->io_list);
	}

	if (!list_empty(&rdma_hndl->tx_ready_list)) {
		TRACE_LOG("tx_ready_list not empty!\n");
		xio_rdma_flush_task_list(rdma_hndl, &rdma_hndl->tx_ready_list);
		/* for task that attched to senders with ref coount = 2 */
		xio_rdma_flush_task_list(rdma_hndl, &rdma_hndl->tx_ready_list);
	}

	if (!list_empty(&rdma_hndl->rx_list)) {
		TRACE_LOG("rx_list not empty!\n");
		xio_rdma_flush_task_list(rdma_hndl, &rdma_hndl->rx_list);
	}


	if (rdma_hndl->state == XIO_STATE_DISCONNECTED) {
		xio_rdma_notify_observer(rdma_hndl,
					 XIO_TRANSPORT_DISCONNECTED, NULL);
		rdma_hndl->state = XIO_STATE_CLOSED;
	} else if (rdma_hndl->state == XIO_STATE_CLOSED) {
		xio_rdma_notify_observer(rdma_hndl, XIO_TRANSPORT_CLOSED,
					 NULL);
		xio_rdma_close_complete(
				(struct xio_transport_base *)rdma_hndl);
	}
}

/*---------------------------------------------------------------------------*/
/* on_cm_error								     */
/*---------------------------------------------------------------------------*/
static void on_cm_error(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	int	reason;

	ERROR_LOG("rdma transport [error] %s, hndl:%p\n",
		  rdma_event_str(ev->event), rdma_hndl);

	switch (ev->event) {
	case RDMA_CM_EVENT_CONNECT_ERROR:
		reason = XIO_E_CONNECT_ERROR;
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
		reason = XIO_E_ADDR_ERROR;
		break;
	case RDMA_CM_EVENT_ROUTE_ERROR:
		reason = XIO_E_ROUTE_ERROR;
		break;
	case RDMA_CM_EVENT_UNREACHABLE:
		reason = XIO_E_UNREACHABLE;
		break;
	default:
		reason = XIO_E_NOT_SUPPORTED;
		break;
	};
	xio_rdma_notify_observer_error(rdma_hndl, reason);
}

/*---------------------------------------------------------------------------*/
/* xio_handle_cm_event							     */
/*---------------------------------------------------------------------------*/
static int xio_handle_cm_event(struct rdma_cm_id *cma_id,
			       struct rdma_cm_event *ev)
{
	struct xio_rdma_transport *rdma_hndl = cma_id->context;
	struct ib_device *ib_dev = cma_id->device;

	TRACE_LOG("cm event %s, hndl:%p\n",
		  rdma_event_str(ev->event), rdma_hndl);

	switch (ev->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		on_cm_addr_resolved(ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		on_cm_route_resolved(cma_id, ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		on_cm_connect_request(cma_id, ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		on_cm_established(ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_REJECTED:
		on_cm_rejected(ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_DISCONNECTED:
		on_cm_disconnected(ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		on_cm_timewait_exit(ev, rdma_hndl);
		break;

	case RDMA_CM_EVENT_MULTICAST_JOIN:
	case RDMA_CM_EVENT_MULTICAST_ERROR:
		ERROR_LOG("Unreleated event:%d, %s - ignored\n", ev->event,
			  rdma_event_str(ev->event));
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		ERROR_LOG("Unsupported event:%d, %s - ignored\n", ev->event,
			  rdma_event_str(ev->event));
		break;

	case RDMA_CM_EVENT_CONNECT_RESPONSE:
		break;

	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	default:
		on_cm_error(ev, rdma_hndl);
		break;
	};
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_open		                                             */
/*---------------------------------------------------------------------------*/
static struct xio_transport_base *xio_rdma_open(
		struct xio_transport *transport,
		struct xio_context *ctx,
		void  *observer,
		notification_handler_t notif_cb)
{
	struct xio_rdma_transport *rdma_hndl;

	/*allocate rdma handl */
	rdma_hndl = kzalloc(sizeof(struct xio_rdma_transport));
	if (rdma_hndl == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("calloc failed. %m\n");
		return NULL;
	}

	rdma_hndl->rdma_mempool = xio_rdma_mempool_array_get(ctx);
	if (rdma_hndl->rdma_mempool == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("allocating rdma mempool failed. %m\n");
		goto cleanup;
	}

	rdma_hndl->base.portal_uri	= NULL;
	atomic_set(&rdma_hndl->base.refcnt, 1);
	rdma_hndl->transport		= transport;
	rdma_hndl->cm_id		= NULL;
	rdma_hndl->qp			= NULL;
	rdma_hndl->tcq			= NULL;
	rdma_hndl->base.ctx		= ctx;
	rdma_hndl->base.observer	= observer;
	rdma_hndl->base.notify_observer	= notif_cb;
	rdma_hndl->rq_depth		= MAX_RECV_WR;
	rdma_hndl->sq_depth		= MAX_SEND_WR;
	rdma_hndl->peer_credits		= 0;

	/* set the new rdma_hndl to be the observer */
	xio_context_add_observer(ctx, rdma_hndl, xio_on_context_event);

	INIT_LIST_HEAD(&rdma_hndl->in_flight_list);
	INIT_LIST_HEAD(&rdma_hndl->rdma_rd_in_flight_list);
	INIT_LIST_HEAD(&rdma_hndl->tx_ready_list);
	INIT_LIST_HEAD(&rdma_hndl->tx_comp_list);
	INIT_LIST_HEAD(&rdma_hndl->rx_list);
	INIT_LIST_HEAD(&rdma_hndl->io_list);
	INIT_LIST_HEAD(&rdma_hndl->rdma_rd_list);

	TRACE_LOG("rdma transport: [new] handle:%p\n", rdma_hndl);

	return (struct xio_transport_base *)rdma_hndl;

cleanup:
	kfree(rdma_hndl);

	return NULL;
}



/*
 * Start closing connection. Transfer IB QP to error state.
 * This will be followed by WC error and buffers flush events.
 * We also should expect DISCONNECTED and TIMEWAIT_EXIT events.
 * Only after the draining is over we are sure to have reclaimed
 * all buffers (and tasks). After the RDMA CM events are collected,
 * the connection QP may be destroyed, and its number may be recycled.
 */
/*---------------------------------------------------------------------------*/
/* xio_rdma_close							     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_close(struct xio_transport_base *transport)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	int	retval;
	int was = __atomic_add_unless(&rdma_hndl->base.refcnt, -1, 0);

	/* was allready 0 */
	if (!was)
		return;

	if (was == 1) {
		/* now it is zero */
		DEBUG_LOG("rdma transport: [close] handle:%p, qp:%p\n",
			  rdma_hndl, rdma_hndl->qp);

		if (rdma_hndl->state == XIO_STATE_CONNECTED) {
			rdma_hndl->state = XIO_STATE_CLOSED;
			retval = rdma_disconnect(rdma_hndl->cm_id);
			if (retval)
				ERROR_LOG("conn:%p rdma_disconnect failed, " \
					  "%d\n", rdma_hndl, retval);
		}  else  {
			xio_rdma_notify_observer(rdma_hndl,
						 XIO_TRANSPORT_CLOSED,
						 NULL);
			xio_rdma_close_complete(
				(struct xio_transport_base *)rdma_hndl);
		}
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_accept		                                             */
/*---------------------------------------------------------------------------*/
static int xio_rdma_accept(struct xio_transport_base *transport)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	int				retval;
	struct rdma_conn_param		cm_params = {
		.initiator_depth		= 1,
		.responder_resources		= 1,
		.rnr_retry_count		= 0, /* 7 - infinite retry */
		.retry_count			= 0
	};

	/*
	 * Limit the responder resources requested by the remote
	 * to our capabilities.  Note that the kernel swaps
	 * req->responder_resources and req->initiator_depth, so
	 * that req->responder_resources is actually the active
	 * side's initiator depth.
	 */
	if (rdma_hndl->client_responder_resources >
	    rdma_hndl->tcq->dev->device_attr.max_qp_rd_atom)
		cm_params.responder_resources =
			rdma_hndl->tcq->dev->device_attr.max_qp_rd_atom;
	else
		cm_params.responder_resources =
			rdma_hndl->client_responder_resources;

	/*
	 * Note: if this side of the connection is never going to
	 * use RDMA read opreations, then initiator_depth can be set
	 * to 0 here.
	 */
	if (rdma_hndl->client_initiator_depth >
	    rdma_hndl->tcq->dev->device_attr.max_qp_init_rd_atom)
		cm_params.initiator_depth =
			rdma_hndl->tcq->dev->device_attr.max_qp_init_rd_atom;
	else
		cm_params.initiator_depth = rdma_hndl->client_initiator_depth;

	/* "accept" the connection */
	retval = rdma_accept(rdma_hndl->cm_id, &cm_params);
	if (retval) {
		xio_set_error(retval);
		ERROR_LOG("rdma_accept failed. (err=%d)\n", retval);
		return -1;
	}
	rdma_hndl->client_responder_resources = cm_params.responder_resources;
	rdma_hndl->client_initiator_depth = cm_params.initiator_depth;

	TRACE_LOG("rdma transport: [accept] handle:%p\n", rdma_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_reject							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_reject(struct xio_transport_base *transport)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	int				retval;

	/* "reject" the connection */
	retval = rdma_reject(rdma_hndl->cm_id, NULL, 0);
	if (retval) {
		xio_set_error(retval);
		ERROR_LOG("rdma_reject failed. (err=%d)\n", retval);
		return -1;
	}
	TRACE_LOG("rdma transport: [reject] handle:%p\n", rdma_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_connect							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_connect(struct xio_transport_base *transport,
			    const char *portal_uri)
{
	struct xio_rdma_transport	*rdma_hndl =
		(struct xio_rdma_transport *)transport;
	union xio_sockaddr		sa;
	int				retval = 0;

		/* resolve the portal_uri */
	if (xio_uri_to_ss(portal_uri, &sa.sa_stor) == -1) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("address [%s] resolving failed\n", portal_uri);
		return -1;
	}
	/* allocate memory for portal_uri */
	rdma_hndl->base.portal_uri = kstrdup(portal_uri, GFP_KERNEL);
	if (rdma_hndl->base.portal_uri == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("calloc failed. %m\n");
		goto exit1;
	}
	rdma_hndl->base.is_client = 1;

	/* create cm id */
	rdma_hndl->cm_id = rdma_create_id(xio_handle_cm_event,
					  (void *)rdma_hndl,
					  RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(rdma_hndl->cm_id)) {
		retval = PTR_ERR(rdma_hndl->cma_id);
		xio_set_error(retval);
		ERROR_LOG("rdma_create id failed. (err=%d)\n", retval);
		goto exit2;
	}
	retval = rdma_resolve_addr(rdma_hndl->cm_id, NULL, &sa.sa,
				   ADDR_RESOLVE_TIMEOUT);
	if (retval) {
		xio_set_error(retval);
		ERROR_LOG("rdma_resolve_addr failed. (err=%d)\n", retval);
		goto exit2;
	}

	return 0;

exit2:
	rdma_destroy_id(rdma_hndl->cm_id);
	rdma_hndl->cm_id = NULL;
exit1:
	kfree(rdma_hndl->base.portal_uri);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_listen							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_listen(struct xio_transport_base *transport,
		const char *portal_uri, uint16_t *src_port)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	union xio_sockaddr	sa;
	int			retval = 0;
	uint16_t		sport;

	/* resolve the portal_uri */
	if (xio_uri_to_ss(portal_uri, &sa.sa_stor) == -1) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("address [%s] resolving failed\n", portal_uri);
		return -1;
	}
	rdma_hndl->base.is_client = 0;
	/* is_server = 1; */

	/* create cm id */
	rdma_hndl->cm_id = rdma_create_id(xio_handle_cm_event,
					  (void *)rdma_hndl,
					  RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(ib_conn->cma_id)) {
		retval = PTR_ERR(ib_conn->cma_id);
		xio_set_error(retval);
		ERROR_LOG("rdma_create id failed. (err=%d)\n", retval);
		goto exit2;
	}

	retval = rdma_bind_addr(rdma_hndl->cm_id, &sa.sa);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("rdma_bind_addr failed. (err=%d)\n", retval);
		goto exit2;
	}

	/* 0 == maximum backlog */
	retval  = rdma_listen(rdma_hndl->cm_id, 0);
	if (retval) {
		xio_set_error(retval);
		ERROR_LOG("rdma_listen failed. (err=%d)\n", retval);
		goto exit2;
	}

	sport = ntohs(rdma_get_src_port(rdma_hndl->cm_id));
	if (src_port)
		*src_port = sport;

	INFO_LOG("listen on [%s] src_port:%d\n", portal_uri, sport);

	return 0;

exit2:
	rdma_destroy_id(rdma_hndl->cm_id);
	rdma_hndl->cm_id = NULL;

	return -1;
}


/*---------------------------------------------------------------------------*/
/* xio_rdma_set_opt                                                          */
/*---------------------------------------------------------------------------*/
static int xio_rdma_set_opt(struct xio_transport_base *transport,
			      int optname, const void *optval, int optlen)
{
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_get_opt                                                          */
/*---------------------------------------------------------------------------*/
static int xio_rdma_get_opt(struct xio_transport_base *transport,
			      int optname, void *optval, int *optlen)
{
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_init						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_transport_init(struct xio_transport *transport)
{
	int retval;

	retval = xio_device_list_init();
	if (retval != 0) {
		ERROR_LOG("Failed to ininitalize device list\n");
		return -1;
	}

	xio_rdma_mempool_array_init();

	return 0;
}

/*
 * To dynamically control C-states, open the file /dev/cpu_dma_latency and
 * write the maximum allowable latency to it. This will prevent C-states with
 * transition latencies higher than the specified value from being used, as
 * long as the file /dev/cpu_dma_latency is kept open.
 * Writing a maximum allowable latency of 0 will keep the processors in C0
 * (like using kernel parameter ―idle=poll), and writing 1 should force
 * the processors to C1 when idle. Higher values could also be written to
 * restrict the use of C-states with latency greater than the value written.
 *
 * http://en.community.dell.com/techcenter/extras/m/white_papers/20227764/download.aspx
 */

/*---------------------------------------------------------------------------*/
/* xio_set_cpu_latency							     */
/*---------------------------------------------------------------------------*/
static int xio_set_cpu_latency()
{
	int32_t latency = 0;

	/* Check Documentation/power/pm_qos_interface.txt */
	DEBUG_LOG("setting latency to %d us\n", latency);
	ERROR_LOG("%s - not yet implemented\n", __func__);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_release		                                     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_transport_release(struct xio_transport *transport)
{
	xio_rdma_mempool_array_release();

	/* free devices */
	xio_device_list_release();
}

/*---------------------------------------------------------------------------*/
/* xio_is_valid_in_req							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_is_valid_in_req(struct xio_msg *msg)
{
	struct xio_vmsg *vmsg = &msg->in;
	int		i;

	if (vmsg->data_iovlen >= XIO_MAX_IOV)
		return 0;

	if ((vmsg->header.iov_base != NULL)  &&
	    (vmsg->header.iov_len == 0))
		return 0;

	for (i = 0; i < vmsg->data_iovlen; i++) {
		if ((vmsg->data_iov[i].iov_base != NULL) &&
		    (vmsg->data_iov[i].iov_len == 0))
			return 0;
	}

	return 1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_is_valid_out_msg						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_is_valid_out_msg(struct xio_msg *msg)
{
	struct xio_vmsg *vmsg = &msg->out;
	int		i;

	if (vmsg->data_iovlen >= XIO_MAX_IOV)
		return 0;

	if (((vmsg->header.iov_base != NULL)  &&
	     (vmsg->header.iov_len == 0)) ||
	    ((vmsg->header.iov_base == NULL)  &&
	     (vmsg->header.iov_len != 0)))
			return 0;

	for (i = 0; i < vmsg->data_iovlen; i++) {
		if ((vmsg->data_iov[i].iov_base == NULL) ||
		    (vmsg->data_iov[i].iov_len == 0))
				return 0;
	}

	return 1;
}

static struct xio_transport xio_rdma_transport = {
	.name			= "rdma",
	.init			= xio_rdma_transport_init,
	.release		= NULL,
	.open			= xio_rdma_open,
	.connect		= xio_rdma_connect,
	.listen			= xio_rdma_listen,
	.accept			= xio_rdma_accept,
	.reject			= xio_rdma_reject,
	.close			= xio_rdma_close,
	.send			= xio_rdma_send,
	.poll			= xio_rdma_poll,
	.set_opt		= xio_rdma_set_opt,
	.get_opt		= xio_rdma_get_opt,
	.add_observer		= xio_transport_add_observer,
	.remove_observer	= xio_transport_remove_observer,
	.trans_cls.is_valid_in_req  = xio_rdma_is_valid_in_req,
	.trans_cls.is_valid_out_msg = xio_rdma_is_valid_out_msg,
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_constructor					     */
/*---------------------------------------------------------------------------*/
static int __init xio_rdma_transport_constructor(void)
{
	struct xio_transport *transport = &xio_rdma_transport;
	int retval;

	/* set cpu latency until process is down */
	/* xio_set_cpu_latency(); */

	/* register the transport */
	xio_reg_transport(transport);

	/* initialize the transport */
	retval = xio_rdma_transport_init(transport);
	if (retval != 0) {
		ERROR_LOG("rdma transport constructor failed\n");
		goto cleanup;
	}

	return 0;

cleanup:
	xio_unreg_transport(transport);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_destructor					     */
/*---------------------------------------------------------------------------*/
static void __exit xio_rdma_transport_destructor(void)
{
	struct xio_transport *transport = &xio_rdma_transport;
	struct xio_device   *dev, *ndev;

	/* Called after all devices were deleted */

	/* release the transport */
	xio_rdma_transport_release(transport);

	xio_unreg_transport(transport);
}

/*---------------------------------------------------------------------------*/
/* xio_add_one								     */
/*---------------------------------------------------------------------------*/
static void xio_add_one(struct ib_device *device)
{
	struct xio_device **xio_devs;
	int s, e, p;

	/* IB or ROCE */
	if (rdma_node_get_transport(device->node_type) != RDMA_TRANSPORT_IB)
		return;

	if (device->node_type == RDMA_NODE_IB_SWITCH) {
		s = 0;
		e = 0;
	} else {
		s = 1;
		e = device->phys_port_cnt;
	}

	xio_devs = kcalloc(e + 1, sizeof(struct xio_device *), GFP_KERNEL);
	if (xio_devs == NULL) {
		ERROR_LOG("Couldn't allocate n(%d) pointers\n", e + 1);
		return;
	}

	for (p = s; p <= e; p++) {
		struct xio_device *xio_dev;
		xio_dev = xio_device_init(device, p);
		if (!xio_dev) {
			ERROR_LOG("int xio device on dev(%s) port(%d) failed\n",
				  ib_get_device_name(device), p);
			goto cleanup;
		}
		xio_devs[p] = xio_dev;
	}

	ib_set_client_data(device, &xio_client, xio_devs);

cleanup:
	for (p = s; p <= e; p++) {
		if (xio_devs[p]) {
			xio_device_release(xio_devs[p]);
			xio_devs[p] = NULL;
		}
	}
	kfree(xio_devs);
}

/*---------------------------------------------------------------------------*/
/* xio_remove_one							     */
/*---------------------------------------------------------------------------*/

static void xio_remove_one(struct ib_device *device)
{
	struct xio_device **xio_devs;
	int s, e, p;

	/* IB or ROCE */
	if (rdma_node_get_transport(dev->node_type) != RDMA_TRANSPORT_IB)
		return;

	/* xio_del_one is called before the core clients' list is deleted
	 * so calling ib_get_client_data in xio_del_one is O.K.
	 */

	xio_devs = ib_get_client_data(device, &xio_client);
	if (!xio_devs) {
		ERROR_LOG("Couldn't find xio device on %s\n",
			  ib_get_device_name(ib_dev));
		return;
	}

	if (device->node_type == RDMA_NODE_IB_SWITCH) {
		s = 0;
		e = 0;
	} else {
		s = 1;
		e = device->phys_port_cnt;
	}

	for (p = s; p <= e; p++) {
		if (xio_devs[p]) {
			xio_device_release(xio_devs[p]);
			xio_devs[p] = NULL;
		}
	}

	kfree(xio_devs);
}

static struct ib_client xio_client = {
	.name	= "xio",
	.add	= xio_add_one,
	.remove	= xio_del_one
};

static int __init xio_init_module(void)
{
	xio_rdma_transport_constructor();

	/* xio_add_one will be called for all existing devices
	 * add for all new devices
	 */

	ret = ib_register_client(&xio_client);
	if (ret) {
		pr_err("couldn't register IB client ret%d\n", ret);
		return ret;
	}
}

static void __exit xio_cleanup_module(void)
{
	/* xio_del_one will called for all devices */

	ib_unregister_client(&xio_client);

	xio_rdma_transport_destructor();
}

module_init(xio_init_module);
module_exit(xio_cleanup_module);
