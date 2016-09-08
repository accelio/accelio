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
#include <linux/interrupt.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include "libxio.h"
#include <xio_os.h>
#include "xio_common.h"
#include "xio_log.h"
#include "xio_observer.h"
#include "xio_ktransport.h"
#include "xio_transport.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_mem.h"
#include "xio_mempool.h"
#include "xio_rdma_utils.h"
#include "xio_rdma_transport.h"
#include "xio_sg_table.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_ev_loop.h"
#include "xio_context.h"
#include "xio_context_priv.h"

MODULE_AUTHOR("Eyal Solomon, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO library " \
	   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

/* The root of xio_rdma debugfs tree */
static struct dentry *xio_rdma_root;

int xio_rdma_cq_completions;
module_param_named(cq_completions, xio_rdma_cq_completions, int, 0644);
MODULE_PARM_DESC(cq_completions, "moderate CQ to N completions if N > 0 (default:disabled)");

int xio_rdma_cq_timeout;
module_param_named(cq_timeout, xio_rdma_cq_timeout, int, 0644);
MODULE_PARM_DESC(cq_timeout, "moderate CQ to max T micro-sec if T > 0 (default:disabled)");

/* TODO: move to an include file like xio_usr_transport.h in user space */
#define VALIDATE_SZ(sz)	do {			\
		if (optlen != (sz)) {		\
			xio_set_error(EINVAL);	\
			return -1;		\
		}				\
	} while (0)

/* default option values */
#define XIO_OPTVAL_DEF_ENABLE_MEM_POOL			1
#define XIO_OPTVAL_DEF_ENABLE_DMA_LATENCY		0
#define XIO_OPTVAL_DEF_MAX_IN_IOVSZ			XIO_IOVLEN
#define XIO_OPTVAL_DEF_MAX_OUT_IOVSZ			XIO_IOVLEN
#define XIO_OPTVAL_DEF_QP_CAP_MAX_INLINE_DATA		(200)

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
struct xio_options			*g_poptions;

/* rdma options */
struct xio_rdma_options			rdma_options = {
	.enable_mem_pool		= XIO_OPTVAL_DEF_ENABLE_MEM_POOL,
	.enable_dma_latency		= XIO_OPTVAL_DEF_ENABLE_DMA_LATENCY,
	.max_in_iovsz			= XIO_OPTVAL_DEF_MAX_IN_IOVSZ,
	.max_out_iovsz			= XIO_OPTVAL_DEF_MAX_OUT_IOVSZ,
	.qp_cap_max_inline_data		= XIO_OPTVAL_DEF_QP_CAP_MAX_INLINE_DATA,
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_get_max_header_size						     */
/*---------------------------------------------------------------------------*/
int xio_rdma_get_max_header_size(void)
{
	int req_hdr = XIO_TRANSPORT_OFFSET + sizeof(struct xio_rdma_req_hdr);
	int rsp_hdr = XIO_TRANSPORT_OFFSET + sizeof(struct xio_rdma_rsp_hdr);
	int iovsz = rdma_options.max_out_iovsz + rdma_options.max_in_iovsz;

	req_hdr += iovsz * sizeof(struct xio_sge);
	rsp_hdr += rdma_options.max_out_iovsz * sizeof(struct xio_sge);

	return max(req_hdr, rsp_hdr);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_get_inline_buffer_size					     */
/*---------------------------------------------------------------------------*/
int xio_rdma_get_inline_buffer_size(void)
{
	int inline_buf_sz = ALIGN(xio_rdma_get_max_header_size() +
				  g_poptions->max_inline_xio_hdr +
				  g_poptions->max_inline_xio_data, 1024);
	return inline_buf_sz;
}

/*---------------------------------------------------------------------------*/
/* forward declaration							     */
/*---------------------------------------------------------------------------*/
static struct xio_transport_base *xio_rdma_open(
					struct xio_transport *transport,
					struct xio_context *ctx,
					struct xio_observer *observer,
					uint32_t trans_attr_mask,
					struct xio_transport_init_attr *attr);

static void xio_rdma_close(struct xio_transport_base *transport);
static int xio_rdma_reject(struct xio_transport_base *transport);
static void xio_rdma_post_close(struct xio_transport_base *transport);
static int xio_rdma_flush_all_tasks(struct xio_rdma_transport *rdma_hndl);

static void xio_cq_event_callback(struct ib_event *cause, void *context)
{
	ERROR_LOG("got cq event %d ctx(%p)\n", cause->event, context);
}

static void xio_add_one(struct ib_device *ib_dev);
static void xio_del_one(struct ib_device *ib_dev);

static struct ib_client xio_client = {
	.name	= "xio",
	.add	= xio_add_one,
	.remove	= xio_del_one
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_context_shutdown						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_context_shutdown(struct xio_transport_base *trans_hndl,
				     struct xio_context *ctx)
{
	xio_context_destroy_wait(trans_hndl->ctx);

	xio_rdma_close(trans_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_cq_down								     */
/*---------------------------------------------------------------------------*/
static void xio_cq_down(struct kref *kref)
{
	struct xio_cq *tcq = container_of(kref, struct xio_cq, kref);
	int retval;

	write_lock_bh(&tcq->dev->cq_lock);
	retval = list_empty(&tcq->cq_list_entry);
	list_del_init(&tcq->cq_list_entry);
	write_unlock_bh(&tcq->dev->cq_lock);

	if (retval)
		ERROR_LOG("tcq double free\n");

	if (!list_empty(&tcq->trans_list))
		ERROR_LOG("rdma_hndl memory leakage\n");

	xio_context_unreg_observer(tcq->ctx, &tcq->observer);

	/* the event loop may be release by the time this function is called */
	retval = ib_destroy_cq(tcq->cq);
	if (retval)
		ERROR_LOG("ib_destroy_cq failed. (err=%d)\n", retval);

	XIO_OBSERVER_DESTROY(&tcq->observer);

	kfree(tcq->wc_array);
	kfree(tcq);
}

/*---------------------------------------------------------------------------*/
/* xio_cq_release							     */
/*---------------------------------------------------------------------------*/
static inline void xio_cq_release(struct xio_cq *tcq)
{
	kref_put(&tcq->kref, xio_cq_down);
}

/*---------------------------------------------------------------------------*/
/* xio_on_context_event							     */
/*---------------------------------------------------------------------------*/
static int xio_on_context_event(void *observer, void *sender,
				int event, void *event_data)
{
	if (event == XIO_CONTEXT_EVENT_POST_CLOSE) {
		TRACE_LOG("context: [close] ctx:%p\n", sender);
		xio_cq_release((struct xio_cq *)observer);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_cq_get								     */
/*---------------------------------------------------------------------------*/
static struct xio_cq *xio_cq_get(struct xio_device *dev,
				 struct xio_context *ctx)
{
	struct xio_cq	*tcq;
	int		num_cores = num_online_cpus();
	u32		alloc_sz;
	int		cpu;

	/* If two session were created with the same context and
	 * the address resolved on the same device than the same
	 * CQ is used
	 */
	read_lock_bh(&dev->cq_lock);
	list_for_each_entry(tcq, &dev->cq_list, cq_list_entry) {
		if (tcq->ctx == ctx) {
			kref_get(&tcq->kref);
			read_unlock_bh(&dev->cq_lock);
			return tcq;
		}
	}
	read_unlock_bh(&dev->cq_lock);

	if (ctx->cpuid < 0 || ctx->cpuid >= num_cores) {
		ERROR_LOG("BUG, wrong cpuid(%d) check init\n", ctx->cpuid);
		goto cleanup0;
	} else {
		cpu = ctx->cpuid;
	}
	cpu = cpu % dev->cqs_used;

	tcq = kzalloc(sizeof(*tcq), GFP_KERNEL);
	if (!tcq) {
		ERROR_LOG("xio_cq_init kzalloc failed\n");
		goto cleanup0;
	}

	tcq->alloc_sz	= min(dev->device_attr.max_cqe, CQE_ALLOC_SIZE);
	alloc_sz	= tcq->alloc_sz;

	/* allocate device wc array */
	tcq->wc_array = kcalloc(MAX_POLL_WC, sizeof(struct ib_wc), GFP_KERNEL);
	if (!tcq->wc_array) {
		xio_set_error(ENOMEM);
		ERROR_LOG("wc array allocation failed\n");
		goto cleanup1;
	}

	tcq->ctx	= ctx;
	tcq->dev	= dev;
	tcq->max_cqe	= dev->device_attr.max_cqe;
	tcq->wc_array_len = MAX_POLL_WC;
	INIT_LIST_HEAD(&tcq->trans_list);
	INIT_LIST_HEAD(&tcq->cq_list_entry);

	/* xio_rdma_poll doesn't support separate tx & rx poll
	 * so we use only one cq for RX and TX
	 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
	tcq->cq = ib_create_cq(dev->ib_dev,
			       xio_cq_data_callback,
			       xio_cq_event_callback,
			       (void *)tcq,
			       alloc_sz, cpu);
#else
	{
		struct ib_cq_init_attr ia = {
			.cqe             = alloc_sz,
			.comp_vector     = cpu,
		};

		tcq->cq = ib_create_cq(dev->ib_dev,
				       xio_cq_data_callback,
				       xio_cq_event_callback,
				       (void *)tcq,
				       &ia);
	}
#endif
	if (IS_ERR(tcq->cq)) {
		ERROR_LOG("ib_create_cq err(%ld)\n", PTR_ERR(tcq->cq));
		goto cleanup2;
	}
	tcq->cq_depth	= tcq->cq->cqe;
	tcq->cqe_avail	= tcq->cq->cqe;

/* due to ib_modify_cq API change, need to add backporting */
#if 0
	if (xio_rdma_cq_completions && xio_rdma_cq_timeout) {
		if (xio_rdma_cq_completions > 0xffff ||
		    xio_rdma_cq_timeout > 0xffff) {
			ERROR_LOG("invalid CQ moderation values\n");
		} else {
			ret = ib_modify_cq(tcq->cq,
					   xio_rdma_cq_completions,
					   xio_rdma_cq_timeout);
			if (ret && ret != -ENOSYS) {
				ERROR_LOG("failed modifying CQ (%d)\n", ret);
				goto cleanup3;
			}
		}
	}
#endif

	/* we don't expect missed events (if supported) so it is an error */
	if (ib_req_notify_cq(tcq->cq,
			     IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS)) {
		ERROR_LOG("ib_req_notify_cq\n");
		goto cleanup3;
	}

	write_lock_bh(&dev->cq_lock);
	list_add(&tcq->cq_list_entry, &dev->cq_list);
	write_unlock_bh(&dev->cq_lock);

	/* One reference count for the context and one for the rdma handle */
	kref_init(&tcq->kref);
	kref_get(&tcq->kref);

	/* set the tcq to be the observer for context events */
	XIO_OBSERVER_INIT(&tcq->observer, tcq, xio_on_context_event);
	xio_context_reg_observer(ctx, &tcq->observer);

	/* regiter completion function to be called directly */
	xio_context_set_poll_completions_fn(
		ctx,
		(poll_completions_fn_t)xio_rdma_poll_completions,
		tcq);

	return tcq;

cleanup3:
	ib_destroy_cq(tcq->cq);
cleanup2:
	kfree(tcq->wc_array);
cleanup1:
	kfree(tcq);
cleanup0:
	ERROR_LOG("xio_cq_init failed\n");
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_dev_event_handler						     */
/*---------------------------------------------------------------------------*/
static void xio_dev_event_handler(struct ib_event_handler *handler,
				  struct ib_event *event)
{
	ERROR_LOG("async event %d on device %s port %d\n", event->event,
		  event->device->name, event->element.port_num);
}

/*---------------------------------------------------------------------------*/
/* xio_device_init							     */
/*---------------------------------------------------------------------------*/
static struct xio_device *xio_device_init(struct ib_device *ib_dev, int port)
{
	struct xio_device	*dev;
	int			num_cores;
	int			retval;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kzalloc failed.\n");
		goto cleanup0;
	}

	retval = ib_query_device(ib_dev, &dev->device_attr);
	if (retval < 0) {
		ERROR_LOG("ib_query_device failed. (ret=%d)\n", retval);
		xio_set_error(-retval);
		goto cleanup1;
	}

	/* FMR not yet supported */
#if 0
	/* Assign function handles  - based on FMR support */
	if (ib_dev->alloc_fmr && ib_dev->dealloc_fmr &&
	    ib_dev->map_phys_fmr && ib_dev->unmap_fmr)
		ERROR_LOG("not supported");
#endif

	if (dev->device_attr.device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS) {
		if (xio_fast_reg_init(XIO_FAST_MEM_FRWR, &dev->fastreg))
			goto cleanup1;
	} else {
		if (xio_fast_reg_init(XIO_FAST_MEM_NONE, &dev->fastreg))
			goto cleanup1;
	}

	dev->ib_dev = ib_dev;
	dev->port_num = port;

	dev->pd = ib_alloc_pd(ib_dev);
	if (!dev->pd) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ibv_alloc_pd failed.\n");
		goto cleanup1;
	}

	dev->mr = ib_get_dma_mr(dev->pd,
				IB_ACCESS_LOCAL_WRITE |
				IB_ACCESS_REMOTE_WRITE |
				IB_ACCESS_REMOTE_READ);
	if (IS_ERR(dev->mr)) {
		xio_set_error(PTR_ERR(dev->mr));
		ERROR_LOG("ib_get_dma_mr failed. (ret=%ld)\n",
			  PTR_ERR(dev->mr));
		goto cleanup2;
	}

	kref_init(&dev->kref);
	rwlock_init(&dev->cq_lock);
	INIT_LIST_HEAD(&dev->cq_list);
	num_cores = num_online_cpus();
	num_cores = roundup_pow_of_two(num_cores);
	dev->cqs_used = min(num_cores, ib_dev->num_comp_vectors);

	TRACE_LOG("rdma device: [new] %p\n", dev);

	INIT_IB_EVENT_HANDLER(&dev->event_handler, dev->ib_dev,
			      xio_dev_event_handler);

	if (ib_register_event_handler(&dev->event_handler))
		goto cleanup3;

	return dev;

cleanup3:
	ib_dereg_mr(dev->mr);
cleanup2:
	ib_dealloc_pd(dev->pd);
cleanup1:
	kfree(dev);
cleanup0:
	ERROR_LOG("rdma device: [new] failed\n");
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_device_down							     */
/*---------------------------------------------------------------------------*/
void xio_device_down(struct kref *kref)
{
	struct xio_device *dev = container_of(kref, struct xio_device, kref);

	ib_dereg_mr(dev->mr);
	ib_dealloc_pd(dev->pd);

	kfree(dev);
}

/*---------------------------------------------------------------------------*/
/* xio_device_release							     */
/*---------------------------------------------------------------------------*/
static void xio_device_release(struct xio_device *dev)
{
	TRACE_LOG("rdma device: [close] dev:%p\n", dev);

	(void)ib_unregister_event_handler(&dev->event_handler);

	write_lock_bh(&dev->cq_lock);

	if (!list_empty(&dev->cq_list)) {
		write_unlock_bh(&dev->cq_lock);
		ERROR_LOG("cq memory leakage\n");
	} else {
		write_unlock_bh(&dev->cq_lock);
	}

	/* ib_dereg_mr & ib_dealloc_pd will be called from xio_device_down
	 *  (kerf)
	 */
	xio_device_put(dev);
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
		int cqe = tcq->cq->cqe;
		int retval = ib_resize_cq(tcq->cq,
					  tcq->cq_depth + tcq->alloc_sz);
		if (retval != 0 || (cqe == tcq->cq->cqe)) {
			ERROR_LOG("ibv_resize_cq failed. ret=%d, cqe:%d\n",
				  retval, cqe);
			return -1;
		}
		tcq->cq_depth  += (tcq->cq->cqe - cqe);
		tcq->cqe_avail += (tcq->cq->cqe - cqe);
		DEBUG_LOG("cq_resize: expected:%d, actual:%d\n",
			  tcq->cq_depth, tcq->cq->cqe);
		tcq->cqe_avail -= cqe_num;
		return 0;
	}

	ERROR_LOG("cq overflow reached\n");

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
	ERROR_LOG("got qp event %d\n", cause->event);
}

/*---------------------------------------------------------------------------*/
/* xio_qp_create                                                              */
/*---------------------------------------------------------------------------*/
static int xio_qp_create(struct xio_rdma_transport *rdma_hndl)
{
	struct xio_device	*dev;
	struct ib_qp_init_attr	qp_init_attr;
	struct ib_qp_attr	qp_attr;
	struct	xio_cq		*tcq;
	int			retval = 0;

	/* Should be set by now */
	dev = rdma_hndl->dev;
	if (!dev) {
		ERROR_LOG("failed to find device\n");
		return -1;
	}

	tcq = xio_cq_get(dev, rdma_hndl->base.ctx);
	if (!tcq) {
		ERROR_LOG("cq initialization failed\n");
		return -1;
	}

	retval = xio_cq_alloc_slots(tcq, MAX_CQE_PER_QP);
	if (retval != 0) {
		ERROR_LOG("cq full capacity reached\n");
		return -1;
	}

	memset(&qp_init_attr, 0, sizeof(qp_init_attr));

	qp_init_attr.event_handler	 = xio_qp_event_handler;
	qp_init_attr.qp_context		 = rdma_hndl;
	qp_init_attr.qp_type		 = IB_QPT_RC;
	qp_init_attr.send_cq		 = tcq->cq;
	qp_init_attr.recv_cq		 = tcq->cq;
	qp_init_attr.cap.max_send_wr	 = 5 * MAX_SEND_WR;
	qp_init_attr.cap.max_recv_wr	 = MAX_RECV_WR + EXTRA_RQE;
	qp_init_attr.cap.max_inline_data = rdma_options.qp_cap_max_inline_data;
	qp_init_attr.cap.max_send_sge	 = min(rdma_options.max_out_iovsz + 1,
						dev->device_attr.max_sge);
	qp_init_attr.cap.max_recv_sge	 = 1;

	/* only generate completion queue entries if requested
	 * User space version sets sq_sig_all to 0, according to
	 * ib_uverbs_create_qp this translates to IB_SIGNAL_REQ_WR
	 */
	qp_init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

	retval = rdma_create_qp(rdma_hndl->cm_id, dev->pd, &qp_init_attr);
	if (retval) {
		xio_set_error(retval);
		xio_cq_free_slots(tcq, MAX_CQE_PER_QP);
		ERROR_LOG("rdma_create_qp failed. (err=%d)\n", retval);
		return -1;
	}
	rdma_hndl->dev		= dev;
	rdma_hndl->tcq		= tcq;
	rdma_hndl->qp		= rdma_hndl->cm_id->qp;
	rdma_hndl->sqe_avail	= 5 * MAX_SEND_WR;

	rdma_hndl->beacon_task.dd_data = ptr_from_int64(XIO_BEACON_WRID);
	rdma_hndl->beacon.wr_id	 = uint64_from_ptr(&rdma_hndl->beacon_task);
	rdma_hndl->beacon.opcode = IB_WR_SEND;

	memset(&qp_attr, 0, sizeof(qp_attr));
	retval = ib_query_qp(rdma_hndl->qp, &qp_attr, 0, &qp_init_attr);
	if (retval)
		ERROR_LOG("ib_query_qp failed. (err=%d)\n", retval);

	rdma_hndl->max_inline_data = qp_attr.cap.max_inline_data;
	rdma_hndl->max_sge	   = min(rdma_options.max_out_iovsz + 1,
					 dev->device_attr.max_sge);

	list_add(&rdma_hndl->trans_list_entry, &tcq->trans_list);

	TRACE_LOG("rdma qp: [new] handle:%p, qp:0x%x\n", rdma_hndl,
		  rdma_hndl->qp->qp_num);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_qp_release							     */
/*---------------------------------------------------------------------------*/
static void xio_qp_release(struct xio_rdma_transport *rdma_hndl)
{
	if (rdma_hndl->qp) {
		TRACE_LOG("rdma qp: [close] handle:%p, qp:0x%x\n", rdma_hndl,
			  rdma_hndl->qp->qp_num);
		xio_cq_free_slots(rdma_hndl->tcq, MAX_CQE_PER_QP);
		if (list_empty(&rdma_hndl->trans_list_entry))
			ERROR_LOG("rdma_hndl has qp but not cq\n");

		list_del_init(&rdma_hndl->trans_list_entry);
		rdma_destroy_qp(rdma_hndl->cm_id);
		xio_cq_release(rdma_hndl->tcq);
		rdma_hndl->qp	= NULL;
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rxd_init								     */
/*---------------------------------------------------------------------------*/
static void xio_rxd_init(struct xio_work_req *rxd,
			 size_t rxd_nr,
			 struct xio_task *task,
			 struct scatterlist *sgl,
			 unsigned size,
			 struct ib_mr *srmr)
{
	int i;
	/* This address need to be dma mapped */
	/* rxd->sge[0].addr	= uint64_from_ptr(buf); */
	/* rxd->sge[0].length	= size; */
	if (srmr) {
		for (i = 0; i < rxd_nr; i++)
			rxd->sge[i].lkey = srmr->lkey;
	}

	if (size) {
		rxd->sgt.sgl = sgl;
		rxd->sgt.orig_nents = 1;
		rxd->sgt.nents = 1;
		rxd->nents  = 1;
	} else {
		rxd->sgt.sgl = NULL;
		rxd->sgt.orig_nents = 0;
		rxd->sgt.nents = 0;
		rxd->nents  = 0;
	}

	rxd->recv_wr.wr_id	= uint64_from_ptr(task);
	rxd->recv_wr.sg_list	= rxd->sge;
	rxd->recv_wr.num_sge	= rxd->nents;
	rxd->recv_wr.next	= NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_txd_init								     */
/*---------------------------------------------------------------------------*/
static void xio_txd_init(struct xio_work_req *txd,
			 size_t txd_nr,
			 struct xio_task *task,
			 struct scatterlist *sgl,
			 unsigned size,
			 struct ib_mr *srmr)
{
	int i;
	/* This address need to be dma mapped */
	/* txd->sge[0].addr	= uint64_from_ptr(buf); */
	/* txd->sge[0].length	= size; */
	if (srmr) {
		for (i = 0; i < txd_nr; i++)
			txd->sge[i].lkey = srmr->lkey;
	}

	if (size) {
		txd->sgt.sgl = sgl;
		txd->sgt.orig_nents = 1;
		txd->sgt.nents = 1;
		txd->nents  = 1;
	} else {
		txd->sgt.sgl = NULL;
		txd->sgt.orig_nents = 0;
		txd->sgt.nents = 0;
		txd->nents  = 0;
	}

	txd->send_wr.wr_id	= uint64_from_ptr(task);
	txd->send_wr.next	= NULL;
	txd->send_wr.sg_list	= txd->sge;
	txd->send_wr.num_sge	= txd->sgt.nents;
	txd->send_wr.opcode	= IB_WR_SEND;

	txd->mapped = 0;
	/* txd->send_wr.send_flags = IB_SEND_SIGNALED; */
}

/*---------------------------------------------------------------------------*/
/* xio_rdmad_init							     */
/*---------------------------------------------------------------------------*/
static int xio_rdmad_init(struct xio_work_req *rdmad,
			  size_t rdmad_nr,
			  struct xio_task *task)
{
	rdmad->send_wr.wr_id = uint64_from_ptr(task);
	rdmad->send_wr.sg_list = rdmad->sge;
	rdmad->send_wr.num_sge = 1;
	rdmad->send_wr.next = NULL;
	rdmad->send_wr.send_flags = IB_SEND_SIGNALED;

	/* rdmad has no sgl of it's own since it doesn't have a buffer */
	if (rdmad_nr) {
		if (sg_alloc_table(&rdmad->sgt, rdmad_nr, GFP_KERNEL)) {
			ERROR_LOG("sg_write_table(rdmad)\n");
			return -1;
		}
	} else {
		rdmad->sgt.sgl = NULL;
		rdmad->sgt.orig_nents = 0;
		rdmad->sgt.nents = 0;
	}

	rdmad->nents  = 1;
	rdmad->mapped = 0;

	/* to be set before posting:
	   rdmad->xio_ib_op, rdmad->send_wr.opcode
	   rdmad->sge.addr, rdmad->sge.length
	   rdmad->send_wr.wr.rdma.(remote_addr,rkey) */
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_task_init							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_task_init(struct xio_task *task,
			      struct xio_rdma_transport *rdma_hndl,
			      void *buf,
			      unsigned long size,
			      struct ib_mr *srmr,
			      size_t txd_nr,
			      size_t rxd_nr,
			      size_t rdmad_nr)
{
	XIO_TO_RDMA_TASK(task, rdma_task);

	rdma_task->buf = buf;

	if (buf) {
		sg_init_one(rdma_task->rx_sgl, buf, size);
		/* txd's scatterlist has and extra entry for chaining
		 * with the application's scatterlist
		 */
		sg_init_table(rdma_task->tx_sgl, 2);
		sg_set_buf(rdma_task->tx_sgl, buf, size);
		sg_mark_end(rdma_task->tx_sgl);
		/* The link entry shoulden't be marked end */
		sg_unmark_end(&rdma_task->tx_sgl[1]);
	}

	if (rxd_nr)
		xio_rxd_init(&rdma_task->rxd, rxd_nr, task, rdma_task->rx_sgl,
			     size, srmr);
	if (txd_nr)
		xio_txd_init(&rdma_task->txd, txd_nr, task, rdma_task->tx_sgl,
			     size, srmr);
	if (rdmad_nr)
		xio_rdmad_init(&rdma_task->rdmad, rdmad_nr, task);

	/* initialize the mbuf */
	xio_mbuf_init(&task->mbuf, buf, size, 0);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_txd_init								     */
/*---------------------------------------------------------------------------*/
static void xio_xd_reinit(struct xio_work_req *xd,
			  size_t xd_nr,
			  struct ib_mr *srmr)
{
	int i;

	if (!srmr || !xd || !xd->sge)
		return;

	for (i = 0; i < xd_nr; i++) {
		if (!xd->sge[i].lkey)
			break;
		xd->sge[i].lkey = srmr->lkey;
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_task_reinit							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_task_reinit(struct xio_task *task,
				struct xio_rdma_transport *rdma_hndl,
				struct ib_mr *srmr)
{
	XIO_TO_RDMA_TASK(task, rdma_task);

	xio_xd_reinit(&rdma_task->rxd, rdma_hndl->max_sge, srmr);
	xio_xd_reinit(&rdma_task->txd, rdma_hndl->max_sge, srmr);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_flush_all_tasks						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_flush_all_tasks(struct xio_rdma_transport *rdma_hndl)
{
	if (!list_empty(&rdma_hndl->in_flight_list)) {
		TRACE_LOG("in_flight_list not empty!\n");
		xio_transport_flush_task_list(&rdma_hndl->in_flight_list);
		/* for task that attached to senders with ref count = 2 */
		xio_transport_flush_task_list(&rdma_hndl->in_flight_list);
	}

	if (!list_empty(&rdma_hndl->rdma_rd_req_in_flight_list)) {
		TRACE_LOG("rdma_rd_req_in_flight_list not empty!\n");
		xio_transport_flush_task_list(
				&rdma_hndl->rdma_rd_req_in_flight_list);
	}
	if (!list_empty(&rdma_hndl->rdma_rd_req_list)) {
		TRACE_LOG("rdma_rd_req_list not empty!\n");
		xio_transport_flush_task_list(&rdma_hndl->rdma_rd_req_list);
	}
	if (!list_empty(&rdma_hndl->rdma_rd_rsp_in_flight_list)) {
		TRACE_LOG("rdma_rd_rsp_in_flight_list not empty!\n");
		xio_transport_flush_task_list(
				&rdma_hndl->rdma_rd_rsp_in_flight_list);
	}
	if (!list_empty(&rdma_hndl->rdma_rd_rsp_list)) {
		TRACE_LOG("rdma_rd_rsp_list not empty!\n");
		xio_transport_flush_task_list(&rdma_hndl->rdma_rd_rsp_list);
	}
	if (!list_empty(&rdma_hndl->tx_comp_list)) {
		TRACE_LOG("tx_comp_list not empty!\n");
		xio_transport_flush_task_list(&rdma_hndl->tx_comp_list);
	}
	if (!list_empty(&rdma_hndl->io_list)) {
		TRACE_LOG("io_list not empty!\n");
		xio_transport_flush_task_list(&rdma_hndl->io_list);
	}

	if (!list_empty(&rdma_hndl->tx_ready_list)) {
		TRACE_LOG("tx_ready_list not empty!\n");
		xio_transport_flush_task_list(&rdma_hndl->tx_ready_list);
		/* for task that attached to senders with ref count = 2 */
		xio_transport_flush_task_list(&rdma_hndl->tx_ready_list);
	}

	if (!list_empty(&rdma_hndl->rx_list)) {
		TRACE_LOG("rx_list not empty!\n");
		xio_transport_flush_task_list(&rdma_hndl->rx_list);
	}

	rdma_hndl->kick_rdma_rd_req = 0;
	rdma_hndl->kick_rdma_rd_rsp = 0;
	rdma_hndl->rdma_rd_req_in_flight = 0;
	rdma_hndl->rdma_rd_rsp_in_flight = 0;
	rdma_hndl->reqs_in_flight_nr = 0;
	rdma_hndl->rsps_in_flight_nr = 0;
	rdma_hndl->tx_ready_tasks_num = 0;

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_slab_pre_create				     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_initial_pool_slab_pre_create(
				struct xio_transport_base *transport_hndl,
				int alloc_nr,
				void *pool_dd_data, void *slab_dd_data)
{
	struct xio_rdma_tasks_slab *rdma_slab =
		(struct xio_rdma_tasks_slab *)slab_dd_data;

	rdma_slab->buf_size = CONN_SETUP_BUF_SIZE;
	/* The name must be valid until the pool is destroyed
	 * Use the address of the pool structure to create a unique
	 * name for the pool
	 */
	sprintf(rdma_slab->name, "initial_pool-%p", rdma_slab);
	rdma_slab->data_pool = kmem_cache_create(rdma_slab->name,
						 rdma_slab->buf_size, PAGE_SIZE,
						 SLAB_HWCACHE_ALIGN, NULL);
	if (!rdma_slab->data_pool) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcache(initial_pool) creation failed\n");
		return -1;
	}
	DEBUG_LOG("kcache(%s) created(%p)\n",
		  rdma_slab->name, rdma_slab->data_pool);
	rdma_slab->count = 0;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_task_alloc						     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_rdma_initial_task_alloc(
					struct xio_rdma_transport *rdma_hndl)
{
	return rdma_hndl->initial_pool_cls.task_get(
				rdma_hndl->initial_pool_cls.pool, rdma_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_task_alloc						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_rdma_primary_task_alloc(
					struct xio_rdma_transport *rdma_hndl)
{
	return rdma_hndl->primary_pool_cls.task_get(
				rdma_hndl->primary_pool_cls.pool, rdma_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_task_lookup						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_rdma_primary_task_lookup(
					struct xio_rdma_transport *rdma_hndl,
					int tid)
{
	if (rdma_hndl->primary_pool_cls.task_lookup)
		return rdma_hndl->primary_pool_cls.task_lookup(
					rdma_hndl->primary_pool_cls.pool, tid);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_task_free							     */
/*---------------------------------------------------------------------------*/
inline void xio_rdma_task_free(struct xio_rdma_transport *rdma_hndl,
			       struct xio_task *task)
{
	if (rdma_hndl->primary_pool_cls.task_put)
		return rdma_hndl->primary_pool_cls.task_put(task);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_post_create					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_initial_pool_post_create(
		struct xio_transport_base *transport_hndl,
		void *pool, void *pool_dd_data)
{
	struct xio_task *task;
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;
	struct xio_rdma_task *rdma_task;
	int	retval;

	if (!rdma_hndl)
		return 0;

	rdma_hndl->initial_pool_cls.pool = pool;
	rdma_pool->dev = rdma_hndl->dev;

	task = xio_rdma_initial_task_alloc(rdma_hndl);
	if (!task) {
		ERROR_LOG("failed to get task\n");
	} else {
		DEBUG_LOG("post_recv conn_setup rx task:%p\n", task);
		rdma_task = (struct xio_rdma_task *)task->dd_data;
		if (xio_map_rx_work_req(rdma_hndl->dev, &rdma_task->rxd)) {
			ERROR_LOG("DMA map from device failed\n");
			return -1;
		}

		/* set the lkey prior to receiving */
		rdma_task->rxd.recv_wr.sg_list[0].lkey = rdma_hndl->dev->mr->lkey;

		retval = xio_post_recv(rdma_hndl, task, 1);
		if (retval)
			ERROR_LOG("xio_post_recv failed\n");

		/* assuming that both sides posted one recv wr for initial
		 * negotiation
		 */
		rdma_hndl->peer_credits	= 1;
		rdma_hndl->sim_peer_credits = 1;

		rdma_task->out_ib_op	= XIO_IB_RECV;
		list_add_tail(&task->tasks_list_entry, &rdma_hndl->rx_list);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_task_pre_put						     */
/*---------------------------------------------------------------------------*/
int xio_rdma_task_pre_put(struct xio_transport_base *trans_hndl,
			  struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)trans_hndl;
	struct xio_device *dev;

	dev = rdma_hndl->dev;

	/* Unmap before releasing */

	if (rdma_task->rxd.mapped)
		xio_unmap_rx_work_req(dev, &rdma_task->rxd);

	if (rdma_task->txd.mapped)
		xio_unmap_tx_work_req(dev, &rdma_task->txd);

	if (rdma_task->rdmad.mapped) {
		if (rdma_task->out_ib_op == XIO_IB_RDMA_WRITE)
			xio_unmap_txmad_work_req(dev, &rdma_task->rdmad);
		else
			xio_unmap_rxmad_work_req(dev, &rdma_task->rdmad);
	}

	if (rdma_task->in_ib_op != XIO_IB_SEND) {
		if (rdma_task->read_mem_desc.nents &&
		    rdma_task->read_mem_desc.mapped)
			xio_unmap_desc(rdma_hndl,
				       &rdma_task->read_mem_desc,
				       DMA_FROM_DEVICE);
	}

	if (rdma_task->out_ib_op != XIO_IB_SEND) {
		if (rdma_task->write_mem_desc.nents &&
		    rdma_task->write_mem_desc.mapped)
			xio_unmap_desc(rdma_hndl,
				       &rdma_task->write_mem_desc,
				       DMA_TO_DEVICE);
	}

	/* recycle RDMA  buffers back to pool */

	/* put buffers back to pool */
	xio_mempool_free(&rdma_task->read_mem_desc);
	rdma_task->read_num_mem_desc = 0;

	xio_mempool_free(&rdma_task->write_mem_desc);
	rdma_task->write_num_mem_desc = 0;
	/*
	rdma_task->req_write_num_mem_desc	= 0;
	rdma_task->rsp_write_num_mem_desc	= 0;
	rdma_task->req_read_num_mem_desc	= 0;
	rdma_task->req_recv_num_sge		= 0;

	rdma_task->txd.send_wr.num_sge = 1;
	rdma_task->out_ib_op = XIO_IB_NULL;
	rdma_task->phantom_idx = 0;
	rdma_task->sn = 0;
	*/
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_slab_destroy					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_initial_pool_slab_destroy(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, void *slab_dd_data)
{
	struct xio_rdma_tasks_slab *rdma_slab =
		(struct xio_rdma_tasks_slab *)slab_dd_data;

	DEBUG_LOG("kcache(%s) freed\n", rdma_slab->name);

	if (rdma_slab->count)
		ERROR_LOG("pool(%s) not-free(%d)\n",
			  rdma_slab->name, rdma_slab->count);

	kmem_cache_destroy(rdma_slab->data_pool);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_pool_slab_uninit_task				     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_pool_slab_uninit_task(struct xio_transport_base *trans_hndl,
					  void *pool_dd_data,
					  void *slab_dd_data,
					  struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)trans_hndl;
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;
	struct xio_rdma_tasks_slab *rdma_slab =
		(struct xio_rdma_tasks_slab *)slab_dd_data;
	struct xio_device *dev;

	dev = rdma_pool->dev;
	if (!dev)
		return 0;

	if (!dev->ib_dev) {
		ERROR_LOG("ib_dev not set\n");
		return -1;
	}

	if (rdma_task->rxd.mapped)
		xio_unmap_rx_work_req(dev, &rdma_task->rxd);

	if (rdma_task->txd.mapped)
		xio_unmap_tx_work_req(dev, &rdma_task->txd);

	if (rdma_task->rdmad.mapped) {
		if (rdma_task->out_ib_op == XIO_IB_RDMA_WRITE)
			xio_unmap_txmad_work_req(dev, &rdma_task->rdmad);
		else
			xio_unmap_rxmad_work_req(dev, &rdma_task->rdmad);
	}

	if (rdma_task->read_mem_desc.nents && rdma_task->read_mem_desc.mapped)
		xio_unmap_desc(rdma_hndl, &rdma_task->read_mem_desc,
			       DMA_FROM_DEVICE);

	if (rdma_task->write_mem_desc.nents && rdma_task->write_mem_desc.mapped)
		xio_unmap_desc(rdma_hndl, &rdma_task->write_mem_desc,
			       DMA_TO_DEVICE);

	if (rdma_task->rdmad.sgt.sgl)
		sg_free_table(&rdma_task->rdmad.sgt);
#if 0
	if (rdma_task->write_mem_desc.sgt.sgl)
		sg_free_table(&rdma_task->write_mem_desc.sgt);

	if (rdma_task->read_mem_desc.sgt.sgl)
		sg_free_table(&rdma_task->read_mem_desc.sgt);
#endif
	/* Phantom tasks have no buffer */
	if (rdma_task->buf) {
		if (rdma_slab->count)
			rdma_slab->count--;
		else
			ERROR_LOG("pool(%s) double free?\n", rdma_slab->name);

		kmem_cache_free(rdma_slab->data_pool, rdma_task->buf);
		rdma_task->buf = NULL;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_slab_init_task					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_initial_pool_slab_init_task(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, void *slab_dd_data,
		int tid, struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	struct xio_rdma_tasks_slab *rdma_slab =
		(struct xio_rdma_tasks_slab *)slab_dd_data;
	void *buf;
	char *ptr;

	if (!rdma_hndl || rdma_task->buf)
		return 0;

	/* fill xio_rdma_task */
	ptr = (char *)rdma_task;
	ptr += sizeof(struct xio_rdma_task);

	/* fill xio_work_req */
	rdma_task->txd.sge = (void *)ptr;
	ptr += sizeof(struct ib_sge);

	rdma_task->rxd.sge = (void *)ptr;
	ptr += sizeof(struct ib_sge);
	/*****************************************/

	buf = kmem_cache_zalloc(rdma_slab->data_pool, GFP_KERNEL);
	if (!buf) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kmem_cache_zalloc(initial_pool)\n");
		return -ENOMEM;
	}
	rdma_slab->count++;

	return xio_rdma_task_init(task,
				  rdma_hndl,
				  buf,
				  rdma_slab->buf_size,
				  rdma_hndl->dev->mr,
				  1,	/* txd_nr */
				  1,    /* rxd_nr */
				  0);	/* rdmad_nr */
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_pool_get_params					     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_initial_pool_get_params(
		struct xio_transport_base *transport_hndl,
		int *start_nr, int *max_nr, int *alloc_nr,
		int *pool_dd_sz, int *slab_dd_sz, int *task_dd_sz)
{
	*start_nr = 10 * NUM_CONN_SETUP_TASKS;
	*alloc_nr = 10 * NUM_CONN_SETUP_TASKS;
	*max_nr = 10 * NUM_CONN_SETUP_TASKS;

	*pool_dd_sz = sizeof(struct xio_rdma_tasks_pool);
	*slab_dd_sz = sizeof(struct xio_rdma_tasks_slab);
	*task_dd_sz = sizeof(struct xio_rdma_task) +
		      2 * sizeof(struct ib_sge);
}

static struct xio_tasks_pool_ops initial_tasks_pool_ops = {
	.pool_get_params	= xio_rdma_initial_pool_get_params,
	.slab_pre_create	= xio_rdma_initial_pool_slab_pre_create,
	.slab_destroy		= xio_rdma_initial_pool_slab_destroy,
	.slab_init_task		= xio_rdma_initial_pool_slab_init_task,
	.slab_uninit_task	= xio_rdma_pool_slab_uninit_task,
	.pool_post_create	= xio_rdma_initial_pool_post_create
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_phantom_pool_slab_init_task					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_phantom_pool_slab_init_task(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, void *slab_dd_data,
		int tid, struct xio_task *task)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	int  max_iovsz = max(rdma_options.max_out_iovsz,
			     rdma_options.max_in_iovsz) + 1;
	int  max_sge = min(rdma_hndl->max_sge, max_iovsz);
	char *ptr;

	XIO_TO_RDMA_TASK(task, rdma_task);

	/* fill xio_rdma_task */
	ptr = (char *)rdma_task;
	ptr += sizeof(struct xio_rdma_task);

	/* fill xio_work_req */
	rdma_task->rdmad.sge = (void *)ptr;
	ptr += rdma_hndl->max_sge * sizeof(struct ib_sge);
	/*****************************************/

	rdma_task->out_ib_op = 0x200;
	xio_rdma_task_init(
			task,
			rdma_hndl,
			NULL,
			0,
			NULL,
			0,			/* txd_nr */
			0,			/* rxd_nr */
			max_sge);		/* rdmad_nr */

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_phantom_pool_post_create					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_phantom_pool_post_create(
		struct xio_transport_base *transport_hndl,
		void *pool, void *pool_dd_data)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;

	if (!rdma_hndl)
		return 0;

	rdma_pool->dev = rdma_hndl->dev;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_phantom_pool_create						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_phantom_pool_create(struct xio_rdma_transport *rdma_hndl)
{
	struct xio_tasks_pool_params	params;

	memset(&params, 0, sizeof(params));

	params.start_nr			   = NUM_START_PHANTOM_POOL_TASKS;
	params.max_nr			   = NUM_MAX_PHANTOM_POOL_TASKS;
	params.alloc_nr			   = NUM_ALLOC_PHANTOM_POOL_TASKS;
	params.pool_dd_data_sz		   = sizeof(struct xio_rdma_tasks_pool);
	params.slab_dd_data_sz		   = sizeof(struct xio_rdma_tasks_slab);
	params.task_dd_data_sz		   = sizeof(struct xio_rdma_task) +
					     rdma_hndl->max_sge *
					     sizeof(struct ib_sge);

	params.pool_hooks.context	   = rdma_hndl;
	params.pool_hooks.slab_init_task   =
		(void *)xio_rdma_phantom_pool_slab_init_task;
	params.pool_hooks.slab_uninit_task =
		(void *)xio_rdma_pool_slab_uninit_task;
	params.pool_hooks.task_pre_put	   =
		(void *)xio_rdma_task_pre_put;

	params.pool_hooks.pool_post_create   =
		(void *)xio_rdma_phantom_pool_post_create;

	/* initialize the tasks pool */
	rdma_hndl->phantom_tasks_pool = xio_tasks_pool_create(&params);
	if (!rdma_hndl->phantom_tasks_pool) {
		ERROR_LOG("xio_tasks_pool_create failed\n");
		goto cleanup;
	}

	return 0;

cleanup:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_phantom_pool_destroy					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_phantom_pool_destroy(struct xio_rdma_transport *rdma_hndl)
{
	if (!rdma_hndl->phantom_tasks_pool)
		return -1;

	xio_tasks_pool_destroy(rdma_hndl->phantom_tasks_pool);
	return  0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_slab_pre_create				     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_primary_pool_slab_pre_create(
		struct xio_transport_base *transport_hndl,
		int alloc_nr, void *pool_dd_data, void *slab_dd_data)
{
	struct xio_rdma_tasks_slab *rdma_slab =
		(struct xio_rdma_tasks_slab *)slab_dd_data;
	size_t inline_buf_sz = xio_rdma_get_inline_buffer_size();

	rdma_slab->buf_size = inline_buf_sz;
	/* The name must be valid until the pool is destroyed
	 * Use the address of the pool structure to create a unique
	 * name for the pool
	 */
	sprintf(rdma_slab->name, "primary_pool-%p", rdma_slab);
	rdma_slab->data_pool = kmem_cache_create(rdma_slab->name,
						 rdma_slab->buf_size, PAGE_SIZE,
						 SLAB_HWCACHE_ALIGN, NULL);
	if (!rdma_slab->data_pool) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcache(primary_pool) creation failed\n");
		return -1;
	}
	DEBUG_LOG("kcache(%s) created(%p)\n",
		  rdma_slab->name, rdma_slab->data_pool);

	DEBUG_LOG("pool buf:%p\n", rdma_slab->data_pool);
	rdma_slab->count = 0;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_post_create					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_primary_pool_post_create(
		struct xio_transport_base *transport_hndl,
		void *pool, void *pool_dd_data)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;

	if (!rdma_hndl)
		return 0;

	rdma_hndl->primary_pool_cls.pool = pool;
	rdma_pool->dev = rdma_hndl->dev;

	/* tasks may require fast registration for RDMA read and write */
	if (rdma_hndl->dev->fastreg.alloc_rdma_reg_res(rdma_hndl)) {
		xio_set_error(ENOMEM);
		ERROR_LOG("fast reg init failed\n");
		return -1;
	}

	xio_rdma_rearm_rq(rdma_hndl);

	/* late creation */
	xio_rdma_phantom_pool_create(rdma_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_slab_destroy					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_primary_pool_slab_destroy(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, void *slab_dd_data)
{
	struct xio_rdma_tasks_slab *rdma_slab =
		(struct xio_rdma_tasks_slab *)slab_dd_data;

	DEBUG_LOG("kcache(%s) freed\n", rdma_slab->name);


	if (rdma_slab->count)
		ERROR_LOG("pool(%s) not-free(%d)\n",
			  rdma_slab->name, rdma_slab->count);

	kmem_cache_destroy(rdma_slab->data_pool);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_slab_remap_task				     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_primary_pool_slab_remap_task(
					    struct xio_transport_base *old_th,
					    struct xio_transport_base *new_th,
					    void *pool_dd_data,
					    void *slab_dd_data,
					    struct xio_task *task)
{
	XIO_TO_RDMA_TASK(task, rdma_task);
	struct xio_rdma_transport *old_hndl =
		(struct xio_rdma_transport *)old_th;
	struct xio_rdma_transport *new_hndl =
		(struct xio_rdma_transport *)new_th;
	struct xio_device *old_dev = old_hndl->dev;
	struct xio_device *new_dev = new_hndl->dev;
	struct xio_rkey_tbl *te;

	task->context = new_th;

	/* if the same device is used then there is no need to remap */
	if (old_dev && old_dev == new_dev)
		return 0;

	xio_rdma_task_reinit(task, new_hndl, new_dev->mr);

	if (!new_hndl->rkey_tbl) {
		/* one for each possible desc and one for device mr */
		new_hndl->rkey_tbl = kcalloc(2 * old_hndl->num_tasks + 1,
					     sizeof(struct xio_rkey_tbl),
					     GFP_KERNEL);
		if (!new_hndl->rkey_tbl)
			return -ENOMEM;
	}

	if (rdma_task->rxd.mapped) {
		if (xio_remap_work_req(old_dev, new_dev, &rdma_task->rxd,
				       DMA_FROM_DEVICE)) {
			ERROR_LOG("DMA re-map failed\n");
			return -1;
		}
	}

	if (rdma_task->txd.mapped) {
		if (xio_remap_work_req(old_dev, new_dev, &rdma_task->txd,
				       DMA_TO_DEVICE)) {
			ERROR_LOG("DMA re-map failed\n");
			return -1;
		}
	}

	if (rdma_task->rdmad.mapped) {
		enum dma_data_direction direction =
				(rdma_task->out_ib_op == XIO_IB_RDMA_WRITE) ?
					DMA_TO_DEVICE : DMA_FROM_DEVICE;
		if (xio_remap_work_req(old_dev, new_dev, &rdma_task->rdmad,
				       direction)) {
			ERROR_LOG("DMA re-map to/from device failed\n");
			return -1;
		}
	}

	if (rdma_task->read_mem_desc.nents && rdma_task->read_mem_desc.mapped) {
		int used_fast;
		unsigned int sqe_used = 0;
		/* was FRWR/FMR in use */
		if (rdma_task->read_mem_desc.mem_reg.mem_h) {
			te = &new_hndl->rkey_tbl[new_hndl->rkey_tbl_size];
			te->old_rkey = rdma_task->read_mem_desc.mem_reg.rkey;
			used_fast = 1;
		} else {
			used_fast = 0;
		}
		xio_remap_desc(old_hndl, new_hndl, &rdma_task->read_mem_desc,
			       DMA_FROM_DEVICE, &sqe_used);
		rdma_task->sqe_used += sqe_used;
		if (used_fast) {
			if (!rdma_task->read_mem_desc.mem_reg.mem_h) {
				ERROR_LOG("Fast re-reg from device failed\n");
				return -1;
			}
			te->new_rkey = rdma_task->read_mem_desc.mem_reg.rkey;
			new_hndl->rkey_tbl_size++;
		}
	}

	if (rdma_task->write_mem_desc.nents &&
	    rdma_task->write_mem_desc.mapped) {
		int used_fast;
		unsigned int sqe_used = 0;
		/* was FRWR/FMR in use */
		if (rdma_task->write_mem_desc.mem_reg.mem_h) {
			te = &new_hndl->rkey_tbl[new_hndl->rkey_tbl_size];
			te->old_rkey = rdma_task->write_mem_desc.mem_reg.rkey;
			used_fast = 1;
		} else {
			used_fast = 0;
		}
		xio_remap_desc(old_hndl, new_hndl, &rdma_task->write_mem_desc,
			       DMA_TO_DEVICE, &sqe_used);
		rdma_task->sqe_used += sqe_used;
		if (used_fast) {
			if (!rdma_task->write_mem_desc.mem_reg.mem_h) {
				ERROR_LOG("Fast re-reg tom device failed\n");
				return -1;
			}
			te->new_rkey = rdma_task->write_mem_desc.mem_reg.rkey;
			new_hndl->rkey_tbl_size++;
		}
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_slab_init_task					     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_primary_pool_slab_init_task(
		struct xio_transport_base *t_hndl,
		void *pool_dd_data, void *slab_dd_data,
		int tid,
		struct xio_task *task)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)t_hndl;
	struct xio_rdma_tasks_slab *rdma_slab =
		(struct xio_rdma_tasks_slab *)slab_dd_data;
	XIO_TO_RDMA_TASK(task, rdma_task);
	int  max_iovsz = max(rdma_options.max_out_iovsz,
			     rdma_options.max_in_iovsz) + 1;
	int  max_sge = min(rdma_hndl->max_sge, max_iovsz);
	void *buf;
	char *ptr;

	if (rdma_task->buf)
		return 0;

	/* fill xio_rdma_task */
	ptr = (char *)rdma_task;
	ptr += sizeof(struct xio_rdma_task);

	/* fill xio_work_req */
	rdma_task->txd.sge = (void *)ptr;
	ptr += max_sge * sizeof(struct ib_sge);
	rdma_task->rxd.sge = (void *)ptr;
	ptr += sizeof(struct ib_sge);
	rdma_task->rdmad.sge = (void *)ptr;
	ptr += max_sge * sizeof(struct ib_sge);

	rdma_task->read_mem_desc.mp_sge = (void *)ptr;
	ptr += max_iovsz * sizeof(struct xio_mp_mem);

	rdma_task->write_mem_desc.mp_sge = (void *)ptr;
	ptr += max_iovsz * sizeof(struct xio_mp_mem);

	rdma_task->req_in_sge = (void *)ptr;
	ptr += max_iovsz * sizeof(struct xio_sge);
	rdma_task->req_out_sge = (void *)ptr;
	ptr += max_iovsz * sizeof(struct xio_sge);
	rdma_task->rsp_out_sge = (void *)ptr;
	ptr += max_iovsz * sizeof(struct xio_sge);
	/*****************************************/

#if 0
	if (sg_alloc_table(&rdma_task->read_mem_desc.sgt,
			   max_iovsz, GFP_KERNEL)) {
		ERROR_LOG("sg_alloc_table(read_mem_desc)\n");
		goto cleanup0;
	}

	if (sg_alloc_table(&rdma_task->write_mem_desc.sgt,
			   max_iovsz, GFP_KERNEL)) {
		ERROR_LOG("sg_alloc_table(write_mem_desc)\n");
		goto cleanup1;
	}
#endif

	rdma_task->out_ib_op = 0x200;

	buf = kmem_cache_zalloc(rdma_slab->data_pool, GFP_KERNEL);
	if (!buf) {
		ERROR_LOG("kmem_cache_zalloc(primary_pool)\n");
		goto cleanup2;
	}
	rdma_slab->count++;

	xio_rdma_task_init(task,
			   rdma_hndl,
			   buf,
			   rdma_slab->buf_size,
			   rdma_hndl->dev->mr,
			   max_sge,	/* txd_nr */
			   1,		/* rxd_nr */
			   max_sge);	/* rdmad_nr */

	return 0;

cleanup2:
#if 0
	sg_free_table(&rdma_task->write_mem_desc.sgt);
cleanup1:
	sg_free_table(&rdma_task->read_mem_desc.sgt);
cleanup0:
#endif
	xio_set_error(ENOMEM);
	return -ENOMEM;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_get_params					     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_primary_pool_get_params(
		struct xio_transport_base *transport_hndl,
		int *start_nr, int *max_nr, int *alloc_nr,
		int *pool_dd_sz, int *slab_dd_sz, int *task_dd_sz)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	int  max_iovsz = max(rdma_options.max_out_iovsz,
			     rdma_options.max_in_iovsz) + 1;
	int  max_sge;
	int queued_nr;


	if (rdma_hndl)
		max_sge = min(rdma_hndl->max_sge, max_iovsz);
	else
		max_sge = min(XIO_DEV_ATTR_MAX_SGE, max_iovsz);

	queued_nr = g_poptions->snd_queue_depth_msgs +
		    g_poptions->rcv_queue_depth_msgs +
		    MAX_CQE_PER_QP; /* for ibv_post_recv */

	if (rdma_hndl)
		*start_nr = rdma_hndl->rq_depth + EXTRA_RQE + SEND_QE;
	else
		*start_nr = NUM_START_PRIMARY_POOL_TASKS;

	*alloc_nr = NUM_ALLOC_PRIMARY_POOL_TASKS;
	*max_nr =  max(queued_nr, *start_nr);

	*pool_dd_sz = sizeof(struct xio_rdma_tasks_pool);
	*slab_dd_sz = sizeof(struct xio_rdma_tasks_slab);
	*task_dd_sz = sizeof(struct xio_rdma_task) +
		(max_sge + 1 + max_sge) * sizeof(struct ib_sge) +
		 2 * max_iovsz * sizeof(struct xio_mp_mem) +
		 3 * max_iovsz * sizeof(struct xio_sge);
}

static struct xio_tasks_pool_ops primary_tasks_pool_ops = {
	.pool_get_params	= xio_rdma_primary_pool_get_params,
	.slab_pre_create	= xio_rdma_primary_pool_slab_pre_create,
	.slab_destroy		= xio_rdma_primary_pool_slab_destroy,
	.slab_init_task		= xio_rdma_primary_pool_slab_init_task,
	.slab_uninit_task	= xio_rdma_pool_slab_uninit_task,
	.slab_remap_task	= xio_rdma_primary_pool_slab_remap_task,
	.pool_post_create	= xio_rdma_primary_pool_post_create,
	.task_pre_put		= xio_rdma_task_pre_put,
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_post_close			                                     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_post_close(struct xio_transport_base *trans_base)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)trans_base;

	if (rdma_hndl->handler_nesting) {
		rdma_hndl->state = XIO_TRANSPORT_STATE_DESTROYED;
		return;
	}

	TRACE_LOG("rdma transport: [post_close] handle:%p, qp:%p\n",
		  rdma_hndl, rdma_hndl->qp);

	xio_observable_unreg_all_observers(&trans_base->observable);

	if (rdma_hndl->dev)
		rdma_hndl->dev->fastreg.free_rdma_reg_res(rdma_hndl);

	xio_rdma_phantom_pool_destroy(rdma_hndl);

	xio_qp_release(rdma_hndl);
	/* Don't call rdma_destroy_id from event handler. see comment in
	 * xio_handle_cm_event
	 */
	if (rdma_hndl->cm_id) {
		TRACE_LOG("call rdma_destroy_id\n");
		rdma_destroy_id(rdma_hndl->cm_id);
		rdma_hndl->cm_id = NULL;
	}

	xio_context_destroy_resume(rdma_hndl->base.ctx);

	kfree(rdma_hndl->rkey_tbl);
	rdma_hndl->rkey_tbl = NULL;

	kfree(rdma_hndl->peer_rkey_tbl);
	rdma_hndl->peer_rkey_tbl = NULL;

	kfree(trans_base->portal_uri);
	trans_base->portal_uri = NULL;

	XIO_OBSERVABLE_DESTROY(&rdma_hndl->base.observable);
	/* last chance to flush all tasks */
	xio_rdma_flush_all_tasks(rdma_hndl);

	kfree(rdma_hndl);
}

/*---------------------------------------------------------------------------*/
/* on_cm_addr_resolved	                                                     */
/*---------------------------------------------------------------------------*/
static void on_cm_addr_resolved(struct rdma_cm_event *ev,
				struct xio_rdma_transport *rdma_hndl)
{
	int retval = 0;
	struct xio_device **xio_devs;
	struct xio_device *dev;

	/* Find the device on which the connection was established */
	xio_devs = ib_get_client_data(rdma_hndl->cm_id->device, &xio_client);
	if (!(xio_devs && xio_devs[rdma_hndl->cm_id->port_num])) {
		ERROR_LOG("device(%s) port(%d) not registered\n",
			  rdma_hndl->cm_id->device->name,
			  rdma_hndl->cm_id->port_num);
		xio_set_error(ENODEV);
		goto notify_err0;
	}

	dev = xio_devs[rdma_hndl->cm_id->port_num];
	/* increment device reference count */
	xio_device_get(dev);
	rdma_hndl->dev = dev;

	if (test_bits(XIO_TRANSPORT_ATTR_TOS, &rdma_hndl->trans_attr_mask)) {
		rdma_set_service_type(rdma_hndl->cm_id,
				      rdma_hndl->trans_attr.tos);
		DEBUG_LOG("set TOS option success. mask:0x%x, tos:0x%x\n",
			  rdma_hndl->trans_attr_mask,
			  rdma_hndl->trans_attr.tos);
	}

	retval = rdma_resolve_route(rdma_hndl->cm_id, ROUTE_RESOLVE_TIMEOUT);
	if (retval) {
		xio_set_error(retval);
		ERROR_LOG("rdma_resolve_route failed. (err=%d)\n", retval);
		goto notify_err1;
	}

	return;

notify_err1:
	xio_device_put(dev);
notify_err0:
	xio_transport_notify_observer_error(&rdma_hndl->base, xio_errno());
}

/*---------------------------------------------------------------------------*/
/* on_cm_route_resolved (client)					     */
/*---------------------------------------------------------------------------*/
static void on_cm_route_resolved(struct rdma_cm_id *cm_id,
				 struct rdma_cm_event *ev,
				 struct xio_rdma_transport *rdma_hndl)
{
	struct rdma_conn_param		cm_params = {
		.initiator_depth		= 1,
		.responder_resources		= 1,
		.rnr_retry_count		= 3, /* 7 - infinite retry */
		.retry_count			= 3
	};
	int	retval = 0;

	retval = xio_qp_create(rdma_hndl);
	if (retval != 0) {
		ERROR_LOG("internal logic error in create_endpoint\n");
		goto notify_err0;
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
		ERROR_LOG("rdma_connect failed.\n");
		goto notify_err1;
	}
	rdma_hndl->client_responder_resources = cm_params.responder_resources;
	rdma_hndl->client_initiator_depth = cm_params.initiator_depth;
	rdma_hndl->state = XIO_TRANSPORT_STATE_CONNECTING;

	return;

notify_err1:
	xio_qp_release(rdma_hndl);
notify_err0:
	xio_transport_notify_observer_error(&rdma_hndl->base, xio_errno());
}

/*---------------------------------------------------------------------------*/
/* on_cm_connect_request (server)					     */
/*---------------------------------------------------------------------------*/
static void  on_cm_connect_request(struct rdma_cm_id *cm_id,
				   struct rdma_cm_event *ev,
				   struct xio_rdma_transport *parent_hndl)
{
	struct xio_rdma_transport *child_hndl;
	union xio_transport_event_data event_data;
	struct xio_device **xio_devs;
	struct xio_device *dev;
	int retval = 0;

	/* Find the device on which the connection was established */
	xio_devs = ib_get_client_data(cm_id->device, &xio_client);
	if (!(xio_devs && xio_devs[cm_id->port_num])) {
		ERROR_LOG("device(%s) port(%d) not registered\n",
			  cm_id->device->name,
			  cm_id->port_num);
		xio_set_error(ENODEV);
		retval = rdma_reject(cm_id, NULL, 0);
		if (retval) {
			xio_set_error(retval);
			ERROR_LOG("rdma_reject failed. (err=%d %m)\n", retval);
		}
		goto notify_err1;
	}

	child_hndl = (struct xio_rdma_transport *)xio_rdma_open(
		parent_hndl->transport,
		parent_hndl->base.ctx,
		NULL, 0, NULL);
	if (!child_hndl) {
		ERROR_LOG("failed to open rdma transport\n");
		retval = rdma_reject(cm_id, NULL, 0);
		if (retval) {
			xio_set_error(retval);
			ERROR_LOG("rdma_reject failed. (err=%d %m)\n",
				  retval);
		}
		goto notify_err1;
	}
	child_hndl->state = XIO_TRANSPORT_STATE_CONNECTING;

	dev = xio_devs[cm_id->port_num];
	/* increment device reference count */
	xio_device_get(dev);

	child_hndl->dev		= dev;
	child_hndl->cm_id	= cm_id;
	child_hndl->state	= XIO_TRANSPORT_STATE_CONNECTING;

	/* Parent handle i.e. listener doesn't have a CQ */
	child_hndl->tcq		= NULL;

	/* Can we set it ? is it a new cm_id */
	cm_id->context		= child_hndl;
	child_hndl->client_initiator_depth =
		ev->param.conn.initiator_depth;
	child_hndl->client_responder_resources =
		ev->param.conn.responder_resources;

	/* initiator is dst, target is src */
	memcpy(&child_hndl->base.peer_addr,
	       &child_hndl->cm_id->route.addr.dst_addr,
	       sizeof(child_hndl->base.peer_addr));
	memcpy(&child_hndl->base.local_addr,
	       &child_hndl->cm_id->route.addr.src_addr,
	       sizeof(child_hndl->base.local_addr));
	child_hndl->base.proto = XIO_PROTO_RDMA;

	retval = xio_qp_create(child_hndl);
	if (retval != 0) {
		ERROR_LOG("failed to setup qp\n");
		xio_rdma_reject((struct xio_transport_base *)child_hndl);
		goto notify_err2;
	}

	event_data.new_connection.child_trans_hndl =
		(struct xio_transport_base *)child_hndl;
	xio_transport_notify_observer(&parent_hndl->base,
				      XIO_TRANSPORT_EVENT_NEW_CONNECTION,
				      &event_data);

	return;

notify_err2:
	xio_rdma_close((struct xio_transport_base *)child_hndl);
	xio_device_put(dev);

notify_err1:
	xio_transport_notify_observer_error(&parent_hndl->base, xio_errno());
}

/*---------------------------------------------------------------------------*/
/* on_cm_refused							     */
/*---------------------------------------------------------------------------*/
static void on_cm_refused(struct rdma_cm_event *ev,
			  struct xio_rdma_transport *rdma_hndl)
{
	TRACE_LOG("on_cm_refused. rdma_hndl:%p, reason:%s\n",
		  rdma_hndl, xio_cm_rej_reason_str(ev->status));
	/* we get CM_ESTABLISHED and afterward we get cm_refused. It looks like
	 * cm state machine error.
	 */
	if (rdma_hndl->state == XIO_TRANSPORT_STATE_CONNECTED) {
		/* one for beacon */
		kref_put(&rdma_hndl->base.kref, xio_rdma_close_cb);
		/* one for timedwait_exit */
		kref_put(&rdma_hndl->base.kref, xio_rdma_close_cb);
		rdma_hndl->state = XIO_TRANSPORT_STATE_ERROR;
	}
	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_EVENT_REFUSED, NULL);
}

/*---------------------------------------------------------------------------*/
/* on_cm_established						             */
/*---------------------------------------------------------------------------*/
static void on_cm_established(struct rdma_cm_event *ev,
			      struct xio_rdma_transport *rdma_hndl)
{
	/* initiator is dst, target is src */
	memcpy(&rdma_hndl->base.peer_addr,
	       &rdma_hndl->cm_id->route.addr.dst_addr,
	       sizeof(rdma_hndl->base.peer_addr));
	memcpy(&rdma_hndl->base.local_addr,
	       &rdma_hndl->cm_id->route.addr.src_addr,
	       sizeof(rdma_hndl->base.local_addr));

	rdma_hndl->state = XIO_TRANSPORT_STATE_CONNECTED;

	/* one for beacon */
	kref_get(&rdma_hndl->base.kref);
	/* one for timedwait_exit */
	kref_get(&rdma_hndl->base.kref);

	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_EVENT_ESTABLISHED, NULL);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_disconnect							     */
/*---------------------------------------------------------------------------*/
int xio_rdma_disconnect(struct xio_rdma_transport *rdma_hndl, int send_beacon)
{
	struct ib_send_wr	*bad_wr;
	int			retval;

	retval = rdma_disconnect(rdma_hndl->cm_id);
	if (retval) {
		ERROR_LOG("rdma_hndl:%p rdma_disconnect failed, %m\n",
			  rdma_hndl);
		return -1;
	}

	if (!send_beacon)
		return 0;

	/* post an indication that all flush errors were consumed */
	retval = ib_post_send(rdma_hndl->qp, &rdma_hndl->beacon, &bad_wr);
	if (retval == -ENOTCONN) {
		/* softiwarp returns ENOTCONN right away if the QP is not
		   in RTS state. */
		WARN_LOG("rdma_hndl %p failed to post beacon - " \
			 "ignored because the QP is not in RTS state.\n",
			 rdma_hndl);
		/* for beacon */
		kref_put(&rdma_hndl->base.kref, xio_rdma_close_cb);
	} else if (retval) {
		ERROR_LOG("rdma_hndl %p failed to post beacon (%d)\n",
			  rdma_hndl, retval);
		return -1;
	} else
		rdma_hndl->beacon_sent = 1;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_cm_disconnected							     */
/*---------------------------------------------------------------------------*/
static void on_cm_disconnected(struct rdma_cm_event *ev,
			       struct xio_rdma_transport *rdma_hndl)
{
	int retval;

	TRACE_LOG("on_cm_disconnected. rdma_hndl:%p, state:%d\n",
		  rdma_hndl, rdma_hndl->state);
	switch (rdma_hndl->state) {
	case XIO_TRANSPORT_STATE_CONNECTED:
		TRACE_LOG("call to rdma_disconnect. rdma_hndl:%p\n",
			  rdma_hndl);
		rdma_hndl->state = XIO_TRANSPORT_STATE_DISCONNECTED;
		retval = xio_rdma_disconnect(rdma_hndl, 1);
		if (retval)
			ERROR_LOG("rdma_hndl:%p rdma_disconnect failed, %m\n",
				  rdma_hndl);
		break;
	case XIO_TRANSPORT_STATE_CONNECTING:
		TRACE_LOG("call to rdma_disconnect. rdma_hndl:%p\n",
			  rdma_hndl);
		rdma_hndl->state = XIO_TRANSPORT_STATE_DISCONNECTED;
		retval = xio_rdma_disconnect(rdma_hndl, 0);
		if (retval)
			ERROR_LOG("rdma_hndl:%p rdma_disconnect failed, %m\n",
				  rdma_hndl);
		/*  for beacon */
		kref_put(&rdma_hndl->base.kref, xio_rdma_close_cb);
	break;
	case XIO_TRANSPORT_STATE_CLOSED:
		/* coming here from
		 * context_shutdown/rdma_close,
		 * don't go to disconnect state
		 */
		retval = xio_rdma_disconnect(rdma_hndl, 1);
		if (retval)
			ERROR_LOG("rdma_hndl:%p rdma_disconnect failed, " \
				  "err=%d\n", rdma_hndl, retval);
	break;
	case XIO_TRANSPORT_STATE_INIT:
	case XIO_TRANSPORT_STATE_LISTEN:
	case XIO_TRANSPORT_STATE_DISCONNECTED:
	case XIO_TRANSPORT_STATE_RECONNECT:
	case XIO_TRANSPORT_STATE_DESTROYED:
	case XIO_TRANSPORT_STATE_ERROR:
	break;
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
static void on_cm_timewait_exit(void *hndl)
{
	struct xio_rdma_transport *rdma_hndl = hndl;

	TRACE_LOG("on_cm_timedwait_exit rdma_hndl:%p state:%s\n",
		  rdma_hndl, xio_transport_state_str(rdma_hndl->state));

	xio_rdma_flush_all_tasks(rdma_hndl);

	if (rdma_hndl->state == XIO_TRANSPORT_STATE_DISCONNECTED) {
		xio_transport_notify_observer(&rdma_hndl->base,
					      XIO_TRANSPORT_EVENT_DISCONNECTED,
					      NULL);
	}
	/* if beacon was sent but was never received as wc error then reduce
	   ref count */
	if (rdma_hndl->beacon_sent) {
		rdma_hndl->beacon_sent = 0;
		kref_put(&rdma_hndl->base.kref, xio_rdma_close_cb);
	}

	kref_put(&rdma_hndl->base.kref, xio_rdma_close_cb);
}

/*---------------------------------------------------------------------------*/
/* on_cm_device_release							     */
/*---------------------------------------------------------------------------*/
static void on_cm_device_release(struct rdma_cm_event *ev,
				 struct xio_rdma_transport *rdma_hndl)
{
	struct xio_device **xio_devs;
	struct xio_device *dev;

	dev = rdma_hndl->dev;
	if (!dev) {
		ERROR_LOG("device releases, device not found\n");
		return;
	}

	xio_devs = ib_get_client_data(dev->ib_dev, &xio_client);
	if (!xio_devs) {
		ERROR_LOG("Couldn't find xio device on %s\n",
			  dev->ib_dev->name);
	} else {
		xio_devs[dev->port_num] = NULL;
	}

	xio_device_release(dev);
}

/*---------------------------------------------------------------------------*/
/* on_cm_error								     */
/*---------------------------------------------------------------------------*/
static void on_cm_error(struct rdma_cm_event *ev,
			struct xio_rdma_transport *rdma_hndl)
{
	int	reason;

	ERROR_LOG("rdma transport [error] %s, rdma_hndl:%p\n",
		  xio_rdma_event_str(ev->event), rdma_hndl);

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
	}

	xio_transport_notify_observer_error(&rdma_hndl->base, reason);
}

/*---------------------------------------------------------------------------*/
/* xio_close_handler							     */
/*---------------------------------------------------------------------------*/
void xio_close_handler(void *hndl)
{
	xio_rdma_post_close((struct xio_transport_base *)hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_handle_cm_event							     */
/*---------------------------------------------------------------------------*/
/**
 * xio_cm_event_handler - Callback used to report user events.
 *
 * Notes: Users may not call rdma_destroy_id from this callback to destroy
 *   the passed in id, or a corresponding listen id.  Returning a
 *   non-zero value from the callback will destroy the passed in id.
 */
static int xio_handle_cm_event(struct rdma_cm_id *cm_id,
			       struct rdma_cm_event *ev)
{
	struct xio_rdma_transport *rdma_hndl = cm_id->context;

	TRACE_LOG("cm event %s, hndl:%p\n",
		  xio_rdma_event_str(ev->event), rdma_hndl);

	/* TODO: Handling these events here from the cm handler context,
	 * might cause races with the poller thread context.
	 * 1. Need to handle each of these events using a dedicated
	 *    event handler from the poller context.
	 * 2. Need to make sure the events are removed properly before
	 *    rdma_handler shutdown.
	 */
	rdma_hndl->handler_nesting++;
	switch (ev->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		on_cm_addr_resolved(ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		on_cm_route_resolved(cm_id, ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		on_cm_connect_request(cm_id, ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		on_cm_established(ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_REJECTED:
		on_cm_refused(ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_DISCONNECTED:
		on_cm_disconnected(ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		/* The caller of this callback i.e. cma_ib_handler is holding
		 * cma_disable_callback, thus rdma_destroy_id should not
		 * be called in xio_rdma_close_complete! this is prevented as
		 * rdma_hndl->handler_nesting > 0. We return one to ensure that
		 * cma_ib_handler will call
		 */
		rdma_hndl->ev_data_timewait_exit.handler = on_cm_timewait_exit;
		rdma_hndl->ev_data_timewait_exit.data    = (void *)rdma_hndl;
		xio_context_add_event(rdma_hndl->base.ctx,
				      &rdma_hndl->ev_data_timewait_exit);
		break;

	case RDMA_CM_EVENT_MULTICAST_JOIN:
	case RDMA_CM_EVENT_MULTICAST_ERROR:
		ERROR_LOG("Unreleated event:%d, %s - ignored\n", ev->event,
			  xio_rdma_event_str(ev->event));
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		on_cm_device_release(ev, rdma_hndl);
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
	}
	rdma_hndl->handler_nesting--;

	/* state can be modified to destroyed (side effect) */
	if (rdma_hndl->state == XIO_TRANSPORT_STATE_DESTROYED) {
		/* user space code calls here, xio_rdma_post_close which may
		 * call rdma_destroy_id which is not allowed in an handler
		 */
		rdma_hndl->event_data_close.handler = xio_close_handler;
		rdma_hndl->event_data_close.data    = (void *)rdma_hndl;
		/* tell "poller mechanism" */
		xio_context_add_event(rdma_hndl->base.ctx,
				      &rdma_hndl->event_data_close);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_open		                                             */
/*---------------------------------------------------------------------------*/
static struct xio_transport_base *xio_rdma_open(
					struct xio_transport *transport,
					struct xio_context *ctx,
					struct xio_observer *observer,
					uint32_t trans_attr_mask,
					struct xio_transport_init_attr *attr)
{
	struct xio_rdma_transport *rdma_hndl;

	/* allocate rdma handle */
	rdma_hndl = kzalloc(sizeof(*rdma_hndl), GFP_KERNEL);
	if (!rdma_hndl) {
		xio_set_error(ENOMEM);
		ERROR_LOG("calloc failed.\n");
		return NULL;
	}
	if (attr && trans_attr_mask) {
		memcpy(&rdma_hndl->trans_attr, attr, sizeof(*attr));
		rdma_hndl->trans_attr_mask = trans_attr_mask;
	}

	rdma_hndl->rdma_mempool = xio_mempool_get(ctx);
	if (!rdma_hndl->rdma_mempool) {
		xio_set_error(ENOMEM);
		ERROR_LOG("allocating rdma mempool failed.\n");
		goto cleanup;
	}
	rdma_hndl->base.portal_uri	= NULL;
	kref_init(&rdma_hndl->base.kref);
	rdma_hndl->transport		= transport;
	rdma_hndl->cm_id		= NULL;
	rdma_hndl->qp			= NULL;
	rdma_hndl->tcq			= NULL;
	rdma_hndl->base.ctx		= ctx;
	rdma_hndl->peer_credits		= 0;
	rdma_hndl->max_inline_buf_sz	= xio_rdma_get_inline_buffer_size();

	if (rdma_hndl->base.ctx->rq_depth) {
		//user chose to confgure rq depth
		rdma_hndl->rq_depth = max(g_poptions->max_in_iovsz, rdma_hndl->base.ctx->rq_depth);
	} else {
		rdma_hndl->rq_depth = MAX_RECV_WR;
	}
	rdma_hndl->sq_depth             = g_poptions->max_out_iovsz + 1;

	rdma_hndl->frwr_task.dd_data = ptr_from_int64(XIO_FRWR_LI_WRID);

	INIT_LIST_HEAD(&rdma_hndl->trans_list_entry);
	INIT_LIST_HEAD(&rdma_hndl->in_flight_list);
	INIT_LIST_HEAD(&rdma_hndl->rdma_rd_req_in_flight_list);
	INIT_LIST_HEAD(&rdma_hndl->rdma_rd_rsp_in_flight_list);
	INIT_LIST_HEAD(&rdma_hndl->tx_ready_list);
	INIT_LIST_HEAD(&rdma_hndl->tx_comp_list);
	INIT_LIST_HEAD(&rdma_hndl->rx_list);
	INIT_LIST_HEAD(&rdma_hndl->io_list);
	INIT_LIST_HEAD(&rdma_hndl->rdma_rd_req_list);
	INIT_LIST_HEAD(&rdma_hndl->rdma_rd_rsp_list);

	XIO_OBSERVABLE_INIT(&rdma_hndl->base.observable, rdma_hndl);
	if (observer)
		xio_observable_reg_observer(&rdma_hndl->base.observable,
					    observer);

	TRACE_LOG("xio_rdma_open: [new] handle:%p\n", rdma_hndl);

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
void xio_rdma_close_cb(struct kref *kref)
{
	struct xio_transport_base *transport = container_of(
					kref, struct xio_transport_base, kref);
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;

	xio_transport_notify_observer(
				transport,
				XIO_TRANSPORT_EVENT_CLOSED,
				NULL);
	xio_rdma_post_close((struct xio_transport_base *)rdma_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_close		                                             */
/*---------------------------------------------------------------------------*/
static void xio_rdma_close(struct xio_transport_base *transport)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	int	retval;

	/* now it is zero */
	DEBUG_LOG("xio_rmda_close: [close] handle:%p, qp:%p\n",
		  rdma_hndl, rdma_hndl->qp);

	switch (rdma_hndl->state) {
	case XIO_TRANSPORT_STATE_LISTEN:
		rdma_hndl->state = XIO_TRANSPORT_STATE_CLOSED;
		break;
	case XIO_TRANSPORT_STATE_CONNECTED:
		TRACE_LOG("call to rdma_disconnect. rdma_hndl:%p\n",
			  rdma_hndl);

		rdma_hndl->state = XIO_TRANSPORT_STATE_CLOSED;
		retval = xio_rdma_disconnect(rdma_hndl, 0);
		if (retval)
			DEBUG_LOG("handle:%p rdma_disconnect failed, " \
				  "%d\n", rdma_hndl, retval);
		break;
	case XIO_TRANSPORT_STATE_DISCONNECTED:
		rdma_hndl->state = XIO_TRANSPORT_STATE_CLOSED;
		break;
	case XIO_TRANSPORT_STATE_CLOSED:
		/* do not kref_put - already done */
		return;
	default:
		rdma_hndl->state = XIO_TRANSPORT_STATE_CLOSED;
		break;
	}
	kref_put(&transport->kref, xio_rdma_close_cb);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_dup2		                                             */
/* makes new_trans_hndl be the copy of old_trans_hndl, closes new_trans_hndl */
/* Note old and new are in dup2 terminology opposite to reconnect terms	     */
/* --------------------------------------------------------------------------*/
static int xio_rdma_dup2(struct xio_transport_base *old_trans_hndl,
			 struct xio_transport_base **new_trans_hndl)
{
	struct xio_rdma_transport *old_hndl =
		(struct xio_rdma_transport *)old_trans_hndl;
	struct xio_rdma_transport *new_hndl =
		(struct xio_rdma_transport *)*new_trans_hndl;

	/* if device is not the same an R_KEY replacement table is created */
	if (old_hndl->dev != new_hndl->dev) {
		struct xio_rkey_tbl *te;

		te = &old_hndl->rkey_tbl[old_hndl->rkey_tbl_size];
		/* new is actually the old one we want to replace */
		te->old_rkey = new_hndl->dev->mr->rkey;
		te->new_rkey = old_hndl->dev->mr->rkey;
		old_hndl->rkey_tbl_size++;
	}

	xio_rdma_close(*new_trans_hndl);

	/* nexus layer will call close which will only decrement */
	/*kref_get(&old_trans_hndl->kref);*/
	*new_trans_hndl = old_trans_hndl;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_new_rkey			                                             */
/*---------------------------------------------------------------------------*/

static int xio_new_rkey(struct xio_rdma_transport *rdma_hndl, uint32_t *key)
{
	int i;

	if (!*key)
		return 0;

	for (i = 0; i < rdma_hndl->peer_rkey_tbl_size; i++) {
		if (rdma_hndl->peer_rkey_tbl[i].old_rkey == *key) {
			*key = rdma_hndl->peer_rkey_tbl[i].new_rkey;
			return 0;
		}
	}
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_update_task		                                             */
/*---------------------------------------------------------------------------*/
static int xio_rdma_update_task(struct xio_transport_base *trans_hndl,
				struct xio_task *task)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)trans_hndl;
	XIO_TO_RDMA_TASK(task, rdma_task);
	int i;

	for (i = 0; i < rdma_task->req_in_num_sge; i++) {
		if (xio_new_rkey(rdma_hndl, &rdma_task->req_in_sge[i].stag))
			return -1;
	}

	for (i = 0; i < rdma_task->req_out_num_sge; i++) {
		if (xio_new_rkey(rdma_hndl, &rdma_task->req_out_sge[i].stag))
			return -1;
	}

	return 0;
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
		DEBUG_LOG("rdma_accept failed. (err=%d)\n", retval);
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
		DEBUG_LOG("rdma_reject failed. (err=%d)\n", retval);
		return -1;
	}
	TRACE_LOG("rdma transport: [reject] handle:%p\n", rdma_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_do_connect							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_do_connect(struct xio_transport_base *trans_hndl,
			       const char *out_if_addr)
{
	struct xio_rdma_transport	*rdma_hndl =
		(struct xio_rdma_transport *)trans_hndl;
	union xio_sockaddr		sa;
	int				retval = 0;

	/* resolve the portal_uri */
	if (xio_uri_to_ss(trans_hndl->portal_uri, &sa.sa_stor) == -1) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("address [%s] resolving failed\n",
			  trans_hndl->portal_uri);
		return -1;
	}

	/* create cm id */
	rdma_hndl->cm_id = rdma_create_id(xio_handle_cm_event,
					  (void *)rdma_hndl,
					  RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(rdma_hndl->cm_id)) {
		retval = PTR_ERR(rdma_hndl->cm_id);
		xio_set_error(retval);
		ERROR_LOG("rdma_create id failed. (err=%d)\n", retval);
		goto exit1;
	}

	/* TODO: support out_if_addr */

	if (out_if_addr) {
		union xio_sockaddr if_sa;

		if (xio_host_port_to_ss(out_if_addr,
					&if_sa.sa_stor) == -1) {
			xio_set_error(XIO_E_ADDR_ERROR);
			ERROR_LOG("outgoing interface [%s] resolving failed\n",
				  out_if_addr);
			goto exit2;
		}
		retval = rdma_bind_addr(rdma_hndl->cm_id, &if_sa.sa);
		if (retval) {
			xio_set_error(retval);
			ERROR_LOG("rdma_bind_addr failed. (err=%d)\n",
				  retval);
			goto exit2;
		}
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
	TRACE_LOG("call rdma_destroy_id\n");
	rdma_destroy_id(rdma_hndl->cm_id);
exit1:
	rdma_hndl->cm_id = NULL;

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_connect							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_connect(struct xio_transport_base *trans_hndl,
			    const char *portal_uri, const char *out_if_addr)
{
	struct xio_rdma_transport	*rdma_hndl =
		(struct xio_rdma_transport *)trans_hndl;

	trans_hndl->is_client = 1;

	if (!portal_uri) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("address [%s] resolving failed\n", portal_uri);
		goto exit1;
	}

	/* allocate memory for portal_uri */
	trans_hndl->portal_uri = kstrdup(portal_uri, GFP_KERNEL);
	if (!rdma_hndl->base.portal_uri) {
		xio_set_error(ENOMEM);
		ERROR_LOG("calloc failed. %m\n");
		goto exit1;
	}

	if (xio_rdma_do_connect(trans_hndl, out_if_addr) < 0)
		goto exit2;

	return 0;

exit2:
	kfree(trans_hndl->portal_uri);

exit1:
	return -1;
}

static __be16 priv_get_src_port(struct rdma_cm_id *cm_id)
{
	struct rdma_route *route = &cm_id->route;
	struct rdma_addr *addr = &route->addr;
	struct sockaddr_storage *src_addr = &addr->src_addr;
	__be16 sin_port;

	if (src_addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)src_addr;

		sin_port = s6->sin6_port;
	} else {
		struct sockaddr_in *s4 = (struct sockaddr_in *)src_addr;

		sin_port = s4->sin_port;
	}
	return sin_port;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_listen							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_listen(struct xio_transport_base *transport,
			   const char *portal_uri,
			   uint16_t *src_port, int backlog)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	union xio_sockaddr	sa;
	int			retval = 0;
	uint16_t		sport;

	/* resolve the portal_uri */
	if (xio_uri_to_ss(portal_uri, &sa.sa_stor) == -1) {
		xio_set_error(XIO_E_ADDR_ERROR);
		DEBUG_LOG("address [%s] resolving failed\n", portal_uri);
		return -1;
	}
	rdma_hndl->base.is_client = 0;

	/* create cm id */
	rdma_hndl->cm_id = rdma_create_id(xio_handle_cm_event,
					  (void *)rdma_hndl,
					  RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(rdma_hndl->cm_id)) {
		retval = PTR_ERR(rdma_hndl->cm_id);
		xio_set_error(retval);
		DEBUG_LOG("rdma_create id failed. (err=%d)\n", retval);
		goto exit1;
	}

	retval = rdma_bind_addr(rdma_hndl->cm_id, &sa.sa);
	if (retval) {
		xio_set_error(retval);
		DEBUG_LOG("rdma_bind_addr failed. (err=%d)\n", retval);
		goto exit2;
	}

	backlog = backlog > 0 ? backlog : RDMA_DEFAULT_BACKLOG;
	DEBUG_LOG("Calling rdma_listen() for CM with backlog %d\n", backlog);
	retval = rdma_listen(rdma_hndl->cm_id, backlog);
	if (retval) {
		xio_set_error(retval);
		DEBUG_LOG("rdma_listen failed. (err=%d)\n", retval);
		goto exit2;
	}

	sport = ntohs(priv_get_src_port(rdma_hndl->cm_id));
	if (src_port)
		*src_port = sport;

	rdma_hndl->state = XIO_TRANSPORT_STATE_LISTEN;
	DEBUG_LOG("listen on [%s] src_port:%d\n", portal_uri, sport);

	return 0;

exit2:
	rdma_destroy_id(rdma_hndl->cm_id);
exit1:
	rdma_hndl->cm_id = NULL;

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_set_opt                                                          */
/*---------------------------------------------------------------------------*/
static int xio_rdma_set_opt(void *xio_obj,
			    int optname, const void *optval, int optlen)
{
	switch (optname) {
	case XIO_OPTNAME_ENABLE_MEM_POOL:
		VALIDATE_SZ(sizeof(int));
		rdma_options.enable_mem_pool = *((int *)optval);
		return 0;
	case XIO_OPTNAME_ENABLE_DMA_LATENCY:
		VALIDATE_SZ(sizeof(int));
		rdma_options.enable_dma_latency = *((int *)optval);
		return 0;
	case XIO_OPTNAME_MAX_IN_IOVLEN:
		VALIDATE_SZ(sizeof(int));
		rdma_options.max_in_iovsz = *((int *)optval);
		return 0;
	case XIO_OPTNAME_MAX_OUT_IOVLEN:
		VALIDATE_SZ(sizeof(int));
		rdma_options.max_out_iovsz = *((int *)optval);
		return 0;
	case XIO_OPTNAME_QP_CAP_MAX_INLINE_DATA:
		VALIDATE_SZ(sizeof(int));
		rdma_options.qp_cap_max_inline_data = *((int *)optval);
		return 0;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_get_opt                                                          */
/*---------------------------------------------------------------------------*/
static int xio_rdma_get_opt(void  *xio_obj,
			    int optname, void *optval, int *optlen)
{
	switch (optname) {
	case XIO_OPTNAME_ENABLE_MEM_POOL:
		*((int *)optval) = rdma_options.enable_mem_pool;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_ENABLE_DMA_LATENCY:
		*((int *)optval) = rdma_options.enable_dma_latency;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_MAX_IN_IOVLEN:
		*((int *)optval) = rdma_options.max_in_iovsz;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_MAX_OUT_IOVLEN:
		*((int *)optval) = rdma_options.max_out_iovsz;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_QP_CAP_MAX_INLINE_DATA:
		 *((int *)optval) = rdma_options.qp_cap_max_inline_data;
		*optlen = sizeof(int);
		 return 0;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_is_valid_in_req							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_is_valid_in_req(struct xio_msg *msg)
{
	struct xio_vmsg *vmsg = &msg->in;
	int		i;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sge;
	unsigned int		nents, max_nents;
	size_t		length = 0;

	/* kernel works only with kernel's scatterlist */
	if (unlikely(vmsg->sgl_type != XIO_SGL_TYPE_SCATTERLIST)) {
		/* src/common/xio_session_client.c uses XIO_SGL_TYPE_IOV but len
		 * should be zero. Note, other types are not supported!
		 */
		if (vmsg->sgl_type != XIO_SGL_TYPE_IOV) {
			ERROR_LOG("Incompatible sgl type %d\n", vmsg->sgl_type);
			return 0;
		}
		if (vmsg->data_tbl.nents){
			ERROR_LOG("Bad data_tbl.nents %d\n", vmsg->data_tbl.nents);
			return 0;
		}
		/* Just check header */
		if (vmsg->header.iov_base &&
		    (vmsg->header.iov_len == 0)){
			ERROR_LOG("Bad header %p %zu\n", vmsg->header.iov_base,
				vmsg->header.iov_len);
			return 0;
		} else {
			return 1;
		}
	}

	sgtbl		= xio_sg_table_get(vmsg);
	sgtbl_ops	= xio_sg_table_ops_get(vmsg->sgl_type);
	nents		= tbl_nents(sgtbl_ops, sgtbl);
	max_nents	= tbl_max_nents(sgtbl_ops, sgtbl);

	if ((nents > rdma_options.max_in_iovsz) ||
	    (nents > max_nents) ||
	    (max_nents > rdma_options.max_in_iovsz)) {
		ERROR_LOG("Too many SG entries %u (%u, %u)\n",
			nents, max_nents, rdma_options.max_in_iovsz);
		return 0;
	}

	if (vmsg->header.iov_base  &&
	    (vmsg->header.iov_len == 0)) {
		ERROR_LOG("Bad header %p %zu\n", vmsg->header.iov_base,
			vmsg->header.iov_len);
		return 0;
	}

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		length += sge_length(sgtbl_ops, sge);
		if (sge_addr(sgtbl_ops, sge) &&
		    (sge_length(sgtbl_ops, sge)  == 0)){
			ERROR_LOG("Zero SGE length\n");
			return 0;
		}
	}
	if (length >= (XIO_MAX_IOV + 1) * PAGE_SIZE) {
		ERROR_LOG("Total length %zu > %zu\n",
			length, (XIO_MAX_IOV + 1) * PAGE_SIZE);
		return 0;
	}

	return 1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_is_valid_out_msg						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_is_valid_out_msg(struct xio_msg *msg)
{
	struct xio_vmsg		*vmsg = &msg->out;
	int			i;
	struct xio_sg_table_ops *sgtbl_ops;
	void			*sgtbl;
	void			*sge;
	unsigned int		nents, max_nents;

	/* kernel works only with kernel's scatterlist */
	if (unlikely(vmsg->sgl_type != XIO_SGL_TYPE_SCATTERLIST)) {
		/* src/common/xio_session_client.c uses XIO_SGL_TYPE_IOV but len
		 * should be zero. Note, other types are not supported!
		 */
		if (vmsg->sgl_type != XIO_SGL_TYPE_IOV) {
			ERROR_LOG("Invalid SGL type %d for msg %p\n",
				  vmsg->sgl_type, msg);
			return 0;
		}
		if (vmsg->data_tbl.nents) {
			ERROR_LOG("SGL type is XIO_SGL_TYPE_IOV and nents=%u\n",
				  vmsg->data_tbl.nents);
			return 0;
		}

		/* Just check header */
		if ((vmsg->header.iov_base  &&
		     (vmsg->header.iov_len == 0)) ||
		    (!vmsg->header.iov_base  &&
		     (vmsg->header.iov_len != 0))) {
			ERROR_LOG("Bad header for IOV SGL base=%p len=%zu\n",
				  vmsg->header.iov_base,
				  vmsg->header.iov_len);
			return 0;
		} else {
			return 1;
		}
	}

	sgtbl		= xio_sg_table_get(vmsg);
	sgtbl_ops	= xio_sg_table_ops_get(vmsg->sgl_type);
	nents		= tbl_nents(sgtbl_ops, sgtbl);
	max_nents	= tbl_max_nents(sgtbl_ops, sgtbl);

	if ((nents > rdma_options.max_out_iovsz) ||
	    (nents > max_nents) ||
	    (max_nents > rdma_options.max_out_iovsz)) {
		ERROR_LOG("Bad nents=%u rdma_options.max_out_iovsz=%u " \
			  "max_nents=%u\n",
			  nents, rdma_options.max_out_iovsz, max_nents);
		return 0;
	}

	if ((vmsg->header.iov_base  &&
	     (vmsg->header.iov_len == 0)) ||
	    (!vmsg->header.iov_base  &&
	     (vmsg->header.iov_len != 0))) {
		ERROR_LOG("Bad header base=%p len=%zu\n",
			  vmsg->header.iov_base,
			  vmsg->header.iov_len);
		return 0;
	}

	if (vmsg->header.iov_len >
	    (size_t)xio_get_options()->max_inline_xio_hdr) {
		ERROR_LOG("Header is too large %zu>%zu\n", vmsg->header.iov_len,
			  (size_t)xio_get_options()->max_inline_xio_hdr);
		return 0;
	}

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		if ((!sge_addr(sgtbl_ops, sge)) ||
		    (sge_length(sgtbl_ops, sge) == 0)) {
			ERROR_LOG("Addr is NULL or length is zero " \
				  "for an SGE\n");
			return 0;
		}
	}

	return 1;
}

/* task pools management */
/*---------------------------------------------------------------------------*/
/* xio_rdma_get_pools_ops						     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_get_pools_ops(struct xio_transport_base *trans_hndl,
				   struct xio_tasks_pool_ops **initial_pool_ops,
				   struct xio_tasks_pool_ops **primary_pool_ops)
{
	*initial_pool_ops = &initial_tasks_pool_ops;
	*primary_pool_ops = &primary_tasks_pool_ops;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_set_pools_cls						     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_set_pools_cls(struct xio_transport_base *trans_hndl,
				   struct xio_tasks_pool_cls *initial_pool_cls,
				   struct xio_tasks_pool_cls *primary_pool_cls)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)trans_hndl;

	if (initial_pool_cls)
		rdma_hndl->initial_pool_cls = *initial_pool_cls;
	if (primary_pool_cls)
		rdma_hndl->primary_pool_cls = *primary_pool_cls;
}

static struct xio_transport xio_rdma_transport = {
	.name			= "rdma",
	.ctor			= NULL,
	.dtor			= NULL,
	.init			= NULL,
	.release		= NULL,
	.context_shutdown	= xio_rdma_context_shutdown,
	.open			= xio_rdma_open,
	.connect		= xio_rdma_connect,
	.listen			= xio_rdma_listen,
	.accept			= xio_rdma_accept,
	.reject			= xio_rdma_reject,
	.close			= xio_rdma_close,
	.dup2			= xio_rdma_dup2,
	.update_task		= xio_rdma_update_task,
	.send			= xio_rdma_send,
	.poll			= NULL,
	.set_opt		= xio_rdma_set_opt,
	.get_opt		= xio_rdma_get_opt,
	.cancel_req		= xio_rdma_cancel_req,
	.cancel_rsp		= xio_rdma_cancel_rsp,
	.get_pools_setup_ops	= xio_rdma_get_pools_ops,
	.set_pools_cls		= xio_rdma_set_pools_cls,

	.validators_cls.is_valid_in_req  = xio_rdma_is_valid_in_req,
	.validators_cls.is_valid_out_msg = xio_rdma_is_valid_out_msg,
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_constructor					     */
/*---------------------------------------------------------------------------*/
static int __init xio_rdma_transport_constructor(void)
{
	struct xio_transport *transport = &xio_rdma_transport;

	/* set cpu latency until process is down */
	/* xio_set_cpu_latency(); */

	/* register the transport */
	xio_reg_transport(transport);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_destructor					     */
/*---------------------------------------------------------------------------*/
static void __exit xio_rdma_transport_destructor(void)
{
	struct xio_transport *transport = &xio_rdma_transport;

	/* Called after all devices were deleted */

	xio_unreg_transport(transport);
}

/*---------------------------------------------------------------------------*/
/* xio_add_one								     */
/*---------------------------------------------------------------------------*/
static void xio_add_one(struct ib_device *ib_dev)
{
	struct xio_device **xio_devs;
	int s, e, p;
	enum rdma_transport_type transport_type = rdma_node_get_transport(
		ib_dev->node_type);

	if (transport_type != RDMA_TRANSPORT_IB &&
	    transport_type != RDMA_TRANSPORT_IWARP)
		return;

	if (ib_dev->node_type == RDMA_NODE_IB_SWITCH) {
		s = 0;
		e = 0;
	} else {
		s = 1;
		e = ib_dev->phys_port_cnt;
	}

	xio_devs = kcalloc(e + 1, sizeof(struct xio_device *), GFP_KERNEL);
	if (!xio_devs) {
		ERROR_LOG("Couldn't allocate n(%d) pointers\n", e + 1);
		return;
	}

	for (p = s; p <= e; p++) {
		struct xio_device *xio_dev;

		xio_dev = xio_device_init(ib_dev, p);
		if (!xio_dev) {
			ERROR_LOG("init xio_dev on dev(%s) port(%d) failed\n",
				  ib_dev->name, p);
			goto cleanup;
		}
		xio_devs[p] = xio_dev;
	}

	ib_set_client_data(ib_dev, &xio_client, xio_devs);

	return;

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
/* xio_del_one							     */
/*---------------------------------------------------------------------------*/

static void xio_del_one(struct ib_device *ib_dev)
{
	struct xio_device **xio_devs;
	int s, e, p;
	enum rdma_transport_type transport_type = rdma_node_get_transport(
		ib_dev->node_type);

	if (transport_type != RDMA_TRANSPORT_IB &&
	    transport_type != RDMA_TRANSPORT_IWARP)
		return;

	/* xio_del_one is called before the core clients' list is deleted
	 * so calling ib_get_client_data in xio_del_one is O.K.
	 */

	xio_devs = ib_get_client_data(ib_dev, &xio_client);
	if (!xio_devs) {
		ERROR_LOG("Couldn't find xio device on %s\n",
			  ib_dev->name);
		return;
	}

	if (ib_dev->node_type == RDMA_NODE_IB_SWITCH) {
		s = 0;
		e = 0;
	} else {
		s = 1;
		e = ib_dev->phys_port_cnt;
	}

	for (p = s; p <= e; p++) {
		if (xio_devs[p]) {
			xio_device_release(xio_devs[p]);
			xio_devs[p] = NULL;
		}
	}

	kfree(xio_devs);
}

static int __init xio_init_module(void)
{
	int ret;

	if (debugfs_initialized()) {
		xio_rdma_root = debugfs_create_dir("xio_rdma", NULL);
		if (!xio_rdma_root) {
			pr_err("xio_rdma root debugfs creation failed\n");
			return -ENOMEM;
		}
	} else {
		xio_rdma_root = NULL;
		pr_err("debugfs not initialized\n");
	}

	xio_rdma_transport_constructor();

	g_poptions = xio_get_options();

	/* xio_add_one will be called for all existing devices
	 * add for all new devices
	 */

	ret = ib_register_client(&xio_client);
	if (ret) {
		pr_err("couldn't register IB client ret%d\n", ret);
		return ret;
	}
	return 0;
}

static void __exit xio_cleanup_module(void)
{
	/* xio_del_one will called for all devices */

	ib_unregister_client(&xio_client);

	xio_rdma_transport_destructor();

	debugfs_remove_recursive(xio_rdma_root);
}

struct dentry *xio_rdma_debugfs_root(void)
{
	return xio_rdma_root;
}

module_init(xio_init_module);
module_exit(xio_cleanup_module);
