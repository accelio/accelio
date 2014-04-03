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
#include "xio_observer.h"
#include "xio_context.h"
#include "xio_task.h"
#include "xio_transport.h"
#include "xio_protocol.h"
#include "get_clock.h"
#include "xio_mem.h"
#include "xio_rdma_mempool.h"
#include "xio_rdma_transport.h"
#include "xio_rdma_utils.h"
#include "xio_ev_loop.h"


/* default option values */
#define XIO_OPTVAL_DEF_ENABLE_MEM_POOL			1
#define XIO_OPTVAL_DEF_ENABLE_DMA_LATENCY		0
#define XIO_OPTVAL_DEF_RDMA_BUF_THRESHOLD		SEND_BUF_SZ
#define XIO_OPTVAL_MIN_RDMA_BUF_THRESHOLD		256
#define XIO_OPTVAL_MAX_RDMA_BUF_THRESHOLD		65536

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static struct xio_rdma_mempool		**mempool_array;
static int				mempool_array_len;
static spinlock_t			mngmt_lock;
static pthread_rwlock_t			dev_lock;
static pthread_rwlock_t			cm_lock;
static pthread_once_t			ctor_key_once = PTHREAD_ONCE_INIT;
static pthread_once_t			dtor_key_once = PTHREAD_ONCE_INIT;
struct xio_transport			xio_rdma_transport;


LIST_HEAD(dev_list);
static LIST_HEAD(cm_list);

static struct xio_dev_tdata		dev_tdata;

/* rdma options */
struct xio_rdma_options			rdma_options = {
	.enable_mem_pool		= XIO_OPTVAL_DEF_ENABLE_MEM_POOL,
	.enable_dma_latency		= XIO_OPTVAL_DEF_ENABLE_DMA_LATENCY,
	.rdma_buf_threshold		= XIO_OPTVAL_DEF_RDMA_BUF_THRESHOLD,
	.rdma_buf_attr_rdonly		= 0,
};

/*---------------------------------------------------------------------------*/
/* forward declaration							     */
/*---------------------------------------------------------------------------*/
static struct xio_transport_base *xio_rdma_open(
		struct xio_transport	*transport,
		struct xio_context	*ctx,
		struct xio_observer	*observer);
static void xio_rdma_close(struct xio_transport_base *transport);
static struct rdma_event_channel *xio_cm_channel_get(struct xio_context *ctx);
static void xio_rdma_post_close(struct xio_transport_base *transport);
static int xio_rdma_flush_all_tasks(struct xio_rdma_transport *rdma_hndl);


/*---------------------------------------------------------------------------*/
/* xio_async_ev_handler							     */
/*---------------------------------------------------------------------------*/
static void xio_async_ev_handler(int fd, int events, void *user_context)
{
	char			*dev_name = NULL;
	struct ibv_async_event	async_event;
	struct xio_device	*dev = (struct xio_device *)user_context;

	dev_name = dev->verbs->device->name;

	while (1) {
		if (ibv_get_async_event(dev->verbs, &async_event)) {
			if (errno == EAGAIN)
				return;

			xio_set_error(errno);
			ERROR_LOG("ibv_get_async_event failed. (errno=%d %m)\n",
				  errno);
			return;
		}
		ERROR_LOG("ibv_get_async_event: dev:%s evt: %s\n", dev_name,
			  ibv_event_type_str(async_event.event_type));

		ibv_ack_async_event(&async_event);
	}

	return;
}

/*---------------------------------------------------------------------------*/
/* device thread callback						     */
/*---------------------------------------------------------------------------*/
static void *device_thread_cb(void *data)
{
	cpu_set_t		cpuset;
	pthread_t		thread;

	/* set affinity to thread */
	thread = pthread_self();

	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset); /* bind the devices thread to first core */

	pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);

	/* the default xio supplied main loop */
	xio_ev_loop_run(dev_tdata.async_loop);

	/* normal exit phase */
	TRACE_LOG("devices thread exit signaled\n");

	/* destroy the default loop */
	xio_ev_loop_destroy(&dev_tdata.async_loop);
	dev_tdata.async_loop = NULL;

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_device_thread_init						     */
/*---------------------------------------------------------------------------*/
static int xio_device_thread_init()
{
	int ret;

	/* open default event loop */
	dev_tdata.async_loop = xio_ev_loop_create();
	if (!dev_tdata.async_loop) {
		ERROR_LOG("xio_ev_loop_init failed\n");
		return -1;
	}
	ret = pthread_create(&dev_tdata.dev_thread, NULL,
			     device_thread_cb, NULL);
	if (ret < 0) {
		ERROR_LOG("pthread_create failed. %m\n");
		/* destroy the default loop */
		xio_ev_loop_destroy(&dev_tdata.async_loop);
		dev_tdata.async_loop = NULL;
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_device_thread_stop						     */
/*---------------------------------------------------------------------------*/
static void xio_device_thread_stop()
{
	xio_ev_loop_stop(dev_tdata.async_loop, 0);

	pthread_join(dev_tdata.dev_thread, NULL);
}

/*---------------------------------------------------------------------------*/
/* xio_device_thread_add_device						     */
/*---------------------------------------------------------------------------*/
int xio_device_thread_add_device(struct xio_device *dev)
{
	int retval;

	fcntl(dev->verbs->async_fd, F_SETFL,
	      fcntl(dev->verbs->async_fd, F_GETFL, 0) | O_NONBLOCK);

	/* add to epoll */
	retval = xio_ev_loop_add(
			dev_tdata.async_loop,
			dev->verbs->async_fd,
			XIO_POLLIN,
			xio_async_ev_handler,
			dev);
	if (retval != 0) {
		xio_set_error(errno);
		ERROR_LOG("ev_loop_add failed. (errno=%d %m)\n", errno);
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_device_thread_remove_device					     */
/*---------------------------------------------------------------------------*/
int xio_device_thread_remove_device(struct xio_device *dev)
{
	if (dev_tdata.async_loop)
		return xio_ev_loop_del(
				dev_tdata.async_loop,
				dev->verbs->async_fd);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_cq_create							     */
/*---------------------------------------------------------------------------*/
static struct xio_cq *xio_cq_init(struct xio_device *dev,
				      struct xio_context *ctx)
{
	struct xio_cq		*tcq;
	int			retval;
	int			comp_vec = 0;

	list_for_each_entry(tcq, &dev->cq_list, cq_list_entry) {
		if (tcq->ctx == ctx)
			return tcq;
	}
	tcq = ucalloc(1, sizeof(struct xio_cq));
	if (tcq == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc failed. %m\n");
		goto cleanup;
	}
	tcq->ctx = ctx;

	tcq->wc_array_len = MAX_CQE_PER_QP;
	/* allocate device wc array */
	tcq->wc_array = ucalloc(tcq->wc_array_len, sizeof(struct ibv_wc));
	if (tcq->wc_array == NULL) {
		xio_set_error(errno);
		ERROR_LOG("ev_loop_add failed. (errno=%d %m)\n", errno);
		goto cleanup1;
	}

	tcq->alloc_sz = min(dev->device_attr.max_cqe, CQE_ALLOC_SIZE);
	tcq->max_cqe  = dev->device_attr.max_cqe;

	/* set com_vector to cpu */
	comp_vec = ctx->cpuid % dev->verbs->num_comp_vectors;

	tcq->channel = ibv_create_comp_channel(dev->verbs);
	if (tcq->channel == NULL) {
		xio_set_error(errno);
		ERROR_LOG("ibv_create_comp_channel failed. (errno=%d %m)\n",
			  errno);
		goto cleanup2;
	}
	fcntl(tcq->channel->fd, F_SETFL,
	      fcntl(tcq->channel->fd, F_GETFL, 0) | O_NONBLOCK);


	/* add to epoll */
	retval = xio_context_add_ev_handler(
			ctx,
			tcq->channel->fd,
			XIO_POLLIN,
			xio_cq_event_handler,
			tcq);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("ev_loop_add_cb failed. (errno=%d %m)\n", errno);
		goto cleanup3;
	}


	tcq->cq = ibv_create_cq(dev->verbs, tcq->alloc_sz, tcq,
				tcq->channel, comp_vec);
	TRACE_LOG("comp_vec:%d\n", comp_vec);
	if (tcq->cq == NULL) {
		xio_set_error(errno);
		ERROR_LOG("ibv_create_cq failed. (errno=%d %m)\n", errno);
		goto cleanup4;
	}

	retval = ibv_req_notify_cq(tcq->cq, 0);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("ibv_req_notify_cq failed. (errno=%d %m)\n",
			  errno);
		goto cleanup5;
	}

	/* set cq depth params */
	tcq->dev	= dev;
	tcq->cq_depth	= tcq->alloc_sz;
	tcq->cqe_avail	= tcq->alloc_sz;
	atomic_set(&tcq->refcnt, 0);

	INIT_LIST_HEAD(&tcq->trans_list);

	list_add(&tcq->cq_list_entry, &dev->cq_list);

	return tcq;

cleanup5:
	retval = ibv_destroy_cq(tcq->cq);
	if (retval)
		ERROR_LOG("ibv_destroy_cq failed. (errno=%d %m)\n", errno);
cleanup4:
	xio_context_del_ev_handler(
			ctx,
			tcq->channel->fd);
cleanup3:
	retval = ibv_destroy_comp_channel(tcq->channel);
	if (retval)
		ERROR_LOG("ibv_destroy_comp_channel failed. (errno=%d %m)\n",
			  errno);
cleanup2:
	ufree(tcq->wc_array);
cleanup1:
	ufree(tcq);
cleanup:
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_cq_release							     */
/*---------------------------------------------------------------------------*/
static void xio_cq_release(struct xio_cq *tcq, int delete_fd)
{
	int		retval;
	struct xio_rdma_transport *rdma_hndl, *tmp_rdma_hndl;

	list_del(&tcq->cq_list_entry);

	/* clean all redundant connections attached to this cq */
	list_for_each_entry_safe(rdma_hndl, tmp_rdma_hndl, &tcq->trans_list,
				 trans_list_entry) {
		xio_rdma_flush_all_tasks(rdma_hndl);
		xio_rdma_post_close(
				(struct xio_transport_base *)rdma_hndl);
	}

	if (tcq->cq_events_that_need_ack != 0) {
				ibv_ack_cq_events(
				   tcq->cq,
				   tcq->cq_events_that_need_ack);
				   tcq->cq_events_that_need_ack = 0;
	}
	if (delete_fd) {
		retval = xio_context_del_ev_handler(
				tcq->ctx,
				tcq->channel->fd);
		if (retval)
			ERROR_LOG("ev_loop_del_cb failed. (errno=%d %m)\n",
				  errno);
	}
	/* if  event is scheduled, then remove it */
	xio_ctx_remove_event(tcq->ctx, &tcq->event_data);

	/* the event loop may be release by the time this function is called */
	retval = ibv_destroy_cq(tcq->cq);
	if (retval)
		ERROR_LOG("ibv_destroy_cq failed. (errno=%d %m)\n", errno);

	retval = ibv_destroy_comp_channel(tcq->channel);
	if (retval)
		ERROR_LOG("ibv_destroy_comp_channel failed. (errno=%d %m)\n",
			  errno);

	ufree(tcq->wc_array);
	ufree(tcq);
}

/*---------------------------------------------------------------------------*/
/* xio_device_init							     */
/*---------------------------------------------------------------------------*/
static struct xio_device *xio_device_init(struct ibv_context *ib_ctx)
{
	struct xio_device	*dev;
	int			retval;

	dev = ucalloc(1, sizeof(*dev));
	if (dev == NULL) {
		xio_set_error(errno);
		ERROR_LOG("ucalloc failed. (errno=%d %m)\n", errno);
		return NULL;
	}
	dev->verbs	= ib_ctx;

	dev->pd = ibv_alloc_pd(dev->verbs);
	if (dev->pd == NULL) {
		xio_set_error(errno);
		ERROR_LOG("ibv_alloc_pd failed. (errno=%d %m)\n", errno);
		goto cleanup;
	}
	retval = ibv_query_device(dev->verbs, &dev->device_attr);
	if (retval < 0) {
		ERROR_LOG("ibv_query_device failed. (errno=%d %m)\n", errno);
		goto cleanup1;
	}

	retval = xio_device_thread_add_device(dev);
	if (retval) {
		ERROR_LOG(
		"xio_device_thread_add_device failed. (errno=%d %m)\n",
		errno);
		goto cleanup1;
	}

	INIT_LIST_HEAD(&dev->cq_list);
	pthread_rwlock_init(&dev->cq_lock, NULL);
	TRACE_LOG("rdma device: [new] %p\n", dev);

	return dev;

cleanup1:
	ibv_dealloc_pd(dev->pd);
cleanup:
	ERROR_LOG("rdma device: [new] failed\n");
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_device_release							     */
/*---------------------------------------------------------------------------*/
static void xio_device_release(struct xio_device *dev, int delete_fd)
{
	int			retval;
	struct xio_cq		*tcq, *next;

	TRACE_LOG("rdma device: [close] dev:%p\n", dev);

	retval = xio_device_thread_remove_device(dev);
	if (retval) {
		ERROR_LOG(
			"xio_device_thread_add_device failed. (errno=%d %m)\n",
			errno);
	}

	/* acknowledge all accumulated successful
	 * ibv_get_cq_event() calls
	 */
	/* don't delete the fd - the  loop may not exist at this stage */
	list_for_each_entry_safe(tcq, next, &dev->cq_list, cq_list_entry) {
		xio_cq_release(tcq, delete_fd);
	}
	pthread_rwlock_destroy(&dev->cq_lock);

	retval = ibv_dealloc_pd(dev->pd);
	if (retval)
		ERROR_LOG("ibv_dealloc_pd(%p) failed. (errno=%d %s)\n",
			  dev->pd, retval, strerror(retval));

	ufree(dev);
}

/*---------------------------------------------------------------------------*/
/* xio_device_list_init							     */
/*---------------------------------------------------------------------------*/
static int xio_device_list_init()
{
	struct ibv_context **ctx_list;
	struct xio_device *dev;
	int num_devices = 0, i;
	int retval = 0;

	INIT_LIST_HEAD(&dev_list);

	ctx_list = rdma_get_devices(&num_devices);
	if (!ctx_list) {
		xio_set_error(errno);
		ERROR_LOG("Failed to get IB devices list\n");
		return -1;
	}

	if (!*ctx_list) {
		xio_set_error(ENODEV);
		ERROR_LOG("No IB devices found\n");
		retval = -1;
		goto exit;
	}
	for (i = 0; i < num_devices; ++i) {
		dev = xio_device_init(ctx_list[i]);
		if (!dev) {
			ERROR_LOG("Couldn't allocate device %s\n",
				  ibv_get_device_name(ctx_list[i]->device));
			retval = -1;
			goto exit;
		}
		pthread_rwlock_wrlock(&dev_lock);
		list_add(&dev->dev_list_entry, &dev_list);
		pthread_rwlock_unlock(&dev_lock);
	}
exit:
	rdma_free_devices(ctx_list);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_device_list_release						     */
/*---------------------------------------------------------------------------*/
static void xio_device_list_release(int del_fd)
{
	struct xio_device	*dev, *next;

	/* free devices */
	pthread_rwlock_wrlock(&dev_lock);
	list_for_each_entry_safe(dev, next, &dev_list, dev_list_entry) {
		list_del(&dev->dev_list_entry);
		xio_device_release(dev, del_fd);
	}
	pthread_rwlock_unlock(&dev_lock);
}

/*---------------------------------------------------------------------------*/
/* xio_rmda_mempool_array_init						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_mempool_array_init()
{
	int cpus_nr = sysconf(_SC_NPROCESSORS_CONF);

	/* free devices */
	mempool_array_len = 0;
	mempool_array = ucalloc(cpus_nr, sizeof(struct xio_rmda_mempool *));
	if (mempool_array == NULL) {
		xio_set_error(errno);
		ERROR_LOG("mempool_array_init failed. (errno=%d %m)\n", errno);
		return -1;
	}
	mempool_array_len = cpus_nr;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_array_release					     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_mempool_array_release()
{
	int i;

	for (i = 0; i < mempool_array_len; i++) {
		if (mempool_array[i]) {
			xio_rdma_mempool_destroy(mempool_array[i]);
			mempool_array[i] = NULL;
		}
	}
	ufree(mempool_array);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_mempool_array_get						     */
/*---------------------------------------------------------------------------*/
static struct xio_rdma_mempool *xio_rdma_mempool_array_get(
		struct xio_context *ctx)
{
	if (ctx->nodeid > mempool_array_len) {
		ERROR_LOG("xio_rdma_mempool_create failed. array overflow\n");
		return NULL;
	}
	if (mempool_array[ctx->nodeid])
		return mempool_array[ctx->nodeid];

	mempool_array[ctx->nodeid] = xio_rdma_mempool_create();
	if (!mempool_array[ctx->nodeid]) {
		ERROR_LOG("xio_rdma_mempool_create failed " \
			  "(errno=%d %m)\n", errno);
		return NULL;
	}
	return mempool_array[ctx->nodeid];
}

/*---------------------------------------------------------------------------*/
/* xio_cm_channel_release						     */
/*---------------------------------------------------------------------------*/
static void xio_cm_channel_release(struct xio_cm_channel *channel)
{
	list_del(&channel->channels_list_entry);
	xio_context_del_ev_handler(channel->ctx, channel->cm_channel->fd);
	rdma_destroy_event_channel(channel->cm_channel);

	ufree(channel);
}

/*---------------------------------------------------------------------------*/
/* xio_cm_list_release							     */
/*---------------------------------------------------------------------------*/
static void xio_cm_list_release()
{
	struct xio_cm_channel	*channel, *next;

	pthread_rwlock_wrlock(&cm_lock);
	list_for_each_entry_safe(channel, next, &cm_list, channels_list_entry) {
		list_del(&channel->channels_list_entry);
		rdma_destroy_event_channel(channel->cm_channel);
		ufree(channel);
	}
	pthread_rwlock_unlock(&cm_lock);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_context_shutdown						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_context_shutdown(struct xio_transport_base *trans_hndl,
				     struct xio_context *ctx)
{
	struct xio_device	*dev;
	struct xio_cq		*tcq, *next;
	struct xio_cm_channel	*channel = NULL;

	pthread_rwlock_wrlock(&dev_lock);
	list_for_each_entry(dev, &dev_list, dev_list_entry) {
		pthread_rwlock_wrlock(&dev->cq_lock);
		list_for_each_entry_safe(tcq, next, &dev->cq_list,
					 cq_list_entry) {
			if (ctx == tcq->ctx)
				xio_cq_release(tcq, 1);
		}
		pthread_rwlock_unlock(&dev->cq_lock);
	}
	pthread_rwlock_unlock(&dev_lock);


	/* find the channel and release it */
	pthread_rwlock_wrlock(&cm_lock);
	list_for_each_entry(channel, &cm_list, channels_list_entry) {
		if (channel->ctx == ctx) {
			xio_cm_channel_release(channel);
			break;
		}
	}
	pthread_rwlock_unlock(&cm_lock);

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
		int retval = ibv_resize_cq(tcq->cq,
					   (tcq->cq_depth + tcq->alloc_sz));
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

/*---------------------------------------------------------------------------*/
/* xio_setup_qp                                                              */
/*---------------------------------------------------------------------------*/
static int xio_setup_qp(struct xio_rdma_transport *rdma_hndl)
{
	struct xio_device		*dev;
	struct ibv_qp_init_attr		qp_init_attr;
	struct ibv_qp_attr		qp_attr;
	int				dev_found = 0;
	int				retval = 0;
	struct	xio_cq			*tcq;

	/* find device */
	pthread_rwlock_rdlock(&dev_lock);
	list_for_each_entry(dev, &dev_list, dev_list_entry) {
		if (dev->verbs == rdma_hndl->cm_id->verbs) {
			dev_found = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&dev_lock);
	if (!dev_found) {
		xio_set_error(ENODEV);
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

	memset(&qp_init_attr, 0, sizeof(qp_init_attr));

	qp_init_attr.qp_context			= rdma_hndl;
	qp_init_attr.qp_type			= IBV_QPT_RC;
	qp_init_attr.send_cq			= tcq->cq;
	qp_init_attr.recv_cq			= tcq->cq;
	qp_init_attr.cap.max_send_wr		= MAX_SEND_WR;
	qp_init_attr.cap.max_recv_wr		= MAX_RECV_WR + EXTRA_RQE;
	qp_init_attr.cap.max_send_sge		= MAX_SGE;
	qp_init_attr.cap.max_recv_sge		= 1;
	qp_init_attr.cap.max_inline_data	= MAX_INLINE_DATA;

	/* only generate completion queue entries if requested */
	qp_init_attr.sq_sig_all		= 0;

	retval = rdma_create_qp(rdma_hndl->cm_id, dev->pd, &qp_init_attr);
	if (retval) {
		xio_set_error(errno);
		xio_cq_free_slots(tcq, MAX_CQE_PER_QP);
		ERROR_LOG("rdma_create_qp failed. (errno=%d %m)\n", errno);
		return -1;
	}
	rdma_hndl->tcq		= tcq;
	rdma_hndl->qp		= rdma_hndl->cm_id->qp;
	rdma_hndl->sqe_avail	= MAX_SEND_WR;

	memset(&qp_attr, 0, sizeof(qp_attr));
	if (ibv_query_qp(rdma_hndl->qp, &qp_attr, 0, &qp_init_attr) != 0)
		ERROR_LOG("ibv_query_qp failed. (errno=%d %m)\n", errno);
	rdma_hndl->max_inline_data = qp_attr.cap.max_inline_data;


	list_add(&rdma_hndl->trans_list_entry, &tcq->trans_list);

	TRACE_LOG("rdma qp: [new] handle:%p, qp:0x%x, max inline:%d\n",
		  rdma_hndl,
		  rdma_hndl->qp->qp_num,
		  rdma_hndl->max_inline_data);

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
		list_del(&rdma_hndl->trans_list_entry);
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
			   struct ibv_mr *srmr)
{
	rxd->sge[0].addr	= uint64_from_ptr(buf);
	rxd->sge[0].length	= size;
	rxd->sge[0].lkey	= srmr->lkey;

	rxd->recv_wr.wr_id	= uint64_from_ptr(task);
	rxd->recv_wr.sg_list	= rxd->sge;
	rxd->recv_wr.num_sge	= 1;
	rxd->recv_wr.next	= NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_txd_init								     */
/*---------------------------------------------------------------------------*/
static void xio_txd_init(struct xio_work_req *txd,
			  struct xio_task *task,
			  void *buf, unsigned size,
			  struct ibv_mr *srmr)
{
	txd->sge[0].addr	= uint64_from_ptr(buf);
	txd->sge[0].length	= size;
	txd->sge[0].lkey	= srmr->lkey;

	txd->send_wr.wr_id	= uint64_from_ptr(task);
	txd->send_wr.next	= NULL;
	txd->send_wr.sg_list	= txd->sge;
	txd->send_wr.num_sge	= 1;
	txd->send_wr.opcode	= IBV_WR_SEND;

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

	/* to be set before posting:
	   rdmad->iser_ib_op, rdmad->send_wr.opcode
	   rdmad->sge.addr, rdmad->sge.length
	   rdmad->send_wr.wr.rdma.(remote_addr,rkey) */
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_task_init							     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_task_init(struct xio_task *task,
				 struct xio_rdma_transport *rdma_hndl,
				 void *buf,
				 unsigned long size,
				 struct ibv_mr *srmr)
{
	XIO_TO_RDMA_TASK(task, rdma_task);

	rdma_task->rdma_hndl = rdma_hndl;

	xio_rxd_init(&rdma_task->rxd, task, buf, size, srmr);
	xio_txd_init(&rdma_task->txd, task, buf, size, srmr);
	xio_rdmad_init(&rdma_task->rdmad, task);

	/* initialize the mbuf */
	xio_mbuf_init(&task->mbuf, buf, size, 0);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_flush_task_list						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_flush_task_list(struct xio_rdma_transport *rdma_hndl,
				    struct list_head *list)
{
	struct xio_task *ptask, *next_ptask;

	list_for_each_entry_safe(ptask, next_ptask, list,
				 tasks_list_entry) {
		TRACE_LOG("flushing task %p type 0x%x\n",
			  ptask, ptask->tlv_type);
		if (ptask->sender_task) {
			xio_tasks_pool_put(ptask->sender_task);
			ptask->sender_task = NULL;
		}
		xio_tasks_pool_put(ptask);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_flush_all_tasks						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_flush_all_tasks(struct xio_rdma_transport *rdma_hndl)
{
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
		/* for task that attached to senders with ref coount = 2 */
		xio_rdma_flush_task_list(rdma_hndl, &rdma_hndl->tx_ready_list);
	}

	if (!list_empty(&rdma_hndl->rx_list)) {
		TRACE_LOG("rx_list not empty!\n");
		xio_rdma_flush_task_list(rdma_hndl, &rdma_hndl->rx_list);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_calc_pool_size						     */
/*---------------------------------------------------------------------------*/
void xio_rdma_calc_pool_size(struct xio_rdma_transport *rdma_hndl)
{
	/* four queues are involved:
	 * tx_ready_queue, recv_queue, sent_queue, io_submit_queue,
	 * also note that client holds the sent and recv tasks
	 * simultaneously */

	rdma_hndl->num_tasks = 6*(rdma_hndl->sq_depth +
				  rdma_hndl->actual_rq_depth);

	rdma_hndl->alloc_sz  = rdma_hndl->num_tasks*rdma_hndl->membuf_sz;

	rdma_hndl->max_tx_ready_tasks_num = rdma_hndl->sq_depth;

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
	uint32_t pool_size;

	rdma_pool->buf_size = CONN_SETUP_BUF_SIZE;
	pool_size = rdma_pool->buf_size * max;
	rdma_pool->data_pool = ucalloc(pool_size, sizeof(uint8_t));
	if (rdma_pool->data_pool == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc conn_setup_data_pool sz: %u failed\n",
			  pool_size);
		return -1;
	}
	rdma_pool->data_mr = ibv_reg_mr(rdma_hndl->tcq->dev->pd,
			rdma_pool->data_pool,
			pool_size, IBV_ACCESS_LOCAL_WRITE);
	if (!rdma_pool->data_mr) {
		xio_set_error(errno);
		ufree(rdma_pool->data_pool);
		ERROR_LOG("ibv_reg_mr conn_setup pool failed, %m\n");
		return -1;
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_initial_task_alloc						     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_rdma_initial_task_alloc(
					struct xio_rdma_transport *rdma_hndl)
{
	if (rdma_hndl->initial_pool_cls.task_alloc)
		return rdma_hndl->initial_pool_cls.task_alloc(
					rdma_hndl->initial_pool_cls.pool);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_task_alloc						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_rdma_primary_task_alloc(
					struct xio_rdma_transport *rdma_hndl)
{
	if (rdma_hndl->primary_pool_cls.task_alloc)
		return rdma_hndl->primary_pool_cls.task_alloc(
					rdma_hndl->primary_pool_cls.pool);
	return NULL;
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
	if (rdma_hndl->primary_pool_cls.task_free)
		return rdma_hndl->primary_pool_cls.task_free(task);
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


	task = xio_rdma_initial_task_alloc(rdma_hndl);
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

	ibv_dereg_mr(rdma_pool->data_mr);
	ufree(rdma_pool->data_pool);

	return 0;
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

	xio_rdma_task_init(
			task,
			rdma_hndl,
			buf,
			rdma_pool->buf_size,
			rdma_pool->data_mr);

	return 0;
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
	.pool_run		= xio_rdma_initial_pool_run
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_pool_alloc						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_primary_pool_alloc(
		struct xio_transport_base *transport_hndl,
		int max, void *pool_dd_data)
{
	struct xio_mr_elem *tmr_elem;

	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport_hndl;
	struct xio_rdma_tasks_pool *rdma_pool =
		(struct xio_rdma_tasks_pool *)pool_dd_data;

	rdma_pool->buf_size = rdma_hndl->membuf_sz;

	if (disable_huge_pages) {
		rdma_pool->io_buf = xio_alloc(rdma_hndl->alloc_sz);
		if (!rdma_pool->io_buf) {
			xio_set_error(ENOMEM);
			ERROR_LOG("xio_alloc rdma pool sz:%zu failed\n",
					rdma_hndl->alloc_sz);
			return -1;
		}
		rdma_pool->data_pool = rdma_pool->io_buf->addr;
		rdma_pool->data_mr = NULL;
		list_for_each_entry(tmr_elem,
				    &rdma_pool->io_buf->mr->dm_list,
				    dm_list_entry) {
			if (rdma_hndl->tcq->dev == tmr_elem->dev)  {
				rdma_pool->data_mr = tmr_elem->mr;
				break;
			}
		}
		if (!rdma_pool->data_mr) {
			xio_set_error(errno);
			ERROR_LOG("ibv_reg_mr failed, %m\n");
			return -1;
		}
	} else {
		rdma_pool->data_pool = umalloc_huge_pages(rdma_hndl->alloc_sz);
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
			ufree_huge_pages(rdma_pool->data_pool);
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

	if (rdma_pool->io_buf) {
		xio_free(&rdma_pool->io_buf);
	} else {
		ibv_dereg_mr(rdma_pool->data_mr);
		ufree_huge_pages(rdma_pool->data_pool);
	}

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

	XIO_TO_RDMA_TASK(task, rdma_task);
	rdma_task->ib_op = 0x200;


	xio_rdma_task_init(
			task,
			rdma_hndl,
			buf,
			rdma_pool->buf_size,
			rdma_pool->data_mr);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_task_pre_put						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_task_pre_put(
		struct xio_transport_base *trans_hndl,
		struct xio_task *task)
{
	int	i;
	XIO_TO_RDMA_TASK(task, rdma_task);

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
	rdma_task->phantom_idx = 0;
	rdma_task->sn = 0;

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
	.pool_run		= xio_rdma_primary_pool_run,
	.pre_put		= xio_rdma_task_pre_put,
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_post_close							     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_post_close(struct xio_transport_base *transport)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;

	TRACE_LOG("rdma transport: [post close] handle:%p, qp:%p\n",
		  rdma_hndl, rdma_hndl->qp);

	xio_observable_unreg_all_observers(&rdma_hndl->base.observable);

	xio_release_qp(rdma_hndl);
	if (rdma_hndl->cm_id)
		rdma_destroy_id(rdma_hndl->cm_id);

	ufree(rdma_hndl->base.portal_uri);

	ufree(rdma_hndl);
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
		DEBUG_LOG("rdma_resolve_route failed. (errno=%d %m)\n", errno);
		xio_transport_notify_observer_error(&rdma_hndl->base,
						    xio_errno());
	}
}

/*---------------------------------------------------------------------------*/
/* on_cm_route_resolved	                                                     */
/*---------------------------------------------------------------------------*/
static void on_cm_route_resolved(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	int				retval = 0;
	struct rdma_conn_param		cm_params;


	retval = xio_setup_qp(rdma_hndl);
	if (retval != 0) {
		ERROR_LOG("internal logic error in create_endpoint\n");
		goto notify_err1;
	}

	memset(&cm_params, 0 , sizeof(cm_params));
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

		DEBUG_LOG("rdma_connect failed. (errno=%d %m)\n", errno);
		goto notify_err2;
	}
	rdma_hndl->client_responder_resources = cm_params.responder_resources;
	rdma_hndl->client_initiator_depth = cm_params.initiator_depth;


	return;

notify_err2:
	xio_release_qp(rdma_hndl);
notify_err1:
	xio_transport_notify_observer_error(&rdma_hndl->base, xio_errno());
}

/*---------------------------------------------------------------------------*/
/* on_cm_connect_request						     */
/*---------------------------------------------------------------------------*/
static void  on_cm_connect_request(struct rdma_cm_event *ev,
		struct xio_rdma_transport *parent_hndl)
{
	struct xio_rdma_transport	*child_hndl;
	union xio_transport_event_data	event_data;
	int	retval = 0;

	child_hndl = (struct xio_rdma_transport *)xio_rdma_open(
		parent_hndl->transport,
		parent_hndl->base.ctx,
		NULL);
	if (child_hndl == NULL) {
		ERROR_LOG("failed to open rdma transport\n");
		goto notify_err1;
	}

	child_hndl->cm_id	= ev->id;
	child_hndl->tcq		= parent_hndl->tcq;
	ev->id->context		= child_hndl;
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

	event_data.new_connection.child_trans_hndl =
		(struct xio_transport_base *)child_hndl;
	xio_transport_notify_observer(&parent_hndl->base,
				 XIO_TRANSPORT_NEW_CONNECTION,
				 &event_data);

	return;

notify_err2:
	xio_rdma_close((struct xio_transport_base *)child_hndl);

notify_err1:
	xio_transport_notify_observer_error(&parent_hndl->base, xio_errno());
}

/*---------------------------------------------------------------------------*/
/* on_cm_refused							     */
/*---------------------------------------------------------------------------*/
static void  on_cm_refused(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	ERROR_LOG("on_cm refused. reason:%s\n",
		  xio_cm_rej_reason_str(ev->status));
	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_REFUSED, NULL);
}

/*---------------------------------------------------------------------------*/
/* on_cm_established						             */
/*---------------------------------------------------------------------------*/
static void  on_cm_established(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	xio_transport_notify_observer(&rdma_hndl->base,
				      XIO_TRANSPORT_ESTABLISHED,
				      NULL);
}

/*---------------------------------------------------------------------------*/
/* on_cm_disconnected							     */
/*---------------------------------------------------------------------------*/
static void  on_cm_disconnected(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	int retval;

	TRACE_LOG("on_cm_disconnected. rdma_hndl:%p, state:%d\n",
		  rdma_hndl, rdma_hndl->state);
	if (rdma_hndl->state == XIO_STATE_CONNECTED ||
	    rdma_hndl->state == XIO_STATE_LISTEN) {
		TRACE_LOG("call to rdma_disconnect. rdma_hndl:%p\n",
			  rdma_hndl);
		rdma_hndl->state = XIO_STATE_DISCONNECTED;
		retval = rdma_disconnect(rdma_hndl->cm_id);
		if (retval)
			DEBUG_LOG("rdma_hndl:%p rdma_disconnect failed, %m\n",
				  rdma_hndl);
	}
}

/*
 * Handle RDMA_CM_EVENT_TIMEWAIT_EXIT which is expected to be the last
 * event during the life cycle of a connection, when it had been shut down
 * and the network has cleared from the remaining in-flight messages.
*/
/*---------------------------------------------------------------------------*/
/* on_cm_timedwait_exit							     */
/*---------------------------------------------------------------------------*/
static void on_cm_timewait_exit(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	TRACE_LOG("on_cm_timedwait_exit rdma_hndl:%p\n", rdma_hndl);

	xio_rdma_flush_all_tasks(rdma_hndl);

	if (rdma_hndl->state == XIO_STATE_DISCONNECTED) {
		xio_transport_notify_observer(&rdma_hndl->base,
					      XIO_TRANSPORT_DISCONNECTED,
					      NULL);
	}

	if (rdma_hndl->state == XIO_STATE_CLOSED) {
		xio_transport_notify_observer(&rdma_hndl->base,
					      XIO_TRANSPORT_CLOSED,
					      NULL);
		rdma_hndl->state = XIO_STATE_DESTROYED;
	}
}

/*---------------------------------------------------------------------------*/
/* on_cm_error								     */
/*---------------------------------------------------------------------------*/
static void on_cm_error(struct rdma_cm_event *ev,
		struct xio_rdma_transport *rdma_hndl)
{
	int	reason;

	DEBUG_LOG("rdma transport [error] %s, hndl:%p\n",
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
	xio_transport_notify_observer_error(&rdma_hndl->base, reason);
}

/*---------------------------------------------------------------------------*/
/* xio_handle_cm_event							     */
/*---------------------------------------------------------------------------*/
static void xio_handle_cm_event(struct rdma_cm_event *ev,
			  struct xio_rdma_transport *rdma_hndl)
{
	TRACE_LOG("cm event %s, hndl:%p\n",
		  rdma_event_str(ev->event), rdma_hndl);

	switch (ev->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		on_cm_addr_resolved(ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		on_cm_route_resolved(ev, rdma_hndl);
		break;
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		on_cm_connect_request(ev, rdma_hndl);
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
/* xio_connection_ev_handler		                                     */
/*---------------------------------------------------------------------------*/
static void xio_connection_ev_handler(int fd, int events, void *user_context)
{
	struct rdma_event_channel	*p_cm_channel =
		(struct rdma_event_channel *)(user_context);
	struct rdma_cm_event		*ev;
	struct xio_rdma_transport	*rdma_hndl;
	int				retval;

	/* get the event */
	retval = rdma_get_cm_event(p_cm_channel, &ev);
	if (retval) {
		if (errno == EAGAIN)
			return;
		xio_set_error(errno);
		ERROR_LOG("rdma_get_cm_event failed. " \
			  "(errno=%d %m)\n", errno);
		return;
	}

	rdma_hndl = (struct xio_rdma_transport *)ev->id->context;

	DEBUG_LOG("cm_event: [%s] rdma_hndl:%p\n",
		  rdma_event_str(ev->event), rdma_hndl);

	xio_handle_cm_event(ev, rdma_hndl);

	rdma_ack_cm_event(ev);

	if (rdma_hndl->state  == XIO_STATE_DESTROYED)
		xio_rdma_post_close(
				(struct xio_transport_base *)rdma_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_cm_channel_get							     */
/*---------------------------------------------------------------------------*/
static struct rdma_event_channel *xio_cm_channel_get(struct xio_context *ctx)
{
	struct xio_cm_channel	*channel;
	int retval;

	pthread_rwlock_rdlock(&cm_lock);
	list_for_each_entry(channel, &cm_list, channels_list_entry) {
		if (channel->ctx == ctx) {
			pthread_rwlock_unlock(&cm_lock);
			return channel->cm_channel;
		}
	}
	pthread_rwlock_unlock(&cm_lock);

	channel = ucalloc(1, sizeof(struct xio_cm_channel));
	if (!channel) {
		ERROR_LOG("rdma_create_event_channel failed " \
				"(errno=%d %m)\n", errno);
		return NULL;
	}

	channel->cm_channel = rdma_create_event_channel();
	if (!channel->cm_channel) {
		ERROR_LOG("rdma_create_event_channel failed " \
				"(errno=%d %m)\n", errno);
		return NULL;
	}
	/* turn the file descriptor to non blocking */
	fcntl(channel->cm_channel->fd, F_SETFL,
	      fcntl(channel->cm_channel->fd, F_GETFL, 0) | O_NONBLOCK);

	retval = xio_context_add_ev_handler(
			ctx,
			channel->cm_channel->fd,
			XIO_POLLIN,
			xio_connection_ev_handler,
			channel->cm_channel);
	if (retval != 0) {
		xio_set_error(errno);
		ERROR_LOG("Adding to event loop failed (errno=%d %m)\n",
			  errno);
		goto cleanup;
	}
	channel->ctx = ctx;

	pthread_rwlock_wrlock(&cm_lock);
	list_add(&channel->channels_list_entry, &cm_list);
	pthread_rwlock_unlock(&cm_lock);

	return channel->cm_channel;

cleanup:
	rdma_destroy_event_channel(channel->cm_channel);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_open		                                             */
/*---------------------------------------------------------------------------*/
static struct xio_transport_base *xio_rdma_open(
		struct xio_transport	*transport,
		struct xio_context	*ctx,
		struct xio_observer	*observer)
{
	struct xio_rdma_transport	*rdma_hndl;


	/*allocate rdma handl */
	rdma_hndl = ucalloc(1, sizeof(struct xio_rdma_transport));
	if (!rdma_hndl) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc failed. %m\n");
		return NULL;
	}

	XIO_OBSERVABLE_INIT(&rdma_hndl->base.observable, rdma_hndl);

	if (rdma_options.enable_mem_pool) {
		rdma_hndl->rdma_mempool = xio_rdma_mempool_array_get(ctx);
		if (rdma_hndl->rdma_mempool == NULL) {
			xio_set_error(ENOMEM);
			ERROR_LOG("allocating rdma mempool failed. %m\n");
			goto cleanup;
		}
	}

	rdma_hndl->base.portal_uri	= NULL;
	atomic_set(&rdma_hndl->base.refcnt, 1);
	rdma_hndl->transport		= transport;
	rdma_hndl->cm_id		= NULL;
	rdma_hndl->qp			= NULL;
	rdma_hndl->tcq			= NULL;
	rdma_hndl->base.ctx		= ctx;
	rdma_hndl->rq_depth		= MAX_RECV_WR;
	rdma_hndl->sq_depth		= MAX_SEND_WR;
	rdma_hndl->peer_credits		= 0;
	rdma_hndl->cm_channel		= xio_cm_channel_get(ctx);
	rdma_hndl->max_send_buf_sz	= rdma_options.rdma_buf_threshold;
	/* from now on don't allow changes */
	rdma_options.rdma_buf_attr_rdonly = 1;

	if (!rdma_hndl->cm_channel) {
		TRACE_LOG("rdma transport: failed to allocate cm_channel\n");
		goto cleanup;
	}
	if (observer)
		xio_observable_reg_observer(&rdma_hndl->base.observable,
					    observer);

	INIT_LIST_HEAD(&rdma_hndl->in_flight_list);
	INIT_LIST_HEAD(&rdma_hndl->rdma_rd_in_flight_list);
	INIT_LIST_HEAD(&rdma_hndl->tx_ready_list);
	INIT_LIST_HEAD(&rdma_hndl->tx_comp_list);
	INIT_LIST_HEAD(&rdma_hndl->rx_list);
	INIT_LIST_HEAD(&rdma_hndl->io_list);
	INIT_LIST_HEAD(&rdma_hndl->rdma_rd_list);

	TRACE_LOG("xio_rdma_open: [new] handle:%p\n", rdma_hndl);

	return (struct xio_transport_base *)rdma_hndl;

cleanup:
	ufree(rdma_hndl);

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
/* xio_rdma_close		                                             */
/*---------------------------------------------------------------------------*/
static void xio_rdma_close(struct xio_transport_base *transport)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	int	retval;
	int was = __atomic_add_unless(&rdma_hndl->base.refcnt, -1, 0);

	/* was already 0 */
	if (!was)
		return;

	if (was == 1) {
		/* now it is zero */
		TRACE_LOG("xio_rmda_close: [close] handle:%p, qp:%p\n",
			  rdma_hndl, rdma_hndl->qp);

		switch (rdma_hndl->state) {
		case XIO_STATE_LISTEN:
			rdma_hndl->state = XIO_STATE_CLOSED;
			 xio_rdma_post_close(
				(struct xio_transport_base *)rdma_hndl);
			 break;
		case XIO_STATE_CONNECTED:
			 rdma_hndl->state = XIO_STATE_CLOSED;
			 retval = rdma_disconnect(rdma_hndl->cm_id);
			 if (retval)
				DEBUG_LOG("handle:%p rdma_disconnect failed, " \
					  "%m\n", rdma_hndl);
			 break;
		case XIO_STATE_DISCONNECTED:
			 rdma_hndl->state = XIO_STATE_CLOSED;
			 break;
		default:
			 xio_transport_notify_observer(&rdma_hndl->base,
						       XIO_TRANSPORT_CLOSED,
						       NULL);
			 rdma_hndl->state = XIO_STATE_DESTROYED;
			 break;
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
	struct rdma_conn_param		cm_params;

	memset(&cm_params, 0, sizeof(cm_params));
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
	 * use RDMA read operations, then initiator_depth can be set
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
		xio_set_error(errno);
		DEBUG_LOG("rdma_accept failed. (errno=%d %m)\n", errno);
		return -1;
	}
	rdma_hndl->client_responder_resources = cm_params.responder_resources;
	rdma_hndl->client_initiator_depth = cm_params.initiator_depth;

	TRACE_LOG("rdma transport: [accept] handle:%p\n", rdma_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_reject		                                             */
/*---------------------------------------------------------------------------*/
static int xio_rdma_reject(struct xio_transport_base *transport)
{
	struct xio_rdma_transport *rdma_hndl =
		(struct xio_rdma_transport *)transport;
	int				retval;

	/* "reject" the connection */
	retval = rdma_reject(rdma_hndl->cm_id, NULL, 0);
	if (retval) {
		xio_set_error(errno);
		DEBUG_LOG("rdma_reject failed. (errno=%d %m)\n", errno);
		return -1;
	}
	TRACE_LOG("rdma transport: [reject] handle:%p\n", rdma_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_connect		                                             */
/*---------------------------------------------------------------------------*/
static int xio_rdma_connect(struct xio_transport_base *transport,
			    const char *portal_uri, const char *out_if_addr)
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
	rdma_hndl->base.portal_uri = strdup(portal_uri);
	if (rdma_hndl->base.portal_uri == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc failed. %m\n");
		goto exit1;
	}
	rdma_hndl->base.is_client = 1;

	/* create cm id */
	retval = rdma_create_id(rdma_hndl->cm_channel, &rdma_hndl->cm_id,
				rdma_hndl, RDMA_PS_TCP);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("rdma_create id failed. (errno=%d %m)\n", errno);
		goto exit2;
	}
	if (out_if_addr) {
		union xio_sockaddr if_sa;

		if (xio_host_port_to_ss(out_if_addr, &if_sa.sa_stor) == -1) {
			xio_set_error(XIO_E_ADDR_ERROR);
			ERROR_LOG("outgoing interface [%s] resolving failed\n",
				  out_if_addr);
			goto exit2;
		}
		retval = rdma_bind_addr(rdma_hndl->cm_id, &if_sa.sa);
		if (retval) {
			xio_set_error(errno);
			DEBUG_LOG("rdma_bind_addr failed. (errno=%d %m)\n",
				  errno);
			goto exit2;
		}
	}

	retval = rdma_resolve_addr(rdma_hndl->cm_id, NULL, &sa.sa,
				   ADDR_RESOLVE_TIMEOUT);
	if (retval) {
		xio_set_error(errno);
		DEBUG_LOG("rdma_resolve_addr failed. (errno=%d %m)\n", errno);
		goto exit2;
	}

	return 0;

exit2:
	rdma_destroy_id(rdma_hndl->cm_id);
	rdma_hndl->cm_id = NULL;
exit1:
	ufree(rdma_hndl->base.portal_uri);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_listen							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_listen(struct xio_transport_base *transport,
		const char *portal_uri, uint16_t *src_port, int backlog)
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
	/*is_server = 1; */

	/* create cm id */
	retval = rdma_create_id(rdma_hndl->cm_channel, &rdma_hndl->cm_id,
				rdma_hndl, RDMA_PS_TCP);
	if (retval) {
		xio_set_error(errno);
		DEBUG_LOG("rdma_create id failed. (errno=%d %m)\n", errno);
		goto exit2;
	}

	retval = rdma_bind_addr(rdma_hndl->cm_id, &sa.sa);
	if (retval) {
		xio_set_error(errno);
		DEBUG_LOG("rdma_bind_addr failed. (errno=%d %m)\n", errno);
		goto exit2;
	}

	/* 0 == maximum backlog */
	retval  = rdma_listen(rdma_hndl->cm_id, backlog);
	if (retval) {
		xio_set_error(errno);
		DEBUG_LOG("rdma_listen failed. (errno=%d %m)\n", errno);
		goto exit2;
	}

	sport = ntohs(rdma_get_src_port(rdma_hndl->cm_id));
	if (src_port)
		*src_port = sport;

	rdma_hndl->state = XIO_STATE_LISTEN;
	DEBUG_LOG("listen on [%s] src_port:%d\n", portal_uri, sport);

	return 0;

exit2:
	rdma_destroy_id(rdma_hndl->cm_id);
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
		break;
	case XIO_OPTNAME_ENABLE_DMA_LATENCY:
		VALIDATE_SZ(sizeof(int));
		rdma_options.enable_dma_latency = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_RDMA_BUF_THRESHOLD:
		VALIDATE_SZ(sizeof(int));

		/* changing the parameter is not allowed */
		if (rdma_options.rdma_buf_attr_rdonly) {
			xio_set_error(EPERM);
			return -1;
		}
		if (*(int *)optval < 0 ||
		    *(int *)optval > XIO_OPTVAL_MAX_RDMA_BUF_THRESHOLD) {
			xio_set_error(EINVAL);
			return -1;
		}
		rdma_options.rdma_buf_threshold = *((int *)optval) +
					XIO_OPTVAL_MIN_RDMA_BUF_THRESHOLD;
		rdma_options.rdma_buf_threshold =
			ALIGN(rdma_options.rdma_buf_threshold, 64);
		return 0;
		break;
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
		break;
	case XIO_OPTNAME_ENABLE_DMA_LATENCY:
		*((int *)optval) = rdma_options.enable_dma_latency;
		*optlen = sizeof(int);
		return 0;
		break;
	case XIO_OPTNAME_RDMA_BUF_THRESHOLD:
		*((int *)optval) =
			rdma_options.rdma_buf_threshold -
				XIO_OPTVAL_MIN_RDMA_BUF_THRESHOLD;
		*optlen = sizeof(int);
		return 0;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
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
	int fd;

	if (!rdma_options.enable_dma_latency)
		return 0;

	DEBUG_LOG("setting latency to %d us\n", latency);
	fd = open("/dev/cpu_dma_latency", O_WRONLY);
	if (fd < 0) {
		ERROR_LOG(
		 "open /dev/cpu_dma_latency %m - need root permissions\n");
		return -1;
	}
	if (write(fd, &latency, sizeof(latency)) != sizeof(latency)) {
		ERROR_LOG(
		 "write to /dev/cpu_dma_latency %m - need root permissions\n");
		return -1;
	}
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_init							     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_init()
{
	int			retval = 0;

	INIT_LIST_HEAD(&cm_list);

	spin_lock_init(&mngmt_lock);
	pthread_rwlock_init(&dev_lock, NULL);
	pthread_rwlock_init(&cm_lock, NULL);

	/* set cpu latency until process is down */
	xio_set_cpu_latency();

	retval = xio_device_thread_init();
	if (retval != 0) {
		ERROR_LOG("Failed to initialize devices thread\n");
		return;
	}

	retval = xio_device_list_init();
	if (retval != 0) {
		ERROR_LOG("Failed to initialize device list\n");
		return;
	}

	/* storage for all memory registrations */
	xio_mr_list_init();

	xio_rdma_mempool_array_init();
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_init						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_transport_init(struct xio_transport *transport)
{
	pthread_once(&ctor_key_once, xio_rdma_init);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_release							     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_release()
{
	xio_rdma_mempool_array_release();

	/* free all redundant registered memory */
	xio_mr_list_free();

	xio_device_thread_stop();

	/* free devices */
	xio_device_list_release(0);

	xio_cm_list_release();

	pthread_rwlock_destroy(&dev_lock);
	pthread_rwlock_destroy(&cm_lock);
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_release		                                     */
/*---------------------------------------------------------------------------*/
static void xio_rdma_transport_release(struct xio_transport *transport)
{
	if (ctor_key_once == PTHREAD_ONCE_INIT)
		return;

	pthread_once(&dtor_key_once, xio_rdma_release);
}


/*---------------------------------------------------------------------------*/
/* xio_is_valid_in_req							     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_is_valid_in_req(struct xio_msg *msg)
{
	int		i;
	int		mr_found = 0;
	struct xio_vmsg *vmsg = &msg->in;

	if (vmsg->data_iovlen >= XIO_MAX_IOV)
		return 0;

	if ((vmsg->header.iov_base != NULL)  &&
	    (vmsg->header.iov_len == 0))
		return 0;

	for (i = 0; i < vmsg->data_iovlen; i++) {
		if (vmsg->data_iov[i].mr)
			mr_found++;
		if (vmsg->data_iov[i].iov_base == NULL) {
			if (vmsg->data_iov[i].mr)
				return 0;
		} else {
			if (vmsg->data_iov[i].iov_len == 0)
				return 0;
		}
	}
	if ((mr_found != vmsg->data_iovlen) && mr_found)
		return 0;

	return 1;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_is_valid_out_msg						     */
/*---------------------------------------------------------------------------*/
static int xio_rdma_is_valid_out_msg(struct xio_msg *msg)
{
	int		i;
	int		mr_found = 0;
	struct xio_vmsg *vmsg = &msg->out;

	if (vmsg->data_iovlen >= XIO_MAX_IOV)
		return 0;

	if (((vmsg->header.iov_base != NULL)  &&
	     (vmsg->header.iov_len == 0)) ||
	    ((vmsg->header.iov_base == NULL)  &&
	     (vmsg->header.iov_len != 0)))
			return 0;

	for (i = 0; i < vmsg->data_iovlen; i++) {
		if (vmsg->data_iov[i].mr)
			mr_found++;
		if ((vmsg->data_iov[i].iov_base == NULL) ||
		    (vmsg->data_iov[i].iov_len == 0))
				return 0;
	}
	if ((mr_found != vmsg->data_iovlen) && mr_found)
		return 0;

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


/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_constructor					     */
/*---------------------------------------------------------------------------*/
void xio_rdma_transport_constructor(void)
{
	int			retval;
	/* struct xio_transport	*transport = &xio_rdma_transport; */

	/* Mellanox OFED's User Manual */
	/*
	setenv("MLX_QP_ALLOC_TYPE","PREFER_CONTIG", 1);
	setenv("MLX_CQ_ALLOC_TYPE","ALL", 1);
	setenv("MLX_MR_ALLOC_TYPE","ALL", 1);
	*/
	if (0) {
		setenv("RDMAV_FORK_SAFE", "YES", 1);
		setenv("RDMAV_HUGEPAGES_SAFE", "YES", 1);
		retval = ibv_fork_init();
		if (retval)
			ERROR_LOG("ibv_fork_init failed (errno=%d %s)\n",
				  retval, strerror(retval));
	}
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_destructor					     */
/*---------------------------------------------------------------------------*/
void xio_rdma_transport_destructor(void)
{
	ctor_key_once = PTHREAD_ONCE_INIT;
	dtor_key_once = PTHREAD_ONCE_INIT;
}

struct xio_transport xio_rdma_transport = {
	.name			= "rdma",
	.ctor			= xio_rdma_transport_constructor,
	.dtor			= xio_rdma_transport_destructor,
	.init			= xio_rdma_transport_init,
	.release		= xio_rdma_transport_release,
	.context_shutdown	= xio_rdma_context_shutdown,
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
	.cancel_req		= xio_rdma_cancel_req,
	.cancel_rsp		= xio_rdma_cancel_rsp,
//	.reg_observer		= xio_transport_reg_observer,
//	.unreg_observer		= xio_transport_unreg_observer,
	.get_pools_setup_ops	= xio_rdma_get_pools_ops,
	.set_pools_cls		= xio_rdma_set_pools_cls,

	.validators_cls.is_valid_in_req  = xio_rdma_is_valid_in_req,
	.validators_cls.is_valid_out_msg = xio_rdma_is_valid_out_msg,
};

