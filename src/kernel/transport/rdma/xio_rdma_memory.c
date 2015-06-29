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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/scatterlist.h>
#include <linux/version.h>

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
#include "xio_transport.h"
#include "xio_ktransport.h"
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

#define XIO_KMALLOC_THRESHOLD 0x20000 /* 128K - kmalloc limit */

#ifndef IS_PAGE_ALIGNED
#define IS_PAGE_ALIGNED(ptr)	(((PAGE_SIZE-1) & (uintptr_t)(ptr)) == 0)
#endif

struct fast_reg_descriptor {
	struct llist_node		llist_entry;
	/* For fast registration - FRWR */
	struct ib_mr			*data_mr;
	struct ib_fast_reg_page_list	*data_frpl;
	/* Valid for fast registration flag */
	int				valid;
};

/*---------------------------------------------------------------------------*/
/* xio_unmap_rx_work_req						     */
/*---------------------------------------------------------------------------*/
void xio_unmap_rx_work_req(struct xio_device *dev, struct xio_work_req *xd)
{
	struct ib_device *ib_dev = dev->ib_dev;

	if (!xd->nents || !xd->mapped)
		return;

	/* Assume scatterlist is terminated properly */

	ib_dma_unmap_sg(ib_dev, xd->sgt.sgl, xd->sgt.nents, DMA_FROM_DEVICE);

	xd->mapped = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_unmap_tx_work_req						     */
/*---------------------------------------------------------------------------*/

void xio_unmap_tx_work_req(struct xio_device *dev, struct xio_work_req *xd)
{
	struct ib_device *ib_dev = dev->ib_dev;

	if (!xd->nents || !xd->mapped)
		return;

	/* Assume scatterlist is terminated properly */

	/* Inline were not mapped */
	if (!(xd->send_wr.send_flags & IB_SEND_INLINE))
		ib_dma_unmap_sg(ib_dev, xd->sgt.sgl, xd->sgt.nents,
				DMA_TO_DEVICE);

	/* Disconnect header from data if any */
	sg_mark_end(&xd->sgt.sgl[1]);
	sg_mark_end(xd->sgt.sgl);
	xd->sgt.nents = xd->sgt.orig_nents;

	xd->mapped = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_map_rx_work_req							     */
/*---------------------------------------------------------------------------*/
int xio_map_rx_work_req(struct xio_device *dev, struct xio_work_req *xd)
{
	struct ib_device *ib_dev = dev->ib_dev;
	struct sg_table *sgt = &xd->sgt;
	struct scatterlist *sg;
	int nents;
	int i;

	if (!xd->nents)
		return -1;

	/* Assume scatterlist is terminated properly */

	nents = ib_dma_map_sg(ib_dev, sgt->sgl, sgt->nents,
			      DMA_FROM_DEVICE);
	if (!nents) {
		xd->mapped = 0;
		return -1;
	}

	sg = sgt->sgl;
	for (i = 0; i < nents; i++) {
		xd->sge[i].addr   = ib_sg_dma_address(ib_dev, sg);
		xd->sge[i].length = ib_sg_dma_len(ib_dev, sg);
		/* lkey is already initialized */
		sg = sg_next(sg);
	}

	xd->mapped = nents;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_map_tx_work_req							     */
/*---------------------------------------------------------------------------*/
int xio_map_tx_work_req(struct xio_device *dev, struct xio_work_req *xd)
{
	struct ib_device *ib_dev = dev->ib_dev;
	struct sg_table *sgt = &xd->sgt;
	struct scatterlist *sg;
	int nents;
	int i;

	if (!xd->nents)
		return -1;

	/* Assume scatterlist is terminated properly */

	sg = sgt->sgl;

	if (xd->send_wr.send_flags & IB_SEND_INLINE) {
		/* Inline need not be mapped just return to virt addresses
		 * from sg's page + offset
		 */
		for (i = 0; i < xd->nents; i++) {
			xd->sge[i].addr = uint64_from_ptr(sg_virt(sg));
			xd->sge[i].length = sg->length;
			/* lkey is already initialized */
			sg = sg_next(sg);
		}
		xd->mapped = xd->nents;
		return 0;
	}

	nents = ib_dma_map_sg(ib_dev, sgt->sgl, sgt->nents, DMA_TO_DEVICE);
	if (!nents) {
		/* Disconnect header from data if any*/
		sg_mark_end(sg);
		sgt->nents = sgt->orig_nents;
		xd->mapped = 0;
		return -1;
	}

	for (i = 0; i < nents; i++) {
		xd->sge[i].addr   = ib_sg_dma_address(ib_dev, sg);
		xd->sge[i].length = ib_sg_dma_len(ib_dev, sg);
		/* lkey is already initialized */
		sg = sg_next(sg);
	}
	xd->mapped = nents;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_unmap_rxmad_work_req						     */
/*---------------------------------------------------------------------------*/
void xio_unmap_rxmad_work_req(struct xio_device *dev, struct xio_work_req *xd)
{
	struct ib_device *ib_dev = dev->ib_dev;

	if (!xd->nents || !xd->mapped)
		return;

	/* Assume scatterlist is terminated properly */

	ib_dma_unmap_sg(ib_dev, xd->sgt.sgl, xd->sgt.nents, DMA_FROM_DEVICE);

	/* xio_prep_rdma_op calls sg_mark_end need to undo  */
	if (xd->last_sg) {
		sg_unmark_end(xd->last_sg);
		xd->last_sg = NULL;
		xd->sgt.nents = xd->sgt.orig_nents;
	}

	xd->mapped = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_unmap_txmad_work_req						     */
/*---------------------------------------------------------------------------*/

void xio_unmap_txmad_work_req(struct xio_device *dev, struct xio_work_req *xd)
{
	struct ib_device *ib_dev = dev->ib_dev;

	if (!xd->nents || !xd->mapped)
		return;

	/* Assume scatterlist is terminated properly */

	ib_dma_unmap_sg(ib_dev, xd->sgt.sgl, xd->sgt.nents, DMA_TO_DEVICE);

	/* xio_prep_rdma_op calls sg_mark_end need to undo  */
	if (xd->last_sg) {
		sg_unmark_end(xd->last_sg);
		xd->last_sg = NULL;
		xd->sgt.nents = xd->sgt.orig_nents;
	}

	xd->mapped = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_map_rxmad_work_req						     */
/*---------------------------------------------------------------------------*/
int xio_map_rxmad_work_req(struct xio_device *dev, struct xio_work_req *xd)
{
	struct ib_device *ib_dev = dev->ib_dev;
	u32 lkey = dev->mr->lkey;
	struct sg_table *sgt = &xd->sgt;
	struct scatterlist *sg;
	int nents;
	int i;

	if (!xd->nents)
		return -1;

	/* Assume scatterlist is terminated properly */

	nents = ib_dma_map_sg(ib_dev, sgt->sgl, sgt->nents, DMA_FROM_DEVICE);
	if (!nents) {
		if (xd->last_sg) {
			sg_unmark_end(xd->last_sg);
			xd->last_sg = NULL;
			xd->sgt.nents = xd->sgt.orig_nents;
		}
		xd->mapped = 0;
		return -1;
	}

	sg = sgt->sgl;
	for (i = 0; i < nents; i++) {
		xd->sge[i].addr   = ib_sg_dma_address(ib_dev, sg);
		xd->sge[i].length = ib_sg_dma_len(ib_dev, sg);
		xd->sge[i].lkey	= lkey;
		sg = sg_next(sg);
	}

	xd->mapped = nents;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_map_txmad_work_req						     */
/*---------------------------------------------------------------------------*/
int xio_map_txmad_work_req(struct xio_device *dev, struct xio_work_req *xd)
{
	struct ib_device *ib_dev = dev->ib_dev;
	u32 lkey = dev->mr->lkey;
	struct sg_table *sgt = &xd->sgt;
	struct scatterlist *sg;
	int nents;
	int i;

	if (!xd->nents)
		return -1;

	sg = sgt->sgl;

	nents = ib_dma_map_sg(ib_dev, sgt->sgl, sgt->nents, DMA_TO_DEVICE);
	if (!nents) {
		if (xd->last_sg) {
			sg_unmark_end(xd->last_sg);
			xd->last_sg = NULL;
			sgt->nents = sgt->orig_nents;
		}
		xd->mapped = 0;
		return -1;
	}

	for (i = 0; i < nents; i++) {
		xd->sge[i].addr   = ib_sg_dma_address(ib_dev, sg);
		xd->sge[i].length = ib_sg_dma_len(ib_dev, sg);
		xd->sge[i].lkey	= lkey;
		sg = sg_next(sg);
	}
	xd->mapped = nents;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_remap_work_req							     */
/*---------------------------------------------------------------------------*/
int xio_remap_work_req(struct xio_device *odev, struct xio_device *ndev,
		       struct xio_work_req *xd,
		       enum dma_data_direction direction)
{
	struct ib_device *ib_odev = odev->ib_dev;
	struct ib_device *ib_ndev = ndev->ib_dev;
	u32 lkey =  ndev->mr->lkey;
	struct sg_table *sgt = &xd->sgt;
	struct scatterlist *sg;
	int nents;
	int i;

	if (!xd->nents || !xd->mapped)
		return -1;

	/* Assume scatterlist is terminated properly */

	if ((direction == DMA_TO_DEVICE) &&
	    (xd->send_wr.send_flags & IB_SEND_INLINE)) {
		/* Just update lkey */
		for (i = 0; i < xd->nents; i++)
			xd->sge[i].lkey	= lkey;
		return 0;
	}

	ib_dma_unmap_sg(ib_odev, sgt->sgl, sgt->nents, direction);
	nents = ib_dma_map_sg(ib_ndev, sgt->sgl, sgt->nents, direction);
	if (!nents) {
		if (xd->last_sg) {
			/* rdmad */
			sg_unmark_end(xd->last_sg);
			xd->last_sg = NULL;
			sgt->nents = sgt->orig_nents;
		} else {
			/* Disconnect header from data if any*/
			if (direction == DMA_TO_DEVICE &&
			    sgt->orig_nents > sgt->nents) {
				sg_mark_end(sgt->sgl);
				sgt->nents = sgt->orig_nents;
			}
		}
		xd->mapped = 0;
		return -1;
	}

	sg = sgt->sgl;
	for (i = 0; i < nents; i++) {
		xd->sge[i].addr   = ib_sg_dma_address(ib_ndev, sg);
		xd->sge[i].length = ib_sg_dma_len(ib_ndev, sg);
		xd->sge[i].lkey	= lkey;
		sg = sg_next(sg);
	}
	xd->mapped = nents;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_reset_desc							     */
/*---------------------------------------------------------------------------*/
void xio_reset_desc(struct xio_mem_desc *desc)
{
	memset(&desc->sgt, 0, sizeof(desc->sgt));
}

/*---------------------------------------------------------------------------*/
/* xio_unmap_desc							     */
/*---------------------------------------------------------------------------*/
void xio_unmap_desc(struct xio_rdma_transport *rdma_hndl,
		    struct xio_mem_desc *desc,
		    enum dma_data_direction direction)
{
	struct xio_device *dev = rdma_hndl->dev;
	struct ib_device *ib_dev = dev->ib_dev;

	if (!desc->nents || !desc->mapped)
		return;

	/* fast unregistration routine may do nothing but it is always exists */
	dev->fastreg.unreg_rdma_mem(rdma_hndl, desc, direction);

	/* Assume scatterlist is terminated properly */

	ib_dma_unmap_sg(ib_dev, desc->sgt.sgl, desc->sgt.nents, direction);

	desc->mapped = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_map_desc								     */
/*---------------------------------------------------------------------------*/
int xio_map_desc(struct xio_rdma_transport *rdma_hndl,
		 struct xio_mem_desc *desc,
		 enum dma_data_direction direction,
		 unsigned int *sqe_used)
{
	struct xio_device *dev = rdma_hndl->dev;
	struct ib_device *ib_dev = dev->ib_dev;
	int nents;

	if (!desc->nents)
		return -1;

	/* Assume scatterlist is terminated properly */

	nents = ib_dma_map_sg(ib_dev, desc->sgt.sgl, desc->sgt.nents,
			      direction);
	if (!nents) {
		memset(&desc->sgt, 0, sizeof(desc->sgt));
		desc->mapped = 0;
		return -1;
	}
	desc->mapped = nents;

	/* fast registration routine may do nothing but it is always exists */
	if (dev->fastreg.reg_rdma_mem(rdma_hndl, desc, direction, sqe_used)) {
		ib_dma_unmap_sg(ib_dev, desc->sgt.sgl, desc->sgt.nents,
				direction);
		memset(&desc->sgt, 0, sizeof(desc->sgt));
		desc->mapped = 0;
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_remap_desc							     */
/*---------------------------------------------------------------------------*/
int xio_remap_desc(struct xio_rdma_transport *rdma_ohndl,
		   struct xio_rdma_transport *rdma_nhndl,
		   struct xio_mem_desc *desc,
		   enum dma_data_direction direction,
		   unsigned int *sqe_used)
{
	struct xio_device *dev;
	struct ib_device *ib_dev;
	int nents;

	if (!desc->nents || !desc->mapped)
		return -1;

	dev = rdma_ohndl->dev;
	ib_dev = dev->ib_dev;
	/* fast unregistration routine may do nothing but it is
	 * always exists */
	dev->fastreg.unreg_rdma_mem(rdma_ohndl, desc, direction);

	/* Assume scatterlist is terminated properly */
	ib_dma_unmap_sg(ib_dev, desc->sgt.sgl, desc->sgt.nents, direction);

	dev = rdma_nhndl->dev;
	ib_dev = dev->ib_dev;
	nents = ib_dma_map_sg(ib_dev, desc->sgt.sgl, desc->sgt.nents,
			      direction);
	if (!nents) {
		memset(&desc->sgt, 0, sizeof(desc->sgt));
		desc->mapped = 0;
		return -1;
	}

	/* fast registration routine may do nothing but it is always exists */
	if (dev->fastreg.reg_rdma_mem(rdma_nhndl, desc, direction, sqe_used)) {
		ib_dma_unmap_sg(ib_dev, desc->sgt.sgl, desc->sgt.nents,
				direction);
		memset(&desc->sgt, 0, sizeof(desc->sgt));
		desc->mapped = 0;
		return -1;
	}

	return 0;
}

void xio_free_dummy_pool(struct xio_rdma_transport *rdma_hndl)
{
}

int xio_create_dummy_pool(struct xio_rdma_transport *rdma_hndl)
{
	return 0;
}

void xio_unreg_mem_dummy(struct xio_rdma_transport *rdma_hndl,
			 struct xio_mem_desc *desc,
			 enum dma_data_direction cmd_dir)
{
}

int xio_reg_rdma_mem_dummy(struct xio_rdma_transport *rdma_hndl,
			   struct xio_mem_desc *desc,
			   enum dma_data_direction cmd_dir,
			   unsigned int *sqe_used)
{
	desc->mem_reg.mem_h = NULL;

	return 0;
}

/**
 * xio_sg_to_page_vec - Translates scatterlist entries to physical addresses
 * and returns the length of resulting physical address array (may be less than
 * the original due to possible compaction).
 *
 * we build a "page vec" under the assumption that the SG meets the RDMA
 * alignment requirements. Other then the first and last SG elements, all
 * the "internal" elements can be compacted into a list whose elements are
 * dma addresses of physical pages. The code supports also the weird case
 * where --few fragments of the same page-- are present in the SG as
 * consecutive elements. Also, it handles one entry SG.
 */

static int xio_sg_to_page_vec(struct xio_mem_desc *mdesc,
			      struct ib_device *ibdev,
			      struct ib_fast_reg_page_list *data_frpl,
			      int *offset, int *data_size)
{
	struct scatterlist *sg, *sgl = mdesc->sgt.sgl;
	u64 start_addr, end_addr, page, chunk_start = 0;
	unsigned long total_sz = 0;
	unsigned int dma_len;
	int i, new_chunk, cur_page, last_ent = mdesc->nents - 1;
	u64 *pages = data_frpl->page_list;

	/* compute the offset of first element */
	*offset = (u64)sgl[0].offset & ~PAGE_MASK;

	new_chunk = 1;
	cur_page  = 0;
	for_each_sg(sgl, sg, mdesc->nents, i) {
		start_addr = ib_sg_dma_address(ibdev, sg);
		if (new_chunk)
			chunk_start = start_addr;
		dma_len = ib_sg_dma_len(ibdev, sg);
		end_addr = start_addr + dma_len;
		total_sz += dma_len;

		/* collect page fragments until aligned or end of SG list */
		if (!IS_PAGE_ALIGNED(end_addr) && i < last_ent) {
			new_chunk = 0;
			continue;
		}
		new_chunk = 1;

		/* address of the first page in the contiguous chunk;
		   masking relevant for the very first SG entry,
		   which might be unaligned */
		page = chunk_start & PAGE_MASK;
		do {
			if (cur_page >= data_frpl->max_page_list_len) {
				ERROR_LOG("Overflowing page list " \
					  "array. cur_page = %d, " \
					  "max = %u, tot sz=%lu\n",
					  cur_page,
					  data_frpl->max_page_list_len,
					  total_sz);
				break;
			}
			pages[cur_page++] = page;
			page += PAGE_SIZE;
		} while (page < end_addr);
	}

	*data_size = total_sz;
	TRACE_LOG("page_vec->data_size:%d cur_page %d\n",
		  *data_size, cur_page);
	return cur_page;
}

/**
 * xio_data_buf_aligned_len - Tries to determine the maximal correctly aligned
 * for RDMA sub-list of a scatter-gather list of memory buffers, and  returns
 * the number of entries which are aligned correctly. Supports the case where
 * consecutive SG elements are actually fragments of the same physcial page.
 */
static int xio_data_buf_aligned_len(struct xio_mem_desc *mdesc,
				    struct ib_device *ibdev)
{
	struct scatterlist *sgl, *sg, *next_sg = NULL;
	u64 start_addr, end_addr;
	int i, ret_len, start_check = 0;

	if (mdesc->nents == 1)
		return 1;

	sgl = mdesc->sgt.sgl;
	start_addr  = ib_sg_dma_address(ibdev, sgl);

	for_each_sg(sgl, sg, mdesc->nents, i) {
		if (start_check && !IS_PAGE_ALIGNED(start_addr))
			break;

		next_sg = sg_next(sg);
		if (!next_sg)
			break;

		end_addr   = start_addr + ib_sg_dma_len(ibdev, sg);
		start_addr = ib_sg_dma_address(ibdev, next_sg);

		if (end_addr == start_addr) {
			start_check = 0;
			continue;
		} else {
			start_check = 1;
		}

		if (!IS_PAGE_ALIGNED(end_addr))
			break;
	}
	ret_len = (next_sg) ? i : i+1;
	TRACE_LOG("Found %d aligned entries out of %d in mdesc:%p\n",
		  ret_len, mdesc->nents, mdesc);
	return ret_len;
}

/**
 * xio_free_frwr_pool - releases the pool of fast_reg descriptors
 */
void xio_free_frwr_pool(struct xio_rdma_transport *rdma_hndl)
{
	struct xio_frwr *frwr = &rdma_hndl->fastreg.frwr;
	struct fast_reg_descriptor *fdesc;
	struct llist_node *node;
	int i = 0;

	DEBUG_LOG("freeing rdma_hndl %p FRWR pool\n", rdma_hndl);

	node = llist_del_all(&frwr->pool);
	while (node) {
		fdesc = llist_entry(node, struct fast_reg_descriptor,
				    llist_entry);
		node = llist_next(node);
		ib_free_fast_reg_page_list(fdesc->data_frpl);
		ib_dereg_mr(fdesc->data_mr);
		kfree(fdesc);
		i++;
	}

	node = llist_del_all(&frwr->pool_ret);
	while (node) {
		fdesc = llist_entry(node, struct fast_reg_descriptor,
				    llist_entry);
		node = llist_next(node);
		ib_free_fast_reg_page_list(fdesc->data_frpl);
		ib_dereg_mr(fdesc->data_mr);
		kfree(fdesc);
		i++;
	}

	if (i < frwr->pool_size)
		WARN_LOG("pool still has %d regions registered\n",
			 frwr->pool_size - i);
}

/**
 * xio_create_frwr_pool - Creates pool of fast_reg descriptors
 * for fast registration work requests.
 * returns 0 on success, or errno code on failure
 */
int xio_create_frwr_pool(struct xio_rdma_transport *rdma_hndl)
{
	struct xio_device *dev = rdma_hndl->dev;
	struct xio_frwr *frwr = &rdma_hndl->fastreg.frwr;
	struct fast_reg_descriptor *desc;
	int i, ret;

	init_llist_head(&frwr->pool);
	frwr->pool_size = 0;
	/* There can be only max_tx_ready_tasks_num simultaneously inflight
	 * request tasks at any given time, each of which may need both RDMA
	 * read and write (both data form server to client may be big)
	 */
	for (i = 0; i < rdma_hndl->max_tx_ready_tasks_num * 2; i++) {
		desc = kzalloc(sizeof(*desc), GFP_KERNEL);
		if (!desc) {
			ERROR_LOG("Failed to allocate a new fast_reg " \
				  "descriptor\n");
			ret = -ENOMEM;
			goto err;
		}

		desc->data_frpl = ib_alloc_fast_reg_page_list(dev->ib_dev,
							      XIO_MAX_IOV + 1);
		if (IS_ERR(desc->data_frpl)) {
			ret = PTR_ERR(desc->data_frpl);
			ERROR_LOG("Failed to allocate ib_fast_reg_page_list " \
				  "err=%d\n", ret);
			kfree(desc);
			goto err;
		}
		desc->data_frpl->max_page_list_len = XIO_MAX_IOV + 1;

		desc->data_mr = ib_alloc_fast_reg_mr(dev->pd, XIO_MAX_IOV + 1);
		if (IS_ERR(desc->data_mr)) {
			ret = PTR_ERR(desc->data_mr);
			ERROR_LOG("Failed to allocate ib_fast_reg_mr err=%d\n",
				  ret);
			ib_free_fast_reg_page_list(desc->data_frpl);
			kfree(desc);
			goto err;
		}
		desc->valid = true;
		llist_add(&desc->llist_entry, &frwr->pool_ret);
		frwr->pool_size++;
	}

	return 0;
err:
	xio_free_frwr_pool(rdma_hndl);
	return ret;
}

void xio_unreg_mem_frwr(struct xio_rdma_transport *rdma_hndl,
			struct xio_mem_desc *mdesc,
			enum dma_data_direction cmd_dir)
{
	struct xio_mem_reg *reg = &mdesc->mem_reg;
	struct fast_reg_descriptor *fdesc = reg->mem_h;

	if (!reg->mem_h)
		return;

	reg->mem_h = NULL;
	llist_add(&fdesc->llist_entry, &rdma_hndl->fastreg.frwr.pool_ret);
}

static int xio_fast_reg_mr(struct fast_reg_descriptor *fdesc,
			   struct xio_rdma_transport *rdma_hndl,
			   struct xio_mem_reg *reg,
			   u32 offset, unsigned int data_size,
			   unsigned int page_list_len,
			   unsigned int *sqe_used)
{
	struct ib_send_wr fastreg_wr, inv_wr;
	struct ib_send_wr *bad_wr, *wr = NULL;
	u8 key;
	int ret;

	if (!fdesc->valid) {
		/* don't send signaled */
		memset(&inv_wr, 0, sizeof(inv_wr));
		inv_wr.opcode = IB_WR_LOCAL_INV;
		inv_wr.wr_id = uint64_from_ptr(&rdma_hndl->frwr_task);
		inv_wr.ex.invalidate_rkey = fdesc->data_mr->rkey;
		/* Bump the key */
		key = (u8)(fdesc->data_mr->rkey & 0x000000FF);
		ib_update_fast_reg_key(fdesc->data_mr, ++key);
		/* send two work requests */
		wr = &inv_wr;
		wr->next = &fastreg_wr;
		rdma_hndl->sqe_avail--;
		(*sqe_used)++;
	} else {
		wr = &fastreg_wr;
	}
	rdma_hndl->sqe_avail--;
	(*sqe_used)++;
	/* Prepare FASTREG WR */
	memset(&fastreg_wr, 0, sizeof(fastreg_wr));
	fastreg_wr.opcode = IB_WR_FAST_REG_MR;
	fastreg_wr.wr_id = uint64_from_ptr(&rdma_hndl->frwr_task);
	fastreg_wr.wr.fast_reg.iova_start =
				fdesc->data_frpl->page_list[0] + offset;
	fastreg_wr.wr.fast_reg.page_list = fdesc->data_frpl;
	fastreg_wr.wr.fast_reg.page_list_len = page_list_len;
	fastreg_wr.wr.fast_reg.page_shift = PAGE_SHIFT;
	fastreg_wr.wr.fast_reg.length = data_size;
	fastreg_wr.wr.fast_reg.rkey = fdesc->data_mr->rkey;
	fastreg_wr.wr.fast_reg.access_flags = (IB_ACCESS_LOCAL_WRITE  |
					       IB_ACCESS_REMOTE_WRITE |
					       IB_ACCESS_REMOTE_READ);

	ret = ib_post_send(rdma_hndl->qp, wr, &bad_wr);
	if (unlikely(ret)) {
		ERROR_LOG("fast registration failed, ret:%d\n", ret);
		return ret;
	}

	fdesc->valid = false;

	reg->mem_h = (void *)fdesc;
	reg->lkey  = fdesc->data_mr->lkey;
	reg->rkey  = fdesc->data_mr->rkey;
	reg->va    = fdesc->data_frpl->page_list[0] + offset;
	reg->len   = data_size;

	return ret;
}

static struct fast_reg_descriptor *get_fdesc(
				struct xio_rdma_transport *rdma_hndl)
{
	struct llist_node *node, *nnode;
	struct fast_reg_descriptor *fdesc;

	node = llist_del_first(&rdma_hndl->fastreg.frwr.pool);
	if (node)
		return llist_entry(node, struct fast_reg_descriptor,
				   llist_entry);

	node = llist_del_all(&rdma_hndl->fastreg.frwr.pool_ret);
	if (!node)
		return NULL;

	nnode = llist_reverse_order(node);
	fdesc = llist_entry(nnode, struct fast_reg_descriptor, llist_entry);
	nnode = llist_next(nnode);
	fdesc->llist_entry.next = NULL;

	if (nnode)
		llist_add_batch(nnode, node, &rdma_hndl->fastreg.frwr.pool);

	return fdesc;
}

/**
 * xio_reg_rdma_mem_frwr - Registers memory intended for RDMA,
 * using Fast Registration WR (if possible) obtaining rkey and va
 *
 * returns 0 on success, errno code on failure
 */
static int xio_reg_rdma_mem_frwr(struct xio_rdma_transport *rdma_hndl,
				 struct xio_mem_desc *mdesc,
				 enum dma_data_direction cmd_dir,
				 unsigned int *sqe_used)
{
	struct xio_device *dev = rdma_hndl->dev;
	struct ib_device *ibdev = dev->ib_dev;
	struct fast_reg_descriptor *fdesc;
	unsigned int data_size, page_list_len;
	int err, aligned_len;
	u32 offset;

	/* if there a single dma entry, fail to dummy */
	if (mdesc->nents == 1)
		return xio_reg_rdma_mem_dummy(rdma_hndl, mdesc,
					      cmd_dir, sqe_used);

	/* if not enough sqe for post_send */
	if (rdma_hndl->sqe_avail < 2) {
		ERROR_LOG("no rdma_hndl->sqe_avail=%d\n", rdma_hndl->sqe_avail);
		return xio_reg_rdma_mem_dummy(rdma_hndl, mdesc,
					      cmd_dir, sqe_used);
	}

	aligned_len = xio_data_buf_aligned_len(mdesc, ibdev);
	if (aligned_len != mdesc->nents)
		/* fail to dummy, i.e. will use multiple RDMA  */
		return xio_reg_rdma_mem_dummy(rdma_hndl, mdesc,
					      cmd_dir, sqe_used);

	fdesc = get_fdesc(rdma_hndl);
	if (!fdesc) {
		/* We may have temporary pressure on pool */
		DEBUG_LOG("pool is empty!\n");
		/* fail to dummy, i.e. will use multiple RDMA  */
		return xio_reg_rdma_mem_dummy(rdma_hndl, mdesc,
					      cmd_dir, sqe_used);
	}

	page_list_len = xio_sg_to_page_vec(mdesc, dev->ib_dev,
					   fdesc->data_frpl,
					   &offset, &data_size);

	if (unlikely(page_list_len * PAGE_SIZE < data_size)) {
		ERROR_LOG("fast reg page_list too short to hold this SG\n");
		err = -EINVAL;
		goto err_reg;
	}

	err = xio_fast_reg_mr(fdesc, rdma_hndl, &mdesc->mem_reg,
			      offset, data_size, page_list_len, sqe_used);
	if (err)
		goto err_reg;

	return 0;
err_reg:
	llist_add(&fdesc->llist_entry, &rdma_hndl->fastreg.frwr.pool);
	return err;
}

int xio_fast_reg_init(enum xio_fast_reg reg, struct xio_fastreg_ops *ops)
{
	switch (reg) {
	case XIO_FAST_MEM_NONE:
		ops->alloc_rdma_reg_res = xio_create_dummy_pool;
		ops->free_rdma_reg_res = xio_free_dummy_pool;
		ops->reg_rdma_mem = xio_reg_rdma_mem_dummy;
		ops->unreg_rdma_mem = xio_unreg_mem_dummy;
		WARN_LOG("Fast registration not supported\n");
		return 0;
	case XIO_FAST_MEM_FRWR:
		ops->alloc_rdma_reg_res = xio_create_frwr_pool;
		ops->free_rdma_reg_res = xio_free_frwr_pool;
		ops->reg_rdma_mem = xio_reg_rdma_mem_frwr;
		ops->unreg_rdma_mem = xio_unreg_mem_frwr;
		DEBUG_LOG("FRWR supported, using FRWR for registration\n");
		return 0;
	case XIO_FAST_MEM_FMR:
		ERROR_LOG("FMRs not yet implemented\n");
		return -1;
	default:
		ERROR_LOG("Unknown registration type\n");
		return -1;
	}
}

/* drivers/block/nvme.c nvme_map_bio */
#define XIO_VEC_NOT_VIRT_MERGEABLE(vec1, vec2)   ((vec2)->bv_offset || \
		(((vec1)->bv_offset + (vec1)->bv_len) % PAGE_SIZE))

void xio_copy_vmsg_to_buffer(struct xio_vmsg *vmsg,
			     struct xio_mp_mem *mp)
{
	void *ptr = mp->addr;
	int i;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sge;

	sgtbl		= xio_sg_table_get(vmsg);
	sgtbl_ops	= xio_sg_table_ops_get(vmsg->sgl_type);

	sge = sge_first(sgtbl_ops, sgtbl);
	for (i = 0; i < tbl_nents(sgtbl_ops, sgtbl) - 1; i++) {
		memmove(ptr, sge_addr(sgtbl_ops, sge),
			sge_length(sgtbl_ops, sge));
		ptr += sge_length(sgtbl_ops, sge);
		sge = sge_next(sgtbl_ops, sgtbl, sge);
	}
}

void xio_reinit_header(struct xio_rdma_task *rdma_task, size_t len)
{
	sg_set_page(rdma_task->txd.sgt.sgl, virt_to_page(rdma_task->buf),
		    len, offset_in_page(rdma_task->buf));
}

int xio_vmsg_to_tx_sgt(struct xio_vmsg *vmsg, struct sg_table *sgt, int *nents)
{
	switch (vmsg->sgl_type) {
	case XIO_SGL_TYPE_IOV:
	case XIO_SGL_TYPE_IOV_PTR:
		WARN_LOG("wrong vmsg type %d\n", vmsg->sgl_type);
		if (unlikely(vmsg->data_tbl.nents)) {
			*nents = 0;
			return -EINVAL;
		}
		goto done;
	case XIO_SGL_TYPE_SCATTERLIST:
		break;
	default:
		WARN_LOG("wrong vmsg type %d\n", vmsg->sgl_type);
		*nents = 0;
		return -EINVAL;
	}

	/* TODO: validate vmsg sgl */
	if (unlikely(vmsg->data_tbl.nents > XIO_MAX_IOV)) {
		WARN_LOG("scatterlist too long %u\n", vmsg->data_tbl.nents);
		*nents = 0;
		return -EINVAL;
	}

#ifdef CONFIG_DEBUG_SG
	BUG_ON(vmsg->data_tbl.sgl->sg_magic != SG_MAGIC);
#endif

	/* Only the header will be sent  */
	if (vmsg->data_tbl.nents) {
		/* txd has one more entry we need to chain */
		sg_unmark_end(sgt->sgl);
		/* Assume scatterlist is terminated properly */
		sg_chain(sgt->sgl, 2, vmsg->data_tbl.sgl);
		sgt->nents = 1 + vmsg->data_tbl.nents;
	}

done:
	*nents = sgt->nents;

	return 0;
}

int xio_vmsg_to_sgt(struct xio_vmsg *vmsg, struct sg_table *sgt, int *nents)
{
	switch (vmsg->sgl_type) {
	case XIO_SGL_TYPE_IOV:
	case XIO_SGL_TYPE_IOV_PTR:
		WARN_LOG("wrong vmsg type %d\n", vmsg->sgl_type);
		if (unlikely(vmsg->data_tbl.nents)) {
			*nents = 0;
			return -EINVAL;
		}
		memset(sgt, 0, sizeof(*sgt));
		goto done;
	case XIO_SGL_TYPE_SCATTERLIST:
		break;
	default:
		WARN_LOG("wrong vmsg type %d\n", vmsg->sgl_type);
		*nents = 0;
		return -EINVAL;
	}

	/* TODO: validate vmsg sgl */
	if (unlikely(vmsg->data_tbl.nents > XIO_MAX_IOV)) {
		WARN_LOG("scatterlist too long %u\n", vmsg->data_tbl.nents);
		*nents = 0;
		return -EINVAL;
	}

	if (vmsg->data_tbl.nents)
		memcpy(sgt, &vmsg->data_tbl, sizeof(*sgt));
	else
		memset(sgt, 0, sizeof(*sgt));

done:
	*nents = sgt->nents;

	return 0;
}
