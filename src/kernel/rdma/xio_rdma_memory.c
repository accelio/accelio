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
#include "xio_observer.h"
#include "xio_common.h"
#include "xio_context.h"
#include "xio_task.h"
#include "xio_transport.h"
#include "xio_conn.h"
#include "xio_protocol.h"
#include "xio_mem.h"
#include "xio_rdma_mempool.h"
#include "xio_rdma_transport.h"

#define XIO_KMALLOC_THRESHOLD 0x20000 /* 128K - kmalloc limit */

#ifndef IS_PAGE_ALIGNED
#define IS_PAGE_ALIGNED(ptr)	(((PAGE_SIZE-1) & (uintptr_t)(ptr)) == 0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
/**
 * sg_unmark_end - Undo setting the end of the scatterlist
 * @sg:          SG entryScatterlist
 *
 * Description:
 *   Removes the termination marker from the given entry of the scatterlist.
 *
**/
static inline void sg_unmark_end(struct scatterlist *sg)
{
#ifdef CONFIG_DEBUG_SG
	BUG_ON(sg->sg_magic != SG_MAGIC);
#endif
	sg->page_link &= ~0x02;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
/**
 * llist_reverse_order - reverse order of a llist chain
 * @head:       first item of the list to be reversed
 *
 * Reverse the order of a chain of llist entries and return the
 * new first entry.
 */
static struct llist_node *llist_reverse_order(struct llist_node *head)
{
	struct llist_node *new_head = NULL;

	while (head) {
		struct llist_node *tmp = head;
		head = head->next;
		tmp->next = new_head;
		new_head = tmp;
	}

	return new_head;
}
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
/* xio_unmap_desc							     */
/*---------------------------------------------------------------------------*/

void xio_unmap_desc(struct xio_rdma_transport *rdma_hndl,
		    struct xio_rdma_mem_desc *desc,
		    enum dma_data_direction direction)
{
	struct xio_device *dev = rdma_hndl->dev;
	struct ib_device *ib_dev = dev->ib_dev;

	if (!desc->nents)
		return;

	/* fast unregistration routine may do nothing but it is always exists */
	dev->fastreg.unreg_rdma_mem(rdma_hndl, desc, direction);

	ib_dma_unmap_sg(ib_dev, desc->sgl, desc->mapped, direction);
	desc->mapped = 0;

	/* marked in map */
	sg_unmark_end(&desc->sgl[desc->nents - 1]);
}

/*---------------------------------------------------------------------------*/
/* xio_unmap_work_req							     */
/*---------------------------------------------------------------------------*/

void xio_unmap_work_req(struct ib_device *ib_dev, struct xio_work_req *xd,
			enum dma_data_direction direction)
{
	if (!xd->nents)
		return;

	ib_dma_unmap_sg(ib_dev, xd->sgl, xd->mapped, direction);
	xd->mapped = 0;

	/* marked in map */
	sg_unmark_end(&xd->sgl[xd->nents - 1]);
}

/*---------------------------------------------------------------------------*/
/* xio_map_work_req							     */
/*---------------------------------------------------------------------------*/
int xio_map_work_req(struct ib_device *ib_dev, struct xio_work_req *xd,
		     enum dma_data_direction direction)
{
	int nents;
	int i;

	if (!xd->nents)
		return -1;

	/* cleared in unmap */
	sg_mark_end(&xd->sgl[xd->nents - 1]);
	nents = ib_dma_map_sg(ib_dev, xd->sgl, xd->nents, direction);
	if (!nents) {
		sg_unmark_end(&xd->sgl[xd->nents - 1]);
		xd->mapped = 0;
		return -1;
	}
	for (i = 0; i < nents; i++) {
		xd->sge[i].addr   = ib_sg_dma_address(ib_dev, &xd->sgl[i]);
		xd->sge[i].length = ib_sg_dma_len(ib_dev, &xd->sgl[i]);
	}
	xd->mapped = nents;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_map_desc							     */
/*---------------------------------------------------------------------------*/
int xio_map_desc(struct xio_rdma_transport *rdma_hndl,
		 struct xio_rdma_mem_desc *desc,
		 enum dma_data_direction direction)
{
	struct xio_device *dev = rdma_hndl->dev;
	struct ib_device *ib_dev = dev->ib_dev;
	int nents;

	if (!desc->nents)
		return -1;

	/* cleared in unmap */
	sg_mark_end(&desc->sgl[desc->nents - 1]);
	nents = ib_dma_map_sg(ib_dev, desc->sgl, desc->nents, direction);
	if (!nents) {
		sg_unmark_end(&desc->sgl[desc->nents - 1]);
		desc->mapped = 0;
		return -1;
	}
	desc->mapped = nents;

	/* fast registration routine may do nothing but it is always exists */
	return dev->fastreg.reg_rdma_mem(rdma_hndl, desc, direction);
}

void xio_free_dummy_pool(struct xio_rdma_transport *rdma_hndl)
{
	return;
}

int xio_create_dummy_pool(struct xio_rdma_transport *rdma_hndl)
{
	return 0;
}

void xio_unreg_mem_dummy(struct xio_rdma_transport *rdma_hndl,
			 struct xio_rdma_mem_desc *desc,
			 enum dma_data_direction cmd_dir)
{
	return;
}

int xio_reg_rdma_mem_dummy(struct xio_rdma_transport *rdma_hndl,
			   struct xio_rdma_mem_desc *desc,
			   enum dma_data_direction cmd_dir)
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

static int xio_sg_to_page_vec(struct xio_rdma_mem_desc *mdesc,
                              struct ib_device *ibdev, u64 *pages,
                              int *offset, int *data_size)
{
	struct scatterlist *sg, *sgl = mdesc->sgl;
	u64 start_addr, end_addr, page, chunk_start = 0;
	unsigned long total_sz = 0;
	unsigned int dma_len;
	int i, new_chunk, cur_page, last_ent = mdesc->nents - 1;

	/* compute the offset of first element */
	*offset = (u64) sgl[0].offset & ~PAGE_MASK;

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
			pages[cur_page++] = page;
			page += PAGE_SIZE;
		} while (page < end_addr);
	}

	*data_size = total_sz;
	DEBUG_LOG("page_vec->data_size:%d cur_page %d\n",
		  *data_size, cur_page);
	return cur_page;
}

/**
 * xio_data_buf_aligned_len - Tries to determine the maximal correctly aligned
 * for RDMA sub-list of a scatter-gather list of memory buffers, and  returns
 * the number of entries which are aligned correctly. Supports the case where
 * consecutive SG elements are actually fragments of the same physcial page.
 */
static int xio_data_buf_aligned_len(struct xio_rdma_mem_desc *mdesc,
		                    struct ib_device *ibdev)
{
	struct scatterlist *sgl, *sg, *next_sg = NULL;
	u64 start_addr, end_addr;
	int i, ret_len, start_check = 0;

	if (mdesc->nents == 1)
		return 1;

	sgl = mdesc->sgl;
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
	DEBUG_LOG("Found %d aligned entries out of %d in mdesc:%p\n",
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

	INFO_LOG("freeing rdma_hndl %p FRWR pool\n", rdma_hndl);

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
	/* a task can many need both RDMA read and write */
	for (i = 0; i < rdma_hndl->num_tasks * 2; i++) {
		desc = kzalloc(sizeof(*desc), GFP_KERNEL);
		if (!desc) {
			ERROR_LOG("Failed to allocate a new fast_reg descriptor\n");
			ret = -ENOMEM;
			goto err;
		}

		desc->data_frpl = ib_alloc_fast_reg_page_list(dev->ib_dev,
							      XIO_MAX_IOV + 1);
		if (IS_ERR(desc->data_frpl)) {
			ret = PTR_ERR(desc->data_frpl);
			ERROR_LOG("Failed to allocate ib_fast_reg_page_list err=%d\n", ret);
			goto err;
		}

		desc->data_mr = ib_alloc_fast_reg_mr(dev->pd, XIO_MAX_IOV + 1);
		if (IS_ERR(desc->data_mr)) {
			ret = PTR_ERR(desc->data_mr);
			ERROR_LOG("Failed to allocate ib_fast_reg_mr err=%d\n", ret);
			ib_free_fast_reg_page_list(desc->data_frpl);
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
			struct xio_rdma_mem_desc *mdesc,
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
			   unsigned int page_list_len)
{
	struct ib_send_wr fastreg_wr, inv_wr;
	struct ib_send_wr *bad_wr, *wr = NULL;
	u8 key;
	int ret;

	if (!fdesc->valid) {
		/* don't send signaled */
		memset(&inv_wr, 0, sizeof(inv_wr));
		inv_wr.opcode = IB_WR_LOCAL_INV;
		inv_wr.wr_id = XIO_FRWR_LI_WRID;
		inv_wr.ex.invalidate_rkey = fdesc->data_mr->rkey;
		/* Bump the key */
		key = (u8)(fdesc->data_mr->rkey & 0x000000FF);
		ib_update_fast_reg_key(fdesc->data_mr, ++key);
		/* send two work requests */
		wr = &inv_wr;
		wr->next = &fastreg_wr;
	} else {
		wr = &fastreg_wr;
	}

	/* Prepare FASTREG WR */
	memset(&fastreg_wr, 0, sizeof(fastreg_wr));
	fastreg_wr.opcode = IB_WR_FAST_REG_MR;
	fastreg_wr.wr_id = XIO_FRWR_LI_WRID;
	fastreg_wr.wr.fast_reg.iova_start = fdesc->data_frpl->page_list[0] + offset;
	fastreg_wr.wr.fast_reg.page_list = fdesc->data_frpl;
	fastreg_wr.wr.fast_reg.page_list_len = page_list_len;
	fastreg_wr.wr.fast_reg.page_shift = PAGE_SHIFT;
	fastreg_wr.wr.fast_reg.length = data_size;
	fastreg_wr.wr.fast_reg.rkey = fdesc->data_mr->rkey;
	fastreg_wr.wr.fast_reg.access_flags = (IB_ACCESS_LOCAL_WRITE  |
					       IB_ACCESS_REMOTE_WRITE |
					       IB_ACCESS_REMOTE_READ);

	ret = ib_post_send(rdma_hndl->qp, wr, &bad_wr);
	if (ret) {
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

static struct fast_reg_descriptor *get_fdesc(struct xio_rdma_transport *rdma_hndl)
{
	struct llist_node *node, *nnode;
	struct fast_reg_descriptor *fdesc;

	node = llist_del_first(&rdma_hndl->fastreg.frwr.pool);
	if (node)
		return llist_entry(node, struct fast_reg_descriptor, llist_entry);

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
int xio_reg_rdma_mem_frwr(struct xio_rdma_transport *rdma_hndl,
			  struct xio_rdma_mem_desc *mdesc,
			  enum dma_data_direction cmd_dir)
{
	struct xio_device *dev = rdma_hndl->dev;
	struct ib_device *ibdev = dev->ib_dev;
	struct fast_reg_descriptor *fdesc;
	unsigned int data_size, page_list_len;
	int err, aligned_len;
	u32 offset;

	/* if there a single dma entry, fail to dummy */
	if (mdesc->nents == 1)
		return xio_reg_rdma_mem_dummy(rdma_hndl, mdesc, cmd_dir);

	aligned_len = xio_data_buf_aligned_len(mdesc, ibdev);
	if (aligned_len != mdesc->nents)
		/* fail to dummy, i.e. will use multiple RDMA  */
		return xio_reg_rdma_mem_dummy(rdma_hndl, mdesc, cmd_dir);

	fdesc = get_fdesc(rdma_hndl);
	if (!fdesc) {
		ERROR_LOG("pool is empty!\n");
		err = -ENOMEM;
		goto err_reg;
	}

	page_list_len = xio_sg_to_page_vec(mdesc, dev->ib_dev,
					   fdesc->data_frpl->page_list,
					   &offset, &data_size);

	if (page_list_len * PAGE_SIZE < data_size) {
		ERROR_LOG("fast reg page_list too short to hold this SG\n");
		err = -EINVAL;
		goto err_reg;
	}

	err = xio_fast_reg_mr(fdesc, rdma_hndl, &mdesc->mem_reg,
			      offset, data_size, page_list_len);
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
		INFO_LOG("Fast registration not supported\n");
		return 0;
	case XIO_FAST_MEM_FRWR:
		ops->alloc_rdma_reg_res = xio_create_frwr_pool;
		ops->free_rdma_reg_res = xio_free_frwr_pool;
		ops->reg_rdma_mem = xio_reg_rdma_mem_frwr;
		ops->unreg_rdma_mem = xio_unreg_mem_frwr;
		INFO_LOG("FRWR supported, using FRWR for registration\n");
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
			     struct xio_rdma_mp_mem *mp)
{
	void *ptr = mp->addr;
	int i;

	for (i = 0; i < vmsg->data_iovlen - 1; i++) {
		memmove(ptr, vmsg->data_iov[i].iov_base,
			vmsg->data_iov[i].iov_len);
		ptr += vmsg->data_iov[i].iov_len;
	}
}

void xio_reinit_header(struct xio_rdma_task *rdma_task, size_t len)
{
	sg_set_page(rdma_task->txd.sgl, virt_to_page(rdma_task->buf),
		    len, offset_in_page(rdma_task->buf));
}

int xio_vmsg_to_sgl(struct xio_vmsg *vmsg, struct scatterlist *sgl, int *nents)
{
	struct xio_iovec_ex *iov, *niov;
	struct scatterlist *sg;
	void *start_addr, *end_addr;
	size_t total_len;
	int i;

	if (vmsg->data_iovlen > XIO_MAX_IOV) {
		WARN_LOG("IOV too long %zu\n", vmsg->data_iovlen);
		*nents = 0;
		return -EINVAL;
	}

	if (vmsg->data_iovlen == 0) {
		*nents = 0;
		return 0;
	}

	niov = &vmsg->data_iov[0];
	start_addr = niov->iov_base;
	total_len = niov->iov_len;
	sg = sgl;

	for (i = 0; i < vmsg->data_iovlen - 1; i++) {
		iov = niov;
		niov++;
		end_addr = iov->iov_base + iov->iov_len;

		/* Can iov and niov be merged ? */
		if (end_addr == niov->iov_base) {
			total_len += niov->iov_len;
			continue;
		}

		/* Not merge-able close current sg */
		sg_set_page(sg, virt_to_page(start_addr),
			    total_len, offset_in_page(start_addr));

		/* New segment starts here */
		start_addr = niov->iov_base;
		total_len = niov->iov_len;
		sg++;
	}

	/* close last segment (can be the first and last one) */
	sg_set_page(sg, virt_to_page(start_addr),
		    total_len, offset_in_page(start_addr));

	sg_mark_end(sg);

	sg++;

	*nents = sg - sgl;

	return 0;
}
