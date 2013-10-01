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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/scatterlist.h>

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

#define ISER_KMALLOC_THRESHOLD 0x20000 /* 128K - kmalloc limit */

/*---------------------------------------------------------------------------*/
/* xio_unmap_desc							     */
/*---------------------------------------------------------------------------*/

void xio_unmap_desc(ib_device *ib_dev, struct xio_rdma_mem_desc *desc,
			enum dma_data_direction direction)
{
	ib_dma_unmap_sg(ib_dev, desc->sgl, desc->mapped, direction);
	desc->mapped = 0;

	/* marked in map */
	sg_unmark_end(&desc->sgl[xd->nents]);
}

/*---------------------------------------------------------------------------*/
/* xio_unmap_work_req							     */
/*---------------------------------------------------------------------------*/

void xio_unmap_work_req(ib_device *ib_dev, struct xio_work_req *xd,
			enum dma_data_direction direction)
{
	ib_dma_unmap_sg(ib_dev, xd->sgl, xd->mapped, direction);
	xd->mapped = 0;

	/* marked in map */
	sg_unmark_end(&xd->sgl[xd->nents]);
}

/*---------------------------------------------------------------------------*/
/* xio_map_work_req							     */
/*---------------------------------------------------------------------------*/
int xio_map_work_req(ib_device *ib_dev, struct xio_work_req *xd,
		     enum dma_data_direction direction)
{
	struct scatterlist *sgl = xd->sgl;
	struct page *page,
	unsigned int len;
	unsigned int offset;
	int nents, i;


	/* cleared in unmap */
	sg_mark_end(&xd->sgl[xd->nents]);
	nents = ib_dma_map_sg(ib_dev, xd->sgl, xd->nents,
			      direction);
	if (!nents) {
		sg_unmark_end(&xd->sgl[xd->nents]);
		xd->mapped = 0;
		return -1;
	}
	xd->mapped = nents;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_map_desc							     */
/*---------------------------------------------------------------------------*/
int xio_map_desc(ib_device *ib_dev, struct xio_rdma_mem_desc *desc,
		 enum dma_data_direction direction)
{
	struct scatterlist *sgl = desc->sgl;
	struct page *page,
	unsigned int len;
	unsigned int offset;
	int nents, i;


	/* cleared in unmap */
	sg_mark_end(&desc->sgl[desc->nents]);
	nents = ib_dma_map_sg(ib_dev, desc->sgl, desc->nents,
			      direction);
	if (!nents) {
		sg_unmark_end(&desc->sgl[desc->nents]);
		desc->mapped = 0;
		return -1;
	}
	desc->mapped = nents;

	return 0;
}

#if 0

/**
 * iser_start_rdma_unaligned_sg
 */
static int iser_start_rdma_unaligned_sg(struct iscsi_iser_task *iser_task,
					enum iser_data_dir cmd_dir)
{
	int dma_nents;
	struct ib_device *dev;
	char *mem = NULL;
	struct iser_data_buf *data = &iser_task->data[cmd_dir];
	unsigned long  cmd_data_len = data->data_len;

	if (cmd_data_len > ISER_KMALLOC_THRESHOLD)
		mem = (void *)__get_free_pages(GFP_ATOMIC,
		      ilog2(roundup_pow_of_two(cmd_data_len)) - PAGE_SHIFT);
	else
		mem = kmalloc(cmd_data_len, GFP_ATOMIC);

	if (mem == NULL) {
		iser_err("Failed to allocate mem size %d %d for copying sglist\n",
			 data->size,(int)cmd_data_len);
		return -ENOMEM;
	}

	if (cmd_dir == ISER_DIR_OUT) {
		/* copy the unaligned sg the buffer which is used for RDMA */
		struct scatterlist *sgl = (struct scatterlist *)data->buf;
		struct scatterlist *sg;
		int i;
		char *p, *from;

		p = mem;
		for_each_sg(sgl, sg, data->size, i) {
			from = kmap_atomic(sg_page(sg));
			memcpy(p,
			       from + sg->offset,
			       sg->length);
			kunmap_atomic(from);
			p += sg->length;
		}
	}

	sg_init_one(&iser_task->data_copy[cmd_dir].sg_single, mem, cmd_data_len);
	iser_task->data_copy[cmd_dir].buf  =
		&iser_task->data_copy[cmd_dir].sg_single;
	iser_task->data_copy[cmd_dir].size = 1;

	iser_task->data_copy[cmd_dir].copy_buf  = mem;

	dev = iser_task->iser_conn->ib_conn->device->ib_device;
	dma_nents = ib_dma_map_sg(dev,
				  &iser_task->data_copy[cmd_dir].sg_single,
				  1,
				  (cmd_dir == ISER_DIR_OUT) ?
				  DMA_TO_DEVICE : DMA_FROM_DEVICE);
	BUG_ON(dma_nents == 0);

	iser_task->data_copy[cmd_dir].dma_nents = dma_nents;
	return 0;
}

/**
 * iser_finalize_rdma_unaligned_sg
 */
void iser_finalize_rdma_unaligned_sg(struct iscsi_iser_task *iser_task,
				     enum iser_data_dir         cmd_dir)
{
	struct ib_device *dev;
	struct iser_data_buf *mem_copy;
	unsigned long  cmd_data_len;

	dev = iser_task->iser_conn->ib_conn->device->ib_device;
	mem_copy = &iser_task->data_copy[cmd_dir];

	ib_dma_unmap_sg(dev, &mem_copy->sg_single, 1,
			(cmd_dir == ISER_DIR_OUT) ?
			DMA_TO_DEVICE : DMA_FROM_DEVICE);

	if (cmd_dir == ISER_DIR_IN) {
		char *mem;
		struct scatterlist *sgl, *sg;
		unsigned char *p, *to;
		unsigned int sg_size;
		int i;

		/* copy back read RDMA to unaligned sg */
		mem	= mem_copy->copy_buf;

		sgl	= (struct scatterlist *)iser_task->data[ISER_DIR_IN].buf;
		sg_size = iser_task->data[ISER_DIR_IN].size;

		p = mem;
		for_each_sg(sgl, sg, sg_size, i) {
			to = kmap_atomic(sg_page(sg));
			memcpy(to + sg->offset,
			       p,
			       sg->length);
			kunmap_atomic(to);
			p += sg->length;
		}
	}

	cmd_data_len = iser_task->data[cmd_dir].data_len;

	if (cmd_data_len > ISER_KMALLOC_THRESHOLD)
		free_pages((unsigned long)mem_copy->copy_buf,
			   ilog2(roundup_pow_of_two(cmd_data_len)) - PAGE_SHIFT);
	else
		kfree(mem_copy->copy_buf);

	mem_copy->copy_buf = NULL;
}

#define IS_4K_ALIGNED(addr)	((((unsigned long)addr) & ~MASK_4K) == 0)

/**
 * iser_sg_to_page_vec - Translates scatterlist entries to physical addresses
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

static int iser_sg_to_page_vec(struct iser_data_buf *data,
			       struct ib_device *ibdev, u64 *pages,
			       int *offset, int *data_size)
{
	struct scatterlist *sg, *sgl = (struct scatterlist *)data->buf;
	u64 start_addr, end_addr, page, chunk_start = 0;
	unsigned long total_sz = 0;
	unsigned int dma_len;
	int i, new_chunk, cur_page, last_ent = data->dma_nents - 1;

	/* compute the offset of first element */
	*offset = (u64) sgl[0].offset & ~MASK_4K;

	new_chunk = 1;
	cur_page  = 0;
	for_each_sg(sgl, sg, data->dma_nents, i) {
		start_addr = ib_sg_dma_address(ibdev, sg);
		if (new_chunk)
			chunk_start = start_addr;
		dma_len = ib_sg_dma_len(ibdev, sg);
		end_addr = start_addr + dma_len;
		total_sz += dma_len;

		/* collect page fragments until aligned or end of SG list */
		if (!IS_4K_ALIGNED(end_addr) && i < last_ent) {
			new_chunk = 0;
			continue;
		}
		new_chunk = 1;

		/* address of the first page in the contiguous chunk;
		   masking relevant for the very first SG entry,
		   which might be unaligned */
		page = chunk_start & MASK_4K;
		do {
			pages[cur_page++] = page;
			page += SIZE_4K;
		} while (page < end_addr);
	}

	*data_size = total_sz;
	iser_dbg("page_vec->data_size:%d cur_page %d\n",
		 *data_size, cur_page);
	return cur_page;
}


/**
 * xio_data_buf_aligned_len - Tries to determine the maximal correctly aligned
 * for RDMA sub-list of a scatter-gather list of memory buffers, and  returns
 * the number of entries which are aligned correctly. Supports the case where
 * consecutive SG elements are actually fragments of the same physcial page.
 */
static int xio_data_buf_aligned_len(struct iser_data_buf *data,
				    struct ib_device *ibdev)
{
	struct scatterlist *sgl, *sg, *next_sg = NULL;
	u64 start_addr, end_addr;
	int i, ret_len, start_check = 0;

	if (data->dma_nents == 1)
		return 1;

	sgl = (struct scatterlist *)data->buf;
	start_addr  = ib_sg_dma_address(ibdev, sgl);

	for_each_sg(sgl, sg, data->dma_nents, i) {
		if (start_check && !IS_4K_ALIGNED(start_addr))
			break;

		next_sg = sg_next(sg);
		if (!next_sg)
			break;

		end_addr    = start_addr + ib_sg_dma_len(ibdev, sg);
		start_addr  = ib_sg_dma_address(ibdev, next_sg);

		if (end_addr == start_addr) {
			start_check = 0;
			continue;
		} else
			start_check = 1;

		if (!IS_4K_ALIGNED(end_addr))
			break;
	}
	ret_len = (next_sg) ? i : i+1;
	iser_dbg("Found %d aligned entries out of %d in sg:0x%p\n",
		 ret_len, data->dma_nents, data);
	return ret_len;
}

static void iser_data_buf_dump(struct iser_data_buf *data,
			       struct ib_device *ibdev)
{
	struct scatterlist *sgl = (struct scatterlist *)data->buf;
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, data->dma_nents, i)
		iser_dbg("sg[%d] dma_addr:0x%lX page:0x%p "
			 "off:0x%x sz:0x%x dma_len:0x%x\n",
			 i, (unsigned long)ib_sg_dma_address(ibdev, sg),
			 sg_page(sg), sg->offset,
			 sg->length, ib_sg_dma_len(ibdev, sg));
}

static void iser_dump_page_vec(struct iser_page_vec *page_vec)
{
	int i;

	iser_err("page vec length %d data size %d\n",
		 page_vec->length, page_vec->data_size);
	for (i = 0; i < page_vec->length; i++)
		iser_err("%d %lx\n",i,(unsigned long)page_vec->pages[i]);
}

static void iser_page_vec_build(struct iser_data_buf *data,
				struct iser_page_vec *page_vec,
				struct ib_device *ibdev)
{
	int page_vec_len = 0;

	page_vec->length = 0;
	page_vec->offset = 0;

	iser_dbg("Translating sg sz: %d\n", data->dma_nents);
	page_vec_len = iser_sg_to_page_vec(data, ibdev, page_vec->pages,
					   &page_vec->offset,
					   &page_vec->data_size);
	iser_dbg("sg len %d page_vec_len %d\n", data->dma_nents, page_vec_len);

	page_vec->length = page_vec_len;

	if (page_vec_len * SIZE_4K < page_vec->data_size) {
		iser_err("page_vec too short to hold this SG\n");
		iser_data_buf_dump(data, ibdev);
		iser_dump_page_vec(page_vec);
		BUG();
	}
}

int iser_dma_map_task_data(struct iscsi_iser_task *iser_task,
			    struct iser_data_buf *data,
			    enum iser_data_dir iser_dir,
			    enum dma_data_direction dma_dir)
{
	struct ib_device *dev;

	iser_task->dir[iser_dir] = 1;
	dev = iser_task->iser_conn->ib_conn->device->ib_device;

	data->dma_nents = ib_dma_map_sg(dev, data->buf, data->size, dma_dir);
	if (data->dma_nents == 0) {
		iser_err("dma_map_sg failed!!!\n");
		return -EINVAL;
	}
	return 0;
}

void iser_dma_unmap_task_data(struct iscsi_iser_task *iser_task)
{
	struct ib_device *dev;
	struct iser_data_buf *data;

	dev = iser_task->iser_conn->ib_conn->device->ib_device;

	if (iser_task->dir[ISER_DIR_IN]) {
		data = &iser_task->data[ISER_DIR_IN];
		ib_dma_unmap_sg(dev, data->buf, data->size, DMA_FROM_DEVICE);
	}

	if (iser_task->dir[ISER_DIR_OUT]) {
		data = &iser_task->data[ISER_DIR_OUT];
		ib_dma_unmap_sg(dev, data->buf, data->size, DMA_TO_DEVICE);
	}
}

static int fall_to_bounce_buf(struct iscsi_iser_task *iser_task,
			      struct ib_device *ibdev,
			      enum iser_data_dir cmd_dir,
			      int aligned_len)
{
	struct iscsi_conn    *iscsi_conn = iser_task->iser_conn->iscsi_conn;
	struct iser_data_buf *mem = &iser_task->data[cmd_dir];

	iscsi_conn->fmr_unalign_cnt++;
	iser_warn("rdma alignment violation (%d/%d aligned) or FMR not supported\n",
		  aligned_len, mem->size);

	if (iser_debug_level > 0)
		iser_data_buf_dump(mem, ibdev);

	/* unmap the command data before accessing it */
	iser_dma_unmap_task_data(iser_task);

	/* allocate copy buf, if we are writing, copy the */
	/* unaligned scatterlist, dma map the copy        */
	if (iser_start_rdma_unaligned_sg(iser_task, cmd_dir) != 0)
			return -ENOMEM;

	return 0;
}

/**
 * xio_create_fmr_pool - Creates FMR pool and page_vector
 *
 * returns 0 on success, or errno code on failure
 */
int xio_create_fmr_pool(struct xio_dev *dev, u32 cmds_max)
{
	struct xio_fmr *fmr = &dev->fastreg.fmr;
	struct ib_fmr_pool_param params;
	size_t size;
	int ret = -ENOMEM;

	size = sizeof(struct xio_page_vec);
	size += sizeof(u64)*(ISCSI_ISER_SG_TABLESIZE + 1);
	fmr->page_vec = kzalloc(size, GFP_KERNEL);
	if (!fmr->page_vec)
		return ret;

	fmr->page_vec->pages = (u64 *)(fmr->page_vec + 1);

	params.page_shift        = SHIFT_4K;
	/* when the first/last SG element are not start/end *
	 * page aligned, the map whould be of N+1 pages     */
	params.max_pages_per_fmr = ISCSI_ISER_SG_TABLESIZE + 1;
	/* make the pool size twice the max number of SCSI commands *
	 * the ML is expected to queue, watermark for unmap at 50%  */
	params.pool_size	 = cmds_max * 2;
	params.dirty_watermark	 = cmds_max;
	params.cache		 = 0;
	params.flush_function	 = NULL;
	params.access		 = (IB_ACCESS_LOCAL_WRITE  |
				    IB_ACCESS_REMOTE_WRITE |
				    IB_ACCESS_REMOTE_READ);

	fmr->pool = ib_create_fmr_pool(dev->pd, &params);
	if (!IS_ERR(fmr->pool))
		return 0;

	/* no FMR => no need for page_vec */
	kfree(fmr->page_vec);
	fmr->page_vec = NULL;

	ret = PTR_ERR(fmr->pool);
	fmr->pool = NULL;
	if (ret != -ENOSYS) {
		ERROR_LOG("FMR allocation failed, err %d\n", ret);
		return ret;
	} else {
		WARN_LOG("FMRs are not supported, try using FRWR\n");
		return 0;
	}
}

/**
 * xio_free_fmr_pool - releases the FMR pool and page vec
 */
void xio_free_fmr_pool(struct xio_dev *dev)
{
	struct xio_fmr *fmr = &dev->fastreg.fmr;

	INFO_LOG("freeing dev %p fmr pool %p\n", dev, fmr->pool);

	if (fmr->pool)
		ib_destroy_fmr_pool(fmr->pool);

	fmr->pool = NULL;

	kfree(fmr->page_vec);
	fmr->page_vec = NULL;
}

/**
 * xio_create_frwr_pool - Creates pool of fast_reg descriptors
 * for fast registration work requests.
 * returns 0 on success, or errno code on failure
 */
int xio_create_frwr_pool(struct xio_dev *dev, u32 cmds_max)
{
	struct xio_frwr *frwr = &dev->fastreg.frwr;
	struct fast_reg_descriptor *desc;
	int i, ret;

	INIT_LIST_HEAD(&frwr->pool);
	frwr->pool_size = 0;
	for (i = 0; i < cmds_max; i++) {
		desc = kzalloc(sizeof(*desc), GFP_KERNEL);
		if (!desc) {
			ERROR_LOG("Failed to allocate a new fast_reg descriptor\n");
			ret = -ENOMEM;
			goto err;
		}

		desc->data_frpl = ib_alloc_fast_reg_page_list(dev>ib_dev,
							 ISCSI_ISER_SG_TABLESIZE + 1);
		if (IS_ERR(desc->data_frpl)) {
			ret = PTR_ERR(desc->data_frpl);
			ERROR_LOG("Failed to allocate ib_fast_reg_page_list err=%d\n", ret);
			goto err;
		}

		desc->data_mr = ib_alloc_fast_reg_mr(dev->pd,
						     ISCSI_ISER_SG_TABLESIZE + 1);
		if (IS_ERR(desc->data_mr)) {
			ret = PTR_ERR(desc->data_mr);
			ERROR_LOG("Failed to allocate ib_fast_reg_mr err=%d\n", ret);
			ib_free_fast_reg_page_list(desc->data_frpl);
			goto err;
		}
		desc->valid = true;
		list_add_tail(&desc->list, &frwr->pool);
		frwr->pool_size++;
	}

	return 0;
err:
	xio_free_frwr_pool(ib_conn);
	return ret;
}

/**
 * xio_free_frwr_pool - releases the pool of fast_reg descriptors
 */
void xio_free_frwr_pool(struct xio_dev *dev)
{
	struct xio_frwr *frwr = &dev->fastreg.frwr;
	struct fast_reg_descriptor *desc, *tmp;
	int i = 0;

	if (list_empty(&frwr->pool))
		return;

	INFO_LOG("freeing conn %p frwr pool\n", ib_conn);

	list_for_each_entry_safe(desc, tmp, &frwr->pool, list) {
		list_del(&desc->list);
		ib_free_fast_reg_page_list(desc->data_frpl);
		ib_dereg_mr(desc->data_mr);
		kfree(desc);
		++i;
	}

	if (i < frwr->pool_size)
		WARN_LOG("pool still has %d regions registered\n",
			  frwr->pool_size - i);
}

/**
 * Unregister (previosuly registered using FMR) memory.
 * If memory is non-FMR does nothing.
 */
void xio_unreg_mem_fmr(struct xio_task *xio_task,
			enum dma_data_direction cmd_dir)
{
	struct xio_rdma_task *rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	struct xio_mem_reg *reg = &xio_task->rdma_regd[cmd_dir].reg;
	int ret;

	if (!reg->is_mr)
		return;

	DEBUG_LOG("PHYSICAL Mem.Unregister mem_h %p\n",reg->mem_h);

	ret = ib_fmr_pool_unmap((struct ib_pool_fmr *)reg->mem_h);
	if (ret)
		ERROR_LOG("ib_fmr_pool_unmap failed %d\n", ret);

	reg->mem_h = NULL;
}

void xio_unreg_mem_frwr(struct xio_task *xio_task,
			 enum dma_data_direction cmd_dir)
{
	struct xio_rdma_task *rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	struct xio_mem_reg *reg = &xio_task->rdma_regd[cmd_dir].reg;
	struct xio_dev *dev = xio_task->xio_conn->ib_conn;
	struct fast_reg_descriptor *desc = reg->mem_h;

	if (!reg->is_mr)
		return;

	reg->mem_h = NULL;
	reg->is_mr = 0;
	spin_lock_bh(&ib_conn->lock);
	list_add_tail(&desc->list, &ib_conn->fastreg.frwr.pool);
	spin_unlock_bh(&ib_conn->lock);
}

/**
 * xio_reg_rdma_mem_fmr - Registers memory intended for RDMA,
 * using FMR (if possible) obtaining rkey and va
 *
 * returns 0 on success, errno code on failure
 */
int xio_reg_rdma_mem_fmr(struct xio_task *xio_task,
			  enum dma_data_direction cmd_dir)
{
	struct xio_rdma_task *rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	struct xio_conn     *ib_conn = xio_task->xio_conn->ib_conn;
	struct xio_device   *device = ib_conn->device;
	struct ib_device     *ibdev = device->ib_device;
	struct xio_data_buf *mem = &xio_task->data[cmd_dir];
	struct xio_regd_buf *regd_buf;
	int aligned_len;
	int err;
	int i;
	struct scatterlist *sg;

	regd_buf = &xio_task->rdma_regd[cmd_dir];

	aligned_len = xio_data_buf_aligned_len(mem, ibdev);
	if (aligned_len != mem->dma_nents) {
		err = fall_to_bounce_buf(xio_task, ibdev,
					 cmd_dir, aligned_len);
		if (err) {
			ERROR_LOG("failed to allocate bounce buffer\n");
			return err;
		}
		mem = &xio_task->data_copy[cmd_dir];
	}

	/* if there a single dma entry, FMR is not needed */
	if (mem->dma_nents == 1) {
		sg = (struct scatterlist *)mem->buf;

		regd_buf->reg.lkey = device->mr->lkey;
		regd_buf->reg.rkey = device->mr->rkey;
		regd_buf->reg.len  = ib_sg_dma_len(ibdev, &sg[0]);
		regd_buf->reg.va   = ib_sg_dma_address(ibdev, &sg[0]);
		regd_buf->reg.is_mr = 0;

		xio_dbg("PHYSICAL Mem.register: lkey: 0x%08X rkey: 0x%08X  "
			 "va: 0x%08lX sz: %ld]\n",
			 (unsigned int)regd_buf->reg.lkey,
			 (unsigned int)regd_buf->reg.rkey,
			 (unsigned long)regd_buf->reg.va,
			 (unsigned long)regd_buf->reg.len);
	} else { /* use FMR for multiple dma entries */
		xio_page_vec_build(mem, ib_conn->fastreg.fmr.page_vec, ibdev);
		err = xio_reg_page_vec(ib_conn, ib_conn->fastreg.fmr.page_vec,
					&regd_buf->reg);
		if (err && err != -EAGAIN) {
			xio_data_buf_dump(mem, ibdev);
			ERROR_LOG("mem->dma_nents = %d (dlength = 0x%x)\n",
				 mem->dma_nents,
				 ntoh24(xio_task->desc.iscsi_header.dlength));
			ERROR_LOG("page_vec: data_size = 0x%x, length = %d, offset = 0x%x\n",
				 ib_conn->fastreg.fmr.page_vec->data_size,
				 ib_conn->fastreg.fmr.page_vec->length,
				 ib_conn->fastreg.fmr.page_vec->offset);
			for (i = 0; i < ib_conn->fastreg.fmr.page_vec->length; i++)
				ERROR_LOG("page_vec[%d] = 0x%llx\n", i,
					 (unsigned long long) ib_conn->fastreg.fmr.page_vec->pages[i]);
		}
		if (err)
			return err;
	}
	return 0;
}

static int xio_fast_reg_mr(struct fast_reg_descriptor *desc,
			    struct xio_dev *dev,
			    struct xio_regd_buf *regd_buf,
			    u32 offset, unsigned int data_size,
			    unsigned int page_list_len)
{
	struct ib_send_wr fastreg_wr, inv_wr;
	struct ib_send_wr *bad_wr, *wr = NULL;
	u8 key;
	int ret;

	if (!desc->valid) {
		memset(&inv_wr, 0, sizeof(inv_wr));
		inv_wr.opcode = IB_WR_LOCAL_INV;
		inv_wr.send_flags = IB_SEND_SIGNALED;
		inv_wr.ex.invalidate_rkey = desc->data_mr->rkey;
		wr = &inv_wr;
		/* Bump the key */
		key = (u8)(desc->data_mr->rkey & 0x000000FF);
		ib_update_fast_reg_key(desc->data_mr, ++key);
	}

	/* Prepare FASTREG WR */
	memset(&fastreg_wr, 0, sizeof(fastreg_wr));
	fastreg_wr.opcode = IB_WR_FAST_REG_MR;
	fastreg_wr.send_flags = IB_SEND_SIGNALED;
	fastreg_wr.wr.fast_reg.iova_start = desc->data_frpl->page_list[0] + offset;
	fastreg_wr.wr.fast_reg.page_list = desc->data_frpl;
	fastreg_wr.wr.fast_reg.page_list_len = page_list_len;
	fastreg_wr.wr.fast_reg.page_shift = SHIFT_4K;
	fastreg_wr.wr.fast_reg.length = data_size;
	fastreg_wr.wr.fast_reg.rkey = desc->data_mr->rkey;
	fastreg_wr.wr.fast_reg.access_flags = (IB_ACCESS_LOCAL_WRITE  |
					       IB_ACCESS_REMOTE_WRITE |
					       IB_ACCESS_REMOTE_READ);

	if (!wr) {
		wr = &fastreg_wr;
		atomic_inc(&ib_conn->post_send_buf_count);
	} else {
		wr->next = &fastreg_wr;
		atomic_add(2, &ib_conn->post_send_buf_count);
	}

	ret = ib_post_send(ib_conn->qp, wr, &bad_wr);
	if (ret) {
		if (bad_wr->next)
			atomic_sub(2, &ib_conn->post_send_buf_count);
		else
			atomic_dec(&ib_conn->post_send_buf_count);
		ERROR_LOG("fast registration failed, ret:%d\n", ret);
		return ret;
	}
	desc->valid = false;

	regd_buf->reg.mem_h = desc;
	regd_buf->reg.lkey = desc->data_mr->lkey;
	regd_buf->reg.rkey = desc->data_mr->rkey;
	regd_buf->reg.va = desc->data_frpl->page_list[0] + offset;
	regd_buf->reg.len = data_size;
	regd_buf->reg.is_mr = 1;

	return ret;
}

/**
 * xio_reg_rdma_mem_frwr - Registers memory intended for RDMA,
 * using Fast Registration WR (if possible) obtaining rkey and va
 *
 * returns 0 on success, errno code on failure
 */
int xio_reg_rdma_mem_frwr(struct xio_task *xio_task,
			  enum dma_data_direction cmd_dir)
{
	struct xio_rdma_task *rdma_task =
		(struct xio_rdma_task *)task->dd_data;
	struct xio_dev *dev = xio_task->xio_conn->ib_conn;
	struct xio_device *device = ib_conn->device;
	struct ib_device *ibdev = device->ib_device;
	struct xio_data_buf *mem = &xio_task->data[cmd_dir];
	struct xio_regd_buf *regd_buf = &xio_task->rdma_regd[cmd_dir];
	struct fast_reg_descriptor *desc;
	unsigned int data_size, page_list_len;
	int err, aligned_len;
	unsigned long flags;
	u32 offset;

	aligned_len = xio_data_buf_aligned_len(mem, ibdev);
	if (aligned_len != mem->dma_nents) {
		err = fall_to_bounce_buf(xio_task, ibdev,
					 cmd_dir, aligned_len);
		if (err) {
			ERROR_LOG("failed to allocate bounce buffer\n");
			return err;
		}
		mem = &xio_task->data_copy[cmd_dir];
	}

	/* if there a single dma entry, dma mr suffices */
	if (mem->dma_nents == 1) {
		struct scatterlist *sg = (struct scatterlist *)mem->buf;

		regd_buf->reg.lkey = device->mr->lkey;
		regd_buf->reg.rkey = device->mr->rkey;
		regd_buf->reg.len  = ib_sg_dma_len(ibdev, &sg[0]);
		regd_buf->reg.va   = ib_sg_dma_address(ibdev, &sg[0]);
		regd_buf->reg.is_mr = 0;
	} else {
		spin_lock_irqsave(&ib_conn->lock, flags);
		desc = list_first_entry(&ib_conn->fastreg.frwr.pool,
					struct fast_reg_descriptor, list);
		list_del(&desc->list);
		spin_unlock_irqrestore(&ib_conn->lock, flags);
		page_list_len = xio_sg_to_page_vec(mem, device->ib_device,
						    desc->data_frpl->page_list,
						    &offset, &data_size);

		if (page_list_len * SIZE_4K < data_size) {
			ERROR_LOG("fast reg page_list too short to hold this SG\n");
			err = -EINVAL;
			goto err_reg;
		}

		err = xio_fast_reg_mr(desc, ib_conn, regd_buf,
				       offset, data_size, page_list_len);
		if (err)
			goto err_reg;
	}

	return 0;
err_reg:
	spin_lock_irqsave(&ib_conn->lock, flags);
	list_add_tail(&desc->list, &ib_conn->fastreg.frwr.pool);
	spin_unlock_irqrestore(&ib_conn->lock, flags);
	return err;
}
#endif

#define IS_PAGE_ALIGNED(addr)	((((unsigned long)addr) & ~PAGE_MASK) == 0)

/* drivers/block/nvme.c nvme_map_bio */
#define XIOVEC_NOT_VIRT_MERGEABLE(vec1, vec2)   ((vec2)->bv_offset || \
                        (((vec1)->bv_offset + (vec1)->bv_len) % PAGE_SIZE))

/**
 * xio_data_buf_aligned_and_len - Tries to determine if the IOVEC is correctly
 * aligned
 * for RDMA sub-list of a scatter-gather list of memory buffers, and  returns
 * the number of entries which are aligned correctly. Supports the case where
 * consecutive IOVEC elements are actually fragments of the same physcial page.
 */

static int xio_data_buf_aligned_and_len(struct xio_vmsg *vmsg, size_t *total_len)
{
	struct xio_iovec *iov, *niov;
	u64 end_addr;
	int i, aligned;

	if (vmsg->iov_len == 0) {
		*total_len = 0;
		return 0;
	}

	niov = &vmsg->data_iov[0];
	*total_len = niov->data_len;
	/* be optimistic */
	aligned = 1;

	for (i = 0; i < vmsg->data_iovlen - 1; i++) {
		iov = niov;
		niov++;
		*total_len += niov->data_len;
		end_addr = iov->iov_base + iov->data_len;

		/* Can iov and niov be merged ? */
		if (end_addr == niov->iov_base)
			continue;

		/* Not mergable */

		/* Only first segment can start at unaligned address */
		if (!IS_PAGE_ALIGNED(niov->iov_base) {
			aligned = 0;
			continue;
		}

		/* Only last segment can ent at unaligned address */
		if (!IS_PAGE_ALIGNED(end_addr)) {
			aligned = 0;
			continue;
		}
	}

	return aligned;
}

int xio_vmsg_to_sge(struct xio_rdma_transport *rdma_hndl,
		    struct xio_vmsg *vmsg,
		    xio_rdma_desc_mem *desc,
		    enum dma_data_direction direction)
{
	struct xio_iovec *iov, *niov;
	struct scatterlist *sgl = &desc->sgl;
	struct scatterlist *sg = NULL;
	struct page *page,
	unsigned int len;
	unsigned int offset;
	size_t total_len = 0;
	u64 start_addr, end_addr;
	int i;

	if (vmsg->iov_len > XIO_MAX_IOV) {
		WARN_LOG("IOV too long %d\n", vmsg->iov_len);
		return -EINVAL;
	}

	if (!xio_data_buf_aligned_and_len(vmsg, &total_len)) {
		/* Fall to bounce buffer */
		struct xio_rdma_mp_mem *xsge;
		retval = xio_rdma_mempool_alloc(rdma_hndl->rdma_mempool,
						total_len,
						desc);
		if (retval) {
			xio_set_error(ENOMEM);
			ERROR_LOG("mempool faild for %zd bytes\n", total_len);
			goto cleanup;
		}
		sg = dsec->sgl;
		desc->nents = 1;
		xsge = &desc->mp_sge[0];
		sg_init_one(sg, xsge->addr, xsge->length);
		if (direction == DMA_TO_DEVICE)
			copy_iov_to_buffer;

		return 0;
	}

	/* sge will point to user buffers */
	xsge->cache = NULL;
	xsge->addr  = NULL;

	sg_init_table(sgl, XIO_MAX_IOV);
	niov = &vmsg->data_iov[0];
	start_address = niov->iov_base;
	total_len = niov->data_len;
	sg = sgl;
	desc->nents = 0;

	for (i = 0; i < vmsg->data_iovlen - 1; i++) {
		iov = niov;
		niov++;
		end_addr = iov->iov_base + iov->data_len;

		/* Can iov and niov be merged ? */
		if (end_addr == niov->iov_base) {
			total_len += niov->data_len;
			continue;
		}

		/* Not mergable close current sg */
		page = virt_to_page(start_address);
		offset = start_address - page_to_virt(page);
		sg_set_page(sg, page, total_len, offset);
		desc->nents++;

		/* New segmet starts here */
		start_address = niov->iov_base;
		total_len = niov->data_len;
		sg++;
	}

	/* close last segment (can be the first and last one) */
	page = virt_to_page(start_address);
	offset = start_address - page_to_virt(page);
	sg_set_page(sg, page, total_len, offset);
	desc->nents++;

	sg_mark_end(sg);

	return 0;
}

int xio_data_buf_aligned_to_ib_sge(struct xio_vmsg *vmsg, ib_mr *mr,
				   ib_sge *sge, int *num_sge, size_t *total_len)
{
	struct xio_iovec *iov, *niov;
	size_t total_len = 0;
	u64 start_addr, end_addr;
	u64 end_addr;
	int i, aligned;


	if (vmsg->iov_len > XIO_MAX_IOV) {
		WARN_LOG("IOV too long %d\n", vmsg->iov_len);
		return -EINVAL;
	}

	if (vmsg->iov_len == 0) {
		*total_len = 0;
		return 0;
	}

	niov = &vmsg->data_iov[0];
	*total_len = niov->data_len;
	/* be optimistic */
	aligned = 1;

	for (i = 0; i < vmsg->data_iovlen - 1; i++) {
		page = virt_to_page(start_address);
		offset = start_address - page_to_virt(page);
		sg_set_page(sg, page, total_len, offset);
		iov = niov;
		niov++;
		*total_len += niov->data_len;
		end_addr = iov->iov_base + iov->data_len;

		/* Can iov and niov be merged ? */
		if (end_addr == niov->iov_base)
			continue;

		/* Not mergable */

		/* Only first segment can start at unaligned address */
		if (!IS_PAGE_ALIGNED(niov->iov_base) {
			aligned = 0;
			continue;
		}

		/* Only last segment can ent at unaligned address */
		if (!IS_PAGE_ALIGNED(end_addr)) {
			aligned = 0;
			continue;
		}
	}

	return aligned;
}

int xio_vmsg_to_sgl(struct xio_vmsg *vmsg, struct scatterlist *sgl)
{
	struct xio_iovec *iov, *niov;
	struct page *page,
	unsigned int len;
	unsigned int offset;
	int i;

	if (vmsg->iov_len > XIO_MAX_IOV) {
		WARN_LOG("IOV too long %d\n", vmsg->iov_len);
		return -EINVAL;
	}

	if (vmsg->iov_len == 0) {
		*total_len = 0;
		return 0;
	}

	iov = &vmsg->data_iov[0];

	for (i = 0; i < vmsg->data_iovlen; i++) {
		page = virt_to_page(iov->iov_base);
		offset = iov->iov_base - page_to_virt(page);
		sg_set_page(sgl, page, iov->data_len, offset);
	}

	return 0;
}
