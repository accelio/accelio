/*
 * Copyright (c) 2013 Mellanox Technologies��. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies�� BSD license
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
 *      - Neither the name of the Mellanox Technologies�� nor the names of its
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

#include "nbdx.h"

int nbdx_rq_map_sg(struct request *rq, struct xio_vmsg *vmsg,
		    unsigned long long *len)
{
	if (unlikely(vmsg->data_tbl.orig_nents < rq->nr_phys_segments)) {
		pr_err("unsupported sg table size\n");
		return -ENOMEM;
	}
	sg_init_table(vmsg->data_tbl.sgl, rq->nr_phys_segments);
	vmsg->data_tbl.nents = blk_rq_map_sg(rq->q, rq, vmsg->data_tbl.sgl);
	if (unlikely(vmsg->data_tbl.nents <= 0)) {
		pr_err("mapped %d sg nents\n", vmsg->data_tbl.nents);
		return -EINVAL;
	}

	*len = blk_rq_bytes(rq);

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
static struct blk_mq_hw_ctx *nbdx_alloc_hctx(struct blk_mq_reg *reg,
					     unsigned int hctx_index)
{
	int b_size = DIV_ROUND_UP(reg->nr_hw_queues, nr_online_nodes);
	int tip = (reg->nr_hw_queues % nr_online_nodes);
	int node = 0, i, n;
	struct blk_mq_hw_ctx * hctx;

	pr_debug("%s called\n", __func__);
	pr_debug("hctx_index=%u, b_size=%d, tip=%d, nr_online_nodes=%d\n",
		 hctx_index, b_size, tip, nr_online_nodes);
	/*
	 * Split submit queues evenly wrt to the number of nodes. If uneven,
	 * fill the first buckets with one extra, until the rest is filled with
	 * no extra.
	 */
	for (i = 0, n = 1; i < hctx_index; i++, n++) {
		if (n % b_size == 0) {
			n = 0;
			node++;

			tip--;
			if (!tip)
				b_size = reg->nr_hw_queues / nr_online_nodes;
		}
	}

	/*
	 * A node might not be online, therefore map the relative node id to the
	 * real node id.
	 */
	for_each_online_node(n) {
		if (!node)
			break;
		node--;
	}
	pr_debug("%s: n=%d\n", __func__, n);
	hctx = kzalloc_node(sizeof(struct blk_mq_hw_ctx), GFP_KERNEL, n);

	return hctx;
}

static void nbdx_free_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_index)
{
	pr_err("%s called\n", __func__);

	kfree(hctx);
}
#endif

static int nbdx_request(struct request *req, struct nbdx_queue *xq)
{
	struct nbdx_file *xdev;
	unsigned long start = blk_rq_pos(req) << NBDX_SECT_SHIFT;
	unsigned long len  = blk_rq_cur_bytes(req);
	int write = rq_data_dir(req) == WRITE;
	int err;
	void* buffer = bio_data(req->bio);

	pr_debug("%s called\n", __func__);

	xdev = req->rq_disk->private_data;

	err = nbdx_transfer(xdev, buffer, start, len, write, req, xq);
	if (unlikely(err))
		pr_err("transfer failed for req %p\n", req);

	return err;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
static int nbdx_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 18, 0)
static int nbdx_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *rq, bool last)
#else
static int nbdx_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *rq)
#endif
{
	struct nbdx_queue *nbdx_q;
	int err;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct request *rq = bd->rq;
#endif

	pr_debug("%s called\n", __func__);

	nbdx_q = hctx->driver_data;
	err = nbdx_request(rq, nbdx_q);

	if (unlikely(err)) {
		rq->errors = -EIO;
		return BLK_MQ_RQ_QUEUE_ERROR;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	blk_mq_start_request(rq);
#endif

	return BLK_MQ_RQ_QUEUE_OK;
}

static int nbdx_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
			  unsigned int index)
{
	struct nbdx_file *xdev = data;
	struct nbdx_queue *xq;

	pr_debug("%s called index=%u\n", __func__, index);

	xq = &xdev->queues[index];
	pr_debug("%s called xq=%p\n", __func__, xq);
	xq->nbdx_conn = xdev->nbdx_conns[index];
	xq->xdev = xdev;
	xq->queue_depth = xdev->queue_depth;
	hctx->driver_data = xq;

	return 0;
}

static struct blk_mq_ops nbdx_mq_ops = {
	.queue_rq       = nbdx_queue_rq,
	.map_queue      = blk_mq_map_queue,
	.init_hctx	= nbdx_init_hctx,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
	.alloc_hctx	= nbdx_alloc_hctx,
	.free_hctx	= nbdx_free_hctx,
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
static struct blk_mq_reg nbdx_mq_reg = {
	.ops		= &nbdx_mq_ops,
	.cmd_size	= sizeof(struct raio_io_u),
	.flags		= BLK_MQ_F_SHOULD_MERGE,
	.numa_node	= NUMA_NO_NODE,
	.queue_depth	= NBDX_QUEUE_DEPTH,
};
#endif

int nbdx_setup_queues(struct nbdx_file *xdev)
{
	pr_debug("%s called\n", __func__);

	xdev->queues = kzalloc(submit_queues * sizeof(*xdev->queues),
			GFP_KERNEL);
	if (!xdev->queues)
		return -ENOMEM;

	return 0;
}

static int nbdx_open(struct block_device *bd, fmode_t mode)
{
	pr_debug("%s called\n", __func__);
	return 0;
}

static void nbdx_release(struct gendisk *gd, fmode_t mode)
{
	pr_debug("%s called\n", __func__);
}

static int nbdx_media_changed(struct gendisk *gd)
{
	pr_debug("%s called\n", __func__);
	return 0;
}

static int nbdx_revalidate(struct gendisk *gd)
{
	pr_debug("%s called\n", __func__);
	return 0;
}

static int nbdx_ioctl(struct block_device *bd, fmode_t mode,
		      unsigned cmd, unsigned long arg)
{
	pr_debug("%s called\n", __func__);
	return -ENOTTY;
}


static struct block_device_operations nbdx_ops = {
	.owner           = THIS_MODULE,
	.open 	         = nbdx_open,
	.release 	 = nbdx_release,
	.media_changed   = nbdx_media_changed,
	.revalidate_disk = nbdx_revalidate,
	.ioctl	         = nbdx_ioctl
};

void nbdx_destroy_queues(struct nbdx_file *xdev)
{
	pr_debug("%s called\n", __func__);

	kfree(xdev->queues);
}

int nbdx_register_block_device(struct nbdx_file *nbdx_file)
{
	sector_t size = nbdx_file->stbuf.st_size;
	int page_size = PAGE_SIZE;
	int err = 0;

	pr_debug("%s called\n", __func__);

	nbdx_file->major = nbdx_major;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
	nbdx_mq_reg.nr_hw_queues = submit_queues;

	nbdx_file->queue = blk_mq_init_queue(&nbdx_mq_reg, nbdx_file);
#else
	nbdx_file->tag_set.ops = &nbdx_mq_ops;
	nbdx_file->tag_set.nr_hw_queues = submit_queues;
	nbdx_file->tag_set.queue_depth = NBDX_QUEUE_DEPTH;
	nbdx_file->tag_set.numa_node = NUMA_NO_NODE;
	nbdx_file->tag_set.cmd_size	= sizeof(struct raio_io_u);
	nbdx_file->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	nbdx_file->tag_set.driver_data = nbdx_file;

	err = blk_mq_alloc_tag_set(&nbdx_file->tag_set);
	if (err)
		goto out;

	nbdx_file->queue = blk_mq_init_queue(&nbdx_file->tag_set);
#endif
	if (IS_ERR(nbdx_file->queue)) {
		pr_err("%s: Failed to allocate blk queue ret=%ld\n",
		       __func__, PTR_ERR(nbdx_file->queue));
		err = PTR_ERR(nbdx_file->queue);
		goto blk_mq_init;
	}

	nbdx_file->queue->queuedata = nbdx_file;
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, nbdx_file->queue);
	queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, nbdx_file->queue);

	nbdx_file->disk = alloc_disk_node(1, NUMA_NO_NODE);
	if (!nbdx_file->disk) {
		pr_err("%s: Failed to allocate disk node\n", __func__);
		err = -ENOMEM;
		goto alloc_disk;
	}

	nbdx_file->disk->major = nbdx_file->major;
	nbdx_file->disk->first_minor = nbdx_file->index;
	nbdx_file->disk->fops = &nbdx_ops;
	nbdx_file->disk->queue = nbdx_file->queue;
	nbdx_file->disk->private_data = nbdx_file;
	blk_queue_logical_block_size(nbdx_file->queue, NBDX_SECT_SIZE);
	blk_queue_physical_block_size(nbdx_file->queue, NBDX_SECT_SIZE);
	sector_div(page_size, NBDX_SECT_SIZE);
	blk_queue_max_hw_sectors(nbdx_file->queue, page_size * MAX_SGL_LEN);
	sector_div(size, NBDX_SECT_SIZE);
	set_capacity(nbdx_file->disk, size);
	sscanf(nbdx_file->dev_name, "%s", nbdx_file->disk->disk_name);
	add_disk(nbdx_file->disk);
	goto out;

alloc_disk:
	blk_cleanup_queue(nbdx_file->queue);
blk_mq_init:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	blk_mq_free_tag_set(&nbdx_file->tag_set);
#endif
out:
	return err;
}

void nbdx_unregister_block_device(struct nbdx_file *nbdx_file)
{
	del_gendisk(nbdx_file->disk);
	blk_cleanup_queue(nbdx_file->queue);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	blk_mq_free_tag_set(&nbdx_file->tag_set);
#endif
	put_disk(nbdx_file->disk);
}
