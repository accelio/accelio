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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "raio_bs.h"
#include "raio_msg_pool.h"

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static SLIST_HEAD(, backingstore_template) bst_list =
	SLIST_HEAD_INITIALIZER(bst_list);


/*---------------------------------------------------------------------------*/
/* register_backingstore_template					     */
/*---------------------------------------------------------------------------*/
int register_backingstore_template(struct backingstore_template *bst)
{
	if (!bst->bs_open ||
		!bst->bs_close ||
		!bst->bs_init ||
		!bst->bs_exit ||
		!bst->bs_cmd_submit ||
		!bst->bs_poll) {
		fprintf(stderr, "Unable to register backingstore %s: Not all methods defined\n", bst->bs_name);
		return -1;
	}

	SLIST_INSERT_HEAD(&bst_list, bst, backingstore_siblings);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* get_backingstore_template						     */
/*---------------------------------------------------------------------------*/
struct backingstore_template *get_backingstore_template(const char *name)
{
	struct backingstore_template *bst;

	SLIST_FOREACH(bst, &bst_list, backingstore_siblings) {
		if (!strcmp(name, bst->bs_name))
			return bst;
	}
	return NULL;
}

extern void raio_bs_aio_constructor(void);
extern void raio_bs_null_constructor(void);

/*---------------------------------------------------------------------------*/
/* register_backingstores						     */
/*---------------------------------------------------------------------------*/
static void register_backingstores(void)
{
	if (SLIST_EMPTY(&bst_list)) {
		raio_bs_aio_constructor();
		raio_bs_null_constructor();
	}
}

/*---------------------------------------------------------------------------*/
/* raio_bs_init								     */
/*---------------------------------------------------------------------------*/
struct raio_bs *raio_bs_init(void *ctx, const char *name)
{
	struct raio_bs			*dev = NULL;
	struct backingstore_template	*bst;

	register_backingstores();

	bst = get_backingstore_template(name);
	if (bst == NULL) {
		fprintf(stderr, "backingstore does not exist name:%s\n", name);
		goto cleanup;
	}

	dev = (struct raio_bs *)calloc(1, sizeof(*dev)+bst->bs_datasize);
	if (dev == NULL) {
		fprintf(stderr, "calloc failed\n");
		goto cleanup;
	}

	dev->dd		= ((char *)dev) + sizeof(*dev);
	dev->bst	= bst;
	dev->ctx	= ctx;

	if (dev->bst->bs_init) {
		int retval = dev->bst->bs_init(dev);
		if (retval != 0)
			goto cleanup1;
	}
	return dev;

cleanup1:
	free(dev);
cleanup:
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* raio_bs_exit								     */
/*---------------------------------------------------------------------------*/
void raio_bs_exit(struct raio_bs *dev)
{
	dev->bst->bs_exit(dev);
	free(dev);
}

/*---------------------------------------------------------------------------*/
/* raio_bs_open								     */
/*---------------------------------------------------------------------------*/
int raio_bs_open(struct raio_bs *dev, int fd, int io_u_free_nr)
{
	struct xio_iovec_ex		*sglist;
	int j;
	int retval = dev->bst->bs_open(dev, fd);
	if (retval == 0) {
		dev->fd = fd;
		dev->io_u_free_nr = io_u_free_nr;
		dev->io_us_free = (struct raio_io_u *)calloc(io_u_free_nr,
						 sizeof(struct raio_io_u));
		dev->rsp_pool = msg_pool_create(RAIO_CMD_HDR_SZ, MAXBLOCKSIZE,
						io_u_free_nr);
		TAILQ_INIT(&dev->io_u_free_list);

		/* register each io_u in the free list */
		for (j = 0; j < dev->io_u_free_nr; j++) {
			dev->io_us_free[j].bs_dev = dev;
			dev->io_us_free[j].rsp = msg_pool_get(dev->rsp_pool);
			sglist = vmsg_sglist(&dev->io_us_free[j].rsp->out);
			dev->io_us_free[j].buf = sglist[0].iov_base;
			TAILQ_INSERT_TAIL(&dev->io_u_free_list,
					  &dev->io_us_free[j],
					  io_u_list);
		}
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* raio_bs_close							     */
/*---------------------------------------------------------------------------*/
void raio_bs_close(struct raio_bs *dev)
{
	int j;

	for (j = 0; j < dev->io_u_free_nr; j++) {
		TAILQ_REMOVE(&dev->io_u_free_list,
			     &dev->io_us_free[j],
			     io_u_list);
		msg_pool_put(dev->rsp_pool, dev->io_us_free[j].rsp);
		dev->io_us_free[j].buf = NULL;
	}
	dev->io_u_free_nr = 0;
	free(dev->io_us_free);
	msg_pool_delete(dev->rsp_pool);

	dev->bst->bs_close(dev);
}

/*---------------------------------------------------------------------------*/
/* raio_bs_cmd_submit							     */
/*---------------------------------------------------------------------------*/
int raio_bs_cmd_submit(struct raio_bs *dev, struct raio_io_cmd *cmd)
{
	return dev->bst->bs_cmd_submit(dev, cmd);
}

/*---------------------------------------------------------------------------*/
/* raio_bs_set_last_in_batch						     */
/*---------------------------------------------------------------------------*/
void raio_bs_set_last_in_batch(struct raio_bs *dev)
{
	if (dev->bst->bs_set_last_in_batch)
		dev->bst->bs_set_last_in_batch(dev);
}

/*---------------------------------------------------------------------------*/
/* raio_bs_poll								     */
/*---------------------------------------------------------------------------*/
void raio_bs_poll(struct raio_bs *dev)
{
	dev->bst->bs_poll(dev);
}

