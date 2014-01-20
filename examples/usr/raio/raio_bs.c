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
#include "libraio.h"
#include "raio_bs.h"

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

	dev = calloc(1, sizeof(*dev)+bst->bs_datasize);
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
			goto cleanup;
	}
	return dev;

cleanup:
	free(dev);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* raio_bs_exit								     */
/*---------------------------------------------------------------------------*/
void raio_bs_exit(struct raio_bs *dev)
{
	if (dev->bst->bs_exit)
		dev->bst->bs_exit(dev);
	free(dev);
}

/*---------------------------------------------------------------------------*/
/* raio_bs_open								     */
/*---------------------------------------------------------------------------*/
int raio_bs_open(struct raio_bs *dev, int fd)
{
	if (dev->bst->bs_open) {
		int retval = dev->bst->bs_open(dev, fd);
		if (retval == 0)
			dev->fd = fd;
		return retval;
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_bs_close							     */
/*---------------------------------------------------------------------------*/
void raio_bs_close(struct raio_bs *dev)
{
	if (dev->bst->bs_close)
		dev->bst->bs_close(dev);
}

/*---------------------------------------------------------------------------*/
/* raio_bs_cmd_submit							     */
/*---------------------------------------------------------------------------*/
int raio_bs_cmd_submit(struct raio_bs *dev, struct raio_io_cmd *cmd)
{
	if (dev->bst->bs_cmd_submit)
		return dev->bst->bs_cmd_submit(dev, cmd);

	return 0;
}


