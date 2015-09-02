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
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "libraio.h"
#include "raio_bs.h"


/*---------------------------------------------------------------------------*/
/* preprocessor directives                                                   */
/*---------------------------------------------------------------------------*/
#define NULL_BS_DEV_SIZE        (1ULL << 32)

/*---------------------------------------------------------------------------*/
/* raio_bs_null_cmd_submit						     */
/*---------------------------------------------------------------------------*/
int raio_bs_null_cmd_submit(struct raio_bs *dev,
			    struct raio_io_cmd *cmd)
{
	cmd->res = cmd->bcount;
	cmd->res2 = 0;
	if (cmd->comp_cb)
		cmd->comp_cb(cmd);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_bs_null_open							     */
/*---------------------------------------------------------------------------*/
static int raio_bs_null_open(struct raio_bs *dev, int fd)
{
	dev->stbuf.st_size = NULL_BS_DEV_SIZE;
	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_bs_null_close							     */
/*---------------------------------------------------------------------------*/
static inline void raio_bs_null_close(struct raio_bs *dev)
{
}

/*---------------------------------------------------------------------------*/
/* raio_bs_null_set_last_in_batch					     */
/*---------------------------------------------------------------------------*/
static inline void raio_bs_null_set_last_in_batch(struct raio_bs *dev)
{
}

/*---------------------------------------------------------------------------*/
/* raio_bs_null_poll							     */
/*---------------------------------------------------------------------------*/
static inline void raio_bs_null_poll(struct raio_bs *dev)
{
}


/*---------------------------------------------------------------------------*/
/* raio_bs_null_exit                                                           */
/*---------------------------------------------------------------------------*/
static void raio_bs_null_exit(struct raio_bs *dev)
{
}

/*---------------------------------------------------------------------------*/
/* raio_bs_null_init                                                           */
/*---------------------------------------------------------------------------*/
static int raio_bs_null_init(struct raio_bs *dev)
{
	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_null_bst							     */
/*---------------------------------------------------------------------------*/
static struct backingstore_template raio_null_bst = {
	.bs_name		= "null",
	.bs_datasize		= 0,
	.bs_init		= raio_bs_null_init,
	.bs_exit		= raio_bs_null_exit,
	.bs_open		= raio_bs_null_open,
	.bs_close		= raio_bs_null_close,
	.bs_cmd_submit		= raio_bs_null_cmd_submit,
	.bs_set_last_in_batch	= raio_bs_null_set_last_in_batch,
	.bs_poll		= raio_bs_null_poll
};

/*---------------------------------------------------------------------------*/
/* raio_bs_null_constructor						     */
/*---------------------------------------------------------------------------*/
void raio_bs_null_constructor(void)
{
	register_backingstore_template(&raio_null_bst);
}

