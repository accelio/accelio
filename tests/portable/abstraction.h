/*
 * Copyright (c) 2013 Mellanox Technologies®. All rights reserved.
 * Copyright (c) 2014-2015, E8 Storage Systems Ltd. All Rights Reserved.
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

#include "libxio.h"

#ifdef __KERNEL__

#include <linux/slab.h>

static inline int xio_mem_alloc(size_t length, struct xio_reg_mem *reg_mem)
{
	reg_mem->addr = kzalloc(length, GFP_KERNEL);
	if (!reg_mem->addr)
		return -ENOMEM;
	reg_mem->length = length;
	return 0;
}

static inline int xio_mem_free(struct xio_reg_mem *reg_mem)
{
	kfree(reg_mem->addr);
	reg_mem->addr = NULL;
	return 0;
}

static inline uint32_t xio_lookup_rkey_by_response(
	const struct xio_reg_mem *reg_mem,
	const struct xio_msg *rsp)
{
	/* TODO: add support for portably mapping buffers in both
	   user-mode and kernel-mode to xio.
           For now, server-side RDMA buffers are not supported in kernel.
	*/
	return 0;
	/*return xio_rsp_to_device(rsp)->mr->rkey;*/
}

#else /* __KERNEL__ */

#define pr_info printf

#define __GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#endif
