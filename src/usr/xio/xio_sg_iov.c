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

/* sg represents xio_sg_iov; */
#include "libxio.h"
#include <xio_env.h>
#include "xio_sg_table.h"

/*---------------------------------------------------------------------------*/
/* xio_sgve_set_buf							     */
/*---------------------------------------------------------------------------*/
static inline void xio_sgve_set_buf(struct xio_iovec_ex *sg, const void *buf,
				    uint32_t buflen, void *mr)
{
	sg->iov_base	= (void *)buf;
	sg->iov_len	= buflen;
	sg->mr		= (struct xio_mr *)mr;
}

/*---------------------------------------------------------------------------*/
/* xio_sgve_addr							     */
/*---------------------------------------------------------------------------*/
static inline void *xio_sgve_addr(struct xio_iovec_ex *sg)
{
	return sg->iov_base;
}

/*---------------------------------------------------------------------------*/
/* xio_sgve_set_addr							     */
/*---------------------------------------------------------------------------*/
static inline void xio_sgve_set_addr(struct xio_iovec_ex *sg, void *addr)
{
	sg->iov_base = addr;
}

/*---------------------------------------------------------------------------*/
/* xio_sgve_length							     */
/*---------------------------------------------------------------------------*/
static inline size_t xio_sgve_length(struct xio_iovec_ex *sg)
{
	return sg->iov_len;
}

/*---------------------------------------------------------------------------*/
/* xio_sgve_set_length							     */
/*---------------------------------------------------------------------------*/
static inline void xio_sgve_set_length(struct xio_iovec_ex *sg,
				       uint32_t length)
{
	sg->iov_len = length;
}

/*---------------------------------------------------------------------------*/
/* xio_sgve_mr								     */
/*---------------------------------------------------------------------------*/
static inline void *xio_sgve_mr(struct xio_iovec_ex *sg)
{
	return sg->mr;
}

/*---------------------------------------------------------------------------*/
/* xio_sgve_set_mr							     */
/*---------------------------------------------------------------------------*/
static inline void xio_sgve_set_mr(struct xio_iovec_ex *sg, void *mr)
{
	sg->mr = (struct xio_mr *)mr;
}

/*---------------------------------------------------------------------------*/
/* xio_sgve_first							     */
/*---------------------------------------------------------------------------*/
static struct xio_iovec_ex *xio_sgve_first(struct xio_sg_iov *sgv)
{
	return ((!sgv || sgv->nents == 0) ?
		NULL : &sgv->sglist[0]);
}

/*---------------------------------------------------------------------------*/
/* xio_sgve_last							     */
/*---------------------------------------------------------------------------*/
static struct xio_iovec_ex *xio_sgve_last(struct xio_sg_iov *sgv)
{
	return ((!sgv || sgv->nents == 0) ?
		NULL : &sgv->sglist[sgv->nents - 1]);
}

/*---------------------------------------------------------------------------*/
/* xio_sgve_next							     */
/*---------------------------------------------------------------------------*/
static struct xio_iovec_ex *xio_sgve_next(struct xio_sg_iov *sgv,
					  struct xio_iovec_ex *sgve)
{
	return (!sgv || sgv->nents == 0 ||
		(sgve == &sgv->sglist[sgv->nents - 1]))
			? NULL : ++sgve;
}

/*---------------------------------------------------------------------------*/
/* xio_sgv_sglist							     */
/*---------------------------------------------------------------------------*/
static inline struct xio_iovec_ex *xio_sgv_sglist(struct xio_sg_iov *sgv)
{
	return sgv->sglist;
}

/*---------------------------------------------------------------------------*/
/* xio_sgv_nents							     */
/*---------------------------------------------------------------------------*/
static inline int xio_sgv_nents(struct xio_sg_iov *sgv)
{
	return sgv->nents;
}

/*---------------------------------------------------------------------------*/
/* xio_sgv_max_nents							     */
/*---------------------------------------------------------------------------*/
static inline int xio_sgv_max_nents(struct xio_sg_iov *sgv)
{
	return XIO_IOVLEN;
}

/*---------------------------------------------------------------------------*/
/* xio_sgv_set_nents							     */
/*---------------------------------------------------------------------------*/
static inline void xio_sgv_set_nents(struct xio_sg_iov *sgv, uint32_t nents)
{
	if (!sgv || XIO_IOVLEN < nents)
		return;
	sgv->nents = nents;
}

/*---------------------------------------------------------------------------*/
/* xio_sgv_set_max_nents						     */
/*---------------------------------------------------------------------------*/
static inline void xio_sgv_set_max_nents(struct xio_sg_iov *sgv,
					 uint32_t max_nents)
{
	sgv->max_nents = XIO_IOVLEN;
}

/*---------------------------------------------------------------------------*/
/* xio_sgv_empty							     */
/*---------------------------------------------------------------------------*/
static int xio_sgv_empty(struct xio_sg_iov *sgv)
{
	return (!sgv || sgv->nents == 0);
}

/*---------------------------------------------------------------------------*/
/* xio_sgv_length							     */
/*---------------------------------------------------------------------------*/
static size_t xio_sgv_length(struct xio_sg_iov *sgv)
{
	size_t		sz = 0;
	uint32_t	i;

	for (i = 0; i < sgv->nents; i++)
		sz += sgv->sglist[i].iov_len;

	return sz;
}

/*---------------------------------------------------------------------------*/
/* sgtbl_ops_iov							     */
/*---------------------------------------------------------------------------*/
struct xio_sg_table_ops sgtbl_ops_iov = {
	.sge_set_buf		= (sge_set_buf_fn)xio_sgve_set_buf,
	.sge_addr		= (sge_addr_fn)xio_sgve_addr,
	.sge_set_addr		= (sge_set_addr_fn)xio_sgve_set_addr,
	.sge_mr			= (sge_mr_fn)xio_sgve_mr,
	.sge_set_mr		= (sge_set_mr_fn)xio_sgve_set_mr,
	.sge_length		= (sge_length_fn)xio_sgve_length,
	.sge_set_length		= (sge_set_length_fn)xio_sgve_set_length,
	.sge_first		= (sge_first_fn)xio_sgve_first,
	.sge_last		= (sge_last_fn)xio_sgve_last,
	.sge_next		= (sge_next_fn)xio_sgve_next,
	.tbl_empty		= (tbl_empty_fn)xio_sgv_empty,
	.tbl_nents		= (tbl_nents_fn)xio_sgv_nents,
	.tbl_sglist		= (tbl_sglist_fn)xio_sgv_sglist,
	.tbl_set_nents		= (tbl_set_nents_fn)xio_sgv_set_nents,
	.tbl_max_nents		= (tbl_max_nents_fn)xio_sgv_max_nents,
	.tbl_set_max_nents	= (tbl_set_max_nents_fn)xio_sgv_set_max_nents,
	.tbl_length		= (tbl_length_fn)xio_sgv_length,
};

