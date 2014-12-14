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

#include <linux/scatterlist.h>
/* sg represents xio_sg_iovptr; */
#include "libxio.h"
#include <xio_os.h>
#include "xio_sg_table.h"

#ifdef CONFIG_DEBUG_SG
/* not defined by default */
#undef XIO_DEBUG_SG
#ifdef XIO_DEBUG_SG
static inline void verify_tbl(struct sg_table *tbl)
{
	if (tbl && tbl->sgl) {
		struct scatterlist *sg;
		int i;

		sg = tbl->sgl;
		for (i = 0; i < tbl->nents; i++) {
			if (!sg)
				break;
			BUG_ON(sg->sg_magic != SG_MAGIC);
			/* if is last is marked the next is NULL */
			sg = sg_next(sg);
		}
		BUG_ON(i != tbl->nents);
	}
}
#endif
#else
/* if CONFIG_DEBUG_SG is not defined we can't define XIO_DEBUG_SG */
#undef XIO_DEBUG_SG
#endif

/*---------------------------------------------------------------------------*/
/* xio_tble_set_buf							     */
/*---------------------------------------------------------------------------*/
static inline void xio_sg_set_buf(struct scatterlist *sg, const void *buf,
				  uint32_t buflen, void *mr)
{
#ifdef XIO_DEBUG_SG
	BUG_ON(sg->sg_magic != SG_MAGIC);
#endif
	sg_set_page(sg, virt_to_page(buf), buflen, offset_in_page(buf));
}

/*---------------------------------------------------------------------------*/
/* xio_tble_addr							     */
/*---------------------------------------------------------------------------*/
static inline void *xio_sg_addr(struct scatterlist *sg)
{
#ifdef XIO_DEBUG_SG
	BUG_ON(sg->sg_magic != SG_MAGIC);
#endif
	return sg_virt(sg);
}

/*---------------------------------------------------------------------------*/
/* xio_tble_set_addr							     */
/*---------------------------------------------------------------------------*/
static inline void xio_sg_set_addr(struct scatterlist *sg, void *addr)
{
	/* keep the length */
#ifdef XIO_DEBUG_SG
	BUG_ON(sg->sg_magic != SG_MAGIC);
#endif
	sg_set_page(sg, virt_to_page(addr), sg->length, offset_in_page(addr));
}

/*---------------------------------------------------------------------------*/
/* xio_tble_length							     */
/*---------------------------------------------------------------------------*/
static inline size_t xio_sg_length(struct scatterlist *sg)
{
#ifdef XIO_DEBUG_SG
	BUG_ON(sg->sg_magic != SG_MAGIC);
#endif
	return sg->length;
}

/*---------------------------------------------------------------------------*/
/* xio_tble_set_length							     */
/*---------------------------------------------------------------------------*/
static inline void xio_sg_set_length(struct scatterlist *sg, uint32_t length)
{
#ifdef XIO_DEBUG_SG
	BUG_ON(sg->sg_magic != SG_MAGIC);
#endif
	sg->length = length;
}

/*---------------------------------------------------------------------------*/
/* xio_tble_first							     */
/*---------------------------------------------------------------------------*/
static struct scatterlist *xio_sg_first(struct sg_table *tbl)
{
#ifdef XIO_DEBUG_SG
	verify_tbl(tbl);
#endif
	return ((!tbl || tbl->nents == 0) ? NULL : tbl->sgl);
}

/*---------------------------------------------------------------------------*/
/* xio_tble_last							     */
/*---------------------------------------------------------------------------*/
static struct scatterlist *xio_sg_last(struct sg_table *tbl)
{
#ifdef XIO_DEBUG_SG
	verify_tbl(tbl);
#endif
	return (!tbl || tbl->nents == 0) ?
		NULL : sg_last(tbl->sgl, tbl->nents);
}

/*---------------------------------------------------------------------------*/
/* xio_tble_next							     */
/*---------------------------------------------------------------------------*/
static struct scatterlist *xio_sg_next(struct sg_table *tbl,
				       struct scatterlist *tble)
{
#ifdef XIO_DEBUG_SG
	verify_tbl(tbl);
#endif
	/* Note sg_next is checking for last and returns NULL for end */
	return (!tbl || tbl->nents == 0)
			? NULL : sg_next(tble);
}

/*---------------------------------------------------------------------------*/
/* xio_tbl_sglist							     */
/*---------------------------------------------------------------------------*/
static inline struct scatterlist *xio_tbl_sglist(struct sg_table *tbl)
{
#ifdef XIO_DEBUG_SG
	verify_tbl(tbl);
#endif
	return tbl->sgl;
}

/*---------------------------------------------------------------------------*/
/* xio_tbl_nents							     */
/*---------------------------------------------------------------------------*/
static inline int xio_tbl_nents(struct sg_table *tbl)
{
#ifdef XIO_DEBUG_SG
	verify_tbl(tbl);
#endif
	return tbl->nents;
}

/*---------------------------------------------------------------------------*/
/* xio_tbl_max_nents							     */
/*---------------------------------------------------------------------------*/
static inline int xio_tbl_max_nents(struct sg_table *tbl)
{
#ifdef XIO_DEBUG_SG
	verify_tbl(tbl);
#endif
	return tbl->orig_nents;
}

/*---------------------------------------------------------------------------*/
/* xio_tbl_set_nents							     */
/*---------------------------------------------------------------------------*/
static inline void xio_tbl_set_nents(struct sg_table *tbl, uint32_t nents)
{
	struct scatterlist *sg;
	int i;

#ifdef XIO_DEBUG_SG
	verify_tbl(tbl);
#endif
	if (!tbl || tbl->orig_nents < nents)
		return;

	sg = tbl->sgl;
	/* tbl->nents is unsigned so if tbl->nents is ZERO then tbl->nents - 1
	 * is a huge number, so check this.
	 */
	if (tbl->nents && (tbl->nents < tbl->orig_nents)) {
		for (i = 0; i < tbl->nents - 1; i++)
			sg = sg_next(sg);
		sg_unmark_end(sg);
	}

	if (!nents) {
		tbl->nents = nents;
		return;
	}

	sg = tbl->sgl;
	for (i = 0; i < nents - 1; i++)
		sg = sg_next(sg);

	sg_mark_end(sg);

	tbl->nents = nents;
}

/*---------------------------------------------------------------------------*/
/* xio_tbl_empty							     */
/*---------------------------------------------------------------------------*/
static int xio_tbl_empty(struct sg_table *tbl)
{
#ifdef XIO_DEBUG_SG
	verify_tbl(tbl);
#endif
	return (!tbl || tbl->nents == 0);
}

/*---------------------------------------------------------------------------*/
/* xio_tbl_set_length							     */
/*---------------------------------------------------------------------------*/
static size_t xio_tbl_length(struct sg_table *tbl)
{
	struct scatterlist *sg;
	size_t		sz = 0;
	uint32_t	i;

#ifdef XIO_DEBUG_SG
	verify_tbl(tbl);
#endif
	sg = tbl->sgl;
	for (i = 0; i < tbl->nents; i++) {
		sz += sg->length;
		sg = sg_next(sg);
	}

	return sz;
}

/*---------------------------------------------------------------------------*/
/* sgtbl_ops_iovptr							     */
/*---------------------------------------------------------------------------*/
struct xio_sg_table_ops sgtbl_ops_sg = {
	.sge_set_buf		= (void *)xio_sg_set_buf,
	.sge_addr		= (void *)xio_sg_addr,
	.sge_set_addr		= (void *)xio_sg_set_addr,
	.sge_mr			= NULL,
	.sge_set_mr		= NULL,
	.sge_length		= (void *)xio_sg_length,
	.sge_set_length		= (void *)xio_sg_set_length,
	.sge_first		= (void *)xio_sg_first,
	.sge_last		= (void *)xio_sg_last,
	.sge_next		= (void *)xio_sg_next,
	.tbl_empty		= (void *)xio_tbl_empty,
	.tbl_nents		= (void *)xio_tbl_nents,
	.tbl_sglist		= (void *)xio_tbl_sglist,
	.tbl_set_nents		= (void *)xio_tbl_set_nents,
	.tbl_max_nents		= (void *)xio_tbl_max_nents,
	.tbl_set_max_nents	= NULL,
	.tbl_length		= (void *)xio_tbl_length,
};

