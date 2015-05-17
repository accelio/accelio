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
#include <xio_os.h>
#include "xio_log.h"
#include "xio_sg_table.h"

extern struct  xio_sg_table_ops sgtbl_ops_iov;
extern struct  xio_sg_table_ops sgtbl_ops_iovptr;

void *xio_sg_table_ops_get(enum xio_sgl_type sgl_type)
{
	static void *vec[XIO_SGL_TYPE_LAST] = {
		[XIO_SGL_TYPE_IOV] = (void *)&sgtbl_ops_iov,
		[XIO_SGL_TYPE_IOV_PTR] = (void *)&sgtbl_ops_iovptr,
		[XIO_SGL_TYPE_SCATTERLIST] = NULL
	};

	return vec[sgl_type];
}
EXPORT_SYMBOL(xio_sg_table_ops_get);

/*---------------------------------------------------------------------------*/
/* tbl_clone								     */
/*---------------------------------------------------------------------------*/
int tbl_clone(struct xio_sg_table_ops *dtbl_ops, void *dtbl,
	      struct xio_sg_table_ops *stbl_ops, void *stbl)
{
	void		*dsge;
	void		*ssge;
	unsigned int	i;

	if (tbl_max_nents(dtbl_ops, dtbl) < tbl_nents(stbl_ops, stbl)) {
		ERROR_LOG("dest max nents is %d while src nents is %d\n",
			  tbl_max_nents(dtbl_ops, dtbl),
			  tbl_nents(stbl_ops, stbl));
		return -1;
	}

	tbl_set_nents(dtbl_ops, dtbl,
		      tbl_nents(stbl_ops, stbl));
	ssge = sge_first(stbl_ops, stbl);
	for_each_sge(dtbl, dtbl_ops, dsge, i) {
		sge_set_addr(dtbl_ops, dsge,
			     sge_addr(stbl_ops, ssge));
		sge_set_length(dtbl_ops, dsge,
			       sge_length(stbl_ops, ssge));

		ssge = sge_next(stbl_ops, stbl, ssge);
	}

	return 0;
}
EXPORT_SYMBOL(tbl_clone);

/*---------------------------------------------------------------------------*/
/* tbl_copy								     */
/*---------------------------------------------------------------------------*/
int tbl_copy(struct xio_sg_table_ops *dtbl_ops, void *dtbl,
	     struct xio_sg_table_ops *stbl_ops, void *stbl)
{
	void		*dsge	= sge_first(dtbl_ops, dtbl);
	void		*ssge	= sge_first(stbl_ops, stbl);
	void		*daddr	= sge_addr(dtbl_ops, dsge);
	void		*saddr	= sge_addr(stbl_ops, ssge);
	size_t		dlen	= sge_length(dtbl_ops, dsge);
	size_t		slen	= sge_length(stbl_ops, ssge);
	size_t		dnents	= tbl_nents(dtbl_ops, dtbl);
	size_t		snents	= tbl_nents(stbl_ops, stbl);

	size_t		d	= 0,
			s	= 0,
			dst_len = 0;

	if (dnents < 1 || snents < 1) {
		ERROR_LOG("nents < 1 dnents:%zd, snents:%zd\n",
			  dnents, snents);
		return 0;
	}

	while (1) {
		if (slen < dlen) {
			memcpy(daddr, saddr, slen);
			dst_len	+= slen;

			s++;
			ssge = sge_next(stbl_ops, stbl, ssge);
			if (s == snents) {
				sge_set_length(dtbl_ops, dsge, dst_len);
				d++;
				/*dsge = sge_next(dtbl_ops, dtbl, dsge);*/
				break;
			}
			dlen	-= slen;
			inc_ptr(daddr, slen);
			saddr	= sge_addr(stbl_ops, ssge);
			slen	= sge_length(stbl_ops, ssge);
		} else if (dlen < slen) {
			memcpy(daddr, saddr, dlen);
			sge_set_length(dtbl_ops, dsge, (dst_len + dlen));
			dst_len = 0;
			d++;
			dsge = sge_next(dtbl_ops, dtbl, dsge);
			if (d == dnents)
				break;
			slen	-= dlen;
			inc_ptr(saddr, dlen);
			daddr	= sge_addr(dtbl_ops, dsge);
			dlen	= sge_length(dtbl_ops, dsge);
		} else {
			memcpy(daddr, saddr, dlen);
			sge_set_length(dtbl_ops, dsge, (dst_len + dlen));
			dst_len = 0;

			d++;
			s++;
			dsge = sge_next(dtbl_ops, dtbl, dsge);
			ssge = sge_next(stbl_ops, stbl, ssge);
			if ((d == dnents) || (s == snents))
				break;

			daddr	= sge_addr(dtbl_ops, dsge);
			dlen	= sge_length(dtbl_ops, dsge);
			saddr	= sge_addr(stbl_ops, ssge);
			slen	= sge_length(stbl_ops, ssge);
		}
	}

	/* not enough buffers to complete */
	if (s < snents) {
		ERROR_LOG("dest iovec exhausted\n");
		return 0;
	}
	tbl_set_nents(dtbl_ops, dtbl, d);

	return 0;
}
EXPORT_SYMBOL(tbl_copy);

/*---------------------------------------------------------------------------*/
/* tbl_copy_sg								     */
/*---------------------------------------------------------------------------*/
int tbl_copy_sg(struct xio_sg_table_ops *dtbl_ops, void *dtbl,
		struct xio_sg_table_ops *stbl_ops, void *stbl)
{
	void		*dsge	= sge_first(dtbl_ops, dtbl);
	void		*ssge	= sge_first(stbl_ops, stbl);
	void		*daddr	= sge_addr(dtbl_ops, dsge);
	void		*saddr	= sge_addr(stbl_ops, ssge);
	size_t		dlen	= sge_length(dtbl_ops, dsge);
	size_t		slen	= sge_length(stbl_ops, ssge);
	size_t		dnents	= tbl_nents(dtbl_ops, dtbl);
	size_t		snents	= tbl_nents(stbl_ops, stbl);

	size_t		d	= 0,
			s	= 0;

	if (dnents < 1 || snents < 1) {
		ERROR_LOG("nents < 1 dnents:%zd, snents:%zd\n",
			  dnents, snents);
		return 0;
	}
	if (dnents < snents) {
		ERROR_LOG("dnents < snents dnents:%zd, snents:%zd\n",
			  dnents, snents);
		return 0;
	}

	dnents = snents;
	while (1) {
		if (slen <= dlen) {
			dlen = slen;
			memcpy(daddr, saddr, dlen);
			sge_set_length(dtbl_ops, dsge, dlen);

			d++;
			s++;
			dsge = sge_next(dtbl_ops, dtbl, dsge);
			ssge = sge_next(stbl_ops, stbl, ssge);
			if ((d == dnents) || (s == snents))
				break;

			daddr	= sge_addr(dtbl_ops, dsge);
			dlen	= sge_length(dtbl_ops, dsge);
			saddr	= sge_addr(stbl_ops, ssge);
			slen	= sge_length(stbl_ops, ssge);
		} else {
			ERROR_LOG("not enough buffer to complete " \
				  "slen:%d dlen:%d\n", slen, dlen);
			break;
		}
	}
	tbl_set_nents(dtbl_ops, dtbl, d);

	return 0;
}
EXPORT_SYMBOL(tbl_copy_sg);

