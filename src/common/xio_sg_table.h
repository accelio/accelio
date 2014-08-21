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

#ifndef XIO_SG_TABLE_OPS
#define XIO_SG_TABLE_OPS

#include "libxio.h"

struct  xio_sg_table_ops {
	void		(*sge_set_buf)(void *sge, const void *buf,
				       uint32_t buflen, void *mr);
	void		*(*sge_addr)(void *sge);
	void		(*sge_set_addr)(void *sge, void *addr);
	void		*(*sge_mr)(void *sge);
	void		(*sge_set_mr)(void *sge, void *mr);
	size_t		(*sge_length)(void *sge);
	void		(*sge_set_length)(void *sge, size_t len);

	void		*(*sge_first)(void *tbl);
	void		*(*sge_last)(void *tbl);
	void		*(*sge_next)(void *tbl, void *sge);

	int		(*tbl_empty)(void *tbl);
	void		*(*tbl_sglist)(void *tbl);
	uint32_t	(*tbl_nents)(void *tbl);
	void		(*tbl_set_nents)(void *tbl, uint32_t nents);
	uint32_t	(*tbl_max_nents)(void *tbl);
	void		(*tbl_set_max_nents)(void *tbl, uint32_t max_nents);
	size_t		(*tbl_length)(void *tbl);
};

int tbl_copy(struct xio_sg_table_ops *dtbl_ops, void *dtbl,
	     struct xio_sg_table_ops *stbl_ops, void *stbl);

int tbl_clone(struct xio_sg_table_ops *dtbl_ops, void *dtbl,
	      struct xio_sg_table_ops *stbl_ops, void *stbl);

#define sge_set_buf(ops, sge, buf, buflen, mr)		\
		((ops)->sge_set_buf((sge), (buf), (buflen), (mr)))
#define sge_addr(ops, sge)				\
		((ops)->sge_addr((sge)))
#define sge_set_addr(ops, sge, addr)			\
		((ops)->sge_set_addr((sge), (addr)))
#define sge_mr(ops, sge)				\
		((ops)->sge_mr((sge)))
#define sge_set_mr(ops, sge, mr)			\
		((ops)->sge_set_mr((sge), (mr)))
#define sge_length(ops, sge)				\
		((ops)->sge_length((sge)))
#define sge_set_length(ops, sge, len)			\
		((ops)->sge_set_length((sge), (len)))
#define sge_first(ops, tbl)				\
		((ops)->sge_first((tbl)))
#define sge_last(ops, tbl)				\
		((ops)->sge_last((tbl)))
#define sge_next(ops, tbl, sge)				\
		((ops)->sge_next((tbl), (sge)))
#define tbl_empty(ops, tbl)				\
		((ops)->tbl_empty((tbl)))
#define tbl_nents(ops, tbl)				\
		((ops)->tbl_nents((tbl)))
#define tbl_sglist(ops, tbl)				\
		((ops)->tbl_sglist((tbl)))
#define tbl_max_nents(ops, tbl)				\
		((ops)->tbl_max_nents((tbl)))
#define tbl_set_nents(ops, tbl, nents)			\
		((ops)->tbl_set_nents((tbl), nents))
#define tbl_set_max_nents(ops, tbl, max_nents)	\
		((ops)->tbl_set_max_nents((tbl), max_nents))
#define tbl_length(ops, tbl)				\
		((ops)->tbl_length((tbl)))

#define for_each_sge(sgtbl, ops, sg, __i)			\
	for ((__i) = 0, (sg) = sge_first((ops), (sgtbl));	\
	     (__i) < tbl_nents((ops), (sgtbl));			\
	     (__i)++, (sg) = sge_next((ops), (sgtbl), (sg)))


static inline void *xio_sg_table_get(struct xio_vmsg *vmsg)
{
	return (void *)&((vmsg)->data_iov);
}

void *xio_sg_table_ops_get(enum xio_sgl_type sgl_type);


#endif
