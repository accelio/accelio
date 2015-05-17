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

#ifdef __cplusplus
extern "C" {
#endif

typedef	void		(*sge_set_buf_fn)(void *sge, const void *buf,
					  uint32_t buflen, void *mr);
typedef	void		*(*sge_addr_fn)(void *sge);
typedef	void		(*sge_set_addr_fn)(void *sge, void *addr);
typedef	void		*(*sge_mr_fn)(void *sge);
typedef	void		(*sge_set_mr_fn)(void *sge, void *mr);
typedef	size_t		(*sge_length_fn)(void *sge);
typedef	void		(*sge_set_length_fn)(void *sge, size_t len);

typedef	void		*(*sge_first_fn)(void *tbl);
typedef	void		*(*sge_last_fn)(void *tbl);
typedef	void		*(*sge_next_fn)(void *tbl, void *sge);

typedef	int		(*tbl_empty_fn)(void *tbl);
typedef	void		*(*tbl_sglist_fn)(void *tbl);
typedef	uint32_t	(*tbl_nents_fn)(void *tbl);
typedef	void		(*tbl_set_nents_fn)(void *tbl, uint32_t nents);
typedef	uint32_t	(*tbl_max_nents_fn)(void *tbl);
typedef	void		(*tbl_set_max_nents_fn)(void *tbl, uint32_t max_nents);
typedef	size_t		(*tbl_length_fn)(void *tbl);

struct  xio_sg_table_ops {
	sge_set_buf_fn		sge_set_buf;
	sge_addr_fn		sge_addr;
	sge_set_addr_fn		sge_set_addr;
	sge_mr_fn		sge_mr;
	sge_set_mr_fn		sge_set_mr;
	sge_length_fn		sge_length;
	sge_set_length_fn	sge_set_length;

	sge_first_fn		sge_first;
	sge_last_fn		sge_last;
	sge_next_fn		sge_next;

	tbl_empty_fn		tbl_empty;
	tbl_sglist_fn		tbl_sglist;
	tbl_nents_fn		tbl_nents;
	tbl_set_nents_fn	tbl_set_nents;
	tbl_max_nents_fn	tbl_max_nents;
	tbl_set_max_nents_fn	tbl_set_max_nents;
	tbl_length_fn		tbl_length;
};

int tbl_copy(struct xio_sg_table_ops *dtbl_ops, void *dtbl,
	     struct xio_sg_table_ops *stbl_ops, void *stbl);

int tbl_copy_sg(struct xio_sg_table_ops *dtbl_ops, void *dtbl,
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

#define xio_sg_table_get(vmsg)	\
	((void *)&((vmsg)->data_tbl))

void *xio_sg_table_ops_get(enum xio_sgl_type sgl_type);

#ifdef __cplusplus
}
#endif

#endif
