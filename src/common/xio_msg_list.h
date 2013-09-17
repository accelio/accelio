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
#ifndef XIO_MSG_LIST_H
#define XIO_MSG_LIST_H

#include <libxio.h>


struct xio_msg_list {
	struct xio_msg *first;			/* first element */
	struct xio_msg **last;			/* addr of last next element */
};

#define	XIO_MSG_LIST_HEAD_INITIALIZER(head)				\
	{ NULL, &(head).first }

/*
 * msg list functions.
 */
#define	xio_msg_list_init(head) do {					\
	(head)->first = NULL;						\
	(head)->last = &(head)->first;					\
} while (/*CONSTCOND*/0)

#define	xio_msg_list_insert_head(head, elm) do {			\
	if (((elm)->next = (head)->first) != NULL)			\
		(head)->first->prev =					\
		    &(elm)->next;					\
	else								\
		(head)->last = &(elm)->next;				\
	(head)->first = (elm);						\
	(elm)->prev = &(head)->first;					\
} while (/*CONSTCOND*/0)

#define	xio_msg_list_insert_tail(head, elm) do {			\
	(elm)->next = NULL;						\
	(elm)->prev = (head)->last;					\
	*(head)->last = (elm);						\
	(head)->last = &(elm)->next;					\
} while (/*CONSTCOND*/0)

#define	xio_msg_list_insert_after(head, listelm, elm) do {		\
	if (((elm)->next = (listelm)->next) != NULL)			\
		(elm)->next->prev =					\
		    &(elm)->next;					\
	else								\
		(head)->last = &(elm)->next;				\
	(listelm)->next = (elm);					\
	(elm)->prev = &(listelm)->next;					\
} while (/*CONSTCOND*/0)

#define	xio_msg_list_insert_before(listelm, elm) do {			\
	(elm)->prev = (listelm)->prev;					\
	(elm)->next = (listelm);					\
	*(listelm)->prev = (elm);					\
	(listelm)->prev = &(elm)->next;					\
} while (/*CONSTCOND*/0)

#define	xio_msg_list_remove(head, elm) do {				\
	if (((elm)->next) != NULL)					\
		(elm)->next->prev =					\
		    (elm)->prev;					\
	else								\
		(head)->last = (elm)->prev;				\
	*(elm)->prev = (elm)->next;					\
} while (/*CONSTCOND*/0)

#define	xio_msg_list_foreach(var, head)					\
	for ((var) = ((head)->first);					\
		(var);							\
		(var) = ((var)->next))

#define	xio_msg_list_foreach_reverse(var, head, headname)		\
	for ((var) = (*(((struct headname *)((head)->last))->last));	\
		(var);							\
		(var) = (*(((struct headname *)((var)->prev))->last)))

#define xio_msg_list_foreach_safe(var, head, tvar)			\
	for ((var) = xio_msg_list_first((head));                        \
		(var) && ((tvar) = xio_msg_list_next((var)), 1);	\
		(var) = (tvar))

#define	xio_msg_list_concat(head1, head2) do {				\
	if (!xio_msg_list_empty(head2)) {				\
		*(head1)->last = (head2)->first;			\
		(head2)->first->prev = (head1)->last;			\
		(head1)->last = (head2)->last;				\
		xio_msg_list_init((head2));				\
	}								\
} while (/*CONSTCOND*/0)

#define	xio_msg_list_splice(head, elm) do {			\
	struct xio_msg *curelm = (elm),  *nextelm;		\
	do {							\
		nextelm = (curelm)->next;			\
		xio_msg_list_insert_tail((head), (curelm));	\
		curelm = nextelm;				\
	} while (curelm != NULL);				\
} while (/*CONSTCOND*/0)

/*
 * message list access methods.
 */
#define	xio_msg_list_empty(head)		((head)->first == NULL)
#define	xio_msg_list_first(head)		((head)->first)
#define	xio_msg_list_next(elm)		((elm)->next)

#define	xio_msg_list_last(head, headname) \
	(*(((struct headname *)((head)->last))->last))
#define	xio_msg_list_prev(elm, headname) \
	(*(((struct headname *)((elm)->prev))->last))

#endif /* XIO_MSG_LIST_H */
