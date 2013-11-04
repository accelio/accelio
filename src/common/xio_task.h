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
#ifndef XIO_TASK_H
#define XIO_TASK_H

#include "libxio.h"
#include "xio_mbuf.h"

enum xio_task_state {
	XIO_TASK_STATE_INIT,
	XIO_TASK_STATE_DELIVERED,
	XIO_TASK_STATE_READ,
	XIO_TASK_STATE_RESPONSE_RECV,  /* mark the sender task */
	XIO_TASK_STATE_CANCEL_PENDING,      /* mark for rdma read task */
};

typedef void (*release_task_fn)(struct kref *kref);

/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct xio_task {
	struct list_head	tasks_list_entry;
	void			*dd_data;
	struct xio_mbuf		mbuf;
	struct xio_task		*sender_task;  /* client only on receiver */
	struct xio_msg		*omsg;		/* pointer from user */
	struct xio_session	*session;
	struct xio_conn		*conn;
	struct xio_connection	*connection;

	void			*pool;
	release_task_fn		release;

	enum xio_task_state	state;		/* task state enum	*/
	struct kref		kref;
	uint64_t		magic;
	uint64_t		stag;		/* session unique tag */
	uint16_t		tlv_type;
	uint16_t		force_signal;
	uint32_t		ltid;		/* local task id	*/
	uint32_t		rtid;		/* remote task id	*/
	uint32_t		omsg_flags;
	struct xio_msg		imsg;		/* message to the user */

};

struct xio_tasks_pool {
	/* pool of tasks */
	struct xio_task		**array;
	/* LIFO */
	struct list_head	stack;

	/* max number of elements */
	int			max;
	int			nr;
	void			*dd_data;
	void			*pool_ops;
};

/*---------------------------------------------------------------------------*/
/* xio_task_add_ref							     */
/*---------------------------------------------------------------------------*/
static inline void xio_task_addref(
			struct xio_task *t)
{
	kref_get(&t->kref);
}

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_free						     */
/*---------------------------------------------------------------------------*/
void xio_tasks_pool_free(struct xio_tasks_pool *q);

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_init						     */
/*---------------------------------------------------------------------------*/
struct xio_tasks_pool *xio_tasks_pool_init(int max,
			int pool_dd_data_sz,
			int task_dd_data_sz,
			void *pool_ops);

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_get							     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_tasks_pool_get(
			struct xio_tasks_pool *q)
{
	struct xio_task *t;


	if (list_empty(&q->stack))
		return NULL;

	t = list_first_entry(&q->stack, struct xio_task,  tasks_list_entry);
	list_del_init(&t->tasks_list_entry);
	q->nr--;
	kref_init(&t->kref);
	t->tlv_type = 0xbeef;  /* poison the type */
	return t;
}

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_put							     */
/*---------------------------------------------------------------------------*/
static inline void xio_tasks_pool_put(struct xio_task *task)
{
	kref_put(&task->kref, task->release);
}

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_free_tasks						     */
/*---------------------------------------------------------------------------*/
static inline int xio_tasks_pool_free_tasks(
			struct xio_tasks_pool *q)
{
	if (!q)
		return 0;

	if (q->nr != q->max)
		ERROR_LOG("tasks inventory: %d/%d = missing:%d\n",
			  q->nr, q->max, q->max-q->nr);
	return q->nr;
}

/*---------------------------------------------------------------------------*/
/* xio_tasks_pool_lookup						     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_tasks_pool_lookup(
			struct xio_tasks_pool *q,
			int id)
{
	return  ((id < q->max) ? q->array[id] : NULL);
}

#endif

