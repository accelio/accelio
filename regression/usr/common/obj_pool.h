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
#ifndef MSG_POOL_H
#define MSG_POOL_H


#ifdef __cplusplus
extern "C" {
#endif


/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct obj_pool {
	void		**stack_ptr;
	void		**stack_end;
	void		*data;

	/* pool of tasks */
	void		**array;
	/* LIFO */
	void		**stack;

	/* max number of elements */
	int		max;
	int		nr;
};

/*---------------------------------------------------------------------------*/
/* obj_pool_get								     */
/*---------------------------------------------------------------------------*/
static inline void *obj_pool_get(struct obj_pool *q)
{
	if (q->stack_ptr != q->stack_end)
		q->nr--;

	return (q->stack_ptr != q->stack_end) ?
		*q->stack_ptr++ : NULL;
}

/*---------------------------------------------------------------------------*/
/* obj_pool_put								     */
/*---------------------------------------------------------------------------*/
static inline void obj_pool_put(struct obj_pool *q, void *t)
{
	if (++q->nr > q->max) {
		fprintf(stderr, "queue overrun\n");
		abort();
	}

	*--q->stack_ptr = t;
}

/*---------------------------------------------------------------------------*/
/* obj_pool_init							     */
/*---------------------------------------------------------------------------*/
static inline struct obj_pool *obj_pool_init(int max, size_t size,
					     void *user_context,
					     void (*obj_init)(void *, void *))
{
	int			i;
	char			*buf;
	char			*data;
	struct obj_pool		*q;
	size_t			elems_alloc_sz;


	/* pool + private data */
	size_t pool_alloc_sz = sizeof(struct obj_pool) +
				2*max*sizeof(void *);

	if (max < 1)
		return NULL;

	buf = (char *)calloc(pool_alloc_sz, sizeof(uint8_t));
	if (buf == NULL)
		return NULL;

	/* pool */
	q = (struct obj_pool *)buf;
	buf = buf + sizeof(struct obj_pool);

	/* stack */
	q->stack = (void **)buf;
	buf = buf + max*sizeof(void *);

	/* array */
	q->array = (void **)buf;
	buf = buf + max*sizeof(void *);

	/* pool data */
	elems_alloc_sz = max*size;

	data = (char *)calloc(elems_alloc_sz, sizeof(uint8_t));
	if (data == NULL) {
		free(q);
		return NULL;
	}

	for (i = 0; i < max; i++) {
		q->array[i]		= data;

		if (obj_init)
			obj_init(user_context, q->array[i]);

		q->stack[i]		= q->array[i];
		data = ((char *)data) + size;
	}

	q->data = q->array[0];
	q->stack_ptr = q->stack;
	q->stack_end = (q->stack_ptr + max);
	q->max	= max;
	q->nr	= max;

	return q;
}

/*---------------------------------------------------------------------------*/
/* obj_pool_free							     */
/*---------------------------------------------------------------------------*/
static inline void obj_pool_free(struct obj_pool *q,
				 void *user_context,
				 void (*obj_close)(void *, void *))
{
	int i;

	if (q->nr != q->max)
		fprintf(stderr, "obj_pool: destroying pool while " \
			"missing objects. %d/%d\n", q->nr, q->max);

	if (obj_close) {
		for (i = 0; i < q->max; i++) {
			obj_close(user_context, q->array[i]);
			q->array[i] = NULL;
		}
	}
	free(q->data);
	free(q);
}

#ifdef __cplusplus
}
#endif


#endif /* MSG_POOL_H */

