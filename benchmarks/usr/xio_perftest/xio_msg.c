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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>


#include "xio_msg.h"

#ifndef roundup
# define roundup(x, y)  ((((x) + ((y) - 1)) / (y)) * (y))
#endif /* !defined(roundup) */

#define HUGE_PAGE_SZ (2*1024*1024)
#define ALIGNHUGEPAGE(x) \
	(size_t)((~(HUGE_PAGE_SZ - 1)) & ((x) + HUGE_PAGE_SZ - 1))


/*---------------------------------------------------------------------------*/
/* alloc_mem_buf	                                                     */
/*---------------------------------------------------------------------------*/
uint8_t *alloc_mem_buf(size_t pool_size, int *shmid)
{
	int shmemid;
	uint8_t *buf;
	int	pagesz;

	/* allocate memory */
	shmemid = shmget(IPC_PRIVATE, pool_size,
			SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W);

	if (shmemid < 0) {
		fprintf(stderr,
			"shmget rdma pool sz:%zu failed (errno=%d %m)\n",
			pool_size, errno);
		goto failed_huge_page;
	}

	/* get pointer to allocated memory */
	buf = (uint8_t *)shmat(shmemid, NULL, 0);

	if (buf == (void *)-1) {
		fprintf(stderr, "shmat failure (errno=%d %m)\n", errno);
		shmctl(shmemid, IPC_RMID, NULL);
		goto failed_huge_page;
	}

	/* mark 'to be destroyed' when process detaches from shmem segment
	   this will clear the HugePage resources even if process if killed
	   not nicely. From checking shmctl man page it is unlikely that it
	   will fail here.
	*/
	if (shmctl(shmemid, IPC_RMID, NULL))
		fprintf(stderr,
			"shmctl mark 'todo destroyed' failed (errno=%d %m)\n",
			errno);

	*shmid = shmemid;
	return buf;

failed_huge_page:
	*shmid = -1;
		pagesz = sysconf(_SC_PAGESIZE);
	if (pagesz < 0)
		return NULL;

	buf = (uint8_t *)memalign(pagesz, pool_size);
	if (!buf)
		return NULL;

	return buf;
}

/*---------------------------------------------------------------------------*/
/* free_mem_buf								     */
/*---------------------------------------------------------------------------*/
inline void free_mem_buf(uint8_t *pool_buf, int shmid)
{
	if (shmid >= 0) {
		if (shmdt(pool_buf) != 0) {
			fprintf(stderr, "shmem detach failure (errno=%d %m)\n",
				errno);
		}

	} else {
		free(pool_buf);
	}
}

/*---------------------------------------------------------------------------*/
/* msg_pool_alloc							     */
/*---------------------------------------------------------------------------*/
struct msg_pool *msg_pool_alloc(int max)
{
	struct msg_pool		*msg_pool;
	struct xio_msg		*msg;
	size_t			len;
	int			i;
	uint8_t			*buf;

	/* allocate the structures */
	len = sizeof(struct msg_pool)+
		max*(2*sizeof(struct xio_msg *)+sizeof(struct xio_msg));

	buf = (uint8_t *)calloc(len, sizeof(uint8_t));
	if (!buf) {
		fprintf(stderr, "Couldn't allocate message pool\n");
		exit(1);
	}

	/* pool */
	msg_pool =  (struct msg_pool *)buf;
	buf = buf + sizeof(struct msg_pool);

	/* stack */
	msg_pool->stack = (struct xio_msg **)buf;
	buf = buf + max * sizeof(struct xio_msg *);

	/* array */
	msg_pool->array = (struct xio_msg **)buf;
	buf = buf + max * sizeof(struct xio_msg *);

	for (i = 0; i < max; i++) {
		msg_pool->array[i] = (struct xio_msg *)buf;
		buf = buf + sizeof(struct xio_msg);

		msg = msg_pool->array[i];
		msg_pool->stack[i] = msg;
	}
	msg_pool->stack_ptr = msg_pool->stack;
	msg_pool->stack_end = msg_pool->stack_ptr + max;
	msg_pool->max = max;

	return msg_pool;
}
/*---------------------------------------------------------------------------*/
/* msg_pool_get								     */
/*---------------------------------------------------------------------------*/
inline struct xio_msg *msg_pool_get(struct msg_pool *pool)
{
	return (pool->stack_ptr == pool->stack_end) ? NULL :
		*pool->stack_ptr++;
}

/*---------------------------------------------------------------------------*/
/* msg_pool_put								     */
/*---------------------------------------------------------------------------*/
inline void msg_pool_put(struct msg_pool *pool, struct xio_msg *msg)
{
	*--pool->stack_ptr = msg;
}

/*---------------------------------------------------------------------------*/
/* msg_pool_get								     */
/*---------------------------------------------------------------------------*/
inline void msg_pool_free(struct msg_pool *pool)
{
	free(pool);
}


/*---------------------------------------------------------------------------*/
/* msg_pool_get								     */
/*---------------------------------------------------------------------------*/
struct perf_buf *xio_buf_alloc(size_t size)
{
	struct perf_buf		*pbuf;
	struct xio_reg_mem	reg_mem;

	pbuf = (struct perf_buf *)calloc(1, sizeof(*pbuf));

	pbuf->addr = alloc_mem_buf(ALIGNHUGEPAGE(size) , &pbuf->shmid);
	pbuf->length = size;
	xio_mem_register(pbuf->addr, pbuf->length, &reg_mem);
	pbuf->mr = reg_mem.mr;

	return pbuf;

}

void  xio_buf_free(struct perf_buf *pbuf)
{
	if (pbuf->mr) {
		struct xio_reg_mem	reg_mem;

		reg_mem.mr = pbuf->mr;
		xio_mem_dereg(&reg_mem);
	}

	if (pbuf->addr)
		free_mem_buf((uint8_t *)pbuf->addr, pbuf->shmid);

	free(pbuf);
}

