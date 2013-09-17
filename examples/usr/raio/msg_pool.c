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

#include <msg_pool.h>


#define HUGE_PAGE_SZ (2*1024*1024)
#define ALIGNHUGEPAGE(x)   (size_t)((~(HUGE_PAGE_SZ - 1)) & \
				    ((x) + HUGE_PAGE_SZ - 1))

struct msg_pool {
	/* pool of msgs */
	struct xio_msg				**array;
	/* LIFO */
	struct xio_msg				**stack;

	struct xio_msg				**stack_ptr;
	struct xio_msg				**stack_end;
	void						*header;
	void						*data;

	struct xio_mr					*mr;
	/* max number of elements */
	size_t						max;
	int						in_hdrlen;
	int						in_datalen;
	int						shmid;
	int						pad;
};

/*---------------------------------------------------------------------------*/
/* alloc_mem_buf	                                                     */
/*---------------------------------------------------------------------------*/
static uint8_t *alloc_mem_buf(size_t pool_size, int *shmid)
{
	int shmemid;
	uint8_t *buf;

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
	buf = shmat(shmemid, NULL, 0);

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
	return memalign(sysconf(_SC_PAGESIZE), pool_size);
}

/*---------------------------------------------------------------------------*/
/* free_mem_buf								     */
/*---------------------------------------------------------------------------*/
static void free_mem_buf(uint8_t *pool_buf, int shmid)
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
static struct msg_pool *msg_pool_alloc(int max,
		size_t out_hdrlen, int out_datalen,
		size_t in_hdrlen, int in_datalen)
{
	struct msg_pool		*msg_pool;
	struct xio_msg	*msg;
	size_t			len;
	size_t			hdrlen;
	size_t			datalen;
	int			i;
	uint8_t			*buf;
	uint8_t			*header;
	uint8_t			*data;


	/* allocate the structures */
	len = sizeof(struct msg_pool)+
		max*(2*sizeof(struct xio_msg *)+sizeof(struct xio_msg));

	buf = calloc(len, sizeof(uint8_t));
	if (!buf) {
		fprintf(stderr, "Couldn't allocate message pool\n");
		exit(1);
	}

	datalen = max*(out_datalen + in_datalen);
	hdrlen	= max*(out_hdrlen + in_hdrlen);

	/* pool */
	msg_pool =  (struct msg_pool *)buf;
	buf = buf + sizeof(struct msg_pool);

	/* stack */
	msg_pool->stack = (struct xio_msg **)buf;
	buf = buf + max * sizeof(struct xio_msg *);

	/* array */
	msg_pool->array = (struct xio_msg **)buf;
	buf = buf + max * sizeof(struct xio_msg *);

	/* header */
	msg_pool->header = calloc(hdrlen, sizeof(uint8_t));
	if (!buf) {
		fprintf(stderr, "Couldn't allocate message pool\n");
		exit(1);
	}

	/* data */
	if (datalen) {
		datalen = ALIGNHUGEPAGE(datalen);
		msg_pool->data = alloc_mem_buf(datalen, &msg_pool->shmid);
		if (!msg_pool->data) {
			fprintf(stderr, "Couldn't allocate data buffers\n");
			free(buf);
			exit(1);
		}
		memset(msg_pool->data, 0, datalen);
		msg_pool->mr = xio_reg_mr(msg_pool->data, datalen);
	}


	data = msg_pool->data;
	header = msg_pool->header;

	for (i = 0; i < max; i++) {
		msg_pool->array[i] = (struct xio_msg *)buf;
		buf = buf + sizeof(struct xio_msg);

		msg = msg_pool->array[i];
		msg_pool->stack[i] = msg;

		if (out_hdrlen) {
			msg->out.header.iov_base = header;
			msg->out.header.iov_len = out_hdrlen;
			header = header + out_hdrlen;
		}
		if (out_datalen) {
			msg->out.data_iov[0].iov_base = data;
			msg->out.data_iov[0].iov_len = out_datalen;
			msg->out.data_iov[0].mr = msg_pool->mr;
			data = data + out_datalen;
			msg->out.data_iovlen = 1;
		}
		if (in_hdrlen) {
			msg->in.header.iov_base = header;
			msg->in.header.iov_len = in_hdrlen;
			header = header + in_hdrlen;
		}
		if (in_datalen) {
			msg->in.data_iov[0].iov_base = data;
			msg->in.data_iov[0].iov_len = in_datalen;
			msg->in.data_iov[0].mr = msg_pool->mr;
			data = data + in_datalen;
			msg->in.data_iovlen = 1;
		}
	}
	msg_pool->in_hdrlen	= in_hdrlen;
	msg_pool->in_datalen	= in_datalen;

	msg_pool->stack_ptr = msg_pool->stack;
	msg_pool->stack_end = msg_pool->stack_ptr + max;
	msg_pool->max = max;

	return msg_pool;
}

/*---------------------------------------------------------------------------*/
/* msg_pool_create							     */
/*---------------------------------------------------------------------------*/
struct msg_pool *msg_pool_create(size_t hdr_size, size_t data_size,
				 int num_of_msgs)
{
	return msg_pool_alloc(num_of_msgs, hdr_size,
			       data_size, 0, 0);
}

/*---------------------------------------------------------------------------*/
/* msg_pool_delete							     */
/*---------------------------------------------------------------------------*/
void msg_pool_delete(struct msg_pool *pool)
{
	if (pool) {
		xio_dereg_mr(&pool->mr);
		if (pool->data)
			free_mem_buf(pool->data, pool->shmid);
		free(pool->header);
		free(pool);
	}
}

/*---------------------------------------------------------------------------*/
/* msg_pool_get								     */
/*---------------------------------------------------------------------------*/
struct xio_msg *msg_pool_get(struct msg_pool *pool)
{
	return (pool->stack_ptr == pool->stack_end) ? NULL :
		*pool->stack_ptr++;
}

/*---------------------------------------------------------------------------*/
/* msg_pool_get								     */
/*---------------------------------------------------------------------------*/
void msg_pool_put(struct msg_pool *pool, struct xio_msg *msg)
{
	msg->in.header.iov_len = 0;
	msg->in.data_iovlen = 0;
	msg->out.data_iovlen = 0;
	msg->out.header.iov_len = 0;

	*--pool->stack_ptr = msg;
}


/*---------------------------------------------------------------------------*/
/* msg_pool_get_array							     */
/*---------------------------------------------------------------------------*/
int msg_pool_get_array(struct msg_pool *pool, struct xio_msg **vec,
		       int veclen)
{
	int i;

	for (i = 0; i < veclen; i++) {
		vec[i] = msg_pool_get(pool);
		if (vec[i] == NULL)
			break;
	}
	return i;
}

/*---------------------------------------------------------------------------*/
/* msg_pool_put_array							     */
/*---------------------------------------------------------------------------*/
void msg_pool_put_array(struct msg_pool *pool, struct xio_msg **vec,
		       int veclen)
{
	int i;

	for (i = 0; i < veclen; i++)
		msg_pool_put(pool, vec[i]);
}

/*---------------------------------------------------------------------------*/
/* msg_reset								     */
/*---------------------------------------------------------------------------*/
void msg_reset(struct xio_msg *msg)
{
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	msg->in.data_iovlen = 0;
	msg->out.data_iovlen = 0;
	msg->out.header.iov_len = 0;
}


