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


static uint8_t *g_hdr;
static uint8_t *g_data;
static struct xio_mr *g_data_mr;
static int g_shmid;

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
/* msg_alloc								     */
/*---------------------------------------------------------------------------*/
int msg_api_init(size_t hdrlen, size_t datalen, int is_server)
{
	int pagesize = sysconf(_SC_PAGESIZE);
	const char	*req_hdr = "hello world request header";
	const char	*req_data = "hello world request data";
	const char	*rsp_hdr =  "hello world response header";
	const char	*rsp_data = "hello world response data";
	const char	*ptr;
	int		len, i;
	unsigned char	c;

	g_hdr = NULL;
	g_data = NULL;
	if (hdrlen) {
		g_hdr = memalign(pagesize, hdrlen);
		if (!g_hdr)
			goto cleanup;
		ptr = (is_server) ? rsp_hdr : req_hdr;
		len = strlen(ptr);
		if (hdrlen < len)
			len = hdrlen;
		strncpy((char *)g_hdr, ptr, len);
		g_hdr[len] = 0;
		len++;

		for (i = len, c = 65;  i < hdrlen; i++) {
			g_hdr[i] = c;
			c++;
			if (c > 122)
				c = 65;
		}
	}
	if (datalen) {
		datalen = ALIGNHUGEPAGE(datalen);
		g_data = alloc_mem_buf(datalen, &g_shmid);
		if (!g_data)
			goto cleanup;
		ptr = (is_server) ? rsp_data : req_data;
		len = strlen(ptr);
		if (datalen < len)
			len = datalen;
		strncpy((char *)g_data, ptr, len);
		g_data[len] = 0;
		len++;

		for (i = len, c = 65;  i < datalen; i++) {
			g_data[i] = c;
			c++;
			if (c > 122)
				c = 65;
		}
		g_data_mr = xio_reg_mr(g_data, datalen);
	}
	return 0;

cleanup:
	if (g_hdr) {
		free(g_hdr);
		g_hdr = NULL;
	}

	if (g_data) {
		free_mem_buf(g_data, g_shmid);
		g_data = NULL;
	}

	return -1;
}

void msg_api_free()
{
	if (g_hdr) {
		free(g_hdr);
		g_hdr = NULL;
	}
	if (g_data_mr) {
		xio_dereg_mr(&g_data_mr);
		g_data_mr = NULL;
	}
	if (g_data) {
		free_mem_buf(g_data, g_shmid);
		g_data = NULL;
	}

}

/*---------------------------------------------------------------------------*/
/* msg_write								     */
/*---------------------------------------------------------------------------*/
void msg_write(struct xio_msg *msg,
		void *hdr, size_t hdrlen,
		void *data, size_t datalen)
{
	struct xio_vmsg  *pmsg = &msg->out;

	/* don't do the memcpy */
	pmsg->header.iov_len		= hdrlen;
	pmsg->header.iov_base		= g_hdr;

	pmsg->data_iov[0].iov_base	= g_data;
	pmsg->data_iov[0].iov_len	= datalen;
	pmsg->data_iov[0].mr		= g_data_mr;
	pmsg->data_iovlen		= g_data ? 1 : 0;

}

/*---------------------------------------------------------------------------*/
/* msg_pool_alloc							     */
/*---------------------------------------------------------------------------*/
struct msg_pool *msg_pool_alloc(int max,
		size_t out_hdrlen, size_t out_datalen,
		size_t in_hdrlen, size_t in_datalen)
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
	msg_pool->stack_ptr = msg_pool->stack;
	msg_pool->stack_end = msg_pool->stack_ptr + max;
	msg_pool->max = max;

	return msg_pool;
}

/*---------------------------------------------------------------------------*/
/* msg_reset								     */
/*---------------------------------------------------------------------------*/
inline void msg_reset(struct xio_msg *msg)
{
	msg->in.header.iov_len = 0;
	msg->in.header.iov_len = 0;
	msg->in.data_iovlen = 0;
	msg->out.data_iovlen = 0;
	msg->out.header.iov_len = 0;
	msg->next = NULL;
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
//	msg_reset(msg);
	*--pool->stack_ptr = msg;
}

/*---------------------------------------------------------------------------*/
/* msg_pool_get								     */
/*---------------------------------------------------------------------------*/
inline void msg_pool_free(struct msg_pool *pool)
{
	if (pool) {
		if (pool->mr)
			xio_dereg_mr(&pool->mr);
		if (pool->data)
			free_mem_buf(pool->data, pool->shmid);
		free(pool->header);
		free(pool);
	}
}

