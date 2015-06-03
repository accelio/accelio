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
static void *alloc_mem_buf(size_t pool_size, int *shmid)
{
	int	shmemid = 0;
	void	*buf = NULL;
	int	pagesz;

	/* allocate memory */
	shmemid = shmget(IPC_PRIVATE, pool_size,
			 SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W);
	if (shmemid < 0) {
		fprintf(stderr,
			"warning - failed to allocate %zu bytes with " \
			"hugepages. (errno=%d %m)\n", pool_size, errno);
		fprintf(stderr,
			"check that hugepages are configured. " \
			"falling back to 4K pages allocations...\n");
		goto failed_huge_page;
	}

	/* get pointer to allocated memory */
	buf = shmat(shmemid, NULL, 0);
	if (!buf || buf == (void *)-1) {
		fprintf(stderr, "shmat failure (errno=%d %m)\n", errno);
		shmctl(shmemid, IPC_RMID, NULL);
		goto failed_huge_page;
	}

	/* mark 'to be destroyed' when process detaches from shmem segment
	   this will clear the HugePage resources even if process if killed
	   not nicely. From checking shmctl man page it is unlikely that it
	   will fail here.
	*/
	if (shmctl(shmemid, IPC_RMID, NULL) != 0) {
		fprintf(stderr,
			"shmctl mark 'todo destroyed' failed %m\n");
	}

	*shmid = shmemid;
	return buf;

failed_huge_page:
	*shmid = -1;
	pagesz = sysconf(_SC_PAGESIZE);
	if (pagesz < 0)
		return NULL;

	buf = memalign(pagesz, pool_size);
	if (!buf)
		return NULL;

	return buf;
}

/*---------------------------------------------------------------------------*/
/* free_mem_buf								     */
/*---------------------------------------------------------------------------*/
inline void free_mem_buf(void *pool_buf, int shmid)
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
/* msg_api_free								     */
/*---------------------------------------------------------------------------*/
void msg_api_free(struct msg_params *msg_params)
{
	if (msg_params->g_hdr) {
		free(msg_params->g_hdr);
		msg_params->g_hdr = NULL;
	}
	if (msg_params->g_data_mr) {
		struct xio_reg_mem reg_mem;
		reg_mem.mr = msg_params->g_data_mr;
		xio_mem_dereg(&reg_mem);
		msg_params->g_data_mr = NULL;
	}
	if (msg_params->g_data) {
		free_mem_buf(msg_params->g_data, msg_params->g_shmid);
		msg_params->g_data = NULL;
	}
}

/*---------------------------------------------------------------------------*/
/* msg_api_init								     */
/*---------------------------------------------------------------------------*/
int msg_api_init(struct msg_params *msg_params,
		 size_t hdrlen, size_t datalen, int is_server)
{
	const char	*req_hdr = "hello world request header";
	const char	*req_data = "hello world request data";
	const char	*rsp_hdr =  "hello world response header";
	const char	*rsp_data = "hello world response data";
	const char	*ptr;
	size_t		len;
	int		pagesize = sysconf(_SC_PAGESIZE);
	struct xio_reg_mem reg_mem;

	if (pagesize < 0)
		return -1;

	msg_params->g_hdr = NULL;
	msg_params->g_data = NULL;
	if (hdrlen) {
		msg_params->g_hdr = (uint8_t *)memalign(pagesize, hdrlen);
		if (!msg_params->g_hdr)
			goto cleanup;
		ptr = (is_server) ? rsp_hdr : req_hdr;
		len = strlen(ptr);
		if (hdrlen <= len)
			len = hdrlen - 1;
		if (len)
			strncpy((char *)msg_params->g_hdr, ptr, len);
		msg_params->g_hdr[len] = 0;
	}
	if (datalen) {
		datalen = ALIGNHUGEPAGE(datalen);
		msg_params->g_data = (uint8_t *)alloc_mem_buf(datalen,
						   &msg_params->g_shmid);
		if (!msg_params->g_data)
			goto cleanup;
		ptr = (is_server) ? rsp_data : req_data;
		len = strlen(ptr);
		if (datalen <= len)
			len = datalen - 1;
		if (len)
			strncpy((char *)msg_params->g_data, ptr, len);
		msg_params->g_data[len] = 0;

		xio_mem_register(msg_params->g_data, datalen, &reg_mem);
		msg_params->g_data_mr = reg_mem.mr;
		if (!msg_params->g_data_mr)
			goto cleanup;
	}
	return 0;

cleanup:
	msg_api_free(msg_params);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* msg_build_out_sgl							     */
/*---------------------------------------------------------------------------*/
void msg_build_out_sgl(struct msg_params *msg_params,
		       struct xio_msg *msg,
		       size_t hdrlen,
		       size_t data_iovlen, size_t datalen)
{
	struct xio_vmsg		*pmsg = &msg->out;
	struct xio_iovec_ex	*sglist = vmsg_sglist(pmsg);
	int			nents;
	int			i;

	/* don't do the memcpy */
	pmsg->header.iov_len		= hdrlen;
	pmsg->header.iov_base		= msg_params->g_hdr;
	nents				= datalen ? data_iovlen : 0;

	vmsg_sglist_set_nents(pmsg, nents);

	for (i = 0; i < nents; i++) {
		sglist[i].iov_base	= msg_params->g_data;
		sglist[i].iov_len	= datalen;
		sglist[i].mr		= msg_params->g_data_mr;
	}
}

/*---------------------------------------------------------------------------*/
/* msg_pool_alloc							     */
/*---------------------------------------------------------------------------*/
struct msg_pool *msg_pool_alloc(int max, int in_iovsz, int out_iovsz)
{
	struct msg_pool		*msg_pool;
	struct xio_msg		*msg;
	size_t			len;
	int			i;
	uint8_t			*buf;


	/* allocate the structures */
	len = sizeof(struct msg_pool) +
		max*(2*sizeof(struct xio_msg *)+sizeof(struct xio_msg));

	if (in_iovsz <= XIO_IOVLEN)
		in_iovsz = 0;

	if (out_iovsz <= XIO_IOVLEN)
		out_iovsz = 0;

	len += max*(in_iovsz + out_iovsz)*sizeof(struct xio_iovec_ex);

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

		if (in_iovsz) {
			msg->in.sgl_type	   = XIO_SGL_TYPE_IOV_PTR;
			msg->in.pdata_iov.max_nents = in_iovsz;
			msg->in.pdata_iov.sglist   = (struct xio_iovec_ex *)buf;
			buf = buf + in_iovsz*sizeof(struct xio_iovec_ex);
		} else {
			msg->in.sgl_type  = XIO_SGL_TYPE_IOV;
		}

		if (out_iovsz) {
			msg->out.sgl_type  = XIO_SGL_TYPE_IOV_PTR;
			msg->out.pdata_iov.max_nents = out_iovsz;
			msg->out.pdata_iov.sglist  = (struct xio_iovec_ex *)buf;
			buf = buf + out_iovsz*sizeof(struct xio_iovec_ex);
		} else {
			msg->out.sgl_type  = XIO_SGL_TYPE_IOV;
		}
		msg_pool->stack[i] = msg;
	}
	msg_pool->stack_ptr = msg_pool->stack;
	msg_pool->stack_end = msg_pool->stack_ptr + max;
	msg_pool->max = max;
	msg_pool->free = max;

	return msg_pool;
}

/*---------------------------------------------------------------------------*/
/* msg_pool_get								     */
/*---------------------------------------------------------------------------*/
inline struct xio_msg *msg_pool_get(struct msg_pool *pool)
{
	if (pool->stack_ptr == pool->stack_end)
		return NULL;

	pool->free--;
	return *pool->stack_ptr++;
}

/*---------------------------------------------------------------------------*/
/* msg_pool_put								     */
/*---------------------------------------------------------------------------*/
inline void msg_pool_put(struct msg_pool *pool, struct xio_msg *msg)
{
	if (pool->stack_ptr == pool->stack)
		return;
	pool->free++;
	*--pool->stack_ptr = msg;
}

/*---------------------------------------------------------------------------*/
/* msg_pool_free							     */
/*---------------------------------------------------------------------------*/
inline void msg_pool_free(struct msg_pool *pool)
{
	if (pool)
		free(pool);
}

