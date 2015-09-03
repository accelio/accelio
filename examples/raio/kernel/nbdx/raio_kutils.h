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

#ifndef RAIO_KUTILS_H
#define RAIO_KUTILS_H

#include <linux/blkdev.h>
#include <linux/scatterlist.h>
#include "libxio.h"

#define SUBMIT_BLOCK_SIZE				\
	+ sizeof(uint32_t) /* raio_filedes */		\
	+ sizeof(uint32_t) /* raio_lio_opcode */	\
	+ sizeof(uint64_t) /* nbytes */			\
	+ sizeof(uint64_t) /* offset */

#define STAT_BLOCK_SIZE					\
	+ sizeof(uint64_t) /* dev */			\
	+ sizeof(uint64_t) /* ino */			\
	+ sizeof(uint32_t) /* mode */			\
	+ sizeof(uint32_t) /* nlink */                  \
	+ sizeof(uint64_t) /* uid */			\
	+ sizeof(uint64_t) /* gid */			\
	+ sizeof(uint64_t) /* rdev */			\
	+ sizeof(uint64_t) /* size */                   \
	+ sizeof(uint32_t) /* blksize */                \
	+ sizeof(uint32_t) /* blocks */                 \
	+ sizeof(uint64_t) /* atime */                  \
	+ sizeof(uint64_t) /* mtime */                  \
	+ sizeof(uint64_t) /* ctime */

struct r_stat64 {
	uint64_t     st_dev;     /* ID of device containing file */
	uint64_t     st_ino;     /* inode number */
	uint32_t    st_mode;    /* protection */
	uint32_t   st_nlink;   /* number of hard links */
    uint64_t     st_uid;     /* user ID of owner */
    uint64_t     st_gid;     /* group ID of owner */
    uint64_t     st_rdev;    /* device ID (if special file) */
    uint64_t     st_size;    /* total size, in bytes */
    uint32_t st_blksize; /* blocksize for file system I/O */
    uint32_t  st_blocks;  /* number of 512B blocks allocated */
    uint64_t    st_atime;   /* time of last access */
    uint64_t    st_mtime;   /* time of last modification */
    uint64_t    st_ctime;   /* time of last status change */
};

/* session data for raio open, close, fstat*/
struct raio_session_data {
	struct xio_session *session;
	struct xio_context *ctx;
	struct xio_connection *conn;
	struct xio_msg req;
	struct xio_msg *rsp;
};

/** answer to client */
struct raio_answer {
	uint32_t command;
	uint32_t data_len;
	int32_t ret;
	int32_t ret_errno;
};

/** command for server */
struct raio_command {
	uint32_t command;
	uint32_t data_len;
};


/*---------------------------------------------------------------------------*/
/* enums								     */
/*---------------------------------------------------------------------------*/
enum raio_iocb_cmd {
	RAIO_CMD_PREAD		= 0,
	RAIO_CMD_PWRITE		= 1,
};

struct raio_iocb_common {
	void			*buf;
	unsigned long long	nbytes;
	long long		offset;
	unsigned int		flags;
	unsigned int		resfd;
};	/* result code is the amount read or negative errno */

struct raio_iocb {
	void			*data;  /* Return in the io completion event */
	unsigned int		key;	/* For use in identifying io requests */
	int			raio_fildes;
	int			raio_lio_opcode;
	int			pad;
	union {
		struct raio_iocb_common	c;
	} u;
};

#define LAST_IN_BATCH sizeof(uint32_t)

#define SUBMIT_HEADER_SIZE (SUBMIT_BLOCK_SIZE +	    \
			    LAST_IN_BATCH +	    \
			    sizeof(struct raio_command))

#define MAX_SGL_LEN 128

struct raio_io_u {
	struct scatterlist  sgl[MAX_SGL_LEN];
	struct raio_iocb		iocb;
	struct request		       *breq;
	struct xio_msg			req;
	struct xio_msg		       *rsp;
	int				res;
	int				res2;
	struct raio_answer		ans;
	struct list_head		list;

	char				req_hdr[SUBMIT_HEADER_SIZE];
};

/** commands for raio server */
enum raio_server_commands {
	RAIO_CMD_FIRST		= 0,
	RAIO_CMD_UNKNOWN	= 1,

	/* raio commands */
	RAIO_CMD_OPEN		= 10,
	RAIO_CMD_FSTAT,
	RAIO_CMD_CLOSE,
	RAIO_CMD_IO_SETUP,
	RAIO_CMD_IO_SUBMIT,
	RAIO_CMD_IO_RELEASE,
	RAIO_CMD_IO_DESTROY,

	RAIO_CMD_LAST
};


const char *unpack_stat64(struct r_stat64 *result, const char *buffer);

void pack_open_command(const char *pathname, int flags,
		       void *buf, size_t *len);
void pack_close_command(int fd, void *buf, size_t *len);
void pack_fstat_command(int fd, void *buf, size_t *len);
void pack_destroy_command(void *buf, size_t *len);


int unpack_open_answer(char *buf, size_t len, int *fd);
int unpack_close_answer(char *buf, size_t len);
int unpack_fstat_answer(char *buf, size_t len, struct r_stat64 *stbuf);
int unpack_setup_answer(char *buf, size_t len);
int unpack_destroy_answer(char *buf, size_t len);

char *pack_iocb(struct raio_iocb *iocb, char *buffer);
void pack_submit_command(struct raio_iocb *iocb, int is_last_in_batch,
			 void *buf, size_t *len);

void pack_setup_command(int queues, int qdepth, void *buf, size_t *len);

static inline void raio_prep_pread(struct raio_iocb *iocb,
		int fd, long long offset)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->raio_fildes = fd;
	iocb->raio_lio_opcode = RAIO_CMD_PREAD;
	iocb->u.c.offset = offset;
}

static inline void raio_prep_pwrite(struct raio_iocb *iocb,
		int fd, long long offset)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->raio_fildes = fd;
	iocb->raio_lio_opcode = RAIO_CMD_PWRITE;
	iocb->u.c.offset = offset;
}

#endif  /* RAIO_KUTILS_H */

