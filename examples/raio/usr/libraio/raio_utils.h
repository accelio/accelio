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
#ifndef RAIO_UTILS_H
#define RAIO_UTILS_H

#include <libraio.h>

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




char *pack_stat64(struct stat64 *stbuf, char *buffer);
const char *unpack_stat64(struct stat64 *result, const char *buffer);
char *pack_iocb(struct raio_iocb *iocb, char *buffer);
const char *unpack_iocb(struct raio_iocb *iocb, const char *buffer);

void pack_open_command(const char *pathname, int flags,
		       void *buf, size_t *len);
void pack_close_command(int fd, void *buf, size_t *len);
void pack_fstat_command(int fd, void *buf, size_t *len);
void pack_setup_command(int queues, int qdepth,
			void *buf, size_t *len);
void pack_destroy_command(void *buf, size_t *len);
void pack_submit_command(struct raio_iocb *iocb, int is_last_in_batch,
			 void *buf, size_t *len);



int unpack_open_answer(char *buf, size_t len, int *fd);
int unpack_close_answer(char *buf, size_t len);
int unpack_fstat_answer(char *buf, size_t len, struct stat64 *stbuf);
int unpack_setup_answer(char *buf, size_t len);

#endif  /* RAIO_UTILS_H */

