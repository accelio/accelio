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
#ifndef LIBRAIO_H
#define LIBRAIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef __GNUC__
# define likely(x)      __builtin_expect(!!(x), 1)
# define unlikely(x)    __builtin_expect(!!(x), 0)
#else
# define likely(x)      (x)
# define unlikely(x)    (x)
#endif

/*---------------------------------------------------------------------------*/
/* forward declarations	                                                     */
/*---------------------------------------------------------------------------*/
struct timespec;
struct stat64;
struct raio_iocb;

/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
typedef struct raio_context *raio_context_t;
typedef struct raio_mr *raio_mr_t;

/*---------------------------------------------------------------------------*/
/* enums								     */
/*---------------------------------------------------------------------------*/
enum raio_iocb_cmd {
	RAIO_CMD_PREAD		= 0,
	RAIO_CMD_PWRITE		= 1,
};

/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct raio_iocb_common {
	void			*buf;
	unsigned long long	nbytes;
	long long		offset;
	raio_mr_t		mr;
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

struct raio_event {
	void			*data;  /* Return in the io completion event */
	struct raio_iocb	*obj;
	unsigned long long	handle; /* release handle */
	unsigned long		res;
	unsigned long		res2;
};

/**
 * raio_start - start remote server for aio operations
 *
 * @addr: address to rcopy server
 * @addrlen: address length
 *
 * RETURNS: return the new file descriptor, or -1 if an error occurred (in
 * which case, errno is set appropriately)
 */
int raio_start(const char *transport,
	      const struct sockaddr *addr, socklen_t addrlen);

/**
 * raio_stop - stop and release resources for remote server
 *
 * @fd:	the file's file descriptor
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int raio_stop(int fd);

/**
 * raio_open - open file for io operations
 *
 * @fd:	the file's file descriptor
 * @pathname: fullpath to the file or device
 * @flags:    open flags - see "man 2 open"
 *
 * RETURNS: return the new file descriptor, or -1 if an error occurred (in
 * which case, errno is set appropriately)
 */
int raio_open(int fd, const char *pathname, int flags);

/**
 * raio_fstat - get file status
 *
 * @fd:	the file's file descriptor
 * @buf: the file stat structure
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int raio_fstat(int fd, struct stat64 *buf);

/**
 * raio_close - close file or device
 *
 * @fd:	the file's file descriptor
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int raio_close(int fd);

/**
 * raio_setup - creates an asynchronous I/O context capable of receiving at
 * most maxevents
 *
 * @queues:	num queus
 * @qdepth:	queue depth for each queue
 * @ctxp:	On successful creation of the RAIO context, *ctxp is filled
 *		in with the resulting  handle.
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int raio_setup(int queues, int qdepth, raio_context_t *ctxp);

/**
 * raio_destroy - destroys an asynchronous I/O context
 *
 * @ctx:	the RAIO context
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int raio_destroy(raio_context_t ctx);

/**
 * raio_submit - queues nr I/O request blocks for processing in the RAIO
 *		 context ctx
 *
 * @ctx:	the RAIO context
 * @nr:		number of events to queue
 * @handles:	array of io control block requests to queue
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int raio_submit(raio_context_t ctx, long nr, struct raio_iocb *ios[]);

/**
 * raio_cancel - attempt to cancel an outstanding asynchronous I/O operation
 *
 * @ctx:	the RAIO context ID of the operation to be canceled
 * @iocb:	control block to cancel
 * @result:	upon success, a copy of the canceled event
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int raio_cancel(raio_context_t ctx, struct raio_iocb *iocb,
		struct raio_event *evt);

/**
 * raio_getevents - read asynchronous I/O events from the completion queue
 *
 * @ctx:	the RAIO context ID
 * @min_nr:	at least min_nr to read
 * @nr:		at most nr to read
 * @events:	returned events array
 * @timeout:	specifies the amount of time to wait for events, where a NULL
 *		timeout waits until at least min_nr events have been seen.
 *
 * RETURNS: On  success,  raio_getevents()  returns  the number of events read:
 * 0 if no events are available, or less than min_nr if the timeout has elapsed.
 */
int raio_getevents(raio_context_t ctx, long min_nr, long nr,
		   struct raio_event *events, struct timespec *timeout);

/**
 * raio_release - release raio resources when events is no longer needed
 *
 * @ctx:	the RAIO context ID
 * @nr:		number of events to release
 * @ihandles:	handles array to release
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int raio_release(raio_context_t ctx, long nr, struct raio_event *events);

/**
 * raio_reg_mr - register memory region for rdma operations
 *
 * @ctx:	the RAIO context ID
 * @buf:	pointer to memory buffer
 * @len:	the buffer's length
 * @mr:		returned memory region
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int raio_reg_mr(raio_context_t ctx, void *buf, size_t len, raio_mr_t *mr);

/**
 * raio_dereg_mr - deregister memory region
 *
 * @ctx:	the RAIO context ID
 * @mr:		the memory region
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int raio_dereg_mr(raio_context_t ctx, raio_mr_t mr);


static inline void raio_prep_pread(struct raio_iocb *iocb, int fd, void *buf,
				   size_t count, long long offset,
				   raio_mr_t mr)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->raio_fildes = fd;
	iocb->raio_lio_opcode = RAIO_CMD_PREAD;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = count;
	iocb->u.c.offset = offset;
	iocb->u.c.mr = mr;
}

static inline void raio_prep_pwrite(struct raio_iocb *iocb, int fd, void *buf,
				    size_t count, long long offset,
				    raio_mr_t mr)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->raio_fildes = fd;
	iocb->raio_lio_opcode = RAIO_CMD_PWRITE;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = count;
	iocb->u.c.offset = offset;
	iocb->u.c.mr = mr;
}

static inline void raio_set_eventfd(struct raio_iocb *iocb, int eventfd)
{
	iocb->u.c.flags |= (1 << 0) /* RAIOCB_FLAG_RESFD */;
	iocb->u.c.resfd = eventfd;
}

#ifdef __cplusplus
}
#endif

#endif /* LIBRAIO_H */

