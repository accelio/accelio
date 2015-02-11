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
#ifndef XIO_ENV_H
#define XIO_ENV_H

/*---------------------------------------------------------------------------*/
/*-------------------- Memory related things --------------------------------*/
/*---------------------------------------------------------------------------*/
#define PACKED_MEMORY(__declaration__) \
		__declaration__ __attribute__((__packed__))

/*---------------------------------------------------------------------------*/
#define inc_ptr(_ptr, inc)  ((_ptr) += (inc))
#define sum_to_ptr(_ptr, a) ((_ptr) + (a))

/*---------------------------------------------------------------------------*/
/*-------------------- Threads related things --------------------------------*/
/*---------------------------------------------------------------------------*/
#define xio_sync_bool_compare_and_swap(ptr, oldval, newval) \
		__sync_bool_compare_and_swap(ptr, oldval, newval)
#define  xio_sync_fetch_and_add32(ptr, value) \
	__sync_fetch_and_add((ptr), (value))
#define  xio_sync_fetch_and_add64(ptr, value) \
	__sync_fetch_and_add((ptr), (value))

/*---------------------------------------------------------------------------*/
#define XIO_F_ALWAYS_INLINE inline __attribute__ ((always_inline))

/*---------------------------------------------------------------------------*/
/*-------------------- Socket related things --------------------------------*/
/*---------------------------------------------------------------------------*/
#define INVALID_SOCKET (-1)
#define XIO_ESHUTDOWN		ESHUTDOWN
#define XIO_EINPROGRESS		EINPROGRESS /* connect on non-blocking socket */
#define XIO_EAGAIN		EAGAIN      /* recv    on non-blocking socket */
#define XIO_WOULDBLOCK		EWOULDBLOCK /* recv    on non-blocking socket */
#define XIO_ECONNABORTED	ECONNABORTED
#define XIO_ECONNRESET		ECONNRESET
#define XIO_ECONNREFUSED        ECONNREFUSED

#endif /* XIO_ENV_H */
