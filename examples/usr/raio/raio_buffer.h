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
#ifndef RAIO_BUFFER_H
#define RAIO_BUFFER_H


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>


/* Macro for 64 bit variables to switch to from net */
#ifndef _WIN32
#define ntohll(x) (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) | \
		    (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)
#endif


static inline char *pack_mem(const void *data, const size_t size, char *buffer)
{
	memcpy(buffer, data, size);
	return buffer + size;
}

static inline char *pack_u16(const uint16_t *data, char *buffer)
{
	*((uint16_t *)buffer) = htons(*data);
	return buffer + sizeof(*data);
}

static inline char *pack_s16(const int16_t *data, char *buffer)
{
	*((int16_t *)buffer) = htons(*data);
	return buffer + sizeof(*data);
}

static inline char *pack_u32(const uint32_t *data, char *buffer)
{
	*((uint32_t *)buffer) = htonl(*data);
	return buffer + sizeof(*data);
}

static inline char *pack_s32(const int32_t *data, char *buffer)
{
	*((int32_t *)buffer) = htonl(*data);
	return buffer + sizeof(*data);
}

static inline char *pack_u64(const uint64_t *data, char *buffer)
{
	*((uint64_t *)buffer) = htonll(*data);
	return buffer + sizeof(*data);
}

static inline char *pack_s64(const int64_t *data, char *buffer)
{
	*((int64_t *)buffer) = htonll(*data);
	return buffer + sizeof(*data);
}

static inline const char *unpack_mem(void *data, const size_t size,
				     const char *buffer)
{
	memcpy(data, buffer, size);
	return buffer + size;
}

static inline const char *unpack_u16(uint16_t *data, const char *buffer)
{
	*data = ntohs(*(uint16_t *)buffer);
	return buffer + sizeof(*data);
}

static inline const char *unpack_s16(int16_t *data, const char *buffer)
{
	*data = ntohs(*(int16_t *)buffer);
	return buffer + sizeof(*data);
}

static inline const char *unpack_u32(uint32_t *data, const char *buffer)
{
	*data = ntohl(*((uint32_t *)buffer));
	return buffer + sizeof(*data);
}

static inline const char *unpack_s32(int32_t *data, const char *buffer)
{
	*data = ntohl(*((int32_t *)buffer));
	return buffer + sizeof(*data);
}

static inline const char *unpack_u64(uint64_t *data, const char *buffer)
{
	*data = ntohll(*((uint64_t *)buffer));
	return buffer + sizeof(*data);
}

static inline const char *unpack_s64(int64_t *data, const char *buffer)
{
	*data = ntohll(*((int64_t *)buffer));
	return buffer + sizeof(*data);
}


#endif /* RAIO_BUFFER_H */
