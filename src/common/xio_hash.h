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
#ifndef XIO_HASH_H
#define XIO_HASH_H

struct  xio_key_ptr {
	void  *id;
};

struct  xio_key_int8 {
	uint8_t		id;
	uint8_t		pad[7];
};

struct  xio_key_int16 {
	uint16_t	id;
	uint8_t		pad[6];
};

struct  xio_key_int32 {
	uint32_t	id;
	uint8_t		pad[4];
};

struct  xio_key_int64 {
	uint64_t	id;
};

struct  xio_key_str {
	char		*id;
};

static inline unsigned int int8_hash(uint8_t key8)
{
	unsigned int key = key8;

	key += ~(key << 15);
	key ^= (key >> 10);
	key += (key << 3);
	key ^= (key >> 6);
	key += ~(key << 11);
	key ^= (key >> 16);
	return key;
}

/* Thomas Wang's 32 Bit Mix Function:
 * http://www.cris.com/~Ttwang/tech/inthash.htm
 */
static inline unsigned int int16_hash(uint16_t key16)
{
	unsigned int key = key16;

	key += ~(key << 15);
	key ^= (key >> 10);
	key += (key << 3);
	key ^= (key >> 6);
	key += ~(key << 11);
	key ^= (key >> 16);
	return key;
}

/* Thomas Wang's 32 Bit Mix Function:
 * http://www.cris.com/~Ttwang/tech/inthash.htm
 */
static inline unsigned int int32_hash(uint32_t key)
{
	key += ~(key << 15);
	key ^= (key >> 10);
	key += (key << 3);
	key ^= (key >> 6);
	key += ~(key << 11);
	key ^= (key >> 16);
	return key;
}

/* Thomas Wang's 32 Bit Mix Function:
 * http://www.cris.com/~Ttwang/tech/inthash.htm
 */
static inline unsigned int int64_hash(uint64_t key)
{
	key += ~(key << 32);
	key ^= (key >> 22);
	key += ~(key << 13);
	key ^= (key >> 8);
	key += (key << 3);
	key ^= (key >> 15);
	key += ~(key << 27);
	key ^= (key >> 31);
	return (unsigned int)key;
}

static inline unsigned int str_hash(const char *s)
{
	unsigned int key = 0;

	while (*s)
		key = key*37 + *s++;

	return key;
}

static inline unsigned int xio_int8_hash(
		const struct xio_key_int8 *k)
{
	return int8_hash(k->id);
}

static inline unsigned int xio_int16_hash(
		const struct xio_key_int16 *k)
{
	return int16_hash(k->id);
}

static inline unsigned int xio_int32_hash(
		const struct xio_key_int32 *k)
{
	return int32_hash(k->id);
}

static inline unsigned int xio_int64_hash(
		const struct xio_key_int64 *k)
{
	return int64_hash(k->id);
}

static inline unsigned int xio_str_hash(
		const struct xio_key_str *k)
{
	return str_hash(k->id);
}

static inline unsigned int xio_ptr_hash(
		const struct xio_key_ptr *k)
{
	return int64_hash((uint64_t)(uintptr_t)(k->id));
}

static inline int xio_int32_cmp(
		const struct xio_key_int32 *k1,
		const struct xio_key_int32 *k2)
{
	return (k1->id == k2->id);
}

static inline void xio_int32_cp(
		struct xio_key_int32 *dst,
		const struct xio_key_int32 *src)
{
	dst->id = src->id;
}

static inline int xio_int64_cmp(
		const struct xio_key_int64 *k1,
		const struct xio_key_int64 *k2)
{
	return (k1->id == k2->id);
}

static inline void xio_int64_cp(
		struct xio_key_int64 *dst,
		const struct xio_key_int64 *src)
{
	dst->id = src->id;
}

static inline int xio_ptr_cmp(
		const struct xio_key_ptr *k1,
		const struct xio_key_ptr *k2)
{
	return (k1->id == k2->id);
}

static inline void xio_ptr_cp(
		struct xio_key_ptr *dst,
		const struct xio_key_ptr *src)
{
	dst->id = src->id;
}

#endif
