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
#ifndef XIO_PROTOCOL_H
#define XIO_PROTOCOL_H

union generic_16bit {
	uint8_t b[2];
	int16_t s;
};

union generic_32bit {
	uint8_t b[4];
	float f;
	int32_t i;
	int16_t s;
};

union generic_64bit {
	uint8_t	b[8];
	int64_t	ll; /* Long long (64 bit) */
	double	d; /* IEEE-754 double precision floating point */
};

/**
 * @brief Place an unsigned byte into the buffer
 *
 * @param b the byte to add
 * @param bindex the position in the packet
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_write_uint8(uint8_t b, int bindex, uint8_t *buffer)
{
	*(buffer + bindex) = b;
	return sizeof(b);
}

/**
 * @brief Get an unsigned byte from the buffer
 *
 * @param b the byte to get
 * @param bindex the position in the packet
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_read_uint8(uint8_t *b, int bindex,
				    const uint8_t *buffer)
{
	*b = *(buffer + bindex);
	return sizeof(*b);
}

/**
 * @brief Place a signed byte into the buffer
 *
 * @param b the byte to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_write_int8(int8_t b, int bindex, uint8_t *buffer)
{
	*(buffer + bindex) = (uint8_t)b;
	return sizeof(b);
}

/**
 * @brief Get a signed byte from the buffer
 *
 * @param b the byte to get
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_read_int8(int8_t *b, int bindex,
				   const uint8_t *buffer)
{
	*b = (int8_t)*(buffer + bindex);
	return sizeof(*b);
}

/**
 * @brief Place two unsigned bytes into the buffer
 *
 * @param b the bytes to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_write_uint16(uint16_t b, const int bindex,
				      uint8_t *buffer)
{
	buffer[bindex]   = (b >> 8) & 0xff;
	buffer[bindex+1] = (b)	& 0xff;

	return sizeof(b);
}

/**
 * @brief Get two unsigned bytes from the buffer
 *
 * @param b the bytes to get
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_read_uint16(uint16_t *b, const int bindex,
				     const uint8_t *buffer)
{
	*b = ((((uint32_t)buffer[bindex]) << 8)
			|  ((uint32_t)buffer[bindex+1]));

	return sizeof(*b);
}

/**
 * @brief Place two signed bytes into the buffer
 *
 * @param b the bytes to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_write_int16(int16_t b, int bindex, uint8_t *buffer)
{
	return xio_write_uint16(b, bindex, buffer);
}

/**
 * @brief Get two signed bytes from the buffer
 *
 * @param b the bytes to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_read_int16(int16_t *b, int bindex,
				    const uint8_t *buffer)
{
	return xio_read_uint16((uint16_t *)b, bindex, buffer);
}

/**
 * @brief Place four unsigned bytes into the buffer
 *
 * @param b the bytes to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_write_uint32(uint32_t b, const int bindex,
				      uint8_t *buffer)
{
	buffer[bindex]   = (b >> 24) & 0xff;
	buffer[bindex+1] = (b >> 16) & 0xff;
	buffer[bindex+2] = (b >> 8)  & 0xff;
	buffer[bindex+3] = (b)	 & 0xff;
	return sizeof(b);
}

/**
 * @brief Get four unsigned bytes from the buffer
 *
 * @param b the bytes to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_read_uint32(uint32_t *b, const int bindex,
				     const uint8_t *buffer)
{
	*b = (uint32_t)(buffer[bindex]) << 24 |
	     (uint32_t)(buffer[bindex+1]) << 16 |
	     (uint32_t)(buffer[bindex+2]) << 8 |
	     (uint32_t)(buffer[bindex+3]);

	return sizeof(*b);
}

/**
 * @brief Place four signed bytes into the buffer
 *
 * @param b the bytes to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_write_int32(int32_t b, int bindex, uint8_t *buffer)
{
	buffer[bindex]   = (b >> 24) & 0xff;
	buffer[bindex+1] = (b >> 16) & 0xff;
	buffer[bindex+2] = (b >> 8)  & 0xff;
	buffer[bindex+3] = (b)	 & 0xff;
	return sizeof(b);
}

/**
 * @brief Get four signed bytes from the buffer
 *
 * @param b the bytes to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_read_int32(int32_t *b, int bindex,
				    const uint8_t *buffer)
{
	*b = ((((uint32_t)buffer[bindex])   << 24) |
	      (((uint32_t)buffer[bindex+1]) << 16) |
	      (((uint32_t)buffer[bindex+2]) << 8)  |
	      ((uint32_t)buffer[bindex+3]));

	return sizeof(*b);
}

/**
 * @brief Place four unsigned bytes form the buffer
 *
 * @param b the bytes to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_write_uint64(uint64_t b, const int bindex,
				      uint8_t *buffer)
{
	buffer[bindex]   = (b >> 56) & 0xff;
	buffer[bindex+1] = (b >> 48) & 0xff;
	buffer[bindex+2] = (b >> 40) & 0xff;
	buffer[bindex+3] = (b >> 32) & 0xff;
	buffer[bindex+4] = (b >> 24) & 0xff;
	buffer[bindex+5] = (b >> 16) & 0xff;
	buffer[bindex+6] = (b >> 8)  & 0xff;
	buffer[bindex+7] = (b)	 & 0xff;
	return sizeof(b);
}

/**
 * @brief Get four unsigned bytes from the buffer
 *
 * @param b the bytes to get
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_read_uint64(uint64_t *b, const int bindex,
				     const uint8_t *buffer)
{
	*b = ((((uint64_t)buffer[bindex])   << 56)
			| (((uint64_t)buffer[bindex+1]) << 48)
			| (((uint64_t)buffer[bindex+2]) << 40)
			| (((uint64_t)buffer[bindex+3]) << 32)
			| (((uint64_t)buffer[bindex+4]) << 24)
			| (((uint64_t)buffer[bindex+5]) << 16)
			| (((uint64_t)buffer[bindex+6]) << 8)
			|  ((uint64_t)buffer[bindex+7]));

	return sizeof(*b);
}

/**
 * @brief Place four signed bytes into the buffer
 *
 * @param b the bytes to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_write_int64(int64_t b, int bindex, uint8_t *buffer)
{
	return xio_write_uint64(b, bindex, buffer);
}

/**
 * @brief Get four signed bytes from the buffer
 *
 * @param b the bytes to get
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_read_int64(int64_t *b, int bindex,
				    const uint8_t *buffer)
{
	return xio_read_uint64((uint64_t *)b, bindex, buffer);
}

/**
 * @brief Place a float into the buffer
 *
 * @param b the float to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_write_float(float b, int bindex, uint8_t *buffer)
{
	union generic_32bit g;

	g.f = b;
	return xio_write_int32(g.i, bindex, buffer);
}

/**
 * @brief Get a float from the buffer
 *
 * @param b the float to get
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_read_float(float *b, int bindex,
				    const uint8_t *buffer)
{
	union generic_32bit g;
	size_t len =  xio_read_int32(&g.i, bindex, buffer);

	*b = g.f;

	return len;
}

/**
 * @brief Place a double into the buffer
 *
 * @param b the double to add
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_write_double(double b, int bindex, uint8_t *buffer)
{
	union generic_64bit g;

	g.d = b;
	return xio_write_int64(g.ll, bindex, buffer);
}

/**
 * @brief Get a double from the buffer
 *
 * @param b the double to get
 * @param buffer the packet buffer
 * @return the new position of the last used byte in the buffer
 */
static inline size_t xio_read_double(double *b, int bindex,
				     const uint8_t *buffer)
{
	union generic_64bit g;
	size_t len =  xio_read_int64(&g.ll, bindex, buffer);

	*b = g.d;

	return len;
}

/**
 * @brief Place an array into the buffer
 *
 * @param b the array to add
 * @param length size of the array (for strings: length WITH '\0' char)
 * @param buffer packet buffer
 * @return new position of the last used byte in the buffer
 */
static inline size_t xio_write_array(const uint8_t *b, size_t length,
				     int bindex, uint8_t *buffer)
{
	memcpy(buffer+bindex, b, length);
	return length;
}

/**
 * @brief get an array from the buffer
 *
 * @param b the array to add
 * @param length size of the array (for strings: length WITH '\0' char)
 * @param buffer packet buffer
 * @return new position of the last used byte in the buffer
 */
static inline size_t xio_read_array(uint8_t *b, size_t length,
				    int bindex, const uint8_t *buffer)
{
	memcpy(b, buffer+bindex, length);
	return length;
}

/**
 * @brief Place a string into the buffer
 *
 * @param b the string to add
 * @param maxlength size of the array (for strings: length WITHOUT '\0' char)
 * @param buffer packet buffer
 * @return new position of the last used byte in the buffer
 */
static inline size_t xio_write_string(const char *b, size_t maxlength,
				      int bindex, uint8_t *buffer)
{
	size_t length = 0;

	/* Copy string into buffer, ensuring not to exceed the buffer size */
	unsigned int i;

	for (i = 2; i < maxlength - 1 || (b[i] == '\0'); i++)
		buffer[bindex+i] = b[i];

	length = i - 2;
	/* Enforce null termination at end of buffer */
	buffer[maxlength - 1] = '\0';

	/* Write length into first field */
	xio_write_uint16(length, bindex, buffer);

	return length;
}

/**
 * @brief Get a string from the buffer
 *
 * @param b the string to get
 * @param maxlength size of the array (for strings: length WITHOUT '\0' char)
 * @param buffer packet buffer
 * @return new position of the last used byte in the buffer
 */
static inline size_t xio_read_string(char *b, size_t maxlength,
				     int bindex, const uint8_t *buffer)
{
	uint16_t	length = 0;
	unsigned int	i;

	/* Read length from first field */
	xio_read_uint16(&length, bindex, buffer);

	/* Copy string into buffer, ensuring not to exceed the buffer size */
	for (i = 0; i < min(((size_t)length), maxlength); i++)
		b[i] = buffer[bindex+i+2];

	/* Enforce null termination at end of buffer */
	b[maxlength-1] = '\0';

	return length;
}

#endif /* XIO_PROTOCOL_H */

