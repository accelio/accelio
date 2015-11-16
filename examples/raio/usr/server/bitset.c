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
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "bitset.h"

#ifndef MIN
#define MIN(a, b) (((a) > (b)) ? (b) : (a))
#endif

bitset *bitset_new(int nbits)
{
        bitset *b;

        b = (bitset *)malloc(sizeof(bitset));

        b->bs_nbits = nbits;
        b->bs_size = BIT_INDEX(nbits-1) + 1;
        b->bs_bits = (bits *)malloc(SIZE_TO_BYTES(b->bs_size));
        memset(b->bs_bits, 0, SIZE_TO_BYTES(b->bs_size));

        return b;
}

void bitset_free(bitset *b)
{
	free(b->bs_bits);
	free(b);
}

void bitset_copy(bitset *b1, bitset *b2)
{
	memcpy(b1->bs_bits, b2->bs_bits, MIN(SIZE_TO_BYTES(b1->bs_size), SIZE_TO_BYTES(b2->bs_size)));
}

bitset *bitset_dup(bitset *b)
{
	bitset *nb = bitset_new(b->bs_nbits);

	bitset_copy(nb, b);

	return nb;
}

int bitset_isempty(bitset *b)
{
	unsigned int	i;

	for (i = 0; i < b->bs_size; i++)
		if (b->bs_bits[i] != 0)
			return 0;

	return 1;
}

void bitset_clear(bitset *b)
{
	memset(b->bs_bits, 0, SIZE_TO_BYTES(b->bs_size));
}

/*
 * Compute logical AND of bitsets
 *
 * If bitsets are different sizes, create a new bitset that
 * is the same size as the larger of the two. The high bits
 * will be ANDed with 0.
 */
bitset *bitset_and(bitset *b1, bitset *b2)
{
	bitset *	nb;

	if (b1->bs_size > b2->bs_size) {
		nb = bitset_dup(b1);
		bitset_andeq(nb, b2);
	} else {
		nb = bitset_dup(b2);
		bitset_andeq(nb, b1);
	}

	return nb;
}

/*
 * Compute b1 &= b2
 *
 * If bitsets are different sizes, high bits are assumed
 * to be 0.
 */
void bitset_andeq(bitset *b1, bitset *b2)
{
	unsigned int	i;

	for (i = 0; i < MIN(b1->bs_size, b2->bs_size); i++)
		b1->bs_bits[i] &= b2->bs_bits[i];

	/*
	 * Mask high bits (if any)
	 */
	for ( ; i < b1->bs_size; i++)
		b1->bs_bits[i] = 0;
}

/*
 * Compute b1 &= ~b2
 *
 * If bitsets are different sizes, high bits are assumed
 * to be 0.
 */
void bitset_andeqnot(bitset *b1, bitset *b2)
{
	unsigned int	i;

	for (i = 0; i < MIN(b1->bs_size, b2->bs_size); i++)
		b1->bs_bits[i] &= ~b2->bs_bits[i];

	/*
	 * Mask high bits (if any)
	 */
	for ( ; i < b1->bs_size; i++)
		b1->bs_bits[i] = 0;
}

/*
 * Compute logical OR of bitsets
 */
bitset *bitset_or(bitset *b1, bitset *b2)
{
	bitset *	nb;

	if (b1->bs_size > b2->bs_size) {
		nb = bitset_dup(b1);
		bitset_oreq(nb, b2);
	} else {
		nb = bitset_dup(b2);
		bitset_oreq(nb, b1);
	}

	return nb;
}

/*
 * Compute b1 |= b2
 */
void bitset_oreq(bitset *b1, bitset *b2)
{
	unsigned int	i;

	for (i = 0; i < MIN(b1->bs_size, b2->bs_size); i++)
		b1->bs_bits[i] |= b2->bs_bits[i];

	/*
	 * Mask out unused high bits
	 */
	if (BIT_IN_OBJ(b1->bs_nbits) != 0)
		b1->bs_bits[b1->bs_size-1] &= (1 << (BIT_IN_OBJ(b1->bs_nbits-1) + 1)) - 1;
}

/*
 * Compute ~b
 */
void bitset_invert(bitset *b)
{
	unsigned int	i;

	for (i = 0; i < b->bs_size; i++)
		b->bs_bits[i] = ~b->bs_bits[i];

	/*
	 * Mask out unused high bits
	 */
	if (BIT_IN_OBJ(b->bs_nbits) != 0)
		b->bs_bits[b->bs_size-1] &= (1 << (BIT_IN_OBJ(b->bs_nbits-1) + 1)) - 1;
}

/*
 * Test if two bitsets are equal
 *
 * Bitsets must be the same size
 */
int bitset_eq(bitset *b1, bitset *b2)
{
	unsigned int	i;

	if (b1->bs_nbits != b2->bs_nbits)
		return 0;

	for (i = 0; i < b1->bs_size; i++)
		if (b1->bs_bits[i] != b2->bs_bits[i])
			return 0;

	return 1;
}

/*
 * Test if two bitsets share any bits
 *
 * If bitsets are different sizes, high bits are assumed
 * to be 0.
 */
int bitset_compare(bitset *b1, bitset *b2)
{
	unsigned int	i;

	for (i = 0; i < MIN(b1->bs_size, b2->bs_size); i++)
		if ((b1->bs_bits[i] & b2->bs_bits[i]) != 0)
			return 1;

	return 0;
}

/**
 * Add a bit to the set. Bits are numbered from 0.
 */
void bitset_set(bitset *b, unsigned int bit)
{
	if (bit >= b->bs_nbits)
		return;

	b->bs_bits[BIT_INDEX(bit)] |= (1 << BIT_IN_OBJ(bit));
}

void bitset_unset(bitset *b, unsigned int bit)
{
	if (bit >= b->bs_nbits)
		return;

	b->bs_bits[BIT_INDEX(bit)] &= ~(1 << BIT_IN_OBJ(bit));
}

unsigned int bitset_test(bitset *b, unsigned int bit)
{
	bits		mask = (1 << BIT_IN_OBJ(bit));

	if (bit >= b->bs_nbits)
		return 0;

	return (b->bs_bits[BIT_INDEX(bit)] & mask) == mask;
}

/*
 * Find the first bit set in the bitset.
 *
 * NOTE: ffs() assumes an integer argument. If sizeof(bits) is anything
 * else this will need to be fixed.
 */
unsigned int bitset_firstset(bitset *b)
{
	unsigned int	i;

	for (i = 0; i < b->bs_size; i++)
		if (b->bs_bits[i] != 0)
			break;

	if (i == b->bs_size)
		return -1;

	return (SIZE_TO_BYTES(i) << 3) + ffs(b->bs_bits[i]) - 1;
}

static char tohex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

#define NUM_BYTES(bits) (((bits-1) >> 3) + 1)	/* number of bytes required to store bits */

static bits digittoint(char ch)
{
        if ((ch >= '0') && (ch <= '9'))
                return ch - '0';
        ch = tolower(ch);
        if ((ch >= 'a') && (ch <= 'f'))
                return ch - 'a' + 10;

        return 0;
}

static void hex2binary(char *hexstr, char *binstr)
{
        *binstr = 0;

        while (*hexstr) {
                switch (*hexstr) {
                        case '0':  strcat(binstr, "0000"); break;
                        case '1':  strcat(binstr, "0001"); break;
                        case '2':  strcat(binstr, "0010"); break;
                        case '3':  strcat(binstr, "0011"); break;
                        case '4':  strcat(binstr, "0100"); break;
                        case '5':  strcat(binstr, "0101"); break;
                        case '6':  strcat(binstr, "0110"); break;
                        case '7':  strcat(binstr, "0111"); break;
                        case '8':  strcat(binstr, "1000"); break;
                        case '9':  strcat(binstr, "1001"); break;
                        case 'a':
                        case 'A':  strcat(binstr, "1010"); break;
                        case 'b':
                        case 'B':  strcat(binstr, "1011"); break;
                        case 'c':
                        case 'C':  strcat(binstr, "1100"); break;
                        case 'd':
                        case 'D':  strcat(binstr, "1101"); break;
                        case 'e':
                        case 'E':  strcat(binstr, "1110"); break;
                        case 'f':
                        case 'F':  strcat(binstr, "1111"); break;
                }
                hexstr++;
        }
}

/**
 * Return a string representation of a bitset. We use hex to compress
 * the string somewhat and drop leading zeros.
 *
 * Format is "NN:HHHHHH..." where "NN" is the actual number of bits in hex,
 * and "HHHHH...." is a hex representation of the bits in the set. The number
 * of characters in the bit string is always rounded to the nearest byte.
 *
 * e.g. "111" -> "3:07"
 * 		"11011010101011101" -> "11:01b55d"
 */
char *bitset_to_str(bitset *b)
{
	int			bytes;
	int		        pbit;
	int                     bit;
	char                    *str;
	char                    *s;
	unsigned char           val;
	int                     found = 0;

	if (!b)
		return strdup("00");

	/*
	 * Find out how many bytes needed (rounded up)
	 */
	bytes = NUM_BYTES(b->bs_nbits);

	str = (char *)calloc(bytes * 2 + 1, 1);
	s = str;

	for (pbit = (bytes << 3) - 1; pbit > 0; ) {
		for (val = 0, bit = 3; bit >= 0; bit--, pbit--) {
			if (pbit < (int)b->bs_nbits && bitset_test(b, pbit)) {
				val |= (1 << bit);
                                found = 1;
			}
		}
		if (found)
			*s++ = tohex[val & 0x0f];
	}

	if (b->bs_nbits == 0) {
		*s++ = '0';
	}

	*s = '\0';

	return str;
}

/**
 * Convert string into a bitset. Inverse of bitset_to_str().
 *
 */
bitset *str_to_bitset(char *str, char **end)
{
	int			nbits = 0;
	int			bytes;
	int			n;
	int			pos;
	int			b;
        int                     len;
	bitset                  *bp;
        char                    dst[1024];

        if (!str)
                return NULL;

        /* hex string has 0x prefix */
        if (str[0] == '0' && str[1] == 'x')
                str = str + 2;

        len = strlen(str);
        if (len % 2) {
                nbits = (len + 1) << 2;
                bytes = NUM_BYTES(nbits);
                pos = (bytes << 3) - 5;
        } else {
                nbits = len << 2;
                bytes = NUM_BYTES(nbits);
                pos = (bytes << 3) - 1;
        }

        if (0)
                hex2binary(str, dst);

	bp = bitset_new(nbits);

	for (; *str != '\0' && isxdigit(*str) && pos >= 0; str++) {
		b = digittoint(*str);
		for (n = 3; n >= 0; n--, pos--) {
			if (b & (1 << n)) {
				bitset_set(bp, pos);
			}
		}
	}

	if (end != NULL)
                *end = str - 1;

	return bp;
}

unsigned int count_bits(bits b)
{
        unsigned int	n = 0;

        while (b != 0) {
                n++;
                b &= (b-1);
        }

        return n;
}

/**
 * Number of bits in the set (as opposed to the total size of the set)
 */
int bitset_count(bitset *b)
{
	unsigned int	i;
	int	count = 0;

	for (i = 0; i < b->bs_size; i++)
		count += count_bits(b->bs_bits[i]);

	return count;
}

/**
 * Number of bits this set can represent
 */
int bitset_size(bitset *b)
{
	return b->bs_nbits;
}
