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
#ifndef _BITSET_H_
#define _BITSET_H_

#define BIT_INDEX(bit)		((bit) >> 3) / (sizeof(bits))
#define BIT_IN_OBJ(bit)		((bit) % (sizeof(bits) << 3))
#define SIZE_TO_BYTES(size)	(sizeof(bits) * (size))

/*
 * NOTE: if you change the size of bits, then the ffs() routine may no longer work.
 */
typedef unsigned int	bits;

/*
 * Bitset definition. Note that the LSB is bit number '0'.
 */
struct bitset {
        unsigned int	bs_nbits;	/* total number of bits in set */
        bits            *bs_bits;	/* actual bits (unused bits are always 0)*/
        unsigned int	bs_size;	/* number of 'bits' objects */
}__attribute__((packed));

typedef struct bitset bitset;

bitset *	bitset_new(int num);				/* create a new bitset to contain 'num' bits */
void		bitset_free(bitset *b);				/* dispose of a bitset */
bitset *	bitset_dup(bitset *b);				/* create a copy of a bitset */
void		bitset_copy(bitset *b1, bitset *b2);		/* copy bits from b2 to b1 */
int             bitset_isempty(bitset *b);			/* test if all bits are 0 */
void		bitset_clear(bitset *b);			/* set all bits to 0 */
void		bitset_set(bitset *b, unsigned int n);		/* set bit 'n' (0 == LSB) to 1 */
void		bitset_unset(bitset *b, unsigned int n);	/* set bit 'n' to 0 */
unsigned int    bitset_test(bitset *b, unsigned int n);		/* return the value of bit 'n' */
unsigned int	bitset_firstset(bitset *b);			/* find the first bit set to 1 (starting from LSB) */
bitset *	bitset_and(bitset *b1, bitset *b2);		/* compute b3 = b1 & b2 */
void		bitset_andeq(bitset *b1, bitset *b2);		/* compute b1 &= b2 */
void		bitset_andeqnot(bitset *b1, bitset *b2);	/* compute b1 &= ~b2 */
bitset *	bitset_or(bitset *b1, bitset *b2);		/* compute b3 = b1 | b2 */
void		bitset_oreq(bitset *b1, bitset *b2);		/* compute b1 |= b2 */
void		bitset_invert(bitset *b);			/* compute ~b */
int		bitset_eq(bitset *b1, bitset *b2);		/* test if (b1 & b2) == b1 */
int		bitset_compare(bitset *b1, bitset *b2);		/* test if (b1 & b2) != 0 */
char *		bitset_to_str(bitset *b);			/* convert b to a portable string representation */
bitset *	str_to_bitset(char *str, char **end);		/* convert a portable string represetation to a bitset */
int		bitset_count(bitset *b);			/* return the number of bits in the set */
int		bitset_size(bitset *b);				/* number of bits this bitset can represent */

#endif /*_BITSET_H_*/
