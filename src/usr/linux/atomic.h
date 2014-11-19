/*
 * Dummy C implementation of atomic counter operations. Usable on
 * UP systems only. Do not include in machine independent code.
 *
 * Originally implemented for MN10300.
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#ifndef __DUMMY_ATOMIC_H
#define __DUMMY_ATOMIC_H

/* should be in <linux/types.h> */
typedef struct {
	int counter;
} atomic_t;

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 */

#define ATOMIC_INIT(i)	{ (i) }

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
#ifndef atomic_read
#define atomic_read(v)	(*(volatile int *)&(v)->counter)
#endif

/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
#define atomic_set(v, i) (((v)->counter) = (i))

/**
 * atomic_add_return - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v and returns the result
 */
#ifndef atomic_add_return
static inline int atomic_add_return(int i, atomic_t *v)
{
	int temp;

	temp = v->counter;
	temp += i;
	v->counter = temp;

	return temp;
}
#endif

/**
 * atomic_sub_return - subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v and returns the result
 */
#ifndef atomic_sub_return
static inline int atomic_sub_return(int i, atomic_t *v)
{
	int temp;

	temp = v->counter;
	temp -= i;
	v->counter = temp;

	return temp;
}
#endif

static inline int atomic_add_negative(int i, atomic_t *v)
{
	return atomic_add_return(i, v) < 0;
}

static inline void atomic_add(int i, atomic_t *v)
{
	atomic_add_return(i, v);
}

static inline void atomic_sub(int i, atomic_t *v)
{
	atomic_sub_return(i, v);
}

static inline void atomic_inc(atomic_t *v)
{
	atomic_add_return(1, v);
}

static inline void atomic_dec(atomic_t *v)
{
	atomic_sub_return(1, v);
}

#define atomic_dec_return(v)		atomic_sub_return(1, (v))
#define atomic_inc_return(v)		atomic_add_return(1, (v))

#define atomic_sub_and_test(i, v)	(atomic_sub_return((i), (v)) == 0)
#define atomic_dec_and_test(v)		(atomic_dec_return(v) == 0)
#define atomic_inc_and_test(v)		(atomic_inc_return(v) == 0)

/**
 * atomic_clear_mask - Atomically clear bits in atomic variable
 * @mask: Mask of the bits to be cleared
 * @v: pointer of type atomic_t
 *
 * Atomically clears the bits set in @mask from @v
 */
#ifndef atomic_clear_mask
static inline void atomic_clear_mask(unsigned long mask, atomic_t *v)
{
	mask = ~mask;
	v->counter &= mask;
}
#endif

/**
 * atomic_set_mask - Atomically set bits in atomic variable
 * @mask: Mask of the bits to be set
 * @v: pointer of type atomic_t
 *
 * Atomically sets the bits set in @mask in @v
 */
#ifndef atomic_set_mask
static inline void atomic_set_mask(unsigned int mask, atomic_t *v)
{
	v->counter |= mask;
}
#endif

/**
 * Dummy version of cmpxchg.
 */

static inline int atomic_cmpxchg(atomic_t *v, int old, int _new)
{
	int prev = v->counter;

	if (prev == old)
		v->counter = _new;

	return prev;
}

/**
 * atomic_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns non-zero if @v was not @u, and zero otherwise.
 */

static inline int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old;
	c = atomic_read(v);
	while (c != u && (old = atomic_cmpxchg(v, c, c + a)) != c)
		c = old;
	return c;
}

/**
 * atomic_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns non-zero if @v was not @u, and zero otherwise.
 */
static inline int atomic_add_unless(atomic_t *v, int a, int u)
{
	return __atomic_add_unless(v, a, u) != u;
}

#endif /* __DUMMY_ATOMIC_H */
