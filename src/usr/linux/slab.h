#ifndef _LINUX_SLAB_H
#define _LINUX_SLAB_H

#include <assert.h>
#include <libxio.h>
#include "xio_mem.h"

#define ___GFP_WAIT	0x10u
#define ___GFP_IO	0x40u
#define ___GFP_FS	0x80u

#define GFP_KERNEL (___GFP_WAIT | ___GFP_IO | ___GFP_FS)

/* should be __bitwise__  but it is dummy */
typedef unsigned gfp_t;

static inline void kfree(const void *ptr)
{
	ufree((void *) ptr);
}

static inline void *kmalloc(size_t size, gfp_t flags)
{
	/* Make sure code transfered to kernel will work as expected */
	assert(flags == GFP_KERNEL);
	return umalloc(size);
}

/**
 * kcalloc - allocate memory for an array. The memory is set to zero.
 * @n: number of elements.
 * @size: element size.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline void *kcalloc(size_t n, size_t size, gfp_t flags)
{
	/* Make sure code transfered to kernel will work as expected */
	assert(flags == GFP_KERNEL);
	return ucalloc(n, size);
}

static inline void *vmalloc(unsigned long size)
{
	return umalloc(size);
}

static inline void *vzalloc(unsigned long size)
{
	return ucalloc(1, size);
}

static inline void vfree(const void *addr)
{
	ufree((void *) addr);
}

#endif /* _LINUX_SLAB_H */
