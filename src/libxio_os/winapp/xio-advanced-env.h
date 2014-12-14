#ifndef __ADV_ENV_H_
#define __ADV_ENV_H_
#include <xio_mem.h>
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

#endif /* __ADV_ENV_H_ */
