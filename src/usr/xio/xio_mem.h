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
#ifndef XIO_MEM_H
#define XIO_MEM_H

#include <xio_env.h>

extern int			disable_huge_pages;
extern int			allocator_assigned;
extern int			page_size;
extern struct xio_mem_allocator *mem_allocator;

extern void *malloc_huge_pages(size_t size);
extern void free_huge_pages(void *ptr);
extern void *xio_numa_alloc(size_t bytes, int node);
extern void xio_numa_free_ptr(void *ptr);

static inline void xio_disable_huge_pages(int disable)
{
	if (disable_huge_pages)
		return;
	disable_huge_pages = disable;
}

static inline int xio_set_mem_allocator(struct xio_mem_allocator *allocator)
{
	if (allocator_assigned) {
		/* xio_set_error(EPERM);*/
		return -1;
	}
	memcpy(mem_allocator, allocator, sizeof(*allocator));
	allocator_assigned	= 1;

	return 0;
}

static inline void *ucalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (allocator_assigned && mem_allocator->allocate) {
		ptr = mem_allocator->allocate(nmemb*size,
					      mem_allocator->user_context);
		if (ptr)
			memset(ptr, 0, nmemb*size);
	} else {
		ptr = calloc(nmemb, size);
	}
	return ptr;
}

static inline void *umalloc(size_t size)
{
	if (allocator_assigned && mem_allocator->allocate)
		return mem_allocator->allocate(size,
					       mem_allocator->user_context);
	else
		return malloc(size);
}

static inline void *umemalign(size_t boundary, size_t size)
{
	void *ptr;

	if (allocator_assigned && mem_allocator->memalign) {
		ptr = mem_allocator->memalign(boundary, size,
					      mem_allocator->user_context);
	} else {
		if (xio_memalign(&ptr, boundary, size) != 0)
			return NULL;
	}
	if (ptr)
		memset(ptr, 0, size);
	return ptr;
}

static inline void ufree(void *ptr)
{
	if (allocator_assigned && mem_allocator->free)
		mem_allocator->free(ptr, mem_allocator->user_context);
#ifndef WIN32
	/*TODO: for win, sometimes 'free' and sometimes aligned_free is needed*/
	else
		free(ptr);
#endif
}

static inline void *umalloc_huge_pages(size_t size)
{
	void *ptr;

	if (allocator_assigned && mem_allocator->malloc_huge_pages) {
		ptr = mem_allocator->malloc_huge_pages(
				size, mem_allocator->user_context);
		if (ptr)
			memset(ptr, 0, size);
	} else {
		ptr = malloc_huge_pages(size);
	}
	return ptr;
}

static inline void ufree_huge_pages(void *ptr)
{
	if (allocator_assigned && mem_allocator->free_huge_pages)
		mem_allocator->free_huge_pages(ptr,
					       mem_allocator->user_context);
	else
		free_huge_pages(ptr);
}

static inline void *unuma_alloc(size_t size, int node)
{
	if (allocator_assigned && mem_allocator->numa_alloc)
		return mem_allocator->numa_alloc(size, node,
						 mem_allocator->user_context);
	else
		return xio_numa_alloc(size, node);
}

static inline void unuma_free(void *ptr)
{
	if (allocator_assigned && mem_allocator->numa_free)
		mem_allocator->numa_free(ptr,
					 mem_allocator->user_context);
	else
		xio_numa_free_ptr(ptr);
}

static inline char *ustrdup(char const *s)
{
	size_t len = strlen(s) + 1;
	char *new1 = (char*)umalloc(len);

	if (new1 == NULL)
		return NULL;

	return (char*)memcpy(new1, s, len);
}

static inline char *ustrndup(char const *s, size_t n)
{
	size_t len = strnlen(s, n);
	char *new1 = (char*)umalloc(len + 1);

	if (new1 == NULL)
		return NULL;

	new1[len] = '\0';
	return (char*)memcpy(new1, s, len);
}

#endif

