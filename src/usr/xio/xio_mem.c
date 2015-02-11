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
#include <xio_env.h>
#include <xio_os.h>
#include "xio_log.h"
#include "xio_common.h"
#include "xio_mem.h"

#define HUGE_PAGE_SZ			(2*1024*1024)
#ifndef WIN32
int			  disable_huge_pages	= 0;
#else
int			  disable_huge_pages	= 1; /* bypass hugepages */
#endif
int			  allocator_assigned	= 0;
struct xio_mem_allocator  g_mem_allocator;
struct xio_mem_allocator *mem_allocator = &g_mem_allocator;

/*---------------------------------------------------------------------------*/
/* malloc_huge_pages	                                                     */
/*---------------------------------------------------------------------------*/
void *malloc_huge_pages(size_t size)
{
	int retval;
	size_t	real_size;
	void	*ptr = NULL;

	if (disable_huge_pages) {
		long page_size = xio_get_page_size();

		if (page_size < 0) {
			xio_set_error(errno);
			ERROR_LOG("sysconf failed. (errno=%d %m)\n", errno);
			return NULL;
		}

		real_size = ALIGN(size, page_size);
		retval = xio_memalign(&ptr, page_size, real_size);
		if (retval) {
			ERROR_LOG("posix_memalign failed sz:%zu. %s\n",
				  real_size, strerror(retval));
			return NULL;
		}
		memset(ptr, 0, real_size);
		return ptr;
	}

	/* Use 1 extra page to store allocation metadata */
	/* (libhugetlbfs is more efficient in this regard) */
	real_size = ALIGN(size + HUGE_PAGE_SZ, HUGE_PAGE_SZ);

	ptr = xio_mmap(real_size);
	if (!ptr || ptr == MAP_FAILED) {
		/* The mmap() call failed. Try to malloc instead */
		long page_size = xio_get_page_size();

		if (page_size < 0) {
			xio_set_error(errno);
			ERROR_LOG("sysconf failed. (errno=%d %m)\n", errno);
			return NULL;
		}
		WARN_LOG("huge pages allocation failed, allocating " \
			 "regular pages\n");

		DEBUG_LOG("mmap rdma pool sz:%zu failed (errno=%d %m)\n",
			  real_size, errno);
		real_size = ALIGN(size + HUGE_PAGE_SZ, page_size);
		retval = xio_memalign(&ptr, page_size, real_size);
		if (retval) {
			ERROR_LOG("posix_memalign failed sz:%zu. %s\n",
				  real_size, strerror(retval));
			return NULL;
		}
		memset(ptr, 0, real_size);
		real_size = 0;
	} else {
		DEBUG_LOG("Allocated huge page sz:%zu\n", real_size);
	}
	/* Save real_size since mmunmap() requires a size parameter */
	*((size_t *)ptr) = real_size;
	/* Skip the page with metadata */
	return sum_to_ptr(ptr, HUGE_PAGE_SZ);
}

/*---------------------------------------------------------------------------*/
/* free_huge_pages	                                                     */
/*---------------------------------------------------------------------------*/
void free_huge_pages(void *ptr)
{
	void	*real_ptr;
	size_t	real_size;

	if (!ptr)
		return;

	if (disable_huge_pages)  {
		free(ptr);
		return;
	}

	/* Jump back to the page with metadata */
	real_ptr = (char *)ptr - HUGE_PAGE_SZ;
	/* Read the original allocation size */
	real_size = *((size_t *)real_ptr);

	if (real_size != 0)
		/* The memory was allocated via mmap()
		   and must be deallocated via munmap()
		   */
		xio_munmap(real_ptr, real_size);
	else
		/* The memory was allocated via malloc()
		   and must be deallocated via free()
		   */
		free(real_ptr);
}

/*---------------------------------------------------------------------------*/
/* xio_numa_alloc	                                                     */
/*---------------------------------------------------------------------------*/
void *xio_numa_alloc(size_t bytes, int node)
{
	size_t real_size = ALIGN((bytes + page_size), page_size);
	void *p = xio_numa_alloc_onnode(real_size, node);

	if (!p) {
		ERROR_LOG("numa_alloc_onnode failed sz:%zu. %m\n",
			  real_size);
		return NULL;
	}
	/* force the OS to allocate physical memory for the region */
	memset(p, 0, real_size);

	/* Save real_size since numa_free() requires a size parameter */
	*((size_t *)p) = real_size;

	/* Skip the page with metadata */
	return sum_to_ptr(p, page_size);
}

/*---------------------------------------------------------------------------*/
/* xio_numa_free_ptr	                                                     */
/*---------------------------------------------------------------------------*/
void xio_numa_free_ptr(void *ptr)
{
	void	*real_ptr;
	size_t	real_size;

	if (!ptr)
		return;

	/* Jump back to the page with metadata */
	real_ptr = (char *)ptr - page_size;
	/* Read the original allocation size */
	real_size = *((size_t *)real_ptr);

	if (real_size != 0)
		/* The memory was allocated via numa_alloc()
		   and must be deallocated via numa_free()
		   */
		xio_numa_free(real_ptr, real_size);
}
