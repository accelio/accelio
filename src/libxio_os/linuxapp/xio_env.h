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
#ifndef XIO_ENV_H
#define XIO_ENV_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <malloc.h>
#include <fcntl.h>
#include <utmpx.h>
#include <time.h>
#include <netdb.h>
#include <inttypes.h>
#include <ctype.h>
#include <dirent.h>
#include <pthread.h>
#include <assert.h>
#include <limits.h>
#include <sched.h>
#include <numa.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <linux/tcp.h>
#include <linux/mman.h>


/*---------------------------------------------------------------------------*/
/*-------------------- Memory related things --------------------------------*/
/*---------------------------------------------------------------------------*/
#define PACKED_MEMORY( __Declaration__ ) \
		__Declaration__ __attribute__((__packed__))

/*---------------------------------------------------------------------------*/
static inline int xio_memalign(void **memptr, size_t alignment, size_t size){
	return posix_memalign(memptr, alignment, size);
}

/*---------------------------------------------------------------------------*/
static inline void xio_memfree(void *memptr){
	free(memptr);
}

/*---------------------------------------------------------------------------*/
static inline long xio_get_page_size(void)
{
	static long page_size = 0;

	if (!page_size) {
		page_size = sysconf(_SC_PAGESIZE);
	}
	return page_size;
}

/*---------------------------------------------------------------------------*/
static inline void *xio_mmap(size_t length){
	return mmap(NULL, length, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS |
		    MAP_POPULATE | MAP_HUGETLB, -1, 0);
}

/*---------------------------------------------------------------------------*/
static inline int xio_munmap(void *addr, size_t length){
	return munmap(addr, length);
}

/*---------------------------------------------------------------------------*/
static inline void *xio_numa_alloc_onnode(size_t size, int node)
{
	return numa_alloc_onnode(size, node);
}

/*---------------------------------------------------------------------------*/
static inline void xio_numa_free(void *start, size_t size) {
	numa_free(start, size);
}

/*---------------------------------------------------------------------------*/
/*------------------- CPU and Clock related things --------------------------*/
/*---------------------------------------------------------------------------*/
static inline long xio_get_num_processors(void)
{
	static long num_processors = 0;

	if (!num_processors) {
		num_processors = sysconf(_SC_NPROCESSORS_CONF);
	}
	return num_processors;
}

/*---------------------------------------------------------------------------*/
static inline long xio_get_current_processor_number(void)
{
	return sched_getcpu();
}

/*---------------------------------------------------------------------------*/
static inline int xio_clock_gettime(struct timespec *ts)
{
	return clock_gettime(CLOCK_MONOTONIC, ts);
}

/*---------------------------------------------------------------------------*/
/*-------------------- Thread related things --------------------------------*/
/*---------------------------------------------------------------------------*/
#define xio_tls			__thread
typedef pthread_once_t		thread_once_t;
#define THREAD_ONCE_INIT	PTHREAD_ONCE_INIT
#define CALLBACK
/*---------------------------------------------------------------------------*/
#define thread_once(once_control, init_routine) \
		pthread_once(once_control, init_routine)
/*---------------------------------------------------------------------------*/
#define reset_thread_once_t(once_control) \
		((*(once_control)) = THREAD_ONCE_INIT)
/*---------------------------------------------------------------------------*/
#define is_reset_thread_once_t(once_control) \
		((*(once_control)) == THREAD_ONCE_INIT)

/*---------------------------------------------------------------------------*/
#define xio_sync_bool_compare_and_swap(ptr, oldval, newval) \
		__sync_bool_compare_and_swap(ptr, oldval, newval)

/*---------------------------------------------------------------------------*/
#define LIBRARY_INITIALIZER(f) \
	static void f(void) __attribute__((constructor)); \
	static void f(void)

/*---------------------------------------------------------------------------*/
#define LIBRARY_FINALIZER(f) \
	static void f(void) __attribute__((destructor)); \
	static void f(void)

/*---------------------------------------------------------------------------*/
#define inc_ptr(_ptr, inc)  ((_ptr) += (inc))
#define sum_to_ptr(_ptr, a) ((_ptr) + (a))


/*---------------------------------------------------------------------------*/
/*-------------------- Socket related things --------------------------------*/
/*---------------------------------------------------------------------------*/
#define INVALID_SOCKET (-1)
#define XIO_ESHUTDOWN		ESHUTDOWN
#define XIO_EINPROGRESS		EINPROGRESS /* connect on non-blocking socket */
#define XIO_EAGAIN		EAGAIN      /* recv    on non-blocking socket */
#define XIO_WOULDBLOCK		EWOULDBLOCK /* recv    on non-blocking socket */
#define XIO_ECONNABORTED	ECONNABORTED
#define XIO_ECONNRESET		ECONNRESET

typedef int socket_t;
/*---------------------------------------------------------------------------*/
static inline int xio_closesocket(socket_t sock) {return close(sock);}

/*---------------------------------------------------------------------------*/
static inline int xio_get_last_socket_error() {return errno;}

/*---------------------------------------------------------------------------*/
/* enables or disables the blocking mode for the socket
   If mode != 0, blocking is enabled;
   If mode = 0, non-blocking mode is enabled. */
static inline int xio_set_blocking(socket_t sock, unsigned long mode)
{
	long arg;
	if ((arg = fcntl(sock, F_GETFL, NULL)) < 0) {
		return -1;
	}
	if (mode) { /* blocking */
		arg &= (~O_NONBLOCK);
	}
	else { /* non blocking */
		arg |= O_NONBLOCK;
	}
	if (fcntl(sock, F_SETFL, arg) < 0) {
		return -1;
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
static inline socket_t xio_socket_non_blocking(int domain, int type,
					      int protocol)
{
	return socket(domain, type | SOCK_NONBLOCK, protocol);
}

/*---------------------------------------------------------------------------*/
/* NOTE: we aren't using static inline function here; because accept4 requires
 * defining _GNU_SOURCE and we don't want users to be forced to define it in
 * their application */
#define xio_accept_non_blocking(sockfd, addr, addrlen) \
	accept4(sockfd, addr, addrlen, SOCK_NONBLOCK)


#include <linux/types.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/usr.h>
#include <linux/netlink.h>
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>



#endif /* XIO_ENV_H */
