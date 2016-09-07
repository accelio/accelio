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
#include <dlfcn.h>
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
#include <get_clock.h>

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------*/
/*-------------------- Memory related things --------------------------------*/
/*---------------------------------------------------------------------------*/
#define PACKED_MEMORY(__declaration__) \
		__declaration__ __attribute__((__packed__))

/*---------------------------------------------------------------------------*/
static inline int xio_memalign(void **memptr, size_t alignment, size_t size)
{
	return posix_memalign(memptr, alignment, size);
}

/*---------------------------------------------------------------------------*/
static inline void xio_memfree(void *memptr)
{
	free(memptr);
}

/*---------------------------------------------------------------------------*/
static inline long xio_get_page_size(void)
{
	static long page_size;

	if (!page_size)
		page_size = sysconf(_SC_PAGESIZE);

	return page_size;
}

/*---------------------------------------------------------------------------*/
static inline void *xio_mmap(size_t length)
{
	return mmap(NULL, length, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS |
		    MAP_POPULATE | MAP_HUGETLB, -1, 0);
}

/*---------------------------------------------------------------------------*/
static inline int xio_munmap(void *addr, size_t length)
{
	return munmap(addr, length);
}

/*---------------------------------------------------------------------------*/
static inline void *xio_numa_alloc_onnode(size_t size, int node)
{
	return numa_alloc_onnode(size, node);
}

/*---------------------------------------------------------------------------*/
static inline void xio_numa_free(void *start, size_t size)
{
	numa_free(start, size);
}

/*---------------------------------------------------------------------------*/
/*------------------- CPU and Clock related things --------------------------*/
/*---------------------------------------------------------------------------*/
static inline long xio_get_num_processors(void)
{
	static long num_processors;

	if (!num_processors)
		num_processors = sysconf(_SC_NPROCESSORS_CONF);

	return num_processors;
}

/*---------------------------------------------------------------------------*/
static inline int xio_clock_gettime(struct timespec *ts)
{
	return clock_gettime(CLOCK_MONOTONIC, ts);
}

struct getcpu_cache {
	unsigned long blob[128 / sizeof(long)];
};

typedef long (*vgetcpu_fn)(unsigned *cpu,
			   unsigned *node, struct getcpu_cache *tcache);
static vgetcpu_fn vgetcpu;

static inline int init_vgetcpu(void)
{
	void *vdso;

	dlerror();
	vdso = dlopen("linux-vdso.so.1", RTLD_LAZY);
	if (!vdso)
		return -1;
	vgetcpu = (vgetcpu_fn)dlsym(vdso, "__vdso_getcpu");
	dlclose(vdso);
	return !vgetcpu ? -1 : 0;
}

/*---------------------------------------------------------------------------*/
/* xio_get_cpu								     */
/*---------------------------------------------------------------------------*/
static inline unsigned xio_get_cpu(void)
{
	static int first = 1;
	unsigned cpu;

	if (!first && vgetcpu) {
		vgetcpu(&cpu, NULL, NULL);
		return cpu;
	}
	if (!first)
		return sched_getcpu();

	first = 0;
	if (init_vgetcpu() < 0) {
		vgetcpu = NULL;
		return sched_getcpu();
	}
	vgetcpu(&cpu, NULL, NULL);
	return cpu;
}

/*
#define CACHE_LINE_FILE	\
	"/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"

static inline int arch_cache_line_size(void)
{
	char size[32];
	int fd, ret;

	fd = open(CACHE_LINE_FILE, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, size, sizeof(size));

	close(fd);

	if (ret <= 0)
		return -1;
	else
		return atoi(size);
}

*/

/*---------------------------------------------------------------------------*/
static inline int xio_numa_node_of_cpu(int cpu)
{
	return numa_node_of_cpu(cpu);
}

/*---------------------------------------------------------------------------*/
static inline int xio_numa_run_on_node(int node)
{
	return numa_run_on_node(node);
}

#define XIO_HZ_DIR   "/var/tmp/accelio.d"
#define XIO_HZ_FILE  XIO_HZ_DIR "/hz"

/*---------------------------------------------------------------------------*
 * xio_get_cpu_mhz							     *
 *									     *
 * since this operation may take time cache it on a cookie,		     *
 * and use the cookie if exist						     *
 *									     *
 *---------------------------------------------------------------------------*/
static inline double xio_get_cpu_mhz(void)
{
	char	size[32] = {0};
	double	hz = 0;
	int	fd;
	ssize_t ret;

	fd = open(XIO_HZ_FILE, O_RDONLY);
	if (fd < 0)
		goto try_create;

	ret = read(fd, size, sizeof(size));

	close(fd);

	if (ret > 0)
		return atof(size);

try_create:
	hz = get_cpu_mhz(0);

	ret = mkdir(XIO_HZ_DIR, 0777);
	if (ret < 0)
		goto exit;

	fd = open(XIO_HZ_FILE, O_CREAT | O_TRUNC | O_WRONLY | O_SYNC, 0644);
	if (fd < 0)
		goto exit;

	sprintf(size, "%f", hz);
	ret = write(fd, size, sizeof(size));
	if (ret < 0)
		goto close_and_exit;

close_and_exit:
	close(fd);
exit:
	return hz;
}

/*---------------------------------------------------------------------------*/
/* xio_pin_to_cpu - pin to specific cpu					     */
/*---------------------------------------------------------------------------*/
static inline int xio_pin_to_cpu(int cpu)
{
	int		ncpus = numa_num_task_cpus();
	int		ret;
	cpu_set_t	cs;

	if (ncpus > CPU_SETSIZE)
		return -1;

	CPU_ZERO(&cs);
	CPU_SET(cpu, &cs);
	if (CPU_COUNT(&cs) == 1)
		return 0;

	ret = sched_setaffinity(0, sizeof(cs), &cs);
	if (ret)
		return -1;

	/* guaranteed to take effect immediately */
	sched_yield();

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_pin_to_node - pin to the numa node of the cpu			     */
/*---------------------------------------------------------------------------*/
static inline int xio_pin_to_node(int cpu)
{
	int node = numa_node_of_cpu(cpu);
	/* pin to node */
	int ret = numa_run_on_node(node);

	if (ret)
		return -1;

	/* is numa_run_on_node() guaranteed to take effect immediately? */
	sched_yield();

	return -1;
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
#define  xio_sync_fetch_and_add32(ptr, value) \
	__sync_fetch_and_add((ptr), (value))
#define  xio_sync_fetch_and_add64(ptr, value) \
	__sync_fetch_and_add((ptr), (value))

/*---------------------------------------------------------------------------*/
#define XIO_F_ALWAYS_INLINE inline __attribute__((always_inline))

/*---------------------------------------------------------------------------*/
#define LIBRARY_INITIALIZER(f) \
	static void f(void)__attribute__((constructor)); \
	static void f(void)

/*---------------------------------------------------------------------------*/
#define LIBRARY_FINALIZER(f) \
	static void f(void)__attribute__((destructor)); \
	static void f(void)

/*---------------------------------------------------------------------------*/
#define inc_ptr(_ptr, inc)  ((_ptr) += (inc))
#define sum_to_ptr(_ptr, a) ((_ptr) + (a))

static inline uint64_t xio_get_current_thread_id(void)
{
	return (uint64_t)pthread_self();
}

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
#define XIO_ECONNREFUSED        ECONNREFUSED

typedef int socket_t;
/*---------------------------------------------------------------------------*/
static inline int xio_closesocket(socket_t sock)
{
	return close(sock);
}

/*---------------------------------------------------------------------------*/
static inline int xio_write(socket_t sock, const void *buf, size_t len)
{
	return write(sock, buf, len);
}

/*---------------------------------------------------------------------------*/
static inline ssize_t xio_read(socket_t sock, void *buf, size_t count)
{
	return read(sock, buf, count);
}

/*---------------------------------------------------------------------------*/
static inline int xio_get_last_socket_error(void)
{
	return errno;
}

/*---------------------------------------------------------------------------*/
/* enables or disables the blocking mode for the socket
   If mode != 0, blocking is enabled;
   If mode = 0, non-blocking mode is enabled. */
static inline int xio_set_blocking(socket_t sock, unsigned long mode)
{
	long arg = fcntl(sock, F_GETFL, NULL);

	if (arg < 0)
		return -1;

	if (mode)  /* blocking */
		arg &= (~O_NONBLOCK);

	else  /* non blocking */
		arg |= O_NONBLOCK;

	if (fcntl(sock, F_SETFL, arg) < 0)
		return -1;

	return 0;
}

/*---------------------------------------------------------------------------*/
static inline int xio_pipe(int socks[2], int is_blocking)
{
	return pipe2(socks, O_CLOEXEC | (is_blocking ? 0 : O_NONBLOCK));
}

/*---------------------------------------------------------------------------*/
static inline socket_t xio_socket_non_blocking(int domain, int type,
					       int protocol)
{
	return socket(domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
}

/*---------------------------------------------------------------------------*/
/* NOTE: we aren't using static inline function here; because accept4 requires
 * defining _GNU_SOURCE and we don't want users to be forced to define it in
 * their application */
#define xio_accept_non_blocking(sockfd, addr, addrlen) \
	accept4(sockfd, addr, addrlen, SOCK_NONBLOCK)

/*---------------------------------------------------------------------------*/
static inline void xio_env_cleanup(void)
{
	/* nothing to do */
}

/*---------------------------------------------------------------------------*/
static inline void xio_env_startup(void)
{
	/* nothing to do */
}

/*---------------------------------------------------------------------------*/
static inline int xio_timerfd_create(void)
{
	return timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
}

/*---------------------------------------------------------------------------*/
static inline int xio_timerfd_settime(int fd, int flags,
				      const struct itimerspec *new_value,
				      struct itimerspec *old_value)
{
	return timerfd_settime(fd, flags, new_value, old_value);
}

/*
 *  Determine whether some value is a power of two, where zero is
 * *not* considered a power of two.
 */

static inline __attribute__((const))
bool is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

#ifdef __cplusplus
}
#endif

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
#include <linux/bitops.h>

#endif /* XIO_ENV_H */
