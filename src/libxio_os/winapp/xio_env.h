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

#include <Winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <time.h>
#include <assert.h>

#include <io.h>
#include <stdint.h>
#include <errno.h>
#include <BaseTsd.h>

#include <xio_base.h>
#include <xio_env_basic.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef SSIZE_T ssize_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef int64_t __s64;


#define __func__		__FUNCTION__
#define __builtin_expect(x,y)	(x) /* kickoff likely/unlikely in MSVC */
#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)

#define XIO_F_ALWAYS_INLINE	__forceinline

/*---------------------------------------------------------------------------*/
/*-------------------- Memory related things --------------------------------*/
/*---------------------------------------------------------------------------*/

#define PACKED_MEMORY( __Declaration__ ) __pragma( pack(push, 1) ) \
	__Declaration__ __pragma( pack(pop) )

/*---------------------------------------------------------------------------*/
static inline int xio_memalign(void **memptr, size_t alignment, size_t size){
	*memptr = _aligned_malloc(size, alignment);
	if (*memptr) return 0;     /* success */
	return errno ? errno : -1; /* error */
}

/*---------------------------------------------------------------------------*/
static inline void xio_memfree(void *memptr){
	_aligned_free(memptr);
}

/*---------------------------------------------------------------------------*/
static inline long xio_get_page_size(void)
{
	static long page_size = 0;

	if (!page_size) {
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);
		page_size = sysinfo.dwPageSize;
	}
	return page_size;
}

/*---------------------------------------------------------------------------*/
#define MAP_FAILED ((void *) -1)

/*---------------------------------------------------------------------------*/
static inline void *xio_mmap(size_t length){
	assert(0 && "not yet supported");
	return MAP_FAILED;
}

/*---------------------------------------------------------------------------*/
static inline int xio_munmap(void *addr, size_t length){
	assert(0 && "not yet supported");
	return -1;
}

/*---------------------------------------------------------------------------*/
static inline void *xio_numa_alloc_onnode(size_t size, int node)
{
	assert(0 && "not yet supported");
	return NULL;
}

/*---------------------------------------------------------------------------*/
static inline void xio_numa_free(void *start, size_t size) {
	assert(0 && "not yet supported");
}


/*---------------------------------------------------------------------------*/
/*-------------------- Threads related things -------------------------------*/
/*---------------------------------------------------------------------------*/

#define xio_tls __declspec(thread)

typedef INIT_ONCE thread_once_t;
static const INIT_ONCE INIT_ONCE_RESET_VALUE = INIT_ONCE_STATIC_INIT;
#define THREAD_ONCE_INIT     INIT_ONCE_STATIC_INIT
#define thread_once(once_control, init_routine) \
	InitOnceExecuteOnce(once_control, init_routine ## _msvc, NULL, NULL);
#define reset_thread_once_t(once_control) \
	memcpy(once_control, &INIT_ONCE_RESET_VALUE, sizeof(INIT_ONCE))
#define is_reset_thread_once_t(once_control) \
	(0 == memcmp(once_control, &INIT_ONCE_RESET_VALUE, sizeof(INIT_ONCE)))
#define  xio_sync_fetch_and_add32(ptr, value) \
		(InterlockedAddAcquire((volatile LONG *)(ptr), (value)) - (value))
#define  xio_sync_fetch_and_add64(ptr, value) \
		(InterlockedAddAcquire64((volatile LONG64 *)(ptr), (value)) - (value))

/* TODO: perhaps protect the type cast */
#define xio_sync_bool_compare_and_swap(ptr, oldval, newval) \
	((long)(oldval) == InterlockedCompareExchangeAcquire(\
	(volatile long*)(ptr), (long)(newval), (long)(oldval)))


/* TODO: consider removing (since user already must call xio_init()?
NOTICE:     if you'll use DllMain here - DO NOT call WSAStartup from DllMain */
#define LIBRARY_INITIALIZER(f) \
	static void f(void)

#define LIBRARY_FINALIZER(f) \
	static void f(void)


#ifdef __cplusplus
#define inc_ptr(_ptr, _inc) do {char *temp = (char*)(_ptr); \
				temp += (_inc); (_ptr) = temp; } while (0)
#else
#define inc_ptr(_ptr, _inc) ( ((char*)(_ptr)) += (_inc) )
#endif

#define sum_to_ptr(_ptr, a) ( ((char*)(_ptr)) + (a) )

static inline uint64_t xio_get_current_thread_id() {
	return GetCurrentThreadId();
}

/*---------------------------------------------------------------------------*/
/*------------------- CPU and Clock related things --------------------------*/
/*---------------------------------------------------------------------------*/
static inline long xio_get_num_processors(void)
{
	static long num_processors = 0;

	if (!num_processors) {
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);
		num_processors = sysinfo.dwNumberOfProcessors;
	}
	return num_processors;
}

/*---------------------------------------------------------------------------*/
static inline long xio_get_cpu(void)
{
	/*TODO: consider GetCurrentProcessorNumberEx */
	return GetCurrentProcessorNumber();
}

/*---------------------------------------------------------------------------*/
static inline int xio_numa_node_of_cpu(int cpu)
{
//	assert(0 && "not yet supported");
	return -1; /* error */
}

/*---------------------------------------------------------------------------*/
static inline int xio_numa_run_on_node(int node)
{
//	assert(0 && "not yet supported");
	return -1; /* error */
}

/*---------------------------------------------------------------------------*/
/* xio_pin_to_cpu - pin to specific cpu					     */
/*---------------------------------------------------------------------------*/
static int inline xio_pin_to_cpu(int cpu) {
	/* not supported yet in Windows */
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_pin_to_node - pin to the numa node of the cpu			     */
/*---------------------------------------------------------------------------*/
static inline int xio_pin_to_node(int cpu) {
	/* not supported yet in Windows */
	return 0;
}



struct timespec {
	time_t   tv_sec;        /* seconds */
	long     tv_nsec;       /* nanoseconds */
};

static const __int64 DELTA_EPOCH_IN_MICROSECS = 11644473600000000;

struct timezone2
{
	__int32  tz_minuteswest; /* minutes W of Greenwich */
	int  tz_dsttime;     /* type of dst correction */
};

struct itimerspec {
	struct timespec it_interval;  /* Interval for periodic timer */
	struct timespec it_value;     /* Initial expiration */
};

/*---------------------------------------------------------------------------*/
/* temp code here */
int static inline gettimeofday(struct timeval *tv, struct timezone2 *tz)
{
	if (tv != NULL) {
		FILETIME ft;
		__int64 tmpres = 0;

		ZeroMemory(&ft, sizeof(ft));

		GetSystemTimeAsFileTime(&ft);

		tmpres = ft.dwHighDateTime;
		tmpres <<= 32;
		tmpres |= ft.dwLowDateTime;

		/*converting file time to unix epoch*/
		tmpres /= 10;  /*convert into microseconds*/
		tmpres -= DELTA_EPOCH_IN_MICROSECS;
		tv->tv_sec = (__int32)(tmpres*0.000001);
		tv->tv_usec = (tmpres % 1000000);
	}

	/*_tzset(),don't work properly, so we use GetTimeZoneInformation */
	if (tz != NULL) {
		int rez = 0;
		TIME_ZONE_INFORMATION tz_winapi;
		ZeroMemory(&tz_winapi, sizeof(tz_winapi));
		rez = GetTimeZoneInformation(&tz_winapi);
		tz->tz_dsttime = (rez == 2);
		tz->tz_minuteswest = tz_winapi.Bias +
				     ((rez == 2) ? tz_winapi.DaylightBias : 0);
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
#define localtime_r( _clock, _result ) \
	(*(_result) = *localtime((const time_t *)(_clock)), \
	(_result))

/*---------------------------------------------------------------------------*
 * xio_get_cpu_mhz							     *
 *									     *
 * since this operation may take time cache it on a cookie,		     *
 * and use the cookie if exist						     *
 *									     *
 *---------------------------------------------------------------------------*/
static inline double xio_get_cpu_mhz(void)
{
	static double cpu_mhz;

	if (!cpu_mhz) {
		LARGE_INTEGER performanceFrequency;
		QueryPerformanceFrequency(&performanceFrequency);
		cpu_mhz = (double)performanceFrequency.QuadPart;
	}

	return cpu_mhz;
}

/*---------------------------------------------------------------------------*/
static inline int xio_clock_gettime(struct timespec *ts)
{
	LARGE_INTEGER           t;
	static LARGE_INTEGER    offset;
	static int              initialized = 0;
	static const long NANOSECONDS_IN_SECOND = 1000 * 1000 * 1000;
	static LARGE_INTEGER performanceFrequency;

	if (!initialized) {
		initialized = 1;
		QueryPerformanceFrequency(&performanceFrequency);
		QueryPerformanceCounter(&offset);
	}
	QueryPerformanceCounter(&t);

	t.QuadPart -= offset.QuadPart;
	t.QuadPart *= NANOSECONDS_IN_SECOND;
	t.QuadPart /= performanceFrequency.QuadPart;

	ts->tv_sec = (long)(t.QuadPart / NANOSECONDS_IN_SECOND);
	ts->tv_nsec = (long)(t.QuadPart % NANOSECONDS_IN_SECOND);
	return (0);
}

/*---------------------------------------------------------------------------*/
/*-------------------- Network related things -------------------------------*/
/*---------------------------------------------------------------------------*/

#define XIO_ESHUTDOWN               WSAESHUTDOWN
#define XIO_EINPROGRESS             WSAEWOULDBLOCK /* connect on non-blocking */
#define XIO_EAGAIN                  WSAEWOULDBLOCK /* recv    on non-blocking */
#define XIO_WOULDBLOCK              WSAEWOULDBLOCK /* recv    on non-blocking */
#define XIO_ECONNABORTED            WSAECONNABORTED
#define XIO_ECONNRESET              WSAECONNRESET
#define XIO_ECONNREFUSED            WSAECONNREFUSED


#define SHUT_RDWR SD_BOTH
#define MSG_NOSIGNAL 0

typedef SOCKET socket_t;


/*---------------------------------------------------------------------------*/
static inline int xio_get_last_socket_error() { return WSAGetLastError(); }

/*---------------------------------------------------------------------------*/
static inline int xio_closesocket(socket_t sock) {return closesocket(sock);}

/*---------------------------------------------------------------------------*/
static inline int xio_write(socket_t sock, const void *buf, size_t len) {
	return send(sock, (const char *)buf, len, 0);
}

/*---------------------------------------------------------------------------*/
static inline ssize_t xio_read(socket_t sock, void *buf, size_t count) {
	return recv(sock, (char *)buf, count, 0);
}

/*---------------------------------------------------------------------------*/
/*
*  based on: http://cantrip.org/socketpair.c
*
*  dumb_socketpair:
*  If make_overlapped is nonzero, both sockets created will be usable for
*  "overlapped" operations via WSASend etc.  If make_overlapped is zero,
*  socks[0] (only) will be usable with regular ReadFile etc., and thus
*  suitable for use as stdin or stdout of a child process.  Note that the
*  sockets must be closed with closesocket() regardless.
*
*  int dumb_socketpair(socket_t socks[2], int make_overlapped)
*/
static inline int socketpair(int domain, int type, int protocol,
			     socket_t socks[2])
{
	union {
		struct sockaddr_in inaddr;
		struct sockaddr addr;
	} a;
	socket_t listener;
	int e;
	socklen_t addrlen = sizeof(a.inaddr);
//	DWORD flags = 0; /* was: (make_overlapped ? WSA_FLAG_OVERLAPPED : 0); */
	DWORD flags = WSA_FLAG_OVERLAPPED;
	int reuse = 1;

	if (socks == 0) {
		WSASetLastError(WSAEINVAL);
		return SOCKET_ERROR;
	}

	/* was:	listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); */
	listener = socket(domain, type, protocol);
	if (listener == INVALID_SOCKET)
		return SOCKET_ERROR;

	memset(&a, 0, sizeof(a));
	a.inaddr.sin_family = domain;
	a.inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.inaddr.sin_port = 0;

	socks[0] = socks[1] = INVALID_SOCKET;
	do {
		if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
			(char*)&reuse, (socklen_t) sizeof(reuse)) == -1)
			break;
		if (bind(listener, &a.addr, sizeof(a.inaddr)) == SOCKET_ERROR)
			break;
		if (getsockname(listener, &a.addr, &addrlen) == SOCKET_ERROR)
			break;
		if (listen(listener, 1) == SOCKET_ERROR)
			break;
		/* was: socks[0] = WSASocket(domain, type, 0, NULL, 0, flags);*/
		socks[0] = WSASocket(domain, type, protocol, NULL, 0, flags);
		if (socks[0] == INVALID_SOCKET)
			break;
		if (connect(socks[0], &a.addr, sizeof(a.inaddr)) == SOCKET_ERROR)
			break;
		socks[1] = accept(listener, NULL, NULL);
		if (socks[1] == INVALID_SOCKET)
			break;

		xio_closesocket(listener);
		return 0;

	} while (0);

	e = WSAGetLastError();
	xio_closesocket(listener);
	xio_closesocket(socks[0]);
	xio_closesocket(socks[1]);
	WSASetLastError(e);
	return SOCKET_ERROR;
}

/*---------------------------------------------------------------------------*/
/* enables or disables the blocking mode for the socket
   If mode != 0, blocking is enabled;
   If mode = 0, non-blocking mode is enabled.
-----------------------------------------------------------------------------*/
static inline int xio_set_blocking(socket_t sock, unsigned long mode)
{
	int result;
	mode = !mode;
	result = ioctlsocket(sock, FIONBIO, &mode);
	return result == NO_ERROR ? 0 : -1;
}

/*---------------------------------------------------------------------------*/
static inline int xio_pipe(socket_t socks[2], int is_blocking)
{
	int ret = socketpair(AF_INET, SOCK_STREAM, IPPROTO_TCP, socks);
	if (ret) return -1;
	if (!is_blocking)
		if (xio_set_blocking(socks[0],0)||xio_set_blocking(socks[1],0)){
			xio_closesocket(socks[0]);
			xio_closesocket(socks[1]);
			return -1;
		}
	return 0;
}

/*---------------------------------------------------------------------------*/
static inline socket_t xio_socket_non_blocking(int domain, int type,
					       int protocol)
{
	socket_t sock_fd;
	sock_fd = socket(domain, type, protocol);
	if (sock_fd < 0) {
		return sock_fd;
	}

	if (xio_set_blocking(sock_fd, 0) < 0) {
		xio_closesocket(sock_fd);
		return -1;
	}
	return sock_fd;
}

/*---------------------------------------------------------------------------*/
static inline socket_t xio_accept_non_blocking(int sockfd,
					       struct sockaddr *addr,
					       socklen_t *addrlen) {
	socket_t new_sock_fd;
	new_sock_fd = accept(sockfd, addr, addrlen);
	if (new_sock_fd < 0) {
		return new_sock_fd;
	}

	if (xio_set_blocking(new_sock_fd, 0) < 0) {
		xio_closesocket(new_sock_fd);
		return -1;
	}
	return new_sock_fd;

}


struct iovec {                    /* Scatter/gather array items */
	void  *iov_base;              /* Starting address */
	size_t iov_len;               /* Number of bytes to transfer */
};

struct msghdr {
	void         *msg_name;       /* optional address */
	socklen_t     msg_namelen;    /* size of address */
	struct iovec *msg_iov;        /* scatter/gather array */
	size_t        msg_iovlen;     /* # elements in msg_iov */
	void         *msg_control;    /* ancillary data, see below */
	size_t        msg_controllen; /* ancillary data buffer len */
	int           msg_flags;      /* flags on received message */
};

/*---------------------------------------------------------------------------*/
#define IOV_MAX 50 /* avner temp - TODO: consider the value */

/*---------------------------------------------------------------------------*/
static inline ssize_t MIN(ssize_t x, ssize_t y) { return x < y ? x : y; }

/*---------------------------------------------------------------------------*/
ssize_t inline recvmsg(int sd, struct msghdr *msg, int flags)
{
	ssize_t bytes_read;
	size_t expected_recv_size;
	ssize_t left2move;
	char *tmp_buf;
	char *tmp;
	unsigned int i;

	assert(msg->msg_iov);

	expected_recv_size = 0;
	for (i = 0; i < msg->msg_iovlen; i++)
		expected_recv_size += msg->msg_iov[i].iov_len;
	tmp_buf = (char*)malloc(expected_recv_size);
	if (!tmp_buf)
		return -1;

	left2move = bytes_read = recvfrom(sd,
		tmp_buf,
		expected_recv_size,
		flags,
		(struct sockaddr *)msg->msg_name,
		&msg->msg_namelen
		);

	for (tmp = tmp_buf, i = 0; i < msg->msg_iovlen; i++)
	{
		if (left2move <= 0) break;
		assert(msg->msg_iov[i].iov_base);
		memcpy(
			msg->msg_iov[i].iov_base,
			tmp,
			MIN(msg->msg_iov[i].iov_len, left2move)
			);
		left2move -= msg->msg_iov[i].iov_len;
		tmp += msg->msg_iov[i].iov_len;
	}

	free(tmp_buf);

	return bytes_read;
}

/*---------------------------------------------------------------------------*/
ssize_t inline sendmsg(int sd, struct msghdr *msg, int flags)
{
	ssize_t bytes_send;
	size_t expected_send_size;
	size_t left2move;
	char *tmp_buf;
	char *tmp;
	unsigned int i;

	assert(msg->msg_iov);

	expected_send_size = 0;
	for (i = 0; i < msg->msg_iovlen; i++)
		expected_send_size += msg->msg_iov[i].iov_len;
	tmp_buf = (char*)malloc(expected_send_size);
	if (!tmp_buf)
		return -1;

	for (tmp = tmp_buf, left2move = expected_send_size, i = 0; i <
		msg->msg_iovlen; i++)
	{
		if (left2move <= 0) break;
		assert(msg->msg_iov[i].iov_base);
		memcpy(
			tmp,
			msg->msg_iov[i].iov_base,
			MIN(msg->msg_iov[i].iov_len, left2move));
		left2move -= msg->msg_iov[i].iov_len;
		tmp += msg->msg_iov[i].iov_len;
	}

	bytes_send = sendto(sd,
		tmp_buf,
		expected_send_size,
		flags,
		(struct sockaddr *)msg->msg_name,
		msg->msg_namelen
		);

	free(tmp_buf);

	return bytes_send;
}

/*---------------------------------------------------------------------------*/
/*-------------------- IO & miscelenious things -----------------------------*/
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
static inline void xio_env_cleanup() {
	WSACleanup();
}

/*---------------------------------------------------------------------------*/
static inline void xio_env_startup() {
	WSADATA wsaData;
	/* IMPORTANT: Don't call WSAStartup from DllMain because according to
	documentation it can lead to deadlock */
	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		fprintf(stderr, "FATAL ERROR: WSAStartup has failed\n");
		abort();
	}
}

/*---------------------------------------------------------------------------*/
static inline char *
strndup(char const *s, size_t n)
{
	size_t len = strnlen(s, n);
	char *new1 = (char*)malloc(len + 1);

	if (new1 == NULL)
		return NULL;

	new1[len] = '\0';
	return (char*)memcpy(new1, s, len);
}

/*---------------------------------------------------------------------------*/
/* based on:
http://stackoverflow.com/questions/2915672/snprintf-and-visual-studio-2010 */

#define snprintf c99_snprintf

/*---------------------------------------------------------------------------*/
inline int c99_vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
	int count = -1;

	if (size != 0)
		count = _vsnprintf_s(str, size, _TRUNCATE, format, ap);
	if (count == -1)
		count = _vscprintf(format, ap);

	return count;
}

/*---------------------------------------------------------------------------*/
inline int c99_snprintf(char* str, size_t size, const char* format, ...){
	int count;
	va_list ap;

	va_start(ap, format);
	count = c99_vsnprintf(str, size, format, ap);
	va_end(ap);

	return count;
}

/*---------------------------------------------------------------------------*/
static inline int close(int fd)
{
	return _close(fd);
}

#define ___GFP_WAIT	0x10u
#define ___GFP_IO	0x40u
#define ___GFP_FS	0x80u

#define GFP_KERNEL (___GFP_WAIT | ___GFP_IO | ___GFP_FS)

/* should be __bitwise__  but it is dummy */
typedef unsigned gfp_t;

 static inline char *kstrdup(const char *s, gfp_t gfp)
{
	/* Make sure code transfered to kernel will work as expected */
	assert(gfp == GFP_KERNEL);
	return ustrdup(s);
}

static inline char *kstrndup(const char *s, size_t len, gfp_t gfp)
{
	/* Make sure code transfered to kernel will work as expected */
	assert(gfp == GFP_KERNEL);
	return ustrndup(s, len);
}


/*---------------------------------------------------------------------------*/
/* ****** this section is devoted for not yet supported in Windows ********* */
/*---------------------------------------------------------------------------*/

static inline int xio_timerfd_create()
{
	return (int)xio_socket_non_blocking(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

static inline int xio_timerfd_settime(int fd, int flags,
	const struct itimerspec *new_value,
	struct itimerspec *old_value)
{
	return 0;
}

static inline int  xio_netlink(struct xio_context *ctx)
{
	/* not supported in Windows*/
	return 0;
}

/*
 *  Determine whether some value is a power of two, where zero is
 * *not* considered a power of two.
 */

static inline const bool is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

#ifdef __cplusplus
}
#endif

#endif /* XIO_ENV_H */
