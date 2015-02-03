/*
 * Copyright (c) 2015 Mellanox Technologies®. All rights reserved.
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
#ifndef XIO_THREAD_H
#define XIO_THREAD_H

/* Which platform are we on? */
#if defined(_WIN32) || defined(__WIN32__) || defined(__WINDOWS__)
    #define _XIO_THREAD_WIN32_
#else
    #define _XIO_THREAD_POSIX_
#endif

/* Activate some POSIX functionality (e.g. clock_gettime) */
#if defined(_XIO_THREAD_POSIX_)
  #undef _FEATURES_H
  #if !defined(_GNU_SOURCE)
    #define _GNU_SOURCE
  #endif
  #if !defined(_POSIX_C_SOURCE) || ((_POSIX_C_SOURCE - 0) < 199309L)
    #undef _POSIX_C_SOURCE
    #define _POSIX_C_SOURCE 199309L
  #endif
  #if !defined(_XOPEN_SOURCE) || ((_XOPEN_SOURCE - 0) < 500)
    #undef _XOPEN_SOURCE
    #define _XOPEN_SOURCE 500
  #endif
#endif

/* Generic includes */
#include <time.h>

/* Platform specific includes */
#if defined(_XIO_THREAD_POSIX_)
  #include <pthread.h>
#elif defined(_XIO_THREAD_WIN32_)
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #define __UNDEF_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #ifdef __UNDEF_LEAN_AND_MEAN
    #undef WIN32_LEAN_AND_MEAN
    #undef __UNDEF_LEAN_AND_MEAN
  #endif
#endif

/*
 * The IDs of the various system clocks (for POSIX.1b interval timers):
 */
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME			0
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC			1
#endif


/* Workaround for missing clock_gettime (most Windows compilers) */
#if defined(_XIO_THREAD_WIN32_)
/* Emulate struct timespec */
struct _ttherad_timespec {
	time_t	tv_sec;
	long	tv_nsec;
};

#define timespec _ttherad_timespec

/* Emulate clockid_t */
typedef int xio_thread_clockid_t;
#define clockid_t xio_thread_clockid_t

/* Emulate clock_gettime */
int xio_thread_clock_gettime(clockid_t clk_id, struct timespec *ts);
#define clock_gettime xio_thread_clock_gettime
#endif

/* Function return values */
#define XIO_THREAD_SUCCESS  0 /**< The requested operation succeeded */
#define XIO_THREAD_ERROR    1 /**< The requested operation failed */
#define XIO_THREAD_NOMEM    2 /**< The requested operation failed i
				   because it was unable to allocate memory */

/* Thread */
#if defined(_XIO_THREAD_WIN32_)
typedef HANDLE xio_thread_t;
#else
typedef pthread_t xio_thread_t;
#endif

/**
 * @brief Thread start function.
*
* Any thread that is started with the @ref thread_create() function must be
* started through a function of this type.
*
* @param arg	The thread argument (the @c arg argument of the corresponding
*		@ref thread_create() call).
*
* @return The thread return value, which can be obtained by another thread
*	  by using the @ref thread_join() function.
*/
typedef int (*xio_thread_start_t)(void *arg);

/**
 * @brief Create a new thread.
 *
 * @param thr	Identifier of the newly created thread.
 * @param func	A function pointer to the function that will be executed in
 *		the new thread.
 * @param arg	An argument to the thread function.
 *
 * @return @ref XIO_THREAD_SUCCESS on success, or @ref XIO_THREAD_NOMEM
 *	   if no memory could be allocated for the thread requested,
 *	   or @ref XIO_THREAD_ERROR if the request could not be honored.
 *
 * @note A thread’s identifier may be reused for a different thread once the
 * original thread has exited and either been detached or joined to another
 * thread.
 */
int xio_thread_create(xio_thread_t *thr, xio_thread_start_t func, void *arg);

/**
 * @brief Identify the calling thread.
 *
 * @return The identifier of the calling thread.
 */
xio_thread_t xio_thread_current(void);

/**
 * @brief Terminate execution of the calling thread.
 *
 * @param res Result code of the calling thread.
 */
void xio_thread_exit(int res);

/**
 * @brief Wait for a thread to terminate.
 *
 * The function joins the given thread with the current thread by blocking
 * until the other thread has terminated.
 * @param thr	The thread to join with.
 * @param res	If this pointer is not NULL, the function will store the result
 *		code of the given thread in the integer pointed to by @c res.
 *
 * @return @ref XIO_THREAD_SUCCESS on success,
 *	   or @ref XIO_THREAD_ERROR if the request could not be honored.
 */
int xio_thread_join(xio_thread_t thr, int *res);

#endif /* XIO_THREAD_H_ */

