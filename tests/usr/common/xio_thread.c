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
#include "xio_thread.h"
#include <stdlib.h>

/* Platform specific includes */
#if defined(_XIO_THREAD_POSIX_)
  #include <sys/time.h>
#elif defined(_XIO_THREAD_WIN32_)
  #include <process.h>
  #include <sys/timeb.h>
#endif

/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
/** Information to pass to the new thread (what to run). */
struct xio_thread_start_info {
	xio_thread_start_t function; /* ptr to the function to be executed */
	void		   *arg;     /* argument for the thread function */
};

/*---------------------------------------------------------------------------*/
/* _xio_thread_wrapper_function						     */
/*---------------------------------------------------------------------------*/
/* Thread wrapper function. */
#if defined(_XIO_THREAD_WIN32_)
static unsigned WINAPI _xio_thread_wrapper_function(void *_arg)
#elif defined(_XIO_THREAD_POSIX_)
static void *_xio_thread_wrapper_function(void *_arg)
#endif
{
	xio_thread_start_t func;
	void *arg;
	int  res;
#if defined(_XIO_THREAD_POSIX_)
	void *pres;
#endif

	/* Get thread startup information */
	struct xio_thread_start_info *ti =
					(struct xio_thread_start_info *)_arg;
	func	= ti->function;
	arg	= ti->arg;

	/* The thread is responsible for freeing the startup information */
	free((void *)ti);

	/* Call the actual client thread function */
	res = func(arg);

#if defined(_XIO_THREAD_WIN32_)
	return res;
#else
	pres = malloc(sizeof(int));
	if (pres != NULL)
		*(int *)pres = res;

	  return pres;
#endif
}

/*---------------------------------------------------------------------------*/
/* xio_thread_create							     */
/*---------------------------------------------------------------------------*/
int xio_thread_create(xio_thread_t *thr, xio_thread_start_t func, void *arg)
{
	/* Fill out the thread startup information (passed to
	 * the thread wrapper, which will eventually free it) */
	struct xio_thread_start_info *ti =
		(struct xio_thread_start_info *)malloc(sizeof(*ti));
	if (ti == NULL)
		return XIO_THREAD_NOMEM;

	ti->function = func;
	ti->arg = arg;

	/* Create the thread */
#if defined(_XIO_THREAD_WIN32_)
	*thr = (HANDLE)_beginthreadex(NULL, 0,
			_xio_thread_wrapper_function,
			(void *)ti, 0, NULL);
#elif defined(_XIO_THREAD_POSIX_)
	if (pthread_create(thr, NULL,
			   _xio_thread_wrapper_function,
			   (void *)ti) != 0)
		*thr = 0;
#endif

	/* Did we fail to create the thread? */
	if (!*thr) {
		free(ti);
		return XIO_THREAD_ERROR;
	}

	return XIO_THREAD_SUCCESS;
}

/*---------------------------------------------------------------------------*/
/* xio_thread_current							     */
/*---------------------------------------------------------------------------*/
xio_thread_t xio_thread_current(void)
{
#if defined(_XIO_THREAD_WIN32_)
	return GetCurrentThread();
#else
	return pthread_self();
#endif
}

/*---------------------------------------------------------------------------*/
/* xio_thread_exit							     */
/*---------------------------------------------------------------------------*/
void xio_thread_exit(int res)
{
#if defined(_XIO_THREAD_WIN32_)
	ExitThread(res);
#else
	void *pres = malloc(sizeof(int));

	if (pres != NULL)
		*(int *)pres = res;

	pthread_exit(pres);
#endif
}

/*---------------------------------------------------------------------------*/
/* xio_thread_join							     */
/*---------------------------------------------------------------------------*/
int xio_thread_join(xio_thread_t thr, int *res)
{
#if defined(_XIO_THREAD_WIN32_)
	if (WaitForSingleObject(thr, INFINITE) == WAIT_FAILED)
		return XIO_THREAD_ERROR;

	if (res != NULL) {
		DWORD dwRes;

		GetExitCodeThread(thr, &dwRes);
		*res = dwRes;
	}
	CloseHandle(thr);
#elif defined(_XIO_THREAD_POSIX_)
	void *pres;
	int ires = 0;

	if (pthread_join(thr, &pres) != 0)
		return XIO_THREAD_ERROR;
	if (pres != NULL) {
		ires = *(int *)pres;
		free(pres);
	}
	if (res != NULL)
		*res = ires;
#endif

	return XIO_THREAD_SUCCESS;
}

/*---------------------------------------------------------------------------*/
/* xio_thread_clock_gettime						     */
/*---------------------------------------------------------------------------*/
int xio_thread_clock_gettime(clockid_t clk_id, struct timespec *ts)
{
#if defined(_XIO_THREAD_WIN32_)
	if (clk_id == CLOCK_REALTIME) {
		struct _timeb tb;

		_ftime(&tb);
		ts->tv_sec = (time_t)tb.time;
		ts->tv_nsec = 1000000L * (long)tb.millitm;
	} else if (clk_id == CLOCK_MONOTONIC) {
		ULONGLONG tick = GetTickCount64();

		/* We're just using GetTickCount(). */
		tp->tv_sec = (time_t) (ticks / 1000);
		tp->tv_nsec = (long)(ticks % 1000) * 1000000L;
	}
#else  /*
	struct timeval tv;

	gettimeofday(&tv, NULL);
	ts->tv_sec = (time_t)tv.tv_sec;
	ts->tv_nsec = 1000L * (long)tv.tv_usec;
	*/
	if (clock_gettime(clk_id, ts) != 0)
		return XIO_THREAD_ERROR;

#endif
	return XIO_THREAD_SUCCESS;
}

