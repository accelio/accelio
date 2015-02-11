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
#include <xio_os.h>
#include "libxio.h"
#include "xio_log.h"

void xio_vlog(const char *file, unsigned line, const char *function,
	      unsigned level, const char *fmt, ...);

enum xio_log_level	xio_logging_level = XIO_LOG_LEVEL_ERROR;
xio_log_fn		xio_vlog_fn = xio_vlog;

#define LOG_TIME_FMT "%04d/%02d/%02d-%02d:%02d:%02d.%05ld"

/*---------------------------------------------------------------------------*/
/* xio_vlog								     */
/*---------------------------------------------------------------------------*/
void xio_vlog(const char *file, unsigned line, const char *function,
	      unsigned level, const char *fmt, ...)
{
	va_list			args;
	const char		*short_file;
	struct timeval		tv;
	struct tm		t;
	char			buf[2048];
	char			buf2[256];
	int			length = 0;
	static const char * const level_str[] = {
		"FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
	};
	time_t time1;

	va_start(args, fmt);
	length = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	buf[length] = 0;

	gettimeofday(&tv, NULL);
	time1 = (time_t)tv.tv_sec;
	localtime_r(&time1, &t);

	short_file = strrchr(file, '/');
	short_file = (!short_file) ? file : short_file + 1;

	snprintf(buf2, sizeof(buf2), "%s:%u", short_file, line);
	/*
	fprintf(stderr,
		"[%012lu.%06lu] %-28s [%-5s] - %s",
		tv.tv_sec, tv.tv_usec, buf2, level_str[level], buf);
	*/
	fprintf(stderr,
		"[" LOG_TIME_FMT "] %-28s [%-5s] - %s",
		t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
		t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec,
		buf2,
		level_str[level], buf);

	fflush(stderr);
}

/*---------------------------------------------------------------------------*/
/* xio_read_logging_level						     */
/*---------------------------------------------------------------------------*/
void xio_read_logging_level(void)
{
	char *val = getenv("XIO_TRACE");
	int level  = 0;

	if (!val)
		return;

	level  = atoi(val);
	if (level >= XIO_LOG_LEVEL_FATAL && level <= XIO_LOG_LEVEL_TRACE)
		xio_logging_level = (enum xio_log_level)level;
}

