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
#ifndef XIO_LOG_H
#define XIO_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Enable compiler checks for printf-like formatting.
 *
 * @param fmtargN number of formatting argument
 * @param vargN   number of variadic argument
 */
#define XIO_F_PRINTF(fmtarg, varg) \
	__attribute__((__format__(printf, fmtarg, varg)))

/*---------------------------------------------------------------------------*/
/* enum									     */
/*---------------------------------------------------------------------------*/
extern enum xio_log_level	xio_logging_level;
extern xio_log_fn		xio_vlog_fn;

extern void xio_vlog(const char *file, unsigned line, const char *function,
		     unsigned level, const char *fmt, ...);

#define xio_log(level, fmt, ...) \
	do { \
		if (unlikely(((level) < XIO_LOG_LEVEL_LAST) &&  \
					(level) <= xio_logging_level)) { \
			xio_vlog_fn(__FILE__, __LINE__, __func__, (level), \
				    fmt, ## __VA_ARGS__); \
		} \
	} while (0)

#define FATAL_LOG(fmt, ...)	xio_log(XIO_LOG_LEVEL_FATAL, fmt, \
							## __VA_ARGS__)
#define ERROR_LOG(fmt, ...)	xio_log(XIO_LOG_LEVEL_ERROR, fmt, \
							## __VA_ARGS__)
#define WARN_LOG(fmt, ...)	xio_log(XIO_LOG_LEVEL_WARN, fmt,\
							## __VA_ARGS__)
#define INFO_LOG(fmt, ...)	xio_log(XIO_LOG_LEVEL_INFO, fmt,\
							## __VA_ARGS__)
#define DEBUG_LOG(fmt, ...)	xio_log(XIO_LOG_LEVEL_DEBUG, fmt,\
							##  __VA_ARGS__)
#define TRACE_LOG(fmt, ...)	xio_log(XIO_LOG_LEVEL_TRACE, fmt,\
							## __VA_ARGS__)

void xio_read_logging_level(void);

static inline int xio_set_log_level(enum xio_log_level level)
{
	xio_logging_level = level;

	return 0;
}

static inline enum xio_log_level xio_get_log_level(void)
{
	return xio_logging_level;
}

static inline int xio_set_log_fn(xio_log_fn fn)
{
	if (!fn)
		xio_vlog_fn = xio_vlog;
	else
		xio_vlog_fn = fn;

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* XIO_LOG_H */
