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

#include <linux/kernel.h>

#define FATAL_LOG(fmt, ...) \
	pr_crit("FATAL: %s:%d::%s(): " pr_fmt(fmt), \
		__FILE__, __LINE__, __func__,\
		## __VA_ARGS__)

#define ERROR_LOG(fmt, ...) \
	pr_err("ERROR: %s:%d::%s(): " pr_fmt(fmt), \
		__FILE__, __LINE__, __func__,\
		## __VA_ARGS__)

#define WARN_LOG(fmt, ...) \
	pr_warn("WARN: %s:%d::%s(): " pr_fmt(fmt), \
		__FILE__, __LINE__, __func__,\
		## __VA_ARGS__)

#define INFO_LOG(fmt, ...) \
	pr_info("INFO: %s:%d::%s(): " pr_fmt(fmt), \
		__FILE__, __LINE__, __func__,\
		## __VA_ARGS__)

#define DEBUG_LOG(fmt, ...) \
	pr_debug("DEBUG: %s:%d::%s(): " pr_fmt(fmt), \
		__FILE__, __LINE__, __func__,\
		## __VA_ARGS__)

/* pr_devel() should produce zero code unless DEBUG is defined */
#define TRACE_LOG(fmt, ...) \
	pr_devel("TRACE: %s:%d::%s(): " pr_fmt(fmt), \
		__FILE__, __LINE__, __func__,\
		## __VA_ARGS__)

/* Not yet implemented, parameter or sysfs */
static inline void xio_read_logging_level(void)
{
	pr_devel("xio_read_logging_level\n");
}

static inline int xio_set_log_level(int /*enum xio_log_level*/ level)
{
	return -1;
}

static inline int /*enum xio_log_level*/ xio_get_log_level(void)
{
	return 0;
}

static inline int xio_set_log_fn(void * /*xio_log_fn*/ fn)
{
	return -1;
}

#endif /* XIO_LOG_H */
