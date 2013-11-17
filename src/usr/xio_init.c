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

#include "xio_os.h"
#include "libxio.h"
#include "xio_common.h"
#include "xio_tls.h"
#include "xio_sessions_store.h"
#include "xio_conns_store.h"

int page_size;


/*---------------------------------------------------------------------------*/
/* xio_constructor like module init					     */
/*---------------------------------------------------------------------------*/
__attribute__((constructor)) void xio_init(void)
{
	static atomic_t initialized;
	static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

	if (! atomic_read(&initialized)) {
		pthread_mutex_lock(&mtx);
		if (!atomic_read(&initialized)) {
			page_size = sysconf(_SC_PAGESIZE);
			xio_thread_data_construct();
			sessions_store_construct();
			conns_store_construct();
			atomic_set(&initialized, 1);
		}
		pthread_mutex_unlock(&mtx);
	}
}

__attribute__((destructor)) void xio_shutdown(void)
{
	static atomic_t initialized;
	static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

	if (! atomic_read(&initialized)) {
		pthread_mutex_lock(&mtx);
		if (!atomic_read(&initialized)) {
		}
		pthread_mutex_unlock(&mtx);
	}
}

