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
#include "xio_common.h"
#include "xio_tls.h"
#include "xio_sessions_cache.h"
#include "xio_nexus_cache.h"
#include "xio_observer.h"
#include "xio_transport.h"
#include "xio_idr.h"
#include "xio_init.h"

int		page_size;
double		g_mhz;
struct xio_idr  *usr_idr = NULL;

#ifdef HAVE_INFINIBAND_VERBS_H
extern struct xio_transport xio_rdma_transport;
#endif

struct xio_transport *xio_rdma_get_transport_func_list(void);
struct xio_transport *xio_tcp_get_transport_func_list(void);

typedef struct xio_transport *(*get_transport_func_list_t)(void);

static get_transport_func_list_t  transport_func_list_tbl[] = {
#ifdef HAVE_INFINIBAND_VERBS_H
	xio_rdma_get_transport_func_list,
#endif
	xio_tcp_get_transport_func_list
};

#define  transport_tbl_sz (sizeof(transport_func_list_tbl) \
	/ sizeof(transport_func_list_tbl[0]))

static struct xio_transport  *transport_tbl[transport_tbl_sz];

static volatile int32_t	ini_refcnt; /*= 0 */
static DEFINE_MUTEX(ini_mutex);

extern double xio_get_cpu_mhz(void);

/*---------------------------------------------------------------------------*/
/* xio_dtor								     */
/*---------------------------------------------------------------------------*/
static void xio_dtor(void)
{
	size_t i;

	for (i = 0; i < transport_tbl_sz; i++) {
		if (transport_tbl[i] == NULL)
			continue;
		if (transport_tbl[i]->release)
			transport_tbl[i]->release(transport_tbl[i]);

		if (transport_tbl[i]->dtor)
			transport_tbl[i]->dtor();

		xio_unreg_transport(transport_tbl[i]);
	}
	xio_idr_destroy(usr_idr);
	xio_thread_data_destruct();
	xio_env_cleanup();
}

/*---------------------------------------------------------------------------*/
/* xio_dtor								     */
/*---------------------------------------------------------------------------*/
static void xio_ctor(void)
{
	size_t i;

	xio_env_startup();
	for (i = 0; i < transport_tbl_sz; i++)
		if (!transport_tbl[i])
			transport_tbl[i] = transport_func_list_tbl[i]();

	page_size = xio_get_page_size();
	if (page_size < 0)
		page_size = 4096;
	g_mhz = xio_get_cpu_mhz();
	xio_thread_data_construct();
	usr_idr = xio_idr_create();
	if (!usr_idr)
		ERROR_LOG("usr_idr creation failed");
	sessions_cache_construct();
	nexus_cache_construct();

	for (i = 0; i < transport_tbl_sz; i++) {
		if (transport_tbl[i] == NULL)
			continue;
		xio_reg_transport(transport_tbl[i]);

		if (transport_tbl[i]->ctor)
			transport_tbl[i]->ctor();
	}
}

void xio_init(void)
{
	mutex_lock(&ini_mutex);
	if (++ini_refcnt == 1)
		xio_ctor();
	mutex_unlock(&ini_mutex);
}

void xio_shutdown(void)
{
	mutex_lock(&ini_mutex);
	if (ini_refcnt <= 0) {
		ERROR_LOG("reference count < 0\n");
		abort();
		mutex_unlock(&ini_mutex);
		return;
	}
	if (--ini_refcnt == 0)
		xio_dtor();
	mutex_unlock(&ini_mutex);
}

int xio_inited(void)
{
	int ret;
	mutex_lock(&ini_mutex);
	ret = ini_refcnt;
	mutex_unlock(&ini_mutex);
	return ret;
}

