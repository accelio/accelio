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
#include <linux/kernel.h>
#include <linux/module.h>

#include "libxio.h"
#include "xio_common.h"
#include "xio_sessions_store.h"
#include "xio_conns_store.h"
#include "xio_conn.h"
#include "xio_context.h"

MODULE_AUTHOR("Eyal Solomon, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO generic part "
	   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

/*---------------------------------------------------------------------------*/
/* xio_constructor							     */
/*---------------------------------------------------------------------------*/

static int __init xio_init_module(void)
{
	sessions_store_construct();
	conns_store_construct();

	return 0;
}

static void __exit xio_cleanup_module(void)
{
}

module_init(xio_init_module);
module_exit(xio_cleanup_module);

EXPORT_SYMBOL(xio_ctx_open);
EXPORT_SYMBOL(xio_ctx_close);
EXPORT_SYMBOL(xio_context_add_observer);
EXPORT_SYMBOL(xio_context_remove_observer);

EXPORT_SYMBOL(xio_set_error);
EXPORT_SYMBOL(xio_get_error);
EXPORT_SYMBOL(xio_strerror);
EXPORT_SYMBOL(xio_errno);

EXPORT_SYMBOL(xio_reg_transport);
EXPORT_SYMBOL(xio_unreg_transport);

EXPORT_SYMBOL(xio_conn_get_initial_task);
EXPORT_SYMBOL(xio_conn_get_primary_task);
EXPORT_SYMBOL(xio_conn_task_lookup);
EXPORT_SYMBOL(xio_conn_set_pools_ops);

EXPORT_SYMBOL(memcpyv);
EXPORT_SYMBOL(memclonev);

EXPORT_SYMBOL(xio_ev_loop_add_event);
EXPORT_SYMBOL(xio_ev_loop_stop);
EXPORT_SYMBOL(xio_ev_loop_run);

EXPORT_SYMBOL(xio_uri_to_ss);
EXPORT_SYMBOL(xio_session_open);
EXPORT_SYMBOL(xio_session_close);
EXPORT_SYMBOL(xio_session_event_str);

EXPORT_SYMBOL(xio_bind);
EXPORT_SYMBOL(xio_accept);
EXPORT_SYMBOL(xio_unbind);
EXPORT_SYMBOL(xio_connect);
EXPORT_SYMBOL(xio_disconnect);

EXPORT_SYMBOL(xio_send_request);
EXPORT_SYMBOL(xio_send_response);
EXPORT_SYMBOL(xio_release_response);

EXPORT_SYMBOL(xio_write_tlv);
EXPORT_SYMBOL(xio_read_tlv);
EXPORT_SYMBOL(xio_iov_length);
EXPORT_SYMBOL(xio_iovex_length);
