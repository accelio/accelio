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

#include "xio_os.h"
#include "libxio.h"
#include "xio_observer.h"
#include "xio_common.h"
#include "xio_sessions_cache.h"
#include "xio_nexus_cache.h"
#include "xio_nexus.h"
#include "xio_task.h"
#include "xio_context.h"

MODULE_AUTHOR("Eyal Solomon, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO generic part "
	   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

/* The root of XIO debugfs tree */
static struct dentry *xio_root;

/*---------------------------------------------------------------------------*/
/* xio_constructor							     */
/*---------------------------------------------------------------------------*/

static int __init xio_init_module(void)
{
	if (debugfs_initialized()) {
		xio_root = debugfs_create_dir("xio", NULL);
		if (!xio_root) {
			pr_err("xio_root debugfs creation failed\n");
			return -ENOMEM;
		}
	} else {
		xio_root = NULL;
		pr_err("debugfs not initialized\n");
	}

	sessions_cache_construct();
	nexus_cache_construct();

	return 0;
}

static void __exit xio_cleanup_module(void)
{
	if (xio_root) {
		debugfs_remove_recursive(xio_root);
		xio_root = NULL;
	}
}

struct dentry *xio_debugfs_root(void)
{
	return xio_root;
}

module_init(xio_init_module);
module_exit(xio_cleanup_module);

EXPORT_SYMBOL(xio_context_create);
EXPORT_SYMBOL(xio_context_destroy);
EXPORT_SYMBOL(xio_modify_context);
EXPORT_SYMBOL(xio_query_context);


EXPORT_SYMBOL(xio_context_reg_observer);
EXPORT_SYMBOL(xio_context_unreg_observer);

EXPORT_SYMBOL(xio_observable_reg_observer);
EXPORT_SYMBOL(xio_observable_unreg_observer);
EXPORT_SYMBOL(xio_observable_notify_observer);
EXPORT_SYMBOL(xio_observable_notify_all_observers);
EXPORT_SYMBOL(xio_observable_notify_any_observer);
EXPORT_SYMBOL(xio_observable_unreg_all_observers);

EXPORT_SYMBOL(xio_set_error);
EXPORT_SYMBOL(xio_strerror);
EXPORT_SYMBOL(xio_errno);

EXPORT_SYMBOL(xio_reg_transport);
EXPORT_SYMBOL(xio_unreg_transport);

EXPORT_SYMBOL(memcpyv);
EXPORT_SYMBOL(memclonev);
EXPORT_SYMBOL(memcpyv_ex);
EXPORT_SYMBOL(memclonev_ex);


EXPORT_SYMBOL(xio_context_add_event);
EXPORT_SYMBOL(xio_context_stop_loop);
EXPORT_SYMBOL(xio_context_run_loop);

EXPORT_SYMBOL(xio_uri_to_ss);
EXPORT_SYMBOL(xio_host_port_to_ss);

EXPORT_SYMBOL(xio_session_create);
EXPORT_SYMBOL(xio_session_destroy);
EXPORT_SYMBOL(xio_session_event_str);

EXPORT_SYMBOL(xio_bind);
EXPORT_SYMBOL(xio_accept);
EXPORT_SYMBOL(xio_unbind);
EXPORT_SYMBOL(xio_connect);
EXPORT_SYMBOL(xio_disconnect);

EXPORT_SYMBOL(xio_get_connection);
EXPORT_SYMBOL(xio_connection_destroy);
EXPORT_SYMBOL(xio_modify_connection);
EXPORT_SYMBOL(xio_query_connection);

EXPORT_SYMBOL(xio_query_session);
EXPORT_SYMBOL(xio_modify_session);

EXPORT_SYMBOL(xio_send_request);
EXPORT_SYMBOL(xio_send_response);
EXPORT_SYMBOL(xio_release_response);

EXPORT_SYMBOL(xio_write_tlv);
EXPORT_SYMBOL(xio_read_tlv);
EXPORT_SYMBOL(xio_iov_length);
EXPORT_SYMBOL(xio_iovex_length);

EXPORT_SYMBOL(xio_tasks_pool_create);
EXPORT_SYMBOL(xio_tasks_pool_destroy);
EXPORT_SYMBOL(xio_tasks_pool_alloc_slab);
