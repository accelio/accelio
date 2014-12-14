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

#include <xio_os.h>
#include "libxio.h"
#include "xio_sessions_cache.h"
#include "xio_nexus_cache.h"
#include "xio_idr.h"

MODULE_AUTHOR("Eyal Solomon, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO generic part "	\
	   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

/* The root of XIO debugfs tree */
static struct dentry *xio_root;
struct xio_idr *usr_idr = NULL;

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
	usr_idr = xio_idr_create();
	if (!usr_idr) {
		pr_err("usr_idr creation failed\n");
		return -ENOMEM;
	}

	return 0;
}

static void __exit xio_cleanup_module(void)
{
	xio_idr_destroy(usr_idr);
	debugfs_remove_recursive(xio_root);
}

struct dentry *xio_debugfs_root(void)
{
	return xio_root;
}

module_init(xio_init_module);
module_exit(xio_cleanup_module);

