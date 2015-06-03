/*
 * Copyright (c) 2013 Mellanox Technologies®. All rights reserved.
 * Copyright (c) 2014-2015, E8 Storage Systems Ltd. All Rights Reserved.
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
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/completion.h>
#include <linux/scatterlist.h>

#include "libxio.h"
#include "xio_msg.h"
#include "xio_test_utils.h"
#include "xio_rdma_common.h"

MODULE_AUTHOR("Alex Friedman");
MODULE_LICENSE("Dual BSD/GPL");

static char *url = "rdma://127.0.0.1:2061";
module_param(url, charp, 0);

static struct task_struct *xio_main_th;
static struct completion cleanup_complete;

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	/*struct xio_connection_attr	conn_attr;*/

	pr_info("session event: %s. session:%p, connection:%p, reason: %s\n",
		xio_session_event_str(event_data->event),
		session, event_data->conn,
		xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		if (!test_params.connection)
			test_params.connection = event_data->conn;
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		if (event_data->reason != XIO_E_SESSION_REJECTED)
			test_params.connection = NULL;
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		if (event_data->reason != XIO_E_SESSION_REJECTED)
			xio_context_stop_loop(test_params.ctx);
		break;
	default:
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
static int xio_server_main(void *data)
{
	struct xio_server		*server;
	struct xio_context_params	ctx_params;

	init_xio_rdma_common_test();

	memset(&ctx_params, 0, sizeof(ctx_params));
	ctx_params.flags = XIO_LOOP_GIVEN_THREAD;
	ctx_params.worker = current;

	test_params.ctx = xio_context_create(&ctx_params, 0, 0);
	xio_assert(test_params.ctx);

	session_ops.on_session_event = on_session_event;
	server = xio_bind(test_params.ctx, &session_ops,
			  url, NULL, 0, NULL);
	xio_assert(server);
	pr_info("listen to %s\n", url);

	xio_context_run_loop(test_params.ctx);

	/* normal exit phase */
	pr_info("exit signaled\n");

	/* free the server */
	xio_unbind(server);
	xio_context_destroy(test_params.ctx);
	fini_xio_rdma_common_test();

	complete_and_exit(&cleanup_complete, 0);

	return 0;
}

static int __init xio_rdma_init_module(void)
{
	init_completion(&cleanup_complete);

	xio_main_th = kthread_run(xio_server_main, NULL,
				  "xio-rdma-server");
	if (IS_ERR(xio_main_th)) {
		complete(&cleanup_complete);
		return PTR_ERR(xio_main_th);
	}

	return 0;
}

static void __exit xio_rdma_cleanup_module(void)
{
	wait_for_completion(&cleanup_complete);
}

module_init(xio_rdma_init_module);
module_exit(xio_rdma_cleanup_module);
