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

#include "libxio.h"

#include "abstraction.h"
#include "xio_rdma_common.h"
#include "xio_test_utils.h"
#include "xio_msg.h"

struct rdma_test_buf {
	uint64_t	addr;
	size_t		length;
	uint32_t	rkey;
	uint32_t	pad;
};

struct test_params test_params;
static struct xio_reg_mem rdma_reg_mem;
static struct rdma_test_buf rdma_test_buf;

#define TEST_PATTERN 0xab
#define RDMA_BUF_SIZE 8192

#define MAX_POOL_SIZE		16

static int on_new_session(struct xio_session *session,
			  struct xio_new_session_req *req,
			  void *cb_user_context)
{
	pr_info("**** [%p] on_new_session\n", session);

	if (test_params.connection == NULL)
		xio_accept(session, NULL, 0, NULL, 0);
	else
		xio_reject(session, (enum xio_status)EISCONN, NULL, 0);

	return 0;
}

static int publish_our_buffer(struct xio_session *session, struct xio_msg *req)
{
	struct xio_msg *rsp = msg_pool_get(test_params.pool);
	struct xio_vmsg *pmsg;
	int res;

	xio_assert(rsp);
	rsp->request = req;
	pmsg = &rsp->out;

	/* usually accelio batches on_msg_send_complete callbacks in batches
	 * of 16 to maximize performance. In case server will send just
	 * several responses and wants to receive the callback immidiately
	 * this flag must be on */
	rsp->flags = XIO_MSG_FLAG_IMM_SEND_COMP;

	rdma_test_buf.addr = (uint64_t)rdma_reg_mem.addr;
	rdma_test_buf.length = rdma_reg_mem.length;
	rdma_test_buf.rkey = xio_lookup_rkey_by_response(&rdma_reg_mem, rsp);

	pmsg->header.iov_len = sizeof(rdma_test_buf);
	pmsg->header.iov_base = (void*)&rdma_test_buf;

	vmsg_sglist_set_nents(pmsg, 0);

	res = xio_send_response(rsp);
	xio_assert(!res);
	return 0;
}

static struct rdma_test_buf test_remote_buf;
static struct xio_sge test_rdma_sge;
static struct xio_managed_rkey *test_rkey;
static int test_stage = 0;

static void test_common_do_rdma_op(int is_read)
{
	int res;
	struct xio_msg *outgoing = msg_pool_get(test_params.pool);
	struct xio_rdma_msg *rdma_msg = &outgoing->rdma;

	test_rdma_sge.addr = test_remote_buf.addr;
	test_rdma_sge.length = test_remote_buf.length;
	test_rdma_sge.stag = xio_managed_rkey_unwrap(test_rkey);

	rdma_msg->is_read = is_read;
	rdma_msg->length = test_remote_buf.length;
	rdma_msg->nents = 1;
	rdma_msg->rsg_list = &test_rdma_sge;

	vmsg_sglist_set_by_reg_mem(&outgoing->out, &rdma_reg_mem);

	res = xio_send_rdma(test_params.connection, outgoing);
	xio_assert(!res);
}

static void test_rdma_read_from_remote_buffer(void)
{
	memset(rdma_reg_mem.addr, 0, rdma_reg_mem.length);
	test_common_do_rdma_op(1 /* RDMA read */);
}

static int test_rdma_write_to_remote_buffer(struct xio_session *session,
					    struct xio_msg *rsp)
{
	struct xio_vmsg *pmsg = &rsp->in;
	test_remote_buf = *(struct rdma_test_buf *)
		pmsg->header.iov_base;

	test_rkey = xio_register_remote_rkey(
		test_params.connection, test_remote_buf.rkey);
	xio_assert(test_rkey);

	memset(rdma_reg_mem.addr, TEST_PATTERN, rdma_reg_mem.length);

	test_common_do_rdma_op(0 /* RDMA write */);

	xio_release_response(rsp);
	msg_pool_put(test_params.pool, rsp);
	return 0;
}

static int on_message(struct xio_session *session, struct xio_msg *msg,
		      int last_in_rxq, void *cb_user_context)
{
	switch (msg->type) {
	case XIO_MSG_TYPE_REQ:
		return publish_our_buffer(session, msg);
	case XIO_MSG_TYPE_RSP:
		return test_rdma_write_to_remote_buffer(session, msg);
	default:
		pr_info("unknown message type : %d\n", msg->type); //34
		break;
	}

	return 0;
}

static int on_msg_error(struct xio_session *session,
			enum xio_status error,
			enum xio_msg_direction direction,
			struct xio_msg  *msg,
			void *cb_user_context)
{
	pr_info("**** [%p] message [%lu] failed. reason: %s\n",
		session, (unsigned long)msg->request->sn, xio_strerror(error));
	msg_pool_put(test_params.pool, msg);

	return 0;
}

static void test_teardown(void)
{
	xio_unregister_remote_key(test_rkey);
	pr_info("Calling xio_disconnect\n");
	xio_disconnect(test_params.connection);
	pr_info("Back from xio_disconnect\n");
}

static char test_buf[RDMA_BUF_SIZE];
static void verify_read_buffer(void)
{
	memset(test_buf, TEST_PATTERN, sizeof(test_buf));

	if (memcmp(test_buf, rdma_reg_mem.addr, sizeof(test_buf)) == 0)
		pr_info("RDMA test succeeded!\n");
	else
		pr_info("RDMA test failed (wrong data read from remote)!\n");

}

static int on_rdma_direct_complete(struct xio_session *session,
				   struct xio_msg *msg,
				   void *cb_user_context)
{
	if (test_stage == 0) {
		pr_info("RDMA write done!\n");
		test_rdma_read_from_remote_buffer();
		test_stage++;
	} else {
		pr_info("RDMA read done!\n");
		verify_read_buffer();
		test_teardown();
	}

	msg_pool_put(test_params.pool, msg);
	return 0;
}

static int on_send_response_complete(struct xio_session *session,
				     struct xio_msg *msg,
				     void *cb_user_context)
{
	msg_pool_put(test_params.pool, msg);
	return 0;
}

struct xio_session_ops session_ops = {
	.on_session_event		=  NULL,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  on_send_response_complete,
	.on_msg				=  on_message,
	.on_msg_error			=  on_msg_error,
	.on_rdma_direct_complete	=  on_rdma_direct_complete,
};

void init_xio_rdma_common_test(void)
{
	int res;

	enum xio_log_level xio_log_level = XIO_LOG_LEVEL_TRACE;
if(0)
	xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_LOG_LEVEL,
		    &xio_log_level, sizeof(xio_log_level));

	test_params.pool = msg_pool_alloc(MAX_POOL_SIZE, 0, 1);
	xio_assert(test_params.pool != NULL);

	res = xio_mem_alloc(RDMA_BUF_SIZE, &rdma_reg_mem);
	xio_assert(!res);
	memset(rdma_reg_mem.addr, 0, rdma_reg_mem.length);
}

void fini_xio_rdma_common_test(void)
{
	xio_mem_free(&rdma_reg_mem);
	msg_pool_free(test_params.pool);
}
