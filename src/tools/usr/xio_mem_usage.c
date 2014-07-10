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
#include <libxio.h>
#include "xio_os.h"
#include "xio_common.h"
#include "xio_task.h"
#include "xio_observer.h"
#include "xio_transport.h"

#include "xio_context.h"
#include "xio_connection.h"
#include "xio_session.h"
#include "xio_server.h"
#include "xio_nexus.h"

#ifdef HAVE_INFINIBAND_VERBS_H
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include "xio_rdma_transport.h"
#endif
#include "xio_usr_transport.h"
#include "xio_transport_mempool.h"

#define PRINT_SIZE(type) \
{ \
    int i; \
    printf("    sizeof(%s)%n = ", #type, &i); \
    while (i++ < 48) { \
        printf("."); \
    } \
    printf(" %6lu\n", sizeof(type)); \
}


int main(int argc, char **argv)
{
    printf("\nAPI and Core:\n");
    PRINT_SIZE(struct xio_context);
    PRINT_SIZE(struct xio_connection);
    PRINT_SIZE(struct xio_session);
    PRINT_SIZE(struct xio_msg);
    PRINT_SIZE(struct xio_mr);
    PRINT_SIZE(struct xio_task);
    PRINT_SIZE(struct xio_nexus);

    printf("\nProtocol layer:\n");
    PRINT_SIZE(struct xio_sge);
    PRINT_SIZE(struct xio_tlv);
    PRINT_SIZE(struct xio_session_hdr);
    PRINT_SIZE(struct xio_session_cancel_hdr);
    PRINT_SIZE(struct xio_nexus_setup_req);
    PRINT_SIZE(struct xio_nexus_setup_rsp);

#ifdef HAVE_INFINIBAND_VERBS_H
    printf("\nRDMA Transport:\n");
    PRINT_SIZE(struct xio_rdma_setup_msg);
    PRINT_SIZE(struct xio_rdma_cancel_hdr);
    PRINT_SIZE(struct xio_req_hdr);
    PRINT_SIZE(struct xio_rsp_hdr);
    PRINT_SIZE(struct xio_nop_hdr);
    PRINT_SIZE(struct xio_rdma_task);
    PRINT_SIZE(struct xio_cq);
    PRINT_SIZE(struct xio_device);
    PRINT_SIZE(struct xio_rdma_transport);
    PRINT_SIZE(struct xio_cm_channel);
    PRINT_SIZE(struct xio_work_req);
#endif

#if 0
    PRINT_SIZE(mxm_async_context_t);
    PRINT_SIZE(mxm_proto_ep_t);
    PRINT_SIZE(mxm_req_base_t);
    PRINT_SIZE(mxm_send_req_t);
    PRINT_SIZE(mxm_recv_req_t);
    PRINT_SIZE(mxm_mem_region_t);

    printf("\nProtocol Layer:\n");
    PRINT_SIZE(mxm_proto_mq_t);
    PRINT_SIZE(mxm_proto_ep_t);
    PRINT_SIZE(mxm_proto_conn_t);
    PRINT_SIZE(mxm_req_priv_t);
    PRINT_SIZE(mxm_sreq_priv_t);
    PRINT_SIZE(mxm_rreq_priv_t);
    PRINT_SIZE(mxm_proto_internal_op_t);
    PRINT_SIZE(mxm_proto_recv_seg_t);
    PRINT_SIZE(mxm_proto_header_t);
    PRINT_SIZE(mxm_proto_eager_header_t);
    PRINT_SIZE(mxm_proto_rts_header_t);
    PRINT_SIZE(mxm_proto_rts_resp_header_t);

    printf("\nUtil:\n");
    // TODO

    printf("\nTransport layer:\n");
    PRINT_SIZE(mxm_tl_sge_t);
    PRINT_SIZE(mxm_tl_send_op_t);
    PRINT_SIZE(mxm_tl_send_spec_t);
    PRINT_SIZE(mxm_tl_channel_t);
    PRINT_SIZE(mxm_tl_ep_t);

    printf("\nSelf:\n");
    // TODO

    printf("\nOOB:\n");
    // TODO

#if HAVE_TL_UD
    printf("\nUD:\n");
    PRINT_SIZE(mxm_ud_ep_t);
    PRINT_SIZE(mxm_ud_channel_t);
    PRINT_SIZE(mxm_ud_send_skb_t);
    PRINT_SIZE(mxm_ud_recv_skb_t);
    PRINT_SIZE(mxm_ud_net_header_t);
    PRINT_SIZE(mxm_ud_tx_elem_t);
#endif

#if HAVE_TL_RC
    printf("\nRC:\n");
    PRINT_SIZE(mxm_rc_ep_t);
    PRINT_SIZE(mxm_rc_channel_t);
    PRINT_SIZE(mxm_cib_send_skb_t);
    PRINT_SIZE(mxm_cib_recv_skb_t);
#endif

#if HAVE_TL_DC
    printf("\nDC:\n");
    PRINT_SIZE(mxm_dc_ep_t);
    PRINT_SIZE(mxm_dc_channel_t);
#endif
#endif
    printf("\n");
    return 0;
}


