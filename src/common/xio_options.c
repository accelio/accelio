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
#include "xio_common.h"
#include "xio_mem.h"
#include "xio_observer.h"
#include "xio_transport.h"
#include "xio_log.h"

#define XIO_OPTVAL_DEF_MAX_IN_IOVSZ			XIO_IOVLEN
#define XIO_OPTVAL_DEF_MAX_OUT_IOVSZ			XIO_IOVLEN
#define XIO_OPTVAL_DEF_ENABLE_RECONNECT			0
#define XIO_OPTVAL_DEF_ENABLE_FLOW_CONTROL		0
#define XIO_OPTVAL_DEF_SND_QUEUE_DEPTH_MSGS		1024
#define XIO_OPTVAL_DEF_RCV_QUEUE_DEPTH_MSGS		1024
#define XIO_OPTVAL_DEF_SND_QUEUE_DEPTH_BYTES		(64 * 1024 * 1024)
#define XIO_OPTVAL_DEF_RCV_QUEUE_DEPTH_BYTES		(64 * 1024 * 1024)
#define XIO_OPTVAL_DEF_MAX_INLINE_XIO_HEADER		256
#define XIO_OPTVAL_DEF_MAX_INLINE_XIO_DATA		(8 * 1024)
#define XIO_OPTVAL_DEF_XFER_BUF_ALIGN			(64)
#define XIO_OPTVAL_DEF_INLINE_XIO_DATA_ALIGN		(0)
#define XIO_OPTVAL_DEF_ENABLE_KEEPALIVE			1
#define XIO_OPTVAL_DEF_KEEPALIVE_PROBES			3
#define XIO_OPTVAL_DEF_KEEPALIVE_INTVL			20
#define XIO_OPTVAL_DEF_KEEPALIVE_TIME			60
#define XIO_OPTVAL_DEF_TRANSPORT_CLOSE_TIMEOUT		60000
#define XIO_OPTVAL_DEF_PAD				0

/* xio options */
struct xio_options			g_options = {
	XIO_OPTVAL_DEF_MAX_IN_IOVSZ,		/*max_in_iovsz*/
	XIO_OPTVAL_DEF_MAX_OUT_IOVSZ,		/*max_out_iovsz*/
	XIO_OPTVAL_DEF_ENABLE_RECONNECT,	/*reconnect*/
	XIO_OPTVAL_DEF_MAX_INLINE_XIO_HEADER,	/*max_inline_xio_hdr*/
	XIO_OPTVAL_DEF_MAX_INLINE_XIO_DATA,	/*max_inline_xio_data*/
	XIO_OPTVAL_DEF_ENABLE_FLOW_CONTROL,	/*enable_flow_control*/
	XIO_OPTVAL_DEF_SND_QUEUE_DEPTH_MSGS,	/*snd_queue_depth_msgs*/
	XIO_OPTVAL_DEF_RCV_QUEUE_DEPTH_MSGS,	/*rcv_queue_depth_msgs*/
	XIO_OPTVAL_DEF_SND_QUEUE_DEPTH_BYTES,	/*snd_queue_depth_bytes*/
	XIO_OPTVAL_DEF_RCV_QUEUE_DEPTH_BYTES,	/*rcv_queue_depth_bytes*/
	XIO_OPTVAL_DEF_XFER_BUF_ALIGN,		/* xfer_buf_align */
	XIO_OPTVAL_DEF_INLINE_XIO_DATA_ALIGN,	/* inline_xio_data_align */
	XIO_OPTVAL_DEF_ENABLE_KEEPALIVE,
	XIO_OPTVAL_DEF_TRANSPORT_CLOSE_TIMEOUT, /* transport_close_timeout */
	XIO_OPTVAL_DEF_PAD,
	{
		XIO_OPTVAL_DEF_KEEPALIVE_PROBES,
		XIO_OPTVAL_DEF_KEEPALIVE_TIME,
		XIO_OPTVAL_DEF_KEEPALIVE_INTVL
	}
};

/*---------------------------------------------------------------------------*/
/* xio_get_options							     */
/*---------------------------------------------------------------------------*/
struct xio_options *xio_get_options(void)
{
	return &g_options;
}
EXPORT_SYMBOL(xio_get_options);

/*---------------------------------------------------------------------------*/
/* xio_set_opt								     */
/*---------------------------------------------------------------------------*/
static int xio_general_set_opt(void *xio_obj, int optname,
			       const void *optval, int optlen)
{
	int tmp;

	switch (optname) {
	case XIO_OPTNAME_LOG_FN:
		if (optlen == 0 && !optval)
			return xio_set_log_fn(NULL);
		else if (optlen == sizeof(xio_log_fn))
			return xio_set_log_fn((xio_log_fn)optval);
		break;
	case XIO_OPTNAME_LOG_LEVEL:
		if (optlen != sizeof(enum xio_log_level))
			return -1;
		return xio_set_log_level(*((enum xio_log_level *)optval));
	case XIO_OPTNAME_DISABLE_HUGETBL:
		xio_disable_huge_pages(*((int *)optval));
		return 0;
	case XIO_OPTNAME_MEM_ALLOCATOR:
		if (optlen == sizeof(struct xio_mem_allocator))
			return xio_set_mem_allocator(
					(struct xio_mem_allocator *)optval);
		break;
	case XIO_OPTNAME_CONFIG_MEMPOOL:
		if (optlen == sizeof(struct xio_mempool_config)) {
			memcpy(&g_mempool_config,
			       (struct xio_mempool_config *)optval, optlen);
			return 0;
		}
		break;
	case XIO_OPTNAME_MAX_IN_IOVLEN:
		if (optlen == sizeof(int)) {
			struct xio_transport *rdma_transport =
						xio_get_transport("rdma");
			struct xio_transport *tcp_transport =
						xio_get_transport("tcp");
			int retval = 0;

			if (*((int *)optval) > XIO_IOVLEN &&
			    *((int *)optval) <= XIO_MAX_IOV) {
				g_options.max_in_iovsz = *((int *)optval);
				if (rdma_transport &&
				    rdma_transport->set_opt)
					retval |= rdma_transport->set_opt(
							xio_obj, optname,
							optval, optlen);
				if (tcp_transport &&
				    tcp_transport->set_opt)
					retval |= tcp_transport->set_opt(
							xio_obj, optname,
							optval, optlen);
			}
			return retval;
		}
		break;
	case XIO_OPTNAME_MAX_OUT_IOVLEN:
		if (optlen == sizeof(int)) {
			struct xio_transport *rdma_transport =
						xio_get_transport("rdma");
			struct xio_transport *tcp_transport =
						xio_get_transport("tcp");
			int retval = 0;

			if (*((int *)optval) > XIO_IOVLEN &&
			    *((int *)optval) <= XIO_MAX_IOV) {
				g_options.max_out_iovsz = *((int *)optval);
				if (rdma_transport &&
				    rdma_transport->set_opt)
					retval |= rdma_transport->set_opt(
							xio_obj, optname,
							optval, optlen);
				if (tcp_transport &&
				    tcp_transport->set_opt)
					retval |= tcp_transport->set_opt(
							xio_obj, optname,
							optval, optlen);
			}
			return retval;
		}
		break;
	case XIO_OPTNAME_ENABLE_DMA_LATENCY:
		if (optlen == sizeof(int)) {
			struct xio_transport *rdma_transport =
						xio_get_transport("rdma");
			struct xio_transport *tcp_transport =
						xio_get_transport("tcp");
			int retval = 0;

			if (rdma_transport &&
			    rdma_transport->set_opt)
				retval |= rdma_transport->set_opt(
						xio_obj, optname,
						optval, optlen);
			if (tcp_transport &&
			    tcp_transport->set_opt)
				retval |= tcp_transport->set_opt(
						xio_obj, optname,
						optval, optlen);

			return retval;
		}
		break;
	case XIO_OPTNAME_ENABLE_RECONNECT:
		g_options.reconnect = *((int *)optval);
		if (g_options.reconnect){
			g_options.enable_keepalive = 0;
		}
		return 0;
	case XIO_OPTNAME_ENABLE_FLOW_CONTROL:
		g_options.enable_flow_control = *((int *)optval);
		return 0;
	case XIO_OPTNAME_SND_QUEUE_DEPTH_MSGS:
		if (*((int *)optval) < 1)
			break;
		g_options.snd_queue_depth_msgs = (int)*((uint64_t *)optval);
		return 0;
	case XIO_OPTNAME_RCV_QUEUE_DEPTH_MSGS:
		if (*((int *)optval) < 1)
			break;
		g_options.rcv_queue_depth_msgs = *((int *)optval);
		return 0;
	case XIO_OPTNAME_SND_QUEUE_DEPTH_BYTES:
		if (*((uint64_t *)optval) < 1)
			break;
		g_options.snd_queue_depth_bytes = *((uint64_t *)optval);
		return 0;
	case XIO_OPTNAME_RCV_QUEUE_DEPTH_BYTES:
		if (*((uint64_t *)optval) < 1)
			break;
		g_options.rcv_queue_depth_bytes = *((uint64_t *)optval);
		return 0;
	case XIO_OPTNAME_MAX_INLINE_XIO_HEADER:
		if (optlen != sizeof(int))
			break;
		if (*((int *)optval) < 0)
			break;
		g_options.max_inline_xio_hdr = *((int *)optval);
		return 0;
	case XIO_OPTNAME_MAX_INLINE_XIO_DATA:
		if (optlen != sizeof(int))
			break;
		if (*((int *)optval) < 0)
			break;
		g_options.max_inline_xio_data = *((int *)optval);
		return 0;
	case XIO_OPTNAME_XFER_BUF_ALIGN:
		if (optlen != sizeof(int))
			break;
		tmp = *(int *)optval;
		if (!is_power_of_2(tmp) || !(tmp % sizeof(void *) == 0)) {
			xio_set_error(EINVAL);
			return -1;
		}
		g_options.xfer_buf_align = tmp;
		return 0;
	case XIO_OPTNAME_INLINE_XIO_DATA_ALIGN:
		if (optlen != sizeof(int))
			break;
		tmp = *(int *)optval;
		if (!tmp) {
			g_options.inline_xio_data_align = tmp;
			return 0;
		}
		if (!is_power_of_2(tmp) || !(tmp % sizeof(void *) == 0)) {
			xio_set_error(EINVAL);
			return -1;
		}
		g_options.inline_xio_data_align = tmp;
		return 0;
	case XIO_OPTNAME_ENABLE_KEEPALIVE:
		g_options.enable_keepalive = *((int *)optval);
		return 0;
	case XIO_OPTNAME_CONFIG_KEEPALIVE:
		if (optlen == sizeof(struct xio_options_keepalive)) {
			memcpy(&g_options.ka, optval, optlen);
			return 0;
		} else {
			xio_set_error(EINVAL);
			return -1;
		}
		break;
	case XIO_OPTNAME_TRANSPORT_CLOSE_TIMEOUT:
		if (optlen != sizeof(int))
			break;
		if (*((int *)optval) < 0)
			break;
		g_options.transport_close_timeout = *((int *)optval);
		return 0;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}
EXPORT_SYMBOL(xio_set_opt);

/*---------------------------------------------------------------------------*/
/* xio_general_get_opt                                                       */
/*---------------------------------------------------------------------------*/
static int xio_general_get_opt(void  *xio_obj, int optname,
			       void *optval, int *optlen)
{
	switch (optname) {
	case XIO_OPTNAME_LOG_LEVEL:
		*((enum xio_log_level *)optval) = xio_get_log_level();
		*optlen = sizeof(enum xio_log_level);
		return 0;
	case XIO_OPTNAME_MAX_IN_IOVLEN:
		*optlen = sizeof(int);
		*((int *)optval) = g_options.max_in_iovsz;
		return 0;
	case XIO_OPTNAME_MAX_OUT_IOVLEN:
		*optlen = sizeof(int);
		 *((int *)optval) = g_options.max_out_iovsz;
		 return 0;
	case XIO_OPTNAME_ENABLE_RECONNECT:
		*optlen = sizeof(int);
		 *((int *)optval) = g_options.reconnect;
		 return 0;
	case XIO_OPTNAME_ENABLE_FLOW_CONTROL:
		*optlen = sizeof(int);
		 *((int *)optval) = g_options.enable_flow_control;
		 return 0;
	case XIO_OPTNAME_SND_QUEUE_DEPTH_MSGS:
		*optlen = sizeof(int);
		 *((int *)optval) = g_options.snd_queue_depth_msgs;
		 return 0;
	case XIO_OPTNAME_RCV_QUEUE_DEPTH_MSGS:
		*optlen = sizeof(int);
		 *((int *)optval) = g_options.rcv_queue_depth_msgs;
		 return 0;
	case XIO_OPTNAME_SND_QUEUE_DEPTH_BYTES:
		*optlen = sizeof(uint64_t);
		 *((uint64_t *)optval) = g_options.snd_queue_depth_bytes;
		 return 0;
	case XIO_OPTNAME_RCV_QUEUE_DEPTH_BYTES:
		*optlen = sizeof(uint64_t);
		 *((uint64_t *)optval) = g_options.rcv_queue_depth_bytes;
		 return 0;
	case XIO_OPTNAME_MAX_INLINE_XIO_HEADER:
		*optlen = sizeof(int);
		 *((int *)optval) = g_options.max_inline_xio_hdr;
		 return 0;
	case XIO_OPTNAME_MAX_INLINE_XIO_DATA:
		*optlen = sizeof(int);
		 *((int *)optval) = g_options.max_inline_xio_data;
		 return 0;
	case XIO_OPTNAME_INLINE_XIO_DATA_ALIGN:
		*optlen = sizeof(int);
		 *((int *)optval) = g_options.inline_xio_data_align;
		 return 0;
	case XIO_OPTNAME_XFER_BUF_ALIGN:
		*optlen = sizeof(int);
		 *((int *)optval) = g_options.xfer_buf_align;
		 return 0;
	case XIO_OPTNAME_ENABLE_KEEPALIVE:
		*optlen = sizeof(int);
		*((int *)optval) = g_options.enable_keepalive;
		return 0;
	case XIO_OPTNAME_CONFIG_KEEPALIVE:
		if (*optlen == sizeof(struct xio_options_keepalive)) {
			memcpy(optval, &g_options.ka, *optlen);
			return 0;
		} else {
			xio_set_error(EINVAL);
			return -1;
		}
	case XIO_OPTNAME_TRANSPORT_CLOSE_TIMEOUT:
		*optlen = sizeof(int);
		*((int *)optval) = g_options.transport_close_timeout;
		return 0;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_set_opt								     */
/*---------------------------------------------------------------------------*/
int xio_set_opt(void *xio_obj, int level,  int optname,
		const void *optval, int optlen)
{
	static struct xio_transport *rdma_transport;
	static struct xio_transport *tcp_transport;

	switch (level) {
	case XIO_OPTLEVEL_ACCELIO:
		return xio_general_set_opt(xio_obj, optname, optval, optlen);
	case XIO_OPTLEVEL_RDMA:
		if (!rdma_transport) {
			rdma_transport = xio_get_transport("rdma");
			if (!rdma_transport) {
				xio_set_error(EFAULT);
				return -1;
			}
		}
		if (!rdma_transport->set_opt)
			break;
		return rdma_transport->set_opt(xio_obj,
					       optname, optval, optlen);
		break;
	case XIO_OPTLEVEL_TCP:
		if (!tcp_transport) {
			tcp_transport = xio_get_transport("tcp");
			if (!tcp_transport) {
				xio_set_error(EFAULT);
				return -1;
			}
		}
		if (!tcp_transport->set_opt)
			break;
		return tcp_transport->set_opt(xio_obj,
					      optname, optval, optlen);
		break;
	default:
		break;
	}

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_get_opt								     */
/*---------------------------------------------------------------------------*/
int xio_get_opt(void *xio_obj, int level,  int optname,
		void *optval, int *optlen)
{
	static struct xio_transport *rdma_transport;
	static struct xio_transport *tcp_transport;

	switch (level) {
	case XIO_OPTLEVEL_ACCELIO:
		return xio_general_get_opt(xio_obj, optname, optval, optlen);
	case XIO_OPTLEVEL_RDMA:
		if (!rdma_transport) {
			rdma_transport = xio_get_transport("rdma");
			if (!rdma_transport) {
				xio_set_error(EFAULT);
				return -1;
			}
		}
		if (!rdma_transport->get_opt)
			break;
		return rdma_transport->get_opt(xio_obj,
					       optname, optval, optlen);
		break;
	case XIO_OPTLEVEL_TCP:
		if (!tcp_transport) {
			tcp_transport = xio_get_transport("tcp");
			if (!tcp_transport) {
				xio_set_error(EFAULT);
				return -1;
			}
		}
		if (!tcp_transport->get_opt)
			break;
		return tcp_transport->get_opt(xio_obj,
					      optname, optval, optlen);
		break;
	default:
		break;
	}

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}
EXPORT_SYMBOL(xio_get_opt);
