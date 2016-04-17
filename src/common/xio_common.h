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
#ifndef XIO_COMMON_H
#define XIO_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------*/
/* externals								     */
/*---------------------------------------------------------------------------*/
extern struct xio_options		g_options;
extern double				g_mhz;
extern struct xio_idr			*usr_idr;
extern struct xio_mempool_config	g_mempool_config;

/*---------------------------------------------------------------------------*/
/* defines								     */
/*---------------------------------------------------------------------------*/
/*#define XIO_SESSION_DEBUG*/

/* Macro for 64 bit variables to switch to from net */
#define ntohll(x) (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) | \
		    (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)

#define uint64_from_ptr(p)	(uint64_t)(uintptr_t)(p)
#define ptr_from_int64(p)	(void *)(unsigned long)(p)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/*---------------------------------------------------------------------------*/
/* debuging facilities							     */
/*---------------------------------------------------------------------------*/
void xio_set_error(int errnum);

#define XIO_TLV_LEN			sizeof(struct xio_tlv)
#define XIO_SESSION_HDR_LEN		sizeof(struct xio_session_hdr)
#define XIO_TRANSPORT_OFFSET		(XIO_TLV_LEN + XIO_SESSION_HDR_LEN)
#define MAX_PRIVATE_DATA_LEN		1024

/**
 * extended message flags
 */
enum xio_msg_flags_ex {
	/* [below 1<<10 - reserved for application usage] */
	/* [above 1<<10 - reserved for library usage] */
	XIO_MSG_FLAG_EX_IMM_READ_RECEIPT  = BIT(10), /**< immediate receipt  */
	XIO_MSG_FLAG_EX_RECEIPT_FIRST	  = BIT(11), /**< read receipt first */
	XIO_MSG_FLAG_EX_RECEIPT_LAST	  = BIT(12), /**< read receipt last  */
};

#define xio_clear_ex_flags(flag) \
	((*(flag)) &= ~(XIO_MSG_FLAG_EX_RECEIPT_FIRST | \
			XIO_MSG_FLAG_EX_RECEIPT_LAST  | \
			XIO_MSG_FLAG_EX_IMM_READ_RECEIPT))

#define xio_app_receipt_request(rq) \
	((rq)->flags & (XIO_MSG_FLAG_EX_RECEIPT_FIRST | \
			XIO_MSG_FLAG_EX_RECEIPT_LAST))

#define xio_app_receipt_first_request(rq) \
	(((rq)->flags & XIO_MSG_FLAG_EX_RECEIPT_FIRST) == \
			XIO_MSG_FLAG_EX_RECEIPT_FIRST)

#define xio_app_receipt_last_request(rq) \
	(((rq)->flags & XIO_MSG_FLAG_EX_RECEIPT_LAST) == \
			XIO_MSG_FLAG_EX_RECEIPT_LAST)

/**
 *  TLV types
 */
#define XIO_NOP				1

#define XIO_CREDIT			BIT(6)	/*  0x40  */
#define XIO_NEXUS_SETUP			BIT(7)	/*  0x80  */
#define XIO_SESSION_SETUP		BIT(8)	/*  0x100 */
#define XIO_CONNECTION_HELLO		BIT(9)	/*  0x200 */
#define XIO_FIN				BIT(10)	/*  0x400 */
#define XIO_CANCEL			BIT(11)	/*  0x800 */
#define XIO_ACK				BIT(12)	/*  0x1000 */
#define XIO_RDMA_READ			BIT(13) /*  0x2000 */
#define XIO_CONNECTION_KA		BIT(14)	/*  0x4000 */

#define XIO_MSG_REQ		XIO_MSG_TYPE_REQ
#define XIO_MSG_RSP		XIO_MSG_TYPE_RSP
#define XIO_CREDIT_NOP		(XIO_CREDIT | XIO_NOP)
#define XIO_NEXUS_SETUP_REQ	(XIO_NEXUS_SETUP | XIO_REQUEST)
#define XIO_NEXUS_SETUP_RSP	(XIO_NEXUS_SETUP | XIO_RESPONSE)
#define XIO_SESSION_SETUP_REQ	(XIO_SESSION_SETUP | XIO_REQUEST)
#define XIO_SESSION_SETUP_RSP	(XIO_SESSION_SETUP | XIO_RESPONSE)
#define XIO_ONE_WAY_REQ		XIO_MSG_TYPE_ONE_WAY
#define XIO_ONE_WAY_RSP		(XIO_ONE_WAY | XIO_RESPONSE)
#define XIO_FIN_REQ		(XIO_FIN | XIO_REQUEST)
#define XIO_FIN_RSP		(XIO_FIN | XIO_RESPONSE)
#define XIO_CANCEL_REQ		(XIO_CANCEL | XIO_REQUEST)
#define XIO_CANCEL_RSP		(XIO_CANCEL | XIO_RESPONSE)
#define XIO_CONNECTION_HELLO_REQ (XIO_CONNECTION_HELLO | XIO_REQUEST)
#define XIO_CONNECTION_HELLO_RSP (XIO_CONNECTION_HELLO | XIO_RESPONSE)
#define XIO_CONNECTION_KA_REQ (XIO_CONNECTION_KA | XIO_REQUEST)
#define XIO_CONNECTION_KA_RSP (XIO_CONNECTION_KA | XIO_RESPONSE)
#define XIO_ACK_REQ		(XIO_ACK | XIO_REQUEST)
#define XIO_RDMA_READ_ACK	(XIO_RDMA_READ | XIO_RESPONSE)

#define IS_REQUEST(type)		((type) & XIO_REQUEST)
#define IS_RESPONSE(type)		((type) & XIO_RESPONSE)
#define IS_NOP(type)			((type) & XIO_NOP)
#define IS_RDMA_RD_ACK(type)		((type) & XIO_RDMA_READ)
#define IS_MESSAGE(type)		((type) & XIO_MESSAGE)
#define IS_SESSION_SETUP(type)		((type) & XIO_SESSION_SETUP)
#define IS_NEXUS_SETUP(type)		((type) & XIO_NEXUS_SETUP)
#define IS_ONE_WAY(type)		((type) & XIO_ONE_WAY)
#define IS_FIN(type)			((type) & XIO_FIN)
#define IS_CANCEL(type)			((type) & XIO_CANCEL)
#define IS_CONNECTION_HELLO(type)	((type) & XIO_CONNECTION_HELLO)
#define IS_DIRECT_RDMA(type)		((type) & XIO_RDMA)
#define	IS_APPLICATION_MSG(type) \
		  (IS_MESSAGE(type) || IS_ONE_WAY(type) || IS_DIRECT_RDMA(type))

/**
 *  TLV magic
 */
#define XIO_MAGIC		0x58494F50  /* ascii of 'XIOP' */

/**
 *  TLV macros
 */
#define PACK_SVAL(src, trgt, attr) ((trgt)->attr = htons((src)->attr))
#define PACK_LVAL(src, trgt, attr) ((trgt)->attr = htonl((src)->attr))
#define PACK_LLVAL(src, trgt, attr) ((trgt)->attr = htonll((src)->attr))

#define UNPACK_SVAL(src, trgt, attr) ((trgt)->attr = ntohs((src)->attr))
#define UNPACK_LVAL(src, trgt, attr) ((trgt)->attr = ntohl((src)->attr))
#define UNPACK_LLVAL(src, trgt, attr) ((trgt)->attr = ntohll((src)->attr))

#define test_bits(mask, addr)   (((*addr) & (mask)) != 0)
#define clr_bits(mask, addr)    ((*addr) &= ~(mask))
#define set_bits(mask, addr)    ((*addr) |= (mask))

#define test_flag(flag, addr)   (((*addr) & (flag)) == (flag))

/* header flags */
#define XIO_HEADER_FLAG_NONE			(0)
#define XIO_HEADER_FLAG_PEER_WRITE_RSP		BIT(0)

/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
struct xio_options {
	int			max_in_iovsz;
	int			max_out_iovsz;
	int			reconnect;
	/* transport options needed globally */
	int			max_inline_xio_hdr;
	int			max_inline_xio_data;
	int			enable_flow_control;
	int			snd_queue_depth_msgs;
	int			rcv_queue_depth_msgs;
	uint64_t		snd_queue_depth_bytes;
	uint64_t		rcv_queue_depth_bytes;
	int			xfer_buf_align;
	int			inline_xio_data_align;
	int			enable_keepalive;
	int			transport_close_timeout;
	int			pad;

	struct xio_options_keepalive ka;
};

/*---------------------------------------------------------------------------*/
/* message headers							     */
/*---------------------------------------------------------------------------*/
PACKED_MEMORY(struct xio_tlv {
	uint32_t		magic;
	uint32_t		type;
	uint64_t		len;
});

#ifdef XIO_SESSION_DEBUG
PACKED_MEMORY(struct xio_session_hdr {
	uint32_t		dest_session_id;
	uint32_t		flags;
	uint64_t		serial_num;
	uint16_t		sn;		/* serial number	*/
	uint16_t		ack_sn;		/* ack serial number	*/
	uint16_t		credits_msgs;
	uint16_t		pad[3];
	uint32_t		receipt_result;
	uint64_t		credits_bytes;
	uint64_t		connection;
	uint64_t		session;
});
#else
PACKED_MEMORY(struct xio_session_hdr {
	uint32_t		dest_session_id;
	uint32_t		flags;
	uint64_t		serial_num;
	uint16_t		sn;		/* serial number	*/
	uint16_t		ack_sn;		/* ack serial number	*/
	uint16_t		credits_msgs;
	uint16_t		pad[3];
	uint32_t		receipt_result;
	uint64_t		credits_bytes;
});
#endif

/* setup flags */
#define XIO_CID			1

#define XIO_RECONNECT		(XIO_CID)

PACKED_MEMORY(struct xio_nexus_setup_req {
	uint16_t		version;
	uint16_t		flags;
	uint32_t		cid;
});

PACKED_MEMORY(struct xio_nexus_setup_rsp {
	uint32_t		cid;
	uint32_t		status;
	uint16_t		version;
	uint16_t		flags;
});

PACKED_MEMORY(struct xio_session_cancel_hdr {
	uint32_t		requester_session_id;
	uint32_t		responder_session_id;
	uint64_t		sn;
});

struct xio_msg;
struct xio_vmsg;
struct xio_iovec;
struct xio_iovec_ex;

/*---------------------------------------------------------------------------*/
/* enum									     */
/*---------------------------------------------------------------------------*/

enum xio_wc_op {
	XIO_WC_OP_UNKNOWN,
	XIO_WC_OP_RECV,
	XIO_WC_OP_SEND,
	XIO_WC_OP_RDMA_READ,
	XIO_WC_OP_RDMA_WRITE,
};

/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
union xio_sockaddr {
	struct sockaddr sa;
	struct sockaddr_in sa_in;
	struct sockaddr_in6 sa_in6;
	struct sockaddr_storage sa_stor;
};

/*---------------------------------------------------------------------------*/
/* xio_utils.c								     */
/*---------------------------------------------------------------------------*/

int		xio_uri_get_proto(const char *uri, char *proto,
				  int proto_len);

int		xio_uri_get_portal(const char *uri, char *portal,
				   int portal_len);

int		xio_uri_get_resource(const char *uri, char *resource,
				     int resource_len);

const char	*xio_uri_get_resource_ptr(const char *uri);

int		xio_uri_to_ss(const char *uri, struct sockaddr_storage *ss);

int		xio_host_port_to_ss(const char *buf,
				    struct sockaddr_storage *ss);

size_t		xio_write_tlv(uint32_t type, uint64_t len, uint8_t *buffer);

size_t		xio_read_tlv(uint32_t *type, uint64_t *len, void **value,
			     uint8_t *buffer);

size_t		memcpyv(struct xio_iovec *dst, int dsize,
			struct xio_iovec *src, int ssize);

size_t		memclonev(struct xio_iovec *dst, int dsize,
			  struct xio_iovec *src, int ssize);

size_t		xio_iov_length(const struct xio_iovec *iov,
			       unsigned long nr_segs);

unsigned int	xio_get_nodeid(unsigned int cpu_id);

void		xio_msg_dump(struct xio_msg *xio_msg);

const char	*xio_proto_str(enum xio_proto proto);

/*---------------------------------------------------------------------------*/
/* xio_options.c							     */
/*---------------------------------------------------------------------------*/
struct xio_options *xio_get_options(void);

#ifdef __cplusplus
}
#endif

#endif /*XIO_COMMON_H */
