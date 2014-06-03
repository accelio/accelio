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

#include "xio_os.h"
#include "xio_log.h"

/*---------------------------------------------------------------------------*/
/* externals								     */
/*---------------------------------------------------------------------------*/
extern struct xio_options g_options;

/*---------------------------------------------------------------------------*/
/* defines								     */
/*---------------------------------------------------------------------------*/

/* Macro for 64 bit variables to switch to from net */
#define ntohll(x) (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) | \
		    (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)

#define uint64_from_ptr(p)	(uint64_t)(uintptr_t)(p)
#define ptr_from_int64(p)	(void *)(unsigned long)(p)

/*---------------------------------------------------------------------------*/
/* debuging facilities							     */
/*---------------------------------------------------------------------------*/
void xio_set_error(int errnum);

#define XIO_TLV_LEN			sizeof(struct xio_tlv)
#define XIO_SESSION_HDR_LEN		sizeof(struct xio_session_hdr)
#define XIO_TRANSPORT_OFFSET		(XIO_TLV_LEN + XIO_SESSION_HDR_LEN)
#define MAX_PRIVATE_DATA_LEN		1024

/**
 * message flags
 */

/* response flags */
#define XIO_MSG_RSP_FLAG_FIRST		0x1
#define XIO_MSG_RSP_FLAG_LAST		0x2

/**
 *  TLV types
 */
#define XIO_NOP			1

#define XIO_CREDIT		(1 << 6)
#define XIO_CONN_SETUP		(1 << 7)
#define XIO_SESSION_SETUP	(1 << 8)
#define XIO_CONNECTION_HELLO	(1 << 9)
#define XIO_FIN			(1 << 10)
#define XIO_CANCEL		(1 << 11)


#define XIO_MSG_REQ		XIO_MSG_TYPE_REQ
#define XIO_MSG_RSP		XIO_MSG_TYPE_RSP
#define XIO_CREDIT_NOP		(XIO_CREDIT | XIO_NOP)
#define XIO_CONN_SETUP_REQ	(XIO_CONN_SETUP | XIO_REQUEST)
#define XIO_CONN_SETUP_RSP	(XIO_CONN_SETUP | XIO_RESPONSE)
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


#define IS_REQUEST(type)		((type) & XIO_REQUEST)
#define IS_RESPONSE(type)		((type) & XIO_RESPONSE)
#define IS_NOP(type)			((type) & XIO_NOP)
#define IS_MESSAGE(type)		((type) & XIO_MESSAGE)
#define IS_SESSION_SETUP(type)		((type) & XIO_SESSION_SETUP)
#define IS_CONN_SETUP(type)		((type) & XIO_CONN_SETUP)
#define IS_ONE_WAY(type)		((type) & XIO_ONE_WAY)
#define IS_FIN(type)			((type) & XIO_FIN)
#define IS_CANCEL(type)			((type) & XIO_CANCEL)
#define IS_CONNECTION_HELLO(type)	((type) & XIO_CONNECTION_HELLO)


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

/*---------------------------------------------------------------------------*/
/* structures								     */
/*---------------------------------------------------------------------------*/
struct xio_options {
	int			max_in_iovsz;
	int			max_out_iovsz;
};

/*---------------------------------------------------------------------------*/
/* message headers							     */
/*---------------------------------------------------------------------------*/
struct __attribute__((__packed__)) xio_tlv {
	uint32_t		magic;
	uint32_t		type;
	uint64_t		len;
};

struct __attribute__((__packed__)) xio_session_hdr {
	uint32_t		dest_session_id;
	uint32_t		pad;
	uint64_t		serial_num;
	uint32_t		flags;
	uint32_t		receipt_result;
};

struct __attribute__((__packed__)) xio_conn_setup_req {
	uint16_t		version;
	uint16_t		pad;
};


struct __attribute__((__packed__)) xio_conn_setup_rsp {
	uint32_t		cid;
	uint32_t		status;
	uint16_t		version;
	uint16_t		pad;
};

struct __attribute__((__packed__)) xio_session_cancel_hdr {
	uint32_t		requester_session_id;
	uint32_t		responder_session_id;
	uint64_t		sn;
};

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

int		xio_uri_get_proto(const char *uri,
			char *proto, int proto_len);

int		xio_uri_get_portal(const char *uri,
			char *portal, int portal_len);

int		xio_uri_get_resource(const char *uri,
			char *resource, int resource_len);

char		*xio_uri_get_resource_ptr(const char *uri);

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

size_t		xio_iovex_length(const struct xio_iovec_ex *iov,
				 unsigned long nr_segs);

unsigned int	xio_get_nodeid(unsigned int cpu_id);

void		xio_msg_dump(struct xio_msg *xio_msg);

void		xio_msg_map(struct xio_msg *xio_msg);

void		xio_msg_unmap(struct xio_msg *xio_msg);

void		xio_msg_cp_vec2ptr(struct xio_vmsg *vmsg);

void		xio_msg_cp_ptr2vec(struct xio_vmsg *vmsg);

#endif /*XIO_COMMON_H */

