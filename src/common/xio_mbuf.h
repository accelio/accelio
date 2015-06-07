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
#ifndef XIO_MBUF_H
#define XIO_MBUF_H

	struct xio_mbuf_buf {
		void		*head;
		void		*tail;
		uint32_t	buflen;
		uint32_t	datalen;
	};

	struct xio_mbuf_tlv {
		void		*head;
		void		*tail;
		uint64_t	len;
		uint32_t	type;
		uint32_t	pad;
		void		*val;
	};

struct xio_mbuf {
	void			*curr;
	struct xio_mbuf_buf	buf;
	struct xio_mbuf_tlv	tlv;
	void			*marker;
};

#define xio_mbuf_set_tlv_hdr(mbuf)		 \
		((mbuf)->curr = ((mbuf)->tlv.head))

#define xio_mbuf_set_val_start(mbuf)		 \
		((mbuf)->curr = ((char *)(mbuf)->tlv.head + XIO_TLV_LEN))

#define xio_mbuf_set_session_hdr(mbuf)	 \
		((mbuf)->curr = sum_to_ptr((mbuf)->tlv.head, XIO_TLV_LEN))

#define xio_mbuf_set_trans_hdr(mbuf)		\
			((mbuf)->curr = sum_to_ptr((mbuf)->tlv.head, \
				XIO_TLV_LEN + XIO_SESSION_HDR_LEN))

#define xio_mbuf_tlv_head(mbuf)		((mbuf)->tlv.head)

#define xio_mbuf_tlv_val_ptr(mbuf)	((mbuf)->tlv.val)

#define xio_mbuf_tlv_type(mbuf)		((mbuf)->tlv.type)

#define xio_mbuf_data_length(mbuf)	((mbuf)->buf.datalen)

#define xio_mbuf_tlv_len(mbuf)		\
		((char *)(mbuf)->curr - (char *)(mbuf)->tlv.head)

#define xio_mbuf_tlv_payload_len(mbuf)	\
		((char *)(mbuf)->curr - (char *)(mbuf)->tlv.val)

#define xio_mbuf_reset(mbuf)			\
		((mbuf)->curr = (mbuf)->buf.head)

#define xio_mbuf_tlv_space_left(mbuf)		\
		((mbuf)->buf.tail - (mbuf)->curr)

#define xio_mbuf_get_curr_ptr(mbuf)	((mbuf)->curr)

#define xio_mbuf_get_curr_offset(mbuf)	\
		((char *)(mbuf)->curr - (char *)(mbuf)->buf.head)

#define xio_mbuf_inc(mbuf, len)	\
		((mbuf)->curr = ((char *)(mbuf)->curr + (len)))

#define xio_mbuf_dec(mbuf, len)	\
		((mbuf)->curr = ((mbuf)->curr - (len)))

#define xio_mbuf_push(mbuf)		((mbuf)->marker = (mbuf)->curr)

#define xio_mbuf_pop(mbuf)		((mbuf)->curr = (mbuf)->marker)

/*---------------------------------------------------------------------------*/
/* xio_mbuf_dump							     */
/*---------------------------------------------------------------------------*/
static inline void xio_mbuf_dump(struct xio_mbuf *mbuf)
{
	DEBUG_LOG("########################################################" \
		  "#############\n");
	DEBUG_LOG("buf: mbuf:%p head:%p, tail:%p, buflen:%u, datalen:%u\n",
		  mbuf, mbuf->buf.head, mbuf->buf.tail, mbuf->buf.buflen,
		  mbuf->buf.datalen);
	DEBUG_LOG("tlv: mbuf:%p head:%p, tail:%p, type:%d, len:%llu, val:%p\n",
		  mbuf, mbuf->tlv.head, mbuf->tlv.tail, mbuf->tlv.type,
		  mbuf->tlv.len, mbuf->tlv.val);
	DEBUG_LOG("curr: mbuf:%p curr:%p\n", mbuf, mbuf->curr);
	DEBUG_LOG("#########################################################" \
		  "############\n");
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_init							     */
/*---------------------------------------------------------------------------*/
static inline void xio_mbuf_init(struct xio_mbuf *mbuf, void *buf,
				 uint32_t buflen, uint32_t datalen)
{
	struct xio_mbuf_buf	*pbuf = &mbuf->buf;
	struct xio_mbuf_tlv	*tlv = &mbuf->tlv;

	mbuf->curr		= buf;
	pbuf->head		= buf;
	pbuf->tail		= sum_to_ptr(buf, buflen);
	pbuf->buflen		= buflen;
	pbuf->datalen		= datalen;

	memset(tlv, 0, sizeof(*tlv));
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_tlv_start							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_tlv_start(struct xio_mbuf *mbuf)
{
	struct xio_mbuf_buf *buf = &mbuf->buf;
	struct xio_mbuf_tlv *tlv = &mbuf->tlv;

	if (((uint64_t)((char *)buf->tail - (char *)mbuf->curr)) <=
	    XIO_TLV_LEN) {
		ERROR_LOG("xio_mbuf_tlv start failed. buf.tail:%p, " \
			  "len:%zd, curr:%p\n",
			  buf->tail, XIO_TLV_LEN, mbuf->curr);
		return -1;
	}

	tlv->head	= mbuf->curr;
	tlv->tail	= buf->tail;
	tlv->val	= sum_to_ptr(buf->head, XIO_TLV_LEN);
	mbuf->curr	= tlv->val;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_read_first_tlv						     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_read_first_tlv(struct xio_mbuf *mbuf)
{
	int len;
	struct xio_mbuf_tlv *tlv = &mbuf->tlv;

	tlv->head = mbuf->buf.head;

	len = xio_read_tlv(&tlv->type, &tlv->len,
			   &tlv->val, (uint8_t *)tlv->head);
	if (len == -1 || (sum_to_ptr(tlv->head, len) >  mbuf->buf.tail)) {
		ERROR_LOG("xio_mbuf_first_read_tlv failed. tlv.head:%p, " \
			  "len:%d, buf.tail:%p\n",
			  tlv->head, len, mbuf->buf.tail);
		return -1;
	}
	tlv->tail	= sum_to_ptr(tlv->head, len);
	mbuf->curr	= tlv->val;
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_read_next_tlv						     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_read_next_tlv(struct xio_mbuf *mbuf)
{
	int len;

	mbuf->tlv.head	  = mbuf->tlv.tail;

	len = xio_read_tlv(&mbuf->tlv.type, &mbuf->tlv.len,
			   &mbuf->tlv.val, (uint8_t *)mbuf->tlv.head);
	if (len == -1 || (sum_to_ptr(mbuf->tlv.head, len) >  mbuf->buf.tail)) {
		ERROR_LOG("xio_mbuf_next_read_tlv failed. tlv.head:%p, " \
			  "len:%d, buf.tail:%p\n",
			  mbuf->tlv.head, len, mbuf->buf.tail);
		return -1;
	}
	mbuf->tlv.tail = sum_to_ptr(mbuf->tlv.head, len);
	mbuf->curr	= mbuf->tlv.val;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_write_tlv							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_write_tlv(struct xio_mbuf *mbuf, uint32_t type,
				     uint16_t len)
{
	int retval;

	mbuf->tlv.type = type;
	mbuf->tlv.len = len;

	retval = xio_write_tlv(mbuf->tlv.type, mbuf->tlv.len,
			       (uint8_t *)mbuf->tlv.head);
	if (retval == -1 || (sum_to_ptr(mbuf->tlv.head, retval) >
	    mbuf->buf.tail)) {
		ERROR_LOG("xio_mbuf_write_tlv failed. tlv.head:%p, " \
			  "len:%d, buf.tail:%p\n",
			  mbuf->tlv.head, retval, mbuf->buf.tail);
		return -1;
	}
	mbuf->tlv.tail		= sum_to_ptr(mbuf->tlv.head, retval);
	mbuf->buf.datalen	= (char *)mbuf->curr - (char *)mbuf->tlv.head;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_read_tlv								     */
/*---------------------------------------------------------------------------*/
static inline uint32_t xio_read_tlv_type(struct xio_mbuf *mbuf)
{
	struct xio_tlv *tlv;
	static uint32_t  magic;

	if (magic == 0)
		magic = ntohl(XIO_MAGIC);

	tlv = (struct xio_tlv *)mbuf->tlv.head;
	if (tlv->magic != magic)
		return -1;

	return  ntohl(tlv->type);
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_write_u8							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_write_u8(struct xio_mbuf *mbuf, uint8_t val)
{
	if (sum_to_ptr(mbuf->curr, sizeof(uint8_t)) <= mbuf->buf.tail) {
		inc_ptr(mbuf->curr,
			xio_write_uint8(val, 0, (uint8_t *)mbuf->curr));
		return 0;
	}
	ERROR_LOG("xio_mbuf_write_u8 failed. curr:%p, " \
		  "len:%zd, buf.tail:%p\n",
		  mbuf->curr, sizeof(uint8_t), mbuf->buf.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_read_u8							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_read_u8(struct xio_mbuf *mbuf, uint8_t *val)
{
	if (sum_to_ptr(mbuf->curr, sizeof(uint8_t)) <= mbuf->tlv.tail) {
		inc_ptr(mbuf->curr,
			xio_read_uint8(val, 0, (const uint8_t *)mbuf->curr));
		return 0;
	}
	ERROR_LOG("xio_mbuf_read_u8 failed. curr:%p, " \
		  "len:%zd, tlv.tail:%p\n",
		  mbuf->curr, sizeof(uint8_t), mbuf->tlv.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_write_u16							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_write_u16(struct xio_mbuf *mbuf, uint16_t val)
{
	if (sum_to_ptr(mbuf->curr, sizeof(uint16_t)) <= mbuf->buf.tail) {
		inc_ptr(mbuf->curr,
			xio_write_uint16(val, 0, (uint8_t *)mbuf->curr));
		return 0;
	}
	ERROR_LOG("xio_mbuf_write_u16 failed. curr:%p, " \
		  "len:%zd, buf.tail:%p\n",
		  mbuf->curr, sizeof(uint16_t), mbuf->buf.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_read_u16							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_read_u16(struct xio_mbuf *mbuf, uint16_t *val)
{
	if (sum_to_ptr(mbuf->curr, sizeof(uint16_t)) <= mbuf->tlv.tail) {
		inc_ptr(mbuf->curr,
			xio_read_uint16(val, 0, (const uint8_t *)mbuf->curr));
		return 0;
	}
	ERROR_LOG("xio_mbuf_read_u16 failed. curr:%p, " \
		  "len:%zd, tlv.tail:%p\n",
		  mbuf->curr, sizeof(uint16_t), mbuf->tlv.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_write_u32							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_write_u32(struct xio_mbuf *mbuf, uint32_t val)
{
	if (sum_to_ptr(mbuf->curr, sizeof(uint32_t)) <= mbuf->buf.tail) {
		inc_ptr(mbuf->curr,
			xio_write_uint32(val, 0, (uint8_t *)mbuf->curr));
		return 0;
	}
	ERROR_LOG("xio_mbuf_write_u32 failed. curr:%p, " \
		  "len:%zd, buf.tail:%p\n",
		  mbuf->curr, sizeof(uint32_t), mbuf->buf.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_read_u32							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_read_u32(struct xio_mbuf *mbuf, uint32_t *val)
{
	if (sum_to_ptr(mbuf->curr, sizeof(uint32_t)) <= mbuf->tlv.tail) {
		inc_ptr(mbuf->curr,
			xio_read_uint32(val, 0, (const uint8_t *)mbuf->curr));
		return 0;
	}
	ERROR_LOG("xio_mbuf_read_u32 failed. curr:%p, " \
		  "len:%zd, tlv.tail:%p\n",
		  mbuf->curr, sizeof(uint32_t), mbuf->tlv.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_write_u64							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_write_u64(struct xio_mbuf *mbuf, uint64_t val)
{
	if (sum_to_ptr(mbuf->curr, sizeof(uint64_t)) <= mbuf->buf.tail) {
		inc_ptr(mbuf->curr,
			xio_write_uint64(val, 0, (uint8_t *)mbuf->curr));
		return 0;
	}
	ERROR_LOG("xio_mbuf_write_u64 failed. curr:%p, len:%zd, " \
		  "buf.tail:%p\n", mbuf->curr, sizeof(uint64_t),
		  mbuf->buf.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_read_u64							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_read_u64(struct xio_mbuf *mbuf, uint64_t *val)
{
	if ((uint64_t)((char *)mbuf->tlv.tail - (char *)mbuf->curr) >
							sizeof(uint64_t)) {
		inc_ptr(mbuf->curr,
			xio_read_uint64(val, 0, (const uint8_t *)mbuf->curr));
		return 0;
	}
	ERROR_LOG("xio_mbuf_read_u64 failed. curr:%p, " \
		  "len:%zd, tlv.tail:%p\n",
		  mbuf->curr, sizeof(uint64_t), mbuf->tlv.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_write_array						     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_write_array(struct xio_mbuf *mbuf, void *array,
				       size_t len)
{
	if (sum_to_ptr(mbuf->curr, len) <= mbuf->buf.tail) {
		inc_ptr(mbuf->curr,
			xio_write_array((const uint8_t *)array, len,
					0, (uint8_t *)mbuf->curr));
		return 0;
	}
	ERROR_LOG("xio_mbuf_write_array failed. curr:%p, "  \
		  "len:%zd, buf.tail:%p\n",
		  mbuf->curr, len, mbuf->buf.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_read_array							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_read_array(struct xio_mbuf *mbuf, void *array,
				      size_t len)
{
	if (sum_to_ptr(mbuf->curr, len) <= mbuf->tlv.tail) {
		inc_ptr(mbuf->curr,
			xio_read_array((uint8_t *)array, len, 0,
				       (const uint8_t *)mbuf->curr));
		return 0;
	}
	ERROR_LOG("xio_mbuf_read_array failed. curr:%p, len:%zd, " \
		  "tlv.tail:%p\n",
		  mbuf->curr, len, mbuf->tlv.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_write_string						     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_write_string(struct xio_mbuf *mbuf,
					const char *str, size_t maxlen)
{
	size_t len = strnlen(str, maxlen);

	if (sum_to_ptr(mbuf->curr, len) <= mbuf->buf.tail) {
		inc_ptr(mbuf->curr,
			xio_write_string(str, maxlen, 0,
					 (uint8_t *)mbuf->curr));
		return 0;
	}

	ERROR_LOG("xio_mbuf_write_string failed. curr:%p, " \
		  "len:%zd, buf.tail:%p\n",
		  mbuf->curr, len, mbuf->buf.tail);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_read_string							     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_read_string(struct xio_mbuf *mbuf, char *str,
				       uint16_t maxlen, size_t *len)
{
	*len = xio_read_string(str, maxlen, 0, (const uint8_t *)mbuf->curr);
	inc_ptr(mbuf->curr, *len);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_set_data_length						     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_set_data_length(struct xio_mbuf *mbuf,
					   size_t datalen)
{
	if (likely(datalen <= mbuf->buf.buflen)) {
		mbuf->buf.datalen = datalen;
		return 0;
	}
	ERROR_LOG("xio_mbuf_set_data_length failed. datalen:%zd, " \
		  "buf.buflen:%u\n", datalen, mbuf->buf.buflen);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_mbuf_read_first_tlv						     */
/*---------------------------------------------------------------------------*/
static inline int xio_mbuf_read_type(struct xio_mbuf *mbuf)
{
	struct xio_tlv *tlv = (struct xio_tlv *)mbuf->buf.head;

	return ntohl(tlv->type);
}

#endif

