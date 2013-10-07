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
#include "xio_os.h"
#include "libxio.h"
#include "xio_common.h"
#include "xio_protocol.h"


/*---------------------------------------------------------------------------*/
/* xio_uri_get_proto							     */
/*---------------------------------------------------------------------------*/
int xio_uri_get_proto(const char *uri,
			char *proto, int proto_len)
{
	char *start = (char *)uri;
	char *end;
	char *p;
	int  i;

	end = strstr(uri, "://");
	if (end == NULL)
		return -1;

	p = start;
	for (i = 0; i < proto_len; i++) {
		if (p == end) {
			proto[i] = 0;
			return 0;
		}
		proto[i] = *p;
		p++;
	}

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_uri_get_resource_ptr						     */
/*---------------------------------------------------------------------------*/
char *xio_uri_get_resource_ptr(const char *uri)
{
	char *start;
	char *p1, *p2 = NULL;


	start = strstr(uri, "://");
	if (start == NULL)
		return NULL;


	if (*(start+3) == '[') {  /* IPv6 */
		p1 = strstr(start + 4, "]:");
		if (p1 == NULL)
			return NULL;
		p2 = strchr(p1 + 2, '/');

		return p2;
	}

	p1 = (char *)uri + strlen(uri);
	while (p1 != (start + 3)) {
		if (*p1 == '/')
			p2 = p1;
		p1--;
	}

	return (p2 == NULL) ? NULL : p2;
}
/*---------------------------------------------------------------------------*/
/* xio_uri_get_portal							     */
/*---------------------------------------------------------------------------*/
int xio_uri_get_portal(const char *uri,
		char *portal, int portal_len)
{
	char *res = xio_uri_get_resource_ptr(uri);
	int len = (res == NULL) ? strlen(uri) : (res - uri);
	if (len < portal_len) {
		strncpy(portal, uri, len);
		portal[len] = 0;
		return 0;
	}

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_uri_get_resource						     */
/*---------------------------------------------------------------------------*/
int xio_uri_get_resource(const char *uri,
		char *resource, int resource_len)
{
	char *res = xio_uri_get_resource_ptr(uri);
	if (res != NULL) {
		int  len = strlen(res);
		if (len < resource_len) {
			strcpy(resource, res);
			return 0;
		}
	}

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_write_tlv							     */
/*---------------------------------------------------------------------------*/
size_t xio_write_tlv(uint16_t type, uint64_t len, uint8_t *buffer)
{
	struct xio_tlv *tlv = (struct xio_tlv *)buffer;

	tlv->magic	= htonl(XIO_MAGIC);
	tlv->type	= htons(type);
	tlv->len	= htonll(len);

	return sizeof(struct xio_tlv) + len;
}

/*---------------------------------------------------------------------------*/
/* xio_read_tlv							     */
/*---------------------------------------------------------------------------*/
size_t xio_read_tlv(uint16_t *type, uint64_t *len, void **value,
		      uint8_t *buffer)
{
	struct xio_tlv *tlv;

	tlv = (struct xio_tlv *)buffer;
	if (tlv->magic != ntohl(XIO_MAGIC))
		return -1;

	*type	= ntohs(tlv->type);
	*len	= ntohll(tlv->len);
	*value =  buffer + sizeof(struct xio_tlv);

	return sizeof(struct xio_tlv) + *len;
}

#ifndef SETIOV
#define SETIOV(_iov, _addr, _len)	((_iov)->iov_base = \
				(void *)(_addr), (_iov)->iov_len = (_len))
#endif
#ifndef GETIOVBASE
#define GETIOVBASE(_iov)            ((_iov)->iov_base)
#endif
#ifndef GETIOVLEN
#define GETIOVLEN(_iov)              ((_iov)->iov_len)
#endif

/**
 * memcpyv
 *
 * Copy data from one iov to another.
 *
 * @dst:	An array of iovec structures that you want to
 *		copy the data to.
 * @dparts:	The number of entries in the dst array.
 * @doff:	The offset into the dst array at which to start copying.
 * @src:	An array of iovec structures that you want to
 *		copy the data from.
 * @sparts:	The number of entries in the src array.
 * @soff:	The offset into the src array at which to start copying.
 */
size_t memcpyv(const struct xio_iovec *dst, int dparts, int doff,
	       const struct xio_iovec *src, int sparts, int soff) {
	unsigned char	*saddr, *daddr;
	int			slen, dlen;
	size_t			nbytes;

	/* Check for a dst offset and skip over it. */
	while (doff >= (dlen = GETIOVLEN(dst))) {
		doff -= dlen;
		if (--dparts == 0)	/* No more parts. */
			return 0;
		dst++;
	}
	dlen -= doff;
	daddr = (unsigned char *)GETIOVBASE(dst) + doff;

	/* Check for a src offset and skip over it. */
	while (soff >= (slen = GETIOVLEN(src))) {
		soff -= slen;
		if (--sparts == 0)	/* No more parts. */
			return 0;
		src++;
	}
	slen -= soff;
	saddr = (unsigned char *)GETIOVBASE(src) + soff;

	/* Now we move the data. */
	nbytes = 0;
	for (;;) {
		int len;

		/* Check how many bytes can be moved. */
		len = min(slen, dlen);
		if (len) {
			nbytes += len;
			memcpy(daddr, saddr, len);
		}

		/* Adjust source. */
		saddr += len;
		slen -= len;
		if (slen == 0) {
			if (--sparts == 0)
				break;
			src++;
			saddr = (unsigned char *)GETIOVBASE(src);
			slen  = GETIOVLEN(src);
		}

		/* Adjust dest. */
		daddr += len;
		dlen -= len;
		if (dlen == 0) {
			if (--dparts == 0)
				break;
			dst++;
			daddr = (unsigned char *)GETIOVBASE(dst);
			dlen  = GETIOVLEN(dst);
		}
	}

	return nbytes;
}

/*---------------------------------------------------------------------------*/
/* memclonev								     */
/*---------------------------------------------------------------------------*/
size_t memclonev(struct xio_iovec *dst, int *dparts,
		 const struct xio_iovec *src, int sparts)
{
	size_t		    nbytes = 0;
	struct xio_iovec *pdst = dst;

	if (dparts)
		*dparts =  sparts;
	while (sparts > 0) {
		GETIOVBASE(pdst) = GETIOVBASE(src);
		GETIOVLEN(pdst) = GETIOVLEN(src);
		nbytes += GETIOVLEN(pdst);
		sparts--;
		pdst++;
		src++;
	}

	return nbytes;
}

/*
 * Total number of bytes covered by an iovec.
 */
inline size_t xio_iov_length(const struct xio_iovec *iov,
			       unsigned long nr_segs)
{
	size_t			nbytes = 0;
	const struct xio_iovec	*piov = iov;

	while (nr_segs > 0) {
		nbytes += GETIOVLEN(piov);
		nr_segs--;
		piov++;
	}

	return nbytes;
}

inline size_t xio_iovex_length(const struct xio_iovec_ex *iov,
			       unsigned long nr_segs)
{
	size_t				nbytes = 0;
	const struct xio_iovec_ex	*piov = iov;

	while (nr_segs > 0) {
		nbytes += GETIOVLEN(piov);
		nr_segs--;
		piov++;
	}

	return nbytes;

}

/*---------------------------------------------------------------------------*/
/* msg_reset								     */
/*---------------------------------------------------------------------------*/
void msg_reset(struct xio_msg *msg)
{
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	msg->in.data_iovlen = 0;
	msg->out.header.iov_base = NULL;
	msg->out.header.iov_len = 0;
	msg->out.data_iovlen = 0;
}

/*
void *xio_memcpy(void* dest, const void* src, size_t count)
{
	char* dst8 = (char*)dest;
	char* src8 = (char*)src;

	if (count & 1) {
		dst8[0] = src8[0];
		dst8 += 1;
		src8 += 1;
	}

	count /= 2;
	while (count--) {
		dst8[0] = src8[0];
		dst8[1] = src8[1];

		dst8 += 2;
		src8 += 2;
	}
	return dest;
}

*/
