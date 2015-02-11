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
#include "xio_log.h"
#include "xio_common.h"
#include "xio_protocol.h"

/*---------------------------------------------------------------------------*/
/* xio_uri_get_proto							     */
/*---------------------------------------------------------------------------*/
int xio_uri_get_proto(const char *uri, char *proto, int proto_len)
{
	char *start = (char *)uri;
	const char *end;
	char *p;
	int  i;

	end = strstr(uri, "://");
	if (!end)
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
const char *xio_uri_get_resource_ptr(const char *uri)
{
	const char *start;
	const char *p1, *p2 = NULL;

	start = strstr(uri, "://");
	if (!start)
		return NULL;

	if (*(start+3) == '[') {  /* IPv6 */
		p1 = strstr(start + 4, "]:");
		if (!p1)
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

	return p2;
}

/*---------------------------------------------------------------------------*/
/* xio_uri_get_portal							     */
/*---------------------------------------------------------------------------*/
int xio_uri_get_portal(const char *uri, char *portal, int portal_len)
{
	const char *res = xio_uri_get_resource_ptr(uri);
	int len = (!res) ? strlen(uri) : (size_t)(res - uri);

	if (len < portal_len) {
		strncpy(portal, uri, len);
		portal[len] = 0;
		return 0;
	}

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_uri_get_resource							     */
/*---------------------------------------------------------------------------*/
int xio_uri_get_resource(const char *uri, char *resource, int resource_len)
{
	const char *res = xio_uri_get_resource_ptr(uri);

	if (res) {
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
size_t xio_write_tlv(uint32_t type, uint64_t len, uint8_t *buffer)
{
	struct xio_tlv *tlv = (struct xio_tlv *)buffer;

	tlv->magic	= htonl(XIO_MAGIC);
	tlv->type	= htonl(type);
	tlv->len	= htonll(len);

	return sizeof(struct xio_tlv) + (size_t)len;
}
EXPORT_SYMBOL(xio_write_tlv);

/*---------------------------------------------------------------------------*/
/* xio_read_tlv								     */
/*---------------------------------------------------------------------------*/
size_t xio_read_tlv(uint32_t *type, uint64_t *len, void **value,
		    uint8_t *buffer)
{
	struct xio_tlv *tlv;

	tlv = (struct xio_tlv *)buffer;
	if (unlikely(tlv->magic != htonl(XIO_MAGIC)))
		return -1;

	*type	= ntohl(tlv->type);
	*len	= ntohll(tlv->len);
	*value =  buffer + sizeof(struct xio_tlv);

	return sizeof(struct xio_tlv) + (size_t)*len;
}
EXPORT_SYMBOL(xio_read_tlv);

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

/*---------------------------------------------------------------------------*/
/* memclonev								     */
/*---------------------------------------------------------------------------*/
size_t memclonev(struct xio_iovec *dst, int dsize,
		 struct xio_iovec *src, int ssize)
{
	int			nr = 0;
	int			sz;

	sz = (dsize < ssize) ? dsize : ssize;

	while (nr < sz) {
		dst[nr].iov_base = src[nr].iov_base;
		dst[nr].iov_len = src[nr].iov_len;
		nr++;
	}

	return sz;
}
EXPORT_SYMBOL(memclonev);

/*---------------------------------------------------------------------------*/
/* memclonev_ex								     */
/*---------------------------------------------------------------------------*/
size_t memclonev_ex(struct xio_iovec_ex *dst, int dsize,
		    struct xio_iovec_ex *src, int ssize)
{
	int			nr = 0;
	int			sz;

	sz = (dsize < ssize) ? dsize : ssize;

	while (nr < sz) {
		dst[nr].iov_base = src[nr].iov_base;
		dst[nr].iov_len = src[nr].iov_len;
		nr++;
	}

	return sz;
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

/**
 * memcpyv
 *
 * Copy data from one iov to another.
 *
 * @dst:	An array of iovec structures that you want to
 *		copy the data to.
 * @dsize:	The number of entries in the dst array.
 * @src:	An array of iovec structures that you want to
 *		copy the data from.
 * @ssize:	The number of entries in the src array.
 */
size_t memcpyv(struct xio_iovec *dst, int dsize,
	       struct xio_iovec *src, int ssize)
{
	void		*daddr	= dst[0].iov_base;
	void		*saddr	= src[0].iov_base;
	size_t		dlen	= dst[0].iov_len;
	size_t		slen	= src[0].iov_len;
	int		d	= 0,
			s	= 0,
			dst_len = 0;

	if (dsize < 1 || ssize < 1) {
		ERROR_LOG("iovec size < 1 dsize:%d, ssize:%d\n",
			  dsize, ssize);
		return 0;
	}

	while (1) {
		if (slen < dlen) {
			memcpy(daddr, saddr, slen);
			dst_len	+= slen;

			s++;
			if (s == ssize) {
				dst[d].iov_len = dst_len;
				d++;
				break;
			}
			dlen	-= slen;
			inc_ptr(daddr, slen);
			saddr	= src[s].iov_base;
			slen	= src[s].iov_len;
		} else if (dlen < slen) {
			memcpy(daddr, saddr, dlen);
			dst[d].iov_len = dst_len + dlen;
			dst_len = 0;

			d++;
			if (d == dsize)
				break;
			slen	-= dlen;
			inc_ptr(saddr, dlen);
			daddr	= dst[d].iov_base;
			dlen	= dst[d].iov_len;

		} else {
			memcpy(daddr, saddr, dlen);
			dst[d].iov_len = dst_len + dlen;
			dst_len = 0;

			d++;
			s++;
			if ((d == dsize) || (s == ssize))
				break;

			daddr	= dst[d].iov_base;
			dlen	= dst[d].iov_len;
			saddr	= src[s].iov_base;
			slen	= src[s].iov_len;
		}
	}

	/* not enough buffers to complete */
	if (s < ssize) {
		ERROR_LOG("dest iovec exausted\n");
		return 0;
	}

	return d;
}

/**
 * memcpyv_ex
 *
 * Copy data from one iov to another.
 *
 * @dst:	An array of iovec structures that you want to
 *		copy the data to.
 * @dsize:	The number of entries in the dst array.
 * @src:	An array of iovec structures that you want to
 *		copy the data from.
 * @ssize:	The number of entries in the src array.
 */
size_t memcpyv_ex(struct xio_iovec_ex *dst, int dsize,
		  struct xio_iovec_ex *src, int ssize)
{
	void		*daddr	= dst[0].iov_base;
	void		*saddr	= src[0].iov_base;
	size_t		dlen	= dst[0].iov_len;
	size_t		slen	= src[0].iov_len;
	int		d	= 0,
			s	= 0,
			dst_len = 0;

	if (dsize < 1 || ssize < 1) {
		ERROR_LOG("iovec size < 1 dsize:%d, ssize:%d\n",
			  dsize, ssize);
		return 0;
	}

	while (1) {
		if (slen < dlen) {
			memcpy(daddr, saddr, slen);
			dst_len	+= slen;

			s++;
			if (s == ssize) {
				dst[d].iov_len = dst_len;
				d++;
				break;
			}
			dlen	-= slen;
			inc_ptr(daddr, slen);
			saddr	= src[s].iov_base;
			slen	= src[s].iov_len;
		} else if (dlen < slen) {
			memcpy(daddr, saddr, dlen);
			dst[d].iov_len = dst_len + dlen;
			dst_len = 0;

			d++;
			if (d == dsize)
				break;
			slen	-= dlen;
			inc_ptr(saddr, dlen);
			daddr	= dst[d].iov_base;
			dlen	= dst[d].iov_len;

		} else {
			memcpy(daddr, saddr, dlen);
			dst[d].iov_len = dst_len + dlen;
			dst_len = 0;

			d++;
			s++;
			if ((d == dsize) || (s == ssize))
				break;

			daddr	= dst[d].iov_base;
			dlen	= dst[d].iov_len;
			saddr	= src[s].iov_base;
			slen	= src[s].iov_len;
		}
	}

	/* not enough buffers to complete */
	if (s < ssize) {
		ERROR_LOG("dest iovec exhausted\n");
		return 0;
	}

	return d;
}

extern const char XIO_VERSION_STRING[];

/*---------------------------------------------------------------------------*/
/* xio_version								     */
/*---------------------------------------------------------------------------*/
inline const char *xio_version(void)
{
	return XIO_VERSION_STRING;
}
EXPORT_SYMBOL(xio_version);

/*---------------------------------------------------------------------------*/
/* xio_proto_str							     */
/*---------------------------------------------------------------------------*/
const char *xio_proto_str(enum xio_proto proto)
{
	switch (proto) {
	case XIO_PROTO_RDMA: return "rdma";
	case XIO_PROTO_TCP: return "tcp";
	default: return "proto_unknown";
	}
}
EXPORT_SYMBOL(xio_proto_str);

