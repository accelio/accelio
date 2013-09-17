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


int _xio_errno;

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
/* xio_uri_to_ss							     */
/*---------------------------------------------------------------------------*/
int xio_uri_to_ss(const char *uri, struct sockaddr_storage *ss)
{
	char		*start;
	char		host[NI_MAXHOST];
	char		port[NI_MAXSERV];
	const char	*p1, *p2;
	int		s = 0;
	int		len;
	struct addrinfo hints;
	struct addrinfo *result;
	socklen_t	ss_len;

	/* only supported protocol is rdma */
	start = strstr(uri, "://");
	if (start == NULL)
		return -1;

	if (*(start+3) == '[') {  /* IPv6 */
		p1 = strstr(start + 3, "]:");
		if (p1 == NULL)
			return -1;

		len = p1-(start+4);
		strncpy(host, (start + 4), len);
		host[len] = 0;

		p2 = strchr(p1 + 2, '/');
		if (p2 == NULL) {
			strcpy(port, p1 + 2);
		} else {
			len = (p2-1)-(p1+2);
			strncpy(port, (p1 + 2), len);
			port[len] = 0;
		}
	} else {
		/* extract the resource */
		p1 = uri + strlen(uri);
		p2 = NULL;
		while (p1 != (start + 3)) {
			if (*p1 == '/')
				p2 = p1;
			p1--;
			if (p1 == uri)
				return  -1;
		}

		if (p2 == NULL) { /* no resource */
			p1 = strrchr(uri, ':');
			if (p1 == NULL || p1 == start)
				return -1;
			strcpy(port, (p1 + 1));
		} else {
			p1 = p2;
			while (*p1 != ':') {
				p1--;
				if (p1 == uri)
					return  -1;
			}

			len = (p2-1) - (p1 + 1);

			strncpy(port, p1 + 1, len);
			port[len] = 0;
		}
		len = p1 - (start + 3);

		/* extract the address */
		strncpy(host, (start + 3), len);
		host[len] = 0;
	}
	/*printf("host:%s port:%s\n", host, port); */


	/* Obtain address(es) matching host/port */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family		= AF_UNSPEC;	/* Allow IPv4 or IPv6 */
	hints.ai_socktype	= SOCK_STREAM;	/* STREAM socket */

	if (host[0] == '*' || host[0] == 0) {
		hints.ai_flags	= AI_PASSIVE;
		s = getaddrinfo(NULL, port, &hints, &result);
	} else {
		s = getaddrinfo(host, port, &hints, &result);
	}
	if (s != 0) {
		ERROR_LOG("getaddrinfo failed. %s\n", gai_strerror(s));
		return -1;
	}
	if (result == NULL) {
		ERROR_LOG("unresolved address\n");
		return -1;
	}
	if (result->ai_next && (hints.ai_flags != AI_PASSIVE)) {
		ERROR_LOG("more then one address is matched\n");
		return -1;
	}
	switch (result->ai_family) {
	case AF_INET:
		ss_len = sizeof(struct sockaddr_in);
		memcpy(ss, result->ai_addr, ss_len);
		break;
	case AF_INET6:
		ss_len = sizeof(struct sockaddr_in6);
		memcpy(ss, result->ai_addr, ss_len);
		break;
	}
	freeaddrinfo(result);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_write_tlv							     */
/*---------------------------------------------------------------------------*/
size_t xio_write_tlv(uint16_t type, uint64_t len, uint8_t *buffer)
{
	static  uint32_t  magic;
	struct xio_tlv *tlv = (struct xio_tlv *)buffer;

	if (magic == 0)
		magic = htonl(XIO_MAGIC);

	tlv->magic	= magic;
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
	static uint32_t  magic;

	if (magic == 0)
		magic = ntohl(XIO_MAGIC);

	tlv = (struct xio_tlv *)buffer;
	if (tlv->magic != magic)
		return -1;

	*type	= ntohs(tlv->type);
	*len	= ntohll(tlv->len);
	*value =  buffer + sizeof(struct xio_tlv);

	return sizeof(struct xio_tlv) + *len;
}


const char hex_asc[] = "0123456789abcdef";
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]

/**
 * hex_dump_to_buffer - convert a blob of data to "hex ASCII" in memory
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @rowsize: number of bytes to print per line; must be 16 or 32
 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 * @linebuf: where to put the converted data
 * @linebuflen: total size of @linebuf, including space for terminating NUL
 * @ascii: include ASCII after the hex output
 *
 * hex_dump_to_buffer() works on one "line" of output at a time, i.e.,
 * 16 or 32 bytes of input data converted to hex + ASCII output.
 *
 * Given a buffer of uint8_t data, hex_dump_to_buffer() converts the input data
 * to a hex + ASCII dump at the supplied memory location.
 * The converted output is always NUL-terminated.
 *
 * E.g.:
 *   hex_dump_to_buffer(frame->data, frame->len, 16, 1,
 *			linebuf, sizeof(linebuf), true);
 *
 * example output buffer:
 * 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 */
void hex_dump_to_buffer(const void *buf, size_t len, int rowsize,
			int groupsize, char *linebuf, size_t linebuflen,
			int ascii)
{
	const uint8_t *ptr = buf;
	uint8_t ch;
	int j, lx = 0;
	int ascii_column;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	if (!len)
		goto nil;
	if (len > rowsize)		/* limit to one line at a time */
		len = rowsize;
	if ((len % groupsize) != 0)	/* no mixed size output */
		groupsize = 1;

	switch (groupsize) {
	case 8: {
		const uint64_t *ptr8 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += snprintf(linebuf + lx, linebuflen - lx,
					"%s%16.16llx", j ? " " : "",
					(unsigned long long)*(ptr8 + j));
		ascii_column = 17 * ngroups + 2;
		break;
	}

	case 4: {
		const uint32_t *ptr4 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += snprintf(linebuf + lx, linebuflen - lx,
					"%s%8.8x", j ? " " : "", *(ptr4 + j));
		ascii_column = 9 * ngroups + 2;
		break;
	}

	case 2: {
		const uint16_t *ptr2 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += snprintf(linebuf + lx, linebuflen - lx,
					"%s%4.4x", j ? " " : "", *(ptr2 + j));
		ascii_column = 5 * ngroups + 2;
		break;
	}

	default:
		for (j = 0; (j < len) && (lx + 3) <= linebuflen; j++) {
			ch = ptr[j];
			linebuf[lx++] = hex_asc_hi(ch);
			linebuf[lx++] = hex_asc_lo(ch);
			linebuf[lx++] = ' ';
		}
		if (j)
			lx--;

		ascii_column = 3 * rowsize + 2;
		break;
	}
	if (!ascii)
		goto nil;

	while (lx < (linebuflen - 1) && lx < (ascii_column - 1))
		linebuf[lx++] = ' ';
	for (j = 0; (j < len) && (lx + 2) < linebuflen; j++) {
		ch = ptr[j];
		linebuf[lx++] = (isascii(ch) && isprint(ch)) ? ch : '.';
	}
nil:
	linebuf[lx++] = '\0';
}

/**
 * print_hex_dump - print a text hex dump to syslog for a binary blob of data
 * @level: kernel log level (e.g. KERN_DEBUG)
 * @prefix_str: string to prefix each line with;
 *  caller supplies trailing spaces for alignment if desired
 * @prefix_type: controls whether prefix of an offset, address, or none
 *  is printed (%DUMP_PREFIX_OFFSET, %DUMP_PREFIX_ADDRESS, %DUMP_PREFIX_NONE)
 * @rowsize: number of bytes to print per line; must be 16 or 32
 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @ascii: include ASCII after the hex output
 *
 * Given a buffer of uint8_t data, print_hex_dump() prints a hex + ASCII dump
 * to the kernel log at the specified kernel log level, with an optional
 * leading prefix.
 *
 * print_hex_dump() works on one "line" of output at a time, i.e.,
 * 16 or 32 bytes of input data converted to hex + ASCII output.
 * print_hex_dump() iterates over the entire input @buf, breaking it into
 * "line size" chunks to format and print.
 *
 * E.g.:
 *   print_hex_dump(KERN_DEBUG, "raw data: ", DUMP_PREFIX_ADDRESS,
 *		    16, 1, frame->data, frame->len, true);
 *
 * Example output using %DUMP_PREFIX_OFFSET and 1-byte mode:
 * 0009ab42: 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 * Example output using %DUMP_PREFIX_ADDRESS and 4-byte mode:
 * ffffffff88089af0: 73727170 77767574 7b7a7978 7f7e7d7c  pqrstuvwxyz{|}~.
 */
void print_hex_dump(const char *prefix_str, int prefix_type,
		    int rowsize, int groupsize,
		    const void *buf, size_t len, int ascii)
{
	const uint8_t *ptr = buf;
	int i, linelen, remaining = len;
	unsigned char linebuf[32 * 3 + 2 + 32 + 1];

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
				   (char *)linebuf, sizeof(linebuf), ascii);

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			printf("%s%p: %s\n",
			       prefix_str, ptr + i, linebuf);
			break;
		case DUMP_PREFIX_OFFSET:
			printf("%s%.8x: %s\n", prefix_str, i, linebuf);
			break;
		default:
			printf("%s%s\n", prefix_str, linebuf);
			break;
		}
	}
}

/**
 * print_hex_dump_bytes - shorthand form of print_hex_dump() with default params
 * @prefix_str: string to prefix each line with;
 *  caller supplies trailing spaces for alignment if desired
 * @prefix_type: controls whether prefix of an offset, address, or none
 *  is printed (%DUMP_PREFIX_OFFSET, %DUMP_PREFIX_ADDRESS, %DUMP_PREFIX_NONE)
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 *
 * Calls print_hex_dump(), with log level of KERN_DEBUG,
 * rowsize of 16, groupsize of 1, and ASCII output included.
 */
void print_hex_dump_bytes(const char *prefix_str, int prefix_type,
			  const void *buf, size_t len)
{
	print_hex_dump(prefix_str, prefix_type, 16, 1,
		       buf, len, 1);
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
	unsigned long seg;
	size_t ret = 0;

	for (seg = 0; seg < nr_segs; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

inline size_t xio_iovex_length(const struct xio_iovec_ex *iov,
			       unsigned long nr_segs)
{
	unsigned long seg;
	size_t ret = 0;

	for (seg = 0; seg < nr_segs; seg++)
		ret += iov[seg].iov_len;
	return ret;
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
 * xio_get_nodeid(cpuid) - This will return the node to which selected cpu
 * belongs
 */
unsigned int xio_get_nodeid(unsigned int cpu_id)
{
	DIR *directory_parent, *directory_node;
	struct dirent *de,*dn;
	char directory_path[255];
	unsigned int cpu;
	int node_id = 0;
	int found = 0;

	directory_parent = opendir("/sys/devices/system/node");
	if (!directory_parent)  {
		fprintf(stderr,
			"/sys not mounted or not a numa system. Assuming one node: %s\n",
			strerror(errno));
		return 0; /* By Default assume it to belong to node zero */
	} else {
		while ((de = readdir(directory_parent)) != NULL) {
			if (strncmp(de->d_name, "node", 4))
				continue;
			sprintf(directory_path,"/sys/devices/system/node/%s",de->d_name);
			directory_node = opendir(directory_path);
			while ((dn = readdir(directory_node)) != NULL) {
				if (strncmp(dn->d_name, "cpu", 3))
					continue;
				cpu = strtoul(dn->d_name+3,NULL,0);
				if ( cpu == cpu_id ){
					node_id = strtoul(de->d_name+4, NULL, 0);
					found = 1;
					break;
				}
			}
			closedir(directory_node);
			if (found)
				break;
		}
		closedir(directory_parent);
	}
	return node_id;
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



#define CACHE_LINE_FILE	\
	"/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"

static inline int arch_cache_line_size(void)
{
	char size[32];
	int fd, ret;

	fd = open(CACHE_LINE_FILE, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, size, sizeof(size));

	close(fd);

	if (ret <= 0)
		return -1;
	else
		return atoi(size);
}

*/
