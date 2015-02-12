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
#include <linux/kernel.h>
#include <linux/topology.h>
#include <linux/inet.h>

#include <xio_os.h>
#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "xio_protocol.h"
#include "xio_sg_table.h"

#ifndef IN6ADDR_ANY_INIT
#define IN6ADDR_ANY_INIT \
	{ { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } } }
#endif

/*---------------------------------------------------------------------------*/
/* defines	                                                             */
/*---------------------------------------------------------------------------*/
static int _xio_errno;

/*---------------------------------------------------------------------------*/
/* debuging facilities							     */
/*---------------------------------------------------------------------------*/
void xio_set_error(int errnum) { _xio_errno = errnum; }
EXPORT_SYMBOL(xio_set_error);

/*---------------------------------------------------------------------------*/
/* xio_errno								     */
/*---------------------------------------------------------------------------*/
int xio_errno(void) { return _xio_errno; }
EXPORT_SYMBOL(xio_errno);

static int priv_parse_ip_addr(const char *str, size_t len, __be16 port,
			      struct sockaddr_storage *ss)
{
	const char *end;

	if (strnchr(str, len, '.')) {
		/* Try IPv4 */
		struct sockaddr_in *s4 = (struct sockaddr_in *)ss;

		if (in4_pton(str, len, (void *)&s4->sin_addr, -1, &end) > 0) {
			if (!*end) {
				/* reached the '\0' */
				s4->sin_family = AF_INET;
				s4->sin_port = port;
				return 0;
			}
		}
	} else if (strnchr(str, len, ':')) {
		/* Try IPv6 */
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;

		if (in6_pton(str, -1, (void *)&s6->sin6_addr, -1, &end) > 0) {
			if (!*end) {
				/* reached the '\0' */
				/* what about scope and flow */
				s6->sin6_family = AF_INET6;
				s6->sin6_port = port;
				return 1;
			}
		}
	}
	return -1;
}

#define NI_MAXSERV 32

/*---------------------------------------------------------------------------*/
/* xio_uri_to_ss							     */
/*---------------------------------------------------------------------------*/
int xio_uri_to_ss(const char *uri, struct sockaddr_storage *ss)
{
	char		*start;
	char		*host = NULL;
	char		port[NI_MAXSERV];
	unsigned long	portul;
	unsigned short	port16;
	__be16		port_be16;
	const char	*p1, *p2;
	size_t		len;
	int		ipv6_hint = 0;
	int		ss_len = -1;
	int		retval;

	/* only supported protocol is rdma */
	start = strstr(uri, "://");
	if (!start)
		return -1;

	if (*(start+3) == '[') {  /* IPv6 */
		ipv6_hint = 1;
		p1 = strstr(start + 3, "]:");
		if (!p1)
			return -1;

		len = p1-(start+4);
		host = kstrndup((char *)(start + 4), len, GFP_KERNEL);
		if (host)
			host[len] = 0;

		p2 = strchr(p1 + 2, '/');
		if (!p2) {
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
				goto cleanup;
		}

		if (!p2) { /* no resource */
			p1 = strrchr(uri, ':');
			if (!p1 || p1 == start)
				goto cleanup;
			strcpy(port, (p1 + 1));
		} else {
			if (*p2 != '/')
				goto cleanup;
			p1 = p2;
			while (*p1 != ':') {
				p1--;
				if (p1 == uri)
					goto cleanup;
			}

			len = p2 - (p1 + 1);

			strncpy(port, p1 + 1, len);
			port[len] = 0;
		}
		len = p1 - (start + 3);

		/* extract the address */
		host = kstrndup((char *)(start + 3), len, GFP_KERNEL);
		if (host)
			host[len] = 0;
	}

	/* debug */
	DEBUG_LOG("host:%s port:%s\n", host, port);

	if (kstrtoul(port, 10, &portul)) {
		ERROR_LOG("Invalid port specification(%s)\n", port);
		goto cleanup;
	}
	if (portul > 0xFFFF) {
		ERROR_LOG("Invalid port specification(%s)\n", port);
		goto cleanup;
	}
	port16 = portul;
	port_be16 = htons(port16);

	if (!host || (host && (host[0] == '*' || host[0] == 0))) {
		if (ipv6_hint) {
			struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;

			/* what about scope and flow */
			s6->sin6_family = AF_INET6;
			/* s6->sin6_addr	= IN6ADDR_ANY_INIT; */
			memset((void *)&s6->sin6_addr,
			       0, sizeof(s6->sin6_addr));
			s6->sin6_port	= port_be16;
			ss_len = sizeof(struct sockaddr_in6);
		} else {
			struct sockaddr_in *s4 = (struct sockaddr_in *)ss;

			s4->sin_family		= AF_INET;
			s4->sin_addr.s_addr	= INADDR_ANY;
			s4->sin_port		= port_be16;
			ss_len = sizeof(struct sockaddr_in);
		}
	} else {
		retval = priv_parse_ip_addr(host, len, port_be16, ss);
		if (retval < 0) {
			ERROR_LOG("unresolved address\n");
			goto cleanup;
		} else if (retval == 0) {
			ss_len = sizeof(struct sockaddr_in);
		} else if (retval == 1) {
			ss_len = sizeof(struct sockaddr_in6);
		}
	}

	kfree(host);
	return ss_len;

cleanup:
	kfree(host);
	return -1;
}
EXPORT_SYMBOL(xio_uri_to_ss);

int xio_host_port_to_ss(const char *buf, struct sockaddr_storage *ss)
{
	ERROR_LOG("unsupported\n");
	return -1;
}
EXPORT_SYMBOL(xio_host_port_to_ss);

/*
 * xio_get_nodeid(cpuid) - This will return the node to which selected cpu
 * belongs
 */
unsigned int xio_get_nodeid(unsigned int cpu_id)
{
	return cpu_to_node(cpu_id);
}

void xio_msg_dump(struct xio_msg *xio_msg)
{
	int i;
	struct  xio_sg_table_ops *sgtbl_ops;
	void			 *sgtbl;
	void			 *sge;

	ERROR_LOG("*********************************************\n");
	ERROR_LOG("type:0x%x\n", xio_msg->type);
	if (xio_msg->type == XIO_MSG_TYPE_REQ ||
	    xio_msg->type == XIO_ONE_WAY_REQ)
		ERROR_LOG("serial number:%lld\n", xio_msg->sn);
	else if (xio_msg->type == XIO_MSG_TYPE_RSP)
		ERROR_LOG("response:%p, serial number:%lld\n",
			  xio_msg->request,
			  ((xio_msg->request) ? xio_msg->request->sn : -1));

	sgtbl		= xio_sg_table_get(&xio_msg->in);
	sgtbl_ops	= xio_sg_table_ops_get(xio_msg->in.sgl_type);

	ERROR_LOG("in header: length:%zd, address:%p\n",
		  xio_msg->in.header.iov_len, xio_msg->in.header.iov_base);
	ERROR_LOG("in sgl type:%d max_nents:%d\n", xio_msg->in.sgl_type,
		  tbl_max_nents(sgtbl_ops, sgtbl));
	ERROR_LOG("in data size:%d\n",
		  tbl_nents(sgtbl_ops, sgtbl));

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		ERROR_LOG("in data[%d]: length:%zd, address:%p\n", i,
			  sge_length(sgtbl_ops, sge),
			  sge_addr(sgtbl_ops, sge));
	}

	sgtbl		= xio_sg_table_get(&xio_msg->out);
	sgtbl_ops	= xio_sg_table_ops_get(xio_msg->out.sgl_type);

	ERROR_LOG("out header: length:%zd, address:%p\n",
		  xio_msg->out.header.iov_len,
		  xio_msg->out.header.iov_base);
	ERROR_LOG("out sgl type:%d max_nents:%d\n",
		  xio_msg->out.sgl_type,
		  tbl_max_nents(sgtbl_ops, sgtbl));
	ERROR_LOG("out data size:%d\n", tbl_nents(sgtbl_ops, sgtbl));

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		ERROR_LOG("out data[%d]: length:%zd, address:%p\n", i,
			  sge_length(sgtbl_ops, sge),
			  sge_addr(sgtbl_ops, sge));
	}
	ERROR_LOG("*********************************************\n");
}
EXPORT_SYMBOL(xio_msg_dump);

