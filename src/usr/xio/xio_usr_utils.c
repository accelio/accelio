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
#include <xio_env.h>
#include <xio_os.h>
#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "xio_protocol.h"
#include "xio_sg_table.h"
#include "xio_observer.h"
#include "xio_usr_transport.h"

/*---------------------------------------------------------------------------*/
/* xio_host_port_to_ss							     */
/*---------------------------------------------------------------------------*/
int xio_host_port_to_ss(const char *buf, struct sockaddr_storage *ss)
{
	char		*cp = (char *)buf;
	char		*tp;
	int		len;
	char		host[NI_MAXHOST];
	char		port[NI_MAXSERV];
	int		s = 0;
	struct addrinfo hints;
	struct addrinfo *result;
	socklen_t	ss_len = -1;

	/*
	 * [host]:port, [host]:, [host].
	 * [ipv6addr]:port, [ipv6addr]:, [ipv6addr].
	 */
	if (*cp == '[') {
		++cp;
		tp = strchr(cp, ']');
		if (!tp)
			return -1;
		len = tp - cp;
		strncpy(host, cp, len);
		host[len] = 0;
		tp++;
		if (*tp == 0) {
			strcpy(port, "0");
		} else if (*tp == ':') {
			tp++;
			if (*tp)
				strcpy(port, tp);
			else
				strcpy(port, "0");
		} else {
			strcpy(port, "0");
		}
	} else {
		/*
		 * host:port, host:, host, :port.
		 */
		if (*cp == ':') {
			strcpy(host, "0.0.0.0");
			cp++;
			if (*cp)
				strcpy(port, cp);
			else
				strcpy(port, "0");
		} else {
			tp = strrchr(cp, ':');
			if (tp == NULL) {
				strcpy(host, cp);
				strcpy(port, "0");
			}  else {
				len = tp - cp;
				strncpy(host, cp, len);
				host[len] = 0;
				tp++;
				if (*tp == 0)
					strcpy(port, "0");
				else
					strcpy(port, tp);
			}
		}
	}

	/*printf("host:%s, port:%s\n", host, port); */

	/* Obtain address(es) matching host/port */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family		= AF_UNSPEC;	/* Allow IPv4 or IPv6 */
	hints.ai_socktype	= SOCK_STREAM;	/* STREAM socket */

	s = getaddrinfo(host, port, &hints, &result);
	if (s != 0) {
		ERROR_LOG("getaddrinfo failed. %s\n", gai_strerror(s));
		return -1;
	}
	if (result == NULL) {
		ERROR_LOG("unresolved address\n");
		return -1;
	}
	if (result->ai_next) {
		ERROR_LOG("more then one address is matched\n");
		goto cleanup;
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
	default:
		ERROR_LOG("unknown family :%d\n", result->ai_family);
		break;
	}
cleanup:
	freeaddrinfo(result);

	return ss_len;
}
EXPORT_SYMBOL(xio_host_port_to_ss);

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
	socklen_t	ss_len = -1;

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
			if (*p2 != '/')
				return -1;
			p1 = p2;
			while (*p1 != ':') {
				p1--;
				if (p1 == uri)
					return  -1;
			}

			len = p2 - (p1 + 1);

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

	return ss_len;
}
EXPORT_SYMBOL(xio_uri_to_ss);


/*---------------------------------------------------------------------------*/
/* xio_msg_dump								     */
/*---------------------------------------------------------------------------*/
void xio_msg_dump(struct xio_msg *xio_msg)
{
	struct  xio_sg_table_ops *sgtbl_ops;
	struct  xio_mr		 *mr;
	void			 *sgtbl;
	void			 *sge;
	unsigned int		 i;

	ERROR_LOG("********************************************************\n");
	ERROR_LOG("type:0x%x\n", xio_msg->type);
	if (xio_msg->type == XIO_MSG_TYPE_REQ ||
	    xio_msg->type == XIO_ONE_WAY_REQ)
		ERROR_LOG("serial number:%lld\n", xio_msg->sn);
	else if (xio_msg->type == XIO_MSG_TYPE_RSP)
		ERROR_LOG("response:%p, serial number:%lld\n",
			  xio_msg->request,
			  ((xio_msg->request) ? xio_msg->request->sn : (uint64_t)-1));

	sgtbl		= xio_sg_table_get(&xio_msg->in);
	sgtbl_ops	= (struct xio_sg_table_ops *)
				xio_sg_table_ops_get(xio_msg->in.sgl_type);

	ERROR_LOG("in header: length:%zd, address:%p\n",
		  xio_msg->in.header.iov_len, xio_msg->in.header.iov_base);
	ERROR_LOG("in sgl type:%d max_nents:%d\n", xio_msg->in.sgl_type,
		  tbl_max_nents(sgtbl_ops, sgtbl));
	ERROR_LOG("in data size:%zd\n",
		  tbl_nents(sgtbl_ops, sgtbl));

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		mr = (struct xio_mr *)sge_mr(sgtbl_ops, sge);
		if (mr)
			ERROR_LOG("in data[%d]: length:%zd, " \
				  "address:%p, mr:%p " \
				  "- [addr:%p, len:%d]\n", i,
				  sge_length(sgtbl_ops, sge),
				  sge_addr(sgtbl_ops, sge),
				  mr, mr->addr, mr->length);
		else
			ERROR_LOG("in data[%d]: length:%zd, " \
				  "address:%p, mr:%p\n", i,
				  sge_length(sgtbl_ops, sge),
				  sge_addr(sgtbl_ops, sge), mr);
	}

	sgtbl		= xio_sg_table_get(&xio_msg->out);
	sgtbl_ops	= (struct xio_sg_table_ops *)
				xio_sg_table_ops_get(xio_msg->out.sgl_type);

	ERROR_LOG("out header: length:%zd, address:%p\n",
		  xio_msg->out.header.iov_len, xio_msg->out.header.iov_base);
	ERROR_LOG("out sgl type:%d max_nents:%d\n", xio_msg->out.sgl_type,
		  tbl_max_nents(sgtbl_ops, sgtbl));
	ERROR_LOG("out data size:%zd\n", tbl_nents(sgtbl_ops, sgtbl));

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		mr = (struct xio_mr *)sge_mr(sgtbl_ops, sge);
		if (mr)
			ERROR_LOG("out data[%d]: length:%zd, " \
				  "address:%p, mr:%p " \
				  "- [addr:%p, len:%d]\n", i,
				  sge_length(sgtbl_ops, sge),
				  sge_addr(sgtbl_ops, sge),
				  mr, mr->addr, mr->length);
		else
			ERROR_LOG("out data[%d]: length:%zd, " \
				  "address:%p, mr:%p\n",
				  i,
				  sge_length(sgtbl_ops, sge),
				  sge_addr(sgtbl_ops, sge), mr);
	}
	ERROR_LOG("*******************************************************\n");
}
EXPORT_SYMBOL(xio_msg_dump);


