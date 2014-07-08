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

/*
 * xio_get_nodeid(cpuid) - This will return the node to which selected cpu
 * belongs
 */
unsigned int xio_get_nodeid(unsigned int cpu_id)
{
	DIR *directory_parent, *directory_node;
	struct dirent *de, *dn;
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
			sprintf(directory_path, "/sys/devices/system/node/%s",
				de->d_name);
			directory_node = opendir(directory_path);
			while ((dn = readdir(directory_node)) != NULL) {
				if (strncmp(dn->d_name, "cpu", 3))
					continue;
				cpu = strtoul(dn->d_name+3, NULL, 0);
				if (cpu == cpu_id) {
					node_id = strtoul(de->d_name + 4,
							  NULL, 0);
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

void xio_msg_dump(struct xio_msg *xio_msg)
{
	int i;

	ERROR_LOG("*********************************************\n");
	ERROR_LOG("type:0x%x\n", xio_msg->type);
	ERROR_LOG("status:%d\n", xio_msg->status);
	if (xio_msg->type == XIO_MSG_TYPE_REQ)
		ERROR_LOG("serial number:%lld\n", xio_msg->sn);
	else if (xio_msg->type == XIO_MSG_TYPE_RSP)
		ERROR_LOG("response:%p, serial number:%lld\n",
			  xio_msg->request,
			  ((xio_msg->request) ? xio_msg->request->sn : -1));

	ERROR_LOG("in header: length:%zd, address:%p\n",
		   xio_msg->in.header.iov_len, xio_msg->in.header.iov_base);
	ERROR_LOG("in data type:%d iovsz:%zd\n",xio_msg->in.data_type,
		  xio_msg->in.data_iovsz);
	ERROR_LOG("in data size:%zd\n", xio_msg->in.data_iovlen);
	for (i = 0; i < xio_msg->in.data_iovlen; i++)
		ERROR_LOG("in data[%d]: length:%zd, address:%p, mr:%p\n", i,
			  xio_msg->in.pdata_iov[i].iov_len,
			  xio_msg->in.pdata_iov[i].iov_base,
			  xio_msg->in.pdata_iov[i].mr);

	ERROR_LOG("out header: length:%zd, address:%p\n",
		  xio_msg->out.header.iov_len, xio_msg->out.header.iov_base);
	ERROR_LOG("out data type:%d iovsz:%zd\n",xio_msg->out.data_type,
		  xio_msg->out.data_iovsz);
	ERROR_LOG("out data size:%zd\n", xio_msg->out.data_iovlen);
	for (i = 0; i < xio_msg->out.data_iovlen; i++)
		ERROR_LOG("out data[%d]: length:%zd, address:%p, mr:%p\n", i,
			  xio_msg->out.pdata_iov[i].iov_len,
			  xio_msg->out.pdata_iov[i].iov_base,
			  xio_msg->out.pdata_iov[i].mr);
	ERROR_LOG("*********************************************\n");
}

/*
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
