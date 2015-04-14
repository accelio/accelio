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
#include <linux/net.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/types.h>

#include "xio_test_utils.h"

#ifndef NIPQUAD
#define NIPQUAD(addr) \
		((unsigned char *)&(addr))[0], \
		((unsigned char *)&(addr))[1], \
		((unsigned char *)&(addr))[2], \
		((unsigned char *)&(addr))[3]
#endif

#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#ifndef NIP6
#define NIP6(addr) \
	     ntohs((addr).s6_addr16[0]), \
	     ntohs((addr).s6_addr16[1]), \
	     ntohs((addr).s6_addr16[2]), \
	     ntohs((addr).s6_addr16[3]), \
	     ntohs((addr).s6_addr16[4]), \
	     ntohs((addr).s6_addr16[5]), \
	     ntohs((addr).s6_addr16[6]), \
	     ntohs((addr).s6_addr16[7])
#endif

/*---------------------------------------------------------------------------*/
/* get_time								     */
/*---------------------------------------------------------------------------*/
void get_time(char *time, int len)
{
	struct timeval tv;
	struct tm      t;
	int	       n;

	do_gettimeofday(&tv);
	time_to_tm(tv.tv_sec, 0, &t);
	/* Format the date and time,
	   down to a single second. */
	n = snprintf(time, len,
		     "%04ld/%02d/%02d-%02d:%02d:%02d.%05ld",
		     t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
		     t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec);
	time[n] = 0;
}

/*---------------------------------------------------------------------------*/
/* get_ip								     */
/*---------------------------------------------------------------------------*/
inline char *get_ip(const struct sockaddr *ip, char *buf)
{
	if (ip->sa_family == AF_INET) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;

		sprintf(buf, "%d.%d.%d.%d", NIPQUAD(v4->sin_addr));
		buf[INET_ADDRSTRLEN] = '\0';
	}
	if (ip->sa_family == AF_INET6) {
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ip;

		sprintf(buf, "%d.%d.%d.%d.%d.%d.%d.%d", NIP6(v6->sin6_addr));
		buf[INET6_ADDRSTRLEN] = '\0';
	}
	return buf;
}

/*---------------------------------------------------------------------------*/
/* get_port								     */
/*---------------------------------------------------------------------------*/
inline uint16_t get_port(const struct sockaddr *ip)
{
	if (ip->sa_family == AF_INET) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)ip;

		return ntohs(v4->sin_port);
	}
	if (ip->sa_family == AF_INET6) {
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ip;

		return ntohs(v6->sin6_port);
	}
	return 0;
}
