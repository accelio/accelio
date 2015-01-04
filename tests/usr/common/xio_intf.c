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
#include <unistd.h>
#include <stdio.h>
#include <numa.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "xio_intf.h"

/*---------------------------------------------------------------------------*/
/* intf_name								     */
/*---------------------------------------------------------------------------*/
int intf_name(const char *addr, char *if_name)
{
	struct ifaddrs		*ifaddr, *ifa;
	struct sockaddr_in	iaddr;
	struct sockaddr_in	*saddr;
	int			retval = -1;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		goto cleanup;
	}
	if (inet_pton(AF_INET, addr, &iaddr.sin_addr) == -1) {
		perror("inet_pton");
		goto cleanup1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (!(ifa->ifa_addr && (ifa->ifa_flags & IFF_UP) &&
		      ifa->ifa_addr->sa_family == AF_INET))
			continue;

		saddr = (struct sockaddr_in *)ifa->ifa_addr;
		if (saddr->sin_addr.s_addr == iaddr.sin_addr.s_addr) {
			strcpy(if_name, ifa->ifa_name);
			retval = 0;
			break;
		}
	}

cleanup1:
	freeifaddrs(ifaddr);
cleanup:
	return retval;
}

/*---------------------------------------------------------------------------*/
/* intf_numa_node							     */
/*---------------------------------------------------------------------------*/
int intf_numa_node(const char *iface)
{
	int	fd, numa_node = -1, len;
	char	buf[256];

	snprintf(buf, 256, "/sys/class/net/%s/device/numa_node", iface);
	fd = open(buf, O_RDONLY);
	if (fd == -1)
		return -1;

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		goto cleanup;

	numa_node = strtol(buf, NULL, 0);

cleanup:
	close(fd);

	return numa_node;
}

/*---------------------------------------------------------------------------*/
/* intf_master_name							     */
/*---------------------------------------------------------------------------*/
int intf_master_name(const char *iface, char *master)
{
	int	fd, len;
	char	path[256];
	char	buf[256];
	char    *ptr;

	snprintf(path, 256, "/sys/class/net/%s/master", iface);
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;

	len = read(fd, buf, sizeof(buf)-1);
	if (len < 0) {
		len = readlink(path, buf, sizeof(buf) - 1);
		if (len < 0)
			goto cleanup;
	}
	buf[len] = '\0';
	ptr = strrchr(buf, '/');
	if (ptr) {
		ptr++;
		strcpy(buf, ptr);
	}
	strcpy(master, buf);
cleanup:
	close(fd);

	return (len > 0) ? 0 : -1;
}

/*---------------------------------------------------------------------------*/
/* numa_node_to_cpusmask						     */
/*---------------------------------------------------------------------------*/
static int numa_node_to_cpusmask(int node, uint64_t *cpusmask, int *nr)
{
	struct bitmask *mask;
	uint64_t	bmask = 0;
	int		retval = -1;
	size_t		i;

	mask = numa_allocate_cpumask();
	retval = numa_node_to_cpus(node, mask);
	if (retval < 0)
		goto cleanup;

	*nr = 0;
	for (i = 0; i < mask->size && i < 64; i++) {
		if (numa_bitmask_isbitset(mask, i)) {
			cpusmask_set_bit(i, &bmask);
			(*nr)++;
		}
	}

	retval = 0;
cleanup:
	*cpusmask = bmask;

	numa_free_cpumask(mask);
	return retval;
}

/*---------------------------------------------------------------------------*/
/* intf_best_cpus							     */
/*---------------------------------------------------------------------------*/
int intf_best_cpus(const char *addr, uint64_t *cpusmask, int *nr)
{
	char		if_name[32];
	int		numa_node, retval;

	*cpusmask = 0;
	retval = intf_name(addr, if_name);
	if (retval < 0)
		return  -1;

	numa_node = intf_numa_node(if_name);
	if (numa_node < 0)
		return -1;

	retval = numa_node_to_cpusmask(numa_node, cpusmask, nr);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* intf_name_best_cpus							     */
/*---------------------------------------------------------------------------*/
int intf_name_best_cpus(const char *if_name, uint64_t *cpusmask, int *nr)
{
	int		numa_node, retval;

	*cpusmask = 0;
	numa_node = intf_numa_node(if_name);
	if (numa_node < 0)
		return -1;

	retval = numa_node_to_cpusmask(numa_node, cpusmask, nr);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* intf_name_best_cpus							     */
/*---------------------------------------------------------------------------*/
char *intf_cpusmask_str(uint64_t cpusmask, int nr, char *str)
{
	int len = 0, i, cpus;

	for (i = 0, cpus = 0; i < 64 && cpus < nr; i++) {
		if (cpusmask_test_bit(i, &cpusmask)) {
			len += sprintf(&str[len], "%d ", i);
			cpus++;
		}
	}
	return str;
}

