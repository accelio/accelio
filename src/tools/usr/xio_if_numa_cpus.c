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
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdio.h>
#include <numa.h>

#define cpusmask_test_bit(nr, addr)	(*(addr) & (1ULL << (nr)))
#define cpusmask_set_bit(nr, addr)	(*(addr) |=  (1ULL << (nr)))

/*---------------------------------------------------------------------------*/
/* intf_master_name							     */
/*---------------------------------------------------------------------------*/
static int intf_master_name(const char *iface, char *master)
{
	int	fd, len;
	char	path[256];
	char	buf[256];
	char    *ptr;

	snprintf(path, 256, "/sys/class/net/%s/master", iface);
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;

	len = read(fd, buf, sizeof(buf) - 1);
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
/* intf_numa_node							     */
/*---------------------------------------------------------------------------*/
static int intf_numa_node(const char *iface)
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
/* numa_node_to_cpusmask						     */
/*---------------------------------------------------------------------------*/
static int numa_node_to_cpusmask(int node, uint64_t *cpusmask, int *nr)
{
	struct bitmask *mask;
	uint64_t	bmask = 0;
	int		retval = -1;
	unsigned int	i;

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
/* intf_name_best_cpus							     */
/*---------------------------------------------------------------------------*/
static int intf_name_best_cpus(const char *if_name, uint64_t *cpusmask, int *nr)
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
static char *intf_cpusmask_str(uint64_t cpusmask, int nr, char *str)
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

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct ifaddrs		*ifaddr, *ifa;
	char			host[NI_MAXHOST] = {0};
	char			cpus_str[256];
	char			flags[1024];
	uint64_t		cpusmask = 0;
	int			cpusnum;
	int			retval = -1;
	int			ec = EXIT_FAILURE;
	int			numa_node;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		goto cleanup;
	}
	printf("%-10s %-16s %-30s %-5s %-10s %-40s\n",
	       "interface", "host", "flags", "numa", "cpus mask", "cpus");
	printf("---------------------------------------------------");
	printf("-------------------------------------------------------\n");

	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			if (!(ifa->ifa_flags & IFF_UP))
				continue;
			getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
				    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		break;
		case AF_PACKET:
			if (ifa->ifa_flags & IFF_MASTER)
				continue;
			if (ifa->ifa_flags & IFF_SLAVE)
				break;
			if (!(ifa->ifa_flags & IFF_UP))
				break;
			continue;
			break;
		default:
			continue;
			break;
		}
		flags[0] = 0;
		if (ifa->ifa_flags & IFF_UP)
			sprintf(flags, "%s %s", flags, "UP");
		else
			sprintf(flags, "%s %s", flags, "DOWN");
		if (ifa->ifa_flags & IFF_LOOPBACK)
			sprintf(flags, "%s %s", flags, "LOOPBACK");
		if (ifa->ifa_flags & IFF_RUNNING)
			sprintf(flags, "%s %s", flags, "RUNNING");
		if (ifa->ifa_flags & IFF_SLAVE) {
			char master[256];

			intf_master_name(ifa->ifa_name, master);
			sprintf(flags, "%s %s - [%s]", flags, "SLAVE", master);
		}
		if (ifa->ifa_flags & IFF_MASTER)
			sprintf(flags, "%s %s", flags, "MASTER");

		numa_node = intf_numa_node(ifa->ifa_name);
		retval = intf_name_best_cpus(ifa->ifa_name,
					     &cpusmask, &cpusnum);
		if (retval != 0) {
			/*perror("intf_name_best_cpus"); */
			printf("%-10s %-16s %-30s %-5c 0x%-8lx %-4s[0]\n",
			       ifa->ifa_name, host, flags, 0x20, 0UL, "cpus");
			continue;
		}
		intf_cpusmask_str(cpusmask, cpusnum, cpus_str);

		printf("%-10s %-16s %-30s %-5d 0x%-8lx %-4s[%d] - %s\n",
		       ifa->ifa_name, host, flags, numa_node, cpusmask,
		       "cpus",  cpusnum, cpus_str);
	}
	ec = EXIT_SUCCESS;

	freeifaddrs(ifaddr);

cleanup:
	exit(ec);
}

