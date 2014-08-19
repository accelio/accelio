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
#ifndef XIO_PERFTEST_COMMUNICATION_H
#define XIO_PERFTEST_COMMUNICATION_H

struct perf_comm {
	struct control_context     *control_ctx;
	struct perf_parameters	   *user_param;
};



struct perf_comm *create_comm_struct(struct perf_parameters *user_param);

void destroy_comm_struct(struct perf_comm *comm);

int establish_connection(struct perf_comm *comm);

int ctx_read_data(struct perf_comm *comm, void *data, int size, int *out_size);

int ctx_write_data(struct perf_comm *comm, void *data, int size);

int ctx_xchg_data(struct perf_comm *comm, void *my_data,
		  void *rem_data, int size);

int ctx_hand_shake(struct perf_comm *comm);

int ctx_close_connection(struct perf_comm *comm);

/************* interface helpers ********************/

#define cpusmask_test_bit(nr, addr)	(*(addr) & (1ULL << (nr)))
#define cpusmask_set_bit(nr, addr)	(*(addr) |=  (1ULL << (nr)))

int intf_name(const char *addr, char *if_name);

int intf_numa_node(const char *iface);

int intf_master_name(const char *iface, char *master);

int intf_best_cpus(const char *addr, uint64_t *cpusmask, int *nr);

int intf_name_best_cpus(const char *if_name, uint64_t *cpusmask, int *nr);

char *intf_cpusmask_str(uint64_t cpusmask, int nr, char *str);

#endif /* XIO_PERFTEST_COMMUNICATION_H */

