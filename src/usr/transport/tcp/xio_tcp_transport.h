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
#ifndef XIO_TCP_TRANSPORT_H_
#define XIO_TCP_TRANSPORT_H_

#include "xio_usr_transport.h"

/*---------------------------------------------------------------------------*/
/* externals								     */
/*---------------------------------------------------------------------------*/
extern double				g_mhz;


/* definitions */
#define NUM_TASKS			3264 /* 6 * (MAX_SEND_WR +
					      * MAX_RECV_WR + EXTRA_RQE)
					      */

#define RX_LIST_POST_NR			31   /* Initial number of buffers
					      * to put in the rx_list
					      */

#define COMPLETION_BATCH_MAX		64   /* Trigger TX completion every
					      * COMPLETION_BATCH_MAX
					      * packets
					      */

#define RX_POLL_NR_MAX			16   /* Max num of RX messages
					      * to receive in one poll
					      */

#define XIO_TO_TCP_TASK(xt, tt)			\
		struct xio_tcp_task *(tt) =		\
			(struct xio_tcp_task *)(xt)->dd_data


/*---------------------------------------------------------------------------*/
/* enums								     */
/*---------------------------------------------------------------------------*/
enum xio_tcp_op_code {
	XIO_TCP_NULL,
	XIO_TCP_RECV		= 1,
	XIO_TCP_SEND,
	XIO_TCP_WRITE,
	XIO_TCP_READ
};

enum xio_tcp_rx_stage {
	XIO_TCP_RX_START,
	XIO_TCP_RX_TLV,
	XIO_TCP_RX_HEADER,
	XIO_TCP_RX_IO_DATA,
	XIO_TCP_RX_DONE
};

/*---------------------------------------------------------------------------*/
struct xio_tcp_options {
	int			enable_mem_pool;
	int			enable_dma_latency;
	int			enable_mr_check;
	int			tcp_buf_threshold;
	int			tcp_buf_attr_rdonly;
	int			max_in_iovsz;
	int			max_out_iovsz;
	int			tcp_no_delay;
	int			tcp_so_sndbuf;
	int			tcp_so_rcvbuf;
};


#define XIO_TCP_REQ_HEADER_VERSION	1

struct __attribute__((__packed__)) xio_tcp_req_hdr {
	uint8_t			version;	/* request version	*/
	uint8_t			flags;
	uint16_t		req_hdr_len;	/* req header length	*/
	uint16_t		tid;		/* originator identifier*/
	uint8_t			opcode;		/* opcode  for peers	*/
	uint8_t			pad[1];

	uint16_t		recv_num_sge;
	uint16_t		read_num_sge;
	uint16_t		write_num_sge;
	uint16_t		pad1;

	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/
	uint32_t		remain_data_len;/* remaining data length */
	uint64_t		ulp_imm_len;	/* ulp data length	*/
};

#define XIO_TCP_RSP_HEADER_VERSION	1

struct __attribute__((__packed__)) xio_tcp_rsp_hdr {
	uint8_t			version;	/* response version     */
	uint8_t			flags;
	uint16_t		rsp_hdr_len;	/* rsp header length	*/
	uint16_t		tid;		/* originator identifier*/
	uint8_t			opcode;		/* opcode  for peers	*/
	uint8_t			pad[3];

	uint16_t		write_num_sge;

	uint32_t		status;		/* status		*/
	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/

	uint32_t		remain_data_len;/* remaining data length */
	uint64_t		ulp_imm_len;	/* ulp data length	*/
};

struct __attribute__((__packed__)) xio_tcp_setup_msg {
	uint64_t		buffer_sz;
	uint32_t		max_in_iovsz;
	uint32_t		max_out_iovsz;
};

struct xio_tcp_work_req {
	struct iovec			*msg_iov;
	uint32_t			msg_len;
	uint32_t			tot_iov_byte_len;
	enum xio_tcp_rx_stage		stage;
	uint32_t			pad;
	struct msghdr			msg;
};

struct xio_tcp_task {
	struct xio_tcp_transport	*tcp_hndl;

	enum xio_tcp_op_code		tcp_op;

	uint32_t			recv_num_sge;
	uint32_t			read_num_sge;
	uint32_t			write_num_sge;

	uint32_t			req_write_num_sge;
	uint32_t			rsp_write_num_sge;
	uint32_t			req_read_num_sge;
	uint32_t			req_recv_num_sge;

	uint16_t			more_in_batch;

	uint16_t			pad[3];

	struct xio_tcp_work_req		txd;
	struct xio_tcp_work_req		rxd;

	/* User (from vmsg) or pool buffer used for */
	struct xio_mempool_obj		*read_sge;
	struct xio_mempool_obj		*write_sge;

	/* What this side got from the peer for SEND */
	/* What this side got from the peer for RDMA equivalent R/W
	 */
	struct xio_sge			*req_read_sge;
	struct xio_sge			*req_write_sge;

	/* What this side got from the peer for SEND
	 */
	struct xio_sge			*req_recv_sge;

	/* What this side writes to the peer on RDMA equivalent W
	 */
	struct xio_sge			*rsp_write_sge;


	xio_work_handle_t		comp_work;
};

struct xio_tcp_tasks_slab {
	void				*data_pool;
	struct xio_buf			*io_buf;
	int				buf_size;
	int				pad;
};

struct xio_tcp_transport {
	struct xio_transport_base	base;
	struct xio_mempool		*tcp_mempool;
	struct list_head		trans_list_entry;

	union xio_sockaddr		sa;

	/*  tasks queues */
	struct list_head		tx_ready_list;
	struct list_head		tx_comp_list;
	struct list_head		in_flight_list;
	struct list_head		rx_list;
	struct list_head		io_list;

	int				sock_fd;

	/* fast path params */
	enum xio_transport_state	state;

	/* tx parameters */
	size_t				max_send_buf_sz;

	int				tx_ready_tasks_num;

	uint16_t			tx_comp_cnt;
	uint16_t			pad2[3];

	/* control path params */
	int				num_tasks;

	uint32_t			peer_max_in_iovsz;
	uint32_t			peer_max_out_iovsz;

	/* connection's flow control */
	size_t				alloc_sz;
	size_t				membuf_sz;

	struct xio_transport		*transport;
	struct xio_tasks_pool_cls	initial_pool_cls;
	struct xio_tasks_pool_cls	primary_pool_cls;

	struct xio_tcp_setup_msg	setup_rsp;
};

int xio_tcp_send(struct xio_transport_base *transport,
		 struct xio_task *task);

int xio_tcp_rx_handler(struct xio_tcp_transport *tcp_hndl);

int xio_tcp_poll(struct xio_transport_base *transport,
		 long min_nr, long max_nr,
		 struct timespec *ts_timeout);

void xio_tcp_calc_pool_size(struct xio_tcp_transport *tcp_hndl);

struct xio_task *xio_tcp_primary_task_lookup(
					struct xio_tcp_transport *tcp_hndl,
					int tid);

struct xio_task *xio_tcp_primary_task_alloc(
					struct xio_tcp_transport *tcp_hndl);

void on_sock_disconnected(struct xio_tcp_transport *tcp_hndl,
			  int notify_observer);

#endif /* XIO_TCP_TRANSPORT_H_ */
