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

struct xio_tcp_transport;
struct xio_tcp_socket;

/*---------------------------------------------------------------------------*/
/* externals								     */
/*---------------------------------------------------------------------------*/
extern double				g_mhz;

/* definitions */
#define NUM_TASKS			54400 /* 100 * (MAX_SEND_WR +
					      * MAX_RECV_WR + EXTRA_RQE)
					      */

#define RX_LIST_POST_NR			31   /* Initial number of buffers
					      * to put in the rx_list
					      */

#define COMPLETION_BATCH_MAX		64   /* Trigger TX completion every
					      * COMPLETION_BATCH_MAX
					      * packets
					      */

#define TX_BATCH			32   /* Number of TX tasks to batch */

#define TX_EAGAIN_RETRY			2    /* Number of retries when send
					      * fail with EAGAIN before return.
					      */

#define RX_POLL_NR_MAX			4    /* Max num of RX messages
					      * to receive in one poll
					      */

#define RX_BATCH			32   /* Number of RX tasks to batch */

#define TCP_DEFAULT_BACKLOG		1024 /* listen socket default backlog */

#define TMP_RX_BUF_SIZE			(RX_BATCH * MAX_HDR_SZ)

#define XIO_TO_TCP_TASK(xt, tt)			\
		struct xio_tcp_task *(tt) =		\
			(struct xio_tcp_task *)(xt)->dd_data
#define XIO_TO_TCP_HNDL(xt, th)				\
		struct xio_tcp_transport *(th) =		\
			(struct xio_tcp_transport *)(xt)->context

#define PAGE_SIZE                       page_size

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

enum xio_tcp_tx_stage {
	XIO_TCP_TX_BEFORE,
	XIO_TCP_TX_IN_SEND_CTL,
	XIO_TCP_TX_IN_SEND_DATA,
	XIO_TCP_TX_DONE
};

enum xio_tcp_sock_type {
	XIO_TCP_SINGLE_SOCK = 1,
	XIO_TCP_CTL_SOCK,
	XIO_TCP_DATA_SOCK
};

/*---------------------------------------------------------------------------*/
struct xio_tcp_options {
	int			enable_mem_pool;
	int			enable_dma_latency;
	int			enable_mr_check;
	int			max_in_iovsz;
	int			max_out_iovsz;
	int			tcp_no_delay;
	int			tcp_so_sndbuf;
	int			tcp_so_rcvbuf;
	int			tcp_dual_sock;
	int			pad;
};

#define XIO_TCP_REQ_HEADER_VERSION	1

PACKED_MEMORY(struct xio_tcp_req_hdr {
	uint8_t			version;	/* request version	*/
	uint8_t			flags;
	uint16_t		req_hdr_len;	/* req header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		pad0;

	uint32_t		ltid;		/* originator identifier*/
	uint16_t		pad;
	uint8_t			in_tcp_op;	/* opcode  for peers	*/
	uint8_t			out_tcp_op;

	uint16_t		in_num_sge;
	uint16_t		out_num_sge;
	uint32_t		pad1;

	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/
	uint32_t		remain_data_len;/* remaining data length */

	uint64_t		ulp_imm_len;	/* ulp data length	*/
});

#define XIO_TCP_RSP_HEADER_VERSION	1

PACKED_MEMORY(struct xio_tcp_rsp_hdr {
	uint8_t			version;	/* response version     */
	uint8_t			flags;
	uint16_t		rsp_hdr_len;	/* rsp header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		pad;

	uint32_t		ltid;		/* local task id	*/
	uint32_t                rtid;           /* remote task id       */

	uint8_t			out_tcp_op;	/* opcode  for peers	*/
	uint8_t			pad1;
	uint16_t		out_num_sge;
	uint32_t		status;		/* status		*/

	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/
	uint32_t		remain_data_len;/* remaining data length */

	uint64_t		ulp_imm_len;	/* ulp data length	*/
});

PACKED_MEMORY(struct xio_tcp_connect_msg {
	enum xio_tcp_sock_type	sock_type;
	uint16_t		second_port;
	uint16_t		pad;
});

PACKED_MEMORY(struct xio_tcp_setup_msg {
	uint64_t		buffer_sz;
	uint32_t		max_in_iovsz;
	uint32_t		max_out_iovsz;
	uint32_t                max_header_len;
	uint32_t		pad;
});

PACKED_MEMORY(struct xio_tcp_cancel_hdr {
	uint16_t		hdr_len;	 /* req header length	*/
	uint16_t		sn;		 /* msg serial number	*/
	uint32_t		result;
});

struct xio_tcp_work_req {
	struct iovec			*msg_iov;
	uint32_t			msg_len;
	uint32_t			pad;
	uint64_t			tot_iov_byte_len;
	void				*ctl_msg;
	uint32_t			ctl_msg_len;
	int				stage;
	struct msghdr			msg;
};

struct xio_tcp_task {
	enum xio_tcp_op_code		in_tcp_op;
	enum xio_tcp_op_code		out_tcp_op;

	struct xio_tcp_work_req		txd;
	struct xio_tcp_work_req		rxd;


	/* User (from vmsg) or pool buffer used for */
	uint16_t			read_num_reg_mem;
	uint16_t			write_num_reg_mem;
	uint32_t			pad0;

	struct xio_reg_mem		*read_reg_mem;
	struct xio_reg_mem		*write_reg_mem;

	uint16_t			req_in_num_sge;
	uint16_t			req_out_num_sge;
	uint16_t			rsp_out_num_sge;
	uint16_t			sn;

	/* What this side got from the peer for SEND */
	/* What this side got from the peer for RDMA equivalent R/W
	 */
	/* can serve send/rdma write  */
	struct xio_sge			*req_in_sge;

	/* can serve send/rdma read  */
	struct xio_sge			*req_out_sge;

	/* can serve send/rdma read response/rdma write  */
	struct xio_sge			*rsp_out_sge;

	xio_work_handle_t		comp_work;
};

struct xio_tcp_tasks_slab {
	void				*data_pool;
	struct xio_reg_mem		reg_mem;
	int				buf_size;
	int				pad;
};

struct xio_tcp_pending_conn {
	int				fd;
	int				waiting_for_bytes;
	struct xio_tcp_connect_msg	msg;
	union xio_sockaddr		sa;
	struct list_head		conns_list_entry;
};

struct xio_tcp_socket_ops {
	int (*open)(struct xio_tcp_socket *sock);
	int (*add_ev_handlers)(struct xio_tcp_transport *tcp_hndl);
	int (*del_ev_handlers)(struct xio_tcp_transport *tcp_hndl);
	int (*connect)(struct xio_tcp_transport *tcp_hndl,
		       struct sockaddr *sa, socklen_t sa_len);
	size_t (*set_txd)(struct xio_task *task);
	void (*set_rxd)(struct xio_task *task, void *buf, uint32_t len);
	int (*rx_ctl_work)(struct xio_tcp_transport *tcp_hndl, int fd,
			   struct xio_tcp_work_req *xio_recv,
			   int block);
	int (*rx_ctl_handler)(struct xio_tcp_transport *tcp_hndl);
	int (*rx_data_handler)(struct xio_tcp_transport *tcp_hndl,
			       int batch_nr);
	int (*shutdown)(struct xio_tcp_socket *sock);
	int (*close)(struct xio_tcp_socket *sock);
};

struct xio_tcp_socket {
	int				cfd;
	int				dfd;
	uint16_t			port_cfd;
	uint16_t			port_dfd;
	int				pad;
	struct xio_tcp_socket_ops	ops[1];
};

struct xio_tcp_transport {
	struct xio_transport_base	base;
	struct xio_mempool		*tcp_mempool;
	struct list_head		trans_list_entry;

	/*  tasks queues */
	struct list_head		tx_ready_list;
	struct list_head		tx_comp_list;
	struct list_head		in_flight_list;
	struct list_head		rx_list;
	struct list_head		io_list;

	struct xio_tcp_socket		sock;
	uint16_t			is_listen;
	uint8_t			        in_epoll[2];

	/* fast path params */
	enum xio_transport_state	state;

	/* tx parameters */
	size_t				max_inline_buf_sz;

	int				tx_ready_tasks_num;

	uint16_t			tx_comp_cnt;

	uint16_t			sn;	   /* serial number */

	/* control path params */

	uint32_t			peer_max_in_iovsz;
	uint32_t			peer_max_out_iovsz;

	/* connection's flow control */
	size_t				membuf_sz;

	struct xio_transport		*transport;
	struct xio_tasks_pool_cls	initial_pool_cls;
	struct xio_tasks_pool_cls	primary_pool_cls;

	struct xio_tcp_setup_msg	setup_rsp;

	/* too big to be on stack - use as temporaries */
	union {
		struct xio_msg		dummy_msg;
	};

	struct list_head		pending_conns;

	void				*tmp_rx_buf;
	void				*tmp_rx_buf_cur;
	uint32_t			tmp_rx_buf_len;
	uint32_t			peer_max_header;

	uint32_t			trans_attr_mask;
	struct xio_transport_attr	trans_attr;

	struct xio_tcp_work_req		tmp_work;
	struct iovec			tmp_iovec[IOV_MAX];

	struct xio_ev_data              flush_tx_event;
	struct xio_ev_data		ctl_rx_event;
	struct xio_ev_data		disconnect_event;
};

int xio_tcp_get_max_header_size(void);

int xio_tcp_get_inline_buffer_size(void);

int xio_tcp_send(struct xio_transport_base *transport,
		 struct xio_task *task);

int xio_tcp_rx_handler(struct xio_tcp_transport *tcp_hndl);

int xio_tcp_poll(struct xio_transport_base *transport,
		 long min_nr, long max_nr,
		 struct timespec *ts_timeout);

struct xio_task *xio_tcp_primary_task_lookup(
					struct xio_tcp_transport *tcp_hndl,
					int tid);

struct xio_task *xio_tcp_primary_task_alloc(
					struct xio_tcp_transport *tcp_hndl);

void on_sock_disconnected(struct xio_tcp_transport *tcp_hndl,
			  int notify_observer);

int xio_tcp_cancel_req(struct xio_transport_base *transport,
		       struct xio_msg *req, uint64_t stag,
		       void *ulp_msg, size_t ulp_msg_sz);

int xio_tcp_cancel_rsp(struct xio_transport_base *transport,
		       struct xio_task *task, enum xio_status result,
		       void *ulp_msg, size_t ulp_msg_sz);

int xio_tcp_send_connect_msg(int fd, struct xio_tcp_connect_msg *msg);

size_t xio_tcp_single_sock_set_txd(struct xio_task *task);
size_t xio_tcp_dual_sock_set_txd(struct xio_task *task);
void xio_tcp_single_sock_set_rxd(struct xio_task *task, void *buf,
				 uint32_t len);
void xio_tcp_dual_sock_set_rxd(struct xio_task *task, void *buf, uint32_t len);

int xio_tcp_rx_ctl_handler(struct xio_tcp_transport *tcp_hndl, int batch_nr);
int xio_tcp_rx_data_handler(struct xio_tcp_transport *tcp_hndl, int batch_nr);
int xio_tcp_recv_ctl_work(struct xio_tcp_transport *tcp_hndl, int fd,
			  struct xio_tcp_work_req *xio_recv, int block);
int xio_tcp_recvmsg_work(struct xio_tcp_transport *tcp_hndl, int fd,
			 struct xio_tcp_work_req *xio_recv, int block);

void xio_tcp_disconnect_helper(void *xio_tcp_hndl);

int xio_tcp_xmit(struct xio_tcp_transport *tcp_hndl);

#endif /* XIO_TCP_TRANSPORT_H_ */
