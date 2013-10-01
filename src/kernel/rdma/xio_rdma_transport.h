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
#ifndef  XIO_RDMA_TRANSPORT_H
#define  XIO_RDMA_TRANSPORT_H


/* poll_cq defentions */
#define MAX_RDMA_ADAPTERS		64   /* 64 adapters per unit */
#define MAX_POLL_WC			128

#define ADDR_RESOLVE_TIMEOUT		1000
#define ROUTE_RESOLVE_TIMEOUT		1000

#define MAX_INLINE_DATA			256
#define MAX_SGE				(XIO_MAX_IOV + 1)

#define MAX_SEND_WR			256
#define MAX_RECV_WR			256
#define EXTRA_RQE			32

#define MAX_CQE_PER_QP			(MAX_SEND_WR+MAX_RECV_WR)
#define CQE_ALLOC_SIZE			(10*(MAX_SEND_WR+MAX_RECV_WR))

#define DEF_DATA_ALIGNMENT		0
#define SEND_BUF_SZ			8192
#define OMX_MAX_HDR_SZ			512


#define NUM_CONN_SETUP_TASKS		2 /* one posted for req rx,
					   * one for reply tx
					   */
#define CONN_SETUP_BUF_SIZE		4096

#define SOFT_CQ_MOD			8
#define HARD_CQ_MOD			64
#define SEND_TRESHOLD			8

#define PAGE_SHIFT			12
#define PAGE_SIZE			(1UL << PAGE_SHIFT)
#define IS_PAGE_ALIGNED(ptr)		(((PAGE_SIZE-1) & (intptr_t)ptr) == 0)

#define USECS_IN_SEC			1000000
#define NSECS_IN_USEC			1000

/*---------------------------------------------------------------------------*/
/* enums								     */
/*---------------------------------------------------------------------------*/
enum xio_transport_state {
	XIO_STATE_INIT,
	XIO_STATE_CONNECTED,
	XIO_STATE_DISCONNECTED,
	XIO_STATE_CLOSED,
};

enum xio_ib_op_code {
	XIO_IB_NULL,
	XIO_IB_RECV		= 1,
	XIO_IB_SEND,
	XIO_IB_RDMA_WRITE,
	XIO_IB_RDMA_READ
};

struct xio_rdma_transport;

/*---------------------------------------------------------------------------*/
struct xio_sge {
	u64		addr;
	u32		length;
	u32		stag;
};

struct __attribute__((__packed__)) xio_req_hdr {
	u16		req_hdr_len;	 /* req header length	*/
	u16		sn;		/* serial number	*/
	u16		ack_sn;		/* ack serial number	*/
	u16		credits;	/* peer send credits	*/
	u8		opcode;		/* opcode  for peers	*/
	u8		flags;		/* not used		*/
	u16		tid;		/* originator identifier*/
	u16		ulp_hdr_len;	/* ulp header length	*/
	u16		ulp_pad_len;	/* pad_len length	*/
	u64		ulp_imm_len;	/* ulp data length	*/
	u32		remain_data_len; /* remaining data length */
	u64		read_va;	/* read virtual address */
	u32		read_stag;	/* read rkey		*/
	u32		read_len;	/* read length		*/
	u64		write_va;	/* write virtual address */
	u32		write_stag;	/* write rkey		*/
	u32		write_len;	/* write length		*/
};

struct __attribute__((__packed__)) xio_rsp_hdr {
	u16		rsp_hdr_len;	 /* rsp header length	*/
	u16		sn;		/* serial number	*/
	u16		ack_sn;		/* ack serial number	*/
	u16		credits;	/* peer send credits	*/
	u8		opcode;		/* opcode  for peers	*/
	u8		flags;		/* not used		*/
	u16		tid;		/* originator identifier*/
	u16		ulp_hdr_len;	/* ulp header length	*/
	u16		ulp_pad_len;	/* pad_len length	*/
	u64		ulp_imm_len;	/* ulp data length	*/
	u32		remain_data_len; /* remaining data length */
	u32		status;		/* status		*/
	u64		read_va;	/* read virtual address */
	u32		read_stag;	/* read rkey		*/
	u32		read_len;	/* read length		*/
};

struct __attribute__((__packed__)) xio_rdma_setup_msg {
	u16		credits;	/* peer send credits	*/
	u16		sq_depth;
	u16		rq_depth;
	u64		buffer_sz;
};

struct __attribute__((__packed__)) xio_nop_hdr {
	u16		hdr_len;	 /* req header length	*/
	u16		sn;		/* serial number	*/
	u16		ack_sn;		/* ack serial number	*/
	u16		credits;	/* peer send credits	*/
	u8		opcode;		/* opcode for peers	*/
	u8		flags;		/* not used		*/
};

struct xio_work_req {
	union {
		struct ib_send_wr	send_wr;
		struct ib_recv_wr	recv_wr;
	};
	struct ib_sge			sge[XIO_MAX_IOV + 1];
	struct scatterlist		sgl[XIO_MAX_IOV + 1];
	int				nents; /* number of mapped entries */
};

struct xio_rdma_task {
	struct xio_rdma_transport	*rdma_hndl;
	enum xio_ib_op_code		ib_op;
	u16				pad;
	u16				more_in_batch;

	//struct xio_data_buffer sdb;
	/* The buffer mapped with the 3 xio_work_req
	 * used to transfer the headers
	 */
	void				*buf;
	unsigned long			size;
	struct xio_work_req		txd;
	struct xio_work_req		rxd;
	struct xio_work_req		rdmad;

	/* User (from vmsg) or pool buffer used for */
	u32				read_num_sge;
	u32				write_num_sge;
	struct xio_rdma_mem_desc	read_sge;
	struct xio_rdma_mem_desc	write_sge;

	/* What this side got from the peer for RDMA R/W
	 * Currently limitd to 1
	 */
	u32				req_write_num_sge;
	u32				req_read_num_sge;
	struct xio_sge			req_read_sge[XIO_MAX_IOV];
	struct xio_sge			req_write_sge[XIO_MAX_IOV];
};

struct xio_cq  {
	struct xio_ev_data		ev_data;
	struct ib_cq			*cq;
	struct xio_context		*ctx;
	struct xio_device		*dev;
	struct ib_wc			*wc_array;
	u32				wc_array_len;
	u32				max_cqe;     /* max snd elements  */
	u32				cq_depth;     /* current cq depth  */
	u32				alloc_sz;     /* allocation factor  */
	u32				cqe_avail;    /* free elements  */
	atomic_t			refcnt;       /* utilization counter */
	u32				pad;
	struct list_head		trans_list;   /* list of all transports
						       * attached to this cq
						       */
	struct list_head		cq_list;	/* on device cq list */
};

struct xio_page_vec {
	u64 *pages;
	int length;
	int offset;
	int data_size;
};

struct xio_fmr {
	struct ib_fmr_pool	*pool;	   /* pool of IB FMRs         */
	struct xio_page_vec	*page_vec; /* represents SG to fmr maps*
					    * maps serialized as tx is*/
};

struct xio_frwr {
	struct list_head	pool;
	int			pool_size;
};

struct xio_fastreg {
	int	(*alloc_rdma_reg_res)(struct xio_device *dev, u32 cmds_max);
	void	(*free_rdma_reg_res)(struct xio_device *dev);
	int	(*reg_rdma_mem)(struct xio_task *xio_task,
				enum dma_data_direction cmd_dir);
	void	(*unreg_rdma_mem)(struct xio_task *xio_task,
				  enum dma_data_direction cmd_dir);
	union {
		struct xio_fmr fmr;
		struct xio_frwr frwr;
	};
};

struct xio_device {
	struct xio_fastreg		fastreg;
	struct list_head		cq_list; /* list of all cq per device */
	spinlock_t			cq_lock;
	struct ib_device		*ib_dev;
	struct ib_pd			*pd;
	struct ib_mr			*mr;
	struct ib_device_attr		device_attr;
	struct xio_cq			*cqs;
	int				cqs_used;
	int				port_num;
	struct ib_event_handler		event_handler;
};

struct xio_rdma_transport {
	struct xio_transport_base	base;
	struct xio_cq			*tcq;
	struct xio_dev			*dev;
	struct ib_qp			*qp;
	struct list_head		trans_list;

	/*  tasks queues */
	struct list_head		tx_ready_list;
	struct list_head		tx_comp_list;
	struct list_head		in_flight_list;
	struct list_head		rx_list;
	struct list_head		io_list;
	struct list_head		rdma_rd_list;
	struct list_head		rdma_rd_in_flight_list;

	/* connection's flow control */
	int				sq_depth;     /* max snd allowed  */
	int				rq_depth;     /* max rcv allowed  */
	int				actual_rq_depth; /* max rcv allowed  */
	int				rqe_avail;   /* recv queue elements
							avail */
	int				sqe_avail;
	int				tx_ready_tasks_num;
	u16				req_sig_cnt;
	u16				rsp_sig_cnt;
	enum xio_transport_state	state;
	int				num_tasks;
	int				kick_rdma_rd;

	int				client_initiator_depth;
	int				client_responder_resources;
	int				more_in_batch;
	int				rdma_in_flight;
	int				reqs_in_flight_nr;
	int				rsps_in_flight_nr;

	u16				credits;  /* the ack this peer sends */

	/* sender window parameters */
	u16				peer_credits;

	u16				sn;	   /* serial number */
	u16				ack_sn;	   /* serial number */

	u16				max_sn;	   /* upper edge of
						      sender's window + 1 */

	/* receiver window parameters */
	u16				exp_sn;	   /* lower edge of
						      receiver's window */

	u16				max_exp_sn; /* upper edge of
						       receiver's window + 1 */

	u16				sim_peer_credits;  /* simulates the peer
							    * credits managment
							    * to control nop
							    * sends
							    */

	struct xio_transport		*transport;
	struct rdma_event_channel	*cm_channel;
	struct rdma_cm_id		*cm_id;
	struct xio_rdma_mempool		*rdma_mempool;

	size_t				alloc_sz;
	size_t				membuf_sz;

	struct xio_rdma_setup_msg	setup_rsp;
	u8				setup_rsp_pad[2];
};

/*
 * The next routines deal with comparing 16 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 */

static inline s16 before(u16 seq1, u16 seq2)
{
	return (s16)(seq1 - seq2) < 0;
}
#define after(seq2, seq1)       before(seq1, seq2)

static inline s16 before_eq(u16 seq1, u16 seq2)
{
	return (s16)(seq1 - seq2) <= 0;
}
#define after_eq(seq2, seq1)       before_eq(seq1, seq2)


/* is s2<=s1<s3 ? */
static inline s16 between(u16 seq1, u16 seq2, u16 seq3)
{
	if (before_eq(seq1, seq2) && before(seq2, seq3))
		return 1;
	return 0;
}

static inline
unsigned long long timespec_to_usecs(struct timespec *time_spec)
{
	unsigned long long retval = 0;

	retval  = time_spec->tv_sec * USECS_IN_SEC;
	retval += time_spec->tv_nsec / NSECS_IN_USEC;

	return retval;
}


/* xio_rdma_verbs.c */
void xio_mr_list_init(void);
int xio_mr_list_free(void);
const char *xio_ib_wc_opcode_str(enum ib_wc_opcode opcode);


/* xio_rdma_datapath.c */
static inline int xio_rdma_notify_observer(
		struct xio_rdma_transport *rdma_hndl,
		int event, void *event_data)
{
	int retval = 0;

	if (rdma_hndl->base.notify_observer)
		retval = rdma_hndl->base.notify_observer(
				rdma_hndl->base.observer, rdma_hndl,
				event, event_data);

	return retval;
}

static inline int xio_rdma_notify_observer_error(
				struct xio_rdma_transport *rdma_hndl,
				int reason)
{
	int retval = 0;
	union xio_transport_event_data ev_data = {
		.error.reason = reason
	};

	if (rdma_hndl->base.notify_observer)
		retval = rdma_hndl->base.notify_observer(
				rdma_hndl->base.observer, rdma_hndl,
				XIO_TRANSPORT_ERROR, &ev_data);
	return retval;
}

void xio_data_ev_handler(int fd, int events, void *user_context);
int xio_post_recv(struct xio_rdma_transport *rdma_hndl,
		  struct xio_task *task, int num_recv_bufs);
int xio_rdma_rearm_rq(struct xio_rdma_transport *rdma_hndl);
int xio_rdma_task_put(struct xio_transport_base *trans_hndl,
		      struct xio_task *task);
int xio_rdma_send(struct xio_transport_base *transport,
		  struct xio_task *task);
int xio_rdma_poll(struct xio_transport_base *transport,
		  struct timespec *ts_timeout);


/* xio_rdma_management.c */
void xio_rdma_calc_pool_size(struct xio_rdma_transport *rdma_hndl);


#endif  /* XIO_RDMA_TRANSPORT_H */
