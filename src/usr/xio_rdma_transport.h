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

#define VALIDATE_SZ(sz)				\
		if (optlen != (sz)) {		\
			xio_set_error(EINVAL);	\
			return -1;		\
		}

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

#ifndef IBV_DEVICE_MR_ALLOCATE
#  define IBV_DEVICE_MR_ALLOCATE     (1ULL<<23)
#endif
#ifndef IBV_ACCESS_ALLOCATE_MR
#  define IBV_ACCESS_ALLOCATE_MR     (1ULL<<5)
#endif /* M-pages compatibility */


struct xio_rdma_transport;

/*---------------------------------------------------------------------------*/
struct xio_rdma_options {
	int			enable_mem_pool;
	int			enable_dma_latency;
	int			rdma_buf_threshold;
	int			rdma_buf_attr_rdonly;
};

struct xio_sge {
	uint64_t		addr;
	uint32_t		length;
	uint32_t		stag;
};

struct __attribute__((__packed__)) xio_req_hdr {
	uint16_t		req_hdr_len;	 /* req header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		ack_sn;		/* ack serial number	*/
	uint16_t		credits;	/* peer send credits	*/
	uint8_t			opcode;		/* opcode  for peers	*/
	uint8_t			flags;		/* not used		*/
	uint16_t		tid;		/* originator identifier*/
	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/
	uint64_t		ulp_imm_len;	/* ulp data length	*/
	uint32_t		remain_data_len; /* remaining data length */
	uint64_t		read_va;	/* read virtual address */
	uint32_t		read_stag;	/* read rkey		*/
	uint32_t		read_len;	/* read length		*/
	uint64_t		write_va;	/* write virtual address */
	uint32_t		write_stag;	/* write rkey		*/
	uint32_t		write_len;	/* write length		*/
};

struct __attribute__((__packed__)) xio_rsp_hdr {
	uint16_t		rsp_hdr_len;	 /* rsp header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		ack_sn;		/* ack serial number	*/
	uint16_t		credits;	/* peer send credits	*/
	uint8_t			opcode;		/* opcode  for peers	*/
	uint8_t			flags;		/* not used		*/
	uint16_t		tid;		/* originator identifier*/
	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/
	uint64_t		ulp_imm_len;	/* ulp data length	*/
	uint32_t		remain_data_len; /* remaining data length */
	uint32_t		status;		/* status		*/
	uint64_t		read_va;	/* read virtual address */
	uint32_t		read_stag;	/* read rkey		*/
	uint32_t		read_len;	/* read length		*/
};

struct __attribute__((__packed__)) xio_rdma_setup_msg {
	uint16_t		credits;	/* peer send credits	*/
	uint16_t		sq_depth;
	uint16_t		rq_depth;
	uint64_t		buffer_sz;
};

struct __attribute__((__packed__)) xio_nop_hdr {
	uint16_t		hdr_len;	 /* req header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		ack_sn;		/* ack serial number	*/
	uint16_t		credits;	/* peer send credits	*/
	uint8_t			opcode;		/* opcode for peers	*/
	uint8_t			flags;		/* not used		*/
};

struct xio_work_req {
	union {
		struct ibv_send_wr	send_wr;
		struct ibv_recv_wr	recv_wr;
	};
	struct ibv_sge			sge[XIO_MAX_IOV + 1];
};

struct xio_rdma_task {
	struct xio_rdma_transport	*rdma_hndl;
	enum xio_ib_op_code		ib_op;
	uint16_t			more_in_batch;
	uint16_t			sn;

	struct xio_work_req		txd;
	struct xio_work_req		rxd;
	struct xio_work_req		rdmad;

	uint32_t			read_num_sge;
	uint32_t			write_num_sge;
	struct xio_rdma_mp_mem		read_sge[XIO_MAX_IOV];
	struct xio_rdma_mp_mem		write_sge[XIO_MAX_IOV];

	uint32_t			req_write_num_sge;
	uint32_t			req_read_num_sge;
	struct xio_sge			req_read_sge[XIO_MAX_IOV];
	struct xio_sge			req_write_sge[XIO_MAX_IOV];
};

struct xio_cq  {
	struct ibv_cq			*cq;
	struct ibv_comp_channel		*channel;
	struct xio_context		*ctx;
	struct xio_device		*dev;
	struct ibv_wc			*wc_array;
	int32_t				wc_array_len;
	int32_t				cq_events_that_need_ack;
	int32_t				max_cqe;     /* max snd elements  */
	int32_t				cq_depth;     /* current cq depth  */
	int32_t				alloc_sz;     /* allocation factor  */
	int32_t				cqe_avail;    /* free elements  */
	atomic_t			refcnt;       /* utilization counter */
	int32_t				pad;
	struct list_head		trans_list;   /* list of all transports
						       * attached to this cq
						       */
	struct list_head		cq_list_entry; /* list of all
						       cq per device */
};

struct xio_device {
	struct list_head		cq_list;
	struct list_head		dev_list_entry;    /* list of all
							xio devices */
	pthread_rwlock_t		cq_lock;
	struct ibv_context		*verbs;
	struct ibv_pd			*pd;
	struct ibv_device_attr		device_attr;
};

struct xio_mr_elem {
	struct ibv_mr			*mr;
	struct xio_device		*dev;
	struct list_head		dm_list_entry;
};

struct xio_mr {
	struct list_head		dm_list;
	struct list_head		mr_list_entry;
};

struct xio_rdma_tasks_pool {
	/* memory for non-rdma send/recv */
	void				*data_pool;

	/* memory registration for data */
	struct ibv_mr			*data_mr;
	int				buf_size;
	int				pad;
};

struct xio_rdma_transport {
	struct xio_transport_base	base;
	struct xio_cq			*tcq;
	struct ibv_qp			*qp;
	struct list_head		trans_list_entry;

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
	int				max_tx_ready_tasks_num;
	uint16_t			req_sig_cnt;
	uint16_t			rsp_sig_cnt;
	enum xio_transport_state	state;
	int				num_tasks;
	int				kick_rdma_rd;

	int				client_initiator_depth;
	int				client_responder_resources;
	int				more_in_batch;
	int				rdma_in_flight;
	int				reqs_in_flight_nr;
	int				rsps_in_flight_nr;

	uint16_t			credits;  /* the ack this peer sends */

	/* sender window parameters */
	uint16_t			peer_credits;

	uint16_t			sn;	   /* serial number */
	uint16_t			ack_sn;	   /* serial number */

	uint16_t			max_sn;	   /* upper edge of
						      sender's window + 1 */

	/* receiver window parameters */
	uint16_t			exp_sn;	   /* lower edge of
						      receiver's window */

	uint16_t			max_exp_sn; /* upper edge of
						       receiver's window + 1 */

	uint16_t			sim_peer_credits;  /* simulates the peer
							    * credits managment
							    * to control nop
							    * sends
							    */
	int				max_send_buf_sz;

	struct xio_transport		*transport;
	struct rdma_event_channel	*cm_channel;
	struct rdma_cm_id		*cm_id;
	struct xio_rdma_mempool		*rdma_mempool;

	size_t				alloc_sz;
	size_t				membuf_sz;

	struct xio_rdma_setup_msg	setup_rsp;
	uint8_t				setup_rsp_pad[2];
};

struct xio_cm_channel {
	struct rdma_event_channel	*cm_channel;
	struct xio_context		*ctx;
	struct list_head		channels_list_entry;
};

struct xio_dev_tdata {
	pthread_t			dev_thread;
	void				*async_loop;
};

/*
 * The next routines deal with comparing 16 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 */

static inline int16_t before(uint16_t seq1, uint16_t seq2)
{
	return (int16_t)(seq1 - seq2) < 0;
}
#define after(seq2, seq1)       before(seq1, seq2)

static inline int16_t before_eq(uint16_t seq1, uint16_t seq2)
{
	return (int16_t)(seq1 - seq2) <= 0;
}
#define after_eq(seq2, seq1)       before_eq(seq1, seq2)


/* is s2<=s1<s3 ? */
static inline int16_t between(uint16_t seq1, uint16_t seq2, uint16_t seq3)
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
const char *ibv_wc_opcode_str(enum ibv_wc_opcode opcode);


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

