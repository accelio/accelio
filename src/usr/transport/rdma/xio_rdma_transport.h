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
#ifndef XIO_RDMA_TRANSPORT_H
#define XIO_RDMA_TRANSPORT_H

#include <sys/hashtable.h>
#include "xio_hash.h"

/*---------------------------------------------------------------------------*/
/* externals								     */
/*---------------------------------------------------------------------------*/
extern int			page_size;
extern double			g_mhz;
extern struct xio_rdma_options	rdma_options;
extern struct list_head		dev_list;
extern spinlock_t		dev_list_lock;

#define XIO_DISCONNECT_TIMEOUT		100     /* 100 mili */
#define XIO_TIMEWAIT_EXIT_TIMEOUT	60000  /* 1 minute */
#define XIO_TIMEWAIT_EXIT_FAST_TIMEOUT	0     /*  0 milliseconds */

/* poll_cq definitions */
#define MAX_RDMA_ADAPTERS		64   /* 64 adapters per unit */
#define MAX_POLL_WC			128
#define NUM_POLL_CQ			16

#define ADDR_RESOLVE_TIMEOUT		1000
#define ROUTE_RESOLVE_TIMEOUT		1000

					/* 256 rdma_write + 1 send */
#define MAX_SEND_WR			(XIO_MAX_IOV + 1)
#define MAX_RECV_WR			(XIO_MAX_IOV)
#define EXTRA_RQE			32
#define SEND_QE				NUM_START_PRIMARY_POOL_TASKS - EXTRA_RQE - MAX_RECV_WR
#define MAX_ACKED_CQE			128
#define XIO_DEV_ATTR_MAX_SGE		 30

#define MAX_CQE_PER_QP			(MAX_SEND_WR + MAX_RECV_WR + EXTRA_RQE)
#define CQE_ALLOC_SIZE			(10 * MAX_CQE_PER_QP)

#define BUDGET_SIZE			1024
#define MAX_NUM_DELAYED_ARM		16

#define NUM_START_PHANTOM_POOL_TASKS	0
#define NUM_ALLOC_PHANTOM_POOL_TASKS	512
#define NUM_MAX_PHANTOM_POOL_TASKS	32768

#define SOFT_CQ_MOD			8
#define HARD_CQ_MOD			64
#define SEND_THRESHOLD			8
#define SRQ_DEPTH			1024

#define XIO_BEACON_WRID			0xfffffffffffffffeULL

#define RDMA_DEFAULT_BACKLOG	4 /* rdma_listen default backlog */

#define PAGE_SIZE			page_size
/* see if a pointer is page aligned. */
#define IS_PAGE_ALIGNED(ptr)		\
			(((PAGE_SIZE - 1) & (intptr_t)(ptr)) == 0)

#define XIO_TO_RDMA_TASK(xt, rt)			\
		struct xio_rdma_task *(rt) =		\
			(struct xio_rdma_task *)(xt)->dd_data
#define XIO_TO_RDMA_HNDL(xt, rh)				\
		struct xio_rdma_transport *(rh) =		\
			(struct xio_rdma_transport *)(xt)->context

#ifdef HAVE_MPAGES_EXP
#    define IBV_XIO_ACCESS_ALLOCATE_MR		IBV_EXP_ACCESS_ALLOCATE_MR
#    define IBV_IS_MPAGES_AVAIL(_attr)		((_attr)->exp_device_cap_flags \
						& IBV_EXP_DEVICE_MR_ALLOCATE)
#    define ibv_xio_device_attr			ibv_exp_device_attr
#    define ibv_xio_query_device		ibv_exp_query_device
#    define ibv_xio_reg_mr			ibv_exp_reg_mr
#else
#    ifdef HAVE_MPAGES
#        define IBV_XIO_ACCESS_ALLOCATE_MR	IBV_ACCESS_ALLOCATE_MR
#        define IBV_IS_MPAGES_AVAIL(_attr)	((_attr)->device_cap_flags \
						& IBV_DEVICE_MR_ALLOCATE)
#    else
#        define IBV_XIO_ACCESS_ALLOCATE_MR	(0)
#        define IBV_IS_MPAGES_AVAIL(_attr)	(0)
#    endif

#    define ibv_xio_device_attr			ibv_device_attr
#    define ibv_xio_query_device		ibv_query_device

struct ibv_exp_reg_mr_in {
	struct ibv_pd *pd;
	void *addr;
	size_t length;
	int exp_access;
	uint32_t comp_mask;
};

static inline struct ibv_mr *ibv_xio_reg_mr(struct ibv_exp_reg_mr_in *in)
{
	return ibv_reg_mr(in->pd, in->addr, in->length, in->exp_access);
}
#endif

/*---------------------------------------------------------------------------*/
/* enums								     */
/*---------------------------------------------------------------------------*/
enum xio_ib_op_code {
	XIO_IB_NULL,
	XIO_IB_RECV		= 1,
	XIO_IB_SEND,
	XIO_IB_RDMA_WRITE,
	XIO_IB_RDMA_READ,
	XIO_IB_RDMA_WRITE_DIRECT,
	XIO_IB_RDMA_READ_DIRECT
};

struct xio_transport_base;
struct xio_rdma_transport;

/*---------------------------------------------------------------------------*/
struct xio_rdma_options {
	int			enable_mem_pool;
	int			enable_dma_latency;
	int			max_in_iovsz;
	int			max_out_iovsz;
	int			qp_cap_max_inline_data;
};

#define XIO_REQ_HEADER_VERSION	1

struct __attribute__((__packed__)) xio_rdma_req_hdr {
	uint8_t			version;	/* request version	*/
	uint8_t			flags;
	uint16_t		req_hdr_len;	/* req header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		ack_sn;		/* ack serial number	*/

	uint16_t		credits;	/* peer send credits	*/
	uint32_t		ltid;		/* originator identifier*/
	uint8_t			in_ib_op;	/* opcode  for peers	*/
	uint8_t			out_ib_op;

	uint16_t		in_num_sge;
	uint16_t		out_num_sge;
	uint32_t		pad1;

	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/
	uint32_t		remain_data_len;/* remaining data length */
	uint64_t		ulp_imm_len;	/* ulp data length	*/
};

#define XIO_RSP_HEADER_VERSION	1

struct __attribute__((__packed__)) xio_rdma_rsp_hdr {
	uint8_t			version;	/* response version     */
	uint8_t			flags;
	uint16_t		rsp_hdr_len;	/* rsp header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		ack_sn;		/* ack serial number	*/

	uint16_t		credits;	/* peer send credits	*/
	uint32_t		rtid;		/* originator identifier*/
	uint8_t			out_ib_op;	/* opcode  for peers	*/
	uint8_t			pad;

	uint16_t                pad1;
	uint16_t		out_num_sge;
	uint32_t		status;		/* status		*/

	uint32_t		ltid;		/* local task id	*/
	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/

	uint32_t		remain_data_len;/* remaining data length */

	uint64_t		ulp_imm_len;	/* ulp data length	*/
};

struct __attribute__((__packed__)) xio_rdma_setup_msg {
	uint16_t		credits;	/* peer send credits	*/
	uint16_t		sq_depth;
	uint16_t		rq_depth;
	uint16_t		rkey_tbl_size;
	uint64_t		buffer_sz;
	uint32_t		max_in_iovsz;
	uint32_t		max_out_iovsz;
	uint32_t                max_header_len;
	uint32_t		pad;
};

struct __attribute__((__packed__)) xio_nop_hdr {
	uint16_t		hdr_len;	 /* req header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		ack_sn;		/* ack serial number	*/
	uint16_t		credits;	/* peer send credits	*/
	uint8_t			opcode;		/* opcode for peers	*/
	uint8_t			flags;		/* not used		*/
	uint16_t		pad;
};

struct __attribute__((__packed__)) xio_rdma_read_ack_hdr {
	uint16_t		hdr_len;	 /* req header length	*/
	uint32_t		rtid;		 /* remote task id	*/
};

struct __attribute__((__packed__)) xio_rdma_cancel_hdr {
	uint16_t		hdr_len;	 /* req header length	*/
	uint16_t		sn;		 /* serial number	*/
	uint32_t		result;
};

struct xio_work_req {
	union {
		struct ibv_send_wr	send_wr;
		struct ibv_recv_wr	recv_wr;
	};
	struct ibv_sge			*sge;
};

struct xio_rdma_task {
	enum xio_ib_op_code		out_ib_op;
	enum xio_ib_op_code		in_ib_op;

	/* The buffer mapped with the 3 xio_work_req
	 * used to transfer the headers
	 */
	struct xio_work_req		txd;
	struct xio_work_req		rxd;
	struct xio_work_req		rdmad;

	/* User (from vmsg) or pool buffer used for */
	uint16_t			read_num_reg_mem;
	uint16_t			write_num_reg_mem;
	uint32_t			pad0;
	struct xio_reg_mem		*read_reg_mem;
	struct xio_reg_mem		*write_reg_mem;

	/* What this side got from the peer for RDMA R/W
	 */
	uint16_t			req_in_num_sge;
	uint16_t			req_out_num_sge;
	uint16_t			rsp_out_num_sge;
	uint16_t			pad1;

	/* can serve send/rdma write  */
	struct xio_sge			*req_in_sge;

	/* can serve send/rdma read  */
	struct xio_sge			*req_out_sge;

	/* can serve send/rdma read response/rdma write  */
	struct xio_sge			*rsp_out_sge;

	unsigned int			phantom_idx;
	uint16_t			sn;
	uint8_t				rflags;
	uint8_t				pad;
};

struct xio_cq  {
	struct ibv_cq			*cq;
	struct ibv_comp_channel		*channel;
	struct xio_context		*ctx;
	struct xio_device		*dev;
	struct xio_ev_data		consume_cq_event;
	struct xio_ev_data		poll_cq_event;
	struct ibv_wc			*wc_array;
	int32_t				wc_array_len;
	int32_t				cq_events_that_need_ack;
	int32_t				max_cqe;     /* max snd elements  */
	int32_t				cq_depth;     /* current cq depth  */
	int32_t				alloc_sz;     /* allocation factor  */
	int32_t				cqe_avail;    /* free elements  */
	struct kref			kref;       /* utilization counter */
	int32_t				num_delayed_arm;
	int32_t				num_poll_cq;
	int32_t				pad;
	struct list_head		trans_list;   /* list of all transports
						       * attached to this cq
						       */
	struct list_head		cq_list_entry; /* list of all
						       cq per device */
	struct xio_observer		observer;
	struct xio_srq			*srq;
};

struct xio_srq {
	HT_HEAD(, rdma_hndl, HASHTABLE_PRIME_SMALL)  ht_rdma_hndl;
	struct ibv_srq 			*srq;
	struct list_head		rx_list;
	int				rqe_avail;  /* recv queue elements
						       avail */
	int				pad;
};

struct xio_device {
	struct list_head		cq_list;
	struct list_head		dev_list_entry;    /* list of all
							      xio devices */
	pthread_rwlock_t		cq_lock;
	struct ibv_context		*verbs;
	struct ibv_pd			*pd;
	struct ibv_xio_device_attr	device_attr;
	struct list_head		xm_list; /* list of xio_mr_elem */
	struct kref			kref;
	uint32_t			kref_pad;
};

struct xio_mr_elem {
	struct xio_device		*dev;
	struct ibv_mr			*mr;
	struct list_head		dm_list_entry; /* entry in mr list */
	struct list_head		xm_list_entry; /* entry in dev list */
};

struct xio_rdma_tasks_slab {
	/* memory for non-rdma send/recv */
	void				*data_pool;

	/* memory registration for data */
	struct xio_mr			*data_mr;
	struct xio_reg_mem		reg_mem;
	int				buf_size;
	int				alloc_nr;
};

struct __attribute__((__packed__)) xio_rkey_tbl_pack {
	uint32_t			old_rkey;
	uint32_t			new_rkey;
};

struct xio_rkey_tbl {
	uint32_t			old_rkey;
	uint32_t			new_rkey;
};

struct xio_rdma_transport {
	struct xio_transport_base	base;
	struct xio_cq			*tcq;
	struct ibv_qp			*qp;
	struct xio_mempool		*rdma_mempool;
	struct xio_tasks_pool		*phantom_tasks_pool;

	struct list_head		trans_list_entry;

	/*  tasks queues */
	struct list_head		tx_ready_list;
	struct list_head		tx_comp_list;
	struct list_head		in_flight_list;
	struct list_head		rx_list;
	struct list_head		io_list;
	struct list_head		rdma_rd_req_list;
	struct list_head		rdma_rd_req_in_flight_list;
	struct list_head		rdma_rd_rsp_list;
	struct list_head		rdma_rd_rsp_in_flight_list;

		/* rx parameters */
	int				rq_depth;	 /* max rcv per qp
							    allowed */
	int				rqe_avail;	 /* recv queue elements
							    avail */
	uint16_t			sim_peer_credits;  /* simulates the peer
							    * credits management
							    * to control nop
							    * sends
							    */
	uint16_t			credits;	  /* the ack this
							     peer sends */
	uint16_t			peer_credits;

	uint16_t			pad;
	uint32_t                        peer_max_header;

	/* fast path params */
	int				rdma_rd_req_in_flight;
	int				rdma_rd_rsp_in_flight;
	int				sqe_avail;
	enum xio_transport_state	state;

	/* tx parameters */
	int				kick_rdma_rd_req;
	int				kick_rdma_rd_rsp;
	int				reqs_in_flight_nr;
	int				rsps_in_flight_nr;
	int				tx_ready_tasks_num;
	int				max_tx_ready_tasks_num;
	int				max_inline_data;
	size_t				max_inline_buf_sz;
	int				max_sge;
	uint16_t			req_sig_cnt;
	uint16_t			rsp_sig_cnt;
	/* sender window parameters */
	uint16_t			sn;	   /* serial number */
	uint16_t			ack_sn;	   /* serial number */

	uint16_t			max_sn;	   /* upper edge of
						      sender's window + 1 */

	/* receiver window parameters */
	uint16_t			exp_sn;	   /* lower edge of
						      receiver's window */

	uint16_t			max_exp_sn; /* upper edge of
						       receiver's window + 1 */

	uint16_t			pad1;

	/* control path params */
	int				sq_depth;     /* max snd allowed  */
	uint16_t			client_initiator_depth;
	uint16_t			client_responder_resources;

	uint32_t			peer_max_in_iovsz;
	uint32_t			peer_max_out_iovsz;
	int32_t				handler_nesting;
	/* connection's flow control */
	size_t				membuf_sz;

	struct xio_transport		*transport;
	struct xio_cm_channel		*cm_channel;
	struct rdma_cm_id		*cm_id;
	struct xio_tasks_pool_cls	initial_pool_cls;
	struct xio_tasks_pool_cls	primary_pool_cls;

	struct xio_rdma_setup_msg	setup_rsp;

	/* for reconnect */
	struct xio_device		*dev;
	struct xio_rkey_tbl		*rkey_tbl;
	struct xio_rkey_tbl		*peer_rkey_tbl;

	/* for reconnect */
	uint16_t			rkey_tbl_size;
	uint16_t			peer_rkey_tbl_size;

	uint32_t			ignore_timewait:1;
	uint32_t			timewait_nr:1; /* flag */
	uint32_t			ignore_disconnect:1;
	uint32_t			disconnect_nr:1; /* flag */
	uint32_t                        beacon_sent:1;
	uint32_t			reserved:27;

	/* too big to be on stack - use as temporaries */
	union {
		struct xio_msg		dummy_msg;
		struct xio_work_req	dummy_wr;
	};
	struct xio_ev_data		close_event;
	struct xio_ev_data		timewait_exit_event;
	xio_delayed_work_handle_t	timewait_timeout_work;
	xio_delayed_work_handle_t	disconnect_timeout_work;
	struct ibv_send_wr		beacon;
	struct xio_task			beacon_task;
	uint32_t			trans_attr_mask;
	struct xio_transport_attr	trans_attr;
	struct xio_srq			*xio_srq;
	HT_ENTRY(rdma_hndl, xio_key_int32) rdma_hndl_htbl;
};

struct xio_cm_channel {
	struct rdma_event_channel	*cm_channel;
	struct xio_context		*ctx;
	struct list_head		channels_list_entry;
	struct kref			kref;       /* utilization counter */
	int				pad;
};

struct xio_dev_tdata {
	pthread_t			dev_thread;
	void				*async_loop;
};

/* xio_rdma_verbs.c */
void xio_mr_list_init(void);
int xio_mr_list_free(void);
const char *ibv_wc_opcode_str(enum ibv_wc_opcode opcode);

void xio_cq_event_handler(int fd, int events, void *data);
int xio_post_recv(struct xio_rdma_transport *rdma_hndl,
		  struct xio_task *task, int num_recv_bufs);
int xio_rdma_rearm_rq(struct xio_rdma_transport *rdma_hndl);

int xio_rdma_send(struct xio_transport_base *transport,
		  struct xio_task *task);
int xio_rdma_poll(struct xio_transport_base *transport,
		  long min_nr, long nr,
		  struct timespec *ts_timeout);

int xio_rdma_cancel_req(struct xio_transport_base *transport,
			struct xio_msg *req, uint64_t stag,
			void *ulp_msg, size_t ulp_msg_sz);

int xio_rdma_cancel_rsp(struct xio_transport_base *transport,
			struct xio_task *task, enum xio_status result,
			void *ulp_msg, size_t ulp_msg_sz);

/* xio_rdma_management.c */
int xio_rdma_get_max_header_size(void);

int xio_rdma_get_inline_buffer_size(void);

struct xio_task *xio_rdma_primary_task_alloc(
				struct xio_rdma_transport *rdma_hndl);

struct xio_task *xio_rdma_primary_task_lookup(
					struct xio_rdma_transport *rdma_hndl,
					int tid);

void xio_rdma_task_free(struct xio_rdma_transport *rdma_hndl,
			struct xio_task *task);

static inline void xio_device_get(struct xio_device *dev)
{
	kref_get(&dev->kref);
}

void xio_rdma_close_cb(struct kref *kref);

void xio_device_down(struct kref *kref);

static inline void xio_device_put(struct xio_device *dev)
{
	kref_put(&dev->kref, xio_device_down);
}

void xio_set_timewait_timer(struct xio_rdma_transport *rdma_hndl);

/*---------------------------------------------------------------------------*/
/* xio_reg_mr_add_dev							     */
/* add a new discovered device to a the mr list				     */
/*---------------------------------------------------------------------------*/
int xio_reg_mr_add_dev(struct xio_device *dev);

/*---------------------------------------------------------------------------*/
/* xio_dereg_mr_by_dev							     */
/*---------------------------------------------------------------------------*/
int xio_dereg_mr_by_dev(struct xio_device *dev);

/*---------------------------------------------------------------------------*/
/* xio_rkey_table_create						     */
/*---------------------------------------------------------------------------*/
int xio_rkey_table_create(struct xio_device *old, struct xio_device *_new,
			  struct xio_rkey_tbl **htbl, uint16_t *len);

void xio_rdma_poll_completions(struct xio_cq *tcq, int timeout_us);

#endif  /* XIO_RDMA_TRANSPORT_H */
