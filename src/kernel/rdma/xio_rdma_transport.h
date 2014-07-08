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

#include "xio_transport.h"

/*---------------------------------------------------------------------------*/
/* externals								     */
/*---------------------------------------------------------------------------*/
extern struct xio_rdma_options	rdma_options;


/* poll_cq definitions */
#define MAX_RDMA_ADAPTERS		64   /* 64 adapters per unit */
#define MAX_POLL_WC			128

#define ADDR_RESOLVE_TIMEOUT		1000
#define ROUTE_RESOLVE_TIMEOUT		1000

#define MAX_SGE				(XIO_MAX_IOV + 1)

#define MAX_SEND_WR			257  /* 256 rdma_write + 1 send */
#define MAX_RECV_WR			256
#define EXTRA_RQE			32

#define MAX_CQE_PER_QP			(MAX_SEND_WR+MAX_RECV_WR)
#define CQE_ALLOC_SIZE			(10*(MAX_SEND_WR+MAX_RECV_WR))

#define DEF_DATA_ALIGNMENT		0
#define SEND_BUF_SZ			9216
#define MAX_HDR_SZ			512
#define MAX_INLINE_DATA			200
#define BUDGET_SIZE			1024
#define MAX_NUM_DELAYED_ARM		16

#define NUM_CONN_SETUP_TASKS		2 /* one posted for req rx,
					   * one for reply tx
					   */
#define CONN_SETUP_BUF_SIZE		4096

#define NUM_START_PHANTOM_POOL_TASKS	0
#define NUM_ALLOC_PHANTOM_POOL_TASKS	256
#define NUM_MAX_PHANTOM_POOL_TASKS	32768

#define SOFT_CQ_MOD			8
#define HARD_CQ_MOD			64
#define SEND_TRESHOLD			8

#ifndef PAGE_SHIFT
#define PAGE_SHIFT			12
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE			(1UL << PAGE_SHIFT)
#endif
#ifndef PAGE_MASK
#define PAGE_MASK			(~(PAGE_SIZE-1))
#endif

#define USECS_IN_SEC			1000000
#define NSECS_IN_USEC			1000


#define XIO_TO_RDMA_TASK(xt, rt) \
		struct xio_rdma_task *rt = (struct xio_rdma_task *)(xt)->dd_data

#define xio_prefetch(p)		prefetch(p)

#define XIO_FRWR_LI_WRID 0xffffffffffffffffULL

/* header flags */
#define XIO_HEADER_FLAG_NONE		0x00
#define XIO_HEADER_FLAG_SMALL_ZERO_COPY	0x01

/*---------------------------------------------------------------------------*/
/* enums								     */
/*---------------------------------------------------------------------------*/
enum xio_transport_state {
	XIO_STATE_INIT,
	XIO_STATE_LISTEN,
	XIO_STATE_CONNECTED,
	XIO_STATE_DISCONNECTED,
	XIO_STATE_RECONNECT,
	XIO_STATE_CLOSED,
	XIO_STATE_DESTROYED
};

enum xio_ib_op_code {
	XIO_IB_NULL,
	XIO_IB_RECV		= 1,
	XIO_IB_SEND,
	XIO_IB_RDMA_WRITE,
	XIO_IB_RDMA_READ
};

struct xio_transport_base;
struct xio_rdma_transport;

/*---------------------------------------------------------------------------*/
struct xio_rdma_options {
	int	enable_mem_pool;
	int	enable_dma_latency;
	int	rdma_buf_threshold;
	int	rdma_buf_attr_rdonly;
	int	max_in_iovsz;
	int	max_out_iovsz;
};

#define XIO_REQ_HEADER_VERSION	1

struct __attribute__((__packed__)) xio_req_hdr {
	uint8_t			version;	/* request version	*/
	uint8_t			flags;
	uint16_t		req_hdr_len;	/* req header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		ack_sn;		/* ack serial number	*/

	uint16_t		credits;	/* peer send credits	*/
	uint16_t		tid;		/* originator identifier*/
	uint8_t			opcode;		/* opcode  for peers	*/
	uint8_t			pad[3];

	uint16_t		recv_num_sge;
	uint16_t		read_num_sge;
	uint16_t		write_num_sge;
	uint16_t		pad1;

	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/
	uint32_t		remain_data_len;/* remaining data length */
	uint64_t		ulp_imm_len;	/* ulp data length	*/
};

#define XIO_RSP_HEADER_VERSION	1

struct __attribute__((__packed__)) xio_rsp_hdr {
	uint8_t			version;	/* response version     */
	uint8_t			flags;
	uint16_t		rsp_hdr_len;	/* rsp header length	*/
	uint16_t		sn;		/* serial number	*/
	uint16_t		ack_sn;		/* ack serial number	*/

	uint16_t		credits;	/* peer send credits	*/
	uint16_t		tid;		/* originator identifier*/
	uint8_t			opcode;		/* opcode  for peers	*/
	uint8_t			pad[3];

	uint16_t		write_num_sge;
	uint16_t		pad1;
	uint32_t		status;		/* status		*/
	uint16_t		ulp_hdr_len;	/* ulp header length	*/
	uint16_t		ulp_pad_len;	/* pad_len length	*/

	uint32_t		remain_data_len;/* remaining data length */
	uint64_t		ulp_imm_len;	/* ulp data length	*/
};

struct __attribute__((__packed__)) xio_rdma_setup_msg {
	u16		credits;	/* peer send credits	*/
	u16		sq_depth;
	u16		rq_depth;
	u16		rkey_tbl_size;
	u64		buffer_sz;
	u32		max_in_iovsz;
	u32		max_out_iovsz;
};

struct __attribute__((__packed__)) xio_nop_hdr {
	u16		hdr_len;	 /* req header length	*/
	u16		sn;		/* serial number	*/
	u16		ack_sn;		/* ack serial number	*/
	u16		credits;	/* peer send credits	*/
	u8		opcode;		/* opcode for peers	*/
	u8		flags;		/* not used		*/
	u16		pad;
};

struct __attribute__((__packed__)) xio_rdma_cancel_hdr {
	uint16_t		hdr_len;	 /* req header length	*/
	uint16_t		sn;		 /* serial number	*/
	uint32_t		result;
};

struct xio_work_req {
	union {
		struct ib_send_wr	send_wr;
		struct ib_recv_wr	recv_wr;
	};
	struct ib_sge			*sge;
	struct scatterlist		*sgl;
	int				nents; /* number of sgl entries */
	int				mapped; /* number of mapped entries */
};

struct xio_rdma_task {
	struct xio_rdma_transport	*rdma_hndl;
	enum xio_ib_op_code		ib_op;
	u16				more_in_batch;
	u16				sn;
	u16				phantom_idx;
	u16				pad[3];

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
	u32				recv_num_sge;
	struct xio_rdma_mem_desc	read_sge;
	struct xio_rdma_mem_desc	write_sge;

	/* What this side got from the peer for RDMA R/W */
	u32				req_write_num_sge;
	u32				rsp_write_num_sge;
	u32				req_read_num_sge;
	u32				req_recv_num_sge;
	struct xio_sge			*req_read_sge;
	struct xio_sge			*req_write_sge;
	/* What this side got from the peer for SEND
	*/
	struct xio_sge			*req_recv_sge;

	/* What this side writes to the peer on RDMA W
	 */
	struct xio_sge			*rsp_write_sge;
};

struct xio_cq  {
	struct xio_ev_data		event_data;
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
	u32				num_delayed_arm;
	struct list_head		trans_list;   /* list of all transports
						       * attached to this cq
						       */
	struct list_head		cq_list_entry;	/* on device cq list */
	struct xio_observer		observer;	/* context observer */
	struct dentry			*tcq_dentry;	/* debugfs */
	u64				events;
	u64				wqes;
	u64				scheds;
};

struct xio_page_vec {
	u64 *pages;
	int length;
	int offset;
	int data_size;
};

enum xio_fast_reg {
	XIO_FAST_MEM_NONE,
	XIO_FAST_MEM_FRWR,
	XIO_FAST_MEM_FMR
};

struct xio_fmr {
	struct ib_fmr_pool	*pool;	   /* pool of IB FMRs         */
	struct xio_page_vec	*page_vec; /* represents SG to fmr maps*
					    * maps serialized as tx is*/
};

struct xio_frwr {
	struct llist_head	pool;
	struct llist_head	pool_ret;
	int			pool_size;
};

union xio_fastreg {
	struct xio_fmr fmr;
	struct xio_frwr frwr;
};

struct xio_fastreg_ops {
	int	(*alloc_rdma_reg_res)(struct xio_rdma_transport *rdma_hndl);
	void	(*free_rdma_reg_res)(struct xio_rdma_transport *rdma_hndl);
	int	(*reg_rdma_mem)(struct xio_rdma_transport *rdma_hndl,
				struct xio_rdma_mem_desc *desc,
				enum dma_data_direction cmd_dir);
	void	(*unreg_rdma_mem)(struct xio_rdma_transport *rdma_hndl,
				  struct xio_rdma_mem_desc *desc,
				  enum dma_data_direction cmd_dir);
};

struct xio_device {
	struct xio_fastreg_ops		fastreg;
	struct list_head		cq_list; /* list of all cq per device */
	rwlock_t			cq_lock;
	struct ib_device		*ib_dev;
	struct ib_pd			*pd;
	struct ib_mr			*mr;
	struct ib_device_attr		device_attr;
	struct xio_cq			*cqs;
	int				cqs_used;
	int				port_num;
	struct ib_event_handler		event_handler;
	struct kref			kref; /* 1 + #xio_rdma_transport */
};

struct xio_rdma_tasks_slab {
	/* memory for non-rdma send/recv */
	struct kmem_cache		*data_pool;
	char name[32];	/* kmem_cache_create keeps a pointer to the pool's name
			 * Therefore the name must be valid until the pool
			 * is destroyed
			 */
	int				buf_size;
	int				count;
};

struct xio_rdma_tasks_pool {
	struct xio_device		*dev;
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
	struct xio_device		*dev;
	struct ib_qp			*qp;
	struct xio_rdma_mempool		*rdma_mempool;
	struct xio_tasks_pool		*phantom_tasks_pool;
	union xio_fastreg		fastreg;
	struct xio_ev_data		event_data;

	struct list_head		trans_list_entry;

	/*  tasks queues */
	struct list_head		tx_ready_list;
	struct list_head		tx_comp_list;
	struct list_head		in_flight_list;
	struct list_head		rx_list;
	struct list_head		io_list;
	struct list_head		rdma_rd_list;
	struct list_head		rdma_rd_in_flight_list;

	/* rx parameters */
	int				rq_depth;	 /* max rcv allowed  */
	int				actual_rq_depth; /* max rcv allowed  */
	int				rqe_avail;	 /* recv queue elements
							    avail */
	uint16_t			sim_peer_credits;  /* simulates the peer
							    * credits managment
							    * to control nop
							    * sends
							    */
	uint16_t			credits;	  /* the ack this
							     peer sends */
	uint16_t			peer_credits;

	uint16_t			pad;

	/* fast path params */
	int				rdma_in_flight;
	int				sqe_avail;
	enum xio_transport_state	state;

	/* tx parameters */
	size_t				max_send_buf_sz;
	int				kick_rdma_rd;
	int				reqs_in_flight_nr;
	int				rsps_in_flight_nr;
	int				tx_ready_tasks_num;
	int				max_tx_ready_tasks_num;
	int				max_inline_data;
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
	int				num_tasks;
	uint16_t			client_initiator_depth;
	uint16_t			client_responder_resources;

	uint32_t			peer_max_in_iovsz;
	uint32_t			peer_max_out_iovsz;

	/* connection's flow control */
	size_t				alloc_sz;
	size_t				membuf_sz;

	struct xio_transport		*transport;
	struct rdma_event_channel	*cm_channel;
	struct rdma_cm_id		*cm_id;
	struct xio_tasks_pool_cls	initial_pool_cls;
	struct xio_tasks_pool_cls	primary_pool_cls;

	struct xio_rdma_setup_msg	setup_rsp;

	/* for reconnect */
	struct xio_rkey_tbl		*rkey_tbl;
	struct xio_rkey_tbl		*peer_rkey_tbl;

	uint16_t			handler_nesting;

	/* for reconnect */
	uint16_t			rkey_tbl_size;
	uint16_t			peer_rkey_tbl_size;
	uint16_t			pad2[2];

	/* too big to be on stack - use as temporaries */
	union {
		struct xio_msg		dummy_msg;
		struct xio_work_req	dummy_wr;
	};
};

/*
 * The next routines deal with comparing 16 bit unsigned integers
 * and worry about wrap-around (automatic with unsigned arithmetic).
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
const char *xio_ib_wc_status_str(enum ib_wc_status status);
const char *xio_rdma_event_str(enum rdma_cm_event_type event);


/* xio_rdma_datapath.c */
void xio_data_ev_handler(int fd, int events, void *user_context);
int xio_post_recv(struct xio_rdma_transport *rdma_hndl,
		  struct xio_task *task, int num_recv_bufs);
int xio_rdma_rearm_rq(struct xio_rdma_transport *rdma_hndl);
int xio_rdma_send(struct xio_transport_base *transport,
		  struct xio_task *task);
int xio_rdma_poll(struct xio_transport_base *transport,
		  long min_nr, long max_nr,
		  struct timespec *ts_timeout);


/* xio_rdma_management.c */
void xio_rdma_calc_pool_size(struct xio_rdma_transport *rdma_hndl);

/* Should create a xio_memory.h */
void xio_unmap_desc(struct xio_rdma_transport *rdma_hndl,
		    struct xio_rdma_mem_desc *desc,
		    enum dma_data_direction direction);

void xio_unmap_work_req(struct ib_device *ib_dev, struct xio_work_req *xd,
			enum dma_data_direction direction);

int xio_map_work_req(struct ib_device *ib_dev, struct xio_work_req *xd,
		     enum dma_data_direction direction);

int xio_map_desc(struct xio_rdma_transport *rdma_hndl,
		 struct xio_rdma_mem_desc *desc,
		 enum dma_data_direction direction);

void xio_reinit_header(struct xio_rdma_task *rdma_task, size_t len);

int xio_vmsg_to_sgl(struct xio_vmsg *vmsg, struct scatterlist *sgl, int *nents);

int xio_fast_reg_init(enum xio_fast_reg reg, struct xio_fastreg_ops *ops);

void xio_cq_data_callback(struct ib_cq *cq, void *cq_context);

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

void xio_device_down(struct kref *kref);

static inline void xio_device_put(struct xio_device *dev)
{
	kref_put(&dev->kref, xio_device_down);
}

#endif  /* XIO_RDMA_TRANSPORT_H */
