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
#ifndef XIO_API_H
#define XIO_API_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/llist.h>
#include <linux/debugfs.h>
#include <linux/scatterlist.h>
#include "xio_base.h"

#define DRV_VERSION "0.1"
#define DRV_RELDATE "2013-Oct-01"

/**
 * @struct xio_reg_mem
 * @brief registered memory buffer descriptor
 *        (Compatibility with user mode)
 */
struct xio_reg_mem {
	void		*addr;		/**< buffer's memory address	     */
	size_t		length;		/**< buffer's memory length	     */
};

/*---------------------------------------------------------------------------*/
/* message data type							     */
/*---------------------------------------------------------------------------*/
/**
 * @struct xio_iovec_ex
 * @brief extended IO vector
 */
struct xio_iovec_ex {
	void			*iov_base;	/**< base address */
	size_t			iov_len;	/**< base length  */
	void			*user_context;	/**< private user data    */
};

/**
 * @struct xio_sg_iov
 * @brief scatter gather iovec vector data structure
 */
struct xio_sg_iov {
	uint32_t			nents;	    /**< number of entries */
	uint32_t			max_nents;  /**< maximum entries   */
						    /**< allowed	   */

	struct xio_iovec_ex		sglist[XIO_IOVLEN]; /**< scatter vec */

};

/**
 * @struct xio_sg_iovptr
 * @brief scatter gather iovec pointer data structure
 */
struct xio_sg_iovptr {
	uint32_t			nents;	    /**< number of entries */
	uint32_t			max_nents;  /**< maximum entries   */
						    /**< allowed	   */

	struct xio_iovec_ex		*sglist;    /**< scatter list	   */
};

/**
 * @struct xio_vmsg
 * @brief message sub element type
 */
struct xio_vmsg {
	struct xio_iovec	header;	    /**< header's io vector  */
	enum xio_sgl_type	sgl_type;
	int			pad;
	struct sg_table		data_tbl;   /**< data table	     */
	void			*user_context;	/**< private user data */
};

/**
 * @struct xio_msg
 * @brief  accelio's message definition
 *
 * An object representing a message received from or to be sent to another
 * peer.
 */
struct xio_msg {
	union {
		uint64_t		sn;	/* unique message serial number
						 * returned by the library
						 */
		struct xio_msg		*request;  /* on server side - attached
						    * request
						    */
	};
	struct xio_vmsg		in;		/**< incoming side of message */
	struct xio_vmsg		out;
	struct xio_rdma_msg	rdma;		/**< RDMA source/target       */
	void			*user_context;	/* for user usage - not sent */

	enum xio_msg_type	type;
	enum xio_receipt_result	receipt_res;
	uint64_t		flags;
	uint64_t		timestamp;	/**< submission timestamp     */
	uint64_t		hints;		/**< hints flags from library */
						/**< to application	      */

	struct xio_msg_pdata	pdata;		/**< accelio private data     */
	struct xio_msg		*next;          /* internal use */
};

#define vmsg_sglist_nents(vmsg)					\
		 (vmsg)->data_tbl.nents

#define vmsg_sglist_set_nents(vmsg, n)				\
		 (vmsg)->data_tbl.nents = (n)

static inline void vmsg_sglist_set_by_reg_mem(struct xio_vmsg *vmsg,
					      const struct xio_reg_mem *reg_mem)
{
	BUG_ON(vmsg->sgl_type != XIO_SGL_TYPE_SCATTERLIST);
	vmsg_sglist_set_nents(vmsg, 1);
	sg_init_one(vmsg->data_tbl.sgl, reg_mem->addr, reg_mem->length);
}

static inline void *vmsg_sglist_one_base(const struct xio_vmsg *vmsg)
{
	struct scatterlist *sg = vmsg->data_tbl.sgl;

	return sg_virt(sg);
}

static inline size_t vmsg_sglist_one_len(const struct xio_vmsg *vmsg)
{
	const struct scatterlist *sg = vmsg->data_tbl.sgl;

	return sg->length;
}

static inline void vmsg_sglist_set_user_context(struct xio_vmsg *vmsg,
						void *user_context)
{
	vmsg->user_context = user_context;
}

static inline void *vmsg_sglist_get_user_context(struct xio_vmsg *vmsg)
{
	return vmsg->user_context;
}

static inline int xio_init_vmsg(struct xio_vmsg *vmsg, unsigned int nents)
{
	int ret;

	vmsg->sgl_type = XIO_SGL_TYPE_SCATTERLIST;
	ret = sg_alloc_table(&vmsg->data_tbl, nents, GFP_KERNEL);
	vmsg_sglist_set_nents(vmsg, 0);

	return ret;
}

static inline void xio_fini_vmsg(struct xio_vmsg *vmsg)
{
	sg_free_table(&vmsg->data_tbl);
}

static inline void xio_init_vmsg_from_sg_table(struct xio_vmsg *vmsg,
					       const struct sg_table *tbl)
{
	vmsg->sgl_type = XIO_SGL_TYPE_SCATTERLIST;
	vmsg->data_tbl = *tbl;
	vmsg_sglist_set_nents(vmsg, 0);
}

static inline void xio_reinit_msg(struct xio_msg *msg)
{
	const struct sg_table in_tbl = msg->in.data_tbl;
	const struct sg_table out_tbl = msg->out.data_tbl;

	memset(msg, 0, sizeof(*msg));
	xio_init_vmsg_from_sg_table(&msg->in, &in_tbl);
	xio_init_vmsg_from_sg_table(&msg->out, &out_tbl);
}

/*---------------------------------------------------------------------------*/
/* XIO context API							     */
/*---------------------------------------------------------------------------*/
#define XIO_LOOP_USER_LOOP	0
#define XIO_LOOP_GIVEN_THREAD	1
#define XIO_LOOP_TASKLET	2
#define XIO_LOOP_WORKQUEUE	3

/**
 * @typedef xio_ev_handler_t
 * @brief   event loop callback function
 *
 * @param[in] data	user private data
 */
typedef void (*xio_ev_handler_t)(void *data);

struct xio_ev_data {
	xio_ev_handler_t handler;
	void		 *data;
	union {
		struct llist_node  ev_llist;
		struct work_struct work;
	};
	volatile unsigned long int states; /* xio private data */
};

/**
 *  user provided function for adding an event to the event loop
 *  to be processed on ctx worker context
 */
struct xio_loop_ops {
	void *ev_loop;
	int (*run)(void *loop);
	void (*stop)(void *loop);
	int (*add_event)(void *loop, struct xio_ev_data *data);
};

/**
 * @struct xio_context_params
 * @brief context creation parameters structure
 */
struct xio_context_params {

	unsigned int		flags;		/**< creation flags */

	/* User's structure of callbacks operations for this context
	 * (case flag XIO_LOOP_USER_LOOP)
	 */
	struct xio_loop_ops	*loop_ops;

	/* kthread if flags XIO_LOOP_GIVEN_THREAD can be current
	*/
	struct task_struct	*worker;

	/**< private user data passed saved on context can be queried/modified */
	/**< via xio_query_context/xio_modify_context			       */
	void			*user_context;

	/**< preallocate and registers rdma inline buffers for send/recv	*/
	int			prealloc_xio_inline_bufs;

	/**< number of connections that this context will handle		*/
	int			max_conns_per_ctx;

	/** depth of receive queue in RDMA.
	* pass 0 if want the depth to remain default (XIO_MAX_IOV + constant) */
	int         rq_depth;
};

/**
 * xio_context - creates xio context - a context is mapped internally to
 *		a cpu core.
 *
 * @ctx_params: context creation creation flags
 * @polling_timeout: polling timeout in microsecs - 0 ignore
 * @cpu_hint: -1 (current)
 *
 * RETURNS: xio context handle, or NULL upon error.
 */
struct xio_context *xio_context_create(
		struct xio_context_params  *ctx_params,
		int polling_timeout,
		int cpu_hint);

/*---------------------------------------------------------------------------*/
/* XIO default event loop API						     */
/*									     */
/* Note: xio provides default muxer implementation around epoll.	     */
/* users are encouraged to utilize their own implementations and provides    */
/* appropriate services to xio via the xio's context open interface.	     */
/*---------------------------------------------------------------------------*/

int xio_context_run_loop(struct xio_context *ctx);

void xio_context_stop_loop(struct xio_context *ctx);

int xio_context_add_event(struct xio_context *ctx, struct xio_ev_data *data);

void xio_destroy_context_continue(struct work_struct *work);
/*---------------------------------------------------------------------------*/
/* XIO debugfs facility							     */
/*---------------------------------------------------------------------------*/
struct dentry *xio_debugfs_root(void);

#endif /*XIO_API_H */
