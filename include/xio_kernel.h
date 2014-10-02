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
	/* Only sg_table is used in the kernel other are ignored!!!*/
	union {
		struct xio_sg_iov	data_iov;   /**< iov vector	     */
		struct xio_sg_iovptr	pdata_iov;  /**< iov pointer	     */
		struct sg_table		data_tbl;   /**< data table	     */
	};
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
	struct xio_vmsg		in;
	struct xio_vmsg		out;
	union {
		uint64_t		sn;	/* unique message serial number
						 * returned by the library
						 */
		struct xio_msg		*request;  /* on server side - attached
						    * request
						    */
	};
	void			*user_context;	/* for user usage - not sent */

	enum xio_msg_type	type;
	enum xio_receipt_result	receipt_res;
	uint64_t		flags;
	uint64_t		timestamp;	/**< submission timestamp     */

	struct xio_msg_pdata	pdata;		/**< accelio private data     */
	struct xio_msg		*next;          /* internal use */
};


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
 * xio_context - creates xio context - a context is mapped internally to
 *		a cpu core.
 *
 * @flags: Creation flags
 * @loop_ops: User's structure of callbacks operations for this context
 *	      (case flag XIO_LOOP_USER_LOOP)
 * @worker: kthread if flags XIO_LOOP_GIVEN_THREAD can be current
 * @polling_timeout: polling timeout in microsecs - 0 ignore
 * @cpu_hint: -1 (current)
 *
 * RETURNS: xio context handle, or NULL upon error.
 */
struct xio_context *xio_context_create(unsigned int flags,
				       struct xio_loop_ops *loop_ops,
				       struct task_struct *worker,
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


/*---------------------------------------------------------------------------*/
/* XIO debugfs facility							     */
/*---------------------------------------------------------------------------*/
struct dentry *xio_debugfs_root(void);

#endif /*XIO_API_H */

