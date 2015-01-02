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

/**
 * @file xio_user.h
 * @brief interface file for accelio user space library
 */

#ifndef XIO_API_H
#define XIO_API_H

#include <stdint.h>
#include <stdlib.h>
#include "xio_predefs.h"
#include "xio_base.h"

#ifdef __cplusplus
extern "C" {
#endif


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
	struct xio_mr		*mr;		/**< rdma specific memory */
						/**< region		  */
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
	struct xio_iovec		header;	    /**< header's io vector  */
	enum xio_sgl_type		sgl_type;   /**< @ref xio_sgl_type   */
	int				pad;	    /**< padding	     */
	/**< union for different scatter gather representations		     */
	union {
		struct xio_sg_table	data_tbl;   /**< data table	     */
		struct xio_sg_iov	data_iov;   /**< iov vector	     */
		struct xio_sg_iovptr	pdata_iov;  /**< iov pointer	     */
	};
};

/**
 * @struct xio_msg
 * @brief  accelio's message definition
 *
 * An object representing a message received from or to be sent to another
 * peer.
 */
struct xio_msg {
	struct xio_vmsg		in;		/**< incoming side of message */
	struct xio_vmsg		out;		/**< outgoing side of message */

	union {
		uint64_t		sn;	/**< unique message serial    */
						/**< number returned by the   */
						/**< library		      */

		struct xio_msg		*request;  /**< responder - attached  */
						   /**< the request           */
	};
	void			*user_context;	/**< private user data        */
						/**< not sent to the peer     */

	enum xio_msg_type	type;		/**< message type	      */
	enum xio_receipt_result	receipt_res;    /**< the receipt result if    */
	uint64_t		flags;		/**< message flags mask       */
	uint64_t		timestamp;	/**< submission timestamp     */

	struct xio_msg_pdata	pdata;		/**< accelio private data     */
	struct xio_msg		*next;          /**< send list of messages    */
};


/**
 *  helper macros to iterate over scatter lists
 */
#define vmsg_sglist(vmsg)					\
		(((vmsg)->sgl_type == XIO_SGL_TYPE_IOV) ?	\
		 (vmsg)->data_iov.sglist :			\
		 (((vmsg)->sgl_type ==  XIO_SGL_TYPE_IOV_PTR) ?	\
		 (vmsg)->pdata_iov.sglist : NULL))

#define vmsg_sglist_nents(vmsg)					\
		 (vmsg)->data_tbl.nents

#define vmsg_sglist_set_nents(vmsg, n)				\
		 (vmsg)->data_tbl.nents = (n)



/*---------------------------------------------------------------------------*/
/* XIO context API							     */
/*---------------------------------------------------------------------------*/
/**
 * @def XIO_INFINITE
 * @brief infinite time flag for event loop
 */
#define XIO_INFINITE			-1

/**
 * @enum xio_ev_loop_events
 * @brief accelio's event dispatcher event types
 */
enum xio_ev_loop_events {
	XIO_POLLIN			= (1<<0),
	XIO_POLLOUT			= (1<<1),
	XIO_POLLET			= (1<<2),  /**< edge-triggered poll */
	XIO_ONESHOT			= (1<<3),
	XIO_POLLRDHUP			= (1<<4),
	XIO_POLLHUP                     = (1<<5),
	XIO_POLLERR                     = (1<<6),
};

/**
 * @typedef xio_ev_handler_t
 * @brief   event loop callback function
 *
 * @param[in] fd	the signaled file descriptor
 * @param[in] events	the event signaled as defined in enum xio_ev_loop_events
 * @param[in] data	user private data
 */
typedef void (*xio_ev_handler_t)(int fd, int events, void *data);

/**
 * @struct xio_poll_params
 * @brief  polling parameters to be used by external dispatcher
 */
struct xio_poll_params {
	int			fd;	 /**< the descriptor	              */
	int			events;	 /**< the types of signals as defined */
					 /**< in enum xio_ev_loop_events      */
	xio_ev_handler_t	handler; /**< event handler that handles the  */
					 /**< event                           */
	void			*data;	 /**< user private data provided to   */
					 /**< the handler                     */
};

/**
 * creates xio context - a context object represent concurrency unit
 *
 * @param[in] ctx_attr context attributes
 * @param[in] polling_timeout_us Polling timeout in microsecs - 0 ignore
 * @param[in] cpu_hint: -1 - don't care, n - core on which the cpu is bounded
 *
 * @returns xio context handle, or NULL upon error
 */
struct xio_context *xio_context_create(struct xio_context_attr *ctx_attr,
				       int polling_timeout_us,
				       int cpu_hint);

/**
 * get context poll parameters to assign to external dispatcher
 *
 * @param[in] ctx	  The xio context handle
 * @param[in] poll_params Structure with polling parameters
 *			  to be added to external dispatcher
 *
 * @returns success (0), or a (negative) error value
 */
int xio_context_get_poll_params(struct xio_context *ctx,
				struct xio_poll_params *poll_params);

/**
 * add external fd to be used by internal dispatcher
 *
 * @param[in] ctx	  The xio context handle
 * @param[in] fd	the file descriptor
 * @param[in] events	the event signaled as defined in
 *			enum xio_ev_loop_events
 * @param[in] handler	event handler that handles the event
 * @param[in] data	user private data
 *
 * @returns success (0), or a (negative) error value
 */
int xio_context_add_ev_handler(struct xio_context *ctx,
			       int fd, int events,
			       xio_ev_handler_t handler,
			       void *data);

/**
 * removes external fd from internal dispatcher
 *
 * @param[in] ctx	The xio context handle
 * @param[in] fd	the file descriptor
 *
 * @returns success (0), or a (negative) error value
 */
int xio_context_del_ev_handler(struct xio_context *ctx,
			       int fd);

/**
 * closes the xio context and free its resources
 *
 * @param[in] ctx		Pointer to the xio context handle
 * @param[in] timeout_ms	The timeout argument specifies the minimum
 *				number of milliseconds that
 *				xio_context_loop_run will block
 *				before exiting
 *
 * @returns success (0), or a (negative) error value
 */
int xio_context_run_loop(struct xio_context *ctx, int timeout_ms);

/**
 * stops context's running event loop
 *
 * @param[in] ctx		Pointer to the xio context handle
 */
void xio_context_stop_loop(struct xio_context *ctx);

/**
 * attempts to read at least min_nr events and up to nr events
 * from the completion queue associated with connection conn
 *
 *
 * @param[in] conn	The xio connection handle
 * @param[in] min_nr	read at least min_nr events
 * @param[in] nr	read no more then nr events
 * @param[in] timeout   specifies the amount of time to wait for events,
 *			where a NULL timeout waits until at least min_nr
 *			events have been seen.
 *
 * @returns On success,  xio_poll_completions() returns the number of events
 *	    read: 0 if no events are available, or less than min_nr if the
 *	    timeout has elapsed.  the failure return -1.
 */
int xio_poll_completions(struct xio_connection *conn,
			 long min_nr, long nr,
			 struct timespec *timeout);

/*---------------------------------------------------------------------------*/
/* library initialization routines					     */
/*---------------------------------------------------------------------------*/

/**
 * Initiates use of the libxio.so by a process.
 *
 * Idempotent routine to initialize the library.
 *
 */
void xio_init(void);

/**
 * Terminates use of the libxio.so by a process.
 *
 * Idempotent routine to shutdown the library.
 *
 */
void xio_shutdown(void);

/*---------------------------------------------------------------------------*/
/* Memory registration/allocation API					     */
/*---------------------------------------------------------------------------*/
/**
 * @struct xio_reg_mem
 * @brief registered memory buffer descriptor
 *        used by all allocation and registration methods
 *        it's the user responsibility to save allocation type and use an
 *        appropriate free method appropriately
 */
struct xio_reg_mem {
	void		*addr;		/**< buffer's memory address	     */
	size_t		length;		/**< buffer's memory length	     */
	struct xio_mr	*mr;		/**< xio specific memory region	     */
	void		*priv;		/**< xio private data		     */
};

/**
 * register/allocate memory for RDMA operations
 *
 * @param[in] addr	memory address or NULL if allocation required.
 * @param[in] length	length of the allocated/registered memory.
 * @param[out] reg_mem	registered memory data structure
 *
 * @returns success (0), or a (negative) error value
 */
int xio_mem_register(void *addr, size_t length, struct xio_reg_mem *reg_mem);

/**
 * unregister registered memory region, create by @ref xio_mem_register
 *
 * @param[in,out] reg_mem - previously registered memory data structure.
 *
 * @returns success (0), or a (negative) error value
 */
int xio_mem_dereg(struct xio_reg_mem *reg_mem);

/**
 * register memory for RDMA operations
 *
 * @param[in] length	length of the allocated memory.
 * @param[out] reg_mem	registered memory data structure
 *
 * @returns success (0), or a (negative) error value
 */
int xio_mem_alloc(size_t length, struct xio_reg_mem *reg_mem);

/**
 * free registered memory region, create by @ref xio_mem_alloc
 *
 * @param[in,out] reg_mem - previously registered memory data structure.
 *
 * @returns success (0), or a (negative) error value
 */
int xio_mem_free(struct xio_reg_mem *reg_mem);

/*---------------------------------------------------------------------------*/
/* XIO memory pool API							     */
/*---------------------------------------------------------------------------*/

/**
 * @enum xio_mempool_flag
 * @brief creation flags for mempool
 */
enum xio_mempool_flag {
	XIO_MEMPOOL_FLAG_NONE			= 0x0000,
	XIO_MEMPOOL_FLAG_REG_MR			= 0x0001,
	XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC	= 0x0002,
	XIO_MEMPOOL_FLAG_NUMA_ALLOC		= 0x0004,
	XIO_MEMPOOL_FLAG_REGULAR_PAGES_ALLOC	= 0x0008,
	/**< do not allocate buffers from larger slabs,
	 *   if the smallest slab is empty
	 */
	XIO_MEMPOOL_FLAG_USE_SMALLEST_SLAB	= 0x0016
};


/**
 * create mempool with NO (!) slabs
 *
 * @param[in] nodeid	  numa node id. -1 if don't care
 * @param[in] flags	  mask of mempool creation flags
 *			  defined (@ref xio_mempool_flag)
 *
 * @returns success (0), or a (negative) error value
 */
struct xio_mempool *xio_mempool_create(int nodeid, uint32_t flags);

/* for backward compatibility - shall be deprecated in the future */

/**
 * add a slab to current set (setup only)
 *
 * @param[in] mpool	  the memory pool
 * @param[in] size	  slab memory size
 * @param[in] min	  initial buffers to allocate
 * @param[in] max	  maximum buffers to allocate
 * @param[in] alloc_quantum_nr	growing quantum
 *
 * @returns success (0), or a (negative) error value
 */
int xio_mempool_add_slab(struct xio_mempool *mpool,
			 size_t size, size_t min, size_t max,
			 size_t alloc_quantum_nr);

/**
 * destroy memory pool
 *
 * @param[in] mpool	  the memory pool
 *
 */
void xio_mempool_destroy(struct xio_mempool *mpool);

/**
 * allocate mempool object from memory pool
 *
 * @param[in] mpool	  the memory pool
 * @param[in] length	  buffer size to allocate
 * @param[in] reg_mem	  registered memory block.
 *
 * @returns success (0), or a (negative) error value
 */
int xio_mempool_alloc(struct xio_mempool *mpool,
		      size_t length, struct xio_reg_mem *reg_mem);

/**
 * free mempool object back to memory pool
 *
 * @param[in] reg_mem	  the allocated mempool object
 *
 */
void xio_mempool_free(struct xio_reg_mem *reg_mem);


#ifdef __cplusplus
}
#endif


#endif /*XIO_API_H */

