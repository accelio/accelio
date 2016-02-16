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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "xio_predefs.h"
#include "xio_base.h"

#ifdef __cplusplus
extern "C" {
#endif

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
	enum xio_sgl_type		sgl_type;   /**< sg list type enum   */
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
	union {
		uint64_t		sn;	/**< unique message serial    */
						/**< number returned by the   */
						/**< library		      */

		struct xio_msg		*request;  /**< responder - attached  */
						   /**< the request           */
	};
	struct xio_vmsg		in;		/**< incoming side of message */
	struct xio_vmsg		out;		/**< outgoing side of message */
	struct xio_rdma_msg	rdma;		/**< RDMA source/target       */

	void			*user_context;	/**< private user data        */
						/**< not sent to the peer     */
	enum xio_msg_type	type;		/**< message type	      */
	enum xio_receipt_result	receipt_res;    /**< the receipt result if    */
	uint64_t		flags;		/**< message flags mask       */
	uint64_t		timestamp;	/**< submission timestamp     */
	uint64_t		hints;		/**< hints flags from library */
						/**< to application	      */

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

static inline void vmsg_sglist_set_by_reg_mem(struct xio_vmsg *vmsg,
					      const struct xio_reg_mem *reg_mem)
{
	struct xio_iovec_ex *sgl = vmsg_sglist(vmsg);

	vmsg_sglist_set_nents(vmsg, 1);
	sgl[0].iov_base = reg_mem->addr;
	sgl[0].iov_len = reg_mem->length;
	sgl[0].mr = reg_mem->mr;
}

static inline void *vmsg_sglist_one_base(const struct xio_vmsg *vmsg)
{
	const struct xio_iovec_ex *sgl = vmsg_sglist(vmsg);
	return sgl[0].iov_base;
}

static inline size_t vmsg_sglist_one_len(const struct xio_vmsg *vmsg)
{
	const struct xio_iovec_ex *sgl = vmsg_sglist(vmsg);

	return sgl[0].iov_len;
}

static inline void vmsg_sglist_set_user_context(struct xio_vmsg *vmsg,
						void *user_context)
{
	struct xio_iovec_ex *sgl = vmsg_sglist(vmsg);

	sgl[0].user_context = user_context;
}

static inline void *vmsg_sglist_get_user_context(struct xio_vmsg *vmsg)
{
	struct xio_iovec_ex *sgl = vmsg_sglist(vmsg);

	return sgl[0].user_context;
}

static inline int xio_init_vmsg(struct xio_vmsg *vmsg, unsigned int nents)
{
	vmsg->sgl_type = XIO_SGL_TYPE_IOV;
	return 0;
}

static inline void xio_fini_vmsg(struct xio_vmsg *vmsg)
{
}

static inline void xio_reinit_msg(struct xio_msg *msg)
{
	memset(msg, 0, sizeof(*msg));
}

/*---------------------------------------------------------------------------*/
/* XIO context API							     */
/*---------------------------------------------------------------------------*/
/**
 * @def XIO_INFINITE
 * @brief infinite time flag for event loop
 */
#define XIO_INFINITE			-1

/**
 * @struct xio_context_params
 * @brief context creation parameters structure
 */
struct xio_context_params {
	/**< private user data passed saved on context can be queried/modified */
	/**< via xio_query_context/xio_modify_context			       */
	void			*user_context;

	/**< preallocate and registers rdma inline buffers for send/recv	*/
	int			prealloc_xio_inline_bufs;

	/**< number of connections that this context will handle		*/
	int			max_conns_per_ctx;

	/**< apply memory registration to internal accelio memory pool		*/
        int                     register_internal_mempool;

        int                     reserved;
};


/**
 * creates xio context - a context object represent concurrency unit
 *
 * @param[in] ctx_params: context creation parameters (can be NULL)
 * @param[in] polling_timeout_us: Polling timeout in microsecs - 0 ignore
 * @param[in] cpu_hint: -1 - don't care, n - core on which the cpu is bounded
 *
 * @return xio context handle, or NULL upon error
 */
struct xio_context *xio_context_create(struct xio_context_params *ctx_params,
				       int polling_timeout_us,
				       int cpu_hint);

/**
 * get context poll fd, which can be later passed to an external dispatcher
 *
 * @param[in] ctx	  The xio context handle
 *
 * @return fd (non-negative) on success, or -1 on error. If an error occurs,
 *         call xio_errno function to get the failure reason.
 */
int xio_context_get_poll_fd(struct xio_context *ctx);

/**
 * @enum xio_ev_loop_events
 * @brief accelio's event dispatcher event types
 */
enum xio_ev_loop_events {
	XIO_POLLIN			= (1 << 0),
	XIO_POLLOUT			= (1 << 1),
	XIO_POLLET			= (1 << 2),  /**< edge-triggered poll */
	XIO_ONESHOT			= (1 << 3),
	XIO_POLLRDHUP			= (1 << 4),
	XIO_POLLHUP                     = (1 << 5),
	XIO_POLLERR                     = (1 << 6),
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
 * add external fd to be used by internal dispatcher
 *
 * @param[in] ctx	  The xio context handle
 * @param[in] fd	the file descriptor
 * @param[in] events	the event signaled as defined in
 *			enum xio_ev_loop_events
 * @param[in] handler	event handler that handles the event
 * @param[in] data	user private data
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_context_add_ev_handler(struct xio_context *ctx,
			       int fd, int events,
			       xio_ev_handler_t handler,
			       void *data);
/**
 * change the event event associated with the target file descriptor fd.
 *
 * @param[in] ctx	The xio context handle
 * @param[in] fd	the file descriptor
 * @param[in] events	the event signaled as defined in
 *			enum xio_ev_loop_events
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_context_modify_ev_handler(struct xio_context *ctx,
				  int fd, int events);

/**
 * removes external fd from internal dispatcher
 *
 * @param[in] ctx	The xio context handle
 * @param[in] fd	the file descriptor
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_context_del_ev_handler(struct xio_context *ctx,
			       int fd);

/**
 * run event loop for a specified (possibly infinite) amount of time;
 *
 * this function relies on polling and waiting mechanisms applied to all file
 * descriptors and other event signaling resources (e.g. hw event queues)
 * associated with the context; these mechanisms are continuously invoked
 * until either the specified timeout period expires or the loop is stopped;
 *
 * all events which become pending during that time are handled and the user
 * callbacks are called as appropriate for those events
 *
 * @param[in] ctx		Pointer to the xio context handle
 * @param[in] timeout_ms	number of milliseconds to run the loop
 *				before exiting, if not stopped.
 *				0 : just poll instantly, don't wait
 *				XIO_INFINITE: run continuously until stopped
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_context_run_loop(struct xio_context *ctx, int timeout_ms);

/**
 * stops context's running event loop
 *
 * @param[in] ctx		Pointer to the xio context handle
 */
void xio_context_stop_loop(struct xio_context *ctx);

/**
 * poll for events for a specified (possibly infinite) amount of time;
 *
 * this function relies on polling and waiting mechanisms applied to all file
 * descriptors and other event signaling resources (e.g. hw event queues)
 * associated with the context; these mechanisms are invoked until the first
 * successful polling attempt is made;
 *
 * all events which became pending till then are handled and the user callbacks
 * are called as appropriate for those events; then the functions exits
 *
 * the number of actual events handled originated by any source of events is
 * guaranteed to be limited
 *
 * @param[in] ctx		Pointer to the xio context handle
 * @param[in] timeout_ms	number of milliseconds to wait before exiting,
 *				with or without events handled
 *				0 : just poll instantly, don't wait
 *				XIO_INFINITE: wait for at least a single event
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_context_poll_wait(struct xio_context *ctx, int timeout_ms);


/*---------------------------------------------------------------------------*/
/* library initialization routines					     */
/*---------------------------------------------------------------------------*/

/**
 * Initiates use of the libxio.so by a process. MUST BE CALLED in the "main"
 * method before any accelio methods are called
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
 * register pre allocated memory for RDMA operations
 *
 * @param[in] addr	buffer's memory address
 * @param[in] length	buffer's memory length
 * @param[out] reg_mem	registered memory data structure
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_mem_register(void *addr, size_t length, struct xio_reg_mem *reg_mem);

/**
 * unregister registered memory region, create by @ref xio_mem_register
 *
 * @param[in,out] reg_mem - previously registered memory data structure.
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_mem_dereg(struct xio_reg_mem *reg_mem);

/**
 * extract the rkey of the registered message assisting the
 * arrived request
 *
 * @param[in] reg_mem	registered memory data structure
 * @param[in] req	the incoming request.
 *
 * @return rkey of the registered memory
 */
uint32_t xio_lookup_rkey_by_request(const struct xio_reg_mem *reg_mem,
				    const struct xio_msg *req);

/**
 * extract the rkey of the registered message assisting the
 * arrived response
 *
 * @param[in] reg_mem	registered memory data structure
 * @param[in] rsp	the incoming response.
 *
 * @return rkey of the registered memory
 */
uint32_t xio_lookup_rkey_by_response(const struct xio_reg_mem *reg_mem,
				     const struct xio_msg *rsp);

/**
 * allocate and register memory for RDMA operations
 *
 * @param[in] length	length of required buffer memory.
 * @param[out] reg_mem	registered memory data structure
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_mem_alloc(size_t length, struct xio_reg_mem *reg_mem);

/**
 * free registered memory region, create by @ref xio_mem_alloc
 *
 * @param[in,out] reg_mem - previously registered memory data structure.
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
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
 * @return pointer to xio_mempool object or NULL upon failure
 */
struct xio_mempool *xio_mempool_create(int nodeid, uint32_t flags);

/**
 * add a slab to current set (setup only). This method is not thread safe.
 *
 * @param[in] mpool	  the memory pool
 * @param[in] size	  slab memory size
 * @param[in] min	  initial buffers to allocate
 * @param[in] max	  maximum buffers to allocate
 * @param[in] alloc_quantum_nr	growing quantum
 * @param[in] alignment	  if not 0, the address of the allocated
 *			  memory will be a multiple of alignment, which
 *			  must be a power of two and a multiple
 *			  of sizeof(void *)
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_mempool_add_slab(struct xio_mempool *mpool,
			 size_t size, size_t min, size_t max,
			 size_t alloc_quantum_nr, int alignment);

/**
 * destroy memory pool
 *
 * @param[in] mpool	  the memory pool
 *
 */
void xio_mempool_destroy(struct xio_mempool *mpool);

/**
 * allocate memory buffer from memory pool. This method is thread safe
 *
 * @param[in] mpool	  the memory pool
 * @param[in] length	  buffer size to allocate
 * @param[in] reg_mem	  registered memory data structure
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_mempool_alloc(struct xio_mempool *mpool,
		      size_t length, struct xio_reg_mem *reg_mem);

/**
 * free memory buffer back to memory pool. This method is thread safe.
 *
 * @param[in] reg_mem	  registered memory data structure
 *
 */
void xio_mempool_free(struct xio_reg_mem *reg_mem);

#ifdef __cplusplus
}
#endif

#endif /*XIO_API_H */
