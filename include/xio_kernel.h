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

#define DRV_VERSION "0.1"
#define DRV_RELDATE "2013-Oct-01"

/*---------------------------------------------------------------------------*/
/* preprocessor directives                                                   */
/*---------------------------------------------------------------------------*/
#define XIO_IOVLEN			4
#define XIO_MAX_IOV			256	/* limit message fragments */
#define XIO_VERSION			0x0100


/*---------------------------------------------------------------------------*/
/* enums                                                                     */
/*---------------------------------------------------------------------------*/
/**
 * @enum xio_log_level
 * @brief logging levels
 */
enum xio_log_level {
	XIO_LOG_LEVEL_FATAL,
	XIO_LOG_LEVEL_ERROR,
	XIO_LOG_LEVEL_WARN,
	XIO_LOG_LEVEL_INFO,
	XIO_LOG_LEVEL_DEBUG,
	XIO_LOG_LEVEL_TRACE,
	XIO_LOG_LEVEL_LAST
};

/**
 * @enum xio_sgl_type
 * @brief message data scatter gather type
 */
enum xio_sgl_type {
	XIO_SGL_TYPE_IOV		= 0,
	XIO_SGL_TYPE_IOV_PTR		= 1,
	XIO_SGL_TYPE_SCATTERLIST	= 2,
	XIO_SGL_TYPE_LAST
};

enum xio_session_type {
	XIO_SESSION_CLIENT, /**< represents the active side that initiate    */
			    /**< connection				     */
	XIO_SESSION_REQ = XIO_SESSION_CLIENT, /**< deprecated		     */
	XIO_SESSION_SERVER,  /**< represents the passive side that listen to */
			    /**< incoming connections			     */
	XIO_SESSION_REP = XIO_SESSION_SERVER /**< deprecated		     */
};

enum xio_proto {
	XIO_PROTO_RDMA
};

enum xio_optlevel {
	XIO_OPTLEVEL_ACCELIO,
	XIO_OPTLEVEL_RDMA,
	XIO_OPTLEVEL_TCP,  /* not supported yet */
};

enum xio_optname {
	/* XIO_OPTLEVEL_ACCELIO */
	XIO_OPTNAME_DISABLE_HUGETBL = 0,  /**< disable huge pages allocations */
	XIO_OPTNAME_LOG_FN,		  /**< set user log function	      */
	XIO_OPTNAME_LOG_LEVEL,		  /**< set/get logging level          */
	XIO_OPTNAME_MEM_ALLOCATOR,        /**< set customed allocators hooks  */

	/* XIO_OPTLEVEL_ACCELIO/RDMA/TCP */
	XIO_OPTNAME_MAX_IN_IOVLEN = 100,  /**< set message's max in iovec     */
	XIO_OPTNAME_MAX_OUT_IOVLEN,       /**< set message's max out iovec    */
	XIO_OPTNAME_ENABLE_DMA_LATENCY,   /**< enables the dma latency	      */
	XIO_OPTNAME_ENABLE_RECONNECT,	  /**< enables reconnection	      */
	XIO_OPTNAME_QUEUE_DEPTH,	  /**< application max queued msgs    */

	/* XIO_OPTLEVEL_RDMA/TCP */
	XIO_OPTNAME_ENABLE_MEM_POOL = 200,/**< enables the internal	      */
					  /**< transport memory pool	      */
	XIO_OPTNAME_TRANS_BUF_THRESHOLD,  /**< set/get transport buffer	      */
					  /**< threshold		      */

	/* XIO_OPTLEVEL_RDMA */
	XIO_OPTNAME_RDMA_PLACE_HOLDER = 300,   /**< place holder for rdma opt */

	/* XIO_OPTLEVEL_TCP */
	XIO_OPTNAME_TCP_PLACE_HOLDER = 400,    /**< place holder for tcp opt  */
};

/*  A number random enough not to collide with different errno ranges.       */
/*  The assumption is that errno is at least 32-bit type.                    */
#define XIO_BASE_STATUS 1247689300

enum xio_status {
	XIO_E_SUCCESS			= 0,
	XIO_E_NOT_SUPPORTED		= XIO_BASE_STATUS,
	XIO_E_NO_BUFS			= (XIO_BASE_STATUS + 1),
	XIO_E_CONNECT_ERROR		= (XIO_BASE_STATUS + 2),
	XIO_E_ROUTE_ERROR		= (XIO_BASE_STATUS + 3),
	XIO_E_ADDR_ERROR		= (XIO_BASE_STATUS + 4),
	XIO_E_UNREACHABLE		= (XIO_BASE_STATUS + 5),
	XIO_E_MSG_SIZE			= (XIO_BASE_STATUS + 6),
	XIO_E_PARTIAL_MSG		= (XIO_BASE_STATUS + 7),
	XIO_E_MSG_INVALID		= (XIO_BASE_STATUS + 8),
	XIO_E_MSG_UNKNOWN		= (XIO_BASE_STATUS + 9),
	XIO_E_SESSION_REFUSED		= (XIO_BASE_STATUS + 10),
	XIO_E_SESSION_ABORTED		= (XIO_BASE_STATUS + 11),
	XIO_E_SESSION_DISCONECTED	= (XIO_BASE_STATUS + 12),
	XIO_E_SESSION_REJECTED		= (XIO_BASE_STATUS + 13),
	XIO_E_SESSION_REDIRECTED	= (XIO_BASE_STATUS + 14),
	XIO_E_SESSION_CLOSED		= (XIO_BASE_STATUS + 15),
	XIO_E_BIND_FAILED		= (XIO_BASE_STATUS + 16),
	XIO_E_TIMEOUT			= (XIO_BASE_STATUS + 17),
	XIO_E_IN_PORGRESS		= (XIO_BASE_STATUS + 18),
	XIO_E_INVALID_VERSION		= (XIO_BASE_STATUS + 19),
	XIO_E_NOT_SESSION		= (XIO_BASE_STATUS + 20),
	XIO_E_OPEN_FAILED		= (XIO_BASE_STATUS + 21),
	XIO_E_READ_FAILED		= (XIO_BASE_STATUS + 22),
	XIO_E_WRITE_FAILED		= (XIO_BASE_STATUS + 23),
	XIO_E_CLOSE_FAILED		= (XIO_BASE_STATUS + 24),
	XIO_E_UNSUCCESSFUL		= (XIO_BASE_STATUS + 25),
	XIO_E_MSG_CANCELED		= (XIO_BASE_STATUS + 26),
	XIO_E_MSG_CANCEL_FAILED		= (XIO_BASE_STATUS + 27),
	XIO_E_MSG_NOT_FOUND		= (XIO_BASE_STATUS + 28),
	XIO_E_MSG_FLUSHED		= (XIO_BASE_STATUS + 29),
	XIO_E_MSG_DISCARDED		= (XIO_BASE_STATUS + 30),
	XIO_E_STATE			= (XIO_BASE_STATUS + 31),
	XIO_E_NO_USER_BUFS		= (XIO_BASE_STATUS + 32),
	XIO_E_NO_USER_MR		= (XIO_BASE_STATUS + 33),
	XIO_E_USER_BUF_OVERFLOW		= (XIO_BASE_STATUS + 34),
	XIO_E_REM_USER_BUF_OVERFLOW	= (XIO_BASE_STATUS + 35),
	XIO_E_TX_QUEUE_OVERFLOW		= (XIO_BASE_STATUS + 36),
	XIO_E_USER_OBJ_NOT_FOUND	= (XIO_BASE_STATUS + 37),
	XIO_E_LAST_STATUS		= (XIO_BASE_STATUS + 38)
};

enum xio_msg_flags {
	XIO_MSG_FLAG_REQUEST_READ_RECEIPT = 0x1,  /**< request read receipt    */
	XIO_MSG_FLAG_SMALL_ZERO_COPY	  = 0x2,  /**< zero copy for transfers */
	XIO_MSG_FLAG_IMM_SEND_COMP	  = 0x4   /**< request an immediate    */
						  /**< send completion         */
};

enum xio_session_event {
	XIO_SESSION_REJECT_EVENT,		  /**< session reject event   */
	XIO_SESSION_TEARDOWN_EVENT,		  /**< session teardown event */
	XIO_SESSION_NEW_CONNECTION_EVENT,	  /**< new connection event   */
	XIO_SESSION_CONNECTION_ESTABLISHED_EVENT, /**< connection established */
	XIO_SESSION_CONNECTION_TEARDOWN_EVENT,	  /**< connection teardown event*/
	XIO_SESSION_CONNECTION_CLOSED_EVENT,	  /**< connection closed event*/
	XIO_SESSION_CONNECTION_DISCONNECTED_EVENT, /**< disconnection event   */
	XIO_SESSION_CONNECTION_REFUSED_EVENT,	  /**< connection refused event*/
	XIO_SESSION_CONNECTION_ERROR_EVENT,	  /**< connection error event */
	XIO_SESSION_ERROR_EVENT,		  /**< session error event    */
};

#define XIO_REQUEST			(1 << 1)
#define XIO_RESPONSE			(1 << 2)

#define XIO_MESSAGE			(1 << 4)
#define XIO_ONE_WAY			(1 << 5)

enum xio_msg_type {
	XIO_MSG_TYPE_REQ		= (XIO_MESSAGE | XIO_REQUEST),
	XIO_MSG_TYPE_RSP		= (XIO_MESSAGE | XIO_RESPONSE),
	XIO_MSG_TYPE_ONE_WAY		= (XIO_ONE_WAY | XIO_REQUEST),
};

enum xio_receipt_result {
	XIO_READ_RECEIPT_ACCEPT,
	XIO_READ_RECEIPT_REJECT,
};

enum xio_connection_attr_mask {
	XIO_CONNECTION_ATTR_CTX                 = 1 << 0,
	XIO_CONNECTION_ATTR_USER_CTX		= 1 << 1,
	XIO_CONNECTION_ATTR_PROTO		= 1 << 2,
	XIO_CONNECTION_ATTR_PEER_ADDR		= 1 << 3,
	XIO_CONNECTION_ATTR_LOCAL_ADDR		= 1 << 4
};

enum xio_context_attr_mask {
	XIO_CONTEXT_ATTR_USER_CTX		= 1 << 0
};

enum xio_session_attr_mask {
	XIO_SESSION_ATTR_USER_CTX		= 1 << 0,
	XIO_SESSION_ATTR_SES_OPS		= 1 << 1,
	XIO_SESSION_ATTR_URI			= 1 << 2
};

/*---------------------------------------------------------------------------*/
/* opaque data structures                                                    */
/*---------------------------------------------------------------------------*/
struct xio_context;		/* xio context			*/
struct xio_server;		/* server handle		*/
struct xio_session;		/* session handle		*/
struct xio_connection;		/* connection handle		*/
struct xio_mr;			/* registered memory handle	*/

/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
/*
 * The library user may wish to register their own logging function.
 * By default errors go to stderr.
 * Use xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_LOG_FN, NULL, 0)
 * to restore the default log fn.
 */
typedef void (*xio_log_fn)(const char *file, unsigned line,
			   const char *function, unsigned level,
			   const char *fmt, ...);

/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
/**
 * @struct xio_session_params
 * @brief session creation params
 */
struct xio_session_params {
	enum xio_session_type	type;		 /**< The type of the session */

	uint32_t		initial_sn;      /**< initial serial number   */
						 /**< to start with	      */

	struct xio_session_ops	*ses_ops;	/**< session's ops callbacks  */
	void			*user_context;  /**< session user context     */
	void			*private_data;  /**< private user data snt to */
						/**< server upon new session  */
	size_t			private_data_len; /**< private data length    */
	char			*uri;		  /**< the uri		      */
};


/**
 * @struct xio_session_attr
 * @brief session attributes
 */
struct xio_session_attr {
	struct xio_session_ops	*ses_ops;	/**< session's ops callbacks  */
	void			*user_context;  /**< session user context     */
	char			*uri;		/**< the uri		      */
};

/**
 * @struct xio_connection_attr
 * @brief connection attributes structure
 */
struct xio_connection_attr {
	void			*user_context;  /**< private user context to */
						/**< pass to connection      */
						/**< oriented callbacks      */
	struct xio_context	*ctx;
	int			reserved;
	enum xio_proto		proto;		/**< protocol type	     */
	struct sockaddr_storage	peer_addr;	/**< address of peer	      */
	struct sockaddr_storage	local_addr;	/**< address of local	      */
};

/**
 * @struct xio_context_attr
 * @brief context attributes structure
 */
struct xio_context_attr {
	void			*user_context;  /**< private user context to */
						/**< pass to connection      */
						/**< oriented callbacks      */
};

struct xio_buf {
	void			*addr;
	size_t			length;
	struct xio_mr		*mr;
};

struct xio_iovec {
	void			*iov_base;
	size_t			iov_len;
};

/* In user space xio_iovec and this structure differ */
struct xio_iovec_ex {
	void			*iov_base;	/**< base address */
	size_t			iov_len;	/**< base length  */
	void			*user_context;	/**< private user data    */
};

/**
 * @struct xio_msg_pdata
 * @brief message private data structure used internally by the library
 */
struct xio_msg_pdata {
	struct xio_msg		*next;		/**< internal library usage   */
	struct xio_msg		**prev;		/**< internal library usage   */
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
	enum xio_msg_type	type;
	int		        more_in_batch;	/* more messages are expected */
	int			flags;
	enum xio_receipt_result	receipt_res;
	uint64_t		timestamp;	/**< submission timestamp     */
	void			*user_context;	/* for user usage - not sent */
	struct xio_msg_pdata	pdata;		/**< accelio private data     */
	struct xio_msg		*next;          /* internal use */
};

/**
 * @struct xio_session_event_data
 * @brief  session event callback parameters
 */
struct xio_session_event_data {
	struct xio_connection	*conn;		    /**< connection object   */
	void			*conn_user_context; /**< user context        */
	enum xio_session_event	event;		    /**< the specific event  */
	enum xio_status		reason;		    /**< elaborated message  */
	void			*private_data;	    /**< user private data   */
						    /**< relevant to reject  */
	size_t			private_data_len;   /**< private length      */
};

struct xio_new_session_req {
	char			*uri;		  /* the uri */
	void			*private_data;	  /* private data form client */
	uint16_t		uri_len;	  /* uri length */
	uint16_t		private_data_len; /* private data length */
	enum xio_proto		proto;
	struct sockaddr_storage	src_addr;
};

struct xio_new_session_rsp {
	void			*private_data;	/* private data form server */
	uint16_t		private_data_len;  /* private data length */
	uint16_t		reserved[3];
};

/**
 * event loop callback function
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
 *  user provided callback functions to handle session events
 */
struct xio_session_ops {
	/* generic error event notification */
	int (*on_session_event)(struct xio_session *session,
			struct xio_session_event_data *data,
			void *cb_user_context);

	/* new session notification */
	int (*on_new_session)(struct xio_session *session,
			struct xio_new_session_req *req,
			void *cb_user_context);

	/* session established notification */
	int (*on_session_established)(struct xio_session *session,
			struct xio_new_session_rsp *rsp,
			void *cb_user_context);

	/* send completion notification */
	int (*on_msg_send_complete)(struct xio_session *session,
			struct xio_msg *msg,
			void *conn_user_context);

	/* message arrived */
	int (*on_msg)(struct xio_session *session,
			struct xio_msg *msg,
			int more_in_batch,
			void *conn_user_context);

	/* one way message delivered */
	int (*on_msg_delivered)(struct xio_session *session,
			struct xio_msg *msg,
			int more_in_batch,
			void *conn_user_context);

	/* message error */
	int (*on_msg_error)(struct xio_session *session,
			enum xio_status error,
			struct xio_msg  *msg,
			void *conn_user_context);

	/* requester's message cancelation notification */
	int (*on_cancel)(struct xio_session *session,
			struct xio_msg  *msg,
			enum xio_status result,
			void *conn_user_context);

	/* responder's message cancelation notification */
	int (*on_cancel_request)(struct xio_session *session,
				 struct xio_msg  *msg,
				 void *conn_user_context);

	/* notify the user to assign a data buffer for incoming read */
	int (*assign_data_in_buf)(struct xio_msg *msg,
				  void *cb_user_context);

	 /* sender's send completion notification - one way message only */
	int (*on_ow_msg_send_complete)(struct xio_session *session,
				       struct xio_msg *msg,
				       void *conn_user_context);
};

/**
 *  @struct xio_mem_allocator
 *  @brief user provided customed allocator hook functions for library usage
 */
struct xio_mem_allocator {
	void	*user_context;			/**< user specific context */

	/**
	 *  allocates block of memory
	 *
	 *  @param[in] size		        size in bytes to allocate
	 *  @param[in] user_context		user specific context
	 *
	 *  @returns pointer to allocated memory or NULL if allocate fails
	 */
	void * (*allocate)(size_t size, void *user_context);

	/**
	 *  allocates aligned block of memory and zero it content
	 *
	 *  @param[in] boundary			memory size will be a multiple
	 *					of boundary, which must be a
	 *					power of two and a multiple of
	 *					sizeof(void *)
	 *  @param[in] size			size in  bytes to allocate
	 *  @param[in] user_context		user specific context
	 *
	 *  @returns pointer to allocated memory or NULL if allocate fails
	 */
	void *  (*memalign)(size_t boundary, size_t size, void *user_context);

	/**
	 *  deallocates block of memory
	 *
	 *  @param[in] ptr			pointer to allocated block
	 *  @param[in] user_context		user specific context
	 *
	 */
	void   (*free)(void *ptr, void *user_context);

	/**
	 *  allocates block of memory using huge page
	 *
	 *  @param[in] size			block size to allocate
	 *  @param[in] user_context		user specific context
	 *
	 *  @returns pointer to allocated memory or NULL if allocate fails
	 */
	void * (*malloc_huge_pages)(size_t size, void *user_context);

	/**
	 *  deallocates block of memory previously allocated by
	 *  malloc_huge_pages
	 *
	 *  @param[in] ptr			pointer to allocated block
	 *  @param[in] user_context		user specific context
	 *
	 *  @returns pointer to block or NULL if allocate fails
	 */
	void   (*free_huge_pages)(void *ptr, void *user_context);
};

/**
 *  user provided callback functions to handle session events
 */
struct xio_server_ops {
	/* generic error event notification */
	int (*on_session_event)(struct xio_session *session,
			struct xio_session_event_data *data,
			void *cb_user_context);

	/* new session notification */
	int (*on_new_session)(struct xio_session *session,
			struct xio_new_session_req *req,
			void *cb_user_context);

	/* send completion notification */
	int (*on_msg_send_complete)(struct xio_session *session,
			struct xio_msg *msg,
			void *cb_user_context);

	/* message receive completion */
	int (*on_msg)(struct xio_session *session,
			struct xio_msg *msg,
			int more_in_batch,
			void *cb_user_context);

	/* one way message delivered */
	int (*on_msg_delivered)(struct xio_session *session,
			struct xio_msg *msg,
			int more_in_batch,
			void *conn_user_context);

	/* message error */
	int (*on_msg_error)(struct xio_session *session,
			enum xio_status error,
			struct xio_msg  *msg,
			void *cb_user_context);

	/* notify the user to assign a data buffer for incoming read */
	int (*assign_data_in_buf)(struct xio_msg *msg,
				  void *cb_user_context);
};

/*---------------------------------------------------------------------------*/
/* Memory registration API                                                   */
/*---------------------------------------------------------------------------*/
/**
 * xio_reg_mr - register memory region for RDMA operations.
 *
 * @buf: Pre-allocated memory aimed to store the data
 * @len: The pre allocated memory length.
 *
 * RETURNS: success (0), or a (negative) error value.
 */
struct xio_mr *xio_reg_mr(void *buf, size_t len);

/**
 * xio_dereg_mr - unregister registered memory region
 *
 * @p_mr: Pointer to registered memory handle.
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_dereg_mr(struct xio_mr **p_mr);

/*---------------------------------------------------------------------------*/
/* Memory allocators API						     */
/*---------------------------------------------------------------------------*/
/**
 * xio_alloc - allocate and register memory region for RDMA operations.
 *
 * @len: The required memory length.
 *
 * RETURNS: success (0), or a (negative) error value.
 */
struct xio_buf *xio_alloc(size_t len);

/**
 * xio_free - free and unregister registered memory region
 *
 * @p_mr: Pointer to the alloced buffer.
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_free(struct xio_buf **buf);

/*---------------------------------------------------------------------------*/
/* XIO errors		                                                     */
/*---------------------------------------------------------------------------*/
/**
 * xio_strerror - resolves system errors and XIO errors to human-readable
 * string.
 *
 * @errnum: The xio error code.
 *
 */
const char *xio_strerror(int errnum);

/**
 * xio_errno - return last xio error
 *
 */
int xio_errno(void);

/**
 * xio_session_event_str - return session event string
 * string.
 *
 * @event: The session event.
 *
 */
const char *xio_session_event_str(enum xio_session_event event);

/*---------------------------------------------------------------------------*/
/* XIO conncurrency (a.k.a context) initialization and termination	     */
/*---------------------------------------------------------------------------*/

#define XIO_LOOP_USER_LOOP	0
#define XIO_LOOP_GIVEN_THREAD	1
#define XIO_LOOP_TASKLET	2
#define XIO_LOOP_WORKQUEUE	3

/*---------------------------------------------------------------------------*/
/* xio_ctx_create                                                            */
/*---------------------------------------------------------------------------*/
/**
 * xio_context - creates xio context - a context is mapped internaly to
 *		   a cpu core./
 *
 * @flags: Creatation flags
 * @loop_ops: User's structure of callbacks operations for this context (case flag XIO_LOOP_USER_LOOP)
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

/**
 * closes the xio context and free its resources
 *
 * @param[in] ctx	Pointer to the xio context handle
 *
 */
void xio_context_destroy(struct xio_context *ctx);

/**
 * modify context parameters
 *
 * @param[in] ctx	The xio context handle
 * @param[in] attr	The context attributes structure
 * @param[in] attr_mask Attribute mask to modify
 *
 * @returns success (0), or a (negative) error value
 */
int xio_modify_context(struct xio_context *ctx,
		       struct xio_context_attr *attr,
		       int attr_mask);

/**
 * get context attributes
 *
 * @param[in] ctx	The xio context handle
 * @param[in] attr	The context attributes structure
 * @param[in] attr_mask Attribute mask to query
 *
 * @returns success (0), or a (negative) error value
  *
 */
int xio_query_context(struct xio_context *ctx,
		      struct xio_context_attr *attr,
		      int attr_mask);

/*---------------------------------------------------------------------------*/
/* XIO session API                                                           */
/*---------------------------------------------------------------------------*/
/**
 * creates new requester session
 *
 * @param[in] params	session creations parameters
  *
 * @returns xio session context, or NULL upon error
 */
struct xio_session *xio_session_create(struct xio_session_params *params);

/**
 * teardown an opened session
 *
 * @param[in] session		The xio session handle
 *
 * @returns success (0), or a (negative) error value
 */
int xio_session_destroy(struct xio_session *session);

/**
 * query session parameters
 *
 * @param[in] session	The xio session handle
 * @param[in] attr	The session attributes structure
 * @param[in] attr_mask attribute mask to query
 *
 * @returns success (0), or a (negative) error value
 */
int xio_query_session(struct xio_session *session,
		      struct xio_session_attr *attr,
		      int attr_mask);

/**
 * modify session parameters
 *
 * @param[in] session	The xio session handle
 * @param[in] attr	The session attributes structure
 * @param[in] attr_mask attribute mask to query
 *
 * @returns success (0), or a (negative) error value
 */
int xio_modify_session(struct xio_session *session,
		       struct xio_session_attr *attr,
		       int attr_mask);

/**
 * xio_connect - create connection handle.
 *
 * @session: The xio session handle.
 * @ctx: the xio context handle.
 * @conn_idx: connection index greater then 0. if 0 - auto count.
 * @out_if: bounded outgoing interface address
 * @conn_user_context: Private data pointer to pass to each connection callback
 *
 * RETURNS: xio session context, or NULL upon error.
 */
struct xio_connection *xio_connect(
				struct xio_session  *session,
				struct xio_context  *ctx,
				uint32_t conn_idx,
				const char *out_if,
				void *conn_user_context);

/**
 * xio_disconnect - teardown an opened connection.
 *
 * @conn: The xio connection handle.
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_disconnect(struct xio_connection *conn);

/**
 * free connection object
 *
 * @param[in] conn	The xio connection handle
 *
 * @returns success (0), or a (negative) error value
 */
int xio_connection_destroy(struct xio_connection *conn);

/**
 * modify connection parameters
 *
 * @param[in] conn	The xio connection handle
 * @param[in] attr	The connection attributes structure
 * @param[in] attr_mask Attribute mask to modify
 *
 * @returns success (0), or a (negative) error value
 */
int xio_modify_connection(struct xio_connection *conn,
		       struct xio_connection_attr *attr,
		       int attr_mask);
/**
 * query connection parameters
 *
 * @param[in] conn	The xio connection handle
 * @param[in] attr	The connection attributes structure
 * @param[in] attr_mask attribute mask to modify
 *
 * @returns success (0), or a (negative) error value
 */
int xio_query_connection(struct xio_connection *conn,
		         struct xio_connection_attr *attr,
			 int attr_mask);

/**
 * xio_send_request - send request.
 *
 * @conn: The xio connection handle.
 * @req: request to send
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_send_request(struct xio_connection *conn,
		     struct xio_msg *req);

/**
 * xio_release_response - release message resources back to xio.
 *
 * Note: the message is allocated by the application and is not freed.
 *	 by this function.
 *
 * @rsp: The released response
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_release_response(struct xio_msg *rsp);

/**
 * xio_send_msg - send one way message to remote peer.
 *
 * @conn: The xio connection handle.
 * @req: request to send
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_send_msg(struct xio_connection *conn,
		 struct xio_msg *msg);

/**
 * xio_release_msg - release one way message resources back to xio.
 *
 * Note: the message is allocated by the application and is not freed.
 *	 by this function.
 *
 * @rsp: The released response
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_release_msg(struct xio_msg *rsp);


/*---------------------------------------------------------------------------*/
/* XIO server API							     */
/*---------------------------------------------------------------------------*/

/**
 * xio_bind - open a server.
 *
 * @ctx: the xio context handle.
 * @ops: structure of server's event handlers
 * @uri: uri to connect or to bind
 * @src_port: returned listen port in host order, can be NULL if not needed
 * @flags: message related flags as defined in xio_msg_flags
 * @cb_user_context: Private data pointer to pass to each callback
 *
 * RETURNS: xio server context, or NULL upon error.
 */
struct xio_server *xio_bind(struct xio_context *ctx,
			    struct xio_session_ops *ops,
			    const char *uri,
			    uint16_t *src_port,
			    uint32_t flags,
			    void *cb_user_context);

/**
 * xio_unbind - teardown a server.
 *
 * @server: The xio server handle.
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_unbind(struct xio_server *server);

/**
 * accept new session or "light redirect" it to anther thread
 *
 * @param[in] session		The xio session handle
 * @param[in] portals_array	string array of alternative portals to the
 *				resource in form of "rdma://host:port"
 *				"rdma://127.0.0.1:1234"
 * @param[in] portals_array_len The string array length
 * @param[in] private_data	References a user-controlled data buffer
 *			        The contents of the buffer are copied and
 *			        transparently passed to the remote side as
 *			        part of the communication request. May be
 *			        NULL if user_context is not required
 * @param[in] private_data_len	Specifies the size of the user-controlled
 *				data buffer
 *
 * @returns	success (0), or a (negative) error value
 */
int xio_accept(struct xio_session *session,
	       const char **portals_array,
	       size_t portals_array_len,
	       void *private_data,
	       size_t private_data_len);

/**
 * xio_redirect - redirect connecting session to connect to
 *		     alternative resources
 *
 * @session: The xio session handle.
 * @portals_array: String array of alternative portals to the resource
 *		in form of "rdma://host:port" "rdma://127.0.0.1:1234"
 * @portals_array_len: The string array length
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_redirect(struct xio_session *session,
				  const char **portals_array,
				  size_t portals_array_len);

/**
 * reject a connecting session
 *
 *
 * @param[in] session		The xio session handle
 * @param[in] reason		Reason for rejection
 * @param[in] private_data	References a user-controlled data buffer
 *				The contents of the buffer are copied and
 *				transparently passed to the peer as part
 *				of the communication request. May be NULL
 *				if user_context is not required
 * @param[in] private_data_len	Specifies the size of the user-controlled
 *				data buffer
 *
 * @return success (0), or a (negative) error value
 */
int xio_reject(struct xio_session *session,
	       enum xio_status reason,
	       void *private_data,
	       size_t private_data_len);

/**
 * xio_send_response - send response.
 *
 * @rsp: response to send
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_send_response(struct xio_msg *rsp);

/**
 * set xio's configuration tuning option
 *
 * @param[in] xio_obj	Pointer to xio object or NULL
 * @param[in] level	The level at which the option is
 *			defined (@ref xio_optlevel)
 * @param[in] optname	The option for which the value is to be set.
 *			The optname parameter must be a socket option
 *			defined within the specified level, or behavior
 *			is undefined (@ref xio_optname)
 * @param[in] optval	A pointer to the buffer in which the value
 *			for the requested option is specified
 * @param[in] optlen	The size, in bytes, of the buffer pointed to by
 *			the optval parameter
 *
 * @returns success (0), or a (negative) error value
 */
int xio_set_opt(void *xio_obj, int level, int optname,
		const void *optval, int optlen);

/**
 * set xio's configuration tuning option
 *
 * @param[in] xio_obj	  Pointer to xio object or NULL
 * @param[in] level	  The level at which the option is
 *			  defined (@ref xio_optlevel)
 * @param[in] optname	  The option for which the value is to be set.
 *			  The optname parameter must be a socket option
 *			  defined within the specified level, or behavior
 *			  is undefined (@ref xio_optname)
 * @param[in,out] optval  A pointer to the buffer in which the value
 *			  for the requested option is specified
 * @param[in,out] optlen  The size, in bytes, of the buffer pointed to by
 *			  the optval parameter
 *
 * @returns success (0), or a (negative) error value
 */
int xio_get_opt(void *xio_obj, int level, int optname,
		void *optval, int *optlen);


/**
 * attempts to read at least min_nr events and up to nr events
 * from the completion queue assiociated with connection conn
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
/* XIO default event loop API						     */
/*									     */
/* Note: xio provides default muxer implementation around epoll.	     */
/* users are encouraged to utilize their own implementations and provides    */
/* appropriate services to xio via the xio's context open interface.	     */
/*---------------------------------------------------------------------------*/

int xio_context_run_loop(struct xio_context *ctx);

void xio_context_stop_loop(struct xio_context *ctx);

int xio_context_add_event(struct xio_context *ctx, struct xio_ev_data *data);

struct dentry *xio_debugfs_root(void);

#endif /*XIO_API_H */

