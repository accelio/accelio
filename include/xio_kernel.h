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

#define DRV_VERSION "0.1"
#define DRV_RELDATE "2013-Oct-01"

/*---------------------------------------------------------------------------*/
/* preprocessor directives                                                   */
/*---------------------------------------------------------------------------*/
#define XIO_MAX_IOV			256	/* limit message fragments */
#define XIO_VERSION			0x0100


/*---------------------------------------------------------------------------*/
/* enums                                                                     */
/*---------------------------------------------------------------------------*/
/**
 * @enum xio_log_leve
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
};

enum xio_optname {
	XIO_OPTNAME_ENABLE_MEM_POOL,	  /**< enables the internal rdma      */
					  /**< memory pool		      */

	XIO_OPTNAME_DISABLE_HUGETBL,	  /**< disable huge pages allocations */
	XIO_OPTNAME_LOG_FN,		  /**< set user log function	      */
	XIO_OPTNAME_LOG_LEVEL,		  /**< set/get logging level          */
	XIO_OPTNAME_ENABLE_DMA_LATENCY,   /**< enables the dma latency        */

	XIO_OPTNAME_RDMA_BUF_THRESHOLD,   /**< set/get rdma buffer threshold  */
	XIO_OPTNAME_MEM_ALLOCATOR         /**< set customed allocators hooks  */
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
	XIO_E_BIND_FAILED		= (XIO_BASE_STATUS + 15),
	XIO_E_TIMEOUT			= (XIO_BASE_STATUS + 16),
	XIO_E_IN_PORGRESS		= (XIO_BASE_STATUS + 17),
	XIO_E_INVALID_VERSION		= (XIO_BASE_STATUS + 18),
	XIO_E_NOT_SESSION		= (XIO_BASE_STATUS + 19),
	XIO_E_OPEN_FAILED		= (XIO_BASE_STATUS + 20),
	XIO_E_READ_FAILED		= (XIO_BASE_STATUS + 21),
	XIO_E_WRITE_FAILED		= (XIO_BASE_STATUS + 22),
	XIO_E_CLOSE_FAILED		= (XIO_BASE_STATUS + 23),
	XIO_E_UNSUCCESSFUL		= (XIO_BASE_STATUS + 24),
	XIO_E_MSG_CANCELED		= (XIO_BASE_STATUS + 25),
	XIO_E_MSG_CANCEL_FAILED		= (XIO_BASE_STATUS + 26),
	XIO_E_MSG_NOT_FOUND		= (XIO_BASE_STATUS + 27),
	XIO_E_MSG_FLUSHED		= (XIO_BASE_STATUS + 28)
};

enum xio_session_flags {
	XIO_SESSION_FLAG_DONTQUEUE	= 0x001, /*  do not queue messages */
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

#define XIO_REQUEST			2
#define XIO_RESPONSE			4

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
	XIO_CONNECTION_ATTR_USER_CTX		= 1 << 1
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
struct xio_session_attr {
	struct xio_session_ops	*ses_ops;	/* session's ops callbacks */
	void			*user_context;  /* sent to server upon new
						   session */
	char			*uri;		  /**< the uri		   */
	size_t			user_context_len;
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

/* In user space these struct xio_iovec and this struct differ */
struct xio_iovec_ex {
	void			*iov_base;
	size_t			iov_len;
};

/**
 * @struct xio_msg_pdata
 * @brief message private data structure used internaly by the library
 */
struct xio_msg_pdata {
	struct xio_msg		*next;          /**< internal library usage   */
	struct xio_msg		**prev;		/**< internal library usage   */
};

struct xio_vmsg {
	struct xio_iovec	header;		/* header's iovec */
	size_t			data_iovlen;	/* number of items in vector  */
	struct xio_iovec_ex	data_iov[XIO_MAX_IOV];
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
	int			status;
	int			flags;
	enum xio_receipt_result	receipt_res;
	uint64_t		timestamp;	/**< submission timestamp     */
	int			reserved;
	void			*user_context;	/* for user usage - not sent */
	struct xio_msg_pdata	pdata;		/**< accelio private data     */
	struct xio_msg		*next;          /* internal use */
};

/**
 * @struct xio_session_event_data
 * @brief  session enent callback parmaters
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
	void			*user_context;	  /* private data form client */
	uint16_t		uri_len;	  /* uri length */
	uint16_t		user_context_len; /* private data length */
	enum xio_proto		proto;
	struct sockaddr_storage	src_addr;
};

struct xio_new_session_rsp {
	void			*user_context;	/* private data form server */
	uint16_t		user_context_len;  /* private data length */
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
 * @param[in] type	The type of the session
 * @param[in] attr	Structure of session attributes
 * @param[in] uri	uri to connect
 * @param[in] initial_sn Initial serial number to start with
 * @param[in] flags	 Session related flags as defined in xio_session_flags
 * @param[in] cb_user_context Private data pointer to pass to each session
 *			       callback
 *
 * @returns xio session context, or NULL upon error
 */
struct xio_session *xio_session_create(
		enum xio_session_type type,
		struct xio_session_attr *attr,
		const char *uri,
		uint32_t initial_sn,
		uint32_t flags,
		void *cb_user_context);

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
 * xio_get_connection - return connection handle on server.
 *
 * @session: The xio session handle.
 * @ctx: the xio context handle.
 *
 * RETURNS: xio session context, or NULL upon error.
 */
struct xio_connection *xio_get_connection(struct xio_session  *session,
					  struct xio_context  *ctx);

/**
 * xio_accept - accept new session or "light redirect" it to anther thread
 *
 * @session: The xio session handle.
 * @portals_array: String array of alternative portals to the resource
 *		in form of "rdma://host:port" "rdma://127.0.0.1:1234"
 * @portals_array_len: The string array length
 * @user_context: References a user-controlled data buffer. The contents of
 *		  the buffer are copied and transparently passed to the remote
 *		  side as part of the communication request. May be NULL
 *		  if user_context is not required.
 * @user_context_len: Specifies the size of the user-controlled data buffer.
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_accept(struct xio_session *session,
				const char **portals_array,
				size_t portals_array_len,
				void *user_context,
				size_t user_context_len);

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
 * xio_reject - reject connecting session.
 *
 *
 * @session: The xio session handle.
 * @reason: reason for rejection
 * @private_status: user provided status as hint to the peer
 * @user_context: References a user-controlled data buffer. The contents of
 *		  the buffer are copied and transparently passed to the remote
 *		  side as part of the communication request. May be NULL
 *		  if user_context is not required.
 * @user_context_len: Specifies the size of the user-controlled data buffer.
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_reject(struct xio_session *session,
				enum xio_status reason,
				void *user_context,
				size_t user_context_len);

/**
 * xio_send_response - send response.
 *
 * @rsp: response to send
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_send_response(struct xio_msg *rsp);

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

