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
#ifndef XIO_BASE_H
#define XIO_BASE_H

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------*/
/* preprocessor directives                                                   */
/*---------------------------------------------------------------------------*/
/**
 * @def XIO_VERSION
 * @brief accelio current api version number
 */
#define XIO_VERSION			0x0100

/**
 * @def XIO_IOVLEN
 * @brief array size of data IO vector in message
 */
#define XIO_IOVLEN			4

/**
 * @def XIO_MAX_IOV
 * @brief maximum size of data IO vector in message
 */
#define XIO_MAX_IOV			256

/*---------------------------------------------------------------------------*/
/* opaque data structures                                                    */
/*---------------------------------------------------------------------------*/
struct xio_context;			     /* xio context		     */
struct xio_server;			     /* server handle                */
struct xio_session;			     /* session handle		     */
struct xio_connection;			     /* connection handle	     */
struct xio_mr;				     /* registered memory handle     */

/*---------------------------------------------------------------------------*/
/* accelio extended errors                                                    */
/*---------------------------------------------------------------------------*/

/**
 * A number random enough not to collide with different errno ranges
 * The assumption is that errno is at least 32-bit type
 */
#define XIO_BASE_STATUS		1247689300

/**
 * @enum xio_status
 * @brief accelio's extended error codes
 */
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
	XIO_E_SESSION_DISCONNECTED	= (XIO_BASE_STATUS + 12),
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
	XIO_E_PEER_QUEUE_SIZE_MISMATCH  = (XIO_BASE_STATUS + 38),
	XIO_E_RSP_BUF_SIZE_MISMATCH	= (XIO_BASE_STATUS + 39),
	XIO_E_LAST_STATUS		= (XIO_BASE_STATUS + 40)
};

/*---------------------------------------------------------------------------*/
/* message data type							     */
/*---------------------------------------------------------------------------*/

/** message request referred type  */
#define XIO_REQUEST			(1 << 1)
/** message response referred type */
#define XIO_RESPONSE			(1 << 2)

/** RDMA message family type      */
#define XIO_RDMA			(1 << 3)
/** general message family type   */
#define XIO_MESSAGE			(1 << 4)
/** one sided message family type */
#define XIO_ONE_WAY			(1 << 5)

/**
 * @enum xio_msg_type
 * @brief supported message types
 */
enum xio_msg_type {
	XIO_MSG_TYPE_REQ		= (XIO_MESSAGE | XIO_REQUEST),
	XIO_MSG_TYPE_RSP		= (XIO_MESSAGE | XIO_RESPONSE),
	XIO_MSG_TYPE_ONE_WAY		= (XIO_ONE_WAY | XIO_REQUEST),
	XIO_MSG_TYPE_RDMA		= (XIO_RDMA)
};

/**
 * @enum xio_msg_direction
 * @brief message flow direction
 */
enum xio_msg_direction {
	XIO_MSG_DIRECTION_OUT,
	XIO_MSG_DIRECTION_IN
};

/**
 * @enum xio_msg_flags
 * @brief message level specific flags
 */
enum xio_msg_flags {
	/** request read receipt. If the user wants to know that the msg was
	 * delivered to the recipient he can turn on this flag. Msg is
	 * considered delivered after callback on_msg (in case msg was
	 * delivered successfully)/on_msg_error (in case there was an error)
	 * was called for this msg. This flag can be set for one way msg or
	 * for request (but not for the response). In case of request: if the
	 * responder sends the response immediately (from within the on_msg
	 * callback), the receipt will be piggy backed on the response and the
	 * requester will receive on_msg_delivered callback, immediately
	 * followed by the on_msg callback. In case of one way msg or if the
	 * responder needs to do some asynchronous work before sending a
	 * response, a special inner msg will be sent to the requester
	 * triggering on_msg_delivered callback.
	 */
	XIO_MSG_FLAG_REQUEST_READ_RECEIPT = (1 << 0),

	/** force peer to rdma write. This flag should be enabled in case of
	 * request-response flow, when the application wants to enforce the
	 * response to be written using RDMA write (even if the response size
	 * is smaller than 8k)
	 */
	XIO_MSG_FLAG_PEER_WRITE_RSP	  = (1 << 1),

	/** force peer to rdma read. This flag should be enabled when the
	 * application wants to enforce the request/one way msg to be written
	 * using RDMA READ (even if the request size is smaller than 8k).
	 */
	XIO_MSG_FLAG_PEER_READ_REQ	  = (1 << 2),

	/** request an immediate send completion. Accelio batches cq signals
	 * to optimize performance.  In order to decrease number of cq wake
	 * ups, on_msg_send_complete callback is called in batches of 16.
	 * Meaning that every 16th msg (or in case xio_connection was closed)
	 * will trigger on_msg_send_complete callback for itself and for the
	 * 15 msgs that preceded it. Meaning that if the user sent a number of
	 * msgs that is not divided by 16 (for example 13), he will not
	 * receive completion until 16 msgs will be sent or until the
	 * connection is closed (which ever happens first). In order to
	 * expedite signaling the user can enable this flag for the last msg
	 */
	XIO_MSG_FLAG_IMM_SEND_COMP	  = (1 << 3),

	/** last in batch. Typically, door bell to hardware indicating that
	 * there are msgs to be sent is rang for every msg. In case the user
	 * calls xio_send method several times in a row and wants to send the
	 * msgs in batch, this flag should be enabled for the last msg
	 */
	XIO_MSG_FLAG_LAST_IN_BATCH	  = (1 << 4),

	/* [1<<10 and above - reserved for library usage] */
};

/**
 * @enum xio_msg_hints
 * @brief message level specific hints
 */
enum xio_msg_hints {
	/**< message "in" assigned via assign_data_in_buf   */
	XIO_MSG_HINT_ASSIGNED_DATA_IN_BUF = (1 << 0)
};

/**
 * @enum xio_receipt_result
 * @brief message receipt result as sent by the message recipient
 */
enum xio_receipt_result {
	XIO_READ_RECEIPT_ACCEPT,
	XIO_READ_RECEIPT_REJECT,
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

/**
 * @struct xio_iovec
 * @brief IO vector
 */
struct xio_iovec {
	void			*iov_base;	/**< base address */
	size_t			iov_len;	/**< base length  */
};

/**
 * @struct xio_msg_pdata
 * @brief message private data structure used internally by the library
 */
struct xio_msg_pdata {
	struct xio_msg		*next;          /**< internal library usage   */
	struct xio_msg		**prev;		/**< internal library usage   */
};

/**
 * @struct xio_sg_table
 * @brief scatter gather table data structure
 */
struct xio_sg_table {
	uint32_t			nents;	    /**< number of entries */
	uint32_t			max_nents;  /**< maximum entries   */
						    /**< allowed	   */

	void				*sglist;  /**< scatter list	   */
};

struct xio_sge {
	uint64_t		addr;		/* virtual address */
	uint32_t		length;		/* length	   */
	uint32_t		stag;		/* rkey		   */
};

/**
 * @struct xio_rdma_msg
 * @brief Describes the source/target memory of an RDMA op
 */
struct xio_rdma_msg {
	size_t length;
	size_t nents;
	struct xio_sge *rsg_list;
	int is_read;
	int pad;
};

/*---------------------------------------------------------------------------*/
/* XIO context API							     */
/*---------------------------------------------------------------------------*/
/**
 * @enum xio_context_attr_mask
 * @brief supported context attributes to query/modify
 */
enum xio_context_attr_mask {
	XIO_CONTEXT_ATTR_USER_CTX		= 1 << 0
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
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
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
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 *
 */
int xio_query_context(struct xio_context *ctx,
		      struct xio_context_attr *attr,
		      int attr_mask);

/**
 * poll for events using direct access to the event signaling resources
 * (e.g. hw event queues) associated with the context;
 * polling is performed continuously (by busy-waiting) during the specified
 * timeout period
 *
 * all events which become pending during that time are handled and the user
 * callbacks are called as appropriate for those events
 *
 * as there is no way to interrupt the loop, infinite polling is unsupported;
 * the polling period may be limited internally by an unspecified value
 *
 * @param[in] ctx		Pointer to the xio context handle
 * @param[in] timeout_us	number of microseconds to poll for events
 *				0 : just poll instantly, don't busy-wait;
 *
 * @return 0 on success, or -1 on error. If an error occurs, call
 *	    xio_errno function to get the failure reason.
 *
 * @note supported only for RDMA
 */
int xio_context_poll_completions(struct xio_context *ctx, int timeout_us);

/*---------------------------------------------------------------------------*/
/* XIO session API                                                           */
/*---------------------------------------------------------------------------*/
/**
 * @enum xio_session_type
 * @brief session's type definition
 */
enum xio_session_type {
	XIO_SESSION_CLIENT, /**< represents the active side that initiate    */
			    /**< connection				     */
	XIO_SESSION_SERVER,  /**< represents the passive side that listen to */
			    /**< incoming connections			     */
};

/**
 * @enum xio_proto
 * @brief session's transport protocol as received on the server side upon
 *	  new session request
 */
enum xio_proto {
	XIO_PROTO_RDMA,		/**< Infiniband's RDMA protocol		     */
	XIO_PROTO_TCP		/**< TCP protocol - userspace only	     */
};

/**
 * @enum xio_session_event
 * @brief session events
 */
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

/**
 * @enum xio_session_attr_mask
 * @brief supported session attributes to query/modify
 */
enum xio_session_attr_mask {
	XIO_SESSION_ATTR_USER_CTX		= 1 << 0,
	XIO_SESSION_ATTR_SES_OPS		= 1 << 1,
	XIO_SESSION_ATTR_URI			= 1 << 2
};

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
	const char		*uri;		  /**< the uri		      */
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

/**
 * @struct xio_new_session_req
 * @brief  new session request message
 */
struct xio_new_session_req {
	char			*uri;		  /**< the uri		     */
	void			*private_data;	  /**< client private data   */
	uint16_t		uri_len;	  /**< uri length            */
	uint16_t		private_data_len; /**< private data length   */
	enum xio_proto		proto;		  /**< source protocol type  */
	struct sockaddr_storage	src_addr;	  /**< source address of     */
						  /**< requester	     */
};

/**
 * @struct xio_new_session_rsp
 * @brief  new session response message
 */
struct xio_new_session_rsp {
	void			*private_data;	 /**< server private data    */
	uint16_t		private_data_len;/**< private data length    */
	uint16_t		reserved[3];	 /**< structure alignment    */
};

/**
 *  @struct xio_session_ops
 *  @brief user provided callback functions that handles various session events
 */
struct xio_session_ops {
	/**
	 * generic error event notification
	 *
	 *  @param[in] session		the session
	 *  @param[in] data		session event data information
	 *  @param[in] cb_user_context	user private data provided in session
	 *			        open
	 *  @return 0
	 */
	int (*on_session_event)(struct xio_session *session,
				struct xio_session_event_data *data,
				void *cb_user_context);

	/**
	 * new session notification - server side only
	 *
	 *  @param[in] session		the session
	 *  @param[in] req		new session request information
	 *  @param[in] cb_user_context	user private data provided in session
	 *			        open
	 *  @return 0
	 */
	int (*on_new_session)(struct xio_session *session,
			      struct xio_new_session_req *req,
			      void *cb_user_context);

	/**
	 * session established notification - client side only
	 *
	 *  @param[in] session		the session
	 *  @param[in] rsp		new session's response information
	 *  @param[in] cb_user_context	user private data provided in session
	 *			        open
	 *  @return 0
	 */
	int (*on_session_established)(struct xio_session *session,
				      struct xio_new_session_rsp *rsp,
				      void *cb_user_context);

	/**
	 * send completion notification - responder only
	 *
	 *  @param[in] session		the session
	 *  @param[in] rsp		the response that was sent from
	 *				responder
	 *  @param[in] cb_user_context	user private data provided in
	 *			        xio_bind
	 *  @return 0
	 */
	int (*on_msg_send_complete)(struct xio_session *session,
				    struct xio_msg *rsp,
				    void *conn_user_context);

	/**
	 * message arrived notification
	 *
	 *  @param[in] session			the session
	 *  @param[in] msg			the incoming message
	 *  @param[in] last_in_rxq		hint that more incoming messages
	 *					are expected
	 *  @param[in] conn_user_context	user private data provided in
	 *					connection open on which
	 *					the message send
	 *  @return 0
	 */
	int (*on_msg)(struct xio_session *session,
		      struct xio_msg *msg,
		      int last_in_rxq,
		      void *conn_user_context);

	/**
	 * one way message delivery receipt notification
	 *
	 *  @param[in] session			the session
	 *  @param[in] msg			the incoming message
	 *  @param[in] last_in_rxq		hint that more incoming messages
	 *					are expected
	 *  @param[in] conn_user_context	user private data provided in
	 *					connection open on which
	 *					the message send
	 *  @return 0
	 */
	int (*on_msg_delivered)(struct xio_session *session,
				struct xio_msg *msg,
				int last_in_rxq,
				void *conn_user_context);

	/**
	 * message error notification
	 *
	 *  @param[in] session			the session
	 *  @param[in] error			the error code
	 *  @param[in] msg			the incoming message
	 *  @param[in] conn_user_context	user private data provided in
	 *					connection open on which
	 *					the message send
	 *  @return 0
	 */
	int (*on_msg_error)(struct xio_session *session,
			    enum xio_status error,
			    enum xio_msg_direction,
			    struct xio_msg  *msg,
			    void *conn_user_context);

	/**
	 * requester's message cancellation notification
	 *
	 *  @param[in] session			the session
	 *  @param[in] result			the result code
	 *  @param[in] msg			the message to cancel
	 *  @param[in] conn_user_context	user private data provided in
	 *					connection open on which
	 *					the message send
	 *  @return 0
	 */
	int (*on_cancel)(struct xio_session *session,
			 struct xio_msg  *msg,
			 enum xio_status result,
			 void *conn_user_context);

	/**
	 * responder's message cancellation notification
	 *
	 *  @param[in] session			the session
	 *  @param[in] req			the request to cancel
	 *  @param[in] conn_user_context	user private data provided in
	 *					connection open on which
	 *					the message send
	 *  @return 0
	 */
	int (*on_cancel_request)(struct xio_session *session,
				 struct xio_msg  *msg,
				 void *conn_user_context);

	/**
	 * notify the user to assign a data buffer for incoming read
	 *
	 *  @param[in] msg			the incoming message
	 *  @param[in] conn_user_context	user private data provided in
	 *					connection open on which
	 *					the message send
	 *  @return 0
	 */
	int (*assign_data_in_buf)(struct xio_msg *msg,
				  void *conn_user_context);

	/**
	 * sender's send completion notification - one way message only
	 *
	 *  @param[in] session			the session
	 *  @param[in] msg			the sent message
	 *  @param[in] conn_user_context	user private data provided on
	 *					connection creation
	 *
	 *  @return 0
	 *  @note  called only if "read receipt" was not requested
	 */
	int (*on_ow_msg_send_complete)(struct xio_session *session,
				       struct xio_msg *msg,
				       void *conn_user_context);

	/**
	 * RDMA direct completion notification
	 *
	 *  @param[in] session			the session
	 *  @param[in] msg			the sent message
	 *  @param[in] conn_user_context	user private data provided on
	 *					connection creation
	 *
	 *  @returns 0
	 */
	int (*on_rdma_direct_complete)(struct xio_session *session,
				       struct xio_msg *msg,
				       void *conn_user_context);
};

/**
 * creates new requester session
 *
 * @param[in] params	session creations parameters
 *
 * @return xio session context, or NULL upon error
 */
struct xio_session *xio_session_create(struct xio_session_params *params);

/**
 * teardown an opened session
 *
 * @param[in] session		The xio session handle
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_session_destroy(struct xio_session *session);

/**
 * query session parameters
 *
 * @param[in] session	The xio session handle
 * @param[in] attr	The session attributes structure
 * @param[in] attr_mask attribute mask to query
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
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
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_modify_session(struct xio_session *session,
		       struct xio_session_attr *attr,
		       int attr_mask);

/**
 * maps session event code to event string
 *
 * @param[in] event	The session event
 *
 * @return a string that describes the event code
 */
const char *xio_session_event_str(enum xio_session_event event);

/*---------------------------------------------------------------------------*/
/* XIO connection API							     */
/*---------------------------------------------------------------------------*/
/**
 * @enum xio_connection_attr_mask
 * @brief supported connection attributes to query/modify
 */
enum xio_connection_attr_mask {
	XIO_CONNECTION_ATTR_CTX                 = 1 << 0,
	XIO_CONNECTION_ATTR_USER_CTX		= 1 << 1,
	XIO_CONNECTION_ATTR_PROTO		= 1 << 2,
	XIO_CONNECTION_ATTR_PEER_ADDR		= 1 << 3,
	XIO_CONNECTION_ATTR_LOCAL_ADDR		= 1 << 4,
	XIO_CONNECTION_ATTR_DISCONNECT_TIMEOUT	= 1 << 5,
};

/**
 * @struct xio_connection_attr
 * @brief connection attributes structure
 */
struct xio_connection_attr {
	void			*user_context;  /**< private user context to */
						/**< pass to connection      */
						/**< oriented callbacks      */
	struct xio_context	*ctx;		/**< context data type	     */
	uint8_t			tos;		/**< type of service RFC 2474 */
	uint8_t			pad;            /**< padding                 */
        uint16_t                disconnect_timeout_secs;
	enum xio_proto		proto;	        /**< protocol type           */
	struct sockaddr_storage	peer_addr;	/**< address of peer	     */
	struct sockaddr_storage	local_addr;	/**< address of local	     */
};

/**
 * @struct xio_connection_params
 * @brief connection attributes structure
 */
struct xio_connection_params {
	struct xio_session	*session;	/**< xio session handle       */
	struct xio_context	*ctx;		/**< xio context handle       */
	uint32_t		conn_idx;	/**< Connection index greater */
						/**< then 0 if 0 - auto count */
	uint8_t			enable_tos;	/**< explicitly enable tos    */
	uint8_t			tos;		/**< type of service RFC 2474 */

        /**< disconnect timeout in seconds */
	uint16_t		disconnect_timeout_secs;

	/**< bounded outgoing interface address and/or port - NULL if not     */
	/**< specified in form:                                               */
	/**< host:port, host:, host, :port.                                   */
	/**< [host]:port, [host]:, [host]. [ipv6addr]:port, [ipv6addr]:,      */
	/**< [ipv6addr].                                                      */
	const char		*out_addr;

	/**< Private data pointer to pass to each connection callback         */
	void			*conn_user_context;
};

/**
 * creates connection handle
 *
 * @param[in] cparams	The xio connection parameters structure
 *
 * @return xio connection, or NULL upon error
 */
struct xio_connection *xio_connect(struct xio_connection_params  *cparams);

/**
 * teardown an opened connection
 *
 * @param[in] conn	The xio connection handle
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_disconnect(struct xio_connection *conn);

/**
 * free connection object
 *
 * @param[in] conn	The xio connection handle
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_connection_destroy(struct xio_connection *conn);

/**
 * modify connection parameters
 *
 * @param[in] conn	The xio connection handle
 * @param[in] attr	The connection attributes structure
 * @param[in] attr_mask Attribute mask to modify
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
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
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_query_connection(struct xio_connection *conn,
			 struct xio_connection_attr *attr,
			 int attr_mask);

/**
 * @enum xio_connection_optname
 * @brief connection option name
 */
enum xio_connection_optname {
	XIO_CONNECTION_FIONWRITE_BYTES,  /**< uint64_t: the number of bytes */
		/**< in send queue */
	XIO_CONNECTION_FIONWRITE_MSGS,  /**< int: the number of msgs in */
		/**< send queue */
	XIO_CONNECTION_LEADING_CONN /**< int: check if connection is leading: */
		/**<1 for leading conn, 0 otherwise */
};

/**
 * get xio_connections's info
 *
 * @param[in] connection  Pointer to xio_connection
 * @param[in] con_optname Get value of this option.
 *			  (@ref xio_connection_optname)
 * @param[in,out] optval  A pointer to the buffer in which the value
 *			  for the requested option is specified
 * @param[in,out] optlen  The size, in bytes, of the buffer pointed to by
 *			  the optval parameter
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_connection_ioctl(struct xio_connection *connection, int con_optname,
			 void *optval, int *optlen);
/**
 * send request to responder
 *
 * @param[in] conn	The xio connection handle
 * @param[in] req	request message to send
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_send_request(struct xio_connection *conn,
		     struct xio_msg *req);

/**
 * send response back to requester
 *
 * @param[in] rsp	Response to send
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_send_response(struct xio_msg *rsp);

/**
 * cancel an outstanding asynchronous I/O request
 *
 * @param[in] conn	The xio connection handle on which the message was
 *			sent
 * @param[in] req	request message to cancel
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_cancel_request(struct xio_connection *conn,
		       struct xio_msg *req);
/**
 * responder cancellation response
 *
 * @param[in] req	the outstanding request to cancel
 * @param[in] result	responder cancellation code
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_cancel(struct xio_msg *req, enum xio_status result);

/**
 * release response resources back to xio
 *
 * @note the message itself is allocated by the application
 *	 and is not freed by this function
 *
 * @param[in] rsp The released response
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_release_response(struct xio_msg *rsp);

/**
 * send one way message to remote peer
 *
 * @param[in] conn	The xio connection handle
 * @param[in] msg	The message to send
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_send_msg(struct xio_connection *conn,
		 struct xio_msg *msg);

/**
 * send direct RDMA read/write command
 *
 * @param[in] conn	The xio connection handle
 * @param[in] msg	The message describing the RDMA op
 *
 * @returns success (0), or a (negative) error value
 */
int xio_send_rdma(struct xio_connection *conn,
		  struct xio_msg *msg);

/**
 * release one way message resources back to xio when message is no longer
 * needed
 *
 * @note	the message is allocated by the application and is not freed
 *		by this function
 *
 * @param[in] msg	The released message
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_release_msg(struct xio_msg *msg);

/*---------------------------------------------------------------------------*/
/* XIO rkey management	                                                     */
/*---------------------------------------------------------------------------*/

struct xio_managed_rkey;

/**
 * Get raw rkey value from a managed rkey.
 *
 * @note	Should only be used with the connection the managed key is
 *		registered with.
 *
 * @param[in] managed_rkey	The managed rkey
 *
 * @return raw rkey
 */
uint32_t xio_managed_rkey_unwrap(
	const struct xio_managed_rkey *managed_rkey);

/**
 * Register a remote rkey with a connection such that it will be automatically
 * updated on reconnects, failovers, etc.
 *
 * @param[in] connection	connection
 * @param[in] raw_rkey		A raw rkey received through connection from the
 *				other side.
 * @return	The managed rkey, or NULL if failed.
 */
struct xio_managed_rkey *xio_register_remote_rkey(
	struct xio_connection *connection, uint32_t raw_rkey);

/**
 * Unregister a remote rkey from connection such that it will no longer
 * be automatically updated on reconnects, failovers, etc.
 *
 * @param[in] managed_rkey	The managed rkey
 */
void xio_unregister_remote_key(struct xio_managed_rkey *managed_rkey);

/*---------------------------------------------------------------------------*/
/* XIO server API							     */
/*---------------------------------------------------------------------------*/
/**
 * open a server listener object
 *
 * @param[in] ctx	The xio context handle
 * @param[in] ops	Structure of server's event handlers
 * @param[in] uri	Uri to connect or to bind
 * @param[in] src_port  Returned listen port in host order, can be NULL
 *			if not needed
 * @param[in] flags	Message related flags as defined in enum xio_msg_flags
 * @param[in] cb_user_context Private data pointer to pass to each callback
 *
 * @return xio server context, or NULL upon error
 */
struct xio_server *xio_bind(struct xio_context *ctx,
			    struct xio_session_ops *ops,
			    const char *uri,
			    uint16_t *src_port,
			    uint32_t flags,
			    void *cb_user_context);

/**
 * teardown a server
 *
 * @param[in] server	The xio server handle
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
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
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_accept(struct xio_session *session,
	       const char **portals_array,
	       size_t portals_array_len,
	       void *private_data,
	       size_t private_data_len);

/**
 * redirect connecting session to connect to alternative resources
 *
 * @param[in] session		The xio session handle
 * @param[in] portals_array	string array of alternative portals to the
 *				resource in form of "rdma://host:port"
 *				"rdma://127.0.0.1:1234"
 * @param[in] portals_array_len The string array length
 *
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
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
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_reject(struct xio_session *session,
	       enum xio_status reason,
	       void *private_data,
	       size_t private_data_len);

/*---------------------------------------------------------------------------*/
/* XIO configuration tuning API						     */
/*---------------------------------------------------------------------------*/
/**
 * @enum xio_log_level
 * @brief logging levels
 */
enum xio_log_level {
	XIO_LOG_LEVEL_FATAL,		   /**< fatal logging level         */
	XIO_LOG_LEVEL_ERROR,		   /**< error logging level         */
	XIO_LOG_LEVEL_WARN,		   /**< warnings logging level      */
	XIO_LOG_LEVEL_INFO,		   /**< informational logging level */
	XIO_LOG_LEVEL_DEBUG,		   /**< debugging logging level     */
	XIO_LOG_LEVEL_TRACE,		   /**< tracing logging level       */
	XIO_LOG_LEVEL_LAST
};

/**
 * @enum xio_optlevel
 * @brief configuration tuning option level
 */
enum xio_optlevel {
	XIO_OPTLEVEL_ACCELIO, /**< General library option level             */
	XIO_OPTLEVEL_RDMA,    /**< RDMA transport level			    */
	XIO_OPTLEVEL_TCP,     /**< TCP transport level			    */
};

/**
 * @enum xio_optname
 * @brief configuration tuning option name
 */
enum xio_optname {
	/* XIO_OPTLEVEL_ACCELIO */
	/** disable huge pages allocation. This flag is disabled by default.
	 * Typically, accelio allocates memory in huge pages (usually 2M) and
	 * not in regular pages (4k). This flag will cause accelio to allocate
	 * memory in regular pages.
	 */
	XIO_OPTNAME_DISABLE_HUGETBL = 0,
	/** set user log function					      */
	XIO_OPTNAME_LOG_FN,
	/** set/get logging level					      */
	XIO_OPTNAME_LOG_LEVEL,
	/** set customed allocators hooks				      */
	XIO_OPTNAME_MEM_ALLOCATOR,
	/**< enables/disables connection's keep alive. type: int	      */
	XIO_OPTNAME_ENABLE_KEEPALIVE,
	/**< configure keep alive variables.type: struct xio_options_keepalive*/
	XIO_OPTNAME_CONFIG_KEEPALIVE,

	/* XIO_OPTLEVEL_ACCELIO/RDMA/TCP */
	/** message's max in iovec. This flag indicates what will be the max
	 * in iovec for xio_msg. In case the in iovec size is smaller than the
	 * default, it is best to configure it in order to save memory.
	 */
	XIO_OPTNAME_MAX_IN_IOVLEN = 100,
	/** message's max out iovec. This flag indicates what will be the max
	 * out iovec for xio_msg. It is best to configure it to the out iovec
	 * size that the application uses in order to save memory.
	 */
	XIO_OPTNAME_MAX_OUT_IOVLEN,
	/** enables the dma latency. Disables the CPU hybernation, triggering
	 * a higher power consumption. Hybernating can also be prevented via a
	 * system CPU policy. This is an override to it. This flag will be
	 * deprecated soon
	 */
	XIO_OPTNAME_ENABLE_DMA_LATENCY,
	/** enables reconnection. This flag is disabled by default and should
	 * only be activated it when bonding is turned on. Otherwise, it will
	 * not handle the failover in a timely fashion. (Will take a very long
	 * or exponential time to disconnect).
	 */
	XIO_OPTNAME_ENABLE_RECONNECT,
	/** enables byte based flow control. Application-driven flow control,
	 * based on app releasing each message. Especially suitable for
	 * one-way messages. Also works on the initiator side, if he doesn't
	 * release messages, he will stop getting responses. When client sends
	 * multiple msgs to server and it takes a lot of time for the server
	 * to process them, it can cause the server side to run out of memory.
	 * This case is more common in one way msgs. User can configure flow
	 * control and the msgs will stay in queues on client side. Both sides
	 * need to configure the queue depth to be the same.
	 */
	XIO_OPTNAME_ENABLE_FLOW_CONTROL,
	/** maximum tx queued msgs. Default value is 1024                     */
	XIO_OPTNAME_SND_QUEUE_DEPTH_MSGS,
	/** maximum rx queued msgs. Default value is 1024                     */
	XIO_OPTNAME_RCV_QUEUE_DEPTH_MSGS,
	/** maximum tx queued bytes. Default value is 64M		      */
	XIO_OPTNAME_SND_QUEUE_DEPTH_BYTES,
	/** maximum rx queued bytes. Default value is 64M		      */
	XIO_OPTNAME_RCV_QUEUE_DEPTH_BYTES,
	/** configure internal memory pool. In case the user wants to
	 * configure accelio’s memory slab, he needs to pass this flag.
	 */
	XIO_OPTNAME_CONFIG_MEMPOOL,

	/** set/get max inline XIO header size. If the application sends small
	 * header this flag can be configured in order to save memory. Default
	 * value is 256
	 */
	XIO_OPTNAME_MAX_INLINE_XIO_HEADER,

	/** set/get max inline XIO data size. This flag is used to set/get the
	 * max inline xio data. If the application sends small data this flag
	 * can be configured in order to save memory. Default value is 8k.
	 */
	XIO_OPTNAME_MAX_INLINE_XIO_DATA,
	/** set/get alignment of data buffer address. Used to configure buffer
	 * alignment inside accelio’s internal pool.
	 */
	XIO_OPTNAME_XFER_BUF_ALIGN,
	/** set/get alignment of inline xio data buffer address		      */
	XIO_OPTNAME_INLINE_XIO_DATA_ALIGN,

	/* XIO_OPTLEVEL_RDMA/TCP */
	/** enables the internal transport memory pool. This flag is enabled
	 * by default. Accelio provides its own memory pool. In case the user
	 * knows that when sending large data (via RDMA read/write) the memory
	 * is always registered this pool can be disabled in order to save
	 * memory. This requires the user to implement the "assign_in_buffer"
	 * and take full ownership on memory registration.  In case the user
	 * will send msg without filling “mr” error is expected.
	 */
	XIO_OPTNAME_ENABLE_MEM_POOL = 200,

	/* XIO_OPTLEVEL_RDMA */
	/** number of RDMA-capable HCAs on the machine. Read only	      */
	XIO_OPTNAME_RDMA_NUM_DEVICES = 300,
	/** Call ibv_fork_init(). Forking with RDMA requires a special
	 * synchronization. This is a wrapper over a correspondent ib verb, as
	 * raw verbs are not accessible (calls ibv_fork_init()  )
	 */
	XIO_OPTNAME_ENABLE_FORK_INIT,
	/** Max number of data (bytes) that can be posted inline to the SQ
	 * passed to ib(v)_create_qp
	 */
	XIO_OPTNAME_QP_CAP_MAX_INLINE_DATA,

	/* XIO_OPTLEVEL_TCP */
	/** check tcp mr validity. Disable sanity check for proper MRs in case
	 * of TCP transport. In case this flag is enabled, a check is being
	 * done whether the application provided MRs.  This flag should be
	 * used only for the development stage: in case the user writes the
	 * application above tcp and he want to make sure that it would work
	 * on rdma as well he should enable this flag. For production, or in
	 * case the development is done when rdma enabled the flag should be
	 * disabled. This flag is disabled by default.
	 */
	XIO_OPTNAME_TCP_ENABLE_MR_CHECK = 400,
	/** turn-off Nagle algorithm. In case this flag is enabled, tcp socket
	 * that is created by accelio will have TCP_NODELAY flag. This will
	 * turn off Nagle algorithm which collects small outgoing packets to
	 * be sent all at once, thereby improving latency
	 */
	XIO_OPTNAME_TCP_NO_DELAY,
	/** tcp socket send buffer. Sets maximum socket send buffer to this
	 * value (SO_SNDBUF socket option).
	 */
	XIO_OPTNAME_TCP_SO_SNDBUF,
	/** tcp socket receive buffer. Sets maximum socket receive buffer to
	 * this value (SO_RCVUF socket option)
	 */
	XIO_OPTNAME_TCP_SO_RCVBUF,
	/** performance boost for the price of two fd resources. The flag is
	 * enabled by default. This flag allows to open 2 sockets for each
	 * xio_connection. One is for internal accelio headers and the other
	 * for data. This causes performance boost. The downside: for each
	 * xio_connection 2 file descriptors are used.
	 */
	XIO_OPTNAME_TCP_DUAL_STREAM,
};

/**
 * Callback prototype for libxio log message handler.
 * The library user may wish to register their own logging function.
 * By default errors go to stderr.
 * Use xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_LOG_FN, NULL, 0)
 * to restore the default log fn.
 *
 *@param[in] file	file name from which the callback is called
 *@param[in] line	the line number in the above file
 *@param[in] function	name of the function in which the callback is called
 *@param[in] level	message level (@ref xio_log_level)
 *@param[in] fmt	printf() format string
 *
 */
typedef void (*xio_log_fn)(const char *file, unsigned line,
			   const char *function, unsigned level,
			   const char *fmt, ...);

/**
 *  @struct xio_mem_allocator
 *  @brief user provided costumed allocator hook functions for library usage
 */
struct xio_mem_allocator {
	void	*user_context;			/**< user specific context */

	/**
	 *  allocates block of memory
	 *
	 *  @param[in] size		        size in bytes to allocate
	 *  @param[in] user_context		user specific context
	 *
	 *  @return pointer to allocated memory or NULL if allocate fails
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
	 *  @return pointer to allocated memory or NULL if allocate fails
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
	 *  @return pointer to allocated memory or NULL if allocate fails
	 */
	void * (*malloc_huge_pages)(size_t size, void *user_context);

	/**
	 *  deallocates block of memory previously allocated by
	 *  malloc_huge_pages
	 *
	 *  @param[in] ptr			pointer to allocated block
	 *  @param[in] user_context		user specific context
	 *
	 *  @return pointer to block or NULL if allocate fails
	 */
	void   (*free_huge_pages)(void *ptr, void *user_context);

	/**
	 *  allocates block of memory on specific numa node
	 *
	 *  @param[in] size			block size to allocate
	 *  @param[in] node			the numa node
	 *  @param[in] user_context		user specific context
	 *
	 *  @return pointer to allocated memory or NULL if allocate fails
	 */
	void * (*numa_alloc)(size_t size, int node, void *user_context);

	/**
	 *  deallocates block of memory previously allocated by
	 *  numa_alloc
	 *
	 *  @param[in] ptr			pointer to allocated block
	 *  @param[in] user_context		user specific context
	 *
	 *  @return pointer to block or NULL if allocate fails
	 */
	void   (*numa_free)(void *ptr, void *user_context);
};

/**
 *  @struct xio_options_keepalive
 *  @brief user provided values for connection's keepalive
 * Use xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_CONFIG_KEEPALIVE,
 *		   &ka, sizeof(ka)))
 */
struct xio_options_keepalive {
	/**< the number of unacknowledged probes to send before considering  */
	/**< the connection dead and notifying the application layer	     */
	int	probes;

	/**<  the heartbeat interval in seconds between two initial	     */
	/**<  keepalive probes.						     */
	int	time;

	/**< the interval in seconds between subsequential keepalive probes, */
	/**< regardless of what the connection has exchanged in the meantime */
	int	intvl;
};

#define XIO_MAX_SLABS_NR  6

/**
 *  @struct xio_mempool_config
 *  @brief tuning parameters for internal Accelio's memory pool
 *
 *  Use: xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO,
 *		     XIO_OPTNAME_CONFIG_MEMPOOL, &mempool_config,
 *		     sizeof(mempool_config));
 *
 */
struct xio_mempool_config {
	/**< number of slabs */
	size_t			    slabs_nr;

	/**< per slab configuration */
	struct xio_mempool_slab_config {
		/**< slab's block memory size in bytes */
		size_t			block_sz;

		/**< initial number of allocated blocks */
		size_t			init_blocks_nr;
		/**< growing quantum of block allocations */
		size_t			grow_blocks_nr;
		/**< maximum number of allocated blocks */
		size_t			max_blocks_nr;
	} slab_cfg[XIO_MAX_SLABS_NR];
};

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
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
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
 * @return 0 on success, or -1 on error.  If an error occurs, call
 *	    xio_errno function to get the failure reason.
 */
int xio_get_opt(void *xio_obj, int level, int optname,
		void *optval, int *optlen);

/*---------------------------------------------------------------------------*/
/* XIO errors		                                                     */
/*---------------------------------------------------------------------------*/
/**
 * resolves system errors and XIO errors to human-readable
 * string
 *
 * @param[in] errnum	The xio error code
 *
 * @return a string that describes the error code
 */
const char *xio_strerror(int errnum);

/**
 * return last xio error
 *
 * @return last xio error code
 */
int xio_errno(void);

/**
 * Get library version string.
 *
 * @return Pointer to static buffer in library that holds the version string.
 */
const char *xio_version(void);

#ifdef __cplusplus
}
#endif

#endif
