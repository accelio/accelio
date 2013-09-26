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


#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------*/
/* preprocessor directives                                                   */
/*---------------------------------------------------------------------------*/
#define XIO_MAX_IOV			16	/* limit message fragments */
#define XIO_VERSION			0x0100


/*---------------------------------------------------------------------------*/
/* enums                                                                     */
/*---------------------------------------------------------------------------*/
enum xio_session_type {
	XIO_SESSION_REQ,  /* is used by a client to send requests to and
			       receive replies from a service. */
	XIO_SESSION_REP  /* is used by a service to receive requests from and
			      send replies to a client. */

};

enum xio_proto {
	XIO_PROTO_RDMA
};

enum xio_optlevel {
	XIO_OPTLEVEL_RDMA,
};

enum xio_optname {
	XIO_OPTNAME_ENABLE_MEM_POOL,		/* int */
	XIO_OPTNAME_DISABLE_DMA_LATENCY,	/* int */
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
	XIO_E_BIND_FAILED		= (XIO_BASE_STATUS + 13),
	XIO_E_TIMEOUT			= (XIO_BASE_STATUS + 14),
	XIO_E_IN_PORGRESS		= (XIO_BASE_STATUS + 15),
	XIO_E_INVALID_VERSION		= (XIO_BASE_STATUS + 16),
	XIO_E_NOT_SESSION		= (XIO_BASE_STATUS + 17),
	XIO_E_OPEN_FAILED		= (XIO_BASE_STATUS + 18),
	XIO_E_READ_FAILED		= (XIO_BASE_STATUS + 19),
	XIO_E_WRITE_FAILED		= (XIO_BASE_STATUS + 20),
	XIO_E_CLOSE_FAILED		= (XIO_BASE_STATUS + 21),
	XIO_E_UNSUCCESSFUL		= (XIO_BASE_STATUS + 22),
};

enum xio_ev_loop_events {
	XIO_POLLIN			= 0x001,
	XIO_POLLOUT			= 0x002
};

enum xio_session_flags {
	XIO_SESSION_FLAG_DONTQUEUE	= 0x001, /*  do not queue messages */
};

enum xio_msg_flags {
	/* request flags */
	XIO_MSG_FLAG_REQUEST_READ_RECEIPT = 0x1
};

enum xio_session_event {
	XIO_SESSION_REJECT_EVENT,
	XIO_SESSION_TEARDOWN_EVENT,
	XIO_SESSION_CONNECTION_CLOSED_EVENT,
	XIO_SESSION_CONNECTION_DISCONNECTED_EVENT,
	XIO_SESSION_CONNECTION_ERROR_EVENT,
	XIO_SESSION_ERROR_EVENT,
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

/*---------------------------------------------------------------------------*/
/* opaque data structures                                                    */
/*---------------------------------------------------------------------------*/
struct xio_context;		/* xio context			*/
struct xio_server;		/* server handle		*/
struct xio_session;		/* session handle		*/
struct xio_connection;		/* connection handle		*/
struct xio_mr;			/* registered memory handle	*/

/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct xio_session_attr {
	struct xio_session_ops	*ses_ops;	/* session's ops callbacks */
	void			*user_context;  /* sent to server upon new
						   session */
	size_t			user_context_len;
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

struct xio_iovec_ex {
	void			*iov_base;
	size_t			iov_len;
	struct xio_mr		*mr;
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
	void			*user_context;	/* for user usage - not sent */
	struct xio_msg		*next;          /* internal use */
	struct xio_msg		**prev;		/* internal use */
};

struct xio_session_event_data {
	struct xio_connection	*conn;		/* optional connection for
						   connection events */
	void			*conn_user_context;
	enum xio_session_event	event;
	enum xio_status		reason;
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
typedef void (*xio_ev_handler_t)(int fd, int events, void *data);

/**
 *  user provided function for adding or removing of file descriptors
 *  on the user's event handler (i.e. epoll, libevent etc)
 */
struct xio_loop_ops {
	int (*ev_loop_add_cb)(void *loop, int fd,
			      int events,
			      xio_ev_handler_t handler,
			      void *data);
	int (*ev_loop_del_cb)(void *loop, int fd);
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
/**
 * xio_context - creates xio context - a context is mapped internaly to
 *		   a cpu core./
 *
 * @loop_ops: Structure of callbacks operations for this context
 * @ev_loop: Event loop handler
 * @polling_timeout: polling timeout in microsecs - 0 ignore
 *
 *
 * RETURNS: xio context handle, or NULL upon error.
 */
struct xio_context *xio_ctx_open(
				struct xio_loop_ops *loop_ops,
				void *ev_loop,
				int polling_timeout_us);

/**
 * xio_context_close - close the xio context and free its resources.
 *
 * @ctx: Pointer to the xio context handle.
 *
 */
void xio_ctx_close(struct xio_context *ctx);

/*---------------------------------------------------------------------------*/
/* XIO session API                                                           */
/*---------------------------------------------------------------------------*/
/**
 * xio_session_open - open new session.
 *
 * @type: the type of the session.
 * @attr: structure of session attributes
 * @uri: uri to connect
 * @initial_sn: initial serial number to start with
 * @flags: message related flags as defined in xio_msg_flags
 * @cb_user_context: Private data pointer to pass to each session callback
 *
 * RETURNS: xio session context, or NULL upon error.
 */
struct xio_session *xio_session_open(
		enum xio_session_type type,
		struct xio_session_attr *attr,
		const char *uri,
		uint32_t initial_sn,
		uint32_t flags,
		void *cb_user_context);

/**
 * xio_session_close - teardown an opened session.
 *
 * @session: The xio session handle.
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_session_close(struct xio_session *session);

/**
 * xio_connect - create connection handle.
 *
 * @session: The xio session handle.
 * @ctx: the xio context handle.
 * @conn_idx: connection index greater then 0. if 0 - auto count.
 * @conn_user_context: Private data pointer to pass to each connection callback
 *
 * RETURNS: xio session context, or NULL upon error.
 */
struct xio_connection *xio_connect(
				struct xio_session  *session,
				struct xio_context  *ctx,
				uint32_t conn_idx,
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
 * @msg: The released message
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_release_msg(struct xio_msg *msg);

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
struct xio_connection *xio_get_connection(
				struct xio_session  *session,
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
 * xio_poll_completions - poll the connection queue for number of completions
 *
 * @conn: The xio connection handle.
 * @timeout:	timeout to poll
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_poll_completions(struct xio_connection *conn,
			 struct timespec *timeout);

/**
 * xio_set_opt - sets xio's object option
 *
 * @xio_obj: Pointer to xio object or NULL.
 * @level:   The level at which the option is defined (i.e, XIO_OPTLEVEL_RDMA)
 * @optname: The option for which the value is to be set.
 *	     The optname parameter must be a socket option defined within
 *	     the specified level, or behavior is undefined.
 * @optval:  A pointer to the buffer in which the value for the requested
 *	     option is specified.
 * @optlen:  The size, in bytes, of the buffer pointed to by the optval
 *	     parameter.
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_set_opt(void *xio_obj, int level, int optname,
		const void *optval, int optlen);

/**
 * xio_get_opt - gets xio's object option
 *
 * @xio_obj: Pointer to xio object or NULL.
 * @level:   The level at which the option is defined (i.e, XIO_OPTLEVEL_RDMA)
 * @optname: The option for which the value is to be set.
 *	     The optname parameter must be a socket option defined within
 *	     the specified level, or behavior is undefined.
 * @optval:  A pointer to the buffer in which the value for the requested
 *	     option is specified.
 * @optlen:  The size, in bytes, of the buffer pointed to by the optval
 *	     parameter.
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_get_opt(void *xio_obj, int level, int optname,
		void *optval, int *optlen);

/*---------------------------------------------------------------------------*/
/* XIO default event loop API						     */
/*									     */
/* NoTE: xio provides default muxer implementation around epoll.	     */
/* users are encouraged to utilize their own implementations and provides    */
/* appropriate services to xio via the xio's context open interface.     */
/*---------------------------------------------------------------------------*/
/**
 * xio_ev_loop_init - initializes event loop handle.
 *
 * RETURNS: event loop handle or NULL upon error
 */
void *xio_ev_loop_init();

/**
 * xio_ev_loop_run - event loop main loop.
 *
 * @loop: pointer to event loop
 */
int xio_ev_loop_run(void *loop);

/**
 * xio_ev_loop_stop - stops event loop main loop.
 *
 * @loop: pointer to event loop
 */
void xio_ev_loop_stop(void *loop);

/**
 * xio_ev_loop_destroy - destroy the event loop.
 *
 * @loop: pointer to event loop
 */
void xio_ev_loop_destroy(void **loop);

/**
 * xio_ev_loop_add - add fd to be handled by event loop
 *
 * @loop: pointer to event loop
 * @fd:	the added file descriptor
 * @events: event to poll
 * @handler: the callback to call upon fd signal
 * @data: private data to pass to the callback
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_ev_loop_add(void *loop,
		int fd,
		int /*enum xio_ev_loop_events*/ events,
		xio_ev_handler_t handler, void *data);
/**
 * xio_ev_loop_del - del fd to be handled by event loop
 *
 * @loop: pointer to event loop
 * @fd:	the added file descriptor
 *
 * RETURNS: success (0), or a (negative) error value.
 */
int xio_ev_loop_del(void *loop, int fd);


#ifdef __cplusplus
}
#endif


#endif /*XIO_API_H */

