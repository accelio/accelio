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

#include "linux/tcp.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_log.h"
#include "xio_task.h"
#include "xio_transport_mempool.h"
#include "xio_tcp_transport.h"
#include "xio_sg_table.h"

/* default option values */
#define XIO_OPTVAL_DEF_ENABLE_MEM_POOL			1
#define XIO_OPTVAL_DEF_ENABLE_MR_CHECK			0
#define XIO_OPTVAL_DEF_TCP_ENABLE_DMA_LATENCY		0
#define XIO_OPTVAL_DEF_TCP_BUF_THRESHOLD		SEND_BUF_SZ
#define XIO_OPTVAL_DEF_TCP_MAX_IN_IOVSZ			XIO_IOVLEN
#define XIO_OPTVAL_DEF_TCP_MAX_OUT_IOVSZ		XIO_IOVLEN
#define XIO_OPTVAL_DEF_TCP_NO_DELAY			0
#define XIO_OPTVAL_DEF_TCP_SO_SNDBUF			4194304
#define XIO_OPTVAL_DEF_TCP_SO_RCVBUF			4194304

#define XIO_OPTVAL_MIN_TCP_BUF_THRESHOLD		256
#define XIO_OPTVAL_MAX_TCP_BUF_THRESHOLD		65536


/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static struct xio_mempool		**mempool_array;
static int				mempool_array_len;
static spinlock_t			mngmt_lock;
static pthread_once_t			ctor_key_once = PTHREAD_ONCE_INIT;
static pthread_once_t			dtor_key_once = PTHREAD_ONCE_INIT;
struct xio_transport			xio_tcp_transport;

static int				cdl_fd = -1;

/* tcp options */
struct xio_tcp_options			tcp_options = {
	.enable_mem_pool		= XIO_OPTVAL_DEF_ENABLE_MEM_POOL,
	.enable_dma_latency		= XIO_OPTVAL_DEF_TCP_ENABLE_DMA_LATENCY,
	.enable_mr_check		= XIO_OPTVAL_DEF_ENABLE_MR_CHECK,
	.tcp_buf_threshold		= XIO_OPTVAL_DEF_TCP_BUF_THRESHOLD,
	.tcp_buf_attr_rdonly		= 0,
	.max_in_iovsz			= XIO_OPTVAL_DEF_TCP_MAX_IN_IOVSZ,
	.max_out_iovsz			= XIO_OPTVAL_DEF_TCP_MAX_OUT_IOVSZ,
	.tcp_no_delay			= XIO_OPTVAL_DEF_TCP_NO_DELAY,
	.tcp_so_sndbuf			= XIO_OPTVAL_DEF_TCP_SO_SNDBUF,
	.tcp_so_rcvbuf			= XIO_OPTVAL_DEF_TCP_SO_RCVBUF,
};

/*---------------------------------------------------------------------------*/
/* xio_tcp_flush_all_tasks						     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_flush_all_tasks(struct xio_tcp_transport *tcp_hndl)
{
	if (!list_empty(&tcp_hndl->in_flight_list)) {
		TRACE_LOG("in_flight_list not empty!\n");
		xio_transport_flush_task_list(&tcp_hndl->in_flight_list);
		/* for task that attched to senders with ref count = 2 */
		xio_transport_flush_task_list(&tcp_hndl->in_flight_list);
	}

	if (!list_empty(&tcp_hndl->tx_comp_list)) {
		TRACE_LOG("tx_comp_list not empty!\n");
		xio_transport_flush_task_list(&tcp_hndl->tx_comp_list);
	}
	if (!list_empty(&tcp_hndl->io_list)) {
		TRACE_LOG("io_list not empty!\n");
		xio_transport_flush_task_list(&tcp_hndl->io_list);
	}

	if (!list_empty(&tcp_hndl->tx_ready_list)) {
		TRACE_LOG("tx_ready_list not empty!\n");
		xio_transport_flush_task_list(&tcp_hndl->tx_ready_list);
		/* for task that attached to senders with ref count = 2 */
		xio_transport_flush_task_list(&tcp_hndl->tx_ready_list);
	}

	if (!list_empty(&tcp_hndl->rx_list)) {
		TRACE_LOG("rx_list not empty!\n");
		xio_transport_flush_task_list(&tcp_hndl->rx_list);
	}

	tcp_hndl->tx_ready_tasks_num = 0;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_sock_close							     */
/*---------------------------------------------------------------------------*/
static void on_sock_close(struct xio_tcp_transport *tcp_hndl)
{
	TRACE_LOG("on_sock_close tcp_hndl:%p, state:%d\n\n",
		  tcp_hndl, tcp_hndl->state);

	xio_tcp_flush_all_tasks(tcp_hndl);

	if (tcp_hndl->state == XIO_STATE_CLOSED) {
		xio_transport_notify_observer(&tcp_hndl->base,
					      XIO_TRANSPORT_CLOSED,
					      NULL);
		tcp_hndl->state = XIO_STATE_DESTROYED;
	}
}

/*---------------------------------------------------------------------------*/
/* on_sock_disconnected							     */
/*---------------------------------------------------------------------------*/
void on_sock_disconnected(struct xio_tcp_transport *tcp_hndl,
			  int notify_observer)
{
	int retval;

	TRACE_LOG("on_sock_disconnected. tcp_hndl:%p, state:%d\n",
		  tcp_hndl, tcp_hndl->state);
	if (tcp_hndl->state == XIO_STATE_CONNECTED ||
	    tcp_hndl->state == XIO_STATE_LISTEN) {
		TRACE_LOG("call to close. tcp_hndl:%p\n",
			  tcp_hndl);
		tcp_hndl->state = XIO_STATE_DISCONNECTED;

		retval = xio_context_del_ev_handler(tcp_hndl->base.ctx,
						    tcp_hndl->sock_fd);
		if (retval)
			DEBUG_LOG("tcp_hndl:%p del_ev_handler failed, %m\n",
				  tcp_hndl);

		if (!notify_observer) { /*active close*/
			retval = shutdown(tcp_hndl->sock_fd, SHUT_RDWR);
			if (retval) {
				xio_set_error(errno);
				DEBUG_LOG("tcp shutdown failed.(errno=%d %m)\n",
					  errno);
			}
		}
		retval = close(tcp_hndl->sock_fd);
		if (retval)
			DEBUG_LOG("tcp_hndl:%p close failed, %m\n",
				  tcp_hndl);

		if (notify_observer)
			xio_transport_notify_observer
				(&tcp_hndl->base,
				 XIO_TRANSPORT_DISCONNECTED,
				 NULL);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_post_close							     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_post_close(struct xio_tcp_transport *tcp_hndl)
{
	TRACE_LOG("tcp transport: [post close] handle:%p\n",
		  tcp_hndl);

	xio_observable_unreg_all_observers(&tcp_hndl->base.observable);

	ufree(tcp_hndl->base.portal_uri);

	ufree(tcp_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_close		                                             */
/*---------------------------------------------------------------------------*/
static void xio_tcp_close(struct xio_transport_base *transport)
{
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport;
	int was = __atomic_add_unless(&tcp_hndl->base.refcnt, -1, 0);

	/* was already 0 */
	if (!was)
		return;

	if (was == 1) {
		/* now it is zero */
		TRACE_LOG("xio_tcp_close: [close] handle:%p, fd:%d\n",
			  tcp_hndl, tcp_hndl->sock_fd);

		switch (tcp_hndl->state) {
		case XIO_STATE_LISTEN:
		case XIO_STATE_CONNECTED:
			on_sock_disconnected(tcp_hndl, 0);
			/*fallthrough*/
		case XIO_STATE_DISCONNECTED:
			tcp_hndl->state = XIO_STATE_CLOSED;
			on_sock_close(tcp_hndl);
			break;
		default:
			xio_transport_notify_observer(&tcp_hndl->base,
						      XIO_TRANSPORT_CLOSED,
						      NULL);
			tcp_hndl->state = XIO_STATE_DESTROYED;
			break;
		}

		if (tcp_hndl->state  == XIO_STATE_DESTROYED)
			xio_tcp_post_close(tcp_hndl);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_reject		                                             */
/*---------------------------------------------------------------------------*/
static int xio_tcp_reject(struct xio_transport_base *transport)
{
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport;
	int				retval;

	retval = shutdown(tcp_hndl->sock_fd, SHUT_RDWR);
	if (retval) {
		xio_set_error(errno);
		DEBUG_LOG("tcp shutdown failed. (errno=%d %m)\n", errno);
	}

	retval = close(tcp_hndl->sock_fd);
	if (retval) {
		xio_set_error(errno);
		DEBUG_LOG("tcp close failed. (errno=%d %m)\n", errno);
		return -1;
	}
	TRACE_LOG("tcp transport: [reject] handle:%p\n", tcp_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_context_shutdown						     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_context_shutdown(struct xio_transport_base *trans_hndl,
				    struct xio_context *ctx)
{
	struct xio_tcp_transport *tcp_hndl =
			(struct xio_tcp_transport *)trans_hndl;

	TRACE_LOG("tcp transport context_shutdown handle:%p\n", tcp_hndl);

	on_sock_disconnected(tcp_hndl, 0);
	tcp_hndl->state = XIO_STATE_CLOSED;
	xio_tcp_flush_all_tasks(tcp_hndl);
	xio_tcp_post_close(tcp_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_conn_ev_handler						     */
/*---------------------------------------------------------------------------*/
void xio_tcp_conn_ready_ev_handler(int fd, int events, void *user_context)
{
	struct xio_tcp_transport	*tcp_hndl = user_context;
	int retval = 0, count = 0;

	if (events & XIO_POLLIN) {
		do {
			retval = xio_tcp_rx_handler(tcp_hndl);
			++count;
		} while (retval > 0 && count <  RX_POLL_NR_MAX);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_accept		                                             */
/*---------------------------------------------------------------------------*/
static int xio_tcp_accept(struct xio_transport_base *transport)
{
	struct xio_tcp_transport *tcp_hndl =
			(struct xio_tcp_transport *)transport;

	/* add to epoll */
	xio_context_add_ev_handler(
			tcp_hndl->base.ctx,
			tcp_hndl->sock_fd,
			XIO_POLLIN,
			xio_tcp_conn_ready_ev_handler,
			tcp_hndl);

	TRACE_LOG("tcp transport: [accept] handle:%p\n", tcp_hndl);

	xio_transport_notify_observer(
			&tcp_hndl->base,
			XIO_TRANSPORT_ESTABLISHED,
			NULL);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_transport_create		                                     */
/*---------------------------------------------------------------------------*/
struct xio_tcp_transport *xio_tcp_transport_create(
		struct xio_transport	*transport,
		struct xio_context	*ctx,
		struct xio_observer	*observer,
		int			create_socket)
{
	struct xio_tcp_transport	*tcp_hndl;
	int				optval = 1;
	int				retval;


	/*allocate tcp handl */
	tcp_hndl = ucalloc(1, sizeof(struct xio_tcp_transport));
	if (!tcp_hndl) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc failed. %m\n");
		return NULL;
	}

	XIO_OBSERVABLE_INIT(&tcp_hndl->base.observable, tcp_hndl);

	if (tcp_options.enable_mem_pool) {
		tcp_hndl->tcp_mempool =
			xio_transport_mempool_array_get(ctx,
							mempool_array,
							mempool_array_len,
							0);
		if (tcp_hndl->tcp_mempool == NULL) {
			xio_set_error(ENOMEM);
			ERROR_LOG("allocating tcp mempool failed. %m\n");
			goto cleanup;
		}
	}

	tcp_hndl->base.portal_uri	= NULL;
	tcp_hndl->base.proto		= XIO_PROTO_TCP;
	atomic_set(&tcp_hndl->base.refcnt, 1);
	tcp_hndl->transport		= transport;
	tcp_hndl->base.ctx		= ctx;

	/* create tcp socket */
	if (create_socket) {
		tcp_hndl->sock_fd = socket(AF_INET,
					   SOCK_STREAM | SOCK_NONBLOCK,
					   0);
		if (tcp_hndl->sock_fd < 0) {
			xio_set_error(errno);
			ERROR_LOG("create socket failed. (errno=%d %m)\n",
				  errno);
			goto cleanup;
		}

		retval = setsockopt(tcp_hndl->sock_fd,
				    SOL_SOCKET,
				    SO_REUSEADDR,
				    &optval,
				    sizeof(optval));
		if (retval) {
			xio_set_error(errno);
			ERROR_LOG("setsockopt failed. (errno=%d %m)\n",
				  errno);
			goto cleanup;
		}

		if (tcp_options.tcp_no_delay) {
			retval = setsockopt(tcp_hndl->sock_fd,
					    IPPROTO_TCP,
					    TCP_NODELAY,
					    (char *)&optval,
					    sizeof(int));
			if (retval) {
				xio_set_error(errno);
				ERROR_LOG("setsockopt failed. (errno=%d %m)\n",
					  errno);
				goto cleanup;
			}
		}


		optval = tcp_options.tcp_so_sndbuf;
		retval = setsockopt(tcp_hndl->sock_fd, SOL_SOCKET, SO_SNDBUF,
				    (char *)&optval, sizeof(optval));
		if (retval) {
			xio_set_error(errno);
			ERROR_LOG("setsockopt failed. (errno=%d %m)\n", errno);
			goto cleanup;
		}
		optval = tcp_options.tcp_so_rcvbuf;
		retval = setsockopt(tcp_hndl->sock_fd, SOL_SOCKET, SO_RCVBUF,
				    (char *)&optval, sizeof(optval));
		if (retval) {
			xio_set_error(errno);
			ERROR_LOG("setsockopt failed. (errno=%d %m)\n",
				  errno);
			goto cleanup;
		}
	}

	/* from now on don't allow changes */
	tcp_options.tcp_buf_attr_rdonly = 1;
	tcp_hndl->max_send_buf_sz	= tcp_options.tcp_buf_threshold;
	tcp_hndl->membuf_sz		= tcp_hndl->max_send_buf_sz;

	if (observer)
		xio_observable_reg_observer(&tcp_hndl->base.observable,
					    observer);

	INIT_LIST_HEAD(&tcp_hndl->in_flight_list);
	INIT_LIST_HEAD(&tcp_hndl->tx_ready_list);
	INIT_LIST_HEAD(&tcp_hndl->tx_comp_list);
	INIT_LIST_HEAD(&tcp_hndl->rx_list);
	INIT_LIST_HEAD(&tcp_hndl->io_list);

	TRACE_LOG("xio_tcp_open: [new] handle:%p\n", tcp_hndl);

	return tcp_hndl;

cleanup:
	ufree(tcp_hndl);

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_new_connection						     */
/*---------------------------------------------------------------------------*/
void xio_tcp_new_connection(struct xio_tcp_transport *parent_hndl)
{
	struct xio_tcp_transport *child_hndl;
	union xio_transport_event_data ev_data;
	int retval;
	socklen_t		 len = sizeof(struct sockaddr_storage);

	/* no observer , don't create socket yet */
	child_hndl = xio_tcp_transport_create(parent_hndl->transport,
					      parent_hndl->base.ctx,
					      NULL,
					      0);
	if (!child_hndl) {
		ERROR_LOG("failed to create tcp child\n");
		xio_transport_notify_observer_error(&parent_hndl->base,
						    xio_errno());
		return;
	}

	/* "accept" the connection */
	retval = accept4(parent_hndl->sock_fd,
			 (struct sockaddr *)&child_hndl->base.peer_addr,
			 &len,
			 SOCK_NONBLOCK);
	if (retval < 0) {
		xio_set_error(errno);
		ERROR_LOG("tcp accept failed. (errno=%d %m)\n", errno);
		child_hndl->sock_fd = retval;
		return;
	}
	child_hndl->sock_fd = retval;

	child_hndl->base.proto = XIO_PROTO_TCP;

	ev_data.new_connection.child_trans_hndl =
		(struct xio_transport_base *)child_hndl;
	xio_transport_notify_observer((struct xio_transport_base *)parent_hndl,
				      XIO_TRANSPORT_NEW_CONNECTION,
				      &ev_data);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_listener_ev_handler						     */
/*---------------------------------------------------------------------------*/
void xio_tcp_listener_ev_handler(int fd, int events, void *user_context)
{
	struct xio_tcp_transport *tcp_hndl = user_context;

	if (events | XIO_POLLIN)
		xio_tcp_new_connection(tcp_hndl);
	/* ORK TODO */
	/*else if (events | XIO_HUP) {
		 notify_observable(..., DISCONNECTED/CLOSED)
	}*/
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_listen							     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_listen(struct xio_transport_base *transport,
			  const char *portal_uri, uint16_t *src_port,
			  int backlog)
{
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport;
	union xio_sockaddr	sa;
	int			sa_len;
	int			retval = 0;
	uint16_t		sport;

	/* resolve the portal_uri */
	sa_len = xio_uri_to_ss(portal_uri, &sa.sa_stor);
	if (sa_len == -1) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("address [%s] resolving failed\n", portal_uri);
		return -1;
	}
	tcp_hndl->base.is_client = 0;

	/* bind */
	retval = bind(tcp_hndl->sock_fd,
		      (struct sockaddr *)&sa.sa_stor,
		      sa_len);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("tcp bind failed. (errno=%d %m)\n", errno);
		goto exit;
	}

	/* add to epoll */
	retval = xio_context_add_ev_handler(
			tcp_hndl->base.ctx,
			tcp_hndl->sock_fd,
			XIO_POLLIN, /* ORK ToDo: XIO_ERR, XIO_HUP */
			xio_tcp_listener_ev_handler,
			tcp_hndl);

	retval  = listen(tcp_hndl->sock_fd, backlog);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("tcp listen failed. (errno=%d %m)\n", errno);
		goto exit;
	}

	retval  = getsockname(tcp_hndl->sock_fd,
			      (struct sockaddr *)&sa.sa_stor,
			      (socklen_t *)&sa_len);
	if (retval) {
		xio_set_error(errno);
		ERROR_LOG("getsockname failed. (errno=%d %m)\n", errno);
		goto exit;
	}

	switch (sa.sa_stor.ss_family) {
	case AF_INET:
		sport = ntohs(sa.sa_in.sin_port);
		break;
	case AF_INET6:
		sport = ntohs(sa.sa_in6.sin6_port);
		break;
	default:
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("invalid family type %d.\n", sa.sa_stor.ss_family);
		goto exit;
	}

	if (src_port)
		*src_port = sport;

	tcp_hndl->state = XIO_STATE_LISTEN;
	DEBUG_LOG("listen on [%s] src_port:%d\n", portal_uri, sport);

	return 0;

exit:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_conn_established_ev_handler	                                     */
/*---------------------------------------------------------------------------*/
void xio_tcp_conn_established_ev_handler(int fd, int events, void *user_context)
{
	struct xio_tcp_transport	*tcp_hndl = user_context;
	int				retval = 0;
	int				so_error = 0;
	socklen_t			so_error_len = sizeof(so_error);

	/* remove from epoll */
	retval = xio_context_del_ev_handler(
			tcp_hndl->base.ctx,
			tcp_hndl->sock_fd);
	if (retval) {
		ERROR_LOG("removing connection handler failed.(errno=%d %m)\n",
			  errno);
		so_error = errno;
	}

	/* add to epoll */
	retval = xio_context_add_ev_handler(
			tcp_hndl->base.ctx,
			tcp_hndl->sock_fd,
			XIO_POLLIN,
			xio_tcp_conn_ready_ev_handler,
			tcp_hndl);
	if (retval) {
		ERROR_LOG("setting connection handler failed. (errno=%d %m)\n",
			  errno);
		so_error = errno;
	}

	retval = getsockopt(tcp_hndl->sock_fd,
			    SOL_SOCKET,
			    SO_ERROR,
			    &so_error,
			    &so_error_len);
	if (retval) {
		ERROR_LOG("getsockopt failed. (errno=%d %m)\n", errno);
		so_error = errno;
	}

	if (so_error) {
		xio_transport_notify_observer_error(&tcp_hndl->base,
						    so_error ? so_error :
						    XIO_E_CONNECT_ERROR);
	} else {
		xio_transport_notify_observer(&tcp_hndl->base,
					      XIO_TRANSPORT_ESTABLISHED,
					      NULL);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_connect		                                             */
/*---------------------------------------------------------------------------*/
static int xio_tcp_connect(struct xio_transport_base *transport,
			   const char *portal_uri, const char *out_if_addr)
{
	struct xio_tcp_transport	*tcp_hndl =
					(struct xio_tcp_transport *)transport;
	int				ss_len = 0;
	int				retval = 0;

	/* resolve the portal_uri */
	ss_len = xio_uri_to_ss(portal_uri, &tcp_hndl->sa.sa_stor);
	if (ss_len == -1) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("address [%s] resolving failed\n", portal_uri);
		return -1;
	}
	/* allocate memory for portal_uri */
	tcp_hndl->base.portal_uri = strdup(portal_uri);
	if (tcp_hndl->base.portal_uri == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("strdup failed. %m\n");
		return -1;
	}
	tcp_hndl->base.is_client = 1;

	if (out_if_addr) {
		union xio_sockaddr	if_sa;
		int			sa_len;

		sa_len = xio_host_port_to_ss(out_if_addr, &if_sa.sa_stor);
		if (sa_len == -1) {
			xio_set_error(XIO_E_ADDR_ERROR);
			ERROR_LOG("outgoing interface [%s] resolving failed\n",
				  out_if_addr);
			goto exit;
		}
		retval = bind(tcp_hndl->sock_fd,
			      (struct sockaddr *)&if_sa.sa_stor,
			      sa_len);
		if (retval) {
			xio_set_error(errno);
			ERROR_LOG("tcp bind failed. (errno=%d %m)\n",
				  errno);
			goto exit;
		}
	}

	/* add to epoll */
	retval = xio_context_add_ev_handler(
			tcp_hndl->base.ctx,
			tcp_hndl->sock_fd,
			XIO_POLLOUT,
			xio_tcp_conn_established_ev_handler,
			tcp_hndl);
	if (retval) {
		ERROR_LOG("setting connection handler failed. (errno=%d %m)\n",
			  errno);
		goto exit;
	}

	/* connect tcp_hndl->sock_fd */
	retval = connect(tcp_hndl->sock_fd,
			 (struct sockaddr *)&tcp_hndl->sa.sa_stor,
			 ss_len);
	if (retval) {
		if (errno == EINPROGRESS) {
			/*set iomux for write event*/
		} else {
			xio_set_error(errno);
			ERROR_LOG("tcp connect failed. (errno=%d %m)\n", errno);
			goto exit;
		}
	} else {
		/*handle in ev_handler*/
	}

	return 0;

exit:
	ufree(tcp_hndl->base.portal_uri);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_open								     */
/*---------------------------------------------------------------------------*/
static struct xio_transport_base *xio_tcp_open(
		struct xio_transport	*transport,
		struct xio_context	*ctx,
		struct xio_observer	*observer)
{
	struct xio_tcp_transport	*tcp_hndl;

	tcp_hndl = xio_tcp_transport_create(transport, ctx, observer, 1);
	if (!tcp_hndl) {
		ERROR_LOG("failed. to create tcp transport%m\n");
		return NULL;
	}
	return (struct xio_transport_base *)tcp_hndl;
}

/*
 * To dynamically control C-states, open the file /dev/cpu_dma_latency and
 * write the maximum allowable latency to it. This will prevent C-states with
 * transition latencies higher than the specified value from being used, as
 * long as the file /dev/cpu_dma_latency is kept open.
 * Writing a maximum allowable latency of 0 will keep the processors in C0
 * (like using kernel parameter ―idle=poll), and writing 1 should force
 * the processors to C1 when idle. Higher values could also be written to
 * restrict the use of C-states with latency greater than the value written.
 *
 * http://en.community.dell.com/techcenter/extras/m/white_papers/20227764/download.aspx
 */

/*---------------------------------------------------------------------------*/
/* xio_set_cpu_latency							     */
/*---------------------------------------------------------------------------*/
static int xio_set_cpu_latency(int *fd)
{
	int32_t latency = 0;

	if (!tcp_options.enable_dma_latency)
		return 0;

	DEBUG_LOG("setting latency to %d us\n", latency);
	*fd = open("/dev/cpu_dma_latency", O_WRONLY);
	if (*fd < 0) {
		ERROR_LOG(
		 "open /dev/cpu_dma_latency %m - need root permissions\n");
		return -1;
	}
	if (write(*fd, &latency, sizeof(latency)) != sizeof(latency)) {
		ERROR_LOG(
		 "write to /dev/cpu_dma_latency %m - need root permissions\n");
		close(*fd);
		*fd = -1;
		return -1;
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_init							     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_init(void)
{
	spin_lock_init(&mngmt_lock);

	/* set cpu latency until process is down */
	xio_set_cpu_latency(&cdl_fd);

	xio_transport_mempool_array_init(&mempool_array, &mempool_array_len);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_transport_init						     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_transport_init(struct xio_transport *transport)
{
	pthread_once(&ctor_key_once, xio_tcp_init);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_release							     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_release(void)
{
	if (cdl_fd >= 0)
		close(cdl_fd);

	xio_transport_mempool_array_release(mempool_array, mempool_array_len);
	/*ORK todo close everything? see xio_cq_release*/
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_transport_constructor					     */
/*---------------------------------------------------------------------------*/
void xio_tcp_transport_constructor(void)
{
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_transport_destructor					     */
/*---------------------------------------------------------------------------*/
void xio_tcp_transport_destructor(void)
{
	ctor_key_once = PTHREAD_ONCE_INIT;
	dtor_key_once = PTHREAD_ONCE_INIT;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_transport_release		                                     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_transport_release(struct xio_transport *transport)
{
	if (ctor_key_once == PTHREAD_ONCE_INIT)
		return;

	pthread_once(&dtor_key_once, xio_tcp_release);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_rxd_init							     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_rxd_init(struct xio_tcp_work_req *rxd,
			     void *buf, unsigned size)
{
	rxd->msg_iov[0].iov_base = buf;
	rxd->msg_iov[0].iov_len	= sizeof(struct xio_tlv);
	rxd->msg_iov[1].iov_base = rxd->msg_iov[0].iov_base +
				   rxd->msg_iov[0].iov_len;
	rxd->msg_iov[1].iov_len	= size - sizeof(struct xio_tlv);
	rxd->msg_len = 2;

	rxd->tot_iov_byte_len = 0;

	rxd->stage = XIO_TCP_RX_START;
	rxd->msg.msg_control = NULL;
	rxd->msg.msg_controllen = 0;
	rxd->msg.msg_flags = 0;
	rxd->msg.msg_name = NULL;
	rxd->msg.msg_namelen = 0;
	rxd->msg.msg_iov = NULL;
	rxd->msg.msg_iovlen = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_txd_init							     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_txd_init(struct xio_tcp_work_req *txd,
			     void *buf, unsigned size)
{
	txd->msg_iov[0].iov_base = buf;
	txd->msg_iov[0].iov_len	= size;
	txd->msg_len = 1;
	txd->tot_iov_byte_len = 0;

	txd->msg.msg_control = NULL;
	txd->msg.msg_controllen = 0;
	txd->msg.msg_flags = 0;
	txd->msg.msg_name = NULL;
	txd->msg.msg_namelen = 0;
	txd->msg.msg_iov = NULL;
	txd->msg.msg_iovlen = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_task_init							     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_task_init(struct xio_task *task,
			      struct xio_tcp_transport *tcp_hndl,
			      void *buf,
			      unsigned long size)
{
	XIO_TO_TCP_TASK(task, tcp_task);

	tcp_task->tcp_hndl = tcp_hndl;

	xio_tcp_rxd_init(&tcp_task->rxd, buf, size);
	xio_tcp_txd_init(&tcp_task->txd, buf, size);

	/* initialize the mbuf */
	xio_mbuf_init(&task->mbuf, buf, size, 0);
}

/* task pools management */

/*---------------------------------------------------------------------------*/
/* xio_tcp_calc_pool_size						     */
/*---------------------------------------------------------------------------*/
void xio_tcp_calc_pool_size(struct xio_tcp_transport *tcp_hndl)
{
	tcp_hndl->num_tasks = NUM_TASKS;

	tcp_hndl->alloc_sz  = tcp_hndl->num_tasks*tcp_hndl->membuf_sz;

	TRACE_LOG("pool size:  alloc_sz:%zd, num_tasks:%d, buf_sz:%zd\n",
		  tcp_hndl->alloc_sz,
		  tcp_hndl->num_tasks,
		  tcp_hndl->membuf_sz);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_initial_pool_slab_pre_create				     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_initial_pool_slab_pre_create(
		struct xio_transport_base *transport_hndl,
		int alloc_nr,
		void *pool_dd_data, void *slab_dd_data)
{
	struct xio_tcp_tasks_slab *tcp_slab =
		(struct xio_tcp_tasks_slab *)slab_dd_data;
	uint32_t pool_size;

	tcp_slab->buf_size = CONN_SETUP_BUF_SIZE;
	pool_size = tcp_slab->buf_size * alloc_nr;

	tcp_slab->data_pool = ucalloc(pool_size * alloc_nr, sizeof(uint8_t));
	if (tcp_slab->data_pool == NULL) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc conn_setup_data_pool sz: %u failed\n",
			  pool_size);
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_initial_task_alloc						     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_tcp_initial_task_alloc(
					struct xio_tcp_transport *tcp_hndl)
{
	if (tcp_hndl->initial_pool_cls.task_get) {
		return tcp_hndl->initial_pool_cls.task_get(
					tcp_hndl->initial_pool_cls.pool);
	}
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_primary_task_alloc						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_tcp_primary_task_alloc(
					struct xio_tcp_transport *tcp_hndl)
{
	if (tcp_hndl->primary_pool_cls.task_get)
		return tcp_hndl->primary_pool_cls.task_get(
					tcp_hndl->primary_pool_cls.pool);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_primary_task_lookup						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_tcp_primary_task_lookup(
					struct xio_tcp_transport *tcp_hndl,
					int tid)
{
	if (tcp_hndl->primary_pool_cls.task_lookup)
		return tcp_hndl->primary_pool_cls.task_lookup(
					tcp_hndl->primary_pool_cls.pool, tid);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_task_free							     */
/*---------------------------------------------------------------------------*/
inline void xio_tcp_task_free(struct xio_tcp_transport *tcp_hndl,
			       struct xio_task *task)
{
	if (tcp_hndl->primary_pool_cls.task_put)
		return tcp_hndl->primary_pool_cls.task_put(task);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_initial_pool_post_create					     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_initial_pool_post_create(
		struct xio_transport_base *transport_hndl,
		void *pool, void *pool_dd_data)
{
	struct xio_task *task;
	struct xio_tcp_task *tcp_task;
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport_hndl;

	tcp_hndl->initial_pool_cls.pool = pool;

	task = xio_tcp_initial_task_alloc(tcp_hndl);
	if (task == NULL) {
		ERROR_LOG("failed to get task\n");
	} else {
		list_add_tail(&task->tasks_list_entry, &tcp_hndl->rx_list);
		tcp_task = (struct xio_tcp_task *)task->dd_data;
		tcp_task->tcp_op = XIO_TCP_RECV;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_initial_pool_slab_destroy					     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_initial_pool_slab_destroy(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, void *slab_dd_data)
{
	struct xio_tcp_tasks_slab *tcp_slab =
		(struct xio_tcp_tasks_slab *)slab_dd_data;

	ufree(tcp_slab->data_pool);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_initial_pool_slab_init_task					     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_initial_pool_slab_init_task(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, void *slab_dd_data,
		int tid, struct xio_task *task)
{
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport_hndl;
	struct xio_tcp_tasks_slab *tcp_slab =
		(struct xio_tcp_tasks_slab *)slab_dd_data;
	void *buf = tcp_slab->data_pool + tid*tcp_slab->buf_size;
	char *ptr;

	XIO_TO_TCP_TASK(task, tcp_task);

	/* fill xio_tcp_task */
	ptr = (char *)tcp_task;
	ptr += sizeof(struct xio_tcp_task);

	/* fill xio_tcp_work_req */
	tcp_task->txd.msg_iov = (void *)ptr;
	ptr += sizeof(struct iovec);

	tcp_task->rxd.msg_iov = (void *)ptr;
	ptr += 2 * sizeof(struct iovec);
	/*****************************************/

	xio_tcp_task_init(
			task,
			tcp_hndl,
			buf,
			tcp_slab->buf_size);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_initial_pool_get_params					     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_initial_pool_get_params(
		struct xio_transport_base *transport_hndl,
		int *start_nr, int *max_nr, int *alloc_nr,
		int *pool_dd_sz, int *slab_dd_sz, int *task_dd_sz)
{
	*start_nr = NUM_CONN_SETUP_TASKS;
	*alloc_nr = 0;
	*max_nr = NUM_CONN_SETUP_TASKS;
	*pool_dd_sz = 0;
	*slab_dd_sz = sizeof(struct xio_tcp_tasks_slab);
	*task_dd_sz = sizeof(struct xio_tcp_task) +
			      3*sizeof(struct iovec);
}

static struct xio_tasks_pool_ops initial_tasks_pool_ops = {
	.pool_get_params	= xio_tcp_initial_pool_get_params,
	.slab_pre_create	= xio_tcp_initial_pool_slab_pre_create,
	.slab_destroy		= xio_tcp_initial_pool_slab_destroy,
	.slab_init_task		= xio_tcp_initial_pool_slab_init_task,
	.pool_post_create	= xio_tcp_initial_pool_post_create
};


/*---------------------------------------------------------------------------*/
/* xio_tcp_primary_pool_slab_pre_create				     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_primary_pool_slab_pre_create(
		struct xio_transport_base *transport_hndl,
		int alloc_nr, void *pool_dd_data, void *slab_dd_data)
{
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport_hndl;
	struct xio_tcp_tasks_slab *tcp_slab =
		(struct xio_tcp_tasks_slab *)slab_dd_data;

	tcp_slab->buf_size = tcp_hndl->membuf_sz;

	if (disable_huge_pages) {
		tcp_slab->io_buf = xio_alloc(tcp_hndl->alloc_sz);
		if (!tcp_slab->io_buf) {
			xio_set_error(ENOMEM);
			ERROR_LOG("xio_alloc tcp pool sz:%zu failed\n",
				  tcp_hndl->alloc_sz);
			return -1;
		}
		tcp_slab->data_pool = tcp_slab->io_buf->addr;
	} else {
		/* maybe allocation of with unuma_alloc can provide better
		 * performance?
		 */
		tcp_slab->data_pool = umalloc_huge_pages(tcp_hndl->alloc_sz);
		if (!tcp_slab->data_pool) {
			xio_set_error(ENOMEM);
			ERROR_LOG("malloc tcp pool sz:%zu failed\n",
				  tcp_hndl->alloc_sz);
			return -1;
		}
	}

	DEBUG_LOG("pool buf:%p\n", tcp_slab->data_pool);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_primary_pool_post_create					     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_primary_pool_post_create(
		struct xio_transport_base *transport_hndl,
		void *pool, void *pool_dd_data)
{
	struct xio_task		*task = NULL;
	struct xio_tcp_task	*tcp_task = NULL;
	int			i;
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport_hndl;

	tcp_hndl->primary_pool_cls.pool = pool;

	for (i = 0; i < RX_LIST_POST_NR; i++) {
		/* get ready to receive message */
		task = xio_tcp_primary_task_alloc(tcp_hndl);
		if (task == 0) {
			ERROR_LOG("primary task pool is empty\n");
			return -1;
		}
		tcp_task = task->dd_data;
		tcp_task->tcp_op = XIO_TCP_RECV;
		list_add_tail(&task->tasks_list_entry, &tcp_hndl->rx_list);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_primary_pool_slab_destroy					     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_primary_pool_slab_destroy(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data, void *slab_dd_data)
{
	struct xio_tcp_tasks_slab *tcp_slab =
		(struct xio_tcp_tasks_slab *)slab_dd_data;

	if (tcp_slab->io_buf)
		xio_free(&tcp_slab->io_buf);
	else
		ufree_huge_pages(tcp_slab->data_pool);


	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_primary_pool_slab_init_task					     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_primary_pool_slab_init_task(
		struct xio_transport_base *transport_hndl,
		void *pool_dd_data,
		void *slab_dd_data, int tid, struct xio_task *task)
{
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport_hndl;
	struct xio_tcp_tasks_slab *tcp_slab =
		(struct xio_tcp_tasks_slab *)slab_dd_data;
	void *buf = tcp_slab->data_pool + tid*tcp_slab->buf_size;
	int  max_iovsz = max(tcp_options.max_out_iovsz,
				     tcp_options.max_in_iovsz) + 1;
	char *ptr;

	XIO_TO_TCP_TASK(task, tcp_task);

	/* fill xio_tco_task */
	ptr = (char *)tcp_task;
	ptr += sizeof(struct xio_tcp_task);

	/* fill xio_tcp_work_req */
	tcp_task->txd.msg_iov = (void *)ptr;
	ptr += (max_iovsz + 1)*sizeof(struct iovec);
	tcp_task->rxd.msg_iov = (void *)ptr;
	ptr += (max_iovsz + 1)*sizeof(struct iovec);

	tcp_task->read_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_mempool_obj);
	tcp_task->write_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_mempool_obj);

	tcp_task->req_read_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_sge);
	tcp_task->req_write_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_sge);
	tcp_task->req_recv_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_sge);
	tcp_task->rsp_write_sge = (void *)ptr;
	ptr += max_iovsz*sizeof(struct xio_sge);
	/*****************************************/

	tcp_task->tcp_op = 0x200;
	xio_tcp_task_init(
			task,
			tcp_hndl,
			buf,
			tcp_slab->buf_size);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_task_pre_put						     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_task_pre_put(
		struct xio_transport_base *trans_hndl,
		struct xio_task *task)
{
	int	i;
	XIO_TO_TCP_TASK(task, tcp_task);

	/* recycle TCP  buffers back to pool */

	/* put buffers back to pool */

	for (i = 0; i < tcp_task->read_num_sge; i++) {
		if (tcp_task->read_sge[i].cache) {
			xio_mempool_free(&tcp_task->read_sge[i]);
			tcp_task->read_sge[i].cache = NULL;
		}
	}
	tcp_task->read_num_sge = 0;

	for (i = 0; i < tcp_task->write_num_sge; i++) {
		if (tcp_task->write_sge[i].cache) {
			xio_mempool_free(&tcp_task->write_sge[i]);
			tcp_task->write_sge[i].cache = NULL;
		}
	}
	tcp_task->write_num_sge		= 0;
	tcp_task->req_write_num_sge	= 0;
	tcp_task->rsp_write_num_sge	= 0;
	tcp_task->req_read_num_sge	= 0;
	tcp_task->req_recv_num_sge	= 0;

	tcp_task->tcp_op		= XIO_TCP_NULL;

	xio_tcp_rxd_init(&tcp_task->rxd,
			 task->mbuf.buf.head,
			 task->mbuf.buf.buflen);
	xio_tcp_txd_init(&tcp_task->txd,
			 task->mbuf.buf.head,
			 task->mbuf.buf.buflen);

	return 0;
}


/*---------------------------------------------------------------------------*/
/* xio_tcp_primary_pool_get_params					     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_primary_pool_get_params(
		struct xio_transport_base *transport_hndl,
		int *start_nr, int *max_nr, int *alloc_nr,
		int *pool_dd_sz, int *slab_dd_sz, int *task_dd_sz)
{
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport_hndl;
	int  max_iovsz = max(tcp_options.max_out_iovsz,
				    tcp_options.max_in_iovsz) + 1;

	*start_nr = NUM_START_PRIMARY_POOL_TASKS;
	*alloc_nr = NUM_ALLOC_PRIMARY_POOL_TASKS;
	*max_nr = tcp_hndl->num_tasks;
	*pool_dd_sz = 0;
	*slab_dd_sz = sizeof(struct xio_tcp_tasks_slab);
	*task_dd_sz = sizeof(struct xio_tcp_task) +
			(2 * (max_iovsz + 1))*sizeof(struct iovec) +
			 2 * max_iovsz * sizeof(struct xio_mempool_obj) +
			 4 * max_iovsz * sizeof(struct xio_sge);
}

static struct xio_tasks_pool_ops   primary_tasks_pool_ops = {
	.pool_get_params	= xio_tcp_primary_pool_get_params,
	.slab_pre_create	= xio_tcp_primary_pool_slab_pre_create,
	.slab_destroy		= xio_tcp_primary_pool_slab_destroy,
	.slab_init_task		= xio_tcp_primary_pool_slab_init_task,
	.pool_post_create	= xio_tcp_primary_pool_post_create,
	.task_pre_put		= xio_tcp_task_pre_put,
};

/*---------------------------------------------------------------------------*/
/* xio_rdma_get_pools_ops						     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_get_pools_ops(struct xio_transport_base *trans_hndl,
				  struct xio_tasks_pool_ops **initial_pool_ops,
				  struct xio_tasks_pool_ops **primary_pool_ops)
{
	*initial_pool_ops = &initial_tasks_pool_ops;
	*primary_pool_ops = &primary_tasks_pool_ops;
}

/*---------------------------------------------------------------------------*/
/* xio_rdma_set_pools_cls						     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_set_pools_cls(struct xio_transport_base *trans_hndl,
				  struct xio_tasks_pool_cls *initial_pool_cls,
				  struct xio_tasks_pool_cls *primary_pool_cls)
{
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)trans_hndl;

	if (initial_pool_cls)
		tcp_hndl->initial_pool_cls = *initial_pool_cls;
	if (primary_pool_cls)
		tcp_hndl->primary_pool_cls = *primary_pool_cls;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_set_opt                                                          */
/*---------------------------------------------------------------------------*/
static int xio_tcp_set_opt(void *xio_obj,
			   int optname, const void *optval, int optlen)
{
	switch (optname) {
	case XIO_OPTNAME_ENABLE_MEM_POOL:
		VALIDATE_SZ(sizeof(int));
		tcp_options.enable_mem_pool = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_ENABLE_DMA_LATENCY:
		VALIDATE_SZ(sizeof(int));
		tcp_options.enable_dma_latency = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_TRANS_BUF_THRESHOLD:
		VALIDATE_SZ(sizeof(int));

		/* changing the parameter is not allowed */
		if (tcp_options.tcp_buf_attr_rdonly) {
			xio_set_error(EPERM);
			return -1;
		}
		if (*(int *)optval < 0 ||
		    *(int *)optval > XIO_OPTVAL_MAX_TCP_BUF_THRESHOLD) {
			xio_set_error(EINVAL);
			return -1;
		}
		tcp_options.tcp_buf_threshold = *((int *)optval) +
					XIO_OPTVAL_MIN_TCP_BUF_THRESHOLD;
		tcp_options.tcp_buf_threshold =
			ALIGN(tcp_options.tcp_buf_threshold, 64);
		return 0;
		break;
	case XIO_OPTNAME_MAX_IN_IOVLEN:
		VALIDATE_SZ(sizeof(int));
		tcp_options.max_in_iovsz = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_MAX_OUT_IOVLEN:
		VALIDATE_SZ(sizeof(int));
		tcp_options.max_out_iovsz = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_TCP_ENABLE_MR_CHECK:
		VALIDATE_SZ(sizeof(int));
		tcp_options.enable_mr_check = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_TCP_NO_DELAY:
		VALIDATE_SZ(sizeof(int));
		tcp_options.tcp_no_delay = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_TCP_SO_SNDBUF:
		VALIDATE_SZ(sizeof(int));
		tcp_options.tcp_so_sndbuf = *((int *)optval);
		return 0;
		break;
	case XIO_OPTNAME_TCP_SO_RCVBUF:
		VALIDATE_SZ(sizeof(int));
		tcp_options.tcp_so_rcvbuf = *((int *)optval);
		return 0;
		break;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_get_opt                                                          */
/*---------------------------------------------------------------------------*/
static int xio_tcp_get_opt(void  *xio_obj,
			   int optname, void *optval, int *optlen)
{
	switch (optname) {
	case XIO_OPTNAME_ENABLE_MEM_POOL:
		*((int *)optval) = tcp_options.enable_mem_pool;
		*optlen = sizeof(int);
		return 0;
		break;
	case XIO_OPTNAME_ENABLE_DMA_LATENCY:
		*((int *)optval) = tcp_options.enable_dma_latency;
		*optlen = sizeof(int);
		return 0;
		break;
	case XIO_OPTNAME_TRANS_BUF_THRESHOLD:
		*((int *)optval) =
			tcp_options.tcp_buf_threshold -
				XIO_OPTVAL_MIN_TCP_BUF_THRESHOLD;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_MAX_IN_IOVLEN:
		*((int *)optval) = tcp_options.max_in_iovsz;
		*optlen = sizeof(int);
		return 0;
		break;
	case XIO_OPTNAME_MAX_OUT_IOVLEN:
		*((int *)optval) = tcp_options.max_out_iovsz;
		*optlen = sizeof(int);
		return 0;
		break;
	case XIO_OPTNAME_TCP_ENABLE_MR_CHECK:
		*((int *)optval) = tcp_options.enable_mr_check;
		*optlen = sizeof(int);
		return 0;
		break;
	case XIO_OPTNAME_TCP_NO_DELAY:
		*((int *)optval) = tcp_options.tcp_no_delay;
		*optlen = sizeof(int);
		return 0;
		break;
	case XIO_OPTNAME_TCP_SO_SNDBUF:
		*((int *)optval) = tcp_options.tcp_so_sndbuf;
		*optlen = sizeof(int);
		return 0;
		break;
	case XIO_OPTNAME_TCP_SO_RCVBUF:
		*((int *)optval) = tcp_options.tcp_so_rcvbuf;
		*optlen = sizeof(int);
		return 0;
		break;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_is_valid_in_req							     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_is_valid_in_req(struct xio_msg *msg)
{
	int		i;
	int		mr_found = 0;
	struct xio_vmsg *vmsg = &msg->in;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sge;
	unsigned long		nents, max_nents;

	sgtbl		= xio_sg_table_get(&msg->in);
	sgtbl_ops	= xio_sg_table_ops_get(msg->in.sgl_type);
	nents		= tbl_nents(sgtbl_ops, sgtbl);
	max_nents	= tbl_max_nents(sgtbl_ops, sgtbl);

	if ((nents > tcp_options.max_in_iovsz) ||
	    (nents > max_nents) ||
	    (max_nents > tcp_options.max_in_iovsz)) {
		return 0;
	}

	if (vmsg->sgl_type == XIO_SGL_TYPE_IOV && nents > XIO_IOVLEN)
		return 0;

	if ((vmsg->header.iov_base != NULL)  &&
	    (vmsg->header.iov_len == 0))
		return 0;

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		if (sge_mr(sgtbl_ops, sge))
			mr_found++;
		if (sge_addr(sgtbl_ops, sge) == NULL) {
			if (sge_mr(sgtbl_ops, sge))
				return 0;
		} else {
			if (sge_length(sgtbl_ops, sge)  == 0)
				return 0;
		}
	}
	if (tcp_options.enable_mr_check &&
	    (mr_found != nents) && mr_found)
		return 0;

	return 1;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_is_valid_out_msg						     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_is_valid_out_msg(struct xio_msg *msg)
{
	int			i;
	int			mr_found = 0;
	struct xio_vmsg		*vmsg = &msg->out;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sge;
	unsigned long		nents, max_nents;

	sgtbl		= xio_sg_table_get(&msg->out);
	sgtbl_ops	= xio_sg_table_ops_get(msg->out.sgl_type);
	nents		= tbl_nents(sgtbl_ops, sgtbl);
	max_nents	= tbl_max_nents(sgtbl_ops, sgtbl);

	if ((nents > tcp_options.max_out_iovsz) ||
	    (nents > max_nents) ||
	    (max_nents > tcp_options.max_out_iovsz))
		return 0;

	if (vmsg->sgl_type == XIO_SGL_TYPE_IOV && nents > XIO_IOVLEN)
		return 0;

	if (((vmsg->header.iov_base != NULL)  &&
	     (vmsg->header.iov_len == 0)) ||
	    ((vmsg->header.iov_base == NULL)  &&
	     (vmsg->header.iov_len != 0)))
			return 0;

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		if (sge_mr(sgtbl_ops, sge))
			mr_found++;
		if ((sge_addr(sgtbl_ops, sge) == NULL) ||
		    (sge_length(sgtbl_ops, sge)  == 0))
			return 0;
	}

	if (tcp_options.enable_mr_check &&
	    (mr_found != nents) && mr_found)
		return 0;

	return 1;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_dup2			                                             */
/* makes new_trans_hndl be the copy of old_trans_hndl, closes new_trans_hndl */
/* Note old and new are in dup2 terminology opposite to reconnect terms	     */
/* --------------------------------------------------------------------------*/
static int xio_tcp_dup2(struct xio_transport_base *old_trans_hndl,
			struct xio_transport_base **new_trans_hndl)
{
	xio_tcp_close(*new_trans_hndl);

	/* conn layer will call close which will only decrement */
	atomic_inc(&old_trans_hndl->refcnt);
	*new_trans_hndl = old_trans_hndl;

	return 0;
}

struct xio_transport xio_tcp_transport = {
	.name			= "tcp",
	.ctor			= xio_tcp_transport_constructor,
	.dtor			= xio_tcp_transport_destructor,
	.init			= xio_tcp_transport_init,
	.release		= xio_tcp_transport_release,
	.context_shutdown	= xio_tcp_context_shutdown,
	.open			= xio_tcp_open,
	.connect		= xio_tcp_connect,
	.listen			= xio_tcp_listen,
	.accept			= xio_tcp_accept,
	.reject			= xio_tcp_reject,
	.close			= xio_tcp_close,
	.dup2			= xio_tcp_dup2,
/*	.update_task		= xio_tcp_update_task,*/
	.send			= xio_tcp_send,
	.poll			= xio_tcp_poll,
	.set_opt		= xio_tcp_set_opt,
	.get_opt		= xio_tcp_get_opt,
/*	.cancel_req		= xio_tcp_cancel_req,*/
/*	.cancel_rsp		= xio_tcp_cancel_rsp,*/
	.get_pools_setup_ops	= xio_tcp_get_pools_ops,
	.set_pools_cls		= xio_tcp_set_pools_cls,

	.validators_cls.is_valid_in_req  = xio_tcp_is_valid_in_req,
	.validators_cls.is_valid_out_msg = xio_tcp_is_valid_out_msg,
};
