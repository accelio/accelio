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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/tcp.h>

#include "libxio.h"
#include <xio_os.h>
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_log.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_ktransport.h"
#include "xio_transport.h"
#include "xio_mempool.h"
#include "xio_ev_data.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_ev_loop.h"
#include "xio_context.h"
#include "xio_context_priv.h"
#include "xio_tcp_transport.h"
#include "xio_sg_table.h"

MODULE_AUTHOR("Or Kehati, Eyal Solomon, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO library v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

/* The root of xio_tcp debugfs tree */
static struct dentry *xio_tcp_root;

#define VALIDATE_SZ(sz)	do {			\
		if (optlen != (sz)) {		\
			xio_set_error(EINVAL);	\
			return -1;		\
		}				\
	} while (0)

/* default option values */
#define XIO_OPTVAL_DEF_ENABLE_MEM_POOL			1
#define XIO_OPTVAL_DEF_ENABLE_MR_CHECK			0
#define XIO_OPTVAL_DEF_TCP_ENABLE_DMA_LATENCY		0
#define XIO_OPTVAL_DEF_TCP_MAX_IN_IOVSZ			XIO_IOVLEN
#define XIO_OPTVAL_DEF_TCP_MAX_OUT_IOVSZ		XIO_IOVLEN
#define XIO_OPTVAL_DEF_TCP_NO_DELAY			0
#define XIO_OPTVAL_DEF_TCP_SO_SNDBUF			4194304
#define XIO_OPTVAL_DEF_TCP_SO_RCVBUF			4194304
#define XIO_OPTVAL_DEF_TCP_DUAL_SOCK			1

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
struct xio_transport			xio_tcp_transport;
static struct xio_tcp_socket_ops	single_sock_ops;
static struct xio_tcp_socket_ops	dual_sock_ops;
struct xio_options                     *g_poptions;

/* tcp options */
struct xio_tcp_options			tcp_options = {
	.enable_mem_pool		= XIO_OPTVAL_DEF_ENABLE_MEM_POOL,
	.enable_dma_latency		= XIO_OPTVAL_DEF_TCP_ENABLE_DMA_LATENCY,
	.enable_mr_check		= XIO_OPTVAL_DEF_ENABLE_MR_CHECK,
	.max_in_iovsz			= XIO_OPTVAL_DEF_TCP_MAX_IN_IOVSZ,
	.max_out_iovsz			= XIO_OPTVAL_DEF_TCP_MAX_OUT_IOVSZ,
	.tcp_no_delay			= XIO_OPTVAL_DEF_TCP_NO_DELAY,
	.tcp_so_sndbuf			= XIO_OPTVAL_DEF_TCP_SO_SNDBUF,
	.tcp_so_rcvbuf			= XIO_OPTVAL_DEF_TCP_SO_RCVBUF,
	.tcp_dual_sock			= XIO_OPTVAL_DEF_TCP_DUAL_SOCK,
};

static int xio_tcp_post_close(struct xio_tcp_transport *tcp_hndl,
			      int force_free);

void xio_tcp_save_orig_callbacks(struct xio_socket *socket)
{
	write_lock_bh(&socket->ksock->sk->sk_callback_lock);
	socket->orig_sk_data_ready = socket->ksock->sk->sk_data_ready;
	socket->orig_sk_state_change = socket->ksock->sk->sk_state_change;
	socket->orig_sk_write_space = socket->ksock->sk->sk_write_space;
	write_unlock_bh(&socket->ksock->sk->sk_callback_lock);
}

void xio_tcp_save_orig_callbacks_from(struct xio_socket *to,
				      struct xio_socket *from)
{
	to->orig_sk_data_ready = from->orig_sk_data_ready;
	to->orig_sk_state_change = from->orig_sk_state_change;
	to->orig_sk_write_space = from->orig_sk_write_space;
}

void xio_tcp_restore_callbacks_from(struct socket *to,
				    struct xio_socket *from)
{
	write_lock_bh(&to->sk->sk_callback_lock);
	if (from->orig_sk_data_ready)
		to->sk->sk_data_ready = from->orig_sk_data_ready;
	if (from->orig_sk_state_change)
		to->sk->sk_state_change = from->orig_sk_state_change;
	if (from->orig_sk_write_space)
		to->sk->sk_write_space = from->orig_sk_write_space;
	to->sk->sk_user_data = NULL;
	write_unlock_bh(&to->sk->sk_callback_lock);
}

void xio_tcp_restore_callbacks(struct xio_socket *socket)
{
	xio_tcp_restore_callbacks_from(socket->ksock, socket);
}

void xio_tcp_set_callbacks(struct socket *sock,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
			   void (*sk_data_ready)(struct sock *sk),
#else
			   void (*sk_data_ready)(struct sock *sk, int bytes),
#endif
			   void	(*sk_state_change)(struct sock *sk),
			   void	(*sk_write_space)(struct sock *sk),
			   void *user_data)
{
	write_lock_bh(&sock->sk->sk_callback_lock);

	if (sk_data_ready)
		sock->sk->sk_data_ready = sk_data_ready;
	if (sk_state_change)
		sock->sk->sk_state_change = sk_state_change;
	if (sk_write_space)
		sock->sk->sk_write_space = sk_write_space;

	sock->sk->sk_user_data = user_data;

	write_unlock_bh(&sock->sk->sk_callback_lock);
}

void xio_tcp_state_change_cb(struct sock *sk)
{
	void (*state_change)(struct sock *sk);
	struct xio_tcp_transport *tcp_hndl;
	struct xio_socket *socket;

	read_lock(&sk->sk_callback_lock);

	DEBUG_LOG("sock %p state_change to %d\n", sk, sk->sk_state);

	tcp_hndl = sk->sk_user_data;
	if (!tcp_hndl) {
		state_change = sk->sk_state_change;
		goto out;
	}

	socket = (tcp_hndl->socket.ctl.ksock->sk == sk) ?
			&tcp_hndl->socket.ctl : &tcp_hndl->socket.data;

	state_change = socket->orig_sk_state_change;

	switch (sk->sk_state) {
	case TCP_ESTABLISHED:
		xio_context_add_event(tcp_hndl->base.ctx,
				      &socket->conn_establish_event_data);
		DEBUG_LOG("establish ksock=%p\n", socket->ksock);
		break;
	case TCP_CLOSE:
		if (tcp_hndl->state != XIO_TRANSPORT_STATE_LISTEN)
			xio_tcp_disconnect_helper(tcp_hndl);
	       break;
	default:
		break;
	}
out:
	read_unlock(&sk->sk_callback_lock);
	state_change(sk);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_get_max_header_size						     */
/*---------------------------------------------------------------------------*/
int xio_tcp_get_max_header_size(void)
{
	int req_hdr = XIO_TRANSPORT_OFFSET + sizeof(struct xio_tcp_req_hdr);
	int rsp_hdr = XIO_TRANSPORT_OFFSET + sizeof(struct xio_tcp_rsp_hdr);
	int iovsz = tcp_options.max_out_iovsz + tcp_options.max_in_iovsz;

	req_hdr += iovsz * sizeof(struct xio_sge);
	rsp_hdr += tcp_options.max_out_iovsz * sizeof(struct xio_sge);

	return max(req_hdr, rsp_hdr);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_get_inline_buffer_size					     */
/*---------------------------------------------------------------------------*/
int xio_tcp_get_inline_buffer_size(void)
{
	int inline_buf_sz = ALIGN(xio_tcp_get_max_header_size() +
				  g_poptions->max_inline_xio_hdr +
				  g_poptions->max_inline_xio_data, 1024);
	return inline_buf_sz;
}
/*---------------------------------------------------------------------------*/
/* xio_tcp_flush_all_tasks						     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_flush_all_tasks(struct xio_tcp_transport *tcp_hndl)
{
	if (!list_empty(&tcp_hndl->in_flight_list)) {
		TRACE_LOG("in_flight_list not empty!\n");
		xio_transport_flush_task_list(&tcp_hndl->in_flight_list);
		/* for task that attached to senders with ref count = 2 */
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

	xio_transport_notify_observer(&tcp_hndl->base,
				      XIO_TRANSPORT_EVENT_CLOSED,
				      NULL);

	tcp_hndl->state = XIO_TRANSPORT_STATE_DESTROYED;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_single_sock_del_ev_handlers		                             */
/*---------------------------------------------------------------------------*/
int xio_tcp_single_sock_del_ev_handlers(struct xio_tcp_transport *tcp_hndl)
{
	xio_tcp_restore_callbacks(&tcp_hndl->socket.ctl);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_dual_sock_del_ev_handlers		                             */
/*---------------------------------------------------------------------------*/
int xio_tcp_dual_sock_del_ev_handlers(struct xio_tcp_transport *tcp_hndl)
{
	xio_tcp_restore_callbacks(&tcp_hndl->socket.ctl);
	xio_tcp_restore_callbacks(&tcp_hndl->socket.data);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_sock_disconnected							     */
/*---------------------------------------------------------------------------*/
void on_sock_disconnected(struct xio_tcp_transport *tcp_hndl,
			  int passive_close)
{
	struct xio_tcp_pending_conn *pconn, *next_pconn;

	TRACE_LOG("on_sock_disconnected. tcp_hndl:%p, state:%d\n",
		  tcp_hndl, tcp_hndl->state);
	if (tcp_hndl->state == XIO_TRANSPORT_STATE_DISCONNECTED) {
		TRACE_LOG("call to close. tcp_hndl:%p\n",
			  tcp_hndl);
		tcp_hndl->state = XIO_TRANSPORT_STATE_CLOSED;

		if (tcp_hndl->socket.ops->del_ev_handlers)
			tcp_hndl->socket.ops->del_ev_handlers(tcp_hndl);

		xio_context_disable_event(
			&tcp_hndl->socket.ctl.conn_establish_event_data);
		xio_context_disable_event(
			&tcp_hndl->socket.data.conn_establish_event_data);
		xio_context_disable_event(&tcp_hndl->socket.accept_event_data);
		xio_context_disable_event(&tcp_hndl->ctl_rx_event);
		xio_context_disable_event(&tcp_hndl->data_rx_event);
		xio_context_disable_event(&tcp_hndl->flush_tx_event);
		xio_context_disable_event(&tcp_hndl->disconnect_event);

		if (!passive_close && !tcp_hndl->is_listen) { /*active close*/
			tcp_hndl->socket.ops->shutdown(&tcp_hndl->socket);
		}
		tcp_hndl->socket.ops->close(&tcp_hndl->socket);

		list_for_each_entry_safe(pconn, next_pconn,
					 &tcp_hndl->pending_conns,
					 conns_list_entry) {
			xio_tcp_restore_callbacks_from(pconn->sock,
						       &tcp_hndl->socket.ctl);
			sock_release(pconn->sock);
			pconn->sock = NULL;
			xio_tcp_pending_conn_remove_handler(pconn);
		}

		if (passive_close) {
			xio_transport_notify_observer(
					&tcp_hndl->base,
					XIO_TRANSPORT_EVENT_DISCONNECTED,
					NULL);
		}
	}
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_post_close_handler						     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_post_close_handler(void *xio_tcp_hndl)
{
	struct xio_tcp_transport *tcp_hndl = xio_tcp_hndl;

	xio_context_destroy_resume(tcp_hndl->base.ctx);
	xio_tcp_post_close(tcp_hndl, 1);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_post_close							     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_post_close(struct xio_tcp_transport *tcp_hndl,
			      int force_free)
{
	int event_pending = 0;
	struct xio_tcp_pending_conn *pconn, *next_pconn;

	TRACE_LOG("tcp transport: [post close] handle:%p, force_free=%d\n",
		  tcp_hndl, force_free);

	if (force_free)
		goto free;

	event_pending |= xio_context_is_pending_event(
			&tcp_hndl->socket.ctl.conn_establish_event_data);
	event_pending |= xio_context_is_pending_event(
			&tcp_hndl->socket.data.conn_establish_event_data);
	event_pending |= xio_context_is_pending_event(
			&tcp_hndl->socket.accept_event_data);
	event_pending |= xio_context_is_pending_event(&tcp_hndl->ctl_rx_event);
	event_pending |= xio_context_is_pending_event(&tcp_hndl->data_rx_event);
	event_pending |= xio_context_is_pending_event(
			&tcp_hndl->flush_tx_event);
	event_pending |= xio_context_is_pending_event(
			&tcp_hndl->disconnect_event);

	event_pending |= !list_empty(&tcp_hndl->pending_conns);

	if (event_pending) {
		tcp_hndl->disconnect_event.data = tcp_hndl;
		tcp_hndl->disconnect_event.handler = xio_tcp_post_close_handler;
		xio_context_add_event(tcp_hndl->base.ctx,
				      &tcp_hndl->disconnect_event);
		return 1;
	}

free:
	TRACE_LOG("tcp transport: [post close - free] handle:%p\n",
		  tcp_hndl);

	xio_observable_unreg_all_observers(&tcp_hndl->base.observable);
	XIO_OBSERVABLE_DESTROY(&tcp_hndl->base.observable);

	list_for_each_entry_safe(pconn, next_pconn,
				 &tcp_hndl->pending_conns,
				 conns_list_entry) {
		kfree(pconn);
	}

	kfree(tcp_hndl->tmp_rx_buf);
	tcp_hndl->tmp_rx_buf = NULL;

	kfree(tcp_hndl->base.portal_uri);
	tcp_hndl->base.portal_uri = NULL;

	kfree(tcp_hndl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_close_cb		                                             */
/*---------------------------------------------------------------------------*/
static void xio_tcp_close_cb(struct kref *kref)
{
	struct xio_transport_base *transport = container_of(
					kref, struct xio_transport_base, kref);
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport;

	/* now it is zero */
	TRACE_LOG("xio_tcp_close: [close] handle:%p, socket:%p\n",
		  tcp_hndl, tcp_hndl->socket.ctl.ksock);

	switch (tcp_hndl->state) {
	case XIO_TRANSPORT_STATE_LISTEN:
	case XIO_TRANSPORT_STATE_CONNECTED:
		tcp_hndl->state = XIO_TRANSPORT_STATE_DISCONNECTED;
		/*fallthrough*/
	case XIO_TRANSPORT_STATE_DISCONNECTED:
		on_sock_disconnected(tcp_hndl, 0);
		/*fallthrough*/
	case XIO_TRANSPORT_STATE_CLOSED:
		on_sock_close(tcp_hndl);
		break;
	default:
		xio_transport_notify_observer(
				&tcp_hndl->base,
				XIO_TRANSPORT_EVENT_CLOSED,
				NULL);
		tcp_hndl->state = XIO_TRANSPORT_STATE_DESTROYED;
		break;
	}

	if (tcp_hndl->state  == XIO_TRANSPORT_STATE_DESTROYED)
		xio_tcp_post_close(tcp_hndl, 0);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_close		                                             */
/*---------------------------------------------------------------------------*/
static void xio_tcp_close(struct xio_transport_base *transport)
{
	int was = atomic_read(&transport->kref.refcount);

	/* this is only for debugging - please note that the combination of
	 * atomic_read and kref_put is not atomic - please remove if this
	 * error does not pop up. Otherwise contact me and report bug.
	 */

	/* was already 0 */
	if (!was) {
		ERROR_LOG("xio_tcp_close double close. handle:%p\n",
			  transport);
		return;
	}

	kref_put(&transport->kref, xio_tcp_close_cb);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_single_sock_shutdown		                                     */
/*---------------------------------------------------------------------------*/
int xio_tcp_single_sock_shutdown(struct xio_tcp_socket *socket)
{
	int retval;

	retval = kernel_sock_shutdown(socket->ctl.ksock, SHUT_RDWR);
	if (retval) {
		xio_set_error(-retval);
		DEBUG_LOG("tcp shutdown failed. (errno=%d)\n", -retval);
	}

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_single_sock_close		                                     */
/*---------------------------------------------------------------------------*/
int xio_tcp_single_sock_close(struct xio_tcp_socket *socket)
{
	DEBUG_LOG("release socket\n");
	xio_tcp_restore_callbacks(&socket->ctl);
	sock_release(socket->ctl.ksock);
	socket->ctl.ksock = NULL;
	socket->data.ksock = NULL;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_dual_sock_shutdown		                                     */
/*---------------------------------------------------------------------------*/
int xio_tcp_dual_sock_shutdown(struct xio_tcp_socket *socket)
{
	int retval1, retval2;

	retval1 = kernel_sock_shutdown(socket->ctl.ksock, SHUT_RDWR);
	if (retval1) {
		xio_set_error(-retval1);
		DEBUG_LOG("tcp shutdown failed. (errno=%d)\n", -retval1);
	}

	retval2 = kernel_sock_shutdown(socket->data.ksock, SHUT_RDWR);
	if (retval2) {
		xio_set_error(-retval2);
		DEBUG_LOG("tcp shutdown failed. (errno=%d)\n", -retval2);
	}

	return (retval1 | retval2);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_dual_sock_close		                                     */
/*---------------------------------------------------------------------------*/
int xio_tcp_dual_sock_close(struct xio_tcp_socket *socket)
{
	DEBUG_LOG("release sockets\n");
	xio_tcp_restore_callbacks(&socket->ctl);
	sock_release(socket->ctl.ksock);
	socket->ctl.ksock = NULL;
	xio_tcp_restore_callbacks(&socket->data);
	sock_release(socket->data.ksock);
	socket->data.ksock = NULL;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_reject		                                             */
/*---------------------------------------------------------------------------*/
static int xio_tcp_reject(struct xio_transport_base *transport)
{
	struct xio_tcp_transport *tcp_hndl =
		(struct xio_tcp_transport *)transport;
	int				retval;

	ERROR_LOG("tcp transport reject - not fully implemented yet!");

	tcp_hndl->socket.ops->shutdown(&tcp_hndl->socket);

	retval = tcp_hndl->socket.ops->close(&tcp_hndl->socket);
	if (retval)
		return -1;

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

	switch (tcp_hndl->state) {
	case XIO_TRANSPORT_STATE_INIT:
		ERROR_LOG("shutting context while tcp_hndl=%p state is INIT?\n",
			  tcp_hndl);
	case XIO_TRANSPORT_STATE_LISTEN:
	case XIO_TRANSPORT_STATE_CONNECTING:
	case XIO_TRANSPORT_STATE_CONNECTED:
		tcp_hndl->state = XIO_TRANSPORT_STATE_DISCONNECTED;
		/*fallthrough*/
	case XIO_TRANSPORT_STATE_DISCONNECTED:
		on_sock_disconnected(tcp_hndl, 0);
		break;
	default:
		break;
	}

	tcp_hndl->state = XIO_TRANSPORT_STATE_DESTROYED;
	xio_tcp_flush_all_tasks(tcp_hndl);

	xio_transport_notify_observer(&tcp_hndl->base,
				      XIO_TRANSPORT_EVENT_CLOSED,
				      NULL);

	if (xio_tcp_post_close(tcp_hndl, 0))
		xio_context_destroy_wait(tcp_hndl->base.ctx);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_disconnect_handler						     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_disconnect_handler(void *xio_tcp_hndl)
{
	struct xio_tcp_transport *tcp_hndl = xio_tcp_hndl;

	on_sock_disconnected(tcp_hndl, 1);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_disconnect_helper						     */
/*---------------------------------------------------------------------------*/
void xio_tcp_disconnect_helper(void *xio_tcp_hndl)
{
	struct xio_tcp_transport *tcp_hndl = xio_tcp_hndl;

	if (tcp_hndl->state >= XIO_TRANSPORT_STATE_DISCONNECTED)
		return;

	tcp_hndl->state = XIO_TRANSPORT_STATE_DISCONNECTED;

	/* flush all tasks in completion */
        if (!list_empty(&tcp_hndl->in_flight_list)) {
		struct xio_task *task = NULL;

		task = list_last_entry(&tcp_hndl->in_flight_list,
				       struct xio_task,
				       tasks_list_entry);
		if (task) {
		    XIO_TO_TCP_TASK(task, tcp_task);

		    xio_context_add_event(tcp_hndl->base.ctx,
					  &tcp_task->comp_event);
	    }
	}
	xio_context_add_event(tcp_hndl->base.ctx, &tcp_hndl->disconnect_event);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_flush_tx_handler						     */
/*---------------------------------------------------------------------------*/
void xio_tcp_flush_tx_handler(void *xio_tcp_hndl)
{
	struct xio_tcp_transport *tcp_hndl = xio_tcp_hndl;

	xio_tcp_xmit(tcp_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_single_sock_rx_ctl_handler					     */
/*---------------------------------------------------------------------------*/
int xio_tcp_single_sock_rx_ctl_handler(struct xio_tcp_transport *tcp_hndl,
				       int *resched)
{
	return xio_tcp_rx_ctl_handler(tcp_hndl, 1, resched);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_dual_sock_rx_ctl_handler					     */
/*---------------------------------------------------------------------------*/
int xio_tcp_dual_sock_rx_ctl_handler(struct xio_tcp_transport *tcp_hndl,
				     int *resched)
{
	return xio_tcp_rx_ctl_handler(tcp_hndl, RX_BATCH, resched);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_consume_ctl_rx						     */
/*---------------------------------------------------------------------------*/
void xio_tcp_consume_ctl_rx(void *xio_tcp_hndl)
{
	struct xio_tcp_transport *tcp_hndl = xio_tcp_hndl;
	int retval = 0, count = 0;
	int resched = 0;

	do {
		retval = tcp_hndl->socket.ops->rx_ctl_handler(tcp_hndl,
							      &resched);
		++count;
	} while (retval > 0 && count <  RX_POLL_NR_MAX);

	if (resched && tcp_hndl->state == XIO_TRANSPORT_STATE_CONNECTED) {
		xio_context_add_event(tcp_hndl->base.ctx,
				      &tcp_hndl->ctl_rx_event);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_consume_data_rx						     */
/*---------------------------------------------------------------------------*/
void xio_tcp_consume_data_rx(void *xio_tcp_hndl)
{
	struct xio_tcp_transport *tcp_hndl = xio_tcp_hndl;
	int retval = 0, count = 0;
	int resched = 0;

	do {
		retval = tcp_hndl->socket.ops->rx_data_handler(tcp_hndl,
							       RX_BATCH,
							       &resched);
		++count;
	} while (retval > 0 && count <  RX_POLL_NR_MAX);

	if (resched && tcp_hndl->state == XIO_TRANSPORT_STATE_CONNECTED) {
		xio_context_add_event(tcp_hndl->base.ctx,
				      &tcp_hndl->data_rx_event);
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
void xio_tcp_data_ready_cb(struct sock *sk)
{
	void (*ready)(struct sock *sk);
#else
void xio_tcp_data_ready_cb(struct sock *sk, int bytes)
{
	void (*ready)(struct sock *sk, int bytes);
#endif
	struct xio_tcp_transport *tcp_hndl;
	int is_ctl = 0;

	read_lock(&sk->sk_callback_lock);
	tcp_hndl = sk->sk_user_data;
	if (!tcp_hndl) { /* check for teardown race */
		ready = sk->sk_data_ready;
		goto out;
	}

	is_ctl = (tcp_hndl->socket.ctl.ksock->sk == sk);
	if (is_ctl) {
		ready = tcp_hndl->socket.ctl.orig_sk_data_ready;
		xio_context_add_event(tcp_hndl->base.ctx,
				      &tcp_hndl->ctl_rx_event);
	} else {
		ready = tcp_hndl->socket.data.orig_sk_data_ready;
		xio_context_add_event(tcp_hndl->base.ctx,
				      &tcp_hndl->data_rx_event);
	}

out:
	read_unlock(&sk->sk_callback_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	ready(sk);
#else
	ready(sk, bytes);
#endif
}

void xio_tcp_write_space_cb(struct sock *sk)
{
	void (*write_space)(struct sock *sk);
	struct xio_tcp_transport *tcp_hndl;
	int is_ctl = 0;

	TRACE_LOG("write space sk %p\n", sk);

	read_lock(&sk->sk_callback_lock);
	tcp_hndl = sk->sk_user_data;
	if (!tcp_hndl) { /* check for teardown race */
		write_space = sk->sk_write_space;
		goto out;
	}
	is_ctl = (tcp_hndl->socket.ctl.ksock->sk == sk);
	if (is_ctl)
		write_space = tcp_hndl->socket.ctl.orig_sk_write_space;
	else
		write_space = tcp_hndl->socket.data.orig_sk_write_space;

	xio_context_add_event(tcp_hndl->base.ctx, &tcp_hndl->flush_tx_event);

out:
	read_unlock(&sk->sk_callback_lock);
	write_space(sk);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_single_sock_add_ev_handlers		                             */
/*---------------------------------------------------------------------------*/
int xio_tcp_single_sock_add_ev_handlers(struct xio_tcp_transport *tcp_hndl)
{
	xio_tcp_set_callbacks(tcp_hndl->socket.ctl.ksock,
			      xio_tcp_data_ready_cb,
			      xio_tcp_state_change_cb,
			      xio_tcp_write_space_cb,
			      tcp_hndl);

	xio_context_add_event(tcp_hndl->base.ctx, &tcp_hndl->ctl_rx_event);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_dual_sock_add_ev_handlers		                             */
/*---------------------------------------------------------------------------*/
int xio_tcp_dual_sock_add_ev_handlers(struct xio_tcp_transport *tcp_hndl)
{
	xio_tcp_set_callbacks(tcp_hndl->socket.ctl.ksock,
			      xio_tcp_data_ready_cb,
			      xio_tcp_state_change_cb,
			      xio_tcp_write_space_cb,
			      tcp_hndl);

	xio_tcp_set_callbacks(tcp_hndl->socket.data.ksock,
			      xio_tcp_data_ready_cb,
			      xio_tcp_state_change_cb,
			      xio_tcp_write_space_cb,
			      tcp_hndl);

	xio_context_add_event(tcp_hndl->base.ctx, &tcp_hndl->ctl_rx_event);
	xio_context_add_event(tcp_hndl->base.ctx, &tcp_hndl->data_rx_event);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_accept		                                             */
/*---------------------------------------------------------------------------*/
static int xio_tcp_accept(struct xio_transport_base *transport)
{
	struct xio_tcp_transport *tcp_hndl =
			(struct xio_tcp_transport *)transport;

	if (tcp_hndl->socket.ops->add_ev_handlers(tcp_hndl)) {
		xio_transport_notify_observer_error(&tcp_hndl->base,
						    XIO_E_UNSUCCESSFUL);
	}

	TRACE_LOG("tcp transport: [accept] handle:%p\n", tcp_hndl);

	xio_transport_notify_observer(
			&tcp_hndl->base,
			XIO_TRANSPORT_EVENT_ESTABLISHED,
			NULL);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_socket_create		                                     */
/*---------------------------------------------------------------------------*/
struct socket *xio_tcp_socket_create(void)
{
	int retval, optval = 1;
	struct socket *sock = NULL;

	retval = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (retval < 0) {
		xio_set_error(-retval);
		ERROR_LOG("create socket failed. (errno=%d)\n", -retval);
		goto cleanup;
	}

	retval = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				   (char *)&optval, sizeof(optval));
	if (retval) {
		xio_set_error(-retval);
		ERROR_LOG("setsockopt failed. (errno=%d)\n", -retval);
		goto cleanup;
	}

	if (tcp_options.tcp_no_delay) {
		retval = kernel_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
					   (char *)&optval, sizeof(int));
		if (retval) {
			xio_set_error(-retval);
			ERROR_LOG("setsockopt failed. (errno=%d)\n", -retval);
			goto cleanup;
		}
	}

	optval = tcp_options.tcp_so_sndbuf;
	retval = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
				   (char *)&optval, sizeof(optval));
	if (retval) {
		xio_set_error(-retval);
		ERROR_LOG("setsockopt failed. (errno=%d)\n", -retval);
		goto cleanup;
	}
	optval = tcp_options.tcp_so_rcvbuf;
	retval = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
				   (char *)&optval, sizeof(optval));
	if (retval) {
		xio_set_error(-retval);
		ERROR_LOG("setsockopt failed. (errno=%d)\n", -retval);
		goto cleanup;
	}

	return sock;

cleanup:
	if (sock)
		sock_release(sock);
	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_single_sock_create		                                     */
/*---------------------------------------------------------------------------*/
int xio_tcp_single_sock_create(struct xio_tcp_socket *socket)
{
	socket->ctl.ksock = xio_tcp_socket_create();
	if (!socket->ctl.ksock)
		return -1;

	socket->data.ksock = socket->ctl.ksock;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_dual_sock_create		                                     */
/*---------------------------------------------------------------------------*/
int xio_tcp_dual_sock_create(struct xio_tcp_socket *socket)
{
	socket->ctl.ksock = xio_tcp_socket_create();
	if (!socket->ctl.ksock)
		return -1;

	socket->data.ksock = xio_tcp_socket_create();
	if (!socket->data.ksock) {
		sock_release(socket->ctl.ksock);
		socket->ctl.ksock = NULL;
		return -1;
	}
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

	/*allocate tcp handl */
	tcp_hndl = kzalloc(sizeof(*tcp_hndl), GFP_KERNEL);
	if (!tcp_hndl) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kzalloc failed. %m\n");
		return NULL;
	}

	XIO_OBSERVABLE_INIT(&tcp_hndl->base.observable, tcp_hndl);

	if (tcp_options.enable_mem_pool) {
		tcp_hndl->tcp_mempool = xio_mempool_get(ctx);
		if (!tcp_hndl->tcp_mempool) {
			xio_set_error(ENOMEM);
			ERROR_LOG("allocating tcp mempool failed. %m\n");
			goto cleanup;
		}
	}

	tcp_hndl->base.portal_uri	= NULL;
	tcp_hndl->base.proto		= XIO_PROTO_TCP;
	kref_init(&tcp_hndl->base.kref);
	tcp_hndl->transport		= transport;
	tcp_hndl->base.ctx		= ctx;
	tcp_hndl->is_listen		= 0;

	tcp_hndl->tmp_rx_buf		= NULL;
	tcp_hndl->tmp_rx_buf_cur	= NULL;
	tcp_hndl->tmp_rx_buf_len	= 0;

	tcp_hndl->tx_ready_tasks_num = 0;
	tcp_hndl->tx_comp_cnt = 0;

	memset(&tcp_hndl->tmp_work, 0, sizeof(struct xio_tcp_work_req));
	tcp_hndl->tmp_work.msg.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT;
	tcp_hndl->tmp_work.msg_iov = tcp_hndl->tmp_iovec;

	/* create tcp socket */
	if (create_socket) {
		memcpy(tcp_hndl->socket.ops, (tcp_options.tcp_dual_sock ?
		       &dual_sock_ops : &single_sock_ops), sizeof(*tcp_hndl->socket.ops));
		if (tcp_hndl->socket.ops->open(&tcp_hndl->socket))
			goto cleanup;
	}

	/* from now on don't allow changes */
	tcp_hndl->max_inline_buf_sz	= xio_tcp_get_inline_buffer_size();
	tcp_hndl->membuf_sz		= tcp_hndl->max_inline_buf_sz;

	if (observer)
		xio_observable_reg_observer(&tcp_hndl->base.observable,
					    observer);

	INIT_LIST_HEAD(&tcp_hndl->in_flight_list);
	INIT_LIST_HEAD(&tcp_hndl->tx_ready_list);
	INIT_LIST_HEAD(&tcp_hndl->tx_comp_list);
	INIT_LIST_HEAD(&tcp_hndl->rx_list);
	INIT_LIST_HEAD(&tcp_hndl->io_list);

	INIT_LIST_HEAD(&tcp_hndl->pending_conns);

	tcp_hndl->socket.accept_event_data.handler = xio_tcp_accept_connections;
	tcp_hndl->socket.accept_event_data.data = tcp_hndl;
	tcp_hndl->ctl_rx_event.handler = xio_tcp_consume_ctl_rx;
	tcp_hndl->ctl_rx_event.data = tcp_hndl;
	tcp_hndl->data_rx_event.handler = xio_tcp_consume_data_rx;
	tcp_hndl->data_rx_event.data = tcp_hndl;
	tcp_hndl->flush_tx_event.handler = xio_tcp_flush_tx_handler;
	tcp_hndl->flush_tx_event.data = tcp_hndl;
	tcp_hndl->disconnect_event.handler = xio_tcp_disconnect_handler;
	tcp_hndl->disconnect_event.data = tcp_hndl;

	TRACE_LOG("xio_tcp_open: [new] handle:%p\n", tcp_hndl);

	return tcp_hndl;

cleanup:
	kfree(tcp_hndl);

	return NULL;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_pending_conn_remove_handler					     */
/*---------------------------------------------------------------------------*/
void xio_tcp_pending_conn_remove_handler(void *user_data)
{
	struct xio_tcp_pending_conn *pending_conn = user_data;

	if (xio_context_is_pending_event(
			&pending_conn->pending_event_data)) {
		pending_conn->pending_event_data.data = pending_conn;
		pending_conn->pending_event_data.handler =
				xio_tcp_pending_conn_remove_handler;
		xio_context_add_event(pending_conn->parent->base.ctx,
				      &pending_conn->pending_event_data);
	} else {
		list_del(&pending_conn->conns_list_entry);
		kfree(pending_conn);
	}
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_handle_pending_conn						     */
/*---------------------------------------------------------------------------*/
void xio_tcp_handle_pending_conn(void *user_data)
{
	int retval = 0;
	struct xio_tcp_pending_conn *pending_conn = user_data;
	struct xio_tcp_pending_conn *matching_conn = NULL;
	struct xio_tcp_transport *parent_hndl = pending_conn->parent;
	struct xio_tcp_pending_conn *pconn = NULL, *next_pconn = NULL;
	struct xio_tcp_pending_conn *ctl_conn = NULL, *data_conn = NULL;
	void *buf;
	int is_single = 1;
	struct socket *ctl_sock = NULL, *data_sock = NULL;
	socklen_t len = 0;
	struct xio_tcp_transport *child_hndl = NULL;
	union xio_transport_event_data ev_data;

	DEBUG_LOG("parent_hndl=%p\n", parent_hndl);

	buf = &pending_conn->msg;
	buf += sizeof(struct xio_tcp_connect_msg) -
			pending_conn->waiting_for_bytes;
	while (pending_conn->waiting_for_bytes) {
		struct msghdr msg;
		struct kvec vec;

		memset(&msg, 0, sizeof(msg));
		msg.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT;
		vec.iov_base = buf;
		vec.iov_len = pending_conn->waiting_for_bytes;
		retval = kernel_recvmsg(pending_conn->sock, &msg, &vec, 1,
					pending_conn->waiting_for_bytes,
					msg.msg_flags);
		if (retval > 0) {
			pending_conn->waiting_for_bytes -= retval;
			buf += retval;
		} else if (retval == 0) {
			ERROR_LOG("got EOF while establishing connection\n");
			goto cleanup;
		} else {
			if (retval != -EAGAIN) {
				ERROR_LOG("recv return with errno=%d\n",
					  -retval);
				goto cleanup;
			}
			return;
		}
	}

	DEBUG_LOG("got init msg\n");

	UNPACK_LVAL(&pending_conn->msg, &pending_conn->msg, sock_type);
	UNPACK_SVAL(&pending_conn->msg, &pending_conn->msg, second_port);
	UNPACK_SVAL(&pending_conn->msg, &pending_conn->msg, pad);

	if (pending_conn->msg.sock_type == XIO_TCP_SINGLE_SOCK) {
		ctl_conn = pending_conn;
		ctl_sock = pending_conn->sock;
		goto single_sock;
	}

	is_single = 0;

	list_for_each_entry_safe(pconn, next_pconn,
				 &parent_hndl->pending_conns,
				 conns_list_entry) {
		if (pconn->waiting_for_bytes)
			continue;

		if (pconn->sa.sa.sa_family == AF_INET) {
			if ((pconn->msg.second_port ==
			    ntohs(pending_conn->sa.sa_in.sin_port)) &&
			    (pconn->sa.sa_in.sin_addr.s_addr ==
			    pending_conn->sa.sa_in.sin_addr.s_addr)) {
				matching_conn = pconn;
				if (ntohs(matching_conn->sa.sa_in.sin_port) !=
				    pending_conn->msg.second_port) {
					ERROR_LOG("ports mismatch\n");
					return;
				}
				break;
			}
		} else if (pconn->sa.sa.sa_family == AF_INET6) {
			if ((pconn->msg.second_port ==
			     ntohs(pending_conn->sa.sa_in6.sin6_port)) &&
			     !memcmp(&pconn->sa.sa_in6.sin6_addr,
				     &pending_conn->sa.sa_in6.sin6_addr,
				     sizeof(pconn->sa.sa_in6.sin6_addr))) {
				matching_conn = pconn;
				if (ntohs(matching_conn->sa.sa_in6.sin6_port)
				    != pending_conn->msg.second_port) {
					ERROR_LOG("ports mismatch\n");
					return;
				}
				break;
			}
		} else {
			ERROR_LOG("unknown family %d\n",
				  pconn->sa.sa.sa_family);
		}
	}

	if (!matching_conn)
		return;

	if (pending_conn->msg.sock_type == XIO_TCP_CTL_SOCK) {
		ctl_conn = pending_conn;
		data_conn = matching_conn;
	} else if (pending_conn->msg.sock_type == XIO_TCP_DATA_SOCK) {
		ctl_conn = matching_conn;
		data_conn = pending_conn;
	}
	ctl_sock = ctl_conn->sock;
	data_sock = data_conn->sock;

single_sock:
	child_hndl = xio_tcp_transport_create(parent_hndl->transport,
					      parent_hndl->base.ctx,
					      NULL,
					      0);
	if (!child_hndl) {
		ERROR_LOG("failed to create tcp child\n");
		xio_transport_notify_observer_error(&parent_hndl->base,
						    xio_errno());
		goto cleanup;
	}

	memcpy(&child_hndl->base.peer_addr,
	       &ctl_conn->sa.sa_stor,
	       sizeof(child_hndl->base.peer_addr));

	if (is_single) {
		child_hndl->socket.ctl.ksock = ctl_sock;
		child_hndl->socket.data.ksock = ctl_sock;
		memcpy(child_hndl->socket.ops, &single_sock_ops,
		       sizeof(*child_hndl->socket.ops));
	} else {
		child_hndl->socket.ctl.ksock = ctl_sock;
		child_hndl->socket.data.ksock = data_sock;
		memcpy(child_hndl->socket.ops, &dual_sock_ops,
		       sizeof(*child_hndl->socket.ops));

		child_hndl->tmp_rx_buf = kzalloc(TMP_RX_BUF_SIZE, GFP_KERNEL);
		if (!child_hndl->tmp_rx_buf) {
			xio_set_error(ENOMEM);
			ERROR_LOG("kzalloc failed.\n");
			goto cleanup;
		}
		child_hndl->tmp_rx_buf_cur = child_hndl->tmp_rx_buf;
	}

	xio_tcp_save_orig_callbacks_from(&child_hndl->socket.ctl,
					 &parent_hndl->socket.ctl);
	xio_tcp_restore_callbacks(&child_hndl->socket.ctl);
	xio_tcp_pending_conn_remove_handler(ctl_conn);

	if (!is_single) {
		xio_tcp_save_orig_callbacks_from(&child_hndl->socket.data,
						 &parent_hndl->socket.ctl);
		xio_tcp_restore_callbacks(&child_hndl->socket.data);
		xio_tcp_pending_conn_remove_handler(data_conn);
	}

	len = sizeof(child_hndl->base.local_addr);
	retval = kernel_getsockname(
			child_hndl->socket.ctl.ksock,
			(struct sockaddr *)&child_hndl->base.local_addr,
			&len);
	if (retval) {
		xio_set_error(-retval);
		ERROR_LOG("tcp getsockname failed. (errno=%d)\n", -retval);
	}

	child_hndl->state = XIO_TRANSPORT_STATE_CONNECTING;

	ev_data.new_connection.child_trans_hndl =
		(struct xio_transport_base *)child_hndl;
	xio_transport_notify_observer((struct xio_transport_base *)parent_hndl,
				      XIO_TRANSPORT_EVENT_NEW_CONNECTION,
				      &ev_data);

	return;

cleanup:
	if (is_single)
		ctl_conn = pending_conn;
	if (ctl_sock)
		xio_tcp_restore_callbacks_from(ctl_sock,
					       &parent_hndl->socket.ctl);
	xio_tcp_pending_conn_remove_handler(ctl_conn);
	sock_release(ctl_sock);

	if (!is_single) {
		xio_tcp_restore_callbacks_from(data_sock,
					       &parent_hndl->socket.ctl);
		xio_tcp_pending_conn_remove_handler(data_conn);
		sock_release(data_sock);
	}

	if (child_hndl)
		xio_tcp_post_close(child_hndl, 1);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_pending_conn_ev_handler					     */
/*---------------------------------------------------------------------------*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
void xio_tcp_pending_conn_ev_handler(struct sock *sk)
{
	void (*ready)(struct sock *sk);
#else
void xio_tcp_pending_conn_ev_handler(struct sock *sk, int bytes)
{
	void (*ready)(struct sock *sk, int bytes);
#endif
	struct xio_tcp_pending_conn *pending_conn;

	read_lock(&sk->sk_callback_lock);

	pending_conn = sk->sk_user_data;

	DEBUG_LOG("pending conn %p ready, sk=%p\n", pending_conn, sk);

	if (!pending_conn) {
		ready = sk->sk_data_ready;
		goto out;
	}

	ready = pending_conn->parent->socket.ctl.orig_sk_data_ready;

	pending_conn->pending_event_data.data = pending_conn;
	pending_conn->pending_event_data.handler = xio_tcp_handle_pending_conn;
	xio_context_add_event(pending_conn->parent->base.ctx,
			      &pending_conn->pending_event_data);

out:
	read_unlock(&sk->sk_callback_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	ready(sk);
#else
	ready(sk, bytes);
#endif
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_new_connection						     */
/*---------------------------------------------------------------------------*/
int xio_tcp_new_connection(struct xio_tcp_transport *parent_hndl)
{
	int retval;
	struct socket *new_sock = NULL;
	socklen_t len = sizeof(struct sockaddr_storage);
	struct xio_tcp_pending_conn *pending_conn;

	DEBUG_LOG("parent_hndl=%p\n", parent_hndl);

	/* "accept" the connection */
	retval = kernel_accept(parent_hndl->socket.ctl.ksock,
			       &new_sock, O_NONBLOCK);
	if (retval < 0 || !new_sock) {
		if (new_sock)
			sock_release(new_sock);
		xio_set_error(-retval);
		if (retval == -EWOULDBLOCK || retval == -EAGAIN)
			return retval;
		ERROR_LOG("tcp accept failed. (errno=%d)\n", -retval);
		return retval;
	}

	/*allocate pending fd struct */
	pending_conn = kzalloc(sizeof(*pending_conn), GFP_KERNEL);
	if (!pending_conn) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kzalloc failed.\n");
		xio_transport_notify_observer_error(&parent_hndl->base,
						    xio_errno());
		sock_release(new_sock);
		return -ENOMEM;
	}

	pending_conn->parent = parent_hndl;
	pending_conn->waiting_for_bytes = sizeof(struct xio_tcp_connect_msg);

	retval = kernel_getpeername(
			new_sock,
			(struct sockaddr *)&pending_conn->sa.sa_stor, &len);
	if (retval < 0) {
		xio_set_error(-retval);
		ERROR_LOG("tcp getpeername failed. (errno=%d)\n", -retval);
		kfree(pending_conn);
		sock_release(new_sock);
		return retval;
	}

	pending_conn->sock = new_sock;

	list_add_tail(&pending_conn->conns_list_entry,
		      &parent_hndl->pending_conns);

	xio_tcp_set_callbacks(new_sock, xio_tcp_pending_conn_ev_handler,
			      NULL, NULL, pending_conn);

	xio_tcp_handle_pending_conn(pending_conn);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_accept_connections						     */
/*---------------------------------------------------------------------------*/
void xio_tcp_accept_connections(void *user_data)
{
	struct xio_tcp_transport *parent_hndl = user_data;

	DEBUG_LOG("try to accept connections\n");

	xio_tcp_new_connection(parent_hndl);

	/*
	 * if accept was successful, try to accept another one later.
	 */
	if (!xio_tcp_new_connection(parent_hndl)) {
		xio_context_add_event(
			parent_hndl->base.ctx,
			&parent_hndl->socket.accept_event_data);
	}

	/*todo while ????*/
	/*while (!xio_tcp_new_connection(parent_hndl)) {
		cond_resched();
		if (++count > MAX_ACCEPT_BATCH) {
			xio_context_add_event(
				parent_hndl->base.ctx,
				&parent_hndl->sock.cfd_accept_event_data);
			break;
		}
	}*/
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_listener_ev_handler						     */
/*---------------------------------------------------------------------------*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
void xio_tcp_listener_ev_handler(struct sock *sk)
{
	void (*ready)(struct sock *sk);
#else
void xio_tcp_listener_ev_handler(struct sock *sk, int bytes)
{
	void (*ready)(struct sock *sk, int bytes);
#endif
	struct xio_tcp_transport *tcp_hndl;

	DEBUG_LOG("listen data ready sk %p\n", sk);

	read_lock(&sk->sk_callback_lock);
	if (!sk->sk_user_data) { /* check for teardown race */
		ready = sk->sk_data_ready;
		goto out;
	}

	tcp_hndl = sk->sk_user_data;
	ready = tcp_hndl->socket.ctl.orig_sk_data_ready;

	/*
	* ->sk_data_ready is also called for a newly established child socket
	* before it has been accepted and the accepter has set up their
	* data_ready.. we only want to queue listen work for our listening
	* socket
	*/
	if (sk->sk_state == TCP_LISTEN) {
		xio_context_add_event(tcp_hndl->base.ctx,
				      &tcp_hndl->socket.accept_event_data);
	}
out:
	read_unlock(&sk->sk_callback_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	ready(sk);
#else
	ready(sk, bytes);
#endif
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

	xio_tcp_save_orig_callbacks(&tcp_hndl->socket.ctl);
	xio_tcp_set_callbacks(tcp_hndl->socket.ctl.ksock,
			      xio_tcp_listener_ev_handler,
			      NULL,
			      NULL,
			      tcp_hndl);

	/* bind */
	retval = kernel_bind(tcp_hndl->socket.ctl.ksock,
			     (struct sockaddr *)&sa.sa_stor, sa_len);
	if (retval) {
		xio_set_error(-retval);
		ERROR_LOG("tcp bind failed. (errno=%d)\n", -retval);
		goto exit;
	}

	tcp_hndl->is_listen = 1;

	retval  = kernel_listen(tcp_hndl->socket.ctl.ksock,
				backlog > 0 ? backlog : TCP_DEFAULT_BACKLOG);
	if (retval) {
		xio_set_error(-retval);
		ERROR_LOG("tcp listen failed. (errno=%d)\n", -retval);
		goto exit;
	}

	retval  = kernel_getsockname(tcp_hndl->socket.ctl.ksock,
				     (struct sockaddr *)&sa.sa_stor,
				     (socklen_t *)&sa_len);
	if (retval) {
		xio_set_error(-retval);
		ERROR_LOG("getsockname failed. (errno=%d)\n", -retval);
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

	tcp_hndl->state = XIO_TRANSPORT_STATE_LISTEN;
	DEBUG_LOG("listen on [%s] src_port:%d\n", portal_uri, sport);

	return 0;

exit:
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_conn_established_helper	                                     */
/*---------------------------------------------------------------------------*/
void xio_tcp_conn_established_helper(struct xio_tcp_transport *tcp_hndl)
{
	int				retval = 0;
	socklen_t			len = 0;

	len = sizeof(tcp_hndl->base.peer_addr);
	retval = kernel_getpeername(
			tcp_hndl->socket.ctl.ksock,
			(struct sockaddr *)&tcp_hndl->base.peer_addr,
			&len);
	if (retval) {
		xio_set_error(-retval);
		ERROR_LOG("tcp getpeername failed. (errno=%d)\n", -retval);
		goto cleanup;
	}
	tcp_hndl->state = XIO_TRANSPORT_STATE_CONNECTING;

	retval = tcp_hndl->socket.ops->add_ev_handlers(tcp_hndl);
	if (retval) {
		ERROR_LOG("setting connection handler failed. (errno=%d)\n",
			  -retval);
		goto cleanup;
	}

	xio_transport_notify_observer(&tcp_hndl->base,
				      XIO_TRANSPORT_EVENT_ESTABLISHED,
				      NULL);

	return;

cleanup:
	if  (retval == -ECONNREFUSED)
		xio_transport_notify_observer(&tcp_hndl->base,
					      XIO_TRANSPORT_EVENT_REFUSED,
					      NULL);
	else
		xio_transport_notify_observer_error(&tcp_hndl->base,
						    XIO_E_CONNECT_ERROR);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_single_conn_established_ev_handler	                             */
/*---------------------------------------------------------------------------*/
void xio_tcp_single_conn_established_ev_handler(void *user_context)
{
	struct xio_tcp_transport	*tcp_hndl = user_context;
	int				retval = 0;
	struct xio_tcp_connect_msg	msg;

	if (test_bits(XIO_SOCK_ESTABLISH_CTL,
		      &tcp_hndl->socket.establish_states)) {
		return;
	}
	set_bits(XIO_SOCK_ESTABLISH_CTL, &tcp_hndl->socket.establish_states);

	msg.sock_type = XIO_TCP_SINGLE_SOCK;
	msg.second_port = 0;
	msg.pad = 0;
	retval = xio_tcp_send_connect_msg(tcp_hndl->socket.ctl.ksock, &msg);
	if (retval)
		goto cleanup;

	xio_tcp_conn_established_helper(tcp_hndl);

	return;

cleanup:
	if  (retval == -ECONNREFUSED)
		xio_transport_notify_observer(&tcp_hndl->base,
					      XIO_TRANSPORT_EVENT_REFUSED,
					      NULL);
	else
		xio_transport_notify_observer_error(&tcp_hndl->base,
						    XIO_E_CONNECT_ERROR);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_connect_helper	                                             */
/*---------------------------------------------------------------------------*/
static int xio_tcp_connect_helper(struct socket *sock, struct sockaddr *sa,
				  socklen_t sa_len, uint16_t *bound_port,
				  struct sockaddr_storage *lss)
{
	int retval;
	union xio_sockaddr *lsa = (union xio_sockaddr *)lss;
	struct sockaddr_storage sa_stor;
	socklen_t lsa_len = sizeof(struct sockaddr_storage);

	DEBUG_LOG("connect sock=%p\n", sock);
	retval = kernel_connect(sock, sa, sa_len, O_NONBLOCK);
	if (retval) {
		if (retval == -EINPROGRESS) {
			/*set iomux for write event*/
		} else {
			xio_set_error(-retval);
			ERROR_LOG("tcp connect failed. (errno=%d)\n", -retval);
			return retval;
		}
	} else {
		/*handle in ev_handler*/
	}

	if (!lss)
		lsa = (union xio_sockaddr *)&sa_stor;

	retval = kernel_getsockname(sock, &lsa->sa, &lsa_len);
	if (retval) {
		xio_set_error(-retval);
		ERROR_LOG("tcp getsockname failed. (errno=%d %m)\n", -retval);
		return retval;
	}

	if (lsa->sa.sa_family == AF_INET) {
		*bound_port = ntohs(lsa->sa_in.sin_port);
	} else if (lsa->sa.sa_family == AF_INET6) {
		*bound_port = ntohs(lsa->sa_in6.sin6_port);
	} else {
		ERROR_LOG("getsockname unknown family = %d\n",
			  lsa->sa.sa_family);
		return -1;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_ctl_conn_established_ev_handler	                             */
/*---------------------------------------------------------------------------*/
void xio_tcp_ctl_conn_established_ev_handler(void *user_context)
{
	struct xio_tcp_transport	*tcp_hndl = user_context;
	int				retval = 0;
	struct xio_tcp_connect_msg	msg;

	if (test_bits(XIO_SOCK_ESTABLISH_CTL,
		      &tcp_hndl->socket.establish_states)) {
		return;
	}
	set_bits(XIO_SOCK_ESTABLISH_CTL, &tcp_hndl->socket.establish_states);

	DEBUG_LOG("tcp_hndl=%p\n", tcp_hndl);
	msg.sock_type = XIO_TCP_CTL_SOCK;
	msg.second_port = tcp_hndl->socket.data.port;
	msg.pad = 0;
	retval = xio_tcp_send_connect_msg(tcp_hndl->socket.ctl.ksock, &msg);
	if (retval)
		goto cleanup;

	if (test_bits(XIO_SOCK_ESTABLISH_DATA,
		      &tcp_hndl->socket.establish_states))
		xio_tcp_conn_established_helper(tcp_hndl);

	return;

cleanup:
	xio_transport_notify_observer_error(&tcp_hndl->base,
					    XIO_E_CONNECT_ERROR);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_data_conn_established_ev_handler	                             */
/*---------------------------------------------------------------------------*/
void xio_tcp_data_conn_established_ev_handler(void *user_context)
{
	struct xio_tcp_transport	*tcp_hndl = user_context;
	int				retval = 0;
	struct xio_tcp_connect_msg	msg;

	if (test_bits(XIO_SOCK_ESTABLISH_DATA,
		      &tcp_hndl->socket.establish_states)) {
		return;
	}
	set_bits(XIO_SOCK_ESTABLISH_DATA, &tcp_hndl->socket.establish_states);

	DEBUG_LOG("tcp_hndl=%p\n", tcp_hndl);

	msg.sock_type = XIO_TCP_DATA_SOCK;
	msg.second_port = tcp_hndl->socket.ctl.port;
	msg.pad = 0;
	retval = xio_tcp_send_connect_msg(tcp_hndl->socket.data.ksock, &msg);
	if (retval)
		goto cleanup;

	if (test_bits(XIO_SOCK_ESTABLISH_CTL,
		      &tcp_hndl->socket.establish_states))
		xio_tcp_conn_established_helper(tcp_hndl);

	return;

cleanup:
	xio_transport_notify_observer_error(&tcp_hndl->base,
					    XIO_E_CONNECT_ERROR);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_single_sock_connect	                                             */
/*---------------------------------------------------------------------------*/
int xio_tcp_single_sock_connect(struct xio_tcp_transport *tcp_hndl,
				struct sockaddr *sa,
				socklen_t sa_len)
{
	int retval;

	tcp_hndl->socket.ctl.conn_establish_event_data.data = tcp_hndl;
	tcp_hndl->socket.ctl.conn_establish_event_data.handler =
				xio_tcp_single_conn_established_ev_handler;

	xio_tcp_save_orig_callbacks(&tcp_hndl->socket.ctl);
	xio_tcp_set_callbacks(tcp_hndl->socket.ctl.ksock,
			      NULL, xio_tcp_state_change_cb, NULL, tcp_hndl);
	retval = xio_tcp_connect_helper(tcp_hndl->socket.ctl.ksock, sa, sa_len,
					&tcp_hndl->socket.ctl.port,
					&tcp_hndl->base.local_addr);
	if (retval)
		return retval;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_dual_sock_connect	                                             */
/*---------------------------------------------------------------------------*/
int xio_tcp_dual_sock_connect(struct xio_tcp_transport *tcp_hndl,
			      struct sockaddr *sa,
			      socklen_t sa_len)
{
	int retval;

	tcp_hndl->tmp_rx_buf = kzalloc(TMP_RX_BUF_SIZE, GFP_KERNEL);
	if (!tcp_hndl->tmp_rx_buf) {
		xio_set_error(ENOMEM);
		ERROR_LOG("ucalloc failed. %m\n");
		return -1;
	}
	tcp_hndl->tmp_rx_buf_cur = tcp_hndl->tmp_rx_buf;

	tcp_hndl->socket.data.conn_establish_event_data.data = tcp_hndl;
	tcp_hndl->socket.data.conn_establish_event_data.handler =
				xio_tcp_data_conn_established_ev_handler;

	xio_tcp_save_orig_callbacks(&tcp_hndl->socket.data);
	xio_tcp_set_callbacks(tcp_hndl->socket.data.ksock,
			      NULL, xio_tcp_state_change_cb, NULL, tcp_hndl);
	retval = xio_tcp_connect_helper(tcp_hndl->socket.data.ksock, sa, sa_len,
					&tcp_hndl->socket.data.port,
					NULL);
	if (retval)
		return retval;

	tcp_hndl->socket.ctl.conn_establish_event_data.data = tcp_hndl;
	tcp_hndl->socket.ctl.conn_establish_event_data.handler =
				xio_tcp_ctl_conn_established_ev_handler;

	xio_tcp_save_orig_callbacks(&tcp_hndl->socket.ctl);
	xio_tcp_set_callbacks(tcp_hndl->socket.ctl.ksock,
			      NULL, xio_tcp_state_change_cb, NULL, tcp_hndl);

	retval = xio_tcp_connect_helper(tcp_hndl->socket.ctl.ksock, sa, sa_len,
					&tcp_hndl->socket.ctl.port,
					&tcp_hndl->base.local_addr);
	if (retval)
		return retval;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_connect		                                             */
/*---------------------------------------------------------------------------*/
static int xio_tcp_connect(struct xio_transport_base *transport,
			   const char *portal_uri, const char *out_if_addr)
{
	struct xio_tcp_transport	*tcp_hndl =
					(struct xio_tcp_transport *)transport;
	union xio_sockaddr		rsa;
	socklen_t			rsa_len = 0;
	int				retval = 0;

	/* resolve the portal_uri */
	rsa_len = xio_uri_to_ss(portal_uri, &rsa.sa_stor);
	if (rsa_len == -1) {
		xio_set_error(XIO_E_ADDR_ERROR);
		ERROR_LOG("address [%s] resolving failed\n", portal_uri);
		return -1;
	}
	/* allocate memory for portal_uri */
	tcp_hndl->base.portal_uri = kstrdup(portal_uri, GFP_KERNEL);
	if (!tcp_hndl->base.portal_uri) {
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
		retval = tcp_hndl->socket.ctl.ksock->ops->bind(
				tcp_hndl->socket.ctl.ksock,
				(struct sockaddr *)&if_sa.sa_stor, sa_len);
		if (retval) {
			xio_set_error(-retval);
			ERROR_LOG("tcp bind failed. (errno=%d %m)\n",
				  -retval);
			goto exit;
		}
	}

	/* connect */
	retval = tcp_hndl->socket.ops->connect(tcp_hndl,
					     (struct sockaddr *)&rsa.sa_stor,
					     rsa_len);
	if (retval)
		goto exit;

	return 0;

exit:
	kfree(tcp_hndl->base.portal_uri);
	tcp_hndl->base.portal_uri = NULL;

	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_open								     */
/*---------------------------------------------------------------------------*/
static struct xio_transport_base *xio_tcp_open(
		struct xio_transport	*transport,
		struct xio_context	*ctx,
		struct xio_observer	*observer,
		uint32_t		trans_attr_mask,
		struct xio_transport_init_attr *attr)
{
	struct xio_tcp_transport	*tcp_hndl;

	tcp_hndl = xio_tcp_transport_create(transport, ctx, observer, 1);
	if (!tcp_hndl) {
		ERROR_LOG("failed. to create tcp transport%m\n");
		return NULL;
	}
	return (struct xio_transport_base *)tcp_hndl;
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
	rxd->msg.msg_flags = MSG_DONTWAIT;
	rxd->msg.msg_name = NULL;
	rxd->msg.msg_namelen = 0;
	MSGHDR_IOV(&rxd->msg) = NULL;
	MSGHDR_IOVLEN(&rxd->msg) = 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_txd_init							     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_txd_init(struct xio_tcp_work_req *txd,
			     void *buf, unsigned size)
{
	txd->ctl_msg = buf;
	txd->ctl_msg_len = 0;
	txd->msg_iov[0].iov_base = buf;
	txd->msg_iov[0].iov_len	= size;
	txd->msg_len = 1;
	txd->tot_iov_byte_len = 0;

	txd->stage = XIO_TCP_TX_BEFORE;
	txd->msg.msg_control = NULL;
	txd->msg.msg_controllen = 0;
	txd->msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
	txd->msg.msg_name = NULL;
	txd->msg.msg_namelen = 0;
	MSGHDR_IOV(&txd->msg) = NULL;
	MSGHDR_IOVLEN(&txd->msg) = 0;
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

	tcp_task->buf = buf;

	xio_tcp_rxd_init(&tcp_task->rxd, buf, size);
	xio_tcp_txd_init(&tcp_task->txd, buf, size);

	/* initialize the mbuf */
	xio_mbuf_init(&task->mbuf, buf, size, 0);

	memset(&tcp_task->comp_event, 0, sizeof(tcp_task->comp_event));
	tcp_task->comp_event.handler = xio_tcp_tx_completion_handler;
	tcp_task->comp_event.data = task;
}

/* task pools management */
/*---------------------------------------------------------------------------*/
/* xio_tcp_initial_pool_slab_pre_create					     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_initial_pool_slab_pre_create(
		struct xio_transport_base *transport_hndl,
		int alloc_nr,
		void *pool_dd_data, void *slab_dd_data)
{
	struct xio_tcp_tasks_slab *tcp_slab =
		(struct xio_tcp_tasks_slab *)slab_dd_data;

	tcp_slab->buf_size = CONN_SETUP_BUF_SIZE;

	/* The name must be valid until the pool is destroyed
	 * Use the address of the pool structure to create a unique
	 * name for the pool
	 */
	sprintf(tcp_slab->name, "initial_pool-%p", tcp_slab);
	tcp_slab->data_pool = kmem_cache_create(
				tcp_slab->name,
				tcp_slab->buf_size/*pool_size * alloc_nr*/,
				PAGE_SIZE,
				SLAB_HWCACHE_ALIGN, NULL);
	if (!tcp_slab->data_pool) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcache(initial_pool) creation failed\n");
		return -1;
	}
	INFO_LOG("kcache(%s) created(%p)\n",
		 tcp_slab->name, tcp_slab->data_pool);
	tcp_slab->count = 0;

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_initial_task_alloc						     */
/*---------------------------------------------------------------------------*/
static inline struct xio_task *xio_tcp_initial_task_alloc(
					struct xio_tcp_transport *tcp_hndl)
{
	return tcp_hndl->initial_pool_cls.task_get(
				tcp_hndl->initial_pool_cls.pool, tcp_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_primary_task_alloc						     */
/*---------------------------------------------------------------------------*/
struct xio_task *xio_tcp_primary_task_alloc(
					struct xio_tcp_transport *tcp_hndl)
{
	return tcp_hndl->primary_pool_cls.task_get(
					tcp_hndl->primary_pool_cls.pool,
					tcp_hndl);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_primary_task_lookup						     */
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

	if (!tcp_hndl)
		return 0;

	tcp_hndl->initial_pool_cls.pool = pool;

	task = xio_tcp_initial_task_alloc(tcp_hndl);
	if (!task) {
		ERROR_LOG("failed to get task\n");
	} else {
		list_add_tail(&task->tasks_list_entry, &tcp_hndl->rx_list);
		tcp_task = (struct xio_tcp_task *)task->dd_data;
		tcp_task->out_tcp_op = XIO_TCP_RECV;
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

	INFO_LOG("kcache(%s) freed\n", tcp_slab->name);

	if (tcp_slab->count)
		ERROR_LOG("pool(%s) not-free(%d)\n", tcp_slab->name,
			  tcp_slab->count);
	kmem_cache_destroy(tcp_slab->data_pool);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_pool_slab_uninit_task					     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_pool_slab_uninit_task(struct xio_transport_base *trans_hndl,
					 void *pool_dd_data, void *slab_dd_data,
					 struct xio_task *task)
{
	struct xio_tcp_tasks_slab *tcp_slab =
		(struct xio_tcp_tasks_slab *)slab_dd_data;

	XIO_TO_TCP_TASK(task, tcp_task);

	/* Phantom tasks have no buffer */
	if (tcp_task->buf) {
		if (tcp_slab->count)
			tcp_slab->count--;
		else
			ERROR_LOG("pool(%s) double free?\n", tcp_slab->name);

		kmem_cache_free(tcp_slab->data_pool, tcp_task->buf);
		tcp_task->buf = NULL;
	}

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
	void *buf;
	char *ptr;

	XIO_TO_TCP_TASK(task, tcp_task);

	if (!tcp_hndl || tcp_task->buf)
		return 0;


	/* fill xio_tcp_task */
	ptr = (char *)tcp_task;
	ptr += sizeof(struct xio_tcp_task);

	/* fill xio_tcp_work_req */
	tcp_task->txd.msg_iov = (void *)ptr;
	ptr += sizeof(struct iovec);

	tcp_task->rxd.msg_iov = (void *)ptr;
	ptr += 2 * sizeof(struct iovec);
	/*****************************************/

	buf = kmem_cache_zalloc(tcp_slab->data_pool, GFP_KERNEL);
	if (!buf) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kmem_cache_zalloc(initial_pool)\n");
		return -ENOMEM;
	}
	tcp_slab->count++;

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
	*start_nr = 10 * NUM_CONN_SETUP_TASKS;
	*alloc_nr = 10 * NUM_CONN_SETUP_TASKS;
	*max_nr = 10 * NUM_CONN_SETUP_TASKS;

	*pool_dd_sz = 0;
	*slab_dd_sz = sizeof(struct xio_tcp_tasks_slab);
	*task_dd_sz = sizeof(struct xio_tcp_task) + 3 * sizeof(struct iovec);
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_task_pre_put							     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_task_pre_put(struct xio_transport_base *trans_hndl,
				struct xio_task *task)
{
	XIO_TO_TCP_TASK(task, tcp_task);
	unsigned int	i;

	/* recycle TCP  buffers back to pool */

	/* put buffers back to pool */

	for (i = 0; i < tcp_task->read_num_mp_mem; i++) {
		if (tcp_task->read_mp_mem[i].cache) {
			xio_mempool_free_mp(&tcp_task->read_mp_mem[i]);
			tcp_task->read_mp_mem[i].cache = NULL;
		}
	}

	tcp_task->read_num_mp_mem = 0;

	for (i = 0; i < tcp_task->write_num_mp_mem; i++) {
		if (tcp_task->write_mp_mem[i].cache) {
			xio_mempool_free_mp(&tcp_task->write_mp_mem[i]);
			tcp_task->write_mp_mem[i].cache = NULL;
		}
	}

	tcp_task->write_num_mp_mem		= 0;
	tcp_task->req_in_num_sge	= 0;
	tcp_task->req_out_num_sge	= 0;
	tcp_task->rsp_out_num_sge	= 0;
	tcp_task->sn			= 0;

	tcp_task->in_tcp_op		= XIO_TCP_NULL;
	tcp_task->out_tcp_op		= XIO_TCP_NULL;

	xio_tcp_rxd_init(&tcp_task->rxd,
			 task->mbuf.buf.head,
			 task->mbuf.buf.buflen);
	xio_tcp_txd_init(&tcp_task->txd,
			 task->mbuf.buf.head,
			 task->mbuf.buf.buflen);

	/* todo how to remove? */
	xio_context_disable_event(&tcp_task->comp_event);

	return 0;
}

static struct xio_tasks_pool_ops initial_tasks_pool_ops = {
	.pool_get_params	= xio_tcp_initial_pool_get_params,
	.slab_pre_create	= xio_tcp_initial_pool_slab_pre_create,
	.slab_destroy		= xio_tcp_initial_pool_slab_destroy,
	.slab_init_task		= xio_tcp_initial_pool_slab_init_task,
	.slab_uninit_task	= xio_tcp_pool_slab_uninit_task,
	.pool_post_create	= xio_tcp_initial_pool_post_create,
	.task_pre_put		= xio_tcp_task_pre_put
};

/*---------------------------------------------------------------------------*/
/* xio_tcp_primary_pool_slab_pre_create				     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_primary_pool_slab_pre_create(
		struct xio_transport_base *transport_hndl,
		int alloc_nr, void *pool_dd_data, void *slab_dd_data)
{
	struct xio_tcp_tasks_slab *tcp_slab =
		(struct xio_tcp_tasks_slab *)slab_dd_data;
	size_t inline_buf_sz = xio_tcp_get_inline_buffer_size();

	tcp_slab->buf_size = inline_buf_sz;
	/* The name must be valid until the pool is destroyed
	 * Use the address of the pool structure to create a unique
	 * name for the pool
	 */
	sprintf(tcp_slab->name, "primary_pool-%p", tcp_slab);
	tcp_slab->data_pool = kmem_cache_create(tcp_slab->name,
						 tcp_slab->buf_size, PAGE_SIZE,
						 SLAB_HWCACHE_ALIGN, NULL);
	if (!tcp_slab->data_pool) {
		xio_set_error(ENOMEM);
		ERROR_LOG("kcache(primary_pool) creation failed\n");
		return -1;
	}
	INFO_LOG("kcache(%s) created(%p)\n",
		 tcp_slab->name, tcp_slab->data_pool);

	DEBUG_LOG("pool buf:%p\n", tcp_slab->data_pool);
	tcp_slab->count = 0;

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

	if (!tcp_hndl)
		return 0;

	tcp_hndl->primary_pool_cls.pool = pool;

	for (i = 0; i < RX_LIST_POST_NR; i++) {
		/* get ready to receive message */
		task = xio_tcp_primary_task_alloc(tcp_hndl);
		if (task == 0) {
			ERROR_LOG("primary task pool is empty\n");
			return -1;
		}
		tcp_task = task->dd_data;
		tcp_task->out_tcp_op = XIO_TCP_RECV;
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

	INFO_LOG("kcache(%s) freed cnt:%d\n", tcp_slab->name, tcp_slab->count);

	if (tcp_slab->count)
		ERROR_LOG("pool(%s) not-free(%d)\n",
			  tcp_slab->name, tcp_slab->count);

	kmem_cache_destroy(tcp_slab->data_pool);

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
	void *buf;
	int  max_iovsz = max(tcp_options.max_out_iovsz,
				     tcp_options.max_in_iovsz) + 1;
	char *ptr;

	XIO_TO_TCP_TASK(task, tcp_task);

	if (!tcp_hndl || tcp_task->buf)
		return 0;

	/* fill xio_tco_task */
	ptr = (char *)tcp_task;
	ptr += sizeof(struct xio_tcp_task);

	/* fill xio_tcp_work_req */
	tcp_task->txd.msg_iov = (void *)ptr;
	ptr += (max_iovsz + 1) * sizeof(struct iovec);
	tcp_task->rxd.msg_iov = (void *)ptr;
	ptr += (max_iovsz + 1) * sizeof(struct iovec);

	tcp_task->read_mp_mem = (void *)ptr;
	ptr += max_iovsz * sizeof(struct xio_mp_mem);
	tcp_task->write_mp_mem = (void *)ptr;
	ptr += max_iovsz * sizeof(struct xio_mp_mem);

	tcp_task->req_in_sge = (void *)ptr;
	ptr += max_iovsz * sizeof(struct xio_sge);
	tcp_task->req_out_sge = (void *)ptr;
	ptr += max_iovsz * sizeof(struct xio_sge);
	tcp_task->rsp_out_sge = (void *)ptr;
	ptr += max_iovsz * sizeof(struct xio_sge);
	/*****************************************/

	buf = kmem_cache_zalloc(tcp_slab->data_pool, GFP_KERNEL);
	if (!buf) {
		ERROR_LOG("kmem_cache_zalloc(primary_pool)\n");
		xio_set_error(ENOMEM);
		return -ENOMEM;
	}
	tcp_slab->count++;

	tcp_task->out_tcp_op = 0x200;
	xio_tcp_task_init(
			task,
			tcp_hndl,
			buf,
			tcp_slab->buf_size);

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
	int  max_iovsz = max(tcp_options.max_out_iovsz,
			     tcp_options.max_in_iovsz) + 1;

	*start_nr = NUM_START_PRIMARY_POOL_TASKS;
	*alloc_nr = NUM_ALLOC_PRIMARY_POOL_TASKS;
	*max_nr = max((g_poptions->snd_queue_depth_msgs +
		       g_poptions->rcv_queue_depth_msgs), *start_nr);

	*pool_dd_sz = 0;
	*slab_dd_sz = sizeof(struct xio_tcp_tasks_slab);
	*task_dd_sz = sizeof(struct xio_tcp_task) +
			(2 * (max_iovsz + 1)) * sizeof(struct iovec) +
			 2 * max_iovsz * sizeof(struct xio_mp_mem) +
			 3 * max_iovsz * sizeof(struct xio_sge);
}

static struct xio_tasks_pool_ops   primary_tasks_pool_ops = {
	.pool_get_params	= xio_tcp_primary_pool_get_params,
	.slab_pre_create	= xio_tcp_primary_pool_slab_pre_create,
	.slab_destroy		= xio_tcp_primary_pool_slab_destroy,
	.slab_init_task		= xio_tcp_primary_pool_slab_init_task,
	.slab_uninit_task	= xio_tcp_pool_slab_uninit_task,
	.pool_post_create	= xio_tcp_primary_pool_post_create,
	.task_pre_put		= xio_tcp_task_pre_put,
};

/*---------------------------------------------------------------------------*/
/* xio_tcp_get_pools_ops						     */
/*---------------------------------------------------------------------------*/
static void xio_tcp_get_pools_ops(struct xio_transport_base *trans_hndl,
				  struct xio_tasks_pool_ops **initial_pool_ops,
				  struct xio_tasks_pool_ops **primary_pool_ops)
{
	*initial_pool_ops = &initial_tasks_pool_ops;
	*primary_pool_ops = &primary_tasks_pool_ops;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_set_pools_cls						     */
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
/* xio_tcp_set_opt                                                           */
/*---------------------------------------------------------------------------*/
static int xio_tcp_set_opt(void *xio_obj,
			   int optname, const void *optval, int optlen)
{
	switch (optname) {
	case XIO_OPTNAME_ENABLE_MEM_POOL:
		VALIDATE_SZ(sizeof(int));
		tcp_options.enable_mem_pool = *((int *)optval);
		return 0;
	case XIO_OPTNAME_ENABLE_DMA_LATENCY:
		VALIDATE_SZ(sizeof(int));
		tcp_options.enable_dma_latency = *((int *)optval);
		return 0;
	case XIO_OPTNAME_MAX_IN_IOVLEN:
		VALIDATE_SZ(sizeof(int));
		tcp_options.max_in_iovsz = *((int *)optval);
		return 0;
	case XIO_OPTNAME_MAX_OUT_IOVLEN:
		VALIDATE_SZ(sizeof(int));
		tcp_options.max_out_iovsz = *((int *)optval);
		return 0;
	case XIO_OPTNAME_TCP_ENABLE_MR_CHECK:
		VALIDATE_SZ(sizeof(int));
		tcp_options.enable_mr_check = *((int *)optval);
		return 0;
	case XIO_OPTNAME_TCP_NO_DELAY:
		VALIDATE_SZ(sizeof(int));
		tcp_options.tcp_no_delay = *((int *)optval);
		return 0;
	case XIO_OPTNAME_TCP_SO_SNDBUF:
		VALIDATE_SZ(sizeof(int));
		tcp_options.tcp_so_sndbuf = *((int *)optval);
		return 0;
	case XIO_OPTNAME_TCP_SO_RCVBUF:
		VALIDATE_SZ(sizeof(int));
		tcp_options.tcp_so_rcvbuf = *((int *)optval);
		return 0;
	case XIO_OPTNAME_TCP_DUAL_STREAM:
		VALIDATE_SZ(sizeof(int));
		tcp_options.tcp_dual_sock = *((int *)optval);
		return 0;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_get_opt                                                           */
/*---------------------------------------------------------------------------*/
static int xio_tcp_get_opt(void  *xio_obj,
			   int optname, void *optval, int *optlen)
{
	switch (optname) {
	case XIO_OPTNAME_ENABLE_MEM_POOL:
		*((int *)optval) = tcp_options.enable_mem_pool;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_ENABLE_DMA_LATENCY:
		*((int *)optval) = tcp_options.enable_dma_latency;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_MAX_IN_IOVLEN:
		*((int *)optval) = tcp_options.max_in_iovsz;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_MAX_OUT_IOVLEN:
		*((int *)optval) = tcp_options.max_out_iovsz;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_TCP_ENABLE_MR_CHECK:
		*((int *)optval) = tcp_options.enable_mr_check;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_TCP_NO_DELAY:
		*((int *)optval) = tcp_options.tcp_no_delay;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_TCP_SO_SNDBUF:
		*((int *)optval) = tcp_options.tcp_so_sndbuf;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_TCP_SO_RCVBUF:
		*((int *)optval) = tcp_options.tcp_so_rcvbuf;
		*optlen = sizeof(int);
		return 0;
	case XIO_OPTNAME_TCP_DUAL_STREAM:
		*((int *)optval) = tcp_options.tcp_dual_sock;
		*optlen = sizeof(int);
		return 0;
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
	unsigned int		i;
	struct xio_vmsg *vmsg = &msg->in;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sge;
	unsigned long		nents, max_nents;

	sgtbl		= xio_sg_table_get(&msg->in);
	sgtbl_ops	= xio_sg_table_ops_get(msg->in.sgl_type);
	nents		= tbl_nents(sgtbl_ops, sgtbl);
	max_nents	= tbl_max_nents(sgtbl_ops, sgtbl);

	if ((nents > (unsigned long)tcp_options.max_in_iovsz) ||
	    (nents > max_nents) ||
	    (max_nents > (unsigned long)tcp_options.max_in_iovsz)) {
		return 0;
	}

	if (vmsg->sgl_type == XIO_SGL_TYPE_IOV && nents > XIO_IOVLEN)
		return 0;

	if (vmsg->header.iov_base  &&
	    (vmsg->header.iov_len == 0))
		return 0;

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		if (sge_addr(sgtbl_ops, sge) &&
		    (sge_length(sgtbl_ops, sge)  == 0))
			return 0;
	}

	return 1;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_is_valid_out_msg						     */
/*---------------------------------------------------------------------------*/
static int xio_tcp_is_valid_out_msg(struct xio_msg *msg)
{
	unsigned int		i;
	struct xio_vmsg		*vmsg = &msg->out;
	struct xio_sg_table_ops	*sgtbl_ops;
	void			*sgtbl;
	void			*sge;
	unsigned long		nents, max_nents;

	sgtbl		= xio_sg_table_get(&msg->out);
	sgtbl_ops	= xio_sg_table_ops_get(msg->out.sgl_type);
	nents		= tbl_nents(sgtbl_ops, sgtbl);
	max_nents	= tbl_max_nents(sgtbl_ops, sgtbl);

	if ((nents > (unsigned long)tcp_options.max_out_iovsz) ||
	    (nents > max_nents) ||
	    (max_nents > (unsigned long)tcp_options.max_out_iovsz))
		return 0;

	if (vmsg->sgl_type == XIO_SGL_TYPE_IOV && nents > XIO_IOVLEN)
		return 0;

	if ((vmsg->header.iov_base  &&
	     (vmsg->header.iov_len == 0)) ||
	    (!vmsg->header.iov_base  &&
	     (vmsg->header.iov_len != 0)))
			return 0;

	if (vmsg->header.iov_len > (size_t)xio_get_options()->max_inline_xio_hdr)
		return 0;

	for_each_sge(sgtbl, sgtbl_ops, sge, i) {
		if (!sge_addr(sgtbl_ops, sge) ||
		    (sge_length(sgtbl_ops, sge) == 0))
			return 0;
	}

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
	/*kref_get(&old_trans_hndl->kref);*/

	*new_trans_hndl = old_trans_hndl;

	return 0;
}

static struct xio_tcp_socket_ops single_sock_ops = {
	.open			= xio_tcp_single_sock_create,
	.add_ev_handlers	= xio_tcp_single_sock_add_ev_handlers,
	.del_ev_handlers	= xio_tcp_single_sock_del_ev_handlers,
	.connect		= xio_tcp_single_sock_connect,
	.set_txd		= xio_tcp_single_sock_set_txd,
	.set_rxd		= xio_tcp_single_sock_set_rxd,
	.rx_ctl_work		= xio_tcp_recvmsg_work,
	.rx_ctl_handler		= xio_tcp_single_sock_rx_ctl_handler,
	.rx_data_handler	= xio_tcp_rx_data_handler,
	.shutdown		= xio_tcp_single_sock_shutdown,
	.close			= xio_tcp_single_sock_close,
};

static struct xio_tcp_socket_ops dual_sock_ops = {
	.open			= xio_tcp_dual_sock_create,
	.add_ev_handlers	= xio_tcp_dual_sock_add_ev_handlers,
	.del_ev_handlers	= xio_tcp_dual_sock_del_ev_handlers,
	.connect		= xio_tcp_dual_sock_connect,
	.set_txd		= xio_tcp_dual_sock_set_txd,
	.set_rxd		= xio_tcp_dual_sock_set_rxd,
	.rx_ctl_work		= xio_tcp_recv_ctl_work,
	.rx_ctl_handler		= xio_tcp_dual_sock_rx_ctl_handler,
	.rx_data_handler	= xio_tcp_rx_data_handler,
	.shutdown		= xio_tcp_dual_sock_shutdown,
	.close			= xio_tcp_dual_sock_close,
};

struct xio_transport xio_tcp_transport = {
	.name			= "tcp",
	.ctor			= NULL,
	.dtor			= NULL,
	.init			= NULL,
	.release		= NULL,
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
	.cancel_req		= xio_tcp_cancel_req,
	.cancel_rsp		= xio_tcp_cancel_rsp,
	.get_pools_setup_ops	= xio_tcp_get_pools_ops,
	.set_pools_cls		= xio_tcp_set_pools_cls,

	.validators_cls.is_valid_in_req  = xio_tcp_is_valid_in_req,
	.validators_cls.is_valid_out_msg = xio_tcp_is_valid_out_msg,
};

/*---------------------------------------------------------------------------*/
/* xio_tcp_transport_constructor					     */
/*---------------------------------------------------------------------------*/
static int __init xio_tcp_transport_constructor(void)
{
	struct xio_transport *transport = &xio_tcp_transport;

	/* register the transport */
	xio_reg_transport(transport);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_tcp_transport_destructor						     */
/*---------------------------------------------------------------------------*/
static void __exit xio_tcp_transport_destructor(void)
{
	struct xio_transport *transport = &xio_tcp_transport;

	/* Called after all devices were deleted */

	xio_unreg_transport(transport);
}

static int __init xio_init_module(void)
{
	if (debugfs_initialized()) {
		xio_tcp_root = debugfs_create_dir("xio_tcp", NULL);
		if (!xio_tcp_root) {
			pr_err("xio_tcp root debugfs creation failed\n");
			return -ENOMEM;
		}
	} else {
		xio_tcp_root = NULL;
		pr_err("debugfs not initialized\n");
	}

	xio_tcp_transport_constructor();
	g_poptions = xio_get_options();
	return 0;
}

static void __exit xio_cleanup_module(void)
{
	xio_tcp_transport_destructor();

	debugfs_remove_recursive(xio_tcp_root);
}

module_init(xio_init_module);
module_exit(xio_cleanup_module);
