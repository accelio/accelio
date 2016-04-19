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
#ifndef XIO_CONTEXT_H
#define XIO_CONTEXT_H

#define xio_ctx_work_t  xio_work_handle_t
#define xio_ctx_delayed_work_t  xio_delayed_work_handle_t

#define XIO_PROTO_LAST  2	/* from enum xio_proto */

#ifdef XIO_THREAD_SAFE_DEBUG
#define BACKTRACE_BUFFER_SIZE 2048
#endif

/*---------------------------------------------------------------------------*/
/* enum									     */
/*---------------------------------------------------------------------------*/
enum xio_context_event {
	XIO_CONTEXT_EVENT_CLOSE,
	XIO_CONTEXT_EVENT_POST_CLOSE
};

enum xio_context_pool_class {
	XIO_CONTEXT_POOL_CLASS_INITIAL,
	XIO_CONTEXT_POOL_CLASS_PRIMARY
};

enum xio_counters {
	XIO_STAT_TX_MSG,
	XIO_STAT_RX_MSG,
	XIO_STAT_TX_BYTES,
	XIO_STAT_RX_BYTES,
	XIO_STAT_DELAY,
	XIO_STAT_APPDELAY,
	/* user can register 10 more messages */
	XIO_STAT_USER_FIRST,
	XIO_STAT_LAST = 16
};

typedef int (*poll_completions_fn_t)(void *, int);

/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct xio_statistics {
	uint64_t	hertz;
	uint64_t	counter[XIO_STAT_LAST];
	char		*name[XIO_STAT_LAST];
};

struct xio_context {
	void				*ev_loop;
	void				*mempool;
	/* pools per transport */
	struct xio_tasks_pool		*primary_tasks_pool[XIO_PROTO_LAST];
	struct xio_tasks_pool_ops	*primary_pool_ops[XIO_PROTO_LAST];

	struct xio_tasks_pool		*initial_tasks_pool[XIO_PROTO_LAST];
	struct xio_tasks_pool_ops	*initial_pool_ops[XIO_PROTO_LAST];

	/* pool per connection */
	struct xio_objpool		*msg_pool;

	void				*poll_completions_ctx;
	poll_completions_fn_t		poll_completions_fn;

	int				cpuid;
	int				nodeid;
	int				polling_timeout;
	unsigned int			flags;
	uint64_t			worker;

	int32_t				run_private;

	uint32_t			is_running:1;
	uint32_t			defered_destroy:1;
	uint32_t			prealloc_xio_inline_bufs:1;
	uint32_t			register_internal_mempool:1;
	uint32_t			resereved:28;

	struct xio_statistics		stats;
	void				*user_context;
	struct xio_workqueue		*workqueue;
	struct list_head		ctx_list;  /* per context storage */

	/* list of sessions using this connection */
	struct xio_observable		observable;
	void				*netlink_sock;
	xio_work_handle_t               destroy_ctx_work;
	spinlock_t                      ctx_list_lock;

	int				max_conns_per_ctx;
	int				rq_depth;
	int				pad;
#ifdef XIO_THREAD_SAFE_DEBUG
	int                             nptrs;
	int				pad1;
	pthread_mutex_t                 dbg_thread_mutex;
	void                            *buffer[BACKTRACE_BUFFER_SIZE];
#endif

};

/*---------------------------------------------------------------------------*/
/* xio_context_reg_observer						     */
/*---------------------------------------------------------------------------*/
int xio_context_reg_observer(struct xio_context *context,
			     struct xio_observer *observer);

/*---------------------------------------------------------------------------*/
/* xio_context_unreg_observer						     */
/*---------------------------------------------------------------------------*/
void xio_context_unreg_observer(struct xio_context *conn,
				struct xio_observer *observer);

/*---------------------------------------------------------------------------*/
/* xio_add_counter							     */
/*---------------------------------------------------------------------------*/
int xio_add_counter(struct xio_context *ctx, char *name);

/*---------------------------------------------------------------------------*/
/* xio_del_counter							     */
/*---------------------------------------------------------------------------*/
int xio_del_counter(struct xio_context *ctx, int counter);

/*---------------------------------------------------------------------------*/
/* xio_ctx_stat_add							     */
/*---------------------------------------------------------------------------*/
static inline void xio_ctx_stat_add(struct xio_context *ctx,
				    int counter, uint64_t val)
{
	ctx->stats.counter[counter] += val;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_stat_inc							     */
/*---------------------------------------------------------------------------*/
static inline void xio_ctx_stat_inc(struct xio_context *ctx, int counter)
{
	ctx->stats.counter[counter]++;
}

/*---------------------------------------------------------------------------*/
/* xio_stat_add								     */
/*---------------------------------------------------------------------------*/
static inline void xio_stat_add(struct xio_statistics *stats,
				int counter, uint64_t val)
{
	stats->counter[counter] += val;
}

/*---------------------------------------------------------------------------*/
/* xio_stat_inc								     */
/*---------------------------------------------------------------------------*/
static inline void xio_stat_inc(struct xio_statistics *stats, int counter)
{
	stats->counter[counter]++;
}

/*---------------------------------------------------------------------------*/
/* xio_ctx_add_delayed_work						     */
/*---------------------------------------------------------------------------*/
int xio_ctx_add_delayed_work(struct xio_context *ctx,
			     int msec_duration, void *data,
			     void (*timer_fn)(void *data),
			     xio_ctx_delayed_work_t *work);

/*---------------------------------------------------------------------------*/
/* xio_ctx_del_delayed_work					             */
/*---------------------------------------------------------------------------*/
int xio_ctx_del_delayed_work(struct xio_context *ctx,
			     xio_ctx_delayed_work_t *work);

/*---------------------------------------------------------------------------*/
/* xio_ctx_add_work							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_add_work(struct xio_context *ctx, void *data,
		     void (*function)(void *data),
		     xio_ctx_work_t *work);

/*---------------------------------------------------------------------------*/
/* xio_ctx_set_work_destructor						     */
/*---------------------------------------------------------------------------*/
int xio_ctx_set_work_destructor(
		     struct xio_context *ctx, void *data,
		     void (*destructor)(void *data),
		     xio_ctx_work_t *work);

/*---------------------------------------------------------------------------*/
/* xio_ctx_is_work_in_handler						     */
/*---------------------------------------------------------------------------*/
int xio_ctx_is_work_in_handler(struct xio_context *ctx, xio_ctx_work_t *work);

/*---------------------------------------------------------------------------*/
/* xio_ctx_del_work							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_del_work(struct xio_context *ctx,
		     xio_ctx_work_t *work);

/*---------------------------------------------------------------------------*/
/* xio_ctx_add_event							     */
/*---------------------------------------------------------------------------*/
int xio_context_add_event(struct xio_context *ctx, struct xio_ev_data *evt);

/*---------------------------------------------------------------------------*/
/* xio_context_disable_event						     */
/*---------------------------------------------------------------------------*/
void xio_context_disable_event(struct xio_ev_data *evt);

/*---------------------------------------------------------------------------*/
/* xio_context_is_pending_event						     */
/*---------------------------------------------------------------------------*/
int xio_context_is_pending_event(struct xio_ev_data *evt);

/*---------------------------------------------------------------------------*/
/* xio_context_is_loop_stopping						     */
/*---------------------------------------------------------------------------*/
int xio_context_is_loop_stopping(struct xio_context *ctx);

/*---------------------------------------------------------------------------*/
/* xio_context_set_poll_completions_fn	                                     */
/*---------------------------------------------------------------------------*/
void xio_context_set_poll_completions_fn(
		struct xio_context *ctx,
		poll_completions_fn_t poll_completions_fn,
		void *poll_completions_ctx);

/*---------------------------------------------------------------------------*/
/* xio_context_modify_ev_handler					     */
/*---------------------------------------------------------------------------*/
int xio_context_modify_ev_handler(struct xio_context *ctx,
				  int fd, int events);

/*
 * should be called only from context_shutdown event context
 */
/*---------------------------------------------------------------------------*/
/* xio_context_destroy_wait	                                             */
/*---------------------------------------------------------------------------*/
static inline void xio_context_destroy_wait(struct xio_context *ctx)
{
	ctx->run_private++;
}

/*
 * should be called only from loop context
 */
/*---------------------------------------------------------------------------*/
/* xio_context_destroy_resume	                                             */
/*---------------------------------------------------------------------------*/
void xio_context_destroy_resume(struct xio_context *ctx);

/*---------------------------------------------------------------------------*/
/* xio_context_msg_pool_get	                                             */
/*---------------------------------------------------------------------------*/
static inline void *xio_context_msg_pool_get(struct xio_context *ctx)
{
	return xio_objpool_alloc(ctx->msg_pool);
}

/*---------------------------------------------------------------------------*/
/* xio_context_msg_pool_put	                                             */
/*---------------------------------------------------------------------------*/
static inline void xio_context_msg_pool_put(void *obj)
{
	xio_objpool_free(obj);
}
/*---------------------------------------------------------------------------*/
/* xio_ctx_pool_create							     */
/*---------------------------------------------------------------------------*/
int xio_ctx_pool_create(struct xio_context *ctx, enum xio_proto proto,
		        enum xio_context_pool_class pool_cls);


#ifdef XIO_THREAD_SAFE_DEBUG
int xio_ctx_debug_thread_lock(struct xio_context *ctx);
int xio_ctx_debug_thread_unlock(struct xio_context *ctx);
#endif

#endif /*XIO_CONTEXT_H */

