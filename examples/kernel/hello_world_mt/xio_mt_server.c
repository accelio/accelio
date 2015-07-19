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
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif
#include <linux/errno.h>
#include <linux/completion.h>

struct multi_completion {
	wait_queue_head_t wq;
	atomic_t thread_count;
};

#include "libxio.h"

MODULE_AUTHOR("Eyal Solomon, Shlomo Pongratz");
MODULE_DESCRIPTION("XIO hello server " \
	   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

static char xio_ip[64];
static char xio_port[8];
static char *xio_argv[] = {"xio_hello_server", xio_ip, xio_port};

static struct multi_completion cleanup_complete;
static struct completion main_complete;

#define MAX_THREADS		4
#define QUEUE_DEPTH		512
#define PRINT_COUNTER		400000
#define MODULE_DOWN		(1)

struct portals_vec {
	int			vec_len;
	int			pad;
	const char		*vec[MAX_THREADS];
};

struct server_data;

struct thread_data {
	struct server_data	*sdata;
	struct xio_connection	*connection;
	struct xio_msg		*rsp;
	void __rcu		*ctx; /* RCU doesn't like incomplete types */
	int			cnt;
	u16			port;
	struct xio_ev_data	down_event;
};

/* server private data */
struct server_data {
	struct task_struct	*tasks[MAX_THREADS];
	struct thread_data	*tdata[MAX_THREADS];
	int			on_cpu[MAX_THREADS];
	void __rcu		*ctx; /* RCU doesn't like incomplete types */
	void __rcu		*session;/* RCU doesn't like incomplete types */
	struct xio_msg		*rsp; /* global message */
	char			base_portal[64];
	struct xio_ev_data	down_event;
	struct kref		kref;
	spinlock_t		lock; /* server data lock */
	unsigned long		flags;
	u16			port;
};

static struct server_data __rcu *g_server_data;

struct portals_vec *portals_get(struct server_data *sdata,
				const char *uri, void *user_context)
{
	/* fill portals array and return it. */
	int i;
	char url[128];

	struct portals_vec *portals = kzalloc(sizeof(*portals), GFP_KERNEL);

	for (i = 0; i < MAX_THREADS; i++) {
		sprintf(url, "%s:%d", sdata->base_portal, sdata->port + i + 1);
		portals->vec[i] = kstrdup(url, GFP_KERNEL);
		portals->vec_len++;
	}

	return portals;
}

void portals_free(struct portals_vec *portals)
{
	int			i;

	for (i = 0; i < portals->vec_len; i++)
		kfree((char *)(portals->vec[i]));

	kfree(portals);
}

/*---------------------------------------------------------------------------*/
/* process_request							     */
/*---------------------------------------------------------------------------*/
void process_request(struct thread_data *tdata, struct xio_msg *req)
{
	if (++tdata->cnt == PRINT_COUNTER) {
		((char *)(req->in.header.iov_base))[req->in.header.iov_len] = 0;
		pr_info("message: [%llu] - %s\n",
			(req->sn + 1), (char *)req->in.header.iov_base);
		tdata->cnt = 0;
	}
}

/*---------------------------------------------------------------------------*/
/* on_request callback							     */
/*---------------------------------------------------------------------------*/
int on_request(struct xio_session *session, struct xio_msg *req,
	       int last_in_rxq, void *cb_user_context)
{
	struct thread_data *tdata;
	int i;

	tdata = cb_user_context;
	i = req->sn % QUEUE_DEPTH;

	/* process request */
	process_request(tdata, req);

	/* attach request to response */
	tdata->rsp[i].request = req;

	xio_send_response(&tdata->rsp[i]);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks for portal thread				     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops portal_server_ops = {
	.on_session_event		=  NULL,
	.on_new_session			=  NULL,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  on_request,
	.on_msg_error			=  NULL
};

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
int on_session_event(struct xio_session *session,
		     struct xio_session_event_data *event_data,
		     void *cb_user_context)
{
	struct server_data *sdata;
	struct thread_data *tdata;
	struct xio_context *tctx[MAX_THREADS];
	struct xio_context *ctx;
	int i;

	sdata = cb_user_context;
	tdata = (event_data->conn_user_context == sdata) ? NULL :
		event_data->conn_user_context;

	pr_info("server session event: %s. reason: %s\n",
		xio_session_event_str(event_data->event),
		xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		if (tdata)
			tdata->connection = event_data->conn;
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		/* NULL assignment is done with preemption disabled */
		xio_connection_destroy(event_data->conn);
		if (tdata)
			tdata->connection = NULL;
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		spin_lock(&sdata->lock);
		rcu_assign_pointer(sdata->session, NULL);
		spin_unlock(&sdata->lock);
		synchronize_rcu();
		xio_session_destroy(session);
		if (!test_bit(MODULE_DOWN, &sdata->flags))
			break;
		/* Module is going down stop loops */
		spin_lock(&sdata->lock);
		for (i = 0; i < MAX_THREADS; i++) {
			tdata = sdata->tdata[i];
			tctx[i] = rcu_dereference_protected(tdata->ctx,
					lockdep_is_held(&sdata->lock));
			rcu_assign_pointer(tdata->ctx, NULL);
		}
		ctx = rcu_dereference_protected(sdata->ctx,
						lockdep_is_held(&sdata->lock));
		rcu_assign_pointer(sdata->ctx, NULL);
		spin_unlock(&sdata->lock);
		synchronize_rcu();
		for (i = 0; i < MAX_THREADS; i++) {
			if (tctx[i])
				xio_context_stop_loop(tctx[i]);
		}
		if (ctx)
			xio_context_stop_loop(ctx);
		break;
	default:
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_new_session							     */
/*---------------------------------------------------------------------------*/
int on_new_session(struct xio_session *session,
		   struct xio_new_session_req *req,
		   void *cb_user_context)
{
	struct portals_vec *portals;
	struct server_data *sdata;

	sdata = cb_user_context;

	spin_lock(&sdata->lock);
	rcu_assign_pointer(sdata->session, (void *)session);
	spin_unlock(&sdata->lock);
	synchronize_rcu();

	portals = portals_get(sdata, req->uri, req->private_data);

	/* Automatically accept the request */
	xio_accept(session, portals->vec, portals->vec_len, NULL, 0);

	portals_free(portals);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks for main					     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops server_ops = {
	.on_session_event		=  on_session_event,
	.on_new_session			=  on_new_session,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  NULL,
	.on_msg_error			=  NULL
};

/*---------------------------------------------------------------------------*/
/* thread								     */
/*---------------------------------------------------------------------------*/
int xio_portal_thread(void *data)
{
	struct thread_data *tdata;
	struct server_data *sdata;
	void *ctx;
	struct xio_server *server;	/* server portal */
	struct xio_context_params ctx_params;
	char url[256];
	int cpu, i;

	atomic_inc(&cleanup_complete.thread_count);

	tdata = data;
	sdata = tdata->sdata;

	cpu = raw_smp_processor_id();
	tdata->rsp = vzalloc_node(sizeof(*tdata->rsp) * QUEUE_DEPTH,
				  cpu_to_node(cpu));
	if (!tdata->rsp)
		goto cleanup0;

	/* create "hello world" message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		char msg[128];
		struct xio_msg *rsp = &tdata->rsp[i];
		struct xio_vmsg *out = &rsp->out;

		sprintf(msg,
			"hello world header response [cpu(%d)-port(%d)-rsp(%d)]",
			cpu, tdata->port, i);
		out->header.iov_base = kstrdup(msg, GFP_KERNEL);
		if (!out->header.iov_base)
			goto cleanup1;

		out->header.iov_len = strlen(msg) + 1;
		out->sgl_type = XIO_SGL_TYPE_SCATTERLIST;
		memset(&out->data_tbl, 0, sizeof(out->data_tbl));
	}

	/* create thread context for the server */
	memset(&ctx_params, 0, sizeof(ctx_params));
	ctx_params.flags = XIO_LOOP_GIVEN_THREAD;
	ctx_params.worker = current;

	ctx = xio_context_create(&ctx_params, 0, -1);
	if (!ctx) {
		pr_err("context open failed\n");
		goto cleanup1;
	}

	spin_lock(&sdata->lock);
	rcu_assign_pointer(tdata->ctx, (void *)ctx);
	spin_unlock(&sdata->lock);
	synchronize_rcu();

	sprintf(url, "%s:%d", sdata->base_portal, tdata->port);

	/* bind a listener server to a portal/url */
	pr_info("thread [%d] - listen:%s\n", tdata->port, url);
	server = xio_bind(tdata->ctx, &portal_server_ops, url,
			  NULL, 0, tdata);
	if (!server) {
		pr_err("bind failed\n");
		goto cleanup2;
	}

	xio_context_run_loop(ctx);

	/* normal exit phase */
	pr_info("exit signaled\n");

	/* free the server */
	xio_unbind(server);

cleanup2:
	spin_lock(&sdata->lock);
	rcu_assign_pointer(tdata->ctx, NULL);
	spin_unlock(&sdata->lock);
	synchronize_rcu();
	/* free the context */
	xio_context_destroy(ctx);

cleanup1:
	/* free the message */
	for (i = 0; i < QUEUE_DEPTH; i++)
		kfree(tdata->rsp[i].out.header.iov_base);

	vfree(tdata->rsp);

cleanup0:
	i = atomic_dec_return(&cleanup_complete.thread_count);
	if (i == 0) {
		pr_info("Last thread finished");
		wake_up_interruptible(&cleanup_complete.wq);
	} else {
		pr_info("Wait for additional %d threads", i);
	}

	return 0;
}

static void free_tdata(struct server_data *sdata)
{
	int i;

	for (i = 0; i < MAX_THREADS; i++) {
		if (sdata->tdata[i]) {
			vfree(sdata->tdata[i]);
			sdata->tdata[i] = NULL;
		}
	}
}

static void free_sdata(struct kref *kref)
{
	struct server_data *sdata;

	sdata = container_of(kref, struct server_data, kref);

	free_tdata(sdata);

	kfree(sdata);

	complete_and_exit(&main_complete, 0);
}

static int init_threads(struct server_data *sdata)
{
	char name[32];
	int i, j, cpu, online;

	online = num_online_cpus();

	for (i = 0; i < MAX_THREADS; i++) {
		struct thread_data *tdata;

		cpu = (i + 1)  % online;
		sdata->on_cpu[i] = cpu;
		tdata = vzalloc_node(sizeof(*tdata) * QUEUE_DEPTH,
				     cpu_to_node(cpu));
		if (!tdata)
			goto cleanup0;

		sdata->tdata[i] = tdata;
		tdata->sdata = sdata;
		tdata->port = sdata->port + (i + 1);
	}

	for (i = 0; i < MAX_THREADS; i++) {
		sprintf(name, "xio-hello-server-%d\n", i);
		sdata->tasks[i] = kthread_create(xio_portal_thread,
						 sdata->tdata[i], name);
		if (IS_ERR(sdata->tasks[i])) {
			pr_err("kthread_create_on_cpu failed err=%ld\n",
			       PTR_ERR(sdata->tasks[i]));
			goto cleanup1;
		}
		kthread_bind(sdata->tasks[i], sdata->on_cpu[i]);
	}

	/* kick all threads */
	for (i = 0; i < MAX_THREADS; i++)
		wake_up_process(sdata->tasks[i]);

	return 0;

cleanup1:
	for (j = 0; j < i; j++) {
		kthread_stop(sdata->tasks[j]);
		sdata->tasks[j] = NULL;
	}

cleanup0:
	/* free_tdata will be called form free_sdata */

	return -1;
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int xio_server_main(void *data)
{
	char **argv;
	struct xio_server	*server;	/* server portal */
	struct server_data	*sdata;
	struct xio_context_params ctx_params;
	char			url[256];
	void			*ctx;
	u16			port;
	int ret = 0;

	argv = (char **)data;

	init_waitqueue_head(&cleanup_complete.wq);
	atomic_set(&cleanup_complete.thread_count, 0);

	if (kstrtou16(argv[2], 10, &port)) {
		pr_err("invalid port number %s\n", argv[2]);
		ret = -EINVAL;
		goto cleanup0;
	}

	sdata = kzalloc(sizeof(*sdata), GFP_KERNEL);
	if (!sdata) {
		/*pr_err("server_data allocation failed\n");*/
		ret = -ENOMEM;
		goto cleanup0;
	}

	sdata->port = port;
	spin_lock_init(&sdata->lock);
	kref_init(&sdata->kref);

	/* create thread context for the server */
	memset(&ctx_params, 0, sizeof(ctx_params));
	ctx_params.flags = XIO_LOOP_GIVEN_THREAD;
	ctx_params.worker = current;

	ctx = xio_context_create(&ctx_params, 0, -1);
	if (!ctx) {
		pr_err("context open filed\n");
		ret = -1;
		goto cleanup1;
	}

	/* create URL to connect to */
	sprintf(sdata->base_portal, "rdma://%s", argv[1]);
	sprintf(url, "%s:%s", sdata->base_portal, argv[2]);

	/* bind a listener server to a portal/url */
	server = xio_bind(ctx, &server_ops, url, NULL, 0, sdata);
	if (!server) {
		pr_err("listen to %s failed\n", url);
		goto cleanup2;
	}

	spin_lock(&sdata->lock);
	rcu_assign_pointer(sdata->ctx, (void *)ctx);
	spin_unlock(&sdata->lock);
	synchronize_rcu();

	pr_info("listen to %s\n", url);

	/* start portals threads */
	if (init_threads(sdata)) {
		pr_err("initialize threads failed\n");
		ret = -1;
		goto cleanup3;
	}

	rcu_assign_pointer(g_server_data, sdata);
	synchronize_rcu();

	xio_context_run_loop(ctx);

	/* wait for portals thread to terminate */
	wait_event_interruptible(cleanup_complete.wq,
				 !atomic_read(&cleanup_complete.thread_count));

	rcu_assign_pointer(g_server_data, NULL);
	synchronize_rcu();

	/* normal exit phase */
	pr_info("exit signaled\n");

cleanup3:
	/* free the server */
	xio_unbind(server);

cleanup2:
	/* free the context */
	xio_context_destroy(ctx);

cleanup1:
	kref_put(&sdata->kref, free_sdata);
	/* complete_and exit should be called from free_sdata */
	return ret;

cleanup0:
	complete_and_exit(&main_complete, 0);

	/* routine is defined as int */
	return ret;
}

void xio_thread_down(void *data)
{
	struct thread_data *tdata;
	struct server_data *sdata;
	struct xio_session *session;
	struct xio_context *ctx;

	tdata = (struct thread_data *)data;
	sdata = tdata->sdata;
	/* This routine is called on this context so it must be non null */
	rcu_read_lock();
	ctx = rcu_dereference(tdata->ctx);
	session = rcu_dereference(tdata->sdata->session);
	if (!session)
		goto stop_loop_now;

	if (!tdata->connection)
		goto stop_loop_now;

	xio_disconnect(tdata->connection);

	rcu_read_unlock();

	return;

stop_loop_now:
	rcu_read_unlock();
	/* there is no session and no connection */
	spin_lock(&sdata->lock);
	ctx = rcu_dereference_protected(tdata->ctx,
					lockdep_is_held(&sdata->lock));
	/* if by any chance context was destroyed */
	if (ctx) {
		rcu_assign_pointer(tdata->ctx, NULL);
		spin_unlock(&sdata->lock);
		synchronize_rcu();
		xio_context_stop_loop(ctx); /* exit */
	} else {
		spin_unlock(&sdata->lock);
	}
}

void xio_server_down(void *data)
{
	struct server_data *sdata;
	struct xio_session *session;
	void *ctx;

	sdata = (struct server_data *)data;

	/* This routine is called on this context so it must be non null */
	rcu_read_lock();
	session = rcu_dereference(sdata->session);
	if (!session) {
		rcu_read_unlock();
		goto stop_loop_now;
	}
	rcu_read_unlock();

	/* Need to wait for all connections to terminate, that is
	 * XIO_SESSION_TEARDOWN_EVENT
	 */
	kref_put(&sdata->kref, free_sdata);

	return;

stop_loop_now:
	/* there is no session */
	spin_lock(&sdata->lock);
	ctx = rcu_dereference_protected(sdata->ctx,
					lockdep_is_held(&sdata->lock));
	/* if by any chance context was destroyed */
	if (ctx) {
		rcu_assign_pointer(sdata->ctx, NULL);
		spin_unlock(&sdata->lock);
		synchronize_rcu();
		xio_context_stop_loop(ctx); /* exit */
	} else {
		spin_unlock(&sdata->lock);
	}

	kref_put(&sdata->kref, free_sdata);
}

void down_threads(struct server_data *sdata)
{
	struct thread_data *tdata;
	struct xio_ev_data *down_event;
	void *ctx;
	int i;

	set_bit(MODULE_DOWN, &sdata->flags);

	/* down the portals threads */
	for (i = 0; i < MAX_THREADS; i++) {
		tdata = sdata->tdata[i];
		down_event = &tdata->down_event;
		down_event->handler = xio_thread_down;
		down_event->data = (void *)tdata;
		rcu_read_lock();
		ctx = rcu_dereference(tdata->ctx);
		if (ctx)
			xio_context_add_event(ctx, down_event);
		rcu_read_unlock();
	}

	/* down the server thread */
	down_event = &sdata->down_event;
	down_event->handler = xio_server_down;
	down_event->data = (void *)sdata;
	rcu_read_lock();
	ctx = rcu_dereference(sdata->ctx);
	if (ctx) {
		xio_context_add_event(ctx, down_event);
		rcu_read_unlock();
	} else {
		rcu_read_unlock();
		/* xio_server_down will not be called and thus will
		 * not call kref_put
		 */
		kref_put(&sdata->kref, free_sdata);
	}
}

/* Module stuff */

ssize_t add_url_show(struct kobject *kobj,
		     struct kobj_attribute *attr,
		     char *buf)
{
	return sprintf(buf, "%s %s %s\n",
		       xio_argv[0], xio_argv[1], xio_argv[2]);
}

ssize_t add_url_store(struct kobject *kobj,
		      struct kobj_attribute *attr,
		      const char *buf, size_t count)
{
	struct task_struct *th;
	int d1, d2, d3, d4, p;
	int ret;

	if (sscanf(buf, "%d.%d.%d.%d %d", &d1, &d2, &d3, &d4, &p) != 5) {
		pr_err("wrong portal %s\n", buf);
		return -EINVAL;
	}

	sprintf(xio_ip, "%d.%d.%d.%d", d1, d2, d3, d4);
	sprintf(xio_port, "%d", p);

	/* re-arm completion */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
	INIT_COMPLETION(main_complete);
#else
	reinit_completion(&main_complete);
#endif

	th = kthread_run(xio_server_main, xio_argv, xio_argv[0]);
	if (IS_ERR(th)) {
		ret = PTR_ERR(th);
		pr_err("Couldn't create new session ret=%d\n", ret);
		complete(&main_complete);
		return ret;
	}

	return count;
}

ssize_t stop_show(struct kobject *kobj,
		  struct kobj_attribute *attr,
		  char *buf)
{
	struct server_data *sdata;

	rcu_read_lock();
	sdata = rcu_dereference(g_server_data);
	rcu_read_unlock();

	return sprintf(buf, "%s %s\n",
		       xio_argv[0],
		       sdata ? "running" : "stopped");
}

ssize_t stop_store(struct kobject *kobj,
		   struct kobj_attribute *attr,
		   const char *buf, size_t count)
{
	struct server_data *sdata;

	rcu_read_lock();
	sdata = rcu_dereference(g_server_data);
	if (sdata) {
		kref_get(&sdata->kref);
		down_threads(sdata);
	}
	rcu_read_unlock();

	xio_ip[0] = '\0';
	xio_port[0] = '\0';

	return count;
}

static struct kobj_attribute add_url_attribute =
	__ATTR(add_url, 0664, add_url_show, add_url_store);

static struct kobj_attribute stop_attribute =
	__ATTR(stop, 0664, stop_show, stop_store);

static struct attribute *default_attrs[] = {
	&add_url_attribute.attr,
	&stop_attribute.attr,
	NULL,
};

static struct attribute_group default_attr_group = {
	.attrs = default_attrs,
};

static struct kobject *sysfs_kobj;

static void destroy_sysfs_files(void)
{
	kobject_put(sysfs_kobj);
}

static int create_sysfs_files(void)
{
	int err = 0;

	sysfs_kobj = kobject_create_and_add(xio_argv[0], NULL);
	if (!sysfs_kobj)
		return -ENOMEM;

	err = sysfs_create_group(sysfs_kobj, &default_attr_group);
	if (err)
		kobject_put(sysfs_kobj);

	return err;
}

int __init xio_hello_init_module(void)
{
	int ret;

	RCU_INIT_POINTER(g_server_data, NULL);
	init_completion(&main_complete);

	/* we need to be able to unload before start */
	complete(&main_complete);

	xio_ip[0] = '\0';
	xio_port[0] = '\0';

	if (create_sysfs_files()) {
		pr_err("sysfs create failed\n");
		ret = -ENOSYS;
		goto cleanup0;
	}

	return 0;

cleanup0:
	return -1;
}

void __exit xio_hello_cleanup_module(void)
{
	struct server_data *sdata;

	destroy_sysfs_files();

	rcu_read_lock();
	sdata = rcu_dereference(g_server_data);
	if (sdata) {
		kref_get(&sdata->kref);
		down_threads(sdata);
	}
	rcu_read_unlock();

	/* wait for main thread to terminate */
	wait_for_completion(&main_complete);
}

module_init(xio_hello_init_module);
module_exit(xio_hello_cleanup_module);
