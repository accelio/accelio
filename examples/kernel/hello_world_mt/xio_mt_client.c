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
MODULE_DESCRIPTION("XIO hello MT client "	\
		   "v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_LICENSE("Dual BSD/GPL");

static char xio_ip[64];
static char xio_port[8];
static char *xio_argv[] = {"xio_hello_client", xio_ip, xio_port};

static struct multi_completion cleanup_complete;
static struct completion main_complete;

#define QUEUE_DEPTH		512
#define HW_PRINT_COUNTER	400000
#define MAX_THREADS		4

struct server_data;

/* private session data */
struct thread_data {
	struct session_data *sdata;
	void __rcu *ctx; /* RCU doesn't like incomplete types */
	void __rcu *connection; /* RCU doesn't like incomplete types */
	struct xio_ev_data down_event;
	struct xio_msg *req;
	int		cnt;
	u16		port;
};

struct session_data {
	struct task_struct *tasks[MAX_THREADS];
	struct xio_session *session;
	int on_cpu[MAX_THREADS];
	struct thread_data *tdata[MAX_THREADS];
	spinlock_t	lock;	/* session data lock */
	u16		port;
};

static struct session_data __rcu *g_session_data;

/*---------------------------------------------------------------------------*/
/* process_response							     */
/*---------------------------------------------------------------------------*/
static void process_response(struct thread_data *tdata, struct xio_msg *rsp)
{
	if (++tdata->cnt == HW_PRINT_COUNTER) {
		((char *)(rsp->in.header.iov_base))[rsp->in.header.iov_len] = 0;
		pr_info("message: [%llu] - %s\n",
			(rsp->request->sn + 1),
			(char *)rsp->in.header.iov_base);
		tdata->cnt = 0;
	}
	rsp->in.header.iov_base	 = NULL;
	rsp->in.header.iov_len	 = 0;
	rsp->in.data_tbl.nents	 = 0;
}

/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct session_data *sdata;
	struct thread_data *tdata;
	struct xio_context *tctx[MAX_THREADS];
	struct xio_connection_attr attr;
	int i;

	sdata = (struct session_data *)cb_user_context;

	pr_info("session event: %s. reason: %s\n",
		xio_session_event_str(event_data->event),
		xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_query_connection(event_data->conn, &attr,
				     XIO_CONNECTION_ATTR_USER_CTX);
		tdata = (struct thread_data *)attr.user_context;
		spin_lock(&sdata->lock);
		rcu_assign_pointer(tdata->connection, NULL);
		spin_unlock(&sdata->lock);
		synchronize_rcu();
		xio_connection_destroy(event_data->conn);
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		spin_lock(&sdata->lock);
		rcu_assign_pointer(sdata->session, NULL);
		spin_unlock(&sdata->lock);
		synchronize_rcu();
		spin_lock(&sdata->lock);
		for (i = 0; i < MAX_THREADS; i++) {
			tdata = sdata->tdata[i];
			tctx[i] = rcu_dereference_protected(tdata->ctx,
					lockdep_is_held(&sdata->lock));
			rcu_assign_pointer(tdata->ctx, NULL);
		}
		spin_unlock(&sdata->lock);
		synchronize_rcu();
		for (i = 0; i < MAX_THREADS; i++) {
			if (tctx[i])
				xio_context_stop_loop(tctx[i]);
		}
		break;
	default:
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_response								     */
/*---------------------------------------------------------------------------*/
static int on_response(struct xio_session *session,
		       struct xio_msg *rsp,
		       int last_in_rxq,
		       void *cb_user_context)
{
	struct thread_data *tdata;
	struct xio_connection *connection;
	struct xio_msg *req = rsp->user_context;
	int ret = 0;

	tdata = (struct thread_data *)cb_user_context;

	/* process the incoming message */
	process_response(tdata, rsp);

	/* acknowledge XIO that response is no longer needed */
	xio_release_response(rsp);

	/* Client didn't allocate this memory */
	req->in.header.iov_base = NULL;
	req->in.header.iov_len  = 0;
	/* Client didn't allocate in data table to reset it */
	memset(&req->in.data_tbl, 0, sizeof(req->in.data_tbl));

	/* re-send the message */
	rcu_read_lock();
	connection = rcu_dereference(tdata->connection);
	if (connection)
		xio_send_request(connection, req);
	else
		ret = -1;
	rcu_read_unlock();

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callback routines							     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  NULL,
	.on_msg				=  on_response,
	.on_msg_error			=  NULL
};

static void xio_thread_down(void *data)
{
	struct thread_data *tdata;
	struct session_data *sdata;
	struct xio_connection *connection;
	struct xio_context *ctx;

	tdata = (struct thread_data *)data;
	sdata = tdata->sdata;

	/* NULL assignment is done with preemption disabled */
	spin_lock(&sdata->lock);
	connection = rcu_dereference_protected(tdata->connection,
					       lockdep_is_held(&sdata->lock));
	if (!connection) {
		spin_unlock(&sdata->lock);
		goto stop_loop_now;
	}
	rcu_assign_pointer(tdata->connection, NULL);
	spin_unlock(&sdata->lock);
	synchronize_rcu();

	xio_disconnect(connection);

	return;

stop_loop_now:
	/* No connection */
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

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
static int xio_client_thread(void *data)
{
	struct thread_data		*tdata;
	struct session_data		*sdata;
	struct xio_connection		*connection;
	struct xio_context_params	ctx_params;
	struct xio_connection_params	cparams;
	struct xio_context		*ctx;
	int				cpu;
	int				i = 0;

	atomic_inc(&cleanup_complete.thread_count);

	tdata = (struct thread_data *)data;
	sdata = tdata->sdata;

	/* no need to disable preemption */
	cpu = raw_smp_processor_id();
	tdata->req = vzalloc_node(sizeof(*tdata->req) * QUEUE_DEPTH,
				  cpu_to_node(cpu));
	if (!tdata->req)
		goto cleanup0;

	/* create "hello world" message */
	for (i = 0; i < QUEUE_DEPTH; i++) {
		char msg[128];
		struct xio_msg *req = &tdata->req[i];
		struct xio_vmsg *out = &req->out;

		sprintf(msg,
			"hello world header request [cpu(%d) port(%d)-req(%d)]",
			cpu, tdata->port, i);
		out->header.iov_base = kstrdup(msg, GFP_KERNEL);
		if (!out->header.iov_base)
			goto cleanup1;

		out->header.iov_len = strlen(msg) + 1;
		out->sgl_type = XIO_SGL_TYPE_SCATTERLIST;
		memset(&out->data_tbl, 0, sizeof(out->data_tbl));

		req->user_context = req;
	}

	/* create thread context for the client */
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

	memset(&cparams, 0, sizeof(cparams));
	cparams.session			= sdata->session;
	cparams.ctx			= ctx;
	cparams.conn_user_context	= tdata;

	connection = xio_connect(&cparams);
	if (!connection) {
		pr_err("connection create failed\n");
		goto cleanup2;
	}

	spin_lock(&sdata->lock);
	rcu_assign_pointer(tdata->connection, (void *)connection);
	spin_unlock(&sdata->lock);
	synchronize_rcu();

	/* messages are actually queued until the loop runs */
	for (i = 0; i < QUEUE_DEPTH; i++)
		xio_send_request(connection, &tdata->req[i]);

	/* the default XIO supplied main loop */
	xio_context_run_loop(ctx);

	/* normal exit phase */
	pr_info("exit signaled\n");

cleanup2:
	spin_lock(&sdata->lock);
	rcu_assign_pointer(tdata->ctx, NULL);
	spin_unlock(&sdata->lock);
	synchronize_rcu();
	/* free the context */
	xio_context_destroy(ctx);

	pr_info("good bye\n");

cleanup1:
	/* free the message */
	for (i = 0; i < QUEUE_DEPTH; i++)
		kfree(tdata->req[i].out.header.iov_base);

	vfree(tdata->req);

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

static void free_tdata(struct session_data *sdata)
{
	int i;

	for (i = 0; i < MAX_THREADS; i++) {
		if (sdata->tdata[i]) {
			vfree(sdata->tdata[i]);
			sdata->tdata[i] = NULL;
		}
	}
}

static int init_threads(struct session_data *sdata)
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
		sprintf(name, "xio-hello-client-%d\n", i);
		sdata->tasks[i] = kthread_create(xio_client_thread,
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
	free_tdata(sdata);

	return -1;
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
static int xio_client_main(void *data)
{
	char **argv;
	char url[256];
	struct session_data *sdata;
	struct xio_session *session;
	struct xio_session_params params;
	u16 port;
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
		/*pr_err("session_data allocation failed\n");*/
		ret = -ENOMEM;
		goto cleanup0;
	}

	sdata->port = port;
	spin_lock_init(&sdata->lock);

	/* create URL to connect to */
	sprintf(url, "rdma://%s:%s", argv[1], argv[2]);

	memset(&params, 0, sizeof(params));
	params.type		= XIO_SESSION_CLIENT;
	params.ses_ops		= &ses_ops;
	params.user_context	= sdata;
	params.uri		= url;

	session = xio_session_create(&params);
	if (!session) {
		pr_err("session creation failed\n");
		ret = -1;
		goto cleanup1;
	}

	if (init_threads(sdata)) {
		pr_err("init threads failed\n");
		ret = -1;
		goto cleanup2;
	}

	sdata->session = session;
	rcu_assign_pointer(g_session_data, sdata);
	synchronize_rcu();

	/* wait for thread to terminate */
	wait_event_interruptible(cleanup_complete.wq,
				 !atomic_read(&cleanup_complete.thread_count));

	rcu_assign_pointer(g_session_data, NULL);
	synchronize_rcu();

	free_tdata(sdata);

cleanup2:
	xio_session_destroy(session);

cleanup1:
	kfree(sdata);

cleanup0:
	complete_and_exit(&main_complete, ret);

	pr_info("Main thread finished\n");

	/* routine is defined as int */
	return ret;
}

static void down_threads(struct session_data *sdata)
{
	struct thread_data *tdata;
	struct xio_ev_data *down_event;
	void *ctx;
	int i;

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
	th = kthread_run(xio_client_main, xio_argv, xio_argv[0]);
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
	struct session_data *sdata;

	rcu_read_lock();
	sdata = rcu_dereference(g_session_data);
	rcu_read_unlock();

	return sprintf(buf, "%s %s\n",
		       xio_argv[0],
		       sdata ? "running" : "stopped");
}

ssize_t stop_store(struct kobject *kobj,
		   struct kobj_attribute *attr,
		   const char *buf, size_t count)
{
	struct session_data *sdata;

	rcu_read_lock();
	sdata = rcu_dereference(g_session_data);
	if (sdata)
		down_threads(sdata);
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

static int __init xio_hello_init_module(void)
{
	int ret;

	RCU_INIT_POINTER(g_session_data, NULL);
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
	return ret;
}

static void __exit xio_hello_cleanup_module(void)
{
	struct session_data *sdata;

	destroy_sysfs_files();

	rcu_read_lock();
	sdata = rcu_dereference(g_session_data);
	if (sdata)
		down_threads(sdata);
	rcu_read_unlock();

	/* wait for main thread to terminate */
	wait_for_completion(&main_complete);
}

module_init(xio_hello_init_module);
module_exit(xio_hello_cleanup_module);
