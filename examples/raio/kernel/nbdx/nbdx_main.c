/*
 * Copyright (c) 2013 Mellanox Technologies��. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies�� BSD license
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
 *      - Neither the name of the Mellanox Technologies�� nor the names of its
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

#include "nbdx.h"

#define DRV_NAME	"nbdx"
#define PFX		DRV_NAME ": "
#define DRV_VERSION	"0.1"

MODULE_AUTHOR("Sagi Grimberg, Max Gurtovoy");
MODULE_DESCRIPTION("XIO network block device");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

int created_portals = 0;
int nbdx_major;
int nbdx_indexes; /* num of devices created*/
int submit_queues;
struct list_head g_nbdx_sessions;
struct mutex g_lock;

static void msg_reset(struct xio_msg *msg)
{
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	msg->in.sgl_type = XIO_SGL_TYPE_SCATTERLIST;
	memset(&msg->in.data_tbl, 0, sizeof(msg->in.data_tbl));
	msg->out.header.iov_len = 0;
	msg->out.sgl_type = XIO_SGL_TYPE_SCATTERLIST;
	memset(&msg->out.data_tbl, 0, sizeof(msg->out.data_tbl));
	msg->next = NULL;
}

inline int nbdx_set_device_state(struct nbdx_file *xdev,
				 enum nbdx_dev_state state)
{
	int ret = 0;

	spin_lock(&xdev->state_lock);
	switch (state) {
	case DEVICE_OPENNING:
		if (xdev->state == DEVICE_OFFLINE ||
		    xdev->state == DEVICE_RUNNING) {
			ret = -EINVAL;
			goto out;
		}
		xdev->state = state;
		break;
	case DEVICE_RUNNING:
		xdev->state = state;
		break;
	case DEVICE_OFFLINE:
		xdev->state = state;
		break;
	default:
		pr_err("Unknown device state %d\n", state);
		ret = -EINVAL;
	}
out:
	spin_unlock(&xdev->state_lock);
	return ret;
}

int nbdx_transfer(struct nbdx_file *xdev, char *buffer, unsigned long start,
		  unsigned long len, int write, struct request *req,
		  struct nbdx_queue *q)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	struct raio_io_u *io_u = blk_mq_rq_to_pdu(req);
#else
	struct raio_io_u *io_u = req->special;
#endif
	struct nbdx_connection *nbdx_conn = q->nbdx_conn;
	int cpu, retval = 0;

	pr_debug("%s called and req=%p\n", __func__, req);

	msg_reset(&io_u->req);

	if (write)
		raio_prep_pwrite(&io_u->iocb, xdev->fd, start);
	else
		raio_prep_pread(&io_u->iocb, xdev->fd, start);

	pr_debug("%s,%d: start=0x%lx, len=0x%lx opcode=%d\n",
		 __func__, __LINE__, start, len, io_u->iocb.raio_lio_opcode);

	if (io_u->iocb.raio_lio_opcode == RAIO_CMD_PWRITE) {
		io_u->req.out.data_tbl.sgl = io_u->sgl;
		/*
		 * TODO: no need to duplicate orig_nents for each IO.
		 * Need to fix in Accelio request validation
		 */
		io_u->req.out.data_tbl.orig_nents = MAX_SGL_LEN;
		retval = nbdx_rq_map_sg(req, &io_u->req.out, &io_u->iocb.u.c.nbytes);
		if (unlikely(retval)) {
			pr_err("failed to map sg\n");
			goto err;
		}
	} else {
		io_u->req.in.data_tbl.sgl = io_u->sgl;
		/*
		 * TODO: no need to duplicate orig_nents for each IO.
		 * Need to fix in Accelio request validation
		 */
		io_u->req.in.data_tbl.orig_nents = MAX_SGL_LEN;
		retval = nbdx_rq_map_sg(req, &io_u->req.in, &io_u->iocb.u.c.nbytes);
		if (unlikely(retval)) {
			pr_err("failed to map sg\n");
			goto err;
		}
	}

	pack_submit_command(&io_u->iocb, 1, io_u->req_hdr,
			    &io_u->req.out.header.iov_len);
	io_u->req.out.header.iov_base = io_u->req_hdr;
	io_u->req.user_context = io_u;
	io_u->breq = req;

	cpu = get_cpu();
	if (cpu != nbdx_conn->cpu_id) {
		pr_debug("conn %d preempted to cpuid %d, switching conn\n",
			 cpu, nbdx_conn->cpu_id);
		nbdx_conn = nbdx_conn->nbdx_sess->nbdx_conns[cpu];
	}
	pr_debug("sending req on conn %d\n", nbdx_conn->cpu_id);
	retval = xio_send_request(nbdx_conn->conn, &io_u->req);
	put_cpu();
	if (unlikely(retval)) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		goto err;
	}

err:
	return retval;
}

struct nbdx_file *nbdx_file_find(struct nbdx_session *nbdx_session,
				 const char *xdev_name)
{
	struct nbdx_file *pos;
	struct nbdx_file *ret = NULL;

	spin_lock(&nbdx_session->devs_lock);
	list_for_each_entry(pos, &nbdx_session->devs_list, list) {
		if (!strcmp(pos->file_name, xdev_name)) {
			ret = pos;
			break;
		}
	}
	spin_unlock(&nbdx_session->devs_lock);

	return ret;
}

struct nbdx_session *nbdx_session_find_by_portal(struct list_head *s_data_list,
						 const char *portal)
{
	struct nbdx_session *pos;
	struct nbdx_session *ret = NULL;

	mutex_lock(&g_lock);
	list_for_each_entry(pos, s_data_list, list) {
		if (!strcmp(pos->portal, portal)) {
			ret = pos;
			break;
		}
	}
	mutex_unlock(&g_lock);

	return ret;
}

/*---------------------------------------------------------------------------*/
/* on_submit_answer							     */
/*---------------------------------------------------------------------------*/
static void on_submit_answer(struct nbdx_connection *nbdx_conn,
			     struct xio_msg *rsp)
{
	struct raio_io_u *io_u;
	struct request *breq;
	int ret;

	io_u = rsp->user_context;
	io_u->rsp = rsp;
	breq = io_u->breq;

	pr_debug("%s: Got submit response\n", __func__);
	unpack_u32((uint32_t *)&io_u->res2,
	unpack_u32((uint32_t *)&io_u->res,
	unpack_u32((uint32_t *)&io_u->ans.ret_errno,
	unpack_u32((uint32_t *)&io_u->ans.ret,
	unpack_u32(&io_u->ans.data_len,
	unpack_u32(&io_u->ans.command,
		   io_u->rsp->in.header.iov_base))))));
	pr_debug("fd=%d, res=%x, res2=%x, ans.ret=%d, ans.ret_errno=%d\n",
			io_u->iocb.raio_fildes, io_u->res, io_u->res2,
			io_u->ans.ret, io_u->ans.ret_errno);

	ret = -io_u->ans.ret;
	if (unlikely(ret)) {
		struct nbdx_file *xdev = io_u->breq->rq_disk->private_data;

		pr_err("error response on xdev %s ret=%d\n", xdev->dev_name,
							     ret);
		nbdx_set_device_state(xdev, DEVICE_OFFLINE);
	}

	if (likely(breq))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
		blk_mq_end_request(breq, ret);
#else
		blk_mq_end_io(breq, ret);
#endif
	else
		pr_err("%s: Got NULL request in response\n", __func__);

	xio_release_response(rsp);
}

/*---------------------------------------------------------------------------*/
/* on_response								     */
/*---------------------------------------------------------------------------*/
static int on_response(struct xio_session *session,
		       struct xio_msg *rsp,
		       int more_in_batch,
		       void *cb_user_context)
{
	struct nbdx_connection *nbdx_conn = cb_user_context;
	uint32_t command;

	unpack_u32(&command, rsp->in.header.iov_base);
	pr_debug("message: [%llu] - %s\n",
			(rsp->request->sn + 1), (char *)rsp->in.header.iov_base);

	switch (command) {
	case RAIO_CMD_IO_SUBMIT:
		on_submit_answer(nbdx_conn, rsp);
		break;
	case RAIO_CMD_OPEN:
	case RAIO_CMD_FSTAT:
	case RAIO_CMD_CLOSE:
	case RAIO_CMD_IO_SETUP:
	case RAIO_CMD_IO_DESTROY:
		/* break the loop */
		nbdx_conn->rsp = rsp;
		nbdx_conn->wq_flag = 1;
		wake_up_interruptible(&nbdx_conn->wq);
		break;
	default:
		printk("on_response: unknown answer %d\n", command);
		break;
	};

	return 0;
}


/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
		struct xio_session_event_data *event_data,
		void *cb_user_context)
{
	struct nbdx_session *nbdx_session = cb_user_context;
	struct nbdx_connection *nbdx_conn;
	struct xio_connection	*conn = event_data->conn;
	int i;

	printk("session event: %s\n",
	       xio_session_event_str(event_data->event));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_ESTABLISHED_EVENT:
		pr_debug("%s: connection=%p established\n", __func__, conn);
		if (atomic_dec_and_test(&nbdx_session->conns_count)) {
			pr_debug("%s: last connection established\n", __func__);
			complete(&nbdx_session->conns_wait);
		}
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		nbdx_session->session = NULL;
		xio_session_destroy(session);
		for (i = 0; i < submit_queues; i++) {
			nbdx_conn = nbdx_session->nbdx_conns[i];
			xio_context_stop_loop(nbdx_conn->ctx); /* exit */
		}
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		printk("destroying connection: %p\n", conn);
		xio_connection_destroy(conn);

		break;
	case XIO_SESSION_CONNECTION_DISCONNECTED_EVENT:
		break;
	default:
		break;
	};

	return 0;
}

/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops nbdx_ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  NULL,
	.on_msg				=  on_response,
	.on_msg_error			=  NULL
};

const char *nbdx_device_state_str(struct nbdx_file *dev)
{
	char *state;

	spin_lock(&dev->state_lock);
	switch (dev->state) {
	case DEVICE_INITIALIZING:
		state = "Initial state";
		break;
	case DEVICE_OPENNING:
		state = "openning";
		break;
	case DEVICE_RUNNING:
		state = "running";
		break;
	case DEVICE_OFFLINE:
		state = "offline";
		break;
	default:
		state = "unknown device state";
	}
	spin_unlock(&dev->state_lock);

	return state;
}

static int nbdx_setup_remote_session(struct nbdx_session *nbdx_session,
			    int queues)
{

	int retval, cpu;
	struct nbdx_connection *nbdx_conn;

	cpu = get_cpu();
	nbdx_conn = nbdx_session->nbdx_conns[cpu];

	msg_reset(&nbdx_conn->req);
	pack_setup_command(queues, NBDX_QUEUE_DEPTH,
			   nbdx_conn->req.out.header.iov_base,
			   &nbdx_conn->req.out.header.iov_len);

	retval = xio_send_request(nbdx_conn->conn, &nbdx_conn->req);
	put_cpu();
	if (retval) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		return retval;
	}

	pr_debug("%s: before waiting for event\n", __func__);
	wait_event_interruptible(nbdx_conn->wq, nbdx_conn->wq_flag != 0);
	pr_debug("%s: after waiting for event\n", __func__);
	nbdx_conn->wq_flag = 0;

	retval = unpack_setup_answer(nbdx_conn->rsp->in.header.iov_base,
				     nbdx_conn->rsp->in.header.iov_len);
	if (retval == -EINVAL)
		pr_err("failed to unpack setup response");

	pr_debug("after unpacking setup_answer\n");

	/* acknowlege xio that response is no longer needed */
	xio_release_response(nbdx_conn->rsp);

	return retval;

}

static int nbdx_destroy_remote_session(struct nbdx_session *nbdx_session)
{

	int retval, cpu;
	struct nbdx_connection *nbdx_conn;

	cpu = get_cpu();
	nbdx_conn = nbdx_session->nbdx_conns[cpu];

	msg_reset(&nbdx_conn->req);
	pack_destroy_command(nbdx_conn->req.out.header.iov_base,
			&nbdx_conn->req.out.header.iov_len);

	retval = xio_send_request(nbdx_conn->conn, &nbdx_conn->req);
	put_cpu();
	if (retval) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		return retval;
	}

	pr_debug("%s: before waiting for event\n", __func__);
	wait_event_interruptible(nbdx_conn->wq, nbdx_conn->wq_flag != 0);
	pr_debug("%s: after waiting for event\n", __func__);
	nbdx_conn->wq_flag = 0;

	retval = unpack_destroy_answer(nbdx_conn->rsp->in.header.iov_base,
			nbdx_conn->rsp->in.header.iov_len);
	if (retval == -EINVAL)
		pr_err("failed to unpack destroy response");

	/* acknowlege xio that response is no longer needed */
	xio_release_response(nbdx_conn->rsp);

	return retval;

}

static int nbdx_stat_remote_device(struct nbdx_session *nbdx_session,
				   struct nbdx_file *nbdx_file)
{
	struct nbdx_connection *nbdx_conn;
	int retval, cpu;

	cpu = get_cpu();
	nbdx_conn = nbdx_session->nbdx_conns[cpu];

	msg_reset(&nbdx_conn->req);
	pack_fstat_command(nbdx_file->fd,
			   nbdx_conn->req.out.header.iov_base,
			   &nbdx_conn->req.out.header.iov_len);

	retval = xio_send_request(nbdx_conn->conn, &nbdx_conn->req);
	put_cpu();
	if (retval) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		return retval;
	}

	pr_debug("%s: before wait_event_interruptible\n", __func__);
	wait_event_interruptible(nbdx_conn->wq, nbdx_conn->wq_flag != 0);
	pr_debug("%s: after wait_event_interruptible\n", __func__);
	nbdx_conn->wq_flag = 0;

	retval = unpack_fstat_answer(nbdx_conn->rsp->in.header.iov_base,
				     nbdx_conn->rsp->in.header.iov_len,
				     &nbdx_file->stbuf);
	if (retval == -EINVAL)
		pr_err("failed to unpack fstat response\n");

	pr_debug("after unpacking fstat response file_size=%llx bytes\n",
		 nbdx_file->stbuf.st_size);

	/* acknowlege xio that response is no longer needed */
	xio_release_response(nbdx_conn->rsp);

	return retval;
}

static int nbdx_open_remote_device(struct nbdx_session *nbdx_session,
				   struct nbdx_file *nbdx_file)
{
	struct nbdx_connection *nbdx_conn;
	int retval, cpu;

	cpu = get_cpu();
	nbdx_conn = nbdx_session->nbdx_conns[cpu];
	msg_reset(&nbdx_conn->req);
	pack_open_command(nbdx_file->file_name, O_RDWR|O_DIRECT,
			  nbdx_conn->req.out.header.iov_base,
			  &nbdx_conn->req.out.header.iov_len);

	retval = xio_send_request(nbdx_conn->conn, &nbdx_conn->req);
	put_cpu();
	if (retval) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		return retval;
	}

	pr_debug("open file: before wait_event_interruptible\n");
	wait_event_interruptible(nbdx_conn->wq, nbdx_conn->wq_flag != 0);
	pr_debug("open file: after wait_event_interruptible\n");
	nbdx_conn->wq_flag = 0;

	retval = unpack_open_answer(nbdx_conn->rsp->in.header.iov_base,
				    nbdx_conn->rsp->in.header.iov_len,
				    &nbdx_file->fd);
	if (retval == -EINVAL)
		pr_err("failed to unpack open response\n");

	xio_release_response(nbdx_conn->rsp);

	return retval;
}

static int nbdx_close_remote_device(struct nbdx_session *nbdx_session,
				   int fd)
{
	struct nbdx_connection *nbdx_conn;
	int retval, cpu;

	cpu = get_cpu();
	nbdx_conn = nbdx_session->nbdx_conns[cpu];
	msg_reset(&nbdx_conn->req);
	pack_close_command(fd,
			nbdx_conn->req.out.header.iov_base,
			&nbdx_conn->req.out.header.iov_len);

	retval = xio_send_request(nbdx_conn->conn, &nbdx_conn->req);
	put_cpu();
	if (retval) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		return retval;
	}

	pr_debug("%s: before wait_event_interruptible\n", __func__);
	wait_event_interruptible(nbdx_conn->wq, nbdx_conn->wq_flag != 0);
	pr_debug("%s: after wait_event_interruptible\n", __func__);
	nbdx_conn->wq_flag = 0;

	retval = unpack_close_answer(nbdx_conn->rsp->in.header.iov_base,
				    nbdx_conn->rsp->in.header.iov_len);
	if (retval == -EINVAL)
		pr_err("failed to unpack close response\n");

	xio_release_response(nbdx_conn->rsp);

	return retval;
}

int nbdx_create_device(struct nbdx_session *nbdx_session,
					   const char *xdev_name, struct nbdx_file *nbdx_file)
{
	int retval;

	sscanf(xdev_name, "%s", nbdx_file->file_name);
	nbdx_file->index = nbdx_indexes++;
	nbdx_file->nr_queues = submit_queues;
	nbdx_file->queue_depth = NBDX_QUEUE_DEPTH;
	nbdx_file->nbdx_conns = nbdx_session->nbdx_conns;

	retval = nbdx_setup_queues(nbdx_file);
	if (retval) {
		pr_err("%s: nbdx_setup_queues failed\n", __func__);
		goto err;
	}

	retval = nbdx_open_remote_device(nbdx_session, nbdx_file);
	if (retval) {
		pr_err("failed to open remote device ret=%d\n", retval);
		goto err_queues;
	}

	retval = nbdx_stat_remote_device(nbdx_session, nbdx_file);
	if (retval) {
		pr_err("failed to stat remote device %s ret=%d\n",
		       nbdx_file->file_name, retval);
		goto err_queues;
	}

	retval = nbdx_register_block_device(nbdx_file);
	if (retval) {
		pr_err("failed to register nbdx device %s ret=%d\n",
		       nbdx_file->file_name, retval);
		goto err_queues;
	}

	nbdx_set_device_state(nbdx_file, DEVICE_RUNNING);

	return 0;

err_queues:
	nbdx_destroy_queues(nbdx_file);
err:
	return retval;
}

void nbdx_destroy_device(struct nbdx_session *nbdx_session,
                         struct nbdx_file *nbdx_file)
{
	pr_debug("%s\n", __func__);

	nbdx_set_device_state(nbdx_file, DEVICE_OFFLINE);
	if (nbdx_file->disk){
		nbdx_unregister_block_device(nbdx_file);
		nbdx_close_remote_device(nbdx_session, nbdx_file->fd);
		nbdx_destroy_queues(nbdx_file);
	}

	spin_lock(&nbdx_session->devs_lock);
	list_del(&nbdx_file->list);
	spin_unlock(&nbdx_session->devs_lock);
}

static void nbdx_destroy_session_devices(struct nbdx_session *nbdx_session)
{
	struct nbdx_file *xdev, *tmp;

	list_for_each_entry_safe(xdev, tmp, &nbdx_session->devs_list, list) {
		nbdx_destroy_device(nbdx_session, xdev);
	}
}

/**
 * destroy nbdx_conn
 */
static void nbdx_destroy_conn(struct nbdx_connection *nbdx_conn)
{
	nbdx_conn->nbdx_sess = NULL;
	nbdx_conn->conn_th = NULL;
	nbdx_conn->conn = NULL;
	nbdx_conn->ctx = NULL;
	/* release buffer for management messages */
	kfree(nbdx_conn->req.out.header.iov_base);
	kfree(nbdx_conn);
}

static int nbdx_connect_work(void *data)
{
	struct nbdx_connection *nbdx_conn = data;
	struct xio_connection_params    cparams;
	struct xio_context_params       xparams;

	pr_info("%s: start connect work on cpu %d\n", __func__,
		nbdx_conn->cpu_id);

	memset(&nbdx_conn->req, 0, sizeof(nbdx_conn->req));
	nbdx_conn->req.out.header.iov_base = kmalloc(MAX_MSG_LEN, GFP_KERNEL);
	nbdx_conn->req.out.header.iov_len = MAX_MSG_LEN;

	init_waitqueue_head(&nbdx_conn->wq);
	nbdx_conn->wq_flag = 0;

	memset(&xparams, 0, sizeof(xparams));
	xparams.flags = XIO_LOOP_GIVEN_THREAD;
	xparams.worker = current;

	nbdx_conn->ctx = xio_context_create(&xparams, 0, nbdx_conn->cpu_id);
	if (!nbdx_conn->ctx) {
		printk("context open failed\n");
		return 1;
	}
	pr_info("cpu %d: context established ctx=%p\n",
		nbdx_conn->cpu_id, nbdx_conn->ctx);

	memset(&cparams, 0, sizeof(cparams));
	cparams.session = nbdx_conn->nbdx_sess->session;
	cparams.ctx = nbdx_conn->ctx;
	cparams.conn_idx = 0;
	cparams.conn_user_context = nbdx_conn;
	nbdx_conn->conn = xio_connect(&cparams);
	if (!nbdx_conn->conn){
		printk("connection open failed\n");
		xio_context_destroy(nbdx_conn->ctx);
		return 1;
	}
	pr_info("cpu %d: connection established conn=%p\n",
		nbdx_conn->cpu_id, nbdx_conn->conn);

	/* the default xio supplied main loop */
	xio_context_run_loop(nbdx_conn->ctx);

	xio_context_destroy(nbdx_conn->ctx);

	/* check if this is the last loop that was stopped */
	if (atomic_dec_and_test(&nbdx_conn->nbdx_sess->destroy_conns_count)) {
		struct nbdx_session *nbdx_session = nbdx_conn->nbdx_sess;
		nbdx_destroy_conn(nbdx_conn);
		/* last connection will release connections array */
		kfree(nbdx_session->nbdx_conns);
	}
	else
		nbdx_destroy_conn(nbdx_conn);

	do_exit(0);
	return 0;
}

static void nbdx_destroy_session_connections(struct nbdx_session *nbdx_session)
{
	struct nbdx_connection *nbdx_conn;
	int i;

	for (i = 0; i < submit_queues; i++) {
		nbdx_conn = nbdx_session->nbdx_conns[i];
		xio_disconnect(nbdx_conn->conn);
	}
}

static int nbdx_create_conn(struct nbdx_session *nbdx_session, int cpu,
			    struct nbdx_connection **conn)
{
	struct nbdx_connection *nbdx_conn;
	char name[50];

	nbdx_conn = kzalloc(sizeof(*nbdx_conn), GFP_KERNEL);
	if (!nbdx_conn) {
		pr_err("failed to allocate nbdx_conn");
		return -ENOMEM;
	}

	sprintf(name, "session thread %d", cpu);
	nbdx_conn->nbdx_sess = nbdx_session;
	nbdx_conn->cpu_id = cpu;

	pr_debug("opening thread on cpu %d\n", cpu);
	nbdx_conn->conn_th = kthread_create(nbdx_connect_work, nbdx_conn, name);
	kthread_bind(nbdx_conn->conn_th, cpu);
	atomic_inc(&nbdx_session->conns_count);
	wake_up_process(nbdx_conn->conn_th);
	*conn = nbdx_conn;

	return 0;
}

int nbdx_session_create(const char *portal, struct nbdx_session *nbdx_session)
{
	struct xio_session_params params;
	int i, j, ret;

	strcpy(nbdx_session->portal, portal);
	/* client session params */
	memset(&params, 0, sizeof(params));
	params.type     = XIO_SESSION_CLIENT;
	params.ses_ops      = &nbdx_ses_ops;
	params.user_context = nbdx_session;
	params.uri      = nbdx_session->portal;
	nbdx_session->session = xio_session_create(&params);
	if (!nbdx_session->session) {
		pr_err("failed to create xio session\n");
		ret = -ENOMEM;
		return ret;
	}

	nbdx_session->nbdx_conns = kzalloc(submit_queues * sizeof(*nbdx_session->nbdx_conns),
					  GFP_KERNEL);
	if (!nbdx_session->nbdx_conns) {
		pr_err("failed to allocate nbdx connections array\n");
		ret = -ENOMEM;
		goto err_destroy_portal;
	}

	init_completion(&nbdx_session->conns_wait);
	atomic_set(&nbdx_session->conns_count, 0);

	for (i = 0; i < submit_queues; i++) {
		ret = nbdx_create_conn(nbdx_session, i,
				       &nbdx_session->nbdx_conns[i]);
		if (ret)
			goto err_destroy_conns;
	}
	atomic_set(&nbdx_session->destroy_conns_count, submit_queues);
	/* wait for all connections establishment to complete */
	if (!wait_for_completion_interruptible_timeout(&nbdx_session->conns_wait,
						       120 * HZ)) {
		pr_err("connection establishment timeout expired\n");
		return -EAGAIN;
	}

	ret = nbdx_setup_remote_session(nbdx_session,
			submit_queues);
	if (ret) {
		pr_err("failed to setup remote session %s ret=%d\n",
				nbdx_session->portal, ret);
		nbdx_destroy_session_connections(nbdx_session);
		return -EAGAIN;
	}

	return 0;

err_destroy_conns:
	for (j = 0; j < i; j++) {
		nbdx_destroy_conn(nbdx_session->nbdx_conns[j]);
		nbdx_session->nbdx_conns[j] = NULL;
	}
	kfree(nbdx_session->nbdx_conns);
err_destroy_portal:
	if (nbdx_session->session)
		xio_session_destroy(nbdx_session->session);
	return ret;

}

void nbdx_session_destroy(struct nbdx_session *nbdx_session)
{
	mutex_lock(&g_lock);
	list_del(&nbdx_session->list);
	mutex_unlock(&g_lock);

	nbdx_destroy_session_devices(nbdx_session);
	if (nbdx_session->session) {
		nbdx_destroy_remote_session(nbdx_session);
		nbdx_destroy_session_connections(nbdx_session);
	}
}

static int __init nbdx_init_module(void)
{
	int size_iov = MAX_SGL_LEN;
	int opt;

	if (nbdx_create_configfs_files())
		return 1;

	pr_debug("nr_cpu_ids=%d, num_online_cpus=%d\n",
		 nr_cpu_ids, num_online_cpus());
	submit_queues = num_online_cpus();

	/* set accelio max message vector used (default is 4) */
	xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO,
		    XIO_OPTNAME_MAX_IN_IOVLEN, &size_iov, sizeof(int));
	xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO,
		    XIO_OPTNAME_MAX_OUT_IOVLEN, &size_iov, sizeof(int));

	opt = 2048;
	xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO,
		    XIO_OPTNAME_SND_QUEUE_DEPTH_MSGS, &opt, sizeof(int));

	opt = 2048;
	xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO,
		    XIO_OPTNAME_RCV_QUEUE_DEPTH_MSGS, &opt, sizeof(int));

	opt = 512;
	xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO,
		    XIO_OPTNAME_INLINE_XIO_DATA_ALIGN, &opt, sizeof(int));

	opt = 512;
	xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO,
		    XIO_OPTNAME_XFER_BUF_ALIGN, &opt, sizeof(int));

	opt = 0;
	xio_set_opt(NULL, XIO_OPTLEVEL_ACCELIO,
		    XIO_OPTNAME_ENABLE_KEEPALIVE, &opt, sizeof(int));

	nbdx_major = register_blkdev(0, "nbdx");
	if (nbdx_major < 0)
		return nbdx_major;

	mutex_init(&g_lock);
	INIT_LIST_HEAD(&g_nbdx_sessions);

	return 0;
}

static void __exit nbdx_cleanup_module(void)
{
	struct nbdx_session *nbdx_session, *tmp;

	unregister_blkdev(nbdx_major, "nbdx");

	list_for_each_entry_safe(nbdx_session, tmp, &g_nbdx_sessions, list) {
		nbdx_session_destroy(nbdx_session);
	}

	nbdx_destroy_configfs_files();

}

module_init(nbdx_init_module);
module_exit(nbdx_cleanup_module);
