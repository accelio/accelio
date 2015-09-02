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

#ifndef NBDX_H
#define NBDX_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/fcntl.h>
#include <linux/cpumask.h>
#include <linux/configfs.h>

#include "libxio.h"
#include "raio_kutils.h"
#include "raio_kbuffer.h"

#define MAX_MSG_LEN	    512
#define MAX_PORTAL_NAME	    256
#define MAX_NBDX_DEV_NAME   256
#define SUPPORTED_DISKS	    256
#define SUPPORTED_PORTALS   5
#define NBDX_SECT_SIZE	    512
#define NBDX_SECT_SHIFT	    ilog2(NBDX_SECT_SIZE)
#define NBDX_QUEUE_DEPTH    64

enum nbdx_dev_state {
	DEVICE_INITIALIZING,
	DEVICE_OPENNING,
	DEVICE_RUNNING,
	DEVICE_OFFLINE
};

struct nbdx_connection {
	struct nbdx_session    *nbdx_sess;
	struct xio_context     *ctx;
	struct xio_connection  *conn;
	struct task_struct     *conn_th;
	int			cpu_id;
	int			wq_flag;
	struct xio_msg		req;
	struct xio_msg	       *rsp;
	wait_queue_head_t	wq;
};

struct nbdx_session {
	struct xio_session	     *session;
	struct nbdx_connection	    **nbdx_conns;
	char			      portal[MAX_PORTAL_NAME];
	struct list_head	      list;
	struct list_head	      devs_list; /* list of struct nbdx_file */
	spinlock_t		      devs_lock;
	struct config_group	      session_cg;
	struct completion	      conns_wait;
	atomic_t		      conns_count;
	atomic_t		      destroy_conns_count;
};

struct nbdx_queue {
	unsigned int		     queue_depth;
	struct nbdx_connection	    *nbdx_conn;
	struct nbdx_file	    *xdev; /* pointer to parent*/
};

struct nbdx_file {
	int			     fd;
	int			     major; /* major number from kernel */
	struct r_stat64		     stbuf; /* remote file stats*/
	char			     file_name[MAX_NBDX_DEV_NAME];
	struct list_head	     list; /* next node in list of struct nbdx_file */
	struct gendisk		    *disk;
	struct request_queue	    *queue; /* The device request queue */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	struct blk_mq_tag_set	     tag_set;
#endif
	struct nbdx_queue	    *queues;
	unsigned int		     queue_depth;
	unsigned int		     nr_queues;
	int			     index; /* drive idx */
	char			     dev_name[MAX_NBDX_DEV_NAME];
	struct nbdx_connection	    **nbdx_conns;
	struct config_group	     dev_cg;
	spinlock_t		     state_lock;
	enum nbdx_dev_state	     state;
};

extern struct list_head g_nbdx_sessions;
extern struct mutex g_lock;
extern int created_portals;
extern int submit_queues;
extern int nbdx_major;
extern int nbdx_indexes;

int nbdx_transfer(struct nbdx_file *xdev, char *buffer, unsigned long start,
		  unsigned long len, int write, struct request *req,
		  struct nbdx_queue *q);
int nbdx_session_create(const char *portal, struct nbdx_session *nbdx_session);
int nbdx_create_device(struct nbdx_session *nbdx_session,
		       const char *xdev_name, struct nbdx_file *nbdx_file);
void nbdx_destroy_device(struct nbdx_session *nbdx_session,
                         struct nbdx_file *nbdx_file);
int nbdx_create_configfs_files(void);
void nbdx_destroy_configfs_files(void);
int nbdx_rq_map_sg(struct request *rq, struct xio_vmsg *vmsg,
		    unsigned long long *len);
int nbdx_register_block_device(struct nbdx_file *nbdx_file);
void nbdx_unregister_block_device(struct nbdx_file *nbdx_file);
int nbdx_setup_queues(struct nbdx_file *xdev);
void nbdx_destroy_queues(struct nbdx_file *xdev);
struct nbdx_session *nbdx_session_find(struct list_head *s_data_list,
					    const char *host_name);
struct nbdx_file *nbdx_file_find(struct nbdx_session *nbdx_session,
				 const char *name);
struct nbdx_session *nbdx_session_find_by_portal(struct list_head *s_data_list,
						 const char *portal);
void nbdx_session_destroy(struct nbdx_session *nbdx_session);
const char* nbdx_device_state_str(struct nbdx_file *dev);
int nbdx_set_device_state(struct nbdx_file *dev, enum nbdx_dev_state state);

#endif  /* NBDX_H */

