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
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/eventfd.h>
#include <libaio.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/sysmacros.h>
#include <arpa/inet.h>

#include "raio_bs.h"
#include "libxio.h"
#include "libraio.h"

/*---------------------------------------------------------------------------*/
/* preprocessor directives                                                   */
/*---------------------------------------------------------------------------*/
#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))
#define AIO_MAX_IODEPTH		128


#ifndef TAILQ_FOREACH_SAFE
# define TAILQ_FOREACH_SAFE(var, tvar, head, field)			 \
	for ((var) = TAILQ_FIRST((head));                                \
			(var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
			(var) = (tvar))
#endif

#define min_t(type, x, y) \
		({ type __x = (x); type __y = (y); __x < __y ? __x : __y; })
#define max_t(type, x, y) \
		({ type __x = (x); type __y = (y); __x > __y ? __x : __y; })


/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct raio_bs_aio_info {
	TAILQ_ENTRY(raio_bs_aio_info)	dev_list_entry;
	io_context_t			ctx;
	TAILQ_HEAD(, raio_io_cmd)	cmd_wait_list;
	uint32_t			nwaiting;
	uint32_t			npending;
	uint32_t			iodepth;

	int				resubmit;

	struct raio_bs			*dev;

	int				evt_fd;
	int				pad;

	struct iocb			iocb_arr[AIO_MAX_IODEPTH];
	struct iocb			*piocb_arr[AIO_MAX_IODEPTH];
	struct io_event			io_evts[AIO_MAX_IODEPTH];
};

/*---------------------------------------------------------------------------*/
/* globals								     */
/*---------------------------------------------------------------------------*/
static TAILQ_HEAD(, raio_bs_aio_info) raio_aio_dev_list =
				TAILQ_HEAD_INITIALIZER(raio_aio_dev_list);

/*---------------------------------------------------------------------------*/
/* raio_aio_iocb_prep							     */
/*---------------------------------------------------------------------------*/
static void raio_aio_iocb_prep(struct raio_bs_aio_info *info, int idx,
			       struct raio_io_cmd *cmd)
{
	struct iocb *iocb = &info->iocb_arr[idx];

	switch (cmd->op) {
	case RAIO_CMD_PREAD:
		/*
		printf("fd:%d, buf:%p, count:%ld, offset:%ld\n",
		       cmd->fd, cmd->buf, cmd->bcount, cmd->offset);
		*/
		io_prep_pread(iocb, cmd->fd, cmd->buf,
			      cmd->bcount, cmd->offset);
		break;
	case RAIO_CMD_PWRITE:
		/*
		printf("%d fd:%d, buf:%p, count:%ld, offset:%ld\n",
		       cmd->fd, cmd->buf, cmd->bcount, cmd->offset);
		*/
		io_prep_pwrite(iocb, cmd->fd, cmd->buf,
			       cmd->bcount, cmd->offset);
		break;
	default:
		return;
		break;
	}
	iocb->data = cmd;
	io_set_eventfd(iocb, info->evt_fd);
}

/*---------------------------------------------------------------------------*/
/* raio_aio_submit_dev_batch						     */
/*---------------------------------------------------------------------------*/
static int raio_aio_submit_dev_batch(struct raio_bs_aio_info *info)
{
	int nsubmit, nsuccess;
	struct raio_io_cmd *cmd, *next;
	int i = 0;

	nsubmit = info->iodepth - info->npending; /* max allowed to submit */
	if (nsubmit > (int)info->nwaiting)
		nsubmit = info->nwaiting;

	if (!nsubmit)
		return 0;

	TAILQ_FOREACH_SAFE(cmd, next, &info->cmd_wait_list, raio_list) {
		raio_aio_iocb_prep(info, i, cmd);
		TAILQ_REMOVE(&info->cmd_wait_list, cmd, raio_list);
		if (++i == nsubmit)
			break;
	}
	nsuccess = io_submit(info->ctx, nsubmit, info->piocb_arr);
	if (unlikely(nsuccess < 0)) {
		if (nsuccess == -EAGAIN) {
			fprintf(stderr, "delayed submit %d\n", nsubmit);
			nsuccess = 0; /* leave the dev pending with all cmds */
		} else {
			fprintf(stderr,
				"failed to submit %d cmds, err: %d - %s\n",
				nsubmit, -nsuccess, strerror(-nsuccess));
			return nsuccess;
		}
	}
	if (nsuccess < nsubmit) {
		for (i = nsubmit-1; i >= nsuccess; i--) {
			cmd = (struct raio_io_cmd *)info->iocb_arr[i].data;
			TAILQ_INSERT_HEAD(&info->cmd_wait_list, cmd, raio_list);
		}
	}

	info->npending += nsuccess;
	info->nwaiting -= nsuccess;

	/* if no cmds remain, remove the dev from the pending list
	 */
	if (!info->nwaiting)
		TAILQ_REMOVE(&raio_aio_dev_list, info, dev_list_entry);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_aio_complete_one						     */
/*---------------------------------------------------------------------------*/
static void raio_aio_complete_one(struct io_event *ep)
{
	struct raio_io_cmd *cmd = (struct raio_io_cmd *)ep->data;

	if (unlikely(ep->res2 != 0)) {
		const char *op = (cmd->op == RAIO_CMD_PREAD) ? "read" : "write";
		fprintf(stderr, "aio %s:err %lu", op, ep->res2);
	}

	cmd->res  = ep->res;
	cmd->res2 = ep->res2;
	if (unlikely(ep->res != cmd->bcount)) {
		if (((long)ep->res) < 0) {
			fprintf(stderr, "completion error: %s - ",
				strerror(-ep->res));
			fprintf(stderr, "fd:%d, buf:%p, count:%lu, " \
				"offset:%ld\n",
				cmd->fd, cmd->buf, cmd->bcount,
				cmd->offset);
		} else  {
			fprintf(stderr, "fd:%d, buf:%p, count:%lu, " \
				"offset:%ld\n",
				cmd->fd, cmd->buf, cmd->bcount,
				cmd->offset);
			fprintf(stderr, "fd:%d missing bytes got %ld\n",
				cmd->fd, ep->res);
		}
	}

	if (likely(cmd->comp_cb))
		cmd->comp_cb(cmd);
}

/*---------------------------------------------------------------------------*/
/* raio_aio_get_events							     */
/*---------------------------------------------------------------------------*/
static void raio_aio_get_events(struct raio_bs_aio_info *info)
{
	unsigned int	i;
	int		ret;
	uint32_t	nevents;

	while (info->npending) {
retry_getevts:
		nevents = ARRAY_SIZE(info->io_evts);
		ret = io_getevents(info->ctx, 0, nevents, info->io_evts, NULL);
		if (ret == 0)
			break;
		if (ret > 0) {
			nevents = ret;
			info->npending -= nevents;
		} else {
			if (ret == -EINTR)
				goto retry_getevts;
			fprintf(stderr, "io_getevents failed, err:%d\n", -ret);
			return;
		}
		for (i = 0; i < nevents; i++)
			raio_aio_complete_one(&info->io_evts[i]);
	}

	if (info->nwaiting)
		raio_aio_submit_dev_batch(info);
}

/*---------------------------------------------------------------------------*/
/* raio_aio_get_completions						     */
/*---------------------------------------------------------------------------*/
static void raio_aio_get_completions(int fd, int events, void *data)
{
	struct raio_bs_aio_info	*info = (struct raio_bs_aio_info *)data;
	int			ret;
	eventfd_t		val;

retry_read:
	ret = eventfd_read(info->evt_fd, &val);
	if (unlikely(ret < 0)) {
		fprintf(stderr, "failed to read AIO completions, %m\n");
		if (errno == EAGAIN || errno == EINTR)
			goto retry_read;
		return;
	}
	if (info->npending)
		raio_aio_get_events(info);
}

/*---------------------------------------------------------------------------*/
/* raio_bs_aio_init                                                           */
/*---------------------------------------------------------------------------*/
static int raio_bs_aio_init(struct raio_bs *dev)
{
	unsigned int		i;
	struct raio_bs_aio_info	*dev_info = (struct raio_bs_aio_info *)dev->dd;

	dev_info->dev  = dev;

	TAILQ_INIT(&dev_info->cmd_wait_list);

	for (i = 0; i < ARRAY_SIZE(dev_info->iocb_arr); i++)
		dev_info->piocb_arr[i] = &dev_info->iocb_arr[i];

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_bs_aio_open                                                          */
/*---------------------------------------------------------------------------*/
static int raio_bs_aio_open(struct raio_bs *dev, int fd)
{
	struct raio_bs_aio_info *info = (struct raio_bs_aio_info *)dev->dd;
	int ret, afd;

	info->iodepth = AIO_MAX_IODEPTH;
	info->ctx = 0;

	ret = io_setup(info->iodepth, &info->ctx);
	if (ret) {
		fprintf(stderr, "failed to create aio context, %m\n");
		return -1;
	}

	afd = eventfd(0, EFD_NONBLOCK);
	if (afd < 0) {
		fprintf(stderr, "failed to create eventfd, %m\n");
		ret = afd;
		goto close_ctx;
	}

	ret = xio_context_add_ev_handler((struct xio_context *)dev->ctx,
					 afd,
					 XIO_POLLIN,
					 raio_aio_get_completions, info);
	if (ret)
		goto close_eventfd;
	info->evt_fd = afd;

	ret = fstat64(fd, &dev->stbuf);
	if (ret == 0) {
		if (S_ISBLK(dev->stbuf.st_mode)) {
			ret = ioctl(fd, BLKGETSIZE64, &dev->stbuf.st_size);
			if (ret < 0) {
				fprintf(stderr, "Cannot get size, %m\n");
				goto close_eventfd;
			}
		}
	} else {
		fprintf(stderr, "Cannot stat file, %m\n");
		goto close_eventfd;
	}

	return 0;

close_eventfd:
	close(afd);
close_ctx:
	io_destroy(info->ctx);

	return ret;
}

/*---------------------------------------------------------------------------*/
/* raio_bs_aio_close							     */
/*---------------------------------------------------------------------------*/
static inline void raio_bs_aio_close(struct raio_bs *dev)
{
}

/*---------------------------------------------------------------------------*/
/* raio_bs_aio_process_events						     */
/*---------------------------------------------------------------------------*/
static void raio_bs_aio_process_events(struct raio_bs *dev)
{
	struct raio_bs_aio_info	*info = (struct raio_bs_aio_info *)dev->dd;

	if (info->npending)
		raio_aio_get_events(info);
}

/*---------------------------------------------------------------------------*/
/* raio_bs_aio_cmd_submit                                                     */
/*---------------------------------------------------------------------------*/
static int raio_bs_aio_cmd_submit(struct raio_bs *dev, struct raio_io_cmd *cmd)
{
	struct raio_bs_aio_info	*info = (struct raio_bs_aio_info *)dev->dd;

	TAILQ_INSERT_TAIL(&info->cmd_wait_list, cmd, raio_list);
	if (!info->nwaiting)
		TAILQ_INSERT_TAIL(&raio_aio_dev_list, info, dev_list_entry);

	info->nwaiting++;

	if (info->nwaiting == info->iodepth - info->npending) {
		raio_aio_submit_dev_batch(info);
		raio_bs_aio_process_events(dev);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_bs_aio_set_last_in_batch                                             */
/*---------------------------------------------------------------------------*/
static void raio_bs_aio_set_last_in_batch(struct raio_bs *dev)
{
	struct raio_bs_aio_info	*info = (struct raio_bs_aio_info *)dev->dd;

	raio_aio_submit_dev_batch(info);
	raio_bs_aio_process_events(dev);
}

/*---------------------------------------------------------------------------*/
/* raio_bs_aio_exit                                                           */
/*---------------------------------------------------------------------------*/
static void raio_bs_aio_exit(struct raio_bs *dev)
{
	struct raio_bs_aio_info *info = (struct raio_bs_aio_info *)dev->dd;

	(void)xio_context_del_ev_handler((struct xio_context *)dev->ctx,
					 info->evt_fd);
	close(info->evt_fd);
	io_destroy(info->ctx);
}

/*---------------------------------------------------------------------------*/
/* struct raio_aio_bst                                                        */
/*---------------------------------------------------------------------------*/
static struct backingstore_template raio_aio_bst = {
	.bs_name		= "aio",
	.bs_datasize		= sizeof(struct raio_bs_aio_info),
	.bs_init		= raio_bs_aio_init,
	.bs_exit		= raio_bs_aio_exit,
	.bs_open		= raio_bs_aio_open,
	.bs_close		= raio_bs_aio_close,
	.bs_cmd_submit		= raio_bs_aio_cmd_submit,
	.bs_set_last_in_batch	= raio_bs_aio_set_last_in_batch,
	.bs_poll		= raio_bs_aio_process_events
};

/*
 * This attribute lead gcc/ld to
 * exec this function
 * before the "main".
 */
/*---------------------------------------------------------------------------*/
/* bs_aio_constructor                                                        */
/*---------------------------------------------------------------------------*/
void raio_bs_aio_constructor(void)
{
	register_backingstore_template(&raio_aio_bst);
}

