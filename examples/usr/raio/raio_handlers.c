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
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/param.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include "libxio.h"

#include "raio_buffer.h"
#include "raio_command.h"
#include "raio_handlers.h"
#include "raio_utils.h"
#include "raio_bs.h"
#include "libraio.h"
#include "raio_msg_pool.h"

/*---------------------------------------------------------------------------*/
/* preprocessor macros				                             */
/*---------------------------------------------------------------------------*/
#define MAXBLOCKSIZE		(128 * 1024)
#define EXTRA_MSGS		512

#define RAIO_CMD_HDR_SZ		512
#define RAIO_CMDS_POOL_SZ	128

#ifndef TAILQ_FOREACH_SAFE
#define	TAILQ_FOREACH_SAFE(var, head, field, next)			\
	for ((var) = ((head)->tqh_first);				\
	     (var) != NULL && ((next) = TAILQ_NEXT((var), field), 1);	\
			(var) = (next))
#endif

/*---------------------------------------------------------------------------*/
/* data structures				                             */
/*---------------------------------------------------------------------------*/
struct raio_io_u {
	struct raio_event		ev_data;
	struct xio_msg			*rsp;
	void				*buf;
	struct raio_io_cmd		iocmd;

	TAILQ_ENTRY(raio_io_u)		io_u_list;
};

struct raio_io_portal_data {
	struct raio_bs			*bs_dev;
	int				pad;
	int				iodepth;
	int				io_nr;
	int				io_u_free_nr;
	struct raio_io_u		*io_us_free;

	TAILQ_HEAD(, raio_io_u)		io_u_free_list;
	struct msg_pool			*rsp_pool; /* for submits */

	struct msg_pool			*cmds_rsp_pool; /* control messages */

	struct xio_context		*ctx;

};

struct raio_io_session_data {
	int				portals_nr;
	int				pad;
	struct raio_io_portal_data	*pd;
};

/*---------------------------------------------------------------------------*/
/* raio_handler_init_session_data				             */
/*---------------------------------------------------------------------------*/
void *raio_handler_init_session_data(int portals_nr)
{
	struct raio_io_session_data	*sd;

	sd = (struct raio_io_session_data *)calloc(1, sizeof(*sd));
	if (!sd)
		return NULL;

	sd->pd	=
	      (struct raio_io_portal_data *)calloc(portals_nr, sizeof(*sd->pd));
	sd->portals_nr	= portals_nr;

	return sd;
}

/*---------------------------------------------------------------------------*/
/* raio_handler_init_portal_data				             */
/*---------------------------------------------------------------------------*/
void *raio_handler_init_portal_data(void *prv_session_data,
				    int portal_nr, void *ctx)
{
	struct raio_io_session_data *sd =
				(struct raio_io_session_data *)prv_session_data;
	struct raio_io_portal_data *pd = &sd->pd[portal_nr];

	pd->ctx = (struct xio_context *)ctx;
	pd->cmds_rsp_pool = msg_pool_create(RAIO_CMD_HDR_SZ, 0,
					    RAIO_CMDS_POOL_SZ);

	return pd;
}

/*---------------------------------------------------------------------------*/
/* raio_handler_get_portal_data						     */
/*---------------------------------------------------------------------------*/
void *raio_handler_get_portal_data(void *prv_session_data, int portal_nr)
{
	struct raio_io_session_data *sd =
				(struct raio_io_session_data *)prv_session_data;

	return &sd->pd[portal_nr];
}

/*---------------------------------------------------------------------------*/
/* raio_handler_free_session_data				             */
/*---------------------------------------------------------------------------*/
void raio_handler_free_session_data(void *prv_session_data)
{
	struct raio_io_session_data *sd =
				(struct raio_io_session_data *)prv_session_data;

	free(sd->pd);

	free(sd);
}

/*---------------------------------------------------------------------------*/
/* raio_handler_free_portal_data				             */
/*---------------------------------------------------------------------------*/
void raio_handler_free_portal_data(void *prv_portal_data)
{
	struct raio_io_portal_data	*pd =
				(struct raio_io_portal_data *)prv_portal_data;

	msg_pool_delete(pd->cmds_rsp_pool);

	if (pd->bs_dev->is_null)
		return;

	close(pd->bs_dev->fd);
	raio_bs_close(pd->bs_dev);
	raio_bs_exit(pd->bs_dev);
}

/*---------------------------------------------------------------------------*/
/* raio_handle_open				                             */
/*---------------------------------------------------------------------------*/
static int raio_handle_open(void *prv_session_data,
			    void *prv_portal_data,
			    struct raio_command *cmd,
			    char *cmd_data,
			    struct xio_msg *req)
{
	struct raio_io_session_data	*sd =
				(struct raio_io_session_data *)prv_session_data;
	struct raio_io_portal_data	*pd =
				(struct raio_io_portal_data *)prv_portal_data;
	const char			*pathname;
	uint32_t			flags = 0;
	unsigned			overall_size;
	int				fd = 0;
	int				i, is_null = 0;
	char				*rsp_hdr;
	struct xio_msg			*rsp;

	rsp	= msg_pool_get(pd->cmds_rsp_pool);
	rsp_hdr = (char *)rsp->out.header.iov_base;

	overall_size = sizeof(fd);

	pathname = unpack_u32(&flags,
			      cmd_data);

	if (sizeof(flags) + strlen(pathname) + 1 != cmd->data_len) {
		fd = -1;
		errno = EINVAL;
		printf("open request rejected\n");
		goto reject;
	}

	if (strcmp(pathname, "/dev/null")) {
		fd = open(pathname, flags);
		if (fd == -1)
			goto reject;
	} else {
		is_null = 1;
		fd = 0;
	}

	for (i = 0; i < sd->portals_nr; i++) {
		struct raio_bs			*bs_dev;
		struct raio_io_portal_data	*cpd;

		cpd = &sd->pd[i];
		if (is_null) {
			bs_dev = raio_bs_init(cpd->ctx, "null");
			bs_dev->is_null = 1;
		} else {
			bs_dev = raio_bs_init(cpd->ctx, "aio");
			bs_dev->is_null = 0;
		}

		errno = -raio_bs_open(bs_dev, fd);
		if (errno)
			break;

		cpd->bs_dev = bs_dev;
	}

reject:
	if (fd == -1) {
		struct raio_answer ans = {RAIO_CMD_OPEN, 0,
					   -1, errno};

		pack_u32((uint32_t *)&ans.ret_errno,
			 pack_u32((uint32_t *)&ans.ret,
			 pack_u32(&ans.data_len,
			 pack_u32(&ans.command,
			 rsp_hdr))));
		fprintf(stderr, "open %s failed %m\n", pathname);
	 } else {
		 unsigned overall_size = sizeof(fd);
		 struct raio_answer ans = {RAIO_CMD_OPEN,
					   overall_size, 0, 0};

		 pack_u32((uint32_t *)&fd,
			  pack_u32((uint32_t *)&ans.ret_errno,
			  pack_u32((uint32_t *)&ans.ret,
			  pack_u32(&ans.data_len,
			  pack_u32(&ans.command,
			  rsp_hdr)))));
	 }

	rsp->out.header.iov_len = (sizeof(struct raio_answer) +
				   overall_size);
	rsp->flags = XIO_MSG_FLAG_IMM_SEND_COMP;
	rsp->request = req;

	xio_send_response(rsp);

	/* coverity[leaked_handle] - 'fd' is not leaked */
	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_handle_close				                             */
/*---------------------------------------------------------------------------*/
static int raio_handle_close(void *prv_session_data,
			     void *prv_portal_data,
			     struct raio_command *cmd,
			     char *cmd_data,
			     struct xio_msg *req)
{
	struct raio_io_session_data	*sd =
				(struct raio_io_session_data *)prv_session_data;
	struct raio_io_portal_data	*pd =
				(struct raio_io_portal_data *)prv_portal_data;
	struct raio_io_portal_data	*cpd;
	int				fd;
	int				i, retval = 0;
	char				*rsp_hdr;
	struct xio_msg			*rsp;

	rsp	= msg_pool_get(pd->cmds_rsp_pool);
	rsp_hdr = (char *)rsp->out.header.iov_base;

	unpack_u32((uint32_t *)&fd,
		    cmd_data);

	if (sizeof(fd) != cmd->data_len) {
		retval = -1;
		errno = EINVAL;
		printf("close request rejected\n");
		goto reject;
	}

	/* close fd only once */
	if (!pd->bs_dev->is_null) {
		retval = close(pd->bs_dev->fd);
		if (retval) {
			printf("close failed\n");
			goto reject;
		}
	}

	for (i = 0; i < sd->portals_nr; i++) {
		cpd = &sd->pd[i];
		if (!cpd->bs_dev->is_null) {
			raio_bs_close(cpd->bs_dev);
			raio_bs_exit(cpd->bs_dev);
		}
	}

reject:
	if (retval != 0) {
		struct raio_answer ans = { RAIO_CMD_CLOSE, 0, -1, errno };

		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 rsp_hdr))));
	} else {
		struct raio_answer ans = { RAIO_CMD_CLOSE, 0, 0, 0 };

		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 rsp_hdr))));
	 }

	rsp->out.header.iov_len = sizeof(struct raio_answer);
	rsp->flags = XIO_MSG_FLAG_IMM_SEND_COMP;
	rsp->request = req;

	xio_send_response(rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_handle_fstat				                             */
/*---------------------------------------------------------------------------*/
static int raio_handle_fstat(void *prv_session_data,
			     void *prv_portal_data,
			     struct raio_command *cmd,
			     char *cmd_data,
			     struct xio_msg *req)
{
	struct raio_io_portal_data	*pd =
				(struct raio_io_portal_data *)prv_portal_data;
	struct raio_bs			*bs_dev;
	int				fd;
	int				retval = 0;
	char				*rsp_hdr;
	struct xio_msg			*rsp;

	rsp	= msg_pool_get(pd->cmds_rsp_pool);
	rsp_hdr = (char *)rsp->out.header.iov_base;

	unpack_u32((uint32_t *)&fd,
		    cmd_data);

	if (sizeof(fd) != cmd->data_len) {
		retval = -1;
		errno = EINVAL;
		printf("fstat request rejected\n");
		goto reject;
	}

	bs_dev = pd->bs_dev;
	if (!bs_dev) {
		printf("%s: Ambiguous device file descriptor %d\n",
		       __func__, fd);
		retval = -1;
		errno = ENODEV;
		goto reject;
	}

reject:
	if (retval != 0) {
		struct raio_answer ans = { RAIO_CMD_FSTAT, 0, -1, errno };

		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 rsp_hdr))));
	} else {
		struct raio_answer ans = {RAIO_CMD_FSTAT,
					  STAT_BLOCK_SIZE, 0, 0};

		pack_stat64(&bs_dev->stbuf,
		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 rsp_hdr)))));
	}

	rsp->out.header.iov_len = sizeof(struct raio_answer) +
				  STAT_BLOCK_SIZE;
	rsp->flags = XIO_MSG_FLAG_IMM_SEND_COMP;
	rsp->request = req;

	xio_send_response(rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_handle_setup				                             */
/*---------------------------------------------------------------------------*/
static int raio_handle_setup(void *prv_session_data,
			     void *prv_portal_data,
			     struct raio_command *cmd,
			     char *cmd_data,
			     struct xio_msg *req)
{
	int				i, j, err = 0;
	uint32_t			iodepth;
	struct raio_io_session_data	*sd =
				(struct raio_io_session_data *)prv_session_data;
	struct raio_io_portal_data	*pd =
				(struct raio_io_portal_data *)prv_portal_data;
	struct raio_io_portal_data	*cpd;
	struct xio_iovec_ex		*sglist;
	char				*rsp_hdr;
	struct xio_msg			*rsp;

	rsp	= msg_pool_get(pd->cmds_rsp_pool);
	rsp_hdr = (char *)rsp->out.header.iov_base;

	if (sizeof(int) != cmd->data_len) {
		err = EINVAL;
		printf("io setup request rejected\n");
		goto reject;
	}

	unpack_u32(&iodepth, cmd_data);

	for (i = 0; i < sd->portals_nr; i++) {
		cpd = &sd->pd[i];
		/* divide remote iodepth between server resources */
		cpd->iodepth = (iodepth / sd->portals_nr) + 1;
		cpd->io_u_free_nr = cpd->iodepth + EXTRA_MSGS;
		cpd->io_us_free = (struct raio_io_u *)calloc(cpd->io_u_free_nr,
					 sizeof(struct raio_io_u));
		cpd->rsp_pool = msg_pool_create(RAIO_CMD_HDR_SZ, MAXBLOCKSIZE,
						cpd->io_u_free_nr);
		TAILQ_INIT(&cpd->io_u_free_list);

		/* register each io_u in the free list */
		for (j = 0; j < cpd->io_u_free_nr; j++) {
			cpd->io_us_free[j].rsp = msg_pool_get(cpd->rsp_pool);
			sglist = vmsg_sglist(&cpd->io_us_free[j].rsp->out);
			cpd->io_us_free[j].buf = sglist[0].iov_base;
			TAILQ_INSERT_TAIL(&cpd->io_u_free_list,
					  &cpd->io_us_free[j],
					  io_u_list);
		}
	}

reject:
	if (err) {
		struct raio_answer ans = { RAIO_CMD_IO_SETUP, 0, -1, err };

		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 rsp_hdr))));
	} else {
		struct raio_answer ans = { RAIO_CMD_IO_SETUP, 0, 0, 0 };

		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 rsp_hdr))));
	 }

	rsp->out.header.iov_len = sizeof(struct raio_answer);
	rsp->flags = XIO_MSG_FLAG_IMM_SEND_COMP;
	rsp->request = req;

	xio_send_response(rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_handle_destroy				                             */
/*---------------------------------------------------------------------------*/
static int raio_handle_destroy(void *prv_session_data,
			       void *prv_portal_data,
			       struct raio_command *cmd,
			       char *cmd_data,
			       struct xio_msg *req)
{
	struct raio_io_portal_data	*pd =
				(struct raio_io_portal_data *)prv_portal_data;
	int				retval = 0;
	char				*rsp_hdr;
	struct xio_msg			*rsp;

	rsp	= msg_pool_get(pd->cmds_rsp_pool);
	rsp_hdr = (char *)rsp->out.header.iov_base;

	if (0 != cmd->data_len) {
		retval = -1;
		errno = EINVAL;
		printf("destroy request rejected\n");
		goto reject;
	}

reject:
	if (retval == -1) {
		struct raio_answer ans = { RAIO_CMD_IO_DESTROY, 0, -1, errno };

		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 rsp_hdr))));
	} else {
		struct raio_answer ans = { RAIO_CMD_IO_DESTROY, 0, 0, 0 };

		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 rsp_hdr))));
	}

	rsp->out.header.iov_len = sizeof(struct raio_answer);
	rsp->flags = XIO_MSG_FLAG_IMM_SEND_COMP;
	rsp->request = req;

	xio_send_response(rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_reject_request				                             */
/*---------------------------------------------------------------------------*/
int raio_reject_request(void *prv_session_data,
			void *prv_portal_data,
			struct raio_command *cmd,
			char *cmd_data,
			struct xio_msg *req)
{
	struct raio_io_portal_data *pd =
				(struct raio_io_portal_data *)prv_portal_data;
	struct raio_answer	ans = { RAIO_CMD_UNKNOWN, 0, -1, errno };
	char			*rsp_hdr;
	struct xio_msg		*rsp;

	rsp	= msg_pool_get(pd->cmds_rsp_pool);
	rsp_hdr = (char *)rsp->out.header.iov_base;

	pack_u32((uint32_t *)&ans.ret_errno,
	pack_u32((uint32_t *)&ans.ret,
	pack_u32(&ans.data_len,
	pack_u32(&ans.command,
		 rsp_hdr))));

	rsp->out.header.iov_len = sizeof(struct raio_answer);
	rsp->flags = XIO_MSG_FLAG_IMM_SEND_COMP;
	vmsg_sglist_set_nents(&rsp->out, 0);
	rsp->request = req;

	xio_send_response(rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_cmd_submit_comp				                             */
/*---------------------------------------------------------------------------*/
static int on_cmd_submit_comp(struct raio_io_cmd *iocmd)
{
	struct raio_io_u	*io_u =
				(struct raio_io_u *)iocmd->user_context;
	struct xio_iovec_ex	*sglist;
	struct raio_answer	ans = { RAIO_CMD_IO_SUBMIT, 0, 0, 0 };

	pack_u32((uint32_t *)&iocmd->res2,
	pack_u32((uint32_t *)&iocmd->res,
	pack_u32((uint32_t *)&ans.ret_errno,
	pack_u32((uint32_t *)&ans.ret,
	pack_u32(&ans.data_len,
	pack_u32(&ans.command,
	(char *)io_u->rsp->out.header.iov_base))))));

	io_u->rsp->out.header.iov_len = sizeof(struct raio_answer) +
					2 * sizeof(uint32_t);

	sglist = vmsg_sglist(&io_u->rsp->out);
	if (io_u->iocmd.op == RAIO_CMD_PREAD) {
		if (iocmd->res != (int)iocmd->bcount) {
			if (iocmd->res < (int)iocmd->bcount) {
				sglist[0].iov_len = iocmd->res;
				if (iocmd->res == 0)
					vmsg_sglist_set_nents(&io_u->rsp->out,
							      0);
			} else {
				vmsg_sglist_set_nents(&io_u->rsp->out, 0);
				sglist[0].iov_len = iocmd->res;
			}
		} else {
			sglist[0].iov_len = iocmd->bcount;
		}
	} else {
		vmsg_sglist_set_nents(&io_u->rsp->out, 0);
		sglist[0].iov_len = 0;
	}
	xio_send_response(io_u->rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_handle_submit				                             */
/*---------------------------------------------------------------------------*/
static int raio_handle_submit(void *prv_session_data,
			      void *prv_portal_data,
			      struct raio_command *cmd,
			      char *cmd_data,
			      int last_in_batch,
			      struct xio_msg *req)
{
	struct raio_io_portal_data	*pd =
				(struct raio_io_portal_data *)prv_portal_data;
	struct xio_iovec_ex		*sglist;
	struct raio_io_u		*io_u;
	struct raio_iocb		iocb;
	struct raio_bs			*bs_dev;
	struct raio_answer		ans;
	int				retval;
	uint32_t			is_last_in_batch;
	uint32_t			msg_sz = SUBMIT_BLOCK_SIZE +
						 sizeof(uint32_t);
	char				*rsp_hdr;
	struct xio_msg			*rsp;

	io_u = TAILQ_FIRST(&pd->io_u_free_list);
	if (!io_u) {
		printf("io_u_free_list empty\n");
		errno = ENOSR;
		return -1;
	}

	TAILQ_REMOVE(&pd->io_u_free_list, io_u, io_u_list);
	msg_reset(io_u->rsp);
	pd->io_u_free_nr--;

	if (msg_sz != cmd->data_len) {
		retval = EINVAL;
		printf("io submit request rejected\n");

		goto reject;
	}
	unpack_iocb(&iocb,
	unpack_u32(&is_last_in_batch,
		   cmd_data));

	io_u->iocmd.fd			= iocb.raio_fildes;
	io_u->iocmd.op			= iocb.raio_lio_opcode;
	io_u->iocmd.bcount		= iocb.u.c.nbytes;

	if (io_u->iocmd.op == RAIO_CMD_PWRITE) {
		sglist = vmsg_sglist(&req->in);

		io_u->iocmd.buf		= sglist[0].iov_base;
		io_u->iocmd.mr		= sglist[0].mr;
	} else {
		sglist = vmsg_sglist(&io_u->rsp->out);

		io_u->iocmd.buf		= sglist[0].iov_base;
		io_u->iocmd.mr		= sglist[0].mr;
	}

	bs_dev = pd->bs_dev;
	if (!bs_dev) {
		printf("Ambiguous device file descriptor %d\n", io_u->iocmd.fd);
		retval = ENODEV;
		goto reject;
	}
	io_u->iocmd.fsize		= bs_dev->stbuf.st_size;
	io_u->iocmd.offset		= iocb.u.c.offset;
	io_u->iocmd.is_last_in_batch    = is_last_in_batch;
	io_u->iocmd.res			= 0;
	io_u->iocmd.res2		= 0;
	io_u->iocmd.user_context	= io_u;
	io_u->iocmd.comp_cb		= on_cmd_submit_comp;

	io_u->rsp->request		= req;
	io_u->rsp->user_context		= io_u;
	io_u->rsp->out.data_iov.nents	= 1;

	/* issues request to bs */
	retval = -raio_bs_cmd_submit(bs_dev, &io_u->iocmd);
	if (retval)
		goto reject;

	if (last_in_batch)
		raio_bs_set_last_in_batch(pd->bs_dev);

	return 0;
reject:
	rsp	= msg_pool_get(pd->cmds_rsp_pool);
	rsp_hdr = (char *)rsp->out.header.iov_base;

	TAILQ_INSERT_TAIL(&pd->io_u_free_list, io_u, io_u_list);
	pd->io_u_free_nr++;
	msg_reset(rsp);

	ans.command	= RAIO_CMD_IO_SUBMIT;
	ans.data_len	= 0;
	ans.ret		= -1;
	ans.ret_errno	= retval;

	pack_u32((uint32_t *)&ans.ret_errno,
	pack_u32((uint32_t *)&ans.ret,
	pack_u32(&ans.data_len,
	pack_u32(&ans.command,
		 rsp_hdr))));

	rsp->out.header.iov_len = sizeof(struct raio_answer);
	rsp->request = req;
	rsp->user_context = NULL;

	xio_send_response(rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_handle_submit_comp				                     */
/*---------------------------------------------------------------------------*/
static int raio_handle_submit_comp(void *prv_session_data,
				   void *prv_portal_data,
				   struct xio_msg *rsp)
{
	struct raio_io_portal_data	*pd =
				(struct raio_io_portal_data *)prv_portal_data;
	struct raio_io_u	*io_u = (struct raio_io_u *)rsp->user_context;
	struct xio_iovec_ex		*sglist;

	if (io_u) {
		sglist = vmsg_sglist(&rsp->out);
		sglist[0].iov_base = io_u->buf;
		TAILQ_INSERT_TAIL(&pd->io_u_free_list, io_u, io_u_list);
		pd->io_u_free_nr++;
	} else {
		msg_pool_put(pd->cmds_rsp_pool, rsp);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_handle_destroy_comp				                     */
/*---------------------------------------------------------------------------*/
static int raio_handle_destroy_comp(void *prv_session_data,
				    void *prv_portal_data,
				    struct xio_msg *rsp)
{
	struct raio_io_session_data	*sd =
				(struct raio_io_session_data *)prv_session_data;
	struct raio_io_portal_data	*cpd;
	int				i, j;

	for (i = 0; i < sd->portals_nr; i++) {
		cpd = &sd->pd[i];
		/* unregister each io_u in the free list */
		for (j = 0; j < cpd->io_u_free_nr; j++) {
			TAILQ_REMOVE(&cpd->io_u_free_list,
				     &cpd->io_us_free[j],
				     io_u_list);
			msg_pool_put(cpd->rsp_pool, cpd->io_us_free[j].rsp);
			cpd->io_us_free[j].buf = NULL;
		}
		cpd->io_u_free_nr = 0;
		free(cpd->io_us_free);
		msg_pool_delete(cpd->rsp_pool);
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* raio_handler_on_req				                             */
/*---------------------------------------------------------------------------*/
int raio_handler_on_req(void *prv_session_data, void *prv_portal_data,
			int last_in_batch,
			struct xio_msg *req)
{
	char			*buffer = (char *)req->in.header.iov_base;
	char			*cmd_data;
	struct raio_command	cmd;
	int			disconnect = 0;

	if (!buffer) {
		raio_reject_request(prv_session_data,
				    prv_portal_data,
				    &cmd, NULL,
				    req);
		return 1;
	}

	buffer = (char *)unpack_u32((uint32_t *)&cmd.command,
				    buffer);
	cmd_data = (char *)unpack_u32((uint32_t *)&cmd.data_len,
			      (char *)buffer);

	switch (cmd.command) {
	case RAIO_CMD_IO_SUBMIT:
		raio_handle_submit(prv_session_data,
				   prv_portal_data,
				   &cmd, cmd_data,
				   last_in_batch,
				   req);
		break;
	case RAIO_CMD_OPEN:
		raio_handle_open(prv_session_data,
				 prv_portal_data,
				 &cmd, cmd_data,
				 req);
		break;
	case RAIO_CMD_CLOSE:
		raio_handle_close(prv_session_data,
				  prv_portal_data,
				  &cmd, cmd_data,
				  req);
		break;
	case RAIO_CMD_FSTAT:
		raio_handle_fstat(prv_session_data,
				  prv_portal_data,
				  &cmd, cmd_data,
				  req);
		break;
	case RAIO_CMD_IO_SETUP:
		raio_handle_setup(prv_session_data,
				  prv_portal_data,
				  &cmd, cmd_data,
				  req);
		break;
	case RAIO_CMD_IO_DESTROY:
		raio_handle_destroy(prv_session_data,
				    prv_portal_data,
				    &cmd, cmd_data,
				    req);
		break;
	default:
		/*
		printf("unknown command %d len:%d, sn:%"PRIu64"\n",
		       cmd.command, cmd.data_len, req->sn);
		xio_disconnect(conn);
		*/
		raio_reject_request(prv_session_data,
				    prv_portal_data,
				    &cmd, cmd_data,
				    req);
		break;
	};
	return disconnect;
}

/*---------------------------------------------------------------------------*/
/* raio_handler_on_rsp_comp				                     */
/*---------------------------------------------------------------------------*/
void raio_handler_on_rsp_comp(void *prv_session_data,
			      void *prv_portal_data,
			      struct xio_msg *rsp)
{
	char				*buffer =
				(char *)rsp->out.header.iov_base;
	struct raio_io_portal_data	*pd =
				(struct raio_io_portal_data *)prv_portal_data;
	struct raio_command		cmd;

	unpack_u32(&cmd.command, buffer);

	switch (cmd.command) {
	case RAIO_CMD_IO_SUBMIT:
		raio_handle_submit_comp(prv_session_data,
					prv_portal_data,
					rsp);
		break;
	case RAIO_CMD_IO_DESTROY:
		raio_handle_destroy_comp(prv_session_data,
					 prv_portal_data,
					 rsp);
		msg_pool_put(pd->cmds_rsp_pool, rsp);
		break;
	case RAIO_CMD_CLOSE:
	case RAIO_CMD_UNKNOWN:
	case RAIO_CMD_OPEN:
	case RAIO_CMD_FSTAT:
	case RAIO_CMD_IO_SETUP:
		msg_pool_put(pd->cmds_rsp_pool, rsp);
		break;
	default:
		printf("unknown answer %d\n", cmd.command);
		break;

	};
}

