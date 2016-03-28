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
/*
 * libraio engine
 *
 * IO engine using the Linux native aio interface.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <libraio.h>

#include "fio.h"

#ifdef VISIBILITY
#define __RAIO_PUBLIC __attribute__((visibility("default")))
#else
#define __RAIO_PUBLIC
#endif

#define TRANSPORT_NAME "rdma"

struct libraio_engine_data;

struct libraio_data {
	raio_context_t raio_ctx;
	struct raio_event *raio_events;
	struct raio_iocb **iocbs;
	struct io_u **io_us;
	struct libraio_engine_data *engine_datas;
	int iocbs_nr;
	int engine_datas_free;
	int fd;
	int force_close;
};

struct libraio_engine_data {
	struct raio_iocb	iocb;
	struct libraio_data	*raio_data;
	raio_mr_t		mr;
};

static int fio_libraio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file			*f = io_u->file;
	struct libraio_engine_data	*engine_data;

	engine_data = io_u->engine_data;

	if (io_u->ddir == DDIR_READ)
		raio_prep_pread(&engine_data->iocb,
				f->fd,
				io_u->xfer_buf,
				io_u->xfer_buflen,
				io_u->offset,
				engine_data->mr);
	else if (io_u->ddir == DDIR_WRITE)
		raio_prep_pwrite(&engine_data->iocb,
				 f->fd,
				 io_u->xfer_buf,
				 io_u->xfer_buflen,
				 io_u->offset,
				 engine_data->mr);

	engine_data->iocb.data = io_u;

	return 0;
}

static struct io_u *fio_libraio_event(struct thread_data *td, int event)
{
	struct libraio_data *ld = td->io_ops->data;
	struct raio_event *ev;
	struct io_u *io_u;

	ev = ld->raio_events + event;
	io_u = ev->data;

	if (ev->res != io_u->xfer_buflen) {
		if (ev->res > io_u->xfer_buflen)
			io_u->error = -ev->res;
		else
			io_u->resid = io_u->xfer_buflen - ev->res;
	} else {
		io_u->error = 0;
	}

	return io_u;
}

static int fio_libraio_getevents(struct thread_data *td, unsigned int min,
				 unsigned int max, const struct timespec *t)
{
	struct libraio_data *ld = td->io_ops->data;
	unsigned actual_min = td->o.iodepth_batch_complete == 0 ? 0 : min;
	int r, events = 0;

	do {
		r = raio_getevents(ld->raio_ctx, actual_min,
				   max, ld->raio_events + events,
				   (struct timespec *)t);
		if (r >= 0) {
			raio_release(ld->raio_ctx, r,
				     ld->raio_events + events);
			events += r;
		} else  {
			log_err("raio_getevents failed. %s\n", strerror(-r));
			return -1;
		}
	} while (events < min);

	return r < 0 ? r : events;
}

static int fio_libraio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct libraio_data *ld = td->io_ops->data;
	struct libraio_engine_data *engine_data = io_u->engine_data;

	fio_ro_check(td, io_u);

	if (ld->iocbs_nr == (int) td->o.iodepth)
		return FIO_Q_BUSY;

	ld->iocbs[ld->iocbs_nr] = &engine_data->iocb;
	ld->io_us[ld->iocbs_nr] = io_u;
	ld->iocbs_nr++;

	return FIO_Q_QUEUED;
}

static void fio_libraio_queued(struct thread_data *td, struct io_u **io_us,
			       unsigned int nr)
{
	struct timeval now;
	unsigned int i;

	if (!fio_fill_issue_time(td))
		return;

	fio_gettime(&now, NULL);

	for (i = 0; i < nr; i++) {
		struct io_u *io_u = io_us[i];

		memcpy(&io_u->issue_time, &now, sizeof(now));
		io_u_queued(td, io_u);
	}
}

static int fio_libraio_commit(struct thread_data *td)
{
	struct libraio_data	*ld = td->io_ops->data;
	struct raio_iocb	**iocbs;
	struct io_u		**io_us;
	int			ret;

	if (!ld->iocbs_nr)
		return 0;

	io_us = ld->io_us;
	iocbs = ld->iocbs;
	do {
		ret = raio_submit(ld->raio_ctx, ld->iocbs_nr, iocbs);
		if (ret > 0) {
			fio_libraio_queued(td, io_us, ret);
			io_u_mark_submit(td, ret);
			ld->iocbs_nr -= ret;
			io_us += ret;
			iocbs += ret;
			ret = 0;
		} else if (!ret || ret == -EAGAIN || ret == -EINTR) {
			if (!ret)
				io_u_mark_submit(td, ret);
			continue;
		} else {
			break;
		}
	} while (ld->iocbs_nr);

	return ret;
}

static int fio_libraio_cancel(struct thread_data *td, struct io_u *io_u)
{
	struct libraio_data *ld = td->io_ops->data;
	struct libraio_engine_data *engine_data = io_u->engine_data;

	return raio_cancel(ld->raio_ctx, &engine_data->iocb, ld->raio_events);
}




/* parse uri scheme of [host]:[port][path]
 */
static int parse_file_name(const char *uri, char *path,
			   char *host, unsigned int *port)
{
	char *sep, *sep1, *urip;

	urip = strdup(uri);
	*port = 0;

	/* first letter must be '/' */
	if (!urip || (*urip != '/'))
		goto bad_host;

	sep1 = urip + 1;

	/* find next '/' */
	sep = strchr(sep1, '/');
	if (!sep)
		goto bad_host;

	*sep = '\0';
	strcpy(host, sep1);

	sep1 = sep + 1;

	/* find next '/' */
	sep = strchr(sep1, '/');
	if (sep == NULL)
		goto bad_host;

	*sep = '\0';

	*port = strtol(sep1, NULL, 10);
	if (*port == 0 || *port > 65535)
		goto bad_host;

	*sep = '/';

	strcpy(path, sep);
	if (!strlen(path))
		goto bad_host;

	free(urip);

	return 0;

bad_host:
	free(urip);
	log_err("fio: bad rdma \"/host/port/path\" %s\n", uri);
	return 1;
}


static int raio_open_flags(struct thread_data *td, struct fio_file *f, int *_flags)
{
	int flags = 0;

	*_flags = -1;

	if (td_trim(td) && f->filetype != FIO_TYPE_BD) {
		log_err("libraio: trim only applies to block device\n");
		return 1;
	}

	if (!strcmp(f->file_name, "-")) {
		if (td_rw(td)) {
			log_err("libraio: can't read/write to stdin/out\n");
			return 1;
		}

		/*
		 * move output logging to stderr, if we are writing to stdout
		 */
		if (td_write(td))
			f_out = stderr;
	}

	if (td_trim(td))
		goto skip_flags;
	if (td->o.odirect)
		flags |= OS_O_DIRECT;
	if (td->o.oatomic) {
		if (!FIO_O_ATOMIC) {
			td_verror(td, EINVAL, "OS does not support atomic IO");
			return 1;
		}
		flags |= OS_O_DIRECT | FIO_O_ATOMIC;
	}
	if (td->o.sync_io)
		flags |= O_SYNC;
	if (td->o.create_on_open)
		flags |= O_CREAT;
skip_flags:
	if (f->filetype != FIO_TYPE_FILE)
		flags |= FIO_O_NOATIME;

	if (td_write(td)) {
		if (!read_only)
			flags |= O_RDWR;

		if (f->filetype == FIO_TYPE_FILE)
			flags |= O_CREAT;

	} else if (td_read(td)) {
		if (f->filetype == FIO_TYPE_CHAR && !read_only)
			flags |= O_RDWR;
		else
			flags |= O_RDONLY;

	} else { //td trim
		flags |= O_RDWR;
	}

	*_flags = flags;

	return 0;
}

static int fio_libraio_open(struct thread_data *td, struct fio_file *f)
{
	int			ret = 0;
	int			flags = 0;
	struct sockaddr_in	servaddr;
	char			path[256];
	char			host[256];
	uint32_t		port;
	struct libraio_data	*ld = td->io_ops->data;

	dprint(FD_FILE, "fd open %s\n", f->file_name);

	/*
	if (td_read(td)) {
		flags |= O_RDONLY|O_LARGEFILE|O_NONBLOCK|O_ASYNC;
	} else if (td_write(td)) {
		flags |= O_WRONLY|O_LARGEFILE|O_CREAT|O_TRUNC;
	} else {
		log_err("libraio: unknown file mode\n");
		return 1;
	}
	if (td->o.odirect)
		flags |= O_DIRECT;
	*/

	if (raio_open_flags(td,f, &flags)) {
		log_err("libraio:  file flags for open failed %s\n",
			f->file_name);
		return 1;
	}

	ret = parse_file_name(f->file_name, path, host, &port);
	if (ret != 0) {
		log_err("libraio:  file name parsing failed. %s\n",
			f->file_name);
		return 1;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(host);
	servaddr.sin_port = htons(port);

	f->fd = raio_start(TRANSPORT_NAME, (struct sockaddr *)&servaddr,
			sizeof(servaddr));
	if (f->fd == -1) {
		fprintf(stderr, "raio_start failed %s://%s:%d %m\n",
			TRANSPORT_NAME, host, port);
		return -1;
	}

	ret = raio_setup(f->fd, td->o.iodepth, &ld->raio_ctx);
	if (ret == -1) {
		fprintf(stderr, "raio_setup failed - fd:%d %m\n", f->fd);
		goto stop;
	}

	ret = raio_open(f->fd, path, flags);

	if (f->fd == -1 && errno == EINVAL &&
	    ((flags & O_DIRECT) == O_DIRECT)) {
		log_err("libraio open failed with o_direct- file:%s " \
			"flags:%x %m\n", f->file_name, flags);
		flags &= ~O_DIRECT;
		f->fd = raio_open(f->fd, path, flags);
	}
	if (f->fd == -1) {
		log_err("libraio open failed - file:%s " \
			"flags:%x %m\n", f->file_name, flags);
		ret = 1;
		goto stop;
	}

	return 0;

stop:
	raio_stop(f->fd);
	return ret;
}

/*
 * Hook for opening the given file. Unless the engine has special
 * needs, it usually just provides generic_file_open() as the handler.
 */
static int fio_libraio_open_file(struct thread_data *td, struct fio_file *f)
{
	int			ret;
	struct libraio_data	*ld = td->io_ops->data;

	if (ld->fd != -1) {
		f->fd = ld->fd;
		return 0;
	}

	ret = fio_libraio_open(td, f);
	if (ret != 0) {
		log_err("libraio:  open file failed. %s\n", f->file_name);
		return ret;
	}

	ld->fd = f->fd;

	return 0;
}

static int fio_libraio_close(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;

	dprint(FD_FILE, "fd close %s\n", f->file_name);

	if (raio_close(f->fd) < 0)
		ret = errno;

	raio_stop(f->fd);
	f->fd = -1;

	return ret;
}

/*
 * Hook for closing a file. See fio_libraio_open().
 */
static int fio_libraio_close_file(struct thread_data *td, struct fio_file *f)
{
	int			ret;
	struct libraio_data	*ld = td->io_ops->data;

	/* don't close the file until cleanup */
	if (ld->force_close == 0) {
		if (f->fd != -1)
			f->fd = -1;
		return 0;
	}

	ret = raio_destroy(ld->raio_ctx);
	if (ret) {
		log_err("libraio: raio_destroy failed. %m\n");
		return 1;
	}

	ret = fio_libraio_close(td, f);
	if (ret != 0) {
		log_err("libraio:  close file failed. %s\n", f->file_name);
		return ret;
	}
	ld->fd = -1;
	ld->force_close = 0;

	return ret;
}

static int fio_libraio_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct stat64		stbuf;
	struct libraio_data	dummy_ld;
	int			ret;

	if (td_write(td)) {
		f->real_file_size = -1;
		return 0;
	}

	td->io_ops->data = &dummy_ld;

	ret = fio_libraio_open(td, f);
	if (ret != 0) {
		log_err("libraio:  open file failed. %s\n", f->file_name);
		return ret;
	}
	/* get the file size */
	ret = raio_fstat(f->fd, &stbuf);
	if (ret == -1) {
		log_err("libraio:  raio_fstat failed - filename:%s %m\n",
			f->file_name);
		goto close_file;
	}
	f->real_file_size = stbuf.st_size;
	fio_file_set_size_known(f);

close_file:
	ret = fio_libraio_close(td, f);
	if (ret != 0) {
		log_err("libraio:  open file failed. %s\n", f->file_name);
		return ret;
	}

	return  0;
}

static int fio_libraio_init(struct thread_data *td)
{
	struct io_u			*io_u;
	struct libraio_data		*ld = malloc(sizeof(*ld));
	unsigned int			max_bs;
	int				ret;
	struct				fio_file f;
	struct libraio_engine_data	*engine_data;

	memset(ld, 0, sizeof(*ld));

	ld->raio_events = malloc(
			td->o.iodepth * sizeof(struct raio_event));
	memset(ld->raio_events, 0,
	       td->o.iodepth * sizeof(struct raio_event));

	ld->iocbs = malloc(td->o.iodepth * sizeof(struct raio_iocb *));
	memset(ld->iocbs, 0,
	       td->o.iodepth * sizeof(struct raio_iocb *));
	ld->io_us = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(ld->io_us, 0,
	       td->o.iodepth * sizeof(struct io_u *));
	ld->engine_datas = malloc(
		td->o.iodepth * sizeof(struct libraio_engine_data));
	memset(ld->engine_datas , 0,
	       td->o.iodepth * sizeof(struct libraio_engine_data));
	ld->engine_datas_free = 0;

	ld->iocbs_nr = 0;
	ld->fd = -1;

	td->io_ops->data = ld;

	f.file_name = td->o.filename;
	ret = fio_libraio_open_file(td, &f);
	if (ret != 0)
		return ret;

	max_bs = max(td->o.max_bs[DDIR_READ], td->o.max_bs[DDIR_WRITE]);
	io_u_qiter(&td->io_u_freelist, io_u, ld->engine_datas_free) {
		io_u->engine_data = &ld->engine_datas[ld->engine_datas_free];

		engine_data = io_u->engine_data;
		raio_reg_mr(ld->raio_ctx,
			    io_u->buf,
			    max_bs,
			    &engine_data->mr);
		if (engine_data->mr == NULL) {
			log_err("libraio: memory registration failed\n");
			return 1;
		}
	}

	return 0;
}

static void fio_libraio_cleanup(struct thread_data *td)
{
	struct libraio_data		*ld = td->io_ops->data;
	struct libraio_engine_data	*engine_data;
	struct io_u			*io_u;
	int				i;

	io_u_qiter(&td->io_u_freelist, io_u, i) {
		engine_data = io_u->engine_data;
		raio_dereg_mr(ld->raio_ctx, engine_data->mr);
	}

	if (ld->fd != -1) {
		struct fio_file f;
		f.fd = ld->fd;
		ld->force_close = 1;
		fio_libraio_close_file(td, &f);
	}
	if (ld) {
		free(ld->raio_events);
		free(ld->iocbs);
		free(ld->io_us);
		free(ld->engine_datas);
		free(ld);
		td->io_ops->data = NULL;
	}
}


/*
 * Note that the structure is exported, so that fio can get it via
 * dlsym(..., "ioengine");
 */
__RAIO_PUBLIC struct ioengine_ops ioengine = {
	.name			= "libraio",
	.version		= FIO_IOOPS_VERSION,
	.init			= fio_libraio_init,
	.prep			= fio_libraio_prep,
	.queue			= fio_libraio_queue,
	.commit			= fio_libraio_commit,
	.cancel			= fio_libraio_cancel,
	.getevents		= fio_libraio_getevents,
	.event			= fio_libraio_event,
	.cleanup		= fio_libraio_cleanup,
	.open_file		= fio_libraio_open_file,
	.close_file		= fio_libraio_close_file,
	.get_file_size		= fio_libraio_get_file_size,
	.flags			= FIO_DISKLESSIO | FIO_UNIDIR /*| FIO_PIPEIO*/,
};

