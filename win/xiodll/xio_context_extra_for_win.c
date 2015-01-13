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
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*---------------------------------------------------------------------------*/
/* ****** this section is devoted for not yet supported in Windows ********* */
/*---------------------------------------------------------------------------*/

struct xio_context;
struct xio_workqueue;
struct xio_work_struct;
struct xio_delayed_work_struct;

struct xio_workqueue * xio_workqueue_create(struct xio_context *) {
	/* not yet supported in Windows */
	return 0;
}

int xio_workqueue_destroy(struct xio_workqueue *) {
	/* not yet supported in Windows */
	return 0;
}

int xio_workqueue_add_delayed_work(struct xio_workqueue *, int, void *, void(*)(void *), struct xio_delayed_work_struct *) {
	/* not yet supported in Windows */
	return 0;
}


int xio_workqueue_del_delayed_work(struct xio_workqueue *, struct xio_delayed_work_struct *) {
	/* not yet supported in Windows */
	return 0;
}


int xio_workqueue_add_work(struct xio_workqueue *, void *, void(__cdecl*)(void *), struct xio_work_struct *) {
	/* not yet supported in Windows */
	return 0;
}


int xio_workqueue_del_work(struct xio_workqueue *, struct xio_work_struct *) {
	/* not yet supported in Windows */
	return 0;
}


int  xio_netlink(struct xio_context *ctx) {
	/* not supported in Windows*/
	return 0;
}
