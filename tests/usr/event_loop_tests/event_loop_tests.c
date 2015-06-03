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
//#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "libxio.h"
//#include "xio_test_utils.h"

#define XIO_DEF_CPU		0

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	int rc;
	struct xio_context	*xio_context;
	xio_init();

	xio_context = xio_context_create(NULL, 0, XIO_DEF_CPU);
	if (xio_context == NULL) {
/*
		int error = xio_errno();
		fprintf(stderr, "context creation failed. reason %d - (%s)\n",
			error, xio_strerror(error));
		xio_assert(xio_context != NULL);
//*/
		fprintf(stderr, "context creation failed.\n");
		return 1; //temp
	}
//	fprintf(stdout, "sizeof(int)=%d, sizeof(SOCKET)=%d \n", (int)sizeof(int), (int)sizeof(SOCKET));
	fprintf(stdout, "running xio loop...\n");
	//	xio_context_run_loop(xio_context, XIO_INFINITE);
	rc = xio_context_run_loop(xio_context, 5 * 1000);
	if (rc != 0) {
		/*
		int error = xio_errno();
		fprintf(stderr, "context creation failed. reason %d - (%s)\n",
		error, xio_strerror(error));
		xio_assert(xio_context != NULL);
		//*/
		fprintf(stderr, "xio_context_run_loop failed.\n");
		return 1; //temp
	}

	/* normal exit phase */
	fprintf(stdout, "exit signaled\n");
	xio_context_destroy(xio_context);
	xio_shutdown();
	return 0;
}
