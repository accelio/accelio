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

#include "xio_os.h"
#include "libxio.h"
#include "xio_common.h"
#include "xio_observer.h"
#include "xio_transport.h"
#include "xio_log.h"

/*---------------------------------------------------------------------------*/
/* xio_set_opt								     */
/*---------------------------------------------------------------------------*/
static int xio_general_set_opt(void *xio_obj, int optname,
			       const void *optval, int optlen)
{
	switch (optname) {
	case XIO_OPTNAME_LOG_FN:
		if (optlen == 0 && optval == NULL)
			return xio_set_log_fn(NULL);
		else if (optlen == sizeof(xio_log_fn))
			return xio_set_log_fn((xio_log_fn)optval);
		break;
	case XIO_OPTNAME_LOG_LEVEL:
		if (optlen != sizeof(enum xio_log_level))
			return -1;
		return xio_set_log_level(*((enum xio_log_level *)optval));
		break;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_general_get_opt                                                       */
/*---------------------------------------------------------------------------*/
static int xio_general_get_opt(void  *xio_obj, int optname,
			       void *optval, int *optlen)
{
	switch (optname) {
	case XIO_OPTNAME_LOG_LEVEL:
		*((enum xio_log_level *)optval) = xio_get_log_level();
		*optlen = sizeof(enum xio_log_level);
		return 0;
		break;
	default:
		break;
	}
	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_set_opt								     */
/*---------------------------------------------------------------------------*/
int xio_set_opt(void *xio_obj, int level,  int optname,
		const void *optval, int optlen)
{
	static struct xio_transport *rdma_transport = NULL;

	switch (level) {
	case XIO_OPTLEVEL_ACCELIO:
		return xio_general_set_opt(xio_obj, optname, optval, optlen);
	case XIO_OPTLEVEL_RDMA:
		if (!rdma_transport) {
			rdma_transport = xio_get_transport("rdma");
			if (!rdma_transport){
				xio_set_error(EFAULT);
				return -1;
			}
		}
		if (!rdma_transport->set_opt)
			break;
		return rdma_transport->set_opt(xio_obj, optname, optval, optlen);
		break;
	default:
		break;
	}

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

/*---------------------------------------------------------------------------*/
/* xio_get_opt								     */
/*---------------------------------------------------------------------------*/
int xio_get_opt(void *xio_obj, int level,  int optname,
		void *optval, int *optlen)
{
	static struct xio_transport *rdma_transport = NULL;

	switch (level) {
	case XIO_OPTLEVEL_ACCELIO:
		return xio_general_get_opt(xio_obj, optname, optval, optlen);
	case XIO_OPTLEVEL_RDMA:
		if (!rdma_transport) {
			rdma_transport = xio_get_transport("rdma");
			if (!rdma_transport){
				xio_set_error(EFAULT);
				return -1;
			}
		}
		if (!rdma_transport->get_opt)
			break;
		return rdma_transport->get_opt(xio_obj, optname, optval, optlen);
		break;
	default:
		break;
	}

	xio_set_error(XIO_E_NOT_SUPPORTED);
	return -1;
}

