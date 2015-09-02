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
#include <xio_os.h>
#include "libxio.h"
#include "xio_common.h"

/*---------------------------------------------------------------------------*/
/* xio_gen_status_str					                     */
/*---------------------------------------------------------------------------*/
static const char *xio_gen_status_str(enum xio_status ev)
{
	switch (ev) {
	case XIO_E_NOT_SUPPORTED:
		return "Not supported";
	case XIO_E_NO_BUFS:
		return "No buffer space available";
	case XIO_E_CONNECT_ERROR:
		return "Connect error";
	case XIO_E_ROUTE_ERROR:
		return "Route error";
	case XIO_E_ADDR_ERROR:
		return "Address error";
	case XIO_E_UNREACHABLE:
		return "No route to host";
	case XIO_E_PARTIAL_MSG:
		return "Partial message";
	case XIO_E_MSG_SIZE:
		return "Message too long";
	case XIO_E_MSG_INVALID:
		return "Message is invalid";
	case XIO_E_MSG_UNKNOWN:
		return "Message unknown";
	case XIO_E_SESSION_REFUSED:
		return "Session refused";
	case XIO_E_SESSION_ABORTED:
		return "Session aborted";
	case XIO_E_SESSION_DISCONNECTED:
		return "Session disconnected";
	case XIO_E_SESSION_REJECTED:
		return "Session rejected";
	case XIO_E_SESSION_REDIRECTED:
		return "Session redirected";
	case XIO_E_SESSION_CLOSED:
		return "Session closed";
	case XIO_E_BIND_FAILED:
		return  "Bind failed";
	case XIO_E_TIMEOUT:
		return  "Timeout";
	case XIO_E_IN_PORGRESS:
		return  "Operation now in progress";
	case XIO_E_INVALID_VERSION:
		return  "Invalid version";
	case XIO_E_NOT_SESSION:
		return  "Not a session";
	case XIO_E_OPEN_FAILED:
		return  "Open failed";
	case XIO_E_READ_FAILED:
		return  "Read failed";
	case XIO_E_WRITE_FAILED:
		return  "Write failed";
	case XIO_E_CLOSE_FAILED:
		return "Close failed";
	case XIO_E_UNSUCCESSFUL:
		return "Operation unsuccessful";
	case XIO_E_MSG_CANCELED:
		return "Message canceled";
	case XIO_E_MSG_CANCEL_FAILED:
		return "Message cancel failed";
	case XIO_E_MSG_NOT_FOUND:
		return "Message not found";
	case XIO_E_MSG_FLUSHED:
		return "Message flushed";
	case XIO_E_MSG_DISCARDED:
		return "Message discarded";
	case XIO_E_STATE:
		return "Operation not permitted in current state";
	case XIO_E_NO_USER_BUFS:
		return "User buffers not available";
	case XIO_E_NO_USER_MR:
		return "User mr not available";
	case XIO_E_USER_BUF_OVERFLOW:
		return "Local user buffers overflow";
	case XIO_E_REM_USER_BUF_OVERFLOW:
		return "Remote user buffers overflow";
	case XIO_E_TX_QUEUE_OVERFLOW:
		return "Send queue overflow";
	case XIO_E_USER_OBJ_NOT_FOUND:
		return "User object not found";
	case XIO_E_PEER_QUEUE_SIZE_MISMATCH:
		return "Peer receive queue is smaller then message size";
	case XIO_E_RSP_BUF_SIZE_MISMATCH:
		return "Response buffer is smaller then actual response";
	default:
		return "Unknown error";
	};
}

/*---------------------------------------------------------------------------*/
/* xio_strerror								     */
/*---------------------------------------------------------------------------*/
const char *xio_strerror(int errnum)
{
	if (errnum < XIO_BASE_STATUS)
		return strerror(errnum);

	if (errnum >= XIO_E_NOT_SUPPORTED && errnum < XIO_E_LAST_STATUS)
		return xio_gen_status_str((enum xio_status)errnum);

	return "Unknown error";
}
EXPORT_SYMBOL(xio_strerror);
