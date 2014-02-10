/*
 * Copyright (c) 2004, 2005 Intel Corporation.  All rights reserved.
 * Copyright (c) 2004 Topspin Corporation.  All rights reserved.
 * Copyright (c) 2004 Voltaire Corporation.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#if !defined(IB_CM_H)
#define IB_CM_H

enum ib_cm_rej_reason {
	IB_CM_REJ_NO_QP				= 1,
	IB_CM_REJ_NO_EEC			= 2,
	IB_CM_REJ_NO_RESOURCES			= 3,
	IB_CM_REJ_TIMEOUT			= 4,
	IB_CM_REJ_UNSUPPORTED			= 5,
	IB_CM_REJ_INVALID_COMM_ID		= 6,
	IB_CM_REJ_INVALID_COMM_INSTANCE		= 7,
	IB_CM_REJ_INVALID_SERVICE_ID		= 8,
	IB_CM_REJ_INVALID_TRANSPORT_TYPE	= 9,
	IB_CM_REJ_STALE_CONN			= 10,
	IB_CM_REJ_RDC_NOT_EXIST			= 11,
	IB_CM_REJ_INVALID_GID			= 12,
	IB_CM_REJ_INVALID_LID			= 13,
	IB_CM_REJ_INVALID_SL			= 14,
	IB_CM_REJ_INVALID_TRAFFIC_CLASS		= 15,
	IB_CM_REJ_INVALID_HOP_LIMIT		= 16,
	IB_CM_REJ_INVALID_PACKET_RATE		= 17,
	IB_CM_REJ_INVALID_ALT_GID		= 18,
	IB_CM_REJ_INVALID_ALT_LID		= 19,
	IB_CM_REJ_INVALID_ALT_SL		= 20,
	IB_CM_REJ_INVALID_ALT_TRAFFIC_CLASS	= 21,
	IB_CM_REJ_INVALID_ALT_HOP_LIMIT		= 22,
	IB_CM_REJ_INVALID_ALT_PACKET_RATE	= 23,
	IB_CM_REJ_PORT_CM_REDIRECT		= 24,
	IB_CM_REJ_PORT_REDIRECT			= 25,
	IB_CM_REJ_INVALID_MTU			= 26,
	IB_CM_REJ_INSUFFICIENT_RESP_RESOURCES	= 27,
	IB_CM_REJ_CONSUMER_DEFINED		= 28,
	IB_CM_REJ_INVALID_RNR_RETRY		= 29,
	IB_CM_REJ_DUPLICATE_LOCAL_COMM_ID	= 30,
	IB_CM_REJ_INVALID_CLASS_VERSION		= 31,
	IB_CM_REJ_INVALID_FLOW_LABEL		= 32,
	IB_CM_REJ_INVALID_ALT_FLOW_LABEL	= 33
};

#endif /* IB_CM_H */
