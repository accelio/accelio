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
#ifndef XIO_CONTEXT_PRIV_H_
#define XIO_CONTEXT_PRIV_H_

/*
 * Suspend the current handler run.
 * Note: Not protected against a race. Another thread may reactivate the event.
 */
/*---------------------------------------------------------------------------*/
/* xio_context_disable_event	                                             */
/*---------------------------------------------------------------------------*/
static inline void xio_context_disable_event(struct xio_ev_data *data)
{
	clear_bit(XIO_EV_HANDLER_ENABLED, &data->states);
}

/*
 * Check if the event is pending.
 * Return true if the event is pending in any list.
 * Return false once the event is removed from the list in order to be executed.
 * (When inside the event handler, the event is no longer pending)
 * Note: Not protected against a race. Another thread may reactivate the event.
 */
/*---------------------------------------------------------------------------*/
/* xio_context_is_pending_event	                                             */
/*---------------------------------------------------------------------------*/
static inline int xio_context_is_pending_event(struct xio_ev_data *data)
{
	return test_bit(XIO_EV_HANDLER_PENDING, &data->states);
}

/*
 * should be called only from context_shutdown event context
 */
/*---------------------------------------------------------------------------*/
/* xio_context_destroy_wait	                                             */
/*---------------------------------------------------------------------------*/
static inline void xio_context_destroy_wait(struct xio_context *ctx)
{
	ctx->run_private++;
}

/*
 * should be called only from loop context
 */
/*---------------------------------------------------------------------------*/
/* xio_context_destroy_resume	                                             */
/*---------------------------------------------------------------------------*/
static inline void xio_context_destroy_resume(struct xio_context *ctx)
{
	if (ctx->run_private) {
		if (!--ctx->run_private)
			xio_context_stop_loop(ctx);
	}
}

struct xio_mempool *xio_mempool_get(struct xio_context *ctx);

#endif /* XIO_CONTEXT_PRIV_H_ */
