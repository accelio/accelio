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
#ifndef RAIO_HANDLERS_H
#define RAIO_HANDLERS_H

struct raio_command;

/*---------------------------------------------------------------------------*/
/* raio_handler_init_session_data				             */
/*---------------------------------------------------------------------------*/
void	*raio_handler_init_session_data(int portals_nr);

/*---------------------------------------------------------------------------*/
/* raio_handler_init_portal_data				             */
/*---------------------------------------------------------------------------*/
void	*raio_handler_init_portal_data(void *prv_session_data,
				       int portal_nr, void *loop);

/*---------------------------------------------------------------------------*/
/* raio_handler_get_portal_data						     */
/*---------------------------------------------------------------------------*/
void *raio_handler_get_portal_data(void *prv_session_data, int portal_nr);

/*---------------------------------------------------------------------------*/
/* raio_handler_free_session_data				             */
/*---------------------------------------------------------------------------*/
void	raio_handler_free_session_data(void *prv_session_data);

/*---------------------------------------------------------------------------*/
/* raio_handler_free_portal_data				             */
/*---------------------------------------------------------------------------*/
void	raio_handler_free_portal_data(void *prv_portal_data);

/*---------------------------------------------------------------------------*/
/* rai_handler_on_req				                             */
/*---------------------------------------------------------------------------*/
int	raio_handler_on_req(void *prv_session_data,
			    void *prv_portal_data,
			    int last_in_batch,
			    struct xio_msg *req);

/*---------------------------------------------------------------------------*/
/* raio_handler_on_rsp_comp				                     */
/*---------------------------------------------------------------------------*/
void	raio_handler_on_rsp_comp(void *prv_session_data,
				 void *prv_portal_data,
				 struct xio_msg *rsp);

/*---------------------------------------------------------------------------*/
/* rai_handler_bs_poll				                             */
/*---------------------------------------------------------------------------*/
void	raio_handler_bs_poll(void *prv_session_data,
			    void *prv_portal_data);
#endif
