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
#ifndef MSG_POOL_H
#define MSG_POOL_H


#include <libxio.h>

#ifdef __cplusplus
extern "C" {
#endif



/**
 * msg_pool_create - creates pool for xio messages
 *
 * @msg_size:	pointer to event loop
 * @num_of_msgs: the added file descrptor
 *
 * RETURNS: pointer to the new created pool
 */
struct msg_pool *msg_pool_create(size_t hdr_size, size_t data_size,
				 int num_of_msgs);

/**
 * msg_pool_delete - deletes pool of xio messages
 *
 * @pool: pointer to the pool
 *
 * RETURNS: void
 */
void msg_pool_delete(struct msg_pool *pool);

/**
 * msg_pool_get - gets one message from pool
 *
 * @pool: pointer to the pool
 *
 * RETURNS: xio message
 */
struct xio_msg *msg_pool_get(struct msg_pool *pool);

/**
 * msg_pool_put - puts one message from pool
 *
 * @pool: pointer to the pool
 * @msg: pointer to xio's message
 *
 * RETURNS: void
 */
void msg_pool_put(struct msg_pool *pool, struct xio_msg *msg);

/**
 * msg_pool_get_array - gets array of messages from pool
 *
 * @pool: pointer to the pool
 * @vec: array of pointer to messages
 * @veclen: the array length
 *
 * RETURNS: number of messages filled in the array.
 */
int msg_pool_get_array(struct msg_pool *pool, struct xio_msg **vec,
		       int veclen);


/**
 * msg_pool_put_array - puts array of messages back to pool
 *
 * @pool: pointer to the pool
 * @vec: array of pointer to messages
 * @veclen: the array length
 *
 * RETURNS: void
 */
void msg_pool_put_array(struct msg_pool *pool, struct xio_msg **vec,
			int veclen);

void  msg_reset(struct xio_msg *msg);

#ifdef __cplusplus
}
#endif


#endif /* MSG_POOL_H */

