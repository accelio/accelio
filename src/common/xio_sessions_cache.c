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
#include <sys/hashtable.h>
#include "libxio.h"
#include "xio_log.h"
#include "xio_common.h"
#include "xio_hash.h"
#include "xio_observer.h"
#include "xio_transport.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_workqueue.h"
#include "xio_session.h"
#include "xio_sessions_cache.h"

static HT_HEAD(, xio_session, HASHTABLE_PRIME_SMALL)  sessions_cache;
static spinlock_t ss_lock;

/*---------------------------------------------------------------------------*/
/* sessions_cache_add							     */
/*---------------------------------------------------------------------------*/
static int sessions_cache_add(struct xio_session *session,
			      uint32_t session_id)
{
	struct xio_session *s;
	struct xio_key_int32  key = {
		.id = session_id,
		.pad = {0},
	};
	HT_LOOKUP(&sessions_cache, &key, s, sessions_htbl);
	if (s)
		return -1;

	HT_INSERT(&sessions_cache, &key, session, sessions_htbl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_sessions_cache_remove				                     */
/*---------------------------------------------------------------------------*/
int xio_sessions_cache_remove(uint32_t session_id)
{
	struct xio_session *s;
	struct xio_key_int32  key;

	spin_lock(&ss_lock);
	key.id = session_id;
	HT_LOOKUP(&sessions_cache, &key, s, sessions_htbl);
	if (!s) {
		spin_unlock(&ss_lock);
		return -1;
	}

	HT_REMOVE(&sessions_cache, s, xio_session, sessions_htbl);
	spin_unlock(&ss_lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_sessions_cache_lookup						     */
/*---------------------------------------------------------------------------*/
struct xio_session *xio_sessions_cache_lookup(uint32_t session_id)
{
	struct xio_session *s;
	struct xio_key_int32  key;

	spin_lock(&ss_lock);
	key.id = session_id;
	HT_LOOKUP(&sessions_cache, &key, s, sessions_htbl);
	spin_unlock(&ss_lock);

	return s;
}

/*---------------------------------------------------------------------------*/
/* xio_sessions_cache_add			                             */
/*---------------------------------------------------------------------------*/
int xio_sessions_cache_add(struct xio_session *session,
			   uint32_t *session_id)
{
	static uint32_t sid;  /* = 0 global session provider */
	int retval;

	spin_lock(&ss_lock);
	retval = sessions_cache_add(session, sid);
	if (retval == 0)
		*session_id = sid++;
	spin_unlock(&ss_lock);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* sessions_cache_construct				                     */
/*---------------------------------------------------------------------------*/
void sessions_cache_construct(void)
{
	HT_INIT(&sessions_cache, xio_int32_hash, xio_int32_cmp, xio_int32_cp);
	spin_lock_init(&ss_lock);
}

/*
void sessions_cache_destruct(void)
{
}
*/
