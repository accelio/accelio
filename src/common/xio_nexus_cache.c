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
#include <sys/hashtable.h>
#include "libxio.h"
#include <xio_os.h>
#include "xio_log.h"
#include "xio_common.h"
#include "xio_hash.h"
#include "xio_protocol.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_observer.h"
#include "xio_objpool.h"
#include "xio_workqueue.h"
#include "xio_ev_data.h"
#include "xio_context.h"
#include "xio_transport.h"
#include "xio_transport.h"
#include "xio_nexus.h"
#include "xio_nexus_cache.h"

static HT_HEAD(, xio_nexus, HASHTABLE_PRIME_SMALL)  nexus_cache;
static spinlock_t cs_lock;

/*---------------------------------------------------------------------------*/
/* xio_nexus_cache_add				                             */
/*---------------------------------------------------------------------------*/
static int nexus_cache_add(struct xio_nexus *nexus, int nexus_id)
{
	struct xio_nexus *c;
	struct xio_key_int32  key = {
		.id = nexus_id,
		.pad = {0},
	};

	HT_LOOKUP(&nexus_cache, &key, c, nexus_htbl);
	if (c)
		return -1;

	HT_INSERT(&nexus_cache, &key, nexus, nexus_htbl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_cache_remove				                     */
/*---------------------------------------------------------------------------*/
int xio_nexus_cache_remove(int nexus_id)
{
	struct xio_nexus *c;
	struct xio_key_int32  key;

	spin_lock(&cs_lock);
	key.id = nexus_id;
	HT_LOOKUP(&nexus_cache, &key, c, nexus_htbl);
	if (!c) {
		spin_unlock(&cs_lock);
		return -1;
	}

	HT_REMOVE(&nexus_cache, c, xio_nexus, nexus_htbl);
	spin_unlock(&cs_lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_cache_lookup			                             */
/*---------------------------------------------------------------------------*/
struct xio_nexus *xio_nexus_cache_lookup(int nexus_id)
{
	struct xio_nexus *c;
	struct xio_key_int32  key;

	spin_lock(&cs_lock);
	key.id = nexus_id;
	HT_LOOKUP(&nexus_cache, &key, c, nexus_htbl);
	spin_unlock(&cs_lock);

	return c;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_cache_add				                             */
/*---------------------------------------------------------------------------*/
int xio_nexus_cache_add(struct xio_nexus *nexus,
			int *nexus_id)
{
	static int cid;  /* = 0 global nexus provider */
	int retval;

	spin_lock(&cs_lock);
	retval = nexus_cache_add(nexus, cid);
	if (retval == 0)
		*nexus_id = cid++;
	spin_unlock(&cs_lock);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_nexus_cache_find				                             */
/*---------------------------------------------------------------------------*/
struct xio_nexus *xio_nexus_cache_find(struct xio_nexus_query_params *query)
{
	struct xio_nexus *nexus;
	int		  tos_enabled;

	spin_lock(&cs_lock);
	HT_FOREACH(nexus, &nexus_cache, nexus_htbl) {
		if (nexus->transport_hndl->portal_uri) {
			if ((strcmp(nexus->transport_hndl->portal_uri,
				    query->portal_uri) != 0) ||
			    (nexus->transport_hndl->ctx != query->ctx))
				continue;

			tos_enabled = test_bits(XIO_NEXUS_ATTR_TOS,
						&nexus->trans_attr_mask);
			if (tos_enabled != query->tos_enabled)
				continue;
			if (tos_enabled && nexus->trans_attr.tos != query->tos)
				continue;

			/* match found */
			xio_nexus_addref(nexus);

			TRACE_LOG("nexus: [addref] nexus:%p, refcnt:%d\n", nexus,
				  atomic_read(&nexus->kref.refcount));
			goto done;
		}
	}
	nexus = NULL;

done:
	spin_unlock(&cs_lock);
	return nexus;
}

/*---------------------------------------------------------------------------*/
/* nexus_cache_construct				                     */
/*---------------------------------------------------------------------------*/
void nexus_cache_construct(void)
{
	HT_INIT(&nexus_cache, xio_int32_hash, xio_int32_cmp, xio_int32_cp);
	spin_lock_init(&cs_lock);
}

/*
void nexus_cache_destruct(void)
{
}
*/

