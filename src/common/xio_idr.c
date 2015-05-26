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
#include <libxio.h>
#include <xio_os.h>
#include "xio_log.h"
#include "xio_common.h"
#include "xio_hash.h"
#include <sys/hashtable.h>
#include "xio_idr.h"
#include <xio_env_adv.h>

struct xio_idr_entry {
	void					*key;
	char					*name;

	HT_ENTRY(xio_idr_entry, xio_key_int64)	idr_ht_entry;
};

struct xio_idr {
	HT_HEAD(, xio_idr_entry, HASHTABLE_PRIME_MEDIUM) cache;
	spinlock_t lock; /* idr lock */
	int	   pad;
};

/*---------------------------------------------------------------------------*/
/* xio_idr_remove_uobj							     */
/*---------------------------------------------------------------------------*/
int xio_idr_remove_uobj(struct xio_idr *idr, void *uobj)
{
	struct xio_idr_entry	*idr_entry = NULL;
	struct xio_key_int64	key;

	if (!idr || !uobj)
		return -1;

	spin_lock(&idr->lock);
	key.id = uint64_from_ptr(uobj);
	HT_LOOKUP(&idr->cache, &key, idr_entry, idr_ht_entry);
	if (!idr_entry) {
		spin_unlock(&idr->lock);
		return -1;
	}

	HT_REMOVE(&idr->cache, idr_entry, xio_idr_entry, idr_ht_entry);
	spin_unlock(&idr->lock);

	kfree(idr_entry->name);
	kfree(idr_entry);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_idr_lookup_uobj							     */
/*---------------------------------------------------------------------------*/
int xio_idr_lookup_uobj(struct xio_idr *idr, void *uobj)
{
	struct xio_idr_entry	*idr_entry = NULL;
	struct xio_key_int64	key;

	if (!idr || !uobj)
		return 0;

	spin_lock(&idr->lock);
	key.id = uint64_from_ptr(uobj);
	HT_LOOKUP(&idr->cache, &key, idr_entry, idr_ht_entry);
	spin_unlock(&idr->lock);

	return idr_entry ? 1 : 0;
}

/*---------------------------------------------------------------------------*/
/* xio_sessions_cache_add			                             */
/*---------------------------------------------------------------------------*/
int xio_idr_add_uobj(struct xio_idr *idr, void *uobj, const char *obj_name)
{
	struct xio_idr_entry	*idr1_entry = NULL, *idr_entry;
	struct xio_key_int64	key;
	int			retval = -1;
	char			*pname = NULL;

	if (!idr || !uobj)
		return -1;

	idr_entry = (struct xio_idr_entry *)
			kcalloc(1, sizeof(*idr_entry), GFP_KERNEL);
	if (!idr_entry)
		return -1;

	pname = kstrdup(obj_name, GFP_KERNEL);

	spin_lock(&idr->lock);
	key.id = uint64_from_ptr(uobj);
	HT_LOOKUP(&idr->cache, &key, idr1_entry, idr_ht_entry);
	if (idr1_entry)
		goto exit;

	idr_entry->key = uobj;
	idr_entry->name = pname;
	HT_INSERT(&idr->cache, &key, idr_entry, idr_ht_entry);
	retval = 0;
exit:
	spin_unlock(&idr->lock);
	if (retval) {
		kfree(pname);
		kfree(idr_entry);
	}
	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_idr_create							     */
/*---------------------------------------------------------------------------*/
struct xio_idr *xio_idr_create(void)
{
	struct xio_idr *idr;

	idr = (struct xio_idr *)kcalloc(1, sizeof(*idr), GFP_KERNEL);
	if (!idr)
		return NULL;

	HT_INIT(&idr->cache, xio_int64_hash, xio_int64_cmp, xio_int64_cp);
	spin_lock_init(&idr->lock);

	return idr;
}

/*---------------------------------------------------------------------------*/
/* xio_idr_destroy							     */
/*---------------------------------------------------------------------------*/
void xio_idr_destroy(struct xio_idr *idr)
{
	struct xio_idr_entry *idr_entry = NULL;

	if (!idr)
		return;

	HT_FOREACH_SAFE(idr_entry, &idr->cache, idr_ht_entry) {
		HT_REMOVE(&idr->cache, idr_entry, xio_idr_entry, idr_ht_entry);
		ERROR_LOG("user object leaked: %p, type:struct %s\n",
			  idr_entry->key, idr_entry->name);
		kfree(idr_entry->name);
		kfree(idr_entry);
	}
	kfree(idr);
}

