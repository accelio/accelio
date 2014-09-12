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
#include "xio_common.h"
#include "xio_hash.h"
#include <sys/hashtable.h>

struct idr_entry {
	void					*key;
	HT_ENTRY(idr_entry, xio_key_int64)	idr_ht_entry;
};

static HT_HEAD(, idr_entry, HASHTABLE_PRIME_MEDIUM) idr_cache;
static spinlock_t idr_lock;

/*---------------------------------------------------------------------------*/
/* xio_idr_remove_uobj							     */
/*---------------------------------------------------------------------------*/
int xio_idr_remove_uobj(void *uobj)
{
	struct idr_entry	*idr = NULL;
	struct xio_key_int64	key;

	spin_lock(&idr_lock);
	key.id = uint64_from_ptr(uobj);
	HT_LOOKUP(&idr_cache, &key, idr, idr_ht_entry);
	if (idr == NULL) {
		spin_unlock(&idr_lock);
		return -1;
	}

	HT_REMOVE(&idr_cache, idr, xio_idr_entry, idr_ht_entry);
	spin_unlock(&idr_lock);

	kfree(idr);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_idr_lookup_uobj							     */
/*---------------------------------------------------------------------------*/
int xio_idr_lookup_uobj(void *uobj)
{
	struct idr_entry	*idr = NULL;
	struct xio_key_int64	key;

	spin_lock(&idr_lock);
	key.id = uint64_from_ptr(uobj);
	HT_LOOKUP(&idr_cache, &key, idr, idr_ht_entry);
	spin_unlock(&idr_lock);

	return (idr != NULL);
}

/*---------------------------------------------------------------------------*/
/* xio_sessions_cache_add			                             */
/*---------------------------------------------------------------------------*/
int xio_idr_add_uobj(void *uobj)
{
	struct idr_entry	*idr1 = NULL, *idr;
	struct xio_key_int64	key;
	int			retval = -1;

	idr = kcalloc(1, sizeof(*idr), GFP_KERNEL);
	if (idr == NULL)
		return -1;

	spin_lock(&idr_lock);
	key.id = uint64_from_ptr(uobj);
	HT_LOOKUP(&idr_cache, &key, idr1, idr_ht_entry);
	if (idr1 != NULL)
		goto exit;

	idr->key = uobj;
	HT_INSERT(&idr_cache, &key, idr, idr_ht_entry);
	retval = 0;
exit:
	spin_unlock(&idr_lock);
	if (retval)
		kfree(idr);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_idr_create							     */
/*---------------------------------------------------------------------------*/
void xio_idr_create(void)
{
	HT_INIT(&idr_cache, xio_int64_hash, xio_int64_cmp, xio_int64_cp);
	spin_lock_init(&idr_lock);
}

/*---------------------------------------------------------------------------*/
/* xio_idr_destroy							     */
/*---------------------------------------------------------------------------*/
void xio_idr_destroy(void)
{
	struct idr_entry *idr = NULL;

	HT_FOREACH_SAFE(idr, &idr_cache, idr_ht_entry) {
		HT_REMOVE(&idr_cache, idr, idr_entry, idr_ht_entry);
		ERROR_LOG("user object leaked: %p\n", idr->key);
		kfree(idr);
	}
}

