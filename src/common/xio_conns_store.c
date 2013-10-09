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
#include "xio_hash.h"
#include "xio_task.h"
#include "xio_conn.h"
#include "xio_conns_store.h"


static HT_HEAD(, xio_conn, 257)  conns_store;
static spinlock_t cs_lock;

/*---------------------------------------------------------------------------*/
/* xio_conns_store_add				                             */
/*---------------------------------------------------------------------------*/
static int conns_store_add(struct xio_conn *conn,
			      int conn_id)
{
	struct xio_conn *c;
	struct xio_key_int32  key = {
		conn_id
	};

	HT_LOOKUP(&conns_store, &key, c, conns_htbl);
	if (c != NULL)
		return -1;

	HT_INSERT(&conns_store, &key, conn, conns_htbl);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conns_store_remove				                     */
/*---------------------------------------------------------------------------*/
int xio_conns_store_remove(int conn_id)
{
	struct xio_conn *c;
	struct xio_key_int32  key;

	spin_lock(&cs_lock);
	key.id = conn_id;
	HT_LOOKUP(&conns_store, &key, c, conns_htbl);
	if (c == NULL) {
		spin_unlock(&cs_lock);
		return -1;
	}

	HT_REMOVE(&conns_store, c, xio_conn, conns_htbl);
	spin_unlock(&cs_lock);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xio_conns_store_lookup			                             */
/*---------------------------------------------------------------------------*/
struct xio_conn *xio_conns_store_lookup(int conn_id)
{
	struct xio_conn *c;
	struct xio_key_int32  key;

	spin_lock(&cs_lock);
	key.id = conn_id;
	HT_LOOKUP(&conns_store, &key, c, conns_htbl);
	spin_unlock(&cs_lock);

	return c;
}

/*---------------------------------------------------------------------------*/
/* xio_conns_store_add				                             */
/*---------------------------------------------------------------------------*/
int xio_conns_store_add(
		struct xio_conn *conn,
		int *conn_id)
{
	static int cid;  /* = 0 global conn provider */

	spin_lock(&cs_lock);
	int retval = conns_store_add(conn, cid);
	if (retval == 0)
		*conn_id = cid++;
	spin_unlock(&cs_lock);

	return retval;
}

/*---------------------------------------------------------------------------*/
/* xio_conns_store_find				                             */
/*---------------------------------------------------------------------------*/
struct xio_conn *xio_conns_store_find(
		struct xio_context *ctx,
		const char *portal_uri)
{
	struct xio_conn *conn;

	spin_lock(&cs_lock);
	HT_FOREACH(conn, &conns_store, conns_htbl) {
		if (conn->transport_hndl->portal_uri) {
			if (
		(strcmp(conn->transport_hndl->portal_uri, portal_uri) == 0) &&
		(conn->transport_hndl->ctx == ctx)) {
				spin_unlock(&cs_lock);
				return conn;
			}
		}
	}
	spin_unlock(&cs_lock);
	return  NULL;
}

/*---------------------------------------------------------------------------*/
/* conns_store_construct				                     */
/*---------------------------------------------------------------------------*/
void conns_store_construct(void)
{
	HT_INIT(&conns_store, xio_int32_hash, xio_int32_cmp, xio_int32_cp);
	spin_lock_init(&cs_lock);
}

/*
void conns_store_destruct(void)
{
}
*/

