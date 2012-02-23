/**
 * tbxsosd/libdb/db_skey.h
 * Copyright (C) 2006-2012 Opersys inc.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License, not any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Secret key database object.
 *
 * @author François-Denis Gonthier
 */

#ifndef _DB_SKEY_H
#define _DB_SKEY_H

#include "common_keys.h"
#include "db_psql.h"

struct __kddbskey {
    apr_pool_t *pool;

    /** Set to 1 after successfully preparing queries. */
    int is_prepared;

    /** Database connection. */
    kdsql *db;
};

typedef struct __kddbskey kddbskey;

void kddbskey_delete(kddbskey *self);

kddbskey *kddbskey_new(apr_pool_t *pool, kdsql *db);

int kddbskey_get(kddbskey *self, 
                 apr_pool_t *pool,
                 enum kdkey_type skey_type, 
                 uint64_t key_id,
                 struct kdkey_info **ki);

#endif // _DB_SKEY_H
