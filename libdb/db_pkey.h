/**
 * tbxsosd/libdb/db_pkey.h
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
 * Public key database object.
 *
 * @author François-Denis Gonthier
 */

#ifndef _DB_PKEY_H
#define _DB_PKEY_H

#include "common_keys.h"
#include "db_psql.h"

/** Public key database private informations. */
struct __kddbpkey {
    apr_pool_t *pool;

    /** Set to 1 after successfully preparing queries. */
    int is_prepared;

    /** Database connection object. */
    kdsql *db;
};

typedef struct __kddbpkey kddbpkey;

kddbpkey *kddbpkey_new(apr_pool_t *pool, kdsql *db);

int kddbpkey_get(kddbpkey *self, 
                 apr_pool_t *pool, 
                 enum kdkey_type type, 
                 uint64_t key_id, 
                 struct kdkey_info **ki);

#endif // _DB_PKEY_H
