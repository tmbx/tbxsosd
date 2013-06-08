/**
 * tbxsosd/libdb/db_skey.h
 * Copyright (C) 2006-2012 Opersys inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Secret key database object.
 *
 * @author François-Denis Gonthier
 */

#ifndef _DB_SKEY_H
#define _DB_SKEY_H

#include "common/common_keys.h"

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
