/**
 * tbxsosd/libdb/db_otut.h
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
 * OTUT database object.
 *
 * @author François-Denis Gonthier
 */

#ifndef _DB_OTUT_H
#define _DB_OTUT_H

typedef struct __kddbotut kddbotut;

#include "db.h"
#include "db_psql.h"

/** OTUT utilities database object. */
struct __kddbotut {
    apr_pool_t *pool;

    /** Set to 1 after successfully preparing queries. */
    int is_prepared;

    /** Database connection object. */
    kdsql *db;
};

kddbotut *kddbotut_new(apr_pool_t *pool, kdsql *db);

int kddbotut_store(kddbotut *self, 
                   const char *otut_str, 
                   size_t otut_str_s,
                   uint64_t mid, 
                   uint32_t use_count, 
                   uint32_t attempt_count);

int kddbotut_store_ticket(kddbotut * self, uint64_t mid, struct timeval * tv);

int kddbotut_login(kddbotut *self, 
                   const char *otut_str, 
                   size_t otut_str_s, 
                   uint64_t *key_id,
                   struct kd_login_result **login_result);

int kddbotut_fail(kddbotut *self, 
                  const char *otut_str, 
                  size_t otut_str_s, 
                  int *nb_usage_left,
                  int *nb_fails_left);

int kddbotut_succeed(kddbotut *self, 
                     const char *otut_str,
                     size_t otut_str_s,
                     int *nb_usages_left,
                     int *nb_fails_left);

int kddbotut_check_otut(kddbotut *self, 
                        const char *otut_str, 
                        size_t otut_str_s, 
                        uint32_t *nb_use);

#endif // _DB_OTUT_H
