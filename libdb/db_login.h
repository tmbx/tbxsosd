/**
 * tbxsosd/libdb/db_login.h
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
 * Login database object.
 *
 * @author François-Denis Gonthier
*/

#ifndef _DB_LOGIN_H
#define _DB_LOGIN_H

#include <apr_pools.h>

#include "common.h"
#include "db_psql.h"

struct __kddblogin {
    apr_pool_t *pool;

    /** Set to 1 after queries have been successfully prepared. */
    int is_prepared;

    /** Database connection object. */
    kdsql *db;       
};

typedef struct __kddblogin kddblogin;

/** Create a new login object. */
kddblogin * kddblogin_new(apr_pool_t *pool, kdsql *db);

/** Start the login transaction. */
int kddblogin_start(kddblogin *self);

/** Commit the login transaction. */
int kddblogin_succeed(kddblogin *self);

/** Fail the login transaction. */
int kddblogin_fail(kddblogin *self);

int kddblogin_token_login(kddblogin *self, 
                          apr_pool_t *pool,
                          const char *username, 
                          const char *token,
                          struct kd_login_result **res);

int kddblogin_pwd_login(kddblogin *self, 
                        apr_pool_t *pool,
                        const char *username, 
                        const char *password,
                        struct kd_login_result **res);

int kddblogin_external(kddblogin *self,
                       apr_pool_t *pool,
                       const char *username,
                       uint64_t org_id,
                       struct kd_login_result **res);

int kddblogin_set_limits(kddblogin *self, int lim, int max);

int kddblogin_reserve_seat(kddblogin *self, const char *username, uint64_t org_id, uint64_t *parent_org_id);

int kddblogin_count_seats(kddblogin *self, uint64_t org_id, int *seats_count);

int kddblogin_get_seats_allocation(kddblogin *self, uint64_t org_id, int *seats_count);

/** Check login slots available. */
int kddblogin_check(kddblogin *self, 
                    apr_pool_t *pool,
                    const char *username,
                    struct kd_login_result **res);
                      
#endif // _DB_LOGIN_H
