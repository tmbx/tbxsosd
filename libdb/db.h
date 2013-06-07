/**
 * tbxsosd/libdb/db.h
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
 * General database interface.
 *
 * @author François-Denis Gonthier
 */

#ifndef _DB_H
#define _DB_H

#include <apr_pools.h>

#include "common/common.h"
#include "db_login.h"
#include "db_otut.h"
#include "db_event.h"
#include "db_pkey.h"
#include "db_skey.h"
#include "db_user.h"
#include "ldapdb.h"

struct __kddb {
    int use_ldap;

    kddblogin *login_db;
    kddbuser *user_db;
    kddbpkey *pkey_db;
    kddbskey *skey_db;
    kddbevent *event_db;
    kddbotut *otut_db;

    kdldap *ldap_db;
};

/** Determine what username the connection will be made with. */
enum kddb_auth_mode {
    /** Connect with the effective username. */
    DB_AUTH_CURRENT_CREDS_MODE,
    
    /** Connect with the configured administrative username from the
        configuration. */
    DB_AUTH_ADMIN_MODE,

    /** Connect with the normal username from the configuration. */
    DB_AUTH_NORMAL_MODE
};

typedef struct __kddb kddb;

enum event_var_type {
    EV_VAR_UINT32,
    EV_VAR_UINT64,
    EV_VAR_STR
};

struct event {    
    const char *key;
    enum event_var_type type;
    union {
        const char *str;
        uint32_t uint32;
        uint64_t uint64;
    } val;
};

int kddb_open(apr_pool_t *pool, enum kddb_auth_mode auth_mode);

int kddb_login(apr_pool_t *pool,
               int is_password,
               const char *username,
               const char *secret,
               struct kd_user *user,
               struct kd_login_result **result);

int kddb_reserve_seat(const char *username, uint64_t org_id, uint64_t *parent_org_id);

int kddb_count_seats(uint64_t org_id, int *seats_count);

int kddb_get_seats_allocation(uint64_t org_id, int *seats_count);

int kddb_get_org_data_from_kdn(apr_pool_t *pool, const char *kdn, struct kd_organization *org_data);

int kddb_get_prim_email(apr_pool_t *pool,
                        struct kd_user *user,
                        char **primary_addr);

int kddb_get_full_name(apr_pool_t *pool,
                       struct kd_user *info,
                       char **full_name);

int kddb_is_email_allowed(apr_pool_t *pool,
                          struct kd_user *info,
                          const char *addr_list,
                          int *is_allowed,
                          char **email_matched);

int kddb_convert_address(apr_pool_t *pool, 
                         const char *default_addr,
                         const char *src_addr, 
                         char **dst_addr);

int kddb_fetch_key(apr_pool_t *pool, 
                   uint64_t key_id,
                   enum kdkey_type ktype, 
                   struct kdkey_info **ki);

int kddb_import_license(const char *kdn, const char *license_data);

int kddb_event(apr_pool_t *pool,
               uint64_t session_id,
               const char *event_name, 
               size_t nvar, 
               struct event *event_vars);

int kddb_search_enc_pkey(apr_pool_t *pool, 
                         const char *addr, 
                         struct kdkey_info **ki);

int kddb_otut_ticket_store(uint64_t key_id, struct timeval *tm);

int kddb_otut_store(const char *otut_str, 
                    size_t otut_str_s, 
                    uint64_t key_id,
                    int nb_use, 
                    int nb_tries);

int kddb_otut_login(apr_pool_t *pool, 
                    struct kd_user *user, 
                    const char *otut_str,
                    size_t otut_str_s,
                    struct kd_login_result **res);

int kddb_otut_success(const char *otut_str, 
                      size_t otut_str_s,
                      int *nb_usages_left,
                      int *nb_fails_left);

int kddb_otut_fail(const char *otut_str, 
                   size_t otut_str_s,
                   int *nb_usages_left,
                   int *nb_fails_left);

int kddb_otut_check(const char *otut_str, size_t otut_str_s, uint32_t *nb_uses);

void kddb_validate();

#endif // _DB_H
