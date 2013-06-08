/**
 * tbxsosd/libdb/db_user.h
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
 * User database object.
 *
 * @author François-Denis Gonthier
 */

#ifndef _DB_USER_SQL_H
#define _DB_USER_SQL_H

#include <apr_tables.h>

#include "common/common.h"

#include "db_psql.h"

/** User profile database object. */
struct __kddbuser {
    apr_pool_t *pool;

    int admin;

    int cur_creds;

    /** Set to 1 after successfully preparing queries. */
    int is_prepared;

    /** Database connection. */
    kdsql *db;       
};

typedef struct __kddbuser kddbuser;

kddbuser *kddbuser_new(apr_pool_t *pool, kdsql *db, int admin, int cur_creds);

int kddbuser_get_prim_email(kddbuser *self,
                            apr_pool_t *pool,
                            uint64_t prof_id,
                            char **prim_addr);

int kddbuser_get_name(kddbuser *self, 
                      apr_pool_t *pool, 
                      uint64_t prof_id, 
                      char **full_name);

int kddbuser_is_email_allowed(kddbuser *self, 
                              apr_pool_t *parent_pool,
                              uint64_t uid, 
                              const char *addr_list, 
                              int *is_allowed,
                              char **email_matched);

int kddbuser_search_email(kddbuser *self, 
                          const char *addr, 
                          uint64_t *key_id,
                          uint64_t *prof_id);

int kddbuser_get_key_id(kddbuser *self,
                        uint64_t prof_id,
                        uint64_t *key_id);

int kddbuser_search_ldap_group(kddbuser *self, 
                               const char *dn_str,
                               uint64_t *prof_id,
                               uint64_t *org_id,
                               uint64_t *key_id);

int kddbuser_list_ldap_groups(kddbuser *self,
                              apr_array_header_t *group_list);

int kddbuser_get_org_data_from_prof_id(kddbuser *self, 
                                       apr_pool_t *pool,
                                       uint64_t prof_id, 
                                       struct kd_organization *org_data);

int kddbuser_get_org_data_from_kdn(kddbuser *self,
                                   apr_pool_t *pool,
                                   const char *kdn,
                                   struct kd_organization *org_data);

int kddbuser_import_license(kddbuser *self, const char *kdn, const char *license_data);

#endif // _DB_USER_H
