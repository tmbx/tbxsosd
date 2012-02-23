/**
 * tbxsosd/libdb/db_user.h
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
 * User database object.
 *
 * @author François-Denis Gonthier
 */

#ifndef _DB_USER_SQL_H
#define _DB_USER_SQL_H

#include <apr_tables.h>

#include "common.h"
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
