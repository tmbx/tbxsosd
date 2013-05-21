/**
 * tbxsosd/libdb/ldapdb.h
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
 * Takes care of LDAP login.
 *
 * @author François-Denis Gonthier
 */

#ifndef _LDAPDB_H
#define _LDAPDB_H

#include <apr_pools.h>
#include <adns.h>
#include <ldap.h>
#include <ktools.h>

typedef struct __kdldap kdldap;

#include "common.h"
#include "db.h"
#include "ldapdb_servers.h"

struct __kdldap {
    /** Own pool.  Used to hold the instance of the object. */
    apr_pool_t *pool;

    /** Connexion to catalog LDAP server, to do global searches. */
    struct kdldap_conn *conn_catalog;

    /** LDAP server list manager. */
    kdldap_servers *servers;

    /* System DN */
    const char *sys_dn;

    /* Username of sys_dn. */
    const char *sys_username;

    /* System password. */
    const char *sys_password;
    
    /* Search base for global searches with the catalog connection.  This is
     * AD-specific.
     */
    char *ad_catalog_base;

    struct kdldap_functions *f;
};

extern struct kdldap_functions kdldap_ad_functions;
extern struct kdldap_functions kdldap_domino_functions;

struct kdldap_functions {
    int (* ldap_user_bind)(kdldap *self, 
                           apr_pool_t *parent_pool, 
                           struct kd_user *user,
                           kddbuser *user_db,
                           const char *username,
                           const char *secret,
                           uint64_t *prof_id,
                           uint64_t *org_id,
                           uint64_t *key_id);

    int (* ldap_is_email_allowed)(kdldap *self,
                                  apr_pool_t *parent_pool,
                                  struct kd_user *user,
                                  const char *addr_list,
                                  int *is_allowed,
                                  char **email_matched);

    int (* ldap_search_enc_pkey)(kdldap *self, 
                                 apr_pool_t *parent_pool,
                                 kddbuser *user_db,
                                 const char *addr,
                                 uint64_t *prof_id,
                                 uint64_t *key_id);

    int (* ldap_get_prim_email)(kdldap *self, 
                                apr_pool_t *parent_pool, 
                                const char *dn,
                                char **primary_email_addr);

    int (* ldap_get_name)(kdldap *self, 
                          apr_pool_t *parent_pool, 
                          struct kd_user *user, 
                          char **name);

    int (* ldap_convert_address)(kdldap *self,
                                 apr_pool_t *parent_pool,
                                 const char *src_addr,
                                 char **real_addr);

    int (* ldap_sys_bind)(kdldap *self, apr_pool_t *parent_pool);
};

/** Instanciate a new LDAP object. */
kdldap *kdldap_new(apr_pool_t *pool);

/** Initialize the ldapdb object. */
int kdldap_init();

/** Static initialization of LDAP options. */
int kdldap_static_init();

/** Check if an address is part of the user accepted email
    addresses. */
int kdldap_is_email_allowed(kdldap *self, 
                            apr_pool_t *parent_pool,
                            struct kd_user *user, 
                            const char *addr_list, 
                            int *is_allowed,
                            char **email_matched);

/** Return the primary email address for the user we are bound to. */
int kdldap_get_prim_email(kdldap *self, 
                          apr_pool_t *parent_pool, 
                          struct kd_user *user, 
                          char **primary_email_addr);

int kdldap_get_name(kdldap *self, 
                    apr_pool_t *parent_pool, 
                    struct kd_user *user, 
                    char **name);

int kdldap_search_enc_pkey(kdldap *self, 
                           apr_pool_t *parent_pool,
                           kddbuser *user_db, 
                           const char *addr, 
                           uint64_t *prof_id,
                           uint64_t *key_id);

/** Attempt an LDAP bind (login) */
int kdldap_user_bind(kdldap *self, 
                     apr_pool_t *parent_pool,
                     struct kd_user *info,
                     kddbuser *user_db,
                     const char *username, 
                     const char *password,
                     uint64_t *prof_id,
                     uint64_t *org_id,
                     uint64_t *key_id);

int kdldap_convert_address(kdldap *self, apr_pool_t *pool, const char *addr, char **email);

#endif // _LDAPDB_H
