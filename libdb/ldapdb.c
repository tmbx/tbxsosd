/**
 * tbxsosd/libdb/ldapdb.c
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
 * High-level interface for tbxsosd DB
 * François-Denis Gonthier
 */

#include <ldap.h>
#include <sasl/sasl.h>
#include <apr_tables.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <ktools.h>
#include <string.h>

#include "common/common_keys.h"
#include "common/common.h"
#include "common/logid.h"
#include "common/config.h"
#include "libutils/options.h"
#include "libutils/logging.h"

#include "ldapdb.h"
#include "ldapdb_base.h"

/** FIXME: Beautify this module. */

/** Create a new LDAP object. */
kdldap *kdldap_new(apr_pool_t *pool) {
    kdldap *self;
    struct kdldap_conn_params params;
    apr_pool_t *obj_pool;

    apr_pool_create(&obj_pool, pool);

    self = apr_pcalloc(obj_pool, sizeof(kdldap));
    self->pool = obj_pool;

    do {
        params.use_sasl = options_get_bool("ldap.use_sasl");
        params.use_tls = options_get_bool("ldap.use_tls");

        /* Load the other options. */
        self->sys_dn = options_get_str("ldap.sys_dn");
        if (strlen(self->sys_dn) == 0) {
            KERROR_SET(_ldap_, 0, "ldap.sys_dn not specified");
            break;
        }

        /* KPS system username and password. */
        self->sys_username = options_get_str("ldap.sys_username");
        self->sys_password = options_get_str("ldap.sys_password");

        /* Initialize a connection to the root DSE of any server we
           can connect on. */
        params.dn = NULL;
        params.username = NULL;
        params.password = NULL;

        kdldap_servers_list *srv_lst;

        if ((self->servers = kdldap_servers_new(obj_pool, params.use_sasl)) == NULL) {
            KERROR_PUSH(_ldap_, 0, "failed to create LDAP server manager");
            break;
        }

        if (kdldap_servers_for_RootDSE(self->servers, obj_pool, &srv_lst) < 0) {
            KERROR_PUSH(_ldap_, 0, "failed to find any LDAP servers");
            break;
        }
        
        /* Start with a root DSE connection. */
        self->conn_catalog = kdldap_bind(obj_pool, &params, srv_lst);
        if (!self->conn_catalog) break;
        else {
            switch (self->conn_catalog->ldap_type) {
            case LDAP_TYPE_MS_AD:
                self->f = &kdldap_ad_functions; break;
            case LDAP_TYPE_LOTUS:
                self->f = &kdldap_domino_functions; break;
            default:
                break;
            }

            if (self->conn_catalog->ldap_type == LDAP_TYPE_OTHER) {
                KERROR_SET(_ldap_, 0, "unknown server type");
                break;
            }

            DEBUG(_log_ldap_, "Logging-in KPS system user.");

            /* Do the KPS system login. */
            if ((self->f->ldap_sys_bind)(self, obj_pool) < 0) {
                KERROR_PUSH(_ldap_, 0, "system login failed");
                break;
            }
        }

        return self;
 
    } while (0);

    apr_pool_destroy(obj_pool);

    return NULL;
}

int kdldap_get_name(kdldap *self, 
                    apr_pool_t *pool, 
                    struct kd_user *user, 
                    char **name) {
    return (self->f->ldap_get_name)(self, pool, user, name);
}

int kdldap_get_prim_email(kdldap *self, 
                                  apr_pool_t *pool, 
                                  struct kd_user *user,
                                  char **primary_email_addr) {
    return (self->f->ldap_get_prim_email)(self, pool, 
                                          user->user_dn, 
                                          primary_email_addr);
}

int kdldap_convert_address(kdldap *self, apr_pool_t *pool, const char *addr, char **email) {
    return (self->f->ldap_convert_address)(self, pool, addr, email);
}

int kdldap_search_enc_pkey(kdldap *self, 
                           apr_pool_t *parent_pool,
                           kddbuser *user_db, 
                           const char *addr,
                           uint64_t *prof_id,
                           uint64_t *key_id) {
    return (self->f->ldap_search_enc_pkey)(self, parent_pool, user_db, addr, prof_id, key_id);
}

int kdldap_is_email_allowed(kdldap *self, 
                            apr_pool_t *parent_pool,
                            struct kd_user *info, 
                            const char *addr_list, 
                            int *is_allowed,
                            char **email_matched) {
    return (self->f->ldap_is_email_allowed)(self, 
                                            parent_pool, 
                                            info, 
                                            addr_list, 
                                            is_allowed, 
                                            email_matched);
}

int kdldap_user_bind(kdldap *self, 
                     apr_pool_t *pool,
                     struct kd_user *user,
                     kddbuser *user_db,
                     const char *username,
                     const char *password,
                     uint64_t *prof_id,
                     uint64_t *org_id,
                     uint64_t *key_id) {
    return (self->f->ldap_user_bind)(self, pool, user, user_db, 
                                     username, password, prof_id, org_id, key_id);
}

/* FIXME: no prototype, no caller. Remove? Use? */
int kdldap_sys_bind(kdldap *self, apr_pool_t *pool) {
    return (self->f->ldap_sys_bind)(self, pool);
}
                    
