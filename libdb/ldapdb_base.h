/**
 * tbxsosd/libdb/ldapdb_base.h
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
 * Basic LDAP functions.
 * @author: François-Denis Gonthier 
 */

#ifndef _LDAPDB_BASE_H
#define _LDAPDB_BASE_H

#include <apr_hash.h>

#include "ldapdb.h"
#include "ldapdb_servers.h"

struct kdldap_result {   
    /** List of attribute DNs. */
    apr_array_header_t *attr_dn;
    
    /** List of attribute names. */
    apr_array_header_t *attr_names;
    
    /** List of attribute values. */
    apr_array_header_t *attributes;

    /** Hashtable of DN->array of attributes. */
    apr_hash_t *dn_attributes;
};

struct kdldap_conn_params {
    const char *dn;

    const char *username;

    const char *password;

    int use_sasl;
    
    int use_tls;
};

enum ldap_type {
    /** Microsoft Active Directory, any version. */
    LDAP_TYPE_MS_AD,

    /** Lotus Domino, any version. */
    LDAP_TYPE_LOTUS,

    /** Unidentified server. */
    LDAP_TYPE_OTHER
};

struct kdldap_conn {    
    apr_pool_t *pool;

    /** Params that were used for the connection. */
    struct kdldap_conn_params params;

    /** LDAP connection. */
    LDAP *ldap;

    /** Server where we are connected on. */
    struct kdldap_server server;

    /** DNS hostname of the server, to use with SASL DIGEST-MD5. */
    char *ldap_dnshostname;

    /** Can we use DIGEST-MD5? */
    int can_digest;

    /** Can we use TLS */
    int can_tls;

    /** Current search base. */
    char *server_base_dn;

    /** LDAP server type. */
    enum ldap_type ldap_type;
};

struct kdldap_result *kdldap_result_new(apr_pool_t *pool);

char *kdldap_escape_string(apr_pool_t *pool, const char *src, size_t src_sz);

/** Bind on a server. */
struct kdldap_conn *kdldap_bind(apr_pool_t *pool, 
                                struct kdldap_conn_params *params, 
                                kdldap_servers_list *srv_lst);

/** Rebind on the current bound connection, or reconnect to another
    server if needed. */
int kdldap_rebind(struct kdldap_conn **conn,
                  struct kdldap_conn_params *params,
                  kdldap_servers_list *srv_lst);

/** Do a query on the connected server. */
struct kdldap_result *kdldap_query(struct kdldap_conn *conn,
                                   apr_pool_t *pool,
                                   int scope,
                                   const char *base,
                                   const char **attr,
                                   const char *filter);

#endif // _LDAPDB_BASE_H
