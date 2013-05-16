/**
 * tbxsosd/libdb/ldapdb_servers.h
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
 * LDAP server list management
 * @author: François-Denis Gonthier
 */

#ifndef _LDAPDB_SERVERS_H
#define _LDAPDB_SERVERS_H

struct kdldap_server {
    const char *host;
    int port;
};

typedef struct {
    apr_pool_t *pool;

    /** List of LDAP servers. */
    apr_array_header_t *ldap_servers;

    /** Current LDAP server in the list. */
    int current;

} kdldap_servers_list;

typedef struct {
    apr_pool_t *pool;

    /* ADNS state. */
    adns_state adns_state;

    /** Set to true if adns_state has to be cleaned out. */
    int adns_init;

    /** Do we care about DNS resolution or not? */
    int use_dns;

    /** Do we use SASL? */
    int use_sasl;

    /** Target AD forest. */
    char *ad_forest;

    /** Target AD site. */
    char *ad_site;

    /** Static server list. */
    kdldap_servers_list *static_ldap_servers;

} kdldap_servers;

/** Create a new object able to obtain server lists. */
kdldap_servers *kdldap_servers_new(apr_pool_t *pool, int use_sasl);

/** Convert a LDAP DN to a DNS domain name. */
int kdldap_DN_to_DNS(apr_pool_t *pool, const char *ldap_dn, char **dns_dom);

/** Converts a DNS name to a domain DN. */
char *kdldap_DNS_to_dn(apr_pool_t *pool, const char *dns_dom);

/** Return a list of LDAP servers suitable for the KPS system login. */
int kdldap_servers_for_catalog(kdldap_servers *self, 
                                apr_pool_t *pool, 
                                const char *user_dn, 
                                kdldap_servers_list **srv_lst,
                                char **search_base);

/** Return a list of hosts that have user information (Domain Controllers). */
int kdldap_servers_for_user(kdldap_servers *self, 
                            apr_pool_t *pool, 
                            const char *sys_dn,
                            kdldap_servers_list **srv_lst);

/** Return a list of LDAP servers able to handle RootDSE requests. */
int kdldap_servers_for_RootDSE(kdldap_servers *self, apr_pool_t *pool, kdldap_servers_list **srv_lst);

/** Move to the next LDAP server in the list. */
void kdldap_servers_list_next(kdldap_servers_list *self);

/** Get the current LDAP server in the list, or NULL if there is none
    left or if there was none to begin with. */
const struct kdldap_server *kdldap_servers_list_current(kdldap_servers_list *self);

size_t kdldap_servers_list_count(kdldap_servers_list *self);

/** Reset the iterator to the start of the list. */
void kdldap_servers_list_reset(kdldap_servers_list *self);

#endif // _LDAPDB_SERVERS_H
