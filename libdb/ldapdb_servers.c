/**
 * tbxsosd/libdb/ldapdb_servers.c
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
 * LDAP server list management.
 * @author: François-Denis Gonthier
 */

#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include <adns.h>
#include <ldap.h>
#include <kerror.h>

#include "logid.h"
#include "logging.h"
#include "options.h"
#include "ldapdb_servers.h"
#include "ldapdb_utils.h"

/* FIXME: DNS query caching. */

static apr_status_t kdldap_servers_cleanup(void *data) {
    kdldap_servers *self = (kdldap_servers *)data;

    if (self->use_dns && self->adns_init) 
        adns_finish(self->adns_state);

    return APR_SUCCESS;
}

/** Create a new server list. */
static kdldap_servers_list *kdldap_servers_list_new(apr_pool_t *pool) {
    kdldap_servers_list *self;

    self = apr_pcalloc(pool, sizeof(kdldap_servers_list));
    self->pool = pool;
    self->ldap_servers = apr_array_make(self->pool, 0, sizeof(struct kdldap_server));

    return self;
}

/** Add a server in the list. */
static void kdldap_servers_list_add(kdldap_servers_list *self, const char *host, int port) {
    struct kdldap_server *srv;

    srv = apr_array_push(self->ldap_servers);
    srv->host = apr_pstrdup(self->pool, host);
    srv->port = port;
}

void kdldap_servers_list_reset(kdldap_servers_list *self) {
    self->current = 0;
}

size_t kdldap_servers_list_count(kdldap_servers_list *self) {
    return self->ldap_servers->nelts;
}

const struct kdldap_server *kdldap_servers_list_current(kdldap_servers_list *self) {
    if (self->current < self->ldap_servers->nelts)
        return &((struct kdldap_server *)self->ldap_servers->elts)[self->current];
    return NULL;
}

void kdldap_servers_list_next(kdldap_servers_list *self) {
    if (self->current < self->ldap_servers->nelts)
        self->current++;
}

/** Load the statically defined list of servers in the LDAP config. */
static int kdldap_servers_load_static_servers(kdldap_servers *self,
                                              apr_pool_t *pool, 
                                              kdldap_servers_list **srv_lst) {
    size_t i, max;
    char *hosts, *host = NULL, *port_str = NULL;
    apr_pool_t *lst_pool;
    const char *cfg_hosts;

    apr_pool_create(&lst_pool, pool);

    self->static_ldap_servers = kdldap_servers_list_new(lst_pool); 
    cfg_hosts = options_get_str("ldap.host");
    hosts = apr_pstrdup(lst_pool, cfg_hosts);
    max = strlen(hosts);

    for (i = 0; i <= max; i++) {
        int is_whitespace = (hosts[i] == ' ' || hosts[i] == '\n' || hosts[i] == '\0');

        /* Start of new host. */
        if (host == NULL && port_str == NULL && !is_whitespace) 
            host = &hosts[i];

        /* Start of port. */
        else if (host != NULL && port_str == NULL && hosts[i - 1] == ':') {
            port_str = &hosts[i];
            hosts[i - 1] = '\0';
        }

        /* End of host:port. */
        if (host != NULL && port_str != NULL && is_whitespace) {
            int port;

            hosts[i] = '\0';
               
            port = strtoimax(port_str, NULL, 10);
            if (port == 0) {
                KERROR_SET(_ldap_, 0, "invalid port: %s", port_str);
                apr_pool_destroy(lst_pool);
                *srv_lst = NULL;
                return -1;
            }
            
            kdldap_servers_list_add(*srv_lst, host, port);
            host = NULL;
            port_str = NULL;
        }
    }             

    return 0;
}

/** DNS query on a specific SRV record service. */
static int kdldap_ad_DNS_get_service(kdldap_servers *self,
                                     apr_pool_t *pool,
                                     const char *ldap_service,
                                     kdldap_servers_list **srv_lst) {
    apr_pool_t *lst_pool;
    adns_answer *answer = NULL;
    int i, err = -1;

    DEBUG(_log_ldap_, "Querying DNS for %s.", ldap_service);

    apr_pool_create(&lst_pool, pool);

    *srv_lst = kdldap_servers_list_new(lst_pool);

    /* adns_qf_quoteok_query is needed since the query might include
       caracters that are thought to be invalid for DNS query by ADNS. */
    err = adns_synchronous(self->adns_state, ldap_service, 
                           adns_r_srv_raw, adns_qf_quoteok_query, &answer);
    if (err < 0) 
        KERROR_SET(_ldap_, 0, "request for SRV record %s failed", ldap_service);
    else {
        if (answer->status == adns_s_ok) {
            for (i = 0 ; i < answer->nrrs ; i++) {
                char *host;
                int port;

                host = answer->rrs.srvraw[i].host;
                port = answer->rrs.srvraw[i].port;

                DEBUG(_log_ldap_, "DNS query found: %s:%d.", host, port);

                kdldap_servers_list_add(*srv_lst, host, port);
            }

            if (answer->nrrs == 0) 
                DEBUG(_log_ldap_, "DNS query found nothing.");

            err = 0; 
        } 
            
        free(answer);
    }

    if (err) {
        apr_pool_destroy(lst_pool);
        *srv_lst = NULL;
    }

    return err < 0 ? -1 : 0;
}

/** Return a DC in a domain or forest. */
static int kdldap_ad_DNS_get_DC(kdldap_servers *self, 
                                apr_pool_t *pool, 
                                const char *dns_dom, 
                                kdldap_servers_list **srv_lst) {
    apr_pool_t *fn_pool;
    char *ldap_service;
    int err;

    DEBUG(_log_ldap_, "Looking for DC servers in domain %s.", dns_dom);
    
    apr_pool_create(&fn_pool, pool);

    /* Query the site first. */
    if (self->ad_site) {
        ldap_service = apr_psprintf(fn_pool, "_ldap._tcp.%s._sites.dc._msdcs.%s", 
                                    self->ad_site, dns_dom);
        err = kdldap_ad_DNS_get_service(self, pool, ldap_service, srv_lst);

        if (err) {
            apr_pool_destroy(fn_pool);
            return err;
        }
    }

    /* Query the entire forest. */
    if (!self->ad_site || (*srv_lst && kdldap_servers_list_count(*srv_lst) == 0)) { 
        ldap_service = apr_psprintf(fn_pool, "_ldap._tcp.dc._msdcs.%s", dns_dom);
        err = kdldap_ad_DNS_get_service(self, pool, ldap_service, srv_lst);
    }
    
    apr_pool_destroy(fn_pool);

    return err;
}

/** Return a GC server in a domain or forest. */
static int kdldap_ad_DNS_get_GC(kdldap_servers *self, 
                                apr_pool_t *pool, 
                                const char *dns_dom, 
                                kdldap_servers_list **srv_lst) {
    apr_pool_t *fn_pool;
    char *ldap_service;
    int err;
    
    apr_pool_create(&fn_pool, pool);

    /* Query the site first. */
    if (self->ad_site) {
        DEBUG(_log_ldap_, "Looking for GC servers in site %s.", dns_dom);
        ldap_service = apr_psprintf(fn_pool, "_ldap._tcp.%s._sites.gc._msdcs.%s", 
                                    self->ad_site, dns_dom);
        err = kdldap_ad_DNS_get_service(self, pool, ldap_service, srv_lst);

        if (err) {
            apr_pool_destroy(fn_pool);
            return err;
        }
    }

    /* Query the entire forest. */
    if (!self->ad_site || (*srv_lst && kdldap_servers_list_count(*srv_lst) == 0)) {
        DEBUG(_log_ldap_, "Looking for GC servers in forest %s.", dns_dom);
        ldap_service = apr_psprintf(fn_pool, "_ldap._tcp.gc._msdcs.%s", dns_dom);
        err = kdldap_ad_DNS_get_service(self, pool, ldap_service, srv_lst);    
    }

    apr_pool_destroy(fn_pool);

    return err < 0 ? -1 : 0;
}

/** Return a GC server located in a specific domain. */
static int kdldap_ad_DNS_get_domain_GC(kdldap_servers *self,
                                       apr_pool_t *pool,
                                       const char *dns_forest,
                                       const char *dns_dom,
                                       kdldap_servers_list **srv_lst) {
    apr_pool_t *fn_pool, *lst_pool;
    kdldap_servers_list *gc_hosts;
    kdldap_servers_list *dc_hosts;
    const struct kdldap_server *gc, *dc;
    int err = -1;

    apr_pool_create(&fn_pool, pool);

    /* Find the GCs in that domain. */
    if (kdldap_ad_DNS_get_GC(self, fn_pool, dns_forest, &gc_hosts) < 0) {
        KERROR_PUSH(_ldap_, 0, "failed to get GC in %s", dns_forest);
        apr_pool_destroy(fn_pool);        
        return -1;
    } 
      
    /* Find the DCs in that domain. */
    if (kdldap_ad_DNS_get_DC(self, fn_pool, dns_dom, &dc_hosts) < 0) {
        KERROR_PUSH(_ldap_, 0, "failed to get DC in %s", dns_dom);
        apr_pool_destroy(fn_pool);
        return -1;
    }

    apr_pool_create(&lst_pool, pool);   

    *srv_lst = kdldap_servers_list_new(lst_pool);
    
    /* From the GC list, remove the servers that are not in the DC list. In
     * other words, obtain the servers that are both a DC and a GC for the
     * domain specified.
     */
    while ((gc = kdldap_servers_list_current(gc_hosts)) != NULL) {
        while ((dc = kdldap_servers_list_current(dc_hosts)) != NULL) {
            if (strcasecmp(gc->host, dc->host) == 0) 
                kdldap_servers_list_add(*srv_lst, gc->host, gc->port);
            kdldap_servers_list_next(dc_hosts);
        }
        kdldap_servers_list_next(gc_hosts);
        kdldap_servers_list_reset(dc_hosts);
    }

    if (kdldap_servers_list_count(*srv_lst) == 0) {
        *srv_lst = NULL;
        apr_pool_destroy(lst_pool);
    } 
    else err = 0;    

    apr_pool_destroy(fn_pool);

    return err;
}

/** Convert a LDAP DN to a DNS domain name. 
 * 
 * Example: CN=Blarg,CN=Blorg,DC=AD,DC=LOCAL => AD.LOCAL.
 *
 * This is very much AD specific.  It won't work for Lotus Domino DNs.
 */
int kdldap_DN_to_DNS(apr_pool_t *pool, const char *ldap_dn, char **dns_dom) {
    apr_pool_t *fn_pool;
    char *dom_str = NULL;
#if LDAP_API_VERSION == 3001
    LDAPDN dn;
#elif LDAP_API_VERSION == 2004
    LDAPDN *dn;
#else
#error Unknown LDAP API version
#endif
    int i, err = -1;
   
    err = ldap_str2dn(ldap_dn, &dn, LDAP_DN_FORMAT_LDAPV3);
    if (err < 0) {
        kdldap_paranoid_push_error(NULL, err);
        KERROR_PUSH(_ldap_, 0, "unable to convert DN %s to DNS domain");
        return -1;
    }

    if (dn) {
        apr_pool_create(&fn_pool, pool);
    
        for (i = 0; 
#if LDAP_API_VERSION == 2004
             (*dn)[i] != NULL; 
#elif LDAP_API_VERSION == 3001
             dn[i] != NULL;
#endif
             i++) {
            char *attr, *val;
#if LDAP_API_VERSION == 2004
            LDAPAVA *v = **(*dn)[i];
#elif LDAP_API_VERSION == 3001
            LDAPAVA *v = *dn[i];
#endif

#if LDAP_API_VERSION == 3001
            /* Security to make sure we don't append binary crap. */
            if (!(v->la_flags & LDAP_AVA_STRING))
                continue;
#endif // LDAP_API_VERSION
        
            attr = apr_pstrmemdup(fn_pool, v->la_attr.bv_val, v->la_attr.bv_len);
            val = apr_pstrmemdup(fn_pool, v->la_value.bv_val, v->la_value.bv_len);
            
            if (strcasecmp(attr, "DC") == 0) {
                if (dom_str == NULL)
                    dom_str = apr_pstrdup(fn_pool, val);
                else
                    dom_str = apr_pstrcat(fn_pool, dom_str, ".", val, NULL);
            }
        }

        ldap_dnfree(dn);
    }

    if (dom_str != NULL) {
        *dns_dom = apr_pstrdup(pool, dom_str);
        err = 0;
    }
    else 
        KERROR_PUSH(_ldap_, 0, "unable to convert system DN to DNS domain");

    apr_pool_destroy(fn_pool);

    return err;
}

/** Converts a DNS name to a domain DN.
 * 
 * Example: AD.LOCAL => DC=AD,DC=LOCAL.
 *
 * This is very much AD specific.  It won't work for Lotus Domino DNs.
 */
char *kdldap_DNS_to_dn(apr_pool_t *pool, const char *dns_dom) {
    kstr r;
    const char *s = dns_dom;
    char *dn;
    
    kstr_init_cstr(&r, "DC=");
    
    while (*s) {
        if (*s == '.') kstr_append_cstr(&r, ",DC=");
        else kstr_append_char(&r, *s);
        s++;
    }
    
    dn = apr_pstrdup(pool, r.data);
    kstr_clean(&r);
    
    return dn;
}

/** Return a list of LDAP servers suitable for the KPS system login.
 * 
 * The KPS system login must be a Global Catalog server and in case of
 * SASL must be in the same domain as the KPS system user.
 */
int kdldap_servers_for_catalog(kdldap_servers *self,
                               apr_pool_t *pool,
                               const char *dn,
                               kdldap_servers_list **srv_lst,
                               char **search_base) {
    int err = 0, use_dc_fallback = 0;
    char *dns_dom = NULL;
    apr_pool_t *fn_pool, *lst_pool;
    
    apr_pool_create(&fn_pool, pool);
    apr_pool_create(&lst_pool, pool);
    
    DEBUG(_log_ldap_, "Obtaining global catalog connection for system user %s.", dn);
    
    /* For a GC, we use a NULL search base. */
    *search_base = NULL;
    
    do {
        /* We're not using DNS, use the static server list.  Search
           base will be NULL in that case. */
        if (! self->use_dns) {
            DEBUG(_log_ldap_, "Using static server list.");
            *srv_lst = apr_pmemdup(lst_pool, self->static_ldap_servers, sizeof(kdldap_servers_list));
        }
        
        /* We're not using SASL. Use any GC server. */ 
        else if (! self->use_sasl) {
            DEBUG(_log_ldap_, "Not using SASL. Any GC in the forest will do.");
            
            if (kdldap_ad_DNS_get_GC(self, lst_pool, self->ad_forest, srv_lst) < 0 ||
                ! kdldap_servers_list_count(*srv_lst)) {
                WARN(_log_ldap_, "No global catalog server found in forest %s.", self->ad_forest);
                use_dc_fallback = 1;
            }
        }
        
        /* We're using SASL. Find a GC server in the system user's domain. */
        else {
            DEBUG(_log_ldap_, "Using SASL. Looking for GC server in the system user's domain.");
            
            /* Find the DNS domain name corresponding to the system user. */
            if (kdldap_DN_to_DNS(fn_pool, dn, &dns_dom) < 0) {
                KERROR_PUSH(_ldap_, 0, "failed to convert DN %s to DNS domain", dn);
                err = -1;
                break;
            }
           
            if (kdldap_ad_DNS_get_domain_GC(self, lst_pool, self->ad_forest, dns_dom, srv_lst) < 0 ||
                ! kdldap_servers_list_count(*srv_lst)) {
                WARN(_log_ldap_, "No global catalog server in domain %s.", dns_dom);
                use_dc_fallback = 1;
            }
        }
        
        /* As a fallback, look for a domain controller in the forest root. */
        if (use_dc_fallback) {
            DEBUG(_log_ldap_, "Fallback: looking for DC in forest root");
            
            /* Get the DNS domain of the user. */
            if (! dns_dom && kdldap_DN_to_DNS(fn_pool, dn, &dns_dom) < 0) {
                KERROR_PUSH(_ldap_, 0, "failed to convert DN %s to DNS domain", dn);
                err = -1;
                break;
            }
            
            /* Complain if the DNS domain of the user doesn't match the forest
             * root.
             */
            if (strcasecmp(dns_dom, self->ad_forest)) {
                KERROR_SET(_ldap_, 0, "system user's domain (%s) does not match forest root (%s)",
                           dns_dom, self->ad_forest);
                err = -1;
                break;
            }
            
            /* Look for a DC. */
            if (kdldap_ad_DNS_get_DC(self, lst_pool, dns_dom, srv_lst) < 0) {
                KERROR_PUSH(_ldap_, 0, "failed to find a DC in %s", dns_dom);
                err = -1;
                break;
            }
            
            /* The search base is the forest root. */
            *search_base = kdldap_DNS_to_dn(pool, dns_dom);
        }
        /* Use the empty search base.  Domino doesn't deal with an
           empty search base so this is AD-specific.
         */
        else *search_base = "";

    } while (0);
    
    if (err) {
        apr_pool_destroy(lst_pool);
        *srv_lst = NULL;
        *search_base = NULL;
    }
    
    apr_pool_destroy(fn_pool);
    return err;
}

/** Return a DC server suitable to check a user login. */
int kdldap_servers_for_user(kdldap_servers *self,
                            apr_pool_t *pool,
                            const char *dn,
                            kdldap_servers_list **srv_lst) {
    apr_pool_t *lst_pool;
    int err = -1;

    apr_pool_create(&lst_pool, pool);

    if (self->use_dns) {    
        apr_pool_t *fn_pool;
        char *dns_dom;

        DEBUG(_log_ldap_, "Looking for AD servers associated to DN %s.", dn);
        
        apr_pool_create(&fn_pool, pool);

        if (kdldap_DN_to_DNS(fn_pool, dn, &dns_dom) < 0) 
            KERROR_PUSH(_ldap_, 0, "failed to convert DN %s to DNS domain");
        else {
            /* Check on what domain the login attempt should be performed. */
            DEBUG(_log_ldap_, "Looking for DC in domain %s.", dns_dom);
            
            /* Find the DC. */
            if (kdldap_ad_DNS_get_DC(self, lst_pool, dns_dom, srv_lst) < 0) 
                KERROR_PUSH(_ldap_, 0, "Failed to find a DC in %s", dns_dom);
            else
                err = 0;
        }

        if (err) {
            apr_pool_destroy(lst_pool);
            *srv_lst = NULL;
        }

        apr_pool_destroy(fn_pool);

        return err;
    }
    else {
        *srv_lst = apr_pmemdup(lst_pool, self->static_ldap_servers, sizeof(kdldap_servers_list));
        return 0;
    }
}

/** Return a LDAP server suitable for an anonymous login to obtain its
    RootDSE. */
int kdldap_servers_for_RootDSE(kdldap_servers *self, 
                               apr_pool_t *pool, 
                               kdldap_servers_list **srv_lst) {
    if (self->use_dns) 
        return kdldap_ad_DNS_get_DC(self, pool, self->ad_forest, srv_lst);   
    else {
        *srv_lst = apr_pmemdup(pool, self->static_ldap_servers, sizeof(kdldap_servers_list));
        return 0;
    }
}

kdldap_servers *kdldap_servers_new(apr_pool_t *pool, int use_sasl) {
    apr_pool_t *obj_pool;
    kdldap_servers *self;
    const char *ldap_dom, *ldap_ad_site;

    apr_pool_create(&obj_pool, pool);

    self = apr_pcalloc(obj_pool, sizeof(kdldap_servers));
    self->use_sasl = use_sasl;

    /* Get the AD forest to query. */
    ldap_dom = options_get_str("ldap.domain");
    if (ldap_dom == NULL || strlen(ldap_dom) == 0) 
        self->ad_forest = NULL;
    else
        self->ad_forest = apr_pstrdup(obj_pool, ldap_dom);

    ldap_ad_site = options_get_str("ldap.ad_site");
    if (ldap_ad_site == NULL || strlen(ldap_ad_site) == 0)
        self->ad_site = NULL;
    else
        self->ad_site = apr_pstrdup(obj_pool, ldap_ad_site);

    /* Check if we were told to search in the DNS. */
    if (!self->ad_forest || options_get_bool("ldap.domain_search") <= 0) {
        WARN(_log_ldap_, "LDAP server search will use static server list.");
        self->use_dns = 0;
    } else
        self->use_dns = 1;

    if (self->use_dns) {
        if ((self->ad_forest && self->use_dns) && !self->ad_site)
            WARN(_log_ldap_, "No AD site defined.  LDAP server queries will be done forest-wide.");
        else
            INFO(_log_ldap_, "AD site: %s.", self->ad_site);
    }

    /* Parse the static server list. */
    if (!self->use_dns) {
        if (kdldap_servers_load_static_servers(self, obj_pool, &self->static_ldap_servers) < 0) {
            KERROR_PUSH(_ldap_, 0, "error loading static LDAP server list");
            apr_pool_destroy(obj_pool);
            return NULL;
        }
    }
    else {
        /* ADNS initialization. */
        if (adns_init(&self->adns_state, adns_if_noenv, 0)) {
            self->adns_init = 0;
            KERROR_SET(_ldap_, 0, "cannot initialize adns");
            apr_pool_destroy(obj_pool);
            return NULL;
        } else
            self->adns_init = 1;    
    }

    apr_pool_cleanup_register(obj_pool, self, kdldap_servers_cleanup, kdldap_servers_cleanup);

    return self;
}

