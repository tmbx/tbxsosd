/**
 * tbxsosd/libdb/ldapdb_ad.c
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
 */

#include <apr_pools.h>
#include <assert.h>
#include <kerror.h>
#include <stdlib.h>

#include "options.h"
#include "logid.h"
#include "logging.h"
#include "ldapdb.h"
#include "ldapdb_base.h"
#include "utils.h"

/* The following attributes are part of the partial attributes set (PAS) by
 * default:
 * - sAMAccountName
 * - userPrincipalName
 * - mail
 * - proxyAddresses
 * - displayName
 * - legacyExchangeDN
 * - objectSid
 *
 * The following attributes are NOT part of the PAS by default:
 * - tokenGroups
 * 
 * The sAMAccountName attribute is a token identifying the user to Windows. It
 * is unique per-domain.
 * 
 * The userPrincipalName attribute is a token of the form "leftpart@rightpart"
 * identifying the user to Windows. It is unique per forest. In the general case
 * there is no relation between the UPN and the sAMAccountName attribute or the
 * domain of the user.
 * 
 * The mail attribute contains the primary email address of the user.
 * 
 * The proxyAddresses contains the alternate email addresses of the user.
 * 
 * The displayName attribute contains the real name of the user.
 * 
 * The legacyExchangeDN attribute is used to convert Exchange addresses to SMTP
 * addresses.
 * 
 * The objectSid attribute is used to locate an object in AD. In our case, we
 * use this attribute to find the groups of which the user is a member.
 * 
 * The tokenGroups attribute contains the security identifiers (as in objectSid)
 * of the groups of which the user is a member. This attribute can only be
 * obtained by accessing a domain controller in the user's domain.
 * 
 * The global catalogs in an AD setup contain most of the information we need,
 * except the tokenGroups attribute. Additionally, when SASL is used, it is
 * possible to bind a user to a server only if the server owns the domain of
 * that user.
 * 
 * To cope with these limitations, we use two LDAP connections: the global
 * connection and the client connection. The global connection is obtained by
 * binding the system's user against a global catalog. If SASL is used, we use a
 * global catalog that controls the system user's domain. We use the global
 * connections to perform most of the LDAP searches. In the cases where we need
 * to obtain the tokenGroups attribute, or when we need to validate the
 * credentials of a client, we open the client connection by binding the client
 * against a domain controller that owns the domain of the client.
 */

/** Parse the username passed by the plugin.
 *
 * This function tries to split the user name provided into two parts, the part
 * before the last '@' and the part after the last '@'. If the user name does
 * not contain a '@' character, the last part is set to NULL.
 */
static int kdldap_ad_parse_username(apr_pool_t *pool, 
                                    const char *username, 
                                    char **first_part, 
                                    char **last_part) {
    const char *t, *last_amp = NULL;
    int amp_cnt = 0;

    t = username;
    if (strlen(t) < 1) {
        KERROR_SET(_ldap_, 0, "unable to parse username");
        return -1;
    }
    
    while ((t = strchr(t + 1, '@')) != NULL) {
        amp_cnt++;
        last_amp = t;
    }

    if (amp_cnt == 0) {
        *last_part = NULL;
        *first_part = apr_pstrdup(pool, username);
    }
    else {
        *last_part = apr_pstrdup(pool, last_amp + 1);
        *first_part = apr_pstrmemdup(pool, username, last_amp - username);
    }   

    return 0;
}

/** Convert a user name to a LDAP DN.
 *
 * This function puts NULL in dn if no match is found. It returns -1 on failure.
 */
static int kdldap_ad_find_username_dn(kdldap *self,
                                      apr_pool_t *pool,
                                      const char *username,
                                      char **dn,
				      char **sasl_username) {
    int err = 0, nb_match;
    apr_pool_t *fn_pool;
    const char *attrs[] = {"distinguishedName", "sAMAccountName", NULL};
    char *lp, *rp, *filter;
    struct kdldap_result *res;
    
    *dn = NULL;
    *sasl_username = NULL;

    apr_pool_create(&fn_pool, pool);
    
    do {
        /* Parse the user name. */
        if (kdldap_ad_parse_username(fn_pool, username, &lp, &rp) < 0)
            return -1;
        
        /* We don't have a right part. Search for sAMAccountName. */
        if (!rp) 
            filter = apr_psprintf(fn_pool, "(sAMAccountName=%s)", 
                                  kdldap_escape_string(fn_pool, lp, strlen(lp)));
        
        /* Search for the UPN. */
        else 
            filter = apr_psprintf(fn_pool, "(userPrincipalName=%s)",
                                  kdldap_escape_string(fn_pool, username, strlen(username)));
        
        /* Search for our attributes forest-wide. */
        res = kdldap_query(self->conn_catalog, fn_pool, 
                           LDAP_SCOPE_SUBTREE, self->ad_catalog_base, attrs, filter);
        if (res == NULL) {
            KERROR_PUSH(_ldap_, 0, "LDAP query error");
            err = -1;
            break;
        }
        
        nb_match = apr_hash_count(res->dn_attributes);
        
        /* We didn't find a unique user. */
        if (nb_match != 1) {
            if (! nb_match)
                KERROR_SET(_ldap_, 0, "unable to find user %s in the forest", username);
            else 
                KERROR_SET(_ldap_, 0, "unable to find user %s in the forest (%d ambiguous matches)",
                           username, nb_match);
        }
        
        /* Extract the DN and the sAMAccountName values. */        
        else {
            int j;
            
            for (j = 0; j < res->attr_names->nelts; j++) {
                char *attr_name = ((char **)res->attr_names->elts)[j];
                char *attr_value = ((char **)res->attributes->elts)[j];
	    
                if (attr_name == NULL) break;
	    
                else if (!strcmp(attr_name, "distinguishedName")) 
                    *dn = apr_pstrdup(pool, attr_value);
	    
                else if (!strcmp(attr_name, "sAMAccountName")) 
                    *sasl_username = apr_pstrdup(pool, attr_value);
            }

            /* Unlikely to happen, but still. */
            if (*sasl_username == NULL) {
                KERROR_SET(_ldap_, 0, "got a NULL answer searching for user's sAMAccountName");
                err = -1;
                break;
            }
                  
            if (*dn == NULL) {
                KERROR_SET(_ldap_, 0, "got a NULL answer searching for user's distinguishedName");
                err = -1;
                break;
            }
        }
        
    } while (0);
    
    apr_pool_destroy(fn_pool);

    return err;
}

static int kdldap_ad_get_profile_using_group_dn(kddbuser *user_db,
                                                const char *group_dn,
                                                uint64_t *prof_id,
                                                uint64_t *org_id,
                                                uint64_t *key_id) {
    int n = kddbuser_search_ldap_group(user_db, group_dn, prof_id, org_id, key_id);
    if (n < 0) 
        KERROR_PUSH(_ldap_, 0, "error searching LDAP group");

    return n;
}

/** Create a filter that will match all the user's group. */
static int kdldap_ad_get_group_filter(struct kdldap_conn *conn, 
                                      apr_pool_t *pool,
                                      const char *dn, char **flt_str) {
    apr_pool_t *fn_pool;
    const char *attrs[] = {"tokenGroups", NULL};
    struct iovec *flt_iovec;
    struct kdldap_result *res; 
    size_t nb_match, nb_iovec;
    char flt_start[] = "(|", sid_start[] = "(objectSid=", end[] = ")";
    char **group_sid;
    int i = 1;

    apr_pool_create(&fn_pool, pool);

    /* Get the group SIDs of the user. */
    res = kdldap_query(conn, fn_pool, LDAP_SCOPE_BASE, dn, attrs, NULL);

    if (res == NULL) {
        KERROR_PUSH(_ldap_, 0, "failed to get group membership information for DN %s");
        apr_pool_destroy(fn_pool);
        return -1;
    }

    nb_match = res->attributes->nelts;
    nb_iovec = nb_match * 3 + 2;

    flt_iovec = apr_pcalloc(fn_pool, sizeof(struct iovec) * nb_iovec);

    flt_iovec[0].iov_base = flt_start;
    flt_iovec[0].iov_len = strlen(flt_start);
    flt_iovec[nb_iovec - 1].iov_base = end;
    flt_iovec[nb_iovec - 1].iov_len = strlen(end);

    /* Make a big filter for all the SIDs. */
    while ((group_sid = apr_array_pop(res->attributes)) != NULL) {
        /* Calculate the size of the SID.  This is by Microsoft
           definition. */
        size_t sid_sz = 8 + (uint8_t)(*group_sid)[1] * 4;
        char *sid = kdldap_escape_string(fn_pool, *group_sid, sid_sz);

        flt_iovec[i + 0].iov_base = sid_start;
        flt_iovec[i + 0].iov_len = strlen(sid_start);
        flt_iovec[i + 1].iov_base = sid;
        flt_iovec[i + 1].iov_len = strlen(sid);
        flt_iovec[i + 2].iov_base = end;
        flt_iovec[i + 2].iov_len = strlen(end);

        i += 3;
    }

    *flt_str = apr_pstrcatv(pool, flt_iovec, nb_iovec, NULL);
    
    apr_pool_destroy(fn_pool);

    return 0;
}

/* FIXME: Connection caching.  Caching is difficult and just midly
 useful because the default working mode for this daemon is to fork
 for every clients. */
 
/** Returns 1 if the LDAP server we are connected on has group
    membership information, 0 if not and -1 on failure. */
static int kdldap_ad_has_group_info(kdldap *self, apr_pool_t *pool, const char *dn) {
    apr_pool_t *fn_pool;
    char *usr_dns_dom, *server_dns_dom;
    int ret;

    apr_pool_create(&fn_pool, pool);

    if (kdldap_DN_to_DNS(fn_pool, dn, &usr_dns_dom) < 0) {
        KERROR_PUSH(_ldap_, 0, "failed to convert user DN to DNS name");
        ret = -1;
    } 
    else {
        if (kdldap_DN_to_DNS(fn_pool, self->conn_catalog->server_base_dn, &server_dns_dom) < 0) {
            KERROR_PUSH(_ldap_, 0, "failed to convert KPS system DN to DNS name");
            ret = -1;            
        }
        else 
            ret = (strcasecmp(usr_dns_dom, server_dns_dom) == 0);
    }

    apr_pool_destroy(fn_pool);
    
    return ret;
}

static int kdldap_ad_bind_for_group_info(kdldap *self, 
                                         apr_pool_t *pool, 
                                         const char *dn, 
                                         struct kdldap_conn **conn) {
    kdldap_servers_list *srv_lst;
    struct kdldap_conn_params params;
    apr_pool_t *fn_pool;
    int err = 0;

    apr_pool_create(&fn_pool, pool);

    /* Check if the GC server we are connected on will have the
       information we need to find the user's profile on the KPS.
       Only a server (GC or not) in the DN's domain will have that
       information.  This will return the active connection if that
       connection is determined to contain the information needed. */
    
    do {
        int n = kdldap_ad_has_group_info(self, fn_pool, dn);
        
        if (n < 0) {
            KERROR_PUSH(_ldap_, 0, 
                        "failed to determine if LDAP server has group membership information");
            err = -1;
            break;
        }
        
        if (n > 0) {
            DEBUG(_log_ldap_, "%s:%d will have group membership information.", 
                  self->conn_catalog->server.host, self->conn_catalog->server.port);
            *conn = self->conn_catalog;
            break;
        }
        
        /* Get and connect to a DC server that has the information we need. */
        DEBUG(_log_ldap_, "%s:%d does not have group membership information.", 
              self->conn_catalog->server.host, self->conn_catalog->server.port);

        params.dn = self->sys_dn;
        params.username = self->sys_username;
        params.password = self->sys_password;
        params.use_sasl = self->conn_catalog->params.use_sasl;
        params.use_tls = self->conn_catalog->params.use_tls;

        if (kdldap_servers_for_user(self->servers, fn_pool, dn, &srv_lst) < 0) {
            KERROR_PUSH(_ldap_, 0, "failed to find a DC server with group information for DN %s", dn);
            err = -1;
            break;
        }
        
        if ((*conn = kdldap_bind(pool, &params, srv_lst)) == NULL) {
            KERROR_PUSH(_ldap_, 0, 
                        "failed to connect to a LDAP server with group "
                        "information for DN %s", dn);
            err = -1;
            break;
        }
        
    } while (0);

    apr_pool_destroy(fn_pool);
    return err;
}

/** Return the profile ID of the user.
 *
 * Returns 0 if the user is not part of any LDAP group, 1 on success, -1 on failure.
 */
static int kdldap_ad_get_profile(kdldap *self,
                                 apr_pool_t *pool,
                                 struct kdldap_conn *user_conn,
                                 kddbuser *user_db,
                                 const char *dn,
                                 uint64_t *prof_id,
                                 uint64_t *org_id,
                                 uint64_t *key_id) {
    apr_pool_t *fn_pool;
    struct kdldap_result *res;
    struct kdldap_conn *conn = NULL;
    const char *sid_attrs[] = {"distinguishedName", NULL};
    char *flt;
    int i, err = -1;

    DEBUG(_log_ldap_, "Checking DN %s group membership.", dn);

    apr_pool_create(&fn_pool, pool);
    
    do {
        if (user_conn == NULL) {
            DEBUG(_log_ldap_, "Need to connect to user DC to check group membership.");
            if (kdldap_ad_bind_for_group_info(self, fn_pool, dn, &conn) < 0) break;
        }
        else {
            DEBUG(_log_ldap_, "Using user DC connection to check group membership.");
            conn = user_conn;
        }

        if (kdldap_ad_get_group_filter(conn, fn_pool, dn, &flt) < 0) break;

        res = kdldap_query(self->conn_catalog, fn_pool, 
                           LDAP_SCOPE_SUBTREE, self->ad_catalog_base, sid_attrs, flt);
        if (res == NULL) {
            KERROR_PUSH(_ldap_, 0, "failed to find group membership for DN %s", dn);
            break;
        }
        
        err = 0;
        for (i = 0; i < res->attr_dn->nelts; i++) {
            const char *dn = ((const char **)res->attr_dn->elts)[i];
            int n = kdldap_ad_get_profile_using_group_dn(user_db, dn, prof_id, org_id, key_id);

            if (n == 1) {
                err = 1;
                break;
            }

            else if (n < 0) {
                KERROR_SET(_ldap_, 0, "failed to find matching groupDN in user");
                err = -1;
                break;
            }
        }
    
    } while (0);

    apr_pool_destroy(fn_pool);

    return err;
}

static int kdldap_ad_get_prim_email(kdldap *self,
                                    apr_pool_t *pool,
                                    const char *dn,
                                    char **prim_addr) {
    int err = 0;
    struct kdldap_result *ret;
    const char *attrs[] = {"mail", NULL};
    char **answer;

    do {
        /* LDAP query. */
        ret = kdldap_query(self->conn_catalog, pool, LDAP_SCOPE_BASE, dn, attrs, NULL);
        if (ret == NULL) {
            KERROR_PUSH(_ldap_, 0, "LDAP query error");
            err = -1;
            break;
        }

        /* Too many result for the query.  This is unlikely to
           happen. */
        if (ret->attributes->nelts > 1) {
            KERROR_SET(_ldap_, 0,
                       "primary email address query has returned more than one record");
            err = -1;
            break;
        }

        /* No results from the query. */
        if (ret->attributes->nelts == 0) {
            KERROR_SET(_ldap_, 0, "primary email address query has returned no record");
            err = -1;
            break;
        }

        /* Pop a result. */
        answer = apr_array_pop(ret->attributes);
        
        if (answer == NULL) {
            KERROR_SET(_ldap_, 0, "got a null answer searching for the primary email address");
            err = -1;
            break;
        }
        
        *prim_addr = apr_pstrdup(pool, *answer);

    } while (0);

    return err;
}

static int kdldap_ad_search_enc_pkey(kdldap *self,
                                     apr_pool_t *pool,
                                     kddbuser *user_db,
                                     const char *addr,
                                     uint64_t *prof_id,
                                     uint64_t *key_id) {
    int n, err = 0;
    struct kdldap_result *ret;
    const char filter_fmt[] = "(|(proxyAddresses=SMTP:%s)(mail=%s))";
    const char *mail_attributes[] = {"proxyAddresses", "mail", NULL};
    char *addr_esc, *filter_str;
    uint64_t pid, kid, oid;
    apr_pool_t *fn_pool;
    apr_hash_index_t *hi;
    char *dn;

    apr_pool_create(&fn_pool, pool);

    /* Format the filter. */
    addr_esc = kdldap_escape_string(fn_pool, addr, strlen(addr));
    filter_str = apr_psprintf(fn_pool, filter_fmt, addr_esc, addr_esc);

    /* This fetches all the email addresses of the user. */
    do {
        ret = kdldap_query(self->conn_catalog, fn_pool, LDAP_SCOPE_SUBTREE, 
                           self->ad_catalog_base, mail_attributes, filter_str);
        if (ret == NULL) {
            KERROR_PUSH(_ldap_, 0, "LDAP query error");
            err = -1;
            break;
        }

        /* No results. This is not fatal in this case. */
        if (ret->attributes->nelts == 0) break;

        /* If we found an user, we must check if he is allowable on
           the KPS.  We can find a key if we match an email address to
           a the profile of an user that can access the KPS. */
        hi = apr_hash_first(fn_pool, ret->dn_attributes);
        apr_hash_this(hi, (const void **)&dn, NULL, NULL);
        
        n = kdldap_ad_get_profile(self, fn_pool, NULL, user_db, dn, &pid, &oid, &kid);
       
        /* No result. */
        if (n == 0) {
            break;
        }
        /* Error. */
        else if (n < 0) {
            KERROR_SET(_ldap_, 0, "cannot match any public encryption key to %s", addr);
            err = -1;
            break;
        }
        /* Result. */
        else {
            if (prof_id != NULL) *prof_id = pid;
            if (key_id != NULL) *key_id = kid;
            err = 1;
            break;
        }
        
    } while (0);

    apr_pool_destroy(fn_pool);

    return err;
}

/** Check if an user address matches some in the list. */
static int kdldap_ad_is_email_allowed(kdldap *self,
                                      apr_pool_t *pool,
                                      struct kd_user *info,
                                      const char *addr_list,
                                      int *is_allowed,
                                      char **email_matched) {
    struct kdldap_result *ret;
    const char filter_fmt[] = "(|(proxyAddresses=SMTP:%s)(mail=%s))";
    const char *attrs[] = {"proxyAddresses", "mail", NULL};
    char *filter_str;
    apr_pool_t *fn_pool, *loop_pool;
    char *addr_esc, **addrs = NULL;
    int i, err = 0;

    /* We need to tokenize the string, create a pool for it. */
    apr_pool_create(&fn_pool, pool);
    apr_pool_create(&loop_pool, fn_pool);
    apr_tokenize_to_argv(addr_list, &addrs, fn_pool);

    /* Proceed to the LDAP query. */
    for (i = 0; addrs[i] != NULL; i++) {
        apr_pool_clear(loop_pool);

        DEBUG(_log_ldap_, "Looking for user email addresses %s.", addrs[i]);

        /* Format the filter string. */
        addr_esc = kdldap_escape_string(loop_pool, addrs[i], strlen(addrs[i]));
        filter_str = apr_psprintf(loop_pool, filter_fmt, addr_esc, addr_esc);

        ret = kdldap_query(self->conn_catalog, loop_pool, LDAP_SCOPE_BASE, 
                           info->user_dn, attrs, filter_str);
        if (ret == NULL) {
            err = -1;
            KERROR_PUSH(_ldap_, 0, "LDAP query error");
            break;
        }

        if (ret->attributes->nelts > 0)
            break;

        ret = NULL;
    }

    if (ret != NULL && ret->attributes->nelts > 0) {
        *is_allowed = 1;
        if (email_matched != NULL)
            *email_matched = apr_pstrdup(pool, addrs[i]);
        ret = NULL;
    }
    else *is_allowed = 0;

    apr_pool_destroy(fn_pool);
    return err;
}

static int kdldap_ad_get_name(kdldap *self,
                              apr_pool_t *pool,
                              struct kd_user *user,
                              char **name) {
    int err = 0;
    struct kdldap_result *ret;
    const char *attrs[] = {"displayName", NULL};
    char **answer;

    do {
        /* LDAP query. */
        ret = kdldap_query(self->conn_catalog, pool, LDAP_SCOPE_BASE, 
                           user->user_dn, attrs, NULL);

        if (ret == NULL) {
            KERROR_PUSH(_ldap_, 0, "LDAP query error");
            err = -1;
            break;
        }

        /* Too many result for the query.  This is unlikely to
           happen. */
        if (ret->attributes->nelts > 1) {
            KERROR_SET(_ldap_, 0, "full name query has returned more than one record");
            err = -1;
            break;
        }

        /* Pop a result. */
        answer = apr_array_pop(ret->attributes);

	/* Convert the name from UTF-8 to ISO-8859-1. */
        if (answer != NULL) {
            if (name != NULL) {
                if (utf8_to_iso88591(pool, *answer, name)) {
                    KERROR_SET(_ldap_, 0, "failed to convert name to ISO-8859-1");
                    err = -1;
                    break;
                }
            }
	}
        else
            KERROR_SET(_ldap_, 0, "got a null answer searching for the user name");

    } while (0);

    return err;
}

/** Search a legacyExchangeDN in the LDAP database.
 *
 * legacyExchangeDN are sent by Microsoft Outlook as targets adresses
 * of persons the database.  We need to return the email address
 * corresponding to that person in the LDAP database.
 */
static int kdldap_ad_convert_address(kdldap *self,
                                     apr_pool_t *pool,
                                     const char *addr,
                                     char **email) {
    int err = 0;
    apr_pool_t *fn_pool;
    struct kdldap_result *res;
    const char filter_fmt[] = "(legacyExchangeDN=%s)";
    const char *attrs[] = {"mail", NULL};
    const char *real_addr;
    char *filter_str;
    char **answer = NULL;

    if (strstr(addr, "/ex=") == NULL) {
        KERROR_SET(_ldap_, 0, "Don't know how to convert that address: %s.", addr);
        return -1;
    }

    apr_pool_create(&fn_pool, pool);

    /* Format the filter. */
    real_addr = kdldap_escape_string(fn_pool, addr + 4, strlen(addr + 4));
    filter_str = apr_psprintf(fn_pool, filter_fmt, real_addr);

    do {
        res = kdldap_query(self->conn_catalog, fn_pool, LDAP_SCOPE_SUBTREE, 
                           self->ad_catalog_base, attrs, filter_str);
        if (res == NULL) {
            KERROR_PUSH(_ldap_, 0, "LDAP query error");
            err = -1;
            break;
        }

        if (res->attributes->nelts == 1) {
            answer = apr_array_pop(res->attributes);
            
            if (answer != NULL) {
                if (email != NULL) {
                    *email = apr_pstrdup(pool, *answer);
                    strlwr(*email);
                    break;
                }
            }
            else {
                KERROR_SET(_ldap_, 0, "got a null answer searching for legacyExchangeDN");
                err = -1;
                break;
            }
        }
        
        KERROR_SET(_ldap_, 0, "query returned no answer throughout the forest");
        err = -1;
        
    } while (0);
    
    apr_pool_destroy(fn_pool);

    return err;
}

static int kdldap_ad_sys_bind(kdldap *self, apr_pool_t *pool) {
    struct kdldap_conn_params params;
    kdldap_servers_list *cat_srv_lst;
    apr_pool_t *fn_pool;
    char *search_base;
    int err = -1;

    apr_pool_create(&fn_pool, pool);
            
    DEBUG(_log_ldap_, "Creating global catalog connection.");
    
    do {
        /* FIXME: In the case of SASL: you are using sys_dn to search for global
         * catalogs and also, the system DN is used in the SASL bind procedure
         * (i.e. ldap_sasl_bind_s(ldap_conn, dn, mech, &client_creds, NULL,
         * NULL, &server_creds);
         *
         * Experimental tests suggest that the DN is indeed ignored, but why?
         */
        
        /* Prepare the catalog connection. */
        if (kdldap_servers_for_catalog(self->servers, fn_pool, 
                                       self->sys_dn, &cat_srv_lst, &search_base) < 0) {
            KERROR_PUSH(_ldap_, 0, "failed to get catalog server list for KPS login");
            break;
        }
        
        /* Copy the search base if it was obtained from the DNS query. */
        self->ad_catalog_base = apr_pstrdup(self->pool, search_base);

        params.dn = self->sys_dn;
        params.username = self->sys_username;
        params.password = self->sys_password;
        params.use_sasl = self->conn_catalog->params.use_sasl;
        params.use_tls = self->conn_catalog->params.use_tls;

        /* Just rebind as this connexion is already connected. */
        if (kdldap_rebind(&self->conn_catalog, &params, cat_srv_lst) < 0) {
            KERROR_PUSH(_ldap_, 0, "system login failed");
            break;
        }
        
        err = 0;
        
    } while (0);
        
    apr_pool_destroy(fn_pool);
    return err;
}

static int kdldap_ad_user_bind(kdldap *self,
                               apr_pool_t *pool,
                               struct kd_user *user,
                               kddbuser *user_db,
                               const char *username,
                               const char *password,
                               uint64_t *prof_id,
                               uint64_t *org_id,
                               uint64_t *key_id) {
    int err = 0;
    int n = 0;
    apr_pool_t *fn_pool;
    char *dn;
    char *sasl_username;
    kdldap_servers_list *srv_lst;
    struct kdldap_conn *user_conn = NULL;
    struct kdldap_conn_params params;

    apr_pool_create(&fn_pool, pool);

    do {
        if (kdldap_ad_find_username_dn(self, fn_pool, username, &dn, &sasl_username) < 0) {
            KERROR_PUSH(_ldap_, 0, "search for full name from username failed: %s", username);
            err = -1;
            break;
        }
        
        if (dn == NULL) {
            err = -1;
            break;
        }

        user->user_dn = apr_pstrdup(user->pool, dn);
        
        params.dn = user->user_dn;
        params.username = sasl_username;
        params.password = password;
        params.use_sasl = self->conn_catalog->params.use_sasl;
        params.use_tls = self->conn_catalog->params.use_tls;

        if (kdldap_servers_for_user(self->servers, fn_pool, user->user_dn, &srv_lst) < 0) {
            KERROR_PUSH(_ldap_, 0, "failed to find a AD server to check the user credentials");
            err = -1;
            break;
        }
        
        /* Bind and connect to that place.  The bind is new and will
           be destroyed at the end of that function. */

        if (password == NULL || (user_conn = kdldap_bind(fn_pool, &params, srv_lst)) != NULL) {
            n = kdldap_ad_get_profile(self, fn_pool,
                                      user_conn, user_db, user->user_dn, prof_id, org_id, key_id);
            if (n <= 0) {
                KERROR_PUSH(_ldap_, 0, 
                            "login failed, user is not part of a "
                            "group that has access to the KPS");
                err = -1;
                break;
            }
        } else {
            KERROR_PUSH(_ldap_, 0, "login failed");
            err = -1;
            break;
        }
    } while (0);

    apr_pool_destroy(fn_pool);

    return err;
}

struct kdldap_functions kdldap_ad_functions = {
    .ldap_is_email_allowed = kdldap_ad_is_email_allowed,
    .ldap_search_enc_pkey = kdldap_ad_search_enc_pkey,
    .ldap_get_prim_email = kdldap_ad_get_prim_email,
    .ldap_get_name = kdldap_ad_get_name,
    .ldap_user_bind = kdldap_ad_user_bind,
    .ldap_sys_bind = kdldap_ad_sys_bind,
    .ldap_convert_address = kdldap_ad_convert_address
};
