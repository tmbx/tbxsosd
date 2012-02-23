/**
 * tbxsosd/libdb/ldapdb_base.c
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

#include <ldap.h>
#include <sasl/sasl.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <ktools.h>
#include <math.h>

#include "logid.h"
#include "logging.h"
#include "ldapdb.h"
#include "ldapdb_base.h"
#include "ldapdb_utils.h"
#include "ldapdb_servers.h"
#include "options.h"
#include "utils.h"

/** Allocate a new LDAP result structure. */
struct kdldap_result *kdldap_result_new(apr_pool_t *pool) {
    struct kdldap_result *r;

    r = apr_pcalloc(pool, sizeof(struct kdldap_result));
    r->attr_dn = apr_array_make(pool, 0, sizeof(char *));
    r->attr_names = apr_array_make(pool, 0, sizeof(char *));
    r->attributes = apr_array_make(pool, 0, sizeof(char *));
    r->dn_attributes = apr_hash_make(pool);

    return r;
}

static const sasl_callback_t client_callbacks[] = {
    { SASL_CB_GETREALM, NULL, NULL },
    { SASL_CB_USER, NULL, NULL },
    { SASL_CB_AUTHNAME, NULL, NULL },
    { SASL_CB_PASS, NULL, NULL },
    { SASL_CB_ECHOPROMPT, NULL, NULL },
    { SASL_CB_NOECHOPROMPT, NULL, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

/** LDAP connexion cleanup. */
apr_status_t kdldap_cleanup(void *data) {
    struct kdldap_conn *conn = (struct kdldap_conn *)data;

    /* Unbind. */
    if (conn->ldap) {
        DEBUG(_log_ldap_, "Disconnecting from %s:%d", conn->server.host, conn->server.port);
        ldap_unbind(conn->ldap);
        conn->ldap = NULL;
    }

    return APR_SUCCESS;
}

/** LDAP connexion cleanup for child process.  Dummy cleanup since we
    don't want to destroy the LDAP connection of the parent. */
apr_status_t kdldap_child_cleanup(void *data) {
    data = data;
    return APR_SUCCESS;
}

static int kdldap_sasl_interact(sasl_conn_t *conn,
                                const char *username,
                                const char *password,
                                sasl_interact_t *si,
                                struct berval *server_creds,
                                struct berval *client_creds) {
    int sasl_err = 0;
    sasl_interact_t *si_tmp = si;

    /* Iterate over every request. */
    for (; si_tmp->id != SASL_CB_LIST_END; si_tmp++) {
        switch (si_tmp->id) {

            /* Authentication name. */
        case SASL_CB_AUTHNAME:
            si_tmp->result = username;
            si_tmp->len = strlen(username);
            break;

            /* Password. */
        case SASL_CB_PASS:
            si_tmp->result = password;
            si_tmp->len = strlen(password);
            break;

            /* SASL_CB_USER or something else: ignore. */
        default:
            si_tmp->result = NULL;
            si_tmp->len = 0;
        }
    }

    /* The information is filled, get the creds. */
    sasl_err = sasl_client_step(conn,
                                server_creds->bv_val,
                                server_creds->bv_len,
                                &si,
                                (const char **)&client_creds->bv_val,
                                (unsigned *)&client_creds->bv_len);
    return sasl_err;
}

static int kdldap_sasl_digest_md5_bind(LDAP *ldap_conn,
                                       const char *server_name,
                                       const char *dn,
                                       const char *username,
                                       const char *password) {
    int err = 0, ldap_err = 0, sasl_err = 0;
    const char *mech = "DIGEST-MD5";
    const char *choosen_mech = NULL;
    sasl_conn_t *sasl_conn = NULL;
    sasl_interact_t *si = NULL;
    struct berval client_creds;
    struct berval *server_creds = NULL;

    DEBUG(_log_ldap_, "LDAP SASL bind with username %s.", username);

    do {
        sasl_err = sasl_client_new("ldap", server_name, NULL, NULL, client_callbacks, 0, &sasl_conn);
        if (sasl_err != SASL_OK) break;
        else sasl_err = 0;

        /* Start the SASL negociation. */
        sasl_err = sasl_client_start(sasl_conn, "DIGEST-MD5", NULL,
                                     (const char **)&client_creds.bv_val,
                                     (unsigned *)&client_creds.bv_len,
                                     &choosen_mech);
        /* For DIGEST-MD5, there is no reason to request interaction
           after that. */
        if (sasl_err != SASL_CONTINUE) break;
        else sasl_err = 0;

        ldap_err = ldap_sasl_bind_s(ldap_conn, dn, mech, &client_creds, NULL, NULL, &server_creds);

        /* Bind-in-progress means the SASL login can continue. */
        if (ldap_err != LDAP_SASL_BIND_IN_PROGRESS) break;
        else ldap_err = 0;

        /* Give SASL what the server gave us, so that we know what
           we can send back to the server. */
        sasl_err = sasl_client_step(sasl_conn,
                                    server_creds->bv_val,
                                    server_creds->bv_len,
                                    &si,
                                    (const char **)&client_creds.bv_val,
                                    (unsigned *)&client_creds.bv_len);

        /* SASL_INTERACT means SASL needs some informations to
           continue. */
        if (sasl_err == SASL_INTERACT) {
            sasl_err = kdldap_sasl_interact(sasl_conn,
                                            username,
                                            password,
                                            si,
                                            server_creds,
                                            &client_creds);
            /* Check if we got told to continue after interaction. */
            if (sasl_err != SASL_CONTINUE) break;
            else sasl_err = 0;
        }
        else {
            /* Check we are correctly done. */
            if (sasl_err != SASL_OK) break;
            else sasl_err = 0;
        }

        ber_bvfree(server_creds);

        ldap_err = ldap_sasl_bind_s(ldap_conn,
                                    NULL,
                                    mech,
                                    &client_creds,
                                    NULL,
                                    NULL,
                                    &server_creds);
        if (ldap_err) break;
        else ldap_err = 0;

        ber_bvfree(server_creds);

        /* At this point, no error == success. */
        break;

    } while (1);

    /* Check if the error is from OpenLDAP. */
    if (ldap_err != 0) {
        kdldap_paranoid_push_error(ldap_conn, ldap_err);
        KERROR_PUSH(_ldap_, 0, "LDAP login error");
        err = -1;
    }

    /* Check if the error is from SASL. */
    if (sasl_err != 0) {
        KERROR_SET(_ldap_, 0, sasl_errstring(sasl_err, NULL, NULL));
        KERROR_PUSH(_ldap_, 0, "SASL login error");
        err = -1;
    }

    sasl_dispose(&sasl_conn);

    return err;
}

struct kdldap_result *kdldap_query(struct kdldap_conn *conn,
                                   apr_pool_t *pool,
                                   int scope,
                                   const char *base,
                                   const char **attr,
                                   const char *input_filter) {
    int err;
    LDAPMessage *msg = NULL;
    LDAPMessage *entry = NULL;
    struct kdldap_result *r;
    const char *default_filter = "(objectClass=*)";
    const char *filter;

    r = kdldap_result_new(pool);

    if (input_filter == NULL)
        filter = default_filter;
    else
        filter = input_filter;

    err = ldap_search_s(conn->ldap, base, scope, (char *)filter, (char **)attr, 0, &msg);
    if (err) {
        ldap_msgfree(msg);
        KERROR_SET(_ldap_, 0, ldap_err2string(err));
        KERROR_PUSH(_ldap_, 0, "search on %s failed", base);
        return NULL;
    }

    for (entry = ldap_first_entry(conn->ldap, msg);
         entry != NULL;
         entry = ldap_next_entry(conn->ldap, entry)) {
        char *attr = NULL, *dn, *_dn;
        BerElement *ber = NULL;
        apr_array_header_t *dn_attrs = NULL;

        /* Check if an entry exists for this dn.  I don't want to
           keep libldap-allocated strings around. */
        _dn = ldap_get_dn(conn->ldap, entry);
        if (_dn != NULL) {
            dn = apr_pstrdup(pool, _dn);
            ldap_memfree(_dn);

            /* Also create a list of attributes per-DN using a hashtable.
               Initialize the hashtable item if required. */
            if (apr_hash_get(r->dn_attributes, dn, APR_HASH_KEY_STRING) == NULL) {
                dn_attrs = apr_array_make(pool, 0, sizeof(char *));
                apr_hash_set(r->dn_attributes, dn, APR_HASH_KEY_STRING, dn_attrs);
            }
            else {
                void *p = apr_hash_get(r->dn_attributes, dn, APR_HASH_KEY_STRING);
                dn_attrs = (apr_array_header_t *)p;
            }
        } else {
            KERROR_SET(_ldap_, 0, "failed to convert DN to string");
            return NULL;
        }

        for (attr = ldap_first_attribute(conn->ldap, entry, &ber);
             attr != NULL;
             attr = ldap_next_attribute(conn->ldap, entry, ber)) {
            struct berval **values = ldap_get_values_len(conn->ldap, entry, attr);
            int nb_val = ldap_count_values_len(values);

            if (nb_val) {
                int i;

                for (i = 0; i < nb_val; i++) {
                    char **v, *s;

                    /* Push the attribute DN in the global list. */
                    v = apr_array_push(r->attr_dn);
                    *v = dn;

                    /* Push the attribute name in the global list. */
                    s = apr_pstrdup(pool, attr);
                    v = apr_array_push(r->attr_names);
                    *v = s;

                    /* Push the attribute value in the global list. */
                    s = apr_pstrmemdup(pool, values[i]->bv_val, values[i]->bv_len);
                    v = apr_array_push(r->attributes);
                    *v = s;

                    /* Push the attribute value in the local list
                       for the object */
                    v = apr_array_push(dn_attrs);
                    *v = s;
                }
            }

            ldap_value_free_len(values);
            ldap_memfree(attr);
            if (err) break;
        }

        if (ber) ber_free(ber, 0);
        if (err) break;
    }

    ldap_msgfree(msg);

    return r;
}

static void kdldap_init_set_debug() {
    int err, ldap_debug;

    /* Set the debug value of LDAP.  This default to 0. */
    ldap_debug = options_get_uint32("ldap.debug");

    err = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &ldap_debug);
    if (err)
        WARN(_log_ldap_, "Failed to set LDAP_OPT_DEBUG_LEVEL.");
}

/* Handle LDAP extensions we might need. */
static void kdldap_check_extensions(struct kdldap_conn *conn, const char *ext) { 
    /*const char fast_bind_oid[] = "1.2.840.113556.1.4.1781"*/
    const char start_tls_oid[] = "1.3.6.1.4.1.1466.20037";

    /* TLS. */
    if (!conn->can_tls && strcasecmp(ext, start_tls_oid) == 0) {
        DEBUG(_log_ldap_, "LDAP server has TLS support.");
        conn->can_tls = 1;
    }   
}

/* Check if the LDAP type makes sense. */
static int kdldap_check_ldap_type(struct kdldap_conn *conn) {
    switch (conn->ldap_type) {
    case LDAP_TYPE_MS_AD:
        DEBUG(_log_ldap_, "LDAP server type is: Microsoft Active Directory (any version)."); 
        break;

    case LDAP_TYPE_LOTUS:
        DEBUG(_log_ldap_, "LDAP server type: Lotus Domino (any version)"); 

        /* Lotus supports SSL, but not TLS, despite advertising TLS
           support. */
        if (conn->ldap_type == LDAP_TYPE_LOTUS) {
            DEBUG(_log_ldap_, "Server is Lotus Domino.  We can't use TLS.");
            conn->can_tls = 0;
        }

        break;

    case LDAP_TYPE_OTHER:
        KERROR_SET(_ldap_, 0, "unknown LDAP server type");
        return -1;
    }                   

    return 0;
}

static int kdldap_check_conn(struct kdldap_conn *conn) {
    apr_pool_t *fn_pool;
    const char *attrs[] = {"supportedSASLmechanisms",
                           "supportedExtension",
                           "dnshostname",
                           "highestCommittedUSN",
                           "vendorname",
                           "defaultNamingContext",
                           NULL};
    struct kdldap_result *res;
    char **key, **val;
    int err;

    err = ldap_bind_s(conn->ldap, NULL, NULL, LDAP_AUTH_SIMPLE);   
    if (err) {
        kdldap_paranoid_push_error(conn->ldap, err);
        KERROR_PUSH(_ldap_, 0, "failed to check supported server options");
        return -1;
    }

    apr_pool_create(&fn_pool, conn->pool);

    res = kdldap_query(conn, fn_pool, LDAP_SCOPE_BASE, "", attrs, NULL);
    if (!res) {
        KERROR_PUSH(_ldap_, 0, "failed to obtain information from LDAP server");
        apr_pool_destroy(fn_pool);
        return -1;
    }
    else {        
        conn->ldap_type = LDAP_TYPE_OTHER;

        while ((key = apr_array_pop(res->attr_names)) != NULL) {
            val = apr_array_pop(res->attributes);

            /* Check for SASL mechanisms. */
            if (strcasecmp(*key, "supportedSASLmechanisms") == 0) {
                if (!conn->can_digest && strcasecmp(*val, "digest-md5") == 0) {
                    DEBUG(_log_ldap_, "LDAP server has SASL DIGEST-MD5 support.");
                    conn->can_digest = 1;
                }
            }
            
            /* Grab the DNS hostname. */
            else if (strcasecmp(*key, "dnsHostName") == 0) {
                conn->ldap_dnshostname = apr_pstrdup(conn->pool, *val);
                DEBUG(_log_ldap_, "LDAP server DNS hostname for SASL: %s", *val);
            }
            
            /* Check for supported extensions. */
            else if (strcasecmp(*key, "supportedExtension") == 0) 
                kdldap_check_extensions(conn, *val);

            /* Lotus Domino has a vendorName attribute. */
            else if (strcasecmp(*key, "vendorname") == 0) {
                if (strcasestr(*val, "lotus") != NULL) {
                    if (conn->ldap_type == LDAP_TYPE_OTHER) 
                        conn->ldap_type = LDAP_TYPE_LOTUS;
                    
                    /* Reset to unknown in case of conflicting clues. */
                    else conn->ldap_type = LDAP_TYPE_OTHER;
                }
            }
            
            /* The highestCommittedUSN attribute seem to be Active
               Directory specific. */            
            else if (strcasecmp(*key, "highestCommittedUSN") == 0) {
                if (conn->ldap_type == LDAP_TYPE_OTHER) 
                    conn->ldap_type = LDAP_TYPE_MS_AD;

                /* Reset to unknown in case of conflicting clues. */
                else conn->ldap_type = LDAP_TYPE_OTHER;
            }

            /* Default naming context for this server. */
            else if (strcasecmp(*key, "defaultNamingContext") == 0) {
                conn->server_base_dn = apr_pstrdup(conn->pool, *val);
                DEBUG(_log_ldap_, "LDAP server default naming context: %s", 
                      conn->server_base_dn);
            }                
        }
    }

    if (kdldap_check_ldap_type(conn) < 0)
        return -1;

    if (!conn->server_base_dn) {
        const char *dn_base;

        dn_base = options_get_str("ldap.dn_base");
        
        if (dn_base == NULL || strlen(dn_base) == 0) {
            KERROR_SET(_ldap_, 0, 
                       "no LDAP DN base specified, and could not find it automatically");
            return -1;
        }
        conn->server_base_dn = apr_pstrdup(conn->pool, dn_base);
    }

    apr_pool_destroy(fn_pool);

    return 0;
}

static int kdldap_init_set_protocol(struct kdldap_conn *conn) {
    int err, desired_version = 3;

    /* Require LDAPv3. */
    err = ldap_set_option(conn->ldap, LDAP_OPT_PROTOCOL_VERSION, &desired_version);
    if (err) {
        kdldap_paranoid_push_error(conn->ldap, err);
        KERROR_PUSH(_ldap_, 0, "failed to set LDAP version");
        return -1;
    }

    return 0;
}

static void kdldap_init_set_timeout(struct kdldap_conn *conn) {
    int err;
    float conf_timeout;
    struct timeval tv = {1, 0};

    /* Be wary that MDNS totally breaks this delay because it takes
       over name resolution.  That means if you have Avahi installed,
       which is becoming more common, this will take more time that
       the value of ldap.timeout. */
    conf_timeout = options_get_float("ldap.timeout");

    if (conf_timeout) {
        tv.tv_sec = (long) conf_timeout;
        tv.tv_usec = (conf_timeout - tv.tv_sec) * 1000000;
    }

    err = ldap_set_option(conn->ldap, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (err) 
        WARN(_log_ldap_, "Failed to set LDAP network timeout.");
}

static int kdldap_init_set_misc_options(struct kdldap_conn *conn) {  
    int err;

    err = ldap_set_option(conn->ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (err) {
        kdldap_paranoid_push_error(conn->ldap, err);
        KERROR_PUSH(_ldap_, 0, "failed to turn off LDAP referrals");
        return -1;
    }

    return 0;
}

static int kdldap_init_set_sasl(struct kdldap_conn *conn) {
    int max_ssf = 1, sasl_err, err;

    /* Initialize the SASL library. */
    sasl_err = sasl_client_init(NULL);
    if (sasl_err != SASL_OK) {
        KERROR_PUSH(_ldap_, 0, "failed to initialize SASL library: %d", sasl_err);
        return -1;
    }

    /* Set minimum possible security factor for SASL.  One of
       Active Directory or OpenLDAP doesn't want to encrypt
       twice.  That's admitedly useless.  Setting maxssf to 1
       makes sure SASL will only be used for authentication. */
    err = ldap_set_option(conn->ldap, LDAP_OPT_X_SASL_SSF_MAX, &max_ssf);
    if (err) {
        kdldap_paranoid_push_error(conn->ldap, err);
        KERROR_PUSH(_ldap_, 0, "failed to set max SASL security factor");
        return -1;
    }

    DEBUG(_log_ldap_, "SASL enabled on LDAP connection.");

    return 0;
}

static int kdldap_init_set_tls(struct kdldap_conn *conn) {
    int err, req_cert = LDAP_OPT_X_TLS_NEVER;

    /* Disable certificate verification.  We have SASL after all. */
    err = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &req_cert);
    if (err) {
        kdldap_paranoid_push_error(conn->ldap, err);
        KERROR_PUSH(_ldap_, 0, "failed to set TLS option");
        return -1;
    }

    /* Start TLS on the connection. */
    err = ldap_start_tls_s(conn->ldap, NULL, NULL);
    if (err) {
        kdldap_paranoid_push_error(conn->ldap, err);
        KERROR_PUSH(_ldap_, 0, "failed to start TLS");
        return -1;
    }

    DEBUG(_log_ldap_, "TLS enabled on LDAP connection.");

    return 0;
}

/** Initialize the LDAP connection options. */
static int kdldap_init_conn(struct kdldap_conn *conn, struct kdldap_conn_params *params) {

    if (kdldap_init_set_protocol(conn) < 0) 
        return -1;
    if (kdldap_init_set_misc_options(conn) < 0)
        return -1;

    if (conn->can_digest && params->use_sasl && kdldap_init_set_sasl(conn) < 0) 
        return -1;

    if (conn->can_tls && params->use_tls && kdldap_init_set_tls(conn) < 0) 
        return -1;

    return 0;
}

/** LDAP system login.
 *
 * This is a low-level bind which simply tries to bind to the system
 * DN on an LDAP server.
 */
static int kdldap_try_bind(struct kdldap_conn *conn,
                           struct kdldap_conn_params *params) {
    int err = 0;
    int is_rootdse;

    is_rootdse = (params->dn == NULL && params->username == NULL && params->password == NULL);

    if (params->use_sasl && !is_rootdse) {
        DEBUG(_log_ldap_, "LDAP SASL DIGEST-MD5 bind with username %s.", params->dn);
        err = kdldap_sasl_digest_md5_bind(conn->ldap,
                                          conn->ldap_dnshostname,
                                          params->dn,
                                          params->username,
                                          params->password);
    }
    else {
        if (!is_rootdse)
            DEBUG(_log_ldap_, "LDAP simple bind with DN %s.", params->dn);
        else
            DEBUG(_log_ldap_, "LDAP simple bind on root DSE.");
        err = ldap_simple_bind_s(conn->ldap, params->dn, params->password);
    }

    /* SASL login. */
    if (err && params->use_sasl && is_rootdse) {
        KERROR_PUSH(_ldap_, 0, "SASL login with %s failed", params->username);
        return -1;
    }
    /* Simple bind. */
    else if (err && !is_rootdse) {
        kdldap_paranoid_push_error(conn->ldap, err);
        KERROR_PUSH(_ldap_, 0, "login with %s failed", params->dn);
        return -1;
    }
    /* Simple bind on RootDSE. */
    else if (err && is_rootdse) {
        kdldap_paranoid_push_error(conn->ldap, err);
        KERROR_PUSH(_ldap_, 0, "bind on RootDSE failed");
        return -1;
    }

    DEBUG(_log_ldap_, "LDAP bind successful.");

    return err;
}

static int kdldap_try_connect(struct kdldap_conn *conn,
                              const struct kdldap_server *srv,
                              struct kdldap_conn_params *params) {
    conn->ldap = ldap_init(srv->host, srv->port);

    /* Try to connect to the server. */
    if (conn->ldap == NULL) {
        KERROR_SET(_ldap_, 0, "LDAP cannot connect to %s:%d", srv->host, srv->port);
        return -1;
    }

    /* Set preliminary global options. */
    kdldap_init_set_debug();
    kdldap_init_set_timeout(conn);

    /* Check the capability of the connection by binding to the
       RootDSE. */
    if (kdldap_check_conn(conn) < 0) {
        KERROR_PUSH(_ldap_, 0, "failed to check LDAP server capabilities");
        return -1;
    }

    /* Initialize the connection parameters. */
    if (kdldap_init_conn(conn, params) < 0) {
        KERROR_PUSH(_ldap_, 0, "failed to initialize LDAP connection with demanded options");
        return -1;
    }

    return 0;
}

/** Try to bind to any server in the list with the passed user
    credentials. */
struct kdldap_conn *kdldap_bind(apr_pool_t *pool,
                                struct kdldap_conn_params *params,
                                kdldap_servers_list *srv_lst) {
    const struct kdldap_server *h;
    struct kdldap_conn *conn;
    apr_pool_t *obj_pool;
    int err = -1;

    apr_pool_create(&obj_pool, pool);

    conn = apr_pcalloc(obj_pool, sizeof(struct kdldap_conn));
    conn->pool = obj_pool;

    apr_pool_cleanup_register(obj_pool, conn, kdldap_cleanup, kdldap_child_cleanup);

    /* Loop until we find a server that can deal with us. */
    while ((h = kdldap_servers_list_current(srv_lst)) != NULL) {
        INFO(_log_ldap_, "Trying to connect to %s:%i.", h->host, h->port);

        conn->server.host = apr_pstrdup(conn->pool, h->host);
        conn->server.port = h->port;

        err = kdldap_try_connect(conn, h, params);

        if (err == 0) {
            err = kdldap_try_bind(conn, params);

            /* We don't try the next server on authentication error. */
            if (err == -1) {
                kdclient_error("Failed to authenticate to %s:%i", h->host, h->port);
                kerror_reset();
            } 
            break;
        }
        else {
            kdclient_warn("Failed to connect to %s:%i.", h->host, h->port);
            kerror_reset();
        }

        kdldap_servers_list_next(srv_lst);
    }

    if (err) {
        KERROR_SET(_ldap_, 0, "failed to connect to any LDAP servers");
        apr_pool_destroy(obj_pool);
        return NULL;
    }
    else {
        /* Got the server? Save the connection information. */

        INFO(_log_ldap_, "Connected to %s:%i.", h->host, h->port);

        if (conn->params.dn)
            conn->params.dn = apr_pstrdup(conn->pool, params->dn);

        if (conn->params.username)
            conn->params.username = apr_pstrdup(conn->pool, params->username);

        if (conn->params.password)
            conn->params.password = apr_pstrdup(conn->pool, params->password);

        conn->params.use_sasl = params->use_sasl;
        conn->params.use_tls = params->use_tls;

        kerror_reset();
    }

    return conn;
}

/** Change the connection parameters.
 *
 * This may reconnect to another LDAP server but will try to figure
 * out if it's needed.  In case reconnecting to another server is not
 * needed, the connection is rebound with new credentials.
 */
int kdldap_rebind(struct kdldap_conn **conn,
                  struct kdldap_conn_params *params,
                  kdldap_servers_list *srv_lst) {
    const struct kdldap_server *h;
    int do_reconnect = 1, do_rebind = 1;

    /* Check if the credentials are the same. */
    if ((*conn)->params.username && strcmp((*conn)->params.username, params->username) == 0 &&
        (*conn)->params.password && strcmp((*conn)->params.password, params->password) == 0 &&
        (*conn)->params.dn && strcmp((*conn)->params.dn, params->dn) == 0)
        do_rebind = 0;

    /* Search if the server we are connected on is in the list of
       servers we can connect to. */
    while ((h = kdldap_servers_list_current(srv_lst)) != NULL) {
        if (h->port == (*conn)->server.port && strcmp(h->host, (*conn)->server.host) == 0)
            do_reconnect = 0;

        kdldap_servers_list_next(srv_lst);
    }

    /* Reconnect implies rebind. */
    if (do_reconnect) do_rebind = 0;

    /* Connect to another LDAP server. */
    if (do_reconnect) {
        apr_pool_t *tmp_pool;

        DEBUG(_log_ldap_, "Rebinding.  Will try another server.");

        tmp_pool = (*conn)->pool;
        apr_pool_clear((*conn)->pool);

        /* After this, *conn is no longer valid. */

        kdldap_servers_list_reset(srv_lst);

        if ((*conn = kdldap_bind(tmp_pool, params, srv_lst)) == NULL) {
            KERROR_PUSH(_ldap_, 0, "failed to rebind LDAP connection");
            return -1;
        }
    }

    /* Just rebind to another place on the same connection. */
    if (do_rebind) {
        DEBUG(_log_ldap_, "Rebinding.  Will rebind on the same server.");

        if (kdldap_try_bind(*conn, params) < 0) {
            KERROR_PUSH(_ldap_, 0, "failed to rebind LDAP connection");
            return -1;
        }
    }

    if (!do_rebind && !do_reconnect)
        DEBUG(_log_ldap_, "Rebinding. Nothing to do.");

    return 0;
}
