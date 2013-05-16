/**
 * tbxsosd/libdb/db.c
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

#include <assert.h>
#include <apr_pools.h>
#include <apr_user.h>
#include <kerror.h>

#include "config.h"
#include "options.h"
#include "common.h"
#include "db.h"
#include "logid.h"
#include "ldapdb.h"
#include "db_psql.h"
#include "db_user.h"
#include "db_pkey.h"
#include "db_skey.h"
#include "db_login.h"
#include "logging.h"

static kddb *db;

static void kddb_validate_kdsql(kdsql *s) {
    if (s && kdsql_is_connected(s) && kdsql_noop(s) < 0) {
        WARN(_log_db_, "Invalidating connection to database %s.", s);
        kdsql_disconnect(s);            
    }   
}

void kddb_validate() {   
    if (db->login_db && db->login_db->db) 
        kddb_validate_kdsql(db->login_db->db);        

    if (db->user_db && db->user_db->db) 
        kddb_validate_kdsql(db->user_db->db);

    if (db->otut_db && db->otut_db->db)
        kddb_validate_kdsql(db->otut_db->db);

    if (db->skey_db && db->skey_db->db)
        kddb_validate_kdsql(db->skey_db->db);

    if (db->pkey_db && db->pkey_db->db)
        kddb_validate_kdsql(db->pkey_db->db);

    if (db->event_db && db->event_db->db)
        kddb_validate_kdsql(db->event_db->db);
}

/** Connect a single database. */
static kdsql *kddb_connect_db(apr_pool_t *pool, enum kddb_auth_mode auth_mode) {
    kdsql *conn;

    /* Connect to the database. */
    conn = kdsql_new(pool);    
    conn->db_host = options_get_str("db.host");

    switch (auth_mode) {
    case DB_AUTH_CURRENT_CREDS_MODE: {
        apr_uid_t uid;
        apr_gid_t gid;
        char *username;

        DEBUG(_log_db_, "Connecting using current username.");

        apr_uid_current(&uid, &gid, pool);
        apr_uid_name_get(&username, uid, pool);

        conn->db_username = username;
        conn->db_password = "";
        break;
    }

    case DB_AUTH_ADMIN_MODE:
        DEBUG(_log_db_, "Connecting to %s using administrator username/password.", conn->db_host);
        conn->db_username = options_get_str("db.admin_username");
        conn->db_password = options_get_str("db.admin_password");
        break;

    case DB_AUTH_NORMAL_MODE:
        DEBUG(_log_db_, "Connecting to %s using normal username/password.", conn->db_host);
        conn->db_username = options_get_str("db.username");
        conn->db_password = options_get_str("db.password");
        break;
    }

    conn->db_name = "teamboxd_db";
    conn->db_port = options_get_uint16("db.port");
    conn->db_timeout = options_get_uint32("db.timeout");
    
    if (kdsql_connect(conn) < 0) 
        return NULL;

    return conn;
}

int kddb_open(apr_pool_t *pool, enum kddb_auth_mode auth_mode) {
    kdsql *main_conn;
    int err = -1;

    kdsql_init(pool);

    db = apr_pcalloc(pool, sizeof(kddb));

    do {
        main_conn = kddb_connect_db(pool, auth_mode);
        if (!main_conn) break;

        db->login_db = kddblogin_new(pool, main_conn);
        if (!db->login_db) break;
        db->user_db = kddbuser_new(pool, main_conn, 0, 0);
        if (!db->user_db) break;
        db->skey_db = kddbskey_new(pool, main_conn);
        if (!db->skey_db) break;
        db->pkey_db = kddbpkey_new(pool, main_conn);
        if (!db->pkey_db) break;
        db->event_db = kddbevent_new(pool, main_conn);
        if (!db->event_db) break;
        db->otut_db = kddbotut_new(pool, main_conn);
        if (!db->otut_db) break;

        db->use_ldap = options_get_bool("ldap.enabled");

        if (db->use_ldap) {
            if ((db->ldap_db = kdldap_new(pool)) == NULL) {
                KERROR_PUSH(_db_, 0, "cannot connect to LDAP server");
                break;
            }
        }

        err = 0;
    } while (0);

    return err;
}

/** Ordinary database login.
 *
 * Ordinary database login is quite simple too.
 */
static int kddb_pwd_db_login(apr_pool_t *pool,
                             const char *username,
                             const char *password,
                             struct kd_login_result **res) {  

    if (kddblogin_pwd_login(db->login_db, pool, username, password, res) < 0)
        return -1;

    return 0;
}

/** Token login.
 *
 * Token login is the simplest login procedure that is available.  It
 * doesn't care about LDAP.
 */
static int kddb_token_login(apr_pool_t *pool,
                            const char *username,
                            const char *token,
                            struct kd_user *info,
                            struct kd_login_result **res) {
    uint64_t prof_id, key_id, org_id;
    int n;

    /* If this server is configured to use LDAP, we need to check the
       user credentials. */
    if (db->use_ldap) {
        /* Attempt an user-bind through LDAP. */
        if (kdldap_user_bind(db->ldap_db, 
                             pool,
                             info,
                             db->user_db, 
                             username,
                             NULL,
                             &prof_id,
                             &org_id,
                             &key_id) < 0) 
            return -1;
    }

    /** Do the proper login attempt with the token on the database. */
    n = kddblogin_token_login(db->login_db, pool, username, token, res);

    /* In the case of LDAP, the profile ID cannot be obtained through
       token login. */
    if (db->use_ldap) {
        (*res)->prof_id = prof_id;
        (*res)->org_id = org_id;
    }

    return (n < 0 ? -1 : 0);
}

/** LDAP login.
 *
 * This is the hardest.  This needs to be done in a transaction in
 * order for us to keep a consistent view on the login_slots table.
 */
static int kddb_pwd_ldap_login(apr_pool_t *pool,
                               const char *username,
                               const char *password,
                               struct kd_user *info,
                               struct kd_login_result **res) {
    uint64_t prof_id;
    uint64_t key_id;
    uint64_t org_id;

    do {
        /* Attempt an user-bind on the Active Directory. */
        if (kdldap_user_bind(db->ldap_db, 
                             pool,
                             info,
                             db->user_db, 
                             username,
                             password,
                             &prof_id,
                             &org_id,
                             &key_id) < 0) 
            break;

        /* Insert the login in the login slots if necesary and
           generate a token for the login. */
        if (kddblogin_external(db->login_db, pool, username, org_id, res) < 0) {
            KERROR_PUSH(_db_, 0, "user token registration failed");
            break;
        }                            

        (*res)->prof_id = prof_id;
        (*res)->org_id = org_id;
        
        return 0;

    } while (0);

    return -1;
}

/** Match the provided username and password with one in the database
 * 
 * This function sets login_result to 1 if the login has been
 * successful.
 */
int kddb_login(apr_pool_t *pool,
               int is_password,
               const char *username, 
               const char *secret,
               struct kd_user *user,
               struct kd_login_result **res) {   
    int n = -1, login_denied, login_ok;
   
    if (kddblogin_start(db->login_db) < 0) {
        KERROR_PUSH(_db_, 0, "failed to begin login transaction");
        return -1;
    }

    *res = apr_pcalloc(pool, sizeof(struct kd_login_result));  

    do {
        /* If a token has been provided, login using it.  This is the same
           both backends. */
        if (!is_password) 
            n = kddb_token_login(pool, username, secret, user, res);
    
        /* If what has been provided is not a token and if we don't use
           LDAP, try an ordinary password login. */
        else if (!db->use_ldap)
            n = kddb_pwd_db_login(pool, username, secret, res);

        /* If what has been provided is not a token and if we use LDAP, we
           need to check the usernames and passwords with the LDAP then
           generate the token with the database. */
        else
            n = kddb_pwd_ldap_login(pool, username, secret, user, res);

        login_ok = ((*res)->rights == LOGIN_RIGHTS_OK || (*res)->rights == LOGIN_RIGHTS_OK_NEW);
        login_denied = ((*res)->rights == LOGIN_RIGHTS_DENIED);

        if (n == 0) {
            if (login_ok) {
                user->type = KD_USER_NORMAL;
                user->username = apr_pstrdup(user->pool, username);
                user->prof_id = (*res)->prof_id;
                user->org_id = (*res)->org_id;
            }            
        }
        else if (n < 0) {
            KERROR_PUSH(_db_, 0, "login error");
            break;
        }
        /* End the login transaction. */
        if (kddblogin_succeed(db->login_db) < 0) {
            KERROR_PUSH(_db_, 0, "failed to commit login transaction");
            return -1;
        }

        /* If we know the user will proceed further, load the keys. */
        if (login_ok) {
            if (kddbuser_get_key_id(db->user_db, user->prof_id, &user->key_id) < 0) {
                KERROR_PUSH(_db_, 0, 
                            "failed to find key ID for profile %llu", user->prof_id);
                return -1;
            }            

            /* Find the full name and the primary email address of the
               user in case other process need it. */
            if (kddb_get_full_name(user->pool, user, &user->full_name) < 0) {
                WARN(_log_db_, "Failed to obtain full name for user.");
                kerror_reset();
            }
            if (kddb_get_prim_email(user->pool, user, &user->primary_email_addr) < 0) {
                WARN(_log_db_, "Failed to obtain primary email for user.");
                kerror_reset();
            }
            
            /* Find the archiving address of the user. */
            if (kddbuser_get_org_data_from_prof_id(db->user_db, 
                                                   user->pool, 
                                                   user->prof_id,
                                                   &user->org) < 0) {
                KERROR_PUSH(_db_, 0, "failed to obtain archiving address");
                return -1;
            }

            if (user->primary_email_addr)
                DEBUG(_log_db_, "User: %s <%s> logged in.", 
                      user->full_name, user->primary_email_addr);
            else
                DEBUG(_log_db_, "User: %s (with no email address) logged in.",
                      user->full_name);
        }     

        return 0;
  
    } while (0);

    if (kddblogin_fail(db->login_db) < 0) {
        KERROR_PUSH(_db_, 0, "failed to rollback LDAP login transaction");
        return -1;
    }

    return n;
}

/** Check whether an email address of the user is present in addr_list */
int kddb_is_email_allowed(apr_pool_t *parent_pool, 
                          struct kd_user *user,
                          const char *addr_list,
                          int *is_allowed,
                          char **email_matched) {
    int n;

    if (!db->use_ldap) {
        n = kddbuser_is_email_allowed(db->user_db, 
                                      parent_pool,
                                      user->prof_id, 
                                      addr_list, 
                                      is_allowed, 
                                      email_matched);      
        if (n < 0) {
            KERROR_PUSH(_db_, 0, "failed to search for user email through DB");
            return -1;
        }    
    }
    else {
        n = kdldap_is_email_allowed(db->ldap_db, 
                                    parent_pool, 
                                    user, 
                                    addr_list, 
                                    is_allowed,
                                    email_matched);
        if (n < 0) {
            KERROR_PUSH(_db_, 0, "failed to search for user email through LDAP");
            return -1;
        }
    }

    return 0;
}

int kddb_import_license(const char *kdn, const char *license_data) {
    if (kddbuser_import_license(db->user_db, kdn, license_data) < 0) {
        KERROR_PUSH(_db_, 0, "failed to import license");
        return -1;
    }

    return 0;
}

/** Return the active seats count. */
int kddb_count_seats(uint64_t org_id, int *seats_count) {
    if (kddblogin_count_seats(db->login_db, org_id, seats_count) < 0) {
        KERROR_PUSH(_db_, 0, "failed to get active seat count");
        return -1;
    }

    return 0;
}

int kddb_get_seats_allocation(uint64_t org_id, int *seats_count) {
    if (kddblogin_get_seats_allocation(db->login_db, org_id, seats_count) < 0) {
        KERROR_PUSH(_db_, 0, "failed to get seats allocation");
        return -1;
    }

    return 0;
}

int kddb_reserve_seat(const char *username, uint64_t org_id, uint64_t *parent_org_id) {
    if (kddblogin_reserve_seat(db->login_db, username, org_id, parent_org_id) < 0) {
        KERROR_PUSH(_db_, 0, "failed to reserve a seat for the user");
        return -1;
    }

    return 0;
}

int kddb_get_org_data_from_kdn(apr_pool_t *pool, const char *kdn, struct kd_organization *org) {
    if (kddbuser_get_org_data_from_kdn(db->user_db, pool, kdn, org) < 0) {
        KERROR_PUSH(_db_, 0, "failed to get organization data");
        return -1;
    }

    return 0;
}

/** Return an SMTP address given a foreign mail address.  Use the
    default_addr provided as the real_addr in case conversion is
    impossible due to the DB backend not using LDAP. */
int kddb_convert_address(apr_pool_t *pool, 
                         const char *addr, 
                         const char *default_addr, 
                         char **real_addr) {   
    int err = 0;

    if (!db->use_ldap && default_addr) 
        *real_addr = apr_pstrdup(pool, default_addr);

    else if (!db->use_ldap && !default_addr) {
        KERROR_SET(_db_, 0, 
                   "cannot convert Exchange mailbox %s to SMTP "
                   "without default or LDAP support", addr);
        err = -1;
    }

    else if (db->use_ldap) 
        err = kdldap_convert_address(db->ldap_db, pool, addr, real_addr);
    
    if (!err)
        DEBUG(_log_db_, "Exchange mailbox %s SMTP address: %s", addr, *real_addr);

    return err;
}

int kddb_get_prim_email(apr_pool_t *pool, struct kd_user *info, char **prim_addr) {
    int n;

    if (db->use_ldap) 
        n = kdldap_get_prim_email(db->ldap_db, pool, info, prim_addr);
    else 
        n = kddbuser_get_prim_email(db->user_db, pool, info->prof_id, prim_addr);

    if (n < 0) {
        KERROR_PUSH(_db_, 0, "failed to fetch user primary email address");
        return -1;
    }
    else
        DEBUG(_log_db_, "User %s email address: %s.", info->username, *prim_addr);

    return 0;
}

static apr_status_t kddb_otut_clean(void *data) {
    struct tagcrypt_otut *otut = (struct tagcrypt_otut *)data;
    tagcrypt_otut_clean(otut);
    
    return APR_SUCCESS;
}

int kddb_otut_login(apr_pool_t *pool, 
                    struct kd_user *user, 
                    const char *otut_str,
                    size_t otut_str_s,
                    struct kd_login_result **res) {
    kbuffer *otut_buf = kbuffer_new();

    DEBUG(_log_db_, "OTUT login attempted.");

    *res = apr_pcalloc(pool, sizeof(struct kd_login_result));

    if (kddbotut_login(db->otut_db, 
                       otut_str,
                       otut_str_s,
                       &user->key_id,
                       res) < 0) {
        KERROR_PUSH(_otut_, 0, "failed to login with OTUT");        
        return -1;
    }

    /* OTUT login is allowed or flat-out denied. */
    if ((*res)->rights == LOGIN_RIGHTS_DENIED) {
        DEBUG(_log_db_, "OTUT login failed.");
        return 0;
    }

    /* If the login has been successful, extricate the data from the
       OTUT. */
    user->type = KD_USER_OTUT;
    user->otut_info = apr_pcalloc(user->pool, sizeof(struct kd_otut));
    user->otut_info->otut_str = apr_pstrmemdup(user->pool, otut_str, otut_str_s);
    user->otut_info->otut_str_s = otut_str_s;
    
    /* Create the tagcrypt OTUT object. */
    user->otut_info->otut = apr_pcalloc(user->pool, sizeof(struct tagcrypt_otut));
    tagcrypt_otut_init(user->otut_info->otut);
    kbuffer_write(otut_buf, (uint8_t *)otut_str, otut_str_s);
    tagcrypt_otut_realize(otut_buf, user->otut_info->otut);
    kbuffer_destroy(otut_buf);   

    /* Make up an username.  It may be needed later on. */
    user->username = apr_pstrmemdup(user->pool,
                                    (const char *)user->otut_info->otut->addr->data,
                                    user->otut_info->otut->addr->len);

    apr_pool_cleanup_register(user->pool, 
                              user->otut_info->otut, 
                              kddb_otut_clean, 
                              kddb_otut_clean);

    DEBUG(_log_db_, "OTUT login succeeded.");

    return 0;
}

int kddb_otut_ticket_store(uint64_t key_id, struct timeval *tm) {
    DEBUG(_log_db_, "Storing OTUT ticket for key ID: %llu", key_id);

    if (kddbotut_store_ticket(db->otut_db, key_id, tm) < 0) {
        KERROR_PUSH(_otut_, 0, "failed to store OTUT ticket");
        return -1;
    }

    return 0;
}

int kddb_otut_store(const char *otut_str, 
                    size_t otut_str_s, 
                    uint64_t key_id,
                    int nb_use, 
                    int nb_tries) {
    if (kddbotut_store(db->otut_db, 
                       otut_str,
                       otut_str_s,
                       key_id,
                       nb_use, 
                       nb_tries) < 0) {
        KERROR_PUSH(_otut_, 0, "failed to store OTUT");
        return -1;
    }

    DEBUG(_log_db_, "Stored OTUT (key ID %llu, nb_uses: %d, nb_tries: %d).", key_id, nb_use, nb_tries);

    return 0;
}

int kddb_otut_fail(const char *otut_str, 
                   size_t otut_str_s, 
                   int *nb_usages_left, 
                   int *nb_fails_left) {
    if (kddbotut_fail(db->otut_db, 
                      otut_str, 
                      otut_str_s,
                      nb_usages_left,
                      nb_fails_left) < 0) {
        KERROR_PUSH(_dpkg_, 0, "failed to register failure for OTUT");
        return -1;
    }

    DEBUG(_log_db_, "Registered OTUT failure (nb_uses %d, nb_tries: %d).", *nb_usages_left, *nb_fails_left);

    return 0;
}

int kddb_otut_success(const char *otut_str, 
                      size_t otut_str_s,
                      int *nb_usages_left,
                      int *nb_fails_left) {
    if (kddbotut_succeed(db->otut_db, 
                         otut_str,
                         otut_str_s,
                         nb_usages_left,
                         nb_fails_left) < 0) {
        KERROR_PUSH(_dpkg_, 0, "failed to register success for OTUT");
        return -1;
    }

    DEBUG(_log_db_, "Registered OTUT success (nb_uses %d, nb_tries: %d).", *nb_usages_left, *nb_fails_left);

    return 0;
}

int kddb_otut_check(const char *otut_str, size_t otut_str_s, uint32_t *nb_uses) {
    if (kddbotut_check_otut(db->otut_db, otut_str, otut_str_s, nb_uses) < 0) {
        KERROR_PUSH(_dpkg_, 0, "failed to check OTUT validity");
        return -1;
    }

    DEBUG(_log_db_, "Checked OTUT validity.");

    return 0;
}

int kddb_get_full_name(apr_pool_t *pool, 
                       struct kd_user *user, 
                       char **full_name) {
    int n;

   
    if (!db->use_ldap) {
        n = kddbuser_get_name(db->user_db, pool, user->prof_id, full_name);
    }
    else 
        n = kdldap_get_name(db->ldap_db, pool, user, full_name);            
    
    if (n < 0) {
        KERROR_PUSH(_db_, 0, "failed to get user full name");
        return -1;
    }
    else
        DEBUG(_log_db_, "Full name for user %s: %s", user->username, *full_name);

    return 0;
}

int kddb_event(apr_pool_t *pool,
               uint64_t session_id,
               const char *event_name, 
               size_t nvar, 
               struct event *event_vars) {
    int error = 0;
    apr_pool_t *ev_pool;
    char hostname[255];
    
    apr_pool_create(&ev_pool, pool);
    
    do {
	size_t i;
	const char ***vars = apr_palloc(ev_pool, sizeof(char ***) * nvar);
	
	/* Format the variables. */
	for (i = 0; i < nvar; i++) {
	    vars[i] = apr_palloc(ev_pool, sizeof(char **) * 2);
	    vars[i][0] = apr_pstrdup(ev_pool, event_vars[i].key);

	    switch (event_vars[i].type) {
	    case EV_VAR_STR:
		vars[i][1] = apr_pstrdup(ev_pool, event_vars[i].val.str);
		break;
	    case EV_VAR_UINT32:
		vars[i][1] = apr_psprintf(ev_pool, "%u", (uint32_t)event_vars[i].val.uint32);
		break;
	    case EV_VAR_UINT64:
		vars[i][1] = apr_psprintf(ev_pool, "%llu", (uint64_t)event_vars[i].val.uint64);
		break;
	    }
	}

        if (gethostname(hostname, sizeof(hostname)) < 0) {
            KERROR_PUSH(_db_, 0, "failed to obtain the hostname");
            error = -1;
            break;
        }

	if (kddbevent_add(db->event_db, hostname, session_id, event_name, nvar, vars) < 0) {
	    KERROR_PUSH(_db_, 0, "failed to add event");    
	    error = -1;
	    break;
	}
	    
    } while (0);
    
    apr_pool_destroy(ev_pool);

    return error;
}

/* Returns -1 on error, 0 on missing key, 1 on success. */
int kddb_fetch_key(apr_pool_t *pool, 
                   uint64_t key_id,
                   enum kdkey_type ktype, 
                   struct kdkey_info **ki) {
    int err = 0;

    /** Only those types of keys can be stored in the database. */
    assert(ktype == SKEY_ENCRYPTION ||
           ktype == SKEY_SIGNATURE  ||
           ktype == PKEY_ENCRYPTION ||
           ktype == PKEY_SIGNATURE);

    switch (ktype) {
    case SKEY_ENCRYPTION:
        DEBUG(_log_db_, "Fetching private encryption key %llu.", key_id);

    case SKEY_SIGNATURE:
        if (ktype == SKEY_SIGNATURE)
            DEBUG(_log_db_, "Fetching private signature key %llu.", key_id);

        err = kddbskey_get(db->skey_db, pool, ktype, key_id, ki);
        if (err < 0) {
            KERROR_PUSH(_db_, 0, "failed to get secret key");
            return -1;
        }
        break;

    case PKEY_ENCRYPTION:
        DEBUG(_log_db_, "Fetching public encryption key %llu.", key_id);

    case PKEY_SIGNATURE:
        if (ktype == PKEY_SIGNATURE)
            DEBUG(_log_db_, "Fetching public signature key %llu.", key_id);

        err = kddbpkey_get(db->pkey_db, pool, ktype, key_id, ki);
        if (err < 0) {
            KERROR_PUSH(_db_, 0, "failed to get public key");
            return -1;
        }
        break;
        
    default: 
        /* Caught by assert earlier. */
        abort();
    }

    return err;
}

int kddb_search_enc_pkey(apr_pool_t *key_pool, 
                         const char *addr, 
                         struct kdkey_info **ki) {
    uint64_t key_id;
    uint64_t prof_id;
    apr_pool_t *pool;
    int n, r = 0;

    DEBUG(_log_db_, "Searching for encryption key for %s.", addr);

    apr_pool_create(&pool, key_pool);

    do {
        /* Search in the DB. */
        if (!db->use_ldap) {
            /* First fetch the key ID matching that address. */
            n = kddbuser_search_email(db->user_db, addr, &prof_id, &key_id);
            if (n < 0) {
                KERROR_PUSH(_db_, 0, "Database error while search for key.");        
                r = -1;
                break;
            } 
            /* The query returned no results for that particular address. */
            else if (n == 0) {
                r = 0;
                break;
            }
            
            r = 1;
        }
        /* Search with LDAP. */
        else {
            char *real_addr;

            /* Convert the address if needed. */
            if (addr[0] == '/') {
                if (kddb_convert_address(pool, addr, NULL, &real_addr) < 0) {
                    r = -1;
                    break;
                }
            } else real_addr = (char *)addr;

            n = kdldap_search_enc_pkey(db->ldap_db, 
                                       pool, 
                                       db->user_db,
                                       real_addr,
                                       &prof_id, &key_id);
            if (n < 0) {
                KERROR_PUSH(_db_, 0, "Cannot get key for address %s.", addr);
                r = -1;
                break;
            }
            /* The query returned no results for that particular address. */
            else if (n == 0) {
                r = 0;
                break;
            }
        }
    
        /* Fetch the key we found above. */
        if (kddbpkey_get(db->pkey_db, key_pool, PKEY_ENCRYPTION, key_id, ki) < 0) {
            KERROR_PUSH(_db_, 0, "Cannot get key for key id %llu.", key_id);        
            r = -1;
            break;
        }
        
        r = 1;
    } while (0);

    apr_pool_destroy(pool);

    return r;
}

