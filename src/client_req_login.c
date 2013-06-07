/**
 * tbxsosd/client_req_login.c
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
 * Client login requests.
 *
 * Splitted of client.c for convenience.  Include normal and OTUT
 * login functions.
 *
 * @author François-Denis Gonthier
*/

#include <apr_pools.h>
#include <apr_strings.h>
#include <tagcrypt.h>
#include <kerror.h>
#include <assert.h>

#include "common/common_pkg.h"
#include "common/logid.h"
#include "common/config.h"
#include "libutils/logging.h"
#include "libutils/utils.h"
#include "libdb/db.h"

#include "client.h"
#include "shared.h"
#include "keys.h"

#if defined(REQUEST_OTUT_LOGIN) || defined(REQUEST_LOGIN)
static int kdclient_load_user_keys(struct kd_user *user) {
    int has_sig_pkey = 1, has_sig_skey = 2;
    int has_enc_pkey = 1, has_enc_skey = 2;
    int err;

    /* FIXME: Theorically, an user with just a private encryption key
       can encrypt, and an user with just a public encryption key can
       encrypt.  I'm just not sure we can assume the rest of the code
       follows that theorical pattern yet. */

    err = kdkey_get_sig_skey(user->pool, user->key_id, &user->sig_skey);
    if (err < 0) {
        KERROR_PUSH(_client_, 0, "error while trying to fetch private signature key "PRINTF_64"u", 
                    user->key_id);
        return -1;
    }
    else if (err == 0)
        has_sig_pkey = 0;

    err = kdkey_get_sig_pkey(user->pool, user->key_id, &user->sig_pkey);
    if (err < 0) {
        KERROR_PUSH(_client_, 0, "error while trying to fetch public signature key "PRINTF_64"u",
                    user->key_id);
        return -1;
    }
    else if (err == 0)
        has_sig_skey = 0;
    
    if ((has_sig_skey | has_sig_pkey) == 0) 
        WARN(_log_client_, 
             "User %s has no signature key pair.  This is odd.",
             user->username);
    else if ((has_sig_pkey | has_sig_skey) != 3) {
        KERROR_SET(_client_, 0, "incorrect signature key pair for user");
        return -1;
    }
    else user->caps |= (CAN_SIGN | CAN_POD);
    
    err = kdkey_get_enc_skey(user->pool, user->key_id, &user->enc_skey);
    if (err < 0) {
        KERROR_PUSH(_client_, 0, "error while trying to fetch private signature key "PRINTF_64"u",
                    user->key_id);
        return -1;
    } else if (err == 0)
        has_enc_skey = 0;

    err = kdkey_get_enc_pkey(user->pool, user->key_id, &user->enc_pkey);
    if (err < 0) {
        KERROR_PUSH(_client_, 0, "error while trying to fetch public encryption key "PRINTF_64"u",
                    user->key_id);
        return -1;
    }
    else if (err == 0)
        has_enc_pkey = 0;

    if ((has_enc_skey | has_enc_pkey) == 0) 
        WARN(_log_client_,
             "User %s has no encryption key pair.",
             user->username);
    else if (user->otut_info == NULL && (has_enc_skey | has_enc_pkey) != 3) {
        KERROR_SET(_client_, 0, "incorrect encryption key pair for user");
        return -1;
    } 
    else user->caps |= (CAN_ENCRYPT | CAN_APPS);

    return 0;
}
#endif

#ifdef REQUEST_OTUT_LOGIN
/** Process a request to login with an OTUT string. */
enum client_state kdclient_user_otut_login_request(kdclient *self, 
                                                   apr_pool_t *pkt_pool,
                                                   struct kdpacket *in_pkt,
                                                   struct kdpacket **out_pkt) {
    size_t otut_str_s;
    const char *otut_str;
    struct kd_login_result *res;
    enum client_state next_state = self->cstate;
    apr_pool_t *pool;

    apr_pool_create(&pool, pkt_pool);

    do {
        INFO(_log_client_, "Request: Login with OTUT.");

        /* Try to log-in. */
        kdpacket_get_raw(in_pkt, EL_OTUT_STRING, (void **)&otut_str, &otut_str_s);

        if (kddb_otut_login(pool, self->user, otut_str, otut_str_s, &res) < 0) {
            kdclient_error("Login attempt failed.");
            *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
            next_state = CSTATE_DROP_ACK;
        }

        if (res->rights == LOGIN_RIGHTS_OK) {
            INFO(_log_client_, "Request: Login with OTUT successful.");            
            *out_pkt = kdpacket_new(pkt_pool, PKT_LOGIN_OK_RES);
            kdpacket_set_str(*out_pkt, EL_LOGIN_TOKEN, NULL, 0);            
            next_state = CSTATE_CONNECTED_OTUT;        

            if (kdclient_load_user_keys(self->user) < 0) {
                kdclient_error("Key loading error.");
                next_state = CSTATE_DROP_ACK;
                break;
            }

            /* Set the default OTUT user license rights. */
            self->user->lic |= (CAN_SIGN | CAN_ENCRYPT);
        } 
        else {
            kdclient_error("OTUT login denied.");
            *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
            next_state = CSTATE_DROP_ACK;
        }

        /* Log the login event. */
        if (kddb_event(pool, kdsh_get_session_counter(), "otut-login", 0, NULL) < 0) 
            kdclient_warn("Failed to log 'otut-loging' event.");

    } while (0);

    apr_pool_destroy(pool);

    return next_state;
}
#endif // REQUEST_OTUT_LOGIN

#ifdef REQUEST_LOGIN
/** Process an user login request. */
enum client_state kdclient_login_user_request(kdclient *self, 
                                              apr_pool_t *out_pkt_pool,
                                              struct kdpacket *in_pkt,
                                              struct kdpacket **out_pkt)  {	
    int n;
    uint32_t is_password;
    enum client_state next_state = self->cstate;
    const char *username = NULL;
    const char *secret;
    apr_pool_t *pool;
    struct kd_login_result *login_result;
    struct kd_license lic;
    
    apr_pool_create(&pool, out_pkt_pool);

    assert(kdpacket_is_present(in_pkt, EL_LOGIN_USERNAME));
    assert(kdpacket_is_present(in_pkt, EL_LOGIN_PASSWORD));

    /* If the LOGIN_TYPE was not provided, the login is plain text. */
    if (kdpacket_is_present(in_pkt, EL_LOGIN_IS_PASSWORD))
        kdpacket_get_uint32(in_pkt, EL_LOGIN_IS_PASSWORD, &is_password);
    else
        is_password = 1;

    kdpacket_get_str(in_pkt, EL_LOGIN_USERNAME, &username, NULL);
    kdpacket_get_str(in_pkt, EL_LOGIN_PASSWORD, &secret, NULL);

    /* Log the clean login request. */
    INFO(_log_client_, "Request: Login [user: %s].", username);

    do {
        /* Ask the BD for the correct password. */
        n = kddb_login(pool, is_password, username, secret, self->user, &login_result);
        if (n < 0) {
            kdclient_error("Login error.");
            next_state = CSTATE_DROP_ACK;
            break;
        }
        
        switch (login_result->rights) {
        case LOGIN_RIGHTS_DENIED:
            kdclient_error("Login denied.");
            next_state = CSTATE_DROP_ACK;
            break;
            
        case LOGIN_RIGHTS_OK_NEW:
        case LOGIN_RIGHTS_OK:
            break;
        }

        /* Bail out? */
        if (next_state == CSTATE_DROP_ACK) break;

        /* Load the user keys. */
        if (kdclient_load_user_keys(self->user) < 0) {
            kdclient_error("Key loading error.");
            next_state = CSTATE_DROP_ACK;
            break;
        }

        /* The old licensing code was here. */
        self->user->lic = CAN_DO_EVERYTHING;

        /* If the flow reaches this point, that means the login is okay. */
        INFO(_log_client_, "Request: Login [user: %s] successful.", username);

        *out_pkt = kdpacket_new(out_pkt_pool, PKT_LOGIN_OK_RES);
        kdpacket_set_cstr(*out_pkt, EL_LOGIN_TOKEN, login_result->token);
        next_state = CSTATE_CONNECTED;

        /* Write basic statistics about the request. */
        struct event ev[1] = 
            {{.key = "username", .type = EV_VAR_STR, .val.str = username}};

        if (kddb_event(pool, kdsh_get_session_counter(), "login", 1, ev) < 0) 
            kdclient_warn("failed to log 'login' event."); 

        apr_pool_destroy(pool);

        return next_state;

    } while (0);

    apr_pool_destroy(pool);

    if (next_state == CSTATE_DROP_ACK)
        *out_pkt = kdpacket_new(out_pkt_pool, PKT_FAIL);

    return next_state;
}
#endif // REQUEST_LOGIN


