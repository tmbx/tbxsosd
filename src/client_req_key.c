/**
 * tbxsosd/client_req_key.c
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
 * Client key requests
 *
 * Splitted of client.c for convenience.  Include signature key and
 * encryption key fetch functions.
 *
 * @author François-Denis Gonthier
*/

#include <kerror.h>
#include <kstr.h>

#include "common/common_keys.h"
#include "common/logid.h"
#include "libutils/logging.h"
#include "libutils/utils.h"
#include "libdb/db.h"

#include "client.h"
#include "client_req_key.h"
#include "shared.h"
#include "keys.h"

#ifdef REQUEST_GETENC
enum client_state kdclient_get_enc_key_request(kdclient *self,
                                               apr_pool_t *pkt_pool,
                                               struct kdpacket *in_pkt,
                                               struct kdpacket **out_pkt) {    
    int n, found_keys = 0;
    size_t i, nb;
    const char *str = NULL;
    size_t str_s = 0;
    const char empty_key[] = "";
    struct kdpacket *op = NULL;
    enum client_state next_state = self->cstate;
    struct kdkey_info *ki;
    kbuffer *signed_key = kbuffer_new();
    apr_pool_t *pool;

    apr_pool_create(&pool, pkt_pool);

    do {
        /* Read the number of item from the packet. */
        nb = kdpacket_get_list_len(in_pkt, EL_ADDRESS_ARRAY);

        /* Prepare the return packet. */
        op = kdpacket_new(pkt_pool, PKT_GET_ENC_KEY_RES);
        kdpacket_set_list(op, EL_KEY_DATA_ARRAY, nb);
	kdpacket_set_list(op, EL_SUBSCRIBER_ARRAY, nb);
    	
        /* Loop to ask for all the addresses. */
        for (i = 0; i < nb; i++) {
            kbuffer_reset(signed_key);
            kdpacket_get_list_item(in_pkt, EL_ADDRESS_ARRAY, i, (void **)&str, &str_s);
              
            n = kddb_search_enc_pkey(pool, str, &ki);

            /* If n == 0, nothing was found for that key. */
            if (n == 0) {
                kdpacket_set_list_item(op, EL_KEY_DATA_ARRAY, i, empty_key, strlen(empty_key));
		kdpacket_set_list_item(op, EL_SUBSCRIBER_ARRAY, i, "", 0);
    	    }
	    
            /* If n < 0, there was a error searching for the key and we must bail out. */
            else if (n < 0) {
                kdclient_error("Error while searching for %s.", str);
                *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
                next_state = CSTATE_DROP_ACK;
                goto err;
            }
            /* Otherwise, something has been found. */
            else {
                if (in_pkt->major >= 3) {
                    if (kdkey_sign_key(ki, signed_key, 1)) {                
                        kdclient_error("Failed to sign the public key "PRINTF_64"u.", ki->key_id);
                        *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
                        next_state = CSTATE_DROP_ACK;
                        goto err;
                    }
                    
                    kdpacket_set_list_item(op, EL_KEY_DATA_ARRAY, i, signed_key->data, signed_key->len);
		    kdpacket_set_list_item(op, EL_SUBSCRIBER_ARRAY, i, ki->owner, strlen(ki->owner));
                }          
                else {
                    kdpacket_set_list_item(op, EL_KEY_DATA_ARRAY, i, ki->data, strlen(ki->data));
		    kdpacket_set_list_item(op, EL_SUBSCRIBER_ARRAY, i, ki->owner, strlen(ki->owner));
		}

                found_keys++;
            }
        }

        /* Write some basic statistics about the request. */
        struct event ev[2] = {{.key = "nb_addr_in",
                               .type = EV_VAR_UINT32,
                               .val.uint32 = nb},
                              {.key = "nb_addr_out",
                               .type = EV_VAR_UINT32,
                               .val.uint32 = found_keys}};

        if (kddb_event(pool, kdsh_get_session_counter(), "getsig", 2, ev) < 0) 
            kdclient_warn("Failed to log 'getenc' event.");
        
        kbuffer_destroy (signed_key);

        apr_pool_destroy(pool);

        *out_pkt = op;
        return next_state;

    } while (0);
   
    /* Bad errors go through here. */
 err:
    if (signed_key)
        kbuffer_destroy(signed_key);

    apr_pool_destroy(pool);
    
    return -1;
}

/** Returns an encryption key data given a key ID.
 * FIXME: refactor with function below.
 *
 * This request doesn't change the client state if its successful.
 */
enum client_state kdclient_get_enc_key_by_id_request(kdclient *self,
                            	    	    	     apr_pool_t *pkt_pool,
                                                     struct kdpacket *in_pkt,
                                            	     struct kdpacket **out_pkt) {
    enum client_state next_state = self->cstate;
    struct kdkey_info *ki;
    uint64_t key_id;
    kbuffer *signed_key = kbuffer_new();
    struct kdkey_info *tm_pkey_info;
    apr_pool_t *pool;

    apr_pool_create(&pool, pkt_pool);

    kdpacket_get_uint64(in_pkt, EL_KEYID, &key_id);

    INFO(_log_client_, "Key request for "PRINTF_64"u.", key_id);

    do {
        if (kdkey_get_key(pool, key_id, PKEY_ENCRYPTION, &ki) <= 0) {
            kdclient_error("Failed to fetch key "PRINTF_64"u.", key_id);
            *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
            break;
        }

        /* We only have to sign the key with version 3.x and above. */
        if (in_pkt->major >= 3) {
            if (kdkey_sign_key(ki, signed_key, 0)) {
                kdclient_error("Failed to sign the public key "PRINTF_64"u.", key_id);
                *out_pkt = kdpacket_new(pool, PKT_FAIL);
                next_state = CSTATE_DROP_ACK;
                break;
            }
        }

        INFO(_log_client_, "Key request for "PRINTF_64"u successful.", key_id);

        /* Success! Prepare the outgoing packet. */
        *out_pkt = kdpacket_new(pkt_pool, PKT_GET_ENC_KEY_BY_ID_RES);

        /* won't fail. */
        kdkey_get_key(NULL, 0, PKEY_TIMESTAMP, &tm_pkey_info);

        if (in_pkt->major >= 3) {
            kdpacket_set_cstr(*out_pkt, EL_TM_KEY_DATA, tm_pkey_info->data);
            kdpacket_set_cstr(*out_pkt, EL_KEY_DATA, (char *)signed_key->data);
        } 
        else 
            kdpacket_set_cstr(*out_pkt, EL_KEY_DATA, ki->data);

        kdpacket_set_cstr(*out_pkt, EL_OWNER_NAME, ki->owner);

        struct event ev[1] = {{.key = "key_id",
                               .type = EV_VAR_UINT64,
                               .val.uint64 = key_id}};

        if (kddb_event(pool, kdsh_get_session_counter(), "getencbyid", 1, ev) < 0) 
            kdclient_warn("Failed to log 'getencbyid' request.");
    } while (0);

    apr_pool_destroy(pool);

    kbuffer_destroy(signed_key);
    return next_state;
}

#endif // REQUEST_GETENC

#ifdef REQUEST_GETSIG
/** Returns an signature key data given a key ID. 
 *
 * This request doesn't change the client state if its successful.
 */
enum client_state kdclient_get_sign_key_request(kdclient *self,
                                                apr_pool_t *pkt_pool,
                                                struct kdpacket *in_pkt,
                                                struct kdpacket **out_pkt) {
    enum client_state next_state = self->cstate;
    struct kdkey_info *ki;
    uint64_t key_id;
    kbuffer *signed_key = kbuffer_new();
    struct kdkey_info *tm_pkey_info;
    apr_pool_t *pool;

    apr_pool_create(&pool, pkt_pool);

    kdpacket_get_uint64(in_pkt, EL_KEYID, &key_id);

    INFO(_log_client_, "Key request for "PRINTF_64"u.", key_id);

    do {
        if (kdkey_get_key(pool, key_id, PKEY_SIGNATURE, &ki) <= 0) {
            kdclient_error("Failed to fetch key "PRINTF_64"u.", key_id);
            *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
            break;
        }

        /* We only have to sign the key with version 3.x and above. */
        if (in_pkt->major >= 3) {
            if (kdkey_sign_key(ki, signed_key, 0)) {
                kdclient_error("Failed to sign the public key "PRINTF_64"u.", key_id);
                *out_pkt = kdpacket_new(pool, PKT_FAIL);
                next_state = CSTATE_DROP_ACK;
                break;
            }
        }

        INFO(_log_client_, "Key request for "PRINTF_64"u successful.", key_id);

        /* Success! Prepare the outgoing packet. */
        *out_pkt = kdpacket_new(pkt_pool, PKT_GET_SIGN_KEY_RES);

        /* won't fail. */
        kdkey_get_key(NULL, 0, PKEY_TIMESTAMP, &tm_pkey_info);

        if (in_pkt->major >= 3) {
            kdpacket_set_cstr(*out_pkt, EL_TM_KEY_DATA, tm_pkey_info->data);
            kdpacket_set_cstr(*out_pkt, EL_KEY_DATA, (char *)signed_key->data);
        } 
        else 
            kdpacket_set_cstr(*out_pkt, EL_KEY_DATA, ki->data);

        kdpacket_set_cstr(*out_pkt, EL_OWNER_NAME, ki->owner);

        struct event ev[1] = {{.key = "key_id",
                               .type = EV_VAR_UINT64,
                               .val.uint64 = key_id}};

        if (kddb_event(pool, kdsh_get_session_counter(), "getsig", 1, ev) < 0) 
            kdclient_warn("Failed to log 'getsig' request.");
    } while (0);

    apr_pool_destroy(pool);

    kbuffer_destroy(signed_key);
    return next_state;
}
#endif // REQUEST_GETSIG
