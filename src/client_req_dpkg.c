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
 * Splitted of client.c for convenience.  Include functions to return
 * the symmetric key for messages encrypted for PoD, encrypted for
 * other members, or encrypted with passwords.
 *
 * @author François-Denis Gonthier
*/

#include <assert.h>
#include <kerror.h>
#include <kstr.h>

#include "common/common_keys.h"
#include "common/common_dpkg.h"
#include "common/common.h"
#include "common/logid.h"
#include "common/config.h"
#include "libdb/db.h"
#include "libutils/options.h"
#include "libutils/utils.h"
#include "libutils/logging.h"

#include "client.h"
#include "dpkg.h"
#include "keys.h"
#include "packet.h"
#include "podder.h"
#include "shared.h"

#include "client_req_dpkg.h"

static int client_pkg_type_from_tag_type(uint32_t tag_type) {
    return 
        tag_type == TAG_P_TYPE_POD ? KNP_PKG_TYPE_POD :
        tag_type == TAG_P_TYPE_PODNENC ? (KNP_PKG_TYPE_POD | KNP_PKG_TYPE_ENC) :
        tag_type == TAG_P_TYPE_ENC ? KNP_PKG_TYPE_ENC :
        0;    
}

#ifdef REQUEST_KEY_DECRYPT
/**
 * This is ordinary decryption.  This means that the user must logged in to be
 * able to fetch his private encryption key.
 */
enum client_state kdclient_request_key_dpkg(kdclient *self, 
                                            apr_pool_t *pkt_pool,
                                            struct kd_dpkg *dpkg,
                                            struct kd_decrypted *dec,
                                            struct kdpacket **out_pkt) {
    enum client_state next_state = self->cstate;
    enum kd_dpkg_result r;
    struct kdpacket *po = NULL;
    apr_pool_t *pool;

    apr_pool_create(&pool, pkt_pool);

    do {
        /* Get the encryption for the receiver. */
        dpkg->recver_enc_skey = self->user->enc_skey;
        
        /* At this point, we should have all we need to pull the symmetric key
           out of the signature packet but it may be incomplete decryption
           since the key might have been PoD-encrypted too. */

        r = kddpkg_decrypt(dpkg, self->user, dec) ;

        if (r == DPKG_PARTIAL || r == DPKG_FULL) {

            if (r == DPKG_PARTIAL)
                po = kdpacket_new(pkt_pool, PKT_DEC_SYM_KEY_HALF_RES);
            else if (r == DPKG_FULL)
                po = kdpacket_new(pkt_pool, PKT_DEC_SYM_KEY_FULL_RES);

            kdpacket_set_raw(po, EL_SYMKEY, dec->symkey_str, dec->symkey_str_s);
            /* Never any OTUT in this case. */
            kdpacket_set_raw(po, EL_OTUT_STRING, NULL, 0);
            /* 0 for PoD date. */
            kdpacket_set_uint32(po, EL_POD_DATE, 0);
	    kdpacket_set_cstr(po, EL_DEC_EMAIL, dec->dec_email);
            
            struct event ev[3] = {
                {.key = "pkg_type",
                 .type = EV_VAR_UINT32,
                 .val.uint32 = client_pkg_type_from_tag_type(dpkg->sign->type)},
                {.key = "key_id",
                 .type = EV_VAR_UINT64,
                 .val.uint64 = dpkg->sign->keyid},
                {.key = "has_pwd",
                 .type = EV_VAR_UINT32,
                 .val.uint32 = (dec->password != NULL)}
            };

            if (kddb_event(pool, kdsh_get_session_counter(), "key-dpkg", 3, ev) < 0) 
                kdclient_warn("Failed to log 'key-dpkg' event.");
        }
        else if (r == DPKG_ERROR) {
            kdclient_error("Client failed to decrypt the symmetric key.");
            break;
        }
        else if (r == DPKG_NOT_ALLOWED) {
            kdclient_warn("Client is not allowed to decrypt the message.");
            po = kdpacket_new(pkt_pool, PKT_DEC_SYM_KEY_AUTH_ERR);
        }
        /* Cover our asses out of corner cases here. 
           Note: the bad password case is impossible in this case. */
        else {
	    kdclient_error("Client failed to decrypt the symmetric key.");
            break;
        }
        
        apr_pool_destroy(pool);

        INFO(_log_client_, "Request: Decrypt with Key successful.");

        *out_pkt = po;        
        return next_state;

    } while (0);

    apr_pool_destroy(pool);

    *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
    return next_state;
}
#endif

#if defined(REQUEST_GUEST_DECRYPT)
/** Send a PoD message to a target. */
static int client_send_pod(kdclient *self, 
                           apr_pool_t *parent_pool,
                           struct timeval *pod_date,
                           struct kd_dpkg *dpkg) {
    int error = -1;
    const char *ip;
    apr_pool_t *pool;
    struct kdpodder_params *pod_params;

    apr_pool_create(&pool, parent_pool);

    do {       
        if (kdcomm_get_peer(self->main_comm, pool, &ip, NULL) < 0) {
            KERROR_PUSH(_client_, 0, "failed to get peer's name");
            break;
        }

        pod_params = apr_pcalloc(pool, sizeof(struct kdpodder_params));
        pod_params->orig_from_addr = apr_pstrmemdup(pool, dpkg->podfrom_str, dpkg->podfrom_str_s);
        pod_params->orig_subject = apr_pstrmemdup(pool, dpkg->subject_str, dpkg->subject_str_s);
        pod_params->pod_to = apr_pstrmemdup(pool, dpkg->podto_str, dpkg->podto_str_s);
        pod_params->pod_date = pod_date;
        pod_params->ip = ip;
        pod_params->sign = dpkg->sign;

        /* Send the PoD message itself. */
        if (kdpodder_send(pool, pod_params) < 0) {
            KERROR_PUSH(_client_, 0, "PoD sender error");
            break;
        }

        INFO(_log_client_, "PoD message sent to %s.", dpkg->podto_str);
	
	error = 0;
       
    } while (0);

    apr_pool_destroy(pool);
    return error;
}
#endif // REQUEST_GUEST_DECRYPT

#if defined(REQUEST_KEY_DECRYPT) || defined(REQUEST_GUEST_DECRYPT)
/**
 * This is to initialize the parameters common to all three depackaging
 * requests.
 */ 
enum client_state kdclient_request_dpkg(kdclient *self, 
                                        apr_pool_t *pkt_pool,
                                        struct kd_dpkg *dpkg,
                                        struct kdpacket *in_pkt,
                                        struct kdpacket **out_pkt) {
    enum client_state next_state = self->cstate;
    const char *sig_str = NULL, *pkey_str = NULL, *sk_str = NULL,
        *podfrom_str = NULL, *pwd_str = NULL, *tm_pkey_str = NULL;
    size_t sig_str_s = 0, pkey_str_s = 0, sk_str_s = 0,
        podfrom_str_s = 0, pwd_str_s = 0, tm_pkey_str_s = 0;
    struct kdkey_info tm_pkey, pkey;

    INFO(_log_client_, "Request: Generic decryption.");

    do {
        /* Check the presence of the elements */
        assert(kdpacket_get_type(in_pkt) == PKT_DEC_SYM_KEY_CMD);
        assert(kdpacket_is_present(in_pkt, EL_KEY_DATA));
        assert(kdpacket_is_present(in_pkt, EL_SIG_TEXT));
        assert(kdpacket_is_present(in_pkt, EL_INTER_SYMKEY_DATA));
        assert(kdpacket_is_present(in_pkt, EL_POD_FROM));
        assert(kdpacket_is_present(in_pkt, EL_PASSWORD));

        /* Get the elements int the request packet */
        if (in_pkt->major >= 3) 
            kdpacket_get_str(in_pkt, EL_TM_KEY_DATA, &tm_pkey_str, &tm_pkey_str_s);

        kdpacket_get_str(in_pkt, EL_KEY_DATA, &pkey_str, &pkey_str_s);
        kdpacket_get_str(in_pkt, EL_SIG_TEXT, &sig_str, &sig_str_s);
        kdpacket_get_raw(in_pkt, EL_INTER_SYMKEY_DATA, (void **)&sk_str, &sk_str_s);
        kdpacket_get_str(in_pkt, EL_PASSWORD, &pwd_str, &pwd_str_s);
        kdpacket_get_str(in_pkt, EL_POD_FROM, &podfrom_str, &podfrom_str_s);
	
	/* Check if the decryption email is requested. */
	if (kdpacket_is_present(in_pkt, EL_WANT_DEC_EMAIL)) {
	    kdpacket_get_uint32(in_pkt, EL_WANT_DEC_EMAIL, &dpkg->want_dec_email);
	}
	
        /* The packet elements are there? Yes. Fine, but being there includes
           being empty. */

        /* Those 2 must not be empty. */
        if (sig_str == NULL) {
            kdclient_error("Signature empty in packet.");
            next_state = CSTATE_DROP_ACK;
            break;           
        }
        if (pkey_str == NULL) {
            kdclient_error("Public key empty in packet.");
            next_state = CSTATE_DROP_ACK;
            break;
        }
        if (in_pkt->major >= 3 && tm_pkey_str == NULL) {
            kdclient_error("Timestamp signature key empty in packet.");
            next_state = CSTATE_DROP_ACK;
            break;
        }
       
        /* Get the timestamp key */
        if (in_pkt->major >= 3) {
            if (kdkey_extract_tm_pkey(dpkg->pool,
                                      tm_pkey_str, 
                                      tm_pkey_str_s, 
                                      &tm_pkey) < 0) {
                kdclient_error("Client error in getting the provided timestamp key.");
                next_state = CSTATE_DROP_ACK;
                break;
            } 

            /* Extract the public key from signed key that was sent by the
               client. */
            if (kdkey_extract_signed_pkey(dpkg->pool, &tm_pkey, pkey_str, pkey_str_s, &pkey) < 0) {
                kdclient_error("Client error in getting public key.");
                next_state = CSTATE_DROP_ACK;
                break;
            }
        }
        /* For KNP 2.1, there were no signed keys. */
        else if (in_pkt->major < 3) {
            if (kdkey_new_unsigned_pkey(dpkg->pool, 
                                        pkey_str, 
                                        pkey_str_s, 
                                        KEY_TYPE_ENCRYPTION, 
                                        &pkey) < 0) {
                kdclient_error("Client error in getting unsigned public key.");
                next_state = CSTATE_DROP_ACK;
                break;
            }
        }

        dpkg->symkey_str = sk_str;
        dpkg->symkey_str_s = sk_str_s;
        dpkg->podfrom_str = podfrom_str;
        dpkg->podfrom_str_s = podfrom_str_s;
        dpkg->tm_pkey = &tm_pkey;
        dpkg->sender_sig_pkey = &pkey;

        if (kddpkg_set_signature(dpkg, sig_str, sig_str_s) < 0) {
            kdclient_error("Failed to set signature in decryption parameter block.");
            next_state = CSTATE_DROP_ACK;
            break;
        }

        /* Initialize some elements that were provided in the
           parameter block even if they are not required.  The
           validity of those elements is examined later. */

        /* Intermediate symmetric key. */
        if (sk_str != NULL) {
            dpkg->symkey_str = sk_str;
            dpkg->symkey_str_s = sk_str_s;
        }
        /* Password */
        if (pwd_str != NULL) {
            dpkg->password_str = pwd_str;
            dpkg->password_str_s = pwd_str_s;
        }
        
        /* Check if the subject was provided in the decryption
           request. */
        if (kdpacket_is_present(in_pkt, EL_SUBJECT)) 
            kdpacket_get_str(in_pkt, EL_SUBJECT, &dpkg->subject_str, &dpkg->subject_str_s);

        return next_state;

    } while (0);
   
    *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
    return next_state;
}
#endif

#ifdef REQUEST_GUEST_DECRYPT
/**
 * Non-member decryption means we expect to decrypt with a password.
 */
enum client_state kdclient_request_pwd_dpkg(kdclient *self, 
                                            apr_pool_t *pkt_pool,
                                            struct kd_dpkg *dpkg,
                                            struct kd_decrypted *dec,
                                            struct kdpacket **out_pkt) {
    struct kdkey_info *ki;
    enum client_state next_state = self->cstate;
    struct kdpacket *po = NULL;
    struct timeval pod_date;
    apr_pool_t *pool;
    enum kd_dpkg_result r;

    apr_pool_create(&pool, pkt_pool);

    INFO(_log_client_, "Request: Decryption with Password.");

    do {        
        if (kdkey_get_sig_skey(pool, dpkg->sign->keyid, &ki) <= 0) {
            kdclient_error("Failed to fetch key to decrypt the message.");
            break;
        }        

        dpkg->sender_sig_skey = ki;

        /* Return the symmetric key. */
        r = kddpkg_decrypt(dpkg, self->user, dec);

        /* Full decryption. */
        if (r == DPKG_FULL) {

            /* Get the date we will use as the PoD date. */
            if (gettimeofday(&pod_date, NULL) < 0) {
                kdclient_error("gettimeofday failed.");
                break;
            }
            
            if (dpkg->sign->type != TAG_P_TYPE_ENC) {
                if (tagcrypt_signature_get_podto(dpkg->sign, 
                                                 (char **)&dpkg->podto_str,
                                                 &dpkg->podto_str_s) < 0) {
                    kdclient_error("Failed to get PoD address.");
                    break;
                }

                if (client_send_pod(self, pool, &pod_date, dpkg) < 0) {
                    kdclient_error("Failed to send PoD.");
                    break;
                }
            }

            po = kdpacket_new(pkt_pool, PKT_DEC_SYM_KEY_FULL_RES);         
            kdpacket_set_raw(po, EL_SYMKEY, (void *)dec->symkey_str, dec->symkey_str_s);
            kdpacket_set_raw(po, EL_OTUT_STRING, (void *)dec->otut_str, dec->otut_str_s);

            /* If the message is a PoD with password, we need to send
               back the PoD date. */
            if (dpkg->sign->type != TAG_P_TYPE_ENC) 
                kdpacket_set_uint32(po, EL_POD_DATE, pod_date.tv_sec);
            /* 0 for PoD date in the encrypted-only case.. */
            else 
                kdpacket_set_uint32(po, EL_POD_DATE, 0);
	    
	    kdpacket_set_cstr(po, EL_DEC_EMAIL, dec->dec_email);

            struct event ev[3] =  {
                {.key = "pkg_type",
                 .type = EV_VAR_UINT32, 
                 .val.uint32 = client_pkg_type_from_tag_type(dpkg->sign->type)},
                {.key = "key_id", 
                 .type = EV_VAR_UINT64, 
                 .val.uint64 = dpkg->sign->keyid},
                {.key = "has_pwd",
                 .type = EV_VAR_UINT32, 
                 .val.uint32 = (dec->password != NULL)}
            };

            if (kddb_event(pool, kdsh_get_session_counter(), "pwd-dpkg", 3, ev) < 0) 
                kdclient_warn("Failed to log 'pwd-dpkg' event.");
        }
        /* Decryption error. */
        else if (r == DPKG_ERROR) 
            kdclient_error("Client failed to decrypt the symmetric key.");

        /* Bad decryption password. */
        else if (r == DPKG_BAD_PWD) {
            kdclient_warn("Client has sent a bad password.");
            po = kdpacket_new(pkt_pool, PKT_DEC_SYM_KEY_PWD_ERR);
        }
        /* Cover our asses out of corner cases here. 
           Note: Partial decryption impossible too. */
        else {
	    kdclient_error("Client failed to decrypt the symmetric key.");
            break;
        }

        INFO(_log_client_, "Request: Decrypt with Password successful.");

        *out_pkt = po;
        apr_pool_destroy(pool);

        return next_state;

    } while (0);

    apr_pool_destroy(pool);
    *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);

    return next_state;
}

/**
 * De-PoD request.  This means decrypting the message symmetric key with the 
 * sender's private signature key and sending an email to the sender acknowledging
 * message decryption.
 */
enum client_state kdclient_request_pod_dpkg(kdclient *self, 
                                            apr_pool_t *pkt_pool, 
                                            struct kd_dpkg *dpkg,
                                            struct kd_decrypted *dec,
                                            struct kdpacket **out_pkt) {
    struct kdkey_info *ki;
    enum kd_dpkg_result r;
    enum client_state next_state = self->cstate;
    struct kdpacket *po = NULL;
    struct timeval pod_date;
    apr_pool_t *pool;
   
    apr_pool_create(&pool, pkt_pool);

    INFO(_log_client_, "Request: Decrypt PoD.");

    do {
        /* Fetch the sender signature key. */
        if (kdkey_get_sig_skey(pool, dpkg->sign->keyid, &ki) <= 0) {
            kdclient_error("Failed to fetch secret signature key "PRINTF_64"u.");
            break;
        }

        dpkg->sender_sig_skey = ki;

        /* Fetch the symmetric key. */
        r = kddpkg_depod(dpkg, dec);

        if ((dpkg->sign->type == TAG_P_TYPE_PODNENC || dpkg->sign->type == TAG_P_TYPE_POD)) {
            if (dpkg->podfrom_str == NULL) {
                kdclient_error("No PoD source address provided.");               
                next_state = CSTATE_DROP_ACK;
                break;            
            } 
        }

        if (r == DPKG_FULL) {
            if (tagcrypt_signature_get_podto(dpkg->sign, 
                                             (char **)&dpkg->podto_str, 
                                             &dpkg->podto_str_s) < 0) {
                kdclient_error("Failed to get PoD address.");
                break;
            }

            /* Set the PoD date. */
            if (gettimeofday(&pod_date, NULL) < 0) {
                kdclient_error("gettimeofday failed.");
                break;
            }

            /* Send the PoD at that address. */
            if (client_send_pod(self, pool, &pod_date, dpkg) < 0) {
                kdclient_error("Failed to send PoD.");
                break;
            }

            po = kdpacket_new(pkt_pool, PKT_DEC_SYM_KEY_FULL_RES);         
            kdpacket_set_raw(po, EL_SYMKEY, (void *)dec->symkey_str, dec->symkey_str_s);
            kdpacket_set_raw(po, EL_OTUT_STRING, NULL, 0);
            kdpacket_set_uint32(po, EL_POD_DATE, pod_date.tv_sec);
	    kdpacket_set_cstr(po, EL_DEC_EMAIL, dec->dec_email);

            struct event ev[3] =  {
                {.key = "pkg_type",
                 .type = EV_VAR_UINT32, 
                 .val.uint32 = client_pkg_type_from_tag_type(dpkg->sign->type)},
                {.key = "key_id", 
                 .type = EV_VAR_UINT64, 
                 .val.uint64 = dpkg->sign->keyid},
                {.key = "has_pwd",
                 .type = EV_VAR_UINT32, 
                 .val.uint32 = (dec->password != NULL)}
            };

            if (kddb_event(pool, kdsh_get_session_counter(), "pod-dpkg", 3, ev) < 0) 
                kdclient_warn("Failed to log 'pod-dpkg' event.");
        }
        else if (r == DPKG_ERROR) {
            kdclient_error("Client failed to decrypt the symmetric key.");
            break;
        }
        /* Cover our asses out of corner cases here. 
           Note: the bad password case is impossible in this case, nor
           is partial decryption possible too. */
        else {        
	    kdclient_error("Client failed to decrypt the symmetric key.");
        }

        INFO(_log_client_, "Request: Decrypt PoD successful.");

        apr_pool_destroy(pool);

        *out_pkt = po;
        return next_state;
        
    } while (0);

    apr_pool_destroy(pool);

    *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
    return next_state;
}
#endif // REQUEST_GUEST_DECRYPT
