/**
 * tbxsosd/package.c
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
 * Teambox Sign-On Server Daemon mail messages processing functions.
 *
 * @author François-Denis Gonthier
*/

#include <assert.h>
#include <kerror.h>
#include <apr_tables.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <kbuffer.h>
#include <tagcryptsignature.h>
#include <base64.h>

#include "common/common_pkg.h"
#include "common/common_keys.h"
#include "common/logid.h"
#include "libutils/logging.h"
#include "libutils/utils.h"
#include "libutils/str.h"

#include "proto.h"
#include "keys.h"
#include "package.h"
#include "proto_defs.h"
#include "packet.h"
#include "shared.h"
#include "crypto_proto_str.h"

struct kdpackage_pwd_data {
    kbuffer *pwd;
    // FIXME: Temporary member.
    int has_otut;
    struct tagcrypt_otut otut;
};

/** Clear the memory allocated by the process info structure. */
static apr_status_t kdpackage_delete(void *data) {
    struct kd_package *pkg = (struct kd_package *)data;        
    apr_array_header_t *a;
    struct tagcrypt_symkey_params * skp;
    struct kdpackage_pwd_data *pd;

    a = pkg->recv_keys_array;
    while ((skp = (struct tagcrypt_symkey_params *)apr_array_pop(a)) != NULL) 
        kbuffer_destroy(skp->destination_list);
    
    a = pkg->recv_pwd_array;
    while ((pd = (struct kdpackage_pwd_data *)apr_array_pop(a)) != NULL) {
        kbuffer_destroy(pd->pwd);
        tagcrypt_otut_clean(&pd->otut);
    }

    return APR_SUCCESS;
}

static apr_status_t kdpackage_encrypted_delete(void *data) {
    struct kd_encrypted *enc = (struct kd_encrypted *)data;

    if (enc->symkey != NULL)
        tagcrypt_symkey_destroy(enc->symkey);
    if (enc->encrypted_content != NULL)
        kbuffer_destroy(enc->encrypted_content);
    if (enc->serialized_symkey != NULL)
        kbuffer_destroy(enc->serialized_symkey);
    if (enc->content != NULL)
        tbuffer_destroy(enc->content);

    return APR_SUCCESS;
}

static apr_status_t kdpackage_signed_delete(void *data) {
    struct kd_signed *sig = (struct kd_signed *)data;

    if (sig->sign != NULL)
        tagcrypt_sign_destroy(sig->sign);
    if (sig->wsbody_html != NULL)
        kstr_destroy(sig->wsbody_html);
    if (sig->wsbody_text != NULL)
        kstr_destroy(sig->wsbody_text);
    if (sig->trimed_subject != NULL)
        kstr_destroy(sig->trimed_subject);
    if (sig->sig_text != NULL)
        kbuffer_destroy(sig->sig_text);

    return APR_SUCCESS;
}

struct kd_encrypted *kdpackage_new_encrypted(apr_pool_t *pool) {
    struct kd_encrypted *enc;

    enc = apr_pcalloc(pool, sizeof(struct kd_encrypted));
    enc->pool = pool;
    apr_pool_cleanup_register(enc->pool, enc, kdpackage_encrypted_delete, kdpackage_encrypted_delete);
    return enc;
}

struct kd_signed *kdpackage_new_signed(apr_pool_t *pool, struct kd_package *pkg) {
    struct kd_signed *sig;

    sig = apr_pcalloc(pool, sizeof(struct kd_signed));
    sig->pool = pool;
    apr_pool_cleanup_register(sig->pool, sig, kdpackage_signed_delete, kdpackage_signed_delete);

    /* Only KNP v1.1 produces v1.1 signatures. */
    if (pkg->major == 1 && pkg->minor == 1) {
        if ((sig->sign = tagcrypt_sign_new(pkg->pkg_type, 1, 1,
                                           pkg->sender_sig_skey->key)) == NULL)
            KERROR_SET(_pkg_, 0, "cannot create signature");
    }
    else {
        if ((sig->sign = tagcrypt_sign_new(pkg->pkg_type, 2, 1,
                                           pkg->sender_sig_skey->key)) == NULL)
            KERROR_SET(_pkg_, 0, "cannot create signature");
    }

    return sig;
}

struct kd_package *kdpackage_new(apr_pool_t *pool) {
    struct kd_package *pkg;

    pkg = apr_pcalloc(pool, sizeof(struct kd_package));
    pkg->pool = pool;
    apr_pool_cleanup_register(pool, pkg, kdpackage_delete, kdpackage_delete);

    return pkg;
}

/** Add a receiver password in the parameter block. */
int kdpackage_add_recver_pwd(struct kd_package *pkg, 
                             const char *pwd, 
                             const char *otut,
                             size_t otut_s) {    
    int error = -1;
    struct kdpackage_pwd_data *pd;    
    kbuffer *otut_buf = NULL;
    size_t n;

    /* Check if the password array has been instantiated. */
    if (pkg->recv_pwd_array == NULL) {
        n = sizeof(struct kdpackage_pwd_data);
        pkg->recv_pwd_array = apr_array_make(pkg->pool, 0, n);
        pkg->recv_pwd_hash = apr_hash_make(pkg->pool);
    }

    do {
        /* Check if the password isn't already in the hash table. */
        if ((pd = apr_hash_get(pkg->recv_pwd_hash, pwd, strlen(pwd))) == NULL) {

            /* Add the key to the array. */
            pd = apr_array_push(pkg->recv_pwd_array);

            tagcrypt_otut_init(&pd->otut);
        
            /* Add the password in the buffer. */
            pd->pwd = kbuffer_new();
            kbuffer_write_cstr(pd->pwd, pwd);

            if (otut_s > 0 && otut != NULL) {
                kbuffer *otut_buf = kbuffer_new();
                kbuffer_write(otut_buf, (uint8_t *)otut, otut_s);

                /* Add the OTUT. */
                if (tagcrypt_otut_realize(otut_buf, &pd->otut) < 0) 
                    break;

                kbuffer_destroy(otut_buf);
                otut_buf = NULL;

                pd->has_otut = 1;
            }
            else pd->has_otut = 0;

            /* Add the key to the hash. */
            apr_hash_set(pkg->recv_pwd_hash, pwd, strlen(pwd), pd);
        }
	
	error = 0;

    } while (0);

    kbuffer_destroy(otut_buf);

    if (error) {
        apr_array_pop(pkg->recv_pwd_array);
        return -1;
    } else
        return 0;
}

/** */
int kdpackage_add_recver_enc_pkey(struct kd_package *pkg, 
                                  struct kdkey_info *tm_pkey,
                                  const char *pkey,
                                  const char *addr) {
    int error = -1;
    uint64_t key_id;
    kbuffer *key_buffer = NULL;
    size_t n;
    int m;
    struct tagcrypt_symkey_params * skp = NULL;
    struct kdkey_info ki;

    /* Check if the key array has been instanciated. */
    if (pkg->recv_keys_array == NULL) {
        n = sizeof(struct tagcrypt_symkey_params);
        pkg->recv_keys_array = apr_array_make(pkg->pool, 1, n);
        pkg->recv_keys_hash = apr_hash_make(pkg->pool);
    }

    do {
        m = kdkey_extract_signed_pkey(pkg->pool, tm_pkey, pkey, strlen(pkey), &ki);
        /* FIXME: Support old version KNP (UNSIGNED KEYS)... SECURITY ISSUE. */
        if (m < 0) {
            WARN(_log_pkg_, "Using unsigned signature keys.");

            /* The key might be unsigned, try to create it as an
               unsigned key. */
            if (kdkey_new_unsigned_pkey(pkg->pool, 
                                        pkey, 
                                        strlen(pkey), 
                                        KEY_TYPE_ENCRYPTION,
                                        &ki) < 0) {
                KERROR_PUSH(_pkg_, 0, "cannot create public key");
                break;
            }
        }

        key_id = ((tagcrypt_pkey *)ki.key)->keyid;

        /* Check if the key for that recipient isn't already in the 
           recipient table. */
        if ((skp = apr_hash_get(pkg->recv_keys_hash, &key_id, sizeof(uint64_t))) == NULL) {

            /* Add the key to the array. */
            skp = apr_array_push(pkg->recv_keys_array);
            memset(skp, 0, sizeof(struct tagcrypt_symkey_params));
            skp->encryption_key = ki.key;             

            /* Create the destination list buffer. */
            if ((skp->destination_list = kbuffer_new()) == NULL) {
                apr_array_pop(pkg->recv_keys_array);
                KERROR_SET(_pkg_, 0, "cannot create destination list for key");
                break;
            }

            /* Add the key to the table. */
            apr_hash_set(pkg->recv_keys_hash, &key_id, sizeof(uint64_t), skp);
        } 

        if (skp->destination_list) {
            /* Add a space after the destination list if it's not empty. */
            if (skp->destination_list->len > 0)
                kbuffer_write8(skp->destination_list, ' ');

            /* Write the address in the destination list buffer. */
            kbuffer_write_cstr(skp->destination_list, addr);
        }
	
	error = 0;

    } while(0);

    if (key_buffer != NULL)
        kbuffer_destroy(key_buffer);

    return error;
}

/** Initialize the encryptable content buffer.
 *
 * Calling this function many times is harmless.
 */
static int kdpackage_init_content(struct kd_encrypted *enc) {
    kbuffer *dbuf;

    if (enc->content == NULL) {
        enc->content = tbuffer_new(1024);
        
        dbuf = tbuffer_get_dbuf(enc->content);

        /* Write the encryption magic in the newly allocated buffers. */
        kbuffer_write8(dbuf, KNP_UINT64);
        kbuffer_write64(dbuf, KNP_ENC_BODY_MAGIC);
        kbuffer_write8(dbuf, KNP_UINT64);
        kbuffer_write64(dbuf, KNP_ENC_BODY_MAGIC);
    }
    
    return 0;
}

/** Add an attachment to the body to be encrypted. */
static void kdpackage_add_content(struct kd_package *pkg,
                                  struct kd_encrypted *enc, 
                                  struct proto_body_entry *body_entry) {

    if (enc->content == NULL) 
        kdpackage_init_content(enc);
 
    body_entry->attch_type = kdprotocol_get_attachment_type(pkg->major, pkg->minor,
                                                            body_entry->attch_type);

    tbuffer_write_uint32(enc->content, body_entry->attch_type);
    tbuffer_write_cstr(enc->content, body_entry->encoding);
    tbuffer_write_cstr(enc->content, body_entry->mime_type);
    tbuffer_write_cstr(enc->content, body_entry->name);
    tbuffer_write_str(enc->content, body_entry->payload, body_entry->payload_s);
}

/** Add an HTML body to the message to be encrypted. */
static void kdpackage_encrypt_text(struct kd_package *pkg, struct kd_encrypted *enc) {
    struct proto_body_entry body_entry;

    body_entry.attch_type = ATTACH_TEXT_BODY;
    body_entry.encoding = NULL;
    body_entry.mime_type = NULL;
    body_entry.name = NULL;    
    body_entry.payload_s = pkg->text_body_s;
    body_entry.payload = pkg->text_body;
    
    kdpackage_add_content(pkg, enc, &body_entry);
}

/** Add a text body to the message to be encrypted. */
static void kdpackage_encrypt_html(struct kd_package *pkg, struct kd_encrypted *enc) {
    struct proto_body_entry body_entry;

    body_entry.attch_type = ATTACH_HTML_BODY;
    body_entry.encoding = NULL;
    body_entry.mime_type = NULL;
    body_entry.name = NULL;
    body_entry.payload_s = pkg->html_body_s;
    body_entry.payload = pkg->html_body;

    kdpackage_add_content(pkg, enc, &body_entry);
}
 
/** Add an ordinary attachment to the message to be encrypted. */
static void kdpackage_encrypt_file(struct kd_package *pkg, 
                                   struct kd_encrypted *enc,
                                   struct proto_attachment *attch) {
    struct proto_body_entry body_entry;

    body_entry.attch_type = attch->attch_type;
    body_entry.encoding = attch->encoding;
    body_entry.mime_type = attch->mime_type;
    body_entry.name = attch->name;
    body_entry.payload_s = attch->payload_s;
    body_entry.payload = attch->payload;

    kdpackage_add_content(pkg, enc, &body_entry);
}

/** Encrypt the content that was added to the object.
 *
 * This function should be called once per package object lifetime
 * because it destroys the content buffer once it is encrypted.
 */
int kdpackage_encrypt(struct kd_package *pkg, struct kd_encrypted *enc) {    
    int error = -1;
    int i;
    kbuffer *encrypted_raw= NULL;
    kbuffer *dbuf;

    kdpackage_init_content(enc);   

    do {
        if (pkg->body_type == BODY_TYPE_HTML || pkg->body_type == BODY_TYPE_BOTH)
            kdpackage_encrypt_html(pkg, enc);

        if (pkg->body_type == BODY_TYPE_TEXT || pkg->body_type == BODY_TYPE_BOTH)
            kdpackage_encrypt_text(pkg, enc);

        for (i = 0; i < pkg->attachment_count; i++) 
            kdpackage_encrypt_file(pkg, enc, pkg->attachments[i]);

        if ((enc->symkey = tagcrypt_symkey_new()) == NULL) {
            KERROR_SET(_pkg_, 0, "failed to create the symmetric key");
            break;
        }

        /* Temporary buffers. */
        encrypted_raw = kbuffer_new();

        /* Object buffers. */
        enc->encrypted_content = kbuffer_new();
        enc->serialized_symkey = kbuffer_new();

        /* Serialize the symmetric key. */
        if (tagcrypt_symkey_serialize(enc->symkey, enc->serialized_symkey) < 0) {
            KERROR_SET(_pkg_, 0, "failed to serialized the symmetric key");
            break;
        }
            
        /* Encrypt the clear data. */
        dbuf = tbuffer_get_dbuf(enc->content);
        if (tagcrypt_symkey_encrypt(enc->symkey, dbuf, encrypted_raw) < 0) {
            KERROR_SET(_pkg_, 0, "failed to encrypt symmetric key");
            break;
        }
        else			
            /* Convert encrypted body to base64. */
           kbin2b64(encrypted_raw, enc->encrypted_content);
	
	error = 0;
        
    } while (0);

    /* Destroy the content buffer, we no longer need it and it
       occupies quite a bit of memory we probably will no longer need. */
    if (enc->content != NULL) {
        tbuffer_destroy(enc->content);
        enc->content = NULL;
    }

    if (encrypted_raw != NULL)
        kbuffer_destroy(encrypted_raw);
	
    return error;
}

int kdpackage_sign_add_podto(struct kd_package *pkg, struct kd_signed *sig) {
    struct tagcrypt_podto_params pp;

    if (pkg->pod_addr == NULL) return 0;

    pp.data = (uint8_t *)pkg->pod_addr;
    pp.len = strlen(pkg->pod_addr);
    
    int r = tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_PODTO, (void *)&pp);
    DEBUG(_log_pkg_, "Added PoD address: %s.", pkg->pod_addr);

    return r;
}

int kdpackage_add_passwords(struct kd_package *pkg, 
                            struct kd_encrypted *enc, 
                            struct kd_signed *sig) {
    struct kdpackage_pwd_data *pd;
    apr_array_header_t *p;
    apr_array_header_t *pcopy;
    struct tagcrypt_snd_symkey_params ssp;        
    struct tagcrypt_passwd_params pp;
    int idx = 0;

    if (pkg->recv_pwd_array == NULL) return 0;

    p = pkg->recv_pwd_array;
    pcopy = apr_array_copy(sig->pool, p);

    /* Add a sender symmetric key for the password. */
    ssp.symkey = enc->symkey;
    ssp.snd_key = pkg->sender_sig_pkey->key;
    
    tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_SND_SYMKEY, &ssp);

    /* Add the passwords. */
    while ((pd = (struct kdpackage_pwd_data *)apr_array_pop(pcopy)) != NULL) {
        pp.pkey = pkg->sender_sig_pkey->key;
        pp.passwd = pd->pwd;

        if (pd->has_otut)
            pp.otut = &pd->otut;
        else
            pp.otut = NULL;
        
        tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_PASSWD, &pp);
        DEBUG(_log_pkg_, "Signed non-member recipient no %d.", idx++);
    }

    return 0;
}

int kdpackage_add_keys(struct kd_package *pkg, 
                       struct kd_encrypted *enc, 
                       struct kd_signed *sig) {
    apr_array_header_t *p;
    apr_array_header_t *pcopy;
    struct tagcrypt_symkey_params *skp;
    int idx = 0;

    if (pkg->recv_keys_array == NULL) return 0;

    p = pkg->recv_keys_array;
    pcopy = apr_array_copy(sig->pool, p);

    /* Add the encryption keys. */
    while ((skp = (struct tagcrypt_symkey_params *)apr_array_pop(pcopy)) != NULL) {
        skp->symkey = enc->symkey;
        if (pkg->pkg_type == TAG_P_TYPE_PODNENC)
            skp->pod_key = pkg->sender_sig_pkey->key;
        
        tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_SYMKEY, skp);
        DEBUG(_log_pkg_, "Signed member recipient no %d.", idx++);
    }

    return 0;
}

/*
 * Those function do the proper signing.  We expect all the required
 * packet elements to be present for the signature unless stated otherwise.
 */

static int kdpackage_sign_html_body(struct kd_package *pkg, struct kd_signed *sig) {
    struct tagcrypt_hash_params hp;
    kstr html_body;

    kstr_init_buf(&html_body, pkg->html_body, pkg->html_body_s);
    sig->wsbody_html = kstr_new();

    /* Remove the newlines in what we will sign. */   

    /* For KNP v1.1. */
    if (pkg->major == 1 && pkg->minor == 1) 
        str_merge_whitespace(&html_body, sig->wsbody_html);

    /* For KNP v2.1 and up. */
    else if (pkg->major >= 2) 
        str_trim_whitespace(&html_body, sig->wsbody_html);

    kstr_clean(&html_body);
        
    /* Add the hash to the signature. */
    hp.data = (uint8_t *)sig->wsbody_html->data;
    hp.len = sig->wsbody_html->slen;
    
    return tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_HTML, (void *)&hp);
}

static int kdpackage_sign_text_body(struct kd_package *pkg, 
                                    struct kd_encrypted *enc,
                                    struct kd_signed *sig) {
    char *tosign;
    size_t tosign_s;
    struct tagcrypt_hash_params hp;
    kstr text_body;

    kstr_init_buf(&text_body, pkg->text_body, pkg->text_body_s);
    sig->wsbody_text = kstr_new();

    /* Determine what to sign exactly. */
    if (sig->sign->type == TAG_P_TYPE_SIGN) {        
        /* Remove the newlines in what we will sign. */

        /* For KNP v1.1. */
        if (pkg->major == 1 && pkg->minor == 1)
            str_newline2space(&text_body, sig->wsbody_text);

        /* For KNP v2.1 and up. */
        else if (pkg->major >= 2) 
            str_trim_whitespace(&text_body, sig->wsbody_text);

        tosign = sig->wsbody_text->data;
        tosign_s = sig->wsbody_text->slen;
    } 
    /* Here we sign the encrypted content. */
    else {
        tosign = (char *)enc->encrypted_content->data;
        tosign_s = enc->encrypted_content->len;
    }

    kstr_clean(&text_body);

    /* Add the hash to the signature. */
    hp.data = (uint8_t *)tosign;
    hp.len = tosign_s;

    tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_PLAIN, (void *)&hp);

    return 0;
}

/** Sign the TO field. */
static int kdpackage_sign_to(struct kd_package *pkg, struct kd_signed *sig) {
    struct tagcrypt_hash_params hp;
    const char *orig_to = NULL;
    const char *sign_to = NULL;
    char *lwr_to = NULL;    

    if (pkg->to == NULL) return 0;

    if (pkg->major >= 3) {
        orig_to = pkg->to;
        
        if (orig_to != NULL) {
            lwr_to = apr_pstrdup(sig->pool, orig_to);
            strlwr(lwr_to);
            sign_to = lwr_to;
        }
    }
    else
        sign_to = pkg->to;

    hp.data = (uint8_t *)sign_to;
    hp.len = strlen(sign_to);

    return tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_TO, (void *)&hp);	
}

/** Sign the FROM_NAME field. */
static int kdpackage_sign_from_name(struct kd_package *pkg, struct kd_signed *sig) {
    struct tagcrypt_hash_params hp;
    const char *orig_from_name = NULL;
    const char *sign_from_name = NULL;
    char *lwr_from_name = NULL;

    if (pkg->from_name == NULL) return 0;

    if (pkg->major >= 3) {
        orig_from_name = pkg->from_name;

        if (orig_from_name != NULL) {
            lwr_from_name = apr_pstrdup(sig->pool, orig_from_name);
            strlwr(lwr_from_name);
            sign_from_name = lwr_from_name;
        }
    } 
    else
        sign_from_name = pkg->from_name;
        
    hp.data = (uint8_t *)sign_from_name;
    hp.len = strlen(sign_from_name);

    return tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_FROM_NAME, (void *)&hp);
}

/** Sign the FROM_ADDR field. */
static int kdpackage_sign_from_addr(struct kd_package *pkg, struct kd_signed *sig) {
    struct tagcrypt_hash_params hp;
    const char *orig_from_addr = NULL;
    const char *sign_from_addr = NULL;
    char *lwr_from_addr = NULL;

    if (pkg->from_addr == NULL) return 0;

    if (pkg->major >= 3) {
        orig_from_addr = pkg->from_addr;

        if (orig_from_addr != NULL) {
            lwr_from_addr = apr_pstrdup(sig->pool, orig_from_addr);
            strlwr(lwr_from_addr);
            sign_from_addr = lwr_from_addr;
        }
    }
    else
        sign_from_addr = pkg->from_addr;

    hp.data = (uint8_t *)sign_from_addr;
    hp.len = strlen(sign_from_addr);

    return tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_FROM_ADDR, (void *)&hp);
}

/** Sign the CC field. */
static int kdpackage_sign_cc(struct kd_package *pkg, struct kd_signed *sig) {
    struct tagcrypt_hash_params hp;
    const char *orig_cc = NULL;
    const char *sign_cc = NULL;
    char *lwr_cc = NULL;
    
    if (pkg->cc == NULL) return 0;

    if (pkg->major >= 3) {
        orig_cc = pkg->cc;

        if (orig_cc != NULL) {
            lwr_cc = apr_pstrdup(sig->pool, orig_cc);
            strlwr(lwr_cc);
            sign_cc = lwr_cc;
        }
    }
    else
        sign_cc = pkg->cc;

    hp.data = (uint8_t *)sign_cc;
    hp.len = strlen(sign_cc);

    return tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_CC, (void *)&hp);
}

/** Sign the SUBJECT field. */
static int kdpackage_sign_subject(struct kd_package *pkg, struct kd_signed *sig) {
    struct tagcrypt_hash_params hp;
    kstr s;

    if (pkg->subject == NULL) return 0;

    kstr_init_cstr(&s, pkg->subject);
    sig->trimed_subject = kstr_new();
    str_trim_whitespace(&s, sig->trimed_subject);

    hp.data = (uint8_t *)sig->trimed_subject->data;
    hp.len = sig->trimed_subject->slen;

    kstr_clean(&s);

    return tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_SUBJECT, (void *)&hp);
}

/** Sign the KPG information packet. */
static int kdpackage_sign_kpg_info(struct kd_package *pkg, struct kd_signed *sig) {
    struct tagcrypt_kpg_params kpgp;
    /* FIXME: We default to the HOST KPG information. */
    enum tagcrypt_kpg_type kpg_type = KPG_ADDR_HOST;
    kstr s;
    int n;

    /* No-op if kpg_addr was not set. */
    if (pkg->kpg_addr == NULL) return 0;
    
    kstr_init_cstr(&s, pkg->kpg_addr);
    
    kpgp.type = kpg_type;
    kpgp.addr = &s;
    kpgp.port = pkg->kpg_port;

    n = tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_KPG_ADDR, (void *)&kpgp);

    kstr_clean(&s);

    return n;
}

/** Add a sender symkey. */
static int kdpackage_sign_add_sender_symkey(struct kd_package *pkg, 
                                            struct kd_encrypted *enc,
                                            struct kd_signed *sig) {
    struct tagcrypt_snd_symkey_params sk;

    sk.symkey = enc->symkey;
    sk.snd_key = pkg->sender_sig_pkey->key;
    
    return tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_SND_SYMKEY, &sk);
}

/** Add the IP address. */
static int kdpackage_sign_ip(struct kd_package *pkg, struct kd_signed *sig) {
    tagcrypt_ipv4_params ip;

    ip = ((struct sockaddr_in *)pkg->addr)->sin_addr.s_addr;
    return tagcrypt_sign_add_subpacket(sig->sign, TAG_SP_TYPE_IPV4, &ip);
}

/** Sign all the attachments. */
static int kdpackage_sign_attachments(struct kd_package *pkg, struct kd_signed *sig) {
    uint32_t nb, i;

    nb = pkg->attachment_count;

    for (i = 0; i < nb; i++) { 
        struct proto_attachment *pattch;
        struct tagcrypt_attachment_params att_params;

        pattch = pkg->attachments[i];
        memset(&att_params, 0, sizeof(att_params));
        
        /* Note that we don't care about signing the encoding and the
           MIME type.  Those 2 properties don't identify the
           attachment in any ways and thus could be modified by the
           various MUAs */

        if (pattch->name != NULL) {
            att_params.filename = (uint8_t *)pattch->name;
            att_params.filename_len = strlen(pattch->name);
        }

        if (pattch->payload != NULL) {
            att_params.payload = (uint8_t *)pattch->payload;
            att_params.payload_len = pattch->payload_s;
        }

        if (tagcrypt_sign_add_subpacket(sig->sign, 
                                        TAG_SP_TYPE_ATTACHMENT,
                                        &att_params) < 0) {
            DEBUG(_log_pkg_, "Attachment no %d has been signed.", i);
            return -1;
        }
    } 

    return 0;
}

/** Set the langage code. */
static inline int kdpackage_set_lang(struct kd_package *pkg, struct kd_signed *sig) {
    return tagcrypt_sign_add_subpacket(sig->sign,
                                       TAG_SP_TYPE_LANG,
                                       (void *)pkg->lang);
}

/** Sign the KNP protocol version. */
static int kdpackage_sign_proto(struct kd_package *pkg, struct kd_signed *sig) {
    uint32_t proto_params[2];

    /* Protocol version. */
    proto_params[0] = pkg->major;
    proto_params[1] = pkg->minor;
    return tagcrypt_sign_add_subpacket(sig->sign, 
                                       TAG_SP_TYPE_PROTO, 
                                       (void *)&proto_params);    
}

static void kdpackage_format_signature(apr_pool_t *ppool,
                                       struct kd_package *pkg,
                                       struct kd_signed *sig,
                                       kbuffer *rb) {
    char * sb = NULL;
    size_t sb_s = 0;
    apr_pool_t *pool;

    apr_pool_create(&pool, ppool);

    sb_s = blockify_get_size(KRYPTIVA_SIG_MAX_LINE_LEN, sig->sig_text->len);
    sb = apr_palloc(pool, sb_s + 1);

    blockify_base64(KRYPTIVA_SIG_MAX_LINE_LEN, 
                    (const char *)sig->sig_text->data, 
                    sig->sig_text->len, 
                    sb, 
                    sb_s);
   
    /* Little text start. */
    kbuffer_write(rb, (uint8_t *)KRYPTIVA_START, sizeof(KRYPTIVA_START) - 1);

    /* FIXME: Better langage support here. */
    if (pkg->lang == 1) {
        kbuffer_write(rb, (uint8_t *)KRYPTIVA_INFO_FR, sizeof(KRYPTIVA_INFO_FR) - 1);
        kbuffer_write(rb, (uint8_t *)KRYPTIVA_INFO_SEP, sizeof(KRYPTIVA_INFO_SEP) - 1);
    }
    kbuffer_write(rb, (uint8_t *)KRYPTIVA_INFO_EN, sizeof(KRYPTIVA_INFO_EN) - 1);

    /* Newline. */
    kbuffer_write8(rb, '\n');

    /* Signature start. */
    kbuffer_write(rb, (uint8_t *)KRYPTIVA_SIGN_START, sizeof(KRYPTIVA_SIGN_START) - 1);

    /* Newline. */
    kbuffer_write8(rb, '\n');

    /* Signature body. */
    kbuffer_write(rb, (uint8_t *)sb, sb_s);

    /* Newline. */
    kbuffer_write8(rb, '\n');

    /* Signature end. */
    kbuffer_write(rb, (uint8_t *)KRYPTIVA_SIGN_END, sizeof(KRYPTIVA_SIGN_END) - 1);

    apr_pool_destroy(pool);
}

static void kdpackage_format_full(apr_pool_t *ppool,
                                  struct kd_package *pkg, 
                                  struct kd_encrypted *enc,
                                  struct kd_signed *sig,
                                  kbuffer *rb) {
    char *bb = NULL, *sb = NULL;
    size_t bb_s = 0, sb_s = 0;
    apr_pool_t *pool;

    apr_pool_create(&pool, ppool);

    bb_s = blockify_get_size(KRYPTIVA_SIG_MAX_LINE_LEN, enc->encrypted_content->len);
    sb_s = blockify_get_size(KRYPTIVA_SIG_MAX_LINE_LEN, sig->sig_text->len);

    bb = apr_palloc(pool, bb_s + 1);
    sb = apr_palloc(pool, sb_s + 1);

    blockify_base64(KRYPTIVA_SIG_MAX_LINE_LEN, 
                    (const char *)enc->encrypted_content->data, 
                    enc->encrypted_content->len,
                    bb, 
                    bb_s);
    blockify_base64(KRYPTIVA_SIG_MAX_LINE_LEN, 
                    (const char *)sig->sig_text->data, 
                    sig->sig_text->len,
                    sb, 
                    sb_s);
    
    kbuffer_write(rb, (uint8_t *)KRYPTIVA_START, sizeof(KRYPTIVA_START) - 1);

    /* FIXME: Better langage support here. */
    if (pkg->lang == 1) {
        kbuffer_write(rb, (uint8_t *)KRYPTIVA_INFO_FR, sizeof(KRYPTIVA_INFO_FR) - 1);
        kbuffer_write(rb, (uint8_t *)KRYPTIVA_INFO_SEP, sizeof(KRYPTIVA_INFO_SEP) - 1);
    }     
    kbuffer_write(rb, (uint8_t *)KRYPTIVA_INFO_EN, sizeof(KRYPTIVA_INFO_EN) - 1);

    /* Newline. */
    kbuffer_write(rb, (uint8_t *)"\n\n", 2);

    /* Start of encrypted body. */
    kbuffer_write(rb, 
                  (uint8_t *)KRYPTIVA_ENC_BODY_START, 
                  sizeof(KRYPTIVA_ENC_BODY_START) - 1);

    /* Newline. */
    kbuffer_write8(rb, '\n');

    /* Encrypted body. */
    kbuffer_write(rb, (uint8_t *)bb, bb_s);

    /* Newline. */
    kbuffer_write8(rb, '\n');

    /* End of encrypted body. */
    kbuffer_write(rb,
                  (uint8_t *)KRYPTIVA_ENC_BODY_END, 
                  sizeof(KRYPTIVA_ENC_BODY_END) - 1);

    /* 2 newlines. */
    kbuffer_write(rb, (uint8_t *)"\n\n", 2);

    /* Start of signature. */        
    kbuffer_write(rb, 
                  (uint8_t *)KRYPTIVA_SIGN_START, 
                  sizeof(KRYPTIVA_SIGN_START) - 1);

    /* Newline. */
    kbuffer_write8(rb, '\n');

    /* Signature. */
    kbuffer_write(rb, (uint8_t *) sb, sb_s);

    /* Newline. */
    kbuffer_write8(rb, '\n');

    /* End of signature. */
    kbuffer_write(rb, (uint8_t *)KRYPTIVA_SIGN_END, sizeof(KRYPTIVA_SIGN_END) - 1);

    /* Newline */
    kbuffer_write8(rb, '\n');

    apr_pool_destroy(pool);
}

/** Produce the package signature as string. */
void kdpackage_format(struct kd_package *pkg,
                      apr_pool_t *pool,
                      struct kd_encrypted *enc,
                      struct kd_signed *sig,
                      kbuffer *buf) {
    switch (pkg->pkg_type) {
    case TAG_P_TYPE_SIGN:
        kdpackage_format_signature(pool, pkg, sig, buf);
        break;
        
    case TAG_P_TYPE_POD:
    case TAG_P_TYPE_ENC:
    case TAG_P_TYPE_PODNENC:
    default:
        kdpackage_format_full(pool, pkg, enc, sig, buf);       
    }
}

/** Sign the package. */
int kdpackage_sign(struct kd_package *pkg, 
                   struct kd_encrypted *enc_in, 
                   struct kd_signed *sig_out) {
    int r;
    uint32_t nb_attch;
    uint64_t counter;
    kbuffer *sig_buf = NULL;

    do {
        if (kdpackage_sign_proto(pkg, sig_out) < 0) {
            KERROR_PUSH(_pkg_, 0, "protocol version signature failed");
            break;
        }
        if (kdpackage_sign_to(pkg, sig_out) < 0) {
            KERROR_PUSH(_pkg_, 0, "'to' signature has failed");
            break;
        }
        if (kdpackage_sign_from_name(pkg, sig_out) < 0) {
            KERROR_PUSH(_pkg_, 0, "'from_name' signature has failed");
            break;
        }
        if (kdpackage_sign_from_addr(pkg, sig_out) < 0) {
            KERROR_PUSH(_pkg_, 0, "'from_addr' signature has failed");
            break;
        }
        if (kdpackage_sign_cc(pkg, sig_out) < 0) {
            KERROR_PUSH(_pkg_, 0, "'cc' signature has failed");
            break;
        }
        if (kdpackage_sign_subject(pkg, sig_out) < 0) {
            KERROR_PUSH(_pkg_, 0, "'subject' signature has failed");
            break;
        }
        if (kdpackage_sign_kpg_info(pkg, sig_out) < 0) {
            KERROR_PUSH(_pkg_, 0, "Signature of KPG information has failed.");
            break;
        }
        if (pkg->addr != NULL)
            if (kdpackage_sign_ip(pkg, sig_out) < 0) {
                KERROR_PUSH(_pkg_, 0, "'ip' signature has failed");
                break;
            }
	
        if (kdpackage_set_lang(pkg, sig_out) < 0) {
            KERROR_PUSH(_pkg_, 0, "language signature failed");
            break;
        }
        
        /* Text/plain.  When the signature type is encryption or PoD,
           there must be a text body to sign. */
        if ((pkg->body_type == BODY_TYPE_TEXT || pkg->body_type == BODY_TYPE_BOTH) ||
            pkg->pkg_type != TAG_P_TYPE_SIGN) {
            r = kdpackage_sign_text_body(pkg, enc_in, sig_out);
            
            if (r < 0) {
                KERROR_PUSH(_pkg_, 0, "text body signature has failed");
                break;
            }
        }

        /* Text/html.  An HTML body is only present when the choosen
           signature type is 'signature'. */
        if ((pkg->body_type == BODY_TYPE_HTML || pkg->body_type == BODY_TYPE_BOTH) &&
            pkg->pkg_type == TAG_P_TYPE_SIGN) {
            r = kdpackage_sign_html_body(pkg, sig_out);
            
            if (r < 0) {
                KERROR_PUSH(_pkg_, 0, "HTML body signature has failed");
                break;
            }
        }

        nb_attch = pkg->attachment_count;

        /* Sign the attachments. */
        if (pkg->pkg_type == TAG_P_TYPE_SIGN && nb_attch > 0) {
            if (kdpackage_sign_attachments(pkg, sig_out) < 0) {
                KERROR_PUSH(_pkg_, 0, "attachment signature failed.");
                break;
            }
        }

        /* PoD things. */
        if (pkg->pkg_type == TAG_P_TYPE_POD || pkg->pkg_type == TAG_P_TYPE_PODNENC) {          
            /* Add the PoD return address. */
            if (kdpackage_sign_add_podto(pkg, sig_out) < 0) {
                KERROR_PUSH(_pkg_, 0, "failed to add PoD return address");
                break;
            }
        }

        /* Encryption or PoD and encryption. */
        if (pkg->pkg_type == TAG_P_TYPE_ENC || pkg->pkg_type == TAG_P_TYPE_PODNENC) {
            if (kdpackage_add_passwords(pkg, enc_in, sig_out) < 0) {
                KERROR_PUSH(_pkg_, 0, "failed to add password(s) to signature");
                break;
            }
            if (kdpackage_add_keys(pkg, enc_in, sig_out) < 0) {
                KERROR_PUSH(_pkg_, 0, "failed to add keys to signature");
                break;
            }
        } 
        else if ((pkg->pkg_type & TAG_P_TYPE_POD) != 0) {
            if (kdpackage_sign_add_sender_symkey(pkg, enc_in, sig_out) < 0) {
                KERROR_PUSH(_pkg_, 0, "failed to add sender symmetric key to signature");
                break;
            }
        }

        /* Add the serial number. */
        counter = kdsh_get_counter();

        if (tagcrypt_sign_add_subpacket(sig_out->sign, TAG_SP_TYPE_KSN, &counter) < 0) {
            KERROR_SET(_pkg_, 0, "failed to add the KSN to the signature");
            break;
        }
        
        if (tagcrypt_signature_get_ksn(sig_out->sign, sig_out->ksn, TAGCRYPT_KSN_SIZE) < 0) {
            KERROR_SET(_pkg_, 0, "failed to retrieve KSN from signature");
            break;
        }
        
        sig_buf = kbuffer_new();
        sig_out->sig_text = kbuffer_new();

        /* Serialize the signature into a new buffer. */
        if (tagcrypt_sign_serialize(sig_out->sign, sig_buf) < 0) {
            KERROR_SET(_pkg_, 0, "failed to serialize signature");
            break;
        }

        kbin2b64(sig_buf, sig_out->sig_text);

        if (sig_buf != NULL) kbuffer_destroy(sig_buf);
        return 0;

    } while (0);
        
    if (sig_buf != NULL)  kbuffer_destroy(sig_buf);
    return -1;
}
