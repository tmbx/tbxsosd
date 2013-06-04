/**
 * tbxsosd/keys.c
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
 * Keys manager. 
 *
 * @author François-Denis Gonthier
*/

#include <sys/time.h>
#include <assert.h>
#include <apr_pools.h>
#include <tagcrypt.h>
#include <kerror.h>
#include <kmem.h>
#include <stdlib.h>

#include "common/common_keys.h"
#include "common/config.h"
#include "common/logid.h"
#include "libutils/options.h"
#include "libutils/utils.h"
#include "libdb/db.h"

#include "keys.h"
#include "shared.h"
#include "crypto_proto_str.h"

/* Timeout in sec after receiving a new timestamp key. */
#define KSH_KEY_TIMEOUT 30 

#define TIMESTAMP_PKEY_LEN 2048
#define TIMESTAMP_SKEY_LEN 4096

static char start_sig_pkey[] = "--- START SIGNATURE PUBLIC KEY ---\n";
static char end_sig_pkey[] = "--- END SIGNATURE PUBLIC KEY ---\n";
static char start_enc_pkey[] = "--- START ENCRYPTION PUBLIC KEY ---\n";
static char end_enc_pkey[] = "--- END ENCRYPTION PUBLIC KEY ---\n";
static char start_sig_skey[] = "--- START SIGNATURE PRIVATE KEY ---\n";
static char end_sig_skey[] = "--- END SIGNATURE PRIVATE KEY ---\n";
static char start_enc_skey[] = "--- START ENCRYPTION PRIVATE KEY ---\n";
static char end_enc_skey[] = "--- END ENCRYPTION PRIVATE KEY ---\n";

static const char *master_pkey_str = "AvWVqQAAAAEAAAABAAAAAAAAAAEAAAIrKDEwOnB1YmxpYy1rZXkoMzpyc2EoMTpuNTEzOgCxy4pn+69izBi5yXC6jkLZHlClf66C02DTx/s4FjhREFlIR+xUDKRaxe9zNe1bpHJpxYhixTxREia1Zb2SslRTo8EGYYf5hWAE6rUIZ+Ex7DLqjFsA0KZ4qp3MqkMTfsmTuUevGLjtVnoh04+yqogt9+XXgwszAxT0jSflo0m5wrHv6kbcUXm5ct9EIiRy1RMbMa0PYFDK/qmfGW32kBwyGKoNuG3iiqBVPQ9Wn5TRlYeFVkt2/8r6mXoe5oJzhPmfvGJ2fe/dQ2IiVXoWatHpLiAbIUgD/mzJrWXdMW+iqH3NZuMDVtOmqdy9AuQxP+CJLaU/E9Q2AamOA8Z6jcrJ7o0GYeM6awBcZptCwQSQ1ERyEu4DNs7T0dkyvcxTCzQu3GuqkvHZaCQGx+R2ehYkY8kjgXUaA4WYmbGy+neXPBF9M3rqpU/PM5ltyBYzGEGtkSyNbq3mlRjQz0T+oUfEuQci20dIxc1iYZ4gLTw1231bHkl+A1RsIJa46pkl+oVQfTrG2o3OckorXen4U7J4pN0SPDeeSIaERqC5EWho3GZEArusaOz9iygV/R+qxSjcJNZOQfjbYxqE6ZyPhe6gyBAPV4txCvOtwtEnqW055obM52bqSfpOFdJ57uQmarSoNy3qV/f9FmqAhvgR/oUUKE0tX7S0icjy+R7RYTV+zykoMTplMzoBAAEpKSkA";

static const char *license_pkey_str = "AvWVqQAAAAEAAAABAAAAAAAAAAAAAACrKDEwOnB1YmxpYy1rZXkoMzpyc2EoMTpuMTI5OgDM+dWhEho/PDmEC+UPP9KVAm9ahQqXw0aCcpDfEFjiYR1rTOpZFxG9HV8BzGcVB4pehTV70M2lP5o2Eh42C9/g90jy5CWxLSauy1DLjApfsRD+yXNXbQ0cy6G9x+/CLaO5eBMb/vji15XrtWFXoZyR8o7DyI9mUSpBIE9zwsKbjykoMTplMzoBAAEpKSkA";

#define KEY_OWNER   "Teambox"
#define KEY_OWNER_S 8

#ifdef REQUEST_GETSIG
static const char *tm_pkey_str;
static const char *tm_skey_str;
#endif // REQUEST_GETSIG

static struct kdkey_info tm_pkey_info = {
    .key_id = 0,
    .owner = KEY_OWNER, 
    .owner_s = KEY_OWNER_S,    
    .type = PKEY_TIMESTAMP,
    .key = NULL
};

static struct kdkey_info tm_skey_info = {
    .key_id = 0,
    .owner = KEY_OWNER,
    .owner_s = KEY_OWNER_S,
    .type = SKEY_TIMESTAMP,
    .key = NULL
};

static struct kdkey_info master_pkey_info = {
    .key_id = 0,
    .owner = KEY_OWNER, 
    .owner_s = KEY_OWNER_S,
    .type = PKEY_MASTER,
    .key = NULL
};

static struct kdkey_info license_pkey_info = {
    .key_id = 0,
    .owner = KEY_OWNER,
    .owner_s = KEY_OWNER_S,
    .type = PKEY_LICENSE,
    .key = NULL
};

/** Initialize common data for the kdkey object. */
int kdkey_static_init() {
    kbuffer buf, mk_buf, lk_buf;
    kstr str;
    int err;

    master_pkey_info.data = master_pkey_str;
    master_pkey_info.data_s = strlen(master_pkey_str);

    license_pkey_info.data = license_pkey_str;
    license_pkey_info.data_s = strlen(license_pkey_str);

    do {
        /* Load the master public key. */
        kstr_init_cstr(&str, master_pkey_str);
        kbuffer_init_b64(&mk_buf, &str);
        kstr_clean(&str);
        master_pkey_info.key = tagcrypt_pkey_new(&mk_buf, KEY_TYPE_MASTER);

        /* Load the license public key. */
        kstr_init_cstr(&str, license_pkey_str);
        kbuffer_init_b64(&lk_buf, &str);
        kstr_clean(&str);
        license_pkey_info.key = tagcrypt_pkey_new(&lk_buf, KEY_TYPE_MASTER);

        kbuffer_clean(&lk_buf);
        kbuffer_clean(&mk_buf);

#ifdef REQUEST_GETSIG
        tm_pkey_str = options_get_str("keysign.public");
        tm_skey_str = options_get_str("keysign.private");

        tm_pkey_info.data = tm_pkey_str;
        tm_pkey_info.data_s = strlen(tm_pkey_str);
        tm_skey_info.data = tm_skey_str;
        tm_skey_info.data_s = strlen(tm_skey_str);

        kstr_init_buf(&str, tm_skey_info.data, tm_skey_info.data_s);
        err = kbuffer_init_b64(&buf, &str);
        kstr_clean(&str);
        if (err) {
            KERROR_SET(_keys_, 0, "cannot convert the secret key from base64 to binary");
            break;
        }
        else
            /* FIXME: I believe this is actually a bug in libktools.
               Errors are pushed by libktools even where there is no
               returned errors. */
            kerror_reset();

        tm_skey_info.key = tagcrypt_skey_new(&buf);
        kbuffer_clean(&buf);

        if (tm_skey_info.key == NULL) {
            KERROR_SET(_keys_, 0, "cannot create internal timestamp key object");
            err = -1;
            break;
        }
#endif // REQUEST_GETSIG

        /* Cleans libktools error. */
        kerror_reset();
        err = 0;

    } while (0);

    return err ? -1 : 0;
}

int kdkey_static_clean() {
#ifdef REQUEST_GETSIG
    if (tm_skey_info.key != NULL)
        tagcrypt_skey_destroy(tm_skey_info.key);
#endif // REQUEST_GETSIG

    tagcrypt_pkey_destroy(master_pkey_info.key);    
    tagcrypt_pkey_destroy(license_pkey_info.key);

    return 0;
}

static enum key_type kdkey_to_tagcrypt(enum kdkey_type ktype) {
    switch (ktype) {
    case PKEY_MASTER:
    case SKEY_MASTER:    
        return KEY_TYPE_MASTER; break;
    case PKEY_TIMESTAMP:
    case SKEY_TIMESTAMP: 
        return KEY_TYPE_TIMESTAMP; break;
    case PKEY_ENCRYPTION:
    case SKEY_ENCRYPTION: 
        return KEY_TYPE_ENCRYPTION; break;
    case PKEY_SIGNATURE:
    case SKEY_SIGNATURE: 
        return KEY_TYPE_IDENTITY; break;

    default:
        abort();
    }

    return -1;
}

static apr_status_t kdkey_destroy_pkey(void *data) {
    if (data != NULL) {
        tagcrypt_pkey *pkey = (tagcrypt_pkey *)data;
        tagcrypt_pkey_destroy(pkey);
        pkey = NULL;
    }

    return APR_SUCCESS;
}

static apr_status_t kdkey_destroy_skey(void *data) {
    if (data != NULL) {    
        tagcrypt_skey *skey = (tagcrypt_skey *)data;        
        tagcrypt_skey_destroy(skey);
        skey = NULL;
    }

    return APR_SUCCESS;
}

/** Return an ordinary key object.  Returns -1 on error, 0 on missing
    key, and 1 on success. */
int kdkey_get_key(apr_pool_t *pool, 
                  uint64_t key_id, 
                  enum kdkey_type ktype, 
                  struct kdkey_info **ki) {
    kbuffer buf;
    enum key_type type;
    kstr str;
    int err = 0;
    
    assert((ktype > SKEY_START && ktype < SKEY_END) ||
           (ktype > PKEY_START && ktype < PKEY_END));

    switch (ktype) {
        /* Those go through the database object. */
    case SKEY_ENCRYPTION:
    case SKEY_SIGNATURE:
    case PKEY_ENCRYPTION:
    case PKEY_SIGNATURE:
        err = kddb_fetch_key(pool, key_id, ktype, ki);
        /* Key fetch error. */
        if (err < 0) {
            KERROR_PUSH(_keys_, 0, "failed to fetch key "PRINTF_64"u", key_id);
            err = -1;
            break;
        }
        /* Key not found. */
        if (err == 0) return 0;

        type = kdkey_to_tagcrypt(ktype);
        kstr_init_buf(&str, (*ki)->data, (*ki)->data_s);
        err = kbuffer_init_b64(&buf, &str);
        kstr_clean(&str);

        if (err) break;

        if (ktype == SKEY_ENCRYPTION || ktype == SKEY_SIGNATURE) {
            (*ki)->key = tagcrypt_skey_new(&buf);        

            if ((*ki)->key == NULL) {
                KERROR_SET(_keys_, 0, "ill-formed secret key in database");
                err = -1;
                break;
            }

            /* Check for inconsistent key ID. */
            if (((tagcrypt_skey *)(*ki)->key)->keyid != (*ki)->key_id) {
                KERROR_SET(_keys_, 0, 
                           "ill-formed key, internal key ID: "PRINTF_64"u, external key ID: "PRINTF_64"u", 
                           ((tagcrypt_skey *)(*ki)->key)->keyid, (*ki)->key_id);
                err = -1;
                break;
            }

            /* Register memory cleanup function. */
            if ((*ki)->key != NULL)
                apr_pool_cleanup_register(pool, (*ki)->key, kdkey_destroy_skey, kdkey_destroy_skey);
        } 
        else if (ktype == PKEY_ENCRYPTION || ktype == PKEY_SIGNATURE) {
            (*ki)->key = tagcrypt_pkey_new(&buf, type);        

            if ((*ki)->key == NULL) {
                KERROR_SET(_keys_, 0, "ill-formed public key in database");
                err = -1;
                break;
            }

            /* Check for inconsistent key ID. */
            if (((tagcrypt_pkey *)(*ki)->key)->keyid != (*ki)->key_id) {
                KERROR_SET(_keys_, 0, 
                           "ill-formed key, internal key ID: "PRINTF_64"u, external key ID: "PRINTF_64"u", 
                           ((tagcrypt_pkey *)(*ki)->key)->keyid, (*ki)->key_id);
                err = -1;
                break;
            }
            
            /* Register memory cleanup function. */
            if ((*ki)->key != NULL)
                apr_pool_cleanup_register(pool, (*ki)->key, kdkey_destroy_pkey, kdkey_destroy_pkey);
        }

        if ((*ki)->key == NULL) {
            err = -1;
            KERROR_SET(_keys_, 0, "failed to create key "PRINTF_64"u", key_id);
        }

        kbuffer_clean(&buf);
        err = 1;
        break;

    case PKEY_TIMESTAMP:
        *ki = &tm_pkey_info;
        break;

    case PKEY_LICENSE:
        *ki = &license_pkey_info;
        break;

#ifdef REQUEST_GETSIG
    case SKEY_TIMESTAMP:
        *ki = &tm_skey_info;
        break;

#endif // REQUEST_GETSIG

    default:
        abort();
    }
    
    return err;
}

/** Get a timestamping key from a signed key. 
 *
 * Won't allocate anything on the pool.  Uses the pool to register a
 * destructor for the allocated key.
 */
/* FIXME: This is a rather nasty possible failure point.  I have no
   idea how to test this. */
int kdkey_extract_tm_pkey(apr_pool_t *pool,
                          const char *str_key, 
                          size_t str_key_s, 
                          struct kdkey_info *ki) {
    int error = -1;
    struct kdsh_tm_pkey_time tm_pkey_time[2];
    struct tagcrypt_signed_pkey *tm_pkey_obj[2] = {NULL, NULL};
    struct tagcrypt_signed_pkey *signed_pkey;
    kbuffer *buf = kbuffer_new();
    int cur_key, old_key;
    
    /* TRY */
    do {
        kbuffer_write(buf, (uint8_t *)str_key, str_key_s);
        signed_pkey = tagcrypt_sign_get_pkey(buf, master_pkey_info.key);

        if (!signed_pkey) {
            KERROR_SET(_shared_, 0, "error getting the signed public timestamp key");
            break;
        }

        kdsh_lock();
        cur_key = kdsh_get_cur_tm_pkey();
        old_key = !cur_key;

        kdsh_get_cur_tm_pkey_time(&tm_pkey_time[cur_key]);
        kdsh_get_old_tm_pkey_time(&tm_pkey_time[old_key]);

        /* This is the first tm key we receive */
        if (tm_pkey_time[cur_key].status == 0) {
            if (kdsh_set_cur_tm_pkey_time(signed_pkey)) {
                KERROR_PUSH(_shared_, 0, "error saving new timestamp key");
                break;
            }
            kdsh_set_cur_tm_pkey_time(signed_pkey);
        }

        /* We are receiving the current key (Normal path) */
        else if (tm_pkey_time[cur_key].activation_time.tv_sec == signed_pkey->time.tv_sec) {
            struct timeval tv;
            /* Is there an old key ? */
            if (tm_pkey_time[old_key].status == 1) {
                if (gettimeofday(&tv, NULL) == -1) {
                    KERROR_SET(_shared_, 0, "could not gettimeofday: %s", strerror(errno));
                    break;
                }
                /* Flush it if it's too old */
                if (tm_pkey_time[cur_key].received_time.tv_sec + KSH_KEY_TIMEOUT < tv.tv_sec) {
                    tm_pkey_time[old_key].status = 0;
                    tagcrypt_signed_pkey_destroy(tm_pkey_obj[old_key]);
                }
            }

            /* Check if an instance of the current_key is available */
            if (tm_pkey_obj[cur_key] == NULL) { /* not in cache for this process */
                tm_pkey_obj[cur_key] = signed_pkey;
            } else {
                tagcrypt_signed_pkey_destroy(signed_pkey);
                signed_pkey = tm_pkey_obj[cur_key];
            }
        }

        /* We are receiving a new key for the first time */
        else if (tm_pkey_time[old_key].status == 0) {

            /* This new key is older than the current one */
            if (tm_pkey_time[cur_key].activation_time.tv_sec > signed_pkey->time.tv_sec) {
                KERROR_SET(_shared_, 0, "received an outdated timestamp key");
                break;
            }

            kdsh_switch_tm_pkey_time();
            cur_key = kdsh_get_cur_tm_pkey();
            old_key = !cur_key;

            kdsh_get_cur_tm_pkey_time(&tm_pkey_time[cur_key]);
            kdsh_get_old_tm_pkey_time(&tm_pkey_time[old_key]);

            if (kdsh_set_cur_tm_pkey_time(signed_pkey) < 0) {
                kdsh_switch_tm_pkey_time();
                KERROR_PUSH(_shared_, 0, "error saving new timestamp key");
                break;
            }
            tm_pkey_obj[cur_key] = signed_pkey;
        }

        /* We are receiving an old key, let's see if it's still valid. */
        else if (tm_pkey_time[old_key].activation_time.tv_sec == signed_pkey->time.tv_sec) {
            /* Check if an instance of the current_key is available */
            if (tm_pkey_obj[old_key] == NULL) { /* not in cache for this process */
                tm_pkey_obj[old_key] = signed_pkey;
            } else {
                tagcrypt_signed_pkey_destroy(signed_pkey);
                signed_pkey = tm_pkey_obj[old_key];
            }
        }
        /* This is an unknown old key */
        else 
            KERROR_SET(_shared_, 0, "received an outdated timestamp key");
	
	error = 0;

    } while (0);

    if (error) {
        tagcrypt_signed_pkey_destroy(signed_pkey);
        signed_pkey = NULL;
    } 
    else {
        ki->owner = KEY_OWNER;
        ki->owner_s = KEY_OWNER_S;
        ki->data = NULL;
        ki->data_s = 0;
        ki->key = signed_pkey->key;
        /* HACK: We should not free structures under the nose of
           tagcryp.t */
        kfree(signed_pkey);

        apr_pool_cleanup_register(pool, ki->key,
                                  kdkey_destroy_pkey, kdkey_destroy_pkey);
    }

    kdsh_unlock();
    kbuffer_destroy(buf);

    return error;
}

/* Sign ki_in into ki_out, using signing_key. The buffered format of
   ki_in and ki_out does not match. */
int kdkey_sign_key(struct kdkey_info *ki_in, kbuffer *out, int for_enc_hack) {
    int err = -1;
    enum key_type type;
    kbuffer buf;
    tagcrypt_pkey *pkey_in = NULL;
    tagcrypt_skey *signing_key = NULL;

    type = kdkey_to_tagcrypt(ki_in->type);
    kstr str;

    /* TRY */
    do {
        /* put the key in a buffer */
        kstr_init_cstr(&str, ki_in->data);
        err = kbuffer_init_b64(&buf, &str);
        kstr_clean(&str);
        if (err) {
            err = -2;
            break;
        }
        err = -1;
        /* instanciate the key */
        pkey_in = tagcrypt_pkey_new(&buf, type);
        if (pkey_in == NULL)
            break;

        /* FIXME: ugly hack */
        if (for_enc_hack) signing_key = NULL;
        else {
            /* get the timestamp key */
            signing_key = tm_skey_info.key;
            if (signing_key == NULL)
                break;
        }
        /* sign the key */
        if (tagcrypt_sign_pkey(out, signing_key, pkey_in)) {
            KERROR_SET(_keys_, 0, "failed to sign key");
            break;
        }
        kbuffer_write8(out, '\0');
        
        err = 0;
    } while (0);
    
    if (err != -2) kbuffer_clean(&buf);
    tagcrypt_pkey_destroy (pkey_in);

    return err;
}

/* 
 * Passing NULL as the timestamp_pkey is a dirty hack to bypass
 * the signature verification. 
 *
 * This function does not, in fact, allocate anything on the pool, but
 * uses it to destroy the key.
 */
int kdkey_extract_signed_pkey(apr_pool_t *pool,
                              struct kdkey_info *tm_pkey,
                              const char *str_key,
                              size_t str_key_s,
                              struct kdkey_info *ki) {
    int error = -1;
    kbuffer *pkey_buffer;
    struct kdsh_tm_pkey_time tm_pkey_time[2];
    struct tagcrypt_signed_pkey *signed_pkey = NULL;
    int cur_key, old_key;
    struct timeval tm;
    tagcrypt_pkey *key;

    pkey_buffer = kbuffer_new();

    /* No locking is needed as we only want to store an approximate
       time. If there's a race, we'll still have an approximation of
       the time anyway. */

    do {
        cur_key = kdsh_get_cur_tm_pkey();
        old_key = !cur_key;

        kdsh_get_cur_tm_pkey_time(&tm_pkey_time[cur_key]);
        kdsh_get_old_tm_pkey_time(&tm_pkey_time[old_key]);

        kbuffer_write(pkey_buffer, (uint8_t *)str_key, str_key_s);
      
        if (tm_pkey == NULL) key = NULL; else key = tm_pkey->key;                                 
        if ((signed_pkey = tagcrypt_sign_get_pkey(pkey_buffer, key)) == NULL) {
            KERROR_SET(_keys_, 0, "cannot create public key from signed key");
            break;
        }

        if (tm_pkey == NULL && signed_pkey->mid != 0) {
            KERROR_SET(_keys_, 0, "invalid timestamp key for the signature");
            tagcrypt_signed_pkey_destroy(signed_pkey);
            break;
        }

        kdsh_get_timestamp(&tm);

        if (tm.tv_sec == 0 || tm.tv_sec - KSH_KEY_TIMEOUT <= signed_pkey->time.tv_sec) {
            if (tm_pkey != NULL) 
                tm.tv_sec = signed_pkey->time.tv_sec;
            
            ki->owner = KEY_OWNER;
            ki->owner_s = KEY_OWNER_S;
            ki->data = NULL;
            ki->data_s = 0;
            ki->key = signed_pkey->key;

            /* HACK: We should not free structure memory under the
               nose of tagcrypt that way. */
            kfree(signed_pkey);

            apr_pool_cleanup_register(pool, ki->key, 
                                      kdkey_destroy_pkey, kdkey_destroy_pkey);
        } 
        else {
            KERROR_SET(_keys_, 0, "received an outdated public key");
            tagcrypt_signed_pkey_destroy(signed_pkey);
        }
	
	error = 0;
    } while (0);

    if (error) {
        tagcrypt_signed_pkey_destroy(signed_pkey);
        signed_pkey = NULL;
    }

    kbuffer_destroy(pkey_buffer);

    return error;
}

/** Create a new unsigned public key.
 *
 * This is used to support older version of the key.  This does not
 * allocate anything on the pool but register a cleanup function to
 * remove the key.
 */
int kdkey_new_unsigned_pkey(apr_pool_t *pool, 
                            const char *pkey, 
                            size_t pkey_s, 
                            enum key_type ktype,
                            struct kdkey_info *ki) {
    tagcrypt_pkey *pk;
    kbuffer pkey_buf;
    int err = 0;
    kstr str;

    kstr_init_buf(&str, pkey, pkey_s);
    err = kbuffer_init_b64(&pkey_buf, &str);
    
    if (err != 0) {
        KERROR_SET(_keys_, 0, "cannot create public key");
        kstr_clean(&str);
        return -1;
    }
       
    do {
        pk = tagcrypt_pkey_new(&pkey_buf, ktype);
        if (pk == NULL) {
            KERROR_SET(_keys_, 0, "cannot create public key");
            err = -1;
            break;
        }

        ki->owner = KEY_OWNER;
        ki->owner_s = KEY_OWNER_S;
        ki->data = NULL;
        ki->data_s = 0;
        ki->key = pk;

        /* Register the key cleanup function. */
        apr_pool_cleanup_register(pool, pk, kdkey_destroy_pkey, kdkey_destroy_pkey);

    } while (0);

    kstr_clean(&str);
    kbuffer_clean(&pkey_buf);

    return err;
}

static int kdkey_load_skey(apr_pool_t *pool, kbuffer *key_data, struct kdkey_info *ki) {
    tagcrypt_skey *sk = NULL;

    sk = tagcrypt_skey_new(key_data);  
    ki->key = sk;

    /* Register a hook to remove the key. */
    apr_pool_cleanup_register(pool, sk, kdkey_destroy_skey, kdkey_destroy_skey);

    return (sk ? 0 : -1);
}

static int kdkey_load_pkey(apr_pool_t *pool, 
                           enum kdkey_type type, 
                           kbuffer *key_data, 
                           struct kdkey_info *ki) {
    tagcrypt_pkey *pk = NULL;
    enum key_type pk_type;

    switch (type) {
    case PKEY_ENCRYPTION:
        pk_type = KEY_TYPE_ENCRYPTION;
        break;
    case PKEY_SIGNATURE:
        pk_type = KEY_TYPE_IDENTITY;
        break;
    default:
        KERROR_SET(_keys_, 1, "Unknown key type.");
        return -1;
    }

    pk = tagcrypt_pkey_new(key_data, pk_type);
    ki->key = pk;

    /* Register a hook to remove the key. */
    apr_pool_cleanup_register(pool, pk, kdkey_destroy_pkey, kdkey_destroy_pkey);

    return (pk ? 0 : -1);
}

/** Tries to instanciate the key. 
 *
 * This call tagcrypt to instanciate a key.  This is useful to check
 * if the key was correctly loaded.
 * 
 * The object will be destroyed at pool destruction time.
 */
int kdkey_load_key(apr_pool_t *pool, struct kdkey_info *ki) {
    kbuffer key_data;
    kstr key_data_str;
    int r = -1;

    kstr_init_buf(&key_data_str, ki->data, ki->data_s);
    if (kbuffer_init_b64(&key_data, &key_data_str) < 0) {
        KERROR_SET(_keys_, 1, "failed to read key");
        return -1;
    }

    switch (ki->type) {
    case SKEY_ENCRYPTION:
    case SKEY_SIGNATURE:
        r = kdkey_load_skey(pool, &key_data, ki);
        break;
    case PKEY_ENCRYPTION:
    case PKEY_SIGNATURE:
        r = kdkey_load_pkey(pool, ki->type, &key_data, ki);
        break;
    default:
        KERROR_SET(_keys_, 1, "unknown key type");
        return -1;
    }

    kstr_clean(&key_data_str);
    kbuffer_clean(&key_data);

    return r;
}

static int kdkey_read_key_file(apr_pool_t *pool, apr_file_t *f, struct kdkey_info *ki) {
    apr_status_t s;
    char start[256];
    char key_id_str[256];
    char owner_str[256];
    char key[256];
    size_t sz;
    kbuffer *key_buffer;
    int r = -1;

    ki->owner = NULL;
    ki->owner_s = 0;
    ki->data = NULL;
    ki->data_s = 0;

    do {
        key_buffer = kbuffer_new();

        s = apr_file_gets(start, sizeof(start), f);
        if (s != APR_SUCCESS) {
            KERROR_SET_APR(_keys_, 0, s);
            break;
        }

        if (strcmp(start, start_sig_pkey) == 0) 
            ki->type = PKEY_SIGNATURE;
        else if (strcmp(start, start_sig_skey) == 0) 
            ki->type = SKEY_SIGNATURE;
        else if (strcmp(start, start_enc_pkey) == 0) 
            ki->type = PKEY_ENCRYPTION;
        else if (strcmp(start, start_enc_skey) == 0) 
            ki->type = SKEY_ENCRYPTION;
        else {
            KERROR_SET(_kctl_, 1, "Incorrect key format.  Unknown key type in %s.\n", start);
            break;
        }

        /* Read the key ID. */
        s = apr_file_gets(key_id_str, sizeof(key_id_str), f);            
        if (s != APR_SUCCESS) {
            KERROR_SET_APR(_keys_, 0, s);
            break;
        }

        /* Check the key number. */
        if (sscanf(key_id_str, PRINTF_64"u", &ki->key_id) < 1) {
            KERROR_SET(_kctl_, 1, "Invalid number: %s\n", key_id_str);
            break;
        }
        
        /* Read the key owner. */
        s = apr_file_gets(owner_str, sizeof(owner_str), f);
        if (s != APR_SUCCESS) {
            KERROR_SET_APR(_keys_, 0, s);
            break;
        }

        sz = strlen(owner_str);
        ki->owner = apr_pmemdup(pool, owner_str, sz - 1);
        ki->owner_s = sz - 1;

        /* Loop until we find the end delimiter, removing newlines on the
           way. */
        s = apr_file_gets(key, sizeof(key), f);
        if (s != APR_SUCCESS) {
            KERROR_SET_APR(_keys_, 0, s);
            break;
        }
        do {
            sz = strlen(key);
            if (key[sz - 1] == '\n')
                kbuffer_write(key_buffer, (uint8_t *)key, sz - 1);
            else
                kbuffer_write(key_buffer, (uint8_t *)key, sz);

            s = apr_file_gets(key, sizeof(key), f);
            if (s != APR_SUCCESS) {
                KERROR_SET_APR(_keys_, 0, s);
                break;
            }

        } while (strncmp(key, "---", 3) != 0);

        /* Copy the content of the buffer. */
        ki->data = apr_pmemdup(pool, key_buffer->data, key_buffer->len);
        ki->data_s = key_buffer->len;
   
        r = 0;
    } while (0);

    kbuffer_destroy(key_buffer);

    /* We don't create the tagcrypt right now. */
    ki->key = NULL;

    return r;
}

int kdkey_read_key(apr_pool_t *parent_pool, const char *key_file, struct kdkey_info *ki) {
    apr_file_t *f;
    apr_status_t s;
    apr_pool_t *pool;
    int r = -1;

    apr_pool_create(&pool, parent_pool);

    s = apr_file_open(&f, key_file, APR_READ, APR_OS_DEFAULT, pool);
    if (s != APR_SUCCESS) {
        KERROR_SET_APR(_keys_, 0, s);
        KERROR_PUSH(_keys_, 0, "failed to open key file: %s", key_file);
    } 
    else {
        if (kdkey_read_key_file(parent_pool, f, ki) < 0) 
            KERROR_PUSH(_keys_, 0, "key read error: %s", strerror(errno));
        else
            if (kdkey_load_key(parent_pool, ki) < 0) 
                KERROR_PUSH(_kctl_, 0, "invalid key");
            else        
                r = 0;
    } while (0);

    apr_pool_destroy(pool);

    return r;
}

/** Write a key in a file. */
int kdkey_write_key(apr_pool_t *parent_pool, const char *key_file, struct kdkey_info *ki) {
    int r = -1;
    apr_file_t *f;
    apr_status_t s;
    apr_pool_t *pool;
    const char *key_start = NULL, *key_end = NULL;
    char *str, *b64_data;
    size_t b64_sz, sz;

    apr_pool_create(&pool, parent_pool);

    s = apr_file_open(&f, key_file, APR_WRITE | APR_TRUNCATE | APR_CREATE, APR_OS_DEFAULT, pool);
    if (s != APR_SUCCESS) {
        KERROR_SET_APR(_keys_, 0, s);
        apr_pool_destroy(pool);
        return -1;
    }

    do {
        b64_sz = blockify_get_size(72, ki->data_s);
        b64_data = apr_palloc(pool, b64_sz);

        switch (ki->type) {
        case SKEY_ENCRYPTION:
            key_start = start_enc_skey;
            key_end = end_enc_skey;
            break;
        case SKEY_SIGNATURE:
            key_start = start_sig_skey;
            key_end = end_sig_skey;
            break;
        case PKEY_ENCRYPTION:
            key_start = start_enc_pkey;
            key_end = end_enc_pkey;
            break;
        case PKEY_SIGNATURE:
            key_start = start_sig_pkey;
            key_end = end_sig_pkey;
            break;
        default:
            KERROR_SET(_keys_, 0, "wrong key type");
            break;
        }
        if (key_start == NULL) break;
    
        blockify_base64(72, ki->data, ki->data_s, b64_data, b64_sz);

        s = apr_file_puts(key_start, f);
        if (s != APR_SUCCESS) goto write_error;
        
        str = apr_psprintf(pool, PRINTF_64"u\n", ki->key_id);
        s = apr_file_puts(str, f);
        if (s != APR_SUCCESS) goto write_error;

        sz = ki->owner_s;
        s = apr_file_write(f, ki->owner, &sz);
        if (s != APR_SUCCESS) goto write_error;

        s = apr_file_puts("\n", f);
        if (s != APR_SUCCESS) goto write_error;
        
        sz = b64_sz;
        s = apr_file_write(f, b64_data, &sz);
        if (s != APR_SUCCESS) goto write_error;

        if (b64_data[b64_sz - 1] != '\n') {
            s = apr_file_puts("\n", f);
            if (s != APR_SUCCESS) goto write_error;
        }           

        s = apr_file_puts(key_end, f);
        if (s != APR_SUCCESS) goto write_error;

        r = 0;
        break;

    write_error:
        KERROR_SET_APR(_keys_, 0, s);
        KERROR_PUSH(_keys_, 0, "error writing the key");

    } while (0);

    apr_pool_destroy(pool);

    return r;
}
