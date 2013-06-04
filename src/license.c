/**
 * tbxsosd/license.c
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
 * Loads and check organization license data.
 * Author: François-Denis Gonthier
*/

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <tagcrypt.h>
#include <tagcryptsignature.h>
#include <kbuffer.h>
#include <tbuffer.h>
#include <kerror.h>
#include <base64.h>

#include "common/logid.h"
#include "common/common_keys.h"
#include "libutils/utils.h"

#include "keys.h"
#include "license.h"

static int kdlicense_load_data(apr_pool_t *pool, tbuffer *tbuf, struct kd_license *lic) {
    int terr;
    const char *kdn, *parent_kdn;
    size_t kdn_s, parent_kdn_s;
    uint32_t dummy_ver;

    /* Version (ignored and dummy for now). */
    terr = tbuffer_read_uint32(tbuf, &dummy_ver);
    if (terr) {
        KERROR_PUSH(_misc_, 0, "failed to read license data: license version");
        return -1;
    }

    /* KDN. */
    terr = tbuffer_read_string(tbuf, &kdn, &kdn_s);   
    if (terr) {
        KERROR_PUSH(_misc_, 0, "failed to read license data: KDN");
        return -1;
    }
    lic->kdn = apr_pstrmemdup(pool, kdn, kdn_s);

    /* Parent's KDN. */
    terr = tbuffer_read_string(tbuf, &parent_kdn, &parent_kdn_s);
    if (terr) {
        KERROR_PUSH(_misc_, 0, "failed to read license data: Parent KDN");
        return -1;
    }
    lic->parent_kdn = apr_pstrmemdup(pool, parent_kdn, parent_kdn_s);
    
    /* Capacity. */
    terr = tbuffer_read_uint32(tbuf, &lic->caps);
    if (terr) {
        KERROR_PUSH(_misc_, 0, "failed to read license data: capacities");
        return -1;
    }

    /* Best after. */
    terr = tbuffer_read_uint32(tbuf, (uint32_t *)&lic->best_after);
    if (terr) {
        KERROR_PUSH(_misc_, 0, "failed to read license data: best after date");
        return -1;
    }    

    /* Best before. */
    terr = tbuffer_read_uint32(tbuf, (uint32_t *)&lic->best_before);
    if (terr) {
        KERROR_PUSH(_misc_, 0, "failed to read license data: best before date");
        return -1;
    }

    /* Limit of seats before warning. */
    terr = tbuffer_read_uint32(tbuf, (uint32_t *)&lic->lim_seats);
    if (terr) {
        KERROR_PUSH(_misc_, 0, "failed to read license data: seats limit");
        return -1;
    }

    /* Absolute maximum seats. */
    terr = tbuffer_read_uint32(tbuf, (uint32_t *)&lic->max_seats);
    if (terr) {
        KERROR_PUSH(_misc_, 0, "failed to read license data: maximum seats");
        return -1;
    }

    /* Is reseller?. */
    terr = tbuffer_read_uint32(tbuf, (uint32_t *)&lic->is_reseller);
    if (terr) {
        KERROR_PUSH(_misc_, 0, "failed to read license data: is_reseller");
        return -1;
    }

    return 0;
}

int kdlicense_check(struct kd_license *lic) {
    time_t now;

    now = time(NULL);

    /* Check if the license has expired. */
    if (lic->best_before < now) {
        KERROR_SET(_misc_, 0, "license has expired");
        return -1;
    }
    
    /* Check if the license is valid. */
    if (lic->best_after > now) {
        KERROR_SET(_misc_, 0, "license is not valid yet");
        return -1;
    }

    return 0;
}

static int kdlicense_load(apr_pool_t *pool, kbuffer *lic_bin, struct kd_license *lic) {
    int err = -1;
    tbuffer *tbuf;
    tagcrypt_signature *sig = NULL;
    char *blob = NULL;
    size_t blob_s = 0;
    struct kdkey_info *ki;
    kbuffer *buf;
    
    /* Load the license key. */
    if (kdkey_get_key(pool, 0, PKEY_LICENSE, &ki) < 0) {
        KERROR_PUSH(_misc_, 0, "failed to obtain license public key");
        return err;
    } 

    /* Check the license data signature. */
    sig = tagcrypt_signature_new_serialized(lic_bin, ki->key);
    if (sig == NULL) {
        KERROR_SET(_misc_, 0, "license signature is invalid");
        return err;
    } 
        
    if (tagcrypt_signature_get_blob(sig, &blob, &blob_s) < 0) {
        KERROR_SET(_misc_, 0, "failed to obtain license data from license");
        return err;
    } 

    /* Look inside the license for data. */
    else {
        buf = kbuffer_new();
        kbuffer_write(buf, (uint8_t *)blob, blob_s);
        tbuf = tbuffer_new_dbuf(buf);
        
        if (kdlicense_load_data(pool, tbuf, lic) < 0) 
            KERROR_PUSH(_misc_, 0, "failed to read license data");
        else
            err = 0;
        
        kbuffer_destroy(buf);
        tbuffer_destroy(tbuf);
    }

    tagcrypt_sign_destroy(sig);

    return err;
}

/** Decode a license string and return the data it contains. */
int kdlicense_new(apr_pool_t *parent_pool, char *license_data, struct kd_license *lic) {
    int err = -1;
    kbuffer *lic_bin, *lic_b64;

    /* Convert to binary. */
    lic_bin = kbuffer_new();
    lic_b64 = kbuffer_new();

    kbuffer_write_cstr(lic_b64, license_data);
    kb642bin(lic_b64, lic_bin, 0);

    /* Load the license object. */
    if (kdlicense_load(parent_pool, lic_bin, lic) == 0) 
        err = 0;
    
    kbuffer_destroy(lic_bin);
    kbuffer_destroy(lic_b64);

    return err;
}

int kdlicense_open(apr_pool_t *parent_pool, char *lic_file, struct kd_license *lic) {
    int err = -1;
    apr_pool_t *pool;
    apr_file_t *f;
    apr_status_t s;
    char *lic_buf;
    const size_t lic_buf_s = 4096;
    size_t sz;

    apr_pool_create(&pool, parent_pool);
    
    lic_buf = apr_palloc(parent_pool, lic_buf_s);

    /* Open the license file key. */
    s = apr_file_open(&f, lic_file, APR_READ, APR_OS_DEFAULT, pool);
    if (s != APR_SUCCESS) {
        KERROR_SET_APR(_misc_, 0, s);
        KERROR_PUSH(_misc_, 0, "failed to open license file: %s", lic_file);
    }

    else {    
        /* Fully read the file. */
        s = apr_file_read_full(f, lic_buf, lic_buf_s - 1, &sz);
        if (s != APR_EOF) {
            KERROR_SET_APR(_misc_, 0, s);
            KERROR_PUSH(_misc_, 0, "failed to read from file: %s", lic_file);
        }

        /* Decode the license. */
        else {
            lic_buf[sz < 4096 ? sz : 4096] = '\0';
            lic->license_data = lic_buf;

            err = kdlicense_new(parent_pool, lic_buf, lic);
        }
    }

    apr_pool_destroy(pool);
        
    return err;
}

static void kdlicense_to_tbuffer(struct kd_license *lic, tbuffer *tbuf) {
    /* License version (version 1 right now). */
    tbuffer_write_uint32(tbuf, 1);

    /* KDN. */
    tbuffer_write_cstr(tbuf, lic->kdn);

    /* Parent KDN (empty string if == none). */
    if (lic->parent_kdn == NULL) 
        tbuffer_write_cstr(tbuf, "");
    else
        tbuffer_write_cstr(tbuf, lic->parent_kdn);

    /* Capacities. */
    tbuffer_write_uint32(tbuf, lic->caps); 

    /* Best after. */
    tbuffer_write_uint32(tbuf, lic->best_after);

    /* Best before. */
    tbuffer_write_uint32(tbuf, lic->best_before);

    /* Seats limits. */
    tbuffer_write_uint32(tbuf, lic->lim_seats);
    tbuffer_write_uint32(tbuf, lic->max_seats);
    
    /* Is reseller? */
    tbuffer_write_uint32(tbuf, lic->is_reseller);
}

int kdlicense_sign(apr_pool_t *pp, const char *key_file, struct kd_license *lic, kbuffer *sig_buf) {
    int err = -1;
    tbuffer *tbuf;
    kbuffer *kbuf;
    struct kdkey_info ki;    
    tagcrypt_signature *sig;
    struct tagcrypt_blob_params bp;
    apr_pool_t *pool;

    apr_pool_create(&pool, pp);

    /* Load the license signature key. */
    if (kdkey_read_key(pool, key_file, &ki) < 0) 
        KERROR_PUSH(_misc_, 0, "failed to read key file: %s", key_file);
        
    else {    
        /* Make sure this is a private key. */
        if (ki.type != SKEY_SIGNATURE && ki.type != SKEY_ENCRYPTION) 
            KERROR_SET(_misc_, 0, "wrong key type");
        else {
            sig = tagcrypt_sign_new(TAG_P_TYPE_SIGN, 2, 1, (tagcrypt_skey *)ki.key);
            if (!sig) 
                KERROR_SET(_misc_, 0, "cannot create signature with key");

            /* Actually create the signature for the license. */
            else {
                tbuf = tbuffer_new(1024);
                kbuf = kbuffer_new();

                kdlicense_to_tbuffer(lic, tbuf);

                bp.type = 0;
                bp.blob = tbuffer_get_dbuf(tbuf);

                /* Add the license data to the signature. */
                tagcrypt_sign_add_subpacket(sig, TAG_SP_TYPE_BLOB, &bp);

                /* Serialize the signed license data. */
                tagcrypt_sign_serialize(sig, kbuf);
                tagcrypt_sign_destroy(sig);
                kbin2b64(kbuf, sig_buf);

                tbuffer_destroy(tbuf);
                kbuffer_destroy(kbuf);

                err = 0;
            }
        }
    }

    apr_pool_destroy(pool);

    return err;
}
