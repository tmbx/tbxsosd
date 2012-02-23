/**
 * tbxsosd/common/common_dpkg.h
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
 * Generic data structure for depackaging.
 *
 * @author François-Denis Gonthier
 */

#ifndef _COMMON_DPKG_H
#define _COMMON_DPKG_H

#include <apr_pools.h>
#include <stdint.h>
#include <tagcrypt.h>

enum kd_dpkg_result {
    DPKG_NONE,
    DPKG_PARTIAL,
    DPKG_FULL,
    DPKG_BAD_PWD,
    DPKG_NOT_ALLOWED,
    DPKG_ERROR 
};

struct kd_decrypted {
    apr_pool_t *pool;
    
    /** OTUT. */
    kbuffer *otut;

    /** Symmetric key. */
    kbuffer *symkey;

    /** OTUT buffer. */
    kbuffer *otut_buf;

    /** Symmetric key (partial or final), to be returned to the client. */
    kbuffer *symkey_out;

    /** Decryption password. */
    kbuffer *password;

    /** */
    char *otut_str;
    size_t otut_str_s;

    /* This points to symkey_final. */
    char *symkey_str;
    size_t symkey_str_s;
    
    /** Decryption email, if requested and if available, otherwise "". */
    char *dec_email;
};

struct kd_dpkg {
    apr_pool_t *pool;

    /** Required for signature. */
    tagcrypt_signature *sign;

    const char *password_str;
    size_t password_str_s;

    const char *symkey_str;
    size_t symkey_str_s;

    const char *otut_str;
    size_t otut_str_s;

    /** PoD source address. */
    const char *podfrom_str;
    size_t podfrom_str_s;

    /** PoD destination address. */
    const char *podto_str;
    size_t podto_str_s;

    const char *subject_str;
    size_t subject_str_s;

    /** Teambox's timestamp key. */
    struct kdkey_info *tm_pkey;

    /** Sender's public identity key. */
    struct kdkey_info *sender_sig_pkey;

    /** Sender's private identity key. */
    struct kdkey_info *sender_sig_skey;

    /** Sender's public encryption key. */
    struct kdkey_info *sender_enc_pkey;

    /** Sender's private encryption key. */
    struct kdkey_info *sender_enc_skey;

    /** Receiver own encryption key. */
    struct kdkey_info *recver_enc_skey;
    
    /** True if the client wants to receive the decryption email adress. */
    uint32_t want_dec_email;
};

#endif // _COMMON_DPKG_H
