/**
 * tbxsosd/common/common_pkg.h
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
 * Generic data structure for packaging.
 *
 * @author François-Denis Gonthier
 */

#ifndef _COMMON_PKG_H
#define _COMMON_PKG_H

#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_hash.h>
#include <tagcrypt.h>
#include <kstr.h>
#include <tbuffer.h>

enum proto_recipient_type { RECIP_KEY = 1, RECIP_PWD, RECIP_DONTCARE };

enum proto_body_type {
    BODY_TYPE_TEXT = 1,
    BODY_TYPE_HTML,
    BODY_TYPE_BOTH
};

enum proto_attachment_type { 
    ATTACH_HTML_BODY,
    ATTACH_TEXT_BODY,
    ATTACH_IMPLICIT,
    ATTACH_EXPLICIT, 
    ATTACH_UNKNOWN 
};

struct proto_attachment {
    /* Type of attachment we are dealing with. */
    enum proto_attachment_type attch_type;    

    /* Encoding of attachment. */
    const char *encoding;

    /* MIME-type of attachment. */
    const char *mime_type;

    /* Name of attachment. */
    const char *name;

    /* Payload. */
    char *payload;
    size_t payload_s;
};

struct proto_recipient {
    
    /* Address of the recipient, e.g. "left_part@right_part". */
    const char *addr;

    /* Key data if available.  Otherwise empty string. */
    const char *key_data;

    /* Type of recipient. */
    enum proto_recipient_type enc_type;    
};

struct proto_password {
    
    /* The password! */
    const char *pwd;

    /* The OTUT if available. */
    char *otut;

    /* Size of OTUT. */
    size_t otut_s;
};

struct proto_body_entry {
    uint32_t attch_type;

    const char *encoding;
    const char *mime_type;
    const char *name;

    const char *payload;
    size_t payload_s;
};

struct kd_signed {
    apr_pool_t *pool;

    /** Signature object. */
    tagcrypt_signature *sign;

    /* HTML body with fixed whitespaces. */
    kstr *wsbody_html;
        
    /* Text body with fixed newlines. */
    kstr *wsbody_text;

    /** Trimmed subject. */
    kstr *trimed_subject;
       
    /** Signature buffer. */
    kbuffer *sig_text;

    /** The KSN to be used for the signature. */
    char ksn[TAGCRYPT_KSN_SIZE];
};

struct kd_encrypted {
    apr_pool_t *pool;

    /** Encryptable content. */
    tbuffer *content;

    /** Symetric key for encryption. */
    tagcrypt_symkey *symkey;

    /** Encrypted content. */
    kbuffer *encrypted_content;

    /** Serialized symmetric key. */
    kbuffer *serialized_symkey;
};

/** Packaging informations. */
struct kd_package {
    apr_pool_t *pool;

    enum packet_type pkg_type;

    /* Counter for the KSN. */
    uint32_t counter;

    /** from name. */
    const char *from_name;

    /** From address. */
    const char *from_addr;

    /** PoD address. */
    const char *pod_addr;

    /** To. */
    const char *to;

    /** Cc. */
    const char *cc;

    /** Subject. */
    const char *subject;

    /* License data. */
    int with_license;
    uint32_t license_max;
    uint32_t license_lim;
    const char *license_kdn;

    /* Packet version. */
    uint32_t major;
    uint32_t minor;

    /* Packet langage */
    uint32_t lang;

    /* IP address to package. */
    struct sockaddr *addr;

    enum proto_body_type body_type;

    const char *text_body;
    size_t text_body_s;

    const char *html_body;
    size_t html_body_s;

    /* KPG address and port. */
    const char *kpg_addr;
    uint32_t kpg_port;

    /** */
    struct kdkey_info *sender_sig_skey;

    /** For PoD encryption of PoD. */
    struct kdkey_info *sender_sig_pkey;

    /** Table of receiver keys. */
    apr_array_header_t *recv_keys_array;

    /** Hash of receiver keys. */
    apr_hash_t *recv_keys_hash;

    /** Table of receiver passwords. */
    apr_array_header_t *recv_pwd_array;

    /** Hash of received passwords. */
    apr_hash_t *recv_pwd_hash;

    int attachment_count;

    struct proto_attachment **attachments;
};

#endif // _COMMON_PKG_H
