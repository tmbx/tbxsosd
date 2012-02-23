/**
 * tbxsosd/common/common.h
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
 * Generic data structures.
 *
 * @author François-Denis Gonthier
 */

#ifndef _COMMON_H
#define _COMMON_H

#include <apr_time.h>
#include <apr_pools.h>
#include <tagcrypt.h>
#include <kstr.h>

enum kd_user_type {
    /* Anonymous user is not identified. */
    KD_USER_ANONYMOUS,

    /* A normal user has been logged in. */
    KD_USER_NORMAL,

    /* User logged with OTUT. */
    KD_USER_OTUT
};

struct kd_organization {
    uint64_t org_id;

    char *license;

    char *forward_to;
};

struct kd_license {
    /** Time after which the license is no longer valid. */
    time_t best_after; 

    /** Time at which the license is no longer valid. */
    time_t best_before; 

    /** Capacity allocated by the license. */
    uint32_t caps;

    /** KDN to which the license is allocated. */
    char *kdn;

    /** KDN of the reseller organization. */
    char *parent_kdn;

    /** This will be set to 1 if the issued license is for a
        reseller. */
    uint32_t is_reseller;

    /** Limit of seat before warning. */
    int lim_seats;

    /** Maximum number of seats before refusing logins. */
    int max_seats;

    /** Raw license string. */
    char *license_data;
};

/* What the user CAN do. */
#define CAN_POD            0x01
#define CAN_ENCRYPT        0x02
#define CAN_SIGN           0x04
#define CAN_APPS           0x08
#define CAN_DO_EVERYTHING  CAN_POD | CAN_ENCRYPT | CAN_SIGN | CAN_APPS

enum kd_login_rights {
    LOGIN_RIGHTS_OK = 0,

    /* No longer used.
     *
     * LOGIN_RIGHTS_LIMIT = 1, 
     * LOGIN_RIGHTS_MAX = 2,
     */

    LOGIN_RIGHTS_DENIED = 3,

    LOGIN_RIGHTS_OK_NEW = 4
};

/** Data returned by a call to kddb_login_check. */
struct kd_login_result {
    /** Login rights.
     *
     * 0 = allowed.
     * 1-2 no longer used.
     * 3 = denied
     */
    enum kd_login_rights rights;

    uint64_t prof_id;

    uint64_t org_id;

    const char *token;
};

/** Additionnal information related to OTUT management. */
struct kd_otut {
    /** OTUT string used for login. */
    char *otut_str;

    /** Size of the OTUT string. */
    size_t otut_str_s;

    /** Key ID used to set the OTUT. */
    uint64_t key_id;

    /** tagcrypt OTUT object. */
    struct tagcrypt_otut *otut;
};

struct kd_user {
    /* Information is duplicated in that pool. */
    apr_pool_t *pool;

    /** The type of user. */
    enum kd_user_type type;

    /** What the user is technically able to do. */
    uint32_t caps;

    /** What the user is allowed to do. */
    uint32_t lic;

    /** Organization ID. */
    uint64_t org_id; 

    /** Profile ID for the user. (0 if unfiled) */
    uint64_t prof_id;

    /** Key ID for the user. (0 if unfiled) */
    uint64_t key_id;

    /** Distinguished name of the user in the LDAP directory. */
    char *user_dn;

    /** KPS Username */
    char *username;

    /** Profile name (full name of the user or the group). */
    char *full_name;

    struct kd_organization org;
    
    /** Primary email address. */
    char *primary_email_addr;

    /** Secret signature key. */
    struct kdkey_info *sig_skey;

    /** Public signature key. */
    struct kdkey_info *sig_pkey;

    /** Secret encryption key. */
    struct kdkey_info *enc_skey;

    /** Public encryption key. */
    struct kdkey_info *enc_pkey;

    /** OTUT information. */
    struct kd_otut *otut_info;
};

/** User object constructeur. */
static inline struct kd_user *kduser_new(apr_pool_t *pool) {
    struct kd_user *self;

    /* Allocate memory for the object. */
    self = apr_pcalloc(pool, sizeof(struct kd_user));
    self->pool = pool;

    return self;
}

#endif // _COMMON_H
