/**
 * tbxsosd/common/common_keys.h
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
 * Generic data structures for key management.
 *
 * @author François-Denis Gonthier
 */

#ifndef _COMMON_KEYS_H
#define _COMMON_KEYS_H

#include <stdlib.h>
#include <stdint.h>

/*
 * Those objects are used to select the right query to get encryption or
 * signature keys.
 */

/** Key types. */
enum kdkey_type {
    SKEY_START,

    /** secret keys */
    SKEY_MASTER,

    SKEY_TIMESTAMP,
    
    SKEY_ENCRYPTION,

    SKEY_SIGNATURE,

    SKEY_END,

    PKEY_START,

    /** public keys */
    PKEY_MASTER,

    PKEY_TIMESTAMP,
    
    PKEY_ENCRYPTION,

    PKEY_SIGNATURE,

    PKEY_LICENSE,

    PKEY_END
};

struct kdkey_info {
    uint64_t key_id;

    /* Owner name. */
    const char *owner;

    /* Size of owner name string. */
    size_t owner_s;

    /* Key data. */
    const char *data;

    /* Key data size. */
    size_t data_s;

    /** Type of the key. */
    enum kdkey_type type;

    /** Key object.  Cast to tagcrypt_*key for use. */
    void *key;
};

#endif // _COMMON_KEYS_H
