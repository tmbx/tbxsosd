/**
 * tbxsosd/common/common_keys.h
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
