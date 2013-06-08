/**
 * tbxsosd/keys.h
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

#ifndef KEYS_H
#define KEYS_H

#include <tagcrypt.h>

#include "common/common_keys.h"

/** Initialize static data for this module. 
 * 
 * This needs to be called for the module to work correctly.
 */
int kdkey_static_init();

/** Free static data for this module. */
int kdkey_static_clean();

/** Fetches a key. */
int kdkey_get_key(apr_pool_t *pool, 
                  uint64_t key_id, 
                  enum kdkey_type ktype, 
                  struct kdkey_info **ki);

/** Fetches a public encryption key. */
#define kdkey_get_enc_pkey(P, KID, KI)             \
    kdkey_get_key(P, KID, PKEY_ENCRYPTION, KI)

/** Fetches a private encryption key. */
#define kdkey_get_enc_skey(P, KID, KI)             \
    kdkey_get_key(P, KID, SKEY_ENCRYPTION, KI)

/** Fetches a public signature key. */
#define kdkey_get_sig_pkey(P, KID, KI)             \
    kdkey_get_key(P, KID, PKEY_SIGNATURE, KI)

/** Fetches a secret signature key. */
#define kdkey_get_sig_skey(P, KID, KI)             \
    kdkey_get_key(P, KID, SKEY_SIGNATURE, KI)

/** Extract a tagcrypt key from a signature. *
 *
 * HACK: Pass null to tm_pkey to bypass verification.
 * Uses the pool to register key cleanup.
 */
int kdkey_extract_signed_pkey(apr_pool_t *pool,
                              struct kdkey_info *tm_pkey,
                              const char *str_key,
                              size_t str_key_s,
                              struct kdkey_info *ki);

/** Get a timestamping key from a signed key.
 *
 * Uses the pool to register key cleanup.
 */
int kdkey_extract_tm_pkey(apr_pool_t *pool,
                          const char *str_key, 
                          size_t str_key_s, 
                          struct kdkey_info *tm_pkey);

/** Fetch the mastey pkey. 
 *
 * Returns a pointer to static data. 
 */
int kdkey_get_master_pkey(struct kdkey_info *ki);

/** Return a signed tagcrypt key in a buffer.
 *
 * HACK: For for_enc_hack is 1, skip signature an use a unchecked key.
 */
int kdkey_sign_key(struct kdkey_info *ki_in, 
                   kbuffer *out, 
                   int for_enc_hack);

/** Create a new unsigned tagcrypt key from key data.
 *
 * Uses the pool to register cleanup.  This is for older version of
 * protocols which used unsigned keys.
 */
int kdkey_new_unsigned_pkey(apr_pool_t *pool, 
                            const char *pkey, 
                            size_t pkey_s, 
                            enum key_type ktype,
                            struct kdkey_info *ki);

/** Write key data in a file.
 *
 */
int kdkey_write_key(apr_pool_t *parent_pool, const char *key_file, struct kdkey_info *ki);

/** Read key data from a file.
 *
 * This functions expect a key formatted with the kdkey_write_key
 * function.
 */
int kdkey_read_key(apr_pool_t *parent_pool, const char *key_file, struct kdkey_info *ki);

#endif // KEYS_H
