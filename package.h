/**
 * tbxsosd/package.h
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
 * Teambox Sign-On Server Daemon mail messages processing functions.
 *
 * @author François-Denis Gonthier
 */

#ifndef _PACKAGE_H
#define _PACKAGE_H

#include <apr_tables.h>
#include <apr_pools.h>
#include <apr_hash.h>
#include <assert.h>
#include <tagcrypt.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>

#include "common_pkg.h"
#include "packet.h"

/** Set the KSN to be used for the signature. */
int kdpackage_set_ksn(struct kd_package *pkg, const char *ksn);

/** Add an encryption key. */
int kdpackage_add_recver_enc_pkey(struct kd_package *pkg,
                                  struct kdkey_info *tm_pkey, 
                                  const char *pkey,
                                  const char *addr);

/** Add an encryption password. */
int kdpackage_add_recver_pwd(struct kd_package *self, 
                             const char *pwd,
                             const char *otut, 
                             size_t otut_s);

/** Encrypt the message, producing a new text body. */
int kdpackage_encrypt(struct kd_package *pkg, struct kd_encrypted *enc);

/** Produce the signature. */
int kdpackage_sign(struct kd_package *self, struct kd_encrypted *enc, struct kd_signed *sig);

/** Make the packet out of the signed thingee. */
int kdpackage_packet(apr_pool_t *pool,
                     struct kd_package *pkg,
                     struct kd_encrypted *enc,
                     struct kd_signed *sig,
                     struct kdpacket *pkt);

struct kd_package *kdpackage_new(apr_pool_t *pool);

struct kd_signed *kdpackage_new_signed(apr_pool_t *pool, struct kd_package *pkg);

struct kd_encrypted *kdpackage_new_encrypted(apr_pool_t *pool);

void kdpackage_format(struct kd_package *pkg,
                      apr_pool_t *pool,
                      struct kd_encrypted *enc,
                      struct kd_signed *sig,
                      kbuffer *buf);

#endif // _PACKAGE_H
