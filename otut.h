/**
 * tbxsosd/otut.c
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
 * High level OTUT management.
 *
 * @author François-Denis Gonthier
 */

#ifndef _OTUT_H
#define _OTUT_H

#include <tagcryptotut.h>

#include "common.h"
#include "keys.h"
#include "db.h"

int otut_gen_otuts(apr_pool_t *pool, 
                   struct tagcrypt_ticket *ticket,
                   uint32_t otut_count,
                   uint32_t *otut_replies,
                   char ***otut_str,
                   size_t **otut_str_s);

int otut_extract_ticket(apr_pool_t *pool,
                        const char *ticket_str,
                        size_t ticket_str_s,
                        struct tagcrypt_ticket **ticket);

int otut_gen_ticket(apr_pool_t *pool,
                    struct kd_user *self, 
                    uint32_t nb_valid, 
                    const char *otut_addr, 
                    kbuffer *sign_buf);

int otut_check_address(struct kd_user *self, const char *addr, const size_t addr_s);

#endif // _OTUT_H
