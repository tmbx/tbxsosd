/**
 * tbxsosd/otut.c
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
