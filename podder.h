/**
 * tbxsosd/podder.h
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
 * Teambox Sign-On Server Daemon Proof of Delivery sender.
 * @author: François-Denis Gonthier 
 */

#ifndef _PODDER_H
#define _PODDER_H

#include <apr_pools.h>
#include <common_msg.h>
#include <tagcrypt.h>

struct kdpodder_params {
    /* PoD source from_addr. */
    const char *orig_from_addr;

    /* PoD source subject. */
    const char *orig_subject;

    /* PoD source IP. */
    const char *ip;

    /* PoD destination. */
    const char *pod_to;

    /* Signature packet. */
    tagcrypt_signature *sign;

    /* PoD date. */
    struct timeval *pod_date;
};

int kdpodder_send(apr_pool_t *pool, 
                  struct kdpodder_params *pod_params);

#endif // _PODDER_H
