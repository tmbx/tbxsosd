/**
 * tbxsosd/podder.h
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
