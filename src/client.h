/**
 * tbxsosd/client.h
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
 * Teambox Sign-On Server Daemon client process manager.
 *
 * @author François-Denis Gonthier
 */

#ifndef _CLIENT_H
#define _CLIENT_H

#include <apr_pools.h>

#include "common/common.h"
#include "common/common_dpkg.h"
#include "common/common_keys.h"
#include "libfilters/filters.h"
#include "libcomm/gen_comm.h"

#include "childset.h"
#include "proto.h"

enum client_state {
    /* The client will be dropped as soon as possible. */
    CSTATE_DROP_NOW = 1,
    
    /* The client will be dropped after the next outgoing message. */
    CSTATE_DROP_ACK,
    
    /* The client is not logged-in. */
    CSTATE_NOT_CONNECTED,
    
    /* The client is fully logged-in. */
    CSTATE_CONNECTED,

    /* The client is logged-in with an OTUT. */
    CSTATE_CONNECTED_OTUT
};

/** Client private data... and I mean *private*! */
struct __kdclient {
    apr_pool_t *pool;

    enum client_state cstate;

    /** Client socket. */
    kdcomm *main_comm;

    /** Child data. */
    struct kdchild_data *child_data;
	
    /** Evil Filter Object. */
    kdfilter *filter_obj;

    /** */
    struct kd_user *user;

    /** Protocol translator. */
    kdprotocol *proto;

    /** Counter to use for generatings KSNs. */
    uint32_t counter;

    int allow_html;

    /** Number of the certificate this client was sent. */
    int cert_num;
};

typedef struct __kdclient kdclient;

kdclient *kdclient_new(apr_pool_t *pool, struct kdchild_data *cd);

int kdclient_static_init(apr_pool_t *pool);

void kdclient_static_clean();

int kdclient_mem_abort_handler(int retcode);

/** Client handling entry point. */
int kdclient_main(apr_pool_t *pool, struct kdchild_data *cd);

#endif // _CLIENT_H
