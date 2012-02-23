/**
 * tbxsosd/client.h
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
 * Teambox Sign-On Server Daemon client process manager.
 *
 * @author François-Denis Gonthier
 */

#ifndef _CLIENT_H
#define _CLIENT_H

#include <apr_pools.h>

#include "libfilters/filters.h"
#include "childset.h"
#include "common.h"
#include "common_dpkg.h"
#include "common_keys.h"
#include "proto.h"
#include "gen_comm.h"

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
