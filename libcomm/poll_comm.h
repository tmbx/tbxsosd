/**
 * tbxsosd/libcomm/poll_comm.h
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
 * Simple APR poll wrapper using generic communication.
 * @author: François-Denis Gonthier
*/

#ifndef _COMM_POLL_H
#define _COMM_POLL_H

#include <sys/epoll.h>
#include <apr_pools.h>

#include "gen_comm.h"

#define COMM_POLLIN   EPOLLIN
#define COMM_POLLPRI  EPOLLPRI
#define COMM_POLLOUT  EPOLLOUT
#define COMM_POLLERR  EPOLLERR
#define COMM_POLLHUP  EPOLLHUP
#define COMM_POLLNVAL EPOLLNVAL

/** Returned items from kdcomm_poll. */
struct kdcomm_pollset_event {

    /** Flags raised for the channel. */
    int status;

    /** Communication channel. */
    kdcomm *comm;

    /** Miscellaneous data. */
    void *data;
};

typedef struct kdcomm_pollset kdcomm_pollset;

enum kdcomm_pollset_error {
    COMM_POLL_ERROR,
    COMM_POLL_INTR,
    COMM_POLL_OK
};

kdcomm_pollset *kdcomm_pollset_new(apr_pool_t *pool, int poll_nclient);

int kdcomm_pollset_add(kdcomm_pollset *p, kdcomm *c, int event_type, void *data);

int kdcomm_pollset_remove(kdcomm_pollset *p, kdcomm *c);

enum kdcomm_pollset_error kdcomm_pollset_poll(kdcomm_pollset *p, 
                                              apr_pool_t *pool, 
                                              int *nevents, 
                                              struct kdcomm_pollset_event **events);

int kdcomm_pollset_count(kdcomm_pollset *p);

void kdcomm_pollset_set_timeout(kdcomm_pollset *p, int timeout);

void kdcomm_pollset_set_sigset(kdcomm_pollset *p, sigset_t *s);

#endif // _COMM_POLL_H
