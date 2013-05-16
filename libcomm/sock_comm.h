/**
 * tbxsosd/libcomm/sock_comm.h
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
 * Standard socket.
 *
 * @author François-Denis Gonthier
 */

#ifndef _SOCK_COMM_H
#define _SOCK_COMM_H

#include <apr_network_io.h>
#include <apr_pools.h>

#include "gen_comm.h"

/** NOTE: The destructor effectively close the underlying socket. */

#define COMM_SHUT_RD    SHUT_RD
#define COMM_SHUT_WR    SHUT_WR
#define COMM_SHUT_RDWR  SHUT_RDWR

/** Socket communication object. */
struct __kdsock_comm {
    /** Pool for the object. */
    apr_pool_t *pool;

    /** APR socket. */
    apr_socket_t *apr_sock;

    /** Generic communication object. */
    kdcomm *c;

    /** Set this to 1 if you want to shutdown the socket on close. */
    int auto_shutdown;
};

typedef struct __kdsock_comm kdsock_comm;

/** Return a generic communication object given a socket. */
kdcomm *kdsock_comm_get_comm(kdsock_comm *self);

/** Return the native file descriptor wrapped by this object. */
int kdsock_comm_get_sock(kdsock_comm *self);

/** Return the APR socket underlying this socket. */
int kdsock_comm_get_apr_sock(kdsock_comm *self);

/** Shutdown the socket. */
void kdsock_comm_shutdown(kdsock_comm *self, int how);

/** Creates a new socket object around a native file descriptor. */
kdsock_comm *kdsock_comm_new(apr_pool_t *pool, int sock, int auto_shutdown);

kdsock_comm *kdsock_comm_new_apr(apr_pool_t *pool, apr_socket_t *apr_sock, int auto_shutdown);

int kdsock_comm_new_socketpair(apr_pool_t *pool1, kdsock_comm **comm1, 
                               apr_pool_t *pool2, kdsock_comm **comm2,
                               int auto_shutdown);

#endif // _SOCK_COMM_H
