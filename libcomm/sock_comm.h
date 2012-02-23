/**
 * tbxsosd/libcomm/sock_comm.h
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
