/**
 * tbxsosd/server.h
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
 * Master server process.
 *
 * @author François-Denis Gonthier
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <apr_hash.h>

#include "gen_comm.h"
#include "shared.h"
#include "filters.h"
#include "childset.h"

/** Signal flag values. */
#define FLAG_NONE   0
#define FLAG_QUIT   1
#define FLAG_REHASH 2
#define FLAG_USER1  3
#define FLAG_CHILD  8
#define FLAG_ALARM  16

/** Private server data. */
struct __kdserver {
    apr_pool_t *pool;

    /** Raised when the server received a signal. */
    volatile sig_atomic_t sig_flag;

    /** Maximum client. */
    int client_max;

    /** Waiting time for clients that arrive beyond the maximum. */
    int client_wait;

    /** Number of clients to prefork. */
    int client_prefork;

    /** Listening socket backlog. */
    int sock_backlog;

    /** Number of listening server sockets. */
    int sock_count;

    /** Number of listening SSL sockets. */
    int ssl_sock_count;

    /** Number of listening normal sockets. */
    int n_sock_count;

    /** Number of strikes after which we terminate a hung child. */
    int term_strikes;

    /** Number of strikes after which we kill a hung child. */
    int kill_strikes;

    /** Interval at which child will be poked for activity. */
    int hang_check;

    /** All server sockets. */
    kdcomm **sock;

    /** SSL sockets. */
    kdcomm **ssl_sock;

    /** Normal sockets. */
    kdcomm **n_sock;

    /** All socket addresses. */
    struct sockaddr_in *sock_addr;

    /** SSL Server socket bind address. */
    struct sockaddr_in **ssl_sock_addr;

    /** Normal socket bind address. */
    struct sockaddr_in **n_sock_addr;

    /** Set of child process. */
    kdchildset *child_set;

    int fork;
};

typedef struct __kdserver kdserver;

/** Server instance signal handler. */
void kdserver_sig_handler(kdserver *sobj, int sig_id);

/** Instanciate a server object. */
kdserver *kdserver_new(apr_pool_t *pool);

/** Main server loop. */
int kdserver_main(kdserver *self, apr_pool_t *parent_pool);
