/**
 * tbxsosd/server.h
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
 * Master server process.
 *
 * @author François-Denis Gonthier
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <apr_hash.h>

#include "libcomm/gen_comm.h"
#include "libfilters/filters.h"

#include "shared.h"
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
