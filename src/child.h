/**
 * tbxsosd/child.c
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
 * Child process utitity functions.
 *
 * @author François-Denis Gonthier
*/

#ifndef CHILDS_H
#define CHILDS_H

#include "libcomm/gen_comm.h"

#define CHILD_MSG_NONE 0

/** Sent by the client when processing is done and it is ready for
    handling a new request. */
#define CHILD_MSG_DONE 1

/** Sent by the server to a client to check for child health. */
#define CHILD_MSG_PING 2

/** Sent by the client to the server in reply to a ping message. */
#define CHILD_MSG_PONG 3

/** Sent by the server to the client to announce a client fd is
    following. */
#define CHILD_MSG_CLIENT 4

enum kdchild_state {
    /** Not handling a client, waiting one. */
    CHILD_FREE,

    /** Handling a client at the moment. */
    CHILD_BUSY,

    /** Debug mode.  Not forked. */
    CHILD_DEBUG,
};

struct kdchild_data;
typedef int kdchild_entry_proc(apr_pool_t *pool, struct kdchild_data *cd);

struct kdchild_data {
    /** Pool for the structure. */
    apr_pool_t *pool;

    /** Identifier. */
    pid_t pid;

    /** Socket to the client process, used for passing descriptors
        around. */
    kdcomm *pf_comm;

    /** State of the client process. */
    enum kdchild_state state;

    /** Loop for clients. */
    int child_loops;

    /** Child entry procedure. */
    kdchild_entry_proc *entry_proc;

    /** Number of strikes against the child (for master process). */
    int num_strikes;

    /** Start timestamp. */
    time_t start_time;
};

/** Passed to debug pseudo-childs. */
extern int debug_child_fd;
extern int debug_child_fd_is_ssl;

/** Wait for an incoming client connection from the parent. */
int kdchild_wait_client(struct kdchild_data *child_data);

/** Send the fd for a client connection to a child. */
int kdchild_send_client(struct kdchild_data *child_data, int cli_fd, int cli_fd_is_ssl);

/** Read a command from a child communication channel. */
int kdchild_read(struct kdchild_data *child_data, uint32_t *child_cmd);

/** Low-memory handler for APR. */
int kdchild_lowmem_handler_apr(int retcode);

/** Low-memory handler for libktools. */
void kdchild_lowmem_handler_libktools();

#endif // CHILDS_H
