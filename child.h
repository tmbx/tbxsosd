/**
 * tbxsosd/child.c
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
 * Child process utitity functions.
 *
 * @author François-Denis Gonthier
*/

#ifndef CHILDS_H
#define CHILDS_H

#include "gen_comm.h"

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
