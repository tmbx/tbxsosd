/**
 * tbxsosd/libutils/process.h
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
 * @author: François-Denis Gonthier
 */

#ifndef _UTILS_PROCESS_H
#define _UTILS_PROCESS_H

#include <apr_pools.h>
#include <signal.h>
#include <kbuffer.h>

#include "gen_comm.h"
#include "file_comm.h"
#include "poll_comm.h"

struct process_args {
    /** Timeout */
    int timeout;    

    /** */
    const char **cmdline;
};

struct process {
    /** Timeout. */
    int timeout;
    
    /** Object pool. */
    apr_pool_t *pool;

    /** Process ID */
    pid_t pid;

    /** The process standard input. */
    kdcomm *pipe_in;

    /** The process standard output. */
    kdcomm *pipe_out;

    /** The process standard error. */
    kdcomm *pipe_err;

    /** SIGPIPE action. */
    struct sigaction sigpipe_action;

    /** SIGCHLD action. */
    struct sigaction sigchld_action;
};

int process_start(apr_pool_t *pool, struct process_args *args, struct process **proc);

int process_interact(struct process *proc,
                     kbuffer *in_buf,
                     kbuffer *out_buf,
                     kbuffer *err_buf);

#endif // _UTILS_PROCESS_H
