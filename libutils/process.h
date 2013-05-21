/**
 * tbxsosd/libutils/process.h
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
