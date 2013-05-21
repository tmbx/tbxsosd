/**
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
*/

#ifndef _PIPE_COMM_H
#define _PIPE_COMM_H

#include <apr_file_io.h>

#include "gen_comm.h"

struct __kdfile_comm {
    /** Pool. */
    apr_pool_t *pool;
    
    /** APR file. */
    apr_file_t *apr_file;

    /** Generic communication object. */
    kdcomm *c;
};

typedef struct __kdfile_comm kdfile_comm;

kdfile_comm *kdfile_comm_new(apr_pool_t *pool, int pipe_flags, int sock);

kdfile_comm *kdfile_comm_new_apr(apr_pool_t *pool, apr_file_t *apr_file);

kdcomm *kdfile_comm_get_comm(kdfile_comm *self);

int kdfile_comm_get_sock(kdfile_comm *self);

int kdfile_comm_get_apr_sock(kdfile_comm *self);

#endif // _PIPE_COMM_H
