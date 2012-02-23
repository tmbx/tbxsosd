/**
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
