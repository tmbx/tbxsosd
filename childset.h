/**
 * tbxsosd/childset.h
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
 * Child process set management.
 *
 * @author François-Denis Gonthier
*/

#ifndef _CHILDSET_H
#define _CHILDSET_H

#include <apr_pools.h>
#include <apr_poll.h>
#include <apr_hash.h>

#include "child.h"
#include "gen_comm.h"

struct __kdchildset {
    /** Pool for the object. */
    apr_pool_t *pool;
    
    /** Array of childs information. */
    apr_hash_t *childs;
};

typedef int kdchildset_do_proc(struct kdchild_data *cd, void *data);

typedef struct __kdchildset kdchildset;

/** Create a new childset. */
kdchildset *kdchildset_new(apr_pool_t *pool);

/** Add a new child in the childset. */
void kdchildset_add(kdchildset *cs, struct kdchild_data *cd);

/** Remove a child from the childset. */
void kdchildset_remove(kdchildset *self, struct kdchild_data *cd);

/** Get informations about a child given its PID. */
struct kdchild_data *kdchildset_get(kdchildset *cs, pid_t pid);

/** Send a signal to all childs. */
int kdchildset_do(kdchildset *cs, 
                  kdchildset_do_proc *proc, 
                  void *data);

/** Return a preforked client able to handle a request. */
struct kdchild_data *kdchildset_get_prefork_free(kdchildset *self);

/** Fork a new child, calling the 'entry' proc after fork. */
int kdchildset_fork_debug(kdchildset *self,
                          kdchild_entry_proc *entry);

/** Fork a new child, calling the 'entry' proc after fork. */
int kdchildset_fork(kdchildset *self,
                    int child_loop,
                    kdchild_entry_proc *entry,
                    struct kdchild_data **child_data);

/** ************* */

/** Wait for a request from the parent. */
int kdchild_wait(struct kdchild_data *cd);

/** Send a request to a child. */
int kdchild_send(struct kdchild_data *cd, int r);

#endif // _CHILDSET_H
