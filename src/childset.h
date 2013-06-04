/**
 * tbxsosd/childset.h
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
#include "libcomm/gen_comm.h"

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
