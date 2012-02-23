/**
 * tbxsosd/childset.c
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

#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_thread_proc.h>
#include <apr_poll.h>
#include <apr_strings.h>
#include <unistd.h>
#include <kerror.h>
#include <kmem.h>
#include <time.h>

#include "signals.h"
#include "logid.h"
#include "logging.h"
#include "sock_comm.h"
#include "gen_comm.h"
#include "childset.h"
#include "child.h"
#include "utils.h"

/** Create a new childset. */
kdchildset *kdchildset_new(apr_pool_t *pool) {
    kdchildset *cs;

    cs = apr_pcalloc(pool, sizeof(kdchildset));
    cs->childs = apr_hash_make(pool);
    cs->pool = pool;

    return cs;
}

/** Get informations about a child given its PID. */
struct kdchild_data *kdchildset_get(kdchildset *self, pid_t pid) {
    return apr_hash_get(self->childs, &pid, sizeof(pid_t));
}

/** Add a new child in the childset. 
 *
 * Makes a copy of the struct passed as parameter.  This procedure is
 * called by the forking procedures so it should not be necessary to
 * call it manually.
 */
void kdchildset_add(kdchildset *self, struct kdchild_data *child_data) {
    DEBUG(_log_prefork_, "Adding child %d.", child_data->pid);

    apr_hash_set(self->childs, &child_data->pid, sizeof(pid_t), child_data);
}

/** Remove a child from the childset. */
void kdchildset_remove(kdchildset *self, struct kdchild_data *child_data) {
    DEBUG(_log_prefork_, "Removing child %d.", child_data->pid);

    apr_hash_set(self->childs, &child_data->pid, sizeof(pid_t), NULL);
    apr_pool_destroy(child_data->pool);    
}

/** Get access to a preforked client that is not busy. */
struct kdchild_data *kdchildset_get_prefork_free(kdchildset *self) {
    apr_hash_index_t *hi;
    apr_pool_t *pool;
    struct kdchild_data *cd = NULL;
    struct kdchild_data *cd_ret = NULL;
    void *p;

    apr_pool_create(&pool, self->pool);

    for (hi = apr_hash_first(pool, self->childs);
         hi;
         hi = apr_hash_next(hi)) {
        p = &cd;
        apr_hash_this(hi, NULL, 0, p);

        /* Return the first free client we find. */
        if (cd->state == CHILD_FREE) {
            DEBUG(_log_prefork_, "Found child %d.", cd->pid);
            cd_ret = cd;
            break;
        }
    }   

    apr_pool_destroy(pool);

    return cd_ret;
}

/** Call a function on all childs. */
int kdchildset_do(kdchildset *self, 
                  kdchildset_do_proc *exec_proc, 
                  void *data) {
    apr_hash_index_t *hi;
    apr_pool_t *pool;
    struct kdchild_data *cd = NULL;
    void *p;
    int n = 0;

    apr_pool_create(&pool, self->pool);

    for (hi = apr_hash_first(pool, self->childs);
         hi;
         hi = apr_hash_next(hi)) {
        p = &cd;
        apr_hash_this(hi, NULL, 0, p);

        n = exec_proc(cd, data);
        if (n < 0) {
            apr_pool_destroy(pool);
            return -1;
        }
    }

    apr_pool_destroy(pool);
    return 0;
}


/** Pseudo for for single process debugging
 *
 * Doesn't return any child data since it doesn't fork any childs ^_^.
 */
int kdchildset_fork_debug(kdchildset *self, kdchild_entry_proc *proc) {  
    struct kdchild_data cd;
    apr_pool_t *child_pool;

    self = self;

    /* Create the root pool for the child. */
    /* FIXME: Lowmem handler. */
    apr_pool_create(&child_pool, NULL);

    cd.pool = NULL;
    cd.pid = 0;
    cd.pf_comm = NULL;
    cd.state = CHILD_DEBUG;

    /* Call the child entry procedure. */
    if ((*proc)(child_pool, &cd) < 0) {
        kd_error(_log_server_, "Client process returned an error");
    }

    apr_pool_destroy(child_pool);

    return 0;
}

/** Fork a new child process. */
int kdchildset_fork(kdchildset *self, 
                    int child_loops,
                    kdchild_entry_proc *proc,
                    struct kdchild_data **child_data) {
    int cur_stderr;
    apr_proc_t child_proc;
    apr_pool_t *child_pool, *proc_pool, *cd_pool;
    kdsock_comm *child_comm, *parent_comm;
    apr_status_t err;
    struct kdchild_data *cd;

    /* Duplicate our stderr to the client, he'll need it later. */
    cur_stderr = dup(2);

    /* Create the pool that will hold the process object. */
    apr_pool_create(&proc_pool, self->pool);
    /* Parent's child data pool. */
    apr_pool_create(&cd_pool, self->pool);
    /* Child pool. */
    apr_pool_create_ex(&child_pool, NULL, kdchild_lowmem_handler_apr, NULL);

    /* Setup the libktools handler. */       
    kmem_set_handler(NULL, NULL, NULL, NULL, kdchild_lowmem_handler_libktools, NULL);

    /** Create the socket pair. */
    if (kdsock_comm_new_socketpair(cd_pool, &parent_comm, child_pool, &child_comm, 0) < 0) {
        KERROR_PUSH(_server_, 0, "failed to create socket pair");
        return -1;
    }

    /* Both of those socket will behave like blocking sockets. */
    parent_comm->c->timeout = COMM_TIMEOUT_INFINITE;
    child_comm->c->timeout = COMM_TIMEOUT_INFINITE;

    /* Forks the client process. */
    err = apr_proc_fork(&child_proc, proc_pool);

    if (err != APR_INPARENT && err != APR_INCHILD) {
        KERROR_SET_APR(_server_, 0, err);
        KERROR_PUSH(_server_, 0, apr_perror(self->pool, err));
        return -1;
    }
    if (err == APR_INPARENT) {
        apr_pool_destroy(child_pool);

        /* Don't need that one anymore. */
        close(cur_stderr);

        DEBUG(_log_prefork_, "Forked client %d", child_proc.pid);

        cd = apr_pcalloc(cd_pool, sizeof(struct kdchild_data));
        cd->pid = child_proc.pid;
        cd->child_loops = child_loops;
        cd->pool = cd_pool;
        cd->state = CHILD_FREE;
        cd->pf_comm = parent_comm->c;
        cd->start_time = time(NULL);

        /* Add the child record in the set of running child. */
        kdchildset_add(self, cd);
        *child_data = cd;

        apr_pool_destroy(proc_pool);

        return 0;
    }
    if (err == APR_INCHILD) {
        int e;

        apr_pool_destroy(proc_pool);
        apr_pool_destroy(cd_pool);

        /* Reset the signal handling. */
        kdsignal_clear_handled();
        kdsignal_clear_ignored();

        /* Redirect the server stderr to our own. */
        dup2(cur_stderr, 2);
        close(cur_stderr);

        cd = apr_pcalloc(child_pool, sizeof(struct kdchild_data));
        cd->child_loops = child_loops;
        cd->pid = getpid();
        cd->state = CHILD_FREE;
        cd->pf_comm = child_comm->c;
        cd->start_time = time(NULL);

        /* Close the standard outputs and server-side communication
           socket. */
        close(0);
        close(1);  

        /* Call the child entry procedure. */
        e = (*proc)(child_pool, cd);
        if (e < 0) 
            kd_error(_log_server_, "Child process quit with error");
        
        /* Hard exit. */
        apr_pool_destroy(child_pool);
        _exit(e < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
    }

    /* Should not be reached. */
    return -1;
}

