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

#include <unistd.h>
#include <apr_file_io.h>
#include <apr_poll.h>
#include <apr_pools.h>
#include <apr_portable.h>
#include <assert.h>
#include <kerror.h>

#include "logid.h"
#include "gen_comm.h"
#include "file_comm.h"
#include "misc_comm.h"

static int kdfile_comm_get_peer(kdcomm *c, 
                                apr_pool_t *pool, 
                                const char **addr, 
                                struct sockaddr **sa) {
    c = c;
    pool = pool;
    addr = addr;
    sa = sa;
    
    /* This doesn't need to be implemented for now. */
    assert(1);
    return 0;
}

enum comm_state kdfile_comm_wait_write(kdcomm *c) {
    return kdcomm_fd_wait(c, APR_POLLOUT);
}

enum comm_state kdfile_comm_wait_read(kdcomm *c) {
    return kdcomm_fd_wait(c, APR_POLLIN);
}

static ssize_t kdfile_comm_read(kdcomm *c, void *buf, ssize_t buf_s) {
    kdfile_comm *self = (kdfile_comm *)c->obj;
    enum comm_state s;
    size_t recv_size;
    ssize_t bytes_read = 0;
    apr_status_t recv_err;
    apr_pool_t *read_pool;

    apr_pool_create(&read_pool, self->pool);

    do {
        s = kdfile_comm_wait_read(c);

        /* Perform the actual read. */
        if (s == COMM_READY) {
            recv_size = buf_s - bytes_read;
            recv_err = apr_file_read(self->apr_file, buf + bytes_read, &recv_size);

            if (recv_err != APR_SUCCESS )
                break;
            else if (recv_size > 0)
                bytes_read += recv_size;
        }

        /* No error, let the caller examine the state. */
        if (s == COMM_HUP || s == COMM_EINTR) 
            break;

        /* Error. */
        else if (s == COMM_ERR) {
            KERROR_SET(_comm_, 0, "read error");
            bytes_read = -1;
        }
    } while (0);

    apr_pool_destroy(read_pool);
    
    return bytes_read;
}

static ssize_t kdfile_comm_write(kdcomm *c, void *buf, ssize_t buf_s) {   
    kdfile_comm *self = (kdfile_comm *)c->obj;
    ssize_t bytes_sent = 0;
    apr_size_t send_size;
    apr_pool_t *write_pool;
    apr_status_t write_err;
    enum comm_state s = COMM_READY;

    apr_pool_create(&write_pool, self->pool);

    while (bytes_sent < buf_s) {
        s = kdfile_comm_wait_write(c);

        if (s == COMM_READY) {
            send_size = buf_s - bytes_sent;
            write_err = apr_file_write(self->apr_file, (buf + bytes_sent), &send_size);

            /* Write error. */
            if (send_size <= 0) {
                s = COMM_ERR;
                break;
            }

            /* Successful write. */
            else if (send_size > 0)
                bytes_sent += send_size;
        }

        else if (s == COMM_HUP || s == COMM_EINTR) 
            break;

        /* Error. */
        else if (s == COMM_ERR)
            break;
    }

    if (s == COMM_ERR) {
        c->state = COMM_ERR;
        KERROR_SET(_comm_, 0, "write error");
    }

    apr_pool_destroy(write_pool);

    if (bytes_sent < buf_s) 
        return 0;
    else
        return bytes_sent;
}

static void kdfile_comm_close(kdcomm *c) {
    kdfile_comm *self = (kdfile_comm *)c->obj;

    if (self->apr_file) {
        apr_file_close(self->apr_file);

        self->apr_file = NULL;
        self->c->fd = -1;
    }
}

static apr_status_t kdfile_comm_delete(void *data) {
    kdfile_comm *self = (kdfile_comm *)data;

    kdfile_comm_close(self->c);
    return APR_SUCCESS;
}

static struct comm_functions file_comm_funcs = {
    .wait_write_func  = kdfile_comm_wait_write,
    .wait_read_func   = kdfile_comm_wait_read,
    .read_func        = kdfile_comm_read,
    .write_func       = kdfile_comm_write,    
    .get_peer_func    = kdfile_comm_get_peer,
    .close_func       = kdfile_comm_close,
};

kdfile_comm *kdfile_comm_new_apr(apr_pool_t *pool, apr_file_t *apr_file) {
    kdfile_comm *self;

    self = apr_pcalloc(pool, sizeof(kdfile_comm));
    self->c = apr_pcalloc(pool, sizeof(kdcomm));
    self->c->funcs = &file_comm_funcs;
    self->c->state = COMM_READY;
    self->c->obj = self;

    self->apr_file = apr_file;

    /* Get the file descriptor for the APR socket. */
    apr_os_file_get(&self->c->fd, self->apr_file);
    
    /* Timeout is controlled by poll(). */
    apr_file_pipe_timeout_set(self->apr_file, 0);

    apr_pool_cleanup_register(pool, self, kdfile_comm_delete, kdfile_comm_delete);

    return self;
}

/** Constructor. */
kdfile_comm *kdfile_comm_new(apr_pool_t *pool, int file_flags, int fd) {
    kdfile_comm *self;

    self = apr_pcalloc(pool, sizeof(kdfile_comm));
    self->pool = pool;

    self->c = apr_pcalloc(pool, sizeof(kdcomm));
    self->c->funcs = &file_comm_funcs;
    self->c->state = COMM_READY;
    self->c->fd = fd;
    self->c->obj = self;

    /* Wrap in an APR file. */
    apr_os_file_put(&self->apr_file, &self->c->fd, file_flags, pool);

    /* Timeout is controlled by poll(). */
    apr_file_pipe_timeout_set(self->apr_file, 0);

    apr_pool_cleanup_register(pool, self, kdfile_comm_delete, kdfile_comm_delete);

    return self;
}

