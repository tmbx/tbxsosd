/**
 * tbxsosd/libcomm/gen_comm.h
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
 * Generic IO functions.
 *
 * @author François-Denis Gonthier
 */

#ifndef _GEN_COMM_H
#define _GEN_COMM_H

#include <apr_poll.h>
#include <apr_pools.h>
#include <apr_network_io.h>
#include <kbuffer.h>

/** Just poll() without delay. */
#define COMM_TIMEOUT_POLL      -1

/** Don't even poll(), just consider the stream ready. */
#define COMM_TIMEOUT_NONE      -2

/** Wait indefinitely. */
#define COMM_TIMEOUT_INFINITE  -3

enum comm_state {
    COMM_READY,
    COMM_EINTR,
    COMM_ERR,
    COMM_HUP,
    COMM_UNKNOWN
};

struct __kdcomm {
    /** Timeout in milliseconds. */
    int timeout;

    /** Concrete implementation functions. */
    struct comm_functions *funcs;

    /** The object last state. */
    enum comm_state state;

    /** Underlying file descriptor. */
    int fd;

    /** Comm implementation private state. */
    void *obj;
};

typedef struct __kdcomm kdcomm;

struct comm_functions {
    /** Waits for read-readyness. */

    enum comm_state (*wait_read_func)(kdcomm *self);

    /** Waits for write-readyness. */
    enum comm_state (*wait_write_func)(kdcomm *self);

    /** Concrete close function. */
    void (*close_func)(kdcomm *self);

    /** Concrete read function. */
    ssize_t (*read_func)(kdcomm *self, void *buf, ssize_t buf_s);

    /** Concrete write function. */
    ssize_t (*write_func)(kdcomm *self, void * buf, ssize_t buf_s);

    /** Return the peer name. */
    int (*get_peer_func)(kdcomm *self, 
                         apr_pool_t *pool, 
                         const char **addr, 
                         struct sockaddr **sa);
};

static inline int kdcomm_get_peer(kdcomm *self, 
                                  apr_pool_t *pool, 
                                  const char **addr, 
                                  struct sockaddr **sa) {
    return (self->funcs->get_peer_func)(self, pool, addr, sa);
}

static inline ssize_t kdcomm_write(kdcomm *self, kbuffer *buf) {
    return (self->funcs->write_func)(self, buf->data, buf->len);
}

ssize_t kdcomm_read(kdcomm *self, kbuffer *buf, ssize_t buf_s);

/** Wait for the comm channel to be ready to write. */
static inline enum comm_state kdcomm_wait_write(kdcomm *self) {
    return (self->funcs->wait_write_func)(self);
}

/** Wait for the comm channel to be ready to read. */
static inline enum comm_state kdcomm_wait_read(kdcomm *self) {
    return (self->funcs->wait_read_func)(self);
}

/** Write a static buffer on a comm channel. */
static inline ssize_t kdcomm_write_raw(kdcomm *self, void *buf, ssize_t buf_s) {
    return (self->funcs->write_func)(self, buf, buf_s);
}

/** Read a static buffer on a comm channel. */
static inline ssize_t kdcomm_read_raw(kdcomm *self, void *buf, ssize_t buf_s) {
    return (self->funcs->read_func)(self, buf, buf_s);
}

static inline void kdcomm_close(kdcomm *self) {
    (self->funcs->close_func)(self);
}

int kdcomm_read_line(kdcomm *self, 
                     kbuffer *line_buf, 
                     kbuffer *store_buf);

int kdcomm_write_fully(kdcomm *self, kbuffer *buf);

int kdcomm_read_fully(kdcomm *self, kbuffer *buf);

void kdcomm_close(kdcomm *self);

#endif // _GEN_CLIENT_H
