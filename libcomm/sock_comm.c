/**
 * tbxsosd/libcomm/sock_comm.c
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
 * Standard socket.
 *
 * @author François-Denis Gonthier
*/

#include <sys/poll.h>
#include <apr_poll.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_portable.h>
#include <unistd.h>
#include <kerror.h>

#include "logid.h"
#include "logging.h"
#include "sock_comm.h"
#include "gen_comm.h"
#include "misc_comm.h"
#include "utils.h"

/** Return the address of the peer connected to the socket.
 *
 * Calls getpeername() on the socket.
 */
static int kdsock_comm_get_peer(kdcomm *c,
                                apr_pool_t *pool, 
                                const char **addr, 
                                struct sockaddr **peer) {
    kdsock_comm *self = (kdsock_comm *)c->obj;
    char *ad, *ads;
    socklen_t n;
    struct sockaddr_in si;

    n = sizeof(struct sockaddr_in);
    if (getpeername(self->c->fd, (struct sockaddr *)&si, &n) < 0)
        return -1;

    ad = inet_ntoa(si.sin_addr);
    ads = apr_pstrdup(pool, ad);

    if (addr != NULL) *addr = ads;
    if (peer != NULL) *peer = (struct sockaddr *)&si;

    return 0;
}

enum comm_state kdsock_comm_wait_read(kdcomm *c) {
    return kdcomm_fd_wait(c, APR_POLLIN);
}

enum comm_state kdsock_comm_wait_write(kdcomm *c) {
    return kdcomm_fd_wait(c, APR_POLLOUT);
}

/** Socket-specific read. */
static ssize_t kdsock_comm_read(kdcomm *c, void *buf, ssize_t buf_s) {
    kdsock_comm *self = (kdsock_comm *)c->obj;
    ssize_t bytes_read = 0;
    size_t recv_size;
    apr_pool_t *read_pool;    
    apr_status_t recv_err;
    enum comm_state s;
  
    apr_pool_create(&read_pool, self->pool);
       
    do {
        s = kdsock_comm_wait_read(c);

        if (s == COMM_READY) {
            recv_size = buf_s - bytes_read;
            recv_err = apr_socket_recv(self->apr_sock, buf + bytes_read, &recv_size);

            /* Read error. */
            if (recv_err != APR_SUCCESS || recv_err != APR_SUCCESS) {
                s = COMM_ERR;
                break;
            }

            /* Successful read. */
            else if (recv_size > 0) 
                bytes_read += recv_size;
        }

        /* No error, let the caller examine the state. */
        else if (s == COMM_HUP || s == COMM_EINTR) 
            break;

        /* Error. */
        else if (s ==  COMM_ERR) 
            break;
    } while (0);

    if (s == COMM_ERR) {
        self->c->state = COMM_ERR;
        KERROR_SET(_comm_, 0, "read error");
        bytes_read = -1;
    }

    apr_pool_destroy(read_pool);
    
    return bytes_read;
}

/** Socket-specific write. */
static ssize_t kdsock_comm_write(kdcomm *c, void *buf, ssize_t buf_s) {
    kdsock_comm *self = (kdsock_comm *)c->obj;
    ssize_t bytes_sent = 0;
    apr_size_t send_size;    
    apr_pool_t *write_pool;
    apr_status_t write_err;
    enum comm_state s = COMM_READY;

    apr_pool_create(&write_pool, self->pool);

    while (bytes_sent < buf_s) {
        s = kdsock_comm_wait_write(c);
        
        if (s == COMM_READY) {
            send_size = buf_s - bytes_sent;
            write_err = apr_socket_send(self->apr_sock, (buf + bytes_sent), &send_size);
            
            /* Write error. */
            if (send_size <= 0 || write_err != APR_SUCCESS) {
                s = COMM_ERR;
                break;
            }

            /* Succesful write. */
            else if (send_size > 0) 
                bytes_sent += send_size;                
        }

        /* No real error, let the caller examine the state. */
        else if (s == COMM_HUP || s == COMM_EINTR) 
            break;

        /* Error. */
        else if (s == COMM_ERR) 
            break;
    }

    if (s == COMM_ERR) {
        self->c->state = COMM_ERR;
        KERROR_SET(_comm_, 0, "write error");
    }

    apr_pool_destroy(write_pool);

    /* Note: we lie here about the number of data that was sent.  A
       partial write should be considered as a write failure by the callers. */
    if (bytes_sent < buf_s) 
        return 0;
    else
        return bytes_sent;
}

static void kdsock_comm_close(kdcomm *c) {
    kdsock_comm *self = (kdsock_comm *)c->obj;

    if (self->apr_sock) {
        if (self->auto_shutdown)
            kdsock_comm_shutdown(self, self->auto_shutdown);

        apr_socket_close(self->apr_sock);

        self->apr_sock = NULL;
        self->c->fd = -1;
    }
}

static struct comm_functions sock_comm_funcs = {
    .wait_write_func   = kdsock_comm_wait_write,
    .wait_read_func    = kdsock_comm_wait_read,
    .write_func        = kdsock_comm_write,
    .read_func         = kdsock_comm_read,
    .get_peer_func     = kdsock_comm_get_peer,
    .close_func        = kdsock_comm_close
};

/** Destructor. */
static apr_status_t kdsock_comm_delete(void *data) {
    kdsock_comm *self = (kdsock_comm *)data;

    kdsock_comm_close(self->c);
    return APR_SUCCESS;
}

/** Child-side destructor. */
static apr_status_t kdsock_comm_child_delete(void *data) {
    kdsock_comm *self = (kdsock_comm *)data;

    if (self->apr_sock) {
        apr_socket_close(self->apr_sock);

        self->apr_sock = NULL;
        self->c->fd = -1;
    }

    return APR_SUCCESS;
}

/** Constructor. */
kdsock_comm *kdsock_comm_new(apr_pool_t *pool, int fd, int auto_shutdown) {
    kdsock_comm *self;

    self = apr_pcalloc(pool, sizeof(kdsock_comm));
    self->pool = pool;

    self->c = apr_pcalloc(pool, sizeof(kdcomm));
    self->c->funcs = &sock_comm_funcs;
    self->c->state = COMM_UNKNOWN;
    self->c->fd = fd;
    self->c->obj = self;    

    self->auto_shutdown = auto_shutdown;

    /* Wrap in an APR socket. */
    apr_os_sock_put(&self->apr_sock, &self->c->fd, pool);

    /* We call the shots for the timeouts. */
    apr_socket_timeout_set(self->apr_sock, 0);

    /* Register a function to call close on the socket. */
    apr_pool_cleanup_register(pool, self, kdsock_comm_delete, kdsock_comm_child_delete);

    return self;
}

/** Construct a socket comm object from an APR socket. */
kdsock_comm *kdsock_comm_new_apr(apr_pool_t *pool, apr_socket_t *apr_sock, int auto_shutdown) {
    kdsock_comm *self;

    self = apr_pcalloc(pool, sizeof(kdsock_comm));
    self->pool = pool;

    self->c = apr_pcalloc(pool, sizeof(kdcomm));
    self->c->funcs = &sock_comm_funcs;
    self->c->state = COMM_UNKNOWN;
    self->c->obj = self;

    self->apr_sock = apr_sock;
    self->auto_shutdown = auto_shutdown;

    /* Extract the file descriptor. */
    apr_os_sock_get(&self->c->fd, self->apr_sock);

    /* We call the shots for the timeout. */
    apr_socket_timeout_set(self->apr_sock, 0);

    /* Register a function to close on the socket on pool
       destruction. */
    apr_pool_cleanup_register(pool, self, kdsock_comm_delete, kdsock_comm_child_delete);
    
    return self;
}

/** Wrapper for socketpair. */
int kdsock_comm_new_socketpair(apr_pool_t *pool1, kdsock_comm **comm1, 
                               apr_pool_t *pool2, kdsock_comm **comm2,
                               int auto_shutdown) {
    int fd[2] = {-1, -1};

    /* Create a pair of socket for communicating with the child. */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
        KERROR_SET(_server_, 0, "failed to create child communication socket");
        return -1;
    }

    /* Circumvent a kernel 2.6.22 bug.  Check if the file descriptors
       were actually set to something. */
    if (fd[0] == -1 || fd[1] == -1) {
        KERROR_SET(_server_, 0, "socketpair returned no file descriptors");
        return -1;
    }
    
    /* Create the communication objects. */
    *comm1 = kdsock_comm_new(pool1, fd[0], auto_shutdown);
    *comm2 = kdsock_comm_new(pool2, fd[1], auto_shutdown);

    apr_socket_opt_set((*comm1)->apr_sock, APR_SO_NONBLOCK, 1);
    apr_socket_opt_set((*comm2)->apr_sock, APR_SO_NONBLOCK, 1);
    
    return 0;
}

void kdsock_comm_shutdown(kdsock_comm *self, int how) {
    if (self->apr_sock)
        apr_socket_shutdown(self->apr_sock, how);
}
