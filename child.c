/**
 * tbxsosd/child.h
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
 * Child process utitity functions.
 *
 * @author François-Denis Gonthier
 * 
*/

#include <assert.h>
#include <kerror.h>
#include <unistd.h>

#include "childset.h"
#include "child.h"
#include "utils.h"
#include "logid.h"
#include "logging.h"

/** Child low-memory handler for APR. */
int kdchild_lowmem_handler_apr(int retcode) {
    retcode = retcode;
    ERROR(_log_client_, "Out of memory.");
    _exit(EXIT_FAILURE);
}

/** Child low-memory handler for libktools. */
void kdchild_lowmem_handler_libktools() {
    kdchild_lowmem_handler_apr(0);
}

/** The file descriptor of the client connection in debug mode. */
int debug_child_fd;

/** Set to 1 before calling the client handler if the client is to be
    handled as SSL. */
int debug_child_fd_is_ssl;

/** Send a message down a child communication pipe. 
 *
 * EINTR will return an error.
 */
int kdchild_send(struct kdchild_data *child_data, int msg) {
    kbuffer *kb;

    assert(child_data->state != CHILD_DEBUG);

    kb = kbuffer_new();
    kbuffer_write32(kb, msg);
   
    /* Send the message. */
    if (kdcomm_write(child_data->pf_comm, kb) < 0) {
        KERROR_PUSH(_client_, 0, "error sending command to child");

        kbuffer_destroy(kb);
        return -1;
    }

    kbuffer_destroy(kb);

    return 0;
}

/** Send a file descriptor down a child communication pipe. 
 *
 * EINTR will return an error.
 */
int kdchild_send_client(struct kdchild_data *child_data, int cli_fd, int cli_fd_is_ssl) {
    assert(child_data->state != CHILD_DEBUG);
   
    if (kdchild_send(child_data, CHILD_MSG_CLIENT) < 0) {
        KERROR_PUSH(_client_, 0, "error sending command to child");
        return -1;
    }

    /* Send the file descriptor. */
    if (write_fd(child_data->pf_comm->fd, cli_fd, cli_fd_is_ssl) < 0) {
        KERROR_PUSH(_client_, 0, "error sending file descriptor to child");
        return -1;
    }

    return 0;
}

int kdchild_read(struct kdchild_data *child_data, uint32_t *child_cmd) {
    kbuffer *kb;
    uint32_t cmd;
        
    kb = kbuffer_new();

    assert(child_data->state != CHILD_DEBUG);

    if (kdcomm_read(child_data->pf_comm, kb, sizeof(cmd)) <= 0) {
        KERROR_PUSH(_client_, 0, "error reading command");

        kbuffer_destroy(kb);
        *child_cmd = CHILD_MSG_NONE;                    
        return -1;
    }

    kbuffer_read32(kb, &cmd);
    kerror_reset();
    kbuffer_destroy(kb);

    *child_cmd = cmd;

    return 0;
}
