/**
 * tbxsosd/libcomm/misc_common.c
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
 * Miscellaneous routines for comm module.
 * @author: François-Denis Gonthier
 */

#include <poll.h>

#include "misc_comm.h"

enum comm_state kdcomm_fd_wait(kdcomm *self, int wait_what) {
    struct pollfd pfd;
    enum comm_state s = COMM_UNKNOWN;
    int n, e, tm;

    pfd.fd = self->fd;
    pfd.events = wait_what;

    if (self->timeout == COMM_TIMEOUT_POLL)
        tm = 0;
    else if (self->timeout == COMM_TIMEOUT_INFINITE)
        tm = -1;
    else
        tm = self->timeout;

    n = poll(&pfd, 1, tm);
    e = errno;

    /* Check for typical readyness. */
    if (n == 1 && (pfd.revents & wait_what))
        s = COMM_READY;

    /* Check for interruptions. */
    else if (n < 0 && e == APR_EINTR) 
        s = COMM_EINTR;
    
    /* Check for polling errors. */
    else if (n < 0)
        s = COMM_ERR;

    /* Check for hangup. */
    else if (pfd.revents & APR_POLLHUP) 
        s = COMM_HUP;

    /* Check for communication errors. */
    else if (pfd.revents & APR_POLLERR) 
        s = COMM_ERR;

    self->state = s;   

    return self->state;
}
