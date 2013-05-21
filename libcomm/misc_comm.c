/**
 * tbxsosd/libcomm/misc_common.c
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
