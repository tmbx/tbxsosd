/**
 * tbxsosd/libcomm/poll_comm.h
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
 * Simple APR poll wrapper using generic communication.
 * @author: François-Denis Gonthier
*/

#ifndef _COMM_POLL_H
#define _COMM_POLL_H

#include <sys/epoll.h>
#include <apr_pools.h>

#include "gen_comm.h"

#define COMM_POLLIN   EPOLLIN
#define COMM_POLLPRI  EPOLLPRI
#define COMM_POLLOUT  EPOLLOUT
#define COMM_POLLERR  EPOLLERR
#define COMM_POLLHUP  EPOLLHUP
#define COMM_POLLNVAL EPOLLNVAL

/** Returned items from kdcomm_poll. */
struct kdcomm_pollset_event {

    /** Flags raised for the channel. */
    int status;

    /** Communication channel. */
    kdcomm *comm;

    /** Miscellaneous data. */
    void *data;
};

typedef struct kdcomm_pollset kdcomm_pollset;

enum kdcomm_pollset_error {
    COMM_POLL_ERROR,
    COMM_POLL_INTR,
    COMM_POLL_OK
};

kdcomm_pollset *kdcomm_pollset_new(apr_pool_t *pool, int poll_nclient);

int kdcomm_pollset_add(kdcomm_pollset *p, kdcomm *c, int event_type, void *data);

int kdcomm_pollset_remove(kdcomm_pollset *p, kdcomm *c);

enum kdcomm_pollset_error kdcomm_pollset_poll(kdcomm_pollset *p, 
                                              apr_pool_t *pool, 
                                              int *nevents, 
                                              struct kdcomm_pollset_event **events);

int kdcomm_pollset_count(kdcomm_pollset *p);

void kdcomm_pollset_set_timeout(kdcomm_pollset *p, int timeout);

void kdcomm_pollset_set_sigset(kdcomm_pollset *p, sigset_t *s);

#endif // _COMM_POLL_H
