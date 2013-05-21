/**
 * tbxsosd/libcomm/poll_comm.c
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
 * Simple APR poll wrapper using generic communication.
 * @author: François-Denis Gonthier
 */

#include <sys/epoll.h>
#include <apr_pools.h>
#include <signal.h>
#include <kerror.h>
#include <unistd.h>

#include "logging.h"
#include "gen_comm.h"
#include "logid.h"
#include "utils.h"
#include "poll_comm.h"

struct kdcomm_pollset_data {
    /** Void miscellaneous data. */
    void *data;

    /** Comm object. */
    kdcomm *comm;
};

struct kdcomm_pollset {
    /** Pool to use to allocate internal objects. */
    apr_pool_t *pool;

    /** epoll fd. */
    int epfd;

    /** Number of file descriptions registered with epoll. */
    int cnt;

    /** Timeout, in milliseconds. */
    int timeout;

    /** Signal mask. */
    sigset_t *sigset;
};

unsigned int kdcomm_hashfunc(const char *key, apr_ssize_t *s) {
    *s = *s;
    return (unsigned int)key;
}

static apr_status_t kdcomm_pollset_destroy(void *data) {
    kdcomm_pollset *p = (void *)data;

    close(p->epfd);
    return APR_SUCCESS;
}

/** Creates a new poll set. */
kdcomm_pollset *kdcomm_pollset_new(apr_pool_t *pool, int nclient) {
    kdcomm_pollset *p;

    p = apr_pcalloc(pool, sizeof(struct kdcomm_pollset));

    p->epfd = epoll_create(nclient);
    if (p->epfd < 0) {
        KERROR_SET(_misc_, 0, kerror_sys(errno));
        return NULL;
    }
    
    p->pool = pool;

    apr_pool_cleanup_register(p->pool, p, kdcomm_pollset_destroy, kdcomm_pollset_destroy);

    return p;
}

/** Add a communication channel in the poll set. */
int kdcomm_pollset_add(kdcomm_pollset *p, kdcomm *c, int event_type, void *data) {
    struct kdcomm_pollset_data *ev_data;
    struct epoll_event *ev;

    /* Setup the epoll event. */
    ev = apr_pcalloc(p->pool, sizeof(struct epoll_event));
    ev_data = apr_pcalloc(p->pool, sizeof(struct kdcomm_pollset_data));

    ev->events = event_type;
    ev->data.ptr = ev_data;

    ev_data->comm = c;
    ev_data->data = data;

    p->cnt++;

    /* Add to the epoll set. */
    if (epoll_ctl(p->epfd, EPOLL_CTL_ADD, c->fd, ev) < 0) {
        KERROR_SET(_misc_, 0, "error adding fd %d: %s", c->fd, kerror_sys(errno));
        return -1;
    }

    return 0;
}

/** Remove a communication channel from the poll set. */
int kdcomm_pollset_remove(kdcomm_pollset *p, kdcomm *c) {
    if (epoll_ctl(p->epfd, EPOLL_CTL_DEL, c->fd, NULL) < 0) {
        KERROR_SET(_misc_, 0, "error removing fd %d: %s", c->fd, kerror_sys(errno));
        return -1;
    }

    p->cnt--;

    return 0;
}

/** Return the number of sockets we are waiting on. */
int kdcomm_pollset_count(kdcomm_pollset *p) {
    return p->cnt;
}
 
/** Set the poll timeout in milliseconds. */
void kdcomm_pollset_set_timeout(kdcomm_pollset *p, int timeout) {
    p->timeout = timeout;
}

/** Set the signal mask. */
void kdcomm_pollset_set_sigset(kdcomm_pollset *p, sigset_t *s) {
    p->sigset = s;
}

/** Perform the poll on all channels. */
enum kdcomm_pollset_error kdcomm_pollset_poll(kdcomm_pollset *p, 
                                              apr_pool_t *pool, 
                                              int *nevents, 
                                              struct kdcomm_pollset_event **events) {
    int n, e;
    struct epoll_event *ev;
    apr_pool_t *tmp_pool;

    apr_pool_create(&tmp_pool, pool);

    *nevents = -1;
    *events = NULL;

    ev = apr_pcalloc(tmp_pool, sizeof(struct epoll_event) * p->cnt);

    if (!p->sigset) 
        n = epoll_wait(p->epfd, ev, p->cnt, p->timeout);        
    else
        n = epoll_pwait(p->epfd, ev, p->cnt, p->timeout, p->sigset);

    e = errno;

    if (n < 0 && e == EINTR) {
        apr_pool_destroy(tmp_pool);
        return COMM_POLL_INTR;
    }
    else if (n < 0) {
        KERROR_SET(_misc_, 0, "poll error");
        apr_pool_destroy(tmp_pool);
        return COMM_POLL_ERROR;
    }

    /* Prepare an array for the return values. */
    if (n > 0) {
        int i;
        struct kdcomm_pollset_event *pev;

        /* Translate the returned events into kdcomm_pollset_event
           structs. */
        pev = apr_pcalloc(pool, sizeof(struct kdcomm_pollset_event) * n);

        for (i = 0; i < n; i++) {
            pev[i].status = ev[i].events;
            pev[i].comm = ((struct kdcomm_pollset_data *)ev[i].data.ptr)->comm;
            pev[i].data = ((struct kdcomm_pollset_data *)ev[i].data.ptr)->data;
        }
        *events = pev;
        *nevents = n;
    }
    else 
        *nevents = 0;

    apr_pool_destroy(tmp_pool);
    
    return COMM_POLL_OK;
}
