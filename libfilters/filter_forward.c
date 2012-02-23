/**
 * tbxsosd/libfilters/filter_forward.c
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
 * Forwards mail to an address prior to packaging.
 * @author: François-Denis Gonthier
 */

#include <kerror.h>
#include <sendmail.h>

#include "db.h"
#include "common.h"
#include "filters.h"
#include "sendmail.h"
#include "logid.h"

int kdfilter_forward_open(kdfilter *filter, void **data) {
    filter = filter;
    data = data;
    return 0;
}

int kdfilter_forward_close(kdfilter *filter, void *data) {
    filter = filter;
    data = data;
    return 0;
}

int kdfilter_forward_test(kdfilter *filter, void *data) {
    filter = filter;
    data = data;
    return 0;
}

int kdfilter_forward_scan(kdfilter *filter,
                          void *private_data,
                          struct filter_params *params,
                          struct filter_result *res) {
    apr_pool_t *pool;
    struct sendmail_args sm;
    char *addr;
    int err = -1;

    private_data = private_data;

    /* If we have a non-empty archiving address we can proceed. */
    addr = params->user->org.forward_to;

    res->rating = FILTER_EXEC_OK;
    res->msg_state = 1;

    if (addr != NULL && strlen(addr) > 0) {
        apr_pool_create(&pool, filter->pool);

        sm.mail_to = addr;
        sm.msg = &params->msg;

        /* Send the message. */
        if (sendmail(pool, &sm) < 0) 
            KERROR_PUSH(_filter_, 0, "failed to forward message");

        /* Prepare the result. */
        else {
            sprintf(res->msg, "Message has been forwarded to %s for archiving.", addr);
            err = 0;
        }

        apr_pool_destroy(pool);
    } 
    /* Let the message through. */
    else {
        sprintf(res->msg, "Message does not need to be forwarded.");
        err = 0;
    }
    
    return err;
}

struct filter_driver filter_forward = {
    .filter_name = "Pre-packaging forwarder",
    .filter_id = 30,

    .p_open = kdfilter_forward_open,
    .p_close = kdfilter_forward_close,
    .p_test = kdfilter_forward_test,
    .p_scan = kdfilter_forward_scan,
    
    NULL
};
