/**
 * tbxsosd/libfilters/filter_forward.c
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
 * Forwards mail to an address prior to packaging.
 * @author: François-Denis Gonthier
 */

#include <kerror.h>

#include "common/common.h"
#include "common/logid.h"

#include "libutils/sendmail.h"
#include "libdb/db.h"

#include "filters.h"

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
