/**
 * tbxsosd/libfilters/filter_from.c
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
 * From address/from name checker.
 *
 * @author François-Denis Gonthier
 */

#include <kerror.h>

#include "db.h"
#include "common.h"
#include "logid.h"
#include "filters.h"

#if defined(REQUEST_PACKAGE) || defined(REQUEST_PACKAGE_LICENSE)

int kdfilter_from_open(kdfilter* filter, void** data) {
    *data = filter;    
    return 0;
}

int kdfilter_from_close(kdfilter* filter, void *data) {
    filter = filter;
    data = data;

    /* No close operation. */
    return 0;
}

int kdfilter_from_test(kdfilter *filter, void *data) {
    filter = filter;
    data = data;

    /* No test operation. */
    return 0;
}

/** Makes sure the from_name and from_address fields are valid for the
    logged-in user. */
int kdfilter_from_scan(kdfilter *filter,
                       __attribute__ ((unused)) void *private_data,
                       struct filter_params *params,
                       struct filter_result *res) {
    int error = -1;
    apr_pool_t *pool;
    char *fullname;
    int is_allowed;

    /* If res == NULL, that means the result is not relevant.
       We don't have any serious processing to do here so bail out. */
    if (res == NULL) return 0;

    /* Can't do anything of the user is logged-in with an OTUT. */
    if (params->user->type == KD_USER_OTUT)
        return 0;

    apr_pool_create(&pool, filter->pool);
    
    do {
        /* First check if the user from name is valid. */
        if (kddb_get_full_name(pool, params->user, &fullname) < 0) {
            KERROR_PUSH(_filter_, 0, "failed to get full user name");      
            break;
        }
    
        if (strlen(params->msg.from_name) > 0 && strcasecmp(fullname, params->msg.from_name) != 0) {
            res->rating += 100;
            res->msg_state = 1;
            snprintf(res->msg, FILTER_MSG_SIZE, 
                     "The \"From name\" configured in your email client "
                     "application, %s, does not match the \"From name\" in "
                     "your KPS or LDAP profile, %s. Contact your system "
                     " administrator to apply the appropriate changes for"
                     " them to match.", 
                     params->msg.from_name, fullname);
	    error = 0;
            break;
        }

        /* Then check if the user is allowed to use that from_address for
           himself. */
	if (strlen(params->msg.from_addr) == 0) 
	    is_allowed = 0;
	
	else if (kddb_is_email_allowed(pool, 
                                       params->user, params->msg.from_addr, 
                                       &is_allowed, NULL) < 0) {
            KERROR_PUSH(_filter_, 0, "failed to verify user email address");    
            break;
	}

        if (!is_allowed) {
            res->rating += 100;
            res->msg_state = 1;
            snprintf(res->msg, FILTER_MSG_SIZE, 
                     "The \"From address\" configured in your email "
                     "client application, %s, does not match any of the "
                     "email addresses in your KPS or LDAP profile. Contact "
                     "your system administrator to apply the appropriate "
                     "changes for them to match.", params->msg.from_addr);
        }
    
        else {
            res->rating += (is_allowed == 1 ? 0 : 100);
            res->msg_state = 1;
            snprintf(res->msg, FILTER_MSG_SIZE, 
                     "from name/address are allowed for the user.");
        }
	
	error = 0;
	
    } while (0);

    apr_pool_destroy(pool);

    return error;
}

struct filter_driver filter_from = {
    .filter_name = "From Name/Address",
    .filter_id = 20,

    .p_open  = kdfilter_from_open,
    .p_close = kdfilter_from_close,
    .p_test  = kdfilter_from_test,
    .p_scan  = kdfilter_from_scan,

    NULL
};

#endif // REQUEST_PACKAGE || REQUEST_PACKAGE_LICENSE
