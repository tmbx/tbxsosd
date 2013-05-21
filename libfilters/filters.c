/**
 * tbxsosd/libfilters/filters.c
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
 * The Evil Filter.
 *
 * @author François-Denis Gonthier
 */

#include <apr_ring.h>
#include <kerror.h>

#include "options.h"
#include "filters.h"
#include "logid.h"
#include "logging.h"
#include "filter_spam.h"
#include "filter_virus.h"
#include "filter_from.h"
#include "filter_forward.h"

/* Worthless file if there is nothing to filter (ie, no packaging
   request compiled-in. */
#if defined(REQUEST_PACKAGE) || defined(REQUEST_PACKAGE_LICENSE)
             
/** Execute the filters. */
int kdfilter_exec(kdfilter *self, 
                  struct filter_params *params, 
                  struct filter_result *res) {
    struct filter_driver * en;

    memset(res, 0, sizeof(struct filter_result));

    for (en = APR_RING_FIRST(&self->filter_drv_list); 
         en != APR_RING_SENTINEL(&self->filter_drv_list, filter_driver, link);
         en = APR_RING_NEXT(en, link)) {

        kerror_reset();

        INFO(_log_filter_, "Filtering message with filter: %s", en->filter_name);

        /* Filter test phase. */
        DEBUG(_log_filter_, "Filter %s test phase.", en->filter_name);
        if ((en->p_test)(self, en->private_data) < 0) {
            if (kerror_has_error())
                KERROR_PUSH(_filter_, 0, "filter %s failed test phase", en->filter_name);
            else
                KERROR_SET(_filter_, 0, "filter %s failed test phase", en->filter_name);
            return -1;
        }
        
        /* Proceed to filtering. */
        DEBUG(_log_filter_, "Filter %s scan phase.", en->filter_name);
        if ((en->p_scan)(self, en->private_data, params, res) < 0) {
            if (kerror_has_error())
                KERROR_PUSH(_filter_, 0, "filter %s failed scan", en->filter_name);
            else
                KERROR_SET(_filter_, 0, "filter %s failed scan", en->filter_name);
            return -1;
        }

        if (res->msg_state)
            INFO(_log_filter_, "Filter %s report: %s", en->filter_name, res->msg);
        else
            INFO(_log_filter_, "Filter %s returned an empty report.", en->filter_name);

        DEBUG(_log_filter_, "Filter %s rating: %d.", en->filter_name, res->rating);

        /*
         * If one of those bit is set, that means we need to interrupt the filtering
         * and go back to the main loop for confirmation.
         */
        if ((res->rating & FILTER_EXEC_DENY) != 0 || (res->rating & FILTER_EXEC_CHALLENGE) != 0) 
            return 0;
    }

    return 0;
}

/** Open the filter and add the filter object to the list. */
int kdfilter_add(kdfilter *self, struct filter_driver *filter_drv) {
    DEBUG(_log_filter_, "Registering filter: %s.", filter_drv->filter_name);
	
    /* Open the filter driver. */
    if ((filter_drv->p_open)(self, &filter_drv->private_data) < 0) {
        filter_drv->private_data = NULL;
        filter_drv = NULL;
		
        return -1;
    }    
	
    /* Append the filter to the list. */
    APR_RING_INSERT_TAIL(&self->filter_drv_list, filter_drv, filter_driver, link);

    return 0;
}

/* Cleanup function. */
static apr_status_t kdfilter_delete(void *data) {
    kdfilter *self = (kdfilter *)data;
    struct filter_driver *drv;
    
    /* Call the close method of each filters. */
    for (drv = APR_RING_FIRST(&self->filter_drv_list); 
         drv != APR_RING_SENTINEL(&self->filter_drv_list, filter_driver, link); 
         drv = APR_RING_NEXT(drv, link)) {
        DEBUG(_log_filter_, "Unregistering filter: %s.", drv->filter_name);
        (drv->p_close)(self, drv->private_data);
    }
    
    return APR_SUCCESS;
}

/** */
kdfilter *kdfilter_new(apr_pool_t *pool) {
    kdfilter *self;
    apr_pool_t *obj_pool;
    const char *name = NULL;
    int spam_enabled, virus_enabled, from_enabled;

    apr_pool_create(&obj_pool, pool);

    self = apr_pcalloc(obj_pool, sizeof(kdfilter));
    APR_RING_INIT(&self->filter_drv_list, filter_driver, link);
    
    /* Register cleanup function. */
    apr_pool_cleanup_register(obj_pool, self, kdfilter_delete, kdfilter_delete);

    /* Add the default filters. */
    do {
        /* Check if we enable the spam filter. */
        spam_enabled = options_get_bool("filter_spam.enabled");
        virus_enabled = options_get_bool("filter_virus.enabled");
        from_enabled = options_get_bool("filter_spam.enabled");

        if (from_enabled && kdfilter_add(self, &filter_from) < 0) {
            name = filter_from.filter_name;
            break;
        }

        if (spam_enabled && kdfilter_add(self, &filter_spam) < 0) {
            name = filter_spam.filter_name;
            break;            
        }

        if (virus_enabled && kdfilter_add(self, &filter_virus) < 0) {
            name = filter_virus.filter_name;
            break;
        }

        if (kdfilter_add(self, &filter_forward) < 0) {
            name = filter_forward.filter_name;
            break;
        }

        self->pool = obj_pool;
        return self;

    } while (0);

    KERROR_PUSH(_filter_, 0, "filter %s failed initialization", name);
    
    apr_pool_destroy(obj_pool);

    return NULL;
}

#endif // REQUEST_PACKAGE || REQUEST_PACKAGE_LICENSE
