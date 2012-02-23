/**
 * tbxsosd/libfilters/filters.h
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
 * The Evil Filter.
 *
 * @author François-Denis Gonthier
 */

#ifndef _FILTERS_H
#define _FILTERS_H

#include <apr_ring.h>

#include "common_msg.h"
#include "config.h"

typedef struct __kdfilter kdfilter;

/** List of filter drivers. */
APR_RING_HEAD(filter_driver_list, filter_driver);

/** Structure of a message to be filtered. */
struct filter_params {    
    struct kd_user *user;

    struct message msg;
};

#define FILTER_MSG_SIZE 250

/** Result of filtering. */
struct filter_result {
    int rating;

    /** Determines the presence of data inside the msg element. */
    int msg_state;

    /** Formatted message describing the result of the filter.  
     *
     * This message is only set when msg_state != 0.
     */
    char msg[FILTER_MSG_SIZE];
};

struct filter_driver {
    /** Pointer to the next filter driver. */
    APR_RING_ENTRY(filter_driver)
    link;

    /** Friendly name of the filter. */
    const char * filter_name;

    /** ID of the filter. 
     * 
     * Does not need to be unique (yet).  Identifies specific internal filters.
     */
    const int filter_id;

    /** Filter open function.  Must return < 0 on failure. */
    int (* p_open)(kdfilter *filter, void **pv);

    /** Filter close function.  
     * 
     * Should return < 0 on failure.  Failure may/will be ignored.
     */
    int (* p_close)(kdfilter *filter, void *pv);

    /** Filter test function.  
     *
     * Used to test the liveness of the filter, for example the
     * liveness to the daemon that will filter the message.
     */
    int (* p_test)(kdfilter *filter, void *pv);

    /** Proceeds to filtering.  
     * 
     * Fills the filter_result structure.  Returns < 0 on failure to
     * process the message.
     */
    int (* p_scan)(kdfilter *filter, 
                   void *pv,
                   struct filter_params *params,
                   struct filter_result *res);

    /** Private data for this filter.
     * 
     * This should be free on driver close.
     */
    void * private_data;
};

struct __kdfilter {
    apr_pool_t *pool;

    struct filter_driver_list filter_drv_list;    
};

/**
 * ID that identifies the spam filter.
 */
#define FILTER_ID_SPAM         10

/**
 * ID that identifies the virus filter.
 */
#define FILTER_ID_VIRUS        11

/**
 * Bit that determines that the filter result,
 * whatever it is, means the message wants confirmation
 * of the user.
 */
#define FILTER_EXEC_CHALLENGE  0x10

/**
 * Bit that determines that the filter result,
 * whatever it is, means the message is denied.
 */
#define FILTER_EXEC_DENY       0x20

/**
 * Sent when the filtered message can be sent.
 */
#define FILTER_EXEC_OK             0

/**
 * Sent when the filtered message maybe be spam
 * and when a confirmation is demanded.
 */
#define FILTER_EXEC_MAYBE_SPAM     1 | FILTER_EXEC_CONFIRM

/**
 * Sent when the filtered message is spam and
 * will not be sent.
 */
#define FILTER_EXEC_IS_SPAM        2 | FILTER_EXEC_DENY

/**
 * Sent when the filtered message contains a
 * virus and can't be sent.
 */
#define FILTER_EXEC_IS_VIRUS       3 | FILTER_EXEC_DENY

/**
 * Sent when a filter ask that a particular
 * message should be set for proof of delivery.
 */
#define FILTER_EXEC_POD_PLEASE     4 | FILTER_EXEC_CONFIRM

/**
 * Sent when a filter ask that a particupar
 * message should be encrypted.
 */
#define FILTER_EXEC_ENCRYPT_PLEASE 5 | FILTER_EXEC_CONFIRM

/**
 * Sent when a filter decides that a message
 * should not be sent at all for any kind of
 * reason.
 */
#define FILTER_EXEC_DENY_RUDELY    6 | FILTER_EXEC_DENY

int kdfilter_exec(kdfilter *self, 
                  struct filter_params *params, 
                  struct filter_result *res);

int kdfilter_add(kdfilter *self,
                 struct filter_driver *drv);

int filter_remove(kdfilter *self,
                  struct filter_driver *drv);

kdfilter *kdfilter_new(apr_pool_t *pool);

#endif // _FILTERS_H
