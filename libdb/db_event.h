/**
 * tbxsosd/libdb/db_devent.h
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
 * Event database object.
 *
 * @author François-Denis Gonthier
 */

#ifndef _KDDB_EVENT_H
#define _KDDB_EVENT_H

#include "db_psql.h"

/** Event database object. */
struct __kddbevent {   
    apr_pool_t *pool;

    /** Set to 1 after successfully preparing queries. */
    int is_prepared;
        
    /** Database connection. */
    kdsql *db;
};

typedef struct __kddbevent kddbevent;

/** Create an event database object. */
kddbevent *kddbevent_new();

/** Initialize the event database object. */
int kddbevent_init(kddbevent *self);

/** Disconnect and delete from the event database. */
void kddbevent_delete(kddbevent *self);

/** Add an event to the event database. */
int kddbevent_add(kddbevent *self, 
                  const char *hostname,
                  uint64_t session_id, 
                  const char *event_name, 
                  size_t n, 
                  const char ***attr);

extern uint64_t event_counter;

#endif // _KDDB_EVENT_H
