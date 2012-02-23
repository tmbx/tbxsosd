/**
 * tbxsosd/libdb/db_devent.h
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
