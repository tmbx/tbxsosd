/**
 * tbxsosd/libdb/db_devent.c
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

#include <kerror.h>

#include "logid.h"
#include "db_psql.h"
#include "db_event.h"

uint64_t event_counter;

static struct db_statement db_stmts[2] = {
    {
        .statement_name = "db_event_create",
        .statement = 
        "prepare db_event_create (varchar, bigint, bigint, varchar) as "
        "select * from event_create($1, $2, $3, $4)"
    },
    {
        .statement_name = "db_event_add_var",
        .statement = 
        "prepare db_event_add_var (varchar, bigint, bigint, varchar, varchar) as "
        " select event_add_variable($1, $2, $3, $4, $5)"
    }
};
static struct db_config db_cfg = {
    .statement_count = 2,
    .statements = db_stmts
};

/** Create an event database object. */
kddbevent *kddbevent_new(apr_pool_t *pool, kdsql *db) {
    kddbevent *self;
    apr_pool_t *obj_pool;

    apr_pool_create(&obj_pool, pool);

    self = apr_pcalloc(obj_pool, sizeof(kddbevent));
    self->db = db;
    self->pool = obj_pool;

    return self;
}

static int kddbevent_check_db(kddbevent *self) {
    if (!self->is_prepared) {
        if (kdsql_prepare_all(self->db, &db_cfg) < 0) {
            KERROR_PUSH(_db_, 0, "failed to connect to event database");
            return -1;
        }

        self->is_prepared = 1;
    }

    return 0;    
}

static int kddbevent_create(kddbevent *self, 
                            const char *hostname,
                            uint64_t event_id,
                            uint64_t session_id, 
                            const char *event_name) {
    int error = -1;
    PGresult *db_res = NULL;
    const char *params[4] = { NULL, NULL, NULL, NULL };
    int params_s[4];
    
    /* Make sure we are connected to the database. */
    if (kddbevent_check_db(self) < 0) {
        KERROR_SET(_db_, 0, "connection failed");
        return -1;
    }

    /* Fill in the param length. */
    params[0] = hostname;
    params[1] = kdsql_uint64_param(1, event_id);
    params[2] = kdsql_uint64_param(2, session_id);
    params[3] = event_name;
    params_s[0] = strlen(params[0]);
    params_s[1] = strlen(params[1]);
    params_s[2] = strlen(params[2]);
    params_s[3] = strlen(params[3]);

    do {
        /* Call the SQL query. */
        if (kdsql_async_named_query_params(self->db, "db_event_create", 4, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "event creation query failed");
            break;
        }
        
        /* Wait for the response to the query. */
        if (kdsql_async_wait_response(self->db) < 0) {
            KERROR_PUSH(_db_, 0, "event creation query response failed");
            break;
        }
        
        /* Fetch the results. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while creating event");
            break;
        }

        /* We expect to have only 1 result from that query. */
        if (PQntuples(db_res) == 0) {
            KERROR_SET(_db_, 0, "event creation query returned no results");
            break;
        }
        else if (PQntuples(db_res) > 1) {            
            KERROR_SET(_db_, 0, "event creation query returned more than one result");
            break;
        }

        error = 0;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}

static int kddbevent_add_variable(kddbevent *self, 
                                  const char *hostname,
                                  uint64_t event_id,
                                  uint64_t session_id,
                                  const char **var) {
    int error = -1;
    PGresult *db_res = NULL;
    const char *params[5] = { NULL, NULL, NULL, NULL };
    int params_s[5];
    
    /* Make sure we are connected to the database. */
    if (kddbevent_check_db(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    /* Fill in the ID parameter and the length of all parameters. */
    params[0] = hostname;
    params[1] = kdsql_uint64_param(0, event_id);
    params[2] = kdsql_uint64_param(1, session_id);
    params[3] = var[0];
    params[4] = var[1];
    params_s[0] = strlen(params[0]);
    params_s[1] = strlen(params[1]);
    params_s[2] = strlen(params[2]);
    params_s[3] = strlen(params[3]);
    params_s[4] = strlen(params[4]);

    do {
        /* Call the SQL query. */
        if (kdsql_async_named_query_params(self->db, "db_event_add_var", 5, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "event variable addition query failed");
            break;
        }
        
        /* Wait for the response to the query. */
        if (kdsql_async_wait_response(self->db) < 0) {
            KERROR_PUSH(_db_, 0, "event variable addition query response failed");
            break;
        }
        
        /* Fetch the results. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* There is no result, check if the command was at least
           successful. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while adding variable %s to event %llu",
                        var[0], event_id);
            break;
        }
	
	error = 0;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}

/** Add an event to the event database. 
 *
 * attr is a NULL terminated 2D array of key and values.
 */
int kddbevent_add(kddbevent *self, 
                  const char *hostname,
                  uint64_t session_id, 
                  const char *event_name, 
                  size_t n, 
                  const char ***vars) {
    size_t i;
    int err = 0;
    uint64_t event_id = 0;

    /* Make sure we are connected to the database. */
    if (kddbevent_check_db(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    /* Start a transaction. */
    if (kdsql_begin(self->db) < 0) {
        KERROR_PUSH(_db_, 0, "failed to start transaction");
        return -1;
    }
   
    do {
        /* Increment the event counter. */
        event_counter++;     

        /* Create the event. */
        if (kddbevent_create(self, hostname, event_counter, session_id, event_name) < 0) {
            KERROR_PUSH(_db_, 0, "failed to create the event");
            err = -1;
            break;
        }
        
        /* Add the variables to the event. */
        for (i = 0; i < n; i++) {
            if (kddbevent_add_variable(self, hostname, event_counter, session_id, vars[i]) < 0) {
                KERROR_PUSH(_db_, 0, "failed to add a variable to event %llu", event_id);
                err = -1;
                break;
            }
        }
        if (err) break;
        
        /* Commit the transaction. */
        if (kdsql_commit(self->db) < 0) {            
            KERROR_PUSH(_db_, 0, "failed to commit transaction");
            err = -1;
            break;
        }

        return 0;

    } while (0);

    /* Error, rollback the transaction.  If that fails, we are kinda
       fux0red and let it float. */
    if (kdsql_rollback(self->db) < 0) 
        KERROR_PUSH(_db_, 0, "failed to rollback transaction (wtf!!!)");

    return err;
}

