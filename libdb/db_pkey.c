/**
 * tbxsosd/libdb/db_pkey.c
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
 * Public key database object.
 *
 * @author François-Denis Gonthier
 */

#include <apr_strings.h>
#include <kerror.h>

#include "common/common_keys.h"
#include "common/logid.h"

#include "db_psql.h"
#include "db_pkey.h"

static struct db_statement db_stmts[1] = {
     {
         .statement_name = "db_get_pkey_from_key_id",
         .statement = 
         "prepare db_get_pkey_from_key_id (text, bigint) as "
         "select key_id, key_data, owner_name from export_key($1, $2);"
     }
};

static struct db_config db_cfg = {
    .statement_count = 1,
    .statements = db_stmts
};

static int kddbpkey_check_prepared(kddbpkey *self) {
    if (!self->is_prepared) {
        if (kdsql_prepare_all(self->db, &db_cfg) < 0) {
            KERROR_PUSH(_db_, 0, "failed to connect to public key database");
            return -1;
        }

        self->is_prepared = 1;
    }

    return 0;
}

/** Create a new public key database object. */
kddbpkey *kddbpkey_new(apr_pool_t *pool, kdsql *db) {
    kddbpkey * self;
        
    self = apr_pcalloc(pool, sizeof(kddbpkey));    
    self->pool = pool;
    self->db = db;

    return self;
}

/** Fetch a public signature key or public encryption key. */
int kddbpkey_get(kddbpkey *self, 
                 apr_pool_t *pool,
                 enum kdkey_type pkey_type, 
                 uint64_t key_id,
                 struct kdkey_info **ki) {
    int error = 0;
    const char *params[2];
    int params_s[2];
    PGresult *db_res = NULL;
    char *key_text = NULL;
    char *owner_text = NULL;

    assert(pkey_type == PKEY_SIGNATURE || pkey_type == PKEY_ENCRYPTION);

    /* Make sure we are connected to the database. */
    if (kddbpkey_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    /* Prepare the parameter */
    switch (pkey_type) {
    case PKEY_SIGNATURE:
        params[0] = "sig_pkey";
        break;
    case PKEY_ENCRYPTION:
        params[0] = "enc_pkey";
        break;
    default:
        /* Handled in assert above. */
        break;
    }
    params_s[0] = strlen(params[0]);
    params[1] = kdsql_uint64_param(1, key_id);
    params_s[1] = strlen(params[1]);

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, 
                                           "db_get_pkey_from_key_id",
                                           2, 
                                           params, 
                                           params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_get_pkey_from_key_id query failed");
            error = -1;
        }

        /* Check if there was an error. */
        if (error) break;
        
        /* Get the results. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {            
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while fetching public key");
            error = -1;
            break;
        }

        if (PQgetisnull(db_res, 0, 1) && PQgetisnull(db_res, 0, 2))
            break;
                
        /* Get the result fields. */
        key_text = PQgetvalue(db_res, 0, 1);
        owner_text = PQgetvalue(db_res, 0, 2);

        *ki = apr_pcalloc(pool, sizeof(struct kdkey_info));
        (*ki)->type = pkey_type;
        (*ki)->data = apr_pstrdup(pool, key_text);
        (*ki)->data_s = strlen(key_text);
        (*ki)->owner = apr_pstrdup(pool, owner_text);
        (*ki)->owner_s = strlen(owner_text);
        (*ki)->key_id = key_id;
	
        error = 1;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}
