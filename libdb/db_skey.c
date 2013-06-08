/**
 * tbxsosd/libdb/db_skey.c
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
 * Secret key database object.
 *
 * @author François-Denis Gonthier
*/

#include <apr_strings.h>
#include <kerror.h>

#include "common/common_keys.h"
#include "common/logid.h"

#include "db_skey.h"

static struct db_statement db_stmts[1] = {
    {
        .statement_name = "db_get_skey_from_key_id",
        .statement = 
        "prepare db_get_skey_from_key_id (text, bigint) as "
        "select key_id, key_data, owner_name from export_key($1, $2);"
    }
};

static struct db_config db_cfg = {
    .statement_count = 1,
    .statements = db_stmts
};

static int kddbskey_check_prepared(kddbskey *self) {
    if (!self->is_prepared) {
        if (kdsql_prepare_all(self->db, &db_cfg) < 0) {
            KERROR_PUSH(_db_, 0, "failed to connect to secret key database");
            return -1;
        }

        self->is_prepared = 1;
    }

    return 0;
}

kddbskey *kddbskey_new(apr_pool_t *pool, kdsql *db) {    
    kddbskey *self;

    self = apr_pcalloc(pool, sizeof(kddbskey));
    self->db = db;
    self->pool = pool;

    return self;
}

/** Return a secret key given a key ID.
 *
 * Clears the object error stack.  Set the error and returns -1 in
 * case of error.  Returns 0 if it did not find the key.  1 if there
 * is a key.
 */
int kddbskey_get(kddbskey *self, 
                 apr_pool_t *pool,
                 enum kdkey_type skey_type, 
                 uint64_t key_id,
                 struct kdkey_info **ki) {
    int error = 0;
    const char *params[2];
    int params_s[2];
    PGresult * db_res = NULL;
    char *key_text = NULL;
    char *owner_text = NULL;

    assert(skey_type == SKEY_SIGNATURE || skey_type == SKEY_ENCRYPTION);

    /* Make sure we are connected to the database. */
    if (kddbskey_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    /* Setup the params. */
    switch (skey_type) {
    case SKEY_SIGNATURE:
        params[0] = "sig_skey";
        break;
    case SKEY_ENCRYPTION:
        params[0] = "enc_skey";
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
                                           "db_get_skey_from_key_id",
                                           2,
                                           params,
                                           params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_get_skey_from_key_id failed");
            error = -1;
        }

        /* Check if there was an error. */
        if (error) break;

        /* Get the results. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {            
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while fetching secret key");
            error = -1;
            break;
        }

        if (PQgetisnull(db_res, 0, 1) && PQgetisnull(db_res, 0, 2))
            break;

        /* Get the result field for the key data. */
        key_text = PQgetvalue(db_res, 0, 1);
        owner_text = PQgetvalue(db_res, 0, 2);

        *ki = apr_pcalloc(pool, sizeof(struct kdkey_info));
        (*ki)->key_id = key_id;
        (*ki)->type = skey_type;
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
