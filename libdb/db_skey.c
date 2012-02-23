/**
 * tbxsosd/libdb/db_skey.c
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
 * Secret key database object.
 *
 * @author François-Denis Gonthier
*/

#include <apr_strings.h>
#include <kerror.h>

#include "common_keys.h"

#include "logid.h"
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
