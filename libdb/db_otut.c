/**
 * tbxsosd/libdb/db_otut.c
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
 * OTUT database object.
 *
 * @author François-Denis Gonthier
 */

#include <apr_tables.h>
#include <kerror.h>
#include <stdlib.h>
#include <time.h>

#include "logid.h"
#include "db_psql.h"
#include "db_otut.h"

static struct db_statement db_stmts[6] = {
    {
        .statement_name = "db_otut_store_ticket",
        .statement = 
        "prepare db_otut_store_ticket (bigint, timestamp) as "
        "select otut_store_ticket($1, $2);"
    },
    {
        .statement_name = "db_otut_store_otut",
        .statement =
        "prepare db_otut_store_otut (bytea, bigint, int, int) as "
        "select otut_put($1, $2, $3, $4);"
    },
    {
        .statement_name = "db_otut_succeed",
        .statement = "prepare db_otut_succeed (bytea) as select rem_usage, rem_attempts from otut_succeed($1);"
    },
    {
        .statement_name = "db_otut_fail",
        .statement = "prepare db_otut_fail (bytea) as select rem_usage, rem_attempts from otut_fail($1);"
    },
    {
        .statement_name = "db_otut_login",
        .statement = "prepare db_otut_login (bytea) as select otut_login($1);"
    },
    {
        .statement_name = "db_otut_check",
        .statement = "prepare db_otut_check_otut (bytea) as select * from otut_check($1);"
    }
};

static struct db_config db_cfg = {
    .statement_count = 6,
    .statements = db_stmts
};

static int kddbotut_check_prepared(kddbotut *self) {
    if (!self->is_prepared) {
        if (kdsql_prepare_all(self->db, &db_cfg) < 0) {
            KERROR_PUSH(_db_, 0, "failed to connect to public key database");
            return -1;
        }

        self->is_prepared = 1;
    }

    return 0;
}

/** Initialize the OTUT manager object. */
kddbotut *kddbotut_new(apr_pool_t *pool, kdsql *db) {
    kddbotut *self;

    self = apr_pcalloc(pool, sizeof(kddbotut));
    self->db = db;
    self->pool = pool;
    
    return self;
}

/** Login to the server using an OTUT string. */
int kddbotut_login(kddbotut *self, 
                   const char *otut_str, 
                   size_t otut_str_s, 
                   uint64_t *key_id,
                   struct kd_login_result **res) {
    int error = -1;
    int n;
    size_t otut_str_escaped_s;
    PGresult *db_res = NULL;
    char *key_id_text;
    int params_s[1] = { 0 };
    const char *params[1] = { NULL };

    /* Make sure we are connected to the database. */
    if (kddbotut_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    params[0] = (char *)PQescapeByteaConn(kdsql_get_conn(self->db),
                                          (uint8_t *)otut_str, 
                                          otut_str_s, 
                                          &otut_str_escaped_s);
    params_s[0] = otut_str_escaped_s;

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_otut_login",
                                           1, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_otut_login failed");
            break;
        }

        /* Get the result. */
        db_res = PQgetResult(kdsql_get_conn(self->db));
        
        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while loging-in with OTUT");
            break;
        }

        /* The query will return at least 1 record. */
        n = PQntuples(db_res);
        if (n != 1) {
            KERROR_SET(_db_, 0, "no data was returned by OTUT login query");
            break;
        }

        /* Check the returned valude. */
        if (strcmp(PQgetvalue(db_res, 0, 0), "0") != 0) {
            key_id_text = PQgetvalue(db_res, 0, 0);
            if (sscanf(key_id_text, PRINTF_64"u", key_id) < 1) {
                KERROR_SET(_db_, 0, "incorrect data for key ID: %s", key_id_text);
                break;
            }

            /* Not very useful but needed. */
            (*res)->rights = LOGIN_RIGHTS_OK;
        }
        else (*res)->rights = LOGIN_RIGHTS_DENIED;
            
	error = 0;
	
    } while (0);

    PQfreemem((char *)params[0]);
    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}

/** Register a failure with the OTUT. */
int kddbotut_fail(kddbotut *self, 
                  const char *otut_str, 
                  size_t otut_str_s, 
                  int *nb_usages_left,
                  int *nb_fails_left) {
    int error = -1;
    PGresult *db_res = NULL;
    size_t otut_str_escaped_s;
    const char *params[1];
    int params_s[1] = { 0 };
    char *nb_usages_str, *nb_fails_str;

    /* Make sure we are connected to the database. */
    if (kddbotut_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    params[0] = (char *)PQescapeByteaConn(kdsql_get_conn(self->db),
                                          (uint8_t *)otut_str, 
                                          otut_str_s, 
                                          &otut_str_escaped_s);
    params_s[0] = otut_str_escaped_s;

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_otut_fail",
                                           1, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_otut_fail failed");
            break;
        }

        /* Wait for the response to the query. */
        if (kdsql_async_wait_response(self->db) < 0) {
            KERROR_PUSH(_db_, 0, "OTUT failure query response failed");
            break;
        }

        /* Get the result. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while register failure for OTUT");
            break;
        }

        /* Number of legitimate usage left. */
        if (nb_usages_left != NULL) {
            nb_usages_str = PQgetvalue(db_res, 0, 0);
            if (sscanf(nb_usages_str, "%d", nb_usages_left) < 1) {
                KERROR_SET(_db_, 0, "invalid value for OTUT remaining usages: %s", nb_usages_str);
                break;
            }
        }

        /* Number of failures left. */
        if (nb_fails_left != NULL) {
            nb_fails_str = PQgetvalue(db_res, 0, 1);
            if (sscanf(nb_fails_str, "%d", nb_fails_left) < 1) {
                KERROR_SET(_db_, 0, "invalid value for OTUT remaining failures: %s", nb_fails_str);
                break;
            }
        }

        error = 0;

    } while (0);

    PQfreemem((char *)params[0]);
    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}

/** Register a success with the OTUT. */
int kddbotut_succeed(kddbotut *self, 
                     const char *otut_str, 
                     size_t otut_str_s,
                     int *nb_usages_left,
                     int *nb_fails_left) {
    int error = -1;
    PGresult *db_res = NULL;
    size_t otut_str_escaped_s;
    const char *params[1];
    int params_s[1] = { 0 };
    char *nb_usages_str, *nb_fails_str;

    /* Make sure we are connected to the database. */
    if (kddbotut_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    params[0] = (char *)PQescapeByteaConn(kdsql_get_conn(self->db),
                                          (uint8_t *)otut_str, 
                                          otut_str_s, 
                                          &otut_str_escaped_s);
    params_s[0] = otut_str_escaped_s;

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_otut_succeed",
                                        1, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_otut_succeed failed");
            break;
        }

        /* Wait for the response to the query. */
        if (kdsql_async_wait_response(self->db) < 0) {
            KERROR_PUSH(_db_, 0, "OTUT failure query response failed");
            break;
        }

        /* Get the result. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while registering success for OTUT");
            break;
        }

        /* Number of legitimate usage left. */
        if (nb_usages_left != NULL) {
            nb_usages_str = PQgetvalue(db_res, 0, 0);
            if (sscanf(nb_usages_str, "%d", nb_usages_left) < 0) {
                KERROR_SET(_db_, 0, "invalid value for OTUT remaining usages: %s", nb_usages_str);
                break;
            }
        }

        /* Number of failures left. */
        if (nb_fails_left != NULL) {
            nb_fails_str = PQgetvalue(db_res, 0, 1);
            if (sscanf(nb_fails_str, "%d", nb_fails_left) < 0) {
                KERROR_SET(_db_, 0, "invalid value for OTUT remaining failures: %s", nb_fails_str);
                break;
            }
        }

	error = 0;
	
    } while (0);

    PQfreemem((char *)params[0]);
    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}

int kddbotut_check_otut(kddbotut *self, 
                        const char *otut_str, 
                        size_t otut_str_s, 
                        uint32_t *nb_use) {
    int error = -1;
    PGresult *db_res = NULL;
    size_t otut_str_escaped_s;
    int params_s[1] = { 0 };
    const char *params[1] = { NULL };
    char *nb_use_str;
    int n;

    /* Make sure we are connected to the database. */
    if (kddbotut_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }
    
    params[0] = (char *)PQescapeByteaConn(kdsql_get_conn(self->db),
                                          (uint8_t *)otut_str,
                                          otut_str_s, 
                                          &otut_str_escaped_s);
    params_s[0] = otut_str_escaped_s;

    do {
        if (kdsql_async_named_query_params(self->db, "db_otut_check_otut",
                                           1, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_otut_store_otut failed");
            break;
        }

        /* Get the result. */
        db_res = PQgetResult(kdsql_get_conn(self->db));
        
        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while checking OTUT");
            break;
        }

        /* The query will return at least 1 record (t or f). */
        n = PQntuples(db_res);
        if (n != 1) {
            KERROR_SET(_db_, 0, "no data was returned by OTUT login query");
            break;
        }

        /* Check the returned valude. */
        nb_use_str = PQgetvalue(db_res, 0, 0);

        if (sscanf(nb_use_str, "%d", nb_use) < 1) {
            KERROR_SET(_db_, 0, "invalid value for OTUT remaining usages: %s", nb_use_str);
            break;
        }
            
        error = 0;
                          
    } while (0);

    PQfreemem((char *)params[0]);
    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}
                       

/** Store a OTUT string in the database. 
 *
 * The strings is stored as a bytea string an thus needs to be escaped
 * by using PQescapeByteaConn.
 */
int kddbotut_store(kddbotut *self, 
                   const char *otut_str, 
                   size_t otut_str_s,
                   uint64_t mid,
                   uint32_t use_count, 
                   uint32_t attempt_count) {
    int error = -1;
    PGresult *db_res = NULL;
    size_t otut_str_escaped_s;
    int params_s[4] = { 0, 0, 0, 0 };
    const char *params[4] = { NULL, NULL, NULL, NULL };

    /* Make sure we are connected to the database. */
    if (kddbotut_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    params[0] = (char *)PQescapeByteaConn(kdsql_get_conn(self->db),
                                          (uint8_t *)otut_str, 
                                          otut_str_s, 
                                          &otut_str_escaped_s);
    params[1] = kdsql_uint64_param(0, mid);
    params[2] = kdsql_uint32_param(1, use_count);
    params[3] = kdsql_uint32_param(2, attempt_count);
    params_s[0] = otut_str_escaped_s;
    params_s[1] = strlen(params[1]);
    params_s[1] = strlen(params[2]);
    params_s[2] = strlen(params[3]);

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_otut_store_otut",
                                        4, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_otut_store_otut failed");
            break;
        }

        /* Get the result. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while storing OTUT");
            break;
        }
        
	error = 0;

    } while (0);

    PQfreemem((char *)params[0]);
    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}

/** Store ticket information in the OTUT ticket cache. */
int kddbotut_store_ticket(kddbotut *self, uint64_t mid, struct timeval * tv) {
    int error = -1;
    char * tv_str;
    PGresult * db_res = NULL;
    int params_s[2] = { 0, 0 };
    const char * params[2] = { NULL, NULL };

    /* Make sure we are connected to the database. */
    if (kddbotut_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    /* Convert the ticket timeval to a string. */
    if ((tv_str = ctime(&tv->tv_sec)) == NULL) {
        KERROR_SET(_db_, 0, "failed to convert timeval to string");
        return -1;
    }

    params[0] = kdsql_uint64_param(0, mid);
    params[1] = tv_str;
    params_s[0] = strlen(params[0]);
    params_s[1] = strlen(tv_str);

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_otut_store_ticket",
                                        2, params, params_s) < 0) {            
            KERROR_PUSH(_db_, 0, "db_otut_store_ticket failed");
            break;
        }

        /* Get the result. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {            
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while storing ticket");
            break;
        }

	error = 0;
	
    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}

