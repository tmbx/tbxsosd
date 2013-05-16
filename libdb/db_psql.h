/**
 * tbxsosd/libdb/db_psql.h
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
 * Generic database code.
 *
 * @author François-Denis Gonthier
 */

#ifndef _DB_PSQL_H
#define _DB_PSQL_H

#include <libpq-fe.h>
#include <inttypes.h>
#include <apr_strings.h>
#include <apr_pools.h>
#include <apr_hash.h>

typedef struct __kdsql kdsql;
typedef struct __kdsql_conn_cache kdsql_conn_cache;

/** Opaque database connection structure. */
struct kdsql_conn;

struct __kdsql_conn_cache {
    apr_hash_t *cache;
};

struct __kdsql {
    /** PostgreSQL connection object. */
    struct kdsql_conn *conn;

    uint16_t db_port;
    const char *db_name;
    const char *db_host;
    const char *db_username;
    const char *db_password;
    int db_timeout;
};

struct db_statement {
    const char *statement_name;
    const char *statement;
};

/** */
struct db_config {
    size_t statement_count;
    struct db_statement *statements;
};

#define kdsql_clear_res_queue(DB_OBJ) \
    do {                                                               \
        PGresult *db_res;                                               \
        while ((db_res = PQgetResult(kdsql_get_conn(DB_OBJ))) != NULL) \
            PQclear(db_res);                                            \
    } while (0);                                                

char *kdsql_uint64_param(int n, uint64_t val);
char *kdsql_uint32_param(int n, uint32_t val);

void kdsql_init(apr_pool_t *pool);

kdsql *kdsql_new(apr_pool_t *pool);

int kdsql_is_connected(kdsql *self);

/** Return the underlying PostgresSQL connection handle. */
PGconn *kdsql_get_conn(kdsql *self);

void kdsql_error_pgsql(struct kdsql_conn *self);

void kdsql_result_error_pgsql(PGresult *db_res);

int kdsql_prepare_all(kdsql *self, struct db_config *db_cfg);

int kdsql_connect(kdsql *self);
int kdsql_disconnect(kdsql *self);

int kdsql_async_query(kdsql *self, const char *);
int kdsql_async_named_query(kdsql *self, const char *);
int kdsql_async_named_query_params(kdsql *self, const char *, int pn, const char **, int *);

int kdsql_async_wait_response(kdsql *);

int kdsql_begin(kdsql *self);
int kdsql_commit(kdsql *self);
int kdsql_rollback(kdsql *self);

int kdsql_prepare_statement(kdsql *self, 
                            const char *statement_name,
                            const char *statement);

int kdsql_noop(kdsql *self);

#endif // _DB_PSQL_H
