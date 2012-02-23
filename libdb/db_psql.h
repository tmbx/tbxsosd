/**
 * tbxsosd/libdb/db_psql.h
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
