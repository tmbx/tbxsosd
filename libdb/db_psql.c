/**
 * tbxsosd/libdb/db_psql.c
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
 */
 
#include <sys/poll.h>
#include <apr_user.h>
#include <apr_network_io.h>
#include <apr_poll.h>
#include <apr_portable.h>
#include <libpq-fe.h>
#include <inttypes.h>
#include <limits.h>
#include <assert.h>
#include <kerror.h>
#include <unistd.h>

#include "options.h"
#include "logid.h"
#include "db_psql.h"
#include "logging.h"

struct kdsql_conn_link {
    kdsql *db;
    struct kdsql_conn_link *next;
};

struct kdsql_conn {
    /** Reference count. */
    int c;
    
    /** Pool on which this structure was allocated. */
    apr_pool_t *pool;

    /** True when the pg_conn object is connected. */
    int is_connected;

    /** The connection itself. */
    PGconn *pg_conn;

    /** Linked list of connected database objects. */
    struct kdsql_conn_link *dbs;

    /** Name of the database. */
    const char *db_name;

#ifdef KD_DB_DEBUG 
    FILE *trace_file;
#endif // KD_DB_DEBUG
};

static apr_pool_t *cache_pool = NULL;
static apr_pool_t *conn_pool = NULL;

static apr_hash_t *conn_cache = NULL;

/** Per PostgreSQL documentation. */
#define CANCEL_STR_SIZE   256

#define STR(X) #X

/* Param array.  Used for static or moderate length params. */
char params[9][sizeof(STR(ULLONG_MAX)) + 1];

/** Store an uint64_t param. */
char *kdsql_uint64_param(int n, uint64_t val) {
    assert(n < 9);

    /* Prepare the parameter */
    sprintf(params[n], "%llu", val);
    return params[n];
}

/** Store an uint32_t param. */
char *kdsql_uint32_param(int n, uint32_t val) {
    assert(n < 9);

    /* Prepare the parameter. */
    sprintf(params[n], "%u", val);
    return params[n];
}

PGconn *kdsql_get_conn(kdsql *self) {
    return self->conn->pg_conn;
}

/** Push an error message in the error stack. */
void kdsql_error_pgsql(struct kdsql_conn *conn) {
    char *err_msg;

    err_msg = PQerrorMessage(conn->pg_conn);

    if (strlen(err_msg) == 0) err_msg = "unknown PostgreSQL error";
    KERROR_SET(_db_, 0, err_msg);
}

void kdsql_result_error_pgsql(PGresult *db_res) {
    char *err_msg;

    err_msg = PQresultErrorMessage(db_res);

    if (strlen(err_msg) == 0) err_msg = "unknown PostgreSQL error";
    KERROR_SET(_db_, 0, err_msg);
}

/** Disconnect the database connection. */
static apr_status_t kdsql_conn_child_delete(void *data) {
    struct kdsql_conn *self = (struct kdsql_conn *)data;
    int fd;

    /* Close the file descriptor under the nose of PostgreSQL.  If we
       call PQfinish(), the forked child will negociate disconnection
       with the DB and the DB will disconnect other connections from
       the duplicated FD. */
    fd = PQsocket(self->pg_conn);
    close(fd);

    return APR_SUCCESS;
}

/** Disconnect the database connection. */
static apr_status_t kdsql_conn_delete(void *data) {
    struct kdsql_conn *self = (struct kdsql_conn *)data;
    struct kdsql_conn_link *d;

    d = self->dbs;
    if (d) {        
        do {
            if (d->db) 
                d->db->conn = NULL;
            d = d->next;
        } while (d != NULL);
    }

    PQfinish(self->pg_conn);

    return APR_SUCCESS;
}

/** Disconnects the database object. */
static apr_status_t kdsql_delete(void *data) {
    kdsql *self = (kdsql *)data;

    kdsql_disconnect(self);   

    return APR_SUCCESS;
}

/** Disconnect the database object, called when child process is
    forked. */
static apr_status_t kdsql_child_delete(void *data) {
    kdsql *self = (kdsql *)data;

    return kdsql_conn_child_delete(self->conn);
}

/** Create a new database connection wrapper. */
static struct kdsql_conn *kdsql_conn_new(apr_pool_t *pool) {
    struct kdsql_conn *self;
    apr_pool_t *cp;

    apr_pool_create(&cp, pool);

    self = apr_pcalloc(cp, sizeof(struct kdsql_conn));
    self->pool = cp;

    apr_pool_cleanup_register(cp, self, kdsql_conn_delete, kdsql_conn_child_delete);

    return self;
}

/** Connect the database connection wrapper. */
static int kdsql_conn_connect(struct kdsql_conn *self, 
                              const char *db_name, 
                              const char *conn_str) {
#ifdef KD_DB_DEBUG
    char *trace_file_name;
    apr_pool_t *pool;
#endif // KD_DB_DEBUG
    self->db_name = db_name;
    self->pg_conn = PQconnectdb(conn_str);

    /* Check connection status */
    if (PQstatus(self->pg_conn) != CONNECTION_OK) {
        kdsql_error_pgsql(self);
        KERROR_PUSH(_db_, 0, "database connection error");
        return -1;
    }
            
    /* Set link as non-blocking */
    if (PQsetnonblocking(self->pg_conn, 1) != 0) {
        kdsql_error_pgsql(self);
        KERROR_PUSH(_db_, 0, "cannot set database non-blocking");
        return -1;
    }
            
#ifdef KD_DB_DEBUG
    if (!self->trace_file) {
        /* Enable some tracing functions for debugging. */
        PQsetErrorVerbosity(self->pg_conn, PQERRORS_VERBOSE);
    
        apr_pool_create(&pool, self->pool);
        trace_file_name = apr_psprintf(pool, "%s.dbtrace", PQdb(self->pg_conn));
            
        if ((self->trace_file = fopen(trace_file_name, "w")) != NULL) 
            PQtrace(self->pg_conn, self->trace_file);

        apr_pool_destroy(pool);
    }
#endif // KD_DB_DEBUG

    return 0;
}

/** Attach a DB object to a wrapper. */
static void kdsql_conn_attach(struct kdsql_conn *self, kdsql *db) {
    struct kdsql_conn_link *d;

    if (self->dbs == NULL) 
        self->dbs = apr_pcalloc(self->pool, sizeof(struct kdsql_conn_link));

    /* Reuse the first unused slot in the list. */
    d = self->dbs;
    while (d->db != NULL && d->next != NULL) 
        d = d->next;

    /* Append a new element after the current one if this is the last
       element of the list. */
    if (d->next == NULL) 
        d->next = apr_pcalloc(self->pool, sizeof(struct kdsql_conn_link));

    /* Set the choosen element. */
    if (d->db == NULL)
        d->db = db;

    self->c++;
}

/** "Disconnect" the connection wrapper
 *
 * This actually lowers the reference counter and disconnect only if
 * the reference count reaches 0.
 */
static void kdsql_conn_disconnect(struct kdsql_conn *self, kdsql *db) {
    struct kdsql_conn_link *d;
    
#ifdef KD_DB_DEBUG
        if (self->trace_file != NULL) {
            PQuntrace(self->pg_conn);
            fclose(self->trace_file);
        }
#endif // KD_DB_DEBUG

    /* NULLify the connection object of every attached DB object so
       that they don't use an invalid object. */
    if (self->dbs != NULL) {
        d = self->dbs;
        while (d && d->db != db)
            d = d->next;

        if (d) d->db = NULL;            
    }
            
    self->c--;

    if (self->c == 0) {
        PQfinish(self->pg_conn);
        apr_pool_destroy(self->pool);
    }
}

/** NULLify the global structure when the poll that supports them is
    destroyed. */
static apr_status_t kdsql_init_delete(void *data) {
    data = data;

    conn_pool = NULL;
    cache_pool = NULL;
    conn_cache = NULL;

    return APR_SUCCESS;
}

/** Initialize global data structures and pools. */
void kdsql_init(apr_pool_t *pool) {
    if (!conn_pool) 
        apr_pool_create(&conn_pool, pool);

    if (!cache_pool) {
        apr_pool_create(&cache_pool, pool);
        conn_cache = apr_hash_make(cache_pool);
    }

    /* We need to be aware when those structures gets cleaned. */
    apr_pool_cleanup_register(conn_pool, NULL, kdsql_init_delete, kdsql_init_delete);
}

/** Instanciate the database object. */
kdsql *kdsql_new(apr_pool_t *pool) {
    kdsql *self;

    self = apr_pcalloc(pool, sizeof(kdsql));
    apr_pool_cleanup_register(pool, self, kdsql_delete, kdsql_child_delete);

    return self;
}

/** Disconnect the database. */ 
int kdsql_disconnect(kdsql *self) {
    if (self->conn != NULL) {        
#ifdef KD_DB_DEBUG
        if (self->conn->trace_file != NULL) {
            PQuntrace(self->conn->pg_conn);
            fclose(self->conn->trace_file);
            self->conn->trace_file = NULL;
        }
#endif // KD_DB_DEBUG
              
        kdsql_conn_disconnect(self->conn, self);
        self->conn = NULL;
    }
    return 0;
}

/* Do an empty database query to check whether a connection is alive or
   not. */
int kdsql_noop(kdsql *self) {
    if (kdsql_begin(self) < 0) return -1;
    if (kdsql_commit(self) < 0) return -1;
    return 0;
}

int kdsql_prepare_all(kdsql *self, struct db_config *db_cfg) {
    int has_error = 0;
    size_t i;
    
    if (self->conn == NULL) {
        KERROR_PUSH(_db_, 0, "disconnected from database");
        return -1;
    }

    for (i = 0; i < db_cfg->statement_count && !has_error; i++) {
        if (kdsql_prepare_statement(self, 
                                    db_cfg->statements[i].statement_name,
                                    db_cfg->statements[i].statement) < 0) {
            KERROR_PUSH(_db_, 0, "%s prepare failed", db_cfg->statements[i].statement);
            return -1;
        }            
    }

    return 0;
}

/** Connect to the database. */
int kdsql_connect(kdsql *self) {
    char conn_str[2048];
    const char db_conn_fmt[] = "host=%s port=%d dbname=%s user=%s%s%s connect_timeout=15";
    const char *pwd_key, *pwd_val;
    struct kdsql_conn *conn;
    
    if (self->db_password == NULL || strcmp(self->db_password, "") == 0) {
        pwd_key = "";
        pwd_val = "";
    }
    else {
        pwd_key = " password=";
        pwd_val = self->db_password;
    }

    sprintf(conn_str, db_conn_fmt, 
            self->db_host, 
            self->db_port, 
            self->db_name, 
            self->db_username,
            pwd_key, pwd_val);
   
    conn = apr_hash_get(conn_cache, conn_str, APR_HASH_KEY_STRING);
    
    if (conn) {
        self->conn = conn;

        /* Attach the database object to the connection. */
        kdsql_conn_attach(self->conn, self);
        return 0;
    }
    else {
        /* SSL must be initialized here. Tell PostgreSQL not to initialize it.*/
        PQinitSSL(0);

        conn = kdsql_conn_new(conn_pool);

        if (kdsql_conn_connect(conn, self->db_name, conn_str) < 0) {
            apr_pool_destroy(conn->pool);
            self->conn = NULL;
            
            return -1;
        }

        self->conn = conn;

        /* Attach the database object to the connection. */
        kdsql_conn_attach(self->conn, self);

        /* Store the connection in the cache. */
        apr_hash_set(conn_cache, conn_str, APR_HASH_KEY_STRING, conn);

        return 0;
    }
} 

/** Wait for the database channel to be ready for writing. */
static int kdsql_wait_writing_ready(kdsql *self) {
    int n;
    struct pollfd pfd;

    if (self->conn == NULL) {
        KERROR_PUSH(_db_, 0, "disconnected from database");
        return -1;
    }

    /* Get the DB socket so we will poll() on it. */
    pfd.fd = PQsocket(self->conn->pg_conn);
    pfd.events = POLLOUT;
    pfd.revents = 0;

    /* Poll on the database socket.  Make sure it is ready for writing. */
    do {
        n = poll(&pfd, 1, self->db_timeout);

        /* Check the error or termination conditions. */
        if ((pfd.revents & POLLNVAL) != 0 ||
            (pfd.revents & POLLERR) != 0 ||
            (pfd.revents & POLLHUP) != 0) 
            return -1;

        if (n == -1 && errno != EINTR && !PQisBusy(self->conn->pg_conn))
            break;

        pfd.revents = 0;
    } while (n < 1);

    /* FIXME: Writing may be denied if there is a result pending. */
  
    if (n < 0)
        return -1;
    else
        return 0;
}

static int kdsql_ensure_flushed(kdsql *self) {
    int err = 0;

    do {
        if (kdsql_wait_writing_ready(self) < 0) {
            KERROR_PUSH(_db_, 0, "async query error waiting for channel readyness");
            err = -1;
        }
    } while (!err && PQflush(self->conn->pg_conn) != 0);

    if (err) return -1;
    return 0;
}

/** Send an unprepared SQL statement. */
int kdsql_async_query(kdsql *self, const char *stmt) {
    const char msg[] = "async query error waiting for channel readyness";

    if (self->conn == NULL) {
        KERROR_PUSH(_db_, 0, "disconnected from database");
        return -1;
    }

    /* Wait for the readyness of the channel. */
    if (kdsql_wait_writing_ready(self) < 0) {
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, msg);
        return -1;
    }

    /* Send the query.  If that fails, we must retry by calling
       PQflush until there is nothing left in the send queue. */
    if (!PQsendQuery(self->conn->pg_conn, stmt)) {
        if (kdsql_ensure_flushed(self) < 0) {
            kdsql_error_pgsql(self->conn);
            KERROR_PUSH(_db_, 0, "error flushing query");
            return -1;
        }
    }

    return 0;
}

/** Send a query without parameters asynchronously.  Does not wait for
    the result. */
int kdsql_async_named_query(kdsql *self, const char *stmt_name) {

    if (self->conn == NULL) {
        KERROR_PUSH(_db_, 0, "disconnected from database");
        return -1;
    }

    /* Wait for the readyness of the channel. */
    if (kdsql_wait_writing_ready(self) < 0) {
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "async query error waiting for channel readyness");
        return -1;
    }

    /* Send the query. */
    if (PQsendQueryPrepared(self->conn->pg_conn, stmt_name, 0, NULL, NULL, NULL, 0) < 0) {
        if (kdsql_ensure_flushed(self) < 0) {
            kdsql_error_pgsql(self->conn);
            KERROR_PUSH(_db_, 0, "error flushing query");
            return -1;
        }
    } 

    return 0;
}

/** Determine is the database is connected or not.  Returns 1 if so. */
int kdsql_is_connected(kdsql *self) {
    apr_pollfd_t pfd;
    apr_descriptor desc;
    apr_status_t s;
    apr_socket_t *apr_sock = NULL;
    apr_pool_t *pool;
    int db_sock, n, is_connected = 1;

    /* Not connected at all? */
    if (self->conn == NULL) 
        return 0;
    
    /* Connection status bad? */
    else if (PQstatus(self->conn->pg_conn) != CONNECTION_OK) 
        is_connected = 0;

    else {
        apr_pool_create(&pool, self->conn->pool);

        db_sock = PQsocket(self->conn->pg_conn);
        apr_os_sock_put(&apr_sock, &db_sock, pool);

        desc.s = apr_sock;
        pfd.p = pool;
        pfd.desc_type = APR_POLL_SOCKET;
        pfd.reqevents = APR_POLLIN | APR_POLLOUT;
        pfd.rtnevents = 0;
        pfd.desc = desc;
        pfd.client_data = NULL;

        s = apr_poll(&pfd, 1, &n, 0);

        apr_pool_destroy(pool);

        /* Poll error? */
        if (s != APR_SUCCESS) is_connected = 0;

        /* Socket not ready? */
        if (n < 1) is_connected = 0;

        /* Socket is_connected incorrect? */
        if ((pfd.rtnevents & APR_POLLERR) != 0 || (pfd.rtnevents & APR_POLLHUP) != 0) 
            is_connected = 0;
    }

    /* Make sure we are effectively disconnected. */
    if (!is_connected) kdsql_disconnect(self);        
    
    return is_connected;
}

/** Send a query with parameters. */ 
int kdsql_async_named_query_params(kdsql *self, 
                                const char *stmt_name, 
                                int param_count, 
                                const char **p, 
                                int *pl) {
    if (self->conn == NULL) {
        KERROR_PUSH(_db_, 0, "disconnected from database");
        return -1;
    }

    /* Wait for the readyness of the channel. */
    if (kdsql_wait_writing_ready(self) < 0) {
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "async query error waiting for channel readyness");
        return -1;
    }

    /* Send the query. */
    if (PQsendQueryPrepared(self->conn->pg_conn, stmt_name, param_count, p, pl, NULL, 0) < 0) {
        if (kdsql_ensure_flushed(self) < 0) {
            kdsql_error_pgsql(self->conn);
            KERROR_PUSH(_db_, 0, "error flushing query");
            return -1;
        }
    } 

    return 0;
}

/** Wait for the response from the database. */
int kdsql_async_wait_response(kdsql *self) {
    int n, done = 0, timeout = 0;
    struct pollfd pfd;
    PGcancel* db_cancel;
    char db_cancel_str[CANCEL_STR_SIZE];

    if (self->conn == NULL) {
        KERROR_PUSH(_db_, 0, "disconnected from database");
        return -1;
    }

    /* First check if there couldn't be some result already. */
    if (PQisBusy(self->conn->pg_conn)) {	
        
        /* If we are not done yet, prepare to poll() on the database
           socket. */

        pfd.fd = PQsocket(self->conn->pg_conn);
        pfd.events = POLLIN;
        pfd.revents = 0;

        /* Wait for the socket to be ready for reading. */
        do {
            n = poll(&pfd, 1, self->db_timeout);

            /* Check the error or termination conditions. */
            if ((pfd.revents & POLLNVAL) != 0 ||
                (pfd.revents & POLLERR) != 0 ||
                (pfd.revents & POLLHUP) != 0)
                break;
           
            /* Timeout? */
            if (n == 0)	{ 
                timeout = 1; 
                break;
            }

            /* Interruption ? */
            if (n < 0 && errno != EINTR) break;

            /* None of the above? Then try to fetch the results. */
            if (n == 1) {
                PQconsumeInput(self->conn->pg_conn);            
                if (!PQisBusy(self->conn->pg_conn))
                    done = 1;
            }

        } while (n < 1 || !done);
    } else
        done = 1;

    /* If we are simply not done, presume the database connection is
       gone at this point. */
    if (!done) {
        KERROR_PUSH(_db_, 0, "lost connection to database");
        return -1;
    }	
    /* In case of timeout, try to cancel the query, but stil return an
       error. */
    else if (!done && timeout) {
        WARN(_log_db_, "Query is taking too long, cancelling it.");

        db_cancel = PQgetCancel(self->conn->pg_conn);

        /* Try to cancel the query. */
        if (PQcancel(db_cancel, db_cancel_str, CANCEL_STR_SIZE) == 0) 
            WARN(_log_db_, "Failed to cancel the query.");
        else
            WARN(_log_db_, "Query cancelled successfully.");
            
        PQfreeCancel(db_cancel);

        /* Push an error. */
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "database query timeout");

        return -1;
    }
    /* If PQgetResult is null and done == 1. That means we have fetched some
       results.  Return positively. */
    else return 0;
}

/** Post a statement to begin transaction.  
 * 
 * Waits for the completion of the statement.
 */
int kdsql_begin(kdsql *self) {
    PGresult *db_res = NULL;

    if (self->conn == NULL) {
        KERROR_PUSH(_db_, 0, "disconnected from database");
        return -1;
    }

    /* Post the query. */
    if (kdsql_async_query(self, "begin;") < 0) {
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "failed to post transaction begin");
        return -1;
    }

    /* Wait for the answer. */
    if (kdsql_async_wait_response(self) < 0) {
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "failed to wait for begin response");
        return -1;
    }

    db_res = PQgetResult(self->conn->pg_conn);

    if (PQresultStatus(db_res) != PGRES_COMMAND_OK) {
        PQclear(db_res);
        kdsql_clear_res_queue(self);

        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "transaction begin error");
        return -1;
    }
    
    PQclear(db_res);
    kdsql_clear_res_queue(self);

    return 0;
}

/** Post a statement to commit transaction.  
 *
 * Waits for the completion of the statement.
 */
int kdsql_commit(kdsql *self) {
    PGresult* db_res = NULL;
 
    if (self->conn == NULL) {
        KERROR_PUSH(_db_, 0, "disconnected from database");
        return -1;
    }

    /* Post the query. */
    if (kdsql_async_query(self, "commit;") < 0) {
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "failed to post transaction commit");
        return -1;
    }

    /* Wait for the answer. */
    if (kdsql_async_wait_response(self) < 0) {
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "failed to wait for commit response");
        return -1;
    }

    db_res = PQgetResult(self->conn->pg_conn);

    if (PQresultStatus(db_res) != PGRES_COMMAND_OK) {
        PQclear(db_res);
        kdsql_clear_res_queue(self);
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "transaction commit error");
        return -1;
    }

    PQclear(db_res);
    kdsql_clear_res_queue(self);

    return 0;
}

/** Post a statement to rollback transaction.  
 * 
 * Waits for the completion of the statement.  Clears and sets the
 * error stack.
 */
int kdsql_rollback(kdsql *self) {
    PGresult* db_res = NULL;

    if (self->conn == NULL) {
        KERROR_PUSH(_db_, 0, "disconnected from database");
        return -1;
    }

    /* Post the query. */
    if (kdsql_async_query(self, "rollback;") < 0) {
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "failed to post transaction rollback");
        return -1;
    }
    
    /* Wait for the answer. */
    if (kdsql_async_wait_response(self) < 0) {
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "failed to wait for rollback response");
        return -1;
    }

    db_res = PQgetResult(self->conn->pg_conn);

    if (PQresultStatus(db_res) != PGRES_COMMAND_OK) {
        PQclear(db_res);
        kdsql_clear_res_queue(self);
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0, "transaction rollback error");
        return -1;
    }
    
    PQclear(db_res);
    kdsql_clear_res_queue(self);

    return 0;
}

/** Prepare an SQL statement.  Waits for the preparation results. */
int kdsql_prepare_statement(kdsql *self, 
#ifndef KD_DB_DEBUG
                            __attribute__ ((unused))
#endif // DEBUG_DB
                            const char *statement_name,
                            const char *statement) {    
    PGresult *db_res = NULL;

    if (self->conn == NULL) {
        KERROR_PUSH(_db_, 0, "disconnected from database");
        return -1;
    }

#ifdef KD_DB_DEBUG
    DEBUG(_log_db_, "Preparing SQL: %s.", statement_name);
#endif // KD_DB_DEBUG

    /* Wait for output ready. */
    if (kdsql_wait_writing_ready(self) < 0) {
        kdsql_error_pgsql(self->conn);
        KERROR_PUSH(_db_, 0,  "async query error waiting for channel readyness");
        return -1;
    }

    /*
     * PostgreSQL 8.0 supports preparing statement directly.  With PostgreSQL 7.4
     * statement needs to be prepared by sending ordinary queries.
     */

    do {
        /* Send the PREPARE statement. */
        if (kdsql_async_query(self, statement) < 0)             
            break;

        /* Wait for the result. */
        if (kdsql_async_wait_response(self) < 0) 
            break;

        /* Check the results. */
        db_res = PQgetResult(self->conn->pg_conn);
        
        if (PQresultStatus(db_res) != PGRES_COMMAND_OK)
            break;

        PQclear(db_res);
        kdsql_clear_res_queue(self);

        return 0;

    } while (0);

    PQclear(db_res);

    kdsql_clear_res_queue(self);
    kdsql_error_pgsql(self->conn);
    KERROR_PUSH(_db_, 0, "prepare statement error");

    return -1;
}
