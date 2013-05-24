/**
 * tbxsosd/libdb/db_login.c
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
 * Login database object.
 *
 * @author François-Denis Gonthier
*/

#include <apr_pools.h>
#include <apr_strings.h>
#include <kerror.h>
#include <stdlib.h>

#include "logid.h"
#include "db.h"
#include "db_psql.h"
#include "db_login.h"
#include "utils.h"
#include "options.h"
#include "logging.h"

static struct db_statement db_stmts[6] = {
    {
        .statement_name = "db_login_external",
        .statement = 
        "prepare db_login_external (varchar, varchar, bigint) as select rights, "
        "prof_id, token from login_external($1, $2, $3);"
    },
    {
        .statement_name = "db_login_pwd",
        .statement = 
        "prepare db_login_pwd (varchar, varchar, varchar) as select rights, "
        "prof_id, token from login_password($1, $2, $3);"
    },
    {
        .statement_name = "db_login_token",
        .statement = 
        "prepare db_login_token (varchar, varchar) as select rights, "
        "prof_id, token from login_token($1, $2);"
    },
    {
        .statement_name = "db_login_count_seats",
        .statement = "prepare db_login_count_seats (bigint) as select * from login_count_seats($1);"
    },
    {
        .statement_name = "db_login_reserve_seat",
        .statement = 
        "prepare db_login_reserve_seat (varchar, bigint, bigint) as "
        "select * from login_reserve_seat($1, $2, $3);"
    },
    {
        .statement_name = "db_login_get_seats_allocation",
        .statement = 
        "prepare db_login_get_seats_allocation (bigint) as "
        "select * from get_seats_allocation($1);"
    }
};

static struct db_config db_cfg = {
    .statement_count = 6,
    .statements = db_stmts
};

static int kddblogin_check_prepared(kddblogin *self) {
    if (!self->is_prepared) {
        if (kdsql_prepare_all(self->db, &db_cfg) < 0) {
            KERROR_PUSH(_db_, 0, "failed to connect to public key database");
            return -1;
        }

        self->is_prepared = 1;
    }

    return 0;
}

/** Initialize connection database. */
kddblogin *kddblogin_new(apr_pool_t *pool, kdsql *db) {
    kddblogin *self;

    self = apr_pcalloc(pool, sizeof(kddblogin));
    self->db = db;
    self->pool = pool;

    return self;
}

/** Start an external login transaction. */
int kddblogin_start(kddblogin *self) {
    if (kddblogin_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    if (kdsql_begin(self->db) < 0) {
        KERROR_PUSH(_db_, 0, "failed to begin login transaction");
        return -1;
    }

    return 0;
}

/** Commit an external login transaction. */
int kddblogin_succeed(kddblogin *self) {
    if (kddblogin_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    if (kdsql_commit(self->db) < 0) {
        KERROR_PUSH(_db_, 0, "failed to commit login transaction");
        return -1;
    }

    return 0;
}

/** Rollback an external login transaction. */
int kddblogin_fail(kddblogin *self) {
    if (kddblogin_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    if (kdsql_rollback(self->db) < 0) {
        KERROR_PUSH(_db_, 0, "failed to rollback login transaction");
        return -1;
    }

    return 0;
}

int kddblogin_get_seats_allocation(kddblogin *self, uint64_t org_id, int *seats_count) {
    int err = -1;
    const char *params[3] = { NULL, NULL, NULL };
    int params_s[3] = { 0, 0, 0 };
    PGresult *db_res = NULL;
    char *seats_count_text;

    if (kddblogin_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    params[0] = kdsql_uint64_param(0, org_id);
    params_s[0] = strlen(params[0]);

    do {
        if (kdsql_async_named_query_params(self->db,
                                           "db_login_get_seats_allocation",
                                           1,
                                           params,
                                           params_s) < 0) {
            KERROR_PUSH(_db_, 0, "login seat allocation query failed");
            break;
        }

        if (kdsql_async_wait_response(self->db) < 0) {
            KERROR_PUSH(_db_, 0, "login seat allocation query failed");
            break;
        }

        if (kdsql_async_wait_response(self->db) < 0) {
            KERROR_PUSH(_db_, 0, "login seat allocation query response failed");
            break;
        }

        db_res = PQgetResult(kdsql_get_conn(self->db));

        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while getting seat allocation");
            break;
        }

        seats_count_text = PQgetvalue(db_res, 0, 0);

        if (seats_count != NULL) {
            if (sscanf(seats_count_text, "%d", seats_count) < 1) {
                KERROR_SET(_db_, 0, "incorrect seat count value: %s", seats_count_text);
                break;
            }
        }

        err = 0;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return err;
}

int kddblogin_reserve_seat(kddblogin *self, const char *username, uint64_t org_id, uint64_t *parent_org_id) {
    int err = -1;
    const char *params[3] = { NULL, NULL, NULL };
    int params_s[3] = { 0, 0, 0 };
    PGresult *db_res = NULL;

    if (kddblogin_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    params[0] = username;
    params[1] = kdsql_uint64_param(1, org_id);
    params[2] = (parent_org_id == NULL ? NULL : kdsql_uint64_param(2, *parent_org_id));
    params_s[0] = (username == NULL ? 0 : strlen(username));
    params_s[1] = strlen(params[1]);
    params_s[2] = (params[2] == NULL ? 0 : strlen(params[2]));

    do {
        if (kdsql_async_named_query_params(self->db,
                                           "db_login_reserve_seat",
                                           3,
                                           params,
                                           params_s) < 0) {
            KERROR_PUSH(_db_, 0, "login seat reservation query failed");
            break;
        }

        if (kdsql_async_wait_response(self->db) < 0) {
            KERROR_PUSH(_db_, 0, "login seat reservation query response failed");
            break;
        }

        db_res = PQgetResult(kdsql_get_conn(self->db));

        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while counting seats");
            break;
        }

        err = 0;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return err;
}

/* Check if the number of seat matches what the organization was
   allocated. */
int kddblogin_count_seats(kddblogin *self, uint64_t org_id, int *seats_count) {
    int err = -1;
    const char *params[1] = { NULL };
    int params_s[1] = { 0 };
    char *seats_count_text;
    PGresult *db_res = NULL;

    if (kddblogin_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    params[0] = kdsql_uint64_param(0, org_id);
    params_s[0] = strlen(params[0]);

    do {
        if (kdsql_async_named_query_params(self->db,
                                          "db_login_count_seats", 
                                          1,
                                          params,
                                          params_s) < 0) {
            KERROR_PUSH(_db_, 0, "login seat count query failed");
            break;
        }

        if (kdsql_async_wait_response(self->db) < 0) {
            KERROR_PUSH(_db_, 0, "login seat count query response failed");
            break;
        }
        
        db_res = PQgetResult(kdsql_get_conn(self->db));

        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while counting seats");
            break;
        }

        if (PQntuples(db_res) == 0) {
            KERROR_SET(_db_, 0, "login seat count query returned no results");
            break;
        }              

        seats_count_text = PQgetvalue(db_res, 0, 0);

        if (seats_count != NULL) {
            if (sscanf(seats_count_text, "%d", seats_count) < 1) {
                KERROR_SET(_db_, 0, "incorrect seat count value: %s", seats_count_text);
                break;
            }
        }

	err = 0;       

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return err;
}

static int kddblogin_set_results(apr_pool_t *pool, PGresult *db_res, struct kd_login_result **res) {
    /* Convert the results. */
    char *s;

    s = PQgetvalue(db_res, 0, 0);
    if (sscanf(s, "%d", (int *)&(*res)->rights) < 1) {
        KERROR_SET(_db_, 0, "incorrect value for login_rights: %s", s);
        return -1;
    }

    /* In case the login is denied, we don't need to care about the
       rest of the login data which will most likely be NULL. */
    if ((*res)->rights != LOGIN_RIGHTS_DENIED) {

        /* Will be null in case of LDAP login where we can
           conclusively find the profile ID in that place. */
        if (!PQgetisnull(db_res, 0, 1)) {
            s = PQgetvalue(db_res, 0, 1);
            if (sscanf(s, PRINTF_64"u", &(*res)->prof_id) < 1) {
                KERROR_SET(_db_, 0, "incorrect value for profile ID: %s", s);
                return -1;
            }
        } else 
            /* Weird situation.  I don't know where that could
               happen. */
            (*res)->prof_id = -1;
       
        (*res)->token = apr_pstrdup(pool, PQgetvalue(db_res, 0, 2));
    }

    return 0;
}

int kddblogin_login(kddblogin *self, 
                    apr_pool_t *pool,
                    int with_password,
                    const char *login_stmt, 
                    const char *id, 
                    const char *secret,
                    struct kd_login_result **res) {    
    int error = -1;
    PGresult *db_res = NULL;
    const char *params[3] = {id, secret, NULL};
    int params_s[3] = {0, 0, UUID_SIZE};
    char *tok;

    if (kddblogin_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    params_s[0] = (id == NULL ? 0 : strlen(id));
    params_s[1] = (secret == NULL ? 0 : strlen(secret));

    do {
        if (with_password) {
	    int ticket_is_pwd = 0;
	    
            ticket_is_pwd = options_get_bool("server.login_ticket_is_pwd");
	    if (!ticket_is_pwd) {

        	tok = uuid(pool);
        	if (tok == NULL) {
                    KERROR_PUSH(_db_, 0, "could not obtain random UUID");
                    return -1;
        	}
        	params[2] = tok;
	    }
	    
	    else {
	    	DEBUG(_log_client_, "Using password as login ticket.");
	    	params[2] = secret;
	    }

            if (kdsql_async_named_query_params(self->db,
                                               login_stmt, 
                                               3,
                                               params,
                                               params_s) < 0) {
                KERROR_PUSH(_db_, 0, "login query failed");
                break;
            }
        } 
        else {
            if (kdsql_async_named_query_params(self->db,
                                               login_stmt, 
                                               2,
                                               params,
                                               params_s) < 0) {
                KERROR_PUSH(_db_, 0, "login query failed");
                break;
            }
        }

        if (kdsql_async_wait_response(self->db) < 0) {
            KERROR_PUSH(_db_, 0, "login query response failed");
            break;
        }

        db_res = PQgetResult(kdsql_get_conn(self->db));
        
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while logging in");
            break;
        }

        if (PQntuples(db_res) == 0) {
            KERROR_SET(_db_, 0, "login query returned no results");
            break;
        }

        if (kddblogin_set_results(pool, db_res, res) < 0)
            break;
	
	error = 0;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);
    
    return error;
}

int kddblogin_token_login(kddblogin *self, 
                          apr_pool_t *pool,
                          const char *username, 
                          const char *token,
                          struct kd_login_result **res) {
    return kddblogin_login(self, pool, 0, "db_login_token", username, token, res);
}

int kddblogin_pwd_login(kddblogin *self, 
                        apr_pool_t *pool,
                        const char *username, 
                        const char *password,
                        struct kd_login_result **res) {
    return kddblogin_login(self, pool, 1, "db_login_pwd", username, password, res);
}

int kddblogin_external(kddblogin *self,
                       apr_pool_t *pool,
                       const char *username,
                       uint64_t org_id,
                       struct kd_login_result **res) {
    int error = -1;
    PGresult *db_res = NULL;
    const char *params[3];
    int params_s[3];
    char *tok;

    if (kddblogin_check_prepared(self) < 0) {
        KERROR_PUSH(_db_, 0, "query prepare failed");
        return -1;
    }

    *res = apr_pcalloc(pool, sizeof(struct kd_login_result));

    tok = uuid(pool);
    if (tok == NULL) {
        KERROR_PUSH(_db_, 0, "could not obtain random UUID");
        return -1;
    }

    params[0] = username;
    params[1] = tok;
    params[2] = kdsql_uint64_param(0, org_id);

    params_s[0] = (username == NULL ? 0 : strlen(username));
    params_s[1] = UUID_SIZE;
    params_s[2] = strlen(params[2]);

    do {
        if (kdsql_async_named_query_params(self->db,
                                          "db_login_external", 
                                          3,
                                          params,
                                          params_s) < 0) {
            KERROR_PUSH(_db_, 0, "login check query failed");
            break;
        }

        if (kdsql_async_wait_response(self->db) < 0) {
            KERROR_PUSH(_db_, 0, "login external response failed");
            break;
        }

        db_res = PQgetResult(kdsql_get_conn(self->db));

        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while logging in");
            break;
        }
        
        if (PQntuples(db_res) == 0) {
            KERROR_SET(_db_, 0, "login external returned no results");
            break;
        }              

        if (kddblogin_set_results(pool, db_res, res) < 0)
            break;
	
	error = 0;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);
    
    return error;
}
