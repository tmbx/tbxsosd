/**
 * tbxsosd/libdb/db_user.c
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
 * User database object.
 *
 * @author François-Denis Gonthier
 */

#include <apr_tables.h>
#include <apr_strings.h>
#include <stdlib.h>
#include <kerror.h>

#include "common.h"
#include "logid.h"
#include "db_psql.h"
#include "db_user.h"

static struct db_statement db_stmts[12] = {
    {
        .statement_name = "db_user_email_search",
        .statement = 
        "prepare db_user_email_search (varchar) as select * from email_search($1);"
    },
    {
        .statement_name = "db_user_is_email_allowed",
        .statement =
        "prepare db_user_is_email_allowed (bigint, varchar) as "
        "select email_is_allowed($1, $2);"
    },
    {
        .statement_name = "db_user_get_key_id",
        .statement = 
        "prepare db_user_get_key_id (bigint) as "
        "select key_id from profiles where prof_id = $1;"
    },
    {
        .statement_name = "db_user_get_name",
        .statement = 
        "prepare db_user_get_name (bigint) as select * from get_profile_name($1);"
    },
    {
        .statement_name = "db_user_get_primary_email_address",
        .statement =
        "prepare db_user_get_primary_email_address (bigint) as "
        "select * from get_primary_email_address($1);"
    },
    {
        .statement_name = "db_user_ldap_group_search",
        .statement = 
        "prepare db_user_ldap_group_search (varchar) as "
        "select prof_id, org_id, key_id from ldap_groups_view "
        " where group_dn ilike $1;"
    },
    {
        .statement_name = "db_user_ldap_group_list",
        .statement =
        "prepare db_user_ldap_group_list as select group_dn from ldap_groups_view;"
    },
    {
        .statement_name = "db_user_get_prof_status",
        .statement = 
        "prepare db_user_get_prof_status (bigint) as select * from get_prof_status($1);"
    },
    {
        .statement_name = "db_user_get_key_status",
        .statement = 
        "prepare db_user_get_key_status (bigint) as select * from get_key_status($1);"
    },
    {
        .statement_name = "db_user_get_org_data_from_prof_id",
        .statement = 
        "prepare db_user_get_org_data_from_prof_id (bigint) as "
        "select org_id, forward_to, license from get_org_data_from_prof_id($1);"
    },
    {
        .statement_name = "db_user_get_org_data_from_kdn",
        .statement = 
        "prepare db_user_get_org_data_from_kdn (varchar) as "
        "select org_id, forward_to, license from get_org_data_from_kdn($1);"
    },
    {
        .statement_name = "db_user_import_license",
        .statement = 
        "prepare db_user_import_license(varchar, varchar) "
        " as select * from set_org_license($1, $2);"
    }
};
static struct db_config db_cfg = {
    .statement_count = 12,
    .statements = db_stmts
};

static int kddbuser_check_connect(kddbuser *self) {
    if (!self->is_prepared) {
        /* if (self->admin) { */
        /*     db_cfg.username_cfg = "db_user.admin_username"; */
        /*     db_cfg.password_cfg = "db_user.admin_password"; */
        /* } */
        /* else { */
        /*     db_cfg.username_cfg = "db_user.username"; */
        /*     db_cfg.password_cfg = "db_user.password"; */
        /* } */

        if (kdsql_prepare_all(self->db, &db_cfg) < 0) {
            KERROR_PUSH(_db_, 0, "failed to connect to public key database");
            return -1;
        }

        self->is_prepared = 1;
    }

    return 0;
}

/* FIXME: This object access the PROFILES database and thus this is
   wrongly named. */

kddbuser *kddbuser_new(apr_pool_t *pool, kdsql *db, int admin, int cur_creds) {
    kddbuser *self;

    self = apr_pcalloc(pool, sizeof(kddbuser));
    self->db = db;
    self->pool = pool;
    self->admin = admin;
    self->cur_creds = cur_creds;

    return self;
}

/** Return the primary email address of an user. */
int kddbuser_get_prim_email(kddbuser *self,
                            apr_pool_t *pool,
                            uint64_t prof_id,
                            char **prim_addr) {
    int params_s[1] = { 0 };
    const char *params[1] = { NULL };
    PGresult *db_res = NULL;
    char *res;   

    /* Setup the parameters. */
    params[0] = kdsql_uint64_param(0, prof_id);
    params_s[0] = strlen(params[0]);

    /* Make sure we are connected to the database. */
    if (kddbuser_check_connect(self) < 0) {
        KERROR_PUSH(_db_, 0, "not connected");
        return -1;
    }

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_user_get_primary_email_address",
                                          1, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_user_get_email failed");
            break;
        }

        /* Get the results. */
        db_res = PQgetResult(kdsql_get_conn(self->db));
        
        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while check if an user was allowed");
            break;
        }

        /* Check if there is any result. */
        if (PQntuples(db_res) != 1) {
            KERROR_SET(_db_, 0, "result error while fetching key");
            break;
        }

        if (prim_addr != NULL) {
            res = PQgetvalue(db_res, 0, 0);
            *prim_addr = apr_pstrdup(pool, res);
        }

        PQclear(db_res);
        kdsql_clear_res_queue(self->db);

        return 0;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);
    
    return -1;
}

/** Return the full name for a profile. 
 *
 * Allocates memory in the pool passed as a parameter.
 */
int kddbuser_get_name(kddbuser *self, 
                      apr_pool_t *pool, 
                      uint64_t prof_id, 
                      char **full_name) {
    int params_s[1] = { 0 };
    const char *params[1] = { NULL };
    PGresult *db_res = NULL;
    char *res;   

    /* Setup the parameters. */
    params[0] = kdsql_uint64_param(0, prof_id);
    params_s[0] = strlen(params[0]);

    /* Make sure we are connected to the database. */
    if (kddbuser_check_connect(self) < 0) {
        KERROR_PUSH(_db_, 0, "not connected");
        return -1;
    }

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_user_get_name",
                                            1, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_user_get_name failed");
            break;
        }

        /* Get the results. */
        db_res = PQgetResult(kdsql_get_conn(self->db));
        
        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while check if an user was allowed");
            break;
        }

        /* Check if there is any result. */
        if (PQntuples(db_res) != 1) {
            KERROR_SET(_db_, 0, "result error while fetching key");
            break;
        }

        if (full_name != NULL) {
            res = PQgetvalue(db_res, 0, 0);
            *full_name = apr_pstrdup(pool, res);
        }

        PQclear(db_res);
        kdsql_clear_res_queue(self->db);

        return 0;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);
    
    return -1;
}

/** Return the key ID for a profile. */
int kddbuser_get_key_id(kddbuser *self, uint64_t prof_id, uint64_t *key_id) {
    int params_s[1] = { 0 };
    const char * params[1] = { NULL };
    PGresult * db_res = NULL;
    char * res;

    /* Setup the parameters. */
    params[0] = kdsql_uint64_param(0, prof_id);
    params_s[0] = strlen(params[0]);

    /* Make sure we are connected to the database. */
    if (kddbuser_check_connect(self) < 0) {
        KERROR_PUSH(_db_, 0, "not connected");
        return -1;
    }

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_user_get_key_id",
                                          1, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_user_get_key_id failed");
            break;
        }

        /* Get the results. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while check if an user was allowed");
            break;
        }

        /* Check if there is any result. */
        if (PQntuples(db_res) != 1) {
            KERROR_SET(_db_, 0, "result error while fetching key ID");
            break;
        }

        res = PQgetvalue(db_res, 0, 0);

        if (key_id != NULL) {
            if (sscanf(res, "%llu", key_id) < 1) {
                KERROR_SET(_db_, 0, "incorrect key ID value: %s", key_id);
                break;
            }
        }

        PQclear(db_res);
        kdsql_clear_res_queue(self->db);

        return 0;
        
    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);
    
    return -1;
}

/**
 * Check if a specific UID is allowed to decrypt an email, that is check if one of the
 * user email address is in the destination list for the specific key.
 */
int kddbuser_is_email_allowed(kddbuser *self,
                              apr_pool_t *parent_pool,
                              uint64_t uid, 
                              const char *addr_list,
                              int *is_allowed,
                              char **email_matched) {
    int params_s[2] = { 0, 0};
    const char *params[2] = { NULL, NULL };
    PGresult *db_res = NULL;
    char *res;
    
    *is_allowed = 0;

    /* Setup the parameters. */
    params[0] = kdsql_uint64_param(0, uid);    
    params[1] = addr_list;
    params_s[0] = strlen(params[0]);
    params_s[1] = strlen(addr_list);    

    /* Make sure we are connected to the database. */
    if (kddbuser_check_connect(self) < 0) {
        KERROR_PUSH(_db_, 0, "not connected");
        return -1;
    }

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_user_is_email_allowed",
                                            2, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_user_is_email_allowed failed");
            break;
        }

        /* Get the results. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "query error while check if an user was allowed");
            break;
        }

        res = PQgetvalue(db_res, 0, 0);
        
        if (is_allowed != NULL) {
            if (strcmp(res, "") != 0)
                *is_allowed = 1;
            else if (strcmp(res, "") == 0)
                *is_allowed = 0;
            else 
                *is_allowed = 0;
        }

        if (email_matched != NULL)
            *email_matched = apr_pstrdup(parent_pool, res);

        PQclear(db_res);
        kdsql_clear_res_queue(self->db);

        return 0;
        
    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);
    
    return -1;
}

int kddbuser_list_ldap_groups(kddbuser *self,
                              apr_array_header_t *group_list) {
    PGresult *db_res = NULL;

    /* Make sure we are connected to the database. */
    if (kddbuser_check_connect(self) < 0) {
        KERROR_PUSH(_db_, 0, "not connected");
        return -1;
    }

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_user_ldap_group_list", 
                                            0, NULL, NULL) < 0) {
            KERROR_PUSH(_db_, 0, "db_user_ldap_group_list failed");
            break;
        }

        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "no data returned in LDAP group list");
            break;
        }

        if (PQntuples(db_res) == 0) {
            KERROR_SET(_db_, 0, "LDAP group search returned no results");
            break;
        }
        
        /* Loop until we run out of results. */
        int i, n = PQntuples(db_res);

        for (i = 0; i < n; i++) {
            char **group_dn;

            group_dn = apr_array_push(group_list);
            *group_dn = apr_pstrdup(group_list->pool, PQgetvalue(db_res, i, 0));
        }

        PQclear(db_res);
        kdsql_clear_res_queue(self->db);

        return 0;
    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);
    
    return -1;
}

int kddbuser_search_ldap_group(kddbuser *self,
                               const char *dn_str,
                               uint64_t *prof_id,
                               uint64_t *org_id,
                               uint64_t *key_id) {
    int error = -1;
    int param_s[1] = { strlen(dn_str) + 1 };
    const char *param[1] = { dn_str };
    PGresult *db_res = NULL;
    char *prof_id_text;
    char *key_id_text;
    char *org_id_text;

    /* Make sure we are connected to the database. */
    if (kddbuser_check_connect(self) < 0) {
        KERROR_PUSH(_db_, 0, "not connected");
        return -1;
    }

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_user_ldap_group_search",
                                          1, param, param_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_user_ldap_group_search failed");
            break;
        }

        /* Get the results. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);            
            KERROR_SET(_db_, 0, "no data returned in LDAP group search");
            break;
        }

        /* No results. */
        if (PQntuples(db_res) == 0) {
            error = 0;
            break;
        }

        /* Check the result we have.  If the key id is 0, that means
           nothing was found. */        
        prof_id_text = PQgetvalue(db_res, 0, 0);
        org_id_text = PQgetvalue(db_res, 0, 1);
        key_id_text = PQgetvalue(db_res, 0, 2);        

        if (strcmp(key_id_text, "0") == 0) {
	    error = 0;
            break;
	}

        if (key_id != NULL) {
            if (sscanf(key_id_text, "%llu", key_id) < 1) {
                KERROR_SET(_db_, 0, "incorrect key ID value: %s", key_id_text);
                break;
            }
        }

        if (org_id != NULL) {
            if (sscanf(org_id_text, "%llu", org_id) < 1) {
                KERROR_SET(_db_, 0, "incorrect org ID value: %s", org_id_text);
                break;
            }
        }

        if (prof_id != NULL) {
            if (sscanf(prof_id_text, "%llu", prof_id) < 1) {
                KERROR_SET(_db_, 0, "incorrect profile ID value: %s", prof_id_text);
                break;
            }
        }

	error = 1;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}

int kddbuser_get_org_data_from_kdn(kddbuser *self,
                                   apr_pool_t *pool,
                                   const char *kdn,
                                   struct kd_organization *org_data) {
    int err = -1;
    PGresult *db_res = NULL;
    char *org_id_text, *addr_text, *lic_text;
    const char *params[1] = { NULL };
    int params_s[1] = { 0 };

    params[0] = kdn;
    params_s[0] = (kdn == NULL ? 0 : strlen(kdn));

    if (kddbuser_check_connect(self) < 0) {
        KERROR_PUSH(_db_, 0, "not connected");
        return -1;
    }
    
    do {
        if (kdsql_async_named_query_params(self->db, "db_user_get_org_data_from_kdn",
                                           1, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_user_get_org_data_from_kps");
            break;
        }

        db_res = PQgetResult(kdsql_get_conn(self->db));

        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "no data returned in organization search from KDN");
            break;
        }

        if (org_data != NULL) {
            org_id_text = PQgetvalue(db_res, 0, 0);
            if (sscanf(org_id_text, "%llu", &org_data->org_id) < 1) {
                KERROR_SET(_db_, 0, "invalid value for organization ID: %s", org_id_text);
                break;
            }

            addr_text = PQgetvalue(db_res, 0, 1);
            org_data->forward_to = apr_pstrdup(pool, addr_text);

            lic_text = PQgetvalue(db_res, 0, 2);
            org_data->license = apr_pstrdup(pool, lic_text);
        }

        err = 0;
        
    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return err;
}

/** Return the data related to the organization of the user. */
int kddbuser_get_org_data_from_prof_id(kddbuser *self, 
                                       apr_pool_t *pool,
                                       uint64_t prof_id,
                                       struct kd_organization *org_data) {
    int err = -1;
    PGresult *db_res = NULL;
    char *org_id_text, *addr_text, *lic_text;
    const char *params[1] = { NULL };
    int params_s[1] = { 0 };
    
    params[0] = kdsql_uint64_param(0, prof_id);
    params_s[0] = strlen(params[0]);

    if (kddbuser_check_connect(self) < 0) {
        KERROR_PUSH(_db_, 0, "not connected");
        return -1;
    }

    do {
        if (kdsql_async_named_query_params(self->db, "db_user_get_org_data_from_prof_id",
                                           1, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_user_get_org_data failed");
            break;
        }

        db_res = PQgetResult(kdsql_get_conn(self->db));

        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "no data returned in archive email search");
            break;
        }

        if (org_data != NULL) {
            org_id_text = PQgetvalue(db_res, 0, 0);
            if (sscanf(org_id_text, "%llu", &org_data->org_id) < 1) {
                KERROR_SET(_db_, 0, "invalid value for organization ID: %s", org_id_text);
                break;
            }

            addr_text = PQgetvalue(db_res, 0, 1);
            org_data->forward_to = apr_pstrdup(pool, addr_text);

            lic_text = PQgetvalue(db_res, 0, 2);
            org_data->license = apr_pstrdup(pool, lic_text);
        }

        err = 0;
    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return err;
}

/** Import a license string to the database. */
int kddbuser_import_license(kddbuser *self, const char *kdn, const char *license_data) {
    const char *params[2] = { NULL, NULL };
    int params_s[2] = { 0, 0 };
    PGresult *db_res = NULL;
    int err = -1;

    /* Setup the parameters. */
    params[0] = kdn;
    params[1] = license_data;
    params_s[0] = strlen(kdn);
    params_s[1] = strlen(license_data);

    /* Make sure we are connected to the database. */
    if (kddbuser_check_connect(self) < 0) {
        KERROR_PUSH(_db_, 0, "not connected");
        return -1;
    }

    do {
        if (kdsql_async_named_query_params(self->db, "db_user_import_license",
                                           2, params, params_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_user_import_license failed");
            break;
        }

        db_res = PQgetResult(kdsql_get_conn(self->db));

        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "license importation failed");
            break;
        }

        err = 0;

    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return err;
}                          

/** Search a partial email address.
 *
 * Returns the found key ID in the key_id variable but 
 * returns 0 if nothing is found. -1 in case of error.  1 when
 * something is found.
 */
int kddbuser_search_email(kddbuser *self, 
                          const char *email_str,
                          uint64_t *prof_id, 
                          uint64_t *key_id) {
    int error = -1;
    int param_s[1] = { strlen(email_str) + 1 };
    const char *param[1] = { email_str };
    PGresult *db_res = NULL;
    char *key_id_text;
    char *prof_id_text;
    
    /* Make sure we are connected to the database. */
    if (kddbuser_check_connect(self) < 0) {
        KERROR_PUSH(_db_, 0, "not connected");
        return -1;
    }

    /* Call the database. */
    do {
        if (kdsql_async_named_query_params(self->db, "db_user_email_search",
                                            1, param, param_s) < 0) {
            KERROR_PUSH(_db_, 0, "db_user_email_search failed");
            break;
        }

        /* Get the results. */
        db_res = PQgetResult(kdsql_get_conn(self->db));

        /* Check if the command succeeded. */
        if (PQresultStatus(db_res) != PGRES_TUPLES_OK) {
            kdsql_error_pgsql(self->db->conn);
            KERROR_PUSH(_db_, 0, "no data returned in email address search");
            break;
        }

        if (PQntuples(db_res) == 0) {
            KERROR_SET(_db_, 0, "email search query returned no results");
            break;
        }

        /* Check the result we have.  If the key id is 0, that means
           nothing was found. */        
        prof_id_text = PQgetvalue(db_res, 0, 0);
        key_id_text = PQgetvalue(db_res, 0, 1);        
	
        if (strcmp(key_id_text, "0") == 0) {
	    error = 0;
            break;
	}

        if (key_id != NULL) {
            if (sscanf(key_id_text, "%llu", key_id) < 1) {
                KERROR_SET(_db_, 0, "invalid value for key ID: %s", key_id);
                break;
            }
        }

        if (prof_id != NULL) {
            if (sscanf(prof_id_text, "%llu", prof_id) < 1) {
                KERROR_SET(_db_, 0, "invalid value for profile ID: %s", prof_id);
                break;
            }
        }

	error = 1;
	
    } while (0);

    PQclear(db_res);
    kdsql_clear_res_queue(self->db);

    return error;
}
