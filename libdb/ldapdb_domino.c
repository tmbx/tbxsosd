/**
 * tbxsosd/libdb/ldapdb_domino.c
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
 */

#include <apr_pools.h>
#include <assert.h>
#include <kerror.h>

#include "options.h"
#include "logid.h"
#include "logging.h"
#include "ldapdb.h"
#include "ldapdb_base.h"

/* The domino server makes all information we need available with an anonymous
 * bind, except the 'middleinitial' field. Clearly, this information must be
 * kept confidential.
 */

/* This structure represents the user information extracted from the Domino
 * server.
 */
struct domino_user_info {

    /* First name of the user. */
    char *first_name;
    
    /* Middle initial string contained in LDAP. The format seems unrestricted,
     * it might contain dots and underscores. It may be empty.
     */
    char *middle_initial;
    
    /* Last name of the user. */
    char *last_name;
    
    /* Full name of the user. */
    char *full_name;
    
    /* Primary email address. */
    char *prim_email_addr;
    
    /* Array of associated email addresses. */
    apr_array_header_t *email_addr_array;
};

/* This function obtains the domino information of the user having the DN
 * specified.
 * This function returns -1 on failure, 0 otherwise.
 */
static int kdldap_domino_get_user_info(kdldap *self,
				       apr_pool_t *pool,
				       char *user_dn,
				       struct domino_user_info *info) {
    int err = 0, strict_address;
    struct kdldap_result *res;
    const char *attrs[] = {"givenname", "middleinitial", "sn", "mail", "cn", "uid", NULL};
    char *attr_name, *attr_val, *domain;
    apr_array_header_t *short_name_array = apr_array_make(pool, 0, sizeof(char *));
    kstr str;
    
    memset(info, 0, sizeof(struct domino_user_info));
    info->email_addr_array = apr_array_make(pool, 0, sizeof(char *));
    
    kstr_init(&str);

    do {
        /* Obtain the configuration value which controls whether we can build
         * addresses based on the user's name and the domain.
         */
        strict_address = options_get_bool("ldap.strict_address");
	
	/* Obtain the user's information. */
        res = kdldap_query(self->conn_catalog, pool, LDAP_SCOPE_BASE, user_dn, attrs, NULL);
        if (res == NULL) {
            KERROR_PUSH(_ldap_, 0, "LDAP query error");
            err = -1;
            break;
        }
	
	/* No match. */
        if (res->attributes == NULL || res->attributes->nelts == 0) {
	    KERROR_SET(_ldap_, 0, "the user's LDAP entry does not exist");
	    err = -1;
	    break;
	}
	
	/* Extract the information. */
	while (res->attributes->nelts) {
	    attr_name = *(char **) apr_array_pop(res->attr_names);
	    attr_val = *(char **) apr_array_pop(res->attributes);
	    
	    if (! strcmp(attr_name, "givenname")) {
		if (! info->first_name) {
		    info->first_name = attr_val;
		}
	    }
	    
	    /* Must be non-empty. */
	    else if (! strcmp(attr_name, "middleinitial")) {
		if (! info->middle_initial && *attr_val) {
		    info->middle_initial = attr_val;
		}
	    }
	    
	    else if (! strcmp(attr_name, "sn")) {
		if (! info->last_name) {
		    info->last_name = attr_val;
		}
	    }
	    
	    else if (! strcmp(attr_name, "mail")) {
		if (! info->prim_email_addr) {
		    info->prim_email_addr = attr_val;
		    *(char **)apr_array_push(info->email_addr_array) = attr_val;
		}
	    }
	    
	    else if (! strcmp(attr_name, "cn") || ! strcmp(attr_name, "uid")) {
		
		/* This is an alternate email address. */
		if (strstr(attr_val, "@")) {
		    *(char **)apr_array_push(info->email_addr_array) = attr_val;
		}
		
		/* This is a short name. */
		else {
		    *(char **)apr_array_push(short_name_array) = attr_val;
		}
	    }
	    
	    else assert(0);
	}
	
	/* Check if we got our stuff. */
	if (! info->first_name || ! info->last_name || ! info->prim_email_addr) {
            KERROR_SET(_ldap_, 0, "missing attributes in user's LDAP entry");
	    err = -1;
	    break;
	}
	
	/* Build the full name string. */
	kstr_assign_cstr(&str, info->first_name);
	kstr_append_char(&str, ' ');
	if (info->middle_initial) {
	    kstr_append_cstr(&str, info->middle_initial);
	    kstr_append_char(&str, ' ');
	}
	kstr_append_cstr(&str, info->last_name);
	info->full_name = apr_pstrdup(pool, str.data);
	
	/* Extract the domain string. */
	domain = strstr(info->prim_email_addr, "@");
	if (! domain) {
	    KERROR_SET(_ldap_, 0, "malformed user's email address");
	    err = -1;
	    break;
	}
	
	domain++;
	
        /* Build alternate email addresses based on the user's name and the
         * domain, if required.
         */
	if (! strict_address) {
	    kstr_assign_cstr(&str, info->first_name);
	    kstr_append_char(&str, '.');
	    kstr_append_cstr(&str, info->last_name);
	    kstr_append_char(&str, '@');
	    kstr_append_cstr(&str, domain);
	    *(char **)apr_array_push(info->email_addr_array) = apr_pstrdup(pool, str.data);
	    
	    kstr_assign_cstr(&str, info->first_name);
	    kstr_append_char(&str, '_');
	    kstr_append_cstr(&str, info->last_name);
	    kstr_append_char(&str, '@');
	    kstr_append_cstr(&str, domain);
	    *(char **)apr_array_push(info->email_addr_array) = apr_pstrdup(pool, str.data);
	}
	
        /* Build alternate email addresses based on the short names and the
         * domain.
         */
	while (short_name_array->nelts) {
	    char *short_name = *(char **) apr_array_pop(short_name_array);
	    
	    /* Ignore short names with spaces. */
	    if (strstr(short_name, " ") == NULL) {
		kstr_assign_cstr(&str, short_name);
		kstr_append_char(&str, '@');
		kstr_append_cstr(&str, domain);
		*(char **)apr_array_push(info->email_addr_array) = apr_pstrdup(pool, str.data);
	    }
	}

    } while (0);

    kstr_clean(&str);
    
    return err;
}

/* This function obtains the profile information of the user having the DN
 * specified.
 * This function returns -1 on failure, 0 otherwise.
 */
static int kdldap_domino_get_profile_info(kdldap *self,
					  apr_pool_t *parent_pool,
					  kddbuser *user_db,
					  const char *dn,
					  int *is_member,
					  uint64_t *prof_id,
                                          uint64_t *org_id,
					  uint64_t *key_id) {
    apr_array_header_t *group_list;
    apr_pool_t *pool, *loop_pool;
    const char *attrs[] = {"member", NULL};
    char *filter_fmt = "member=%s", *filter, **group_dn;
    struct kdldap_result *res;
    int err = 0;

    apr_pool_create(&pool, parent_pool);
    apr_pool_create(&loop_pool, pool);
    group_list = apr_array_make(pool, 0, sizeof(char *));
    
    *is_member = 0;

    do {
        /* We need to search every group in the KPS list to find if the
           user is part of any of those groups. */
        if (kddbuser_list_ldap_groups(user_db, group_list) < 0) {
            KERROR_PUSH(_db_, 0, "failed to fetch group list");
            err = -1;
            break;
        }

	while ((group_dn = apr_array_pop(group_list)) != NULL) {
            apr_pool_clear(loop_pool);

	    filter = apr_psprintf(loop_pool, filter_fmt, dn);

	    /* Get the members of the group. */
	    res = kdldap_query(self->conn_catalog, loop_pool, LDAP_SCOPE_BASE, 
                               *group_dn, attrs, filter);

	    if (res != NULL && res->attributes->nelts > 0) {
		*is_member = 1;

		/* Found the group, yay! Fetch the profile informations. */
		if (kddbuser_search_ldap_group(user_db, *group_dn, prof_id, org_id, key_id) < 0) {
		    KERROR_PUSH(_db_, 0, "group %s not found", *group_dn);
		    err = -1;
		    break;
		}
		
		break;
	    }
	}
	
	if (err) break;
	
    } while (0);

    apr_pool_destroy(pool);

    return err;
}

static int kdldap_domino_sys_bind(kdldap *self, apr_pool_t *pool) {
    struct kdldap_conn_params params;   
    apr_pool_t *fn_pool;
    kdldap_servers_list *srv_lst;
    int err = -1;
    char *search_base;

    apr_pool_create(&fn_pool, pool);

    if (kdldap_servers_for_catalog(self->servers, fn_pool, self->sys_dn, &srv_lst, &search_base) < 0) 
        KERROR_PUSH(_ldap_, 0, "failed to get server list for KPS login");
    else {
        params.dn = self->sys_dn;
        params.username = self->sys_username;
        params.password = self->sys_password;
        params.use_sasl = self->conn_catalog->params.use_sasl;
        params.use_tls = self->conn_catalog->params.use_tls;
    
        if (kdldap_rebind(&self->conn_catalog, &params, srv_lst) < 0) 
            KERROR_PUSH(_ldap_, 0, "system login failed");
        else
            err = 0;
    }
    
    apr_pool_destroy(fn_pool);

    return err;
}

/* This function binds the user against the domino server and obtains the
 * profile information. Note that the 'username' parameter is in fact the
 * user's DN and that there is no SASL username.
 * This function returns -1 on failure, 0 otherwise.
 */
static int kdldap_domino_user_bind(kdldap *self,
				   apr_pool_t *parent_pool,
				   struct kd_user *user,
				   kddbuser *user_db,
				   const char *username,
				   const char *password,
				   uint64_t *prof_id,
                                   uint64_t *org_id,
				   uint64_t *key_id) {
    int err = 0, is_member;
    apr_pool_t *fn_pool;
    
    /* Set the kd_user DN if necessary. */
    if (user->user_dn == NULL) user->user_dn = apr_pstrdup(user->pool, username);
    
    do {
        /* If password is NULL, then a login ticket is being used. No binding is
         * to be done.
         */
	if (password) {
            struct kdldap_conn_params params;
            kdldap_servers_list *srv_lst;
            char *search_base;

            apr_pool_create(&fn_pool, parent_pool);

            params.dn = user->user_dn;
            params.username = username;
            params.password = password;
            params.use_sasl = self->conn_catalog->params.use_sasl;
            params.use_tls = self->conn_catalog->params.use_tls;

            if (kdldap_servers_for_catalog(self->servers, fn_pool, user->user_dn, &srv_lst, &search_base) < 0) {
                KERROR_PUSH(_ldap_, 0, 
                            "failed to find an LDAP server to check the user credentials");
                err = -1;
                break;
            }        
	
	    /* Bind on the server. */
	    if (!kdldap_bind(fn_pool, &params, srv_lst)) {
                err = -1;
                break;
            }
	}

	/* Obtain the profile information. */
	err = kdldap_domino_get_profile_info(self, parent_pool, user_db, username, &is_member, prof_id, org_id, key_id);
	if (err) break;

	/* Oops, the user is not a member. */
	if (! is_member) {
	    KERROR_SET(_ldap_, 0, "the user is not an authorized member");
	    err = -1;
	    break;
	}

    } while (0);

    if (err) KERROR_PUSH(_ldap_, 0, "login failed");
    return err;
}

/* This function determines if the user is allowed to decrypt a mail.
 * This function returns -1 on failure, 0 otherwise.
 */
static int kdldap_domino_is_email_allowed(kdldap *self,
					  apr_pool_t *parent_pool,
					  struct kd_user *user,
					  const char *addr_list,
					  int *is_allowed,
                                          char **email_matched) {
    apr_pool_t *pool;
    char **addrs = NULL;
    int i, j, err = 0;
    struct domino_user_info info;
    *is_allowed = 0;

    /* Split the address list. */
    apr_pool_create(&pool, parent_pool);
    apr_tokenize_to_argv(addr_list, &addrs, pool);
    
    do {
	/* Obtain the user's information. */
	err = kdldap_domino_get_user_info(self, pool, user->user_dn, &info);
	if (err) break;
	
        /* Check if one the recipient addresses matches one of the user's
         * addresses.
         */
	for (i = 0; addrs[i] != NULL; i++) {
	    char *rec_addr = addrs[i];
	    DEBUG(_log_ldap_, "Looking for user mail addresses %s.", rec_addr);
	    
	    for (j = 0; j < info.email_addr_array->nelts; j++) {
		char *user_addr = ((char**) info.email_addr_array->elts)[j];
		
		if (! strcasecmp(rec_addr, user_addr)) {
		    *is_allowed = 1;
                    if (email_matched != NULL)
                        *email_matched = apr_pstrdup(parent_pool, addrs[i]);
		    break;
		}
	    }
	
	    if (*is_allowed) break;
        }
	
    } while (0);
	
    apr_pool_destroy(pool);
    return err;
}

/* This function determines if the user having the specified address is a member
 * and obtains the profile / key ID of the user in that case.
 * The function returns -1 on failure, 0 is the user is not a member and 1 is
 * the user is a member.
 */
static int kdldap_domino_search_enc_pkey(kdldap *self,
					 apr_pool_t *parent_pool,
					 kddbuser *user_db,
					 const char *addr,
					 uint64_t *prof_id,
					 uint64_t *key_id) {
    int err = 0, is_member = 0;
    struct kdldap_result *res;
    const char *mail_attr[] = {"mail", NULL};
    char *dn, *addr_esc, *filter;
    apr_pool_t *pool;
    const char filter1_fmt[] = "(mail=%s)";
    
    apr_pool_create(&pool, parent_pool);

    do {
        /* First, try to find the user using the 'mail' attribute. */
        addr_esc = kdldap_escape_string(pool, addr, strlen(addr));
        filter = apr_psprintf(pool, filter1_fmt, addr_esc);
	DEBUG(_log_ldap_, "Looking for user with filter %s.", filter);

        res = kdldap_query(self->conn_catalog, pool, LDAP_SCOPE_SUBTREE, 
                           self->conn_catalog->server_base_dn, mail_attr, filter);
        if (res == NULL) {
            KERROR_PUSH(_ldap_, 0, "LDAP query error");
            err = -1;
            break;
        }
	
        /* User not found. Try to find the user by the splitting the email
         * address and extracting the name of the user.
         */
        if (res->attributes->nelts == 0) {
	    char *sep = ".";
	    char *sep_pos_1, *sep_pos_2, *sep_pos_3, *tmp_sep_pos;
            char *gn, *gn_esc, *sn, *sn_esc;
            const char filter_fmt[] = "(&(givenname=%s)(sn=%s))";
	    
	    sep_pos_1 = strstr(addr, sep);
	    
	    if (! sep_pos_1) {
		sep = "_";
		sep_pos_1 = strstr(addr, sep);
		
		/* Cannot split email. */
		if (! sep_pos_1) {
		    break;
		}
	    }
	    
	    /* We didn't split the email at the right place. */
	    if (! strstr(sep_pos_1, "@")) {
		break;
	    }
	    
	    tmp_sep_pos = sep_pos_2 = sep_pos_1;
	    for (; *tmp_sep_pos && *tmp_sep_pos != '@'; tmp_sep_pos++)
		if (*tmp_sep_pos == *sep)
		    sep_pos_2 = tmp_sep_pos;
	    
            sep_pos_3 = sep_pos_2;
	    for (sep_pos_2++; *sep_pos_3 && *sep_pos_3 != '@'; sep_pos_3++);

            gn = apr_pstrmemdup(pool, addr, sep_pos_1 - addr);
            sn = apr_pstrmemdup(pool, sep_pos_2, sep_pos_3 - sep_pos_2);
            gn_esc = kdldap_escape_string(pool, gn, strlen(gn));
            sn_esc = kdldap_escape_string(pool, sn, strlen(sn));
            filter = apr_psprintf(pool, filter_fmt, gn_esc, sn_esc);

#if 0 // KEEP Original code by Laurent Birtz.
	    kstr_assign_cstr(&filter, "(&(givenname=");
	    kstr_append_buf(&filter, addr, sep_pos_1 - addr);
	    kstr_append_cstr(&filter, ")(sn=");
	    for (sep_pos_2++; *sep_pos_2 && *sep_pos_2 != '@'; sep_pos_2++)
		kstr_append_char(&filter, *sep_pos_2);
	    kstr_append_cstr(&filter, "))");
#endif

	    DEBUG(_log_ldap_, "Looking for user with filter %s.", filter);
	
	    res = kdldap_query(self->conn_catalog, pool, LDAP_SCOPE_SUBTREE, 
                               self->conn_catalog->server_base_dn, mail_attr, filter);
	    if (res == NULL) {
		KERROR_PUSH(_ldap_, 0, "LDAP query error");
		err = -1;
		break;
	    }
	    
	    /* Cannot find the user. */
	    if (res->attributes->nelts == 0) {
		DEBUG(_log_ldap_, "User not found.");
		break;
	    }
        }
	
	/* We found many users. Abort. */
	if (res->attributes->nelts > 1) {
	    DEBUG(_log_ldap_, "Several users found.");
	    break;
	}
	
        /* We found a single user. Extract the DN and obtain the user's profile. */
	dn = *(char **) apr_array_pop(res->attr_dn);
	err = kdldap_domino_get_profile_info(self, pool, user_db, dn, &is_member, prof_id, NULL, key_id);
	if (err) break;
	
	/* The user is not a member. Abort. */
	if (! is_member) {
	    DEBUG(_log_ldap_, "User is not a member.");
	    break;
	}
	
	err = 1;

    } while (0);

    apr_pool_destroy(pool);
    
    return err;
}

/* This function returns the primary email address of the user.
 * This function returns -1 on failure, 0 otherwise.
 */
static int kdldap_domino_get_prim_email(kdldap *self,
					apr_pool_t *pool,
					const char *dn,
					char **prim_addr) {
    struct domino_user_info info;
    if (kdldap_domino_get_user_info(self, pool, (char *) dn, &info)) return -1;
    *prim_addr = info.prim_email_addr;
    return 0;
}

/* This function returns the full name of the user.
 * This function returns -1 on failure, 0 otherwise.
 */
static int kdldap_domino_get_name(kdldap *self,
				  apr_pool_t *pool,
				  struct kd_user *user,
				  char **name) {
    struct domino_user_info info;
    if (kdldap_domino_get_user_info(self, pool, user->user_dn, &info)) return -1;
    *name = info.full_name;
    return 0;
}

static int kdldap_domino_convert_address(__attribute__ ((unused)) kdldap *self,
                                          __attribute__ ((unused)) apr_pool_t *pool,
                                          __attribute__ ((unused)) const char *addr,
                                          __attribute__ ((unused)) char **email) {
    KERROR_PUSH(_ldap_, 0, "LDAP server cannot convert addresses");
    return -1;
}

struct kdldap_functions kdldap_domino_functions = {
    .ldap_user_bind = kdldap_domino_user_bind,
    .ldap_sys_bind = kdldap_domino_sys_bind,
    .ldap_is_email_allowed = kdldap_domino_is_email_allowed,
    .ldap_search_enc_pkey = kdldap_domino_search_enc_pkey,
    .ldap_get_prim_email = kdldap_domino_get_prim_email,
    .ldap_get_name = kdldap_domino_get_name,
    .ldap_convert_address = kdldap_domino_convert_address
};
