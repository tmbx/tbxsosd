/**
 * tbxsosd/libdb/ldapdb_utils.c
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
 * LDAP server list management
 * @author: François-Denis Gonthier
 */

#include <apr_pools.h>
#include <ldap.h>
#include <kerror.h>

#include "logid.h"
#include "ldapdb_utils.h"

void kdldap_paranoid_push_error(LDAP *ldap_conn, int ldap_err) {
    int err_code;
    char *err_str;

    if (ldap_conn) {
        /* This is defined in OpenLDAP 2.4.x, which is availabe on Debian
           Sid but not on Teambox K1. */
#ifdef LDAP_OPT_RESULT_CODE
        ldap_err = ldap_err;
        ldap_get_option(ldap_conn, LDAP_OPT_RESULT_CODE, &err_code);
#else
        err_code = ldap_err;
#endif
        ldap_get_option(ldap_conn, LDAP_OPT_ERROR_STRING, &err_str);

        if (err_str != NULL)
            KERROR_SET(_ldap_, 0, "LDAP internal error: %s", err_str);
    }
    else 
        err_code = ldap_err;

    KERROR_PUSH(_ldap_, 0, "LDAP error: %s", ldap_err2string(err_code));
    ldap_memfree(err_str);
}

char *kdldap_escape_string(apr_pool_t *pool, const char *src, size_t src_sz) {
    size_t i, j;
    char *newstr = apr_palloc(pool, src_sz * 3 + 1);

    for (i = 0, j = 0; i < src_sz; i++) {
        if (!isalnum(src[i])) {
            sprintf(&newstr[j], "\\%02x", (uint8_t)src[i]);
            j += 3;
        } 
        else {
            newstr[j] = src[i];
            j++;
        }
    }
    newstr[j] = '\0';

    return newstr;
}
