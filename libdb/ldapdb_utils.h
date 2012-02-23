/**
 * tbxsosd/libdb/ldapdb_utils.h
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
 * Misc LDAP functions that don't fit anywhere else.
 * @author: François-Denis Gonthier
 */

#ifndef _LDAPDB_UTILS_H
#define _LDAPDB_UTILS_H

void kdldap_paranoid_push_error(LDAP *ldap_conn, int ldap_err);

char *kdldap_escape_string(apr_pool_t *pool, const char *src, size_t src_sz);

#endif // _LDAPDB_UTILS_H_
