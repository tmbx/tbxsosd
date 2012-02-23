/**
 * tbxsosd/common/logid.h
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
 * Logging identifiers for tbxsosd.
 * 
 * @author François-Denis Gonthier
 */

#ifndef _LOGID_H
#define _LOGID_H

#define _log_client_ "client"
#define _client_     (1 << 0)

#define _log_server_ "server"
#define _server_     (1 << 1)

#define _log_db_     "db"
#define _db_         (1 << 2)

#define _log_knp_    "knp"
#define _knp_        (1 << 3)

#define _log_shared_ "shared"
#define _shared_     (1 << 4)

#define _log_ldap_   "ldap"
#define _ldap_       (1 << 5)

#define _keys_       (1 << 6)

#define _otut_       (1 << 7)

#define _dpkg_       (1 << 8)

#define _log_pkg_    "pkg"
#define _pkg_        (1 << 9)

#define _log_filter_ "filter"
#define _filter_     (1 << 10)

#define _comm_       (1 << 11)

#define _pod_        (1 << 12)

#define _config_     (1 << 13)

#define _log_prefork_ "prefork"

#define _kctl_       (1 << 14)

#define _log_misc_   "misc"
#define _misc_       (1 << 15)

#endif // _LOGID_H
