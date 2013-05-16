/**
 * tbxsosd/common/logid.h
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
