/**
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

#ifndef _OPTIONS_TABLE_H
#define _OPTIONS_TABLE_H

#include "libutils/options.h"

/* 2009/12/18 server.address is gone. Content should be copied inside
   server.ssl_listen_on. */

struct options opts_tbl[] = {
    /* Server options. */
    { .name = "server.user", .def = "root", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "server.group", .def = "root", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "server.ssl_listen_on", .def = "", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "server.listen_on", .def = "", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "server.log_driver", .def = "syslog", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "server.pid_file", .def = "/var/run/tbxsosd.pid", OPT_STRING | OPT_DEFAULT },
    { .name = "server.data_file", .def = "/var/cache/teambox/tbxsosd.data", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "server.password", .flags = OPT_STRING },
    { .name = "server.kdn", .flags = OPT_STRING },
    { .name = "server.domains", .flags = OPT_STRING },
    { .name = "server.kpg_address", .flags = OPT_STRING },
    { .name = "server.kas_address", .flags = OPT_STRING },
    { .name = "server.port", .def = "443", .flags = OPT_IP_PORT | OPT_DEFAULT },
    { .name = "server.kpg_port", .def = "443", .flags = OPT_IP_PORT | OPT_DEFAULT },
    { .name = "server.kas_port", .def = "443", .flags = OPT_IP_PORT | OPT_DEFAULT },
    { .name = "server.log_verbosity", .def = "9", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "server.backlog", .def = "100", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "server.client_prefork", .def = "1", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "server.client_max", .def = "80", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "server.client_wait", .def = "100", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "server.hang_check", .def = "30", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "server.term_strikes", .def = "3", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "server.kill_strikes", .def = "4", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "server.detach", .def = "1", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "server.fork", .def = "1", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "server.allow_html", .def = "1", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "server.always_decrypt", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "server.login_ticket_is_pwd", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "server.daily_updates", .def = "1", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "server.no_mail_scan_user", .flags = OPT_STRING | OPT_MAYBE_MISSING }, 

    /* Client options. */
    { .name = "client.retries", .def = "6", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "client.timeout", .def = "6000", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "client.random_drop_min", .def = "1", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "client.random_drop_max", .def = "5", .flags = OPT_UINT32 | OPT_DEFAULT },

    /* Database options. */
    { .name = "db.name", .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "db.username", .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "db.password", .flags = OPT_STRING },
    { .name = "db.admin_username", .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "db.admin_password", .flags = OPT_STRING },
    { .name = "db.host", .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "db.port", .flags = OPT_IP_PORT | OPT_NON_EMPTY },
    { .name = "db.timeout", .flags = OPT_UINT32 | OPT_NON_EMPTY },

    { .name = "kctl.curr_creds", .def = "1", .flags = OPT_BOOL | OPT_DEFAULT },

#ifdef REQUEST_PACKAGE
    /* Filter options. */
    { .name = "filter_virus.socket_path", .def = "/var/run/clamav/clamd.ctl", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "filter_virus.socket_addr", .def = "127.0.0.1", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "filter_virus.answer_len", .def = "256", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "filter_virus.timeout", .def = "60000", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "filter_virus.enabled", .def = "1", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "filter_spam.reject_min", .def = "5", .flags = OPT_FLOAT | OPT_DEFAULT },
    { .name = "filter_spam.challenge_min", .def = "5", .flags = OPT_FLOAT | OPT_DEFAULT },
    { .name = "filter_spam.timeout", .def = "60000", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "filter_spam.enabled", .def = "1", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "filter_from.enabled", .def = "1", .flags = OPT_BOOL | OPT_DEFAULT },
#endif // REQUEST_PACKAGE

#ifdef REQUEST_GETSIG
    /* Keysigning stuff. */
    { .name = "keysign.private", .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "keysign.public", .flags = OPT_STRING | OPT_NON_EMPTY },
#endif // REQUEST_GETSIG

    /* LDAP */
    { .name = "ldap.enabled", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "ldap.domain", .flags = OPT_STRING },
    { .name = "ldap.domain_search", .def = "1", OPT_BOOL | OPT_DEFAULT },
    { .name = "ldap.host",  .flags = OPT_STRING },
    { .name = "ldap.timeout", .def = "0.5", .flags = OPT_FLOAT | OPT_DEFAULT },
    { .name = "ldap.debug", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "ldap.dn_base", .flags = OPT_STRING },
    { .name = "ldap.sys_dn", .flags = OPT_STRING },
    { .name = "ldap.sys_username", .flags = OPT_STRING },
    { .name = "ldap.sys_password", .flags = OPT_STRING },
    { .name = "ldap.use_sasl", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "ldap.use_tls", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "ldap.strict_address", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "ldap.ad_site", .flags = OPT_STRING },

    /* Logging options */
    { .name = "log_emergency.driver", .def = "syslog", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "log_emergency.filter", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "log_alert.driver", .def = "syslog", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "log_alert.filter", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "log_critical.driver", .def = "syslog", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "log_critical.filter", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "log_error.driver", .def = "syslog", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "log_error.filter", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "log_warning.driver", .def = "syslog", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "log_warning.filter", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "log_notice.driver", .def = "syslog", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "log_notice.filter", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "log_info.driver", .def = "syslog", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "log_info.filter", .def = "0", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "log_debug.driver", .def = "syslog", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "log_debug.filter", .def = "1", .flags = OPT_BOOL | OPT_DEFAULT },
    { .name = "log_channel.enabled", .def = "log server client db ldap filter", .flags = OPT_STRING | OPT_DEFAULT  },

#ifdef REQUEST_OTUT
    /* OTUT options. */
    { .name = "otut.attempts", .def = "3", .flags = OPT_UINT32 | OPT_DEFAULT },
#endif // REQUEST_OTUT

#ifdef REQUEST_GUEST_DECRYPT
    /* PoD options. */
    { .name = "pod.from_name",  .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "pod.from_addr", .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "pod.locale_fr", .def = "fr_CA.UTF-8", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "pod.locale_en", .def = "en_CA.UTF-8", .flags = OPT_STRING | OPT_DEFAULT },
    { .name = "pod.timeout", .def = "1000", .flags = OPT_UINT32 | OPT_DEFAULT },
    { .name = "pod.formatmail_path", .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "pod.key_id", .flags = OPT_UINT64 | OPT_NON_EMPTY },
#endif // REQUEST_GUEST_DECRYPT

    /* SSL options. */
    { .name = "ssl.keys", .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "ssl.certs", .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "ssl.authentication_mode", .flags = OPT_STRING | OPT_NON_EMPTY },
    { .name = "ssl.fallback_cert", .def = "1", .flags = OPT_UINT32 | OPT_NON_EMPTY }
};

int opts_tbl_cnt = sizeof(opts_tbl) / sizeof(struct options);

#endif // _OPTIONS_TABLE_H
