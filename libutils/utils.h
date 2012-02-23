/**
 * tbxsosd/libutils/utils.h
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
 * Homeless functions shelter.
 *
 * @author François-Denis Gonthier
 */

#ifndef _UTILS_H
#define _UTILS_H

#include <kstr.h>
#include <ctype.h>

int set_gid_name(apr_pool_t *pool, const char *group);

int set_uid_name(apr_pool_t *pool, const char *user);

char *get_self_name(apr_pool_t *pool);

int blockify_get_size(const size_t line_len, const size_t sig_s);

void blockify_base64(const size_t line_len,
                     const char *b64, size_t b64_s, char *new_b64, size_t new_b64_s);

int utf8_to_iso88591(apr_pool_t *pool, char *utf8, char **out);

static inline char *strlwr(char *str) {
    char *s = str;
    for (; *s != '\0'; s++) *s = tolower(*s);
    return str;
}

char *apr_perror(apr_pool_t *pool, apr_status_t err);

#define UUID_SIZE 36

char *uuid(apr_pool_t *pool);

int read_fd(int src_fd, int *ctrl_data);

int write_fd(int target_fd, int fd, int ctrl_data);

void format_current_error_for_user(kstr *dest);

#define KERROR_PUSH_APR(M, L, APR_ERR) _kd_push_apr_error(__FILE__, __LINE__, __func__, M, L, APR_ERR)

#define KERROR_SET_APR(M, L, APR_ERR) _kd_set_apr_error(__FILE__, __LINE__, __func__, M, L, APR_ERR)

void _kd_push_apr_error(const char *file, 
                        int line, 
                        const char *function, 
                        int module, 
                        int level, 
                        apr_status_t err);

void _kd_set_apr_error(const char *file,
                       int line,
                       const char *function,
                       int module, 
                       int level, 
                       apr_status_t err);

kstr *kdclient_format_error(const char *file, int line, const char *msg, va_list va);

#define kdclient_error(...) kdclient_error_internal(__FILE__, __LINE__, _log_client_, __VA_ARGS__)
#define kd_error(C, ...) kdclient_error_internal(__FILE__, __LINE__, C, __VA_ARGS__)

void kdclient_error_internal(const char *file, int line, 
                             const char *log_channel, const char *msg, ...);

#define kdclient_warn(...) kdclient_warn_internal(__FILE__, __LINE__, _log_client_, __VA_ARGS__)
#define kd_warn(C, ...) kdclient_warn_internal(__FILE__, __LINE__, __VA_ARGS__)

void kdclient_warn_internal(const char *file, int line, 
                            const char *log_channel, const char *msg, ...);

#endif // _UTILS_H
