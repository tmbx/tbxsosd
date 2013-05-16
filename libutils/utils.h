/**
 * tbxsosd/libutils/utils.h
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
