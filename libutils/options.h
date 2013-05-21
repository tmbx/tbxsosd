/**
 * tbxsosd/libutils/options.h
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
 * High-level configuration manager
 * @author François-Denis Gonthier
 */

#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <apr_pools.h>

/* Option is a string. */
#define OPT_STRING        (1 << 0)

/* Option is a 32 bit unsigned integer. */
#define OPT_UINT32        (1 << 1)

/* Option is a 64 bit unsigned integer. */
#define OPT_UINT64        (1 << 2)

/* Option is a boolean (0 or 1) */
#define OPT_BOOL          (1 << 3)

/* Option is a floating point value. */
#define OPT_FLOAT         (1 << 4)

/* Option cannot be empty. */
#define OPT_NON_EMPTY     (1 << 5)

/* Option has a default value. */
#define OPT_DEFAULT       (1 << 6)

/* Option has a check function. */
#define OPT_CHECK         (1 << 7)

/* Option is an IP port (int between 0 and 0xFFFF). */
#define OPT_IP_PORT       (1 << 8)

/* Don't throw an error if that option is missing, consider it to be
   empty. */
#define OPT_MAYBE_MISSING (1 << 9)

struct option_value {
    void *v;

    int keep;
};

struct options {
    const char *name;

    const char *def;

    int flags;

    struct option_value value;
};

int options_load(apr_pool_t *pool, 
                 struct options *opts_tbl, 
                 size_t opts_sz, 
                 const char *opts_file,
                 void (*critical_error_func)(),
                 int ignore_empty);

int options_reload(apr_pool_t *pool, const char *opts_file);

int options_exists(const char *key);

int options_get_flags(const char *key);

uint32_t options_get_uint32(const char *key);

uint64_t options_get_uint64(const char *key);

void options_set_uint32(const char *key, uint32_t val);

uint16_t options_get_uint16(const char *key);

void options_set_uint16(const char *key, uint16_t val);

float options_get_float(const char *key);

void options_set_float(const char *key, float val);

int options_get_bool(const char *key);

void options_set_bool(const char *key, int val);

const char *options_get_str(const char *key);

void options_set_str(const char *key, const char *str);

void options_set_critical_error_handler(void (*critical_error_handler)());

#endif // _OPTIONS_H
