/**
 * tbxsosd/libutils/options.h
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
