/**
 * tbxsosd/libutils/str.h
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
 * Misc. string functions.
 *
 * @author François-Denis Gonthier
 */

#ifndef STR_H
#define STR_H

#include <string.h>

/** Return the size of the memory required for string_as_hex. */
static inline size_t string_size_as_hex(size_t n) { 
    return (n * 2) + 1; 
}

void string_as_hex(const char *str, size_t n, char *out);

int string_is_binary(const char *str, size_t n);

int str_merge_whitespace(kstr *in, kstr *out);

int str_newline2space(kstr *in, kstr *out);

void str_trim_whitespace(kstr *in, kstr *out);

#endif // STR_H
