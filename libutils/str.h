/**
 * tbxsosd/libutils/str.h
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
