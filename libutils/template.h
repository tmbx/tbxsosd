/**
 * tbxsosd/libutils/template.h
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
 * Simple template manager using 'formatmail'
 *
 * @author François-Denis Gonthier
 */

#ifndef _TEMPLATE_H
#define _TEMPLATE_H

#include <apr_hash.h>
#include <apr_pools.h>
#include <kstr.h>

#include "process.h"

/** Template object. */
struct template {   
    /** Pool used for this object. */
    apr_pool_t *pool;

    /** Variables/Values mapping for the template. */
    apr_hash_t *vars;

    /** Template file. */
    const char *file;

    /** Path to the formatmail binary. */
    const char *formatmail;

    /** Timeout */
    uint32_t timeout;
};

/** Create a new template tunnel. */
struct template *template_new(apr_pool_t *pool, 
                              const char *tmpl_file, 
                              const char *formatmail_path,
                              uint32_t timeout);

/** Call formatmail using the variables in the object. */
int template_format(struct template *tmpl, kbuffer *out, kbuffer *err);

/** Set a string template variable. */
void template_set_str(struct template *tmpl, const char *key, const char *val);

/** Set a integer template variable. */
void template_set_uint32(struct template *tmpl, const char *key, uint32_t v);

/** set a long integer template variable. */
void template_set_uint64(struct template *tmpl, const char *key, uint64_t v);

#endif // _TEMPLATE_H
