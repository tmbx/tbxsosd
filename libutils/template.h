/**
 * tbxsosd/libutils/template.h
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
