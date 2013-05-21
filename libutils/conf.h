/**
 * tbxsosd/libutils/conf.h
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
 * Simple configuration file object.
 *
 * @author François-Denis Gonthier
 * Reviewed by Laurent Birtz on 22 january 2007.
 */

#ifndef _KLIB_CONFIG_H
#define _KLIB_CONFIG_H

#include <apr_hash.h>
#include <apr_pools.h>
#include <stdlib.h>
#include <stdio.h>

struct __config {
    /* Name of the configuration file. */
    char *config_file;

    /* Hash of hash including configuration file sections then
       configuration file values. */
    apr_hash_t *sections;

    /* Pool with which configuration file values and keys are
       allocated. */
    apr_pool_t *config_pool;
};

typedef struct __config config;

/** Opens a configuration file. */
config *config_open(apr_pool_t *pool, const char *);

/** Reopens a configuration file. */
int config_reopen(config *self, apr_pool_t *pool);

/** Returns a configuration value as a string. */
int config_get_str(config *self, const char *name, char *out, size_t out_s);

/** Returns a configuration value as a 32 bit unsigned integer. */
int config_get_uint32(config *self, const char *name, uint32_t *out);

/** Returns a configuration value as a 64 bit unsigned integer. */
int config_get_uint64(config *self, const char *name, uint64_t *out);

/** Returns a configuration value as a floating point value. */
int config_get_float(config *self, const char *name, float *out);

/** Sets a configuration string. */
int config_set_str(config *self, const char *name, const char *val);

/** Checks for the presence of a configuration item. */
int config_has_value(config *self, const char *fullname);

#endif // _KLIB_CONFIG_H
