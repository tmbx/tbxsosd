/**
 * tbxsosd/libutils/options.c
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

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <kerror.h>
#include <kmem.h>

#include "logging.h"
#include "logid.h"
#include "conf.h"
#include "options.h"

static int opts_ignore_empty;
static struct options *opts_table;
static size_t opts_table_sz;

static int zero_int = 0;
static float zero_float = 0.0f;
static const char zero_string[] = "";

static apr_hash_t *options_hash = NULL;

void (*options_critical_error_handler)();

void options_set_critical_error_handler(void (*critical_error_handler)()) {
    options_critical_error_handler = critical_error_handler;
}

static void options_assert_exists(const char *key, void *v) {
    if (!v) {
        CRITICAL(_log_misc_, "Unknown option %s.", key);
        options_critical_error_handler();
    }
}

static const char *options_type_to_str(int flag) {
    if (flag & OPT_UINT32)
        return "uint32";
    else if (flag & OPT_UINT64)
        return "uint64";
    else if (flag & OPT_STRING)
        return "string";
    else if (flag & OPT_BOOL)
        return "boolean";
    else if (flag & OPT_FLOAT)
        return "floating point";
    else if (flag & OPT_IP_PORT)
        return "TCP number";
    else
        return "unknown";
}

static void options_assert_type(const char *key, int flag, int type) {
    if (!(flag | type)) {
        CRITICAL(_log_misc_, "Option %s type is %s, but used as type %s.", 
                 key, 
                 options_type_to_str(flag),
                 options_type_to_str(type));
        options_critical_error_handler();
    }
}

static void option_set_value(int i, int keep, void *val) {
    void *v;

    v = opts_table[i].value.v;
    if (v != &zero_string && v != &zero_float && v != &zero_int)
        kfree(v);

    opts_table[i].value.v = val;
    opts_table[i].value.keep = keep;
}

static int options_init_read_uint64(config *cfg, int i) {
    int n;
    uint64_t opt_val;

    if (opts_table[i].value.keep) return 0;

    n = config_get_uint64(cfg, opts_table[i].name, &opt_val);
    if (n < 0 && !(opts_table[i].flags & OPT_MAYBE_MISSING)) {
        KERROR_PUSH(_misc_, 1, "error reading long integer option %s", opts_table[i].name);
        return -1;
    }
    /* Check if the option is allowed to be missing. */
    else if (n < 0 && (opts_table[i].flags & OPT_MAYBE_MISSING))
        n = 0;

    /* Convert to integer. */
    if (n > 0) {
        uint64_t *val = kmalloc(sizeof(uint64_t));
        *val = opt_val;
        option_set_value(i, 0, val);
        return 0;
    }
    else {
        /* Check if we have a default to set. */
        if (opts_table[i].flags & OPT_DEFAULT) {
            const char *def, *nam;
            int *val = kmalloc(sizeof(uint64_t));

            def = opts_table[i].def;
            nam = opts_table[i].name;

            WARN(_log_misc_, "using default value %s for option %s", def, nam);
            
            *val = atoi(def);
            option_set_value(i, 0, val);
            return 0;
        }
        /* Check if the value shouldn't stay empty. */
        else if (opts_table[i].flags & OPT_NON_EMPTY && !opts_ignore_empty) {
            KERROR_SET(_misc_, 1, "option %s should have a non-empty value", opts_table[i].name);
            return -1;
        }
        /* Otherwise, set to 0. */
        else {
            option_set_value(i, 0, &zero_int);
            return 0;
        }
    }
}

static int options_init_read_uint32(config *cfg, int i) {
    int n;
    uint32_t opt_val;

    if (opts_table[i].value.keep) return 0;

    n = config_get_uint32(cfg, opts_table[i].name, &opt_val);
    if (n < 0 && !(opts_table[i].flags & OPT_MAYBE_MISSING)) {
        KERROR_PUSH(_misc_, 1, "error reading integer option %s", opts_table[i].name);
        return -1;
    } 
    /* Check if the option is allowed to be missing. */
    else if (n < 0 && (opts_table[i].flags & OPT_MAYBE_MISSING)) 
        n = 0;

    /* Convert to integer. */
    if (n > 0) {
        uint32_t *val = kmalloc(sizeof(uint32_t));
        *val = opt_val;
        option_set_value(i, 0, val);
        return 0;
    }
    /* The value is empty. */
    else {
        /* Check if we have a default to set. */
        if (opts_table[i].flags & OPT_DEFAULT) {
            const char *def, *nam;
            int *val = kmalloc(sizeof(uint32_t));

            def = opts_table[i].def;
            nam = opts_table[i].name;

            WARN(_log_misc_, "using default value %s for option %s", def, nam);
            
            *val = atoi(def);
            option_set_value(i, 0, val);
            return 0;
        }
        /* Check if the value shouldn't stay empty. */
        else if (opts_table[i].flags & OPT_NON_EMPTY && !opts_ignore_empty) {
            KERROR_SET(_misc_, 1, "option %s should have a non-empty value", opts_table[i].name);
            return -1;
        }
        /* Otherwise, set to 0. */
        else {
            option_set_value(i, 0, &zero_int);
            return 0;
        }
    }
}

static int options_init_read_float(config *cfg, int i) {
    float opt_val;
    int n;

    if (opts_table[i].value.keep) return 0;

    n = config_get_float(cfg, opts_table[i].name, &opt_val);
    /* Read error. */
    if (n < 0 && !(opts_table[i].flags & OPT_MAYBE_MISSING)) {
        KERROR_PUSH(_misc_, 1, "error reading string option %s", opts_table[i].name);
        return -1;
    }
    /* Check if the option is allowed to be missing. */
    else if (n < 0 && (opts_table[i].flags & OPT_MAYBE_MISSING))
        n = 0;

    if (n > 0) {
        float *val = kmalloc(sizeof(float));
        *val = opt_val;
        option_set_value(i, 0, val);
        return 0;
    }
    /* The value is empty. */
    else {
        /* Check if we have a default to set. */
        if (opts_table[i].flags & OPT_DEFAULT) {
            const char *def, *nam;
            float *val = kmalloc(sizeof(float));

            def = opts_table[i].def;
            nam = opts_table[i].name;

            WARN(_log_misc_, "using default value %s for option %s", def, nam);

            *val = atof(opts_table[i].def);
            option_set_value(i, 0, val);
            return 0;
        }
        /* Check if the value shouldn't stay empty. */
        else if (opts_table[i].flags & OPT_NON_EMPTY && !opts_ignore_empty) {
            KERROR_SET(_misc_, 1, "option %s should have a non-empty value", opts_table[i].name);
            return -1;
        }
        /* Otherwize, set to 0. */
        else {
            option_set_value(i, 0, &zero_float);
            return 0;
        }
    }
}

static int options_init_read_str(config *cfg, int i) {
    char opt_val[4096];
    int n;

    if (opts_table[i].value.keep) return 0;

    n = config_get_str(cfg, opts_table[i].name, opt_val, sizeof(opt_val));
    /* Read error. */
    if (n < 0 && !(opts_table[i].flags & OPT_MAYBE_MISSING)) {
        KERROR_PUSH(_misc_, 1, "error reading string option %s", opts_table[i].name);
        return -1;
    }
    /* Check if the option is allowed to be missing. */
    else if (n < 0 && (opts_table[i].flags & OPT_MAYBE_MISSING)) 
        n = 0;
            
    /* strlen(opt_val) != 0 */
    if (n > 0 && opt_val[0] != 0) {
        char *val = strdup(opt_val);
        option_set_value(i, 0, val);
        return 0;
    }
    /* The value is empty. */
    else {
        /* Check if we have a default to set. */
        if (opts_table[i].flags & OPT_DEFAULT) {
            const char *nam, *def;
            char *val;
            
            def = opts_table[i].def;
            nam = opts_table[i].name;

            WARN(_log_misc_, "using default value %s for option %s", def, nam);

            val = strdup(opts_table[i].def);
            option_set_value(i, 0, val);
            return 0;
        } 
        /* Check if the value shouldn't stay empty. */
        else if (opts_table[i].flags & OPT_NON_EMPTY && !opts_ignore_empty) {
            KERROR_SET(_misc_, 1, "option %s should have a non-empty value", opts_table[i].name);

            return -1;
        }
        /* Otherwise, set empty. */
        else {
            option_set_value(i, 0, &zero_string);
            return 0;
        }
    }
}

static int options_init_read_bool(config *cfg, int i) {
    const char *n = opts_table[i].name;
    int val;

    if (opts_table[i].value.keep) return 0;

    if (options_init_read_uint32(cfg, i) < 0) 
        return -1;
   
    val = *(uint32_t *)opts_table[i].value.v;
    if (val != 0 && val != 1) {
        KERROR_SET(_misc_, 1, "invalid value for boolean options %s: %d", n, val);    
        return -1;
    }

    return 0;
}

static int options_init_read_uint16(config *cfg, int i) {
    const char *n = opts_table[i].name;
    int val;

    if (opts_table[i].value.keep) return 0;

    if (options_init_read_uint32(cfg, i) < 0)
        return -1;
    
    val = *(uint32_t *)opts_table[i].value.v;
    if (val < 0 || val > 0xFFFF) {
        KERROR_SET(_misc_, 1, "invalid value for IP port option %s: %d", n, val);
        return -1;
    } 

    return 0;
}

static void options_cleanup(int full_cleanup) {
    size_t i, sz;

    sz = sizeof(opts_table) / sizeof(struct options);

    for (i = 0; i < sz; i++) {
        if (full_cleanup || !opts_table[i].value.keep) {
            void *v = opts_table[i].value.v;
            if (v != &zero_string && v != &zero_float && v != &zero_int) {
                kfree((void *)opts_table[i].value.v);
                opts_table[i].value.v = NULL;
            }
        }
    }
}

static apr_status_t options_destroy(void *data) {
    data = data;
    options_cleanup(1);
    return APR_SUCCESS;
}

/* Partial cleanup and load. */
int options_reload(apr_pool_t *pool, const char *opts_file) {
    options_cleanup(0);
    return options_load(pool, opts_table, opts_table_sz, opts_file, 
                        options_critical_error_handler, opts_ignore_empty);
}

int options_load(apr_pool_t *pool, 
                 struct options *opts_tbl, 
                 size_t opts_tbl_sz, 
                 const char *opts_file,
                 void (*critical_error_handler)(),
                 int ignore_empty) {
    size_t i;
    int err = -1;
    apr_pool_t *cfg_pool;
    config *cfg;

    opts_table = opts_tbl;
    opts_table_sz = opts_tbl_sz;
    opts_ignore_empty = ignore_empty;
    options_critical_error_handler = critical_error_handler;

    apr_pool_create(&cfg_pool, pool);

    apr_pool_cleanup_register(pool, NULL, options_destroy, options_destroy);

    cfg = config_open(cfg_pool, opts_file);
    if (cfg == NULL) {
        KERROR_PUSH(_misc_, 1, "failed to open configuration file %s", opts_file);
        apr_pool_destroy(cfg_pool);
        return -1;
    }

    for (i = 0; i < opts_table_sz; i++) {
        if (opts_table[i].flags & OPT_STRING) {
            if (options_init_read_str(cfg, i) < 0)
                break;
        }
        else if (opts_table[i].flags & OPT_UINT32) {
            if (options_init_read_uint32(cfg, i) < 0)
                break;
        }        
        else if (opts_table[i].flags & OPT_UINT64) {
            if (options_init_read_uint64(cfg, i) < 0)
                break;
        }
        else if (opts_table[i].flags & OPT_IP_PORT) {
            if (options_init_read_uint16(cfg, i) < 0)
                break;
        }
        else if (opts_table[i].flags & OPT_BOOL) {
            if (options_init_read_bool(cfg, i) < 0)
                break;
        }
        else if (opts_table[i].flags & OPT_FLOAT) {
            if (options_init_read_float(cfg, i) < 0)
                break;
        }

        if (options_hash == NULL)
            options_hash = apr_hash_make(pool);
        
        int *hash_val = apr_palloc(pool, sizeof(int));
        *hash_val = i;
        apr_hash_set(options_hash, opts_table[i].name, APR_HASH_KEY_STRING, hash_val);
    }

    if (i >= opts_table_sz) err = 0;

    apr_pool_destroy(cfg_pool);
    
    return err;
}

/** Returns TRUE if a particular option has been defined. */
int options_exists(const char *key) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    return (v != NULL);    
}

int options_get_flags(const char *key) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    int idx;

    options_assert_exists(key, v);
    idx = *(int *)v;

    return opts_table[idx].flags;
}

float options_get_float(const char *key) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    int idx;
    
    options_assert_exists(key, v);
    idx = *(int *)v;
    options_assert_type(key, opts_table[idx].flags, OPT_FLOAT);

    return *(float *)opts_table[idx].value.v;
}

uint64_t options_get_uint64(const char *key) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    int idx;

    options_assert_exists(key, v);
    idx = *(int *)v;
    options_assert_type(key, opts_table[idx].flags, OPT_UINT64);

    return *(uint64_t *)opts_table[idx].value.v;
}

uint32_t options_get_uint32(const char *key) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    int idx;

    options_assert_exists(key, v);
    idx = *(int *)v;
    options_assert_type(key, opts_table[idx].flags, OPT_UINT32);
    
    return *(uint32_t *)opts_table[idx].value.v;
}

uint16_t options_get_uint16(const char *key) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    int idx;

    options_assert_exists(key, v);
    idx = *(int *)v;
    options_assert_type(key, opts_table[idx].flags, OPT_IP_PORT);
    
    return (uint16_t)*((uint32_t *)opts_table[idx].value.v);
}

int options_get_bool(const char *key) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    int idx;

    options_assert_exists(key, v);
    idx = *(int *)v;
    options_assert_type(key, opts_table[idx].flags, OPT_BOOL);

    return *(int *)opts_table[idx].value.v;
}

const char *options_get_str(const char *key) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    int idx;

    options_assert_exists(key, v);
    idx = *(int *)v;
    options_assert_type(key, opts_table[idx].flags, OPT_STRING);
    
    return (const char *)opts_table[idx].value.v;
}

void options_set_uint16(const char *key, uint16_t port) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    uint32_t *newval;
    int idx;
    
    options_assert_exists(key, v);
    idx = *(int *)v;
    options_assert_type(key, opts_table[idx].flags, OPT_STRING);

    newval = kmalloc(sizeof(uint32_t));
    *newval = (uint32_t)port;
    option_set_value(idx, 1, newval);
}

void options_set_uint32(const char *key, uint32_t val) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    uint32_t *newval;
    int idx;

    options_assert_exists(key, v);
    idx = *(int *)v;
    options_assert_type(key, opts_table[idx].flags, OPT_UINT32);

    newval = kmalloc(sizeof(uint32_t));
    *newval = val;
    option_set_value(idx, 1, newval);
}

void options_set_bool(const char *key, int val) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    uint32_t *newval;
    int idx;

    options_assert_exists(key, v);
    idx = *(int *)v;
    options_assert_type(key, opts_table[idx].flags, OPT_BOOL);
    
    newval = kmalloc(sizeof(uint32_t));
    *newval = val;
    option_set_value(idx, 1, newval);
}

void options_set_str(const char *key, const char *str) {
    void *v = apr_hash_get(options_hash, key, APR_HASH_KEY_STRING);
    char *newval;
    int idx;

    options_assert_exists(key, v);
    idx = *(int *)v;
    options_assert_type(key, opts_table[idx].flags, OPT_STRING);
        
    newval = strdup(str);
    option_set_value(idx, 1, newval);
}
