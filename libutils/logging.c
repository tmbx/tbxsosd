/**
 * tbxsosd/libutils/logging.c
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
 * @author François-Denis Gonthier
 */

#include <apr_strings.h>
#include <sys/types.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <kmem.h>
#include <unistd.h>

#if 0
#include "shared.h"
#endif
#include "utils.h"
#include "logging.h"

logger *_logger_instance = NULL;
#define self _logger_instance

char * log_level_str_array[] = { 
    "EMERGENCY",    /* 0 */
    "ALERT",        /* 1 */
    "CRITICAL",     /* 2 */ 
    "ERROR",        /* 3 */
    "WARNING",      /* 4 */
    "NOTICE",       /* 5 */
    "INFO",         /* 6 */
    "DEBUG"         /* 7 */
};

#define MSG_BUFFER_SIZE 4096

/** Null logging driver. */
static void null_log(__attribute__ ((unused)) int log_level, 
                     __attribute__ ((unused)) const char *log_id, 
                     __attribute__ ((unused)) const char *msg) {
}

struct log_driver log_driver_null = {
    null_log,
    "null",
    NULL
};

/** Syslog logging driver. */
static void syslog_log(int log_level, const char *log_id, const char *msg) {    
#if 0
    uint64_t s = kdsh_get_session_counter();
    if (s != 0)
        syslog(log_level, "[S: %llu] %s -- %s", s, log_id, msg);
    else
#endif
        syslog(log_level, "%s -- %s", log_id, msg);
}

/** Opens syslog driver. */
static int syslog_open(const char * ident) {
    openlog(ident, LOG_CONS | LOG_PERROR, LOG_DAEMON);
    return 0;
}

/** Closes syslog driver. */
static int syslog_close() {
    closelog();
    return 0;
}

struct log_driver log_driver_syslog = {
    syslog_log,
    "syslog",
    NULL
};

/** stderr log driver. */
static void stderr_log(int log_level, const char * log_id, const char * msg) {
    char * level_str = log_level_str_array[log_level];
#if 0
    uint64_t s = kdsh_get_session_counter();
    if (s != 0)
        fprintf(stderr, "[%s, S: %llu] %s -- %s\n", level_str, s, log_id, msg);    
    else
#endif
        fprintf(stderr, "[%s] %s -- %s\n", level_str, log_id, msg);
}

struct log_driver log_driver_stderr = {
    stderr_log,
    "stderr",
    NULL
};

/** Global verbosity switch. 
 *
 * The global verbosity switch forcibly deactivate all logging
 * statement written to a level above its value.
 */
void log_set_verbosity(int global_level) {
    self->global_level = global_level;
}

/** Enables a logging channel. 
 *
 * This will only take effect for messages that are sent at a level
 * that is filtered.  Non-filtered levels output all messages.
 */
void log_enable_channel(const char *log_channel) {
    uint32_t *n;
    apr_pool_t *parent_pool;
    apr_pool_t *pool;
    char *key = "";
    
    n = apr_hash_get(self->enabled_channels, log_channel, APR_HASH_KEY_STRING);
    if (n == NULL) {
        /* The string is allocated in a child pool of the hash pool.
           That means we can free the key if necessary but also that
           freeing the hash pool will destroy the key. */
        parent_pool = apr_hash_pool_get(self->enabled_channels);
        apr_pool_create(&pool, parent_pool);
        key = apr_pstrdup(pool, log_channel);

        apr_hash_set(self->enabled_channels, key, APR_HASH_KEY_STRING, pool);
    }
}

/** Disables a logging channel.
 *
 * This will only take effect for messages that are sent at a level
 * that is filtered.  Non-filtered levels output all messages.
 */
void log_disable_channel(const char *log_channel) {
    apr_pool_t *key_pool;

    key_pool = apr_hash_get(self->enabled_channels, log_channel, APR_HASH_KEY_STRING);
    if (key_pool != NULL) {
        /* Erase the entry of the table. */
        apr_hash_set(self->enabled_channels,
                     log_channel,
                     APR_HASH_KEY_STRING,
                     NULL);
        /* Free the memory allocated for the key. */
        apr_pool_destroy(key_pool);
    }
}

/** Set properties of a specific logging level. */
void log_set_level(int log_level, const char *log_driver, int is_filtered) {
    struct log_driver *driver;

    driver = log_get_driver(log_driver);

    self->level_array[log_level].log_driver = driver;
    self->level_array[log_level].is_filtered = is_filtered;
}

/** Set properties of all logging levels. */
void log_set_all_level(const char *log_driver, int is_filtered) {
    int i = 0;

    for (i = 0; i < 8; i++) 
        log_set_level(i, log_driver, is_filtered);
}

/** Adds a custom logging driver. 
 *
 * This function will overwrite any other driver stored under the
 * same name.
 */
void log_add_driver(const char *log_driver_name, struct log_driver *driver) {
    apr_pool_t *parent_pool;
    apr_pool_t *pool;
    const char *key;

    /* If nothing was allocated in that spot, allocate some memory of
       the key in the pool of the hash. */
    if (apr_hash_get(self->custom_drivers, log_driver_name, APR_HASH_KEY_STRING) == NULL) {
        parent_pool = apr_hash_pool_get(self->custom_drivers);
        apr_pool_create(&pool, parent_pool);
        key = apr_pstrdup(pool, log_driver_name);
        driver->pool = pool;
    } 
    /* Otherwise the key already stored will be reused. */
    else key = log_driver_name;

    apr_hash_set(self->custom_drivers, key, APR_HASH_KEY_STRING, driver);
}

/** Removes a custom logging driver. */
void log_remove_driver(const char *log_driver_name) {
    struct log_driver *driver;

    driver = apr_hash_get(self->custom_drivers, log_driver_name, APR_HASH_KEY_STRING);
    if (driver != NULL) {
        /* Delete the association between the key and the driver
           structure from the hash. */
        apr_hash_set(self->custom_drivers, log_driver_name, APR_HASH_KEY_STRING, NULL);
        /* Delete the driver pool. */
        apr_pool_destroy(driver->pool);
    }
}

struct log_driver *log_get_driver(const char *log_driver_name) {    
    struct log_driver *driver;

    /* Search the default drivers. */
    if (strcmp(log_driver_name, "null") == 0) 
        return &log_driver_null;
    else if (strcmp(log_driver_name, "stderr") == 0)
        return &log_driver_stderr;
    else if (strcmp(log_driver_name, "syslog") == 0)
        return &log_driver_syslog;

    /* Search the custom drivers. */
    driver = apr_hash_get(self->custom_drivers, log_driver_name, APR_HASH_KEY_STRING);
    if (driver != NULL)
        return driver;

    log_write(LOG_WARNING, "log", "%s log driver unknown.  Will use null driver.", 
              log_driver_name);

    return &log_driver_null;
}

/** Closes logging system. */
static apr_status_t log_close(void *data) {
    data = data;
    syslog_close();
    return APR_SUCCESS;
}

/** Initializes logging. 
 *
 * Trying to use any log function after this functions fails (-1)
 * will result in an assertion error later on.  So be ready to catch
 * this result if you want your program to work.
 */
int log_open(apr_pool_t *pool) {
    apr_pool_t *log_pool;

    assert(self == NULL);

    apr_pool_create(&log_pool, pool);
    apr_pool_tag(log_pool, "logging");
    self = apr_pcalloc(log_pool, sizeof(logger));

    /* Register a cleanup function. */
    apr_pool_cleanup_register(log_pool, NULL, log_close, log_close);

    /* Open the syslog driver as it is the only one of the default
       drivers that needs to be explicitely initialized. */
    self->log_id = get_self_name(log_pool);
    if (self->log_id != NULL) 
        syslog_open(self->log_id);
    else
        /* That means we could not find our process name for some
           reason. */
        syslog_open("klib-logging");

    /* By default everything will be output on the standard error
       stream. */
    log_set_all_level("stderr", 0);

    self->pool = log_pool;
    self->global_level = 9;
    self->enabled_channels = apr_hash_make(pool);
    self->custom_drivers = apr_hash_make(pool);

    return 0;
}

/** Logs an item adding additional file:line information. */
void log_write_line(int level,
                    const char * log_channel,
#ifndef KD_DEBUG
                    __attribute__ ((unused))
#endif // KD_DEBUG
                    const char * file, 
#ifndef KD_DEBUG
                    __attribute__ ((unused))
#endif // KD_DEBUG
                    const int line,
                    const char * fmt,
                    ...) {
    int *n;
    struct log_driver *target_driver;
    char log_buffer[MSG_BUFFER_SIZE];
    char final_buffer[MSG_BUFFER_SIZE];
#ifdef KD_DEBUG
    char dbg_msg[] = "[%s:%d] %s";
#else
    char dbg_msg[] = "%s";
#endif // KD_DEBUG
    va_list vl;

    assert(self != NULL);
    assert(level <= LOG_DEBUG && level >= LOG_CRIT);

    /* Check the global verbosity switch. */
    if (level > self->global_level) return;
    
    target_driver = self->level_array[level].log_driver;

    /* If the level is set to be filtered, check if the channel specified
       is enabled. */
    if (self->level_array[level].is_filtered) {

        /* If the channel is not in the list of filtered channels,
           then return without displaying anything. */
        n = apr_hash_get(self->enabled_channels, log_channel, APR_HASH_KEY_STRING);
        if (n == NULL) return;
    }
        
    va_start(vl, fmt);
    vsnprintf(log_buffer, sizeof(log_buffer), fmt, vl);
#ifdef KD_DEBUG
    snprintf(final_buffer, sizeof(final_buffer), dbg_msg, file, line, log_buffer);
#else
    snprintf(final_buffer, sizeof(final_buffer), dbg_msg, log_buffer);
#endif // KD_DEBUG
    (target_driver->p_log)(level, log_channel, final_buffer);
    va_end(vl);
}

/** Logs an item to the current log driver. */
void log_write(int level, const char * log_channel, const char * fmt, ...) {
    struct log_driver *target_driver;
    int *n;
    char log_buffer[MSG_BUFFER_SIZE];
    va_list vl;

    assert(self != NULL);
    assert(level <= LOG_DEBUG && level >= LOG_CRIT);

    /* Check the global verbosity switch. */
    if (level > self->global_level) return;
    
    target_driver = self->level_array[level].log_driver;

    /* If the level is set to be filtered, check if channel specified
       is enabled. */
    if (self->level_array[level].is_filtered) {

        /* If the channel is not in the list of filtered channels,
           then return without displaying anything. */
        n = apr_hash_get(self->enabled_channels, log_channel, APR_HASH_KEY_STRING);
        if (n == NULL) return;
    }

    va_start(vl, fmt);
    vsnprintf(log_buffer, sizeof(log_buffer), fmt, vl);
    (target_driver->p_log)(level, log_channel, log_buffer);
    va_end(vl);
}
