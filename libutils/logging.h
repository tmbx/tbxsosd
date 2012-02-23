/**
 * tbxsosd/libutils/logging.h
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
 * Reviewed by Laurent Birtz on 22 january 2007.
 */

#ifndef _KLIB_LOGGING_H
#define _KLIB_LOGGING_H

#include <apr_hash.h>
#include <syslog.h>

#define MAX_STRERROR_SIZE 1024

#define LOG_OBJECT _logger_instance

struct log_driver {
    void (* p_log)(int, const char *, const char *);

    const char *driver_name;

    /** Used to allocate memory for the driver.  The pool is
     *  allocated on call by log_add_driver.  
     *
     * This should be NULL in all case.
     */
    apr_pool_t *pool;    
} log_driver;

/** Structure representing the options of a logging level. */
struct log_level_info {

    /** Log driver for that particular item. */
    struct log_driver *log_driver;
    
    /** Boolean determining if this level is filtered. */
    int is_filtered;
};

struct __logger {
    apr_pool_t *pool;

    /* Global verbosity level. */
    int global_level;

    /* List of all enabled channels. */
    apr_hash_t *enabled_channels;

    /* Hash of custom drivers. */
    apr_hash_t *custom_drivers;

    /* Syslog identifier. */
    const char *log_id;

    /* Logging level configuration. */
    struct log_level_info level_array[8];
};

typedef struct __logger logger;

extern logger *_logger_instance;

#define DEBUG(__ID__, ...)       \
    log_write_line(LOG_DEBUG, __ID__, __FILE__, __LINE__, __VA_ARGS__)

#define ERROR(__ID__, ...)       \
    log_write_line(LOG_ERR, __ID__, __FILE__, __LINE__, __VA_ARGS__)
#define INFO(__ID__, ...)        \
    log_write_line(LOG_INFO, __ID__, __FILE__, __LINE__, __VA_ARGS__)
#define WARN(__ID__, ...)        \
    log_write_line(LOG_WARNING, __ID__, __FILE__, __LINE__, __VA_ARGS__)
#define CRITICAL(__ID__, ...)    \
    log_write_line(LOG_CRIT, __ID__, __FILE__, __LINE__, __VA_ARGS__)

/** Opens logging drivers and setup default parameters. */ 
int log_open(apr_pool_t *pool);

/** */
void log_enable_channel(const char *log_channel);

/** */
void log_disable_channel(const char *log_channel);

/** */
void log_set_level(int log_level, const char *log_driver, int is_filtered);

/** */
void log_set_all_level(const char *log_driver, int is_filtered);

void log_set_verbosity(int global_level);

struct log_driver *log_get_driver(const char *log_driver_name);

void log_write_line(int, const char *, const char *, const int, const char *, ...);

void log_write(int, const char *, const char *, ...);

#define STDERR_LOG_DRIVER &log_driver_stderr
#define SYSLOG_LOG_DRIVER &log_driver_syslog

extern struct log_driver log_driver_syslog;
extern struct log_driver log_driver_stderr;

#endif // _KLIB_LOGGING_H
