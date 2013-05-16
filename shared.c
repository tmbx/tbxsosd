/**
 * tbxsosd/shared.c
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
 * Shared data object.
 *
 * @author François-Denis Gonthier
 */

#include <sys/types.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_proc_mutex.h>
#include <apr_strings.h>
#include <unistd.h>
#include <assert.h>
#include <kerror.h>

#include "config.h"
#include "options.h"
#include "tagcrypt.h"
#include "logid.h"
#include "logging.h"
#include "shared.h"
#include "main.h"
#include "utils.h"

/** PiD of the process that initialized this object. */
static pid_t kdsh_pid = 0;

static int we_be_f0rked = 0;

static apr_pool_t *kdsh_pool = NULL;

static apr_file_t *kdsh_shared_file = NULL;

static apr_pool_t *mmap_pool = NULL;
static apr_mmap_t *kdsh_shared_mmap = NULL;

static apr_pool_t *mutex_pool = NULL;
static apr_proc_mutex_t *kdsh_mutex = NULL;

static void kdsh_get_tm_pkey_time(int n, struct kdsh_tm_pkey_time *tm_pkey_time) {
    struct shared_data *shdata;

    assert(n == 0 || n == 1);

    shdata = (struct shared_data *)kdsh_shared_mmap->mm;
    memcpy(tm_pkey_time, &shdata->key_info[n], sizeof(struct kdsh_tm_pkey_time));
}

void kdsh_get_timestamp(struct timeval *tm) {
    struct shared_data *shdata;

    shdata = (struct shared_data *)kdsh_shared_mmap->mm;
    memcpy(tm, &shdata->timestamp, sizeof(struct timeval));
}

void kdsh_get_old_tm_pkey_time(struct kdsh_tm_pkey_time *tm_pkey_time) {
    struct shared_data *shdata;
    int n;

    shdata = (struct shared_data *)kdsh_shared_mmap->mm;
    n = shdata->current_key;

    kdsh_get_tm_pkey_time(n, tm_pkey_time);
}

void kdsh_get_cur_tm_pkey_time(struct kdsh_tm_pkey_time *tm_pkey_time) {
    struct shared_data *shdata;
    int n;

    shdata = (struct shared_data *)kdsh_shared_mmap->mm;
    n = shdata->current_key;

    kdsh_get_tm_pkey_time(n, tm_pkey_time);
}

int kdsh_set_cur_tm_pkey_time(struct tagcrypt_signed_pkey *signed_pkey) {
    struct shared_data *shdata;
    int n;

    shdata = (struct shared_data *)kdsh_shared_mmap->mm;
    n = shdata->current_key;

    if (gettimeofday(&shdata->key_info[n].received_time, NULL) == -1) {
        KERROR_SET(_shared_, 0, "could not gettimeofday: %s", strerror(errno));
        return -1;
    }

    shdata->key_info[n].activation_time.tv_sec  = signed_pkey->time.tv_sec;
    shdata->key_info[n].activation_time.tv_usec = signed_pkey->time.tv_usec;
    shdata->key_info[n].status = 1;

    return 0;
}

void kdsh_switch_tm_pkey_time() {
    struct shared_data *shdata;

    shdata = (struct shared_data *)kdsh_shared_mmap->mm;
    shdata->current_key = !shdata->current_key;
    DEBUG(_log_shared_, "Current timestamp key: %d.", shdata->current_key);
}

int kdsh_get_cur_tm_pkey() {
    int n;
    struct shared_data *shdata;

    shdata = (struct shared_data *)kdsh_shared_mmap->mm;
    n = shdata->current_key;
    DEBUG(_log_shared_, "Current timestamp key: %d.", shdata->current_key);

    return n;
}

/** Return the master counter used to produce KSN. */
uint64_t kdsh_get_counter() {
    uint64_t n;
    struct shared_data *shdata;

    shdata = (struct shared_data *)kdsh_shared_mmap->mm;
    shdata->counter++;
    n = shdata->counter;
    DEBUG(_log_shared_, "Shared counter: %d.", n);

    return n;
}

/** Current counter for the process. */
static int cur_session_counter;

/** Return the value of the session counter. */
uint64_t kdsh_get_session_counter() {
    return cur_session_counter;
}

/** Increment the session counter.
 *
 * This is done in kdsh_child_init.  Use kdsh_get_session_counter to
 * get its value.
 */
static void kdsh_increment_session_counter() {
    struct shared_data *shdata;
    uint64_t n;

    kdsh_lock();

    shdata = (struct shared_data *)kdsh_shared_mmap->mm;
    shdata->session_counter++;
    n = shdata->session_counter;

    kdsh_unlock();

    DEBUG(_log_shared_, "Session counter incremented: %d.", n);

    cur_session_counter = n;
}

/** Prepare the internal structure and initialize the underlying file
    if required. */
static int kdsh_ready_file() {
    int err = 0;
    struct shared_data shdata;
    const char *data_file;
    apr_finfo_t fs;
    apr_status_t n;
    uint32_t s = sizeof(struct shared_data);

    memset(&shdata, 0, sizeof(struct shared_data));

    data_file = options_get_str("server.data_file");
    n = apr_stat(&fs, data_file, APR_FINFO_SIZE, kdsh_pool);

    /* Oops, could not get the size.  Ditch the file and recreate it. */
    if (n != APR_SUCCESS || fs.size != sizeof(struct shared_data)) {
        n = apr_file_open(&kdsh_shared_file,
                          data_file,
                          APR_READ | APR_WRITE | APR_CREATE,
                          APR_UREAD | APR_UWRITE,
                          kdsh_pool);

        /* If this fails, bail out. */
        if (n != APR_SUCCESS) {
            KERROR_SET_APR(_shared_, 0, n);
            KERROR_PUSH(_shared_, 0, "failed to create shared data file");
            err = -1;
        } else
            /* Make sure the is enough space in the file. */
            n = apr_file_write(kdsh_shared_file, &shdata, &s);
            if (n != APR_SUCCESS) {
                KERROR_SET_APR(_shared_, 0, n);
                KERROR_PUSH(_shared_, 0, "failed to write to shared data file");
                err = -1;
            }

        return err;
    }

    /* The file exists and is the right size, great, reuse it. */
    n = apr_file_open(&kdsh_shared_file,
                      data_file,
                      APR_READ | APR_WRITE,
                      APR_UREAD | APR_UWRITE,
                      kdsh_pool);
    if (n != APR_SUCCESS) {
        KERROR_SET_APR(_shared_, 0, n);
        KERROR_PUSH(_shared_, 0, "failed to open the shared data file");
        return -1;
    }

    return 0;
}

/** Delete the shared data object. */
static apr_status_t kdsh_delete(__attribute__ ((unused)) void *data) {
    // FIXME: Deleting the mmap and the mutex here causes a crash.

    kdsh_mutex = NULL;
    kdsh_shared_mmap = NULL;
    kdsh_shared_file = NULL;
    kdsh_pid = 0;

    return APR_SUCCESS;
}

static apr_status_t kdsh_child_delete(__attribute__ ((unused)) void *data) {
    if (kdsh_mutex != NULL)
        apr_proc_mutex_cleanup(kdsh_mutex);
    
    kdsh_mutex = NULL;

    return APR_SUCCESS;
}

/** Globally lock the shared memory mutex. */
void kdsh_lock() {
    if (we_be_f0rked) 
        apr_proc_mutex_lock(kdsh_mutex);
}

/** Globally unlock the shared memory mutex. */
void kdsh_unlock() {
    if (we_be_f0rked)
        apr_proc_mutex_unlock(kdsh_mutex);
}

/** Main initialization of shared datas. */
int kdsh_open(apr_pool_t *pool) {
    apr_status_t n;

    /* This should only every be called in the child. */
    assert(kdsh_pid == 0);

    we_be_f0rked = options_get_bool("server.fork");

    kdsh_pid = getpid();
    kdsh_pool = pool;
    apr_pool_cleanup_register(kdsh_pool, NULL, kdsh_delete, kdsh_child_delete);

    do {
        /* Prepare the file. */
        if (kdsh_ready_file() < 0) {
            KERROR_PUSH(_shared_, 0, "failed to prepare the shared data file");
            break;
        }

        /** apr_mmap wants a pool for itself. */
        apr_pool_create(&mmap_pool, main_pool);
        apr_pool_create(&mutex_pool, main_pool);

        /* mmap the file. */
        n = apr_mmap_create(&kdsh_shared_mmap,
                            kdsh_shared_file,
                            0, sizeof(struct shared_data),
                            APR_MMAP_READ | APR_MMAP_WRITE,
                            pool);
        if (n != APR_SUCCESS) {
            KERROR_SET_APR(_shared_, 0, n);
            KERROR_PUSH(_shared_, 0, "failed to map the shared data file");
            break;
        }

        if (we_be_f0rked)
            /* Create a mutex to access that shared file. */
            n = apr_proc_mutex_create(&kdsh_mutex, "tbxsosd-mutex", APR_LOCK_DEFAULT, pool);
            if (n != APR_SUCCESS) {
                KERROR_SET_APR(_shared_, 0, n);
                KERROR_PUSH(_shared_, 0, "failed to create shared data mutex");
                break;
            }
        return 0;

    } while (0);

    return -1;
}

/** Initialization for forked clients. */
int kdsh_child_open() {
    apr_status_t err;
    const char *data_file;  

    data_file = options_get_str("server.data_file");

    /* Create a mutex to access that shared file. */
    if (we_be_f0rked) {
        err = apr_proc_mutex_child_init(&kdsh_mutex, "tbxsosd-mutex", kdsh_pool);
        if (err != APR_SUCCESS) {
            KERROR_SET_APR(_shared_, 0, err);
            KERROR_PUSH(_shared_, 0, "failed to access shared data mutex");
            return -1;
        }
    }

    /* Increment the session counter. */
    kdsh_increment_session_counter();

    return 0;
}
