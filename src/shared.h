/**
 * tbxsosd/shared.h
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

#ifndef _KDSHARED_H
#define _KDSHARED_H

#include <sys/time.h>
#include <apr_mmap.h>
#include <apr_file_io.h>
#include <apr_proc_mutex.h>
#include <tagcrypt.h>

struct kdsh_tm_pkey_time {
    /* The status (0 = inexistent/1 = existent) of the key */
    int status;

    /* Time the key was first received in this KPS time referencial.
     * It is used to invalidate the other key after ~1 minute. */
    struct timeval received_time;

    /* The time the key was signed by the master key in external time
     * referencial. It is used to sequence the timestamp keys. */
    struct timeval activation_time;
};

/** Structure wrapping the shared data in the memory mapped file. */
struct shared_data {
    /* Generic request counter. */
    uint64_t counter;

    /* Incremented at each new connection. */
    uint64_t session_counter;

    /* The index of the current key (1/2) */
    int current_key;

    /* Info about the 2 last keys since they can overlap in time */
    struct kdsh_tm_pkey_time key_info[2];

    /* The timestamp of the last key received. */
    struct timeval timestamp;
};

/** Master process initialization. */
int kdsh_open();

/** Shared memory initialization in child process. */
int kdsh_child_open();

/** Return a globally unique counter value.
 *
 * The counter is incremented each time this function is called.
 */
uint64_t kdsh_get_counter();

int kdsh_set_current_timestamp_pkey(struct tagcrypt_signed_pkey *signed_pkey);

void kdsh_lock();

void kdsh_unlock();

void kdsh_get_cur_tm_pkey_time(struct kdsh_tm_pkey_time *tm_pkey_time);

void kdsh_get_old_tm_pkey_time(struct kdsh_tm_pkey_time *tm_pkey_time);

void kdsh_switch_tm_pkey_time();

int kdsh_set_cur_tm_pkey_time(struct tagcrypt_signed_pkey *signed_pkey);

void kdsh_get_timestamp(struct timeval *tm);

int kdsh_get_cur_tm_pkey();

uint64_t kdsh_get_session_counter();

extern uint64_t event_counter;

#endif // _KDSHARED_H
