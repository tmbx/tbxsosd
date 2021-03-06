/**
 * tbxsosd/libcomm/ssl_comm.h
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
 * SSL client reader.
 *
 * @author François-Denis Gonthier
 */

#ifndef _SSL_COMM_H
#define _SSL_COMM_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <apr_network_io.h>

#include "gen_comm.h"

enum kdssl_type {
    KDSSL_KEY,
    KDSSL_CERT
};

struct kdssl_file {
    /** Index number of the object of interest. */
    int num;

    /** File name, full path to the file. */
    const char *file_name;

    /** Object type. */
    enum kdssl_type type;

    /** File content as X509 object. */
    union {
        X509 *cert;
        EVP_PKEY *key;
    };
};

/** NOTE: The destructor effectively close the underlying socket. */

/** SSL socket communication object. */
struct __kdssl_comm {
    /* Working pool for the socket. */
    apr_pool_t *pool;

    /* SSL IO tool. */
    BIO * bio;

    /* SSL handle. */
    SSL * ssl;

    apr_socket_t *apr_sock;

    struct sockaddr_in si;
    const char *addr;

    /** Certificate file currently in use. */
    struct kdssl_file *cert_file;

    /** Key file currently in use. */
    struct kdssl_file *key_file;

    /** Certificate number. */
    int cert_num;
    
    kdcomm *c;
};

/** Static SSL initialization. 
 *
 * Call this at the start of your program if you want to use this
 * object.
 */
int kdssl_static_init();

typedef struct __kdssl_comm kdssl_comm;

/** Constructor. */
kdssl_comm *kdssl_comm_new(apr_pool_t *pool, int sock);

/** Initialize the SSL socket. */
int kdssl_comm_init(kdssl_comm *self, void *pre_bytes, size_t pre_bytes_s);

/** Returns generic client structure. */
kdcomm *kdssl_comm_get_comm();

/** Make this communication channel use this certificate number. */
int kdssl_comm_load_cert_number(kdssl_comm *self, int cert_num);

#endif // _SSL_COMM_H
