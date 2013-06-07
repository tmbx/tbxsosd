/**
 * tbxsosd/libfilters/filter_virus.c
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
 * Anti-virus mail filter.
 *
 * @author François-Denis Gonthier
 * @author Kristian Benoit for the original version.
 */

#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdio.h>
#include <kerror.h>

#include "common/common_pkg.h"
#include "common/common.h"
#include "common/logid.h"

#include "libutils/options.h"
#include "libutils/logging.h"
#include "libcomm/gen_comm.h"
#include "libcomm/sock_comm.h"

#include "filter_virus.h"

#if defined(REQUEST_PACKAGE) || defined(REQUEST_PACKAGE_LICENSE)

/* 
 * FIXME: This is totally brain-dead.  We talk to ClamAV using the
 * conventional stream protocol, but as of oct 16, I don't know if
 * ClamAV handles the data correctly. We might be better of using the
 * libclamav API in the future. 
 */

#define CLAMAV_DEFAULT_MILLISEC_TIMEOUT 60000

const char cmd_ping[]    = "PING\n";
const char cmd_session[] = "SESSION\n";
const char cmd_end[]     = "END\n";
const char cmd_stream[]  = "STREAM\n";
const char ans_pong[]    = "PONG\n";

static char virus_name[128];

const char *cfg_socket_path;
const char *cfg_socket_addr;
int cfg_answer_len;
int cfg_timeout;

/** Open an Unix connection to clamd. */
static int kdfilter_virus_connect(apr_pool_t *pool, kdcomm **comm) {
    size_t n = sizeof(struct sockaddr_un);
    struct sockaddr_un addr_un;
    kdsock_comm *uc;
    int fd;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        KERROR_SET(_filter_, 0, "failed to create socket");
        return -1;
    }

    addr_un.sun_family = AF_UNIX;
    strcpy(addr_un.sun_path, cfg_socket_path);

    if (connect(fd, (struct sockaddr *)&addr_un, n) < 0) {
        KERROR_SET(_filter_, 0, "connection failed");
        return -1;
    }

    uc = kdsock_comm_new(pool, fd, COMM_SHUT_RDWR);
    *comm = uc->c;
    (*comm)->timeout = cfg_timeout;
    
    return 0;
}

/** Write the file to the ClamAV socket. */
static int kdfilter_virus_write_mail(apr_pool_t *parent_pool, struct filter_params *params, int port) {
    apr_pool_t *pool;
    kdsock_comm *sock_comm;
    kdcomm *comm;
    int fd, i, r = -1;
    struct sockaddr_in addr_in;
    size_t n = sizeof(struct sockaddr_in);

    do {
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            KERROR_SET(_filter_, 0, "failed to create socket");
            return -1;
        }

        addr_in.sin_family = AF_INET;
        addr_in.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr_in.sin_port = htons(port);

        if (connect(fd, (struct sockaddr *)&addr_in, n) < 0) {
            KERROR_SET(_filter_, 0, "connection failed");
            return -1;
        }

        apr_pool_create(&pool, parent_pool);

        sock_comm = kdsock_comm_new(pool, fd, COMM_SHUT_RDWR);
        comm = sock_comm->c;

        /* Text body. */
        if (params->msg.body_text != NULL && params->msg.body_text_s > 0) {
            n = kdcomm_write_raw(comm, (void *)params->msg.body_text, params->msg.body_text_s);
            if (n < params->msg.body_text_s) 
                break;
        }

        /* HTML body. */
        if (params->msg.body_html != NULL && params->msg.body_html_s > 0) {
            n = kdcomm_write_raw(comm, (void *)params->msg.body_html, params->msg.body_html_s);
            if (n < params->msg.body_html_s)
                break;
        }

        /* Attachments. */
        for (i = 0; i < params->msg.attch_count; i++) {
            n = kdcomm_write_raw(comm, 
                                 (void *)params->msg.attch[i].payload, 
                                 params->msg.attch[i].payload_s);
            if (n < params->msg.attch[i].payload_s)
                break;
        }
        
        r = 0;

    } while (0);

    apr_pool_destroy(pool);

    return r;
}

/** Returns 0.  No specific initialization required. */
int kdfilter_virus_open(__attribute__ ((unused)) kdfilter * filter,
                        __attribute__ ((unused)) void ** data) {

    cfg_socket_path = options_get_str("filter_virus.socket_path");
    cfg_socket_addr = options_get_str("filter_virus.socket_addr");
    cfg_answer_len = options_get_uint32("filter_virus.answer_len");
    cfg_timeout = options_get_uint32("filter_virus.timeout");

    return 0;
}

/** Close connection to the ClamAV filter daemon.*/
int kdfilter_virus_close(kdfilter *filter_obj, 
                         void *data) {
    filter_obj = filter_obj;
    data = data;
    return 0;
}

/** Test the usability of clamd. */
int kdfilter_virus_test(kdfilter *filter, __attribute__ ((unused)) void * data) {
    kdcomm *comm;
    apr_pool_t *pool;
    kbuffer *buf, *line_buf;
    int r = -1;

    apr_pool_create(&pool, filter->pool);

    buf = kbuffer_new();
    line_buf = kbuffer_new();

    do {
        if (kdfilter_virus_connect(pool, &comm) < 0)
            break;

        /* Write the ping message to ClamAV. */
        if (kdcomm_write_raw(comm, (void *)cmd_ping, strlen(cmd_ping)) < 0)
            break;

        /* Read pong and check its value. */
        if (kdcomm_read_line(comm, line_buf, buf) < 0) 
            break;
        if (strncmp((char *)line_buf->data, ans_pong, sizeof(ans_pong)) != 0)
            break;

        r = 0;

    } while (0);

    if (buf) kbuffer_destroy(buf);
    if (line_buf) kbuffer_destroy(line_buf);

    apr_pool_destroy(pool);
    
    return r;
}

int kdfilter_virus_scan(kdfilter *filter,
                        __attribute__ ((unused)) void * private_data, 
                        struct filter_params *params,
                        struct filter_result *res) {
    int r = -1, port = 0;
    apr_pool_t *pool;
    kbuffer *buf, *line_buf;
    kdcomm *comm;

    apr_pool_create(&pool, filter->pool);

    buf = kbuffer_new();
    line_buf = kbuffer_new();
    
    do {  
        if (kdfilter_virus_connect(pool, &comm) < 0) 
            break;
    
        if (kdcomm_write_raw(comm, (void *)cmd_stream, strlen(cmd_stream)) < 0)
            break;

        if (kdcomm_read_line(comm, line_buf, buf) < 0) 
            break;

        /* Get the requested port from clamav answer and send the
           file. */
        if (sscanf((char *)line_buf->data, "PORT %i\n", &port) < 1 || port == 0) 
            break;

        if (kdfilter_virus_write_mail(pool, params, port) < 0)
            break;
        
        kbuffer_reset(buf);

        if (kdcomm_read_line(comm, line_buf, buf) < 0) 
            break;

        /* Get the answer (virus or not) and set the virus_name
           accordingly. */
        if (sscanf((char *)line_buf->data, "stream: %s", virus_name) < 1)
            break;

        if (res != NULL) {
            /* Did ClamAV find a virus? */
            if (strcmp(virus_name, "OK") == 0) {
                res->rating = 0;
                res->msg_state = 1;
                snprintf(res->msg, FILTER_MSG_SIZE, "the message is free of known viruses");
            }
            else {
                res->rating = FILTER_EXEC_IS_VIRUS;
                res->msg_state = 1;
                snprintf(res->msg, FILTER_MSG_SIZE, "virus detected: %s\n", virus_name);
            }
        }

        r = 0;

    } while (0);

    if (buf) kbuffer_destroy(buf);
    if (line_buf) kbuffer_destroy(line_buf);
        
    apr_pool_destroy(pool);

    return r;
}

struct filter_driver filter_virus = {
    .filter_name = "ClamAV (Anti-virus)",
    .filter_id = FILTER_ID_VIRUS,

    .p_open  = kdfilter_virus_open,
    .p_close = kdfilter_virus_close,
    .p_test  = kdfilter_virus_test,
    .p_scan  = kdfilter_virus_scan,

    NULL
};

#endif // REQUEST_PACKAGE || REQUEST_PACKAGE_LICENSE
