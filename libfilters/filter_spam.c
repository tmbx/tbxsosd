/**
 * tbxsosd/libfilters/filter_spam.c
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
 * SpamAssassin message filter.
 *
 * @author François-Denis Gonthier
 * @author Kristian Benoit for the original version.
 */

/*
 * Note that the SpamAssassin does not provide much information on what
 * is wrong.  A failure in the test phase will need external handling.
 */

/*
 * FIXME: This filter currently ignores attachments.  Attachment will
 * need to be provided as MIME parts to SpamAssassin and currently
 * there is not easy way to know the content-type of an attachment as
 * it may not be provided by the client.
 *
 * FIXME: (Update as of 2007/03/28) It seems that SpamAssassin doesn't
 * do squat to attachments, so I'm not entirely sure it's worth
 * sending them at all.
 */

#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <kerror.h>
#include <kmem.h>

#include "common_pkg.h"
#include "common.h"

#include "options.h"
#include "logging.h"
#include "logid.h"
#include "str.h"
#include "gen_comm.h"
#include "sock_comm.h"
#include "filter_spam.h"
#include "filters.h"
#include "utils.h"
#include "mime.h"

#if defined(REQUEST_PACKAGE) || defined(REQUEST_PACKAGE_LICENSE)

/*
 * Everything here should be in configuration somewhere.
 */
#define MAX_SPAMASS_COMM_LEN           1024
#define SPAMASS_SOCKET_ADDR     "127.0.0.1"
#define SPAMASS_SOCKET_PORT             783
#define SPAMASS_CMD                 "CHECK"
#define SPAMASS_PROTOCOL        "SPAMC/1.2"
#define SPAMASS_DEFAULT_MILLISEC_TIMEOUT      60000

static int cfg_timeout;

/** Open connection to SpamAssassin. 
 *
 * @returns -1 on error. 
 */
static int kdfilter_spam_connect(apr_pool_t *pool, kdcomm **comm) {
    size_t n = sizeof(struct sockaddr_in);
    struct sockaddr_in addr_in;
    kdsock_comm *sc;
    int fd;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        KERROR_SET(_filter_, 0, "failed to create socket");
        return -1;
    }

    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = inet_addr(SPAMASS_SOCKET_ADDR);
    addr_in.sin_port = htons(SPAMASS_SOCKET_PORT);

    if (connect(fd, (struct sockaddr*)&addr_in, n) < 0) {
        KERROR_SET(_filter_, 0, "connection failed");
        return -1;
    }

    sc = kdsock_comm_new(pool, fd, COMM_SHUT_RDWR);
    *comm = sc->c;
    (*comm)->timeout = cfg_timeout;

    return 0;
}

/** Loads the filter configuration. */
int kdfilter_spam_open(kdfilter *self, void ** pv) {
    struct filter_spam_data * p;
    
    /* Shut up gcc. */
    self = self;

    p = (struct filter_spam_data *)kmalloc(sizeof(struct filter_spam_data));
    
    p->max_reject_rating = options_get_uint32("filter_spam.reject_min");
    p->max_challenge_rating = options_get_uint32("filter_spam.challenge_min");
    cfg_timeout = options_get_uint32("filter_spam.timeout");
        
    *pv = p;

    return 0;
}

/** Returns OK.  No specific cleanup to do. */
int kdfilter_spam_close(kdfilter *filter_obj, void *data) {
    data = data;
    filter_obj = filter_obj;

    kfree(data);

    return 0;
}

/** Prepare the message for SpamAssassin.
 *
 * SpamAssassin expects to see headers at the begining of messages.
 * If we send him only a body, he will consider the body to be
 * (invalid) headers and report that the message is without body.  We
 * can fake the presence of some headers.
 */
static int kdfilter_spam_write_msg(apr_pool_t *parent_pool,
                                   struct filter_params *params,
                                   kbuffer *msg_buf) {
    int i, err = -1;
    struct message msg;
    apr_pool_t *pool;
    int *txt_attch, txt_attch_count = 0;

    apr_pool_create(&pool, parent_pool);

    /* We need to remove the binary attachments. */
    msg.from_name = params->msg.from_name;
    msg.from_addr = params->msg.from_addr;
    msg.to = params->msg.to;
    msg.cc = params->msg.cc;
    msg.subject = params->msg.subject;
    msg.body_text = params->msg.body_text;
    msg.body_text_s = params->msg.body_text_s;
    msg.body_html = params->msg.body_html;
    msg.body_html_s = params->msg.body_html_s;
    
    if (params->msg.attch_count > 0) {
        txt_attch = apr_pcalloc(pool, sizeof(int) * params->msg.attch_count);

        /* Check which attachments are binary. */
        for (i = 0; i < params->msg.attch_count; i++) {
            if (!kutils_string_is_binary(params->msg.attch[i].payload, params->msg.attch[i].payload_s)) {
                txt_attch[i] = 1;
                txt_attch_count++;
            } else
                txt_attch[i] = 0;
        }

        /* Copy the attachments from the message to the parameter
           bloc, excluding binary attachments. */
        if (txt_attch_count > 0) {
            msg.attch = apr_pcalloc(pool, sizeof(struct message_attachment) * txt_attch_count);

            for (i = 0; i < txt_attch_count; i++) {
                if (txt_attch[i]) {
                    msg.attch[i].encoding = params->msg.attch[i].encoding;
                    msg.attch[i].mime_type = params->msg.attch[i].mime_type;
                    msg.attch[i].name = params->msg.attch[i].name;
                    msg.attch[i].payload = params->msg.attch[i].payload;
                    msg.attch[i].payload_s = params->msg.attch[i].payload_s;
                }
            }

            msg.attch_count = txt_attch_count;
        }
        /* No non-binary attachments. */
        else {
            msg.attch_count = 0;
            msg.attch = NULL;
        }
    } else {
        msg.attch_count = 0;
        msg.attch = NULL;
    }

    if (message_to_mime(pool, &msg, "\r\n", msg_buf) < 0) 
        KERROR_PUSH(_filter_, 0, "failed to generate MIME message");
    else 
        err = 0;

    apr_pool_destroy(pool);

    /* Necessary for SpamAssassin. */
    kbuffer_write_cstr(msg_buf, "\r\n");

    return err;
}

/** Test if the daemon is still fine.  */
int kdfilter_spam_test(kdfilter *filter, void * private_data) {
    kdcomm *comm;
    apr_pool_t *pool;
    kbuffer *buf, *line_buf;
    int r = -1;

    private_data = private_data;

    apr_pool_create(&pool, filter->pool);

    if (kdfilter_spam_connect(pool, &comm) < 0)
        return -1;

    buf = kbuffer_new();
    line_buf = kbuffer_new();

    /* Try writing the PING message. */
    do {
        kbuffer_writef(buf, "PING %s\n", SPAMASS_PROTOCOL);
        if (kdcomm_write(comm, buf) == 0)
            break;
                
        kbuffer_reset(buf);

        if (kdcomm_read_line(comm, line_buf, buf) < 0)
            break;
        if (strstr((char *)buf->data, "PONG") == NULL) 
            break;
           
        /* Success. */
        r = 0;

    } while (0);

    if (buf) kbuffer_destroy(buf);
    if (line_buf) kbuffer_destroy(line_buf);

    apr_pool_destroy(pool);

    return r;
}

int kdfilter_spam_scan(kdfilter *filter,
                       void * private_data, 
                       struct filter_params *msg, 
                       struct filter_result *res) {
    struct filter_spam_data * pv = (struct filter_spam_data *)private_data;
    int r = -1, retval;
    float spam_rating;
    char server_ver[5], str_retval[16];
    char is_spam[6] = "\0";
    kdcomm *comm;
    apr_pool_t *pool;
    kbuffer *msg_buf, *hdr_buf, *ret_buf, *line_buf;

    apr_pool_create(&pool, filter->pool);

    if (kdfilter_spam_connect(pool, &comm) < 0) 
        return -1;

    msg_buf = kbuffer_new();
    hdr_buf = kbuffer_new();
    ret_buf = kbuffer_new();
    line_buf = kbuffer_new();

    do {
        kdfilter_spam_write_msg(pool, msg, msg_buf);

        kbuffer_writef(hdr_buf, "%s %s\r\nContent-length: %u\r\n\r\n", 
                       SPAMASS_CMD, 
                       SPAMASS_PROTOCOL, 
                       msg_buf->len);

        /* Write the message. */
        if (kdcomm_write(comm, hdr_buf) <= 0)
            break;
        if (kdcomm_write(comm, msg_buf) <= 0)
            break;

        kbuffer_reset(ret_buf);

        if (kdcomm_read_line(comm, line_buf, ret_buf) < 0) 
            break;        

        if (sscanf((char *)line_buf->data, 
                   "SPAMD/%4s %i %15s", server_ver, &retval, str_retval) != 3) 
            break;

        /* Check the SpamAssassin version.  (Note: it would have been
           better to check this in the test phase. */           
        if (strncmp(server_ver, "1.1", 4)!=0) 
            break;

        /* Advance past the first newline. */
        if (kdcomm_read_line(comm, line_buf, ret_buf) < 0) 
            break;

        /* Extract the rating from the returned value. */
        if (sscanf((char *)line_buf->data, "Spam: %5s ; %f / ", is_spam, &spam_rating) != 2) 
            break;

        if (res != NULL) {
            /* Check the max rating.  The message is denied in this case. */
            if (spam_rating > pv->max_reject_rating) {
                res->rating = FILTER_EXEC_DENY;
                res->msg_state = 1;
                sprintf(res->msg,
                        "The KPS' internal filters have identified this email "
                        "as potential spam and has therefore refused to package "
                        "your email. If this is a legitimate email, contact your "
                        "system administrator with the following "
                        "information: spam score = %f.",
                        spam_rating);
            } 
#if 0 // KEEP
            /* Check the challenge rating.  The message is challenge in this case. */
            else if (spam_rating > pv->max_challenge_rating) {
                res->rating = FILTER_EXEC_CHALLENGE;
                res->msg_state = 1;
                sprintf(res->msg, 
                        "the message is being challenged by a score of %f", 
                        spam_rating);
            }
#endif
            else {
                res->rating = 0;
                res->msg_state = 1;
                sprintf(res->msg, 
                        "the message is free of spam with a score of %f", 
                        spam_rating);
            }
        }
            
        r = 0;
    } while (0);
    
    if (msg_buf) kbuffer_destroy(msg_buf);
    if (hdr_buf) kbuffer_destroy(hdr_buf);
    if (ret_buf) kbuffer_destroy(ret_buf);
    if (line_buf) kbuffer_destroy(line_buf);

    apr_pool_destroy(pool);

    return r;
}

struct filter_driver filter_spam = {
    .filter_name = "SpamAssassin (Anti-spam)",
    .filter_id = FILTER_ID_SPAM,
    
    .p_open  = kdfilter_spam_open,
    .p_close = kdfilter_spam_close,
    .p_test  = kdfilter_spam_test,
    .p_scan  = kdfilter_spam_scan,
    
    .private_data = NULL
};

#endif // REQUEST_PACKAGE || REQUEST_PACKAGE_LICENSE
