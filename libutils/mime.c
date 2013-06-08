/**
 * tbxsosd/libutils/mime.c
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
 * Simple MIME-compatible mail generator.
 * @author François-Denis Gonthier
 */

/* Okay, maybe it's not comptatible but it tries hard to.  We can say
   that this code is a good friend of MIME. */

#include <apr_pools.h>
#include <apr_strings.h>
#include <time.h>
#include <base64.h>
#include <kerror.h>

#include "common/logid.h"

#include "mime.h"
#include "utils.h"
#include "str.h"

struct mime {
    /** Newline character to use. */
    const char *nl;

    /** Pool for temporary allocations. */
    apr_pool_t *pool;

    /** Output buffer. */
    kbuffer *buf;

    /** MIME Delimiter. */
    char *delim;

    /** Message ID. */
    char *msgid;
};

#define mime_subject(M, S) mime_field(M, "Subject", S)
#define mime_to(M, S)      mime_field(M, "To", S)
#define mime_cc(M, S)      mime_field(M, "Cc", S)

#define mime_set_html_body(M, C, L) mime_set_body(M, "text/html", C, L)
#define mime_set_text_body(M, C, L) mime_set_body(M, "text/plain", C, L)

#define mime_html_part(M, C, L) mime_part(M, NULL, "text/html", C, L)
#define mime_text_part(M, C, L) mime_part(M, NULL, "text/plain", C, L)
#define mime_text_empty_part(M) mime_part(M, NULL, "text/plain","", 0);

static char *mime_gen_delimiter(apr_pool_t *pool) {
    int i;
    char *delim_str;

    delim_str = uuid(pool);
    if (delim_str == NULL) return NULL;
    
    /* Hack the delimiter, prevents SpamAssassin
       MIME_BOUND_TOO_MANY_HEX. */
    for (i = 0; i < UUID_SIZE; i++) 
        if (delim_str[i] == '-') delim_str[i] = 'z';

    return delim_str;
}

static char *mime_gen_msgid(apr_pool_t *pool) {
    char *uuid_str;

    uuid_str = uuid(pool);
    if (uuid_str == NULL) return NULL;

    return uuid_str;
}

static void mime_write_delim(struct mime *msg) {
    kbuffer_writef(msg->buf, "%s--%s%s", msg->nl, msg->delim, msg->nl);
}

static void mime_from(struct mime *msg, 
                      const char *from_name, 
                      const char *from_addr) {
    if (from_name == NULL || strlen(from_name) == 0) 
        kbuffer_writef(msg->buf, "From: %s%s", from_addr, msg->nl);
    else
        kbuffer_writef(msg->buf, "From: %s <%s>%s", from_name, from_addr, msg->nl);
}

static void mime_field(struct mime *msg, 
                       const char *field_name,
                       const char *field_value) {
    if (field_value != NULL && strlen(field_value) > 0)
        kbuffer_writef(msg->buf, "%s: %s%s", field_name, field_value, msg->nl);
}

static void mime_start_header(struct mime *msg) {
    time_t t;
    char *time_str;
    char time_fmt[] = "%a, %d %b %Y %H:%M:%S %z"; 
    struct tm *tm;
    const int time_str_s = 256;

    time(&t);  
    time_str = apr_palloc(msg->pool, time_str_s);

    if ((tm = localtime(&t)) != NULL && strftime(time_str, time_str_s, time_fmt, tm) > 0) 
        mime_field(msg, "Date", time_str);

    kbuffer_writef(msg->buf, "Message-ID: <%s@teambox>%s", msg->msgid, msg->nl);
}

static void mime_end_header(struct mime *msg) {
    msg = msg;
    /* Nothing to do. */
}

static void mime_set_body(struct mime *msg, 
                          const char *content_type, 
                          const char *content, 
                          size_t content_length) {
    mime_field(msg, "Content-Type", content_type);
    
    kbuffer_writef(msg->buf, msg->nl);
    kbuffer_write(msg->buf, (uint8_t *)content, content_length);
}

static void mime_start_multipart_body(struct mime *msg) {
    char *bound;

    bound = apr_psprintf(msg->pool, "multipart/mixed; boundary=%s", msg->delim);

    mime_field(msg, "MIME-Version", "1.0");
    mime_field(msg, "Content-Type", bound);  

    kbuffer_write_cstr(msg->buf, msg->nl);

    kbuffer_write_cstr(msg->buf, "This is a multi-part message in MIME format.");
    mime_write_delim(msg);
}

static void mime_end_multipart_body(struct mime *msg) {
    msg = msg;
    /* Nothing to do for now. */
}

static void mime_part(struct mime *msg, 
                      const char *part_name,
                      const char *content_type,
                      const char *content,
                      size_t content_length) {
    const char *ct;
    kbuffer *ct_buf, *bin_buf, *blk_buf;
    int is_bin;

    ct_buf = kbuffer_new();

    /* FIXME: Binary files are declared to be of
       application/octet-stream MIME type and text files are set to
       text/plain.  We should at least try to guess the file type
       using libmagic. */

    /* We encode binary string in base64. */
    is_bin = kutils_string_is_binary(content, content_length);
    if (is_bin) {
        size_t sz;

        if (content_type == NULL)
            ct = "application/octet-stream";
        else
            ct = content_type;

        bin_buf = kbuffer_new();
        blk_buf = kbuffer_new();

        kbuffer_write(bin_buf, (uint8_t *)content, content_length);
        kbin2b64(bin_buf, blk_buf);

        sz = blockify_get_size(72, blk_buf->len);
        kbuffer_grow(ct_buf, sz);
        
        blockify_base64(72, 
                        (char *)blk_buf->data, blk_buf->len,
                        (char *)ct_buf->data, sz);
        ct_buf->len = sz;

        kbuffer_destroy(blk_buf);
        kbuffer_destroy(bin_buf);
    }
    /* Text attachment are included plainly. */
    else {
        kbuffer_write(ct_buf, (uint8_t *)content, content_length);        

        if (content_type == NULL) 
            ct = "text/plain";
        else
            ct = content_type;
    }

    if (part_name != NULL && strlen(part_name) > 0)
        kbuffer_writef(msg->buf, "Content-Type: %s; name=%s%s", ct, part_name, msg->nl);
    else
        kbuffer_writef(msg->buf, "Content-Type: %s%s", ct, msg->nl);

    kbuffer_writef(msg->buf, "Content-Disposition: inline%s", msg->nl);

    if (is_bin)
        kbuffer_writef(msg->buf, "Content-Transfer-Encoding: base64%s", msg->nl);

    kbuffer_write_cstr(msg->buf, msg->nl);
    kbuffer_write(msg->buf, ct_buf->data, ct_buf->len);

    kbuffer_destroy(ct_buf);

    mime_write_delim(msg);
} 

int message_to_mime(apr_pool_t *pool, struct message *msg, const char *nl, kbuffer *kb) {
    struct mime m;
    int no_text_body, no_html_body;

    m.nl = nl;
    m.buf = kb;

    m.delim = mime_gen_delimiter(pool);
    if (!m.delim) {
        KERROR_PUSH(_misc_, 0, "failed to create random message delimiter");
        return -1;
    }

    m.msgid = mime_gen_msgid(pool);
    if (!m.msgid) {
        KERROR_PUSH(_misc_, 0, "failed to create random message ID");
        return -1;
    }

    m.pool = pool;

    /* Headers. */
    mime_start_header(&m);
    mime_from(&m, msg->from_name, msg->from_addr);
    mime_to(&m, msg->to);
    mime_cc(&m, msg->cc);
    mime_subject(&m, msg->subject);
    mime_end_header(&m);

    /* Determine the number of parts the MIME message has.  A message
       with no part is not made as a multi-part message. */
    no_text_body = (msg->body_text == NULL || msg->body_text_s == 0);
    no_html_body = (msg->body_html == NULL || msg->body_html_s == 0);

    /* Empty body. */
    if (no_text_body && no_html_body && msg->attch_count == 0) 
        mime_set_text_body(&m, "", 0);

    /* Text body with no attachment. */
    else if (!no_text_body && no_html_body && msg->attch_count == 0) 
        mime_set_text_body(&m, msg->body_text, msg->body_text_s);

    else {
        int i;

        mime_start_multipart_body(&m);      

        /* Text/HTML bodies. */
        if (msg->body_text_s != 0 && msg->body_html_s != 0) {
            mime_text_part(&m, msg->body_text, msg->body_text_s);
            mime_html_part(&m, msg->body_html, msg->body_html_s);
        } 
        else if (msg->body_text_s != 0) 
            mime_text_part(&m, msg->body_text, msg->body_text_s);
        else if (msg->body_html_s != 0)
            mime_html_part(&m, msg->body_html, msg->body_html_s);
        else
            mime_text_empty_part(&m);

        /* Attachments. */
        for (i = 0; i < msg->attch_count; i++) 
            mime_part(&m, 
                      msg->attch[i].name, 
                      NULL, 
                      msg->attch[i].payload, 
                      msg->attch[i].payload_s);

        mime_end_multipart_body(&m);
    }

    return 0;
}
