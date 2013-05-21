/**
 * tbxsosd/common/commong_msg.h
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
*/

#ifndef _COMMON_MSG_H
#define _COMMON_MSG_H

struct message_attachment {
    /* Encoding of attachment. */
    const char *encoding;

    /* MIME-type of attachment. */
    const char *mime_type;

    /* Name of attachment. */
    const char *name;

    /* Payload. */
    char *payload;

    /* Size of the payload. */
    size_t payload_s;
};

struct message {
    const char *from_name;

    const char *from_addr;

    const char *to;

    const char *cc;

    const char *subject;

    const char *body_text;
    size_t body_text_s;

    const char *body_html;
    size_t body_html_s;

    int attch_count;

    struct message_attachment *attch;
};

#endif // _COMMON_MSG_H
