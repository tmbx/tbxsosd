/**
 * tbxsosd/common/commong_msg.h
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
