/**
 * tbxsosd/proto.c
 * Copyright (C) 2006-2012 inc.
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
 * Protocol translator.
 *
 * @author François-Denis Gonthier
 */

#ifndef _PROTO_H
#define _PROTO_H

#include "common_pkg.h"
#include "gen_comm.h"
#include "packet.h"

/* You touch this, you die! Is that clear? */
struct __kdprotocol {
    uint32_t curr_major;
    uint32_t curr_minor;

    /* Heap pointer to HTML body. */
    char *body_html;

    /* Heap pointer to text body. */
    char *body_text;

    /* Array of heap pointers to attachments. */
    size_t attachments_count;
    char **attachments;

    kdcomm *comm;
};

typedef struct __kdprotocol kdprotocol;

void kdprotocol_fail_packet(kdprotocol *self, uint32_t *hdr);

uint32_t kdprotocol_get_attachment_type(uint32_t major, 
                                        uint32_t minor, 
                                        enum proto_attachment_type at);

kdprotocol *kdprotocol_new(apr_pool_t *pool, kdcomm *comm);

int kdprotocol_read(kdprotocol *self, 
                    struct kdpacket **pkt_handle, 
                    apr_pool_t *in_pkt_pool);

int kdprotocol_write(kdprotocol *self, struct kdpacket *pkt);

#endif // _PROTO_H
