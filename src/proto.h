/**
 * tbxsosd/proto.c
 * Copyright (C) 2006-2012 inc.
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
 * Protocol translator.
 *
 * @author François-Denis Gonthier
 */

#ifndef _PROTO_H
#define _PROTO_H

#include "common/common_pkg.h"
#include "libcomm/gen_comm.h"
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
