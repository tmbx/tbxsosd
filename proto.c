/**
 * tbxsosd/proto.c
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
 * Protocol translator.
 *
 * @author François-Denis Gonthier
 */

#include <assert.h>
#include <apr_strings.h>
#include <apr_pools.h>
#include <kerror.h>
#include <kmem.h>

#include "config.h"
#include "str.h"
#include "logid.h"
#include "logging.h"
#include "knp_core_defs.h"
#include "gen_comm.h"
#include "packet.h"
#include "proto.h"
#include "proto_defs.h"
#include "proto_funcs.h"

/** Return the content and type of a packet, given its header.
 *
 * Note: note that this function uses variable-length arrays which is
 * a gcc extension.
 */
static enum proto_el_id *kdprotocol_get_packet_def(struct knp_header *hdr,
                                                   uint32_t *type,
                                                   int match_max,
                                                   uint32_t match[PROTO_CNT][match_max],
                                                   uint32_t *matrix[PROTO_CNT][match_max]) {
    int i, idx;
    uint32_t n;

    if (hdr->major == 0 || hdr->major > PROTO_MAJOR_MAX || hdr->minor > PROTO_MINOR_MAX) {
        KERROR_SET(_knp_, 0, "unsupported protocol version %d.%d", hdr->major, hdr->minor);
        return NULL;
    }

    idx = proto_ver_idx[hdr->major][hdr->minor];

    for (i = 0; i < match_max; i++)
        if (match[idx][i] == hdr->type) {
            *type = i;
            return matrix[idx][i];
        }


    if (hdr->type > (KNP_RES_CAT))
        n = hdr->type - (KNP_RES_CAT);
    else
        n = hdr->type - (KNP_CMD_CAT);

    KERROR_SET(_knp_, 0, "packet type %d is unknown in protocol version %d.%d", n, hdr->major, hdr->minor);
    return NULL;
}

/** Translate a wire message into a packet object. */
static int kdprotocol_unpack(kdprotocol *self, enum proto_el_id *pkt_def,
                             tbuffer *tbuf, struct kdpacket *pkt) {
    int i;
    struct proto_el_func *f;

    DEBUG(_log_knp_, "Incoming packet [id %u '%s', major %u, minor %u, size: %u]",
          pkt->pkt_type,
          proto_in_packet_names[pkt->pkt_type],
          pkt->major,
          pkt->minor,
          tbuf->dbuf->len);

    for (i = 0; pkt_def[i] != EL_END; i++) {
        f = &proto_el_functions[pkt_def[i]];

        if (f->el_reader_func == NULL) {
            KERROR_SET(_knp_, 0, "element id %d not readable", pkt_def[i]);
            return -1;
        }

        if ((f->el_reader_func)(self, pkt_def[i], tbuf, pkt) < 0) {
            KERROR_PUSH(_knp_, 0, "packet element id %d read error", pkt_def[i]);
            return -1;
        }

        if (f->el_printer_func == NULL) {
            KERROR_SET(_knp_, 0, "Element id %d is not printable.", pkt_def[i]);
            return -1;
        }

        if ((f->el_printer_func)(self, pkt_def[i], f->el_name, pkt) < 0) {
            KERROR_SET(_knp_, 0, "Packet element id %d print error.", pkt_def[i]);
            return -1;
        }
    }

    /* If there are some data remaining in the packet, we have an
       error! */
    if (tbuf->dbuf->pos != tbuf->dbuf->len) {
        size_t s = tbuf->dbuf->len - tbuf->dbuf->pos;
        KERROR_SET(_knp_, 0, "%u bytes remaining to read in the packet after unpacking.", s);
        return -1;
    }

    return 0;
}

/** Translate and outbound message into stream of bytes. */
static int kdprotocol_pack(kdprotocol *self, enum proto_el_id *pkt_def,
                           tbuffer *tbuf, struct kdpacket *pkt) {
    int i;
    struct proto_el_func *f;

    DEBUG(_log_knp_, "Outgoing packet [id %u '%s', major %u, minor %u]",
         pkt->pkt_type,
         proto_out_packet_names[pkt->pkt_type],
         pkt->major,
         pkt->minor);

    for (i = 0; pkt_def[i] != EL_END; i++) {
        f = &proto_el_functions[pkt_def[i]];

        if (f->el_writer_func == NULL) {
            KERROR_SET(_knp_, 0, "element id %d not writable", pkt_def[i]);
            return -1;
        }

        if ((f->el_writer_func)(self, pkt_def[i], tbuf, pkt) < 0) {
            KERROR_PUSH(_knp_, 0, "packet element id %d write error", pkt_def[i]);
            return -1;
        }

        if (f->el_printer_func == NULL) {
            KERROR_SET(_knp_, 0, "element id %d is not printable", pkt_def[i]);
            return -1;
        }

        if ((f->el_printer_func)(self, pkt_def[i], f->el_name, pkt) < 0) {
            KERROR_SET(_knp_, 0, "packet element id %d print error", pkt_def[i]);
            return -1;
        }
    }

    return 0;
}

/** Return the protocol attachment type given a packet version.
 *
 * Note: this is valid for KNP version 1.1 and 1.2
 */
uint32_t kdprotocol_get_attachment_type(__attribute__ ((unused)) uint32_t major,
                                        __attribute__ ((unused)) uint32_t minor,
                                        enum proto_attachment_type at) {
    switch (at) {
    case ATTACH_HTML_BODY: return KNP_MAIL_PART_HTML_BODY;
    case ATTACH_TEXT_BODY: return KNP_MAIL_PART_TEXT_BODY;
    case ATTACH_UNKNOWN:   return KNP_MAIL_PART_UNKNOWN;
    case ATTACH_IMPLICIT:  return KNP_MAIL_PART_IMPLICIT;
    case ATTACH_EXPLICIT:  return KNP_MAIL_PART_EXPLICIT;
    }

    return 0;
}

/* This function writes a packet on the wire. It returns -1 on failure, 0 if the
 * caller should stop because the client disconnected cleanly and 1 if the
 * caller should continue.
 */
int kdprotocol_write(kdprotocol *self, struct kdpacket *pkt) {
    int error = 0;
    struct knp_header hdr;
    enum proto_el_id *pkt_def;
    tbuffer *body_tbuf;
    kbuffer *hdr_buf;
    uint32_t dummy;
    int idx;

    hdr_buf = kbuffer_new();
    body_tbuf = tbuffer_new(1024);

    do {
        /* Set the fields of the header.  We'll set the size when we'll
           know it. */
        idx = proto_ver_idx[self->curr_major][self->curr_minor];
        hdr.major = self->curr_major;
        hdr.minor = self->curr_minor;
        hdr.type = proto_out_packet_match[idx][kdpacket_get_type(pkt)];

        pkt->major = self->curr_major;
        pkt->minor = self->curr_minor;

        if ((pkt_def = kdprotocol_get_packet_def(&hdr,
                                                 &dummy,
                                                 PKT_OUT_MAX,
                                                 proto_out_packet_match,
                                                 proto_out_matrix)) == NULL) {
            KERROR_PUSH(_knp_, 0, "protocol translation error");
	    error = -1;
            break;
        }

        /* Convert the protocol elements to a stream of bytes. */
        if (kdprotocol_pack(self, pkt_def, body_tbuf, pkt) < 0) {
            KERROR_PUSH(_knp_, 0, "protocol translation error");
	    error = -1;
            break;
        }

        /* We know the size, fill the header. */
        hdr.size = tbuffer_get_dbuf(body_tbuf)->len;
        kbuffer_write32(hdr_buf, hdr.major);
        kbuffer_write32(hdr_buf, hdr.minor);
        kbuffer_write32(hdr_buf, hdr.type);
        kbuffer_write32(hdr_buf, hdr.size);

        /* Send both buffers. */
	error = kdcomm_write(self->comm, hdr_buf);
	if (error <= 0) {
	    if (error) KERROR_PUSH(_knp_, 0, "packet header write failed");
            break;
	}
	
        if (tbuffer_get_dbuf(body_tbuf)->len > 0) {
	    error = kdcomm_write(self->comm, tbuffer_get_dbuf(body_tbuf));
	    if (error <= 0) {
		if (error) KERROR_PUSH(_knp_, 0, "packet body write failed (%d bytes)", body_tbuf->dbuf->len);
		break;
	    }
	}
	
        kerror_reset();
	error = 1;

    } while (0);

    tbuffer_destroy(body_tbuf);
    kbuffer_destroy(hdr_buf);

    return error;
}

static int protocol_is_supported(uint32_t major, uint32_t minor) {
    struct proto_version *v = NULL;
    size_t i = 0, cnt;

    cnt = sizeof(supported_versions) / sizeof(struct proto_version);

    for (i = 0, v = &supported_versions[i];
         i < cnt;
         i++, v = &supported_versions[i]) {
        if (v->major == major && v->minor == minor)
            return 1;
    }

    return 0;
}

static int protocol_is_unsupported(uint32_t major, uint32_t minor) {
    struct proto_version *v = NULL;
    size_t i = 0, cnt;

    cnt = sizeof(unsupported_versions) / sizeof(struct proto_version);

    for (i = 0, v = &unsupported_versions[i];
         i < cnt;
         i++, v = &unsupported_versions[i]) {
        if (v->major == major && v->minor == minor)
            return 1;
    }

    return 0;
}

/* This function reads a packet header on the wire. It returns -1 on failure, 0
 * if the caller should stop because the client disconnected cleanly and 1 if
 * the caller should continue.
 */
static int kdprotocol_read_header(kdprotocol *self, struct knp_header *hdr) {
    int error = 0;
    kbuffer hdr_buf;
    kbuffer_init(&hdr_buf);

    do {
        /* Read the header from the communication object. */
        error = kdcomm_read(self->comm, &hdr_buf, sizeof(struct knp_header));

        /* Clean disconnection. */
        if (error == 0) break;
	
	/* Error. */
        if (error < 0) {
            KERROR_PUSH(_knp_, 0, "header read error");
            break;
        }

        kbuffer_read32(&hdr_buf, &hdr->major);
        kbuffer_read32(&hdr_buf, &hdr->minor);
        kbuffer_read32(&hdr_buf, &hdr->type);
        kbuffer_read32(&hdr_buf, &hdr->size);

        kerror_reset();
	error = 1;

    } while (0);

    kbuffer_clean(&hdr_buf);

    return error;
}

/* This function verifies a packet header. It returns -1 on failure, 0 if the
 * caller should stop because the client disconnected cleanly and 1 if the
 * caller should continue.
 */
static int kdprotocol_verify_header(kdprotocol *self, apr_pool_t *parent_pool, 
                                    struct knp_header *hdr) {
    int error = 0;
    apr_pool_t *pool;
    
    apr_pool_create(&pool, parent_pool);
    
    do {
	/* Ceiling for the request size. */
	if (hdr->size > 25 * 1024 * 1024) {
	    error = kdprotocol_write(self, kdpacket_new(pool, PKT_FAIL));
	    break;
	}

	/* Check if the incoming message isn't too old. */
	if (protocol_is_unsupported(hdr->major, hdr->minor)) {
	    /* KNP 1.x had no versioning support so we must make it fail
	       right away. */
	    if (hdr->major == 1) {
		self->curr_major = PROTO_MAJOR;
		self->curr_minor = PROTO_MINOR;
		error = kdprotocol_write(self, kdpacket_new(pool, PKT_FAIL));
		break;
	    }
	    /* KNP 2.x can send upgrade messages. */
	    if (hdr->major >= 2) {
		self->curr_major = PROTO_MAJOR;
		self->curr_minor = PROTO_MINOR;
		error = kdprotocol_write(self, kdpacket_new(pool, PKT_FAIL_UPGRADE_PLUGIN));
		break;
	    }
	}

	/* If the protocol is not in the explicitely supported protocol
	   list, then make sure it is present in the supported protocol
	   list too. A protocol that is not unsupported and not supported
	   is too new. */
	if (!protocol_is_supported(hdr->major, hdr->minor)) {
	    /* KNP 1.x had no versionning support so we must make it fail
	       right away. */
	    if (hdr->major == 1) {
		self->curr_major = PROTO_MAJOR;
		self->curr_minor = PROTO_MINOR;
		error = kdprotocol_write(self, kdpacket_new(pool, PKT_FAIL));
		break;
	    }
	    /* KNP 2.x can send upgrade messages. */
	    if (hdr->major >= 2) {
		self->curr_major = PROTO_MAJOR;
		self->curr_minor = PROTO_MINOR;
		error = kdprotocol_write(self, kdpacket_new(pool, PKT_FAIL_UPGRADE_KPS));
		break;
	    }
	}

	/* Reject the header if it is not of the same version as the
	   previous packets that we received. */
	if (self->curr_major != 0) {
	    if (hdr->major != self->curr_major || hdr->minor != self->curr_minor) {
		KERROR_SET(_knp_, 0, "inconsistency in protocol version");
		error = -1;
		break;
	    }
	}
	
	/* All good. */
	error = 1;
	
    } while (0);
    
    apr_pool_destroy(pool);
    
    return error;
}

/** Read and process the packet's body. */
static int kdprotocol_handle_body(kdprotocol *self, 
                                  apr_pool_t *in_pkt_pool,
                                  struct kdpacket **pkt_handle,
				  struct knp_header *hdr) {
    int error = -1;
    uint32_t pkt_type;
    kbuffer body_buf;
    tbuffer *tbuf = NULL;
    struct kdpacket *pkt = NULL;
    enum proto_el_id *pkt_def = NULL;
    
    kbuffer_init(&body_buf);
    
    do {
	if (hdr->size) {
	    ssize_t s = kdcomm_read(self->comm, &body_buf, hdr->size);
	    
	    if (s < 0) {
		KERROR_PUSH(_knp_, 0, "body read error");
		break;
	    }
	    
	    else if (s == 0) {
		error = 0;
		break;
	    }
	}
    
        if ((pkt_def = kdprotocol_get_packet_def(hdr,
                                                 &pkt_type,
                                                 PKT_IN_MAX,
                                                 proto_in_packet_match,
                                                 proto_in_matrix)) == NULL) {
            KERROR_PUSH(_knp_, 0, "protocol translation error");
            break;
        }

        /* Translate the body into a packet. */
        tbuf = tbuffer_new_dbuf(&body_buf);
        pkt = kdpacket_new(in_pkt_pool, pkt_type);
        pkt->major = hdr->major;
        pkt->minor = hdr->minor;

        if (kdprotocol_unpack(self, pkt_def, tbuf, pkt) < 0) {
            KERROR_PUSH(_knp_, 0, "protocol translation error");
            break;
        }
	
	/* We have a valid packet. */
	error = 0;
	*pkt_handle = pkt;
	pkt = NULL;
	
        /* The version of the first packet sent becomes the version of the
         * current protocol object.
         */
        if (self->curr_major == 0) {
            self->curr_major = hdr->major;
            self->curr_minor = hdr->minor;
        }

        kerror_reset();

    } while (0);
    
    kbuffer_clean(&body_buf);
    tbuffer_destroy(tbuf);
    
    return error;
}

/** Read a protocol packet on the wire.
 *
 * The packet object set by this function must be deleted by the caller.
 */
int kdprotocol_read(kdprotocol *self, struct kdpacket **pkt_handle, apr_pool_t *in_pkt_pool) {
    int error;
    struct knp_header hdr;
    
    *pkt_handle = NULL;

    /* Read the header from the wire, if any. */
    error = kdprotocol_read_header(self, &hdr);
    if (error <= 0) return error;
    
    /* Verify the header. */
    error = kdprotocol_verify_header(self, in_pkt_pool, &hdr);
    if (error <= 0) return error;
    
    /* Handle the message body. */
    error = kdprotocol_handle_body(self, in_pkt_pool, pkt_handle, &hdr);
    if (error <= 0) return error;
    
    return 0;
}

/** Return a static failure packet header.
 *
 * Return a packet header in a static array ready to be sent over the
 * wire.  This is useful when the caller doesn't want to allocate
 * memory to send a failure message.
 */
void kdprotocol_fail_packet(kdprotocol *self, uint32_t *hdr) {
    int idx;

    idx = proto_ver_idx[self->curr_major][self->curr_minor];

    hdr[0] = htonl(self->curr_major);
    hdr[1] = htonl(self->curr_minor);
    hdr[2] = htonl(proto_out_packet_match[idx][PKT_FAIL]);
    hdr[3] = 0;
}

/** Perform memory cleanup on the object.
 *
 * This is to be called after a package has been handled.  It frees
 * the memory that was allocated on the heap.
 */
static apr_status_t kdprotocol_delete(void *data) {
    size_t i;
    kdprotocol *self = (kdprotocol *)data;

    if (self->body_html != NULL) {
        kfree((void *)self->body_html);
        self->body_html = NULL;
    }

    if (self->body_text != NULL) {
        kfree((void *)self->body_text);
        self->body_text = NULL;
    }

    if (self->attachments != NULL) {
        for (i = 0; i < self->attachments_count; i++)
            kfree((void *)self->attachments[i]);

        kfree(self->attachments);
    }

    return APR_SUCCESS;
}

/** Protocol object constructor. */
kdprotocol *kdprotocol_new(apr_pool_t *pool, kdcomm *comm) {
    kdprotocol *self;

    self = apr_pcalloc(pool, sizeof(kdprotocol));
    self->comm = comm;
    self->curr_major = 0;
    self->curr_minor = 0;
    apr_pool_cleanup_register(pool, self, kdprotocol_delete, kdprotocol_delete);

    return self;
}
