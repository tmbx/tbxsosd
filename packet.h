/**
 * tbxsosd/packet.h
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
 * Generic packet interface
 * @author: François-Denis Gonthier 
 */

/** 
 * This module allow KNP users to use KNP packet in a generic manner
 * without dealing with a set of rigid structures dependent of the
 * protocol version.
 *
 * This is a set of getters and setters with the methods required for
 * knowing which elements has been set or not.
 *
 * A packet needs to have a type set.  As far as this module is
 * concerned, a type is an integer.  proto_* modules set the time
 * dependent of the KNP protocol types.
 */

#ifndef _PACKET_H
#define _PACKET_H

#include <apr_pools.h>

#include "proto_defs.h"

/** Type of element. */
enum proto_el_type {
    /** No type stored. */
    EL_TYPE_NONE, 
    
    /** String element, always zero-terminated. */
    EL_TYPE_STR, 

    /** Unsigned integer. */
    EL_TYPE_UINT32, 

    /** Long unsigned integer. */
    EL_TYPE_UINT64, 
    
    /** Raw byte string. */
    EL_TYPE_RAW, 

    /** List of raw elements. */
    EL_TYPE_LIST
};

/** Protocol element in the packet. */
struct proto_el {
    enum proto_el_type type;
    void *ptr;
};

/** List of protocol element. */
struct el_list {
    size_t nb;
    void **lst;
};

/** Sized element. */
struct el_sized {
    size_t size;
    void *ptr;
};

/** Packet structure. */
struct kdpacket {
    apr_pool_t *pool;

    uint32_t major;
    uint32_t minor;

    int pkt_type;

    struct proto_el elements[EL_MAX];
};

/** Create a new packet object. */
struct kdpacket *kdpacket_new(apr_pool_t *pool, uint32_t packet_type);

/** Return 1 if an element has a value set. */
int kdpacket_is_present(struct kdpacket *self, enum proto_el_id id);

/** Delete a package object. */
void kdpacket_delete(struct kdpacket *self);

/** Return the type of packet. */
int kdpacket_get_type(struct kdpacket *self);

/** Return the number of items in a list of elements. */
int kdpacket_get_list_len(struct kdpacket *self, enum proto_el_id id);

/** Return an item from a list of element. 
 *
 * Returns a pointer to the static buffers allocated when the
 * item was set. 
 */
void kdpacket_get_list_item(struct kdpacket *self, enum proto_el_id id, 
                            uint32_t n, void **item, size_t *s);

/** Return a string element. 
 * 
 * Returns a pointer to the static buffers allocated when the item was
 * set.
 */
void kdpacket_get_str(struct kdpacket *self, 
                      enum proto_el_id id, 
                      const char **str, 
                      size_t *str_s);

/** Return a long integer element. */
void kdpacket_get_uint64(struct kdpacket *self, enum proto_el_id id, uint64_t *n);

/** Return an integer element. */
void kdpacket_get_uint32(struct kdpacket *self, enum proto_el_id id, uint32_t *n);

/** Return a raw buffer. 
 *
 * Returns a pointer to the static buffers allocated when the item was
 * set.
 */
void kdpacket_get_raw(struct kdpacket *self, enum proto_el_id id, void **ptr, size_t *s);

/** Set a string element.
 *
 * This will make sure the string is zero-terminated using the length
 * of the buffer.
 */
void kdpacket_set_str(struct kdpacket *self, 
                      enum proto_el_id id,
                      const char *str, 
                      size_t str_s);

/** Set a correctly formed string element. 
 *
 * Unlike the previous function, this doesn't care about the format of
 * the string.
 */
void kdpacket_set_cstr(struct kdpacket *self, enum proto_el_id id, const char *str);

/** Set a raw element. 
 *
 * This will keep a pointer to the buffers passed in as argument.
 */
void kdpacket_set_raw(struct kdpacket *self, 
                      enum proto_el_id id, 
                      void *ptr, 
                      size_t n);

/** Set an integer element. */
void kdpacket_set_uint32(struct kdpacket *self, enum proto_el_id id, uint32_t n);

/** Set an long integer element. */
void kdpacket_set_uint64(struct kdpacket *self, enum proto_el_id id, uint64_t n);

/** Store a raw pointer in an element without copying the input. */
void kdpacket_set_ptr(struct kdpacket *self, 
                      enum proto_el_id id, 
                      enum proto_el_type type, 
                      void *ptr);

/** Set a list element. 
 * 
 * The list will be initially empty.  Use kdpacket_set_list_item to
 * set the individual elements.
 */
void kdpacket_set_list(struct kdpacket *self, enum proto_el_id id, size_t nel);

/** Set a list element as a raw element.
 *
 * This function will copy the 
 */
void kdpacket_set_list_item(struct kdpacket *self, 
                            enum proto_el_id id, 
                            uint32_t i, 
                            const void *ptr, 
                            size_t ptr_s);

/** Set a list element as a string element.
 * 
 * This will make sure the string is zero-terminated.
 */
void kdpacket_set_str_list_item(struct kdpacket *self,
                                enum proto_el_id id,
                                uint32_t i,
                                const char *ptr,
                                size_t ptr_s);

#endif // _KDPACKET_H
