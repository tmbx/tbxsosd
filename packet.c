/**
 * tbxsosd/packet.c
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
 * Generic protocol packet object.
 *
 * @author François-Denis Gonthier
*/

#include <apr_strings.h>
#include <apr_pools.h>
#include <assert.h>

#include "proto_defs.h"
#include "packet.h"

/** Return the ID of the packet. */
int kdpacket_get_type(struct kdpacket *self) {
    return self->pkt_type;
}

/** Return 1 if an element has a value. */
int kdpacket_is_present(struct kdpacket *self, enum proto_el_id id) {
    return self->elements[id].type != EL_TYPE_NONE;
}

/** Return a packet data. */
void kdpacket_get_raw(struct kdpacket *self, enum proto_el_id id, void **ptr, size_t *s) {
    struct el_sized *el;

    assert(self->elements[id].ptr != NULL);
    assert(self->elements[id].type == EL_TYPE_RAW);

    el = self->elements[id].ptr;
    if (ptr != NULL) *ptr = el->ptr;
    if (s != NULL)   *s = el->size;
}

void kdpacket_get_str(struct kdpacket *self, enum proto_el_id id, const char **str, size_t *str_s) {
    struct el_sized *el;

    assert(self->elements[id].ptr != NULL);
    assert(self->elements[id].type == EL_TYPE_STR);

    el = self->elements[id].ptr;

    if (str != NULL) *str = el->ptr;
    if (str_s != NULL) *str_s = el->size;
}

void kdpacket_get_list_item(struct kdpacket *self, enum proto_el_id id, 
                            uint32_t n, void **item, size_t *s) {
    struct el_list *elst;
    struct el_sized *el;

    assert(self->elements[id].ptr != NULL);
    assert(self->elements[id].type == EL_TYPE_LIST);

    elst = self->elements[id].ptr;
    el = elst->lst[n];

    if (item != NULL) *item = el->ptr;
    if (s != NULL)    *s = el->size;
}

int kdpacket_get_list_len(struct kdpacket *self, enum proto_el_id id) {
    struct el_list *el;

    assert(self->elements[id].ptr != NULL);
    assert(self->elements[id].type == EL_TYPE_LIST);

    el = self->elements[id].ptr;
    return el->nb;
}

void kdpacket_get_uint32(struct kdpacket *self, enum proto_el_id id, uint32_t *n) {
    *n = *(uint32_t *)self->elements[id].ptr;
}

void kdpacket_get_uint64(struct kdpacket *self, enum proto_el_id id, uint64_t *n) {    
    *n = *(uint64_t *)self->elements[id].ptr;
}

/** Store a typical C string.
 *
 * This functions makes a copy of the string for itself.  It is unsafe
 * to use this function when reading data from the client but can
 * safely be used to return to him.  NULL string == no-op.
 */
void kdpacket_set_cstr(struct kdpacket *self, enum proto_el_id id, const char *str) {
    struct el_sized *el;

    if (str != NULL) {
        el = apr_pcalloc(self->pool, sizeof(struct el_sized));
        el->ptr = apr_pstrdup(self->pool, str);
        el->size = strlen(str);

        self->elements[id].type = EL_TYPE_STR;
        self->elements[id].ptr = el;
    }
}

/** Store a string in an element.
 *
 * This function can take non zero terminated strings but will make
 * sure there is always a zero at the end of the string. 
 */
void kdpacket_set_str(struct kdpacket *self, enum proto_el_id id, const char *str, size_t str_s) {
    struct el_sized *el;

    el = apr_pcalloc(self->pool, sizeof(struct el_sized));

    if (str != NULL) {
        el->ptr = apr_palloc(self->pool, str_s + 1);
        memcpy(el->ptr, str, str_s);
        ((char *)el->ptr)[str_s] = 0;
    }
    else
        el->ptr = NULL;
    
    el->size = str_s;
        
    self->elements[id].type = EL_TYPE_STR;
    self->elements[id].ptr = el;    
}

/** Store a block of data in an element.
 *
 * This function copies a block of data in the element.
 */
void kdpacket_set_raw(struct kdpacket *self, enum proto_el_id id, void *ptr, size_t n) {
    struct el_sized *el;

    el = apr_pcalloc(self->pool, sizeof(struct el_sized));

    if (ptr != NULL) {
        el->ptr = apr_palloc(self->pool, n);
        memcpy(el->ptr, ptr, n);
    }
    else
        el->ptr = NULL;
    
    el->size = n;

    self->elements[id].type = EL_TYPE_RAW;
    self->elements[id].ptr = el;
}

/** Store a pointer to an element without copy. */
void kdpacket_set_ptr(struct kdpacket *self, 
                      enum proto_el_id id, 
                      enum proto_el_type type, 
                      void *ptr) {
    self->elements[id].type = type;
    self->elements[id].ptr = ptr;
}

/** Store an unsigned integer in an element. */
void kdpacket_set_uint32(struct kdpacket *self, enum proto_el_id id, uint32_t n) {
    uint32_t *pn;

    pn = apr_palloc(self->pool, sizeof(uint32_t));
    *pn = n;

    self->elements[id].type = EL_TYPE_UINT32;
    self->elements[id].ptr = pn;
}

/** Store an unsigned 64 bit integer in an element. */
void kdpacket_set_uint64(struct kdpacket *self, enum proto_el_id id, uint64_t n) {
    uint64_t *pn;

    pn = apr_palloc(self->pool, sizeof(uint64_t));
    *pn = n;

    self->elements[id].type = EL_TYPE_UINT64;
    self->elements[id].ptr = pn;
}

/** Set the element to be a string list. */
void kdpacket_set_list(struct kdpacket *self, enum proto_el_id id, size_t nel) {
    struct el_list *el;

    el = apr_pcalloc(self->pool, sizeof(struct el_list));
    el->nb = nel;
    el->lst = apr_pcalloc(self->pool, nel * sizeof(void *));

    self->elements[id].type = EL_TYPE_LIST;
    self->elements[id].ptr = el;
}

/** Store a cstr in a list. */
void kdpacket_set_str_list_item(struct kdpacket *self, enum proto_el_id id,
                                uint32_t i, const char *ptr, size_t ptr_s) {
    struct el_list *elst;
    struct el_sized *el;

    elst = self->elements[id].ptr;

    assert(self->elements[id].type == EL_TYPE_LIST);
    assert(i < elst->nb);

    elst->lst[i] = apr_palloc(self->pool, sizeof(struct el_sized));
    el = elst->lst[i];

    el->ptr = apr_palloc(self->pool, ptr_s + 1);
    memcpy(el->ptr, ptr, ptr_s);
    ((char *)el->ptr)[ptr_s] = 0;
    el->size = ptr_s;    
}

/** Store an element in a list.
 *
 * Note, the type of the element the caller is trying to store is
 * asserted to be a list.
 */
void kdpacket_set_list_item(struct kdpacket *self, enum proto_el_id id, 
                            uint32_t i, const void *ptr, size_t ptr_s) {
    struct el_list *elst;
    struct el_sized *el;

    elst = self->elements[id].ptr;

    assert(self->elements[id].type == EL_TYPE_LIST);
    assert(i < elst->nb);
  
    elst->lst[i] = apr_palloc(self->pool, sizeof(struct el_sized));
    el = elst->lst[i];
    
    if (ptr != NULL) {
        el->ptr = apr_palloc(self->pool, ptr_s);
        memcpy(el->ptr, ptr, ptr_s);
    }
    else
        el->ptr = NULL;

    el->size = ptr_s;
}

/** Packet constructor. */
struct kdpacket *kdpacket_new(apr_pool_t *pool, uint32_t pkt_type) {
    struct kdpacket *self;

    self = apr_pcalloc(pool, sizeof(struct kdpacket));
    self->pool = pool;
    self->pkt_type = pkt_type;
    return self;
}
