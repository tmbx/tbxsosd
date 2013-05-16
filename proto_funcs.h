/**
 * tbxsosd/proto_defs.c
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
 * Protocol reader and writer functions.
 * 
 * @author François-Denis Gonthier
 */

#ifndef _PROTO_FUNCS_H
#define _PROTO_FUNCS_H

#include "proto.h"
#include "proto_defs.h"

typedef int (*proto_el_reader_func)(kdprotocol *self, enum proto_el_id id, 
                                    tbuffer *tbuf, struct kdpacket *pkt);
typedef int (*proto_el_writer_func)(kdprotocol *self, enum proto_el_id id,
                                    tbuffer *tbuf, struct kdpacket *pkt);
typedef int (*proto_el_printer_func)(kdprotocol *self, 
                                     enum proto_el_id id,
                                     const char *el_name,
                                     struct kdpacket *pkt);

struct proto_el_func {
    proto_el_reader_func el_reader_func;
    proto_el_writer_func el_writer_func;
    proto_el_printer_func el_printer_func;
    const char *el_name;
};

extern struct proto_el_func proto_el_functions[EL_MAX];

#endif // _PROTO_FUNCS_H
