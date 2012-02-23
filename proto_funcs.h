/**
 * tbxsosd/proto_defs.c
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
