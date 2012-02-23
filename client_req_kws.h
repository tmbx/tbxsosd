/**
 * tbxsosd/client_req_kws.h
 * Copyright (C) 2008-2012 Opersys inc.
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
 * Supply workspace tickets.
*/
#ifndef _CLIENT_REQ_KWS_H
#define _CLIENT_REQ_KWS_H

#include "client.h"

enum client_state kdclient_get_kws_ticket_request(kdclient *self,
                                                  apr_pool_t *pkt_pool,
                                                  struct kdpacket *in_pkt,
                                                  struct kdpacket **out_pkt);

enum client_state kdclient_convert_exchange_addr(kdclient *self,
                                                 apr_pool_t *pkt_pool,
                                                 struct kdpacket *in_pkt,
                                                 struct kdpacket **out_pkt);

#endif // _CLIENT_REQ_KWS_H
