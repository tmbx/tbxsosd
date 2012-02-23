/**
 * tbxsosd/client_req_otut.c
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
 * OTUT string request.
 *
 * @author François-Denis Gonthier
*/

#ifndef _CLIENT_REQ_OTUT
#define _CLIENT_REQ_OTUT

enum client_state kdclient_get_otut_string_request(kdclient *self,
                                                   apr_pool_t *pkt_pool,
                                                   struct kdpacket *in_pkt,
                                                   struct kdpacket **out_pkt);

enum client_state kdclient_get_ticket_request(kdclient *self,
                                              apr_pool_t *pool,
                                              struct kdpacket *in_pkt,
                                              struct kdpacket **out_pkt);

enum client_state kdclient_check_otut_string_request(kdclient *self,
                                                     apr_pool_t *pkt_pool,
                                                     struct kdpacket *in_pkt,
                                                     struct kdpacket **out_pkt);
#endif // _CLIENT_REQ_OTUT
