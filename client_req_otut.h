/**
 * tbxsosd/client_req_otut.c
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
