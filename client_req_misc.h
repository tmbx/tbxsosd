/**
 * tbxsosd/client_req_misc.h
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
 * Other kind of requests.
 *
 * @author François-Denis Gonthier
*/

#ifndef _CLIENT_REQ_MISC_H
#define _CLIENT_REQ_MISC_H

enum client_state kdclient_get_user_info_request(kdclient *self,
                                                 apr_pool_t *pool,
                                                 struct kdpacket *in_pkt,
                                                 struct kdpacket **out_pkt);

#endif // _CLIENT_REQ_MISC_H
