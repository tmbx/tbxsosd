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
 * Protocol elements and ID definition.  Those definition are common
 * to proto.c and packet.c.
 *
 * @author François-Denis Gonthier
*/

#ifndef _PROTO_DEFS_H
#define _PROTO_DEFS_H

#include "knp_core_defs.h"

#define PROTO_MAJOR_MAX 4
#define PROTO_MINOR_MAX 1

#define PROTO_MAJOR 4
#define PROTO_MINOR 1
#define PROTO_CNT   4

struct proto_version { uint32_t major; uint32_t minor; };

extern struct proto_version supported_versions[4];
extern struct proto_version unsupported_versions[0];

enum proto_el_id {
    EL_NONE = 0,
    EL_KEYID,
    EL_KEY_DATA,
    EL_OWNER_NAME,    
    EL_LOGIN_USERNAME,
    EL_LOGIN_PASSWORD,
    EL_OTUT_REPLY_COUNT,
    EL_OTUT_ADDRESS,
    EL_TICKET,
    EL_OTUT_STRING,  
    EL_OTUT_REPLY_COUNT_ARRAY,   /* ID: 10 */
    EL_OTUT_STRING_ARRAY,
    EL_ADDRESS_ARRAY,
    EL_KEY_DATA_ARRAY,
    EL_DOMAINS_ARRAY,  
    EL_PKG_TYPE,
    EL_TO,
    EL_CC,
    EL_RECIPIENT_ARRAY,
    EL_PASSWORD_ARRAY,
    EL_FROM_NAME,                /* ID: 20 */
    EL_FROM_ADDRESS,
    EL_SUBJECT,
    EL_BODY_TYPE,
    EL_BODY_TEXT,
    EL_BODY_HTML,
    EL_ATTACHMENT_ARRAY,
    EL_POD_ADDRESS,
    EL_PACKAGE_OUTPUT,
    EL_KSN,
    EL_SYMKEY,                   /* ID: 30 */
    EL_SIG_TEXT,
    EL_INTER_SYMKEY_DATA,
    EL_PASSWORD,
    EL_POD_FROM,
    EL_LANG,
    EL_LOGIN_IS_PASSWORD,
    EL_LOGIN_TOKEN,
    EL_POD_DATE,
    EL_TM_KEY_DATA,
    EL_LICENSE_LIM,              /* ID: 40 */
    EL_LICENSE_MAX,              
    EL_LICENSE_KDN,
    EL_OTUT_USES,
    EL_PACKAGE_ERR,
    EL_KPG_IS_USED,
    EL_KPG_HOSTNAME,
    EL_KPG_PORT,   
    EL_WANT_DEC_EMAIL,
    EL_DEC_EMAIL,
    EL_SUBSCRIBER_ARRAY,
    EL_KWS_TICKET,
    EL_END,
    EL_MAX
};

/** Define what packet types are to be seen on output to the
    client. */
enum proto_out_packet_type {
    PKT_OUT_NONE = 0,
    
    PKT_FAIL,    
    PKT_LOGIN_OK_RES,
    PKT_GET_SIGN_KEY_RES,
    PKT_GET_ENC_KEY_RES,
    PKT_GET_OTUT_TICKET_RES,
    PKT_GET_OTUT_STRING_RES,
    PKT_GET_USER_INFO_RES,
    PKT_PACKAGE_RES,
    PKT_DEC_SYM_KEY_HALF_RES,
    PKT_DEC_SYM_KEY_FULL_RES,
    PKT_DEC_SYM_KEY_POD_ERR,
    PKT_DEC_SYM_KEY_PWD_ERR,
    PKT_DEC_SYM_KEY_AUTH_ERR,
    PKT_FAIL_UPGRADE_PLUGIN,
    PKT_FAIL_UPGRADE_KPS,
    PKT_VALIDATE_OTUT_RES,
    PKT_PACKAGE_ERR,  
    PKT_GET_ENC_KEY_BY_ID_RES,
    PKT_GET_KWS_TICKET_RES,
    PKT_CONVERT_EXCHANGE_RES,

    PKT_OUT_MAX
};

/** Define what packet types are to be seen on input from the
    client. */
enum proto_in_packet_type {
    PKT_IN_NONE = 0,

    PKT_LOGIN_CMD,
    PKT_OTUT_LOGIN_CMD,
    PKT_GET_SIGN_KEY_CMD,
    PKT_GET_ENC_KEY_CMD,
    PKT_GET_OTUT_TICKET_CMD,
    PKT_GET_OTUT_STRING_CMD,
    PKT_GET_USER_INFO_CMD,
    PKT_PACKAGE_CMD,
    PKT_DEC_SYM_KEY_CMD,
    PKT_PACKAGE_LICENSE_CMD,
    PKT_VALIDATE_OTUT_CMD,
    PKT_GET_ENC_KEY_BY_ID_CMD,
    PKT_GET_KWS_TICKET_CMD,
    PKT_CONVERT_EXCHANGE_CMD,

    PKT_IN_MAX
};

extern int proto_ver_idx[PROTO_MAJOR_MAX + 1][PROTO_MINOR_MAX + 1];

extern uint32_t proto_in_packet_match[PROTO_CNT][PKT_IN_MAX];
extern uint32_t proto_out_packet_match[PROTO_CNT][PKT_OUT_MAX];

extern enum proto_el_id *proto_in_matrix[PROTO_CNT][PKT_IN_MAX];
extern enum proto_el_id *proto_out_matrix[PROTO_CNT][PKT_OUT_MAX];

extern const char *proto_in_packet_names[PKT_IN_MAX];
extern const char *proto_out_packet_names[PKT_OUT_MAX];

#endif // _PROTO_DEFS_H
