/**
 * tbxsosd/proto_defs.c
 * Copyright (C) 2006-2012 Opersys inc.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * Protocol elements and ID definition.
 *
 * @author François-Denis Gonthier
 */

#include <stdlib.h>

#include "proto_defs.h"

/* Supported version.
 *
 * Supported protocol versions are the protocol version that can be
 * used to communicate with this server.
 */
struct proto_version supported_versions[] = {{1, 1}, {2, 1}, {3, 1}, {4,1}};

/** Unsupported version. 
 *
 * Unsupported versions are the ones considered to old to be
 * supported.  Plugins using an unsupported version have to upgrade.
 */
struct proto_version unsupported_versions[] = {};

/* @remark Protocol versions that are not supported nor unsupported
   version are considered to be too recent for the target server. */

/* Packet definition */

/* KNP v1.1 */
static enum proto_el_id pkt_login_user_cmd[] = { EL_LOGIN_USERNAME, EL_LOGIN_PASSWORD, EL_END };
static enum proto_el_id pkt_login_otut_cmd[] = { EL_OTUT_STRING, EL_END };
static enum proto_el_id pkt_get_sign_key_cmd[] = { EL_KEYID, EL_END };
static enum proto_el_id pkt_get_enc_key_cmd[] = { EL_ADDRESS_ARRAY, EL_END };
static enum proto_el_id pkt_get_otut_ticket_cmd[] = { EL_OTUT_REPLY_COUNT, EL_OTUT_ADDRESS, EL_END };
static enum proto_el_id pkt_get_otut_string_cmd[] = { EL_TICKET, EL_OTUT_REPLY_COUNT_ARRAY, EL_END };
static enum proto_el_id pkt_get_user_info_cmd[] = { EL_END };
static enum proto_el_id pkt_package_cmd[] = { EL_PKG_TYPE, EL_TO, EL_CC, 
                                              EL_RECIPIENT_ARRAY, EL_PASSWORD_ARRAY,
                                              EL_FROM_NAME, EL_FROM_ADDRESS,
                                              EL_SUBJECT,
                                              EL_BODY_TYPE, EL_BODY_TEXT, EL_BODY_HTML,
                                              EL_ATTACHMENT_ARRAY,
                                              EL_POD_ADDRESS, EL_END };
static enum proto_el_id pkt_dec_sym_key_cmd[] = { EL_SIG_TEXT, EL_KEY_DATA, EL_INTER_SYMKEY_DATA,
                                                  EL_PASSWORD, EL_POD_FROM, EL_END };
static enum proto_el_id pkt_login_ok_res[] = { EL_END };
static enum proto_el_id pkt_fail_res[] = { EL_END };
static enum proto_el_id pkt_get_sign_key_res[] = { EL_KEY_DATA, EL_OWNER_NAME, EL_END };
static enum proto_el_id pkt_get_enc_key_res[] = { EL_KEY_DATA_ARRAY, EL_END };
static enum proto_el_id pkt_get_otut_ticket_res[] = { EL_TICKET, EL_END };
static enum proto_el_id pkt_get_otut_string_res[] = { EL_OTUT_STRING_ARRAY, EL_END };
static enum proto_el_id pkt_get_user_info_res[] = { EL_KEYID, EL_DOMAINS_ARRAY, EL_END };
static enum proto_el_id pkt_package_res[] = { EL_PACKAGE_OUTPUT, EL_KSN, EL_SYMKEY, EL_END };
static enum proto_el_id pkt_dec_sym_key_half_res[] = { EL_SYMKEY, EL_OTUT_STRING, EL_END };
static enum proto_el_id pkt_dec_sym_key_full_res[] = { EL_SYMKEY, EL_OTUT_STRING, EL_END };
static enum proto_el_id pkt_dec_sym_key_pod_err[] = { EL_END };
static enum proto_el_id pkt_dec_sym_key_pwd_err[] = { EL_END };
static enum proto_el_id pkt_dec_sym_key_auth_err[] = { EL_END };

/* KNP v2.1 */
static enum proto_el_id pkt_dec_sym_key_cmd_2_1[] = { EL_SIG_TEXT, EL_KEY_DATA, EL_INTER_SYMKEY_DATA,
                                                      EL_PASSWORD, EL_POD_FROM, EL_SUBJECT, EL_END };
static enum proto_el_id pkt_package_cmd_2_1[] = { EL_PKG_TYPE, EL_LANG, EL_TO, EL_CC, 
                                                  EL_RECIPIENT_ARRAY, EL_PASSWORD_ARRAY,
                                                  EL_FROM_NAME, EL_FROM_ADDRESS,
                                                  EL_SUBJECT,
                                                  EL_BODY_TYPE, EL_BODY_TEXT, EL_BODY_HTML,
                                                  EL_ATTACHMENT_ARRAY,
                                                  EL_POD_ADDRESS, EL_END };
static enum proto_el_id pkt_fail_upgrade_plugin[] = { EL_END };
static enum proto_el_id pkt_fail_upgrade_kps[] = { EL_END };

/* KNP v3.1 */
static enum proto_el_id pkt_login_user_cmd_3_1[] = 
    { EL_LOGIN_USERNAME, EL_LOGIN_PASSWORD, EL_LOGIN_IS_PASSWORD, EL_END };
static enum proto_el_id pkt_dec_sym_key_half_res_3_1[] = 
    { EL_SYMKEY, EL_OTUT_STRING, EL_POD_DATE, EL_END };
static enum proto_el_id pkt_dec_sym_key_full_res_3_1[] = 
    { EL_SYMKEY, EL_OTUT_STRING, EL_POD_DATE, EL_END };
static enum proto_el_id pkt_validate_otut_cmd[] = { EL_OTUT_STRING, EL_END };
static enum proto_el_id pkt_validate_otut_res[] = { EL_OTUT_USES, EL_END };
static enum proto_el_id pkt_login_ok_res_3_1[] = 
    { EL_LOGIN_TOKEN, EL_END };
static enum proto_el_id pkt_package_lic_cmd[] =
    { EL_PKG_TYPE, EL_LANG, EL_TO, EL_CC,
      EL_RECIPIENT_ARRAY, EL_PASSWORD_ARRAY,
      EL_FROM_NAME, EL_FROM_ADDRESS,
      EL_SUBJECT,
      EL_BODY_TYPE, EL_BODY_TEXT, EL_BODY_HTML,
      EL_ATTACHMENT_ARRAY,
      EL_POD_ADDRESS, 
      EL_LICENSE_LIM, EL_LICENSE_MAX, EL_LICENSE_KDN,
      EL_END };
static enum proto_el_id pkt_dec_sym_key_cmd_3_1[] =
    { EL_SIG_TEXT, EL_TM_KEY_DATA, EL_KEY_DATA, EL_INTER_SYMKEY_DATA,
      EL_PASSWORD, EL_POD_FROM, EL_SUBJECT, EL_END };
static enum proto_el_id pkt_get_sign_key_res_3_1[] =
    { EL_TM_KEY_DATA, EL_KEY_DATA, EL_OWNER_NAME, EL_END };

/** This is what was required for signed encryption keys. */
#if 0 // KEEP
static enum proto_el_id pkt_get_enc_key_res_3_1[] =
    { EL_TM_KEY_DATA, EL_KEY_DATA_ARRAY, EL_END };
static enum proto_el_id pkt_package_cmd_3_1[] =
    { EL_PKG_TYPE, EL_LANG, EL_TO, EL_CC,
      EL_RECIPIENT_ARRAY, EL_PASSWORD_ARRAY,
      EL_FROM_NAME, EL_FROM_ADDRESS,
      EL_SUBJECT,
      EL_BODY_TYPE, EL_BODY_TEXT, EL_BODY_HTML,
      EL_ATTACHMENT_ARRAY,
      EL_POD_ADDRESS, EL_END };
#endif

/* KNP v4.1 */
static enum proto_el_id pkt_get_enc_key_res_4_1[] = { EL_KEY_DATA_ARRAY, EL_SUBSCRIBER_ARRAY, EL_END };

static enum proto_el_id pkt_dec_sym_key_cmd_4_1[] =
    { EL_SIG_TEXT, EL_TM_KEY_DATA, EL_KEY_DATA, EL_INTER_SYMKEY_DATA,
      EL_PASSWORD, EL_POD_FROM, EL_SUBJECT, EL_WANT_DEC_EMAIL, EL_END };
static enum proto_el_id pkt_dec_sym_key_half_res_4_1[] = 
    { EL_SYMKEY, EL_OTUT_STRING, EL_POD_DATE, EL_DEC_EMAIL, EL_END };
static enum proto_el_id pkt_dec_sym_key_full_res_4_1[] = 
    { EL_SYMKEY, EL_OTUT_STRING, EL_POD_DATE, EL_DEC_EMAIL, EL_END };

static enum proto_el_id pkt_get_enc_key_by_id_cmd_4_1[] = { EL_KEYID, EL_END };
static enum proto_el_id pkt_get_enc_key_by_id_res_4_1[] =
    { EL_TM_KEY_DATA, EL_KEY_DATA, EL_OWNER_NAME, EL_END };

static enum proto_el_id pkt_get_kws_ticket_cmd_4_1[] = { EL_END };
static enum proto_el_id pkt_get_kws_ticket_res_4_1[] = { EL_KWS_TICKET, EL_END };

static enum proto_el_id pkt_convert_exchange_cmd_4_1[] = { EL_ADDRESS_ARRAY, EL_END };
static enum proto_el_id pkt_convert_exchange_res_4_1[] = { EL_ADDRESS_ARRAY, EL_END };
 
static enum proto_el_id pkt_get_user_info_res_4_1[] = 
    { EL_KEYID, 
      EL_DOMAINS_ARRAY, 
      EL_KPG_IS_USED,
      EL_KPG_HOSTNAME,
      EL_KPG_PORT,
      EL_END };
static enum proto_el_id pkt_package_err_4_1[] =
   { EL_PACKAGE_ERR, EL_END };


const char *proto_in_packet_names[PKT_IN_MAX] = {
    "NONE",
    "User login",
    "OTUT login",
    "Get Signature Key",
    "Get Encryption Key",
    "Get OTUT ticket",
    "Get OTUT string",
    "Get User Info",
    "Package Mail",
    "Decrypt Symmetric Key",
    "Package Mail (with license)",
    "Check OTUT",
    "Get Encryption Key by Key ID",
    "Workspace ticket request",
    "Convert Exchange address"
};

const char *proto_out_packet_names[PKT_OUT_MAX] = {
    "NONE",
    "Failed",
    "Login successful",
    "Got Signature Key",
    "Got Encryption Key",
    "Got OTUT ticket",
    "Got OTUT string",
    "Got User Info",
    "Packaged",
    "Half Decrypted Symmetric key",
    "Fully Decrypted Symmetric key",
    "PoD Error",
    "Password Error",
    "Authorization Error",
    "Upgrade Plugin Please",
    "Upgrade KPS Please",
    "Checked OTUT",
    "Packaging Failed",
    "Got Encryption Key by Key ID",
    "Workspace Ticket",
    "Converted Exchange Address",
};

int proto_ver_idx[PROTO_MAJOR_MAX + 1][PROTO_MINOR_MAX + 1] = 
    { { -1, /* MAJOR 0, MINOR 0 */
        -1, /* MAJOR 0, MINOR 1 */ },
      { -1, /* MAJOR 1, MINOR 0 */
        0,  /* MAJOR 1, MINOR 1 */ },
      { -1, /* MAJOR 2, MINOR 0 */
        1   /* MAJOR 2, MINOR 1 */ },
      { -1, /* MAJOR 3, MINOR 0 */ 
        2,  /* MAJOR 3, MINOR 1 */ },
      { -1, /* MAJOR 4, MINOR 0 */ 
        3,  /* MAJOR 4, MINOR 1 */ } };

/* KNP packet/type equivalence */
uint32_t proto_in_packet_match[PROTO_CNT][PKT_IN_MAX] = {
    { /* KNP v1.1 */
        0,                       /* PKT_NONE */
        KNP_CMD_LOGIN_USER,      /* PKT_LOGIN_USER_CMD */
        KNP_CMD_LOGIN_OTUT,      /* PKT_LOGIN_OTUT_CMD */
        KNP_CMD_GET_SIGN_KEY,    /* PKT_GET_SIGN_KEY_CMD */
        KNP_CMD_GET_ENC_KEY,     /* PKT_GET_ENC_KEY_CMD */        
        KNP_CMD_GET_OTUT_TICKET, /* PKT_GET_OTUT_TICKET_CMD */
        KNP_CMD_GET_OTUT_STRING, /* PKT_GET_OTUT_STRING_CMD */
        KNP_CMD_GET_USER_INFO,   /* PKT_GET_USER_INFO_CMD */
        KNP_CMD_PACKAGE_MAIL,    /* PKT_PACKAGE_CMD */
        KNP_CMD_DEC_SYM_KEY      /* PKT_DEC_SYM_KEY_CMD */
    },
    { /* KNP v2.1 */
        0,                       /* PKT_NONE */
        KNP_CMD_LOGIN_USER,      /* PKT_LOGIN_USER_CMD */
        KNP_CMD_LOGIN_OTUT,      /* PKT_LOGIN_OTUT_CMD */
        KNP_CMD_GET_SIGN_KEY,    /* PKT_GET_SIGN_KEY_CMD */
        KNP_CMD_GET_ENC_KEY,     /* PKT_GET_ENC_KEY_CMD */        
        KNP_CMD_GET_OTUT_TICKET, /* PKT_GET_OTUT_TICKET_CMD */
        KNP_CMD_GET_OTUT_STRING, /* PKT_GET_OTUT_STRING_CMD */
        KNP_CMD_GET_USER_INFO,   /* PKT_GET_USER_INFO_CMD */
        KNP_CMD_PACKAGE_MAIL,    /* PKT_PACKAGE_CMD */
        KNP_CMD_DEC_SYM_KEY      /* PKT_DEC_SYM_KEY_CMD */
    },
    { /* KNP v3.1 */
        0,
        KNP_CMD_LOGIN_USER,        /* PKT_LOGIN_USER_CMD */
        KNP_CMD_LOGIN_OTUT,        /* PKT_LOGIN_OTUT_CMD */
        KNP_CMD_GET_SIGN_KEY,      /* PKT_GET_SIGN_KEY_CMD */
        KNP_CMD_GET_ENC_KEY,       /* PKT_GET_ENC_KEY_CMD */        
        KNP_CMD_GET_OTUT_TICKET,   /* PKT_GET_OTUT_TICKET_CMD */
        KNP_CMD_GET_OTUT_STRING,   /* PKT_GET_OTUT_STRING_CMD */
        KNP_CMD_GET_USER_INFO,     /* PKT_GET_USER_INFO_CMD */
        KNP_CMD_PACKAGE_MAIL,      /* PKT_PACKAGE_CMD */
        KNP_CMD_DEC_SYM_KEY,       /* PKT_DEC_SYM_KEY_CMD */
        KNP_CMD_PACKAGE_LIC,       /* PKT_PACKAGE_LIC_CMD */
        KNP_CMD_VALIDATE_OTUT,     /* PKT_VALIDATE_OTUT_CMD */
    },
    { /* KNP v4.1 */
        0,
        KNP_CMD_LOGIN_USER,        /* PKT_LOGIN_USER_CMD */
        KNP_CMD_LOGIN_OTUT,        /* PKT_LOGIN_OTUT_CMD */
        KNP_CMD_GET_SIGN_KEY,      /* PKT_GET_SIGN_KEY_CMD */
        KNP_CMD_GET_ENC_KEY,       /* PKT_GET_ENC_KEY_CMD */        
        KNP_CMD_GET_OTUT_TICKET,   /* PKT_GET_OTUT_TICKET_CMD */
        KNP_CMD_GET_OTUT_STRING,   /* PKT_GET_OTUT_STRING_CMD */
        KNP_CMD_GET_USER_INFO,     /* PKT_GET_USER_INFO_CMD */
        KNP_CMD_PACKAGE_MAIL,      /* PKT_PACKAGE_CMD */
        KNP_CMD_DEC_SYM_KEY,       /* PKT_DEC_SYM_KEY_CMD */
        KNP_CMD_PACKAGE_LIC,       /* PKT_PACKAGE_LIC_CMD */
        KNP_CMD_VALIDATE_OTUT,     /* PKT_VALIDATE_OTUT_CMD */
	KNP_CMD_GET_ENC_KEY_BY_ID, /* PKT_GET_ENC_KEY_BY_ID_CMD */
    	KNP_CMD_GET_KWS_TICKET,    /* PKT_GET_KWS_TICKET_CMD */
	KNP_CMD_CONVERT_EXCHANGE,  /* PKT_CONVERT_EXCHANGE_CMD */
    }
};

/* The protocol matrix allow us to obtain what a specific packet
   should contain under a specific version of the protocol. */ 
enum proto_el_id *proto_in_matrix[PROTO_CNT][PKT_IN_MAX] = {
    { /* KNP v1.1 */
        NULL,
        pkt_login_user_cmd,      /* PKT_LOGIN_USER_CMD */
        pkt_login_otut_cmd,      /* PKT_LOGIN_OTUT_CMD */
        pkt_get_sign_key_cmd,    /* PKT_GET_SIGN_KEY_CMD */
        pkt_get_enc_key_cmd,     /* PKT_GET_ENC_KEY_CMD */
        pkt_get_otut_ticket_cmd, /* PKT_GET_OTUT_TICKET_CMD */
        pkt_get_otut_string_cmd, /* PKT_GET_OTUT_STRING_CMD */
        pkt_get_user_info_cmd,   /* PKT_GET_USER_INFO_CMD */
        pkt_package_cmd,         /* PKT_PACKAGE_CMD */
        pkt_dec_sym_key_cmd      /* PKT_DEC_SYM_KEY_CMD */
    },
    { /* KNP v2.1 */
        NULL,
        pkt_login_user_cmd,      /* PKT_LOGIN_USER_CMD */
        pkt_login_otut_cmd,      /* PKT_LOGIN_OTUT_CMD */
        pkt_get_sign_key_cmd,    /* PKT_GET_SIGN_KEY_CMD */
        pkt_get_enc_key_cmd,     /* PKT_GET_ENC_KEY_CMD */
        pkt_get_otut_ticket_cmd, /* PKT_GET_OTUT_TICKET_CMD */
        pkt_get_otut_string_cmd, /* PKT_GET_OTUT_STRING_CMD */
        pkt_get_user_info_cmd,   /* PKT_GET_USER_INFO_CMD */
        pkt_package_cmd_2_1,     /* PKT_PACKAGE_CMD */
        pkt_dec_sym_key_cmd_2_1  /* PKT_DEC_SYM_KEY_CMD */
    },
    { /* KNP v3.1 */
        NULL,
        pkt_login_user_cmd_3_1,     /* PKT_LOGIN_USER_CMD */
        pkt_login_otut_cmd,         /* PKT_LOGIN_OTUT_CMD */
        pkt_get_sign_key_cmd,       /* PKT_GET_SIGN_KEY_CMD */
        pkt_get_enc_key_cmd,        /* PKT_GET_ENC_KEY_CMD */
        pkt_get_otut_ticket_cmd,    /* PKT_GET_OTUT_TICKET_CMD */
        pkt_get_otut_string_cmd,    /* PKT_GET_OTUT_STRING_CMD */
        pkt_get_user_info_cmd,      /* PKT_GET_USER_INFO_CMD */
        pkt_package_cmd_2_1,        /* PKT_PACKAGE_CMD */
        pkt_dec_sym_key_cmd_3_1,    /* PKT_DEC_SYM_KEY_CMD */
        pkt_package_lic_cmd,        /* PKT_PACKAGE_LIC_CMD */
        pkt_validate_otut_cmd,      /* PKT_VALIDATE_OTUT_CMD */
    },
    { /* KNP v4.1 */
        NULL,
        pkt_login_user_cmd_3_1,        /* PKT_LOGIN_USER_CMD */
        pkt_login_otut_cmd,            /* PKT_LOGIN_OTUT_CMD */
        pkt_get_sign_key_cmd,          /* PKT_GET_SIGN_KEY_CMD */
        pkt_get_enc_key_cmd,           /* PKT_GET_ENC_KEY_CMD */
        pkt_get_otut_ticket_cmd,       /* PKT_GET_OTUT_TICKET_CMD */
        pkt_get_otut_string_cmd,       /* PKT_GET_OTUT_STRING_CMD */
        pkt_get_user_info_cmd,         /* PKT_GET_USER_INFO_CMD */
        pkt_package_cmd_2_1,           /* PKT_PACKAGE_CMD */
        pkt_dec_sym_key_cmd_4_1,       /* PKT_DEC_SYM_KEY_CMD */
        pkt_package_lic_cmd,           /* PKT_PACKAGE_LIC_CMD */
        pkt_validate_otut_cmd,         /* PKT_VALIDATE_OTUT_CMD */
	pkt_get_enc_key_by_id_cmd_4_1, /* PKT_GET_ENC_KEY_BY_ID_CMD */
    	pkt_get_kws_ticket_cmd_4_1,    /* PKT_GET_KWS_TICKET_CMD */
	pkt_convert_exchange_cmd_4_1,  /* PKT_CONVERT_EXCHANGE_CMD */
    }
};

uint32_t proto_out_packet_match[PROTO_CNT][PKT_OUT_MAX] = {
    { /* KNP v1.1 */
        0,                         /* PKT_NONE */
        KNP_RES_FAIL,              /* PKT_FAIL */
        KNP_RES_LOGIN_OK,          /* PKT_LOGIN_RES */
        KNP_RES_GET_SIGN_KEY,      /* PKT_GET_SIGN_KEY_RES */
        KNP_RES_GET_ENC_KEY,       /* PKT_GET_ENC_KEY_RES */
        KNP_RES_GET_OTUT_TICKET,   /* PKT_GET_OTUT_TICKET_RES */
        KNP_RES_GET_OTUT_STRING,   /* PKT_GET_OTUT_STRING_RES */
        KNP_RES_GET_USER_INFO,     /* PKT_GET_USER_INFO_RES */
        KNP_RES_PACKAGE_MAIL,      /* PKT_PACKAGE_RES */
        KNP_RES_DEC_KEY_HALF,      /* PKT_DEC_SYM_KEY_HALF_RES */
        KNP_RES_DEC_KEY_FULL,      /* PKT_DEC_SYM_KEY_FULL_RES */
        KNP_RES_DEC_KEY_POD_ERROR, /* PKT_DEC_SYM_KEY_POD_ERR */
        KNP_RES_DEC_KEY_BAD_PWD,   /* PKT_DEC_SYM_KEY_PWD_ERR */
        KNP_RES_DEC_KEY_NOT_AUTH   /* PKT_DEC_SYM_KEY_AUTH_ERR */
    },
    { /* KNP v1.2 */
        0,                         /* PKT_NONE */
        KNP_RES_FAIL,              /* PKT_FAIL */
        KNP_RES_LOGIN_OK,          /* PKT_LOGIN_RES */
        KNP_RES_GET_SIGN_KEY,      /* PKT_GET_SIGN_KEY_RES */
        KNP_RES_GET_ENC_KEY,       /* PKT_GET_ENC_KEY_RES */
        KNP_RES_GET_OTUT_TICKET,   /* PKT_GET_OTUT_TICKET_RES */
        KNP_RES_GET_OTUT_STRING,   /* PKT_GET_OTUT_STRING_RES */
        KNP_RES_GET_USER_INFO,     /* PKT_GET_USER_INFO_RES */
        KNP_RES_PACKAGE_MAIL,      /* PKT_PACKAGE_RES */
        KNP_RES_DEC_KEY_HALF,      /* PKT_DEC_SYM_KEY_HALF_RES */
        KNP_RES_DEC_KEY_FULL,      /* PKT_DEC_SYM_KEY_FULL_RES */
        KNP_RES_DEC_KEY_POD_ERROR, /* PKT_DEC_SYM_KEY_POD_ERR */
        KNP_RES_DEC_KEY_BAD_PWD,   /* PKT_DEC_SYM_KEY_PWD_ERR */
        KNP_RES_DEC_KEY_NOT_AUTH,  /* PKT_DEC_SYM_KEY_AUTH_ERR */
        KNP_RES_UPGRADE_PLUGIN,    /* PKT_FAIL_UPGRADE_PLUGIN */
        KNP_RES_UPGRADE_KPS        /* PKT_FAIL_UPGRATE_KPS */
    },
    { /* KNP v3.1 */
        0,                         /* PKT_NONE */
        KNP_RES_FAIL,              /* PKT_FAIL */
        KNP_RES_LOGIN_OK,          /* PKT_LOGIN_RES */
        KNP_RES_GET_SIGN_KEY,      /* PKT_GET_SIGN_KEY_RES */
        KNP_RES_GET_ENC_KEY,       /* PKT_GET_ENC_KEY_RES */
        KNP_RES_GET_OTUT_TICKET,   /* PKT_GET_OTUT_TICKET_RES */
        KNP_RES_GET_OTUT_STRING,   /* PKT_GET_OTUT_STRING_RES */
        KNP_RES_GET_USER_INFO,     /* PKT_GET_USER_INFO_RES */
        KNP_RES_PACKAGE_MAIL,      /* PKT_PACKAGE_RES */
        KNP_RES_DEC_KEY_HALF,      /* PKT_DEC_SYM_KEY_HALF_RES */
        KNP_RES_DEC_KEY_FULL,      /* PKT_DEC_SYM_KEY_FULL_RES */
        KNP_RES_DEC_KEY_POD_ERROR, /* PKT_DEC_SYM_KEY_POD_ERR */
        KNP_RES_DEC_KEY_BAD_PWD,   /* PKT_DEC_SYM_KEY_PWD_ERR */
        KNP_RES_DEC_KEY_NOT_AUTH,  /* PKT_DEC_SYM_KEY_AUTH_ERR */
        KNP_RES_UPGRADE_PLUGIN,    /* PKT_FAIL_UPGRADE_PLUGIN */
        KNP_RES_UPGRADE_KPS,       /* PKT_FAIL_UPGRATE_KPS */
        KNP_RES_VALIDATE_OTUT,     /* PKT_VALIDATE_OTUT_RES */
    },        
    { /* KNP v4.1 */
        0,                         /* PKT_NONE */
        KNP_RES_FAIL,              /* PKT_FAIL */
        KNP_RES_LOGIN_OK,          /* PKT_LOGIN_RES */
        KNP_RES_GET_SIGN_KEY,      /* PKT_GET_SIGN_KEY_RES */
        KNP_RES_GET_ENC_KEY,       /* PKT_GET_ENC_KEY_RES */
        KNP_RES_GET_OTUT_TICKET,   /* PKT_GET_OTUT_TICKET_RES */
        KNP_RES_GET_OTUT_STRING,   /* PKT_GET_OTUT_STRING_RES */
        KNP_RES_GET_USER_INFO,     /* PKT_GET_USER_INFO_RES */
        KNP_RES_PACKAGE_MAIL,      /* PKT_PACKAGE_RES */
        KNP_RES_DEC_KEY_HALF,      /* PKT_DEC_SYM_KEY_HALF_RES */
        KNP_RES_DEC_KEY_FULL,      /* PKT_DEC_SYM_KEY_FULL_RES */
        KNP_RES_DEC_KEY_POD_ERROR, /* PKT_DEC_SYM_KEY_POD_ERR */
        KNP_RES_DEC_KEY_BAD_PWD,   /* PKT_DEC_SYM_KEY_PWD_ERR */
        KNP_RES_DEC_KEY_NOT_AUTH,  /* PKT_DEC_SYM_KEY_AUTH_ERR */
        KNP_RES_UPGRADE_PLUGIN,    /* PKT_FAIL_UPGRADE_PLUGIN */
        KNP_RES_UPGRADE_KPS,       /* PKT_FAIL_UPGRATE_KPS */
        KNP_RES_VALIDATE_OTUT,     /* PKT_VALIDATE_OTUT_RES */
	KNP_RES_PACKAGE_FAIL,	   /* PKT_PACKAGE_ERR */
	KNP_RES_GET_ENC_KEY_BY_ID, /* PKT_GET_ENC_KEY_BY_ID_RES */
    	KNP_RES_GET_KWS_TICKET,    /* PKT_GET_KWS_TICKET_RES */
	KNP_RES_CONVERT_EXCHANGE,  /* PKT_CONVERT_EXCHANGE_RES */
    }        
};

enum proto_el_id *proto_out_matrix[PROTO_CNT][PKT_OUT_MAX] = {
    { /* KNP v1.1 */
        NULL,                      /* PKT_NONE */
        pkt_fail_res,              /* PKT_FAIL */
        pkt_login_ok_res,          /* PKT_LOGIN_RES */
        pkt_get_sign_key_res,      /* PKT_GET_SIGN_KEY_RES */
        pkt_get_enc_key_res,       /* PKT_GET_ENC_KEY_RES */
        pkt_get_otut_ticket_res,   /* PKT_GET_OTUT_TICKET_RES */
        pkt_get_otut_string_res,   /* PKT_GET_OTUT_STRING_RES */
        pkt_get_user_info_res,     /* PKT_GET_USER_INFO_RES */
        pkt_package_res,           /* PKT_PACKAGE_RES */
        pkt_dec_sym_key_half_res,  /* PKT_DEC_SYM_KEY_HALF_RES */
        pkt_dec_sym_key_full_res,  /* PKT_DEC_SYM_KEY_FULL_RES */
        pkt_dec_sym_key_pod_err,   /* PKT_DEC_SYM_KEY_POD_ERR */
        pkt_dec_sym_key_pwd_err,   /* PKT_DEC_SYM_KEY_PWD_ERR */
        pkt_dec_sym_key_auth_err   /* PKT_DEC_SYM_KEY_AUTH_ERR */
    },
    { /* KNP v2.1 */
        NULL,                      /* PKT_NONE */
        pkt_fail_res,              /* PKT_FAIL */
        pkt_login_ok_res,          /* PKT_LOGIN_RES */
        pkt_get_sign_key_res,      /* PKT_GET_SIGN_KEY_RES */
        pkt_get_enc_key_res,       /* PKT_GET_ENC_KEY_RES */
        pkt_get_otut_ticket_res,   /* PKT_GET_OTUT_TICKET_RES */
        pkt_get_otut_string_res,   /* PKT_GET_OTUT_STRING_RES */
        pkt_get_user_info_res,     /* PKT_GET_USER_INFO_RES */
        pkt_package_res,           /* PKT_PACKAGE_RES */
        pkt_dec_sym_key_half_res,  /* PKT_DEC_SYM_KEY_HALF_RES */
        pkt_dec_sym_key_full_res,  /* PKT_DEC_SYM_KEY_FULL_RES */
        pkt_dec_sym_key_pod_err,   /* PKT_DEC_SYM_KEY_POD_ERR */
        pkt_dec_sym_key_pwd_err,   /* PKT_DEC_SYM_KEY_PWD_ERR */
        pkt_dec_sym_key_auth_err,  /* PKT_DEC_SYM_KEY_AUTH_ERR */
        pkt_fail_upgrade_plugin,   /* PKT_FAIL_UPGRADE_PLUGIN */
        pkt_fail_upgrade_kps       /* PKT_FAIL_UPGRADE_KPS */
    },
    { /* KNP v3.1 */
        NULL,                          /* PKT_NONE */
        pkt_fail_res,                  /* PKT_FAIL */
        pkt_login_ok_res_3_1,          /* PKT_LOGIN_RES */
        pkt_get_sign_key_res_3_1,      /* PKT_GET_SIGN_KEY_RES */
        pkt_get_enc_key_res,           /* PKT_GET_ENC_KEY_RES */
        pkt_get_otut_ticket_res,       /* PKT_GET_OTUT_TICKET_RES */
        pkt_get_otut_string_res,       /* PKT_GET_OTUT_STRING_RES */
        pkt_get_user_info_res,         /* PKT_GET_USER_INFO_RES */
        pkt_package_res,               /* PKT_PACKAGE_RES */
        pkt_dec_sym_key_half_res_3_1,  /* PKT_DEC_SYM_KEY_HALF_RES */
        pkt_dec_sym_key_full_res_3_1,  /* PKT_DEC_SYM_KEY_FULL_RES */
        pkt_dec_sym_key_pod_err,       /* PKT_DEC_SYM_KEY_POD_ERR */
        pkt_dec_sym_key_pwd_err,       /* PKT_DEC_SYM_KEY_PWD_ERR */
        pkt_dec_sym_key_auth_err,      /* PKT_DEC_SYM_KEY_AUTH_ERR */
        pkt_fail_upgrade_plugin,       /* PKT_FAIL_UPGRADE_PLUGIN */
        pkt_fail_upgrade_kps,          /* PKT_FAIL_UPGRADE_KPS */
        pkt_validate_otut_res,         /* PKT_VALIDATE_OTUT_RES */
    },  
    { /* KNP v4.1 */
        NULL,                          /* PKT_NONE */
        pkt_fail_res,                  /* PKT_FAIL */
        pkt_login_ok_res_3_1,          /* PKT_LOGIN_RES */
        pkt_get_sign_key_res_3_1,      /* PKT_GET_SIGN_KEY_RES */
        pkt_get_enc_key_res_4_1,       /* PKT_GET_ENC_KEY_RES */
        pkt_get_otut_ticket_res,       /* PKT_GET_OTUT_TICKET_RES */
        pkt_get_otut_string_res,       /* PKT_GET_OTUT_STRING_RES */
        pkt_get_user_info_res_4_1,     /* PKT_GET_USER_INFO_RES */
        pkt_package_res,               /* PKT_PACKAGE_RES */
        pkt_dec_sym_key_half_res_4_1,  /* PKT_DEC_SYM_KEY_HALF_RES */
        pkt_dec_sym_key_full_res_4_1,  /* PKT_DEC_SYM_KEY_FULL_RES */
        pkt_dec_sym_key_pod_err,       /* PKT_DEC_SYM_KEY_POD_ERR */
        pkt_dec_sym_key_pwd_err,       /* PKT_DEC_SYM_KEY_PWD_ERR */
        pkt_dec_sym_key_auth_err,      /* PKT_DEC_SYM_KEY_AUTH_ERR */
        pkt_fail_upgrade_plugin,       /* PKT_FAIL_UPGRADE_PLUGIN */
        pkt_fail_upgrade_kps,          /* PKT_FAIL_UPGRADE_KPS */
        pkt_validate_otut_res,         /* PKT_VALIDATE_OTUT_RES */
	pkt_package_err_4_1,	       /* PKT_PACKAGE_ERR */
	pkt_get_enc_key_by_id_res_4_1, /* PKT_GET_ENC_KEY_BY_ID_RES */
    	pkt_get_kws_ticket_res_4_1,    /* PKT_GET_KWS_TICKET_RES */
	pkt_convert_exchange_res_4_1,  /* PKT_CONVERT_EXCHANGE_RES */
    }  
};
