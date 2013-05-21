/**
 * tbxsosd/crypto_proto_str.h
 * Copyright (C) 2012 Opersys inc.
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
 * Header and footer for the "Kryptiva" cryptographic protocol
 */

/* FIXME: Better langage support is needed here. */

#ifndef _CRYPTO_PROTO_STR_H
#define _CRYPTO_PROTO_STR_H

/* Kryptiva message tags. */
#define KRYPTIVA_SIGNED_BODY_START \
    "----- KRYPTIVA PACKAGED MESSAGE -----\nPACKAGING TYPE: SIGNED\n"

#define KRYPTIVA_SIGN_START \
    "----- KRYPTIVA SIGNATURE START -----"

#define KRYPTIVA_SIGN_END \
    "----- KRYPTIVA SIGNATURE END -----"

#define KRYPTIVA_START                          \
    "----- KRYPTIVA SIGNED MESSAGE -----\n"                             
    
#define KRYPTIVA_INFO_EN                                                \
    "This email packaged using Kryptiva protocol, the"                  \
    "security system underneath the Teambox(R) suite.\n"                \
    "For more information, visit: http://www.teambox.co\n"

#define KRYPTIVA_INFO_SEP "--\n"                                                              

#define KRYPTIVA_INFO_FR                                                \
    "Ce courriel assemblé par le protocole Kryptiva, le"                \
    "système de sécurité utilisé par la suite Teambox(R).\n"            \
    "Pour plus d'info, visitez: http://www.teambox.co\n"

#define KRYPTIVA_ENC_BODY_START \
    "----- KRYPTIVA ENCRYPTED DATA START -----"

#define KRYPTIVA_ENC_BODY_END \
    "----- KRYPTIVA ENCRYPTED DATA END -----"

#define KRYPTIVA_SIG_MAX_LINE_LEN      72

#endif // _CRYPTO_PROTO_STR_H */
