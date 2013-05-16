/**
 * tbxsosd/crypto_proto_str.h
 * Copyright (C) 2012 Opersys inc.
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
