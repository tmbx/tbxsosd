/**
 * tbxsosd/decrypt.h
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
 * Teambox Sign-On Sever Daemon message processing informations structure and
 * functions.
 *
 * @author François-Denis Gonthier
*/

#ifndef _DPKG_H
#define _DPKG_H

/** Allocate memory for the parameter object. */
struct kd_dpkg *kd_dpkg_new();

/** Allocate memory for the decryption result object. */
struct kd_decrypted *kd_decrypted_new(apr_pool_t *pool);

/** Set the intermediate symmetric key for final decryption. */
int kddpkg_set_symkey(struct kd_dpkg *self, const char *symkey, size_t symkey_s);

/** Set the decryption password. */
int kddpkg_set_password(struct kd_dpkg *self, const char *pwd, size_t pwd_s);

/** Set the signature object for descryption. 
 * 
 * Overwrites the signature object currently set, so there is no leak
 * if called more than once.
 */ 
int kddpkg_set_signature(struct kd_dpkg *self,
                         const char *sig_str, size_t sig_str_s);

/** Decrypt the message with the parameters put in the kd_dpkg
    structure. */
enum kd_dpkg_result kddpkg_decrypt(struct kd_dpkg *dpkg, 
                                   struct kd_user *user, 
                                   struct kd_decrypted *dec);

/** De-PoD the message with the parameters put in the kd_dpkg
    structure. */
enum kd_dpkg_result kddpkg_depod(struct kd_dpkg *self, 
                                 struct kd_decrypted *dec);

#endif // _DPKG_H
