/**
 * tbxsosd/decrypt.h
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
