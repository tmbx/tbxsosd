/**
 * tbxsosd/dpkg.c
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
 * Teambox Sign-On Server Daemon depackaging functions.
 * 
 * This file mostly includes the setters used to insert object
 * in the parameters structure.  The interresting code is in the 
 * decrypt.c and depod.c files.
 *
 * @author François-Denis Gonthier
*/

#include <apr_pools.h>
#include <assert.h>
#include <tagcrypt.h>
#include <kerror.h>
#include <tagcrypt.h>

#include "common_dpkg.h"
#include "common_keys.h"
#include "common.h"

#include "config.h"
#include "db.h"
#include "dpkg.h"
#include "keys.h"
#include "logid.h"
#include "logging.h"
#include "options.h"

/* This whole file is useless unless those requests are defined. */
#if defined(REQUEST_GUEST_DECRYPT) || defined(REQUEST_KEY_DECRYPT)

/** Cleanup the internally allocated objects. */
static apr_status_t kddpkg_delete(void *data) {
    struct kd_dpkg *self = (struct kd_dpkg *)data;

    if (self->sign != NULL)
        tagcrypt_sign_destroy(self->sign);

    return APR_SUCCESS;
}

/** Decryption object constructor. */
struct kd_dpkg *kd_dpkg_new(apr_pool_t *pool) {
    struct kd_dpkg *self;

    /* Allocate memory for the object. */
    self = apr_pcalloc(pool, sizeof(struct kd_dpkg));
    self->pool = pool;
    apr_pool_cleanup_register(pool, self, kddpkg_delete, kddpkg_delete);

    return self;
}

/** Decryption object destructor. */
static apr_status_t kd_decrypted_delete(void *data) {
    struct kd_decrypted *self = (struct kd_decrypted *)data;

    if (self->symkey_out != NULL)
        kbuffer_destroy(self->symkey_out);

    if (self->password != NULL)
        kbuffer_destroy(self->password);

    if (self->symkey != NULL)
        kbuffer_destroy(self->symkey);
    
    if (self->otut_buf != NULL)
        kbuffer_destroy(self->otut_buf);

    return APR_SUCCESS;
}

/** Decryption result object constructor. */
struct kd_decrypted *kd_decrypted_new(apr_pool_t *pool) {
    struct kd_decrypted *self;

    self = apr_pcalloc(pool, sizeof(struct kd_decrypted));
    self->pool = pool;
    self->dec_email = "";
    apr_pool_cleanup_register(pool, self, kd_decrypted_delete, kd_decrypted_delete);

    return self;
}

/** Set the signature object of a decryption object. */
int kddpkg_set_signature(struct kd_dpkg *self, const char *sig_str, size_t sig_str_s) {
    int err;
    kbuffer sign_buf;
    kstr str;

    /* Destroy the existing signature if there is one. */
    if (self->sign != NULL)
        tagcrypt_sign_destroy(self->sign);
   
    kstr_init_buf(&str, sig_str, sig_str_s);
    err = kbuffer_init_b64(&sign_buf, &str);
    kstr_clean(&str);

    if (err) 
        KERROR_SET(_dpkg_, 0, "failed to create signature object");
    else {
        self->sign = tagcrypt_signature_new_serialized(&sign_buf, self->sender_sig_pkey->key);
    
        if (self->sign == NULL)  {
            KERROR_SET(_dpkg_, 0, "failed to create signature object");
	    err = -1;
	}

        kbuffer_clean(&sign_buf);
    }

    return err;
}

enum kd_dpkg_result kddpkg_decrypt(struct kd_dpkg *self, 
                                   struct kd_user *uobj,
                                   struct kd_decrypted *dec) {
    int is_allowed = 0;
    kbuffer *symkey_dest = NULL;
    kbuffer *password_buf = NULL;
    struct tagcrypt_otut otut;
    enum kd_dpkg_result res = DPKG_ERROR;

    /* If there is a password provided, we consider that the user is not a member
       and we try the password. */

    do {
        /* Those assertions are programming errors.  The presence of
           NULL date should be catched earlier in the decryption
           process. */

        /* Asserts the presence of a signature. */
        assert(self->sign != NULL);

        /* Asserts the presence of something to decrypt with. */
        assert(!(self->password_str == NULL && 
                 self->recver_enc_skey == NULL &&
                 self->sender_sig_skey == NULL));

        /* Asserts the presence of a sender signature key for password
           decryption. */
        assert(!(self->password_str != NULL && self->sender_sig_skey == NULL));

        /* Assert the absence of a password and the presence of a key
           for key decryption. */
        assert(!(self->password_str == NULL && self->recver_enc_skey == NULL));
        
        /* Check if the signature needs to be depackaged. */
        if (self->sign->type == TAG_P_TYPE_SIGN) {
            KERROR_SET(_dpkg_, 0, "signature does not contain any symetric key");
            break;
        }

        /* Create the buffers. */
        dec->symkey_out = kbuffer_new();
        dec->otut_buf = kbuffer_new();
        symkey_dest = kbuffer_new();

        do {
            tagcrypt_otut_init(&otut);

            /* Check if we do password decryption. */
            if (self->password_str != NULL) {
                /* Prepare a buffer for the password. */
                password_buf = kbuffer_new();
                kbuffer_write(password_buf, 
                              (uint8_t *)self->password_str, 
                              self->password_str_s);

                if (tagcrypt_sign_check_passwd(self->sign,
                                               self->sender_sig_skey->key,
                                               password_buf,
                                               &otut) < 0) {
                    res = DPKG_BAD_PWD;
                    kbuffer_destroy(password_buf);
                    break;
                }

                kbuffer_destroy(password_buf);

                /* At this point, the password provided matches one in the signature.
                   Grab the symmetric key. */
                if (tagcrypt_sign_get_snd_symkey(self->sign,
                                                 self->sender_sig_skey->key,
                                                 dec->symkey_out) < 0) {
                    KERROR_SET(_dpkg_, 0, 
                               "failed to get the sender symmetric "
                               "key from the signature");
                    break;           
                }               

                /* In the case of non-members, tagcrypt is able to do all the required
                   work by itself. */
                res = DPKG_FULL;
            }
            /* There is no password, the user is expect to be a member. */
            else {
	    	int always_decrypt;
		
                if (tagcrypt_sign_get_enc_symkey(self->sign,
                                                 self->recver_enc_skey->key,
                                                 dec->symkey_out,
                                                 symkey_dest) < 0) {
                    KERROR_SET(_dpkg_, 0, 
                               "failed to get the symmetric "
                               "key from the signature");
                    break;
                }

                /* Null terminate the string since we need to display
                   it. */
                kbuffer_write8(symkey_dest, 0);

                /* We got the encryption key.  Check if the user is allowed to receive it. */
                always_decrypt = options_get_bool("server.always_decrypt");
		if (!always_decrypt) {
	    	    
		    DEBUG(_log_client_, "List of address allowed to decrypt: %s", symkey_dest->data);
		    
		    if (kddb_is_email_allowed(self->pool, uobj,
                                              (char *)symkey_dest->data, 
                                              &is_allowed,
                                              &dec->dec_email) < 0) {
                	KERROR_PUSH(_dpkg_, 0, 
                                    "error while check if the user is "
                                    "allowed to decrypt the mail");
                	break;
                    }

                    /* If the user is not allowed to decrypt the email, return as so. */
                    if (!is_allowed) {
                	res = DPKG_NOT_ALLOWED;
                	break;
                    }
		}
		
		else {
		    DEBUG(_log_client_, "Allowing decryption unconditionally.");
		}
                       
                /* Check if the key we received is partial or complete. */
                if (self->sign->type == TAG_P_TYPE_PODNENC) 
                    res = DPKG_PARTIAL;              
                else if (self->sign->type == TAG_P_TYPE_ENC) 
                    res = DPKG_FULL;            
            }   

            /* Return the symmetric key. */
            dec->symkey_str = (char *)dec->symkey_out->data;
            dec->symkey_str_s = dec->symkey_out->len;

            /* Convert the OTUT to a string. */
            if (otut.addr->len > 0) {
                if (tagcrypt_otut_serialize(&otut, dec->otut_buf) < 0) {
                    KERROR_SET(_dpkg_, 0, "failed to prepare OTUT");
                    break;
                }

                dec->otut_str = (char *)dec->otut_buf->data,
                dec->otut_str_s = dec->otut_buf->len;
            }
            /* Set the OTUT strings to empty. */
            else {
                dec->otut_str = NULL;
                dec->otut_str_s = 0;
            }
        } while (0);

        tagcrypt_otut_clean(&otut);

    } while (0);

    if (symkey_dest != NULL) kbuffer_destroy(symkey_dest);

    return res;
}

enum kd_dpkg_result kddpkg_depod(struct kd_dpkg *self, 
                                 struct kd_decrypted *dec) {
    enum kd_dpkg_result res = DPKG_ERROR;

    do {
        /* Check the presence of all we need. */
        if (self->sign == NULL) {
            KERROR_SET(_dpkg_, 0, "no signature provided?!?");
            break;
        }
        if (self->sign->type == TAG_P_TYPE_PODNENC && self->symkey_str == NULL) {
            KERROR_SET(_dpkg_, 0, "no encrypted symmetric key provided");
            break;
        }

        /* Create buffers for symkey extraction. */
        dec->symkey_out = kbuffer_new();

        /* Special handling is needed depending on the type of signature
           we received. */
        if (self->sign->type == TAG_P_TYPE_POD) {
            if (tagcrypt_sign_get_snd_symkey(self->sign, self->sender_sig_skey->key,
                                             dec->symkey_out) < 0) {
                KERROR_SET(_dpkg_, 0, "failed to get sender symetric key from the signature");
                break;
            }
        } 
        else if (self->sign->type == TAG_P_TYPE_PODNENC) {
            if (tagcrypt_sign_get_symkey(self->sign, 
                                         self->sender_sig_skey->key, 
                                         dec->symkey,
                                         dec->symkey_out) < 0) {
                KERROR_SET(_dpkg_, 0, 
                           "failed to get sender encryption "
                           "symetric key from the signature");
                break;
            }
        }

        dec->symkey_str = (char *)dec->symkey_out->data;
        dec->symkey_str_s = dec->symkey_out->len;

        res = DPKG_FULL;

    } while (0);

    return res;
}

#endif // REQUEST_GUEST_DECRYPT || REQUEST_KEY_DECRYPT
