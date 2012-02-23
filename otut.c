/**
 * tbxsosd/otut.c
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
 * High level OTUT management.
 *
 * @author François-Denis Gonthier
*/

#include <assert.h>
#include <apr_strings.h>
#include <apr_pools.h>
#include <tagcryptsignature.h>
#include <tagcryptotut.h>
#include <kerror.h>

#include "config.h"
#include "common.h"
#include "logid.h"
#include "otut.h"
#include "keys.h"

#define OTUT_DEFAULT_ATTEMPTS 5

#ifdef REQUEST_OTUT
/** Crack a ticket, check its signature and validity vs. the DB. */
int otut_extract_ticket(apr_pool_t *ticket_pool, 
                        const char *ticket_str,
                        size_t ticket_str_s,
                        struct tagcrypt_ticket **ticket) {
    int error = -1;
    uint64_t tkt_keyid;
    kbuffer *signed_tkt_buf;
    struct kdkey_info *tkt_pkey;
    apr_pool_t *pool;
        
    // FIXME: Make sure this may or may not fail. */
    tkt_keyid = tagcrypt_signature_get_keyid(ticket_str, ticket_str_s);
    
    apr_pool_create(&pool, ticket_pool);

    /* Fetch the key for the ticket. */
    if (kdkey_get_sig_pkey(pool, tkt_keyid, &tkt_pkey) <= 0) {
        KERROR_PUSH(_otut_, 0, "failed to fetch key for ticket");
        return -1;
    }

    signed_tkt_buf = kbuffer_new();

    do {
        /* Write the ticket data in the signed ticket buffer for
           conversion. */
        kbuffer_write(signed_tkt_buf, (uint8_t *)ticket_str, ticket_str_s);

        *ticket = apr_pcalloc(ticket_pool, sizeof(struct tagcrypt_ticket));
	tagcrypt_ticket_init(*ticket);

        if (tagcrypt_get_ticket(tkt_pkey->key, signed_tkt_buf, *ticket) < 0) {
            KERROR_SET(_otut_, 0, "failed to extract ticket");
            break;
        }
        
        /* Validate the ticket with the DB. */
        if (kddb_otut_ticket_store(tkt_keyid, &(*ticket)->tv) < 0) {
            KERROR_PUSH(_otut_, 0, "the ticket has been refused by the database");
            break;
        }
	
	error = 0;

    } while (0);

    kbuffer_destroy(signed_tkt_buf);
    apr_pool_destroy(pool);

    return error;
}
#endif // REQUEST_OTUT

#ifdef REQUEST_OTUT
/** Prepare the reply to an OTUT request. */
int otut_gen_otuts(apr_pool_t *pool, 
                   struct tagcrypt_ticket *ticket,
                   uint32_t otut_count,
                   uint32_t *otut_replies,
                   char ***otut_str,
                   size_t **otut_str_s) {
    size_t i;
    kbuffer *otut_str_buf;
    struct tagcrypt_otut otut;
    int nb_attempts;
    int nb_tries;

    /* Allocate the string array. */
    *otut_str = apr_pcalloc(pool, otut_count * sizeof(char *));
    *otut_str_s = apr_pcalloc(pool, otut_count * sizeof(size_t));

    /* Produce all the required OTUTs. */
    for (i = 0; i < otut_count; i++) {
	int error = -1;
	
        do {       
            /* Generate the OTUT string. */
            tagcrypt_otut_init(&otut);

            if (tagcrypt_gen_otut(ticket, &otut) < 0) {
                KERROR_SET(_otut_, 0, "failed to generate OTUT");
                tagcrypt_otut_clean(&otut);
                break;
            }

            otut_str_buf = kbuffer_new();
            tagcrypt_otut_serialize(&otut, otut_str_buf);
            
            /* Copy the newly serialized string locally. */
            (*otut_str)[i] = apr_pcalloc(pool, otut_str_buf->len);
            (*otut_str_s)[i] = otut_str_buf->len;
            memcpy((*otut_str)[i], otut_str_buf->data, (*otut_str_s)[i]);
            
            /* Store the OTUT string in the DB. */
            nb_attempts = otut_replies[i];
            nb_tries = OTUT_DEFAULT_ATTEMPTS * nb_attempts;

            if (kddb_otut_store((*otut_str)[i],
                                (*otut_str_s)[i],
                                ticket->mid,
                                nb_attempts, 
                                nb_tries) < 0) 
                KERROR_PUSH(_otut_, 0, "failed to store OTUT");            

            tagcrypt_otut_clean(&otut);
            kbuffer_destroy(otut_str_buf);
	    
	    error = 0;

        } while (0);                
	
	if (error) return -1;
    }

    return 0;
}
#endif // REQUEST_OTUT

/* Generate a ticket for the user.
 *
 * FIXME: This is a insult to the gods software engineering.  There should not be
 * any calls to tagcrypt from here.  It should be in a seperate module. 
 */
#ifdef REQUEST_TICKET
int otut_gen_ticket(apr_pool_t *parent_pool,
                    struct kd_user *self, 
                    uint32_t nb_valid, 
                    const char *otut_addr, 
                    kbuffer *sign_buf) {    
    int error = -1;
    char *real_addr;
    kbuffer skey_buffer;
    kbuffer *otut_addr_buf = NULL;
    tagcrypt_skey *skey = NULL;
    int is_allowed;
    apr_pool_t *pool;
    int err;
    kstr str;

    /* Check if there is a key. */
    assert(self->sig_skey->key_id != 0);

    apr_pool_create(&pool, parent_pool);

    do {
        /* Make sure the OTUT address is an SMTP address. */
        if (otut_addr[0] != '/') real_addr = (char *)otut_addr;

        /* it's not? well, convert it. */
        else if (kddb_convert_address(pool, 
                                      otut_addr, 
                                      self->primary_email_addr, 
                                      &real_addr) < 0) {
            KERROR_PUSH(_db_, 0, "failed to convert %s to SMTP address.", otut_addr);
            break;
        } 

        /* Check if the user owns the address he is asking the user to
           answer to.  This disallows potential freebies. */
        if (kddb_is_email_allowed(pool, self, real_addr, &is_allowed, NULL) < 0) {
            KERROR_PUSH(_db_, 0, "failed to check if the email address is allowable");
            break;
        }            
        if (!is_allowed) {
            KERROR_SET(_db_, 0, "user is not allowed to request a ticket for the address %s", 
                               real_addr);
            break;
        }

        /* Put the key in a buffer. */
        kstr_init_cstr(&str, self->sig_skey->data);
        err = kbuffer_init_b64(&skey_buffer, &str);
        kstr_clean(&str);
        if (err != 0) {
            KERROR_PUSH(_db_, 0, "failed to convert the key to binary format from base64");
            kbuffer_clean(&skey_buffer);
            break;
        }
            
        /* Instanciate the private signature key. */    
        if ((skey = tagcrypt_skey_new(&skey_buffer)) == NULL) {
            KERROR_SET(_db_, 0, "failed to instanciate key");
            kbuffer_clean(&skey_buffer);
            break;
        }
        kbuffer_clean(&skey_buffer);
    
        /* Make a buffer for the address to keep tagcrypt happy. */
        otut_addr_buf = kbuffer_new();
        kbuffer_write(otut_addr_buf, (uint8_t *)real_addr, strlen(real_addr));
        
        /* Generate the ticket. */
        if (tagcrypt_gen_ticket(skey, nb_valid, otut_addr_buf, sign_buf) < 0) {
            KERROR_SET(_db_, 0, "failed to produce ticket");
            break;
        }
	
	error = 0;
	
    } while (0);

    /* Cleanup. */
    if (otut_addr_buf != NULL) kbuffer_destroy(otut_addr_buf);
    if (skey != NULL)          tagcrypt_skey_destroy(skey);

    return error;
}
#endif // REQUEST_TICKET

#ifdef REQUEST_OTUT_LOGIN
/** Check if a recipient is valid. 
 *
 * Returns 1 if the passed address correspond to the address allowed
 * in the OTUT.
 */
int otut_check_address(struct kd_user *self, const char *addr, const size_t addr_s) {

    if (self->otut_info->otut->addr->len == 0) 
        return -1;

    if (addr_s != self->otut_info->otut->addr->len)
        return -1;

    return strncasecmp(addr, (char *)self->otut_info->otut->addr->data, addr_s) == 0 ? 0 : -1;
}
#endif // REQUEST_OTUT_LOGIN
