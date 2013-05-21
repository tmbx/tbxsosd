/**
 * tbxsosd/client_req_kws.c
 * Copyright (C) 2008-2012 Opersys inc.
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
 * Supply workspace tickets.
*/

#include <kerror.h>
#include <kstr.h>

#include "options.h"
#include "db.h"
#include "client.h"
#include "client_req_kws.h"
#include "shared.h"
#include "keys.h"
#include "logid.h"
#include "logging.h"
#include "utils.h"

enum client_state kdclient_get_kws_ticket_request(kdclient *self,
                                                  apr_pool_t *pkt_pool,
                                                  struct kdpacket *in_pkt,
                                                  struct kdpacket **out_pkt) {
    int error = 0;
    tagcrypt_signature *sig = NULL;
    tbuffer *tbuf = NULL;
    kbuffer out_buf;
    struct tagcrypt_blob_params blob;
    struct kdpacket *op;
    const char *kas_addr;
    uint16_t kas_port;
    int empty_ticket = 0;
    enum client_state next_state = CSTATE_DROP_ACK;
    
    in_pkt = in_pkt;

    /* Check if the user can do an application packet. */
    if ((self->user->caps & CAN_APPS) == 0) {
        ERROR(_log_client_, "Client cannot do applications requests.");
        return CSTATE_DROP_ACK;
    }

    /* Check if the user has access to applications. */
    if ((self->user->lic & CAN_APPS) == 0) 
        empty_ticket = 1;

    /* Pull the KAS address. */
    kas_addr = options_get_str("server.kas_address");
    if (kas_addr[0] == 0) {
        ERROR(_log_client_, "KAS address not specified");
        return CSTATE_DROP_ACK;
    }
    
    /* Pull the KAS port. */
    kas_port = options_get_uint16("server.kas_port");
    
    kbuffer_init(&out_buf);    
    
    do {
    	sig = tagcrypt_sign_new(TAG_P_TYPE_SIGN, 2, 1,
	    	    	    	(tagcrypt_skey *) self->user->enc_skey->key);
	if (sig == NULL) {
	    error = -1;
	    break;
	}
	
	tbuf = tbuffer_new(1000);
	tbuffer_write_cstr(tbuf, self->user->full_name);
	tbuffer_write_cstr(tbuf, self->user->primary_email_addr);

        if (!empty_ticket) {
            tbuffer_write_cstr(tbuf, kas_addr);
            tbuffer_write_uint32(tbuf, kas_port);
        }
        else {
            tbuffer_write_cstr(tbuf, "");
            tbuffer_write_uint32(tbuf, 0);
        }
	tbuffer_write_uint64(tbuf, self->user->enc_skey->key_id);
	
	blob.type = 0;
	blob.blob = tbuffer_get_dbuf(tbuf);
	error = tagcrypt_sign_add_subpacket(sig, TAG_SP_TYPE_BLOB, &blob);
	if (error) break;
	
	error = tagcrypt_sign_serialize(sig, &out_buf);
	if (error) break;
	
	op = kdpacket_new(pkt_pool, PKT_GET_KWS_TICKET_RES);
	kdpacket_set_raw(op, EL_KWS_TICKET, out_buf.data, out_buf.len);
	*out_pkt = op;
	
        /* Success, don't change state. */
        next_state = self->cstate;

    } while (0);
    
    if (sig) tagcrypt_sign_destroy(sig);
    if (tbuf) tbuffer_destroy(tbuf);
    kbuffer_clean(&out_buf);
    
    return next_state;
}

enum client_state kdclient_convert_exchange_addr(kdclient *self,
                                                 apr_pool_t *pkt_pool,
                                                 struct kdpacket *in_pkt,
                                                 struct kdpacket **out_pkt) {
    size_t i, nb;
    struct kdpacket *op;
    char *in_addr, *out_addr;
    size_t str_s;
    
    /* Read the number of item from the packet. */
    nb = kdpacket_get_list_len(in_pkt, EL_ADDRESS_ARRAY);

    /* Prepare the return packet. */
    op = kdpacket_new(pkt_pool, PKT_CONVERT_EXCHANGE_RES);
    kdpacket_set_list(op, EL_ADDRESS_ARRAY, nb);

    /* Loop to ask for all the addresses. */
    for (i = 0; i < nb; i++) {
	kdpacket_get_list_item(in_pkt, EL_ADDRESS_ARRAY, i, (void **)&in_addr, &str_s);

        /* FIXME: Should we handle errors there? */
	if (kddb_convert_address(pkt_pool, in_addr, self->user->primary_email_addr, &out_addr)) {
            kerror_reset();
	    out_addr = "";
        }

	kdpacket_set_list_item(op, EL_ADDRESS_ARRAY, i, out_addr, strlen(out_addr));
    }
    
    *out_pkt = op;
   
    return self->cstate;
}
