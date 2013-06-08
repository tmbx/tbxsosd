/**
 * tbxsosd/client_req_otut.c
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
 * OTUT string request.
 *
 * @author François-Denis Gonthier
*/

#include <kerror.h>
#include <kstr.h>

#include "common/common_keys.h"
#include "common/common_dpkg.h"
#include "common/common.h"
#include "common/config.h"
#include "common/logid.h"
#include "libutils/logging.h"
#include "libutils/utils.h"

#include "client.h"
#include "otut.h"
#include "shared.h"
#include "packet.h"

#ifdef REQUEST_OTUT
enum client_state kdclient_get_otut_string_request(kdclient *self,
                                                   apr_pool_t *pkt_pool,
                                                   struct kdpacket *in_pkt,
                                                   struct kdpacket **out_pkt) { 
    uint32_t i, *n, *otut_reps;
    struct kdpacket *op;
    size_t otut_count;
    apr_pool_t *pool;
    const char *ticket_str = NULL;
    size_t ticket_str_s = 0;
    char **otut_str;
    size_t *otut_str_s;

    enum client_state next_state = self->cstate;
    struct tagcrypt_ticket *ticket = NULL;

    do {         
        apr_pool_create(&pool, pkt_pool);

        kdpacket_get_raw(in_pkt, EL_TICKET, (void **)&ticket_str, &ticket_str_s);
        otut_count = kdpacket_get_list_len(in_pkt, EL_OTUT_REPLY_COUNT_ARRAY);

        /* Copy the array to pass it to the OTUT manager. */
        otut_reps = apr_pcalloc(pool, sizeof(uint32_t) * otut_count);

        for (i = 0; i < otut_count; i++) {
            kdpacket_get_list_item(in_pkt, EL_OTUT_REPLY_COUNT_ARRAY, i, (void **)&n, NULL);
            otut_reps[i] = *n;
        }

        INFO(_log_client_, "Requests: %d OTUT strings.", otut_count);

        /* Extract the ticket from the string sent by the client. */
        if (otut_extract_ticket(pool, ticket_str, ticket_str_s, &ticket) < 0) {
            kdclient_error("Failed to extract valid ticket.");
            break;
        }

        /* Generate the OTUT strings. */
        if (otut_gen_otuts(pool, ticket, 
                           otut_count, otut_reps, 
                           &otut_str, &otut_str_s) < 0) {
            kdclient_error("Failed to generate OTUT strings.");
            break;
        }

        op = kdpacket_new(pkt_pool, PKT_GET_OTUT_STRING_RES);        
        kdpacket_set_list(op, EL_OTUT_STRING_ARRAY, otut_count);
        
        for (i = 0; i < otut_count; i++) {
            kdpacket_set_list_item(op, EL_OTUT_STRING_ARRAY, i, 
                                   otut_str[i],
                                   otut_str_s[i]);
        }

        INFO(_log_client_, "Request: %d OTUT string successful.", otut_count);

        /* Write basic statistics about the request. */
        struct event ev[1] = {{.key = "nb_req",
                               .type = EV_VAR_UINT32,
                               .val.uint32 = otut_count}};
        
        if (kddb_event(pkt_pool, kdsh_get_session_counter(), "otut-string", 1, ev) < 0) 
            kdclient_warn("Failed to log 'otut-string' event.");
   
	if (ticket) tagcrypt_ticket_clean(ticket);
        apr_pool_destroy(pool);
        
        *out_pkt = op;
        return self->cstate;

    } while (0); 
    
    if (ticket) 
        tagcrypt_ticket_clean(ticket);

    apr_pool_destroy(pool);

    *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
    next_state = CSTATE_DROP_ACK;

    return next_state;
} 
#endif // REQUEST_OTUT

#ifdef REQUEST_TICKET
/** Return an OTUT ticket for the client. 
 *
 * This method does not change the client state.  The client is
 * rejected with acknowledgment in case of errors.
 */
enum client_state kdclient_get_ticket_request(kdclient *self,
                                              apr_pool_t *pool,
                                              struct kdpacket *in_pkt,
                                              struct kdpacket **out_pkt) {
    kbuffer *ticket_buff = NULL;
    const char *addr = NULL;
    uint32_t rep_count = 0;
    struct kdpacket *op = NULL;
    enum client_state next_state;
    
    INFO(_log_client_, "Request: OTUT ticket [user: %s].", self->user->username);
    
    do {
        ticket_buff = kbuffer_new();

        kdpacket_get_str(in_pkt, EL_OTUT_ADDRESS, &addr, NULL);
        kdpacket_get_uint32(in_pkt, EL_OTUT_REPLY_COUNT, &rep_count);

        /* Generate the ticket. */
        if (otut_gen_ticket(pool, self->user, rep_count, addr, ticket_buff) < 0) {
            kdclient_error("Failed to generate ticket for user.");
            break;
        }

        op = kdpacket_new(pool, PKT_GET_OTUT_TICKET_RES);
        kdpacket_set_raw(op, EL_TICKET, ticket_buff->data, ticket_buff->len);
        
        /* Cleanup the buffer. */
        kbuffer_destroy(ticket_buff);

        *out_pkt = op;

        INFO(_log_client_, "Request: OTUT ticket [user: %s].", self->user->username);

        /* Write basic statistics about the request. */
        struct event ev[1] = {{.key = "nb_req",
                               .type = EV_VAR_UINT32,
                               .val.uint32 = rep_count}};
        
        if (kddb_event(pool, kdsh_get_session_counter(), "otut-ticket", 1, ev) < 0) 
            kdclient_warn("Failed to log 'otut-ticket' event.");
    
        return self->cstate;
    } while (0);

    *out_pkt = kdpacket_new(pool, PKT_FAIL);
    next_state = CSTATE_DROP_ACK;
    
    /* Cleanup and leave. */
    if (ticket_buff != NULL) kbuffer_destroy(ticket_buff);

    return next_state;
}
#endif // REQUEST_TICKET

#ifdef REQUEST_OTUT
enum client_state kdclient_check_otut_string_request(kdclient *self,
                                                     apr_pool_t *pkt_pool,
                                                     struct kdpacket *in_pkt,
                                                     struct kdpacket **out_pkt) {
    enum client_state next_state = self->cstate;
    const char *otut_str;
    size_t otut_str_s;
    uint32_t nb_uses;
    struct kdpacket *op;

    do {        
        kdpacket_get_raw(in_pkt, EL_OTUT_STRING, (void **)&otut_str, &otut_str_s);

        if (kddb_otut_check(otut_str, otut_str_s, &nb_uses) < 0) {
            kdclient_error("Failed to check OTUT validity.");
            break;
        }

        op = kdpacket_new(pkt_pool, PKT_VALIDATE_OTUT_RES);
        kdpacket_set_uint32(op, EL_OTUT_USES, nb_uses);

        *out_pkt = op;

        if (kddb_event(pkt_pool, kdsh_get_session_counter(), "otut-validate", 0, NULL) < 0)
            kdclient_warn("Failed to log 'otut-validate' event.");

        return next_state;

    } while (0);

    *out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
    next_state = CSTATE_DROP_ACK;

    return next_state;
}
#endif // REQUEST_OTUT
