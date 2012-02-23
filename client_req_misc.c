/**
 * tbxsosd/client_req_misc.h
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
 * Other kind of requests.
 *
 * @author François-Denis Gonthier
*/

#include <apr_strings.h>
#include <apr_pools.h>
#include <kerror.h>

#include "config.h"
#include "logging.h"

#include "options.h"
#include "db.h"
#include "client.h"
#include "packet.h"
#include "logid.h"
#include "logging.h"
#include "utils.h"
#include "shared.h"

#ifdef REQUEST_USER_INFO

static size_t ndomains;
static char **domains;

/** Returns the user own key ID.
 *
 * The key ID is associated to the profile on which the user is
 * logged.  This request does not change the state of the client
 * unless an error happens.
 */
enum client_state kdclient_get_user_info_request(kdclient *self,
                                                 apr_pool_t *pool,
                                                 struct kdpacket *in_pkt,
                                                 struct kdpacket **out_pkt) {
    size_t i;
    struct kdpacket *op;
    apr_pool_t *info_pool;
    enum client_state next_state = self->cstate;
    const char *kpg_address;
    const char *domains_str;
    char *pkt_kpg_addr;
    int kpg_port;
    
    INFO(_log_client_, "Request: Self information [user: %s].", self->user->username);

    /* server.domains is a property of the server, but it only matters
       to the client for now. */
    domains_str = options_get_str("server.domains");

    /* Create a pool to put the list of domains. */
    apr_pool_create(&info_pool, pool);
    apr_tokenize_to_argv(domains_str, &domains, pool);

    /* Count the number of domains. */
    for (ndomains = 0; domains[ndomains] != NULL; ndomains++);

    do {     
        op = kdpacket_new(pool, PKT_GET_USER_INFO_RES);

        kdpacket_set_uint64(op, EL_KEYID, self->user->key_id);
        kdpacket_set_list(op, EL_DOMAINS_ARRAY, ndomains);

        for (i = 0; i < ndomains; i++) 
            kdpacket_set_list_item(op, EL_DOMAINS_ARRAY, i,
                                   domains[i], strlen(domains[i]));

        /* Send the KPG address if it was configured. */
        if (in_pkt->major >= 4) {
            kpg_address = options_get_str("server.kpg_address");

            if (strcmp(kpg_address, "") != 0) {
                pkt_kpg_addr = apr_pstrdup(pool, kpg_address);

                kdpacket_set_uint32(op, EL_KPG_IS_USED, 1);
                kdpacket_set_str(op, EL_KPG_HOSTNAME, pkt_kpg_addr, strlen(pkt_kpg_addr));

                kpg_port = options_get_uint16("server.kpg_port");

                kdpacket_set_uint32(op, EL_KPG_PORT, kpg_port);
            }            
            else
                kdpacket_set_uint32(op, EL_KPG_IS_USED, 0);
        }

        /* Write about that request in the stat log. */
        struct event ev[1] = {{.key = "keyid",
                               .type = EV_VAR_UINT64,
                               .val.uint64 = self->user->key_id}};
        
        if (kddb_event(pool, kdsh_get_session_counter(), "getinfo", 1, ev) < 0) 
            kdclient_warn("Failed to log 'getinfo' event.");

        INFO(_log_client_, "Request: Self information [user: %s] successful.", self->user->username);

        *out_pkt = op;
        return next_state;

    } while (0);
    
    *out_pkt = kdpacket_new(pool, PKT_FAIL);
    return CSTATE_DROP_ACK;
}
#endif // REQUEST_USER_INFO
