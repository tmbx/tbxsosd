/**
 * tbxsosd/client.c
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
 * Teambox Sign-On Server Daemon client process manager.
 *
 * @author François-Denis Gonthier
*/

#include <apr_portable.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <tagcrypt.h>
#include <kerror.h>
#include <kstr.h>
#include <kmem.h>

#include "common_pkg.h"
#include "common_dpkg.h"
#include "common_keys.h"
#include "common.h"

#include "dpkg.h"
#include "options.h"
#include "shared.h"
#include "config.h"
#include "crypto_proto_str.h"
#include "package.h"
#include "logid.h"
#include "logging.h"
#include "client.h"
#include "proto.h"
#include "proto_defs.h"
#include "packet.h"
#include "podder.h"
#include "otut.h"
#include "ssl_comm.h"
#include "sock_comm.h"
#include "utils.h"
#include "child.h"
#include "signals.h"

#include "client_req_key.h"
#include "client_req_kws.h"
#include "client_req_pkg.h"
#include "client_req_login.h"
#include "client_req_dpkg.h"
#include "client_req_otut.h"
#include "client_req_misc.h"

static apr_pool_t *static_pool = NULL;

static int random_drop_max;
static int random_drop_min;

static int client_timeout;
static int client_retries;

/** Client object. */
static kdclient *cli;

/** For the signal handler to access the communication pipe. */
static struct kdchild_data *child_data;

/** Set to 1 when a preforked server must quit. */
static volatile sig_atomic_t do_quit;

#ifdef KD_DEBUG
/** Set to 1 when a preforked server must lockup for debugging. */
static volatile sig_atomic_t do_lockup;
#endif // KD_DEBUG

/** Load the client specific options. */
int kdclient_static_init(apr_pool_t *parent_pool) {
    parent_pool = parent_pool;

    /* Load some control variables.  All those won't change much and
       need to present. */
    random_drop_max = options_get_uint32("client.random_drop_max");
    random_drop_min = options_get_uint32("client.random_drop_min");
    client_timeout = options_get_uint32("client.timeout");
    client_retries = options_get_uint32("client.retries");

    if (static_pool != NULL) {
        apr_pool_destroy(static_pool);
        static_pool = NULL;
    }

    return 0;
}
   
/** Internal initialization. */
kdclient *kdclient_new(apr_pool_t *pool, struct kdchild_data *cd) {
    kdclient *self;
    apr_pool_t *obj_pool;

    apr_pool_create(&obj_pool, pool);

    self = apr_pcalloc(obj_pool, sizeof(kdclient));

    tagcrypt_init();

    do {
#if defined(REQUEST_PACKAGE)
        if ((self->filter_obj = kdfilter_new(obj_pool)) == NULL) {
            KERROR_PUSH(_client_, 0, "unable to initialize filter object");
            break;
        }
#endif // REQUEST_PACKAGE

        self->allow_html = options_get_bool("server.allow_html");
        self->child_data = cd;       
        self->pool = obj_pool;

        return self;

    } while (0);
    
    apr_pool_destroy(obj_pool);

    return NULL;
}

static int kdclient_handle_client(kdclient *self, apr_pool_t *parent_pool) {
    struct kdpacket *in_pkt = NULL;
    struct kdpacket *out_pkt = NULL;
    const char *ip;
    int pkt_type;
    apr_pool_t *in_pkt_pool, *out_pkt_pool, *misc_pool, *dpkg_pool;
    struct kd_dpkg *dpkg;
    struct kd_decrypted *dec;

    /* self->main_comm will be set at this point. */
    self->main_comm->timeout = client_timeout;

    if ((self->user = kduser_new(parent_pool)) == NULL) {
        KERROR_PUSH(_client_, 0, "unable to create user object");
        return -1;
    }

    if ((self->proto = kdprotocol_new(parent_pool, self->main_comm)) == NULL) {
        KERROR_PUSH(_client_, 0, "unable to initialize protocol object");
        return -1;
    }
       
    apr_pool_create(&in_pkt_pool, parent_pool);
    apr_pool_tag(in_pkt_pool, "inbound packet pool");
    apr_pool_create(&out_pkt_pool, parent_pool);
    apr_pool_tag(out_pkt_pool, "outbound packet pool");
    apr_pool_create(&misc_pool, parent_pool);
    apr_pool_tag(misc_pool, "client work pool");

    /* This will fail if the client quits early. */
    if (kdcomm_get_peer(self->main_comm, misc_pool, &ip, NULL) < 0) {
        kdclient_error("Client has quit prematurely.");
        return 0;
    }

    /* Register a connection. */
    struct event ev_connect[2] = {{.key = "ip",
                                   .type = EV_VAR_STR,
                                   .val.str = ip},
                                  {.key = "cert",
                                   .type = EV_VAR_UINT32,
                                   .val.uint32 = self->cert_num}};
    
    if (kddb_event(misc_pool, kdsh_get_session_counter(), "connect", 2, ev_connect) < 0) 
        kdclient_error("Failed to log 'connect' event.");
   
    self->cstate = CSTATE_NOT_CONNECTED;

    while (self->cstate != CSTATE_DROP_NOW) {
	int error = kdprotocol_read(self->proto, &in_pkt, in_pkt_pool);
	
	if (error) {
	    kdclient_error("Client has disconnect with error.");
	    break;
	}
	
	if (in_pkt == NULL) {
	    INFO(_log_client_, "Client has disconnected cleanly.");
	    break;
	}

        pkt_type = kdpacket_get_type(in_pkt);

        switch (pkt_type) {
#ifdef REQUEST_GETSIG
        case PKT_GET_SIGN_KEY_CMD:
            /* Process the signature key request. */
            self->cstate = kdclient_get_sign_key_request(self, out_pkt_pool, in_pkt, &out_pkt);
            break;
#endif // REQUEST_GETSIG
#ifdef REQUEST_GETENC
        case PKT_GET_ENC_KEY_CMD:
            /* Process the encryption key request. */
            self->cstate = kdclient_get_enc_key_request(self, out_pkt_pool, in_pkt, &out_pkt);
            break;
	case PKT_GET_ENC_KEY_BY_ID_CMD:
            self->cstate = kdclient_get_enc_key_by_id_request(self, out_pkt_pool, in_pkt, &out_pkt);
            break;
#endif // REQUEST_GETENC

        default:
            switch (self->cstate) {
            case CSTATE_NOT_CONNECTED:
                switch (pkt_type) {
#ifdef REQUEST_OTUT_LOGIN
                case PKT_OTUT_LOGIN_CMD: 
                    self->cstate = kdclient_user_otut_login_request(self, out_pkt_pool, in_pkt, &out_pkt);
                    break; 
#endif // REQUEST_OTUT_LOGIN
#ifdef REQUEST_LOGIN
                case PKT_LOGIN_CMD:
                    /* Process the login request. */
                    self->cstate = kdclient_login_user_request(self, out_pkt_pool, in_pkt, &out_pkt);
                    break;
#endif // REQUEST_LOGIN
#ifdef REQUEST_OTUT
                case PKT_GET_OTUT_STRING_CMD:
                    /* Process the OTUT string request. */
                    self->cstate = kdclient_get_otut_string_request(self, out_pkt_pool, in_pkt, &out_pkt);
                    break;
                case PKT_VALIDATE_OTUT_CMD:
                    /* Process the request to check the OTUT string. */
                    self->cstate = kdclient_check_otut_string_request(self, out_pkt_pool, in_pkt, &out_pkt);
                    break;
#endif // REQUEST_OTUT
#ifdef REQUEST_GUEST_DECRYPT
                    /* This request is state dependent since
                       people will never login to the server on
                       which the ask PoD and password decryption
                       on. */
                case PKT_DEC_SYM_KEY_CMD:
                    apr_pool_create(&dpkg_pool, misc_pool);
                    dpkg = kd_dpkg_new(dpkg_pool);
                    dec = kd_decrypted_new(dpkg_pool);

                    /* Process non-member decryption request. */
                    if (self->cstate == kdclient_request_dpkg(self, out_pkt_pool, dpkg, in_pkt, &out_pkt)) {
		    	
			dec->symkey = kbuffer_new();
			kbuffer_write(dec->symkey, (uint8_t *)dpkg->symkey_str, dpkg->symkey_str_s);

                        /* PoD decryption only. */
                        if (dpkg->password_str == NULL &&
                            dpkg->symkey_str != NULL &&
                            dpkg->sign->type == TAG_P_TYPE_POD) 
                            self->cstate = kdclient_request_pod_dpkg(self, out_pkt_pool, dpkg, dec, &out_pkt);

                        /* PoD & Enc. decryption for member
                           (without passwords) */
                        else if (dpkg->password_str == NULL && 
                                 (dpkg->sign->type == TAG_P_TYPE_POD ||
                                  dpkg->sign->type == TAG_P_TYPE_PODNENC))
                            self->cstate = kdclient_request_pod_dpkg(self, out_pkt_pool, dpkg, dec, &out_pkt);
                            
                        /* Password decryption for non-members. */
                        else if (dpkg->password_str != NULL && 
                                 (dpkg->sign->type == TAG_P_TYPE_PODNENC ||
                                  dpkg->sign->type == TAG_P_TYPE_ENC))
                            self->cstate = kdclient_request_pwd_dpkg(self, out_pkt_pool, dpkg, dec, &out_pkt);

                        else {
                            /* That means this was a *WEIRD*
                               message.  So weird that I cannot
                               figure how it could happen.  When I
                               doubt, drop the connection. */
                            kdclient_error("Cannot select the right decryption with "
                                           "the given parameters.");
                            self->cstate = CSTATE_DROP_ACK;
                            out_pkt = kdpacket_new(out_pkt_pool, PKT_FAIL);
                        }
                    }

                    apr_pool_destroy(dpkg_pool);

                    break;
#endif // REQUEST_GUEST_DECRYPT
                default:
                    kdclient_error("Unknown or unsupported request received.");
                    self->cstate = CSTATE_DROP_NOW;
                }
                break;                
            case CSTATE_CONNECTED:
                switch (pkt_type) {
#ifdef REQUEST_KEY_DECRYPT
                case PKT_DEC_SYM_KEY_CMD:
                    apr_pool_create(&dpkg_pool, misc_pool);
                    dpkg = kd_dpkg_new(dpkg_pool);
                    dec = kd_decrypted_new(dpkg_pool);

                    /* Process member decryption requests. */                        
                    if (self->cstate == kdclient_request_dpkg(self, out_pkt_pool, dpkg, in_pkt, &out_pkt)) 
                        self->cstate = kdclient_request_key_dpkg(self, out_pkt_pool, dpkg, dec, &out_pkt);
                    apr_pool_destroy(dpkg_pool);
                    break;
#endif // REQUEST_KEY_DECRYPT
#ifdef REQUEST_PACKAGE
                case PKT_PACKAGE_CMD:
                    self->cstate = kdclient_request_package(self, out_pkt_pool, in_pkt, &out_pkt);
                    break;
#endif // REQUEST_PACKAGE
#ifdef REQUEST_USER_INFO
                case PKT_GET_USER_INFO_CMD:
                    self->cstate = kdclient_get_user_info_request(self, out_pkt_pool, in_pkt, &out_pkt);
                    break;
#endif // REQUEST_USER_INFO                     
#ifdef REQUEST_TICKET
                case PKT_GET_OTUT_TICKET_CMD:
                    /* Process the OTUT ticket request. */
                    self->cstate = kdclient_get_ticket_request(self, out_pkt_pool, in_pkt, &out_pkt);
                    break;
#endif // REQUEST_TICKET
    	    	
		case PKT_GET_KWS_TICKET_CMD:
		    self->cstate = kdclient_get_kws_ticket_request(self, out_pkt_pool, in_pkt, &out_pkt);
		    break;
		    
		case PKT_CONVERT_EXCHANGE_CMD:    
		    self->cstate = kdclient_convert_exchange_addr(self, out_pkt_pool, in_pkt, &out_pkt);
		    break;
		
                default:
                    kdclient_error("Unknown or unsupported request received.");
                    self->cstate = CSTATE_DROP_NOW;
                }
                break;

#ifdef REQUEST_OTUT_LOGIN
            case CSTATE_CONNECTED_OTUT:
                switch (pkt_type) {
#ifdef REQUEST_PACKAGE
                case PKT_PACKAGE_CMD:
                    self->cstate = kdclient_request_package_otut(self, out_pkt_pool, in_pkt, &out_pkt);
                    break;
#endif // REQUEST_PACKAGE
                }
                break;            
#endif // REQUEST_OTUT_LOGIN

            case CSTATE_DROP_NOW:
            case CSTATE_DROP_ACK:
            default:
                kdclient_error("Unknown or unsupported request received.");
                self->cstate = CSTATE_DROP_NOW;
                break;
            }            
        }

        /* Delete the inbound packet, it is no longer needed. */
        if (in_pkt != NULL) {
            apr_pool_clear(in_pkt_pool);
            in_pkt = NULL;
        }

        /* Check if the request function has asked for immediate
           drop. */
        if (self->cstate == CSTATE_DROP_NOW) break;

        if (out_pkt != NULL) {
	    int error = kdprotocol_write(self->proto, out_pkt);
	    
            if (error <= 0) {
	    	if (error)
                    kdclient_error("Error writing response to client.");
		else
		    kdclient_error("Client has disconnected before the response could be written.");

                /* Delete the packet right now. */
                if (out_pkt != NULL) {
                    apr_pool_clear(out_pkt_pool);
                    out_pkt = NULL;
                }

                break;
            }
        }

        /* Delete the outbound packet.  It is no longer needed. */
        if (out_pkt != NULL) {
            apr_pool_clear(out_pkt_pool);
            out_pkt = NULL;
        }

        if (self->cstate == CSTATE_DROP_ACK)  break;
    }

    /* Register a disconnection. */
    struct event ev_disconnect[1] = {{.key = "ip",
                                      .type = EV_VAR_STR,
                                      .val.str = ip}};

    if (kddb_event(misc_pool, kdsh_get_session_counter(), "disconnect", 1, ev_disconnect) < 0) 
        kdclient_warn("Failed to log 'disconnect' event.");

    apr_pool_destroy(out_pkt_pool);
    apr_pool_destroy(in_pkt_pool);
    apr_pool_destroy(misc_pool);

    return 0;
}

static void kdclient_critical_fail_packet() {
    kstr *err_msg;
    uint32_t hdr[4];
    kbuffer buf;
    kdclient *self = cli;

    /* Cannot do squat without the protocol module created. */
    if (self && self->proto) {
        kdprotocol_fail_packet(self->proto, hdr);
        buf.data = (void *)hdr;
        buf.len = sizeof(hdr);
        buf.pos = 0;
        buf.allocated = 0;
        
        if (kdcomm_write(self->proto->comm, &buf) < 0) {
            err_msg = kerror_str_n(0);
            CRITICAL(_log_client_, "Error sending failure packet to client: %s.", err_msg->data);
            kstr_destroy(err_msg);
        }
    }
}

void kdclient_options_critical_error_handler() {
    CRITICAL(_log_client_, "Error in server configuration.");
    kdclient_critical_fail_packet();

    /* Exit immediately. */
    exit(1);
}

/** APR low-memory handler. */
int kdclient_lowmem_handler_apr(int retcode) {  
    retcode = retcode;

    CRITICAL(_log_client_, "Low memory condition.  Immediatly dropping the client.");
    kdclient_critical_fail_packet();

    /* Exit immediately. */
    exit(1);
}

/** libktools low-memory handler. */
void kdclient_lowmem_handler_ktools() {
    kdclient_lowmem_handler_apr(0);
}

/** Signal handler. */
static void kdclient_sig_handler(int sig_id) {
    switch (sig_id) {
#ifdef KD_DEBUG
    case SIGUSR1:
        /* This signal performs a mock lock-up of the child.  We don't
           want that signal to be supported on production setup! */
        do_lockup = 1;
        break;
#endif // KD_DEBUG
    case SIGPIPE:
    case SIGTERM:
        /* Set the communication socket timeout to 0.  Reading from
           there will automatically timeout.  Non-preforked client
           does not need to concern themselves with this.  The need
           to finish their processing. */
        if (child_data != NULL) {
            //int s = child_data->state;
            //int is_preforked;
            //is_preforked = (s == CHILD_PREFORK_FREE || s == CHILD_PREFORK_BUSY);

            //if (is_preforked) 
            child_data->pf_comm->timeout = COMM_TIMEOUT_NONE;
        }

        do_quit = 1;
        break;
    }
}

static void kdclient_SIGTERM_handler(int sig_id) {
    kdclient_sig_handler(sig_id);
}

static void kdclient_SIGPIPE_handler(int sig_id) {
    kdclient_sig_handler(sig_id);
}

#ifdef KD_DEBUG
static void kdclient_SIGUSR1_handler(int sig_id) {
    kdclient_sig_handler(sig_id);
}
#endif // KD_DEBUG

static int kdclient_set_gid(apr_pool_t *pool) {
    const char *group;

    /* Get the group name from the configuration file. */
    group = options_get_str("server.group");
    
    if (set_gid_name(pool, group) < 0) {
        CRITICAL(_log_server_, "Cannot change process group name to %s.", group);
        return -1;
    }

    DEBUG(_log_server_, "Changed child process group name to %s.", group);

    return 0;
}

static int kdclient_set_uid(apr_pool_t *pool) {
    const char *user;

    /* Get the group name from the configuration file. */
    user = options_get_str("server.user");

    if (set_uid_name(pool, user) < 0) {
        CRITICAL(_log_server_, "Cannot change process user name to %s.", user);
        return -1;
    }

    DEBUG(_log_server_, "Changed child process username to %s.", user);

    return 0;   
}

/** Process initialization routines. 
 *
 * Proceed to straightforward initialization of the child process. 
 */
static int kdclient_child_init(apr_pool_t *pool, struct kdchild_data *cd) {
    struct kdsignal_info sigs[] = 
        {
            {SIGTERM, kdclient_sig_handler},
            {SIGPIPE, kdclient_sig_handler},
#ifdef KD_DEBUG
            {SIGUSR1, kdclient_sig_handler}
#endif
        };
    enum kddb_auth_mode auth_mode;
    int ignored_sigs[] = {SIGHUP, 0};

    options_set_critical_error_handler(kdclient_options_critical_error_handler);

    /* Set the event counter to 0. */
    event_counter = 0;

    /* If we are forked, set our own signal handlers. */
    if (cd->state != CHILD_DEBUG) {
        kdsignal_handled(sizeof(sigs) / sizeof(struct kdsignal_info), sigs);
        kdsignal_ignored(ignored_sigs);
    }

    /* Set process username and passwords. */
    if (kdclient_set_gid(pool) < 0 || kdclient_set_uid(pool)) 
        return -1;

#ifdef KD_DEBUG
    auth_mode = DB_AUTH_CURRENT_CREDS_MODE;
#else
    auth_mode = DB_AUTH_NORMAL_MODE;
#endif

    if (kddb_open(pool, auth_mode) < 0) {        
        KERROR_PUSH(_client_, 0, "unable to open database");
        return -1;
    }

    /* Open shared data object. */
    if (kdsh_child_open() < 0) {
        KERROR_PUSH(_client_, 0, "unable to initialize shared data object");
        return -1;
    }
    
    return 0;
}

/** This checks what certificate to send to the client.  We have to
    change certificate due to DSA-1571-1.  This mechanism allow use
    to prevent this kind of situation in the future. */
static int kdclient_accept_ssl(kdclient *self, 
                               int client_fd, 
                               kdssl_comm **ssl_comm) {
    kdsock_comm *sc;
    kdcomm *c;
    apr_pool_t *tmp_pool;
    int buf; /* Read buffer, actually. */
    int err = -1, n, fd, has_pre_bytes = 0;
    int cfg_fallback_cert;
    void *pre_bytes = NULL;
    size_t pre_bytes_s;
    const char *cfg_auth_mode;
    enum ssl_auth_mode { SSL_AUTH_CLIENT, SSL_AUTH_FALLBACK, SSL_AUTH_NONE } auth_mode;

    /* Check that we can accept direct SSL connection, by
       using a default certificate. */
    cfg_auth_mode = options_get_str("ssl.authentication_mode");
    cfg_fallback_cert = options_get_uint32("ssl.fallback_cert");

    /* Check the ssl.authentication_mode string. */
    if (strcmp(cfg_auth_mode, "client") == 0) 
        auth_mode = SSL_AUTH_CLIENT;
    else if (strcmp(cfg_auth_mode, "fallback") == 0) 
        auth_mode = SSL_AUTH_FALLBACK;
    else if (strcmp(cfg_auth_mode, "none") == 0) 
        auth_mode = SSL_AUTH_NONE;
    else {
        KERROR_SET(_client_, 0, "invalid value for ssl.authentication_mode");
        return -1;
    }

    apr_pool_create(&tmp_pool, self->pool);

    /* Create the SSL object. */
    *ssl_comm = kdssl_comm_new(self->pool, client_fd);

    /* Duplicate the socket FD since comm object destructor close
       sockets. */
    fd = dup(client_fd);
    sc = kdsock_comm_new(tmp_pool, fd, 0);

    c = sc->c;

    /* Set the timeouts on communication object. */
    c->timeout = client_timeout;
    (*ssl_comm)->c->timeout = client_timeout;

    /* Read the first 4 bytes of the communication. */
    do {
        /* FIXME: This loops over EINTR and I don't like that but
           since we only read 4 bytes this is not unacceptable. */
        while ((n = kdcomm_read_raw(c, (void *)&buf, sizeof(buf))) < 0) {
            if (c->state != COMM_EINTR)
                break;
        }
        /* If we weren't able to read 4 bytes in one shot, we have
           some kind of a problem... */
        if (n < 4) {
            KERROR_SET(_client_, 0, "client did not send enough data");
            break;
        }

        /* Check for SSL client hello and version number.  22 = SSL
           hello.  3 and 0 = SSL version. */
        if (((char *)&buf)[0] == 22 && ((char *)&buf)[1] == 3 && ((char *)&buf)[2] == 0) {
            DEBUG(_log_client_, "Client has not sent a certificate number.");

            /* Bail out if this server is not configured to accept
               direct SSL connexion. */
            if (auth_mode == SSL_AUTH_CLIENT) {
                KERROR_SET(_client_, 0, "cannot accept direct SSL connexions");
                break;
            }

            DEBUG(_log_client_, "Trying fallback certificate.");

            /* SSL_AUTH_NONE and SSL_AUTH_FALLBACK go through here.
               This is where the proper fallback to the default
               certificate is done. */
            if (kdssl_comm_load_cert_number(*ssl_comm, cfg_fallback_cert) < 0) {
                KERROR_SET(_client_, 0, "failed to load fallback certificate: %d", cfg_fallback_cert);
                break;
            }
            self->cert_num = cfg_fallback_cert;
            has_pre_bytes = 1;
        }
        /* This is a certificate number. */
        else {
            int cert_num = ntohl(buf), has_loaded;

            DEBUG(_log_client_, "Client is demanding certificate: %d", cert_num);

            /* Try to load the certificate the user wants. */
            if (auth_mode == SSL_AUTH_CLIENT || auth_mode == SSL_AUTH_FALLBACK) {
                has_loaded = (kdssl_comm_load_cert_number(*ssl_comm, cert_num) == 0);

                if (!has_loaded) {
                    KERROR_SET(_client_, 0, 
                               "Failed to load demanded certificate number: %d.", cert_num);
                    break;
                } else
                    self->cert_num = cert_num;
            }
            
            /* If we don't care about want the client wants, send the
               default certificate. */
            if (auth_mode == SSL_AUTH_NONE) {
                has_loaded = (kdssl_comm_load_cert_number(*ssl_comm, cfg_fallback_cert) == 0);

                if (!has_loaded) {
                    /* If the fallback fails, don't go any further. */
                    KERROR_SET(_client_, 0, "failed to load default certificate");
                    break;
                } else
                    self->cert_num = cfg_fallback_cert;
            }
        }

        /* Set the pre_bytes buffer for accepting the SSL connection
           using partly the buffer, partly the memory. */
        if (has_pre_bytes) {
            pre_bytes = &buf;
            pre_bytes_s = sizeof(buf);
        }

        /* Log the certificate we will use. */
        INFO(_log_client_, "Client will use certificate number: %d", self->cert_num);

        /* Accept the client connection. */
        if (kdssl_comm_init(*ssl_comm, pre_bytes, pre_bytes_s) < 0) {
            KERROR_PUSH(_client_, 0, "failed to accept client SSL connection");
            break;
        }

        err = 0;

    } while (0);
       
    apr_pool_destroy(tmp_pool);

    return err;
}

/** Handle a client connection sent from the master process.
 *
 * When entering this function, the child enters the CHILD_BUSY state
 * and sets it back to CHILD_FREE at exit.  It will not be bothered by
 * signals while in this function.
 */
static int kdclient_child_busy(kdclient *self, int client_fd, int client_fd_is_ssl) {
    kddb_validate();

    if (child_data->state == CHILD_FREE) {
        DEBUG(_log_client_, "Client entering CHILD_BUSY state.");
        child_data->state = CHILD_BUSY;
    }

    if (!client_fd_is_ssl) {
        kdsock_comm *sock_comm;

        sock_comm = kdsock_comm_new(self->pool, client_fd, 1);
        if (sock_comm == NULL) {
            KERROR_PUSH(_client_, 0, "error accepting connection");
            return -1;
        }

        self->main_comm = sock_comm->c;
    } else {
        kdssl_comm *ssl_comm;

        if (kdclient_accept_ssl(self, client_fd, &ssl_comm) < 0) {
            KERROR_PUSH(_client_, 0, "error accepting SSL connection");
            return -1;
        }

        self->main_comm = ssl_comm->c;
    }
    
    apr_pool_abort_set(kdclient_lowmem_handler_apr, self->pool);
    kmem_set_handler(NULL, NULL, NULL, NULL, kdclient_lowmem_handler_ktools, NULL);

    /* Handle the client connection. */
    if (kdclient_handle_client(self, self->pool) < 0) {
        KERROR_PUSH(_client_, 0, "error handling client connection");
        return -1;
    }

    apr_pool_abort_set(kdchild_lowmem_handler_apr, self->pool);
    kmem_set_handler(NULL, NULL, NULL, NULL, kdchild_lowmem_handler_libktools, NULL);

    /* If this is a preforked client, send a message to the master
       process saying we are available.  Standard forked clients will
       just leave the loop. */
    if (child_data->state == CHILD_BUSY && child_data->child_loops) {
        if (kdchild_send(child_data, CHILD_MSG_DONE) < 0) {
        }

        DEBUG(_log_client_, "Client entering CHILD_FREE state.");
        child_data->state = CHILD_FREE;
    }

    return 0;
}

int kdclient_main(apr_pool_t *pool, struct kdchild_data *cd) {
    apr_pool_t *cli_pool;  
    int err = -1;

    child_data = cd;

    if (kdclient_child_init(pool, child_data) < 0) {
        KERROR_PUSH(_client_, 0, "failed to initialize client object");
        return -1;
    }
    
    apr_pool_create(&cli_pool, pool);

    do {
        uint32_t msg_in = CHILD_MSG_NONE;
        int client_fd = 0, client_fd_is_ssl = 0, want_pong = 0, want_socket = 0;

        cli = NULL;
        client_fd = -1;
        client_fd_is_ssl = -1;
        err = -1;
        apr_pool_clear(cli_pool);

        /* Instanciate the client object. */
        if ((cli = kdclient_new(cli_pool, cd)) == NULL) {
            KERROR_PUSH(_client_, 0, "unable to instanciate client object");
            break;
        }
        
        /* Non forked client. */
        if (child_data->state == CHILD_DEBUG) {
            client_fd = debug_child_fd;
            client_fd_is_ssl = debug_child_fd_is_ssl;
        }
          
        /* Wait loop. */
        while (client_fd < 0 && !do_quit) {
            /* If we received a PING message earlier, try to PONG. */
            if (want_pong) {
                if (kdchild_send(child_data, CHILD_MSG_PONG) < 0) {                    
                    if (child_data->pf_comm->state != COMM_EINTR) {
                        KERROR_PUSH(_client_, 0, "error writing to master process");
                        break;
                    }                                        
                }
                else 
                    want_pong = 0;
            }
            /* If we received a socket message earlier try to obtain
               the socket. */
            else if (want_socket) {
                enum comm_state s;

                s = kdcomm_wait_read(child_data->pf_comm);
                if (s == COMM_READY) {
                    client_fd = read_fd(child_data->pf_comm->fd, &client_fd_is_ssl);
                    want_socket = 0;
                    break;
                }
                else if (s == COMM_HUP) {
                    INFO(_log_client_, "Master process hung-up.");
                    break;
                }
                else if (s != COMM_EINTR) {
                    KERROR_PUSH(_client_, 0, "error reading from master process");
                    break;
                } 
            }
            /* No command to resume, read from the master process. */
            else {
                if (kdchild_read(child_data, &msg_in) < 0) {
                    if (child_data->pf_comm->state == COMM_HUP) {
                        INFO(_log_client_, "Master process hung-up.");
                        break;
                    }
                    else if (child_data->pf_comm->state != COMM_EINTR) {
                        KERROR_PUSH(_client_, 0, "error reading from master process");
                        break;
                    }
                    msg_in = CHILD_MSG_NONE;                    
                }
            }

            /* No message? This means an interruption. */
            if (msg_in == CHILD_MSG_NONE) {
                kdsignal_block_all_handled();

                /* Interruption? Handle signals. */
                if (do_quit) {
                    kdsignal_unblock_all_handled();
                    break;
                }
#ifdef KD_DEBUG
                else if (do_lockup) {
                    WARN(_log_client_, "Lockup signal received!");
                    while(1);
                }
#endif // KD_DEBUG

                kdsignal_unblock_all_handled();
            }
            /* Otherwise check what we got. */
            else {
                /* Determine what type of message we received. */
                switch (msg_in) {
                case CHILD_MSG_CLIENT:
                    want_socket = 1;
                    break;

                case CHILD_MSG_PING:
                    want_pong = 1;
                    break;
                    
                case CHILD_MSG_DONE:
                    do_quit = 1;
                    break;
                }

                msg_in = CHILD_MSG_NONE;
            }
        }        

        if (client_fd != -1 && !do_quit) {
            if (kdclient_child_busy(cli, client_fd, client_fd_is_ssl) < 0)
                break;
            else
                err = 0;
        }
        else {
            err = 0;
            break;
        }

    } while (cd->state == CHILD_FREE && cd->child_loops && !do_quit);

    /* Kill the error if the upper loop say there was none. */
    if (!err) kerror_reset();
   
    if (!err && do_quit) 
        INFO(_log_client_, "Client quitting by request.");
    else if (!err)
        INFO(_log_client_, "Client quitting.");
    else if (err)
        kdclient_error("Client quitting.");

    apr_pool_destroy(cli_pool);

    return kerror_has_error() ? -1 : 0;
}

