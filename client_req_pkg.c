/**
 * tbxsosd/client_req_pkg.c
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
 * Client packaging functions.
 *
 * Splitted of client.c for convenience.  Include the functions
 * required to package a packet from a client logged with OTUT or
 * logged normally.
 *
 * @author François-Denis Gonthier
*/

#include <apr_shm.h>
#include <apr_proc_mutex.h>
#include <kerror.h>
#include <kstr.h>
#include <kmem.h>
#include <kbuffer.h>

#include "keys.h"
#include "server.h"
#include "crypto_proto_str.h"
#include "package.h"
#include "packet.h"
#include "client.h"
#include "logid.h"
#include "logging.h"
#include "utils.h"
#include "options.h"
#include "otut.h"

#include "client_req_pkg.h"

#if defined(REQUEST_PACKAGE)

/* FIXME: The big functions at the bottom of this file could benefit
   from being refactored. */

static int pkg_write_stats(apr_pool_t *pool, struct kdpacket *in_pkt, struct kdpacket *out_pkt) {
    uint32_t i, attch_total_size = 0;
    uint32_t nb_attach = 0, nb_pwd = 0, nb_recip = 0, pkg_type = 0;
    size_t body_html_s = 0, body_text_s = 0, pkg_out_s = 0;
    struct proto_attachment *pa;

    assert(kdpacket_is_present(in_pkt, EL_PKG_TYPE));
    kdpacket_get_uint32(in_pkt, EL_PKG_TYPE, &pkg_type);

    assert(kdpacket_is_present(in_pkt, EL_ATTACHMENT_ARRAY));
    nb_attach = kdpacket_get_list_len(in_pkt, EL_ATTACHMENT_ARRAY);

    assert(kdpacket_is_present(in_pkt, EL_PASSWORD_ARRAY));
    nb_pwd = kdpacket_get_list_len(in_pkt, EL_PASSWORD_ARRAY);

    assert(kdpacket_is_present(in_pkt, EL_RECIPIENT_ARRAY));
    nb_recip = kdpacket_get_list_len(in_pkt, EL_RECIPIENT_ARRAY);

    assert(kdpacket_is_present(in_pkt, EL_BODY_TEXT));
    kdpacket_get_raw(in_pkt, EL_BODY_TEXT, NULL, &body_text_s);
    
    assert(kdpacket_is_present(in_pkt, EL_BODY_HTML));
    kdpacket_get_raw(in_pkt, EL_BODY_HTML, NULL, &body_html_s);

    assert(kdpacket_is_present(out_pkt, EL_PACKAGE_OUTPUT));
    kdpacket_get_str(out_pkt, EL_PACKAGE_OUTPUT, NULL, &pkg_out_s);

    for (i = 0; i < nb_attach; i++) {
        kdpacket_get_list_item(in_pkt, EL_ATTACHMENT_ARRAY, i, (void **)&pa, NULL);        
        attch_total_size += pa->payload_s;
    }

    struct event ev[8] = {
        {.key = "pkg_type", .type = EV_VAR_UINT32, .val.uint32 = pkg_type},
        {.key = "nb_recipient", .type = EV_VAR_UINT32, .val.uint32 = nb_recip},
        {.key = "nb_pwd", .type = EV_VAR_UINT32, .val.uint32 = nb_pwd},
        {.key = "nb_attch", .type = EV_VAR_UINT32, .val.uint32 = nb_attach},
        {.key = "body_text_len", .type = EV_VAR_UINT32, .val.uint32 = body_text_s},
        {.key = "body_html_len", .type = EV_VAR_UINT32, .val.uint32 = body_html_s},
        {.key = "attach_total_size", .type = EV_VAR_UINT32, .val.uint32 = attch_total_size},
        {.key = "output_len", .type = EV_VAR_UINT32, .val.uint32 = pkg_out_s}
    };

    if (kddb_event(pool, kdsh_get_session_counter(), "pkg", 8, ev) < 0) 
        kdclient_warn("Failed to log 'pkg' event.");
       
    return 0;
}

static int pkg_filter(kdclient *self, apr_pool_t *parent_pool, struct kdpacket *in_pkt) {
    int error = -1;
    struct filter_result fr;
    struct filter_params params;  
    struct proto_attachment *pa;
    uint32_t i, nb_attach;
    const char *str;
    size_t str_s;
    apr_pool_t *pool;
    
    /* Check if the user packaging the mail should be dispensed from filtering. */
    if (self->user->type == KD_USER_NORMAL) {
        const char *user = options_get_str("server.no_mail_scan_user");

        if (strcmp(self->user->username, user) == 0)
            return 0;
    }
    
    apr_pool_create(&pool, parent_pool);

    memset(&params, 0, sizeof(params));

    /* Assert that all the required elements are present for filtering. */

    /* To */
    assert(kdpacket_is_present(in_pkt, EL_TO));
    kdpacket_get_str(in_pkt, EL_TO, &params.msg.to, NULL);

    /* From name */
    assert(kdpacket_is_present(in_pkt, EL_FROM_NAME));
    kdpacket_get_str(in_pkt, EL_FROM_NAME, &str, NULL);
    if (str != NULL) 
        params.msg.from_name = str;
    else
        params.msg.from_name = "";

    /* From address. */

    assert(kdpacket_is_present(in_pkt, EL_FROM_ADDRESS));
    kdpacket_get_str(in_pkt, EL_FROM_ADDRESS, &str, NULL);

    /* Make sure the recipient address looks like a legitimate
       email address. */
    if (str && str[0] == '/') {    
        char *t;        

        /* Oops, this is not a SMTP address.  Check what kind of
           address it is and try to match the corresponding SMTP
           address. */
        if (kddb_convert_address(pool, str, self->user->primary_email_addr, &t) < 0) {
            kdclient_error("Failed to find SMTP address of %s.", str);
            apr_pool_destroy(pool);
            return -1;
        }

        str = t;
    }

    if (str != NULL)
        params.msg.from_addr = str;
    else
        params.msg.from_addr = "";

    /* Cc */
    assert(kdpacket_is_present(in_pkt, EL_CC));
    kdpacket_get_str(in_pkt, EL_CC, &str, NULL);
    if (str != NULL)
        params.msg.cc = str;
    else
        params.msg.cc = "";

    /* Subject. */
    assert(kdpacket_is_present(in_pkt, EL_SUBJECT));
    kdpacket_get_str(in_pkt, EL_SUBJECT, &str, NULL);
    if (str != NULL)
        params.msg.subject = str;
    else
        params.msg.subject = "";

    /* Text body. */
    assert(kdpacket_is_present(in_pkt, EL_BODY_TEXT));
    kdpacket_get_raw(in_pkt, EL_BODY_TEXT, (void **)&str, &str_s);
    if (str != NULL) {
        params.msg.body_text = str;
        params.msg.body_text_s = str_s;
    } else {
        params.msg.body_text = "";
        params.msg.body_text_s = 0;
    }

    /* HTML body. */
    assert(kdpacket_is_present(in_pkt, EL_BODY_HTML));
    kdpacket_get_raw(in_pkt, EL_BODY_HTML, (void **)&str, &str_s);
    if (str != NULL) {
        params.msg.body_html = str;
        params.msg.body_html_s = str_s;
    } else {
        params.msg.body_html = "";
        params.msg.body_html_s = 0;
    }

    /* Attachments. */
    assert(kdpacket_is_present(in_pkt, EL_ATTACHMENT_ARRAY));
    nb_attach = kdpacket_get_list_len(in_pkt, EL_ATTACHMENT_ARRAY);

    params.msg.attch_count = nb_attach;    
    if (nb_attach > 0) {
        params.msg.attch = apr_pcalloc(pool, nb_attach * sizeof(struct message_attachment));

        for (i = 0; i < nb_attach; i++) {
            kdpacket_get_list_item(in_pkt, EL_ATTACHMENT_ARRAY, i, (void **)&pa, NULL);

            params.msg.attch[i].encoding = pa->encoding;
            params.msg.attch[i].mime_type = pa->mime_type;
            params.msg.attch[i].name = pa->name;
            params.msg.attch[i].payload = pa->payload;
            params.msg.attch[i].payload_s = pa->payload_s;
        }
    }

    /* Give the filters access to database data. */
    params.user = self->user;

    do {
        /* Execute the chain of filters. */
        if (kdfilter_exec(self->filter_obj, &params, &fr) < 0) {
            kdclient_error("Filtering error.");
            break;
        }

        if (fr.rating != 0) {
            kdclient_warn("Message has been denied because of filtering.");
            KERROR_SET(_filter_, 1, "request denied: %s", fr.msg);
            break;
        }
	
	error = 0;
	
    } while (0);

    apr_pool_destroy(pool);

    return error;
}

#if defined(REQUEST_PACKAGE)
static inline int client_tag_type_from_pkg_type(uint32_t pkg_type) {
    return 
        pkg_type == KNP_PKG_TYPE_ENC  ? TAG_P_TYPE_ENC :      
        pkg_type == KNP_PKG_TYPE_POD  ? TAG_P_TYPE_POD :      
        pkg_type == (KNP_PKG_TYPE_POD | KNP_PKG_TYPE_ENC) ? TAG_P_TYPE_PODNENC :
        TAG_P_TYPE_SIGN;                                      
}
#endif

/** Add attachments to the package. */
static void pkg_add_attachments(struct kdpacket *in_pkt,
                                struct kd_package *pkg) {
    size_t n;
    uint32_t i, nb_attachs;
    struct proto_attachment *pa;

    assert(kdpacket_is_present(in_pkt, EL_ATTACHMENT_ARRAY));
    nb_attachs = kdpacket_get_list_len(in_pkt, EL_ATTACHMENT_ARRAY);
    n = nb_attachs * sizeof(struct proto_attachment *);

    if (nb_attachs == 0) return;
    
    pkg->attachments = apr_pcalloc(pkg->pool, n);
    pkg->attachment_count = nb_attachs;

    for (i = 0; i < nb_attachs; i++) { 
        kdpacket_get_list_item(in_pkt, EL_ATTACHMENT_ARRAY, i, (void **)&pa, NULL);
        pkg->attachments[i] = apr_pcalloc(pkg->pool, sizeof(struct proto_attachment));
        memcpy(pkg->attachments[i], pa, sizeof(struct proto_attachment));
    }

    if (nb_attachs > 0)
        DEBUG(_log_pkg_, "Message attachments (%d) are ready to be signed.", nb_attachs);
}

static void pkg_add_basic_informations(struct kdpacket *in_pkt, struct kd_package *pkg) {
    int n;
    uint32_t pkg_type;
    const char *kpg_addr;
    uint16_t kpg_port;

    assert(kdpacket_is_present(in_pkt, EL_FROM_ADDRESS));
    assert(kdpacket_is_present(in_pkt, EL_FROM_NAME));
    assert(kdpacket_is_present(in_pkt, EL_TO));
    assert(kdpacket_is_present(in_pkt, EL_CC));
    assert(kdpacket_is_present(in_pkt, EL_SUBJECT));

    kdpacket_get_uint32(in_pkt, EL_PKG_TYPE, &pkg_type);
    n = client_tag_type_from_pkg_type(pkg_type);

    pkg->pkg_type = n;
    pkg->major = in_pkt->major;
    pkg->minor = in_pkt->minor;

    if (kdpacket_is_present(in_pkt, EL_LANG))
        kdpacket_get_uint32(in_pkt, EL_LANG, &pkg->lang);
    else
        pkg->lang = 0;

    kdpacket_get_str(in_pkt, EL_FROM_ADDRESS, &pkg->from_addr, NULL);
    kdpacket_get_str(in_pkt, EL_FROM_NAME, &pkg->from_name, NULL);
    kdpacket_get_str(in_pkt, EL_TO, &pkg->to, NULL);
    kdpacket_get_str(in_pkt, EL_CC, &pkg->cc, NULL);
    kdpacket_get_str(in_pkt, EL_SUBJECT, &pkg->subject, NULL);

    /* Check if we want to set the KPG address. */
    kpg_addr = options_get_str("server.kpg_address");
    kpg_port = options_get_uint16("server.kpg_address");

    if (strcmp(kpg_addr, "") != 0) {
        pkg->kpg_addr = kpg_addr;
        pkg->kpg_port = kpg_port;
    }

    DEBUG(_log_pkg_, "Message basic informations are ready to be signed.");
}

/** Add text and HTML bodies to the message. */
static void pkg_add_bodies(struct kdpacket *in_pkt,
                           struct kd_package *pkg) {
    uint32_t body_type;
    const char *body_html = NULL, *body_text = NULL;
    size_t body_html_s = 0, body_text_s = 0;

    assert(kdpacket_is_present(in_pkt, EL_BODY_HTML));
    assert(kdpacket_is_present(in_pkt, EL_BODY_TEXT));
    assert(kdpacket_is_present(in_pkt, EL_BODY_TYPE));

    kdpacket_get_uint32(in_pkt, EL_BODY_TYPE, &body_type);
    kdpacket_get_raw(in_pkt, EL_BODY_HTML, (void **)&body_html, &body_html_s);
    kdpacket_get_raw(in_pkt, EL_BODY_TEXT, (void **)&body_text, &body_text_s);

    pkg->body_type = body_type;

    /* Add text and HTML bodies. */
    if (body_type == BODY_TYPE_HTML || body_type == BODY_TYPE_BOTH) {
        pkg->html_body = body_html;
        pkg->html_body_s = body_html_s;

        DEBUG(_log_pkg_, "Message HTML body ready to be signed.");
    }

    if (body_type == BODY_TYPE_TEXT || body_type == BODY_TYPE_BOTH) {
        pkg->text_body = body_text;
        pkg->text_body_s = body_text_s;

        DEBUG(_log_pkg_, "Message text body ready to be signed.");
    }
}

/** Add a set of password recipients to the package. */
static int pkg_add_passwords(struct kdpacket *in_pkt,
                             struct kd_package *pkg) {
    uint32_t i, nb_pwd;
    struct proto_password *pwd;

    assert(kdpacket_is_present(in_pkt, EL_PASSWORD_ARRAY));
    nb_pwd = kdpacket_get_list_len(in_pkt, EL_PASSWORD_ARRAY);

    /* Add all passwords. */
    for (i = 0; i < nb_pwd; i++) {
        kdpacket_get_list_item(in_pkt, EL_PASSWORD_ARRAY, i, (void **)&pwd, NULL);

        /* Guard against empty passwords. */
        if (pwd->pwd == NULL) {
            kdclient_error("Cannot add empty password.");
            return -1;
        }

        if (kdpackage_add_recver_pwd(pkg, pwd->pwd, pwd->otut, pwd->otut_s) < 0) {
            kdclient_error("Failed to add password to packaging parameters.");
            return -1;
        }
    }
    
    if (nb_pwd > 0)
        DEBUG(_log_pkg_, "Message non-members recipients (%d) are ready to be encrypted.", nb_pwd);

    return 0;
}

/** Add a set of recipient to the package.
 *
 * This convert Microsoft Exchange addresses if required.
 */
static int pkg_add_recipients(struct kdpacket *in_pkt, 
                              apr_pool_t *parent_pool, 
                              struct kd_package *pkg) {
    int error = 0;
    uint32_t i, nb_recip;
    struct proto_recipient *recip;
    struct kdkey_info tm_pkey;
    char *real_addr;
    apr_pool_t *pool;
    int n;
    const char *tm_key_data;
    size_t tm_key_size;
   
    /* Update and get the timestamp key if there is one. */
    if (kdpacket_is_present(in_pkt, EL_TM_KEY_DATA)) {
        kdpacket_get_str(in_pkt, EL_TM_KEY_DATA, &tm_key_data, &tm_key_size);

        n = kdkey_extract_tm_pkey(pkg->pool, tm_key_data, tm_key_size, &tm_pkey);
        if (tm_key_size != 0 && n < 0) {
            kdclient_error("Client error in getting the provided timestamp key.");
            return -1;
        }
    }
    
    assert(kdpacket_is_present(in_pkt, EL_RECIPIENT_ARRAY));    
    nb_recip = kdpacket_get_list_len(in_pkt, EL_RECIPIENT_ARRAY);
    apr_pool_create(&pool, parent_pool);

    /* Add all known members. */
    for (i = 0; i < nb_recip; i++) {
        kdpacket_get_list_item(in_pkt, EL_RECIPIENT_ARRAY, i, (void **)&recip, NULL);

        if (recip->addr == NULL) {
            WARN(_log_client_, "Odd recipient, empty address received.");
            continue;
        }

        if (recip->enc_type == RECIP_KEY && recip->key_data != NULL) {
            /* Make sure the recipient address looks like a legitimate
               email address. */
            if (recip->addr[0] != '/') real_addr = (char *)recip->addr;

            /* Oops, this is not a SMTP address.  Check what kind of
               address it is and try to match the corresponding SMTP
               address. */
            else if (kddb_convert_address(pool, recip->addr, NULL, &real_addr) < 0) {
                kdclient_error("Failed to find SMTP address of %s.", recip->addr);
                error = -1;
                break;
            }

            DEBUG(_log_pkg_, "Adding member recipients: %s.", real_addr);

            /* Note that package_add_recver_enc_pkey can accept NULL
               timestamping key. */
            if (kdpackage_add_recver_enc_pkey(pkg, 
                                              NULL, // FIXME: Unsigned
                                                    // encryption keys.
                                              recip->key_data,
                                              real_addr) < 0) {
                kdclient_error("Failed to add key for user %s.", recip->addr);
		error = -1;
	    }
        }
        else if (recip->enc_type == RECIP_KEY && recip->key_data == NULL && recip->addr != NULL)
            WARN(_log_pkg_, "Odd member recipient (%s): no key.", recip->addr);
    }

    if (!error)
        DEBUG(_log_pkg_, "Message members recipients are ready to be encrypted.");

    apr_pool_destroy(pool);

    return error;
}

/** Checks if the HTML is allowed. */
static int pkg_check_html(kdclient *self, struct kdpacket *in_pkt) {
    uint32_t body_type;
    char *html_err = 
        "The KPS you are using is not configured"
        " to allow HTML emails, contact your system administrator "
        "for more information.";

    assert(kdpacket_is_present(in_pkt, EL_BODY_TYPE));
    kdpacket_get_uint32(in_pkt, EL_BODY_TYPE, &body_type);

    /* Check if the server allows HTML. */
    if (!self->allow_html &&
        (body_type == BODY_TYPE_HTML || body_type == BODY_TYPE_BOTH)) {
          
        /* This will reach the user. */
        KERROR_SET(_client_, 1, html_err);
        return -1;
    }
    
    return 0;
}

/** Limits access rights to users logged-in with OTUT. */
#ifdef REQUEST_OTUT_LOGIN
static int pkg_check_otut_access(kdclient *self, struct kdpacket *in_pkt) {
    int n;
    uint32_t nb_recip = 0, nb_pwd = 0, pkg_type = 0;
    const char *dst_addr = 0;
    struct proto_recipient *recip;
    char *otut_err =
        "When using a One Time Use encrypted reply Token,"
        " the email can only be addresses to the original "
        "sender and the only packaging option is encryption.";

    assert(kdpacket_is_present(in_pkt, EL_RECIPIENT_ARRAY));
    assert(kdpacket_is_present(in_pkt, EL_PASSWORD_ARRAY));
    assert(kdpacket_is_present(in_pkt, EL_PKG_TYPE));

    kdpacket_get_uint32(in_pkt, EL_PKG_TYPE, &pkg_type);
    nb_recip = kdpacket_get_list_len(in_pkt, EL_RECIPIENT_ARRAY);
    nb_pwd = kdpacket_get_list_len(in_pkt, EL_PASSWORD_ARRAY);

    /* Check there is at least one recipient. */
    if (nb_recip == 0) {
        KERROR_SET(_client_, 0, "no recipients");
        return -1;
    }

    kdpacket_get_list_item(in_pkt, EL_RECIPIENT_ARRAY, 0, (void **)&recip, NULL);
    dst_addr = recip->addr;

    n = otut_check_address(self->user, dst_addr, strlen(dst_addr));
    /* Proceed to some access-right checkups. */
    if (pkg_type != KNP_PKG_TYPE_ENC /* Wrong packaging type */ 
        || nb_recip > 1 /* Too many recipients */
        || nb_pwd > 0 /* Password recipients. */
        || n < 0 /* Original packager */) {
        KERROR_SET(_client_, 1, otut_err);
        return -1;
    }

    return 0;
}
#endif // REQUEST_OTUT_LOGIN

static int kdclient_check_pkg_caps(kdclient *self, int pkg_type) {
    /* If the user can't sign, we can't continue at all. */
    if ((self->user->caps & CAN_SIGN) == 0) {
        KERROR_SET(_client_, 1, "User cannot sign mails.");
        return -1;
    }
    if ((self->user->lic & CAN_SIGN) == 0) {
        KERROR_SET(_client_, 1, "User does not have the license to sign mails.");
        return -1;
    }

    /* Encryption. */
    if (pkg_type == 1 || pkg_type == 3) {
        if ((self->user->caps & CAN_ENCRYPT) == 0) {
            KERROR_SET(_client_, 1, "User cannot encrypt mails.");
            return -1;
        }
        if ((self->user->lic & CAN_ENCRYPT) == 0) {
            KERROR_SET(_client_, 1, "User does not have the license to encrypt mails.");
            return -1;
        }
    }

    /* PoD */
    if (pkg_type == 2 || pkg_type == 3) {
        if ((self->user->caps & CAN_POD) == 0) {
            KERROR_SET(_client_, 1, "User cannot request proof-of-delivery.");
            return -1;
        }
        if ((self->user->lic & CAN_POD) == 0) {
            KERROR_SET(_client_, 1, "User does not have the license to request proof-of-delivery.");
            return -1;
        }
    }

    return 0;
}

/* FIXME: Cleanup and shorten this function. */
#ifdef REQUEST_OTUT_LOGIN
enum client_state kdclient_request_package_otut(kdclient *self,
                                                apr_pool_t *pkt_pool,
                                                struct kdpacket *in_pkt,
                                                struct kdpacket **out_pkt) {
    int n;
    uint32_t lang, pkg_type;
    int rem_fails, rem_uses;
    enum client_state next_state = self->cstate;
    struct kd_package *pkg = NULL;
    struct kd_signed *sig = NULL;
    struct kd_encrypted *enc = NULL;
    apr_pool_t *pkg_pool;

    INFO(_log_client_, "Request: Encrypt with OTUT.");

    /* This should never be called without a successful OTUT login. */
    assert(kdpacket_get_type(in_pkt) == PKT_PACKAGE_CMD);

    apr_pool_create(&pkg_pool, pkt_pool);

    /* Check if we can get the langage, otherwise default to 0
       (english) */
    if (kdpacket_is_present(in_pkt, EL_LANG)) 
        kdpacket_get_uint32(in_pkt, EL_LANG, &lang);

    do {
        self->counter = kdsh_get_counter();

        /* Get the packaging type that was demanded. */
        kdpacket_get_uint32(in_pkt, EL_PKG_TYPE, &pkg_type);

        /* FIXME: Should probably be a filter. */
        if (pkg_check_otut_access(self, in_pkt) < 0) {
            kdclient_warn("OTUT user tried to strech his limited priviledges.");
            next_state = CSTATE_DROP_ACK;
            break;
        }
        /* FIXME: Should be a filter. */
        if (pkg_check_html(self, in_pkt) < 0) {
            kdclient_warn("Server refuses to package HTML mails.");
            break;
        }
        if (pkg_filter(self, pkg_pool, in_pkt) < 0) {
            kdclient_warn("Filtering denied the request.");
            break;
        }        

        /* Check the client capabilities. */
        if (kdclient_check_pkg_caps(self, pkg_type) < 0) {
            kdclient_warn("User %s cannot package mail in the way he has requested.",
                          self->user->username);
            break;
        }        

        DEBUG(_log_pkg_, "Message has been through the filtering stage.");
        
        n = client_tag_type_from_pkg_type(pkg_type);

        pkg = kdpackage_new(pkg_pool);

        pkg_add_basic_informations(in_pkt, pkg);
        if (pkg_add_recipients(in_pkt, pkg_pool, pkg) < 0) break;
        pkg_add_bodies(in_pkt, pkg);
        pkg_add_attachments(in_pkt, pkg);
        
        /* Get the signature key. */
        pkg->sender_sig_skey = self->user->sig_skey;
        pkg->sender_sig_pkey = self->user->sig_pkey;

        sig = kdpackage_new_signed(pkg_pool, pkg);
        enc = kdpackage_new_encrypted(pkg_pool);

        /* Encrypt the body. */
        if (kdpackage_encrypt(pkg, enc) < 0) {
            kdclient_error("Failed to encrypt body.");
            break;
        }        

        DEBUG(_log_pkg_, "Client message has been successfully encrypted.");

        /* Get the signature text! weeeee! */
        if (kdpackage_sign(pkg, enc, sig) < 0) {
            kdclient_error("Failed to obtain signature.");
            break;
        }

        DEBUG(_log_pkg_, "Client message has been successfully signed.");

        /* Get the output elements. */
        const char *ksn = NULL, *sk = NULL;        
        size_t ksn_s = 0, sk_s = 0;
        kbuffer *result_buf;
        struct sockaddr *sa;        

        kdcomm_get_peer(self->main_comm, pkg_pool, NULL, &sa);

        ksn = sig->ksn;
        ksn_s = TAGCRYPT_KSN_SIZE;
        sk = (char *)enc->serialized_symkey->data;
        sk_s = enc->serialized_symkey->len;

        result_buf = kbuffer_new();
        kdpackage_format(pkg, pkg_pool, enc, sig, result_buf);

        INFO(_log_client_, "Request: Encrypt with OTUT successful.", self->user->username);

        struct kdpacket *op = kdpacket_new(pkt_pool, PKT_PACKAGE_RES);

        kdpacket_set_str(op, EL_PACKAGE_OUTPUT, 
                         (char *)result_buf->data, result_buf->len);
        kdpacket_set_raw(op, EL_KSN, (void *)ksn, ksn_s);
        kdpacket_set_raw(op, EL_SYMKEY, (void *)sk, sk_s);        

        pkg_write_stats(pkg_pool, in_pkt, op);

        kbuffer_destroy(result_buf);

        *out_pkt = op;

        apr_pool_destroy(pkg_pool);

        if (kddb_otut_success(self->user->otut_info->otut_str, 
                              self->user->otut_info->otut_str_s,
                              &rem_uses,
                              &rem_fails) < 0) {
            kdclient_error("Failed to register success for OTUT.");
            break;
        }

        if (rem_uses == 0) 
            INFO(_log_client_, "OTUT: No more uses remaining.  OTUT is gone!");
        else
            INFO(_log_client_, "OTUT: Remaining uses %d, Remaining failures: %d.", rem_uses, rem_fails);

        return next_state;

    } while (0);

    if (kddb_otut_fail(self->user->otut_info->otut_str, 
                       self->user->otut_info->otut_str_s,
                       &rem_uses,
                       &rem_fails) < 0) 
        kdclient_error("Failed to register failure for OTUT.");

    if (rem_fails == 0)
        INFO(_log_client_, "OTUT: No more failures remaining.  OTUT is gone!");
    else
        INFO(_log_client_, "OTUT: Remaining uses %d, Remaining failures: %d.", rem_uses, rem_fails);

    /* Old versions expect just 'fail'. */
    if (in_pkt->major < 4) 
	*out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
    
    /* New versions expect 'package failed'. */
    else {
	kstr error_str;
	kstr_init(&error_str);
	
	format_current_error_for_user(&error_str);
	*out_pkt = kdpacket_new(pkt_pool, PKT_PACKAGE_ERR);
        kdpacket_set_str(*out_pkt, EL_PACKAGE_ERR, error_str.data, error_str.slen);
	
	kstr_clean(&error_str);
    }

    apr_pool_destroy(pkg_pool);

    return next_state;    
}
#endif // REQUEST_OTUT_LOGIN

/* FIXME: Cleanup and shorten this function. */

/** All packaging requests go through here. */
enum client_state kdclient_request_package(kdclient *self,
                                           apr_pool_t *pkt_pool,
                                           struct kdpacket *in_pkt,
                                           struct kdpacket **out_pkt)  {
    char *pod_addr;
    apr_pool_t *pool;
    uint32_t n, nb_pwd, nb_recip, pkg_type, lang = 0;
    const char *req_name = NULL;
    enum client_state next_state = self->cstate;
    struct kd_package *pkg = NULL;
    struct kd_signed *sig = NULL;
    struct kd_encrypted *enc = NULL;

    apr_pool_create(&pool, pkt_pool);

    /* Check if we can get the langage, otherwise default to 0
       (english) */
    if (kdpacket_is_present(in_pkt, EL_LANG)) 
        kdpacket_get_uint32(in_pkt, EL_LANG, &lang);

    do {  
        self->counter = kdsh_get_counter();

        /* Get the packaging type that was demanded. */
        kdpacket_get_uint32(in_pkt, EL_PKG_TYPE, &pkg_type);

        if (pkg_type == 0) 
            req_name = "Sign message";            
        else if (pkg_type == 1)
            req_name = "Sign and Encrypt message";
        else if (pkg_type == 2)
            req_name = "Sign message with PoD";
        else if (pkg_type == 3)
            req_name = "Sign and Encrypt message with PoD";
        else {
            kdclient_error("Unknown packaging type %d.", req_name);
            break;
        }

        INFO(_log_client_, "Request: %s [user: %s].", req_name, self->user->username);

#ifdef REQUEST_PACKAGE_DENY_POD
        if (pkg_type == 2 || pkg_type == 3) {
            kdclient_error("Packaging mail with PoD not allowed on this version of the KPS.");
            break;
        }
#endif // REQUEST_PACKAGE_DENY_POD

        /* Check the client capabilities. */
        if (kdclient_check_pkg_caps(self, pkg_type) < 0) {
            kdclient_error("User %s cannot package mail in the way he has requested.",
                           self->user->username);
            break;
        }        

        /* FIXME: Should be a filter. */
        if (pkg_check_html(self, in_pkt) < 0) {
            kdclient_warn("Server refuses to package HTML mails.");
            break;
        }
        if (pkg_filter(self, pool, in_pkt) < 0) {
            kdclient_warn("Filtering has denied the request");
            break;
        }

        DEBUG(_log_pkg_, "Message has been through the filtering stage.");

        kdpacket_get_str(in_pkt, EL_POD_ADDRESS, (const char **)&pod_addr, NULL);       

        n = client_tag_type_from_pkg_type(pkg_type);       

        pkg = kdpackage_new(pool);

        pkg_add_basic_informations(in_pkt, pkg);
        pkg_add_bodies(in_pkt, pkg);
        pkg_add_attachments(in_pkt, pkg);
                               
        enc = kdpackage_new_encrypted(pool);

        if (((pkg_type & KNP_PKG_TYPE_POD) != 0)) {
            if (pod_addr == NULL) {
                if (kddb_get_prim_email(pool, self->user, &pod_addr) < 0) {
                    kdclient_error("Error while fetching user's primary email address.");
                    break;
                }
                
                /* Set the PoD address in the packet. */
                kdpacket_set_cstr(in_pkt, EL_POD_ADDRESS, pod_addr);
                DEBUG(_log_pkg_, "Fetched %s as primary email address for user.", 
                      pod_addr);                
            }
            else if (pod_addr[0] == '/') {
                char *real_addr;

                if (kddb_convert_address(pool, 
                                         pod_addr, 
                                         self->user->primary_email_addr, 
                                         &real_addr) < 0) {
                    kdclient_error("Failed to convert %s to SMTP address.", pod_addr);
                    break;
                }

                /* Set the PoD address in the packet. */
                kdpacket_set_cstr(in_pkt, EL_POD_ADDRESS, real_addr);
                DEBUG(_log_pkg_, 
                      "Converted %s to %s as primary email address for user.", 
                      pod_addr, real_addr);
	    	
		/* Update pod_addr. */
		pod_addr = real_addr;
            }
	    
	    /* Set the PoD address in 'pkg'. */
	    pkg->pod_addr = pod_addr;
        }

        pkg->sender_sig_pkey = self->user->sig_pkey;
        pkg->sender_sig_skey = self->user->sig_skey;

        if (pkg_type == KNP_PKG_TYPE_ENC || 
            pkg_type == KNP_PKG_TYPE_POD || 
            pkg_type == (KNP_PKG_TYPE_POD | KNP_PKG_TYPE_ENC)) {

            nb_pwd = kdpacket_get_list_len(in_pkt, EL_PASSWORD_ARRAY);
            nb_recip = kdpacket_get_list_len(in_pkt, EL_RECIPIENT_ARRAY);

            if (pkg_add_recipients(in_pkt, pool, pkg) < 0) break;
            if (pkg_add_passwords(in_pkt, pkg) < 0) break;           
	    
            /* Encrypt the body. */
            if (kdpackage_encrypt(pkg, enc) < 0) {
                kdclient_error("Failed to encrypt body.");
                break;
            }

            DEBUG(_log_pkg_, "Client message has been successfully encrypted.");
        }
        sig = kdpackage_new_signed(pool, pkg);

        /* Get the signature text! weeeee! */
        if (kdpackage_sign(pkg, enc, sig) < 0) {
            kdclient_error("Failed to obtain signature.");
            break;
        }

        DEBUG(_log_pkg_, "Client message has been successfully signed.");

        /* Get the output elements. */
        const char *ksn = NULL, *sk = NULL;        
        size_t ksn_s = 0, sk_s = 0;
        kbuffer *result_buf;

        ksn = sig->ksn;
        ksn_s = TAGCRYPT_KSN_SIZE;


        result_buf = kbuffer_new();
        kdpackage_format(pkg, pool, enc, sig, result_buf);
       
        INFO(_log_client_, "Request: %s [user: %s] successful.", req_name, self->user->username);
        
        struct kdpacket *op = kdpacket_new(pkt_pool, PKT_PACKAGE_RES);
        
        kdpacket_set_str(op, EL_PACKAGE_OUTPUT, 
                         (char *)result_buf->data, result_buf->len);
        kdpacket_set_raw(op, EL_KSN, (void *)ksn, ksn_s);
        kdpacket_set_raw(op, EL_SYMKEY, (void *)sk, sk_s);        

        if (pkg_type != 0) {
            sk = (char *)enc->serialized_symkey->data;
            sk_s = enc->serialized_symkey->len;        
        }
        
        pkg_write_stats(pool, in_pkt, op);
        
        kbuffer_destroy(result_buf);
        
        *out_pkt = op;

        apr_pool_destroy(pool);
        
        return next_state;

    } while (0);    
    
    /* Old versions expect just 'fail'. */
    if (in_pkt->major < 4) 
	*out_pkt = kdpacket_new(pkt_pool, PKT_FAIL);
    
    /* New versions expect 'package failed'. */
    else {
	kstr error_str;
	kstr_init(&error_str);
	
	format_current_error_for_user(&error_str);
	*out_pkt = kdpacket_new(pkt_pool, PKT_PACKAGE_ERR);
        kdpacket_set_str(*out_pkt, EL_PACKAGE_ERR, error_str.data, error_str.slen);
	
	kstr_clean(&error_str);
    }
    
    apr_pool_destroy(pool);

    return next_state;
}	

#endif // REQUEST_PACKAGE
