/**
 * tbxsosd/podder.c
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
 * Teambox Sign-On Server Daemon Proof of Delivery sender.
 * @author: François-Denis Gonthier 
 */

#include <sys/time.h>
#include <apr_strings.h>
#include <apr_signal.h>
#include <apr_thread_proc.h>
#include <apr_portable.h>
#include <apr_poll.h>
#include <assert.h>
#include <tagcryptsignature.h>
#include <locale.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <kerror.h>
#include <time.h>

#include "common_pkg.h"

#include "keys.h"
#include "package.h"
#include "options.h"
#include "str.h"
#include "logid.h"
#include "podder.h"
#include "logging.h"
#include "utils.h"
#include "template.h"
#include "sendmail.h"
#include "crypto_proto_str.h"

#define INT_MAX_STR sizeof(STR(INT_MAX)) - 1

const char strsubject[] = "Proof of delivery from %s";
const char strto[] = "<%s>;";

const char *templates[] = {
    "pod_en.tmpl",
    "pod_fr.tmpl"
};

/** Properly format the KSN for display in the PoD message. */
static char *kdpodder_ksn_string(apr_pool_t *pool, struct kdpodder_params *pod_params) {
    size_t i, j = 0;
    char ksn[TAGCRYPT_KSN_SIZE];
    size_t ksn_s = sizeof(ksn);
    char *ksn_str;
    size_t ksn_str_s = 2 * sizeof(ksn);

    tagcrypt_signature_get_ksn((tagcrypt_signature *)pod_params->sign, ksn, ksn_s);
    ksn_str = apr_palloc(pool, ksn_str_s + 4 + 1);

    for (i = 0; i < 8; i++, j += 2)
        sprintf(&ksn_str[j], "%02x", (uint8_t)ksn[i]);

    ksn_str[j++] = '-';

    for (i = 8; i < 16; i++, j += 2)
        sprintf(&ksn_str[j], "%02x", (uint8_t)ksn[i]);

    ksn_str[j++] = '-';

    for (i = 16; i < 24; i++, j += 2)
        sprintf(&ksn_str[j], "%02x", (uint8_t)ksn[i]);

    return ksn_str;
}

/** Set the subject state. */
static int kdpodder_subject_state(struct kdpodder_params *pod_params) {
    int ss;
    kstr subject, trimed_subject;
    size_t s;

    /* We need to trim the subject to check the PoD. */
    kstr_init_cstr(&subject, pod_params->orig_subject);
    kstr_init(&trimed_subject);

    s = strlen(pod_params->orig_subject);

    /* Subject missing in signature and in received message == no
       changes. */
    if (pod_params->sign->subpackets[TAG_SP_TYPE_SUBJECT] == NULL && s == 0) 
        ss = 1;

    /* Subject missing in signature but present in received message ==
       change. */
    else if (pod_params->sign->subpackets[TAG_SP_TYPE_SUBJECT] == NULL && s > 0) 
        ss = 0;
    
    /* Subject present in signature but missing in received message ==
       change. */
    else if (pod_params->sign->subpackets[TAG_SP_TYPE_SUBJECT] != NULL && s == 0)
        ss = 0;

    /* Subject present in signature and message == change. */
    else if (pod_params->sign->subpackets[TAG_SP_TYPE_SUBJECT] != NULL && s > 0) {
        str_trim_whitespace(&subject, &trimed_subject);
    
        if (tagcrypt_signature_check(pod_params->sign, TAG_SP_TYPE_SUBJECT,
                                     (uint8_t *)trimed_subject.data, trimed_subject.slen) == 0)
            ss = 1;
        else
            ss = 0;
    }

    kstr_clean(&subject);
    kstr_clean(&trimed_subject);

    return ss;
}

/** Format the PoD message to be signed. */
static int kdpodder_prepare_body(apr_pool_t *parent_pool, 
                                 struct kdpodder_params *pod_params,
                                 kbuffer *body_buf, 
                                 kbuffer *err_buf) {
    apr_pool_t *pool;
    struct template *tmpl;
    char *ksn;
    int subject_state, err = -1;
    uint32_t lang;

    apr_pool_create(&pool, parent_pool);

    /* Format the KSN */
    ksn = kdpodder_ksn_string(pool, pod_params);

    /* Get the subject state. */
    subject_state = kdpodder_subject_state(pod_params);

    /* Check the langage we need to produce the message in. */
    tagcrypt_sign_get_lang(pod_params->sign, &lang);

    /* Prepare the template. */
    tmpl = template_new(pool, 
                        templates[lang], 
                        options_get_str("pod.formatmail_path"),
                        options_get_uint32("pod.timeout"));
   
    template_set_str(tmpl, "ip", pod_params->ip);
    template_set_str(tmpl, "orig_from_addr", pod_params->orig_from_addr);
    template_set_str(tmpl, "orig_subject", pod_params->orig_subject);
    template_set_uint64(tmpl, "pod_date", pod_params->pod_date->tv_sec);
    template_set_str(tmpl, "orig_serial_number", ksn);
    template_set_uint32(tmpl, "orig_subject_state", subject_state);
    template_set_uint32(tmpl, "orig_packaging_type", pod_params->sign->type);
    
    if (template_format(tmpl, body_buf, err_buf) == 0) 
        err = 0;

    apr_pool_destroy(pool);

    return err;
}

/** Sign the formatted PoD body. */
static int kdpodder_sign_body(apr_pool_t *parent_pool, 
                              const char *pod_subject,
                              const char *pod_to,
                              kbuffer *body_buf, 
                              kbuffer *sign_buf) {
    struct kd_package *pkg;
    struct kd_signed *pkg_sig;
    struct kdkey_info *ki;
    apr_pool_t *pool;    
    int err = -1;

    apr_pool_create(&pool, parent_pool);

    /* Load the PoD key. */    
    if (kdkey_get_sig_skey(pool, options_get_uint64("pod.key_id"), &ki) < 0) 
        KERROR_PUSH(_pod_, 0, "failed to obtain the PoD signing key");       

    else {
        pkg = kdpackage_new(pool);

        /* Set the packaging parameters. */
        pkg->major = 4;
        pkg->minor = 1;
        pkg->pkg_type = TAG_P_TYPE_SIGN;
        pkg->from_name = options_get_str("pod.from_name");
        pkg->from_addr = options_get_str("pod.from_addr");
        pkg->to = pod_to;
        pkg->subject = pod_subject;
        pkg->body_type = BODY_TYPE_TEXT;
        pkg->text_body = (const char *)body_buf->data;
        pkg->text_body_s = body_buf->len;
        pkg->lang = 0;
        pkg->sender_sig_skey = ki;

        pkg_sig = kdpackage_new_signed(pool, pkg);

        /* Package the mail. */
        if (kdpackage_sign(pkg, NULL, pkg_sig) < 0) 
            KERROR_PUSH(_pod_, 0, "failed to package the mail");
        else {
            /* Format the mail. */
            kdpackage_format(pkg, pool, NULL, pkg_sig, sign_buf);
            err = 0;
        }

        apr_pool_destroy(pool);
    }

    return err;
}

static int kdpodder_prepare_PoD(apr_pool_t *parent_pool, 
                                const char *pod_subject,
                                const char *pod_to,
                                struct kdpodder_params *pod_params,
                                kbuffer *main_buf) {
    apr_pool_t *pool;
    kbuffer *body_buf, *sign_buf, *err_buf;
    int err = -1;

    apr_pool_create(&pool, parent_pool);
    body_buf = kbuffer_new();
    err_buf = kbuffer_new();
    sign_buf = kbuffer_new();

    /* Format the PoD message body to be signed. */
    if (kdpodder_prepare_body(pool, pod_params, body_buf, err_buf) < 0) 
        KERROR_PUSH(_pod_, 0, "failed to generate PoD body");
    else {
        /* Sing the PoD message. */
        if (kdpodder_sign_body(pool, pod_subject, pod_to, body_buf, sign_buf) < 0)  
            KERROR_PUSH(_pod_, 0, "failed to sign PoD body");        
        else {
            /* Prepare the message. */
            kbuffer_write_cstr(main_buf, KRYPTIVA_SIGNED_BODY_START);
            kbuffer_write_buffer(main_buf, body_buf);
            kbuffer_write_buffer(main_buf, sign_buf);
        }

        err = 0;
    }

    kbuffer_destroy(body_buf);
    kbuffer_destroy(sign_buf);
    kbuffer_destroy(err_buf);
    apr_pool_destroy(pool);

    return err;
}

int kdpodder_send(apr_pool_t *parent_pool, struct kdpodder_params *pod_params){
    int err = -1;
    apr_pool_t *pool;
    kbuffer *main_buf;
    struct sendmail_args mail_args;
    struct message pod_msg;
    char *pod_subject;
    char *pod_to;

    apr_pool_create(&pool, parent_pool);
    
    main_buf = kbuffer_new();
    pod_subject = apr_psprintf(pool, strsubject, pod_params->orig_from_addr);
    pod_to = apr_psprintf(pool, strto, pod_params->pod_to);
    
    if (kdpodder_prepare_PoD(pool, pod_subject, pod_to, pod_params, main_buf) < 0) 
        KERROR_PUSH(_pod_, 0, "failed to prepare PoD message");
    else {
        /* Call sendmail to send the PoD message. */
        memset(&pod_msg, 0, sizeof(struct message));
        pod_msg.from_name = options_get_str("pod.from_name");
        pod_msg.from_addr = options_get_str("pod.from_addr");
        pod_msg.to = pod_params->pod_to;
        pod_msg.cc = NULL;
        pod_msg.subject = pod_subject;
        pod_msg.body_text = (char *)main_buf->data;
        pod_msg.body_text_s = main_buf->len;
    
        mail_args.mail_to = pod_params->pod_to;
        mail_args.msg = &pod_msg;
    
        /* Send the message through the system's sendmail. */
        if (sendmail(pool, &mail_args) < 0) 
            KERROR_PUSH(_pod_, 0, "failed to send PoD message through sendmail");
        else
            err = 0;    
    }
    
    kbuffer_destroy(main_buf);
    apr_pool_destroy(pool);

    return err;
}
