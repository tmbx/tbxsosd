/**
 * tbxsosd/proto_defs.c
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
 * Protocol function definitions.
 *
 * @author François-Denis Gonthier
 */

#include <assert.h>
#include <apr_strings.h>
#include <kerror.h>
#include <kmem.h>

#include "common/config.h"
#include "common/logid.h"
#include "libutils/logging.h"
#include "libutils/str.h"

#include "knp_core_defs.h"
#include "proto_funcs.h"
#include "proto_defs.h"
#include "proto.h"

/*
 * This macro should only be used locally.  Several parameters in the
 * functions below will have useless parameters but since we want
 * signatures to be all the same, the unused attribute is allowable.
 */
#define U __attribute__ ((unused))

/** Generic string printer for possibly long string. */
#define MAX_LONG_STRING_SIZE 8096

/** String display in case of optional elements. */
static const char optional_str[] = "<missing>";

/** Log the string in the most convenient form. 
 *
 * This is used by el_printer_generic_string and
 * el_printer_generic_string_array so we make it generic enough.
 */
static void el_print_string(const char *str, size_t str_s, 
                            const char *nm, 
                            const char *el_name, 
                            int level) {
    char *ss = NULL, *sh = NULL;
    size_t ss_s;
    int el = 0; 
    const char empty_str[] = "";
    const char *elnm;

    if (el_name != NULL) 
        elnm = el_name;
    else
        elnm = empty_str;

    /* Print a null string as <null> */
    if (str == NULL) {
        if (level == 0)
            DEBUG(_log_knp_, "%s '%s': <null>", nm, elnm);
        else if (level == 1)
            DEBUG(_log_knp_, "  %s '%s': <null>", nm, elnm);

        return;
    }
    
    /* Print nothing when the string is empty. */
    if (str_s == 0) {
        if (level == 0)
            DEBUG(_log_knp_, "%s '%s': ", nm, elnm);
        else if (level == 2)
            DEBUG(_log_knp_, "  %s '%s': ", nm, elnm);

        return;
    }

    /* Make space for the new string plus the ellipsis. */
    ss = kmalloc(MAX_LONG_STRING_SIZE + 5);

    if (str_s < MAX_LONG_STRING_SIZE) {
        memcpy(ss, str, str_s);        
        ss[str_s] = (char)'\0';
        ss_s = str_s;
    } 
    else {
        memcpy(ss, str, MAX_LONG_STRING_SIZE);
        ss_s = MAX_LONG_STRING_SIZE;
        ss[ss_s] = 0;
        el = 1; 
    }

    /* Check if the string is actually displayable. */
    if (kutils_string_is_binary(ss, ss_s)) {
        sh = kmalloc(string_size_as_hex(str_s));
        string_as_hex(str, str_s, sh);

        if (level == 0)           
            DEBUG(_log_knp_, "%s '%s': <%s>", nm, elnm, sh);
        else if (level == 1)
            DEBUG(_log_knp_, "  %s '%s': <%s>", nm, elnm, sh);            

        kfree(sh);
    } 
    /* Display the string as text. */   
    else {
        const char elipsis[] = "...";

        if (el) strcat(ss, elipsis);

        if (level == 0)
            DEBUG(_log_knp_, "%s '%s': %s", nm, elnm, ss);
        else if (level == 1)
            DEBUG(_log_knp_, "  %s '%s': %s", nm, elnm, ss);
    }

    kfree(ss);
}

/** Generic uint64 element reader. */
static int el_reader_generic_uint64(U kdprotocol *self, enum proto_el_id id, 
                                    tbuffer *tbuf, struct kdpacket *pkt) {
    uint64_t n;
    int err;

    err = tbuffer_read_uint64(tbuf, &n);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading uint64");
        return -1;
    }

    kdpacket_set_uint64(pkt, id, n);

    return 0;
}

/** Generic uint64 element writer. */
static int el_writer_generic_uint64(U kdprotocol *self, enum proto_el_id id, 
                                    tbuffer *tbuf, struct kdpacket *pkt) {
    uint64_t n;

    kdpacket_get_uint64(pkt, id, &n);
    tbuffer_write_uint64(tbuf, n);

    return 0;
}

/** Generic uint64 element printer. */
static int el_printer_generic_uint64(U kdprotocol *self, enum proto_el_id id, 
                                     const char *el_name,
                                     struct kdpacket *pkt) {
    uint64_t n;

    kdpacket_get_uint64(pkt, id, &n);
    DEBUG(_log_knp_, "uint64 '%s': "PRINTF_64"u", el_name, n);

    return 0;
}

/** Generic raw data reader. */
static int el_reader_generic_raw(U kdprotocol *self, enum proto_el_id id,
                                 tbuffer *tbuf, struct kdpacket *pkt) {
    const char *str;
    size_t str_s;
    int err;

    err = tbuffer_read_string(tbuf, &str, &str_s);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading raw data");
        return -1;
    }

    kdpacket_set_raw(pkt, id, (void *)str, str_s);

    return 0;
}

/** Generic raw data writer. */
static int el_writer_generic_raw(U kdprotocol *self, enum proto_el_id id,
                                 tbuffer *tbuf, struct kdpacket *pkt) {

    void *ptr;
    size_t s;

    kdpacket_get_raw(pkt, id, (void **)&ptr, &s);
    tbuffer_write_str(tbuf, ptr, s);

    return 0;    
}

/** Generic raw data printer. */
static int el_printer_generic_raw(U kdprotocol *self, enum proto_el_id id,
                                  const char *el_name,
                                  struct kdpacket *pkt) {
    void *ptr;
    size_t s;

    kdpacket_get_raw(pkt, id, (void **)&ptr, &s);
    el_print_string((char *)ptr, s, "Raw", el_name, 0);

    return 0;    
}

/** Generic uint32 reader. */
static int el_reader_generic_uint32(U kdprotocol *self, enum proto_el_id id,
                                    tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t n;
    int err;

    err = tbuffer_read_uint32(tbuf, &n);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading uint32");
        return -1;
    }

    kdpacket_set_uint32(pkt, id, n);
    return 0;
}

/** Optional uint32 reader (ie: the element may not be there). */
static int el_reader_optional_uint32(U kdprotocol *self, enum proto_el_id id,
                                     tbuffer *tbuf, struct kdpacket *pkt) {
    el_reader_generic_uint32(self, id, tbuf, pkt);
    return 0;
}

/** Generic uint32 writer. */
static int el_writer_generic_uint32(U kdprotocol *self, enum proto_el_id id,
                                    tbuffer *tbuf, struct kdpacket *pkt) { 
    uint32_t n;

    kdpacket_get_uint32(pkt, id, &n);
    tbuffer_write_uint32(tbuf, n);

    return 0;   
}

/** Optional uint32 writer (ie: the element may not be there). */
static int el_writer_optional_uint32(U kdprotocol *self, enum proto_el_id id,
                                     tbuffer *tbuf, struct kdpacket *pkt) {   
    if (kdpacket_is_present(pkt, id)) 
        el_writer_generic_uint32(self, id, tbuf, pkt);

    return 0;
}

/** Generic uint32 printer. */
static int el_printer_generic_uint32(U kdprotocol *self, enum proto_el_id id,
                                     const char *el_name,
                                     struct kdpacket *pkt) {
    uint32_t n;

    kdpacket_get_uint32(pkt, id, &n);
    DEBUG(_log_knp_, "uint32 '%s': %u", el_name, n);

    return 0;
}

/** Optional uint32 printer (ie: the element may not be there). */
static int el_printer_optional_uint32(U kdprotocol *self, enum proto_el_id id,
                                      const char *el_name,
                                      struct kdpacket *pkt) {
    if (!kdpacket_is_present(pkt, id)) 
        DEBUG(_log_knp_, "uint32 '%s': %s", el_name, optional_str);
    else
        el_printer_generic_uint32(self, id, el_name, pkt);

    return 0;
}

/** Generic string reader. */
static int el_reader_generic_string(U kdprotocol *self, enum proto_el_id id,
                                    tbuffer *tbuf, struct kdpacket *pkt) {
    const char *str;
    size_t i, str_s;
    int err;

    err = tbuffer_read_string(tbuf, &str, &str_s);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading string");
        return -1;
    }

    /* Make sure the string has no 0 value in it. */
    for (i = 0; i < str_s; i++) 
        if (str[i] == 0) {
            KERROR_SET(_knp_, 0, "Null found inside the string length");
            return -1;
        }

    kdpacket_set_str(pkt, id, str, str_s);
    return 0;
}

/** Generic string writer. */
static int el_writer_generic_string(U kdprotocol *self, enum proto_el_id id,
                                    tbuffer *tbuf, struct kdpacket *pkt) {
    const char *str;
    size_t str_s;

    kdpacket_get_str(pkt, id, &str, &str_s);
    tbuffer_write_str(tbuf, str, str_s);

    return 0;
}

/** Generic string writer. */
static int el_writer_optional_string(U kdprotocol *self, enum proto_el_id id,
                                     tbuffer *tbuf, struct kdpacket *pkt) {
    if (kdpacket_is_present(pkt, id)) 
        el_writer_generic_string(self, id, tbuf, pkt);

    return 0;
}

/** Generic string printer. */
static int el_printer_generic_string(U kdprotocol *self, enum proto_el_id id,
                                     const char *el_name,
                                     struct kdpacket *pkt) {
    const char *str;
    size_t str_s;
    
    kdpacket_get_str(pkt, id, &str, &str_s);
    el_print_string(str, str_s, "String", el_name, 0);

    return 0;
}


/** Optional string printer (ie: the packet element may be absent) */
static int el_printer_optional_string(U kdprotocol *self, enum proto_el_id id,
                                      const char *el_name,
                                      struct kdpacket *pkt) {

    if (!kdpacket_is_present(pkt, id)) 
        el_print_string(optional_str, sizeof(optional_str) - 1, "String", el_name, 0);
    else
        el_printer_generic_string(self, id, el_name, pkt);

    return 0;
}

/** Generic uint32 array reader. */
static int el_reader_generic_uint32_array(U kdprotocol *self, enum proto_el_id id,
                                          tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t i, nb;
    uint32_t item;
    int err;

    err = tbuffer_read_uint32(tbuf, &nb);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading uint32 array length");
        return -1;
    }
    
    kdpacket_set_list(pkt, id, nb);

    for (i = 0; i < nb; i++) {
        err = tbuffer_read_uint32(tbuf, &item);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading uint32 array item");
            return -1;
        }

        kdpacket_set_list_item(pkt, id, i, (void *)&item, sizeof(uint32_t));
    }

    return 0;
}

/** Generic uint32 array writer. */
static int el_writer_generic_uint32_array(U kdprotocol *self, enum proto_el_id id,
                                          tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t nb, i;
    uint32_t *item;

    nb = kdpacket_get_list_len(pkt, id);

    tbuffer_write_uint32(tbuf, nb);

    for (i = 0; i < nb; i++) {
        kdpacket_get_list_item(pkt, id, i, (void **)&item, NULL);
        tbuffer_write_uint32(tbuf, *item);
    }

    return 0;
}

/** Generic uint32 array printer. */
static int el_printer_generic_uint32_array(U kdprotocol *self, enum proto_el_id id,
                                           const char *el_name,
                                           struct kdpacket *pkt) {
    uint32_t nb, i;
    uint32_t *item;

    nb = kdpacket_get_list_len(pkt, id);

    DEBUG(_log_knp_, "uint32 '%s' [%d]:", el_name, nb);

    for (i = 0; i < nb; i++) {
        kdpacket_get_list_item(pkt, id, i, (void **)&item, NULL);
        DEBUG(_log_knp_, "  %u", *item);
    }

    return 0;
}

/** Generic string array reader. */
static int el_reader_generic_string_array(U kdprotocol *self, enum proto_el_id id,
                                          tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t i, nb;
    const char *str;
    size_t str_s;
    int err;

    err = tbuffer_read_uint32(tbuf, &nb);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading string array length");
        return -1;
    }
    
    kdpacket_set_list(pkt, id, nb);

    for (i = 0; i < nb; i++) {
        err = tbuffer_read_string(tbuf, &str, &str_s);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading string array item");
            return -1;
        }

        kdpacket_set_str_list_item(pkt, id, i, str, str_s);
    }

    return 0;
}

/** Generic string array writer. */
static int el_writer_generic_string_array(U kdprotocol *self, enum proto_el_id id,
                                          tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t nb, i;
    const char *str;
    size_t str_s;

    nb = kdpacket_get_list_len(pkt, id);

    tbuffer_write_uint32(tbuf, nb);

    for (i = 0; i < nb; i++) {
        kdpacket_get_list_item(pkt, id, i, (void **)&str, &str_s);
        tbuffer_write_str(tbuf, str, str_s);
    }

    return 0;
}

/** Generic string array printer. */
static int el_printer_generic_string_array(U kdprotocol *self, enum proto_el_id id,
                                           const char *el_name,
                                           struct kdpacket *pkt) {
    uint32_t nb, i;
    const char *str;
    size_t str_s;

    nb = kdpacket_get_list_len(pkt, id);

    DEBUG(_log_knp_, "String '%s' [%d]:", el_name, nb);

    for (i = 0; i < nb; i++) {
        kdpacket_get_list_item(pkt, id, i, (void **)&str, &str_s);
        el_print_string(str, str_s, "String", NULL, 1);
    }

    return 0;    
}

/** Generic raw array reader. */
static int el_reader_generic_raw_array(U kdprotocol *self, enum proto_el_id id,
                                       tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t i, nb;
    const char *raw;
    size_t raw_s;
    int err;

    err = tbuffer_read_uint32(tbuf, &nb);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading raw array length");
        return -1;
    }
    
    kdpacket_set_list(pkt, id, nb);

    for (i = 0; i < nb; i++) {
        err = tbuffer_read_string(tbuf, &raw, &raw_s);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading raw array item");
            return -1;
        }

        kdpacket_set_list_item(pkt, id, i, raw, raw_s);
    }

    return 0;
}

/** Generic raw array writer. */
static int el_writer_generic_raw_array(U kdprotocol *self, enum proto_el_id id,
                                       tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t nb, i;
    const char *raw;
    size_t raw_s;

    nb = kdpacket_get_list_len(pkt, id);

    tbuffer_write_uint32(tbuf, nb);

    for (i = 0; i < nb; i++) {
        kdpacket_get_list_item(pkt, id, i, (void **)&raw, &raw_s);
        tbuffer_write_str(tbuf, raw, raw_s);
    }

    return 0;
}

/** Generic raw array printer. */
static int el_printer_generic_raw_array(U kdprotocol *self, enum proto_el_id id,
                                        const char *el_name,
                                        struct kdpacket *pkt) {
    uint32_t nb, i;
    const char *raw;
    size_t raw_s;

    nb = kdpacket_get_list_len(pkt, id);

    DEBUG(_log_knp_, "Raw '%s' [%d]:", el_name, nb);

    for (i = 0; i < nb; i++) {
        kdpacket_get_list_item(pkt, id, i, (void **)&raw, &raw_s);
        el_print_string(raw, raw_s, "Raw", NULL, 1);
    }

    return 0;    
}

/** Reader of recipient array. */
static int el_reader_EL_RECIPIENT_ARRAY(U kdprotocol *self, U enum proto_el_id id,
                                        tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t i, nb;
    const char *addr, *key_data;
    size_t addr_s, key_data_s;
    uint32_t enc_type;
    int err;
    struct proto_recipient pr;

    err = tbuffer_read_uint32(tbuf, &nb);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading recipient array length");
        return -1;
    }
    
    kdpacket_set_list(pkt, EL_RECIPIENT_ARRAY, nb);

    /* Read the array of recipients. */
    for (i = 0; i < nb; i++) {
        err = tbuffer_read_string(tbuf, &addr, &addr_s);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading recipient %d email address", i);
            return -1;
        }

        err = tbuffer_read_uint32(tbuf, &enc_type);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading recipient %d encryption type", i);
            return -1;
        }

        err = tbuffer_read_string(tbuf, &key_data, &key_data_s);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading recipient %d key data", i);
            return -1;
        }

        pr.addr = apr_pstrndup(pkt->pool, addr, addr_s);
        pr.key_data = apr_pstrndup(pkt->pool, key_data, key_data_s);

        switch (enc_type) {
        case KNP_PKG_ENC_KEY: 
            pr.enc_type = RECIP_KEY; break;
        case KNP_PKG_ENC_PWD: 
            pr.enc_type = RECIP_PWD; break;
        default:
            pr.enc_type = RECIP_DONTCARE; break;
        }

        kdpacket_set_list_item(pkt, EL_RECIPIENT_ARRAY, i, (void *)&pr, sizeof(pr));
    }
    
    return 0;
}

/** Printer of recipient array. */
static int el_printer_EL_RECIPIENT_ARRAY(U kdprotocol *self, U enum proto_el_id id,
                                         const char *el_name,
                                         struct kdpacket *pkt) {
    struct proto_recipient *recip;
    uint32_t i, nb_recip;

    nb_recip = kdpacket_get_list_len(pkt, EL_RECIPIENT_ARRAY);

    DEBUG(_log_knp_, "'%s' [%d]:", el_name, nb_recip);

    for (i = 0; i < nb_recip; i++) {
        kdpacket_get_list_item(pkt, EL_RECIPIENT_ARRAY, i, (void **)&recip, NULL);

        if (recip->enc_type == RECIP_KEY) {
            if (recip->key_data != NULL)
                DEBUG(_log_knp_, "  %s (key data present)", recip->addr);
            else
                DEBUG(_log_knp_, "  %s (key recipient without key)", recip->addr);       
        }
        else if (recip->enc_type == RECIP_PWD) {
                if (recip->key_data != NULL)
                    DEBUG(_log_knp_, "  %s (password recipient with key data!)", recip->addr);
                else
                    DEBUG(_log_knp_, "  %s (password recipient, no key)", recip->addr);
        }        
    }

    return 0;
}

/** Reader of password array. */
static int el_reader_EL_PASSWORD_ARRAY(U kdprotocol *self, U enum proto_el_id id,
                                       tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t i, nb;
    const char *pwd, *otut;
    size_t pwd_s, otut_s;
    struct proto_password pp;
    int err;
    
    err = tbuffer_read_uint32(tbuf, &nb);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading password array length");
        return -1;
    }

    kdpacket_set_list(pkt, EL_PASSWORD_ARRAY, nb);

    /* Read the array of password and OTUTs. */
    for (i = 0; i < nb; i++) {
        err = tbuffer_read_string(tbuf, &pwd, &pwd_s);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading password %d", i);
            return -1;
        }

        err = tbuffer_read_string(tbuf, &otut, &otut_s);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading password %d OTUT string", i);
            return -1;
        }

        pp.pwd = apr_pstrndup(pkt->pool, pwd, pwd_s);        
        pp.otut = apr_pcalloc(pkt->pool, otut_s);
        memcpy(pp.otut, otut, otut_s);
        pp.otut_s = otut_s;

        kdpacket_set_list_item(pkt, EL_PASSWORD_ARRAY, i, (void *)&pp, sizeof(pp));
    }

    return 0;
}

/** Printer of password array. */
static int el_printer_EL_PASSWORD_ARRAY(U kdprotocol *self, U enum proto_el_id id,
                                        const char *el_name,
                                        struct kdpacket *pkt) {
    uint32_t i, nb_pwd;
    struct proto_password *pwd;

    nb_pwd = kdpacket_get_list_len(pkt, EL_PASSWORD_ARRAY);

    DEBUG(_log_knp_, "'%s' [%d]:", el_name, nb_pwd);

    for (i = 0; i < nb_pwd; i++) {
        kdpacket_get_list_item(pkt, EL_PASSWORD_ARRAY, i, (void **)&pwd, NULL);

        if (pwd->otut != NULL)
            DEBUG(_log_knp_, "  %s (OTUT present)", pwd->pwd);
        else
            DEBUG(_log_knp_, "  %s (no OTUT)", pwd->pwd);       
    }

    return 0;
}

static int el_reader_EL_BODY_TYPE(U kdprotocol *self, U enum proto_el_id id,
                                  tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t bt;
    int err;

    err = tbuffer_read_uint32(tbuf, &bt);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading body type");
        return -1;
    }

    switch (bt) {
    case KNP_PKG_BODY_TEXT:
        kdpacket_set_uint32(pkt, EL_BODY_TYPE, BODY_TYPE_TEXT); break;
    case KNP_PKG_BODY_HTML:
        kdpacket_set_uint32(pkt, EL_BODY_TYPE, BODY_TYPE_HTML); break;
    case KNP_PKG_BODY_BOTH:
        kdpacket_set_uint32(pkt, EL_BODY_TYPE, BODY_TYPE_BOTH); break;
    }

    return 0;
}

/* 
 * FIXME: Those are 2 potentially big memory copy.  It would be good
 * if we could do without it in the future.  I'm just want to make
 * sure the code works well before thinking about optimization.
 */

/*
 * Remember to call protocol_clean to free the memory allocated to the
 * bodies and attachments when you no longer need them.
 */

/** HTML body reader. */
static int el_reader_EL_BODY_HTML(kdprotocol *self, U enum proto_el_id id,
                                  tbuffer *tbuf, struct kdpacket *pkt) {
    const char *body_html;
    size_t body_html_s;
    int err;
    struct el_sized *el_html;

    /* Read the HTML body. */
    err = tbuffer_read_string(tbuf, &body_html, &body_html_s);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading HTML body");
        return -1;
    }

    if (self->body_html != NULL)
        kfree(self->body_html);
    
    /* Make sure there is a body. */
    if (body_html_s > 0) {
        self->body_html = kmalloc(body_html_s);
        memcpy(self->body_html, body_html, body_html_s);
    }

    /* Fool the packet into thinking we store a string. */
    el_html = apr_palloc(pkt->pool, sizeof(struct el_sized));
    el_html->size = body_html_s;
    el_html->ptr = self->body_html;
    kdpacket_set_ptr(pkt, EL_BODY_HTML, EL_TYPE_RAW, el_html);

    return 0;
}

/** Text Body reader. */
static int el_reader_EL_BODY_TEXT(kdprotocol *self, U enum proto_el_id id,
                                  tbuffer *tbuf, struct kdpacket *pkt) {
    const char *body_text;
    size_t body_text_s;
    int err;
    struct el_sized *el_text;

    /* Read the text body. */
    err = tbuffer_read_string(tbuf, &body_text, &body_text_s);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading text body");
        return -1;
    }

    if (self->body_text != NULL) {
        kfree(self->body_text);
        self->body_text = NULL;
    }
    
    /* Make sure there is a body. */
    if (body_text_s > 0) {
        self->body_text = kmalloc(body_text_s);  
        memcpy(self->body_text, body_text, body_text_s);
    }

    /* Fool the packet into thinking we store a string. */
    el_text = apr_palloc(pkt->pool, sizeof(struct el_sized));
    el_text->size = body_text_s;
    el_text->ptr = self->body_text;
    kdpacket_set_ptr(pkt, EL_BODY_TEXT, EL_TYPE_RAW, el_text);

    return 0;
}

/** Attachment reader. */
static int el_reader_EL_ATTACHMENT_ARRAY(kdprotocol *self, U enum proto_el_id id,
                                         tbuffer *tbuf, struct kdpacket *pkt) {
    uint32_t i, nb, type;
    int err;
    struct proto_attachment pa;

    /* Read the number of attachments. */
    err = tbuffer_read_uint32(tbuf, &nb);
    if (err) {
        KERROR_PUSH(_knp_, 0, "error when reading attachment array length");
        return -1;
    }

    kdpacket_set_list(pkt, EL_ATTACHMENT_ARRAY, nb);

    /* Make sure we don't crush anything into oblivion. */
    if (self->attachments != NULL) {
        for (i = 0; i < self->attachments_count; i++)
            kfree((void *)self->attachments[i]);
        
        kfree(self->attachments);
    }

    /* Allocate some memory for the attachments array. */
    self->attachments_count = nb;
    self->attachments = kcalloc(nb * sizeof(char *));

    /* Read the array of attachments. */
    for (i = 0; i < nb; i++) {
        const char *encoding, *mime_type, *name, *payload;
        size_t encoding_s, mime_type_s, name_s, payload_s;

        err = tbuffer_read_uint32(tbuf, &type);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading attachment %d type", i);
            return -1;
        }

        err = tbuffer_read_string(tbuf, &encoding, &encoding_s);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading attachment %d encoding", i);
            return -1;
        }

        err = tbuffer_read_string(tbuf, &mime_type, &mime_type_s);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading attachment %d MIME type", i);
            return -1;
        }

        err = tbuffer_read_string(tbuf, &name, &name_s);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading attachment %d MIME type", i);
            return -1;
        }

        err = tbuffer_read_string(tbuf, &payload, &payload_s);
        if (err) {
            KERROR_PUSH(_knp_, 0, "error when reading attachment %d", i);
            return -1;
        }

        /* Convert the KNP 1.x type to the internal type. */
        switch (type) {
        case KNP_MAIL_PART_IMPLICIT: pa.attch_type = ATTACH_IMPLICIT; break;
        case KNP_MAIL_PART_EXPLICIT: pa.attch_type = ATTACH_EXPLICIT; break;
        case KNP_MAIL_PART_UNKNOWN:  pa.attch_type = ATTACH_UNKNOWN;  break;
        }

        pa.encoding = apr_pstrndup(pkt->pool, encoding, encoding_s);
        pa.mime_type = apr_pstrndup(pkt->pool, mime_type, mime_type_s);
        pa.name = apr_pstrndup(pkt->pool, name, name_s);

        pa.payload = kmalloc(payload_s);
        pa.payload_s = payload_s;
        memcpy(pa.payload, payload, payload_s);
        
        self->attachments[i] = pa.payload;

        kdpacket_set_list_item(pkt, EL_ATTACHMENT_ARRAY, i, (void *)&pa, sizeof(pa));
    }

    return 0;
}

static int el_printer_EL_ATTACHMENT_ARRAY(U kdprotocol *self, U enum proto_el_id id,
                                          const char *el_name,
                                          struct kdpacket *pkt) {
    uint32_t i, nb_attch;
    struct proto_attachment *pa;

    nb_attch = kdpacket_get_list_len(pkt, EL_ATTACHMENT_ARRAY);

    DEBUG(_log_knp_, "'%s' [%d]:", el_name, nb_attch);

    for (i = 0; i < nb_attch; i++) {
        kdpacket_get_list_item(pkt, EL_ATTACHMENT_ARRAY, i, (void **)&pa, NULL);
        
        DEBUG(_log_knp_, "  %s (encoding: %s, MIME: %s, length: %u)", 
              pa->name,
              pa->encoding,
              pa->mime_type,
              pa->payload_s);
    }

    return 0;
}

struct proto_el_func proto_el_functions[EL_MAX] = {
    /* EL_NONE. */
    { NULL, NULL, NULL, "NONE" },

    /* EL_KEYID */
    { el_reader_generic_uint64, el_writer_generic_uint64, el_printer_generic_uint64, "Key ID" },
    /* EL_KEY_DATA */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Key data" },
    /* EL_OWNER_NAME */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Owner name" },
    /* EL_LOGIN_USERNAME */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Username" },
    /* EL_LOGIN_PASSWORD */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Password" },
    /* EL_OTUT_REPLY_COUNT */
    { el_reader_generic_uint32, el_writer_generic_uint32, el_printer_generic_uint32, "Reply count" },
    /* EL_OTUT_ADDRESS */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "OTUT address" },
    /* EL_TICKET */
    { el_reader_generic_raw,    el_writer_generic_raw,    el_printer_generic_raw   , "Ticket" },
    /* EL_OTUT_STRING. */
    { el_reader_generic_raw,    el_writer_generic_raw,    el_printer_generic_raw   , "OTUT string" },
    /* EL_OTUT_REPLY_COUNT_ARRAY */
    { el_reader_generic_uint32_array, el_writer_generic_uint32_array, el_printer_generic_uint32_array, "OTUT reply count array" },
    /* EL_OTUT_STRING_ARRAY */
    { el_reader_generic_raw_array,    el_writer_generic_raw_array,    el_printer_generic_raw_array, "OTUT string array"},
    /* EL_ADDRESS_ARRAY. */
    { el_reader_generic_string_array, el_writer_generic_string_array, el_printer_generic_string_array, "Email address array" },
    /* EL_KEY_DATA_ARRAY. */
    { el_reader_generic_string_array, el_writer_generic_string_array, el_printer_generic_string_array, "Key data array" },
    /* EL_DOMAINS_ARRAY. */
    { el_reader_generic_string_array, el_writer_generic_string_array, el_printer_generic_string_array, "Email domains array" },
    /* EL_PKG_TYPE */
    { el_reader_generic_uint32, el_writer_generic_uint32, el_printer_generic_uint32, "Packaging type" },
    /* EL_TO */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "To" },
    /* EL_CC */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "CC" },
    /* EL_RECIPIENT_ARRAY */ 
    { el_reader_EL_RECIPIENT_ARRAY, NULL, el_printer_EL_RECIPIENT_ARRAY, "Recipient array" },
    /* EL_PASSWORD_ARRAY */
    { el_reader_EL_PASSWORD_ARRAY, NULL, el_printer_EL_PASSWORD_ARRAY, "Password array" },
    /* EL_FROM_NAME */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "From name" },
    /* EL_FROM_ADDRESS */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "From address" },
    /* EL_SUBJECT */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Subject" },
    /* EL_BODY_TYPE */
    { el_reader_EL_BODY_TYPE, NULL, el_printer_generic_uint32, "Body type" },
    /* EL_BODY_TEXT */
    { el_reader_EL_BODY_TEXT, NULL, el_printer_generic_raw, "Text body" },
    /* EL_BODY_HTML */
    { el_reader_EL_BODY_HTML, NULL, el_printer_generic_raw, "HTML body" },
    /* EL_ATTACHMENT_ARRAY */
    { el_reader_EL_ATTACHMENT_ARRAY, NULL, el_printer_EL_ATTACHMENT_ARRAY, "Attachments" },
    /* EL_POD_ADDRESS */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "PoD address" },
    /* EL_PACKAGE_OUTPUT */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Packaged content" },
    /* EL_KSN. */
    { el_reader_generic_raw,    el_writer_generic_raw,    el_printer_generic_raw, "KSN"    },
    /* EL_SYMKEY */
    { el_reader_generic_raw,    el_writer_generic_raw,    el_printer_generic_raw, "Symmetric key" },
    /* EL_SIG_TEXT */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Signature text" },
    /* EL_INTER_SYMKEY_DATA */
    { el_reader_generic_raw,    el_writer_generic_raw,    el_printer_generic_raw, "Intermediary symmetric key"    },
    /* EL_PASSWORD */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Password" },
    /* EL_POD_FROM */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "PoD source" },
    /* EL_LANG */
    { el_reader_generic_uint32, el_writer_generic_uint32, el_printer_generic_uint32, "Language code" },
    /* EL_LOGIN_TYPE */
    { el_reader_generic_uint32, el_writer_generic_uint32, el_printer_generic_uint32, "Is password?" },
    /* EL_TOKEN */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Login Token" },
    /* EL_POD_DATE */
    { el_reader_generic_uint32, el_writer_generic_uint32, el_printer_generic_uint32, "PoD date" },
    /* EL_TM_KEY_DATA */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Timestamping key data" },
    /* EL_LICENSE_LIM */
    { el_reader_generic_uint32, NULL, el_printer_generic_uint32, "License Limit" },
    /* EL_LICENSE_MAX */
    { el_reader_generic_uint32, NULL, el_printer_generic_uint32, "License Maximum" },
    /* EL_LICENSE_KDN */
    { el_reader_generic_string, NULL, el_printer_generic_string, "License KDN" },
    /* EL_OTUT_USES */
    { el_reader_generic_uint32, el_writer_generic_uint32, el_printer_generic_uint32, "OTUT use count" },
    /* EL_PACKAGE_ERR */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Package error string" },
    /* EL_KPG_IS_USED */
    { NULL, el_writer_generic_uint32, el_printer_generic_uint32, "KPG is used?" },
    /* EL_KPG_HOSTNAME */
    { NULL, el_writer_optional_string, el_printer_optional_string, "KPG hostname" },
    /* EL_KPG_PORT */
    { NULL, el_writer_optional_uint32, el_printer_optional_uint32, "KPG port" },
    
    /* EL_WANT_DEC_EMAIL */
    { el_reader_optional_uint32, NULL, el_printer_optional_uint32, "Want decryption email?" },
    
    /* EL_DEC_EMAIL */
    { el_reader_generic_string, el_writer_generic_string, el_printer_generic_string, "Decryption email" },
    
    /* EL_SUBSCRIBER_ARRAY */
    { NULL, el_writer_generic_string_array, el_printer_generic_string_array, "Subscriber array" },
    
    /* EL_KWS_TICKET */
    { NULL, el_writer_generic_raw, el_printer_generic_raw, "Workspace ticket" },
};
