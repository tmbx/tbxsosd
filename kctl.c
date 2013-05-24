/**
 * tbxsosd/kctl.c
 * Copyright (C) 2005-2012 Opersys inc.
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
 * Basic database interface for tbxsosd.
 *
 * @author François-Denis Gonthier
*/

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <apr_portable.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_getopt.h>
#include <apr_pools.h>
#include <apr_lib.h>
#include <assert.h>
#include <stdlib.h>
#include <tagcrypt.h>
#include <libpq-fe.h>
#include <kerror.h>
#include <tbuffer.h>
#include <base64.h>

#include "license.h"
#include "logid.h"
#include "logging.h"
#include "config.h"
#include "utils.h"
#include "common.h"
#include "common_keys.h"
#include "keys.h"

#include "main.h"

apr_pool_t *main_pool;

#define NO_ARGC __attribute__ ((unused)) int argc
#define NO_ARGV __attribute__ ((unused)) char ** argv


apr_pool_t *main_pool;

static void kctl_gen_key(apr_pool_t *pool, 
                         int is_enc_key,
                         uint64_t key_id, 
                         const char *owner,
                         struct kdkey_info *pkey_ki,
                         struct kdkey_info *skey_ki) {
    kbuffer *skey, *pkey;

    skey = kbuffer_new();
    pkey = kbuffer_new();

    if (is_enc_key) {
        tagcrypt_gen_enc_pair(pkey, skey, key_id); 
        skey_ki->type = SKEY_ENCRYPTION;
        pkey_ki->type = PKEY_ENCRYPTION;
    }
    else {
        tagcrypt_gen_sig_pair(pkey, skey, key_id);
        skey_ki->type = SKEY_SIGNATURE;
        pkey_ki->type = PKEY_SIGNATURE;
    }

    pkey_ki->key_id = key_id;

    if (owner != NULL) {
        pkey_ki->owner = apr_pstrdup(pool, owner);
        pkey_ki->owner_s = strlen(pkey_ki->owner);
    }
    else {
        pkey_ki->owner = NULL;
        pkey_ki->owner_s = 0;
    }
    pkey_ki->data = apr_pmemdup(pool, pkey->data, pkey->len);
    pkey_ki->data_s = pkey->len;

    skey_ki->key_id = key_id;

    if (owner != NULL) {
        skey_ki->owner = apr_pstrdup(pool, owner);
        skey_ki->owner_s = strlen(skey_ki->owner);
    }
    else {
        skey_ki->owner = NULL;
        skey_ki->owner_s = 0;
    }
    skey_ki->data = apr_pmemdup(pool, skey->data, skey->len);
    skey_ki->data_s = skey->len;

    kbuffer_destroy(skey);
    kbuffer_destroy(pkey);
}

void kctl_gen_sig_key(apr_pool_t *pool, 
                      uint64_t key_id, 
                      const char *owner, 
                      struct kdkey_info *pkey_ki,
                      struct kdkey_info *skey_ki) {
    kctl_gen_key(pool, 0, key_id, owner, pkey_ki, skey_ki);
}

void kctl_gen_enc_key(apr_pool_t *pool,
                      uint64_t key_id,
                      const char *owner,
                      struct kdkey_info *pkey_ki,
                      struct kdkey_info *skey_ki) {
    kctl_gen_key(pool, 1, key_id, owner, pkey_ki, skey_ki);
}

/** Awful hack to change the key ID of a tagcrypt key. 
 *
 * Instead of instanciating the key through tagcrypt, this change the
 * key ID of the key in the base 64 data itself.
 */
int kctl_key_set_key_id(apr_pool_t *pool,
                        uint64_t new_key_id,
                        struct kdkey_info *in_ki, 
                        struct kdkey_info *out_ki) {
    const int key_id_idx = 3 * sizeof(uint32_t);
    kbuffer *binbuf, *b64buf;
    int r = -1;

    binbuf = kbuffer_new();
    b64buf = kbuffer_new();
    
    do {
        kbuffer_write(b64buf, (uint8_t *)in_ki->data, in_ki->data_s);
        if (kb642bin(b64buf, binbuf, 0) < 0) 
            break;

        /* Change the key. */        
        *((uint64_t *)(binbuf->data + key_id_idx)) = htonll(new_key_id);
        out_ki->key_id = new_key_id;
        out_ki->owner = apr_pmemdup(pool, in_ki->owner, in_ki->owner_s);
        out_ki->owner_s = in_ki->owner_s;
        out_ki->type = in_ki->type;

        /* Rewrite the base64 data. */
        kbuffer_reset(b64buf);
        kbin2b64(binbuf, b64buf);
    
        out_ki->data = apr_pmemdup(pool, b64buf->data, b64buf->len);
        out_ki->data_s = b64buf->len;

        r = 0;
    } while (0);
    
    kbuffer_destroy(binbuf);
    kbuffer_destroy(b64buf);

    return r;
}

/** Simple malloc wrapper. */
void * kctl_malloc(size_t n) {
    void *p;

    p = malloc(n);
    if (p == NULL) {
        fprintf(stderr, "Out of memory.\n");
        exit(-1);
    }

    return p;
}

static int kctl_license_capacity(int argc, char **argv) {
    int i;
    uint32_t cap = 0;

    for (i = 0; i < argc; i++) {
        /* Can sign? */
        if (strcasecmp(argv[i], "sig") == 0)
            cap |= CAN_SIGN;

        /* Can encrypt? */
        if (strcasecmp(argv[i], "enc") == 0)
            cap |= CAN_ENCRYPT;

        /* Can pod? */
        if (strcasecmp(argv[i], "pod") == 0)
            cap |= CAN_POD;

        /* Can use applications? */
        if (strcasecmp(argv[i], "apps") == 0)
            cap |= CAN_APPS;
    }

    return cap;
}

static int kctl_args_to_license(int argc, char **argv, struct kd_license *lic) {
    time_t after_t, before_t;
    struct tm before_tm, after_tm;
    char *kdn, *parent_kdn, *lim_seats_text, *max_seats_text, *is_reseller_text;
    char *best_before_str, *best_after_str;
    int is_reseller, max_seats, lim_seats;

    kdn = argv[3];
    parent_kdn = argv[4];
    best_before_str = argv[5];
    best_after_str = argv[6];
    lim_seats_text = argv[7];
    max_seats_text = argv[8];
    is_reseller_text = argv[9];

    memset(&before_tm, 0, sizeof(before_tm));
    memset(&after_tm, 0, sizeof(after_tm));

    /* Interpret the integers on the command line. */
    if (sscanf(is_reseller_text, "%d", &is_reseller) < 1) {
        KERROR_SET(_kctl_, 0, "invalid argument for is_reseller: %s", is_reseller_text);
        return -1;
    }
    if (sscanf(lim_seats_text, "%d", &lim_seats) < 1) {
        KERROR_SET(_kctl_, 0, "invalid argument for lim_seats: %s", lim_seats_text);
        return -1;
    }
    if (sscanf(max_seats_text, "%d", &max_seats) < 1) {
        KERROR_SET(_kctl_, 0, "invalid argument for max_seats: %s", max_seats_text);
        return -1;
    }

    /* Best after date. */
    if (strptime(best_after_str, "%Y-%m-%d", &after_tm) == NULL) {
        KERROR_SET(_kctl_, 0, "invalid best after date: %s", best_after_str);
        return -1;
    }
    after_tm.tm_sec = 0;
    after_tm.tm_min = 0;
    after_tm.tm_hour = 0;
    after_t = mktime(&after_tm);

    /* Best before date. */
    if (strptime(best_before_str, "%Y-%m-%d", &before_tm) == NULL) {
        KERROR_SET(_kctl_, 0, "invalid best before data: %s", best_before_str);
        return -1;
    }
    before_tm.tm_sec = 0;
    before_tm.tm_min = 0;
    before_tm.tm_hour = 0;
    before_t = mktime(&before_tm);

    /* Check the capacity. */
    lic->caps = kctl_license_capacity(argc - 9, argv + 10);

    /* Prepare the structure. */
    if (strcmp(parent_kdn, "none") == 0) 
        lic->parent_kdn = NULL;
    else
        lic->parent_kdn = parent_kdn;

    lic->kdn = kdn;
    lic->best_after = after_t;
    lic->best_before = before_t;
    lic->lim_seats = lim_seats;
    lic->max_seats = max_seats;
    lic->is_reseller = is_reseller; 

    return 0;
}

static void kctl_showlicense(struct kd_license *lic) {
    struct tm *best_after_tm, *best_before_tm;
    char best_after_str[30], best_before_str[30];

    /* Display time strings. */
    best_after_tm = gmtime(&lic->best_after);
    strftime(best_after_str, sizeof(best_after_str), "%Y-%m-%d", best_after_tm);

    best_before_tm = gmtime(&lic->best_before);
    strftime(best_before_str, sizeof(best_before_str), "%Y-%m-%d", best_before_tm);

    fprintf(stdout, "kdn: %s\n", lic->kdn);
    fprintf(stdout, "parent kdn: %s\n", lic->parent_kdn);
    fprintf(stdout, "best after (GMT): %s\n", best_after_str);
    fprintf(stdout, "best before (GMT): %s\n", best_before_str);
    fprintf(stdout, "capacities: %d\n", lic->caps);
    fprintf(stdout, "seat limit: %d\n", lic->lim_seats);
    fprintf(stdout, "seat max: %d\n", lic->max_seats);
    fprintf(stdout, "is reseller: %d\n", lic->is_reseller);
}

int kctl_showlicensefile_cmd(NO_ARGC, char **argv) {
    struct kd_license lic;
    char *lic_file;
    apr_pool_t *pool;
    int err = -1;
    
    apr_pool_create(&pool, main_pool);

    lic_file = argv[1];

    do {
        /* Load the license file. */
        if (kdlicense_open(pool, lic_file, &lic) < 0) {
            KERROR_PUSH(_kctl_, 0, "failed to read license");
            break;
        }

        /* Dump the license. */
        kctl_showlicense(&lic);
        
        err = 0;

    } while (0);

    apr_pool_destroy(pool);

    return err;
}

int kctl_signlicense_cmd(int argc, char **argv) {
    apr_pool_t *pool;
    apr_status_t s;
    apr_file_t *f;
    char *in_key_file, *out_sign_file;
    struct kd_license lic;
    kbuffer *buf;
    int err = -1;
    size_t sz;
   
    in_key_file = argv[1];
    out_sign_file = argv[2];

    apr_pool_create(&pool, main_pool);
    buf = kbuffer_new();

    do {
        /* Interpret the command line argument. */
        if (kctl_args_to_license(argc, argv, &lic) < 0) {
            KERROR_PUSH(_kctl_, 0, "invalid arguments to license");
            break;
        }        

        /* Sign the license structure. */
        if (kdlicense_sign(pool, in_key_file, &lic, buf) < 0) {
            KERROR_PUSH(_kctl_, 0, "failed to sign the license");
            break;
        } 

        /* Open the license file. */
        s = apr_file_open(&f, out_sign_file, APR_WRITE | APR_TRUNCATE | APR_CREATE, APR_OS_DEFAULT, pool);
        if (s != APR_SUCCESS) {
            KERROR_SET_APR(_kctl_, 0, s);
            KERROR_PUSH(_kctl_, 0, "failed to open license file");
            break;
        }

        /* Write to the file. */        
        sz = buf->len;
        s = apr_file_write(f, buf->data, &sz);
        if (s != APR_SUCCESS) {
            KERROR_SET_APR(_kctl_, 0, s);
            KERROR_PUSH(_kctl_, 0, "failed to write license");
            break;
        }

        err = 0;

    } while (0);

    kbuffer_destroy(buf);
    apr_pool_destroy(pool);

    return err;
}

/* FIXME: Key generation to be moved in keys.c. */
static int kctl_genkeys_cmd_enc(uint64_t key_id, char *file_base, char *owner) {
    int r = -1;
    char nm_skey[NAME_MAX];
    char nm_pkey[NAME_MAX];
    struct kdkey_info pkey_ki, skey_ki;
    apr_pool_t *key_pool;

    snprintf(nm_skey, sizeof(nm_skey), "%s.%s.skey", file_base, "enc");
    snprintf(nm_pkey, sizeof(nm_pkey), "%s.%s.pkey", file_base, "enc");

    apr_pool_create(&key_pool, main_pool);

    do {
        kctl_gen_enc_key(key_pool, key_id, owner, &pkey_ki, &skey_ki);

        if (kdkey_write_key(key_pool, nm_pkey, &pkey_ki) < 0) {
            KERROR_PUSH(_kctl_, 0, "Failed to save key %s.\n", nm_pkey);
            break;
        }            

        if (kdkey_write_key(key_pool, nm_skey, &skey_ki) < 0) {
            KERROR_PUSH(_kctl_, 0, "Failed to save key %s.\n", nm_skey);
            break;
        }

        r = 0;
    } while (0);

    apr_pool_destroy(key_pool);

    return r;
}

/* FIXME: Key generation to be moved in keys.c. */
static int kctl_genkeys_cmd_sig(uint64_t key_id, char *file_base, char *owner) {
    char nm_skey[NAME_MAX];
    char nm_pkey[NAME_MAX];
    struct kdkey_info pkey_ki, skey_ki;
    apr_pool_t *key_pool;
    int r = -1;
    
    snprintf(nm_skey, sizeof(nm_skey), "%s.%s.skey", file_base, "sig");
    snprintf(nm_pkey, sizeof(nm_pkey), "%s.%s.pkey", file_base, "sig");

    apr_pool_create(&key_pool, main_pool);

    do {
        kctl_gen_sig_key(key_pool, key_id, owner, &pkey_ki, &skey_ki);

        if (kdkey_write_key(key_pool, nm_pkey, &pkey_ki) < 0) {
            KERROR_PUSH(_kctl_, 0, "Failed to save key %s.\n", nm_pkey);
            break;
        }            

        if (kdkey_write_key(key_pool, nm_skey, &skey_ki) < 0) {
            KERROR_PUSH(_kctl_, 0, "Failed to save key %s.\n", nm_skey);
            break;
        }

        r = 0;
    } while (0);

    apr_pool_destroy(key_pool);

    return r;
}

static int kctl_keysetid_cmd(NO_ARGC, char **argv) {
    char *in_key_file, *key_id_str, *out_key_file;
    uint64_t new_key_id;
    struct kdkey_info in_key;
    struct kdkey_info out_key;
    apr_pool_t *pool;
    int r = -1;

    in_key_file = argv[1];
    key_id_str = argv[2];
    out_key_file = argv[3];

    if (sscanf(key_id_str, PRINTF_64"u", &new_key_id) < 1) {
        KERROR_SET(_kctl_, 1, "Invalid number: %s\n", key_id_str);
        return -1;
    }

    apr_pool_create(&pool, main_pool);

    do {
        if (kdkey_read_key(pool, in_key_file, &in_key) < 0) {
            KERROR_PUSH(_kctl_, 0, "Failed to read key: %s\n", in_key_file);
            break;
        }

        if (kctl_key_set_key_id(pool, new_key_id, &in_key, &out_key) < 0) {
            KERROR_PUSH(_kctl_, 0, "Failed to change key ID.\n");
            break;
        }

        if (kdkey_write_key(pool, out_key_file, &out_key) < 0) {
            KERROR_PUSH(_kctl_, 0, "Failed to write the key.\n");
            break;
        }
        
        r = 0;
    } while (0);

    apr_pool_destroy(pool);

    return r;
}

static int kctl_keysetname_cmd(NO_ARGC, char **argv) {
    char *in_key_file, *out_key_file;
    char *key_name_str;
    struct kdkey_info key;
    apr_pool_t *pool;
    int r = -1;

    in_key_file = argv[1];
    key_name_str = argv[2];
    out_key_file = argv[3];

    apr_pool_create(&pool, main_pool);

    do {
        if (kdkey_read_key(pool, in_key_file, &key) < 0) {
            KERROR_PUSH(_kctl_, 0, "Failed to read key: %s\n", in_key_file);
            break;
        }
	
	key.owner = key_name_str;
	key.owner_s = strlen(key_name_str);

        if (kdkey_write_key(pool, out_key_file, &key) < 0) {
            KERROR_PUSH(_kctl_, 0, "Failed to write the key.\n");
            break;
        }
        
        r = 0;
    } while (0);

    apr_pool_destroy(pool);

    return r;
}

static int kctl_printkey_cmd(NO_ARGC, char **argv) {
    char *key_file;
    struct kdkey_info key;
    apr_pool_t *pool;
    int r = -1;

    key_file = argv[1];

    apr_pool_create(&pool, main_pool);

    do {
	char *key_type;
	char kludge[100];
	unsigned kludge_s;
	
        if (kdkey_read_key(pool, key_file, &key) < 0) {
            KERROR_PUSH(_kctl_, 0, "Failed to read key: %s\n", key_file);
            break;
        }
		
	switch (key.type) {
	    case SKEY_SIGNATURE: key_type = "private signature"; break;
	    case PKEY_SIGNATURE: key_type = "public signature"; break;
	    case SKEY_ENCRYPTION: key_type = "private encryption"; break;
	    case PKEY_ENCRYPTION: key_type = "public encryption"; break;
	    default: key_type = "error";
	}
	
	kludge_s = MIN(99, (int)key.owner_s);
	memcpy(kludge, key.owner, kludge_s);
	kludge[kludge_s] = 0;
	
	printf("KEY: ID="PRINTF_64"u, ORG=%s, TYPE=%s\n", key.key_id, kludge, key_type);
        r = 0;
	
    } while (0);

    apr_pool_destroy(pool);

    return r;
}


/** Generate encryption and signature keys pairs in files. */
/* FIXME: Key generation to be moved in keys.c. */
static int kctl_genkeys_cmd(NO_ARGC, char **argv) {
    uint64_t key_id;
    char *file_base, *owner;
    int err;

    if (sscanf(argv[2], PRINTF_64"u" , &key_id) < 1) {
        KERROR_SET(_kctl_, 1, "Invalid number: %s\n", argv[2]);
        return -1;
    }

    file_base = argv[3];
    owner = argv[4];

    if (strcmp(argv[1], "enc") == 0) 
        err = kctl_genkeys_cmd_enc(key_id, file_base, owner);
    else if (strcmp(argv[1], "sig") == 0) 
        err = kctl_genkeys_cmd_sig(key_id, file_base, owner);
    else if (strcmp(argv[1], "both") == 0) {
        err = kctl_genkeys_cmd_enc(key_id, file_base, owner);
        if (err)
            return err;
        err = kctl_genkeys_cmd_sig(key_id, file_base, owner);
    }
    else {
        KERROR_PUSH(_kctl_, 0, "Invalid key type: %s\n", argv[1]);
        return -1;
    }

    return err;
}

struct cmd {
    char * name;
    char * usage;
    int min_argc;
    int max_argc;
    int (* cmd_func)(int argc, char ** argv);
};

static struct cmd cmd_array[] = {
    { "genkeys",
      "kctl genkeys enc/sig/both keyid keyfile_name owner - Generate a group of key of ID 'keyid' owned by 'owner'",
      4, 4, kctl_genkeys_cmd },
    { "keysetid",
      "kctl keysetid in_key_file key_id out_key_file - Change the internal key ID of a key.",
      3, 3, kctl_keysetid_cmd },
    { "keysetname",
      "kctl keysetname in_key_file key_name out_key_file - Change the internal key name of a key.",
      3, 3, kctl_keysetname_cmd },
    { "printkey",
      "kctl keysetname key_file - Print the information contained in a key.",
      1, 1, kctl_printkey_cmd },
    { "signlicense",
      "signlicense [... Bastard Command Line Arguments From Hell ...]",
      3, 25, kctl_signlicense_cmd },
    { "showlicensefile",
      "showlicensefile license_file",
      1, 1, kctl_showlicensefile_cmd }
};
static size_t cmd_cnt = sizeof(cmd_array) / sizeof(struct cmd);

static int kctl_run_command(const char *cmd, int cmd_argc, char **cmd_argv) {
    size_t i;
    int r = 0;
   
    for (i = 0; i < cmd_cnt; i++) {
        if (strcasecmp(cmd, cmd_array[i].name) == 0) {
            /* Check if we have the minimum number of arguments. */
            if (cmd_argc < cmd_array[i].min_argc) {
                fprintf(stderr, "Not enough arguments for command.\n");
                fprintf(stderr, "\t%s\n", cmd_array[i].usage);
                r = -1;
                break;
            }

            /* Check if we have no more than the maximum number of
               arguments. */
            if (cmd_argc > cmd_array[i].max_argc) {
                fprintf(stderr, "Too much arguments for command.\n");
                fprintf(stderr, "\t%s\n", cmd_array[i].usage);
                r = -1;
                break;
            }

            /* Call the command. */
            r = (cmd_array[i].cmd_func)(cmd_argc, cmd_argv);
            return r;
        }
    }

    return r;
}

int main(int argc, char **argv) {
    int i, r = 0;
    char *cmd;

    apr_initialize();
    tagcrypt_init();

    /* Create the base pool for kctl. */
    apr_pool_create(&main_pool, NULL);

    kerror_initialize();
    log_open(main_pool);
    log_set_all_level("stderr", 9);
    log_enable_channel("client");

    if (argc < 2) 
        fprintf(stderr, "Not enough arguments.\n");
    else {
        cmd = argv[1];
        for (i = 0; i < argc - 2; i++)
            argv[i + 1] = argv[i + 2];
        
        r = kctl_run_command(cmd, argc - 2, argv);

        /* Check error return. */
        if (r < 0 && kerror_has_error()) {
            kd_error(_log_client_, "%s command failed.", cmd);
            kerror_reset();
        }
    }

    /* Drop the main pool and wave bubye to APR. */
    apr_pool_destroy(main_pool);
    apr_terminate();

    return r;
}
