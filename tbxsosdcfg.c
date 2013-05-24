/**
 * tbxsosd/tbxsosdcfg.c
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
 * Manipulate tbxsosd options
 *
 * Author: François-Denis Gonthier <fdgonthier@lostwebsite.net>
 */

/*

  This is a little program that is able to dump options configured in
  tbxsosd configuration files.  It can currently be called in 2
  ways:

  - If you don't put any command line parameters, it will display all
    the options that are currently set in the configuration, ignoring
    unset options which have no default value.
  - If you put the name of an option as the first argument on the
    command line:
    - it will show the value of the option, returning 0 as exit status 
      if the options is properly set to a value. 
    - return 1 as exit status if the options isn't set to a value and 
      has no default value.
    - return 2 if the option doesn't exists.
    - it will use exit code 255 for any other fatal error.

  I intend that a future version of this program will eventually be
  able to set options too.
 */

#include <apr_pools.h>
#include <stdio.h>
#include <stdlib.h>
#include <kstr.h>
#include <kerror.h>

#include "common/config.h"
#include "options_table.h"

#include "logging.h"
#include "utils.h"

apr_pool_t *main_pool;

void options_critical_error() {
    fprintf(stderr, "Error loading standard options.\n");
    exit(255);
}

int dump_single_option(const char *opt_arg) {
    int f;

    if (!options_exists(opt_arg)) {
        fprintf(stderr, "Unknown option %s.\n", opt_arg);
        return 2;
    }

    /* Get the type of the option. */
    f = options_get_flags(opt_arg);

    /* Make sure there is an options set. */
    if (!options_get_str(opt_arg)) {
        fprintf(stderr, "Option %s not set to a value.\n", opt_arg);
        return 1;
    }

    fprintf(stdout, "%s ", opt_arg);

    if (f & OPT_UINT32)
        fprintf(stdout, "%u\n", options_get_uint32(opt_arg));
    else if (f & OPT_UINT64)
        fprintf(stdout, PRINTF_64"u\n", options_get_uint64(opt_arg));
    else if (f & OPT_STRING)
        fprintf(stdout, "%s\n", options_get_str(opt_arg));
    else if (f & OPT_BOOL)
        fprintf(stdout, "%s\n", options_get_bool(opt_arg) ? "True" : "False");
    else if (f & OPT_FLOAT)
        fprintf(stdout, "%f\n", options_get_float(opt_arg));
    else if (f & OPT_IP_PORT)
        fprintf(stdout, "%hu\n", options_get_uint16(opt_arg));

    return 0;
}

int dump_all_options() {
    int i;

    for (i = 0; i < opts_tbl_cnt; i++) 
        dump_single_option(opts_tbl[i].name);

    return 0;
}

int main(int argc, char **argv) {
    kstr s;
    int err;

    apr_initialize();
    apr_pool_create(&main_pool, NULL);
    
    log_open(main_pool);
    log_set_all_level("stderr", 1);

    kstr_init(&s);
    
    if (options_load(main_pool, opts_tbl, opts_tbl_cnt, 
                     CONFIG_PATH "/tbxsosd.conf", options_critical_error, 1) < 0) {
        format_current_error_for_user(&s);
        fprintf(stderr, "Config read error: %s.\n", s.data);
        err = 255;
    }         
    else {
        /* Dump all options. */
        if (argc < 2) 
            err = dump_all_options();
 
        /* Single option on the command line. */
        else if (argc == 2) 
            err = dump_single_option(argv[1]);
    }

    kstr_clean(&s);

    apr_pool_destroy(main_pool);
    apr_terminate();

    exit(err);
}
