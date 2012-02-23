/**
 * tbxsosd/libutils/sendmail.c
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
 * Calls system-wide sendmail to send a mail message.
 * @author: François-Denis Gonthier
 */

#include <apr_thread_proc.h>
#include <apr_pools.h>
#include <stdio.h>
#include <kerror.h>
#include <unistd.h>
#include <utils.h>

#include "mime.h"
#include "gen_comm.h"
#include "file_comm.h"
#include "logid.h"
#include "sendmail.h"
#include "process.h"

int sendmail(apr_pool_t *parent_pool, struct sendmail_args *mail_args) {
    int err = -1;
    apr_pool_t *pool;
    const char *cmdline[] = {"/usr/sbin/sendmail", mail_args->mail_to, NULL};
    struct process *proc;
    struct process_args args = {.timeout = 1000,
                                .cmdline = cmdline};

    if (mail_args->msg->from_addr == NULL) {
        KERROR_SET(_misc_, 0, "missing From address");
        return -1;
    }
    if (mail_args->msg->to == NULL) {
        KERROR_SET(_misc_, 0, "missing To address");
        return -1;
    }
    if (mail_args->msg->subject == NULL) {
        KERROR_SET(_misc_, 0, "missing subject");
        return -1;
    }

    apr_pool_create(&pool, parent_pool);

    /* Start the sendmail process. */
    if (process_start(pool, &args, &proc) < 0) {
        KERROR_PUSH(_misc_, 0, "failed to create process");
        apr_pool_destroy(pool);
        return -1;
    }       
    else {
        kbuffer *in_buf, *out_buf, *err_buf;

        in_buf = kbuffer_new();
        out_buf = kbuffer_new();
        err_buf = kbuffer_new();

        /* Convert the message to so-so MIME. */
        if (message_to_mime(parent_pool, mail_args->msg, "\n", in_buf) < 0) {
            KERROR_PUSH(_misc_, 0, "failed to generate MIME message");
            err = -1;
        }            
        /* Feed the message to sendmail. */
        else if (process_interact(proc, in_buf, out_buf, err_buf) < 0) {
            KERROR_PUSH(_misc_, 0, "failed to send mail message");
            err = -1;
        }
        else 
            err = 0;       

        kbuffer_destroy(in_buf);
        kbuffer_destroy(out_buf);
        kbuffer_destroy(err_buf);
    }

    apr_pool_destroy(pool);

    return err;
}
