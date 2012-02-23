/**
 * tbxsosd/libutils/template.c
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
 * Simple template manager using 'formatmail'
 *
 * @author François-Denis Gonthier
 */

#include <apr_thread_proc.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <kerror.h>

#include "logging.h"
#include "poll_comm.h"
#include "file_comm.h"
#include "gen_comm.h"
#include "utils.h"
#include "template.h"
#include "logid.h"

static void template_misc_input(struct template *self, kbuffer *buf) {
    apr_hash_index_t *hi;
    apr_pool_t *pool;
    char *key, *val;
    ssize_t key_s;

    apr_pool_create(&pool, self->pool);

    /* Loop over all the variables in the hash. */    
    for (hi = apr_hash_first(pool, self->vars);
         hi;
         hi = apr_hash_next(hi)) {
        apr_hash_this(hi, (void *)&key, &key_s, (void *)&val);
        
        kbuffer_writef(buf, "%s %s\n", key, val);
    }

    kbuffer_writef(buf, "template %s\n", self->file);
    kbuffer_writef(buf, "end\n");

    apr_pool_destroy(pool);
}

/** Create a process for formatmail which will format the message. */
int template_format(struct template *self, kbuffer *out_buf, kbuffer *err_buf) {
    struct process *proc;
    const char *cmdline[] = {self->formatmail, NULL};
    struct process_args args = {.timeout = self->timeout,
                                .cmdline = cmdline};
    struct timeval start_tv, end_tv;
    int has_time = 1;
    apr_pool_t *pool;
    kbuffer *in_buf;

    in_buf = kbuffer_new();
    apr_pool_create(&pool, self->pool);

    /* Prepare the buffer to be sent as standard input. */
    template_misc_input(self, in_buf);

    if (gettimeofday(&start_tv, NULL) < 0)
        has_time = 0;

    /* Start the process. */
    if (process_start(pool, &args, &proc) < 0) {
        KERROR_PUSH(_misc_, 0, "failed to create process");
        
        kbuffer_destroy(in_buf);
        apr_pool_destroy(pool);

        return -1;
    }

    /* Interact with formatmail to received the return value. */
    if (process_interact(proc, in_buf, out_buf, err_buf) < 0) {
        char *p, *s;

        KERROR_PUSH(_misc_, 0, "error interacting with formatmail");

        ERROR(_log_misc_, "*** formatmail error ***");

        /* Log the output. */
        kbuffer_write8(err_buf, 0);
        s = apr_strtok((char *)err_buf->data, "\n", &p);

        /* No lines? */
        if (!s) {
            if (strlen((char *)err_buf->data) == 0) 
                ERROR(_log_misc_, "No error output from formatmail.");
            else
                ERROR(_log_misc_, s);
        } 
        /* Multiple lines. */
        else {
            do {
                ERROR(_log_misc_, s);
            } while ((s = apr_strtok(NULL, "\n", &p)) != NULL);
        }

        ERROR(_log_misc_, "*** End ***");

        kbuffer_destroy(in_buf);
        apr_pool_destroy(pool);

        return -1;
    }

    if (has_time && gettimeofday(&end_tv, NULL) >= 0) {
        float diff_usec, diff_sec;
        diff_sec = end_tv.tv_sec - start_tv.tv_sec;
        diff_usec = end_tv.tv_usec - start_tv.tv_usec;

        DEBUG(_log_misc_, "formatmail running time: %f.", diff_sec + (diff_usec / 1000000));
    } 
    else
        WARN(_log_misc_, "Failed to calculate the running time of formatmail.");

    kbuffer_destroy(in_buf);
    apr_pool_destroy(pool);

    return 0;
}

/** Set a string variable in the internal hash for template variables. */
void template_set_str(struct template *self, const char *key, const char *val) {
    apr_hash_set(self->vars, key, APR_HASH_KEY_STRING, val);
}

/** Set a unsigned integer variable in the internal hash. */
void template_set_uint32(struct template *self, const char *key, uint32_t v) {
    char *sv;

    sv = apr_psprintf(self->pool, "%u", v);
    apr_hash_set(self->vars, key, APR_HASH_KEY_STRING, sv);
}

/** Set a long integer variable in the internal hash. */
void template_set_uint64(struct template *self, const char *key, uint64_t v) {
    char *sv;

    sv = apr_psprintf(self->pool, "%llu", v);
    apr_hash_set(self->vars, key, APR_HASH_KEY_STRING, sv);
}

/** Create a new template object. 
 *
 * This will never return null.
 */
struct template *template_new(apr_pool_t *pool, 
                              const char *tmpl_file,
                              const char *formatmail_path,
                              uint32_t timeout) {
    struct template *tmpl;

    tmpl = apr_pcalloc(pool, sizeof(struct template));
    tmpl->file = tmpl_file;
    tmpl->formatmail = formatmail_path;
    tmpl->pool = pool;
    tmpl->vars = apr_hash_make(pool);
    tmpl->timeout = timeout;
    
    return tmpl;    
}
