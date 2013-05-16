/**
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
*/

#include <stdlib.h>
#include <kbuffer.h>
#include <kerror.h>

#include "gen_comm.h"


/** Read a line from a comm object. */
int kdcomm_read_line(kdcomm *self,
                     kbuffer *line_buf,
                     kbuffer *store_buf) {
    void *p;
    ssize_t n = 1;
    size_t s;

    kbuffer_reset(line_buf);

    /* Read no more than what was allocated. */
    while (n > 0) {
        /* Check if there is a line. */
        p = memchr(store_buf->data, '\n', store_buf->len);
        if (p != NULL) {
            s = p - (void *)store_buf->data + 1;
            kbuffer_write(line_buf, store_buf->data, s);
            kbuffer_write8(line_buf, '\0');

            /* Remove the line we just read from the start of the buffer. */
            memmove(store_buf->data, store_buf->data + s, store_buf->len - s);
            store_buf->len -= s;
            store_buf->pos = store_buf->len;

            return line_buf->len;
        }

        /* If the buffer has no \n in it, we must read some more
           data. */
        n = kdcomm_read_raw(self, store_buf->data, store_buf->allocated);
        store_buf->len = n;
    }

    kbuffer_reset(line_buf);
    kbuffer_reset(store_buf);

    return -1;
}

/** All-or-nothing read in kbuffer. */
ssize_t kdcomm_read(kdcomm *self, kbuffer *buf, ssize_t buf_s) {
    ssize_t bytes_read = 0;
    
    kbuffer_reset(buf);

    while (bytes_read < buf_s) {
	ssize_t nb_left = buf_s - bytes_read;
	ssize_t n = kdcomm_read_raw(self, kbuffer_begin_write(buf, nb_left), nb_left);
	
        /* Error. */
        if (n < 0) { bytes_read = -1; break; }
        /* Hangup. */
        if (n == 0) { bytes_read = 0; break; }
	
	kbuffer_end_write(buf, n);
        bytes_read += n;
    }
	
    return bytes_read;
}

/** Read until exhaustion of stream, ignoring EINTR.
 *
 * Use this on pipes or streams that will be short.  It's probably a
 * bad idea to read from a socket using this.
 */
int kdcomm_read_fully(kdcomm *self, kbuffer *buf) {
    char tmp[1024];

    kbuffer_reset(buf);

    while (1) {
        ssize_t n = kdcomm_read_raw(self, tmp, sizeof(tmp));

        if (n <= 0) {            
            if (self->state == COMM_HUP || self->state == COMM_EINTR) 
                return 0;
            else if (self->state == COMM_ERR)
                return -1;
        }

        kbuffer_write(buf, (uint8_t *)tmp, n);
    }
}

/** Fully write the content of a buffer, ignoring EINTR.
 *
 * You can use this for short dialogs on pipes.
 */
int kdcomm_write_fully(kdcomm *self, kbuffer *buf) {
    ssize_t n = 0;
    size_t bs = 0;

    while (bs < buf->len) {
        n = kdcomm_write(self, buf);

        if (n <= 0) {
            if (self->state == COMM_HUP || self->state == COMM_EINTR)
                return 0;
            else if (self->state == COMM_ERR)
                return -1;
        }

        bs = n;
    }

    return 0;
}
