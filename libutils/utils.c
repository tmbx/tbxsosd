/**
 * tbxsosd/libutils/utils.c
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
 * Homeless functions shelter.
 *
 * @author François-Denis Gonthier
 */

#include <poll.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <kmem.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iconv.h>
#include <ktools.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>

#include "common/logid.h"

#include "utils.h"
#include "logging.h"

int set_gid_name(apr_pool_t *pool, const char *group) {
    apr_pool_t *subpool;
    char *buf;
    struct group grp, *g2;
    long s;

    apr_pool_create(&subpool, pool);

    s = sysconf(_SC_GETGR_R_SIZE_MAX);
    buf = apr_pcalloc(subpool, s);

    do {
        getgrnam_r(group, &grp, buf, s, &g2);

        if (g2 == NULL) {
            KERROR_SET(_server_, 0, "Group %s not found.", group);
            break;
        }
        
        if (setegid(grp.gr_gid)) {
            KERROR_SET(_server_, 0, "Cannot change process group name to %s.", group);
            break;
        }

        apr_pool_destroy(subpool);
        
        return 0;

    } while (0);

    apr_pool_destroy(subpool);
    return -1;
}

int set_uid_name(apr_pool_t *pool, const char *user) {
    apr_pool_t *subpool;
    char *buf;
    struct passwd pwd, *p2;    
    long s;

    apr_pool_create(&subpool, pool);

    s = sysconf(_SC_GETPW_R_SIZE_MAX);
    buf = apr_pcalloc(subpool, s);

    do {
        getpwnam_r(user, &pwd, buf, s, &p2);

        if (p2 == NULL) {
            KERROR_SET(_server_, 0, "username %s not found", user);
            break;
        }
        
        if (seteuid(pwd.pw_uid) < 0) {
            KERROR_SET(_server_, 0, "cannot change process username to %s", user);
            break;
        }   

        apr_pool_destroy(subpool);

        return 0;    

    } while (0);

    apr_pool_destroy(subpool);
    return -1;
}

/** Returns the name of the currently executing program.
 *
 * Allocates the result on pool.
 */
char *get_self_name(apr_pool_t *pool) {
    apr_file_t *f;
    apr_pool_t *subpool;
    apr_status_t err;
    char *self_name;
    char line_buf[8096];

    apr_pool_create(&subpool, pool);
    err = apr_file_open(&f, "/proc/self/status", APR_READ, APR_OS_DEFAULT, subpool);
    
    if (err != APR_SUCCESS) {
        apr_pool_destroy(subpool);
        return NULL;
    }

    while (1) {
        char *s;
        size_t line_s;

        /* Read a line of the file. */
        err = apr_file_gets(line_buf, sizeof(line_buf), f);
        if (err != APR_SUCCESS)
            break;
        line_s = strlen(line_buf);
        line_buf[--line_s] = '\0';

        /* Search for the process name in the current line. */
        s = strstr(line_buf, "Name:\t");
        if (s != NULL) {
            /* Go past the space. */
            s += 6;
            line_s -= 6;

            if (line_s > 0) {
                /* We have something, yay! As the memory was
                   allocated by read_line, we expect the returned
                   string to be sanely null-terminated. */
                apr_pool_destroy(subpool);
                self_name = apr_pstrdup(pool, s);

                return self_name;
            }
        }
    }

    apr_pool_destroy(subpool);

    return NULL;
}

/** Blockifies a base64 text. */
void blockify_base64(const size_t line_len,
                     const char *b64, size_t b64_s, char *new_b64, size_t new_b64_s) {
    uint32_t i = 0, j = 0, s = 0;

    while (i < b64_s) {
        s = b64_s - i < line_len ? b64_s - i : line_len;
        memcpy(new_b64 + j, b64 + i, s);
        j += s;
        i += s;
        new_b64[j] = '\n';
        j++;
    }

    new_b64[new_b64_s] = '\0';
}

/** Calculates the size that the base64 will occupy with newlines. */
int blockify_get_size(const size_t line_len, const size_t sig_s) {
    return sig_s + (sig_s / line_len);
}


/* This function converts the specified UTF-8 string to an ISO-8859-1 string. If
 * 'pool' is non-NULL, the memory allocated for the converted string is taken
 * from the pool. Otherwise, the memory is allocated with 'kmalloc()'.
 * This function returns -1 on failure, 0 otherwise.
 */
int utf8_to_iso88591(apr_pool_t *pool, char *utf8, char **out) {
    int error = -1;
    int alloc_len = strlen(utf8) + 1;
    iconv_t iconv_desc = (iconv_t) -1;
    
    *out = pool ? (char *) apr_palloc(pool, alloc_len) : (char *) kmalloc(alloc_len);
    
    /* Try. */
    do {
	char *src = utf8;
	char *dst = *out;
	size_t nb_in = alloc_len - 1;
	size_t nb_out = alloc_len - 1;

	iconv_desc = iconv_open("ISO-8859-1", "UTF-8");

	if (iconv_desc == (iconv_t) -1) {
	    KERROR_SET(_client_, 0, "cannot convert charset: unsupported character set");
	    break;
	}


	if (iconv(iconv_desc, &src, &nb_in, &dst, &nb_out) == (size_t) -1) {
	    KERROR_SET(_client_, 0, "cannot convert charset: %s", strerror(errno));
	    break;
	}
	
	*dst = 0;
	error = 0;
	
    } while (0);
    
    if (iconv_desc != (iconv_t) -1) iconv_close(iconv_desc);
    
    if (error) {
	if (! pool) kfree(*out);
	*out = NULL;
    }
    
    return error;
}

/** Write the APR error string in a pool. 
 *
 * NOTE: At this is not already implemented in APR, it seems to
 * suggest that this might not be a good idea.
 */
char *apr_perror(apr_pool_t *pool, apr_status_t err) {
    char *err_str;

    err_str = apr_pcalloc(pool, 1024);
    apr_strerror(err, err_str, 1024);
    
    return err_str;
}

/** Return an UUID. 
 *
 * The current incarnation of this function return an UUID out of
 * Linux /proc-based UUID generator.  Returns NULL on error.
 */
char *uuid(apr_pool_t *pool) {
    apr_file_t *f;
    apr_status_t err;
    char *fn = "/proc/sys/kernel/random/uuid";
    char *uuid;
    size_t n;

    uuid = apr_pcalloc(pool, UUID_SIZE + 1);

    err = apr_file_open(&f, fn, APR_READ, APR_OS_DEFAULT, pool);
    if (err != APR_SUCCESS) {
        KERROR_SET_APR(_client_, 0, err);
        KERROR_PUSH(_client_, 0, "failed to open UUID generator file");
        return NULL;
    }

    n = UUID_SIZE;
    err = apr_file_read(f, uuid, &n);
    if (err != APR_SUCCESS || n < UUID_SIZE) {
        KERROR_SET_APR(_client_, 0, err);
        KERROR_PUSH(_client_, 0, "failed to read from UUID generator file");
        return NULL;
    }
    uuid[UUID_SIZE] = '\0';

    apr_file_close(f);

    return uuid;
}

/* The two following functions are heavily inspired from the
   identically named function in "UNIX Network Programming volume 1"
   by Richard Stevens. */

/** Write a descriptor on a domain socket. 
 *
 * This function returns the return value of the final sendmsg call or
 * -1 if there was an error elsewhere.
 */
int write_fd(int target_fd, int fd, int ctrl_data) {
    struct cmsghdr *cmsg;
    struct msghdr msg;
    struct iovec iov[1];
    char buf[CMSG_SPACE(sizeof(int))];

    memset(&msg, 0, sizeof(struct msghdr));

    /* Set the information relevant to sending the fd to the
       waiting client. */
    msg.msg_controllen = sizeof(buf);
    msg.msg_control = buf;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsg)) = fd;

    msg.msg_controllen = cmsg->cmsg_len;

    /* Write one puny byte for the other end.  Otherwise he just won't
       know he has anything to read. */
    iov[0].iov_base = &ctrl_data;
    iov[0].iov_len = sizeof(int);
    
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
        
    /* Send the file descriptor. */
    return sendmsg(target_fd, &msg, 0);
}

/** Read a description from a domain socket. 
 *
 * Returns the return value of recvmsg on error and the fd on success.
 */
int read_fd(int src_fd, int *ctrl_data) {
    int err, n, fd;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct iovec iov[1];
    char buf[CMSG_SPACE(sizeof(int))];
    struct pollfd pfd;

    pfd.fd = src_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    /* FIXME: UGLY ASS.  Loops over EINTR. */
    do {
        err = poll(&pfd, 1, -1);

        /* Continue on interruption. */
        if (errno == EINTR) 
            continue;
        else 
            break;
    } while (err <= 0 && pfd.revents | POLLIN);

    memset(&msg, 0, sizeof(struct msghdr));

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    iov[0].iov_base = ctrl_data;
    iov[0].iov_len = sizeof(int);

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if ((n = recvmsg(src_fd, &msg, 0)) < 0) 
        return n;
    
    cmsg = CMSG_FIRSTHDR(&msg); 
        
    /* Make sure we get the right data. */
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) 
        fd = *((int *) CMSG_DATA(cmsg));
    else
        return -1;

    return fd;
}

/* FIXME: In Blackjack this function should become generally available. */
void format_current_error_for_user(kstr *dest) {
    struct kerror *error_instance = kerror_get_current();
    int i;
    
    kstr_reset(dest);

    if (error_instance->stack.size == 0) {
        kstr_assign_cstr(dest, "unknown error");
    }
    
    else {
	for (i = error_instance->stack.size - 1; i >= 0; i--) {
	    struct kerror_node *node = (struct kerror_node *) karray_get(&error_instance->stack, i);
            /* Level 1 error are meant to be readable. */	    
            if (node->level >= 1) {
                if (i != error_instance->stack.size - 1) {
                    kstr_append_cstr(dest, ": ");
                }
            
                    kstr_append_kstr(dest, &node->text);
            }
	}
    }

    if (dest->slen == 0) 
        kstr_assign_cstr(dest, "unknown error");
}

kstr *kdclient_format_error(const char *file, int line, const char *msg, va_list va) {
    char *p;
    kstr *err_msg, *err;
    kstr err_fmt;
    
    /* Search for @ */  
    p = strstr(msg, "@");
    if (p) {
        kstr_init_buf(&err_fmt, msg, p - msg);
        err_msg = kerror_str_n(0);        
        kstr_append_kstr(&err_fmt, err_msg);
        kstr_destroy(err_msg);
        kstr_append_cstr(&err_fmt, p + 1);
    } 
    else kstr_init_cstr(&err_fmt, msg);
    
    err = kmalloc(sizeof(kstr)); 
    kstr_init_sfv(err, err_fmt.data, va);  
    
    /* Add [file:line] before error message. */
    kstr_sf(&err_fmt, "[%s:%d] %s", file, line, err->data);
    kstr_assign_kstr(err, &err_fmt);
    
    kstr_clean(&err_fmt);

    return err;
}

void _kd_push_apr_error(const char *file, 
                        int line, 
                        const char *function, 
                        int module, 
                        int level, 
                        apr_status_t err) {
    char buf[1024];
    struct kerror_node *n;

    apr_strerror(err, buf, sizeof(buf));

    n = kerror_node_new(file, line, function, module, level, buf);
    kerror_push(n);
}

void _kd_set_apr_error(const char *file, 
                       int line, 
                       const char *function, 
                       int module, 
                       int level, 
                       apr_status_t err) {
    char buf[1024];
    struct kerror_node *n;

    apr_strerror(err, buf, sizeof(buf));

    n = kerror_node_new(file, line, function, module, level, buf);

    kerror_reset(); 
    kerror_push(n); 
}

static void kdclient_log_very_internal(int is_err, 
                                       const char *file, 
                                       int line, 
                                       const char *log_channel,
                                       const char *msg, 
                                       va_list va) {
    struct kerror *error_instance = kerror_get_current();
    int i, level = (is_err ? LOG_ERR : LOG_WARNING);
    kstr err;
   
    kstr_init_sfv(&err, msg, va);     

    log_write_line(level, log_channel, file, line, "%s", err.data);

    if (error_instance->stack.size <= 0) {
        kstr_clean(&err);
        return;
    }
    
    if (is_err)
        log_write(level, log_channel, "*** Error stack ***");
    else
        log_write(level, log_channel, "*** Warning stack ***");

    for (i = 0; i < error_instance->stack.size; i++) {
        struct kerror_node *en = (struct kerror_node *)karray_get(&error_instance->stack, i);
        log_write(level, log_channel, "[%s:%d] %s", en->file, en->line, en->text.data);
    }

    log_write(level, log_channel, "*** End ***");

    kstr_clean(&err);
}

void kdclient_error_internal(const char *file, int line, 
                             const char *log_channel, const char *msg, ...) {
    va_list va;

    va_start(va, msg);
    kdclient_log_very_internal(1, file, line, log_channel, msg, va);
    va_end(va);
}

void kdclient_warn_internal(const char *file, int line, 
                            const char *log_channel, const char *msg, ...) {
    va_list va;

    va_start(va, msg);
    kdclient_log_very_internal(0, file, line, log_channel, msg, va);
    va_end(va);
}
