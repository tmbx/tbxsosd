/**
 * tbxsosd/libcomm/ssl_comm.c
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
 * SSL client reader.
 *
 * @author François-Denis Gonthier
 * @author Laurent Birtz (rewrote most of it, who would have thought!)
 */

/* FIXME: The SSL comm object should be built on top of the socket
   comm object, especially for the wait_read/wait_write part. */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <apr_poll.h>
#include <apr_network_io.h>
#include <apr_strings.h>
#include <apr_portable.h>
#include <unistd.h>
#include <kerror.h>
#include <kmem.h>
#include <kbuffer.h>

#include "options.h"
#include "logid.h"
#include "logging.h"
#include "ssl_comm.h"
#include "gen_comm.h"
#include "misc_comm.h"
#include "utils.h"

static const char *ssl_keys_str;
static const char *ssl_certs_str;

struct kdssl_file *ssl_keys;
struct kdssl_file *ssl_certs;

static SSL_CTX *ssl_ctx = NULL;
static SSL_METHOD *ssl_method = NULL;

static struct kdssl_file *kdssl_numpath_split(apr_pool_t *parent_pool, 
                                              enum kdssl_type type,
                                              const char *numpath) {
    size_t i;
    int cnt = 0;
    char *np, *s, *s_num, *s_file, *st_spc, *st_col;
    apr_pool_t *tmp_pool, *stuff_pool;
    struct kdssl_file *stuff;

    apr_pool_create(&tmp_pool, parent_pool);
    apr_pool_create(&stuff_pool, parent_pool);

    np = apr_pstrdup(tmp_pool, numpath);

    /* Count the number of :. */
    for (i = 0; np[i] != '\0'; i++) if (np[i] == ':') cnt++;

    /* Add one since we have to add an empty item at the end. */
    cnt++;

    /* Allocate memory for the structures. */
    stuff = apr_pcalloc(stuff_pool, sizeof(struct kdssl_file) * cnt);

    s = NULL;
    i = 0;
    do {     
        if (s != NULL)
            s = apr_strtok(NULL, " ", &st_spc);
        else 
            s = apr_strtok(np, " ", &st_spc);

        /* Split along : */
        if (s != NULL) {
            s_num = apr_strtok(s, ":", &st_col);
            s_file = apr_strtok(NULL, ":", &st_col);
            
            if (!s_num || !s_file || sscanf(s_num, "%d", &stuff[i].num) < 1) {
                apr_pool_destroy(stuff_pool);
                return NULL;
            } 
            stuff[i].file_name = apr_pstrdup(stuff_pool, s_file);
            stuff[i].type = type;
            i++;
        }
    } while (s != NULL);

    /* Null terminate the stuff array. */
    stuff[cnt - 1].file_name = NULL;

    /* NOTE: We don't destroy stuff_pool here since it controls the
       existence of the stuff array in memory. */
    apr_pool_destroy(tmp_pool);

    return stuff;
}

/** Cleanup function for certificates created by
    kdssl_load_ssl_files. */
static apr_status_t kdssl_destroy_cert(void *data) {
    X509 *cert = (X509 *)data;

    X509_free(cert);
    return APR_SUCCESS;
}

/** Cleanup function for private keys created by
    kdssl_load_ssl_files. */
static apr_status_t kdssl_destroy_key(void *data) {
    EVP_PKEY *key = (EVP_PKEY *)data;

    EVP_PKEY_free(key);
    return APR_SUCCESS;
}

/** Load all SSL files in a set of files. */
static int kdssl_load_ssl_files(apr_pool_t *parent_pool, struct kdssl_file *p) {
    int i, err = 0;
    FILE *f;
    apr_pool_t *pool;

    apr_pool_create(&pool, parent_pool);
    
    for (i = 0; p[i].file_name != NULL; i++) {
        apr_pool_clear(pool);

        f = fopen(p[i].file_name, "r");
        if (!f) {
            KERROR_SET(_comm_, 0, "failed to open %s", p[i].file_name);
            err = -1;
            break;
        }

        switch (p[i].type) {
            /* This instanciate a private key from a file. */
        case KDSSL_KEY:
            p[i].key = PEM_read_PrivateKey(f, NULL, 0, NULL);
            apr_pool_cleanup_register(parent_pool, p[i].key, 
                                      kdssl_destroy_key, kdssl_destroy_key);
            break;

            /* This instanciate a certificate from a file. */
        case KDSSL_CERT:
            p[i].cert = PEM_read_X509(f, NULL, 0, NULL);
            apr_pool_cleanup_register(parent_pool, p[i].cert, 
                                      kdssl_destroy_cert, kdssl_destroy_cert);
            break;
        }
        
        fclose(f);
    }

    apr_pool_destroy(pool);

    return err;
}

static struct kdssl_file *kdssl_get_ssl_file(struct kdssl_file *p, int num) {
    int i;

    for (i = 0; p[i].file_name != NULL && p[i].num != num; i++);

    if (!p[i].file_name) 
        return NULL;
    else
        return &p[i];
}

static int kdssl_prepare_files(apr_pool_t *pool) {
    /* Split the keys. */
    ssl_keys = kdssl_numpath_split(pool, KDSSL_KEY, ssl_keys_str);
    if (ssl_keys == NULL) {
        KERROR_SET(_comm_, 0, "invalid string for ssl.keys");
        return -1;
    }

    /* Split the certificates. */
    ssl_certs = kdssl_numpath_split(pool, KDSSL_CERT, ssl_certs_str);
    if (ssl_certs == NULL) {
        KERROR_SET(_comm_, 0, "invalid string for ssl.certs");
        return -1;
    }

    /* Load the certificates. */
    if (kdssl_load_ssl_files(pool, ssl_certs) < 0) {
        KERROR_PUSH(_comm_, 0, "unable to load SSL certificates");
        return -1;
    }

    /* Load the keys. */
    if (kdssl_load_ssl_files(pool, ssl_keys) < 0) {
        KERROR_PUSH(_comm_, 0, "unable to load SSL keys");
        return -1;
    }
    
    return 0;
}

/** SSL specific initialization.
 *
 * Expensive initialization are done here so that instanciated clients
 * don't have to do it.
 */
int kdssl_static_init(apr_pool_t *pool) {
    static char err_cfg_meth[] = "SSL methods initialization failed";
    static char err_cfg_ctx[]  = "SSL context initialization error";

    ssl_keys_str = options_get_str("ssl.keys");
    ssl_certs_str = options_get_str("ssl.certs");
    
    if (kdssl_prepare_files(pool) < 0) {
        KERROR_PUSH(_comm_, 0, "failed to prepare SSL files, keys or certificates");
        return -1;
    }

    /* Loop through each keys and certificate to check for consistency
       of the configuration. */
    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if ((ssl_method = SSLv3_server_method()) == NULL) {
        KERROR_SET(_comm_, 0, err_cfg_meth);
        return -1;
    }

    if ((ssl_ctx = SSL_CTX_new(ssl_method)) == NULL) {
        KERROR_SET(_comm_, 0, err_cfg_ctx);
        return -1;
    }

    return 0;
}

static int kdssl_comm_get_peer(kdcomm *c,
                               apr_pool_t *pool,
                               const char **addr,
                               struct sockaddr **peer) {
    kdssl_comm *self = (kdssl_comm *)c->obj;
    char *ad;
    socklen_t n;

    n = sizeof(self->si);
    if (getpeername(self->c->fd, (struct sockaddr *)&self->si, &n) < 0)
        return -1;

    ad = inet_ntoa(self->si.sin_addr);
    self->addr = apr_pstrdup(pool, ad);

    if (addr != NULL) *addr = self->addr;
    if (peer != NULL) *peer = (struct sockaddr *)&self->si;

    return 0;
}

enum comm_state kdssl_comm_wait_read(kdcomm *c) {
    return kdcomm_fd_wait(c, APR_POLLIN);
}

enum comm_state kdssl_comm_wait_write(kdcomm *c) {
    return kdcomm_fd_wait(c, APR_POLLOUT);
}

/* This function returns a string describing the SSL error that just occurred.
 * Since SSL has proven to be unreliable in that domain, the function does some
 * checking to ensure some string is set.
 */
static char * get_ssl_error_string(int error) {
    char *msg;
    
    /* The remote side closed the connection. */
    if (error == 0) {
    	return "lost connection";
    }
    
    /* Get the error string from SSL. */
    msg = (char *) ERR_reason_error_string(ERR_get_error());

    /* Oh well. */
    if (msg == NULL) {
    	msg = "unknown SSL error";
    }
    
    return msg;
}

/* This function performs the specified transfer over the SSL connection. */
static ssize_t do_ssl_transfer(kdssl_comm *self, int read_flag, char *buf, int size) {
    int nb_trans = 0;
    enum comm_state state;

    while (nb_trans != size) {
    	int error;
    	int nb_left = size - nb_trans;

        /* We don't poll here since there may be some data in the SSL
           buffers when we enter this function.  Polling is done later
           when OpenSSL says it wants data. */
	if (read_flag) 
	    error = SSL_read(self->ssl, buf + nb_trans, nb_left);
        else 
	    error = SSL_write(self->ssl, buf + nb_trans, nb_left);
            
	/* The remote side closed the connection. */
	if (error == 0) return 0;
	
	/* An error occurred. */
	else if (error < 0) {
	    int ssl_err = SSL_get_error(self->ssl, error);
	    
	    /* Wait for reading. */
	    if (ssl_err == SSL_ERROR_WANT_READ) {
                state = kdssl_comm_wait_read(self->c);

                if (state == COMM_EINTR) 
                    return 0;

                else if (state != COMM_READY) 
                    return -1;
	    }
	    
	    /* Wait for writing. */
	    else if (ssl_err == SSL_ERROR_WANT_WRITE) {
                state = kdssl_comm_wait_write(self->c);

                if (state == COMM_EINTR)
                    return 0;

                else if (state != COMM_READY) 
                    return -1;
	    }
	    
	    /* Oops. */
	    else {
		KERROR_SET(_comm_, 0, "%s", get_ssl_error_string(error)); 
		return -1;
            }
	}
	
	/* We managed to transfer data. */
	else {
	    nb_trans += error;
	}
    }
	
    return nb_trans;
}

static ssize_t kdssl_comm_write(kdcomm *c, void *buf, ssize_t buf_s) {
    kdssl_comm *self = (kdssl_comm *)c->obj;
    int n = do_ssl_transfer(self, 0, buf, buf_s);
    
    if (n < 0) {
	KERROR_PUSH(_comm_, 0, "cannot write data to client");
	return -1;
    }
    
    return n;
}

static ssize_t kdssl_comm_read(kdcomm *c, void *buf, ssize_t buf_s) {
    kdssl_comm *self = (kdssl_comm *)c->obj;
    int n = do_ssl_transfer(self, 1, buf, buf_s); 
    
    if (n < 0) {
	KERROR_PUSH(_comm_, 0, "cannot read data from client");
	return -1;
    }
    
    return n;
}

static void kdssl_comm_close(kdcomm *c) {
    kdssl_comm *self = (kdssl_comm *)c->obj;

    if (self->ssl != NULL) {
        /* Close connection to peer.  That really needs to be called
           twice.  See SSL_shutdown manpage */
        if (!SSL_shutdown(self->ssl)) {
            shutdown(self->c->fd, SHUT_WR);
            SSL_shutdown(self->ssl);
        }

        SSL_free(self->ssl);
        close(self->c->fd);
    }

    self->ssl = NULL;
    self->bio = NULL;
    self->c->fd = -1;
}

static struct comm_functions ssl_comm_funcs = {
    .wait_write_func  = kdssl_comm_wait_read,
    .wait_read_func   = kdssl_comm_wait_write,
    .write_func       = kdssl_comm_write,
    .read_func        = kdssl_comm_read,
    .get_peer_func    = kdssl_comm_get_peer,
    .close_func       = kdssl_comm_close
};

/** Initialize an SSL communication object.
 *
 * This simply accepts whatever SSL connection is pending.
 * 
 * pre_bytes maybe be NULL if there is no bytes to put back inside the
 * SSL connexion.  If it's not NULL, pre_bytes_s bytes from pre_bytes
 * are put inside the SSL buffer.
 */
int kdssl_comm_init(kdssl_comm *self, 
                    void *pre_bytes, 
                    size_t pre_bytes_s) {
    int n, n1, n2, yes = 1;
    char *err_msg;
    enum comm_state state;
    int tmp_pipes[2], rd_pipe = -1, wr_pipe = -1;

    /* This is a more than reasonable assumption since we need to
       check only 4 bytes at the start of the connexion. */
    assert(!pre_bytes || pre_bytes_s < PIPE_BUF);

    self->ssl = SSL_new(ssl_ctx);

    /* Load the certificates in OpenSSL. */
    n1 = SSL_use_certificate(self->ssl, self->cert_file->cert);
    n2 = SSL_use_PrivateKey(self->ssl, self->key_file->key);
    if (n1 != 1 && n2 != 2) {
        KERROR_SET(_comm_, 0, "failed to load SSL certificate or key into SSL");
        return -1;
    }

    if (!pre_bytes) 
        self->bio = BIO_new_fd(self->c->fd, BIO_NOCLOSE);
    else {
        /* This creates a pipe that will we connect to the SSL
           library.  We put the bytes we read from the connexion in
           the write side of the pipe for SSL to read.  Once he has
           read all he can, he will ask for more.  At this point we
           connect it to the socket and resume normal SSL mode. */

        if (pipe(tmp_pipes) != 0) {
            KERROR_SET(_comm_, 0, "failed to create pipes for SSL connexion");
            return -1;
        }

        rd_pipe = tmp_pipes[0];
        wr_pipe = tmp_pipes[1];

        if (write(wr_pipe, pre_bytes, pre_bytes_s) < 0) {
            KERROR_SET(_comm_, 0, "unable to resend bytes on SSL connexion");
            return -1;
        }

        self->bio = BIO_new_fd(rd_pipe, BIO_NOCLOSE);
    }

    SSL_set_bio(self->ssl, self->bio, self->bio);

    /* Set the sockets and pipes to non-blocking. */
    if (ioctl(self->c->fd, FIONBIO, &yes, sizeof(yes)) < 0) {
        KERROR_SET(_comm_, 0, "client unable to set socket as non-blocking");
        return -1;
    }
    if (pre_bytes && ioctl(wr_pipe, FIONBIO, &yes, sizeof(yes)) < 0) {
        KERROR_SET(_comm_, 0, "client unable to set socket as non-blocking");
        return -1;
    }
    if (pre_bytes && ioctl(rd_pipe, FIONBIO, &yes, sizeof(yes)) < 0) {
        KERROR_SET(_comm_, 0, "client unable to set socket as non-blocking");
        return -1;
    }

    /* FIXME: It would be a Good Thing (tm) to support session resumption. */
    
    while (1) {
        n = SSL_accept(self->ssl);

        if (n < 0) {
            int ssl_err = SSL_get_error(self->ssl, n);

            /* SSL wants to read stuff? */
            if (ssl_err == SSL_ERROR_WANT_READ) {
                if (pre_bytes) {
                    int fd;

                    BIO_get_fd(self->bio, &fd);

                    /* Check if the SSL BIO is set to the pipe BIO, if
                       it is, connect it back to the socket. */
                    if (fd == rd_pipe) {
                        close(rd_pipe);
                        close(wr_pipe);

                        BIO_set_fd(self->bio, self->c->fd, 1);
                    }
                }

                state = kdssl_comm_wait_read(self->c);                
                if (state != COMM_READY) break;
            }

            /* SSL wants to write stuff? */
            else if (ssl_err == SSL_ERROR_WANT_WRITE) {
                state = kdssl_comm_wait_write(self->c);
                if (state != COMM_READY) break;
            }

            else {
                err_msg = ERR_error_string(ERR_get_error(), NULL);
                KERROR_SET(_comm_, 0, "SSL accept failed [SSL: %s].", err_msg);
                break;
            }
        }
        else return 0;
    }

    close(self->c->fd);
    close(rd_pipe);
    close(wr_pipe);

    /* This will free the BIO too. */
    //if (self->ssl != NULL)  SSL_free(self->ssl);

    self->ssl = NULL;
    self->bio = NULL;
    self->c->fd = -1;

    return -1;
}

/** In a child, more gentle cleanup. 
 *
 * We can't close the SSL context here.  Just close the socket on the
 * child-side.
 */
static apr_status_t kdssl_comm_child_delete(void *data) {
    kdssl_comm *self = (kdssl_comm *)data;

    /* he won't need it. */
    close(self->c->fd);
    return APR_SUCCESS;
}

/** Delete a client instance.
 *
 * This will rather rudely disconnect the connected client.  This is
 * not the right way to disconnect a client in the user process.
 */
static apr_status_t kdssl_comm_delete(void *data) {
    kdssl_comm *self = (kdssl_comm *)data;

    kdssl_comm_close(self->c);

    return APR_SUCCESS;
}

/** Load the certificate corresponding to the number. */
int kdssl_comm_load_cert_number(kdssl_comm *self, int cert_num) {

    /* Get the certificate corresponding to the number. */
    self->cert_file = kdssl_get_ssl_file(ssl_certs, cert_num);
    if (self->cert_file == NULL) {
        KERROR_SET(_comm_, 0, "no certificate number: %d", cert_num);
        return -1;
    }
    /* Get the key corresponding to the number. */
    self->key_file = kdssl_get_ssl_file(ssl_keys, cert_num);
    if (self->key_file == NULL) {
        KERROR_SET(_comm_, 0, "no key number: %d", cert_num);
        return -1;
    }

#if 0
    /* FIXME: I'm really, really not sure this is useful at all. */
    n = SSL_CTX_load_verify_locations(ssl_ctx, self->cert_file->file_name, NULL);

    if (n != 1) {
        KERROR_SET(_comm_, 0, "SSL certificate setup failed (check certificate paths)");
        return -1;
    }
#endif

    /* Save the certificate number. */
    self->cert_num = cert_num;

    return 0;
}

/** Instanciate a new SSL communication object.
 *
 * This function will return NULL in case the SSL negociation fails.
 */
kdssl_comm *kdssl_comm_new(apr_pool_t *pool, int fd) {
    kdssl_comm *self;

    self = apr_pcalloc(pool, sizeof(kdssl_comm));
    self->pool = pool;
    
    self->c = apr_pcalloc(pool, sizeof(kdcomm));
    self->c->funcs = &ssl_comm_funcs;
    self->c->state = COMM_UNKNOWN;
    self->c->fd = fd;
    self->c->obj = self;

    /* Register a cleanup function to close the socket. */
    apr_pool_cleanup_register(pool, self, 
                              kdssl_comm_delete, 
                              kdssl_comm_child_delete);

    return self;
}
