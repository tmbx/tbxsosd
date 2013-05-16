/**
 * tbxsosd/server.c
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
 * Master server process.
 *
 * @author François-Denis Gonthier
 */

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <apr_thread_proc.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <assert.h>
#include <unistd.h>
#include <kerror.h>
#include <kstr.h>
#include <string.h>
#include <kmem.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "config.h"
#include "options.h"
#include "poll_comm.h"
#include "sock_comm.h"
#include "ssl_comm.h"
#include "gen_comm.h"
#include "server.h"
#include "logid.h"
#include "logging.h"
#include "client.h"
#include "utils.h"
#include "signals.h"

/** Server-specific signal handler. */
void kdserver_sig_handler(kdserver *self, int sig_id) {
    /* If there is a server instance created, deliver the signal to
       the server instance in question. */
    switch (sig_id) {        
    case SIGHUP:
        self->sig_flag |= FLAG_REHASH;
        break;

        /* A child died (RIP), we remove it's PID from the child table. */
    case SIGCHLD:
        self->sig_flag |= FLAG_CHILD;
        break;

        /* TERM signal.  Stop listening.  Wait for children to quit for some time. */
    case SIGTERM:
        self->sig_flag |= FLAG_QUIT;
        break;

        /* USER1.  Dump objects list. */
    case SIGUSR1:
        self->sig_flag |= FLAG_USER1;
        break;

        /* Interruption signal.  This means the same thing as quitting. */
    case SIGINT:
        self->sig_flag |= FLAG_QUIT;
        break;

        /* Alarm signal.  This means we have got to do something. */
    case SIGALRM:
        self->sig_flag |= FLAG_ALARM;
        break;
    }    
}

static int kdserver_child_kill(struct kdchild_data *cd, void *data) {
    data = NULL;

    /* Send a CHILD_DONE message down the pipe before quitting.  This
       is sent in fire-and-forget mode in hope the child will receive
       the message and leave gracefully.  We don't deal with errors,
       the client will detect that the socket got broken. */

    if (kdchild_send(cd, CHILD_MSG_DONE) < 0) 
        WARN(_log_server_, "Failed to communicate with filed process %d: %s", cd->pid, strerror(errno));

    /* Send the TERM signal to the child. */
    if (cd->pid > 0)
        if (kill(cd->pid, SIGTERM) < 0) 
            WARN(_log_server_, "Failed to kill child process %d: %s", cd->pid, strerror(errno));

    return 0;
}

/** Process quit signal requests. */
static void kdserver_sig_quit(kdserver *self) {
    /* Tell the childs to quit. */
    if (apr_hash_count(self->child_set->childs) > 0)
        kdchildset_do(self->child_set, kdserver_child_kill, NULL);

    /* XXX: We don't wait for the child to terminate. */
}

/** Pool destructor. */
static apr_status_t kdserver_child_cleanup(void *data) {
    kdserver *self = (kdserver *)data;

    if (apr_hash_count(self->child_set->childs) > 0) 
        kdchildset_do(self->child_set, kdserver_child_kill, NULL);

    /* XXX: We don't want for the child to terminate. */

    return APR_SUCCESS;
}

/** Return 0 if the child lifetime was long enough to avoid accidental
    fork bomb. */
static int kdserver_eval_child_lifetime(struct kdchild_data *cd) {
    time_t cur_time, delta;

    /* Check if the lifetime of the child is higher than what a
       certain threshold.  This algorithm is suboptimal.  A moving
       average would be better.  This is just enough to avoid
       accidentally fork-bombing the KPS. */

    cur_time = time(NULL);
    delta = cur_time - cd->start_time;

    DEBUG(_log_client_, "Child lifetime: %u seconds.", delta);

    /* FIXME: Make this configurable. */
    return (delta > 60 ? 0 : -1);
}

static int kdserver_restart_child_if_needed(kdserver *self) {
    /* Check if we need to restart a client. */
    if ((int)apr_hash_count(self->child_set->childs) < self->client_prefork) {
        struct kdchild_data *cd;
        int e;

        /* If restarting the preforked client fails, there is not much
           we can do but warn the administrator. */
        e = kdchildset_fork(self->child_set, 1, kdclient_main, &cd);
        if (e < 0) {
            KERROR_SET(_server_, 0, "failed to restart child");
            return -1;
        }
    }

    return 0;
}

/** Process quit. 
 *
 * Send TERM signals to all children.
 */
static int kdserver_sig_child(kdserver *self) {
    pid_t pid;
    int stat, exit_status;
    struct kdchild_data *cd = NULL;

    /* Wait for the child to die. */
    while ((pid = waitpid(0, &stat, WNOHANG)) > 0) {
        cd = kdchildset_get(self->child_set, pid);
        
        /* Maybe already removed. */
        if (cd != NULL)
            kdchildset_remove(self->child_set, cd);

        /* Protect against errors in waitpid, which are unlikely but
           have happened. */
        if (pid >= 0) {
            if (cd != NULL && cd->child_loops && kdserver_eval_child_lifetime(cd) < 0) {
                KERROR_SET(_server_, 0, "child life was too short");
                return -1;
            }

            /* Determine if what caused the child to quit should be source of
               concerns. */
            if (WIFSIGNALED(stat)) {
                if (WTERMSIG(stat) == SIGTERM)
                    INFO(_log_server_, "Client process got signaled (SIGTERM).");
                else if (WTERMSIG(stat) == SIGSEGV)
                    WARN(_log_server_, "Client process crashed (SIGSEGV).");
                else
                    WARN(_log_server_, "Client process got signaled (signal %d).", WTERMSIG(stat));

                exit_status = WEXITSTATUS(stat);
        
                if (exit_status != 0)
                    WARN(_log_server_, "Client process quit with non-zero status: %d.", exit_status);
                else
                    INFO(_log_server_, "Client process quit normally with zero exit status.");
            }
        }
    }

    return 0;
}

static int kdserver_socket_init_single(kdserver *self,
                                       char *addr_port,
                                       struct sockaddr_in *sock_addr,
                                       kdcomm **c) {
    struct in_addr srv_addr;
    int s, n, opt = 1;
    char *nt = NULL, *addr, *port_str;
    int port, is_any = 0;

    if ((addr = apr_strtok(addr_port, ":", &nt)) == NULL ||
        (port_str = apr_strtok(NULL, ":", &nt)) == NULL) {
        KERROR_SET(_server_, 0, "invalid address %s", addr_port);
        return -1;
    }

    port = strtol(port_str, NULL, 10);
    if (errno == EINVAL || errno == ERANGE || port < 0 || port > 0xFFFF) {
        KERROR_SET(_server_, 0, "invalid port number: %s", port_str);
        return -1;
    }

    if (strcmp(addr, "0.0.0.0") != 0) {
        if (inet_aton(addr, &srv_addr) < 0) {
            KERROR_SET(_server_, 0, "invalid address %s", addr);
            return -1;
        }
    }
    else is_any = 1;

    /* Create the server socket. */
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        KERROR_SET(_server_, 0, strerror(errno));
        return -1;
    }
    else {
        /* Initialize the desired listening address. */
        sock_addr->sin_family = AF_INET;
        sock_addr->sin_port = htons(port);
        if (!is_any)
            sock_addr->sin_addr.s_addr = srv_addr.s_addr;
        else
            sock_addr->sin_addr.s_addr = INADDR_ANY;

        /* Call a bunch of operation on the socket, all of them
           interdependent. */
        do {
            /* Make the socket non-blocking. */
            n = fcntl(s, F_SETFL, O_NONBLOCK);
            if (n < 0) break;

            /* Make the socket reuse the address. */
            n = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            if (n < 0) break;

            /* Bind on the wanted address. */
            n = bind(s, (struct sockaddr *)sock_addr, sizeof(struct sockaddr_in));
            if (n < 0) break;

            /* Listen on it too. */
            n = listen(s, self->sock_backlog);
            if (n < 0) break;
        } while (0);

        if (n >= 0) {
            *c = kdsock_comm_new(self->pool, s, 0)->c;
            return 0;
        }
    }

    KERROR_SET(_server_, 0, strerror(errno));
    close(s);
    return -1;
}

/** Initializes the various parameter of the main server socket. */
static int kdserver_socket_init(kdserver *self) {
    int i, idx = 0;
    apr_status_t n;
    const char *ssl_addr, *n_addr;
    char **ssl_addrs, **n_addrs;
    apr_pool_t *sockinit_pool;

    apr_pool_create(&sockinit_pool, self->pool);
    
    /* Get the addresses to listen on in the configuration. */
    ssl_addr = options_get_str("server.ssl_listen_on");
    n_addr = options_get_str("server.listen_on");

    /* Split the SSL addresses. */
    n = apr_tokenize_to_argv(ssl_addr, &ssl_addrs, sockinit_pool);
    if (n != APR_SUCCESS) {
        KERROR_SET(_server_, 0, "invalid string: %s", ssl_addr);
        apr_pool_destroy(sockinit_pool);
        return -1;
    }

    /* Split the regular addresse. */
    n = apr_tokenize_to_argv(n_addr, &n_addrs, sockinit_pool);
    if (n != APR_SUCCESS) {
        KERROR_SET(_server_, 0, "invalid string: %s", n_addr);
        apr_pool_destroy(sockinit_pool);
        return -1;
    }
        
    /* Count the number of sockets we will need. */
    for (i = 0; ssl_addrs[i++] != NULL; self->sock_count++, self->ssl_sock_count++);
    for (i = 0; n_addrs[i++] != NULL; self->sock_count++, self->n_sock_count++);

    /* Allocate space for the socket arrays. */
    self->sock = apr_pcalloc(self->pool, sizeof(kdcomm *) * self->sock_count);
    self->sock_addr = apr_pcalloc(self->pool, sizeof(struct sockaddr_in) * self->sock_count);
    self->ssl_sock_addr = apr_pcalloc(self->pool, sizeof(struct sockaddr_in *) * self->ssl_sock_count);
    self->n_sock_addr = apr_pcalloc(self->pool, sizeof(struct sockaddr_in *) * self->n_sock_count);
    self->ssl_sock = apr_pcalloc(self->pool, sizeof(kdcomm *) * self->ssl_sock_count);
    self->n_sock = apr_pcalloc(self->pool, sizeof(kdcomm *) * self->n_sock_count);

    /* Loop on all the SSL addresses. */
    for (i = 0; ssl_addrs[i] != NULL; i++, idx++) {
        if (kdserver_socket_init_single(self, ssl_addrs[i], &self->sock_addr[idx], &self->sock[idx]) < 0) {
            KERROR_PUSH(_server_, 0, "socket initialization failed");
            return -1;
        }
        self->ssl_sock[i] = self->sock[idx];
        self->ssl_sock_addr[i] = &self->sock_addr[idx];
    }

    /* Loop on all the non SSL addresses. */
    for (i = 0; n_addrs[i] != NULL; i++, idx++) {
        if (kdserver_socket_init_single(self, n_addrs[i], &self->sock_addr[idx], &self->sock[idx]) < 0) {
            KERROR_PUSH(_server_, 0, "socket initialization failed");
            return -1;
        }
        self->n_sock[i] = self->sock[idx];
        self->n_sock_addr[i] = &self->sock_addr[idx];
    }
    
    apr_pool_destroy(sockinit_pool);
    
    return (n < 0 ? -1 : 0);
}

/** Reset the user identifier of the server to 0. */
static int kdserver_reset_uid() {
    if (seteuid(getuid()) < 0) {
        CRITICAL(_log_server_, "Cannot reset process user ID.");
        return -1;
    }

    DEBUG(_log_server_, "Reset server process user ID.");

    return 0;
}

/** Change the user identifier of the server. */
static int kdserver_set_uid(kdserver *self) {
    const char *user;
    apr_pool_t *pool;
      
    /* Get the group name from the configuration file. */

    user = options_get_str("server.user");

    apr_pool_create(&pool, self->pool);

    if (set_uid_name(pool, user) < 0) {
        CRITICAL(_log_server_, "Cannot change process user name to %s.", user);
        apr_pool_destroy(pool);
        return -1;
    }

    DEBUG(_log_server_, "Changed server process username to %s.", user);

    apr_pool_destroy(pool);

    return 0;
}

/** Reset the group identifier of the server to 0. */
static int kdserver_reset_gid() {
    if (setegid(getgid()) < 0) {
        CRITICAL(_log_server_, "Cannot reset process group ID.");
        return -1;
    }

    DEBUG(_log_server_, "Reset server process group ID.");

    return 0;
}

/** Change the group identifier of the server. */
static int kdserver_set_gid(kdserver *self) {
    const char *group;
    apr_pool_t *pool;

    /* Get the group name from the configuration file. */
    group = options_get_str("server.group");
   
    apr_pool_create(&pool, self->pool);

    if (set_gid_name(pool, group) < 0) {
        CRITICAL(_log_server_, "Cannot change process group name to %s.", group);
        apr_pool_destroy(pool);
        return -1;
    }

    DEBUG(_log_server_, "Changed server process group name to %s.", group);

    apr_pool_destroy(pool);

    return 0;
}

/** Server process destructor. 
 *
 * We boldly suppose there are no children left here.  It is unlikely
 * that there are any left. A destruction request will come directly
 * from the main function which means kdserver_main() will have returned
 * due to a signal.
 */
static apr_status_t kdserver_delete(void *data) {
    data = NULL;
   
    /*
     * Clean SSL stuff.  The SSL documentation doesn't make it clear
     * that this needs to be done.  In all cases, it's certainly
     * polite to clean something after using it.
     */
    ERR_free_strings();
    EVP_cleanup();

    /* That's pretty much it. */
    return 0;
}

/** Constructor for server object. */
kdserver *kdserver_new(apr_pool_t *pool) {
    kdserver *self;
    apr_pool_t *obj_pool;
    int i;

    apr_pool_create(&obj_pool, pool);

    /* Allocate the object. */
    self = apr_pcalloc(obj_pool, sizeof(kdserver));
    apr_pool_cleanup_register(obj_pool, self, kdserver_delete, kdserver_delete);

    /* Load the configuration items related to us. */

    do {
        self->sock_backlog = options_get_uint32("server.backlog");
        self->fork = options_get_bool("server.fork");
        self->client_max = options_get_uint32("server.client_max");
        self->client_wait = options_get_uint32("server.client_wait");
        self->client_prefork = options_get_uint32("server.client_prefork");
        self->term_strikes = options_get_uint32("server.term_strikes");
        self->kill_strikes = options_get_uint32("server.kill_strikes");
        self->hang_check = options_get_uint32("server.hang_check");

        self->child_set = kdchildset_new(obj_pool);    
        self->pool = obj_pool;

        if (kdserver_reset_gid() < 0 || kdserver_reset_uid())
            break;

        if (kdsh_open(obj_pool) < 0) {
            KERROR_PUSH(_server_, 0, "failed to initialize shared data object");
            break;
        }

        /* Prefork client objects. */
        for (i = 0; self->fork && i < self->client_prefork; i++) {
            struct kdchild_data *cd;

            if (kdchildset_fork(self->child_set, 1, kdclient_main, &cd) < 0) {
                KERROR_PUSH(_server_, 0, "failed to prefork client");
                break;
            }
        }

        /* Initialize the server socket. */
        if (kdserver_socket_init(self) < 0) {
            KERROR_PUSH(_server_, 0, "socket initialization failed");
            break;
        }

        /* Set the username and group under which to run. */
        if (kdserver_set_gid(self) < 0 || kdserver_set_uid(self) < 0) 
            break;

        return self;         

    } while (0);

    apr_pool_destroy(obj_pool);
    return NULL;
}

static int kdserver_is_sock_ssl(kdserver *self, int server_sock) {
    int i = 0;

    for (i = 0; i < self->ssl_sock_count; i++)
        if (self->ssl_sock[i]->fd == server_sock) return 1;
    return 0;
}

/** Handle incoming client connections. 
 *
 * This will return 0 if the next client must be delayed, and -1 in
 * case of error.  1 in other cases.
 */
static int kdserver_handle_client(kdserver *self, struct kdcomm_pollset_event *pfd) {
    /* If the main server socket was awoken, we create a
       new client process. */
    if (pfd->status & COMM_POLLIN) {
        struct kdchild_data *cd = NULL;
        struct sockaddr_in addr;
        socklen_t addr_len;
        
        /* If we are in forked mode, make sure we can handle the
           client before accepting the connection. */
        if (self->fork) {
            int e, max_reached;
            
            cd = kdchildset_get_prefork_free(self->child_set); 

            /* If this is a standard forked server, fork a child
               which will be ready to accept the client. */
            max_reached = (int)apr_hash_count(self->child_set->childs) >= self->client_max;

            if (cd == NULL && !max_reached) {
                e = kdchildset_fork(self->child_set, 0, &kdclient_main, &cd);
                if (e < 0) {
                    KERROR_PUSH(_server_, 0, "failed to fork child");
                    return -1;
                }
            }
            /* Reached the maximum client count. */
            else if (cd == NULL && max_reached) 
                return 0;
        }

        int client_sock, server_sock = pfd->comm->fd;
        addr_len = sizeof(struct sockaddr_in);
        client_sock = accept(server_sock, &addr, &addr_len);

        if (client_sock < 0) {
            KERROR_SET(_server_, 0, strerror(errno));
            return -1;
        }
        else {
            /* Get the peer address. */            
            INFO(_log_server_, "Accepted connection from %s.", inet_ntoa(addr.sin_addr));

            /* Check what kind of process we will use to handle that
               client connection. */
            if (self->fork) {
                /* Send the client to the child. */
                if (kdchild_send_client(cd, client_sock, kdserver_is_sock_ssl(self, server_sock)) < 0) {
                    if (cd->pf_comm->state != COMM_EINTR) 
                        KERROR_SET(_server_, 0, "failed to send incoming connection to child");
                    else
                        /* Interruption will be handled in the main loop. */
                        return 0;
                }
                else {
                    close(client_sock);
                    cd->state = CHILD_BUSY;
                }
            } 
            /* If we don't fork, jump to the client handling routine
               right away. */
            else {
                debug_child_fd = client_sock;
                debug_child_fd_is_ssl = kdserver_is_sock_ssl(self, server_sock);
                kdchildset_fork_debug(self->child_set, &kdclient_main);
            }
        }
    }
    /* Any other state is not normal. */
    else {
        KERROR_SET(_server_, 0, "unexpected error while handling client");
        return -1;
    }

    return 1;
}

/** Handle communication from childs. */
static int kdserver_handle_child(kdserver *self, struct kdcomm_pollset_event *pfd) {
    struct kdchild_data *cd = NULL;

    cd = kdchildset_get(self->child_set, (pid_t)pfd->data);

    /* There is nothing we can do if the child was removed. */
    if (cd == NULL) return 0;

    /* If read fails on a child socket, the child is considered to be
       dead. */
    if ((pfd->status & COMM_POLLERR) || (pfd->status & COMM_POLLHUP)) {
        /* Make sure he really is. */
        if (cd->pid != -1)
            kill(cd->pid, SIGTERM);
        
        /* Remove it. */
        kdchildset_remove(self->child_set, cd);

        if (cd != NULL && cd->child_loops && kdserver_eval_child_lifetime(cd) < 0) {
            KERROR_SET(_server_, 0, "child life was too short");
            return -1;
        }

        /* Restart child. */
        if (kdserver_restart_child_if_needed(self) < 0) {
            KERROR_PUSH(_client_, 0, "failed to restart child");
            return -1;
        }
    }
    else if (pfd->status & COMM_POLLIN) {
        uint32_t msg;
        ssize_t sz;
        kbuffer *kb;

        kb = kbuffer_new();

        while (1) {
            sz = kdcomm_read(cd->pf_comm, kb, sizeof(msg));

            /* Communication problems are handled above. */
            if (sz < 0 && cd->pf_comm->state != COMM_EINTR) {
                KERROR_SET(_client_, 0, "communication error with client");
                kbuffer_destroy(kb);
                return -1;
            }
            /* Interruption. */
            else if (cd->pf_comm->state == COMM_EINTR) {
                kbuffer_destroy(kb);
                return 0;
            } 
            /* Otherwise, exit out, we got something. */
            else break;
        }

        kbuffer_read32(kb, &msg);
        kerror_reset();
        kbuffer_destroy(kb);

        switch (msg) {
        case CHILD_MSG_PONG:
            DEBUG(_log_prefork_, "Child %d ping? pong!", cd->pid);

            /* Zero the number of strikes against the child. */
            cd->num_strikes = 0;
            break;
        case CHILD_MSG_DONE:
            DEBUG(_log_prefork_, "Child %d is done.", cd->pid);
            cd->state = CHILD_FREE;
        }
    } 

    return 0;
}

/** Send the ping message to the child. */
static int kdserver_child_maint(struct kdchild_data *cd, void *data) {
    data = NULL;

    /* Kill a hung-up client without mercy at this point.  We expect
       that this will work. */
    if (cd->num_strikes > 4) {
        ERROR(_log_server_, "Child %d is locked-up HARD (%d strikes)!  Killing it!",
              cd->pid, cd->num_strikes);
        
        if (cd->pid > 0)
            if (kill(cd->pid, SIGKILL) < 0)
                return -1;
    }
    /* Kill potentially hung-up clients. */
    else if (cd->num_strikes > 3) {
        WARN(_log_server_, "Child %d is locked-up (%d strikes).  Terminating it.", 
             cd->pid, cd->num_strikes);
        
        if (cd->pid > 0)
            if (kill(cd->pid, SIGTERM) < 0)
                return -1;

        /* Raise the strike count. */
        cd->num_strikes++;
    }
    else {
        /* Raise the strike count. */
        cd->num_strikes++;

        /* Send the ping.  Communication error means a strike. */
        if (kdchild_send(cd, CHILD_MSG_PING) < 0) {           
            if (cd->pf_comm->state != COMM_EINTR) 
                cd->num_strikes++;
        }
    }

    return 0;
}

/** Server poll. */
static int kdserver_poll_once(kdserver *self, 
                              apr_pool_t *pool, 
                              kdcomm_pollset *pset, 
                              struct kdcomm_pollset_event **pfd) {
    int n = 0, r = -1, intr = 0;
    enum kdcomm_pollset_error e = 0;

    do {
        n = 0;
        /* Make sure signals can go through. */
        kdsignal_unblock_all_handled();

        kerror_reset();
        intr = 0;
        e = kdcomm_pollset_poll(pset, pool, &n, pfd);

        if (e == COMM_POLL_INTR) 
            intr = 1;
        else if (e == COMM_POLL_ERROR) {
            KERROR_PUSH(_server_, 0, "error listening for incoming connections");
            r = -1;
            break;
        }

        /* Block signals for flag examination. */
        kdsignal_block_all_handled();

        /* Check for timeout. */
        if (intr && (self->sig_flag != FLAG_NONE) && n == 0) {
            r = 0;
            break;
        }

        /* Rehash request, this needs to go through the server to the
           main module in some way. */
        if (self->sig_flag & FLAG_REHASH) {
            r = 0;
            break;
        }

        /* Handle quit requests. */
        if (self->sig_flag & FLAG_QUIT) {
            kdserver_sig_quit(self);            
            self->sig_flag ^= FLAG_QUIT;
            r = 0;
            break;
        }

        /* Handle child departure for a better world... */
        else if (self->sig_flag & FLAG_CHILD) {

            /* This will fail if we can't restart preforked childs. */
            if (kdserver_sig_child(self) < 0) {
                KERROR_PUSH(_server_, 0, "error while handling child process death");
                r = -1;
                break;
            }

            self->sig_flag ^= FLAG_CHILD;
        } 

        /* Perform child maintenance. */
        else if (self->sig_flag & FLAG_ALARM) {
            kdchildset_do(self->child_set, kdserver_child_maint, NULL);
            self->sig_flag ^= FLAG_ALARM;
        }

        /* Resume on signal. */
        if (n < 0 && intr) n = 0;

        /* Actual connection. */
        if (n > 0) r = n;

    } while (n == 0);     

    kdsignal_unblock_all_handled();

    return r;
}

/** Structure to pass parameters to the following function. */
struct child_pollset_args {
    struct kdcomm_pollset *pset;
    int events;
};

/** Add the child data to the pollset. */
static int kdserver_child_pollset(struct kdchild_data *cd, void *data) {
    struct child_pollset_args *args = (struct child_pollset_args *)data;

    if (kdcomm_pollset_add(args->pset, cd->pf_comm, args->events, (void *)cd->pid) < 0) 
        kd_warn(_log_server_, 0, "Cannot listen to client process %d", cd->pid);

    return 0;
}

/** Server process loop. */
int kdserver_main(kdserver *self, apr_pool_t *parent_pool) {
    int i, r = -1, n = 0;
    apr_pool_t *pool, *loop_pool;
    struct itimerval v, ov;
    
    /* Make pools.  loop_pool will be cleared at each loop below. */
    apr_pool_create(&pool, parent_pool);
    apr_pool_create(&loop_pool, pool);

    apr_pool_cleanup_register(pool, self, kdserver_child_cleanup, kdserver_child_cleanup);

    /* Install the child maintenance alarm. */
    v.it_interval.tv_sec = self->hang_check;
    v.it_interval.tv_usec = 0;
    v.it_value.tv_sec = self->hang_check;
    v.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &v, &ov);
    
    /* Accept connections */
    while (1) {
        int err = 0, child_cnt;
        kdcomm_pollset *pset;
        struct child_pollset_args args;
        struct kdcomm_pollset_event *pfd;
        
        apr_pool_clear(loop_pool);

        child_cnt = apr_hash_count(self->child_set->childs);

        pset = kdcomm_pollset_new(loop_pool, 20);
        kdcomm_pollset_set_timeout(pset, -1);

        args.pset = pset;
        args.events = COMM_POLLIN;

        /* Get the pollset for all the childs. */
        if (kdchildset_do(self->child_set, kdserver_child_pollset, &args) < 0) {
            kd_error(_log_server_, "Error preparing listening sockets.");
            break;
        }

        /* Add the master sockets in the poll set. */
        for (i = 0; i < self->sock_count; i++) {
            if (kdcomm_pollset_add(pset, self->sock[i], COMM_POLLIN, NULL) < 0) {
                kd_error(_log_server_, "Error preparing listening sockets.");
                i = -1;
                break;
            }
        }
        if (i < 0) break;

        /* Poll for activity. */
        n = kdserver_poll_once(self, loop_pool, pset, &pfd);
        if (n < 0) break;

        for (i = 0; n > 0 && i < n; i++) {
            /* Check if its a message from a child. */
            if (pfd[i].data == NULL) {
                err = kdserver_handle_client(self, &pfd[i]);

                if (err == 0) 
                    /* Throttle the handling of the next client
                       since we don't want to waste cycles spinning
                       aimelessly if there is no process available. */
                    usleep(self->client_wait * 1000);
                else 
                    /* This is the error case. */
                    if (err < 0) break;
            } 
            else  {
                /* This will rarely fail. */
                if (kdserver_handle_child(self, &pfd[i]) < 0) {
                    kd_error(_log_server_, "Error handling child process input");
                    break;
                }
            }
        }
        
        /* Propagate the error above. */
        if (err < 0) break;

        kdsignal_block_all_handled();

        /* n = 0, this is a special case, check if we are asked to
           quit to allow rehash */
        if (n == 0 && (self->sig_flag & FLAG_REHASH)) {
            r = 0;
            break;
        }
        /* Normal quit. */
        else if (n == 0) {
            kerror_reset();
            r = 0;
            break;
        }
	/* An error occurred. */
        else if (n < 0) break;

        kdsignal_unblock_all_handled();
    }

    kdsignal_unblock_all_handled();
    apr_pool_destroy(pool);

    return r;
}
