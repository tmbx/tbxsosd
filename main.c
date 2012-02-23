/**
 * tbxsosd/main.c
 * Copyright (C) 2006-2012 Opersys inc.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * Authentication daemon main entry
*/

#include <apr_thread_proc.h>
#include <apr_strings.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <getopt.h>
#include <kerror.h>
#include <fcntl.h>
#include <kmem.h>

#include "options.h"
#include "ktools.h"
#include "config.h"
#include "conf.h"
#include "keys.h"
#include "client.h"
#include "ssl_comm.h"
#include "server.h"
#include "knp_core_defs.h"
#include "main.h"
#include "logid.h"
#include "logging.h"
#include "utils.h"
#include "signals.h"
#include "options_table.h"

static kdserver *server = NULL;

/** Displays command line options. */
static void kd_options_print() {
    int p, v;
    const char *d;

    p = options_get_uint16("server.port");
    v = options_get_uint32("server.log_verbosity");
    d = options_get_str("server.log_driver");

    printf("Usage: tbxsosd [OPTIONS] \n\n"                             \
           "Options: \n"                                              \
           "   -V                Print version information \n");
    
    printf("   -D                Debug mode, don't fork nor detach, and log to stderr.\n");
    printf("   -p                Listen on this port (defaults to: %d) \n", p);
    printf("   -v                Output verbosity level (defaults to: %d) \n", v);
    
    printf("   -d                Fork the server in the background.");

    if (strlen(d) != 0) 
        printf(" (enabled) \n");
    else   
        printf(" (disabled) \n");
}

/** Display partial build configuration for the package. */
static void kd_info() {   
#ifdef INFO_REVISION
    printf("Version: %s.\n", INFO_REVISION);
#else
    printf("Version: Unknown.\n");
#endif
    printf("Config path: %s\n\n", CONFIG_PATH);
}

/** Parse command line options. */ 
static int kd_options_parse(int argc, char * argv[]) {
    int c;
    char *oarg;

    opterr = 0;

    /* Parse command-line */
    while (1) {
        c = getopt(argc, argv, "P:v:p:VdfD");
		
        if (c == -1)
            break;

        switch (c) {
            /* Listening port */
        case 'p':
            oarg = optarg;
            if (oarg != NULL) {
                uint16_t port;
                if (sscanf(oarg, "%hd", &port) < 1) {
                    fprintf(stderr, "Invalid port number: %s", oarg);
                    exit(1);
                }

                options_set_uint16("server.port", port);
            } 
            else {
                fprintf(stderr, "The -p option requires a parameter.");
                exit(1);
            }
            break;
			
            /* Verbosity */
        case 'v':
            oarg = optarg;
            if (oarg != NULL) {
                uint32_t v;
                if (sscanf(oarg, "%d", &v) < 1) {
                    fprintf(stderr, "Invalid value for logging verbosity: %s", oarg);
                    exit(1);
                }

                options_set_uint32("server.log_verbosity", v);
            } 
            else {
                fprintf(stderr, "The -v option requires a parameter.");
                exit(1);
            }
            break;
      
            /* Create PID file. */
        case 'P':
            oarg = optarg;
            if (oarg != NULL) 
                options_set_str("server.pid_path", oarg);
            else {
                fprintf(stderr, "The -P option requires a parameter.");
                exit(1);
            }
            break;

            /* Version */
        case 'V':
            kd_info();
            return -1;
					
        case 'D':
            /* DEBUG mode, don't detach nor fork and log to stderr. */
            options_set_bool("server.detach", 0);
            options_set_bool("server.fork", 0);
            options_set_str("server.log_driver", "stderr");
            break;

        case 'd':
            /* Detach from controlling terminal? */
            options_set_bool("server.detach", 1);
            break;

        case 'f':
        case '1':
            /* Fork new clients? */
            options_set_bool("server.fork", 1);
            break;
		
        default:
            kd_options_print();
            return -1;
        }
    }

    return 0;
}

static void kd_sig_handler(int sig_id) {
    if (server != NULL)
        kdserver_sig_handler(server, sig_id);       
}

static void kd_SIGALRM_handler(int sig_id) {
    kd_sig_handler(sig_id);
}

static void kd_SIGINT_handler(int sig_id) {
    kd_sig_handler(sig_id);
}

static void kd_SIGTERM_handler(int sig_id) {
    kd_sig_handler(sig_id);
}

static void kd_SIGCHLD_handler(int sig_id) {
    kd_sig_handler(sig_id);
}

static void kd_SIGUSR1_handler(int sig_id) {
    kd_sig_handler(sig_id);
}

static void kd_SIGHUP_handler(int sig_id) {
    kd_sig_handler(sig_id);
}

static void kd_spawn_save_pid_file(pid_t child_pid) {
    FILE *pidf;
    const char *config_pid_file;
   
    /* Get the run data path. */
    config_pid_file = options_get_str("server.pid_file");

    /* Create the PID if the option specifiying the path to the
       PID file was provided. */     
    if ((pidf = fopen(config_pid_file, "w")) != NULL) {
        fprintf(pidf, "%u", child_pid);
        fclose(pidf);
    }
    else ERROR(_log_server_, "Failed to open PID file.");
}

/** Handles fork() calls and related housekeeping. 
 *
 * This function calls fork twice, as per Unix FAQ 1.7.  It returns 0
 * to processes that should not do further processing after this
 * function is called.
 */
static int kd_spawn(apr_pool_t *pool) {
    apr_proc_t proc;
    apr_status_t err;

    /* Going into daemon, or not? */
    err = apr_proc_fork(&proc, pool);
    if (err != APR_INPARENT && err != APR_INCHILD) {
        CRITICAL(_log_server_, "Cannot fork to daemon.");			
        return -1;
    }

    /* Parent process is bailing out. */
    if (err == APR_INPARENT) {
        kd_spawn_save_pid_file(proc.pid);
        return 0; 
    }

    /* setsid() makes the current process the leader of a new terminal
       session.  The Unix FAQ (1.7) recommends that daemons fork again
       after setsid() so that they can never be attached to a terminal
       again. */
    if (setsid() < 0) 
        WARN(_log_server_, "setsid() failed.");

    /* The child is running at this point.  Close standard inherited
       streams and open new ones to /dev/null.  That means the forked
       server will be totally silent. */    

    /* This is usually mandated by UNIX good practice, but I just
       don't feel like uncommenting that. */
    //chdir("/");
    
    close(0);
    close(1);
    close(2);
    
    open("/dev/null", O_WRONLY);
    dup(0);
    dup(0);

    return 1;
}

/** Initialize the logging drivers and options. */
static void kd_init_logging() {
    int i;
    int is_filtered;    
    char buf[256];
    char *ce, *channel, *last;
    const char *log_chan_enabled;
    const char *log_driver;
    const char log_driver_fmt[] = "log_%s.driver";
    const char log_filtered_fmt[] = "log_%s.filter";
    /* Order matters here.  This is the order of the LOG_* constants
       found in /usr/include/sys/syslog.h. */
    const char *log_levels[] = {"emergency", 
                                "alert",
                                "critical", 
                                "error",
                                "warning",
                                "notice",
                                "info",
                                "debug", 
                                NULL};
    
    /* Configure the basic log levels. */
    for (i = 0; log_levels[i] != NULL; i++) {        
        /* Read the log driver.  If none was provided, we use the null
           driver. */
        sprintf(buf, log_driver_fmt, log_levels[i]);
        log_driver = options_get_str(buf);

        /* Check if the level needs to be filtered.  If the value was
           not provided we default to no. */        
        sprintf(buf, log_filtered_fmt, log_levels[i]);
        is_filtered = options_get_bool(buf);

        log_set_level(i, log_driver, is_filtered);
    }

    /* Configure the enabled channels. */
    log_chan_enabled = options_get_str("log_channel.enabled");
    if (strcmp(log_chan_enabled, "") == 0) return;
    ce = strdup(log_chan_enabled);
    
    for (channel = apr_strtok(ce, " ", &last); 
         channel != NULL;
         channel = apr_strtok(NULL, " ", &last)) 
        log_enable_channel(channel);
    free(ce);
}

/* FIXME: The two following functions should bail out more
   elegantly. */

/** Default out-of-memory handler. */
static void kd_abort_handler() {
    fprintf(stderr, "Fatal error: out of memory.\n");
    abort();
}

/** Default option handler. */
static void kd_options_error_handler() {
    fprintf(stderr, "Fatal error: incorrect use of configuration.\n");
    abort();
}

static void kd_dump_error() {
    kstr *err_msg;
    err_msg = kerror_str();
    fprintf(stderr, "%s", err_msg->data);
    kstr_destroy(err_msg);
}

apr_pool_t *main_pool;

/* MAIN entry point */
int main(int argc, char *argv[]) {
    int i, n, ret = 0;
    int config_loop;
    int verbosity;
    int detach;
    kstr *err_msg;
    struct kdsignal_info sigs[] = { {SIGALRM, kd_SIGALRM_handler },
                                    {SIGINT,  kd_SIGINT_handler  },
                                    {SIGTERM, kd_SIGTERM_handler },
                                    {SIGCHLD, kd_SIGCHLD_handler },
                                    {SIGUSR1, kd_SIGUSR1_handler },
                                    {SIGHUP,  kd_SIGHUP_handler  } };
    int ignored_sigs[] = {SIGPIPE, 0};
    apr_pool_t *server_pool;

    printf("Teambox Sign-On Server daemon\n");
    printf("Copyright (C) 2006-2012 Opersys inc.\n\n");

    ktools_initialize();
    kmem_set_handler(NULL, NULL, NULL, NULL, kd_abort_handler, NULL);

    /* Configuration and option setup.
       1 - Load the internal defaults.  They have the least priority.
       2 - Load the configuration file.
       3 - Load the command line options, overriding 2 and 1. */

    /* Initializes APR. */
    apr_initialize();
    apr_pool_create(&main_pool, NULL);

    /* Configuration. */
    do {
        log_open(main_pool);
        log_set_all_level("syslog", 0);

        if (options_load(main_pool, 
                         opts_tbl, 
                         opts_tbl_cnt, 
                         CONFIG_PATH "/tbxsosd.conf",
                         kd_options_error_handler,
                         0) < 0) {
	    kstr str;
	    kstr_init(&str);
	    format_current_error_for_user(&str);
	    fprintf(stderr, "config read error: %s.\n", str.data);
	    kstr_clean(&str);
            break;
        }

        kd_init_logging();

        /* Command line stuff. */
        if (kd_options_parse(argc, argv) < 0) {
            ret = -1;
            break;
        }      

        /* Load options for local use.  No need to check the return
           value since the values should have been set earlier when
           parsing the command line. */
        detach = options_get_bool("server.detach");
        verbosity = options_get_uint32("server.log_verbosity");

        log_set_verbosity(verbosity);

        /* Proceed to static initialization of modules. */
        if (kdssl_static_init(main_pool) < 0) {
            kd_dump_error();
            err_msg = kerror_str_n(0);
            CRITICAL(_log_server_, "SSL initialization failed: %s.", err_msg->data);
            kstr_destroy(err_msg);
            ret = -1;
            break;
        }        
        if (kdclient_static_init(main_pool) < 0) {
            kd_dump_error();
            err_msg = kerror_str_n(0);
            ERROR(_log_server_, "Basic initialization failed: %s", err_msg->data);
            kstr_destroy(err_msg);
            ret = -1;
            break;
        }
        if (kdkey_static_init() < 0) {
            kd_dump_error();
            err_msg = kerror_str_n(0);
            ERROR(_log_server_, "Basic initialization failed: %s", err_msg->data);
            kstr_destroy(err_msg);
            ret = -1;
            break;
        }
   
        /* Spawn the master process. */
        if (detach && kd_spawn(main_pool) == 0) break;        

        kdsignal_handled(sizeof(sigs) / sizeof(struct kdsignal_info), sigs);
        kdsignal_ignored(ignored_sigs);

        apr_pool_create(&server_pool, main_pool);
        
        /* Block all signals we say we are handling since it's the job
           of the server object to handle them. */
        kdsignal_block_all_handled();

        /* Create the new server object. */
        if ((server = kdserver_new(server_pool)) == NULL) {
            kd_dump_error();
            err_msg = kerror_str_n(0);
            CRITICAL(_log_server_, "Error initializing the server: %s", err_msg->data);
            kstr_destroy(err_msg);
            ret = -1;
            break;
        }        
           
        /* At this point, the expected behavior in signal handling can
           resume. */
        kdsignal_unblock_all_handled();

        for (i = 0; i < server->ssl_sock_count; i++)
            INFO(_log_server_, "Listening for SSL on %s:%ld.",
                 inet_ntoa(server->ssl_sock_addr[i]->sin_addr),
                 ntohs(server->ssl_sock_addr[i]->sin_port));
        for (i = 0; i < server->n_sock_count; i++)
            INFO(_log_server_, "Listening on %s:%ld.",
                 inet_ntoa(server->n_sock_addr[i]->sin_addr),
                 ntohs(server->n_sock_addr[i]->sin_port));

        /* Loop in the server.  This will block until the server
           quits. */
        config_loop = 1;
        while (config_loop && !ret) {
            n = kdserver_main(server, main_pool);

            if (n < 0) {
                err_msg = kerror_str_n(0);
                CRITICAL(_log_server_, "Server error: %s", err_msg->data);
		kstr_destroy(err_msg);
                ret = - 1;
                break;
            } 
            /* Reloading configuration was demanded. */
            else if (n == 0 && server->sig_flag & FLAG_REHASH) {
                INFO(_log_server_, "Reloading configuration.");

                /* Get rid of this block. */
                kdsignal_block_all_handled();

                apr_pool_destroy(server_pool);
                server = NULL;

                kdsignal_unblock_all_handled();

                if (options_reload(main_pool, CONFIG_PATH "/tbxsosd.conf") < 0) {
                    kd_dump_error();
                    CRITICAL(_log_server_, "config read error");
                    ret = -1;
                }
               
                if (kdclient_static_init(main_pool) < 0) {
                    kd_dump_error();
                    err_msg = kerror_str_n(0);
                    CRITICAL(_log_server_, "Basic initialization failed: %s", err_msg->data);
                    kstr_destroy(err_msg);
                    ret = -1;
                }    

                apr_pool_create(&server_pool, main_pool);

                /* Block all signals we say we are handling since it's the job
                   of the server object to handle them. */
                kdsignal_block_all_handled();

                /* Create the new server object. */
                if ((server = kdserver_new(server_pool)) == NULL) {
                    kd_dump_error();
                    err_msg = kerror_str_n(0);
                    CRITICAL(_log_server_, "Error initializing the server: %s", err_msg->data);
                    kstr_destroy(err_msg);
                    ret = -1;
                    break;
                }        
           
                /* At this point, the expected behavior in signal handling can
                   resume. */
                kdsignal_unblock_all_handled();
            }
            /* Clean quit. */
            else if (n == 0) {
                INFO(_log_server_, "Server terminating.");
                config_loop = 0;
            }
        }

    } while (0);

    kdkey_static_clean();

    apr_pool_destroy(main_pool);

    apr_terminate();    
    ktools_finalize();

    return ret;
}
