/**
 * tbxsosd/libutils/process.c
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
 */

#include <apr_pools.h>
#include <unistd.h>
#include <kerror.h>
#include <kmem.h>

#include "process.h"
#include "logging.h"
#include "logid.h"
#include "utils.h"

static int blocked_signals[] = {SIGCHLD, 0};

/* Empty handler. */
static void process_SIGCHLD_handler(int signo) { signo = signo; }

static void process_signal_block(int *signal, int is_blocked) {
    sigset_t sigset;
    int i;

    sigprocmask(0, NULL, &sigset);

    for (i = 0; signal[i] != 0; i++) {
        if (is_blocked) 
            sigaddset(&sigset, signal[i]);
        else
            sigdelset(&sigset, signal[i]);
    }

    sigprocmask(SIG_SETMASK, &sigset, NULL);
}

int process_start(apr_pool_t *pool, struct process_args *args, struct process **proc) {
    const int RD = 0, WR = 1;
    int pipe_in[2], pipe_out[2], pipe_err[2];
    char **cmdline, *prog;
    size_t i;
    struct sigaction sa;

    /* Copy the arguments from the pool to the heap.  We destroy the
       all the pools after forking the child. */
    for (i = 0; args->cmdline[i] != NULL; i++);
    cmdline = kmalloc((i + 1) * sizeof(char *));

    for (i = 0; args->cmdline[i] != NULL; i++) {
        cmdline[i] = kmalloc(strlen(args->cmdline[i]) + 1);
        strcpy(cmdline[i], args->cmdline[i]);
    }

    cmdline[i] = NULL;
    prog = cmdline[0];

    if (pipe(pipe_in) < 0 ||
        pipe(pipe_out) < 0 ||
        pipe(pipe_err) < 0) {
        KERROR_SET(_misc_, 0, kerror_sys(errno));
        return -1;
    }

    *proc = apr_pcalloc(pool, sizeof(struct process));
    memset(&sa, 0, sizeof(struct sigaction));

    /* SIGCHLD is unqueued synchronously below. */
    process_signal_block(blocked_signals, 1);

    /* Ignore SIGPIPE. */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, &((*proc)->sigpipe_action));

    /* We need to at least declare we handle SIGCHLD to receive it
       synchronously. */
    sa.sa_handler = process_SIGCHLD_handler;
    sigaction(SIGCHLD, &sa, &((*proc)->sigchld_action));

    pid_t pid = fork();
    if (pid == 0) {
        apr_pool_cleanup_for_exec();

        /* Child side. */
        close(0);
        close(1);
        close(2);
        close(pipe_in[WR]);
        close(pipe_out[RD]);
        close(pipe_err[RD]);

        dup2(pipe_in[RD], 0);
        dup2(pipe_out[WR], 1);
        dup2(pipe_err[WR], 2);

        setpgid(getpid(), getpid());

        /* exec. */
        if (execve(cmdline[0], cmdline, NULL) < 0) {
            ERROR(_log_misc_, "Failed to execute process: %s.", cmdline);
            _exit(1);
        }
    }
    else if (pid < 0) {
        KERROR_SET(_misc_, 0, "failed to fork to execute process");
        return -1;
    }
    for (i = 0; args->cmdline[i] != NULL; i++)
        kfree(cmdline[i]);
    kfree(cmdline);

    /* Close the parent side pipes. */
    close(pipe_in[RD]);
    close(pipe_out[WR]);
    close(pipe_err[WR]);

    (*proc)->pool = pool;
    (*proc)->pid = pid;
    (*proc)->timeout = args->timeout;

    /* Wrap the pipes. */
    (*proc)->pipe_in = kdfile_comm_new((*proc)->pool, APR_WRITE, pipe_in[WR])->c;
    (*proc)->pipe_out = kdfile_comm_new((*proc)->pool, APR_READ, pipe_out[RD])->c;
    (*proc)->pipe_err = kdfile_comm_new((*proc)->pool, APR_READ, pipe_err[RD])->c;

    /* Timeouts will be controlled by custom poll. */
    (*proc)->pipe_in->timeout = COMM_TIMEOUT_NONE;
    (*proc)->pipe_out->timeout = COMM_TIMEOUT_NONE;
    (*proc)->pipe_err->timeout = COMM_TIMEOUT_NONE;

    return 0;
}

static int process_interact_stdin(int status, struct process *proc, kbuffer *in_buf) {
    /* Standard input ready. */
    if (status & COMM_POLLOUT) {
        DEBUG(_log_misc_, "Writing to PID %d standard input.", proc->pid);

        size_t s = (in_buf->len - in_buf->pos) < PIPE_BUF ? in_buf->len : PIPE_BUF;
        ssize_t n = kdcomm_write_raw(proc->pipe_in, in_buf->data, s);

        if (n <= 0 && s != 0) {
            DEBUG(_log_misc_, "Underflow or error writing to PID %d standard input.", proc->pid);
            return -1;
        }
        else 
            in_buf->pos += n;

        /* Standard input done. */
        if (in_buf->pos >= in_buf->len) {
            DEBUG(_log_misc_, "Writing to PID %d standard input done.", proc->pid);
            return 0;
        } 
        else {
            DEBUG(_log_misc_, "Writing to PID %d standard input not done.", proc->pid);
            return 1;
        }
    }

    /* Hangup. */
    if (status & COMM_POLLHUP) {
        if (in_buf->pos == in_buf->len) {
            DEBUG(_log_misc_, "Writing to PID %d standard input done and hang-up.", proc->pid);
            return 0;
        } else {
            KERROR_SET(_misc_, 0, "client quit before the end of the interaction");
            return -1;
        }
    }

    if (status & COMM_POLLERR) {
        DEBUG(_log_misc_, "Writing to PID %d standard input raison an error.", proc->pid);
        return -1;
    }

    return 1;
}

static int process_interact_stdout(int status, struct process *proc, kbuffer *out_buf) {
    char read_buf[PIPE_BUF];

    if (status & COMM_POLLIN) {
        DEBUG(_log_misc_, "Reading from PID %d standard output.", proc->pid);

        ssize_t n = kdcomm_read_raw(proc->pipe_out, read_buf, sizeof(read_buf));
        if (n < 0) 
            return -1;
        else 
            kbuffer_write(out_buf, (void *)read_buf, n);
    }

    if (status & COMM_POLLHUP) {
        DEBUG(_log_misc_, "Reading from PID %d standard output hang-up.", proc->pid);
        return 0;
    }
    if (status & COMM_POLLERR) {
        DEBUG(_log_misc_, "Reading from PID %d standard output raised an error.", proc->pid);
        return -1;
    }

    DEBUG(_log_misc_, "Reading from PID %d standard output is not done.", proc->pid);
    
    /* Keep going. */
    return 1;
}

static int process_interact_stderr(int status, struct process *proc, kbuffer *err_buf) {
    char read_buf[PIPE_BUF];

    if (status & COMM_POLLIN) {
        DEBUG(_log_misc_, "Reading from PID %d standard error.", proc->pid);

        ssize_t n = kdcomm_read_raw(proc->pipe_err, read_buf, sizeof(read_buf));
        if (n < 0) 
            return -1;
        else 
            kbuffer_write(err_buf, (void *)read_buf, n);
    }

    if (status & COMM_POLLHUP) {
        DEBUG(_log_misc_, "Reading from PID %d standard error hang-up.", proc->pid);
        return 0;
    }
    if (status & COMM_POLLERR) {
        DEBUG(_log_misc_, "Reading from PID %d standard error raised an error.", proc->pid);
        return -1;
    }

    DEBUG(_log_misc_, "Reading from PID %d standard error is not done.", proc->pid);

    /* Keep going. */
    return 1;
}


/** Helper that makes sure the process will be dead when we call
    wait(). */
static int process_wait_end(struct process *proc) {
    struct timespec ts;
    siginfo_t si;
    sigset_t wanted_sigset;
    int signal = SIGTERM;

    /* Wait for the end signal.  I would much rather see this in the
       main loop but signalfd isn't generally available yet. */
    ts.tv_sec = proc->timeout / 1000;
    ts.tv_nsec = (proc->timeout % 1000) * 1000000; 
    
    sigemptyset(&wanted_sigset);
    sigaddset(&wanted_sigset, SIGCHLD);

    while (1) {
        int n, e, is_our_child, is_exited;

        DEBUG(_log_misc_, "Waiting for PID %d end.", proc->pid);        
        n = sigtimedwait(&wanted_sigset, &si, (const struct timespec *)&ts);
        e = errno;

        DEBUG(_log_misc_, "sigtimedwait returns %d.", n);
            
        /* Child signal. */
        if (n == SIGCHLD) {        
            /* Make sure this is the right process. */
            is_our_child = (si.si_signo == SIGCHLD && si.si_pid == proc->pid);
            is_exited = (si.si_code == CLD_EXITED || 
                         si.si_code == CLD_KILLED || 
                         si.si_code == CLD_DUMPED);
            
            if (is_our_child && is_exited) {
                DEBUG(_log_misc_, "PID %d death propery received.", proc->pid);
                return 0;
            }

            /* Fucked up states. */
            if (is_our_child) {
                WARN(_log_misc_, "Child %d is lost.", proc->pid);
                return -1;
            }

            WARN(_log_misc_, "Received illegitimate SIGCHLD from PID %d.", si.si_pid);            
        } 
        
        /* Timeout, or any other kind of error. */
        else if (n < 0 && signal != -1) {
            DEBUG(_log_misc_, "PID %d not dead, sending signal %d to accelerate the process.",
                  proc->pid, signal);
            killpg(proc->pid, signal);

            if (signal == SIGTERM) 
                signal = SIGKILL;
            else if (signal == SIGKILL)
                signal = -1;
        }
        else if (signal == -1)
            return -1;
    }

    return 0;
}                     

int process_interact(struct process *proc,
                     kbuffer *in_buf,
                     kbuffer *out_buf,
                     kbuffer *err_buf) {
    int wstatus, err = -2, we;
    kdcomm_pollset *pset;
    apr_pool_t *pset_pool, *loop_pool;

    apr_pool_create(&pset_pool, proc->pool);
    apr_pool_create(&loop_pool, pset_pool);

    pset = kdcomm_pollset_new(pset_pool, 3);

    if (kdcomm_pollset_add(pset, proc->pipe_in, COMM_POLLOUT, NULL) < 0 ||
        kdcomm_pollset_add(pset, proc->pipe_out, COMM_POLLIN, NULL) < 0 ||
        kdcomm_pollset_add(pset, proc->pipe_err, COMM_POLLIN, NULL) < 0) {
        KERROR_SET(_misc_, 0, "failed to prepare epoll descriptor");
        apr_pool_destroy(pset_pool);
        return -1;
    }

    kdcomm_pollset_set_timeout(pset, proc->timeout);

    /* Loop while there are still pipes alive, and until we receive
       the signal when the pipes are closed. */
    while (kdcomm_pollset_count(pset) > 0) {
        int i, nev;
        struct kdcomm_pollset_event *evs;
        enum kdcomm_pollset_error pset_err;

        apr_pool_clear(loop_pool);

        pset_err = kdcomm_pollset_poll(pset, loop_pool, &nev, &evs);

        if (pset_err == COMM_POLL_ERROR) {
            KERROR_PUSH(_misc_, 0, "poll error");
            err = -1;
            break;
        }
        /* SIGCHLD is blocked, so interruption is actually a problem. */
        else if (pset_err == COMM_POLL_INTR) {
            KERROR_PUSH(_misc_, 0, "poll interrupted by signal");
            err = -1;
            break;
        }
        else /* COMM_POLL_OK */ {
            if (nev > 0) {
                for (i = 0; i < nev; i++) {
                    int n = -1;

                    /* Standard input. */
                    if (evs[i].comm == proc->pipe_in) 
                        n = process_interact_stdin(evs[i].status, proc, in_buf);

                    /* Standard output. */
                    else if (evs[i].comm == proc->pipe_out) 
                        n = process_interact_stdout(evs[i].status, proc, out_buf);
                    
                    /* Standard error. */
                    else if (evs[i].comm == proc->pipe_err) 
                        n = process_interact_stderr(evs[i].status, proc, err_buf);

                    /* Done or error.  In both case we close the
                       pipe. */
                    if (n <= 0) {
                        kdcomm_pollset_remove(pset, evs[i].comm);
                        kdcomm_close(evs[i].comm);
                    }

                    /* Error. */
                    if (n < 0) {
                        KERROR_SET(_misc_, 0, "poll error");
                        err = -1;
                        break;
                    }
                }
            }          

            /* Timeout. */
            else if (nev == 0) {
                KERROR_SET(_misc_, 0, "process timeout");
                err = -1;
                break;
            }
        }
    }

    /* Make absolutely sure wait() will not block. */
    we = process_wait_end(proc);

    /* Make sure everything is closed. */
    if (proc->pipe_in->fd > 0) 
        kdcomm_close(proc->pipe_in);
    if (proc->pipe_out->fd > 0) 
        kdcomm_close(proc->pipe_out);
    if (proc->pipe_err->fd > 0)
        kdcomm_close(proc->pipe_err);

    /* If process_wait_end has done its job, there should be no
       waiting here. */
    if (!we) {
        waitpid(proc->pid, &wstatus, 0);

        if (WIFSIGNALED(wstatus)) 
            KERROR_SET(_misc_, 0, "process died because of signal %d", WTERMSIG(wstatus));
        else if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) != 0) 
            KERROR_SET(_misc_, 0, "process return code non-zero: %d", WEXITSTATUS(wstatus));

        /* If an error hasn't be set above, then the process has quit sanely. */
        else if (err != -1)
            err = 0;
    }

    /* If process_wait_end wasn't successful, we let the zombie roam
       since we don't want to hang waiting for it.  It will be
       collected by the death of this process. */

    apr_pool_destroy(pset_pool);

    /* Unblock signals delivery. */
    process_signal_block(blocked_signals, 0);
    sigaction(SIGPIPE, &proc->sigpipe_action, NULL);
    sigaction(SIGCHLD, &proc->sigchld_action, NULL);

    return err;
}
