/**
 * tbxsosd/signals.c
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
 * Simple signal managment routines. 
 *
 * @author François-Denis Gonthier
 */

/*
 * Basically a wrapper over typical UNIX signal handling routines.
 * This use a global variable for storage so everything is set to be
 * process-wide (of course).  Don't forget to call
 * kdsignal_clear_handles after forking.
 */

#include <signal.h>
#include <stdlib.h>

static int handled_sigs_cleared = 0;
static sigset_t handled_sigs;

static int ignored_sigs_cleared = 0;
static sigset_t ignored_sigs;

static struct sigaction saved_sa[32];

struct kdsignal_info {
    /* The signal to handle. */
    int sig;

    /* The handler. */
    void (*handler)(int);
};

/** Set the mask of handled signals and also the signal handler
    function in the same blow. */
void kdsignal_handled(size_t nsigs, struct kdsignal_info *sigs) {
    size_t i;
    sigset_t sigset;

    if (!handled_sigs_cleared) {
        sigemptyset(&handled_sigs);
        handled_sigs_cleared = 1;
    }

    sigemptyset(&sigset);

    for (i = 0; i < nsigs; i++) {
        sigaddset(&sigset, sigs[i].sig);
        sigaddset(&handled_sigs, sigs[i].sig);
    }
   
    for (i = 0; i < nsigs; i++) {
        const struct sigaction sa = {
            .sa_handler = sigs[i].handler,
            .sa_mask = sigset, /* not sure. */
            .sa_flags = 0
        };
        
        sigaction(sigs[i].sig, &sa, &saved_sa[sigs[i].sig]);
    }
}

void kdsignal_ignored(int *sigs) {
    int i;

    if (!ignored_sigs_cleared) {
        sigemptyset(&ignored_sigs);
        ignored_sigs_cleared = 1;
    }

    for (i = 0; sigs[i] != 0; i++) {
        const struct sigaction sa = {
            .sa_handler = SIG_IGN
        };

        sigaction(sigs[i], &sa, &saved_sa[sigs[i]]);
    }
}

/** Clear the signals handlers for the current process. */
void kdsignal_clear_handled() {
    int i;

    sigprocmask(SIG_UNBLOCK, &handled_sigs, NULL);

    for (i = 1; i < 32; i++) {
        if (sigismember(&handled_sigs, i))
            sigaction(i, &saved_sa[i], NULL);
    }

    for (i = 1; i < 32; i++) 
        sigdelset(&handled_sigs, i);
}

void kdsignal_clear_ignored() {
    int i;

    for (i = 1; i < 32; i++) {
        if (sigismember(&ignored_sigs, i))
            sigaction(i, &saved_sa[i], NULL);
    }

    for (i = 1; i < 32; i++)
        sigdelset(&ignored_sigs, i);
}

/** Block all signals we handle. */
void kdsignal_block_all_handled() {
    sigprocmask(SIG_BLOCK, &handled_sigs, NULL);
}

/** Unblock all signals we handle. */
void kdsignal_unblock_all_handled() {
    sigprocmask(SIG_UNBLOCK, &handled_sigs, NULL);
}
