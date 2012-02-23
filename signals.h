/**
 * tbxsosd/signals.h
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
 * @author François-Denis Gonthier
 */

#ifndef _SIGNALS_H
#define _SIGNALS_H

struct kdsignal_info {
    /* The signal to handle. */
    int sig;

    /* The handler. */
    void (*handler)(int);
};

void kdsignal_handled(size_t nsigs, struct kdsignal_info *sigs);

void kdsignal_ignored(int *sigs);

void kdsignal_clear_handled();

void kdsignal_clear_ignored();

void kdsignal_block_all_handled();

void kdsignal_unblock_all_handled();

#endif // _SIGNALS_H

