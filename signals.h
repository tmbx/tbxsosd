/**
 * tbxsosd/signals.h
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

