/**
 * tbxsosd/libcomm/misc_common.h
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
 * Miscellaneous routines for comm module.
 * @author: François-Denis Gonthier
*/

#ifndef _COMM_MISC_H
#define _COMM_MISC_H

#include "gen_comm.h"

enum comm_state kdcomm_fd_wait(kdcomm *self, int wait_what);

#endif // _COMM_MISC_H
