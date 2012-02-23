/**
 * tbxsosd/libcomm/misc_common.h
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
 * Miscellaneous routines for comm module.
 * @author: François-Denis Gonthier
*/

#ifndef _COMM_MISC_H
#define _COMM_MISC_H

#include "gen_comm.h"

enum comm_state kdcomm_fd_wait(kdcomm *self, int wait_what);

#endif // _COMM_MISC_H
