/**
 * tbxsosd/license.h
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
 * Load and check organization license data
 * Author: François-Denis Gonthier
 */

#ifndef _LICENSE_H
#define _LICENSE_H

#include "common.h"

/** Perform license validity check.
 *
 * This checks the license internal data structures, the signature
 * itself is checked in kdlicense_open.
 */
int kdlicense_check(struct kd_license *lic);

/** Create a new license object from string data.
 *
 * Create a kd_license structure.  This will fail if the license
 * signature is incorrect. 
 */
int kdlicense_new(apr_pool_t *parent_pool, char *license_data, struct kd_license *lic);

/** Open a license object from a file.
 *
 * Open a file containing a license, then call kdlicense_new.
 */
int kdlicense_open(apr_pool_t *parent_pool, char *license_file, struct kd_license *lic);

/** Create a license object from a file.
 *
 * Sign a kd_license structure using the key stored in the file
 * key_file.  The key file needs to be of the correct format.
 */
int kdlicense_sign(apr_pool_t *pp, 
                   const char *key_file, 
                   struct kd_license *lic, 
                   kbuffer *sig_buf);

#endif // _LICENSE_H
