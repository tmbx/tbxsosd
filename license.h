/**
 * tbxsosd/license.h
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
