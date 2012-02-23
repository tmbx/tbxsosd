/**
 * tbxsosd/libdb/db_otut.h
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
 * OTUT database object.
 *
 * @author François-Denis Gonthier
 */

#ifndef _DB_OTUT_H
#define _DB_OTUT_H

typedef struct __kddbotut kddbotut;

#include "db.h"
#include "db_psql.h"

/** OTUT utilities database object. */
struct __kddbotut {
    apr_pool_t *pool;

    /** Set to 1 after successfully preparing queries. */
    int is_prepared;

    /** Database connection object. */
    kdsql *db;
};

kddbotut *kddbotut_new(apr_pool_t *pool, kdsql *db);

int kddbotut_store(kddbotut *self, 
                   const char *otut_str, 
                   size_t otut_str_s,
                   uint64_t mid, 
                   uint32_t use_count, 
                   uint32_t attempt_count);

int kddbotut_store_ticket(kddbotut * self, uint64_t mid, struct timeval * tv);

int kddbotut_login(kddbotut *self, 
                   const char *otut_str, 
                   size_t otut_str_s, 
                   uint64_t *key_id,
                   struct kd_login_result **login_result);

int kddbotut_fail(kddbotut *self, 
                  const char *otut_str, 
                  size_t otut_str_s, 
                  int *nb_usage_left,
                  int *nb_fails_left);

int kddbotut_succeed(kddbotut *self, 
                     const char *otut_str,
                     size_t otut_str_s,
                     int *nb_usages_left,
                     int *nb_fails_left);

int kddbotut_check_otut(kddbotut *self, 
                        const char *otut_str, 
                        size_t otut_str_s, 
                        uint32_t *nb_use);

#endif // _DB_OTUT_H
