/**
 * tbxsosd/libutils/sendmail.h
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
 * Calls system-wide sendmail to send a mail message.
 * @author: François-Denis Gonthier
 */

#ifndef _SENDMAIL_H
#define _SENDMAIL_H

#include <apr_pools.h>
#include <kstr.h>

#include "common_msg.h"

struct sendmail_args {
    const char *mail_to;

    struct message *msg;
};

int sendmail(apr_pool_t *parent_pool, struct sendmail_args *args);

#endif // _SENDMAIL_H
