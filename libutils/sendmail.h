/**
 * tbxsosd/libutils/sendmail.h
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
