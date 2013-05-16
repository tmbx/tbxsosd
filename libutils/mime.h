/**
 * tbxsosd/libutils/mime.h
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
 * Simple MIME-compatible mail generator.
 * @author François-Denis Gonthier
 */

#ifndef _MIME_H
#define _MIME_H

#include <apr_pools.h>
#include <kbuffer.h>

#include "common_msg.h"

int message_to_mime(apr_pool_t *pool, struct message *msg, const char *nl, kbuffer *kb);

#endif // _MIME_H
