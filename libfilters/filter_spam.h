/**
 * tbxsosd/libfilters/filter_spam.h
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
 * SpamAssassin message filter.
 *
 * @author François-Denis Gonthier
 * @author Kristian Benoit
 */

#ifndef _SPAM_H
#define _SPAM_H

extern struct filter_driver filter_spam;

struct filter_spam_data {
    /**
     * Max spam rating for a message to be rejected.
     */
    int max_reject_rating;

    /**
     * Max spam rating for a message to be challenged.
     */
    int max_challenge_rating;
};

#endif // _SPAM_H
