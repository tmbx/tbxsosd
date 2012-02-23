/**
 * tbxsosd/libfilters/filter_spam.h
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
