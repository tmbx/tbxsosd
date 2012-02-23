/**
 * tbxsosd/libutils/str.c
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
 * Some string routines.
 *
 * @author François-Denis Gonthier
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <kstr.h>

#include "str.h"

/* This function merges the sequences of white spaces inside the kstr specified.
 * Each contiguous sequence of whitespaces is replaced by a single space.
 * Furthermore, all leading and trailing whitespaces are skipped. This is
 * necessary since MUAs fiddle a lot with white spaces. 
 */
void str_trim_whitespace(kstr *in, kstr *out) {
    int i;
    int new_len = 0;
    int white_space_mode = 1;
    
    kstr_grow(out, in->slen);
    
    for (i = 0; i < in->slen; i++) {
    	char c = in->data[i];
	
    	if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
	    if (!white_space_mode) {
	    	out->data[new_len] = ' ';
		new_len++;
		white_space_mode = 1;
	    }
	}	
	else {
	    out->data[new_len] = c;
	    new_len++;
	    white_space_mode = 0;
	}
    }
    
    if (new_len && out->data[new_len - 1] == ' ') 
    	new_len--;

    out->slen = new_len;
    out->data[new_len] = 0;
}

/**
 * This function merges the sequences of white spaces inside the kstr specified.
 * Each contiguous sequence of whitespaces is replaced by a single space. This
 * is necessary for HMTL since MUAs fiddle a lot with white spaces.
 */
int str_merge_whitespace(kstr *in, kstr *out) {
    int i;
    int new_len = 0;
    int white_space_mode = 1;

    kstr_grow(out, in->slen);

    for (i = 0; i < in->slen; i++) {
        char c = in->data[i];

        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
            if (!white_space_mode) {
                out->data[new_len] = ' ';
                out->slen++;
                white_space_mode = 1;
            }
        }
        else {
            out->data[new_len] = c;
            out->slen++;
            white_space_mode = 0;
        }
    }

    return 0;
}

/**
 * This functions allocates memory for a new KPSTR with newlines converted
 * to spaces.
 */
int str_newline2space(kstr *in, kstr *out) {
    int i;

    kstr_grow(out, in->slen);
    
    /* Convert the newlines. */
    for (i = 0; i < in->slen; i++) {
    	if (in->data[i] == '\r') {	    
	    if (in->data[i + 1] == '\n') 
	    	i++;
	    
	    out->data[out->slen] = ' ';
	}	
	else if (in->data[i] == '\n') 
	    out->data[out->slen] = ' ';	
	else 
	    out->data[out->slen] = in->data[i];	
	
	out->slen++;
    }
    
    return 0;
}

/** Converts the string to its hex representation. */
void string_as_hex(const char *str, size_t n, char *out) {
    size_t i, j = 0;
   
    for (i = 0; i < n; i++, j += 2)
        sprintf(&out[j], "%02x", (uint8_t)str[i]);
    out[j] = 0;

    return;
}
