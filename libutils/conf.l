/**
 * tbxsosd/libutils/config.l
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
 * Simple configuration file object.
 *
 * @author François-Denis Gonthier
 */

%option noyyalloc noyyrealloc noyyfree

%{ 

#include <sys/types.h>
#include <sys/stat.h>
#include <apr_strings.h>
#include <apr_hash.h>
#include <apr_file_info.h>
#include <apr_general.h>
#include <assert.h>
#include <fcntl.h>
#include <alloca.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdlib.h>
#include <limits.h>
#include <kerror.h>
#include <kmem.h>

#include "conf.h"
#include "logid.h"
#include "logging.h"

struct config_lexer_value {
    char *section;
    char *name;
    char *value;
};

enum config_lexer_state {
    LEXER_EXPECTS_NAME,
    LEXER_EXPECTS_EQUAL,
    LEXER_EXPECTS_VALUE,
    LEXER_EXPECTS_END
};
    
static enum config_lexer_state lexer_state;
static struct config_lexer_value curr_value;
static apr_pool_t *scan_pool;
static char *scan_file;
static int scan_line;
static int scan_error; /* Error handling in lex is a pain in the ass. */
static apr_array_header_t *scan_line_stack;
static apr_array_header_t *scan_file_stack;

static void config_append_error_line();

static int config_splitname(char *txt, char **name, char **value);

static void config_store(struct config_lexer_value *val);
 
static void config_push_expectation_error(const char *txt);

 static config *lex_self;

/* Memory allocators for lex code. */
void *yyalloc(size_t s);
void *yyrealloc(void *ptr, size_t s);
void yyfree(void *ptr);
%}

%%

[:space:]*#.*$ {
    /* Comment handling, nothing to do. */
}

include\(.*\) {
    size_t i, s;
    char *fname = NULL;

    s = strlen(yytext);
    for (i = 0; i < s; i++) {
        if (yytext[i] == '(') fname = &yytext[i + 1];
        if (yytext[i] == ')') yytext[i] = '\0';
    }

    /* Base the search from the same directory the configuration file
       was loaded. */

    if ((yyin = fopen(fname, "r")) == NULL) {
        KERROR_SET(_config_, 1, "cannot open %s: %s", fname, strerror(errno));
	config_append_error_line();
        return -1;
    }

    yypush_buffer_state(yy_create_buffer(yyin, YY_BUF_SIZE));
    *(char **) apr_array_push(scan_file_stack) = scan_file;
    *(int *) apr_array_push(scan_line_stack) = scan_line;
    scan_file = apr_pstrdup(scan_pool, fname);
    scan_line = 1;
}

[a-zA-Z0-9\_]+\.[a-zA-Z0-9\_]+ {
    char *txt;

    /* Section name & variable name */
    if (lexer_state == LEXER_EXPECTS_NAME) {
        txt = apr_pstrdup(lex_self->config_pool, yytext);
        if (config_splitname(txt, &curr_value.section, &curr_value.name)) return -1;
        lexer_state = LEXER_EXPECTS_EQUAL;
    } 
    else {
        config_push_expectation_error(yytext);       
        return -1;
    }
}

= { 
    if (lexer_state == LEXER_EXPECTS_EQUAL)
        /* Assignment. */
        lexer_state = LEXER_EXPECTS_VALUE;
    else {
        config_push_expectation_error(yytext);
        return -1;
    }
}

\"[^\"\n]*\" { 
    /* Configuration value. */

    if (lexer_state == LEXER_EXPECTS_VALUE) {
        /* Skip the double quotes. */
        yytext++;
        yytext[strlen(yytext) - 1] = '\0';      

        curr_value.value = apr_pstrdup(lex_self->config_pool, yytext);    

        lexer_state = LEXER_EXPECTS_END;
    } 
    else {
        config_push_expectation_error(yytext);
        return -1;
    }
}

; { 
    /* ; = end of configuration line. */
    if (lexer_state == LEXER_EXPECTS_END) {
        config_store(&curr_value);
        memset(&curr_value, 0, sizeof(curr_value));
        lexer_state = LEXER_EXPECTS_NAME;
    }
    else {
        config_push_expectation_error(yytext);
        return -1;
    }
}

<*>"\n" {
    /* Newline. */
    scan_line++;
}

[ \t]* {
    /* Empty spaces. */
}

. {
    KERROR_SET(_config_, 1, "unexpected character \'%s\' found", yytext);
    config_append_error_line();
    return -1;
}

<<EOF>> {
    if (lexer_state == LEXER_EXPECTS_NAME) {
        /* End of file. */
        fclose(YY_CURRENT_BUFFER->yy_input_file);
        yypop_buffer_state();
    
        if (YY_CURRENT_BUFFER == NULL) return 0;
	
	scan_file = *(char **) apr_array_pop(scan_file_stack);
	scan_line = *(int *) apr_array_pop(scan_line_stack);

    } else {
        config_push_expectation_error("unexpected end-of-file");
        return -1;
    }
}

%%
void *yyalloc(size_t s) {
    return kmalloc(s);
}

void *yyrealloc(void *ptr, size_t s) {
    return krealloc(ptr, s);
}

void yyfree(void *ptr) {
    kfree(ptr);
}

static void config_append_error_line() {
    /* Remember that an error occurred. */
    scan_error = 1;
    
    /* Specify where the error occurred. */
    KERROR_PUSH(_config_, 1, "%s:%d", scan_file, scan_line);
}

static void config_store(struct config_lexer_value *val) {
    apr_hash_t *name_hash = NULL;

    /* Don't store empty value. */
    if (val->value == NULL) return;

    /* Fetch the right section. */
    name_hash = apr_hash_get(lex_self->sections, val->section, APR_HASH_KEY_STRING);
    if (name_hash == NULL) {
        name_hash = apr_hash_make(lex_self->config_pool);
        apr_hash_set(lex_self->sections, val->section, APR_HASH_KEY_STRING, name_hash);
    }

    /* Store the value in the hash. */
    apr_hash_set(name_hash, val->name, APR_HASH_KEY_STRING, val->value);
}

static int config_splitname(char *nm, char **sec, char **val) {
    char *dot_pos = strstr(nm, ".");
    
    if (dot_pos == NULL) {
	KERROR_SET(_config_, 1, "no '.' separator found");
	config_append_error_line();
	return -1;
    }
    
    /* Change the dot for a zero, to split the strings. */
    *dot_pos = 0;
    *sec = nm;
    *val = dot_pos + 1;
    
    return 0;
}

static void config_push_expectation_error(const char *txt) {
    const char *expect_name = "section.name";
    const char *expect_eq   = "\"=\"";
    const char *expect_val  = "\"value\"";
    const char *expect_end  = ";";
    const char *v = "";

    switch (lexer_state) {
    case LEXER_EXPECTS_NAME:  v = expect_name;
    case LEXER_EXPECTS_EQUAL: v = expect_eq;
    case LEXER_EXPECTS_VALUE: v = expect_val;
    case LEXER_EXPECTS_END:   v = expect_end;
    }

    KERROR_SET(_config_, 1, "%s was expected but %s was found", v, txt);
    config_append_error_line();
}

/** Checks if a configuration item is set.
 *
 * This function should be used to protect caller code against empty
 * or absent configuration entries.  It can be called to check if a
 * value should be validated or not, but where the absence of the
 * value is considered not to be an error. 
 *
 * @returns 1 of the variable has a value, 0 otherwise.
 */
int config_has_value(config *self, const char *fullname) {
    char *txt, *sec, *name, *val;
    apr_hash_t *name_hash;

    txt = alloca(strlen(fullname) + 1);
    strcpy(txt, fullname);
    
    if (config_splitname(txt, &sec, &name)) return 0;

    /* Fetch the right section. */
    name_hash = apr_hash_get(self->sections, sec, APR_HASH_KEY_STRING);
    if (name_hash == NULL) 
    	return 0;
    
    val = apr_hash_get(name_hash, name, APR_HASH_KEY_STRING);
    return !(val == NULL || strlen(val) == 0);
}

/** Sets a value for a configuration string.
 *
 * This does not change the value in the file.  We expect val to be a
 * correct null-terminated string.
 */
int config_set_str(config *self, const char *fullname, const char *val) {
    char *txt, *sec, *name, *newval;
    apr_hash_t *name_hash;

    txt = apr_pstrdup(self->config_pool, fullname);
    if (config_splitname(txt, &sec, &name)) {
        KERROR_SET(_config_, 1, "cannot set config value %s", fullname);
	return -1;
    }

    /* Fetch the right section. */
    name_hash = apr_hash_get(self->sections, sec, APR_HASH_KEY_STRING);
    if (name_hash == NULL) {
        name_hash = apr_hash_make(self->config_pool);
        apr_hash_set(self->sections, sec, APR_HASH_KEY_STRING, name_hash);
    }

    newval = apr_pstrdup(self->config_pool, val);
    apr_hash_set(name_hash, name, APR_HASH_KEY_STRING, newval);
    
    return 0;
}

/** Returns a configuration item as a string.
 *
 * This function will clear the content of val before writing in it,
 * thus making sure that an error will not make the caller use garbage
 * as a value.
 *
 * @returns 0 in case the item is absent, and 1 otherwise.
 */
int config_get_str(config *self, const char *fullname, char *out, size_t out_s) {
    char *txt, *sec, *name, *val;
    apr_hash_t *name_hash;

    memset(out, 0, out_s);
    txt = alloca(strlen(fullname) + 1);
    strcpy(txt, fullname);
    
    /* This error will be ignored. */
    if (config_splitname(txt, &sec, &name)) return 0;

    /* Find the section containing the value. */
    name_hash = apr_hash_get(self->sections, sec, APR_HASH_KEY_STRING);
    if (name_hash == NULL) return 0;
   
    /* Then find the value in the name hash for the section. */
    val = (char *)apr_hash_get(name_hash, name, APR_HASH_KEY_STRING);
    if (val == NULL) return 0;

    /* Empty value means returning 0. */
    if (strcmp(val, "") == 0) return 0;

    strncpy(out, val, out_s);
    out[out_s - 1] = 0;

    return 1;
}

/** Returns a configuration item as an 32 bit unsigned integer.
 *
 * @returns -1 in case of error, 0 in case the item is absent, and 1
 * otherwise.
 */
int config_get_uint32(config *self, const char *name, uint32_t *out) {
    char * p;
    char buffer[sizeof(APR_STRINGIFY(UINT_MAX)) + 1];
	
    if ((config_get_str(self, name, buffer, sizeof(buffer))) == 0)
        return 0;

    *out = strtoul(buffer, &p, 10);

    if (*p != '\0') {
        KERROR_SET(_config_, 1, "unable to convert %s to unsigned integer", buffer);
        return -1;
    }

    return 1;
}

/** Returns a configuration item as a 64 bit unsigned integer.
 *
 * @returns -1 in case of error, 0 in case the item is absent, and 1
 * otherwise.
 */
int config_get_uint64(config *self, const char *name, uint64_t *out) {
    char *p;
    char buffer[sizeof(APR_STRINGIFY(ULLONG_MAX)) + 1];
    
    if ((config_get_str(self, name, buffer, sizeof(buffer))) == 0)
        return 0;

    *out = strtoull(buffer, &p, 10);

    if (*p != '\0') {
        KERROR_SET(_config_, 1, "unable to convert %s to long unsigned integer", buffer);
        return -1;
    }
    
    return 1;
}

/** Returns a configuration item as an floating point number. 
 *
 * @returns -1 in case of error, 0 in case the item is absent, and 1
 * otherwise.
 */
int config_get_float(config *self, const char *name, float *out) {
    char * p;
    /* FLT_MAX is not really useful there, but * 3 should give it
       enough space. */
    char buffer[sizeof(APR_STRINGIFY(FLT_MAX)) * 3];

    if ((config_get_str(self, name, buffer, sizeof(buffer))) == -1)
        return -1;

    *out = strtof(buffer, &p);
	
    if (*p != '\0') {
        KERROR_SET(_config_, 1, "unable to convert %s to float", buffer);
        *out = 0.0f;
        return -1;
    }

    return 1;
}

/** Loads the configuration file. */
int config_load(config *self, apr_pool_t *pool) {
    int err = -1;
    char *current_dir, *config_dir;
    apr_pool_t *p;

    /* Get directory of the configuration file. */
    apr_pool_create(&p, pool);
    config_dir = apr_pstrdup(p, self->config_file);
    config_dir = dirname(config_dir);
    apr_filepath_get(&current_dir, 0, p);

    do {
        if ((yyin = fopen(self->config_file, "r")) == NULL) {
            KERROR_SET(_config_, 1, "cannot open %s", self->config_file);
            break;
        }

        /* Move to the directory containing the configuration file. */
        apr_filepath_set(config_dir, p);

        yypush_buffer_state(yy_create_buffer(yyin, YY_BUF_SIZE));
        memset(&curr_value, 0, sizeof(curr_value));
        lexer_state = LEXER_EXPECTS_NAME;
	scan_pool = p;
	scan_file = self->config_file;
	scan_line = 1;
	scan_error = 0;
	scan_file_stack = apr_array_make(p, 0, sizeof(char *));
	scan_line_stack = apr_array_make(p, 0, sizeof(int));
        lex_self = self;
        yylex();
        lex_self = NULL;
	
	if (scan_error) break;

        err = 0;
    } while (0);

    /* Back to the main directory. */
    apr_filepath_set(current_dir, p);
    apr_pool_destroy(p);
    
    return err;
}

/** Reopens a configuration file.
 *
 * This function keeps the instance of the configuration object but
 * rereads the whole file it was pointing to.
 */
int config_reopen(config *self, apr_pool_t *pool) {
    apr_pool_t *cfg_pool;
    char *cf;
        
    /* Keep the config file name. */
    apr_pool_create(&cfg_pool, pool);
    apr_pool_tag(cfg_pool, "config");
    cf = apr_pstrdup(cfg_pool, self->config_file);

    /* Destroy and recreate the pool and value hashes. */
    apr_pool_destroy(self->config_pool);
    
    self = apr_pcalloc(cfg_pool, sizeof(config));
    self->config_file = cf;
    self->config_pool = cfg_pool;
    self->sections = apr_hash_make(self->config_pool);

    return config_load(self, cfg_pool);
}

/** Opens a configuration file.
 *
 * This function creates a single config_object in the program.  There
 * is always only one instance of config_object in memory.
 */
config *config_open(apr_pool_t *pool, const char *config_file) {
    apr_pool_t *cfg_pool;
    config *self;

    apr_pool_create(&cfg_pool, pool);
    apr_pool_tag(cfg_pool, "config");

    /* First time configuration of the object. */
    self = apr_pcalloc(cfg_pool, sizeof(config));

    self->config_pool = cfg_pool;
    self->sections = apr_hash_make(self->config_pool);
    self->config_file = apr_pstrdup(self->config_pool, config_file);
    
    if (config_load(self, cfg_pool) < 0)
        return NULL;
    else
        return self;
}
