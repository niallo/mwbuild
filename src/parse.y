/*-
 * Copyright (c) 2008-2009 Metaweb Technologies, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Metaweb Technologies nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDES AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

%{

#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "cl.h"

#define MW_MIN(a,b) (((a) < (b)) ? (a) : (b))

/* input buffer */
static char *in = NULL;
/* persistent parse pointer */
static char *parseptr = NULL;
/* most recent section title encountered */
static char *title = NULL;
/* the list to use for configuration */
static struct mw_conf_head *root;

static void mw_skip_to_newline(char **);
static void mw_skip_whitespace(char **);
static char *mw_next_id(char **);
static char *mw_quoted_string(char **);
static int  mw_is_delim(int);
static int lineno = 1;
static char *filename = NULL;
static char *lineptr = NULL;
static int  is_mw_get = 0;

int yyparse(void);
int yyerror(const char *, ...);

/* At parse time, ignore machine nodes which do not match this host. */
static void
mw_try_insert_node(struct mw_conf_head *r, struct conf_node *n)
{
	struct conf_list_entry *new;

	/* this is a machine node, and its hostname matches */
	if (n->title != NULL
	    && strncmp(n->title, "machine", strlen("machine")) == 0
	    && mw_node_hostname_match(n) == 0) {
	
		if (is_mw_get == 1) {
			new = mw_conf_list_entry_create(n);
			TAILQ_INSERT_TAIL(r, new, conf_node_list);
		} else {
			mw_insert_conflist(r, n, n->title);
		}
	}
	/* this is not a machine node - just insert it */
	if (n->title == NULL
	    || strncmp(n->title, "machine", strlen("machine")) != 0) {
		if (is_mw_get == 1) {
			new = mw_conf_list_entry_create(n);
			TAILQ_INSERT_TAIL(r, new, conf_node_list);
		} else {
			mw_insert_conflist(r, n, n->title);
		}
	}
}

%}

%union {
	char		*string;
	struct conf_node *conf_node;
}


%token			START_SECTION
%token			END_SECTION
%token			EQUALS
%token	<string>	ID
%token	<string>	QUOTED_STRING
%token			NEWLINE

%type   <conf_node>     assignment
%type   <conf_node>	section_title
%type   <string>	rval

%start configuration

%%

configuration	: /* empty */
		| configuration line
		;

line		: NEWLINE {
			lineno++;
			lineptr = parseptr;
		}
		| assignment NEWLINE {
			mw_try_insert_node(root, $1);
			lineno++;
			lineptr = parseptr;
		}
		| section_title NEWLINE {
			mw_try_insert_node(root, $1);
			lineno++;
			lineptr = parseptr;
		}
		;

assignment	: ID EQUALS rval {
			struct conf_node *node;

			node = xmalloc(sizeof(*node));
			memset(node, 0, sizeof(*node));
			node->key = $1;
			node->value = $3;
			if (title != NULL)
				node->title = xstrdup(title);

			$$ = node;
		}
		;

section_title	: START_SECTION ID END_SECTION {
			struct conf_node *node;

			/* free the old title */
			if (title != NULL) {
				free(title);
				title = NULL;
			}
			title = $2;
			node = xmalloc(sizeof(*node));
			memset(node, 0, sizeof(*node));
			node->title = xstrdup(title);

			$$ = node;
		}
		;

rval		: QUOTED_STRING {
			$$ = $1;
		}
		;

%%

int
yylex(void)
{
	int c;

	for (;;) {
		/* advance character, skipping whitespace if there is any */
		mw_skip_whitespace(&parseptr);
		c = *parseptr;

		/* check for end of input */
		if (c == '\0') {
			return (0);
		}

		switch (c) {
		/* comment handling */
		case ';':
			mw_skip_to_newline(&parseptr);
			continue;
		/* assignment handling */
		case '=':
			parseptr++;
			return (EQUALS);
		/* section title handling */
		case '[':
			parseptr++;
			return (START_SECTION);
		case ']':
			parseptr++;
			return (END_SECTION);
		/* quotes */
		case '"':
			yylval.string = mw_quoted_string(&parseptr);
			if (yylval.string == NULL) {
				yyerror("invalid quoted string");
				exit(1);
				return (0);
			}
			return (QUOTED_STRING);
		/* INI files are newline-terminated */
		case '\n':
			parseptr++;
			return (NEWLINE);
		/* ID handling */
		default:
			if (isalpha(*parseptr) != 0) {
				yylval.string = mw_next_id(&parseptr);
				return (ID);
			}
			yyerror("ID begins with invalid character");
			exit(1);
			return (0);
		}
	}

	return (0);
}

static int
mw_is_delim(int c)
{
	if (c != '['
	    && c != ']'
	    && c != '='
	    && c != '"'
	    && c != ' '
	    && c != '\t'
	    && c != '\n')
		return (1);

	return (0);

}

/* short utility function to advance pointer to next newline or NUL character */
static void
mw_skip_to_newline(char **p)
{
	for (;**p != '\n' && **p != '\0';(*p)++)
		;	/* nothing */
}

/* advances input pointer over leading whitespace */
static void
mw_skip_whitespace(char **p)
{
	for (;**p != '\0' && isblank(**p) != 0; (*p)++)
		;	/* nothing */
}

/* utility function to keep reading an ID until the next special character */
static char *
mw_next_id(char **p)
{
	char *buf, *c;
	size_t len;

	/* advance pointer until we reach something delimiting an ID */
	for (c = *p; mw_is_delim(*c) != 0 ; c++)
		;	/* nothing */

	/* add 1 for NUL-terminator */
	len = c - *p + 1;
	if (len > CONF_BUFFER_SIZE) {
		fprintf(stderr, "id exceeds CONF_BUFFER_SIZE\n");
		exit(1);
	}
	buf = xmalloc(CONF_BUFFER_SIZE);
	memset(buf, '\0', CONF_BUFFER_SIZE);

	strlcpy(buf, *p, len);

	/* advance our input pointer the requisite amount */
	*p += c - *p;
	return (buf);
}

/* like mw_next_id() but only stops at a " character not preceeded by a \ */
static char *
mw_quoted_string(char **p)
{
	char *buf, *c;
	size_t len;

	/* advance pointer until we reach something delimiting an ID */
	for (c = *p; ; c++) {
		/* first char must be a quote */
		if (c == *p && *c != '"')
			return (NULL);
		/* stop if char is NUL or an un-escaped quote */
		if ((c > *p && *c == '"' && *(c - 1) != '\\')
		    || *c == '\0')
			break;
	}

	len = c - *p;
	if (len > CONF_BUFFER_SIZE) {
		fprintf(stderr, "quoted string exceeds CONF_BUFFER_SIZE\n");
		exit(1);
	}
	buf = xmalloc(CONF_BUFFER_SIZE);
	memset(buf, '\0', CONF_BUFFER_SIZE);

	/* add 1 so we don't include the first quote in our copy */
	strlcpy(buf, *p+1, len);

	/* advance our input pointer the requisite amount - add 1 to move it
	   over the ending quote */
	*p = c + 1;
	return (buf);
}

int
yyerror(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	if (lineptr != NULL) {
		lineptr[strcspn(lineptr, "\n")] = '\0';
		fprintf(stderr, " `%s' (file: %s line: %d)\n",
		    lineptr, filename, lineno);
	} else {
		parseptr[strcspn(parseptr, "\n")] = '\0';
		fprintf(stderr, " `%s' (file: %s line: %d)\n",
		    parseptr, filename, 1);
	}
	va_end(ap);

	exit(1);
}

int
mw_parse_config(struct mw_conf_head *head, struct mw_config_data *config_data, int isget)
{
	in = config_data->data;
	parseptr = in;
	lineptr = NULL;
	root = head;
	title = NULL;
	lineno = 1;
	filename = config_data->filename;
	is_mw_get = isget;

	/* last character before EOF must be newline */
	if (config_data->data[strlen(config_data->data) - 1] != '\n')
		errx(1, "could not parse configuration file, missing newline before end-of-file");

	return (yyparse());
}
