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

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libgen.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "svn_pools.h"
#include "cl.h"

static char *mw_get_expandable(const char *, size_t *);
static int mw_canexpand_node(struct mw_conf_head *, struct conf_node *);
static void mw_preexpand_node(struct conf_node *);
static void mw_expand_node(struct mw_conf_head *, struct conf_node *);
static int  mw_find_and_expand(struct mw_conf_head *,
			       const char *,
			       char *,
			       size_t,
			       struct conf_node *);

static int mw_node_match_prefix(const struct conf_node *,
				const char *,
				const char *);

static int mw_title_suffix_match(const char *, const char *);
static char *mw_get_project_title(const char *);
static char *mw_get_project_shortname(const char *);

static struct conf_list_entry *mw_get_machine_node(struct mw_conf_head *);
static void mw_config_add_default(struct mw_conf_head *, char *, const char *);
static char *mw_realpath(const char *);
static void mw_overwrite_conflist(struct mw_conf_head *, struct conf_node *);

extern char *pretendhostname;

/*
 * mw_get_hostname()
 *
 * Return FQDN.  Static buffer - no need to free.
 */
char *
mw_get_hostname(void)
{
	struct addrinfo hints, *res;
	static char *hbuf = NULL;
	char myhostname[MAXHOSTNAMELEN];
	int error;
	/* hack to allow setting the hostname on command line */
	if (pretendhostname != NULL)
		return (pretendhostname);

	if (hbuf != NULL)
		return (hbuf);
	if (gethostname(myhostname, sizeof(myhostname)) == -1) {
		fprintf(stderr, "mw_get_hostname: gethostname failure\n");
		exit(1);
	}
	/* if the result of gethostname() contains a dot (.) use that,
	since its likely the FQDN */
	if (strchr(myhostname, '.') != NULL) {
		hbuf = strdup(myhostname);
		return (hbuf);
	}
	hbuf = xmalloc(NI_MAXHOST);
	memset(hbuf, '\0', NI_MAXHOST);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(myhostname, NULL, &hints, &res);
	if (error == -1) {
		fprintf(stderr, "mw_get_hostname:  %s\n", gai_strerror(error));
		exit(1);
	}
	/* This sometimes takes forever.  Can we avoid it sometimes?
	 * (E.g., if gethostname() returns a name with '.' somewhere, does
	 * that suffice? */
	if (getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, NI_MAXHOST, NULL,
		NI_MAXSERV, NI_NAMEREQD)) {
		/* could not get FQDN, so we just return the result of
		 * gethostname() */
		(void) strlcpy(hbuf, myhostname, NI_MAXHOST);
	}
	freeaddrinfo(res);

	return (hbuf);
}

/*
 * mw_svn_get()
 *
 * Return the contents of the head of the file at subversion location
 * <url>.  On failure return NULL.
 */
char *
mw_svn_get(const char *url, void *baton, apr_pool_t *pool)
{
	svn_client_ctx_t *ctx = ((svn_cl__cmd_baton_t *) baton)->ctx;
	svn_stream_t *out;
	apr_pool_t *subpool = svn_pool_create(pool);
	svn_stringbuf_t *string;
	svn_error_t *err = NULL;
	svn_opt_revision_t rev;
	char *res;

	string = svn_stringbuf_create("", pool);
	out = svn_stream_from_stringbuf(string, pool);

	/* For now, we always want the HEAD revision, but in future we
	 * may want to support specifying a revision here.*/
	rev.kind = svn_opt_revision_head;

	svn_pool_clear(subpool);

	err = svn_client_cat(out, url, &rev, ctx, subpool);

	if (err != NULL) {
		svn_pool_destroy(subpool);
		svn_stream_close(out);
		return (NULL);
	}

	res = xstrdup(string->data);

	svn_pool_destroy(subpool);
	svn_stream_close(out);

	return (res);
}

/*
 * mw_try_file_read()
 *
 * Try to read the file in <path>.
 * If the file doesn't exist, or there is
 * an error reading, return NULL.
 */
char *
mw_try_file_read(const char *path)
{
	FILE *fp;
	struct stat sb;
	size_t buflen;
	char *buf;
	int fd;

	if ((fd = open(path, O_RDONLY)) == -1) {
		return (NULL);
	}

	if (fstat(fd, &sb) == -1) {
		(void) close(fd);
		return (NULL);
	}

	/* extra byte for NUL-termination */
	buflen = sb.st_size + 1;

	if ((fp = fdopen(fd, "r")) == NULL) {
		(void) close(fd);
		return (NULL);
	}

	buf = xmalloc(buflen);
	memset(buf, '\0', buflen);

	fread(buf, 1, sb.st_size, fp);

	if (ferror(fp) != 0) {
		fprintf(stderr, "error reading file\n");
		exit(1);
	}

	fclose(fp);

	return (buf);
}

/*
 * mw_get_config()
 *
 * Read the configuration file and return it as a char buffer.
 */
struct mw_config_data *
mw_get_config(int action, void *baton, apr_pool_t *pool)
{
	struct mw_config_data *config_data;
	char *config, path[MAXPATHLEN];
	char *myhomedir, *myhostname, *mydomain;
	svn_cl__opt_state_t *opt_state = ((svn_cl__cmd_baton_t *) baton)->opt_state;

	/* If there's a command line specification, use that and ignore
	 * all of the default paths. */
	if (opt_state->config_file != NULL) {
		config = mw_try_file_read(opt_state->config_file);
		if (config != NULL) {
			printf("Reading config from `%s'\n",
			       opt_state->config_file);
			config_data = xmalloc(sizeof(*config_data));
			config_data->filename = opt_state->config_file;
			config_data->data = config;
			return (config_data);
		} else  {
			fprintf(stderr, "Can't read config file `%s'\n",
				opt_state->config_file);
			return (NULL);
		}
	}

	/* Try machine.mw4 from local directory */
	if ((config = mw_try_file_read("machine.mw4")) != NULL) {
		if (opt_state->verbose)
			printf("Reading config from machine.mw4\n");
		config_data = xmalloc(sizeof(*config_data));
		config_data->filename = xstrdup("machine.mw4");
		config_data->data = config;
		return (config_data);
	}

	/* Try mwbuild.conf from local directory */
	if ((config = mw_try_file_read("mwbuild.conf")) != NULL) {
		if (opt_state->verbose)
			printf("Reading config from mwbuild.conf\n");
		config_data = xmalloc(sizeof(*config_data));
		config_data->filename = xstrdup("mwbuild.conf");
		config_data->data = config;
		return (config_data);
	}

	/* Try cached mwbuild config in $HOME */
	if (action != MW_GET_ACTION && (myhomedir = getenv("HOME")) != NULL) {
		xsnprintf(path, sizeof(path), "%s/.mw/cache.mw4", myhomedir);
		config = mw_try_file_read(path);
		if (config != NULL) {
			printf("Reading config from locally-cached copy `%s'\n",
			    path);
			config_data = xmalloc(sizeof(*config_data));
			config_data->filename = xstrdup(path);
			config_data->data = config;
			return (config_data);
		}
	}

	/* Try project.mw4 from local directory if action is not GET */
	if (action != MW_GET_ACTION
	    && (config = mw_try_file_read("project.mw4")) != NULL) {
		char *p, *q, *newconf, *cwd, *local = NULL;
		size_t len = 0, buflen = 0;
#define SYNTHETIC_CONFIG_LEN 1024
		if (opt_state->verbose)
		  printf("Synthesizing machine config from project.mw4\n");

		/* Find the name of the first project;
		 * return prematurely if we can't find a name
		 * or find one that's ridiculously long. */
		p = strstr(config,"[project:");
		if (p == NULL) {
			free(config);
			fprintf(stderr,
			    "No [project:<projectname>] section found in project.mw4\nDo you need to add one?\n");
			return (NULL);
		}
		p += strlen("[project:");
		q = strchr(p, ']');
		if (q == NULL || q - p > 100) {
			free(config);
			return (NULL);
		}
		/* Check for a local.mw4 */
		if ((local = mw_try_file_read("local.mw4")) != NULL) {
			len = strlen(local);
			buflen = len + SYNTHETIC_CONFIG_LEN;
		} else {
			buflen = SYNTHETIC_CONFIG_LEN;
		}

		/* Synthesize a machine.mw4 and return it. */
		newconf = xmalloc(buflen);
		memset(newconf, '\0', buflen);
		cwd = getcwd(NULL, 256);
		xsnprintf(newconf, buflen,
			  "MWBUILD_ROOT=\"%s\"\n"
			  "MWBUILD_APPROOT=\"%s\"\n"
			  "PROJECT_APPDIR=\"%s\"\n"
			  "%s\n"
			  "[machine:*]\n"
			  "PROJECTS=\"",
			  cwd, cwd, cwd, (local != NULL ? local : ""));
		/* XXX TODO: Append all projects to the PROJECTS var. XXX */
		strncat(newconf, p, q - p);
		strlcat(newconf, "\"\n", buflen);
		/* Clean up and return the new configuration. */
		if (local != NULL)
			free(local);
		free(config);
		config_data = xmalloc(sizeof(*config_data));
		config_data->filename = xstrdup("project.mw4");
		config_data->data = newconf;
		return (config_data);
	}

	/* Look for machine configuration in SVN. */
	myhostname = mw_get_hostname();
	xsnprintf(path, sizeof(path), "%s/%s", SVN_SETTINGS_ROOT, myhostname);
	if ((config = mw_svn_get(path, baton, pool)) != NULL) {
		printf("Reading machine config from SVN %s\n", path);
		/* Cache the configuration on local dist on GET */
		mw_write_config_cache(config);
		config_data = xmalloc(sizeof(*config_data));
		config_data->filename = xstrdup(path);
		config_data->data = config;
		return (config_data);
	}

	/* Strip leading host name and try for a cluster configuration. */
	mydomain = strchr(myhostname, '.');
	if (mydomain != NULL) {
		xsnprintf(path, sizeof(path), "%s/%s",
			  SVN_SETTINGS_ROOT, mydomain + 1);
		if ((config = mw_svn_get(path, baton, pool)) != NULL) {
			printf("Reading cluster config from SVN %s\n", path);
			/* Cache the configuration on local dist on GET */
			mw_write_config_cache(config);
			config_data = xmalloc(sizeof(*config_data));
			config_data->filename = xstrdup(path);
			config_data->data = config;
			return (config_data);
		}
	}

	return (NULL);

}

/*
 * mw_mkpath()
 *
 * Like `mkdir -p`.
 */
int
mw_mkpath(const char *s)
{
	char *q, *t, *path = NULL, *up = NULL;
	int rv;

	rv = -1;
	if (strcmp(s, ".") == 0 || strcmp(s, "/") == 0)
		return 0;

	path = xstrdup(s);
	t = xstrdup(s);
	if ((q = dirname(t)) == NULL)
		goto out;
	up = xstrdup(q);

	if ((mw_mkpath(up) == -1) && (errno != EEXIST))
		goto out;

	if ((mkdir(path, 0755) == -1) && (errno != EEXIST)) {
		rv = -1;
	} else {
		rv = 0;
	}

out:
	if (up != NULL)
		free(up);
	free(path);
	free(t);
	return (rv);
}

/*
 * mw_get_base_dir()
 *
 * Returns a string with absolute path to BASEDIR, which for now is $HOME/mw.
 * If BASEDIR does not exist, we create it.
 */
char *
mw_get_base_dir(struct mw_conf_head *root)
{
	char  *home, *mwbuildroot;

	if ((mwbuildroot = mw_get_config_var(root, "MWBUILD_ROOT")) == NULL) {
		mwbuildroot = xmalloc(MAXPATHLEN);
		memset(mwbuildroot, '\0', MAXPATHLEN);
		/* $HOME/mw is the default */
		if ((home = getenv("HOME")) == NULL) {
			fprintf(stderr, "could not find value of $HOME\n");
			exit(1);
		}
		xsnprintf(mwbuildroot, MAXPATHLEN, "%s/mw", home);
	}
	mw_mkpath(mwbuildroot);
	return (mwbuildroot);
}

/*
 * mw_get_project_config()
 *
 * For project <projname>, return the contents of its project.mw4 file.  This
 * file is expected to be located at: ${PROJECT_APPDIR}/project.mw4
 */
struct mw_config_data *
mw_get_project_config(struct mw_conf_head *root, const char *projname)
{
	struct mw_config_data *config_data = NULL;
	char *config, *mwappdir, config_path[MAXPATHLEN];

	mwappdir = mw_get_config_var(root, PROJECT_APPDIR);

	xsnprintf(config_path, sizeof(config_path), "%s/project.mw4", mwappdir);
	if ((config = mw_try_file_read(config_path)) != NULL) {
		config_data = xmalloc(sizeof(*config_data));
		config_data->data = config;
		config_data->filename = xstrdup(config_path);
		return (config_data);
	}

	fprintf(stderr,
	    "Configuration file not found: %s\n"
	    "Maybe you need to run `mw get'?  Alternatively this project may not yet have mwbuild4 support.\n",
	    config_path);
	exit(1);
}

/*
 * Configuration expansion functions
 */

/*
 * mw_get_expandable()
 *
 * Return the next expandable in the string, and set
 * its length in the size_t supplied.
 */
static char *
mw_get_expandable(const char *s, size_t *len)
{
	const char *p = NULL;
	char *start = NULL;
	int expstate = 0, found_expandable = 0;

	*len = 0;
	for (p = s; *p != '\0'; p++) {
		/* Is this an escaped expansion? */
		if (expstate == 0
		    && *p == '\\'
		    && *(p+1) == '$'
		    && *(p+2) == '{') {
			p++;
			continue;
		}
		if (expstate == 0 && *p == '$' && *(p+1) == '{') {
			start = p+2;
			expstate = 1; /* in the expansion */
			p++;
			continue;
		}
		if (expstate == 1) {
			(*len)++;
			if (*p == '}') {
				found_expandable = 1;
				break;
			}
		}
	}
	if (found_expandable != 1 || *len == 0)
		return (NULL);

	return (start);
}

/*
 * mw_preexpand_node()
 */
static void
mw_preexpand_node(struct conf_node *node)
{
	size_t len;

	/* this node has no expandables, so mark it as expanded */
	if (mw_get_expandable(node->value, &len) == NULL)
		node->is_expanded = 1;
}

/*
 * mw_canexpand_node()
 *
 * Are all the dependencies in this node already expanded ?
 */
static int
mw_canexpand_node(struct mw_conf_head *root, struct conf_node *node) {
	struct conf_list_entry *tnode;
	const char *ptr;
	char *mwexp, buf[CONF_BUFFER_SIZE];
	size_t len = 0;

	for (ptr = node->value;
	    (mwexp = mw_get_expandable(ptr, &len)) != NULL; ptr = mwexp) {
		if (len > CONF_BUFFER_SIZE){
			fprintf(stderr,
			    "mw_canexpand_node: buffer overflow detected\n");
		}
		(void) strlcpy(buf, mwexp, len);
		TAILQ_FOREACH(tnode, root, conf_node_list) {
			/* section title nodes have no key nor value */
			if (tnode->conf->key == NULL
			    && tnode->conf->value == NULL)
				continue;
			if (strlen(tnode->conf->key) > sizeof(buf)) {
				fprintf(stderr,
				    "mw_canexpand_node: "
				    "buffer overflow detected\n");
				exit(1);
			}
			/* found the key which matches this expandable */
			if (strcmp(tnode->conf->key, buf) == 0) {
				/* is the node which this depends on already
				 * expanded? */
				if (tnode->conf->is_expanded == 0)
					return (0);
			}
		}
	}

	return (1);
}

/*
 * mw_find_and_expand()
 *
 * The nuts and bolts of variable expansion.
 */
static int
mw_find_and_expand(struct mw_conf_head *root,
		   const char *buf,
		   char *mwexp,
		   size_t len,
		   struct conf_node *n)
{
#define OVERFLOW_MESSAGE "buffer overflow detected"
	struct conf_list_entry *tnode;
	char tbuf[CONF_BUFFER_SIZE];
	size_t tbuflen, oldlen = 0;
	int found = 0;

	TAILQ_FOREACH_REVERSE(tnode, root, mw_conf_head, conf_node_list) {
		/* section title nodes have no key nor value */
		if (tnode->conf->key == NULL && tnode->conf->value == NULL)
			continue;
		/* found the key which matches this expandable */
		if (strcmp(tnode->conf->key, buf) == 0) {
			if (tnode->conf->is_expanded == 0)
				return (0);
			if (strcmp(tnode->conf->key, "PROJECT_APPDIR") == 0) {
				char *newval, *rpath;
				size_t slen;

				rpath = mw_realpath(tnode->conf->value);
				newval = xmalloc(CONF_BUFFER_SIZE);
				slen = strlcpy(newval, rpath, CONF_BUFFER_SIZE);
				if (slen >= CONF_BUFFER_SIZE) {
					fprintf(stderr,
					    "mw_process_project_settings(): "
					    "string truncation in realpath\n");
					exit(1);
				}
				free(tnode->conf->value);
				tnode->conf->value = newval;
			}
			/* save the contents of the string
			 * following the expandable into a
			 * temporary buffer */
			memset(tbuf, '\0', sizeof(tbuf));
			tbuflen = strlen(mwexp + len);
			if (tbuflen > CONF_BUFFER_SIZE) {
				fprintf(stderr, "mw_expand_node: %s\n",
				    OVERFLOW_MESSAGE);
				exit(1);
			}
			if (tbuflen > 0)
				memcpy(tbuf, mwexp + len, tbuflen);
			/* do the expansion */
			memcpy(mwexp - 2, tnode->conf->value,
			    strlen(tnode->conf->value));
			/* load the old contents of the string
			 * following the expandable from the
			 * temporary buffer */
			if (tbuflen > 0)
				memcpy(mwexp + strlen(tnode->conf->value) - 2,
				    tbuf, tbuflen);
			mwexp[strlen(tnode->conf->value) + tbuflen - 2] = '\0';
			oldlen += len;
			found = 1;
			break;
		}
	}
	if (!found) {
		fprintf(stderr,
		    "mw_expand_node: cannot find value for expandable '%s'\n",
		    buf);
		exit(1);
	}
	return (0);
}

/*
 * mw_expand_node()
 *
 * Expand a given node.
 */
static void
mw_expand_node(struct mw_conf_head *root, struct conf_node *node)
{
	const char *ptr;
	char *mwexp, buf[CONF_BUFFER_SIZE];
	size_t len = 0;


	mwexp = NULL;
	/* section title nodes have no key nor value */
	if (node->key == NULL && node->value == NULL)
		return;
	if (!mw_canexpand_node(root, node)) {
		return;
	}
	for (ptr = node->value;
	     (mwexp = mw_get_expandable(ptr, &len)) != NULL; ptr = mwexp) {
		if (len + 1 > sizeof(buf)) {
			fprintf(stderr,
			    "mw_expand_node: %s\n", OVERFLOW_MESSAGE);
			exit(1);
		}
		(void) strlcpy(buf, mwexp, len);
		mw_find_and_expand(root, buf, mwexp, len, node);
	}
	node->is_expanded = 1;
}

/*
 * mw_do_expansion()
 *
 * Expand all the variables in the supplied list.
 */
void
mw_do_expansion(struct mw_conf_head *root)
{
	struct conf_list_entry *node;
	size_t node_count = 0, expanded_count = 0, old_expanded_count = 0;

	/* mark all nodes with no expandables as expanded in a single pass */
	TAILQ_FOREACH(node, root, conf_node_list) {
		/* section title nodes have no key nor value */
		if (node->conf->key == NULL && node->conf->value == NULL)
			continue;
		node_count++;
		mw_preexpand_node(node->conf);
		if (node->conf->is_expanded == 1)
			expanded_count++;
	}
	for (;;) {
		expanded_count = 0;
		/* now actually expand each node */
		TAILQ_FOREACH(node, root, conf_node_list) {
			/* section title nodes have no key nor value */
			if (node->conf->key == NULL
			    && node->conf->value == NULL)
				continue;
			if (node->conf->is_expanded == 1) {
				expanded_count++;
				continue;
			}
			mw_expand_node(root, node->conf);
			if (node->conf->is_expanded == 1)
				expanded_count++;
		}
		/* no more progress, we must be done */
		if (expanded_count == old_expanded_count)
			break;
		old_expanded_count = expanded_count;
	}
	/* if the expanded count is less than node count, then we have a
	 * cycle somewhere */
	if (node_count > expanded_count) {
		fprintf(stderr,
		    "ERROR: Could not expand the following values "
		    "- cycle found:\n");
		/* print the nodes which could not be expanded */
		TAILQ_FOREACH(node, root, conf_node_list) {
			/* section title nodes have no key nor value */
			if (node->conf->key == NULL && node->conf->value == NULL)
				continue;
			if (node->conf->is_expanded == 0)
				fprintf(stderr,
				    "%s=\"%s\"\n",
				    node->conf->key, node->conf->value);
		}
		exit(1);
	}

}

/* Convenience wrapper around malloc() for added safety */
void *
xmalloc(size_t len)
{
	void *buf;
	if ((buf = malloc(len)) == NULL) {
		fprintf(stderr, "malloc failure\n");
		exit(1);
	}
	return (buf);
}

/*
 * mw_conf_list_entry_create()
 *
 * Create a list entry pointing to conf_node <conf>.
 */
struct conf_list_entry *
mw_conf_list_entry_create(struct conf_node *conf)
{
	struct conf_list_entry *cle;

	cle = xmalloc(sizeof(*cle));
	memset(cle, 0, sizeof(*cle));
	cle->conf = conf;

	return (cle);
}


/*
 * mw_node_match_prefix()
 *
 * Returns 0 if specified node is the matching variable and title prefix, or
 * non-zero on failure.  If <key> is NULL, we return success on any key
 * within the specified section.  If <exact> is non-zero, we look for an
 * exact match in title.
 */
static int
mw_node_match_prefix(const struct conf_node *node,
		     const char *title_prefix,
		     const char *key)
{

	char *cpos, prefix[128], *s;

	if (node->title == NULL)
		return (1);

	xsnprintf(prefix, sizeof(prefix), "%s:", title_prefix);
	if ((s = strstr(node->title, prefix)) == NULL)
		return (1);

	/* string must begin with title prefix */
	if (s != node->title)
		return (1);

	/* string following title prefix must be at least 1 byte long */
	cpos = strchr(node->title, ':');
	if (strlen(cpos) < 2)
		return (1);

	/* if key is NULL, match any key in the right section */
	if (key != NULL) {
		return (strcmp(node->key, key));
	} else {
		return (0);
	}

}

/*
 * mw_free_conflist()
 *
 * Convenience function to clear the temporary config list.  If <flags> is
 * non-zero, also free the attached conf_node struct.
 */
void
mw_free_conflist(struct mw_conf_head *myconf, int flags)
{
	struct conf_list_entry *var, *nxt;

	for (var = TAILQ_FIRST(myconf); var != TAILQ_END(myconf); var = nxt) {
		nxt = TAILQ_NEXT(var, conf_node_list);
		TAILQ_REMOVE(myconf, var, conf_node_list);
		if (flags && var->conf != NULL) {
			if (var->conf->value != NULL) {
				free(var->conf->value);
				var->conf->value = NULL;
			}
			if (var->conf->key != NULL) {
				free(var->conf->key);
				var->conf->key = NULL;
			}
			if (var->conf->title != NULL) {
				free(var->conf->title);
				var->conf->title = NULL;
			}
			free(var->conf);
			var->conf = NULL;
		}
		if (var != NULL) {
			free(var);
			var = NULL;
		}
	}
}

/*
 * mw_node_hostname_match()
 *
 * Does a given node match our hostname.  0 if it on success, non-zero on
 * failure.
 */
int
mw_node_hostname_match(struct conf_node *node)
{
	char *cpos, *myhostname;
	myhostname = mw_get_hostname();
	cpos = strchr(node->title, ':');
	if (cpos == NULL) {
		fprintf(stderr,
		    "mw_get_machine_node: "
		    "Missing colon, "
		    "could not parse machine section\n");
		exit(1);
	}
	/* ok, does this pattern match our hostname? */
	return (fnmatch(cpos+1, myhostname, 0));
}

/*
 * mw_insert_conflist()
 *
 * Search the temporary config list for a node with the same key as <node>.
 * If found, remove it from temporary config list before inserting <node>.
 * Otherwise, just go ahead and insert it <node> in the temporary config
 * list.
 */
void
mw_insert_conflist(struct mw_conf_head *myconf, struct conf_node *node, const char *project)
{
	struct conf_list_entry *var, *new, *nxt;
	int found = 0;

	/* Ignore values in machine sections which don't match our hostname */
	if (node->title != NULL
	    && strncmp(node->title, "machine", strlen("machine")) == 0
	    && mw_node_hostname_match(node) != 0) {
		return;
	}


	/* Search for an existing node with this key to override */
	for (var = TAILQ_FIRST(myconf); var != TAILQ_END(myconf); var = nxt) {
		nxt = TAILQ_NEXT(var, conf_node_list);
		/* Skip nodes without keys nor values */
		if (node->key == NULL && node->value == NULL)
			continue;
		if (var->conf->key == NULL && var->conf->value == NULL)
			continue;
		if (project != NULL &&
		    mw_node_match_prefix(node, "project", project) == 0) {
			found = 1;
			break;
		}
		/* if project specified, and titles do not match, never overwrite */
		if (project != NULL
		    && node->title != NULL
		    && var->conf->title != NULL
		    && strcmp(node->key, var->conf->key) == 0
		    && strcmp(node->title, var->conf->title) != 0) {
			continue;
		}
		/* otherwise, overwrite */
		if (strcmp(node->key, var->conf->key) == 0) {
			found = 1;
			break;
		}
	}
	new = mw_conf_list_entry_create(node);
	if (found) {
		TAILQ_INSERT_BEFORE(var, new, conf_node_list);
		TAILQ_REMOVE(myconf, var, conf_node_list);
		free(var);
		var = NULL;
	} else {
		TAILQ_INSERT_TAIL(myconf, new, conf_node_list);
	}
}

/*
 * mw_overwrite_conflist()
 *
 * Search the temporary config list for a node with the same key as <node>.
 * If found, remove it from temporary config list before inserting <node>.
 * Otherwise, just go ahead and insert it <node> in the temporary config
 * list.
 */
void
mw_overwrite_conflist(struct mw_conf_head *myconf, struct conf_node *node)
{
	struct conf_list_entry *var, *new, *nxt;
	int found = 0;

	/* Ignore values in machine sections which don't match our hostname */
	if (node->title != NULL
	    && strncmp(node->title, "machine", strlen("machine")) == 0
	    && mw_node_hostname_match(node) != 0) {
		return;
	}

	/* Search for an existing node with this key to override */
	for (var = TAILQ_FIRST(myconf); var != TAILQ_END(myconf); var = nxt) {
		nxt = TAILQ_NEXT(var, conf_node_list);
		/* Skip nodes without keys nor values */
		if (node->key == NULL && node->value == NULL)
			continue;
		if (var->conf->key == NULL && var->conf->value == NULL)
			continue;
		/* overwrite */
		if (strcmp(node->key, var->conf->key) == 0) {
			found = 1;
			break;
		}
	}
	new = mw_conf_list_entry_create(node);
	if (found) {
		TAILQ_INSERT_BEFORE(var, new, conf_node_list);
		TAILQ_REMOVE(myconf, var, conf_node_list);
		free(var);
		var = NULL;
	} else {
		TAILQ_INSERT_TAIL(myconf, new, conf_node_list);
	}
}

/*
 * mw_title_suffix_match()
 *
 * Given a <title> like "project:gd#1", see if the part after the colon
 * matches <s>.  Return 0 on success, non-zero on failure.
 */
static int
mw_title_suffix_match(const char *title, const char *s)
{
	char *cpos;

	if ((cpos = strchr(title, ':')) == NULL) {
		return (1);
	}
	if (strlen(cpos) < 2) {
		return (1);
	}

	return (strcmp(cpos + 1, s));
}

/*
 * mw_get_project_name()
 *
 * Given an project name like "gd#1", return the project e.g. in this case
 * "gd".  Caller responsible for free.
 */
char *
mw_get_project_name(const char *project)
{
	char *cpos, *res;

	if ((cpos = strchr(project, '#')) == NULL)
		return (xstrdup(project));

	res = xmalloc(cpos - project + 1);
	memset(res, '\0', cpos - project + 1);
	strlcpy(res, project, cpos - project + 1);

	return (res);
}

/*
 * mw_get_project_title()
 *
 * Given an project like "gd#1" return the project title e.g. "project:gd".
 * Allocates a new buffer, caller responsible for free.
 */
static char *
mw_get_project_title(const char *project)
{
#define PROJ_TITLE "project:"
	char *hpos, *res;
	size_t len;

	if ((hpos = strchr(project, '#')) == NULL) {
		len = strlen(project) + strlen(PROJ_TITLE) + 1;
		goto create;
	}
	/* # must not be the first character */
	if (hpos - project == 0)
		return (NULL);
	len = hpos - project + strlen(PROJ_TITLE) + 1;
create:
	res = xmalloc(len);
	strlcpy(res, PROJ_TITLE, len);
	strlcat(res, project, len);

	return (res);
}

/*
 * mw_get_project_shortname()
 *
 * Translates e.g. gd#trunk -> gd.
 */
static char *
mw_get_project_shortname(const char *project)
{
	char *hpos, *res;
	size_t len;

	/* If there is no hash, or the length of the string is zero,
	 * input is invalid */
	if ((hpos = strchr(project, '#')) == NULL
	    && strlen(project) == 0)
		return (NULL);

	/* Return a copy of the string if there is no hash, otherwise the part
	 * up to the hash */
	if (hpos == NULL) {
		return (xstrdup(project));
	} else {
		len = hpos - project + 1;
		res = xmalloc(len);
		strlcpy(res, project, len);
		return (res);
	}
}

/*
 * mw_config_add_default()
 *
 * Create and insert a default configuration value.
 */
void
mw_config_add_default(struct mw_conf_head *root, char *key, const char *val)
{
	struct conf_node *cnode;

	cnode = xmalloc(sizeof(*cnode));
	memset(cnode, 0, sizeof(*cnode));
	cnode->key = xmalloc(CONF_BUFFER_SIZE);
	cnode->value = xmalloc(CONF_BUFFER_SIZE);
	strlcpy(cnode->key, key, CONF_BUFFER_SIZE);
	strlcpy(cnode->value, val, CONF_BUFFER_SIZE);
	mw_insert_conflist(root, cnode, NULL);
}

/*
 * mw_revision_info_cb()
 *
 * Callback function used with the SVN libraries.
 */
static svn_error_t*
mw_revision_info_cb(void *baton, const char *path,
		const svn_info_t *info, apr_pool_t *pool)
{
	svn_revnum_t *rev = baton;
	*rev = info->rev;

	return SVN_NO_ERROR;
}

/*
 * mw_string_to_path()
 *
 * Convert a string to a filesystem path.  Basically convert
 * slashes, colons and hashes to underscores.
 */
static char *
mw_string_to_path(const char *path)
{
	static char *res, *p;

	if (res != NULL)
		free(res);

	res = xstrdup(path);
	for (p = res; *p != '\0'; p++) {
		if (*p == '/' || *p == ':' || *p == '#')
			*p = '_';
	}
	return (res);
}

/*
 * mw_realpath()
 *
 * Wrapper around realpath(3).  Returns static buffer
 * containing the resolved path.
 */
static char *
mw_realpath(const char *path)
{
	static char *therealpath;

	if (therealpath == NULL)
		therealpath = xmalloc(PATH_MAX);
	memset(therealpath, '\0', PATH_MAX);

	if ((realpath(path, therealpath)) == NULL) {
		return (path);
	}

	return (therealpath);
}

/*
 *
 */
static void
mw_generate_project_settings(struct mw_conf_head *newconf,
			     struct mw_config_data *project_config,
			     struct mw_conf_head *oldconf,
			     const char *project)
{
	struct conf_list_entry *node;
	char *prj_title, *machine;

	/*
	 * 0. Collect a few important values.
	 */
	if ((prj_title = mw_get_project_title(project)) == NULL) {
		fprintf(stderr, "Bad project name: %s\n", project);
		exit(1);
	}
	/* Identify which machine section to use. */
	if ((node = mw_get_machine_node(oldconf)) == NULL) {
		fprintf(stderr,
		    "Could not find machine node for this host\n");
		exit(1);
	}
	machine = node->conf->title;

	/*
	 * 1. Core defaults.
	 */
	/* PROJECT */
	mw_config_add_default(newconf, "PROJECT", project);
	/* PROJECT_DIR */
	mw_config_add_default(newconf, "PROJECT_DIR",
	    mw_string_to_path(project));
	/* PROJECT_DATADIR */
	mw_config_add_default(newconf, "PROJECT_DATADIR",
	    "${MWBUILD_DATAROOT}/${PROJECT_DIR}");
	/* PROEJCT_LOGDIR */
	mw_config_add_default(newconf, "PROJECT_LOGDIR",
	    "${MWBUILD_LOGROOT}/${PROJECT_DIR}");
	/* PROEJCT_APPDIR */
	mw_config_add_default(newconf, "PROJECT_APPDIR",
	    "${MWBUILD_APPROOT}/${PROJECT_DIR}");

	/* MWBUILD_ROOT */
	mw_config_add_default(newconf, MWBUILD_ROOT, mw_get_base_dir(oldconf));
	/* MWBUILD_APPROOT */
	mw_config_add_default(newconf, MWBUILD_APPROOT, "${MWBUILD_ROOT}/app");
	/* MWBUILD_DATAROOT */
	mw_config_add_default(newconf, MWBUILD_DATAROOT, "${MWBUILD_ROOT}/data");
	/* MWBUILD_LOGROOT */
	mw_config_add_default(newconf, MWBUILD_LOGROOT, "${MWBUILD_ROOT}/log");

	/*
	 * 2. Project settings.
	 */
	if (project_config != NULL)
		mw_parse_config(newconf, project_config, 0);

	/*
	 * 3. Relevant machine settings.
	 */
	TAILQ_FOREACH(node, oldconf, conf_node_list) {
		if (node->conf->key == NULL || node->conf->value == NULL)
			continue;
		if (node->conf->title == NULL) {
			/* Globals always get copied. */
			mw_insert_conflist(newconf, node->conf, node->conf->title);
		} else if (strcmp(node->conf->title, prj_title) == 0) {
			/* Exact project match gets copied. */
			mw_insert_conflist(newconf, node->conf, node->conf->title);
		} else if (mw_node_match_prefix(node->conf, "machine", NULL) == 0) {
			/* Matching machine sections get copied. */
			if (strcmp(node->conf->title, machine) == 0)
				mw_insert_conflist(newconf, node->conf,
						   node->conf->title);
		} else if (mw_node_match_prefix(node->conf, "project", NULL) == 0) {
			/* Matching project sections get copied. */
			if (mw_title_suffix_match(node->conf->title, project) == 0) {
				mw_overwrite_conflist(newconf, node->conf);
			}
		} else
			/* Unsupported section types get skipped. */
			continue;
	}

	/*
	 * Final: Clean up
	 */
	free(prj_title);
}

/*
 * mw_process_project_settings()
 *
 * The core of the project configuration generation.
 * Build up the configuration for this project, then run the supplied callback
 * over it, before cleaning up.
 */
void
mw_process_project_settings(struct mw_conf_head *machine_config,
			     const char *project,
			     void (*fn)(struct mw_conf_head *, const char *, struct callback_args *),
			     struct callback_args *args)
{
	char *prj_title = NULL, *mysvnpath = NULL, *p;
	struct mw_conf_head tmpconf;
	struct mw_config_data *project_config = NULL;
	struct conf_list_entry *node;
	int found = 0;

	if ((prj_title = mw_get_project_title(project)) == NULL) {
		fprintf(stderr, "Bad project name: %s\n", project);
		exit(1);
	}

	/* Check whether we have any configuration for this project */
	TAILQ_FOREACH(node, machine_config, conf_node_list) {
		if (node->conf->title != NULL
		    && strcmp(node->conf->title, prj_title) == 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		/* Does it look like the user is giving us a branch spec? */
		if (strchr(project, '/') != NULL) {
			fprintf(stderr, "Looks like a Subversion branch spec.  Mwbuild expects a "
			    "project name.\n-> E.g. 'qbert' not 'qbert/trunk'\n");
			exit(1);
		}
	}
	found = 0;

	/* Temporary config which is given to handler function */
	TAILQ_INIT(&tmpconf);

	/* We need to do an initial expansion of the machine config
	 * in order to find the project config. */
	mw_generate_project_settings(&tmpconf, NULL, machine_config, project);
	mw_do_expansion(&tmpconf);
	/* Special handling for PROJECT_APPDIR - make sure its a fully-resolved
	 * absolute path */
	TAILQ_FOREACH(node, &tmpconf, conf_node_list) {
	}

	/* For "get", there isn't yet anything on disk, so we can't lookup
	 * the project config.  For everything else, lookup the project config,
	 * and rebuild the full config with it. */
	if (args->action != MW_GET_ACTION) {
		project_config = mw_get_project_config(&tmpconf,
		    mw_string_to_path(project));

		/* Rebuild the full config including the project config. */
		mw_free_conflist(&tmpconf, 0);
		mw_generate_project_settings(&tmpconf, project_config,
					     machine_config, project);
	}

	/* Make sure the output config is sane */
	if (mw_sanity_check_config(&tmpconf) == -1) {
		fprintf(stderr, "Config file sanity check failed\n");
		exit(1);
	}
	/* Check that the PROJECT_SVN value has a revision.  If it does not,
	 * look one up and insert it. */
	found = 0;
	TAILQ_FOREACH(node, &tmpconf, conf_node_list) {
		if (node->conf->key != NULL
		    && strcmp(node->conf->key, "PROJECT_SVN") == 0) {
			found = 1;
			break;
		}
	}
	/* don't do this for get action, it will only break things
	 * and serves no possible use. */
	if (found
	    && (p = strchr(node->conf->value, ':')) == NULL
	    && args->action != MW_GET_ACTION) {
		char *appdir, buf[MAXPATHLEN], buf2[MAXPATHLEN], revnum[32];
		int pathlen;
		svn_revnum_t rev;
		svn_error_t *err = NULL;
		/* no revision - look it up from disk
		 * if possible.  note that this will fail unless we
		 * have a copy checked out on disk. */
		/* XXX Can we use PROJECT_APPDIR here? XXX */
		appdir = mw_get_config_var(&tmpconf, MWBUILD_APPROOT);
		/* The trailing "/." walks us through a symbolic link. */
		/* Subversion does not like working with symbolic links,
		 * so we need to find the real directory */
		xsnprintf(buf, sizeof(buf), "%s/%s", appdir, mw_get_config_var(&tmpconf, PROJECT_DIR));
		if ((pathlen = readlink(buf, buf2, MAXPATHLEN)) != -1) {
			size_t n;
			/* we must NUL-terminate path */
			buf2[pathlen] = '\0';
			err = svn_client_info2(buf2,
			    svn_opt_revision_unspecified,
			    svn_opt_revision_unspecified,
			    &mw_revision_info_cb, &rev,
			    svn_depth_empty, NULL, args->ctx, args->pool);
			if (err != NULL) {
				fprintf(stderr,
				    "Error fetching info for project `%s' "
				    "at path `%s': %s\n",
				    project, buf2, err->message);
				exit(1);
			}
			xsnprintf(revnum, sizeof(revnum), "%ld", rev);
			n = strlcat(node->conf->value, ":", CONF_BUFFER_SIZE);
			if (n >= CONF_BUFFER_SIZE) {
				fprintf(stderr,
				    "mw_process_project_settings(): "
				    "string truncation fetching svn info\n");
				exit(1);
			}

			n = strlcat(node->conf->value, revnum, CONF_BUFFER_SIZE);
			if (n >= CONF_BUFFER_SIZE) {
				fprintf(stderr,
				    "mw_process_project_settings(): "
				    "string truncation fetching svn info\n");
				exit(1);
			}
		}
	}
	mw_do_expansion(&tmpconf);
	/* Call the project config list handler function */
	fn(&tmpconf, project, args);
	/* Free the conf_list_entry structs of the temporary list */
	mw_free_conflist(&tmpconf, 0);
	if (mysvnpath != NULL)
		free(mysvnpath);
}

/*
 * mw_process_machine_projects()
 *
 * For each project in 'PROJECTS' under machine config,
 * process the project settings (i.e. build up config and run
 * callback)
 */
void
mw_process_machine_projects(struct mw_conf_head *machine_config,
			    void (*fn)(struct mw_conf_head *, const char *, struct callback_args *),
			    struct callback_args *arg)
{
	char *project, *projects, *last;
	struct conf_list_entry *listnode;

	listnode = mw_get_machine_node(machine_config);

	projects = xstrdup(listnode->conf->value);
	/* Now that we have found our PROJECTS node, build up config */
	for ((project = strtok_r(projects, " ", &last)); project;
	    (project = strtok_r(NULL, " ", &last))) {
		mw_process_project_settings(machine_config, project, fn, arg);
	}
	free(projects);
}

/*
 * mw_get_machine_node()
 *
 * Return the conf_list_entry node which a) matches this machine and b)
 * represents the PROJECTS="foo bar" variable
 *
 * Calls exit(1) on failure.
 */
static struct conf_list_entry *
mw_get_machine_node(struct mw_conf_head *root) {
	struct conf_list_entry *node;
	char *myhostname;
	int found = 0;

	/* first, we must look up the right machine section for this hostname */
	myhostname = mw_get_hostname();
	TAILQ_FOREACH(node, root, conf_node_list) {
		/* section title nodes have no key nor value */
		if (node->conf->key == NULL && node->conf->value == NULL)
			continue;
		if (strcmp(node->conf->key, "PROJECTS") == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		fprintf(stderr,
			"Could not find machine node for host ``%s''\n",
			myhostname);
		fprintf(stderr,
		    "You seem to be missing a machine section with a `PROJECTS' setting for this hostname.\n");
		exit(1);
	}

	return (node);
}

/*
 * mw_get_config_var()
 *
 * Return the value of a key, or NULL if not found.
 */
char *
mw_get_config_var(struct mw_conf_head *root, char *key)
{
	struct conf_list_entry *node;

	TAILQ_FOREACH(node, root, conf_node_list) {
		/* section title nodes have no key nor value */
		if (node->conf->key == NULL && node->conf->value == NULL)
			continue;
		if (strcmp(node->conf->key, key) == 0) {
			return (node->conf->value);
		}
	}

	/* Some variables get synthesized here if they're not explicitly
	 * overridden. */
	if (strcmp(key, PROJECT_APPDIR) == 0) {
		char *approot = mw_get_config_var(root, MWBUILD_APPROOT);
		char *project = mw_get_config_var(root, PROJECT_DIR);
		char buff[512];
		xsnprintf(buff, sizeof(buff), "%s/%s", approot, project);
		return xstrdup(buff);
	}

	return (NULL);

}

/*
 * mw_set_config_defaults()
 *
 * Set some global defaults for the config list.
 */
void
mw_set_config_defaults(struct mw_conf_head *root)
{

	/* MWBUILD_ROOT */
	if (mw_get_config_var(root, MWBUILD_ROOT) == NULL) {
		mw_config_add_default(root, MWBUILD_ROOT, mw_get_base_dir(root));
	}
	/* MWBUILD_APPROOT */
	if (mw_get_config_var(root, MWBUILD_APPROOT) == NULL) {
		mw_config_add_default(root, MWBUILD_APPROOT,
		    "${MWBUILD_ROOT}/app");
	}
	/* MWBUILD_DATAROOT */
	if (mw_get_config_var(root, MWBUILD_DATAROOT) == NULL) {
		mw_config_add_default(root, MWBUILD_DATAROOT,
		    "${MWBUILD_ROOT}/data");
	}
	/* MWBUILD_LOGROOT */
	if (mw_get_config_var(root, MWBUILD_LOGROOT) == NULL) {
		mw_config_add_default(root, MWBUILD_LOGROOT,
		    "${MWBUILD_ROOT}/log");
	}

}

/*
 * mw_open_action_log()
 *
 * Given a project name, open a log under
 * $MWBUILD_LOGROOT/mwbuild4/mwbuild4-action.log
 * and return the fd. */
int
mw_open_action_log(struct mw_conf_head *root, char *action)
{
	struct conf_list_entry *node;
	char *logdir, buf[CONF_BUFFER_SIZE], hour[4], sympath[CONF_BUFFER_SIZE];
	time_t now;
	size_t len;
	int logfd;

	logdir = NULL;

	now = time(NULL);

	/* Note that the conf list we are given here is not yet per-project.
	 * This means we have to do a little bit more work to find the
	 * correct node for the machine */
	TAILQ_FOREACH(node, root, conf_node_list) {
		/* section title nodes have no key nor value */
		if (node->conf->key == NULL && node->conf->value == NULL)
			continue;
		if (strcmp(node->conf->key, MWBUILD_LOGROOT) == 0) {
			/* First node which matches hostname wins */
			if (node->conf->title != NULL
			    && mw_node_hostname_match(node->conf) == 0) {
				logdir = node->conf->value;
				break;
			}
		}
	}
	/* If we didn't find MWBUILD_LOGROOT in a matching machine section,
	 * use the regular method for finding it */
	if (logdir == NULL) {
		logdir = mw_get_config_var(root, MWBUILD_LOGROOT);
	}
	/* Ensure our log directory exists */
	xsnprintf(buf, sizeof(buf), "%s/mwbuild4/", logdir);
	if (mw_mkpath(buf) == -1) {
		fprintf(stderr,
		    "mw_open_action_log: mw_mkpath() failure for %s: %s\n", buf,
		    strerror(errno));
		fprintf(stderr, "This may mean that `MWBUILD_LOGROOT' is not configured correctly, or that the permissions on it are wrong.\n");
		exit(1);
	}
	strftime(hour, sizeof(hour), "%H", gmtime(&now));
	/* Open the action log and return its file descriptor */
	xsnprintf(buf, sizeof(buf), "%s/mwbuild4/mwbuild4-action_%s.log",
	    logdir, hour);
	if ((logfd = open(buf, O_CREAT|O_APPEND|O_WRONLY, 0644)) == -1) {
		fprintf(stderr, "mw_open_action_log: open() failure: %s\n",
		    strerror(errno));
		fprintf(stderr, "This may mean that `MWBUILD_LOGROOT' is not configured correctly, or that the permissions on it are wrong.\n");
		exit(1);
	}
	/* After open succeeds, update symlink to point to just-opened file */
	xsnprintf(sympath, sizeof(sympath), "%s/mwbuild4/mwbuild4-action-latest.log", logdir);
	(void) unlink(sympath);
	if (symlink(buf, sympath) == -1) {
		fprintf(stderr, "mw_open_action_log: symlink() failure: %s\n",
		    strerror(errno));
		exit(1);
	}

	memset(buf, '\0', sizeof(buf));
	/* Write a timestamp at the top of the file */
	len = strftime(buf, sizeof(buf),
	    "============ %Y.%m.%d-%H.%M.%S ============\n", gmtime(&now));
	write(logfd, buf, len);
	len = xsnprintf(buf, sizeof(buf), "MWBuild action: %s\n", action);
	write(logfd, buf, len);

	return (logfd);
}

int
xsnprintf(char *str, size_t size, const char *fmt, ...)
{
	va_list ap;
	int i;

	va_start(ap, fmt);
	i = vsnprintf(str, size, fmt, ap);
	va_end(ap);

	if (i == -1 || i >= (int)size) {
		fprintf(stderr, "xsnprintf: overflow");
		exit(1);
	}

	return (i);
}

char *
xstrdup(const char *str)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	if (strlcpy(cp, str, len) >= len) {
		fprintf(stderr, "xstrdup: string truncated");
		exit(1);
	}
	return (cp);
}

/*
 *
 * mw_build_environment()
 *
 * Build up an array usable by exeve() and friends, from our mwbuild4
 * configuration.
 */
char **
mw_build_environment(struct mw_conf_head *root, int setflag)
{
	struct conf_list_entry *node;
	char *env, **envp, *path, buf[CONF_BUFFER_SIZE];
	int count = 0, i = 0;
	size_t len;

	TAILQ_FOREACH(node, root, conf_node_list)
		count++;

	/* Leave some extra slots for special variables which
	 * may be allocated later. */
	if ((envp = calloc(count + 4, sizeof(*envp))) == NULL) {
		fprintf(stderr, "mw_build_environment: calloc failure\n");
		exit(1);
	}

	/* Build up the environment array from this project's setting,
	 * which we will pass to execve()  */
	TAILQ_FOREACH(node, root, conf_node_list) {
		if (node->conf->value != NULL
		    && node->conf->key != NULL) {
			if (setflag)
				setenv(node->conf->key, node->conf->value, 1);
			len = xsnprintf(buf, sizeof(buf), "%s=%s",
			    node->conf->key, node->conf->value) + 1;
			env = xmalloc(len);
			memset(env, '\0', len);
			strlcpy(env, buf, len);
			envp[i] = env;
			i++;
		}
	}
	/*
	 * Preserve PATH from parent environment
	 * XXX: should we preserve others too?
	 */
	if ((path = getenv("PATH")) == NULL) {
		fprintf(stderr,"no PATH in environment\n");
		exit(1);
	}
	len = xsnprintf(buf, sizeof(buf), "PATH=%s", path) + 1;
	env = xmalloc(len);
	memset(env, '\0', len);
	strlcpy(env, buf, len);
	envp[i] = env;

	/* NULL-terminate our environment array */
	envp[i+1] = NULL;

	return (envp);
}

/*
 * mw_sanity_check_config()
 *
 * Check that our config is OK before continuing.
 * At present, this simply ensures that certain filesystem paths
 * are specified in absolute terms.
 */
int
mw_sanity_check_config(struct mw_conf_head *root)
{
	char *path;

	path = mw_get_config_var(root, MWBUILD_ROOT);
	if (*path != '/') {
		fprintf(stderr, "MWBUILD_ROOT is not an absolute path\n");
		return (-1);
	}
	path = mw_get_config_var(root, MWBUILD_APPROOT);
	if (*path != '/') {
		fprintf(stderr, "MWBUILD_APPROOT is not an absolute path\n");
		return (-1);
	}
	path = mw_get_config_var(root, MWBUILD_DATAROOT);
	if (*path != '/') {
		fprintf(stderr, "MWBUILD_DATAROOT is not an absolute path\n");
		return (-1);
	}
	path = mw_get_config_var(root, MWBUILD_LOGROOT);
	if (*path != '/') {
		fprintf(stderr, "MWBUILD_LOGROOT is not an absolute path\n");
		return (-1);
	}

	return (0);
}

static void
mw_vlog(FILE *stream, const char *fmt, va_list vap)
{
	time_t t;
	char tbuf[32];

	t = time(NULL);

	strftime(tbuf, sizeof(tbuf), "[%Y-%m-%d %T] ", gmtime(&t));

	fputs(tbuf, stream);
	fputs(" ", stream);
	vfprintf(stream, fmt, vap);
	fputc('\n', stream);
	fflush(stream);
}

/*
 * mw_log()
 *
 * Write a log message.
 *
 */
void
mw_log(FILE *stream, const char *fmt, ...)
{

	va_list vap;

	va_start(vap, fmt);
	mw_vlog(stream, fmt, vap);
	va_end(vap);
}


/*
 * mw_write_config_cache()
 *
 * Write the configuration to a local cache in $HOME/.mw/cache.mw4
 */
void
mw_write_config_cache(const char *config)
{
	FILE *fp;
	char path[MAXPATHLEN], *myhomedir;

	if ((myhomedir = getenv("HOME")) == NULL) {
		fprintf(stderr, "Could not find homedir!\n");
		exit(1);
	}
	xsnprintf(path, sizeof(path), "%s/.mw/", myhomedir);
	/* Create the directory */
	mw_mkpath(path);
	/* Assemble the absolute filename of cache */
	(void) strlcat(path, "cache.mw4", sizeof(path));

	if ((fp = fopen(path, "w")) == NULL) {
		fprintf(stderr, "Could not open `%s' for writing: %s\n",
		    path, strerror(errno));
		exit(1);
	}
	fprintf(fp, "%s", config);
	fclose(fp);
}

