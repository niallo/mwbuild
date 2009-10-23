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

/*
 * checkout-cmd.c -- Subversion checkout command
 *
 * ====================================================================
 * Copyright (c) 2000-2006 CollabNet.  All rights reserved.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution.  The terms
 * are also available at http://subversion.tigris.org/license-1.html.
 * If newer versions of this license are posted there, you may use a
 * newer version instead, at your option.
 *
 * This software consists of voluntary contributions made by many
 * individuals.  For exact contribution history, see the revision
 * history and logs, available at http://subversion.tigris.org/.
 * ====================================================================
 */

/* ==================================================================== */


/*** Includes. ***/

#include <sys/param.h>
#include <sys/stat.h>

#include <syslog.h> /* syslog() */
#include <stdarg.h>

#include <time.h>

#include "svn_client.h"
#include "svn_path.h"
#include "svn_error.h"
#include "svn_pools.h"
#include "cl.h"

#include "svn_private_config.h"


static void mw_conf_list_get(struct mw_conf_head *,
				  const char *,
				  struct callback_args *);

static svn_error_t*
mw_revision_info_cb(void *baton, const char *path,
		const svn_info_t *info, apr_pool_t *pool)
{
	svn_revnum_t *rev = baton;
	*rev = info->rev;

	return SVN_NO_ERROR;
}

/* Retrieve the current HEAD revision at SVN URL <path> */
static svn_revnum_t
mw_get_head_rev(const char *path, struct callback_args *args,
    const char *project, FILE *logfp)
{
	apr_pool_t *subpool;
	svn_revnum_t rev;
	svn_opt_revision_t pegrev, headrev;
	svn_error_t *err = NULL;

	subpool = svn_pool_create(args->pool);
	pegrev.kind = svn_opt_revision_unspecified;
	headrev.kind = svn_opt_revision_head;
	err = svn_client_info2(path,
	    &pegrev,
	    &headrev,
	    &mw_revision_info_cb, &rev,
	    svn_depth_empty, NULL, args->ctx, args->pool);

	if (err != NULL) {
		mw_log(logfp,
		    "Error fetching info for project `%s' "
		    "at path `%s': %s\n",
		    project, path, err->message);
		fprintf(stderr,
		    "Error fetching info for project `%s' "
		    "at path `%s': %s\n",
		    project, path, err->message);
		exit(1);
	}
	svn_pool_destroy(subpool);

	return (rev);
}

/* Check a string for a revision, and return that as a long long.
 * Returns -1 on failure. */
static long long
mw_svn_rev(const char *value)
{
	char *cpos;
	const char *errstr;
	long long res;

	if ((cpos = strchr(value, ':')) == NULL)
		return (-1);

	/* Must be at least 1 byte long */
	if (strlen(cpos) < 2)
		return (-1);

	res = strtonum(cpos+1, 1, LONG_MAX, &errstr);
	if (errstr) {
		fprintf(stderr, "SVN rev is %s: %s\n", errstr, cpos+1);
		exit(1);
	}

	return (res);

}

/* This is called by the project processor, and runs a checkout for each
 * project.
 */
static void
mw_conf_list_get(struct mw_conf_head *r, const char *project,
    struct callback_args *args)
{
	struct conf_list_entry *node;
	FILE *logfp;
	char *approot, *cpos, *project_dir, buf[MAXPATHLEN], canonical[MAXPATHLEN];
	char slink[MAXPATHLEN];
	char true_url[MAXPATHLEN];
	int found = 0;
	svn_revnum_t revnum, result_revnum;
	svn_opt_revision_t revision, pegrev;
	apr_pool_t *subpool;
	svn_error_t *err = NULL;

	pegrev.kind = svn_opt_revision_unspecified;
	/* Open our per-project checkout log.  This needs to go in /tmp
	 * initially, because we don't have a project checked out */
	if ((logfp = fdopen(args->logfd, "a")) == NULL) {
		exit(1);
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "get", project);
	}

	/* Find the PROJECT_SVN path for this project */
	TAILQ_FOREACH(node, r, conf_node_list) {
		if (node->conf->key != NULL
		    && strcmp(node->conf->key, "PROJECT_SVN") == 0) {
			found = 1;
			break;
		}
		if (node->conf->key != NULL) {
			printf("key: %s val: %s\n", node->conf->key, node->conf->value);
		}
	}
	/* We MUST have a PROJECT_SVN value for each project */
	if (!found) {
		fprintf(stderr,
		    "could not find valid PROJECT_SVN value for project `%s'\n",
		    project);
		mw_log(logfp,
		    "could not find valid PROJECT_SVN value for project `%s'",
		    project);
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "get", project);
		exit(1);
	}

	revision.kind = svn_opt_revision_number;
	/* Couldn't find a revision, fetch revision of HEAD */
	if ((revnum = mw_svn_rev(node->conf->value)) == -1) {
		/* Shorten SVN string to just the URL part */
		if ((cpos = strchr(node->conf->value, ':')) != NULL) {
			*cpos = '\0';
		}
		/* Build up the URL */
		xsnprintf(true_url, sizeof(true_url), "%s/%s", SVN_ROOT,
		    node->conf->value);
		revision.value.number =
		    mw_get_head_rev(true_url, args, project, logfp);
	} else {
		/* Shorten SVN string to just the URL part */
		if ((cpos = strchr(node->conf->value, ':')) != NULL) {
			*cpos = '\0';
		}
		/* Build up the URL */
		xsnprintf(true_url, sizeof(true_url), "%s/%s", SVN_ROOT,
		    node->conf->value);
		revision.value.number = revnum;
	}


	/* Build up the (temporary) local path for checkout */
	project_dir = mw_get_config_var(r, PROJECT_DIR);
	approot = mw_get_config_var(r, MWBUILD_APPROOT);
	xsnprintf(buf, sizeof(buf), "%s/%s_%ld", approot, project_dir,
	    revision.value.number);
	/* On some systems (notably linux), realpath(3) needs the full path to exist first */
	if (mw_mkpath(buf) == -1) {
		fprintf(stderr, "mw_mkpath() failure\n");
	}
	if (realpath(buf, canonical) == NULL) {
		fprintf(stderr, "Could not canonicalise path: %s: %s\n", buf, strerror(errno));
		mw_log(logfp, "Could not canonicalise path: %s: %s\n", buf, strerror(errno));
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "get",
		    mw_get_config_var(r, PROJECT_SVN));
		exit(1);
	}
	subpool = svn_pool_create(args->pool);
	printf("Checking out %s:%ld to %s\n", true_url,
	    revision.value.number, canonical);
	mw_log(logfp, "Checking out %s:%ld to %s", true_url,
	    revision.value.number, canonical);

	/* Run the actual checkout */
	err = svn_client_checkout2(&result_revnum, true_url, canonical,
	    &pegrev,
	    &revision,
	    TRUE,
	    args->opt_state->ignore_externals,
	    args->ctx, subpool);

	svn_pool_destroy(subpool);
	if (err != NULL) {
		fprintf(stderr,
		    "Error checking out project `%s' at URL `%s': %s\n",
		    project, true_url, err->message);
		mw_log(logfp,
		    "Error checking out project `%s' at URL `%s': %s",
		    project, true_url, err->message);
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "get",
		    mw_get_config_var(r, PROJECT_SVN));
		exit(1);
	}
	/* Update symlink */
	xsnprintf(slink, sizeof(slink), "%s/%s", approot, project_dir);
	(void) unlink(slink);
	if (symlink(canonical, slink) == -1) {
		fprintf(stderr,
		    "Error symlinking %s to %s: %s\n", slink, canonical,
		    strerror(errno));
		mw_log(logfp,
		    "Error symlinking %s to %s: %s", slink, canonical,
		    strerror(errno));
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "get",
		    mw_get_config_var(r, PROJECT_SVN));
		exit(1);
	}

	syslog(LOG_DEBUG,
	    "mwbuild: %s succeeded for %s", "get",
	    mw_get_config_var(r, PROJECT_SVN));
}

/*
 * Our main entry point for 'checkout' subcommand.
 */
svn_error_t *
svn_cl__get(apr_getopt_t *os, void *baton, apr_pool_t *pool)
{
	svn_cl__opt_state_t *opt_state = ((svn_cl__cmd_baton_t *) baton)->opt_state;
	svn_client_ctx_t *ctx = ((svn_cl__cmd_baton_t *) baton)->ctx;
	apr_array_header_t *targets;
	struct mw_conf_head machine_config, root;
	struct callback_args args;
	struct mw_config_data *config_data;
	struct conf_list_entry *node;
	const char *project;
	int i;

	openlog("mwbuild", LOG_ODELAY, LOG_USER);

	TAILQ_INIT(&machine_config);
	TAILQ_INIT(&root);

	args.opt_state = opt_state;
	args.pool = pool;
	args.ctx = ctx;
	args.action = MW_GET_ACTION;

	SVN_ERR(svn_opt_args_to_target_array2(&targets, os,
	    opt_state->targets, pool));
	if ((config_data = mw_get_config(args.action, baton, pool)) == NULL) {
		fprintf(stderr, "Could not get config\n");
		exit(1);
	}

	/* machine_config is just the machine config, which is needed to check for
	 * custom MWBUILD_* paths, which effects later actions. */
	mw_parse_config(&machine_config, config_data, 1);
	mw_set_config_defaults(&machine_config);
	mw_do_expansion(&machine_config);
	/* Open the action log */
	args.logfd = mw_open_action_log(&machine_config, "get");
	/* if we have no options, call this to print all known projects */
	if (targets->nelts == 0) {
		mw_process_machine_projects(&machine_config,
		    &mw_conf_list_get, &args);
	} else {
		for (i = 0; i < targets->nelts; i++) {
			project = ((const char **) (targets->elts))[i];
			mw_process_project_settings(&machine_config, project,
			    &mw_conf_list_get, &args);
		}
	}
	mw_free_conflist(&root, 1);


	return (SVN_NO_ERROR);
}

