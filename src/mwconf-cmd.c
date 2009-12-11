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

/* Metaweb 2008.  Based on: */

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

#include <sys/types.h> /* mkdir(2) */
#include <sys/stat.h>
#include <fcntl.h> /* open(2) */
#include <stdio.h> /* stdin, stdout, stderr names */
#include <syslog.h> /* syslog() */
#include <stdarg.h>

#include "svn_client.h"
#include "svn_path.h"
#include "svn_error.h"
#include "svn_pools.h"
#include "cl.h"

#include "svn_private_config.h"

static void mw_conf_list_configure(struct mw_conf_head *,
				   const char *,
				   struct callback_args *);

/* This callback is executed once per project, and will fork and execute
 * the configure action for the project.
 */
static void
mw_conf_list_configure(struct mw_conf_head *root,
		       const char *project,
		       struct callback_args *args)
{
	struct conf_list_entry *node, *bnode = NULL;
	FILE *logfp;
	char *mwargv[4], **envp, buf[256];
	char *appdir, *project_name;
	int found = 0;
	int devnullfd, logfd;

	logfd = args->logfd;
	if ((logfp = fdopen(args->logfd, "a")) == NULL) {
		fprintf(stderr, "fdopen failure\n");
		exit(1);
	}
	/* Find the configure script for this project, and count number
	 * of variables while we are at it */
	TAILQ_FOREACH(node, root, conf_node_list) {
		if (node->conf->key != NULL
		    && strcmp(node->conf->key, "PROJECT_CONFIGURE_CMD") == 0) {
			found = 1;
			bnode = node;
		}
	}
	/* We MUST have a PROJECT_CONFIGURE_CMD value for each project */
	if (!found) {
		fprintf(stderr,
		    "could not find valid PROJECT_CONFIGURE_CMD value for project `%s'\n",
		    project);
		mw_log(logfp,
		    "could not find valid PROJECT_CONFIGURE_CMD value for project `%s'",
		    project);
		goto err;
	}
	envp = mw_build_environment(root, 0);
	setsid();
	/* Change working dir to project app dir */
	appdir = mw_get_config_var(root, MWBUILD_APPROOT);
	project_name = mw_get_project_name(project);
	xsnprintf(buf, sizeof(buf), "%s/%s", appdir,
	    project_name);
	if (chdir(buf) == -1) {
		goto err;
	}
	/* Open the build log and set stderr and stdout to its fd */
	logfd = args->logfd;
	if ((devnullfd = open("/dev/null", O_RDWR)) == -1) {
		goto err;
	}
	if (dup2(devnullfd, STDIN_FILENO) == -1) {
		goto err;
	}
	if (dup2(logfd, STDOUT_FILENO) == -1) {
		goto err;
	}
	if (dup2(logfd, STDERR_FILENO) == -1) {
		goto err;
	}
	/* Execute build command */
	mwargv[0] = "/bin/sh";
	mwargv[1] = "-c";
	mwargv[2] = bnode->conf->value;
	mwargv[3] = NULL;
	mw_log(stderr,
	    "Executing configure command '%s'", bnode->conf->value);
	if (execve("/bin/sh", mwargv, envp) == -1) {
		goto err;
	}
	free(project_name);
	free(envp);
	syslog(LOG_INFO,
	    "mwbuild: %s succeeded for %s", "conf", project);
	return;
err:
	syslog(LOG_ERR,
	    "mwbuild: %s failed for %s", "conf", project);
	exit(1);
}

/*
 * Our main entry point for 'configure' subcommand.
 */
svn_error_t *
svn_cl__configure(apr_getopt_t *os, void *baton, apr_pool_t *pool)
{
	svn_cl__opt_state_t *opt_state = ((svn_cl__cmd_baton_t *) baton)->opt_state;
	svn_client_ctx_t *ctx = ((svn_cl__cmd_baton_t *) baton)->ctx;
	apr_array_header_t *targets;
	struct mw_conf_head root, machine_config;
	struct mw_config_data *config_data;
	struct callback_args args;
	const char *project;
	int i;


	openlog("mwbuild", LOG_ODELAY, LOG_USER);

	TAILQ_INIT(&root);
	TAILQ_INIT(&machine_config);

	args.opt_state = opt_state;
	args.pool = pool;
	args.ctx = ctx;

	SVN_ERR(svn_opt_args_to_target_array2(&targets, os,
	    opt_state->targets, pool));
	if ((config_data = mw_get_config(0, baton, pool)) == NULL) {
		fprintf(stderr, "Could not get config\n");
		exit(1);
	}
	/* machine_config is just the machine config, which is needed to check for
	 * custom MWBUILD_* paths, which effects later actions. */
	mw_parse_config(&machine_config, config_data, 0);
	mw_set_config_defaults(&machine_config);
	mw_do_expansion(&machine_config);
	/* Open the action log */
	args.logfd = mw_open_action_log(&machine_config, "configure");
	/* if we have no options, call this to print all known projects */
	if (targets->nelts == 0) {
		mw_process_machine_projects(&machine_config,
		    &mw_conf_list_configure, &args);
	} else {
		for (i = 0; i < targets->nelts; i++) {
			project = ((const char **) (targets->elts))[i];
			mw_process_project_settings(&machine_config, project,
			    &mw_conf_list_configure, &args);
		}
	}
	mw_free_conflist(&root, 1);

	return (SVN_NO_ERROR);
}
