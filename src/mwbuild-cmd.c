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

static void mw_conf_list_build(struct mw_conf_head *, const char *, struct callback_args *);

/* This callback is executed once per project, and will fork and execute
 * the supplied BUILD target
 */
static void
mw_conf_list_build(struct mw_conf_head *root,
		   const char *project,
		   struct callback_args *args)
{
	struct conf_list_entry *node;
	char buf[256], settingspath[1024];
	FILE *logfp, *settingsfp;
	char *mwargv[4], **envp;
	char *appdir, *datadir, *buildcmd;
	int devnullfd, logfd, status;
	pid_t pid;
	int childout[2];
	size_t l;

	logfd = args->logfd;
	if ((logfp = fdopen(args->logfd, "a")) == NULL) {
		fprintf(stderr, "fdopen failure\n");
		exit(1);
	}

	/* Find PROJECT_BUILD_CMD for this project. */
	buildcmd = mw_get_config_var(root, "PROJECT_BUILD_CMD");
	if (buildcmd == NULL) {
		if (args->opt_state->verbose) {
			fprintf(stderr,
				"%s has no PROJECT_BUILD_CMD defined, skipping\n",
				project);
		}
		mw_log(logfp,
		    "No PROJECT_BUILD_CMD value for project `%s'; skipping.",
		    project);
		return;
	}
	/* Write the configuration used during this build to a shell-sourceable file. */
	if ((datadir = mw_get_config_var(root, PROJECT_DATADIR)) == NULL) {
		mw_log(logfp,
		    "No PROJECT_DATADIR value for project `%s'.",
		    project);
		fprintf(stderr,
		    "No PROJECT_DATADIR value for project `%s'.\n",
		    project);
		exit(1);
	}
	(void) mw_mkpath(datadir);
	xsnprintf(settingspath, sizeof(settingspath), "%s/mwsettings", datadir);
	if ((settingsfp = fopen(settingspath, "w")) == NULL) {
		mw_log(logfp,
		    "Could not open settings file for project `%s' at path `%s': %s",
		    project, settingspath, strerror(errno));
		fprintf(stderr,
		    "Could not open settings file for project `%s' at path `%s': %s\n",
		    project, settingspath, strerror(errno));
		exit(1);
	}
	fprintf(settingsfp, "# shell-sourceable copy of configuration for project %s\n",
	    project);
	TAILQ_FOREACH(node, root, conf_node_list) {
		if (node->conf->key != NULL)
			fprintf(settingsfp, "%s=\"%s\"\n", node->conf->key, node->conf->value);
	}
	fclose(settingsfp);
	mw_log(logfp, "building %s", project);
	pipe(childout);
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Could not fork: %s\n",
			strerror(errno));
		exit(1);
	} else if (pid == 0) {
		close(childout[0]);
		envp = mw_build_environment(root, 0);
		/* setsid(); */
		/* Change working dir to project base */
		appdir = mw_get_config_var(root, PROJECT_APPDIR);
		if (args->opt_state->verbose)
			fprintf(stderr, "PROJECT_APPDIR=\"%s\"\n", appdir);
		if (chdir(appdir) == -1) {
			fprintf(stderr, "Could not chdir to %s: %s\n",
				appdir, strerror(errno));
			_exit(1);
		}
		if ((devnullfd = open("/dev/null", O_RDWR)) == -1) {
			fprintf(stderr, "Could not open /dev/null: %s\n",
				strerror(errno));
			_exit(1);
		}
		if (dup2(devnullfd, STDIN_FILENO) == -1) {
			fprintf(stderr, "Could not redirect stdin: %s\n",
				strerror(errno));
			_exit(1);
		}
		/* Delay this as late as possible, but we have to get it
		 * out before we redirect stderr. */
		if (args->opt_state->verbose)
			fprintf(stderr, "Executing: %s\n", buildcmd);
		/*
		 * If -v, send stdout and stderr to childout[], where the parent
		 * will collect it and send it to both the console and the
		 * log file.
		 * If not -v, stdout goes only to the log, but stderr still goes
		 * both places.
		 */
		if (dup2(args->opt_state->verbose ? childout[1] : logfd, STDOUT_FILENO) == -1) {
			fprintf(stderr,
				"Could not redirect stdout: %s\n",
				strerror(errno));
			_exit(1);
		}
		if (dup2(childout[1], STDERR_FILENO) == -1) {
			fprintf(stderr,
				"Could not redirect stderr: %s\n",
				strerror(errno));
			_exit(1);
		}
		/* Execute build command */
		mwargv[0] = "/bin/sh";
		mwargv[1] = "-c";
		mwargv[2] = buildcmd;
		mwargv[3] = NULL;
		mw_log(logfp,
		    "Executing build command '%s'", buildcmd);
		if (execve("/bin/sh", mwargv, envp) == -1) {
			_exit(1);
		}
		_exit(0);
	}
	close(childout[1]);
	/* Read output from the child and tee it to both the console and the log file. */
	while ((l = read(childout[0], buf, sizeof(buf))) > 0) {
		/* Send it to log first in an attempt to keep
		 * stderr/stdout interleaving correct. */
		write(logfd, buf, l);
		write(1, buf, l);
	}
	/* When read() fails, that probably means child has exited. */
	waitpid(pid, &status, 0);
	close(childout[0]);
	if (status != 0) {
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "build", project);
		if (WIFEXITED(status)) {
			fprintf(stderr, "%s build failed with status %d\n",
				project, WEXITSTATUS(status));
			mw_log(logfp, "%s build failed with status %d",
			       project, WEXITSTATUS(status));
			exit (WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			fprintf(stderr, "%s build failed with signal %d\n",
				project, WTERMSIG(status));
			mw_log(logfp, "%s build failed with signal %d",
			       project, WTERMSIG(status));
		} else {
			fprintf(stderr, "%s build failed!\n", project);
			mw_log(logfp, "%s build failed!\n", project);
		}
		exit (1);
	}

	syslog(LOG_INFO,
	       "mwbuild: %s succeeded for %s", "build", project);
}

/*
 * Our main entry point for 'build' subcommand.
 */
svn_error_t *
svn_cl__build(apr_getopt_t *os, void *baton, apr_pool_t *pool)
{
	svn_cl__opt_state_t *opt_state = ((svn_cl__cmd_baton_t *) baton)->opt_state;
	svn_client_ctx_t *ctx = ((svn_cl__cmd_baton_t *) baton)->ctx;
	apr_array_header_t *targets;
	struct callback_args args;
	struct mw_conf_head root, machine_config;
	struct mw_config_data *config_data;
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
	args.logfd = mw_open_action_log(&machine_config, "build");
	/* if we have no options, call this to print all known projects */
	if (targets->nelts == 0) {
		mw_process_machine_projects(&machine_config,
		    &mw_conf_list_build, &args);
	} else {
		for (i = 0; i < targets->nelts; i++) {
			project = ((const char **) (targets->elts))[i];
			mw_process_project_settings(&machine_config, project,
			    &mw_conf_list_build, &args);
		}
	}
	mw_free_conflist(&root, 1);

	return (SVN_NO_ERROR);
}
