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
 * mwcheck-cmd.c -- Subversion checkout command
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

static void mw_conf_list_check(struct mw_conf_head *,
				   const char *,
				   struct callback_args *);

/*
 * mw_run_check()
 *
 * Run a check and return exit status.
 */
static int
mw_run_check(char *cmd, int timeout, char *appdir, char **envp)
{
	char *mwargv[4];
	int devnullfd, status, i;
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Could not fork: %s\n",
			strerror(errno));
		exit(1);
	} else if (pid == 0) {
		/* Change working dir to project base */
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
		/* Execute check command */
		mwargv[0] = "/bin/sh";
		mwargv[1] = "-c";
		mwargv[2] = cmd;
		mwargv[3] = NULL;
		if (execve("/bin/sh", mwargv, envp) == -1) {
			_exit(1);
		}
		_exit(0);
	}
	/* Don't let a check run for more than <timeout> seconds */
	for (i = 0; i < timeout; i++) {
		if (waitpid(pid, &status, WNOHANG) != 0)
			break;
		sleep(1);
	}
	/* If check process hangs for more than <timeout> seconds, zap it */
	if (i == timeout) {
		(void)  kill(pid, SIGTERM);
		status = 1;
		fprintf(stderr, "Check timed out after %d.\n", timeout);
	}

	return (status);
}

/* This callback is executed once per project, and will fork and execute
 * the check action for the project.
 */
static void
mw_conf_list_check(struct mw_conf_head *root,
		       const char *project,
		       struct callback_args *args)
{
	FILE *logfp;
	char **envp;
	char *appdir, *checkcmd, *errstr, *t;
	int logfd, status;
	int interval, timeout;
	time_t start;

	/* defaults */
	if (args->opt_state->poll) {
		interval = 60; /* Check every minute */
		timeout = 300; /* Give up after 5 minutes */
	}

	logfd = args->logfd;

	if ((logfp = fdopen(args->logfd, "a")) == NULL) {
		fprintf(stderr, "fdopen failure\n");
		exit(1);
	}

	checkcmd = mw_get_config_var(root, "PROJECT_CHECK_CMD");
	if (checkcmd == NULL) {
		fprintf(stderr,
		    "No PROJECT_CHECK_CMD value for project `%s'\n",
		    project);
		mw_log(logfp,
		    "No PROJECT_CHECK_CMD value for project `%s'",
		    project);
		return;
	}
	/* see if we have configured CHECK_INTERVAL / CHECK_TIMEOUT */
	t = mw_get_config_var(root, "PROJECT_CHECK_INTERVAL");
	if (t != NULL) {
		interval = strtonum(t, 1, INT_MAX, &errstr);
		if (errstr) {
			fprintf(stderr, "PROJECT_CHECK_INTERVAL is %s: %s\n", errstr, t);
			exit(1);
		}
	}
	t = mw_get_config_var(root, "PROJECT_CHECK_TIMEOUT");
	if (t != NULL) {
		timeout = strtonum(t, 1, INT_MAX, &errstr);
		if (errstr) {
			fprintf(stderr, "PROJECT_CHECK_TIMEOUT is %s: %s\n", errstr, t);
			exit(1);
		}
	}

	appdir = mw_get_config_var(root, PROJECT_APPDIR);
	envp = mw_build_environment(root, 0);

	mw_log(logfp, "check %s", project);
	if (args->opt_state->poll) {
		start = time(NULL);
		while (1) {
			time_t now = time(NULL);
			status = mw_run_check(checkcmd, 10, appdir, envp);
			if (status == 0 || now >= start + timeout)
				break;
			fprintf(stderr, "%s check failed.  Retrying in %d seconds.  Giving up completely in %d seconds.\n",
					project, interval, start + timeout - now);
			sleep(interval);
		}
	} else {
		status = mw_run_check(checkcmd, 10, appdir, envp);
	}
	if (status != 0) {
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "check", project);
		if (WIFEXITED(status)) {
			fprintf(stderr, "%s check failed with status %d\n",
				project, WEXITSTATUS(status));
			mw_log(logfp, "%s check failed with status %d",
			       project, WEXITSTATUS(status));
			exit (WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			fprintf(stderr, "%s check failed with signal %d\n",
				project, WTERMSIG(status));
			mw_log(logfp, "%s check failed with signal %d",
			       project, WTERMSIG(status));
		} else {
			fprintf(stderr, "%s check failed!\n", project);
			mw_log(logfp, "%s check failed!\n", project);
		}
		exit(1);
	}

	syslog(LOG_INFO,
	       "mwbuild: %s succeeded for %s", "check", project);
}

/*
 * Our main entry point for 'configure' subcommand.
 */
svn_error_t *
svn_cl__check(apr_getopt_t *os, void *baton, apr_pool_t *pool)
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
	args.logfd = mw_open_action_log(&machine_config, "check");
	/* if we have no options, call this to print all known projects */
	if (targets->nelts == 0) {
		mw_process_machine_projects(&machine_config,
		    &mw_conf_list_check, &args);
	} else {
		for (i = 0; i < targets->nelts; i++) {
			project = ((const char **) (targets->elts))[i];
			mw_process_project_settings(&machine_config, project,
			    &mw_conf_list_check, &args);
		}
	}
	mw_free_conflist(&root, 1);

	return (SVN_NO_ERROR);
}
