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
#include <syslog.h> /* syslog() */
#include <stdarg.h>

#include "nanny/nanny.h" /* nanny routines */
#include "nanny/nanny_timer.h" /* nanny timer routines */

#include "svn_client.h"
#include "svn_path.h"
#include "svn_error.h"
#include "svn_pools.h"
#include "cl.h"

#include "svn_private_config.h"

static void mw_conf_list_stop(struct mw_conf_head *, const char *, struct callback_args *);

/* This callback is executed once per project, and will send a TERM signal
 * to the nanny process associated with specified project.
 */
static void
mw_conf_list_stop(struct mw_conf_head *root,
		  const char *project,
		  struct callback_args *args)
{
	FILE *logfp, *pidfp;
	char buf[256];
	char *datadir;
	int ret;
	pid_t pid;

	if ((logfp = fdopen(args->logfd, "a")) == NULL) {
		fprintf(stderr, "fdopen failure\n");
		exit(1);
	}

	/* Find PID of project */
	datadir = mw_get_config_var(root, PROJECT_DATADIR);
	xsnprintf(buf, sizeof(buf), "%s/_mwbuild/%s.pid",
	    datadir, project);
	if ((pidfp = fopen(buf, "r")) == NULL) {
		fprintf(stderr, "no pid file found for project %s at `%s'\n",
		    project, buf);
		mw_log(logfp, "no pid file found for project %s at `%s'",
		    project, buf);
		goto err;
	}
	if (fscanf(pidfp, "%d", &pid) == 0) {
		fprintf(stderr, "error reading pid file for project %s at `%s'\n",
		    project, buf);
		mw_log(logfp, "error reading pid file for project %s at `%s'",
		    project, buf);
		goto err;
	}
	fclose(pidfp);
	mw_log(logfp, "stopping %s (PID: %d)", project, pid);
	/* Send a TERM signal to the nanny. */
	kill(pid, SIGTERM);
	/* Wait for the nanny to shut down. */
	printf("Stopping project '%s' (nanny PID: %d)\n", project, pid);
	for (;;) {
		if ((ret = kill(pid, 0)) == -1
		    && errno == ESRCH)
			break;
		sleep(1);
	}

	printf("Stopped project '%s' (nanny PID: %d)\n", project, pid);
	mw_log(logfp, "stopped %s (PID: %d)", project, pid);
	syslog(LOG_INFO,
	    "mwbuild: %s succeeded for %s", "stop",
	    mw_get_config_var(root, PROJECT_SVN));

	/* unlink the pid */
	(void)  unlink(buf);
	return;
err:
	syslog(LOG_ERR,
	    "mwbuild: %s failed for %s", "stop",
	    mw_get_config_var(root, PROJECT_SVN));
}

/*
 * Our main entry point for 'stop' subcommand.
 */
svn_error_t *
svn_cl__stop(apr_getopt_t *os, void *baton, apr_pool_t *pool)
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
	args.logfd = mw_open_action_log(&machine_config, "stop");
	/* if we have no options, call this to print all known projects */
	if (targets->nelts == 0) {
		mw_process_machine_projects(&machine_config,
		    &mw_conf_list_stop, &args);
	} else {
		for (i = 0; i < targets->nelts; i++) {
			project = ((const char **) (targets->elts))[i];
			mw_process_project_settings(&machine_config, project,
			    &mw_conf_list_stop, &args);
		}
	}
	mw_free_conflist(&root, 1);

	return (SVN_NO_ERROR);
}
