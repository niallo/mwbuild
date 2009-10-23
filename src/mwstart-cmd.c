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

#define MAX_CMD_GROUPS 10
#define CMD_FILE_RETRIES 20

struct cmd_group {
	char *start_cmd;
	char *stop_cmd;
	char *health_cmd;
	int restartable;
};

static void mw_conf_list_start(struct mw_conf_head *, const char *, struct callback_args *);
static void stophandler(int);
static int default_http_page(struct http_request *);
static void http_dispatcher(struct http_request *);
static int mw_project_running(struct mw_conf_head *, const char *);

/* Running flag:  Reset by signal handler, main loop uses this to exit. */
static int running = 1;

static void
stophandler(int s)
{
	running = 0;
}

/* mw_fork_and_wait()
 *
 * fork() a new process to execute (via /bin/sh) a command line.
 * Harvest output from child, and wait for execution to complete
 * before returning exit code to caller.
 *
 */
static int
mw_fork_and_wait(const char *cmd,
		 const char *phase,
		 struct mw_conf_head *root,
		 const char *project,
		 int verbose,
		 int logfd,
		 FILE *logfp)
{
	pid_t pid;
	char *appdir, **envp, *mwargv[4];
	int devnullfd, status;

	mw_log(logfp, "%s for %s", phase, project);
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Could not fork: %s\n",
			strerror(errno));
		exit(1);
	} else if (pid == 0) {
		envp = mw_build_environment(root, 0);
		/* setsid(); */
		/* Change working dir to project base */
		appdir = mw_get_config_var(root, PROJECT_APPDIR);
		if (verbose)
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
		if (verbose)
			fprintf(stderr, "Executing %s: %s\n", phase, cmd);

		if (dup2(logfd, STDOUT_FILENO) == -1) {
			fprintf(stderr,
				"Could not redirect stdout: %s\n",
				strerror(errno));
			_exit(1);
		}
		if (dup2(logfd, STDERR_FILENO) == -1) {
			fprintf(stderr,
				"Could not redirect stderr: %s\n",
				strerror(errno));
			_exit(1);
		}
		/* Execute command */
		mwargv[0] = "/bin/sh";
		mwargv[1] = "-c";
		mwargv[2] = cmd;
		mwargv[3] = NULL;
		mw_log(logfp,
		    "Executing %s command '%s'", phase, cmd);
		if (execve("/bin/sh", mwargv, envp) == -1) {
			_exit(1);
		}
		_exit(0);
	}
	waitpid(pid, &status, 0);
	if (status != 0) {
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "build",
		       mw_get_config_var(root, PROJECT_SVN));
		if (WIFEXITED(status)) {
			fprintf(stderr, "%s %s failed with status %d\n",
				project, phase, WEXITSTATUS(status));
			mw_log(logfp, "%s %s failed with status %d",
			       project, phase, WEXITSTATUS(status));
			exit (WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			fprintf(stderr, "%s %s failed with signal %d\n",
				project, phase, WTERMSIG(status));
			mw_log(logfp, "%s %s failed with signal %d",
			       project, phase, WTERMSIG(status));
		} else {
			fprintf(stderr, "%s %s failed!\n", phase, project);
			mw_log(logfp, "%s %s failed!\n", phase, project);
		}
	}
	fprintf(stderr, "%s completed\n", phase);
	mw_log(logfp, "%s completed", phase);
	return (status);
}


static int
default_http_page(struct http_request *request)
{
	http_printf(request, "HTTP/1.0 200 OK\x0d\x0a");
	http_printf(request, "Content-Type: text/html\x0d\x0a");
	http_printf(request, "\x0d\x0a");
	http_printf(request, "<HTML>\n");
	http_printf(request, "<head><title>Nanny: %s</title></head>\n",
	    nanny_hostname());
	http_printf(request, "<body>\n");
	http_printf(request, "<ul>\n");
	http_printf(request, "<li>Host: %s\n", nanny_hostname());
	http_printf(request, "<li>Time: %s\n", nanny_isotime(0));
	http_printf(request, "<li><a href=\"/status/\">Children</a><br/>\n");
	http_printf(request,
	    "<li><a href=\"/environment\">Environment</a><br/>\n");
	http_printf(request,
	    "<li><a href=\"http://%s:8123/\">Qbert</a><br/>\n",
	    nanny_hostname());
	http_printf(request, "</ul>\n");
	http_printf(request, "<p>TODO: links to ganglia, other nannies on this"
	    " machine, other machines in local cluster</p>\n");
	http_printf(request, "</body>\n");
	http_printf(request, "</HTML>\n");

	return (0);
}

/*
 * The 'dispatcher' is invoked after the request line is parsed
 * but before any headers or HTTP body is read.  It can set
 * function callbacks to process header lines and body.
 * The body callback is expected to generate the response.
 */
static void
http_dispatcher(struct http_request *request)
{
	if (strcmp(request->uri, "/environment") == 0) {
		request->body_processor = nanny_http_environ_body;
		return;
	}
	if (strncmp(request->uri, "/status", 7) == 0) {
		request->body_processor = nanny_children_http_status;
		return;
	}
	request->body_processor = default_http_page;
}

/* Returns 1 if project nanny is running, 0 otherwise. */
static int
mw_project_running(struct mw_conf_head *root, const char *project)
{
	FILE *pidfp;
	pid_t pid;
	char *datadir, buf[256];
	int status = 0;

	/* Find PID of project */
	datadir = mw_get_config_var(root, PROJECT_DATADIR);
	xsnprintf(buf, sizeof(buf), "%s/_mwbuild/%s.pid",
	    datadir, project);
	if ((pidfp = fopen(buf, "r")) == NULL)
		goto out;

	fscanf(pidfp, "%d", &pid);
	fclose(pidfp);
	/* is the process running? */
	if (kill(pid, 0) != -1)
		status = 1;
out:
	return (status);
}

/*
 * mw_handle_project_cmd_file()
 *
 * Handle loading the stop and start commands from
 * PROJECT_CMD_FILE
 * and ensure the nanny is correctly set up.
 */
static int
mw_handle_project_cmd_file(const char *cmdfile,
			   const char *project_logdir,
			   const char *project,
			   FILE *logfp,
			   const char **envp)
{
	FILE *cmdfp;
	struct nanny_child *child;
	char *suffix, *list_of_stop_cmds[512];
	int i, num_stop_cmds = 0, skip = 0;

	/* Special handling for PROJECT_CMD_FILE */
	mw_log(logfp, "Checking for PROJECT_CMD_FILE: %s\n", cmdfile);
	if ((cmdfp = fopen(cmdfile, "r")) == NULL) {
		mw_log(logfp,"Not found\n");
		return (-1);
	}
	/* Java command lines can be very long! */
	char cbuf[2048];

	mw_log(logfp, "Reading %s\n", cmdfile);
	/* Yes, this is O(n2).  If we ever have very large
	 * files, we can optimise it. */
	while (fgets(cbuf, sizeof(cbuf), cmdfp) != NULL) {
		char tcbuf[2048], *stopcmd = NULL;
		size_t cspn, clen;
		off_t pos;
		int j;

		cbuf[strcspn(cbuf, "\n")] = '\0';
		if (cbuf[0] == '\0')
			continue;

		/* Check if this is a stop command which we've already seen */
		for (j = 0; j < num_stop_cmds; j++) {
			if (strcmp(cbuf, list_of_stop_cmds[j]) == 0) {
				skip = 1;
				break;
			}
		}
		if (skip)
			continue;

		/* Search through file from current line looking for suffix matches.
		 * If we see another line with the same suffix, it is the stop command. */
		clen = strlen(cbuf);
		cspn = strcspn(cbuf, "#");
		if (cspn == clen || cspn == clen - 1) {
			mw_log(logfp, "nanny %s: command line without valid suffix: %s", project, cbuf);
			continue;
		}
		suffix = cbuf + cspn;
		/* note current position */
		pos = ftello(cmdfp);
		/* read on looking for the stop command (next command with same suffix) */
		while (fgets(tcbuf, sizeof(tcbuf), cmdfp) != NULL) {
			char *tsuffix;
			size_t tcspn, tclen;
			tcbuf[strcspn(tcbuf, "\n")] = '\0';
			if (tcbuf[0] == '\0')
				continue;
			tcspn = strcspn(tcbuf, "#");
			tclen = strlen(tcbuf);
			if (tcspn == tclen || tcspn == tclen - 1)
				continue;
			tsuffix = tcbuf + tcspn;
			if (strcmp(tsuffix, suffix) == 0) {
				stopcmd = xstrdup(tcbuf);
				/* Maintain a list of found stop commands, so that we do not try to start them. */
				list_of_stop_cmds[num_stop_cmds] = stopcmd;
				num_stop_cmds++;
				mw_log(logfp, "nanny %s: stop command found: %s", project, stopcmd);
			}
		}
		/* rewind to previous position */
		fseeko(cmdfp, pos, SEEK_SET);

		mw_log(logfp, "nanny %s: starting child: %s",
		    project, cbuf);
		child = nanny_child_new(cbuf);
		nanny_child_set_envp(child, (const char **)envp);
		nanny_log_set_filename(child->child_stdout,
		    "%s/%s-nanny-stdout-%d.log",
		    project_logdir, project, i);
		nanny_log_set_filename(child->child_stderr,
		    "%s/%s-nanny-stderr-%d.log",
		    project_logdir, project, i);
		nanny_log_set_filename(child->child_events,
		    "%s/%s-nanny-events-%d.log",
		    project_logdir, project, i);
		mw_log(logfp, "nanny %s: started child",
		    project);
		if (stopcmd != NULL)
			nanny_child_set_stop(child, stopcmd);
		stopcmd = NULL;
		mw_log(logfp, "nanny %s: done.", project);
		i++;
	}
	fclose(cmdfp);
	return (0);
}

/*
 * mw_get_cmd_groups()
 *
 * Find matching stop/start/health commands,
 * put them into cmd_group structs, and return
 * that array.
 */
static struct cmd_group *
mw_get_cmd_groups(struct mw_conf_head *root, const char *project)
{
	struct conf_list_entry *node, *tnode;
	/* Support a maximum of MAX_CMD_GROUPS command groups */
	static struct cmd_group groups[MAX_CMD_GROUPS];
	int startfound = 0, cmdfilefound = 0;
	size_t i = 0;

	memset(groups, 0, sizeof(groups));

	/* A somewhat verbose an inefficient algorithm for now... */

	/* Find the first command (no suffix) */
	TAILQ_FOREACH(node, root, conf_node_list) {
		if (node->conf->key != NULL
		    && strcmp(node->conf->key, "PROJECT_START_CMD") == 0) {
			startfound = 1;
			groups[i].start_cmd = node->conf->value;
		}
		if (node->conf->key != NULL
		    && strcmp(node->conf->key, "PROJECT_CMD_FILE") == 0) {
			cmdfilefound = 1;
		}
		if (node->conf->key != NULL
		    && strcmp(node->conf->key, "PROJECT_STOP_CMD") == 0) {
			if (strlen(node->conf->value) > 0) {
				groups[i].stop_cmd = node->conf->value;
			}
		}
		if (node->conf->key != NULL
		    && strcmp(node->conf->key, "PROJECT_HEALTH_CMD") == 0) {
			if (strlen(node->conf->value) > 0) {
				groups[i].health_cmd = node->conf->value;
			}
		}
		if (node->conf->key != NULL
		    && strcmp(node->conf->key, "RESTART") == 0) {
			groups[i].restartable = 1;
		}
	}
	/* We MUST have a PROJECT_START_CMD or PROJECT_CMD_FILE
	   value for each project */
	if (!startfound && !cmdfilefound) {
		fprintf(stderr,
		    "could not find valid PROJECT_START_CMD nor "
		    "PROJECT_CMD_FILE value for project `%s'",
		    project);
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "start", project);
		exit(1);
	}

	/* Now look for up to (MAX_CMD_GROUPS - 1) secondary children */
	i = 1;
	TAILQ_FOREACH(node, root, conf_node_list) {
		if (node->conf->key != NULL
		    && strlen(node->conf->value) > 0
		    && strncmp(node->conf->key,
			    "PROJECT_START_CMD_",
			    strlen("PROJECT_START_CMD_")) == 0) {
			char *suffix, stop[64], health[64], restart[64];
			groups[i].start_cmd = node->conf->value;
			suffix = node->conf->key
			    + strlen("PROJECT_START_CMD_");
			xsnprintf(stop, sizeof(stop),
			    "PROJECT_STOP_CMD_%s", suffix);
			xsnprintf(health, sizeof(health),
			    "PROJECT_HEALTH_CMD_%s", suffix);
			xsnprintf(restart, sizeof(restart),
			    "RESTART_%s", suffix);
			/* Are STOP, HEALTH, RESTART set for this same child? */
			TAILQ_FOREACH(tnode, root, conf_node_list) {
				if (tnode->conf->key != NULL
				    && strcmp(tnode->conf->key, restart) == 0) {
					groups[i].restartable = 1;
				}
				if (tnode->conf->key != NULL
				    && strlen(tnode->conf->value) > 0) {
					int match;
					match = strcmp(tnode->conf->key, stop);
					if (match == 0) {
						groups[i].stop_cmd = tnode->conf->value;
					}
					match = strcmp(tnode->conf->key,
					    health);
					if (match == 0) {
						groups[i].health_cmd = tnode->conf->value;
					}
				}
			}
			i++;
		}
	}

	return (groups);
}
/* This callback is executed once per project, and will fork and execute
 * the supplied BUILD_CMD target
 */
static void
mw_conf_list_start(struct mw_conf_head *root,
		   const char *project,
		   struct callback_args *args)
{
	struct conf_list_entry *node;
	struct sigaction sa;
	struct timeval tv;
	FILE *logfp, *pidfp;
	struct nanny_child *firstchild, *child;
	struct cmd_group *groups;
	char buf[256];
	char *appdir, *datadir, *logdir, **envp, *cmdfile, *prestartcmd;
	int devnullfd, logfd;
	size_t i = 0;
	pid_t pid;

	logfd = args->logfd;

	if ((logfp = fdopen(logfd, "a")) == NULL) {
		fprintf(stderr, "fdopen failure\n");
		exit(1);
	}


	if (mw_project_running(root, project)) {
		fprintf(stderr,
			"project %s is already running\n",
			project);
		mw_log(logfp,
			"project %s is already running",
			project);
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "start",
		    mw_get_config_var(root, PROJECT_SVN));
		return;
	}
	/* Pre-start commands are executed before start, and we wait
	 * for their completion before continuing startup.  We log their output
	 * to the standard mwbuild logs. */
	prestartcmd = mw_get_config_var(root, "PROJECT_PRESTART_CMD");
	if (prestartcmd != NULL) {
		if (mw_fork_and_wait(prestartcmd, "prestart", root, project,
		    args->opt_state->verbose, logfd, logfp) != 0) {
			mw_log(logfp, "project %s pre-start command failed. Exiting.");
			fprintf(stderr,
				"project %s pre-start command failed. Exiting",
				project);
			syslog(LOG_ERR,
				"mwbuild: project %s pre-start command failed for %s. Exitng.",
				project, mw_get_config_var(root, PROJECT_SVN));
			exit(1);
		}
	}

	/* Fork and have the child execute the START_CMD script  */
	printf("Starting project '%s'\n", project);
	mw_log(logfp, "starting %s", project);
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
		exit(1);
	} else if (pid == 0) {
		/* TODO: If args->opt_state->verbose, give more
		 * detailed progress to stdout. */
		groups = mw_get_cmd_groups(root, project);
		cmdfile = mw_get_config_var(root, "PROJECT_CMD_FILE");
		logdir = mw_get_config_var(root, PROJECT_LOGDIR);
		envp = mw_build_environment(root, 1);
		setsid();
		/* Change working dir to project base */
		appdir = mw_get_config_var(root, PROJECT_APPDIR);
		datadir = mw_get_config_var(root, PROJECT_DATADIR);
		if (chdir(appdir) == -1) {
			fprintf(stderr, "Failed to chdir to %s: %s\n",
				appdir, strerror(errno));
			goto err;
		}
		/* Write out PID */
		pid = getpid();
		(void) mw_mkpath(datadir);
		xsnprintf(buf, sizeof(buf), "%s/_mwbuild", datadir);
		(void) mw_mkpath(buf);
		xsnprintf(buf, sizeof(buf), "%s/_mwbuild/%s.pid",
		    datadir, project);
		if ((pidfp = fopen(buf, "w+")) == NULL) {
			goto err;
		}
		fprintf(pidfp, "%d\n", pid);
		fclose(pidfp);
		mw_log(logfp, "nanny %s: wrote pid (%d) to file %s",
		    project, pid, buf);

		(void) mw_mkpath(mw_get_config_var(root, PROJECT_LOGDIR));
		for (i = 0; groups[i].start_cmd != NULL; i++) {
			mw_log(logfp, "nanny %s: starting child: %s",
			    project, groups[i].start_cmd);
			child = nanny_child_new(groups[i].start_cmd);
			if (groups[i].stop_cmd != NULL)
				nanny_child_set_stop(child, groups[i].stop_cmd);
			if (groups[i].health_cmd != NULL)
				nanny_child_set_health(child,
				    groups[i].health_cmd);
			nanny_child_set_envp(child, (const char **)envp);
			nanny_child_set_restartable(child,
			    groups[i].restartable);
			if (i == 0)
				firstchild = child;

			nanny_log_set_filename(child->child_stdout, "%s/%s-nanny-stdout-%d.log",
			    logdir, project, i);
			nanny_log_set_filename(child->child_stderr, "%s/%s-nanny-stderr-%d.log",
			    logdir, project, i);
			nanny_log_set_filename(child->child_events, "%s/%s-nanny-events-%d.log",
			    logdir, project, i);
		}
		if (cmdfile != NULL) {
			mw_handle_project_cmd_file(cmdfile, logdir, project,
			    logfp, (const char **)envp);
		}

		nanny_globals.nanny_pid = pid;
		/* We need to handle shutdown requests carefully to ensure
		 * that our children are properly signalled. */
		sa.sa_handler = stophandler;
		sa.sa_flags = 0;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGHUP, &sa, NULL);
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGQUIT, &sa, NULL);
		sigaction(SIGABRT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		mw_log(logfp, "nanny %s: created child", project);

		/* Timed operation support: look up all configuration
		 * variables starting with "TIMED_" and install them - unless
		 * their value is the empty string */
		TAILQ_FOREACH(node, root, conf_node_list) {
			if (node->conf->key != NULL
			    && strlen(node->conf->value) > 0
			    && strncmp(node->conf->key,
				    "PROJECT_TIMED_",
				    strlen("PROJECT_TIMED_")) == 0) {
				nanny_child_add_periodic(firstchild,
				    node->conf->value);
				mw_log(logfp,
				    "nanny %s: added periodic operation: %s",
				    project, node->conf->value);
			}
		}

		/* Create a UDP server bound to a well-known multicast socket.
		 */
		udp_server_init("226.1.1.1", 8889);
		/* Ditto, using an anonymous unicast socket. */
		/* Note: udp_announce() will use this unicast socket. */
		udp_server_init(NULL, -1);
		mw_log(logfp, "nanny %s: created UDP servers", project);
		/* Create an HTTP server on an anonymous socket using
		 * http_dispatcher. */
		http_server_init(http_dispatcher);
		mw_log(logfp, "nanny %s: created HTTP server", project);
		setproctitle("nanny: %s HTTP_PORT: %d", project,
		    nanny_globals.http_port);

		/* Announce our HTTP port to multicast group (sent from unicast
		 * socket). */
		printf("nanny: %s http://localhost:%d/\n", project,
		    nanny_globals.http_port);
		udp_announce("HTTP_PORT=%d", nanny_globals.http_port);
		mw_log(logfp,
		    "nanny %s: announced HTTP port to multicast group",
		    project);
		syslog(LOG_INFO,
		    "mwbuild: %s succeeded for %s", "start",
		    mw_get_config_var(root, PROJECT_SVN));

		/* Now that we're really running, close up stdio. */
		/* By putting this off, we retain the ability to print
		 * error messages up until this point. */
		if ((devnullfd = open("/dev/null", O_RDWR)) == -1) {
			goto err;
		}
		if (dup2(devnullfd, STDIN_FILENO) == -1) {
			goto err;
		}

		/* XXX TODO: Provide a command-line option to disable the
		 * stdout/stderr redirects.  Then simple logging to
		 * stdout/stderr can be used to diagnose configuration
		 * problems. */
		if (dup2(logfd, STDOUT_FILENO) == -1) {
			goto err;
		}
		if (dup2(logfd, STDERR_FILENO) == -1) {
			goto err;
		}

		/* Alternately process timers and wait for network io. */
		printf("Nanny:  running...\n");
		while (running) {
			/* Handle sigchld events that may have occurred. */
			nanny_oversee_children();
			/* Service timers and compute delay until the next
			 * timer expires. */
			nanny_timer_next(&tv, NULL);
			/* Wait for network io, a timeout, or a signal. */
			nanny_select(&tv);
		}
		printf("Nanny:  shutting down...\n");
		mw_log(logfp, "nanny %s: exited main loop, cleaning up",
		    project);

		/* We're no longer running, so start shutting things down. */
		/* Same loop as above, but with a different exit condition. */
		while (nanny_stop_all_children()) {
			nanny_oversee_children();
			nanny_timer_next(&tv, NULL);
			nanny_select(&tv);
		}
		mw_log(logfp, "nanny %s: cleanup complete", project);
		printf("Nanny:  exiting.\n");

		/* must forked exit process at this point, otherwise we will
		 * continue the 'startup' action after kill signal! */

		_exit(0);
err:
		syslog(LOG_ERR,
		    "mwbuild: %s failed for %s", "start",
		    mw_get_config_var(root, PROJECT_SVN));
		_exit(1);
	} else {
		/* In the parent. */
		sleep(1); /* Wait for nanny to start up. */
		if (args->opt_state->verbose)
			printf("Nanny started as process %d\n", pid);
	}
}

/*
 * Our main entry point for 'start' subcommand.
 */
svn_error_t *
svn_cl__start(apr_getopt_t *os, void *baton, apr_pool_t *pool)
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
	/* tmproot is just the machine config, which is needed to check for
	 * custom MWBUILD_* paths, which effects later actions. */
	mw_parse_config(&machine_config, config_data, 0);
	mw_set_config_defaults(&machine_config);
	mw_do_expansion(&machine_config);

	/* Open the action log */
	args.logfd = mw_open_action_log(&machine_config, "start");

	/* if we have no options, call this to print all known projects */
	if (targets->nelts == 0) {
		mw_process_machine_projects(&machine_config,
		    &mw_conf_list_start, &args);
	} else {
		for (i = 0; i < targets->nelts; i++) {
			project = ((const char **) (targets->elts))[i];
			mw_process_project_settings(&machine_config, project,
			    &mw_conf_list_start, &args);
		}
	}
	mw_free_conflist(&root, 1);

	return (SVN_NO_ERROR);
}
