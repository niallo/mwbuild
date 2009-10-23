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


#include "svn_client.h"
#include "svn_path.h"
#include "svn_error.h"
#include "svn_pools.h"
#include "cl.h"

#include "svn_private_config.h"

static void mw_conf_list_printer(struct mw_conf_head *, const char *, struct callback_args *);

static void
mw_conf_list_printer(struct mw_conf_head *config, const char *project, struct callback_args *arg)
{
	struct conf_list_entry *node;
	printf("[project:%s]\n", project);
	TAILQ_FOREACH(node, config, conf_node_list) {
		if (node->conf->value != NULL && node->conf->key != NULL)
			printf("%s=\"%s\"\n", node->conf->key,
			    node->conf->value);
	}
}

/*
 * Our main entry point for 'query' subcommand.
 */
svn_error_t *
svn_cl__query(apr_getopt_t *os, void *baton, apr_pool_t *pool)
{
	svn_cl__opt_state_t *opt_state = ((svn_cl__cmd_baton_t *) baton)->opt_state;
	svn_client_ctx_t *ctx = ((svn_cl__cmd_baton_t *) baton)->ctx;
	apr_array_header_t *targets;
	struct callback_args args;
	struct mw_conf_head machine_config, root;
	struct mw_config_data *config_data;
	const char *project;
	int i;


	TAILQ_INIT(&machine_config);
	TAILQ_INIT(&root);

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
	/* if we have no options, call this to print all known projects */
	if (targets->nelts == 0) {
		mw_process_machine_projects(&machine_config,
		    &mw_conf_list_printer, &args);
	} else {
		for (i = 0; i < targets->nelts; i++) {
			project = ((const char **) (targets->elts))[i];
			mw_process_project_settings(&machine_config, project,
			    &mw_conf_list_printer, &args);
		}
	}
	mw_free_conflist(&root, 1);

	return (SVN_NO_ERROR);
}
