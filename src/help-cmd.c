/*
 * help-cmd.c -- Provide help
 *
 * ====================================================================
 * Copyright (c) 2000-2004 CollabNet.  All rights reserved.
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

#include "svn_string.h"
#include "svn_error.h"
#include "svn_version.h"
#include "cl.h"

#include "svn_private_config.h"


/*** Code. ***/

/* This implements the `svn_opt_subcommand_t' interface. */
svn_error_t *
svn_cl__help(apr_getopt_t *os,
             void *baton,
             apr_pool_t *pool)
{
  svn_cl__opt_state_t *opt_state;

  /* xgettext: the %s is for SVN_VER_NUMBER. */
  char help_header_template[] =
  N_("usage: mw <subcommand> [options] [args]\n"
     "Metaweb Build version 4.\n"
     "Type 'mw help <subcommand>' for help on a specific subcommand.\n"
     "\n"
     "Most subcommands take instance arguments.\n"
     "If no arguments are supplied to such a\n"
     "command, it operates on all instances by default.\n"
     "\n"
     "Available subcommands:\n");

  char help_footer[] =
  N_("");

  char *help_header =
    apr_psprintf(pool, _(help_header_template));

  const char *ra_desc_start
    = _("");

  svn_stringbuf_t *version_footer;

  if (baton)
    opt_state = ((svn_cl__cmd_baton_t *) baton)->opt_state;
  else
    opt_state = NULL;

  version_footer = svn_stringbuf_create(ra_desc_start, pool);

  return svn_opt_print_help2(os,
                             "mw",   /* ### erm, derive somehow? */
                             FALSE,
                             FALSE,
                             version_footer->data,
                             help_header,   /* already gettext()'d */
                             svn_cl__cmd_table,
                             svn_cl__options,
                             _(help_footer),
                             pool);
}