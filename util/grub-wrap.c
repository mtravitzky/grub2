/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022 Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <grub/util/misc.h>
#include <grub/i18n.h>
#include <grub/term.h>
#include <grub/util/install.h>

#define _GNU_SOURCE	1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#include <argp.h>
#pragma GCC diagnostic error "-Wmissing-prototypes"
#pragma GCC diagnostic error "-Wmissing-declarations"

#include "progname.h"

struct arguments
{
  char *input;
  char *name;
  char *sbat;
  char *output;
  const struct grub_install_image_target_desc *image_target;
  int verbosity;
};

static struct argp_option options[] = {
  {"input",  'i', N_("FILE"), 0, N_("set input filename."), 0},
  {"name",  'n', N_("NAME"), 0, N_("set section name."), 0},
  {"sbat",  's', N_("FILE"), 0, N_("SBAT metadata"), 0},
  {"output",  'o', N_("FILE"), 0, N_("set output filename."), 0},
  {"format",  'O', N_("FORMAT"), 0, N_("generate an image in FORMAT"), 0},
  {"verbose",     'v', 0,      0, N_("print verbose messages."), 0},
  { 0, 0, 0, 0, 0, 0 }
};

static error_t
argp_parser (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'i':
      free (arguments->input);
      arguments->input = xstrdup (arg);
      break;

    case 'n':
      free (arguments->name);
      arguments->name = xstrdup (arg);
      break;

    case 's':
      free (arguments->sbat);
      arguments->sbat = xstrdup (arg);
      break;

    case 'o':
      free (arguments->output);
      arguments->output = xstrdup (arg);
      break;

    case 'O':
      {
	arguments->image_target = grub_install_get_image_target (arg);
	if (!arguments->image_target)
	  {
	    printf (_("unknown target format %s\n"), arg);
	    argp_usage (state);
	    exit (1);
	  }
	break;
      }

    case 'v':
      arguments->verbosity++;
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp argp = {
  options, argp_parser, N_("[OPTIONS]"),
  N_("Wrap a file as a PE image."),
  NULL, NULL, NULL
};

int
main (int argc, char *argv[])
{
  FILE *out;

  struct arguments arguments;

  grub_util_host_init (&argc, &argv);

  /* Check for options.  */
  memset (&arguments, 0, sizeof (struct arguments));
  if (argp_parse (&argp, argc, argv, 0, 0, &arguments) != 0)
    {
      fprintf (stderr, "%s", _("Error in parsing command line arguments\n"));
      exit(1);
    }

  if (!arguments.input)
    grub_util_error ("%s", _("input file must be specified"));

  if (!arguments.name)
    grub_util_error ("%s", _("section name must be specified"));

  if (!arguments.output)
    grub_util_error ("%s", _("output file must be specified"));

  if (!arguments.image_target)
    grub_util_error ("%s", _("target format must be specified"));

  out = grub_util_fopen (arguments.output, "wb");
  if (!out)
    grub_util_error (_("cannot open `%s': %s"), arguments.output, strerror (errno));

  grub_install_generate_image (NULL, NULL, out, NULL, NULL, NULL, NULL, 0,
			       NULL, 0,
			       NULL, arguments.image_target,
			       0, 0, GRUB_COMPRESSION_NONE, NULL,
			       arguments.sbat, 0,
			       arguments.input, arguments.name);

  return 0;
}
