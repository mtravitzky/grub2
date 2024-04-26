/*
 *   Copyright (C) 2023 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#if 1
#include <grub/dl.h>
#include <grub/extcmd.h>
#endif
#include "uusb.h"
#include "scard.h"

#define le16toh(x) grub_le_to_cpu16(x)
#define le32toh(x) grub_le_to_cpu32(x)
#define le64toh(x) grub_le_to_cpu64(x)
#define htole16(x) grub_cpu_to_le16(x)
#define htole32(x) grub_cpu_to_le32(x)
#define htole64(x) grub_cpu_to_le64(x)
#include "bufparser.h"
#include "util.h"

GRUB_MOD_LICENSE ("GPLv3+");

#if 0
static struct option	options[] = {
	{ "device",	required_argument,	NULL,	'D' },
	{ "type",	required_argument,	NULL,	'T' },
	{ "pin",	required_argument,	NULL,	'p' },
	{ "output",	required_argument,	NULL,	'o' },
	{ "card-option",required_argument,	NULL,	'C' },
	{ "debug",	no_argument,		NULL,	'd' },
	{ "help",	no_argument,		NULL,	'h' },
	{ NULL }
};

#else
enum
{
  UTOKEN_OPTION_DEVICE,
  UTOKEN_OPTION_TYPE,
  UTOKEN_OPTION_PIN,
  UTOKEN_OPTION_OUTPUT,
  UTOKEN_OPTION_CARD_OPTION,
};

static const struct grub_arg_option grub_utoken_decrypt_options[] =
  {
    {
      .longarg  = "device",
      .shortarg = 'D',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_(""),
    },
    {
      .longarg  = "type",
      .shortarg = 'T',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_(""),
    },
    {
      .longarg  = "pin",
      .shortarg = 'p',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_(""),
    },
    {
      .longarg  = "output",
      .shortarg = 'o',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_(""),
    },
    {
      .longarg  = "card-option",
      .shortarg = 'C',
      .flags    = GRUB_ARG_OPTION_REPEATABLE,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_(""),
    },
    /* End of list */
    {0, 0, 0, 0, 0, 0}
  };
#endif

#if 0
unsigned int	opt_debug = 0;
#endif

static buffer_t *	doit(uusb_dev_t *dev, const char *pin, buffer_t *secret, unsigned int ncardopts, char **cardopts);

#define MAX_CARDOPTS	16

#if 0
int
main(int argc, char **argv)
#endif
static grub_err_t
grub_utoken_decrypt (grub_extcmd_context_t ctxt,
    int argc,
    char **args)
{
	char *opt_device = NULL;
	char *opt_type = NULL;
	char *opt_pin = NULL;
	char *opt_input = NULL;
	char *opt_output = NULL;
	char *cardopts[MAX_CARDOPTS];
	unsigned int ncardopts = 0;
	buffer_t *secret;
	uusb_dev_t *dev = NULL;
	buffer_t *cleartext;
#if 0
	int c;
	while ((c = getopt_long(argc, argv, "dhC:D:T:p:o:", options, NULL)) != -1) {
		switch (c) {
		case 'h':
			printf("Sorry, no help message. Please refer to the README.\n");
			exit(0);

		case 'd':
			opt_debug++;
			break;

		case 'C':
			if (ncardopts >= MAX_CARDOPTS) {
				error("Too many card options\n");
				return 1;
			}

			cardopts[ncardopts++] = optarg;
			break;

		case 'D':
			opt_device = optarg;
			break;

		case 'T':
			opt_type = optarg;
			break;

		case 'p':
			opt_pin = optarg;
			break;

		case 'o':
			opt_output = optarg;
			break;

		default:
			error("Unknown option %c\n", c);
			return 1;
		}
	}

	if (optind == argc) {
		opt_input = "-";
		infomsg("Reading data from standard input\n");
	} else {
		opt_input = argv[optind++];
		infomsg("Reading data from \"%s\"\n", opt_input);
	}

	if (optind != argc) {
		error("Expected at most one non-positional argument\n");
		return 1;
	}
#else
  struct grub_arg_list *state = ctxt->state;

  if (!argc)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "no secret file provided");

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "expect only one secret file");

  if (state[UTOKEN_OPTION_DEVICE].set)
    opt_device = state[UTOKEN_OPTION_DEVICE].arg;

  if (state[UTOKEN_OPTION_TYPE].set)
    opt_type = state[UTOKEN_OPTION_TYPE].arg;

  if (state[UTOKEN_OPTION_PIN].set)
    opt_pin = state[UTOKEN_OPTION_PIN].arg;

  if (state[UTOKEN_OPTION_OUTPUT].set)
    opt_output = state[UTOKEN_OPTION_OUTPUT].arg;

  if (state[UTOKEN_OPTION_CARD_OPTION].set)
    {
      int i;

      for (ncardopts = 0; state[UTOKEN_OPTION_CARD_OPTION].args[ncardopts]; ncardopts++);

      if (ncardopts > MAX_CARDOPTS)
	return grub_error (GRUB_ERR_BAD_ARGUMENT, "Too many card options");

      for (i = 0; i < ncardopts; i++)
	cardopts[i] = state[UTOKEN_OPTION_CARD_OPTION].args[i];
    }

  opt_input = args[0];
#endif

	secret = buffer_read_file(opt_input, 0);

	(void) opt_device;

	if (opt_type) {
		uusb_type_t type;

		if (!usb_parse_type(opt_type, &type))
#if 0
			return 1;
#else
			return GRUB_ERR_BAD_ARGUMENT;
#endif
		dev = usb_open_type(&type);
	}

	if (dev == NULL) {
		error("Did not find USB device\n");
#if 0
		return 1;
#else
		return GRUB_ERR_BAD_ARGUMENT;
#endif
	}

	yubikey_init();

	if (!(cleartext = doit(dev, opt_pin, secret, ncardopts, cardopts)))
#if 0
		return 1;
#else
		return GRUB_ERR_BUG;
#endif

	infomsg("Writing data to \"%s\"\n", opt_output?: "<stdout>");
	if (!buffer_write_file(opt_output, cleartext))
		return 1;

	buffer_free(cleartext);
#if 0
	return 0;
#else
	return GRUB_ERR_NONE;
#endif
}

buffer_t *
doit(uusb_dev_t *dev, const char *pin, buffer_t *ciphertext, unsigned int ncardopts, char **cardopts)
{
	ccid_reader_t *reader;
	ifd_card_t *card;
	buffer_t *cleartext;

	if (!(reader = ccid_reader_create(dev))) {
		error("Unable to create reader for USB device\n");
		return NULL;
	}

	if (!ccid_reader_select_slot(reader, 0))
		return NULL;

	card = ccid_reader_identify_card(reader, 0);
	if (card == NULL)
		return NULL;

	if (ncardopts) {
		unsigned int i;
		for (i = 0; i < ncardopts; ++i) {
			if (!ifd_card_set_option(card, cardopts[i]))
				return NULL;
		}
	}

	if (!ifd_card_connect(card))
		return NULL;

	if (pin != NULL) {
		unsigned int retries_left;

		if (!ifd_card_verify(card, pin, strlen(pin), &retries_left)) {
			error("Wrong PIN, %u attempts left\n", retries_left);
			return NULL;
		}

		infomsg("Successfully verified PIN.\n");
	}

	cleartext = ifd_card_decipher(card, ciphertext);
	if (cleartext == NULL) {
		error("Card failed to decrypt secret\n");
		return NULL;
	}

	return cleartext;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(utoken_decrypt)
{
  cmd = grub_register_extcmd ("utoken_decrypt",
	grub_utoken_decrypt, 0,
	N_("[-D device] "
	   "[-T type] "
	   "[-p pin] "
	   "[-o output] "
	   "[-C card-option] "
	   "secret_file"),
	N_("Decrypt secret_file by USB CCID device."),
	grub_utoken_decrypt_options);
}

GRUB_MOD_FINI(utoken_decrypt)
{
  grub_unregister_extcmd (cmd);
}

