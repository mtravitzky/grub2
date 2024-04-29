#include <stdbool.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include "uusb.h"
#include "scard.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define MAX_CARDOPTS	16

bool
uusb_dev_select_ccid_interface(uusb_dev_t *dev, const struct ccid_descriptor **ccid_ret)
{
  (void) dev;
  (void) ccid_ret;
  return false;
}

bool
uusb_send(uusb_dev_t *dev, buffer_t *pkt)
{
  (void) dev;
  (void) pkt;
  return false;
}

buffer_t *
uusb_recv(uusb_dev_t *dev, size_t maxlen, long timeout)
{
  (void) dev;
  (void) maxlen;
  (void) timeout;
  return NULL;
}

enum
{
  UTOKEN_OPTION_DEVICE,
  UTOKEN_OPTION_TYPE,
  UTOKEN_OPTION_PIN,
  UTOKEN_OPTION_OUTPUT,
  UTOKEN_OPTION_CARD_OPTION,
};

static const struct grub_arg_option
grub_utoken_decrypt_options[] =
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
  return GRUB_ERR_NONE;
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
