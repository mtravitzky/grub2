
#include <grub/dl.h>
#include <grub/command.h>
#include <grub/misc.h>
#include <grub/i18n.h>
#include <grub/linux.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_cmd_crypttab_entry (grub_command_t cmd __attribute__ ((unused)),
	       int argc, char **argv)
{
  char buf[64];
  const char *path = NULL;

  if (argc == 2)
    path = NULL;
  else if (argc == 3)
    path = argv[2];
  else
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("two or three arguments expected"));

  if (!path
      || grub_strcmp (path, "none") == 0
      || grub_strcmp (path, "-") == 0)
    {
      grub_snprintf (buf, sizeof (buf), "/etc/cryptsetup-keys.d/%s.key", argv[0]);
      path = buf;
    }

  /*FIXME: Validate UUID string*/
  return grub_initrd_publish_key (argv[1], NULL, 0, path);
}

static grub_command_t cmd;

GRUB_MOD_INIT(crypttab)
{
  cmd = grub_register_command ("crypttab_entry", grub_cmd_crypttab_entry,
			       N_("VOLUME-NAME ENCRYPTED-DEVICE KEY-FILE") , N_("No description"));
}

GRUB_MOD_FINI(crypttab)
{
  grub_unregister_command (cmd);
}
