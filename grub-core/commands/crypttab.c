
#include <grub/dl.h>
#include <grub/command.h>
#include <grub/misc.h>
#include <grub/i18n.h>
#include <grub/mm.h>
#include <grub/list.h>
#include <grub/crypttab.h>

GRUB_MOD_LICENSE ("GPLv3+");

struct grub_key_publisher *kpuber;

grub_err_t
grub_initrd_publish_key (const char *uuid, const char *key, grub_size_t key_len, const char *path)
{
  struct grub_key_publisher *cur =  grub_named_list_find (GRUB_AS_NAMED_LIST (kpuber), uuid);

  if (!cur)
    cur = grub_zalloc (sizeof (*cur));
  if (!cur)
    return grub_errno;

  if (key && key_len)
    {
      grub_free (cur->key);
      cur->key = grub_malloc (key_len);
      if (!cur->key)
	{
	  grub_free (cur);
	  return grub_errno;
	}
      grub_memcpy (cur->key, key, key_len);
      cur->key_len = key_len;
    }

  if (path)
    {
      grub_free (cur->path);
      cur->path = grub_strdup (path);
    }

  if (!cur->name)
    {
      cur->name = grub_strdup (uuid);
      grub_list_push (GRUB_AS_LIST_P (&kpuber), GRUB_AS_LIST (cur));
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_crypttab_entry (grub_command_t cmd __attribute__ ((unused)),
	       int argc, char **argv)
{
  char buf[256];
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
