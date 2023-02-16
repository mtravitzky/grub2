#ifndef GRUB_CRYPTTAB_HEADER
#define GRUB_CRYPTTAB_HEADER 1

#include <grub/types.h>
#include <grub/err.h>

struct grub_key_publisher
{
  struct grub_key_publisher *next;
  struct grub_key_publisher **prev;
  char *name; /* UUID */
  char *path;
  char *key;
  grub_size_t key_len;
};

extern struct grub_key_publisher *EXPORT_VAR (kpuber);

grub_err_t
grub_initrd_publish_key (const char *uuid, const char *key, grub_size_t key_len, const char *path);

#endif /* ! GRUB_CRYPTTAB_HEADER */
