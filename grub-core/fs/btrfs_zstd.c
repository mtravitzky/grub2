
#include <grub/types.h>
#include <grub/dl.h>
/* For NULL.  */
#include <grub/mm.h>
#include <grub/btrfs.h>
#include <grub/lib/zstd.h>

GRUB_MOD_LICENSE ("GPLv3+");

GRUB_MOD_INIT (btrfs_zstd)
{
  grub_btrfs_zstd_decompress_func = grub_zstd_decompress;
}

GRUB_MOD_FINI (btrfs_zstd)
{
  grub_btrfs_zstd_decompress_func = NULL;
}
