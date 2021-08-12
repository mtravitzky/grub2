
/*
 * Tell zstd to expose functions that aren't part of the stable API, which
 * aren't safe to use when linking against a dynamic library. We vendor in a
 * specific zstd version, so we know what we're getting. We need these unstable
 * functions to provide our own allocator, which uses grub_malloc(), to zstd.
 */
#define ZSTD_STATIC_LINKING_ONLY

#include <grub/types.h>
#include <grub/err.h>
#include <grub/btrfs.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <zstd.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define ZSTD_BTRFS_MAX_WINDOWLOG 17
#define ZSTD_BTRFS_MAX_INPUT     (1 << ZSTD_BTRFS_MAX_WINDOWLOG)

static void *grub_zstd_malloc (void *state __attribute__((unused)), size_t size)
{
  return grub_malloc (size);
}

static void grub_zstd_free (void *state __attribute__((unused)), void *address)
{
  return grub_free (address);
}

static ZSTD_customMem grub_zstd_allocator (void)
{
  ZSTD_customMem allocator;

  allocator.customAlloc = &grub_zstd_malloc;
  allocator.customFree = &grub_zstd_free;
  allocator.opaque = NULL;

  return allocator;
}

static grub_ssize_t
grub_btrfs_zstd_decompress_real (char *ibuf, grub_size_t isize, grub_off_t off,
				 char *obuf, grub_size_t osize)
{
  void *allocated = NULL;
  char *otmpbuf = obuf;
  grub_size_t otmpsize = osize;
  ZSTD_DCtx *dctx = NULL;
  grub_size_t zstd_ret;
  grub_ssize_t ret = -1;

  /*
   * Zstd will fail if it can't fit the entire output in the destination
   * buffer, so if osize isn't large enough, allocate a temporary buffer.
   */
  if (otmpsize < ZSTD_BTRFS_MAX_INPUT)
    {
      allocated = grub_malloc (ZSTD_BTRFS_MAX_INPUT);
      if (!allocated)
	{
	  grub_error (GRUB_ERR_OUT_OF_MEMORY, "failed allocate a zstd buffer");
	  goto err;
	}
      otmpbuf = (char *) allocated;
      otmpsize = ZSTD_BTRFS_MAX_INPUT;
    }

  /* Create the ZSTD_DCtx. */
  dctx = ZSTD_createDCtx_advanced (grub_zstd_allocator ());
  if (!dctx)
    {
      /* ZSTD_createDCtx_advanced() only fails if it is out of memory. */
      grub_error (GRUB_ERR_OUT_OF_MEMORY, "failed to create a zstd context");
      goto err;
    }

  /*
   * Get the real input size, there may be junk at the
   * end of the frame.
   */
  isize = ZSTD_findFrameCompressedSize (ibuf, isize);
  if (ZSTD_isError (isize))
    {
      grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "zstd data corrupted");
      goto err;
    }

  /* Decompress and check for errors. */
  zstd_ret = ZSTD_decompressDCtx (dctx, otmpbuf, otmpsize, ibuf, isize);
  if (ZSTD_isError (zstd_ret))
    {
      grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "zstd data corrupted");
      goto err;
    }

  /*
   * Move the requested data into the obuf. obuf may be equal
   * to otmpbuf, which is why grub_memmove() is required.
   */
  grub_memmove (obuf, otmpbuf + off, osize);
  ret = osize;

err:
  grub_free (allocated);
  ZSTD_freeDCtx (dctx);

  return ret;
}

GRUB_MOD_INIT (btrfs_zstd)
{
  grub_btrfs_zstd_decompress = grub_btrfs_zstd_decompress_real;
}

GRUB_MOD_FINI (btrfs_zstd)
{
  grub_btrfs_zstd_decompress = NULL;
}
