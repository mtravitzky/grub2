/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022  Free Software Foundation, Inc.
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
 *
 *  PE unwrapper.
 */

#include <grub/file.h>
#include <grub/unwrap.h>
#include <grub/safemath.h>
#include <grub/efi/pe32.h>

struct grub_unwrapped
{
  grub_file_t file;
  void *buf;
  void *real_data;
  grub_size_t real_size;
};
typedef struct grub_unwrapped *grub_unwrapped_t;

static void
unwrapped_free (grub_unwrapped_t unwrapped)
{
  if (unwrapped)
    {
      grub_free (unwrapped->buf);
      grub_free (unwrapped);
    }
}

static grub_ssize_t
unwrapped_read (struct grub_file *file, char *buf, grub_size_t len)
{
  grub_unwrapped_t unwrapped = file->data;

  grub_memcpy (buf, (char *) unwrapped->real_data + file->offset, len);
  return len;
}

static grub_err_t
unwrapped_close (struct grub_file *file)
{
  grub_unwrapped_t unwrapped = file->data;

  grub_file_close (unwrapped->file);
  unwrapped_free (unwrapped);
  file->data = 0;

  /* Device and name are freed by parent. */
  file->device = 0;
  file->name = 0;

  return grub_errno;
}

struct grub_fs unwrapped_fs =
{
  .name = "unwrapped_read",
  .fs_read = unwrapped_read,
  .fs_close = unwrapped_close
};

static void
try_unwrap (grub_unwrapped_t unwrapped, const char (*name)[8])
{
  void *buffer = unwrapped->real_data;
  grub_size_t size = unwrapped->real_size;
  int i;
  grub_uint32_t pe_image_header, section_table;
  grub_uint16_t num_sections;
  struct grub_pe32_section_table *sections;

  pe_image_header = grub_pe32_get_pe_image_header (buffer, size);
  if (pe_image_header == 0)
    goto fail;
  grub_dprintf ("unwrap", "pe image header at 0x%" PRIxGRUB_UINT32_T ".\n", pe_image_header);

  section_table = grub_pe32_get_section_table (buffer, size, pe_image_header, &num_sections);
  if (section_table == 0)
    goto fail;
  grub_dprintf ("unwrap", "section table at 0x%" PRIxGRUB_UINT32_T ".\n", section_table);

  sections = (void *) ((char *) buffer + section_table);
  for (i = 0; i < (int) num_sections; i++)
    {
      struct grub_pe32_section_table *section = &sections[i];
      if (grub_memcmp (section->name, *name, 8) == 0)
	{
	  grub_uint32_t offset, length, end;
	  grub_memcpy (&offset, &section->raw_data_offset, sizeof (offset));
	  grub_memcpy (&length, &section->virtual_size, sizeof (length));
	  if (grub_add (offset, length, &end) || end > size)
	    goto fail;

	  grub_dprintf ("unwrap", "unwrap ok, offset 0x%" PRIxGRUB_UINT32_T ", length 0x%" PRIxGRUB_UINT32_T ".\n", offset, length);
	  unwrapped->real_data = (char *) buffer + offset;
	  unwrapped->real_size = length;
	  return;
	}
    }
  grub_dprintf ("unwrap", "section %.8s not found.\n", *name);

fail:
  grub_dprintf ("unwrap", "unwrap failed, passthrough original file.\n");
}

static grub_file_t
grub_unwrap_open (grub_file_t io, enum grub_file_type type)
{
  grub_unwrapped_t unwrapped = NULL;
  grub_file_t ret = NULL;
  char name[8] = { 0 };

  switch (type & GRUB_FILE_TYPE_MASK)
    {
    /* Only process file types we known. */
    case GRUB_FILE_TYPE_FONT:
      grub_strncpy(name, ".GRUBpf2", 8);
      break;
    case GRUB_FILE_TYPE_LINUX_INITRD:
      grub_strncpy(name, ".GRUBini", 8);
      break;

    /* Don't touch other files. */
    default:
      return io;
    }

  ret = grub_malloc (sizeof (*ret));
  if (ret == NULL)
    goto fail;
  *ret = *io;

  ret->fs = &unwrapped_fs;
  ret->not_easily_seekable = 0;
  if (ret->size >> (sizeof (grub_size_t) * GRUB_CHAR_BIT - 1))
    {
      grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		  N_("big file unwrapping isn't implemented yet"));
      goto fail;
    }

  unwrapped = grub_malloc (sizeof (*unwrapped));
  if (unwrapped == NULL)
    goto fail;

  unwrapped->buf = grub_malloc (ret->size);
  if (unwrapped->buf == NULL)
    goto fail;
  if (grub_file_read (io, unwrapped->buf, ret->size) != (grub_ssize_t) ret->size)
    {
      if (!grub_errno)
	grub_error (GRUB_ERR_FILE_READ_ERROR, N_("premature end of file %s"),
		    io->name);
      goto fail;
    }
  unwrapped->real_data = unwrapped->buf;
  unwrapped->real_size = ret->size;

  try_unwrap (unwrapped, &name);

  unwrapped->file = io;
  ret->size = unwrapped->real_size;
  ret->data = unwrapped;
  return ret;

fail:
  unwrapped_free (unwrapped);
  grub_free (ret);
  return NULL;
}

void
grub_unwrap_init (void)
{
  grub_file_filter_register (GRUB_FILE_FILTER_UNWRAP, grub_unwrap_open);
}
