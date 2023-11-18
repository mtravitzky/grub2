/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2004,2005,2006,2007,2008,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_DISK_HEADER
#define GRUB_DISK_HEADER	1

#include <config.h>

#include <grub/symbol.h>
#include <grub/err.h>
#include <grub/types.h>
#include <grub/device.h>
/* For NULL.  */
#include <grub/mm.h>
/* For ALIGN_UP.  */
#include <grub/misc.h>

/* These are used to set a device id. When you add a new disk device,
   you must define a new id for it here.  */
enum grub_disk_dev_id
  {
    GRUB_DISK_DEVICE_BIOSDISK_ID,
    GRUB_DISK_DEVICE_OFDISK_ID,
    GRUB_DISK_DEVICE_LOOPBACK_ID,
    GRUB_DISK_DEVICE_EFIDISK_ID,
    GRUB_DISK_DEVICE_DISKFILTER_ID,
    GRUB_DISK_DEVICE_HOST_ID,
    GRUB_DISK_DEVICE_ATA_ID,
    GRUB_DISK_DEVICE_MEMDISK_ID,
    GRUB_DISK_DEVICE_NAND_ID,
    GRUB_DISK_DEVICE_SCSI_ID,
    GRUB_DISK_DEVICE_CRYPTODISK_ID,
    GRUB_DISK_DEVICE_ARCDISK_ID,
    GRUB_DISK_DEVICE_HOSTDISK_ID,
    GRUB_DISK_DEVICE_PROCFS_ID,
    GRUB_DISK_DEVICE_CBFSDISK_ID,
    GRUB_DISK_DEVICE_UBOOTDISK_ID,
    GRUB_DISK_DEVICE_XEN,
    GRUB_DISK_DEVICE_OBDISK_ID,
  };

struct grub_disk;
#ifdef GRUB_UTIL
struct grub_disk_memberlist;
#endif

typedef enum
  {
    GRUB_DISK_PULL_NONE,
    GRUB_DISK_PULL_REMOVABLE,
    GRUB_DISK_PULL_RESCAN,
    GRUB_DISK_PULL_MAX
  } grub_disk_pull_t;

typedef int (*grub_disk_dev_iterate_hook_t) (const char *name, void *data);

/* Disk device.  */
struct grub_disk_dev
{
  /* The device name.  */
  const char *name;

  /* The device id used by the cache manager.  */
  enum grub_disk_dev_id id;

  /* Call HOOK with each device name, until HOOK returns non-zero.  */
  int (*disk_iterate) (grub_disk_dev_iterate_hook_t hook, void *hook_data,
		  grub_disk_pull_t pull);

  /* Open the device named NAME, and set up DISK.  */
  grub_err_t (*disk_open) (const char *name, struct grub_disk *disk);

  /* Close the disk DISK.  */
  void (*disk_close) (struct grub_disk *disk);

  /* Read SIZE sectors from the sector SECTOR of the disk DISK into BUF.  */
  grub_err_t (*disk_read) (struct grub_disk *disk, grub_disk_addr_t sector,
		      grub_size_t size, char *buf);

  /* Write SIZE sectors from BUF into the sector SECTOR of the disk DISK.  */
  grub_err_t (*disk_write) (struct grub_disk *disk, grub_disk_addr_t sector,
		       grub_size_t size, const char *buf);

#ifdef GRUB_UTIL
  struct grub_disk_memberlist *(*disk_memberlist) (struct grub_disk *disk);
  const char * (*disk_raidname) (struct grub_disk *disk);
#endif

  /* The next disk device.  */
  struct grub_disk_dev *next;
};
typedef struct grub_disk_dev *grub_disk_dev_t;

extern grub_disk_dev_t EXPORT_VAR (grub_disk_dev_list);

struct grub_partition;

typedef grub_err_t (*grub_disk_read_hook_t) (grub_disk_addr_t sector,
					     unsigned offset, unsigned length,
					     char *buf, void *data);

/* Disk.  */
struct grub_disk
{
  /* The disk name.  */
  const char *name;

  /* The underlying disk device.  */
  grub_disk_dev_t dev;

  /* The total number of sectors.  */
  grub_uint64_t total_sectors;

  /* Logarithm of sector size.  */
  unsigned int log_sector_size;

  /* Maximum number of sectors read divided by GRUB_DISK_CACHE_SIZE.  */
  unsigned int max_agglomerate;

  /* The id used by the disk cache manager.  */
  unsigned long id;

  /* The partition information. This is machine-specific.  */
  struct grub_partition *partition;

  /* Called when a sector was read. OFFSET is between 0 and
     the sector size minus 1, and LENGTH is between 0 and the sector size.  */
  grub_disk_read_hook_t read_hook;

  /* Caller-specific data passed to the read hook.  */
  void *read_hook_data;

  /* Device-specific data.  */
  void *data;

  int is_crypto_diskfilter;
};
typedef struct grub_disk *grub_disk_t;

#ifdef GRUB_UTIL
struct grub_disk_memberlist
{
  grub_disk_t disk;
  struct grub_disk_memberlist *next;
};
typedef struct grub_disk_memberlist *grub_disk_memberlist_t;
#endif

/* The sector size.  */
#define GRUB_DISK_SECTOR_SIZE	0x200
#define GRUB_DISK_SECTOR_BITS	9

/*
 * Some drivers have problems with disks above reasonable sizes.
 * Set max disk size at 1 EiB.
 */
#define GRUB_DISK_MAX_SECTORS	(1ULL << (60 - GRUB_DISK_SECTOR_BITS))

/* The maximum number of disk caches.  */
#define GRUB_DISK_CACHE_NUM	1021

/*
 * The maximum number of disks in an mdraid device.
 *
 * GET_DISK_INFO nr_disks (total count) does not map to disk.number,
 * which is an internal kernel index. Instead, do what mdadm does
 * and keep scanning until we find enough valid disks. The limit is
 * copied from there, which notes that it is sufficiently high given
 * that the on-disk metadata for v1.x can only support 1920.
 */
#define GRUB_MDRAID_MAX_DISKS	4096

/* The size of a disk cache in 512B units. Must be at least as big as the
   largest supported sector size, currently 16K.  */
#define GRUB_DISK_CACHE_BITS	6
#define GRUB_DISK_CACHE_SIZE	(1 << GRUB_DISK_CACHE_BITS)

#define GRUB_DISK_MAX_MAX_AGGLOMERATE ((1 << (30 - GRUB_DISK_CACHE_BITS - GRUB_DISK_SECTOR_BITS)) - 1)

/* Maximum number of sectors to read in LBA mode at once. */
#define GRUB_DISK_MAX_LBA_SECTORS 63

/* Return value of grub_disk_native_sectors() in case disk size is unknown. */
#define GRUB_DISK_SIZE_UNKNOWN	 0xffffffffffffffffULL

#define GRUB_DISK_KiB_TO_SECTORS(x) ((x) << (10 - GRUB_DISK_SECTOR_BITS))

/* Convert sector number from one sector size to another. */
static inline grub_disk_addr_t
grub_convert_sector (grub_disk_addr_t sector,
		     grub_size_t log_sector_size_from,
		     grub_size_t log_sector_size_to)
{
  if (log_sector_size_from == log_sector_size_to)
    return sector;
  else if (log_sector_size_from < log_sector_size_to)
    {
      sector = ALIGN_UP (sector, 1 << (log_sector_size_to - log_sector_size_from));
      return sector >> (log_sector_size_to - log_sector_size_from);
    }
  else
    return sector << (log_sector_size_from - log_sector_size_to);
}

/* Convert to GRUB native disk sized sector from disk sized sector. */
static inline grub_disk_addr_t
grub_disk_from_native_sector (grub_disk_t disk, grub_disk_addr_t sector)
{
  return sector << (disk->log_sector_size - GRUB_DISK_SECTOR_BITS);
}

/* Convert from GRUB native disk sized sector to disk sized sector. */
static inline grub_disk_addr_t
grub_disk_to_native_sector (grub_disk_t disk, grub_disk_addr_t sector)
{
  return sector >> (disk->log_sector_size - GRUB_DISK_SECTOR_BITS);
}

/* This is called from the memory manager.  */
void grub_disk_cache_invalidate_all (void);

void EXPORT_FUNC(grub_disk_dev_register) (grub_disk_dev_t dev);
void EXPORT_FUNC(grub_disk_dev_unregister) (grub_disk_dev_t dev);
static inline int
grub_disk_dev_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data)
{
  grub_disk_dev_t p;
  grub_disk_pull_t pull;

  for (pull = 0; pull < GRUB_DISK_PULL_MAX; pull++)
    for (p = grub_disk_dev_list; p; p = p->next)
      if (p->disk_iterate && (p->disk_iterate) (hook, hook_data, pull))
	return 1;

  return 0;
}

grub_disk_t EXPORT_FUNC(grub_disk_open) (const char *name);
void EXPORT_FUNC(grub_disk_close) (grub_disk_t disk);
grub_err_t EXPORT_FUNC(grub_disk_read) (grub_disk_t disk,
					grub_disk_addr_t sector,
					grub_off_t offset,
					grub_size_t size,
					void *buf);
grub_err_t grub_disk_write_tail (grub_disk_t disk,
			       grub_size_t size,
			       const void *buf);
grub_err_t grub_disk_write (grub_disk_t disk,
			    grub_disk_addr_t sector,
			    grub_off_t offset,
			    grub_size_t size,
			    const void *buf);
extern grub_err_t (*EXPORT_VAR(grub_disk_write_weak)) (grub_disk_t disk,
						       grub_disk_addr_t sector,
						       grub_off_t offset,
						       grub_size_t size,
						       const void *buf);


grub_uint64_t EXPORT_FUNC(grub_disk_native_sectors) (grub_disk_t disk);

#if DISK_CACHE_STATS
void
EXPORT_FUNC(grub_disk_cache_get_performance) (unsigned long *hits, unsigned long *misses);
#endif

extern void (* EXPORT_VAR(grub_disk_firmware_fini)) (void);
extern int EXPORT_VAR(grub_disk_firmware_is_tainted);

static inline void
grub_stop_disk_firmware (void)
{
  /* To prevent two drivers operating on the same disks.  */
  grub_disk_firmware_is_tainted = 1;
  if (grub_disk_firmware_fini)
    {
      grub_disk_firmware_fini ();
      grub_disk_firmware_fini = NULL;
    }
}

/* Disk cache.  */
struct grub_disk_cache
{
  enum grub_disk_dev_id dev_id;
  unsigned long disk_id;
  grub_disk_addr_t sector;
  char *data;
  int lock;
};

extern struct grub_disk_cache EXPORT_VAR(grub_disk_cache_table)[GRUB_DISK_CACHE_NUM];

#if defined (GRUB_UTIL)
void grub_lvm_init (void);
void grub_ldm_init (void);
void grub_mdraid09_init (void);
void grub_mdraid1x_init (void);
void grub_diskfilter_init (void);
void grub_lvm_fini (void);
void grub_ldm_fini (void);
void grub_mdraid09_fini (void);
void grub_mdraid1x_fini (void);
void grub_diskfilter_fini (void);
#endif

static inline int
grub_disk_is_crypto (grub_disk_t disk)
{
  return ((disk->is_crypto_diskfilter ||
	   disk->dev->id == GRUB_DISK_DEVICE_CRYPTODISK_ID) ?
	  1 : 0);
}

#endif /* ! GRUB_DISK_HEADER */
