/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010,2011,2012,2013  Free Software Foundation, Inc.
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

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <grub/util/install.h>

int
grub_install_sync_fs_journal (const char *path)
{
  int fd, ret;

  fd = open (path, O_RDONLY);

  if (fd == -1)
    return 1;

  if (ioctl (fd, FIFREEZE, 0) == 0)
    {
      ioctl(fd, FITHAW, 0);
      ret = 1;
    }
  else if (errno == EOPNOTSUPP)
    ret = 1;
  else
    ret = 0;

  close (fd);
  return ret;
}

