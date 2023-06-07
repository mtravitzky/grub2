/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1992-1999,2001,2003,2004,2005,2009 Free Software Foundation, Inc.
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

#include <config.h>

#include <grub/types.h>
#include <grub/crypto.h>
#include <grub/auth.h>
#include <grub/emu/misc.h>
#include <grub/util/misc.h>
#include <grub/i18n.h>
#include <grub/misc.h>
#include <grub/gcry/argon2.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _GNU_SOURCE	1

#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#include <argp.h>
#pragma GCC diagnostic error "-Wmissing-prototypes"
#pragma GCC diagnostic error "-Wmissing-declarations"

#include "progname.h"

/******************************
 *                            *
 *  Key Derivation Functions  *
 *                            *
 ******************************/

static void
check_argon2 (void)
{
  gcry_error_t err;
  int verbose = 0;
  const unsigned long param[4] = { 32, 3, 32, 4 };
  const unsigned char pass[32] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
  };
  const unsigned char salt[16] = {
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  };
  const unsigned char key[8] = { 3, 3, 3, 3, 3, 3, 3, 3 };
  const unsigned char ad[12] = { 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 };
  unsigned char out[32];
  unsigned char expected[3][32] = {
    {  /* GCRY_KDF_ARGON2D */
      0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97,
      0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94,
      0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1,
      0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb
    },
    { /* GCRY_KDF_ARGON2I */
      0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa,
      0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94, 0xbd, 0xa1,
      0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2,
      0x99, 0x52, 0xa4, 0xc4, 0x67, 0x2b, 0x6c, 0xe8
    },
    { /* GCRY_KDF_ARGON2ID */
      0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
      0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
      0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
      0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
    }
  };
  int i;
  int subalgo = GRUB_GCRY_KDF_ARGON2D;
  int count = 0;

 again:

  if (verbose)
    fprintf (stderr, "checking ARGON2 test vector %d\n", count);

  err = my_kdf_derive (GRUB_GCRY_KDF_ARGON2, subalgo, param, 4,
                       pass, 32, salt, 16, key, 8, ad, 12,
                       32, out);
  if (err)
    fprintf (stderr, "argon2 test failed: \n");
  else if (memcmp (out, expected[count], 32))
    {
      fprintf (stderr, "argon2 test failed: mismatch\n");
      fputs ("got:", stderr);
      for (i=0; i < 32; i++)
        fprintf (stderr, " %02x", out[i]);
      putc ('\n', stderr);
    }

  /* Next algo */
  if (subalgo == GRUB_GCRY_KDF_ARGON2D)
    subalgo = GRUB_GCRY_KDF_ARGON2I;
  else if (subalgo == GRUB_GCRY_KDF_ARGON2I)
    subalgo = GRUB_GCRY_KDF_ARGON2ID;

  count++;
  if (count < 3)
    goto again;
}

int
main (int argc, char *argv[])
{
  grub_util_host_init (&argc, &argv);
  check_argon2 ();

  return 0;
}
