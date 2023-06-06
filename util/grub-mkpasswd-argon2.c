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

/* Algorithm IDs for the KDFs.  */
enum gcry_kdf_algos
  {
    GCRY_KDF_NONE = 0,
    GCRY_KDF_SIMPLE_S2K = 16,
    GCRY_KDF_SALTED_S2K = 17,
    GCRY_KDF_ITERSALTED_S2K = 19,
    GCRY_KDF_PBKDF1 = 33,
    GCRY_KDF_PBKDF2 = 34,
    GCRY_KDF_SCRYPT = 48,
    GCRY_KDF_ARGON2   = 64,
    GCRY_KDF_BALLOON  = 65
  };

enum gcry_kdf_subalgo_argon2
  {
    GCRY_KDF_ARGON2D  = 0,
    GCRY_KDF_ARGON2I  = 1,
    GCRY_KDF_ARGON2ID = 2
  };

/* Derive a key from a passphrase.  */
gpg_error_t gcry_kdf_derive (const void *passphrase, size_t passphraselen,
                             int algo, int subalgo,
                             const void *salt, size_t saltlen,
                             unsigned long iterations,
                             size_t keysize, void *keybuffer);

/* Another API to derive a key from a passphrase.  */
typedef struct gcry_kdf_handle *gcry_kdf_hd_t;

typedef void (*gcry_kdf_job_fn_t) (void *priv);
typedef int (*gcry_kdf_dispatch_job_fn_t) (void *jobs_context,
                                           gcry_kdf_job_fn_t job_fn,
                                           void *job_priv);
typedef int (*gcry_kdf_wait_all_jobs_fn_t) (void *jobs_context);

/* Exposed structure for KDF computation to decouple thread functionality.  */
typedef struct gcry_kdf_thread_ops
{
  void *jobs_context;
  gcry_kdf_dispatch_job_fn_t dispatch_job;
  gcry_kdf_wait_all_jobs_fn_t wait_all_jobs;
} gcry_kdf_thread_ops_t;

gcry_error_t gcry_kdf_open (gcry_kdf_hd_t *hd, int algo, int subalgo,
                            const unsigned long *param, unsigned int paramlen,
                            const void *passphrase, size_t passphraselen,
                            const void *salt, size_t saltlen,
                            const void *key, size_t keylen,
                            const void *ad, size_t adlen);
gcry_error_t gcry_kdf_compute (gcry_kdf_hd_t h,
                               const gcry_kdf_thread_ops_t *ops);
gcry_error_t gcry_kdf_final (gcry_kdf_hd_t h, size_t resultlen, void *result);
void gcry_kdf_close (gcry_kdf_hd_t h);

static gcry_error_t
my_kdf_derive (int parallel,
               int algo, int subalgo,
               const unsigned long *params, unsigned int paramslen,
               const unsigned char *pass, size_t passlen,
               const unsigned char *salt, size_t saltlen,
               const unsigned char *key, size_t keylen,
               const unsigned char *ad, size_t adlen,
               size_t outlen, unsigned char *out)
{
  gcry_error_t err;
  gcry_kdf_hd_t hd;

  (void)parallel;

  err = gcry_kdf_open (&hd, algo, subalgo, params, paramslen,
                       pass, passlen, salt, saltlen, key, keylen,
                       ad, adlen);
  if (err)
    return err;

  err = gcry_kdf_compute (hd, NULL);

  if (!err)
    err = gcry_kdf_final (hd, outlen, out);

  gcry_kdf_close (hd);
  return err;
}

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
  int subalgo = GCRY_KDF_ARGON2D;
  int count = 0;

 again:

  if (verbose)
    fprintf (stderr, "checking ARGON2 test vector %d\n", count);

  err = my_kdf_derive (0,
                       GCRY_KDF_ARGON2, subalgo, param, 4,
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
  if (subalgo == GCRY_KDF_ARGON2D)
    subalgo = GCRY_KDF_ARGON2I;
  else if (subalgo == GCRY_KDF_ARGON2I)
    subalgo = GCRY_KDF_ARGON2ID;

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
