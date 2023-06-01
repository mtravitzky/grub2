/* cipher-proto.h - Internal declarations
 *	Copyright (C) 2008, 2011 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* This file has been factored out from cipher.h so that it can be
   used standalone in visibility.c . */

#ifndef G10_CIPHER_PROTO_H
#define G10_CIPHER_PROTO_H

/* Definition of a function used to report selftest failures.
   DOMAIN is a string describing the function block:
          "cipher", "digest", "pubkey or "random",
   ALGO   is the algorithm under test,
   WHAT   is a string describing what has been tested,
   DESC   is a string describing the error. */
typedef void (*selftest_report_func_t)(const char *domain,
                                       int algo,
                                       const char *what,
                                       const char *errdesc);

/* Definition of the selftest functions.  */
typedef gpg_err_code_t (*selftest_func_t)
     (int algo, int extended, selftest_report_func_t report);

/*
 *
 * Message digest related definitions.
 *
 */

/* Type for the md_init function.  */
typedef void (*gcry_md_init_t) (void *c, unsigned int flags);

/* Type for the md_write function.  */
typedef void (*gcry_md_write_t) (void *c, const void *buf, size_t nbytes);

/* Type for the md_final function.  */
typedef void (*gcry_md_final_t) (void *c);

/* Type for the md_read function.  */
typedef unsigned char *(*gcry_md_read_t) (void *c);

/* Type for the md_extract function.  */
typedef void (*gcry_md_extract_t) (void *c, void *outbuf, size_t nbytes);

/* Type for the md_hash_buffers function. */
typedef void (*gcry_md_hash_buffers_t) (void *outbuf, size_t nbytes,
					const gcry_buffer_t *iov,
					int iovcnt);

typedef struct gcry_md_oid_spec
{
  const char *oidstring;
} gcry_md_oid_spec_t;

/* Module specification structure for message digests.  */
typedef struct gcry_md_spec
{
  int algo;
  struct {
    unsigned int disabled:1;
    unsigned int fips:1;
  } flags;
  const char *name;
  const unsigned char *asnoid;
  int asnlen;
  const gcry_md_oid_spec_t *oids;
  int mdlen;
  gcry_md_init_t init;
  gcry_md_write_t write;
  gcry_md_final_t final;
  gcry_md_read_t read;
  gcry_md_extract_t extract;
  gcry_md_hash_buffers_t hash_buffers;
  size_t contextsize; /* allocate this amount of context */
  selftest_func_t selftest;
} gcry_md_spec_t;


/* The selftest functions.  */
gcry_error_t _gcry_md_selftest (int algo, int extended,
                                selftest_report_func_t report);

#endif /*G10_CIPHER_PROTO_H*/
