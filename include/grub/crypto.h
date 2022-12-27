/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2006
 *                2007, 2008, 2009  Free Software Foundation, Inc.
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

/* Contains elements based on gcrypt-module.h and gcrypt.h.in.
   If it's changed please update this file.  */

#ifndef GRUB_CRYPTO_HEADER
#define GRUB_CRYPTO_HEADER 1

#include <grub/symbol.h>
#include <grub/types.h>
#include <grub/err.h>
#include <grub/mm.h>

typedef enum 
  {
    GPG_ERR_NO_ERROR,
    GPG_ERR_BAD_MPI,
    GPG_ERR_BAD_SECKEY,
    GPG_ERR_BAD_SIGNATURE,
    GPG_ERR_CIPHER_ALGO,
    GPG_ERR_CONFLICT,
    GPG_ERR_DECRYPT_FAILED,
    GPG_ERR_DIGEST_ALGO,
    GPG_ERR_ENCODING_PROBLEM,
    GPG_ERR_GENERAL,
    GPG_ERR_INTERNAL,
    GPG_ERR_INV_ARG,
    GPG_ERR_INV_CIPHER_MODE,
    GPG_ERR_INV_DATA,
    GPG_ERR_INV_FLAG,
    GPG_ERR_INV_KEYLEN,
    GPG_ERR_INV_LENGTH,
    GPG_ERR_INV_OBJ,
    GPG_ERR_INV_OP,
    GPG_ERR_INV_SEXP,
    GPG_ERR_INV_VALUE,
    GPG_ERR_MISSING_VALUE,
    GPG_ERR_NO_ENCRYPTION_SCHEME,
    GPG_ERR_NO_OBJ,
    GPG_ERR_NO_PRIME,
    GPG_ERR_NO_SIGNATURE_SCHEME,
    GPG_ERR_NOT_FOUND,
    GPG_ERR_NOT_IMPLEMENTED,
    GPG_ERR_NOT_SUPPORTED,
    GPG_ERROR_CFLAGS,
    GPG_ERR_PUBKEY_ALGO,
    GPG_ERR_SELFTEST_FAILED,
    GPG_ERR_TOO_SHORT,
    GPG_ERR_UNSUPPORTED,
    GPG_ERR_WEAK_KEY,
    GPG_ERR_WRONG_KEY_USAGE,
    GPG_ERR_WRONG_PUBKEY_ALGO,
    GPG_ERR_OUT_OF_MEMORY,
    GPG_ERR_TOO_LARGE,
    GPG_ERR_ENOMEM
  } gpg_err_code_t;
typedef gpg_err_code_t gpg_error_t;
typedef gpg_error_t gcry_error_t;
typedef gpg_err_code_t gcry_err_code_t;
#define gcry_error_t gcry_err_code_t
#if 0
enum gcry_cipher_modes 
  {
    GCRY_CIPHER_MODE_NONE   = 0,  /* Not yet specified. */
    GCRY_CIPHER_MODE_ECB    = 1,  /* Electronic codebook. */
    GCRY_CIPHER_MODE_CFB    = 2,  /* Cipher feedback. */
    GCRY_CIPHER_MODE_CBC    = 3,  /* Cipher block chaining. */
    GCRY_CIPHER_MODE_STREAM = 4,  /* Used with stream ciphers. */
    GCRY_CIPHER_MODE_OFB    = 5,  /* Outer feedback. */
    GCRY_CIPHER_MODE_CTR    = 6   /* Counter. */
  };
#endif

/*
 *
 * Symmetric cipher related definitions.
 *
 */

/* Type for the cipher_setkey function.  */
typedef gcry_err_code_t (*gcry_cipher_setkey_t) (void *c,
						 const unsigned char *key,
						 unsigned keylen);

/* Type for the cipher_encrypt function.  */
typedef unsigned int (*gcry_cipher_encrypt_t) (void *c,
					       unsigned char *outbuf,
					       const unsigned char *inbuf);

/* Type for the cipher_decrypt function.  */
typedef unsigned int (*gcry_cipher_decrypt_t) (void *c,
					       unsigned char *outbuf,
					       const unsigned char *inbuf);

/* Type for the cipher_stencrypt function.  */
typedef void (*gcry_cipher_stencrypt_t) (void *c,
					 unsigned char *outbuf,
					 const unsigned char *inbuf,
					 unsigned int n);

/* Type for the cipher_stdecrypt function.  */
typedef void (*gcry_cipher_stdecrypt_t) (void *c,
					 unsigned char *outbuf,
					 const unsigned char *inbuf,
					 unsigned int n);

/* The type used to convey additional information to a cipher.  */
typedef gpg_err_code_t (*cipher_set_extra_info_t)
     (void *c, int what, const void *buffer, grub_size_t buflen);

/* The type used to set an IV directly in the algorithm module.  */
typedef void (*cipher_setiv_func_t)(void *c,
                                    const grub_uint8_t *iv, unsigned int ivlen);

typedef struct gcry_cipher_oid_spec
{
  const char *oid;
  int mode;
} gcry_cipher_oid_spec_t;

struct gcry_mpi;
typedef struct gcry_mpi *gcry_mpi_t;

/* The object to represent an S-expression as used with the public key
   functions.  */
struct gcry_sexp;
typedef struct gcry_sexp *gcry_sexp_t;

/* (Forward declaration.)  */
struct gcry_md_context;

/* This object is used to hold a handle to a message digest object.
   This structure is private - only to be used by the public gcry_md_*
   macros.  */
typedef struct gcry_md_handle
{
  /* Actual context.  */
  struct gcry_md_context *ctx;

  /* Buffer management.  */
  int  bufpos;
  int  bufsize;
  unsigned char buf[1];
} *gcry_md_hd_t;

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

/* Module specification structure for ciphers.  */
typedef struct gcry_cipher_spec
{
  int algo;
  struct {
    unsigned int disabled:1;
    unsigned int fips:1;
  } flags;
  const char *name;
  const char **aliases;
  gcry_cipher_oid_spec_t *oids;
  grub_size_t blocksize;
  grub_size_t keylen;
  grub_size_t contextsize;
  gcry_cipher_setkey_t setkey;
  gcry_cipher_encrypt_t encrypt;
  gcry_cipher_decrypt_t decrypt;
  gcry_cipher_stencrypt_t stencrypt;
  gcry_cipher_stdecrypt_t stdecrypt;
  selftest_func_t selftest;
  cipher_set_extra_info_t set_extra_info;
  cipher_setiv_func_t setiv;
#ifdef GRUB_UTIL
  const char *modname;
#endif
  struct gcry_cipher_spec *next;
} gcry_cipher_spec_t;

/* Type for the pk_generate function.  */
typedef gcry_err_code_t (*gcry_pk_generate_t) (int algo,
					       unsigned int nbits,
					       unsigned long use_e,
					       gcry_mpi_t *skey,
					       gcry_mpi_t **retfactors);

/* Type for the pk_check_secret_key function.  */
typedef gcry_err_code_t (*gcry_pk_check_secret_key_t) (int algo,
						       gcry_mpi_t *skey);

/* Type for the pk_encrypt function.  */
typedef gcry_err_code_t (*gcry_pk_encrypt_t) (int algo,
					      gcry_mpi_t *resarr,
					      gcry_mpi_t data,
					      gcry_mpi_t *pkey,
					      int flags);

/* Type for the pk_decrypt function.  */
typedef gcry_err_code_t (*gcry_pk_decrypt_t) (int algo,
					      gcry_mpi_t *result,
					      gcry_mpi_t *data,
					      gcry_mpi_t *skey,
					      int flags);

/* Type for the pk_sign function.  */
typedef gcry_err_code_t (*gcry_pk_sign_t) (int algo,
					   gcry_mpi_t *resarr,
					   gcry_mpi_t data,
					   gcry_mpi_t *skey);

/* Type for the pk_verify function.  */
typedef gcry_err_code_t (*gcry_pk_verify_t) (int algo,
					     gcry_mpi_t hash,
					     gcry_mpi_t *data,
					     gcry_mpi_t *pkey,
					     int (*cmp) (void *, gcry_mpi_t),
					     void *opaquev,
                                             int flags,
                                             int hashalgo);

/* Type for the pk_get_nbits function.  */
typedef unsigned (*gcry_pk_get_nbits_t) (int algo, gcry_mpi_t *pkey);


/* The type used to compute the keygrip.  */
typedef gpg_err_code_t (*pk_comp_keygrip_t) (gcry_md_hd_t md,
                                             gcry_sexp_t keyparm);

/* The type used to query ECC curve parameters.  */
typedef gcry_err_code_t (*pk_get_param_t) (const char *name,
                                           gcry_mpi_t *pkey);

/* The type used to query an ECC curve name.  */
typedef const char *(*pk_get_curve_t)(gcry_mpi_t *pkey, int iterator,
                                      unsigned int *r_nbits);

/* The type used to query ECC curve parameters by name.  */
typedef gcry_sexp_t (*pk_get_curve_param_t)(const char *name);

/* Module specification structure for message digests.  */
typedef struct gcry_pk_spec
{
  int algo;
  struct {
    unsigned int disabled:1;
    unsigned int fips:1;
  } flags;
  int use;
  const char *name;
  const char **aliases;
  const char *elements_pkey;
  const char *elements_skey;
  const char *elements_enc;
  const char *elements_sig;
  const char *elements_grip;
  gcry_pk_generate_t generate;
  gcry_pk_check_secret_key_t check_secret_key;
  gcry_pk_encrypt_t encrypt;
  gcry_pk_decrypt_t decrypt;
  gcry_pk_sign_t sign;
  gcry_pk_verify_t verify;
  gcry_pk_get_nbits_t get_nbits;
  selftest_func_t selftest;
  pk_comp_keygrip_t comp_keygrip;
  pk_get_param_t get_param;
  pk_get_curve_t get_curve;
  pk_get_curve_param_t get_curve_param;
#ifdef GRUB_UTIL
  const char *modname;
#endif
} gcry_pk_spec_t;

/* Type for the md_init function.  */
typedef void (*gcry_md_init_t) (void *c);

/* Type for the md_write function.  */
typedef void (*gcry_md_write_t) (void *c, const void *buf, grub_size_t nbytes);

/* Type for the md_final function.  */
typedef void (*gcry_md_final_t) (void *c);

/* Type for the md_read function.  */
typedef unsigned char *(*gcry_md_read_t) (void *c);

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
  unsigned char *asnoid;
  int asnlen;
  gcry_md_oid_spec_t *oids;
  grub_size_t mdlen;
  gcry_md_init_t init;
  gcry_md_write_t write;
  gcry_md_final_t final;
  gcry_md_read_t read;
  grub_size_t contextsize; /* allocate this amount of context */
  selftest_func_t selftest;
  /* Block size, needed for HMAC.  */
  grub_size_t blocksize;
#ifdef GRUB_UTIL
  const char *modname;
#endif
  struct gcry_md_spec *next;
} gcry_md_spec_t;

struct grub_crypto_cipher_handle
{
  const struct gcry_cipher_spec *cipher;
  char ctx[0];
};

typedef struct grub_crypto_cipher_handle *grub_crypto_cipher_handle_t;

struct grub_crypto_hmac_handle;

const gcry_cipher_spec_t *
grub_crypto_lookup_cipher_by_name (const char *name);

grub_crypto_cipher_handle_t
grub_crypto_cipher_open (const struct gcry_cipher_spec *cipher);

gcry_err_code_t
grub_crypto_cipher_set_key (grub_crypto_cipher_handle_t cipher,
			    const unsigned char *key,
			    unsigned keylen);

static inline void
grub_crypto_cipher_close (grub_crypto_cipher_handle_t cipher)
{
  grub_free (cipher);
}

static inline void
grub_crypto_xor (void *out, const void *in1, const void *in2, grub_size_t size)
{
  const grub_uint8_t *in1ptr = in1, *in2ptr = in2;
  grub_uint8_t *outptr = out;
  while (size && (((grub_addr_t) in1ptr & (sizeof (grub_uint64_t) - 1))
		  || ((grub_addr_t) in2ptr & (sizeof (grub_uint64_t) - 1))
		  || ((grub_addr_t) outptr & (sizeof (grub_uint64_t) - 1))))
    {
      *outptr = *in1ptr ^ *in2ptr;
      in1ptr++;
      in2ptr++;
      outptr++;
      size--;
    }
  while (size >= sizeof (grub_uint64_t))
    {
      *(grub_uint64_t *) (void *) outptr
	= (*(grub_uint64_t *) (void *) in1ptr
	   ^ *(grub_uint64_t *) (void *) in2ptr);
      in1ptr += sizeof (grub_uint64_t);
      in2ptr += sizeof (grub_uint64_t);
      outptr += sizeof (grub_uint64_t);
      size -= sizeof (grub_uint64_t);
    }
  while (size)
    {
      *outptr = *in1ptr ^ *in2ptr;
      in1ptr++;
      in2ptr++;
      outptr++;
      size--;
    }
}

gcry_err_code_t
grub_crypto_ecb_decrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size);

gcry_err_code_t
grub_crypto_ecb_encrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size);
gcry_err_code_t
grub_crypto_cbc_encrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, void *in, grub_size_t size,
			 void *iv_in);
gcry_err_code_t
grub_crypto_cbc_decrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size,
			 void *iv);
void 
grub_cipher_register (gcry_cipher_spec_t *cipher);
void
grub_cipher_unregister (gcry_cipher_spec_t *cipher);
void 
grub_md_register (gcry_md_spec_t *digest);
void 
grub_md_unregister (gcry_md_spec_t *cipher);

extern struct gcry_pk_spec *grub_crypto_pk_dsa;
extern struct gcry_pk_spec *grub_crypto_pk_ecdsa;
extern struct gcry_pk_spec *grub_crypto_pk_ecdh;
extern struct gcry_pk_spec *grub_crypto_pk_rsa;

void
grub_crypto_hash (const gcry_md_spec_t *hash, void *out, const void *in,
		  grub_size_t inlen);
const gcry_md_spec_t *
grub_crypto_lookup_md_by_name (const char *name);

grub_err_t
grub_crypto_gcry_error (gcry_err_code_t in);

void grub_burn_stack (grub_size_t size);

struct grub_crypto_hmac_handle *
grub_crypto_hmac_init (const struct gcry_md_spec *md,
		       const void *key, grub_size_t keylen);
void
grub_crypto_hmac_write (struct grub_crypto_hmac_handle *hnd,
			const void *data,
			grub_size_t datalen);
gcry_err_code_t
grub_crypto_hmac_fini (struct grub_crypto_hmac_handle *hnd, void *out);

gcry_err_code_t
grub_crypto_hmac_buffer (const struct gcry_md_spec *md,
			 const void *key, grub_size_t keylen,
			 const void *data, grub_size_t datalen, void *out);

extern gcry_md_spec_t _gcry_digest_spec_md5;
extern gcry_md_spec_t _gcry_digest_spec_sha1;
extern gcry_md_spec_t _gcry_digest_spec_sha256;
extern gcry_md_spec_t _gcry_digest_spec_sha512;
extern gcry_md_spec_t _gcry_digest_spec_crc32;
extern gcry_cipher_spec_t _gcry_cipher_spec_aes;
#define GRUB_MD_MD5 ((const gcry_md_spec_t *) &_gcry_digest_spec_md5)
#define GRUB_MD_SHA1 ((const gcry_md_spec_t *) &_gcry_digest_spec_sha1)
#define GRUB_MD_SHA256 ((const gcry_md_spec_t *) &_gcry_digest_spec_sha256)
#define GRUB_MD_SHA512 ((const gcry_md_spec_t *) &_gcry_digest_spec_sha512)
#define GRUB_MD_CRC32 ((const gcry_md_spec_t *) &_gcry_digest_spec_crc32)
#define GRUB_CIPHER_AES ((const gcry_cipher_spec_t *) &_gcry_cipher_spec_aes)

/* Implement PKCS#5 PBKDF2 as per RFC 2898.  The PRF to use is HMAC variant
   of digest supplied by MD.  Inputs are the password P of length PLEN,
   the salt S of length SLEN, the iteration counter C (> 0), and the
   desired derived output length DKLEN.  Output buffer is DK which
   must have room for at least DKLEN octets.  The output buffer will
   be filled with the derived data.  */
gcry_err_code_t
grub_crypto_pbkdf2 (const struct gcry_md_spec *md,
		    const grub_uint8_t *P, grub_size_t Plen,
		    const grub_uint8_t *S, grub_size_t Slen,
		    unsigned int c,
		    grub_uint8_t *DK, grub_size_t dkLen);

int
grub_crypto_memcmp (const void *a, const void *b, grub_size_t n);

int
grub_password_get (char buf[], unsigned buf_size);

/* For indistinguishibility.  */
#define GRUB_ACCESS_DENIED grub_error (GRUB_ERR_ACCESS_DENIED, N_("access denied"))

extern void (*grub_crypto_autoload_hook) (const char *name);

void _gcry_assert_failed (const char *expr, const char *file, int line,
                          const char *func) __attribute__ ((noreturn));
void _gcry_divide_by_zero (void) __attribute__ ((noreturn));

void __gcry_burn_stack (unsigned int bytes);
void __gcry_burn_stack_dummy (void);
void _gcry_log_error( const char *fmt, ... )  __attribute__ ((format (printf, 1, 2)));
void _gcry_bug(const char *file, int line, const char *func);


#ifdef GRUB_UTIL
void grub_gcry_init_all (void);
void grub_gcry_fini_all (void);

int
grub_get_random (void *out, grub_size_t len);

#endif

/* src/cipher.h */

#define PUBKEY_FLAG_NO_BLINDING    (1 << 0)
#define PUBKEY_FLAG_RFC6979        (1 << 1)
#define PUBKEY_FLAG_FIXEDLEN       (1 << 2)
#define PUBKEY_FLAG_LEGACYRESULT   (1 << 3)
#define PUBKEY_FLAG_RAW_FLAG       (1 << 4)
#define PUBKEY_FLAG_TRANSIENT_KEY  (1 << 5)
#define PUBKEY_FLAG_USE_X931       (1 << 6)
#define PUBKEY_FLAG_USE_FIPS186    (1 << 7)
#define PUBKEY_FLAG_USE_FIPS186_2  (1 << 8)
#define PUBKEY_FLAG_ECDSA          (1 << 9)
#define PUBKEY_FLAG_EDDSA          (1 << 10)

enum pk_operation
  {
    PUBKEY_OP_ENCRYPT,
    PUBKEY_OP_DECRYPT,
    PUBKEY_OP_SIGN,
    PUBKEY_OP_VERIFY
  };

enum pk_encoding
  {
    PUBKEY_ENC_RAW,
    PUBKEY_ENC_PKCS1,
    PUBKEY_ENC_OAEP,
    PUBKEY_ENC_PSS,
    PUBKEY_ENC_UNKNOWN
  };

struct pk_encoding_ctx
{
  enum pk_operation op;
  unsigned int nbits;

  enum pk_encoding encoding;
  int flags;

  int hash_algo;

  /* for OAEP */
  unsigned char *label;
  grub_size_t labellen;

  /* for PSS */
  grub_size_t saltlen;

  int (* verify_cmp) (void *opaque, gcry_mpi_t tmp);
  void *verify_arg;
};

#endif

#define gcry_mpi_get_nbits _gcry_mpi_get_nbits
#define gcry_mpi_scan _gcry_mpi_scan
