#include <string.h>
#include <grub/gcrypt/g10lib.h>
#include <grub/gcrypt/gpg-error.h>
#include <grub/term.h>
#include <grub/crypto.h>
#include <grub/dl.h>
#include <grub/env.h>
#include <ctype.h>
#include "mpi.h"
#include "pubkey-internal.h"

GRUB_MOD_LICENSE ("GPLv3+");

gpg_err_code_t
_gcry_pk_util_parse_flaglist (gcry_sexp_t list,
                              int *r_flags, enum pk_encoding *r_encoding)
{
  gpg_err_code_t rc = 0;
  const char *s;
  size_t n;
  int i;
  int encoding = PUBKEY_ENC_UNKNOWN;
  int flags = 0;
  int igninvflag = 0;

  for (i = list ? sexp_length (list)-1 : 0; i > 0; i--)
    {
      s = sexp_nth_data (list, i, &n);
      if (!s)
        continue; /* Not a data element. */

      switch (n)
        {
        case 3:
          if (!memcmp (s, "pss", 3) && encoding == PUBKEY_ENC_UNKNOWN)
            {
              encoding = PUBKEY_ENC_PSS;
              flags |= PUBKEY_FLAG_FIXEDLEN;
            }
          else if (!memcmp (s, "raw", 3) && encoding == PUBKEY_ENC_UNKNOWN)
            {
              encoding = PUBKEY_ENC_RAW;
              flags |= PUBKEY_FLAG_RAW_FLAG; /* Explicitly given.  */
            }
          else if (!igninvflag)
            rc = GPG_ERR_INV_FLAG;
          break;

        case 4:
          if (!memcmp (s, "comp", 4))
            flags |= PUBKEY_FLAG_COMP;
          else if (!memcmp (s, "oaep", 4) && encoding == PUBKEY_ENC_UNKNOWN)
            {
              encoding = PUBKEY_ENC_OAEP;
              flags |= PUBKEY_FLAG_FIXEDLEN;
            }
          else if (!memcmp (s, "gost", 4))
            {
              encoding = PUBKEY_ENC_RAW;
              flags |= PUBKEY_FLAG_GOST;
            }
          else if (!igninvflag)
            rc = GPG_ERR_INV_FLAG;
          break;

        case 5:
          if (!memcmp (s, "eddsa", 5))
            {
              encoding = PUBKEY_ENC_RAW;
              flags |= PUBKEY_FLAG_EDDSA;
            }
          else if (!memcmp (s, "pkcs1", 5) && encoding == PUBKEY_ENC_UNKNOWN)
            {
              encoding = PUBKEY_ENC_PKCS1;
              flags |= PUBKEY_FLAG_FIXEDLEN;
            }
          else if (!memcmp (s, "param", 5))
            flags |= PUBKEY_FLAG_PARAM;
          else if (!igninvflag)
            rc = GPG_ERR_INV_FLAG;
          break;

        case 6:
          if (!memcmp (s, "nocomp", 6))
            flags |= PUBKEY_FLAG_NOCOMP;
          else if (!igninvflag)
            rc = GPG_ERR_INV_FLAG;
          break;

        case 7:
          if (!memcmp (s, "rfc6979", 7))
            flags |= PUBKEY_FLAG_RFC6979;
          else if (!memcmp (s, "noparam", 7))
            ; /* Ignore - it is the default.  */
          else if (!igninvflag)
            rc = GPG_ERR_INV_FLAG;
          break;

        case 8:
          if (!memcmp (s, "use-x931", 8))
            flags |= PUBKEY_FLAG_USE_X931;
          else if (!igninvflag)
            rc = GPG_ERR_INV_FLAG;
          break;

        case 10:
          if (!memcmp (s, "igninvflag", 10))
            igninvflag = 1;
          break;

        case 11:
          if (!memcmp (s, "no-blinding", 11))
            flags |= PUBKEY_FLAG_NO_BLINDING;
          else if (!memcmp (s, "use-fips186", 11))
            flags |= PUBKEY_FLAG_USE_FIPS186;
          else if (!igninvflag)
            rc = GPG_ERR_INV_FLAG;
          break;

        case 13:
          if (!memcmp (s, "use-fips186-2", 13))
            flags |= PUBKEY_FLAG_USE_FIPS186_2;
          else if (!memcmp (s, "transient-key", 13))
            flags |= PUBKEY_FLAG_TRANSIENT_KEY;
          else if (!igninvflag)
            rc = GPG_ERR_INV_FLAG;
          break;

        default:
          if (!igninvflag)
            rc = GPG_ERR_INV_FLAG;
          break;
        }
    }

  if (r_flags)
    *r_flags = flags;
  if (r_encoding)
    *r_encoding = encoding;

  return rc;
}

void
_gcry_pk_util_init_encoding_ctx (struct pk_encoding_ctx *ctx,
                                 enum pk_operation op,
                                 unsigned int nbits)
{
  ctx->op = op;
  ctx->nbits = nbits;
  ctx->encoding = PUBKEY_ENC_UNKNOWN;
  ctx->flags = 0;
  ctx->hash_algo = GCRY_MD_SHA1;
  ctx->label = NULL;
  ctx->labellen = 0;
  ctx->saltlen = 20;
  ctx->verify_cmp = NULL;
  ctx->verify_arg = NULL;
}

void
_gcry_pk_util_free_encoding_ctx (struct pk_encoding_ctx *ctx)
{
  xfree (ctx->label);
}

gpg_err_code_t
_gcry_pk_util_preparse_sigval (gcry_sexp_t s_sig, const char **algo_names,
                               gcry_sexp_t *r_parms, int *r_eccflags)
{
  gpg_err_code_t rc;
  gcry_sexp_t l1 = NULL;
  gcry_sexp_t l2 = NULL;
  char *name = NULL;
  int i;

  *r_parms = NULL;
  if (r_eccflags)
    *r_eccflags = 0;

  /* Extract the signature value.  */
  l1 = sexp_find_token (s_sig, "sig-val", 0);
  if (!l1)
    {
      rc = GPG_ERR_INV_OBJ; /* Does not contain a signature value object.  */
      goto leave;
    }

  l2 = sexp_nth (l1, 1);
  if (!l2)
    {
      rc = GPG_ERR_NO_OBJ;   /* No cadr for the sig object.  */
      goto leave;
    }
  name = sexp_nth_string (l2, 0);
  if (!name)
    {
      rc = GPG_ERR_INV_OBJ;  /* Invalid structure of object.  */
      goto leave;
    }
  else if (!strcmp (name, "flags"))
    {
      /* Skip a "flags" parameter and look again for the algorithm
	 name.  This is not used but here just for the sake of
	 consistent S-expressions we need to handle it. */
      sexp_release (l2);
      l2 = sexp_nth (l1, 2);
      if (!l2)
	{
	  rc = GPG_ERR_INV_OBJ;
          goto leave;
	}
      xfree (name);
      name = sexp_nth_string (l2, 0);
      if (!name)
        {
          rc = GPG_ERR_INV_OBJ;  /* Invalid structure of object.  */
          goto leave;
        }
    }

  for (i=0; algo_names[i]; i++)
    if (!stricmp (name, algo_names[i]))
      break;
  if (!algo_names[i])
    {
      rc = GPG_ERR_CONFLICT; /* "sig-val" uses an unexpected algo. */
      goto leave;
    }
  if (r_eccflags)
    {
      if (!strcmp (name, "eddsa"))
        *r_eccflags = PUBKEY_FLAG_EDDSA;
      if (!strcmp (name, "gost"))
        *r_eccflags = PUBKEY_FLAG_GOST;
    }

  *r_parms = l2;
  l2 = NULL;
  rc = 0;

 leave:
  xfree (name);
  sexp_release (l2);
  sexp_release (l1);
  return rc;
}

gcry_err_code_t
_gcry_pk_util_data_to_mpi (gcry_sexp_t input, gcry_mpi_t *ret_mpi,
                           struct pk_encoding_ctx *ctx)
{
  gcry_err_code_t rc = 0;
  gcry_sexp_t ldata, lhash, lvalue;
  size_t n;
  const char *s;
  int unknown_flag = 0;
  int parsed_flags = 0;

  *ret_mpi = NULL;
  ldata = sexp_find_token (input, "data", 0);
  if (!ldata)
    { /* assume old style */
      *ret_mpi = sexp_nth_mpi (input, 0, 0);
      return *ret_mpi ? GPG_ERR_NO_ERROR : GPG_ERR_INV_OBJ;
    }

  /* See whether there is a flags list.  */
  {
    gcry_sexp_t lflags = sexp_find_token (ldata, "flags", 0);
    if (lflags)
      {
        if (_gcry_pk_util_parse_flaglist (lflags,
                                          &parsed_flags, &ctx->encoding))
          unknown_flag = 1;
        sexp_release (lflags);
      }
  }

  if (ctx->encoding == PUBKEY_ENC_UNKNOWN)
    ctx->encoding = PUBKEY_ENC_RAW; /* default to raw */

  /* Get HASH or MPI */
  lhash = sexp_find_token (ldata, "hash", 0);
  lvalue = lhash? NULL : sexp_find_token (ldata, "value", 0);

  if (!(!lhash ^ !lvalue))
    rc = GPG_ERR_INV_OBJ; /* none or both given */
  else if (unknown_flag)
    rc = GPG_ERR_INV_FLAG;
  else if (ctx->encoding == PUBKEY_ENC_RAW && lvalue)
    {
      /* RFC6969 may only be used with the a hash value and not the
         MPI based value.  */
      if (parsed_flags & PUBKEY_FLAG_RFC6979)
        {
          rc = GPG_ERR_CONFLICT;
          goto leave;
        }

      /* Get the value */
      *ret_mpi = sexp_nth_mpi (lvalue, 1, GCRYMPI_FMT_USG);
      if (!*ret_mpi)
        rc = GPG_ERR_INV_OBJ;
    }
  else
    rc = GPG_ERR_CONFLICT;

 leave:
  sexp_release (ldata);
  sexp_release (lhash);
  sexp_release (lvalue);

  if (!rc)
    ctx->flags = parsed_flags;
  else
    {
      xfree (ctx->label);
      ctx->label = NULL;
    }

  return rc;
}
