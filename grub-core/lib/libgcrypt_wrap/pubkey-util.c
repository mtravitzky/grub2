#include <string.h>
#include <grub/gcrypt/g10lib.h>
#include <grub/gcrypt/gpg-error.h>
#include <grub/crypto.h>
#include <ctype.h>
#include "mpi.h"
#include "pubkey-internal.h"

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

  /* unused */
  (void) n;
  (void) s;

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
