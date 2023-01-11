#include <grub/gcrypt/g10lib.h>
#include <grub/gcrypt/gpg-error.h>
#include <grub/term.h>
#include <grub/crypto.h>
#include <grub/dl.h>
#include <grub/env.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

void *
_gcry_malloc (size_t n)
{
  return grub_malloc (n);
}

void *
_gcry_malloc_secure (size_t n)
{
  return grub_malloc (n);
}

void
_gcry_free (void *a)
{
  grub_free (a);
}

int
_gcry_is_secure (const void *a __attribute__ ((unused)))
{
  return 0;
}

/* FIXME: implement "exit".  */
void *
_gcry_xcalloc (size_t n, size_t m)
{
  void *ret;
  size_t sz;
  if (grub_mul (n, m, &sz))
    grub_fatal ("gcry_xcalloc would overflow");
  ret = grub_zalloc (sz);
  if (!ret)
    grub_fatal ("gcry_xcalloc failed");
  return ret;
}

void *
_gcry_xmalloc_secure (size_t n)
{
  void *ret;
  ret = grub_malloc (n);
  if (!ret)
    grub_fatal ("gcry_xmalloc failed");
  return ret;
}

void *
_gcry_xcalloc_secure (size_t n, size_t m)
{
  void *ret;
  size_t sz;
  if (grub_mul (n, m, &sz))
    grub_fatal ("gcry_xcalloc would overflow");
  ret = grub_zalloc (sz);
  if (!ret)
    grub_fatal ("gcry_xcalloc failed");
  return ret;
}

void *
_gcry_xmalloc (size_t n)
{
  void *ret;
  ret = grub_malloc (n);
  if (!ret)
    grub_fatal ("gcry_xmalloc failed");
  return ret;
}

void *
_gcry_xrealloc (void *a, size_t n)
{
  void *ret;
  ret = grub_realloc (a, n);
  if (!ret)
    grub_fatal ("gcry_xrealloc failed");
  return ret;
}

void *
_gcry_realloc (void *a, size_t n)
{
  return _gcry_xrealloc (a, n);
}

void
_gcry_check_heap (const void *a __attribute__ ((unused)))
{

}

void _gcry_log_printf (const char *fmt, ...)
{
  va_list args;
  const char *debug = grub_env_get ("debug");

  if (! debug)
    return;

  if (grub_strword (debug, "all") || grub_strword (debug, "gcrypt"))
    {
      grub_printf ("gcrypt: ");
      va_start (args, fmt);
      grub_vprintf (fmt, args);
      va_end (args);
      grub_refresh ();
    }
}

void _gcry_log_bug (const char *fmt, ...)
{
  va_list args;

  grub_printf ("gcrypt bug: ");
  va_start (args, fmt);
  grub_vprintf (fmt, args);
  va_end (args);
  grub_refresh ();
  grub_fatal ("gcrypt bug");
}

void _gcry_log_info (const char *fmt, ...)
{
  va_list args;

  grub_printf ("gcrypt info: ");
  va_start (args, fmt);
  grub_vprintf (fmt, args);
  va_end (args);
  grub_refresh ();
  grub_fatal ("gcrypt info");
}

gcry_err_code_t
gpg_error_from_syserror (void)
{
  switch (grub_errno)
    {
    case GRUB_ERR_NONE:
      return GPG_ERR_NO_ERROR;
    case GRUB_ERR_OUT_OF_MEMORY:
      return GPG_ERR_OUT_OF_MEMORY;
    default:
      return GPG_ERR_GENERAL;
    }
}

gpg_err_code_t
gpg_err_code_from_syserror (void)
{
  return gpg_error_from_syserror();
}

gpg_err_code_t
gpg_err_code_from_errno (int err)
{
  /* Currently not used.  */
  (void) err;
  return GPG_ERR_GENERAL;
}

const char *
gpg_strerror (gpg_error_t err)
{
  /* Currently not used.  */
  (void) err;
  return "gpg error function is not implemented";
}

const char *
gpg_strsource (gpg_error_t err)
{
  /* Currently not used.  */
  (void) err;
  return "gpg error function is not implemented";
}

gpg_err_code_t
gpg_err_make_from_errno (gpg_err_source_t source, int err)
{
  /* Currently not used.  */
  (void) source;
  (void) err;
  return GPG_ERR_GENERAL;
}
