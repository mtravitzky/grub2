#ifndef GRUB_GPG_ERROR_H
#define GRUB_GPG_ERROR_H 1

#include <grub/crypto.h>
typedef enum
  {
    GPG_ERR_SOURCE_USER_1
  }
  gpg_err_source_t;
#define GPG_ERR_INLINE inline
static inline int
gpg_err_make (gpg_err_source_t source __attribute__ ((unused)), gpg_err_code_t code)
{
  return code;
}

static inline gpg_err_code_t
gpg_err_code (gpg_error_t err)
{
  return err;
}

static inline gpg_err_source_t
gpg_err_source (gpg_error_t err __attribute__ ((unused)))
{
  return GPG_ERR_SOURCE_USER_1;
}

static inline gpg_error_t
gpg_error (gpg_err_code_t code)
{
  return code;
}

gcry_err_code_t
gpg_error_from_syserror (void);

gcry_err_code_t
gpg_err_code_from_syserror (void);

gpg_err_code_t
gpg_err_code_from_errno (int err);

const char *
gpg_strerror (gcry_error_t err);

const char *
gpg_strsource (gcry_error_t err);

gpg_err_code_t
gpg_err_make_from_errno (gpg_err_source_t source, int err);

#endif
