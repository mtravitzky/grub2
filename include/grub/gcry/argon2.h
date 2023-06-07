#ifndef _ARGON2_H
#define _ARGON2_H

#define GRUB_GCRY_KDF_ARGON2   64
#define GRUB_GCRY_KDF_ARGON2D  0
#define GRUB_GCRY_KDF_ARGON2I  1
#define GRUB_GCRY_KDF_ARGON2ID 2

gcry_error_t
my_kdf_derive (int algo, int subalgo,
               const unsigned long *params, unsigned int paramslen,
               const unsigned char *pass, grub_size_t passlen,
               const unsigned char *salt, grub_size_t saltlen,
               const unsigned char *key, grub_size_t keylen,
               const unsigned char *ad, grub_size_t adlen,
               grub_size_t outlen, unsigned char *out);

#endif /* _ARGON2_H */
