#ifndef GRUB_ZSTD_HEADER
#define GRUB_ZSTD_HEADER	1

grub_ssize_t
grub_zstd_decompress (char *ibuf, grub_size_t isize, grub_off_t off,
		 char *obuf, grub_size_t osize);

#endif /* ! GRUB_ZSTD_HEADER */
