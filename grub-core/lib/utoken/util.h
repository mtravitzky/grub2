/*
 *   Copyright (C) 2022, 2023 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef GRUB_MACHINE
#include <grub/term.h>
#endif

extern unsigned int	opt_debug;

static inline void
debug(const char *fmt, ...)
{
	va_list ap;

	if (opt_debug) {
		va_start(ap, fmt);
#ifdef GRUB_MACHINE
		grub_printf("::: ");
		grub_vprintf (fmt, ap);
#else
		fprintf(stderr, "::: ");
		vfprintf(stderr, fmt, ap);
#endif
		va_end(ap);
	}
}

static inline void
debug2(const char *fmt, ...)
{
	va_list ap;

	if (opt_debug > 1) {
		va_start(ap, fmt);
#ifdef GRUB_MACHINE
		grub_printf("::: ");
		grub_vprintf (fmt, ap);
#else
		fprintf(stderr, "::: ");
		vfprintf(stderr, fmt, ap);
#endif
		va_end(ap);
	}
}

static inline void
infomsg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
#ifdef GRUB_MACHINE
	grub_vprintf (fmt, ap);
#else
	vfprintf(stderr, fmt, ap);
#endif
	va_end(ap);
}

static inline void
warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
#ifdef GRUB_MACHINE
	grub_printf("Warning: ");
	grub_vprintf (fmt, ap);
#else
	fprintf(stderr, "Warning: ");
	vfprintf(stderr, fmt, ap);
#endif
	va_end(ap);
}

static inline void
error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
#ifdef GRUB_MACHINE
	grub_printf("Error: ");
	grub_vprintf (fmt, ap);
#else
	fprintf(stderr, "Error: ");
	vfprintf(stderr, fmt, ap);
#endif
	va_end(ap);
}

static inline void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
#ifdef GRUB_MACHINE
	grub_printf("Fatal: ");
	grub_vprintf (fmt, ap);
#else
	fprintf(stderr, "Fatal: ");
	vfprintf(stderr, fmt, ap);
#endif
	va_end(ap);

#ifdef GRUB_MACHINE
	grub_refresh ();
	grub_abort ();
#else
	exit(2);
#endif
}

static inline void
drop_string(char **var)
{
	if (*var) {
		free(*var);
		*var = NULL;
	}
}

#ifdef GRUB_MACHINE
#define strdup(...) grub_strdup(__VA_ARGS__)
#endif

static inline void
assign_string(char **var, const char *string)
{
	drop_string(var);
	if (string)
		*var = strdup(string);
}

extern void		utoken_hexdump(const void *data, size_t size, void (*)(const char *, ...), unsigned int indent);
extern const char *	print_octet_string(const unsigned char *data, unsigned int len);

#if 0
extern bool		__convert_from_utf16le(char *in_string, size_t in_bytes, char *out_string, size_t out_bytes);
extern bool		__convert_to_utf16le(char *in_string, size_t in_bytes, char *out_string, size_t out_bytes);
#endif

#endif /* UTIL_H */
