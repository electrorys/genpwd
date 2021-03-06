/*
 * MIT License
 *
 * Copyright (c) 2021 Andrey Rys
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#ifndef _GENPWD_H
#define _GENPWD_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <termios.h>
#include <libgen.h>

#include "base64.h"
#include "mkpwd.h"
#include "smalloc.h"
#include "getpasswd.h"
#include "tfdef.h"
#include "tfe.h"
#include "tfprng.h"
#include "skein.h"

typedef short gpwd_yesno;
typedef TF_BYTE_TYPE gpwd_byte;

enum { NO, YES };

#define GENPWD_PWD_MAX 4096
#define GENPWD_MAX_SALT 8192

#define NOSIZE ((size_t)-1)
#define CSTR_SZ(x) (sizeof(x)-1)
#define CPPSTR(x) #x

#define GENPWD_ALNUM_STRING_NAME "<alnum>"
#define GENPWD_ALNUM_STRING MKPWD_ALPHA_STRING MKPWD_DIGIT_STRING
#define GENPWD_ALPHA_STRING_NAME "<alpha>"
#define GENPWD_ALPHA_STRING MKPWD_ALPHA_STRING
#define GENPWD_LOWER_STRING_NAME "<lower>"
#define GENPWD_LOWER_STRING "abcdefghijklmnopqrstuvwxyz"
#define GENPWD_UPPER_STRING_NAME "<upper>"
#define GENPWD_UPPER_STRING "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define GENPWD_DIGIT_STRING_NAME "<digit>"
#define GENPWD_DIGIT_STRING MKPWD_DIGIT_STRING
#define GENPWD_XDIGIT_STRING_NAME "<xdigit>"
#define GENPWD_XDIGIT_STRING "0123456789abcdef"
#define GENPWD_UXDIGIT_STRING_NAME "<uxdigit>"
#define GENPWD_UXDIGIT_STRING "0123456789ABCDEF"
#define GENPWD_ASCII_STRING_NAME "<ascii>"
#define GENPWD_ASCII_STRING " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

typedef void (*sighandler_t)(int);

extern char *progname;

void genpwd_exit(int status);
void signal_handler(int sig);
void install_signals(void);

extern gpwd_byte genpwd_salt[GENPWD_MAX_SALT];
extern size_t genpwd_szsalt;
extern size_t default_password_length;
extern size_t default_string_offset;
extern size_t default_turns_number;
extern short default_password_format;
extern char *default_password_charset;

size_t xstrlcpy(char *dst, const char *src, size_t size);
size_t xstrlcat(char *dst, const char *src, size_t size);

const char *pwl_charset_name(const char *charset);
const char *pwl_charset_string(const char *csname);

void mkpwd_adjust(struct mkpwd_args *mkpwa);

void genpwd_read_defaults(const char *path, gpwd_yesno noerr);
void genpwd_hash_defaults(char *uhash, size_t szuhash);

gpwd_yesno is_comment(const char *str);
gpwd_yesno str_empty(const char *str);
gpwd_yesno genpwd_fgets(char *s, size_t n, FILE *f);
off_t genpwd_fdsize(int fd);
void *genpwd_read_alloc_fd(int fd, size_t blksz, size_t max, size_t *rsz);
void *genpwd_read_alloc_file(const char *file, size_t *rsz);

void genpwd_init_memory(void);
void genpwd_exit_memory(void);
void genpwd_free(void *p);
void *genpwd_malloc(size_t sz);
void *genpwd_zalloc(size_t sz);
void *genpwd_calloc(size_t nm, size_t sz);
void *genpwd_realloc(void *p, size_t newsz);
size_t genpwd_szalloc(const void *p);
char *genpwd_strdup(const char *s);

void genpwd_finirandom(void);
void genpwd_getrandom(void *buf, size_t sz);

void xerror(const char *fmt, ...);
void xexit(const char *fmt, ...);

void genpwd_vfsay(FILE *where, int addnl, const char *fmt, va_list ap);
void genpwd_nvesay(const char *fmt, va_list ap);
void genpwd_nesay(const char *fmt, ...);
void genpwd_nsay(const char *fmt, ...);
void genpwd_esay(const char *fmt, ...);
void genpwd_say(const char *fmt, ...);

#endif
