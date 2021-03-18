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

#define GENPWD_MAXPWD MKPWD_MAXPWD
#define GENPWD_MAX_SALT GENPWD_MAXPWD

#define NOSIZE ((size_t)-1)
#define CSTR_SZ(x) (sizeof(x)-1)

#define ALNUM_STRING "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define ALPHA_STRING "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LOWER_STRING "abcdefghijklmnopqrstuvwxyz"
#define UPPER_STRING "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define DIGIT_STRING "0123456789"
#define XDIGIT_STRING "0123456789abcdef"
#define UXDIGIT_STRING "0123456789ABCDEF"
#define ASCII_STRING " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

typedef void (*sighandler_t)(int);

extern char *progname;

void genpwd_exit(int status);
void signal_handler(int sig);
void install_signals(void);

extern gpwd_yesno genpwd_save_ids;
#define genpwd_ids_fname ".genpwd.ids"
#define genpwd_ids_magic "# _genpwd_ids file"

extern gpwd_byte genpwd_salt[GENPWD_MAX_SALT];
extern size_t genpwd_szsalt;
extern size_t default_password_length;
extern size_t default_string_offset;
extern size_t default_passes_number;

size_t xstrlcpy(char *dst, const char *src, size_t size);
size_t xstrlcat(char *dst, const char *src, size_t size);

void mkpwd_adjust(struct mkpwd_args *mkpwa);

void genpwd_read_defaults(const char *path, gpwd_yesno noerr);
void genpwd_hash_defaults(char *uhash, size_t szuhash);

gpwd_yesno is_comment(const char *str);
gpwd_yesno str_empty(const char *str);
gpwd_yesno genpwd_fgets(char *s, size_t n, FILE *f);
off_t genpwd_fdsize(int fd);
void *genpwd_read_alloc_fd(int fd, size_t blksz, size_t max, size_t *rsz);
void *genpwd_read_alloc_file(const char *file, size_t *rsz);

void base85_encode(char *dst, const unsigned char *src, size_t count);
void base95_encode(char *dst, const unsigned char *src, size_t count);

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

void xerror(gpwd_yesno noexit, gpwd_yesno noerrno, const char *fmt, ...);

extern char **ids;
extern size_t nids;
typedef void (*ids_populate_fn)(const char *str);

#define SAVE_IDS_NEVER		-1 /* like -N */
#define SAVE_IDS_QUERY		0 /* query status */
#define SAVE_IDS_PLEASE		1 /* yes please write out */
#define SAVE_IDS_OVERRIDE	2 /* if you'll not, I'll shoot you I promise! */

extern char *genpwd_ids_filename; /* if set - open this file instead of default genpwd_ids_fname. */

int genpwd_is_dupid(const char *id);
int genpwd_delid(const char *id);
void genpwd_addid(const char *id);
void genpwd_loadids(ids_populate_fn idpfn);
int genpwd_loadids_from_file(const char *path, ids_populate_fn idpfn);
void genpwd_listids(void);
int genpwd_will_saveids(int x);
void genpwd_saveids(void);

void genpwd_vfsay(FILE *where, int addnl, const char *fmt, va_list ap);
void genpwd_nvesay(const char *fmt, va_list ap);
void genpwd_nesay(const char *fmt, ...);
void genpwd_nsay(const char *fmt, ...);
void genpwd_esay(const char *fmt, ...);
void genpwd_say(const char *fmt, ...);

#endif
