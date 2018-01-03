#ifndef _GENPWD_H
#define _GENPWD_H

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
#include <errno.h>
#include <termios.h>
#include <libgen.h>

#include "mkpwd.h"
#include "smalloc.h"
#include "getpasswd.h"
#include "tf1024.h"

#define GENPWD_MAXPWD MKPWD_MAXPWD

#define NOSIZE ((size_t)-1)
#define CSTR_SZ(x) (sizeof(x)-1)

typedef void (*sighandler_t)(int);

extern char *progname;

void genpwd_exit(int status);
void signal_handler(int sig);
void install_signals(void);

extern const int genpwd_save_ids;
extern const char genpwd_ids_fname[];
#define genpwd_ids_magic "# _genpwd_ids file"

extern const unsigned char salt[];
extern size_t default_password_length;
extern size_t default_string_offset;
extern size_t default_passes_number;

size_t xstrlcpy(char *dst, const char *src, size_t size);

void mkpwd_adjust(struct mkpwd_args *mkpwa);

off_t fdsize(int fd);
void *read_alloc_fd(int fd, size_t blksz, size_t max, size_t *rsz);
void *read_alloc_file(const char *file, size_t *rsz);

/* new base64 */
size_t base64_encode(char *output, const char *input, size_t inputl);
/* old base64 */
void b64_encode(char *dst, const unsigned char *src, size_t length);

/* new base85 */
void base85_encode(char *dst, const unsigned char *src, size_t count);
void base95_encode(char *dst, const unsigned char *src, size_t count);
/* old base85 */
void hash85(char *dst, const unsigned char *src, size_t len);
void hash95(char *dst, const unsigned char *src, size_t len);

void genpwd_init_memory(void);
void genpwd_exit_memory(void);
void genpwd_free(void *p);
void *genpwd_malloc(size_t sz);
void *genpwd_zalloc(size_t sz);
void *genpwd_calloc(size_t nm, size_t sz);
void *genpwd_realloc(void *p, size_t newsz);
size_t genpwd_szalloc(const void *p);
char *genpwd_strdup(const char *s);

void genpwd_getrandom(void *buf, size_t size);

void xerror(int noexit, int noerrno, const char *fmt, ...);

extern char **ids;
extern int nids;
typedef void (*ids_populate_fn)(const char *str);

extern const unsigned char *loaded_salt;
extern size_t salt_length;

void sk1024iter(const unsigned char *src, size_t len, unsigned char *digest, unsigned int bits, unsigned int passes);

#define SAVE_IDS_NEVER		-1 /* like -N */
#define SAVE_IDS_QUERY		0 /* query status */
#define SAVE_IDS_PLEASE		1 /* yes please write out */
#define SAVE_IDS_OVERRIDE	2 /* if you'll not, I'll shoot you I promise! */

extern char *genpwd_ids_filename; /* if set - open this file instead of default genpwd_ids_fname. */

int findid(const char *id);
int delid(const char *id);
int is_dupid(const char *id);
void addid(const char *id);
void loadids(ids_populate_fn idpfn);
void listids(void);
int will_saveids(int x);
void saveids(void);

void genpwd_vfsay(FILE *where, int addnl, const char *fmt, va_list ap);
void genpwd_nvesay(const char *fmt, va_list ap);
void genpwd_nesay(const char *fmt, ...);
void genpwd_nsay(const char *fmt, ...);
void genpwd_esay(const char *fmt, ...);
void genpwd_say(const char *fmt, ...);

#endif
