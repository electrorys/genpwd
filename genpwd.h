#ifndef _GENPWD_H
#define _GENPWD_H

#include <stdint.h>
#include "mkpwd.h"
#include "tf1024.h"

extern char *progname;

extern const int genpwd_save_ids;
extern const char genpwd_ids_fname[];
#define genpwd_ids_magic "# _genpwd_ids file"

extern const unsigned char salt[];
extern int default_password_length;
extern int default_string_offset;
extern int default_passes_number;

extern const char testmaster[];
extern const char testname[];
extern const char testxpwd[];

size_t xstrlcpy(char *dst, const char *src, size_t size);

void mkpwd_adjust(void);

int selftest(void);

void loadsalt(const char *fname, const unsigned char **P, size_t *B);

/* new base64 */
size_t base64_encode(char *output, const char *input, size_t inputl);
/* old base64 */
void b64_encode(char *dst, const unsigned char *src, size_t length);
void stripchr(char *s, const char *rem);

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
char *genpwd_strdup(const char *s);

void xerror(int noexit, int noerrno, const char *fmt, ...);
void daemonise(void);

extern char **ids;
extern int nids;
typedef void (*ids_populate_fn)(const char *str);

extern const unsigned char *loaded_salt;
extern size_t salt_length;

void sk1024_loop(const unsigned char *src, size_t len, unsigned char *digest,
			unsigned int bits, unsigned int passes);

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

#endif
