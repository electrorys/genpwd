#ifndef _GENPWD_H
#define _GENPWD_H

#include <stdint.h>
#include "mkpwd.h"
#include "tf1024.h"

#define _genpwd_ids ".genpwd.ids"

extern const unsigned char salt[];
extern int default_password_length;
extern int default_string_offset;
extern int default_passes_number;
extern const unsigned char tweak[16];

extern const char testmaster[];
extern const char testname[];
extern const char testxpwd[];

void load_defs(void);

int selftest(void);

void loadsalt(const char *fname, const unsigned char **P, size_t *B);

void b64_encode(char *dst, const unsigned char *src, size_t length);
void stripchr(char *s, const char *rem);

void hash85(char *dst, const unsigned char *src, size_t len);
void hash95(char *dst, const unsigned char *src, size_t len);

void xerror(const char *reason);
void daemonise(void);

extern char **ids;
extern int nids;
typedef void (*ids_populate_t)(const char *str);

extern const unsigned char *_salt;
extern size_t _slen;

int findid(const char *id);
int delid(const char *id);
int is_dupid(const char *id);
void addid(const char *id);
void loadids(ids_populate_t idpfn);
void to_saveids(int x);
void saveids(void);

#endif
