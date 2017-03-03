#ifndef _GENPWD_H
#define _GENPWD_H

#include <stdint.h>
#include "mkpwd.h"
#include "tf1024.h"

#define _genpwd_ids ".genpwd.ids"

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
extern int need_to_save_ids;
typedef void (*ids_populate_t)(const char *str);

int dupid(const char *id);
void addid(const char *id);
void freeids(void);
void loadids(ids_populate_t idpfn);
void saveids(void);

#endif
