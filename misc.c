#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include "genpwd.h"

char **ids;
int nids;
int need_to_save_ids;

void xerror(const char *reason)
{
	fprintf(stderr, "%s\n", reason);
	exit(2);
}

void daemonise(void)
{
#ifdef DAEMONISE
	pid_t pid, sid;
	int i;

	pid = fork();
	if (pid < 0)
		exit(-1);
	if (pid > 0)
		exit(0);

	sid = setsid();
	if (sid < 0)
		exit(-1);

	close(0);
	close(1);
	close(2);
	for (i = 0; i < 3; i++)
		open("/dev/null", O_RDWR);
#else
	return;
#endif
}


int iscomment(const char *s)
{
	if (!*s
	|| *s == '#'
	|| *s == '\n'
	|| (*s == '\r' && *(s+1) == '\n')) return 1;
	return 0;
}

int dupid(const char *id)
{
	int x;

	if (iscomment(id)) return 0;

	for (x = 0; x < nids; x++) {
		if (!*(ids+x)) return 0;
		if (!strcmp(*(ids+x), id)) return 1;
	}

	return 0;
}

void addid(const char *id)
{
	if (iscomment(id)) return;

	ids = realloc(ids, sizeof(char *) * (nids + 1));
	if (!ids) return;
	*(ids+nids) = strdup(id);
	if (!*(ids+nids)) {
		ids = NULL;
		return;
	}
	nids++;
}

void freeids(void)
{
	int x;
	size_t l;

	if (!ids) return;

	for (x = 0; x < nids; x++) {
		if (!*(ids+x)) continue;
		l = strlen(*(ids+x));
		memset(*(ids+x), 0, l+1);
		free(*(ids+x));
	}

	free(ids); ids = NULL;
}

void loadids(ids_populate_t idpfn)
{
	char path[PATH_MAX], *ppath;
	FILE *f;

	ppath = getenv("HOME");
	if (!ppath) return;

	if (nids == -1) return;
	ids = malloc(sizeof(char *));
	if (!ids) return;

	memset(path, 0, sizeof(path));
	snprintf(path, PATH_MAX-1, "%s/%s", ppath, _genpwd_ids);

	f = fopen(path, "r");
	if (!f) return;

	memset(path, 0, sizeof(path));

	while (fgets(path, sizeof(path), f)) {
		if (*path == '\n' || *path == '#') continue;
		*(path+strnlen(path, sizeof(path))-1) = 0;

		addid(path);

		idpfn(path);
		memset(path, 0, sizeof(path));
	}

	fclose(f);
}

void saveids(void)
{
	char path[PATH_MAX], *ppath;
	FILE *f;
	int x;

	if (nids == -1) return;
	if (!ids) return;
	if (!need_to_save_ids) return;

	ppath = getenv("HOME");
	if (!ppath) return;

	memset(path, 0, sizeof(path));
	snprintf(path, PATH_MAX-1, "%s/%s", ppath, _genpwd_ids);

	f = fopen(path, "w");
	if (!f) return;

	memset(path, 0, sizeof(path));

	x = 0;
	while (x < nids) {
		fputs(*(ids+x), f);
		fputc('\n', f);
		x++;
	}

	freeids();
	fclose(f);
}
