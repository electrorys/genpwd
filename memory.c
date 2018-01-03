#include <stdint.h>
#include "genpwd.h"

#define POOL_MIN_SIZE 65536

static void *genpwd_memory_pool;
static size_t genpwd_memory_pool_sz;
static long sc_page_size;

static void *getrndbase(void)
{
	uintptr_t r;
	genpwd_getrandom(&r, sizeof(uintptr_t));
	r &= ~(sc_page_size-1);
#if UINTPTR_MAX == UINT64_MAX
	r &= 0xffffffffff;
#endif
	return (void *)r;
}

static size_t genpwd_oom_handler(struct smalloc_pool *spool, size_t failsz)
{
	void *t, *base;
	size_t nsz;

	nsz = (failsz / sc_page_size) * sc_page_size;
	if (failsz % sc_page_size) nsz += sc_page_size;
	if (nsz == 0) nsz += sc_page_size;

	base = genpwd_memory_pool+genpwd_memory_pool_sz;
	t = mmap(base, nsz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (t == MAP_FAILED || t != base) {
		if (t != base && t != MAP_FAILED) munmap(t, nsz);
		xerror(0, 1, "OOM: failed to allocate %zu bytes!", failsz);
		return 0;
	}

	genpwd_memory_pool_sz += nsz;
	return genpwd_memory_pool_sz;
}

static void genpwd_ub_handler(struct smalloc_pool *spool, const void *offender)
{
	xerror(0, 1, "UB: %p is not from our data storage!", offender);
}

static int genpwd_memory_initialised;

void genpwd_init_memory(void)
{
	if (!genpwd_memory_initialised) {
		void *base;
		int tries;

		sc_page_size = sysconf(_SC_PAGE_SIZE);
		if (sc_page_size == 0) sc_page_size = PAGE_SIZE;
		sm_set_ub_handler(genpwd_ub_handler);
		tries = 0;
		genpwd_memory_pool_sz = (POOL_MIN_SIZE / sc_page_size) * sc_page_size;
_again:		base = getrndbase();
		genpwd_memory_pool = mmap(base, genpwd_memory_pool_sz,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (genpwd_memory_pool == MAP_FAILED
		|| genpwd_memory_pool != base) {
			if (genpwd_memory_pool != base
			&& genpwd_memory_pool != MAP_FAILED) munmap(base, genpwd_memory_pool_sz);
			tries++;
			if (tries > 100) xerror(0, 0, "mmap");
			goto _again;
		}
		if (!sm_set_default_pool(
		genpwd_memory_pool, genpwd_memory_pool_sz, 1, genpwd_oom_handler))
			xerror(0, 1, "memory pool initialisation failed!");
		genpwd_memory_initialised = 1;
	}
}

void genpwd_exit_memory(void)
{
	/* will erase memory pool automatically */
	sm_release_default_pool();
	memset(genpwd_memory_pool, 0, genpwd_memory_pool_sz);
	munmap(genpwd_memory_pool, genpwd_memory_pool_sz);
	genpwd_memory_initialised = 0;
}

void genpwd_free(void *p)
{
	if (!genpwd_memory_initialised) genpwd_init_memory();
	sm_free(p);
}

void *genpwd_malloc(size_t sz)
{
	if (!genpwd_memory_initialised) genpwd_init_memory();
	return sm_malloc(sz);
}

void *genpwd_zalloc(size_t sz)
{
	if (!genpwd_memory_initialised) genpwd_init_memory();
	return sm_zalloc(sz);
}

void *genpwd_calloc(size_t nm, size_t sz)
{
	if (!genpwd_memory_initialised) genpwd_init_memory();
	return sm_calloc(nm, sz);
}

void *genpwd_realloc(void *p, size_t newsz)
{
	if (!genpwd_memory_initialised) genpwd_init_memory();
	return sm_realloc(p, newsz);
}

size_t genpwd_szalloc(const void *p)
{
	if (!genpwd_memory_initialised) genpwd_init_memory();
	return sm_szalloc(p);
}

char *genpwd_strdup(const char *s)
{
	size_t n = strlen(s);
	char *r = genpwd_zalloc(n+1);
	if (!r) xerror(0, 0, "strdup");
	memcpy(r, s, n);
	return r;
}
