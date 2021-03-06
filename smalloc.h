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

/*
 * SMalloc -- a *static* memory allocator.
 *
 * See README for a complete description.
 *
 * SMalloc is MIT licensed.
 * Copyright (c) 2017 Andrey Rys.
 * Written during Aug2017.
 */

#ifndef _SMALLOC_H
#define _SMALLOC_H

#include <stddef.h>
#include <stdint.h>

struct smalloc_pool;

typedef size_t (*smalloc_oom_handler)(struct smalloc_pool *, size_t);

/* describes static pool, if you're going to use multiple pools at same time */
struct smalloc_pool {
	void *pool; /* pointer to your pool */
	size_t pool_size; /* it's size. Must be aligned with sm_align_pool. */
	int do_zero; /* zero pool before use and all the new allocations from it. */
	smalloc_oom_handler oomfn; /* this will be called, if non-NULL, on OOM condition in pool */
};

/* a default one which is initialised with sm_set_default_pool. */
extern struct smalloc_pool smalloc_curr_pool;

/* undefined behavior handler is called on typical malloc UB situations */
typedef void (*smalloc_ub_handler)(struct smalloc_pool *, const void *);

void sm_set_ub_handler(smalloc_ub_handler);

int sm_align_pool(struct smalloc_pool *);
int sm_set_pool(struct smalloc_pool *, void *, size_t, int, smalloc_oom_handler);
int sm_set_default_pool(void *, size_t, int, smalloc_oom_handler);
int sm_release_pool(struct smalloc_pool *);
int sm_release_default_pool(void);

/* Use these with multiple pools which you control */

void *sm_malloc_pool(struct smalloc_pool *, size_t);
void *sm_zalloc_pool(struct smalloc_pool *, size_t);
void sm_free_pool(struct smalloc_pool *, void *);

void *sm_realloc_pool(struct smalloc_pool *, void *, size_t);
void *sm_calloc_pool(struct smalloc_pool *, size_t, size_t);

int sm_alloc_valid_pool(struct smalloc_pool *spool, const void *p);

size_t sm_szalloc_pool(struct smalloc_pool *, const void *);
int sm_malloc_stats_pool(struct smalloc_pool *, size_t *, size_t *, size_t *, int *);

/* Use these when you use just default smalloc_curr_pool pool */

void *sm_malloc(size_t);
void *sm_zalloc(size_t); /* guarantee zero memory allocation */
void sm_free(void *);

void *sm_realloc(void *, size_t);
void *sm_calloc(size_t, size_t); /* calls zalloc internally */

int sm_alloc_valid(const void *p); /* verify pointer without intentional crash */

size_t sm_szalloc(const void *); /* get size of allocation */
/*
 * get stats: total used, user used, total free, nr. of allocated blocks.
 * any of pointers maybe set to NULL, but at least one must be non NULL.
 */
int sm_malloc_stats(size_t *, size_t *, size_t *, int *);

#endif
