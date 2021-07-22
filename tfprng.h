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

#ifndef _TF_PRNG_DEFINITIONS_HEADER
#define _TF_PRNG_DEFINITIONS_HEADER

#include <stdlib.h>
#include "tfdef.h"

#define TF_PRNG_KEY_SIZE TF_KEY_SIZE
#define TF_PRNG_SIZE_UNIT TF_SIZE_UNIT
#define TF_PRNG_RANGE(C, T, S, D) (S + C / ((T)~0 / (D - S + 1) + 1))

size_t tf_prng_datasize(void);
void tf_prng_seedkey_r(void *sdata, const void *skey);
void tf_prng_seedkey(const void *skey);
void tf_prng_genrandom_r(void *sdata, void *result, size_t need);
void tf_prng_genrandom(void *result, size_t need);
void tf_prng_seed_r(void *sdata, TF_UNIT_TYPE seed);
void tf_prng_seed(TF_UNIT_TYPE seed);
TF_UNIT_TYPE tf_prng_random_r(void *sdata);
TF_UNIT_TYPE tf_prng_random(void);
TF_UNIT_TYPE tf_prng_range_r(void *sdata, TF_UNIT_TYPE s, TF_UNIT_TYPE d);
TF_UNIT_TYPE tf_prng_range(TF_UNIT_TYPE s, TF_UNIT_TYPE d);

#endif
