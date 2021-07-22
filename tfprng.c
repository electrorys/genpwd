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

#include <string.h>
#include "tfe.h"
#include "tfprng.h"

struct tf_prng_data {
	struct tfe_stream tfe;
	short init;
};

struct tf_prng_data tf_prng_sdata;

size_t tf_prng_datasize(void)
{
	return sizeof(struct tf_prng_data);
}

void tf_prng_seedkey_r(void *sdata, const void *skey)
{
	TF_UNIT_TYPE k[TF_NR_KEY_UNITS];
	struct tf_prng_data *rprng = sdata;

	memset(rprng, 0, tf_prng_datasize());
	if (!skey) return;

	memcpy(k, skey, TF_KEY_SIZE);
	tfe_init(&rprng->tfe, k);
	rprng->init = 1;

	memset(k, 0, TF_KEY_SIZE);
}

void tf_prng_seedkey(const void *skey)
{
	tf_prng_seedkey_r(&tf_prng_sdata, skey);
}

void tf_prng_genrandom_r(void *sdata, void *result, size_t need)
{
	struct tf_prng_data *rprng = sdata;
	memset(result, 0, need);
	tfe_emit(result, need, &rprng->tfe);
}

void tf_prng_genrandom(void *result, size_t need)
{
	tf_prng_genrandom_r(&tf_prng_sdata, result, need);
}

void tf_prng_seed_r(void *sdata, TF_UNIT_TYPE seed)
{
	TF_UNIT_TYPE k[TF_NR_KEY_UNITS];
	struct tf_prng_data *rprng = sdata;
	size_t x;

	memset(rprng, 0, tf_prng_datasize());
	for (x = 0; x < TF_NR_KEY_UNITS; x++) k[x] = seed;
	tfe_init(&rprng->tfe, k);
	rprng->init = 1;

	memset(k, 0, TF_KEY_SIZE);
}

void tf_prng_seed(TF_UNIT_TYPE seed)
{
	tf_prng_seed_r(&tf_prng_sdata, seed);
}

TF_UNIT_TYPE tf_prng_random_r(void *sdata)
{
	struct tf_prng_data *rprng = sdata;
	TF_UNIT_TYPE r;

	if (!rprng->init) return 0;

	tfe_emit(&r, sizeof(r), &rprng->tfe);
	return r;
}

TF_UNIT_TYPE tf_prng_random(void)
{
	return tf_prng_random_r(&tf_prng_sdata);
}

TF_UNIT_TYPE tf_prng_range_r(void *sdata, TF_UNIT_TYPE s, TF_UNIT_TYPE d)
{
	TF_UNIT_TYPE c = tf_prng_random_r(sdata);
	if (d <= s) return s;
	return TF_PRNG_RANGE(c, TF_UNIT_TYPE, s, d);
}

TF_UNIT_TYPE tf_prng_range(TF_UNIT_TYPE s, TF_UNIT_TYPE d)
{
	return tf_prng_range_r(&tf_prng_sdata, s, d);
}
