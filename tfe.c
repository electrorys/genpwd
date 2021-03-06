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
#include "tfdef.h"
#include "tfe.h"

void tfe_init_iv(struct tfe_stream *tfe, const void *key, const void *iv)
{
	memset(tfe, 0, sizeof(struct tfe_stream));
	memcpy(tfe->key, key, TF_KEY_SIZE);
	if (iv) memcpy(tfe->iv, iv, TF_BLOCK_SIZE);
	tfe->carry_bytes = 0;
}

void tfe_init(struct tfe_stream *tfe, const void *key)
{
	tfe_init_iv(tfe, key, NULL);
}

void tfe_emit(void *dst, size_t szdst, struct tfe_stream *tfe)
{
	TF_BYTE_TYPE *udst = dst;
	size_t sz = szdst;

	if (!dst && szdst == 0) {
		memset(tfe, 0, sizeof(struct tfe_stream));
		return;
	}

	if (tfe->carry_bytes > 0) {
		if (tfe->carry_bytes > szdst) {
			memcpy(udst, tfe->carry_block, szdst);
			memmove(tfe->carry_block, tfe->carry_block+szdst, tfe->carry_bytes-szdst);
			tfe->carry_bytes -= szdst;
			return;
		}

		memcpy(udst, tfe->carry_block, tfe->carry_bytes);
		udst += tfe->carry_bytes;
		sz -= tfe->carry_bytes;
		tfe->carry_bytes = 0;
	}

	if (sz >= TF_BLOCK_SIZE) {
		do {
			tf_encrypt_rawblk(tfe->iv, tfe->iv, tfe->key);
			memcpy(udst, tfe->iv, TF_BLOCK_SIZE);
			data_to_words(udst, TF_BLOCK_SIZE);
			udst += TF_BLOCK_SIZE;
		} while ((sz -= TF_BLOCK_SIZE) >= TF_BLOCK_SIZE);
	}

	if (sz) {
		TF_UNIT_TYPE t[TF_NR_BLOCK_UNITS];

		tf_encrypt_rawblk(tfe->iv, tfe->iv, tfe->key);
		memcpy(t, tfe->iv, TF_BLOCK_SIZE);
		data_to_words(t, TF_BLOCK_SIZE);
		memcpy(udst, t, sz);
		memset(t, 0, TF_BLOCK_SIZE);
		udst = (TF_BYTE_TYPE *)tfe->iv;
		tfe->carry_bytes = TF_BLOCK_SIZE-sz;
		memcpy(tfe->carry_block, udst+sz, tfe->carry_bytes);
	}
}
