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

#ifndef _TF_STREAM_CIPHER_DEFS
#define _TF_STREAM_CIPHER_DEFS

#include "tfdef.h"

struct tfe_stream {
	TF_UNIT_TYPE key[TF_NR_KEY_UNITS];
	TF_UNIT_TYPE iv[TF_NR_BLOCK_UNITS];
	TF_BYTE_TYPE carry_block[TF_BLOCK_SIZE];
	size_t carry_bytes;
};

void tfe_init(struct tfe_stream *tfe, const void *key);
void tfe_init_iv(struct tfe_stream *tfe, const void *key, const void *iv);
void tfe_emit(void *dst, size_t szdst, struct tfe_stream *tfe);

#endif
