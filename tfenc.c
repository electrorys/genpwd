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

#include "tfdef.h"
#include "tfcore.h"

#if defined(TF_256BITS)

#define PROCESS_BLOCKP(x,k1,k2,k3,k4,k5,k6)						\
	do {										\
		KE_MIX(Y, X, k1 + k2, k3, TFS_KS01);					\
		KE_MIX(T, Z, k4 + x, k5 + k6, TFS_KS02);				\
											\
		BE_MIX(X, T, TFS_BS01); BE_MIX(Z, Y, TFS_BS02);				\
		BE_MIX(X, Y, TFS_BS03); BE_MIX(Z, T, TFS_BS04);				\
		BE_MIX(X, T, TFS_BS05); BE_MIX(Z, Y, TFS_BS06);				\
	} while (0)

#define PROCESS_BLOCKN(x,k1,k2,k3,k4,k5,k6)						\
	do {										\
		KE_MIX(Y, X, k1 + k2, k3, TFS_KS03);					\
		KE_MIX(T, Z, k4 + x, k5 + k6, TFS_KS04);				\
											\
		BE_MIX(X, T, TFS_BS07); BE_MIX(Z, Y, TFS_BS08);				\
		BE_MIX(X, Y, TFS_BS09); BE_MIX(Z, T, TFS_BS10);				\
		BE_MIX(X, T, TFS_BS11); BE_MIX(Z, Y, TFS_BS12);				\
	} while (0)

void tf_encrypt_rawblk(TF_UNIT_TYPE *O, const TF_UNIT_TYPE *I, const TF_UNIT_TYPE *K)
{
	TF_UNIT_TYPE X, Y, Z, T;
	TF_UNIT_TYPE K0, K1, K2, K3;
	TF_UNIT_TYPE K4, T0, T1, T2;

	X = I[0]; Y = I[1]; Z = I[2]; T = I[3];

	K0 = K[0]; K1 = K[1]; K2 = K[2]; K3 = K[3];
	K4 = K[4]; T0 = K[5]; T1 = K[6]; T2 = K[7];

	PROCESS_BLOCKP( 0,K1,T0,K0,K3,K2,T1);
	PROCESS_BLOCKN( 1,K2,T1,K1,K4,K3,T2);
	PROCESS_BLOCKP( 2,K3,T2,K2,K0,K4,T0);
	PROCESS_BLOCKN( 3,K4,T0,K3,K1,K0,T1);

	PROCESS_BLOCKP( 4,K0,T1,K4,K2,K1,T2);
	PROCESS_BLOCKN( 5,K1,T2,K0,K3,K2,T0);
	PROCESS_BLOCKP( 6,K2,T0,K1,K4,K3,T1);
	PROCESS_BLOCKN( 7,K3,T1,K2,K0,K4,T2);

	PROCESS_BLOCKP( 8,K4,T2,K3,K1,K0,T0);
	PROCESS_BLOCKN( 9,K0,T0,K4,K2,K1,T1);
	PROCESS_BLOCKP(10,K1,T1,K0,K3,K2,T2);
	PROCESS_BLOCKN(11,K2,T2,K1,K4,K3,T0);

	PROCESS_BLOCKP(12,K3,T0,K2,K0,K4,T1);
	PROCESS_BLOCKN(13,K4,T1,K3,K1,K0,T2);
	PROCESS_BLOCKP(14,K0,T2,K4,K2,K1,T0);
	PROCESS_BLOCKN(15,K1,T0,K0,K3,K2,T1);

	PROCESS_BLOCKP(16,K2,T1,K1,K4,K3,T2);
	PROCESS_BLOCKN(17,K3,T2,K2,K0,K4,T0);

	O[0] = X + K3; O[1] = Y + K4 + T0; O[2] = Z + K0 + T1; O[3] = T + K1 + 18;
}

#elif defined(TF_512BITS)

#define PROCESS_BLOCKP(x,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10)				\
	do {										\
		KE_MIX(Y, X, k1, k2, TFS_KS01); KE_MIX(T, Z, k3, k4, TFS_KS02);		\
		KE_MIX(W, E, k5 + k6, k7, TFS_KS03);					\
		KE_MIX(N, V, k8 + x, k9 + k10, TFS_KS04);				\
											\
		BE_MIX(Z, Y, TFS_BS01); BE_MIX(E, N, TFS_BS02);				\
		BE_MIX(V, W, TFS_BS03); BE_MIX(X, T, TFS_BS04);				\
		BE_MIX(E, Y, TFS_BS05); BE_MIX(V, T, TFS_BS06);				\
		BE_MIX(X, W, TFS_BS07); BE_MIX(Z, N, TFS_BS08);				\
		BE_MIX(V, Y, TFS_BS09); BE_MIX(X, N, TFS_BS10);				\
		BE_MIX(Z, W, TFS_BS11); BE_MIX(E, T, TFS_BS12);				\
	} while (0)

#define PROCESS_BLOCKN(x,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10)				\
	do {										\
		KE_MIX(Y, X, k1, k2, TFS_KS05); KE_MIX(T, Z, k3, k4, TFS_KS06);		\
		KE_MIX(W, E, k5 + k6, k7, TFS_KS07);					\
		KE_MIX(N, V, k8 + x, k9 + k10, TFS_KS08);				\
											\
		BE_MIX(Z, Y, TFS_BS13); BE_MIX(E, N, TFS_BS14);				\
		BE_MIX(V, W, TFS_BS15); BE_MIX(X, T, TFS_BS16);				\
		BE_MIX(E, Y, TFS_BS17); BE_MIX(V, T, TFS_BS18);				\
		BE_MIX(X, W, TFS_BS19); BE_MIX(Z, N, TFS_BS20);				\
		BE_MIX(V, Y, TFS_BS21); BE_MIX(X, N, TFS_BS22);				\
		BE_MIX(Z, W, TFS_BS23); BE_MIX(E, T, TFS_BS24);				\
	} while (0)

void tf_encrypt_rawblk(TF_UNIT_TYPE *O, const TF_UNIT_TYPE *I, const TF_UNIT_TYPE *K)
{
	TF_UNIT_TYPE X, Y, Z, T;
	TF_UNIT_TYPE E, W, V, N;
	TF_UNIT_TYPE K0, K1, K2, K3;
	TF_UNIT_TYPE K4, K5, K6, K7;
	TF_UNIT_TYPE K8, T0, T1, T2;

	X = I[0]; Y = I[1]; Z = I[2]; T = I[3];
	E = I[4]; W = I[5]; V = I[6]; N = I[7];

	K0 = K[ 0]; K1 = K[ 1]; K2 = K[ 2]; K3 = K[ 3];
	K4 = K[ 4]; K5 = K[ 5]; K6 = K[ 6]; K7 = K[ 7];
	K8 = K[ 8]; T0 = K[ 9]; T1 = K[10]; T2 = K[11];

	PROCESS_BLOCKP( 0,K1,K0,K3,K2,K5,T0,K4,K7,K6,T1);
	PROCESS_BLOCKN( 1,K2,K1,K4,K3,K6,T1,K5,K8,K7,T2);
	PROCESS_BLOCKP( 2,K3,K2,K5,K4,K7,T2,K6,K0,K8,T0);
	PROCESS_BLOCKN( 3,K4,K3,K6,K5,K8,T0,K7,K1,K0,T1);

	PROCESS_BLOCKP( 4,K5,K4,K7,K6,K0,T1,K8,K2,K1,T2);
	PROCESS_BLOCKN( 5,K6,K5,K8,K7,K1,T2,K0,K3,K2,T0);
	PROCESS_BLOCKP( 6,K7,K6,K0,K8,K2,T0,K1,K4,K3,T1);
	PROCESS_BLOCKN( 7,K8,K7,K1,K0,K3,T1,K2,K5,K4,T2);

	PROCESS_BLOCKP( 8,K0,K8,K2,K1,K4,T2,K3,K6,K5,T0);
	PROCESS_BLOCKN( 9,K1,K0,K3,K2,K5,T0,K4,K7,K6,T1);
	PROCESS_BLOCKP(10,K2,K1,K4,K3,K6,T1,K5,K8,K7,T2);
	PROCESS_BLOCKN(11,K3,K2,K5,K4,K7,T2,K6,K0,K8,T0);

	PROCESS_BLOCKP(12,K4,K3,K6,K5,K8,T0,K7,K1,K0,T1);
	PROCESS_BLOCKN(13,K5,K4,K7,K6,K0,T1,K8,K2,K1,T2);
	PROCESS_BLOCKP(14,K6,K5,K8,K7,K1,T2,K0,K3,K2,T0);
	PROCESS_BLOCKN(15,K7,K6,K0,K8,K2,T0,K1,K4,K3,T1);

	PROCESS_BLOCKP(16,K8,K7,K1,K0,K3,T1,K2,K5,K4,T2);
	PROCESS_BLOCKN(17,K0,K8,K2,K1,K4,T2,K3,K6,K5,T0);

	O[0] = X + K0; O[1] = Y + K1; O[2] = Z + K2; O[3] = T + K3;
	O[4] = E + K4; O[5] = W + K5 + T0; O[6] = V + K6 + T1; O[7] = N + K7 + 18;
}

#elif defined(TF_1024BITS)

#define PROCESS_BLOCKP(x,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18)\
	do {										\
		KE_MIX(Y, X, k1, k2, TFS_KS01); KE_MIX(T, Z, k3, k4, TFS_KS02);		\
		KE_MIX(W, E, k5, k6, TFS_KS03); KE_MIX(N, V, k7, k8, TFS_KS04);		\
		KE_MIX(U, P, k9, k10, TFS_KS05); KE_MIX(Q, M, k11, k12, TFS_KS06);	\
		KE_MIX(B, A, k13 + k14, k15, TFS_KS07);					\
		KE_MIX(L, H, k16 + x, k17 + k18, TFS_KS08);				\
											\
		BE_MIX(X, U, TFS_BS01); BE_MIX(Z, B, TFS_BS02);				\
		BE_MIX(V, Q, TFS_BS03); BE_MIX(E, L, TFS_BS04);				\
		BE_MIX(M, N, TFS_BS05); BE_MIX(A, T, TFS_BS06);				\
		BE_MIX(H, W, TFS_BS07); BE_MIX(P, Y, TFS_BS08);				\
		BE_MIX(X, N, TFS_BS09); BE_MIX(Z, W, TFS_BS10);				\
		BE_MIX(E, T, TFS_BS11); BE_MIX(V, Y, TFS_BS12);				\
		BE_MIX(A, L, TFS_BS13); BE_MIX(H, B, TFS_BS14);				\
		BE_MIX(P, Q, TFS_BS15); BE_MIX(M, U, TFS_BS16);				\
		BE_MIX(X, L, TFS_BS17); BE_MIX(Z, Q, TFS_BS18);				\
		BE_MIX(V, B, TFS_BS19); BE_MIX(E, U, TFS_BS20);				\
		BE_MIX(H, Y, TFS_BS21); BE_MIX(P, W, TFS_BS22);				\
		BE_MIX(M, T, TFS_BS23); BE_MIX(A, N, TFS_BS24);				\
	} while (0)

#define PROCESS_BLOCKN(x,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18)\
	do {										\
		KE_MIX(Y, X, k1, k2, TFS_KS09); KE_MIX(T, Z, k3, k4, TFS_KS10);		\
		KE_MIX(W, E, k5, k6, TFS_KS11); KE_MIX(N, V, k7, k8, TFS_KS12);		\
		KE_MIX(U, P, k9, k10, TFS_KS13); KE_MIX(Q, M, k11, k12, TFS_KS14);	\
		KE_MIX(B, A, k13 + k14, k15, TFS_KS15);					\
		KE_MIX(L, H, k16 + x, k17 + k18, TFS_KS16);				\
											\
		BE_MIX(X, U, TFS_BS25); BE_MIX(Z, B, TFS_BS26);				\
		BE_MIX(V, Q, TFS_BS27); BE_MIX(E, L, TFS_BS28);				\
		BE_MIX(M, N, TFS_BS29); BE_MIX(A, T, TFS_BS30);				\
		BE_MIX(H, W, TFS_BS31); BE_MIX(P, Y, TFS_BS32);				\
		BE_MIX(X, N, TFS_BS33); BE_MIX(Z, W, TFS_BS34);				\
		BE_MIX(E, T, TFS_BS35); BE_MIX(V, Y, TFS_BS36);				\
		BE_MIX(A, L, TFS_BS37); BE_MIX(H, B, TFS_BS38);				\
		BE_MIX(P, Q, TFS_BS39); BE_MIX(M, U, TFS_BS40);				\
		BE_MIX(X, L, TFS_BS41); BE_MIX(Z, Q, TFS_BS42);				\
		BE_MIX(V, B, TFS_BS43); BE_MIX(E, U, TFS_BS44);				\
		BE_MIX(H, Y, TFS_BS45); BE_MIX(P, W, TFS_BS46);				\
		BE_MIX(M, T, TFS_BS47); BE_MIX(A, N, TFS_BS48);				\
	} while (0)

void tf_encrypt_rawblk(TF_UNIT_TYPE *O, const TF_UNIT_TYPE *I, const TF_UNIT_TYPE *K)
{
	TF_UNIT_TYPE X, Y, Z, T;
	TF_UNIT_TYPE E, W, V, N;
	TF_UNIT_TYPE P, U, M, Q;
	TF_UNIT_TYPE A, B, H, L;
	TF_UNIT_TYPE K0, K1, K2, K3;
	TF_UNIT_TYPE K4, K5, K6, K7;
	TF_UNIT_TYPE K8, K9, K10, K11;
	TF_UNIT_TYPE K12, K13, K14, K15;
	TF_UNIT_TYPE K16, T0, T1, T2;

	X = I[ 0]; Y = I[ 1]; Z = I[ 2]; T = I[ 3];
	E = I[ 4]; W = I[ 5]; V = I[ 6]; N = I[ 7];
	P = I[ 8]; U = I[ 9]; M = I[10]; Q = I[11];
	A = I[12]; B = I[13]; H = I[14]; L = I[15];

	K0  = K[ 0]; K1  = K[ 1]; K2  = K[ 2]; K3  = K[ 3];
	K4  = K[ 4]; K5  = K[ 5]; K6  = K[ 6]; K7  = K[ 7];
	K8  = K[ 8]; K9  = K[ 9]; K10 = K[10]; K11 = K[11];
	K12 = K[12]; K13 = K[13]; K14 = K[14]; K15 = K[15];
	K16 = K[16]; T0  = K[17]; T1  = K[18]; T2  = K[19];

	PROCESS_BLOCKP( 0, K1, K0, K3, K2, K5, K4, K7, K6, K9, K8,K11,K10,K13, T0,K12,K15,K14, T1);
	PROCESS_BLOCKN( 1, K2, K1, K4, K3, K6, K5, K8, K7,K10, K9,K12,K11,K14, T1,K13,K16,K15, T2);
	PROCESS_BLOCKP( 2, K3, K2, K5, K4, K7, K6, K9, K8,K11,K10,K13,K12,K15, T2,K14, K0,K16, T0);
	PROCESS_BLOCKN( 3, K4, K3, K6, K5, K8, K7,K10, K9,K12,K11,K14,K13,K16, T0,K15, K1, K0, T1);

	PROCESS_BLOCKP( 4, K5, K4, K7, K6, K9, K8,K11,K10,K13,K12,K15,K14, K0, T1,K16, K2, K1, T2);
	PROCESS_BLOCKN( 5, K6, K5, K8, K7,K10, K9,K12,K11,K14,K13,K16,K15, K1, T2, K0, K3, K2, T0);
	PROCESS_BLOCKP( 6, K7, K6, K9, K8,K11,K10,K13,K12,K15,K14, K0,K16, K2, T0, K1, K4, K3, T1);
	PROCESS_BLOCKN( 7, K8, K7,K10, K9,K12,K11,K14,K13,K16,K15, K1, K0, K3, T1, K2, K5, K4, T2);

	PROCESS_BLOCKP( 8, K9, K8,K11,K10,K13,K12,K15,K14, K0,K16, K2, K1, K4, T2, K3, K6, K5, T0);
	PROCESS_BLOCKN( 9,K10, K9,K12,K11,K14,K13,K16,K15, K1, K0, K3, K2, K5, T0, K4, K7, K6, T1);
	PROCESS_BLOCKP(10,K11,K10,K13,K12,K15,K14, K0,K16, K2, K1, K4, K3, K6, T1, K5, K8, K7, T2);
	PROCESS_BLOCKN(11,K12,K11,K14,K13,K16,K15, K1, K0, K3, K2, K5, K4, K7, T2, K6, K9, K8, T0);

	PROCESS_BLOCKP(12,K13,K12,K15,K14, K0,K16, K2, K1, K4, K3, K6, K5, K8, T0, K7,K10, K9, T1);
	PROCESS_BLOCKN(13,K14,K13,K16,K15, K1, K0, K3, K2, K5, K4, K7, K6, K9, T1, K8,K11,K10, T2);
	PROCESS_BLOCKP(14,K15,K14, K0,K16, K2, K1, K4, K3, K6, K5, K8, K7,K10, T2, K9,K12,K11, T0);
	PROCESS_BLOCKN(15,K16,K15, K1, K0, K3, K2, K5, K4, K7, K6, K9, K8,K11, T0,K10,K13,K12, T1);

	PROCESS_BLOCKP(16, K0,K16, K2, K1, K4, K3, K6, K5, K8, K7,K10, K9,K12, T1,K11,K14,K13, T2);
	PROCESS_BLOCKN(17, K1, K0, K3, K2, K5, K4, K7, K6, K9, K8,K11,K10,K13, T2,K12,K15,K14, T0);
	PROCESS_BLOCKP(18, K2, K1, K4, K3, K6, K5, K8, K7,K10, K9,K12,K11,K14, T0,K13,K16,K15, T1);
	PROCESS_BLOCKN(19, K3, K2, K5, K4, K7, K6, K9, K8,K11,K10,K13,K12,K15, T1,K14, K0,K16, T2);

	O[0] = X + K3; O[1] = Y + K4; O[2] = Z + K5; O[3] = T + K6;
	O[4] = E + K7; O[5] = W + K8; O[6] = V + K9; O[7] = N + K10;
	O[8] = P + K11; O[9] = U + K12; O[10] = M + K13; O[11] = Q + K14;
	O[12] = A + K15; O[13] = B + K16 + T2; O[14] = H + K0 + T0; O[15] = L + K1 + 20;
}

#endif
