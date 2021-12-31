/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Implementation of POLYVAL using ARMv8 Crypto Extensions.
 *
 * Copyright 2021 Google LLC
 */
/*
 * This is an efficient implementation of POLYVAL using ARMv8 Crypto Extensions
 * It works on 8 blocks at a time, by precomputing the first 8 keys powers h^8,
 * ..., h^1 in the POLYVAL finite field. This precomputation allows us to split
 * finite field multiplication into two steps.
 *
 * In the first step, we consider h^i, m_i as normal polynomials of degree less
 * than 128. We then compute p(x) = h^8m_0 + ... + h^1m_7 where multiplication
 * is simply polynomial multiplication.
 *
 * In the second step, we compute the reduction of p(x) modulo the finite field
 * modulus g(x) = x^128 + x^127 + x^126 + x^121 + 1.
 *
 * This two step process is equivalent to computing h^8m_0 + ... + h^1m_7 where
 * multiplication is finite field multiplication. The advantage is that the
 * two-step process  only requires 1 finite field reduction for every 8
 * polynomial multiplications. Further parallelism is gained by interleaving the
 * multiplications and polynomial reductions.
 */

#include <linux/linkage.h>
#define NUM_PRECOMPUTE_POWERS 8

BLOCKS_LEFT	.req	x2
KEY_START	.req	x10
EXTRA_BYTES	.req	x11
IND	.req	x12
TMP	.req	x13
PARTIAL_LEFT	.req	x14

M0	.req	v0
M1	.req	v1
M2	.req	v2
M3	.req	v3
M4	.req	v4
M5	.req	v5
M6	.req	v6
M7	.req	v7
KEY8	.req	v8
KEY7	.req	v9
KEY6	.req	v10
KEY5	.req	v11
KEY4	.req	v12
KEY3	.req	v13
KEY2	.req	v14
KEY1	.req	v15
PL	.req	v16
PH	.req	v17
T	.req	v18
V	.req	v19
LO	.req	v20
MI	.req	v21
HI	.req	v22
SUM	.req	v23
GSTAR	.req	v24

	.text
	.align	4

	.arch	armv8-a+crypto
	.align	4

.Lgstar:
	.quad	0xc200000000000000, 0xc200000000000000

/*
 * Computes the product of two 128-bit polynomials in X and Y and XORs the
 * components of the 256-bit product into LO, MI, HI.
 *
 * The multiplication produces four parts:
 *   LOW: The polynomial given by performing carryless multiplication of X_L and
 *   Y_L
 *   MID: The polynomial given by performing carryless multiplication of (X_L ^
 *   X_H) and (Y_L ^ Y_H)
 *   HIGH: The polynomial given by performing carryless multiplication of X_H
 *   and Y_H
 *
 * We compute:
 *  LO ^= LOW
 *  MI ^= MID
 *  HI ^= HIGH
 *
 * Later, the 256-bit result can be extracted as:
 *   [HI_H : HI_L ^ HI_H ^ MI_H ^ LO_H :: LO_H ^ HI_L ^ MI_L ^ LO_L : LO_L]
 * This step is done when computing the polynomial reduction for efficiency
 * reasons.
 */
.macro karatsuba1 X Y
	X .req \X
	Y .req \Y
	ext	v25.16b, X.16b, Y.16b, #8
	ext	v26.16b, Y.16b, Y.16b, #8
	eor	v25.16b, v25.16b, X.16b
	eor	v26.16b, v26.16b, Y.16b
	pmull	v27.1q, v25.1d, v26.1d
	pmull2	v28.1q, X.2d, Y.2d
	pmull	v29.1q, X.1d, Y.1d
	eor	HI.16b, HI.16b, v27.16b
	eor	LO.16b, LO.16b, v28.16b
	eor	MI.16b, MI.16b, v29.16b
	.unreq X
	.unreq Y
.endm

/*
 * Computes the 256-bit polynomial represented by LO, HI, MI. Stores
 * the result in PL, PH.
 *   [PH :: PL] = [HI_H : HI_L ^ HI_H ^ MI_H ^ LO_H :: LO_H ^ HI_L ^ MI_L ^ LO_L
 *   : LO_L]
 */
.macro karatsuba2
	ext	v4.16b, MI.16b, LO.16b, #8
	eor	HI.16b, HI.16b, v4.16b //[HI1 ^ LO0 : HI0 ^ MI1]
	eor	v4.16b, LO.16b, MI.16b //[LO1 ^ MI1 : LO0 ^ MI0]
	//[LO0 ^ LO1 ^ MI1 ^ HI1 : MI1 ^ LO0 ^ MI0 ^ HI0]
	eor	v4.16b, HI.16b, v4.16b
	ext	LO.16b, LO.16b, LO.16b, #8 // [LO0 : LO1]
	ext	MI.16b, MI.16b, MI.16b, #8 // [MI0 : MI1]
	ext	PH.16b, v4.16b, LO.16b, #8 //[LO1 : LO1 ^ MI1 ^ HI1 ^ LO0]
	ext	PL.16b, MI.16b, v4.16b, #8 //[MI1 ^ LO0 ^ MI0 ^ HI0 : MI0]
.endm

/*
 * Computes the 128-bit reduction of PL, PH. Stores the result in PH.
 *
 * This macro computes p(x) mod g(x) where p(x) is in montgomery form and g(x) =
 * x^128 + x^127 + x^126 + x^121 + 1.
 *
 * We have a 256-bit polynomial P_3 : P_2 : P_1 : P_0 that is the product of
 * two 128-bit polynomials in Montgomery form.  We need to reduce it mod g(x).
 * Also, since polynomials in Montgomery form have an "extra" factor of x^128,
 * this product has two extra factors of x^128.  To get it back into Montgomery
 * form, we need to remove one of these factors by dividing by x^128.
 *
 * To accomplish both of these goals, we add multiples of g(x) that cancel out
 * the low 128 bits P_1 : P_0, leaving just the high 128 bits. Since the low
 * bits are zero, the polynomial division by x^128 can be done by right shifting.
 *
 * Since the only nonzero term in the low 64 bits of g(x) is the constant term,
 * the multiple of g(x) needed to cancel out P_0 is P_0 * g(x).  The CPU can
 * only do 64x64 bit multiplications, so split P_0 * g(x) into x^128 * P_0 +
 * x^64 g*(x) * P_0 + P_0, where g*(x) is bits 64-127 of g(x).  Adding this to
 * the original polynomial gives P_3 : P_2 + P_0 + T_1 : P_1 + T_0 : 0, where T
 * = T_1 : T_0 = g*(x) * P0.  Thus, bits 0-63 got "folded" into bits 64-191.
 *
 * Repeating this same process on the next 64 bits "folds" bits 64-127 into bits
 * 128-255, giving the answer in bits 128-255. This time, we need to cancel P_1
 * + T_0 in bits 64-127. The multiple of g(x) required is (P_1 + T_0) * g(x) *
 * x^64. Adding this to our previous computation gives P_3 + P_1 + T_0 + V_1 :
 * P_2 + P_0 + T_1 + V_0 : 0 : 0, where V = V_1 : V_0 = g*(x) * (P_1 + T_0).
 *
 * So our final computation is:
 *   T = T_1 : T_0 = g*(x) * P_0
 *   V = V_1 : V_0 = g*(x) * (T_0 ^ P_1)
 *   p(x) / x^{128} mod g(x) = P_3 ^ P_1 ^ V_1 ^ T_0 : P_2 ^ P_0 ^ V_0 ^ T_1
 *
 * The implementation below saves a XOR instruction by computing P_1 ^ T_0 : P_0
 * ^ T_1 and XORing it into V, rather than directly XORing P_1 : P_0, T_0 : T1
 * into PH.  This allows us to reuse P_1 ^ T_0 when computing V.
 */
.macro montgomery_reduction
	pmull	T.1q, GSTAR.1d, PL.1d
	ext	T.16b, T.16b, T.16b, #8
	eor	PL.16b, PL.16b, T.16b
	pmull2	V.1q, GSTAR.2d, PL.2d
	eor	V.16b, PL.16b, V.16b
	eor	PH.16b, PH.16b, V.16b
.endm

/*
 * Compute Polyval on 8 blocks.
 *
 * If reduce is set, also computes the montgomery reduction of the
 * previous full_stride call and XORs with the first message block.
 * (m_0 + REDUCE(PL, PH))h^8 + ... + m_7h^1.
 * I.e., the first multiplication uses m_0 + REDUCE(PL, PH) instead of m_0.
 *
 * Sets PL, PH.
 */
.macro full_stride reduce
	eor		LO.16b, LO.16b, LO.16b
	eor		MI.16b, MI.16b, MI.16b
	eor		HI.16b, HI.16b, HI.16b

	ld1		{M0.16b, M1.16b, M2.16b, M3.16b}, [x0], #64
	ld1		{M4.16b, M5.16b, M6.16b, M7.16b}, [x0], #64

	karatsuba1 M7 KEY1
	.if (\reduce)
	pmull	T.1q, GSTAR.1d, PL.1d
	.endif

	karatsuba1 M6 KEY2
	.if (\reduce)
	ext	T.16b, T.16b, T.16b, #8
	.endif

	karatsuba1 M5 KEY3
	.if (\reduce)
	eor	PL.16b, PL.16b, T.16b
	.endif

	karatsuba1 M4 KEY4
	.if (\reduce)
	pmull2	V.1q, GSTAR.2d, PL.2d
	.endif

	karatsuba1 M3 KEY5
	.if (\reduce)
	eor	V.16b, PL.16b, V.16b
	.endif

	karatsuba1 M2 KEY6
	.if (\reduce)
	eor	PH.16b, PH.16b, V.16b
	.endif

	karatsuba1 M1 KEY7
	.if (\reduce)
	mov	SUM.16b, PH.16b
	.endif
	eor	M0.16b, M0.16b, SUM.16b

	karatsuba1 M0 KEY8

	karatsuba2
.endm

/*
 * Handle any extra blocks before
 * full_stride loop.
 */
.macro partial_stride
	eor		LO.16b, LO.16b, LO.16b
	eor		MI.16b, MI.16b, MI.16b
	eor		HI.16b, HI.16b, HI.16b
	add		KEY_START, x1, #(NUM_PRECOMPUTE_POWERS << 4)
	sub		KEY_START, KEY_START, PARTIAL_LEFT, lsl #4
	ld1		{v0.16b}, [KEY_START]
	mov		v1.16b, SUM.16b
	karatsuba1 v0 v1
	karatsuba2
	montgomery_reduction
	mov		SUM.16b, PH.16b
	eor		LO.16b, LO.16b, LO.16b
	eor		MI.16b, MI.16b, MI.16b
	eor		HI.16b, HI.16b, HI.16b
	mov		IND, XZR
.LloopPartial:
	cmp		IND, PARTIAL_LEFT
	bge		.LloopExitPartial

	sub		TMP, IND, PARTIAL_LEFT

	cmp		TMP, #-4
	bgt		.Lgt4Partial
	ld1		{M0.16b, M1.16b,  M2.16b, M3.16b}, [x0], #64
	// Clobber key registers
	ld1		{KEY8.16b, KEY7.16b, KEY6.16b,  KEY5.16b}, [KEY_START], #64
	karatsuba1 M0 KEY8
	karatsuba1 M1 KEY7
	karatsuba1 M2 KEY6
	karatsuba1 M3 KEY5
	add		IND, IND, #4
	b		.LoutPartial

.Lgt4Partial:
	cmp		TMP, #-3
	bgt		.Lgt3Partial
	ld1		{M0.16b, M1.16b, M2.16b}, [x0], #48
	// Clobber key registers
	ld1		{KEY8.16b, KEY7.16b, KEY6.16b}, [KEY_START], #48
	karatsuba1 M0 KEY8
	karatsuba1 M1 KEY7
	karatsuba1 M2 KEY6
	add		IND, IND, #3
	b		.LoutPartial

.Lgt3Partial:
	cmp		TMP, #-2
	bgt		.Lgt2Partial
	ld1		{M0.16b, M1.16b}, [x0], #32
	// Clobber key registers
	ld1		{KEY8.16b, KEY7.16b}, [KEY_START], #32
	karatsuba1 M0 KEY8
	karatsuba1 M1 KEY7
	add		IND, IND, #2
	b		.LoutPartial

.Lgt2Partial:
	ld1		{M0.16b}, [x0], #16
	// Clobber key registers
	ld1		{KEY8.16b}, [KEY_START], #16
	karatsuba1 M0 KEY8
	add		IND, IND, #1
.LoutPartial:
	b .LloopPartial
.LloopExitPartial:
	karatsuba2
	montgomery_reduction
	eor		SUM.16b, SUM.16b, PH.16b
.endm

/*
 * Perform montgomery multiplication in GF(2^128) and store result in op1.
 *
 * Computes op1*op2*x^{-128} mod x^128 + x^127 + x^126 + x^121 + 1
 * If op1, op2 are in montgomery form, this computes the montgomery
 * form of op1*op2.
 *
 * void pmull_polyval_mul(u8 *op1, const u8 *op2);
 */
SYM_FUNC_START(pmull_polyval_mul)
	adr		TMP, .Lgstar
	ld1		{GSTAR.2d}, [TMP]
	eor		LO.16b, LO.16b, LO.16b
	eor		MI.16b, MI.16b, MI.16b
	eor		HI.16b, HI.16b, HI.16b
	ld1		{v0.16b}, [x0]
	ld1		{v1.16b}, [x1]
	karatsuba1 v0 v1
	karatsuba2
	montgomery_reduction
	st1		{PH.16b}, [x0]
	ret
SYM_FUNC_END(pmull_polyval_mul)

/*
 * Perform polynomial evaluation as specified by POLYVAL.  This computes:
 * 	h^n * accumulator + h^n * m_0 + ... + h^1 * m_{n-1}
 * where n=nblocks, h is the hash key, and m_i are the message blocks.
 *
 * x0 - pointer to message blocks
 * x1 - pointer to precomputed key powers h^8 ... h^1
 * x2 - number of blocks to hash
 * x3 - pointer to accumulator
 *
 * void pmull_polyval_update(const u8 *in, const struct polyval_ctx *ctx,
 *			     size_t nblocks, u8 *accumulator);
 */
SYM_FUNC_START(pmull_polyval_update)
	adr		TMP, .Lgstar
	ld1		{GSTAR.2d}, [TMP]
	ld1		{SUM.16b}, [x3]
	ands		PARTIAL_LEFT, BLOCKS_LEFT, #7
	beq		.LskipPartial
	partial_stride
.LskipPartial:
	subs		BLOCKS_LEFT, BLOCKS_LEFT, #NUM_PRECOMPUTE_POWERS
	blt		.LstrideLoopExit
	ld1		{KEY8.16b, KEY7.16b, KEY6.16b, KEY5.16b}, [x1], #64
	ld1		{KEY4.16b, KEY3.16b, KEY2.16b, KEY1.16b}, [x1], #64
	full_stride 0
	subs		BLOCKS_LEFT, BLOCKS_LEFT, #NUM_PRECOMPUTE_POWERS
	blt		.LstrideLoopExitReduce
.LstrideLoop:
	full_stride 1
	subs		BLOCKS_LEFT, BLOCKS_LEFT, #NUM_PRECOMPUTE_POWERS
	bge		.LstrideLoop
.LstrideLoopExitReduce:
	montgomery_reduction
	mov		SUM.16b, PH.16b
.LstrideLoopExit:
	st1		{SUM.16b}, [x3]
	ret
SYM_FUNC_END(pmull_polyval_update)
