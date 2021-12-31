/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
/*
 * This is an efficient implementation of POLYVAL using ARMv8 Crypto Extension
 * instructions. It works on 8 blocks at a time, by precomputing the first 8
 * keys powers h^8, ..., h^1 in the POLYVAL finite field. This precomputation
 * allows us to split finite field multiplication into two steps.
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
OP1	.req	x9
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
	eor	v25.16b, v25.16b, X.16b
	ext	v26.16b, Y.16b, Y.16b, #8
	eor	v26.16b, v26.16b, Y.16b
	pmull	v26.1q, v25.1d, v26.1d
	pmull2	v25.1q, X.2d, Y.2d
	pmull	X.1q, X.1d, Y.1d
	eor	HI.16b, HI.16b, v26.16b
	eor	LO.16b, LO.16b, v25.16b
	eor	MI.16b, MI.16b, X.16b
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
 * The montgomery form of a polynomial p(x) is p(x)x^{128}. Montgomery reduction
 * works by simultaneously dividing by x^{128} and computing the modular
 * reduction.
 *
 * Suppose we wish to reduce the montgomery form of p(x) = [P_3 : P_2 : P_1 :
 * P_0] where P_i is a polynomial of degree at most 64 represented as 64-bits.
 * Thus we would like to compute:
 *   p(x) / x^{128} mod g(x)
 *   = (P_3*x^{192} + P_2*x^{128} + P_1*x^{64} + P_0) / x^{128} mod g(x)
 *
 * We would like to divide by x^{128} efficiently. Since P_3*x^{128},
 * P_2*x^{128} are multiples of x^{128}, we can simply bitshift right by 128.
 *
 * We now focus on dividing P_1*x^{64} + P_0 by x^{128}. We do this by making
 * P_1*x^{64} + P_0 divisble by x^{128} then bitshifting. To add divisibility,
 * we consider the polynomials mod x^{128}.
 *
 * Let c(x) = P_1*x^{64} + P_0.
 *
 * Now let m(x) = c(x) mod x^{128}
 * and
 * Let z(x) = [c(x) + m(x)g(x)] / x^{128}
 *
 * First notice that:
 * c(x) + m(x)g(x) = c(x) mod g(x).
 * Furthermore, g(x) mod x^{128} = 1, so we have
 * c(x) + m(x)g(x) = c(x) + c(x) = 0 (mod x^{128}).
 *
 * Thus c(x) + m(x)g(x) is divisible by x^{128} and is equivalent to c(x) mod
 * g(x).
 *
 * In practice we use a slight modification of this idea, by using g*(x) =
 * x^{63} + x^{62} + x^{57}. This is because we can only multiply 64-bit
 * polynomials.  Notice that g(x) = x^128 + g*(x)*x^{64} + 1
 *
 * We do this by substituting g(x) = x^{128} + g*(x)x^{64} + 1
 *   z(x) = [c(x) + c(x)*(x^{128} + g*(x)*x^{64} + 1)] / x^{128}
 *     = [P_1*x^{192} + P_0*x^{128} + P_1*g*(x)x^{128} + P_0*g*(x)*x^{64} z(x)]
 *     / x^{128}
 *     = P_1*x^{64} + P_0 + P_1*g*(x) + P_0*g*(x)*x^{-64}
 *
 * The only difficulty left in this expression is P_0*g*(x)x^{-64}.
 * Let t(x) = P_0*g*(x) = [T_1 : T_0]
 * Notice that we can repeat the above process:
 *   g(x) mod x^{64} = 1
 *   m'(x) = t(x) mod x^{64}
 *   z'(x) = [t(x) + m'(x)g(x)] / x^64
 * Thus we get
 *   z'(x) = [t(x) + (x^{128} + g*(x)x^{64} + 1)T_0] / x^64
 *     = T_1 + T_0*x^{64} + g*(x)*T_0
 *
 * Recall that this is only the reduction for [P_1*x^{64} + P_0] / x^{64}. The
 * full computation we need to make is:
 *   p(x) / x^{128} = P_3*x^{64} + P_2 + P_1*x^{64} + P_0 + P_1*g*(x) +
 *   T_1 + T_0*x^{64} + g*(x)*T_0
 *
 * Thus we have:
 *   t(x) = g*(x) * P_0 = [T_1 : T_0]
 *   v(x) = g*(x) * (T_0 ^ P_1) = [V_1 : V_0]
 *   p(x) / x^{128} mod g(x) = [P_3 ^ P_1 ^ V_1 ^ T_0 : P_2 ^ P_0 ^ V_0 ^ T_1]
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
 * If reduce is set, performs interleaved montgomery reduction
 * on the last full_stride iteration's PL, PH.
 *
 * Sets PL, PH.
 */
.macro full_stride reduce
	.set reduce, \reduce
	eor		LO.16b, LO.16b, LO.16b
	eor		MI.16b, MI.16b, MI.16b
	eor		HI.16b, HI.16b, HI.16b

	ld1		{M0.16b, M1.16b, M2.16b, M3.16b}, [x0], #64
	ld1		{M4.16b, M5.16b, M6.16b, M7.16b}, [x0], #64

	karatsuba1 M7 KEY1
	.if(reduce)
	pmull	T.1q, GSTAR.1d, PL.1d
	.endif

	karatsuba1 M6 KEY2
	.if(reduce)
	ext	T.16b, T.16b, T.16b, #8
	.endif

	karatsuba1 M5 KEY3
	.if(reduce)
	eor	PL.16b, PL.16b, T.16b
	.endif

	karatsuba1 M4 KEY4
	.if(reduce)
	pmull2	V.1q, GSTAR.2d, PL.2d
	.endif

	karatsuba1 M3 KEY5
	.if(reduce)
	eor	V.16b, PL.16b, V.16b
	.endif

	karatsuba1 M2 KEY6
	.if(reduce)
	eor	PH.16b, PH.16b, V.16b
	.endif

	karatsuba1 M1 KEY7
	.if(reduce)
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
 * If op1, op2 are in montgomery form,  this computes the montgomery
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
 * Perform polynomial evaluation as specified by POLYVAL. If nblocks = k, this
 * routine multiplies the value stored at accumulator by h^k and XORs the
 * evaluated polynomial into it.
 *
 * Computes h^k * accumulator + h^kM_0 + ... + h^1M_{k-1} (No constant term)
 *
 * x0 (OP1) - pointer to message blocks
 * x1 - pointer to precomputed key struct
 * x2 - number of blocks to hash
 * x3 - location to XOR with evaluated polynomial
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
