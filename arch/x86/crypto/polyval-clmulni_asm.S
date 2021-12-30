/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
/*
 * This is an efficient implementation of POLYVAL using intel PCLMULQDQ-NI
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
#include <asm/frame.h>

#define NUM_PRECOMPUTE_POWERS 8

#define GSTAR %xmm7
#define PL %xmm8
#define PH %xmm9
#define T %xmm10
#define V %xmm11
#define LO %xmm12
#define HI %xmm13
#define MI %xmm14
#define SUM %xmm15

#define BLOCKS_LEFT %rdx
#define OP1 %rdi
#define OP2 %r10
#define IDX %r11
#define TMP %rax

.section    .rodata.cst16.gstar, "aM", @progbits, 16
.align 16

Lgstar:
	.quad 0xc200000000000000, 0xc200000000000000

.text

/*
 * Performs schoolbook1_iteration on two lists of 128-bit polynomials of length
 * b pointed to by OP1 and OP2.
 */
.macro schoolbook1 b
	.set by, \b
	.set i, 0
	.rept (by)
		schoolbook1_iteration i 0
		.set i, (i +1)
	.endr
.endm

/*
 * Computes the product of two 128-bit polynomials at the memory locations
 * specified by (OP1 + 16*i) and (OP2 + 16*i) and XORs the components of the
 * 256-bit product into LO, MI, HI.
 *
 * The multiplication produces four parts:
 *   LOW: The polynomial given by performing carryless multiplication of the
 *   bottom 64-bits of each polynomial
 *   MID1: The polynomial given by performing carryless multiplication of the
 *   bottom 64-bits of the first polynomial and the top 64-bits of the second
 *   MID2: The polynomial given by performing carryless multiplication of the
 *   bottom 64-bits of the second polynomial and the top 64-bits of the first
 *   HIGH: The polynomial given by performing carryless multiplication of the
 *   top 64-bits of each polynomial
 *
 * We compute:
 *  LO ^= LOW
 *  Mi ^= MID1 ^ MID2
 *  Hi ^= HIGH
 *
 * Later, the 256-bit result can be extracted as:
 *   [HI_H : HI_L ^ MI_H : LO_H ^ MI_L : LO_L]
 * This step is done when computing the polynomial reduction for efficiency
 * reasons.
 *
 * If xor_sum == 1 then XOR the value of SUM into m_0.
 * This avoids an extra multication of SUM and h^N.
 */
.macro schoolbook1_iteration i xor_sum
	.set i, \i
	.set xor_sum, \xor_sum
	movups (16*i)(OP1), %xmm0
	.if(i == 0 && xor_sum == 1)
		pxor SUM, %xmm0
	.endif
	vpclmulqdq $0x01, (16*i)(OP2), %xmm0, %xmm1
	vpxor %xmm1, MI, MI
	vpclmulqdq $0x00, (16*i)(OP2), %xmm0, %xmm2
	vpxor %xmm2, LO, LO
	vpclmulqdq $0x11, (16*i)(OP2), %xmm0, %xmm3
	vpxor %xmm3, HI, HI
	vpclmulqdq $0x10, (16*i)(OP2), %xmm0, %xmm4
	vpxor %xmm4, MI, MI
.endm

/*
 * Performs the same computation as schoolbook1_iteration, except we expect the
 * arguments to already be loaded into xmm0 and xmm1.
 */
.macro schoolbook1_noload
	vpclmulqdq $0x01, %xmm0, %xmm1, %xmm2
	vpxor %xmm2, MI, MI
	vpclmulqdq $0x00, %xmm0, %xmm1, %xmm3
	vpxor %xmm3, LO, LO
	vpclmulqdq $0x11, %xmm0, %xmm1, %xmm4
	vpxor %xmm4, HI, HI
	vpclmulqdq $0x10, %xmm0, %xmm1, %xmm5
	vpxor %xmm5, MI, MI
.endm

/*
 * Computes the 256-bit polynomial represented by LO, HI, MI. Stores
 * the result in PL, PH.
 *   [PH :: PL] = [HI_H : HI_L ^ MI_H :: LO_H ^ MI_L : LO_L]
 */
.macro schoolbook2
	vpslldq $8, MI, PL
	vpsrldq $8, MI, PH
	pxor LO, PL
	pxor HI, PH
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
	movdqa PL, T
	pclmulqdq $0x00, GSTAR, T # T = [P_0 * g*(x)]
	pshufd $0b01001110, T, V # V = [T_0 : T_1]
	pxor V, PL # PL = [P_1 ^ T_0 : P_0 ^ T_1]
	pxor PL, PH # PH = [P_1 ^ T_0 ^ P_3 : P_0 ^ T_1 ^ P_2]
	pclmulqdq $0x11, GSTAR, PL # PL = [(P_1 ^ T_0) * g*(x)]
	pxor PL, PH
.endm

/*
 * Compute schoolbook multiplication for 8 blocks
 * M_0h^8 + ... + M_7h^1 (no constant term)
 *
 * If reduce is set, computes the montgomery reduction of the
 * previous full_stride call and XORs with the first message block.
 * (M_0 + REDUCE(PL, PH))h^8 + ... + M_7h^1 (no constant term)
 *
 * Sets PL, PH
 * Clobbers LO, HI, MI
 *
 */
.macro full_stride reduce
	.set reduce, \reduce
	mov %rsi, OP2
	pxor LO, LO
	pxor HI, HI
	pxor MI, MI

	schoolbook1_iteration 7 0
	.if(reduce)
		movdqa PL, T
	.endif

	schoolbook1_iteration 6 0
	.if(reduce)
		pclmulqdq $0x00, GSTAR, T # T = [X0 * g*(x)]
	.endif

	schoolbook1_iteration 5 0
	.if(reduce)
		pshufd $0b01001110, T, V # V = [T0 : T1]
	.endif

	schoolbook1_iteration 4 0
	.if(reduce)
		pxor V, PL # PL = [X1 ^ T0 : X0 ^ T1]
	.endif

	schoolbook1_iteration 3 0
	.if(reduce)
		pxor PL, PH # PH = [X1 ^ T0 ^ X3 : X0 ^ T1 ^ X2]
	.endif

	schoolbook1_iteration 2 0
	.if(reduce)
		pclmulqdq $0x11, GSTAR, PL # PL = [X1 ^ T0 * g*(x)]
	.endif

	schoolbook1_iteration 1 0
	.if(reduce)
		pxor PL, PH
		movdqa PH, SUM
	.endif

	schoolbook1_iteration 0 1

	addq $(8*16), OP1
	addq $(8*16), OP2
	schoolbook2
.endm

/*
 * Compute poly on window size of %rdx blocks
 * 0 < %rdx < NUM_PRECOMPUTE_POWERS
 */
.macro partial_stride
	pxor LO, LO
	pxor HI, HI
	pxor MI, MI
	mov BLOCKS_LEFT, TMP
	shlq $4, TMP
	mov %rsi, OP2
	addq $(16*NUM_PRECOMPUTE_POWERS), OP2
	subq TMP, OP2
	# Multiply sum by h^N
	movups (OP2), %xmm0
	movdqa SUM, %xmm1
	schoolbook1_noload
	schoolbook2
	montgomery_reduction
	movdqa PH, SUM
	pxor LO, LO
	pxor HI, HI
	pxor MI, MI
	xor IDX, IDX
.LloopPartial:
	cmpq BLOCKS_LEFT, IDX # IDX < rdx
	jae .LloopExitPartial

	movq BLOCKS_LEFT, TMP
	subq IDX, TMP # TMP = rdx - IDX

	cmp $4, TMP # TMP < 4 ?
	jl .Llt4Partial
	schoolbook1 4
	addq $4, IDX
	addq $(4*16), OP1
	addq $(4*16), OP2
	jmp .LoutPartial
.Llt4Partial:
	cmp $3, TMP # TMP < 3 ?
	jl .Llt3Partial
	schoolbook1 3
	addq $3, IDX
	addq $(3*16), OP1
	addq $(3*16), OP2
	jmp .LoutPartial
.Llt3Partial:
	cmp $2, TMP # TMP < 2 ?
	jl .Llt2Partial
	schoolbook1 2
	addq $2, IDX
	addq $(2*16), OP1
	addq $(2*16), OP2
	jmp .LoutPartial
.Llt2Partial:
	schoolbook1 1 # TMP < 1 ?
	addq $1, IDX
	addq $(1*16), OP1
	addq $(1*16), OP2
.LoutPartial:
	jmp .LloopPartial
.LloopExitPartial:
	schoolbook2
	montgomery_reduction
	pxor PH, SUM
.endm

/*
 * Perform montgomery multiplication in GF(2^128) and store result in op1.
 *
 * Computes op1*op2*x^{-128} mod x^128 + x^127 + x^126 + x^121 + 1
 * If op1, op2 are in montgomery form,  this computes the montgomery
 * form of op1*op2.
 *
 * void clmul_polyval_mul(u8 *op1, const u8 *op2);
 */
SYM_FUNC_START(clmul_polyval_mul)
	FRAME_BEGIN
	vmovdqa Lgstar(%rip), GSTAR
	pxor LO, LO
	pxor HI, HI
	pxor MI, MI
	movups (%rdi), %xmm0
	movups (%rsi), %xmm1
	schoolbook1_noload
	schoolbook2
	montgomery_reduction
	movups PH, (%rdi)
	FRAME_END
	ret
SYM_FUNC_END(clmul_polyval_mul)

/*
 * Perform polynomial evaluation as specified by POLYVAL. If nblocks = k, this
 * routine multiplies the value stored at accumulator by h^k and XORs the
 * evaluated polynomial into it.
 *
 * Computes h^k * accumulator + h^kM_0 + ... + h^1M_{k-1} (No constant term)
 *
 * rdi (OP1) - pointer to message blocks
 * rsi - pointer to precomputed key struct
 * rdx - number of blocks to hash
 * rcx - location to XOR with evaluated polynomial
 *
 * void clmul_polyval_update(const u8 *in, const struct polyhash_ctx* ctx,
 *			     size_t nblocks, u8* accumulator);
 */
SYM_FUNC_START(clmul_polyval_update)
	FRAME_BEGIN
	vmovdqa Lgstar(%rip), GSTAR
	movups (%rcx), SUM
	cmpq $NUM_PRECOMPUTE_POWERS, BLOCKS_LEFT
	jb .LstrideLoopExit
	full_stride 0
	subq $NUM_PRECOMPUTE_POWERS, BLOCKS_LEFT
.LstrideLoop:
	cmpq $NUM_PRECOMPUTE_POWERS, BLOCKS_LEFT
	jb .LstrideLoopExitReduce
	full_stride 1
	subq $NUM_PRECOMPUTE_POWERS, BLOCKS_LEFT
	jmp .LstrideLoop
.LstrideLoopExitReduce:
	montgomery_reduction
	movdqa PH, SUM
.LstrideLoopExit:
	test BLOCKS_LEFT, BLOCKS_LEFT
	je .LskipPartial
	partial_stride
.LskipPartial:
	movups SUM, (%rcx)
	FRAME_END
	ret
SYM_FUNC_END(clmul_polyval_update)
