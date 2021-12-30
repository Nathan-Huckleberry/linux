/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2021 Google LLC
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
#define MSG %rdi
#define KEY_POWERS %r10
#define IDX %r11
#define TMP %rax

.section    .rodata.cst16.gstar, "aM", @progbits, 16
.align 16

.Lgstar:
	.quad 0xc200000000000000, 0xc200000000000000

.text

/*
 * Performs schoolbook1_iteration on two lists of 128-bit polynomials of length
 * b pointed to by MSG and KEY_POWERS.
 */
.macro schoolbook1 count
	.set i, 0
	.rept (\count)
		schoolbook1_iteration i 0
		.set i, (i +1)
	.endr
.endm

/*
 * Computes the product of two 128-bit polynomials at the memory locations
 * specified by (MSG + 16*i) and (KEY_POWERS + 16*i) and XORs the components of the
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
 *  MI ^= MID1 ^ MID2
 *  HI ^= HIGH
 *
 * Later, the 256-bit result can be extracted as:
 *   [HI_H : HI_L ^ MI_H : LO_H ^ MI_L : LO_L]
 * This step is done when computing the polynomial reduction for efficiency
 * reasons.
 *
 * If xor_sum == 1, then also XOR the value of SUM into m_0.  This avoids an
 * extra multiplication of SUM and h^N.
 */
.macro schoolbook1_iteration i xor_sum
	movups (16*\i)(MSG), %xmm0
	.if (\i == 0 && \xor_sum == 1)
		pxor SUM, %xmm0
	.endif
	vpclmulqdq $0x00, (16*\i)(KEY_POWERS), %xmm0, %xmm2
	vpclmulqdq $0x01, (16*\i)(KEY_POWERS), %xmm0, %xmm1
	vpclmulqdq $0x11, (16*\i)(KEY_POWERS), %xmm0, %xmm3
	vpclmulqdq $0x10, (16*\i)(KEY_POWERS), %xmm0, %xmm4
	vpxor %xmm2, LO, LO
	vpxor %xmm1, MI, MI
	vpxor %xmm4, MI, MI
	vpxor %xmm3, HI, HI
.endm

/*
 * Performs the same computation as schoolbook1_iteration, except we expect the
 * arguments to already be loaded into xmm0 and xmm1.
 */
.macro schoolbook1_noload
	vpclmulqdq $0x01, %xmm0, %xmm1, %xmm2
	vpclmulqdq $0x00, %xmm0, %xmm1, %xmm3
	vpclmulqdq $0x11, %xmm0, %xmm1, %xmm4
	vpclmulqdq $0x10, %xmm0, %xmm1, %xmm5
	vpxor %xmm2, MI, MI
	vpxor %xmm3, LO, LO
	vpxor %xmm5, MI, MI
	vpxor %xmm4, HI, HI
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
 * ^ T_1 and XORing into PH, rather than directly XORing P_1 : P_0, T_0 : T1
 * into PH.  This allows us to reuse P_1 ^ T_0 when computing V.
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
 * m_0h^8 + ... + m_7h^1
 *
 * If reduce is set, also computes the montgomery reduction of the
 * previous full_stride call and XORs with the first message block.
 * (m_0 + REDUCE(PL, PH))h^8 + ... + m_7h^1.
 * I.e., the first multiplication uses m_0 + REDUCE(PL, PH) instead of m_0.
 *
 * Sets PL, PH
 * Clobbers LO, HI, MI
 *
 */
.macro full_stride reduce
	mov %rsi, KEY_POWERS
	pxor LO, LO
	pxor HI, HI
	pxor MI, MI

	schoolbook1_iteration 7 0
	.if (\reduce)
		movdqa PL, T
	.endif

	schoolbook1_iteration 6 0
	.if (\reduce)
		pclmulqdq $0x00, GSTAR, T # T = [X0 * g*(x)]
	.endif

	schoolbook1_iteration 5 0
	.if (\reduce)
		pshufd $0b01001110, T, V # V = [T0 : T1]
	.endif

	schoolbook1_iteration 4 0
	.if (\reduce)
		pxor V, PL # PL = [X1 ^ T0 : X0 ^ T1]
	.endif

	schoolbook1_iteration 3 0
	.if (\reduce)
		pxor PL, PH # PH = [X1 ^ T0 ^ X3 : X0 ^ T1 ^ X2]
	.endif

	schoolbook1_iteration 2 0
	.if (\reduce)
		pclmulqdq $0x11, GSTAR, PL # PL = [X1 ^ T0 * g*(x)]
	.endif

	schoolbook1_iteration 1 0
	.if (\reduce)
		pxor PL, PH
		movdqa PH, SUM
	.endif

	schoolbook1_iteration 0 1

	addq $(8*16), MSG
	addq $(8*16), KEY_POWERS
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
	mov %rsi, KEY_POWERS
	addq $(16*NUM_PRECOMPUTE_POWERS), KEY_POWERS
	subq TMP, KEY_POWERS
	# Multiply sum by h^N
	movups (KEY_POWERS), %xmm0
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
	addq $(4*16), MSG
	addq $(4*16), KEY_POWERS
	jmp .LoutPartial
.Llt4Partial:
	cmp $3, TMP # TMP < 3 ?
	jl .Llt3Partial
	schoolbook1 3
	addq $3, IDX
	addq $(3*16), MSG
	addq $(3*16), KEY_POWERS
	jmp .LoutPartial
.Llt3Partial:
	cmp $2, TMP # TMP < 2 ?
	jl .Llt2Partial
	schoolbook1 2
	addq $2, IDX
	addq $(2*16), MSG
	addq $(2*16), KEY_POWERS
	jmp .LoutPartial
.Llt2Partial:
	schoolbook1 1 # TMP < 1 ?
	addq $1, IDX
	addq $(1*16), MSG
	addq $(1*16), KEY_POWERS
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
	vmovdqa .Lgstar(%rip), GSTAR
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
 * Perform polynomial evaluation as specified by POLYVAL.  This computes:
 * 	h^n * accumulator + h^n * m_0 + ... + h^1 * m_{n-1}
 * where n=nblocks, h is the hash key, and m_i are the message blocks.
 *
 * rdi - pointer to message blocks
 * rsi - pointer to precomputed key powers h^8 ... h^1
 * rdx - number of blocks to hash
 * rcx - pointer to the accumulator
 *
 * void clmul_polyval_update(const u8 *in, const struct polyval_ctx *ctx,
 *			     size_t nblocks, u8 *accumulator);
 */
SYM_FUNC_START(clmul_polyval_update)
	FRAME_BEGIN
	vmovdqa .Lgstar(%rip), GSTAR
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
