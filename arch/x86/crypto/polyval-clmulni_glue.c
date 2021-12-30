// SPDX-License-Identifier: GPL-2.0-only
/*
 * Accelerated POLYVAL implementation with Intel PCLMULQDQ-NI
 * instructions. This file contains glue code.
 *
 * Copyright (c) 2007 Nokia Siemens Networks - Mikko Herranen <mh1@iki.fi>
 * Copyright (c) 2009 Intel Corp.
 *   Author: Huang Ying <ying.huang@intel.com>
 * Copyright 2021 Google LLC
 */
/*
 * Glue code based on ghash-clmulni-intel_glue.c.
 *
 * This implementation of POLYVAL uses montgomery multiplication
 * accelerated by PCLMULQDQ-NI to implement the finite field
 * operations.
 *
 */

#include <crypto/algapi.h>
#include <crypto/cryptd.h>
#include <crypto/gf128mul.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <crypto/polyval.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/cpu_device_id.h>
#include <asm/simd.h>

#define NUM_PRECOMPUTE_POWERS	8

struct polyval_ctx {
	/*
	 * These powers must be in the order h^8, ..., h^1.
	 */
	u8 key_powers[NUM_PRECOMPUTE_POWERS][POLYVAL_BLOCK_SIZE];
};

struct polyval_desc_ctx {
	u8 buffer[POLYVAL_BLOCK_SIZE];
	u32 bytes;
};

asmlinkage void clmul_polyval_update(const u8 *in, struct polyval_ctx *keys,
				     size_t nblocks, u8 *accumulator);
asmlinkage void clmul_polyval_mul(u8 *op1, const u8 *op2);

static void reverse_be128(be128 *x)
{
	__be64 a = x->a;
	__be64 b = x->b;

	x->a = swab64(b);
	x->b = swab64(a);
}

static void generic_polyval_mul(u8 *op1, const u8 *op2)
{
	be128 a, b;

	// Assume one argument is in Montgomery form and one is not.
	memcpy(&a, op1, sizeof(a));
	memcpy(&b, op2, sizeof(b));
	reverse_be128(&a);
	reverse_be128(&b);
	gf128mul_x_lle(&a, &a);
	gf128mul_lle(&a, &b);
	reverse_be128(&a);
	memcpy(op1, &a, sizeof(a));
}

static void generic_polyval_update(const u8 *in, struct polyval_ctx *keys,
			  size_t nblocks, u8 *accumulator)
{
	while (nblocks--) {
		crypto_xor(accumulator, in, POLYVAL_BLOCK_SIZE);
		generic_polyval_mul(accumulator, keys->key_powers[7]);
		in += POLYVAL_BLOCK_SIZE;
	}
}

static void internal_polyval_update(const u8 *in, struct polyval_ctx *keys,
			  size_t nblocks, u8 *accumulator)
{
	if (likely(crypto_simd_usable())) {
		kernel_fpu_begin();
		clmul_polyval_update(in, keys, nblocks, accumulator);
		kernel_fpu_end();
	} else {
		generic_polyval_update(in, keys, nblocks, accumulator);
	}
}

static void internal_polyval_mul(u8 *op1, const u8 *op2)
{
	if (likely(crypto_simd_usable())) {
		kernel_fpu_begin();
		clmul_polyval_mul(op1, op2);
		kernel_fpu_end();
	} else {
		generic_polyval_mul(op1, op2);
	}
}

static int polyval_init(struct shash_desc *desc)
{
	struct polyval_desc_ctx *dctx = shash_desc_ctx(desc);

	memset(dctx, 0, sizeof(*dctx));

	return 0;
}

static int polyval_setkey(struct crypto_shash *tfm,
			const u8 *key, unsigned int keylen)
{
	struct polyval_ctx *ctx = crypto_shash_ctx(tfm);
	int i;

	if (keylen != POLYVAL_BLOCK_SIZE)
		return -EINVAL;

	memcpy(ctx->key_powers[NUM_PRECOMPUTE_POWERS-1], key,
	       POLYVAL_BLOCK_SIZE);

	for (i = NUM_PRECOMPUTE_POWERS-2; i >= 0; i--) {
		memcpy(ctx->key_powers[i], key, POLYVAL_BLOCK_SIZE);
		internal_polyval_mul(ctx->key_powers[i], ctx->key_powers[i+1]);
	}

	return 0;
}

static int polyval_update(struct shash_desc *desc,
			 const u8 *src, unsigned int srclen)
{
	struct polyval_desc_ctx *dctx = shash_desc_ctx(desc);
	struct polyval_ctx *ctx = crypto_shash_ctx(desc->tfm);
	u8 *pos;
	unsigned int nblocks;
	int n;

	if (dctx->bytes) {
		n = min(srclen, dctx->bytes);
		pos = dctx->buffer + POLYVAL_BLOCK_SIZE - dctx->bytes;

		dctx->bytes -= n;
		srclen -= n;

		while (n--)
			*pos++ ^= *src++;

		if (!dctx->bytes)
			internal_polyval_mul(dctx->buffer,
					     ctx->key_powers[NUM_PRECOMPUTE_POWERS-1]);
	}

	nblocks = srclen/POLYVAL_BLOCK_SIZE;
	internal_polyval_update(src, ctx, nblocks, dctx->buffer);
	srclen -= nblocks*POLYVAL_BLOCK_SIZE;

	if (srclen) {
		dctx->bytes = POLYVAL_BLOCK_SIZE - srclen;
		src += nblocks*POLYVAL_BLOCK_SIZE;
		pos = dctx->buffer;
		while (srclen--)
			*pos++ ^= *src++;
	}

	return 0;
}

static int polyval_final(struct shash_desc *desc, u8 *dst)
{
	struct polyval_desc_ctx *dctx = shash_desc_ctx(desc);
	struct polyval_ctx *ctx = crypto_shash_ctx(desc->tfm);

	if (dctx->bytes) {
		internal_polyval_mul(dctx->buffer,
				     ctx->key_powers[NUM_PRECOMPUTE_POWERS-1]);
	}

	dctx->bytes = 0;
	memcpy(dst, dctx->buffer, POLYVAL_BLOCK_SIZE);

	return 0;
}

static struct shash_alg polyval_alg = {
	.digestsize	= POLYVAL_DIGEST_SIZE,
	.init		= polyval_init,
	.update		= polyval_update,
	.final		= polyval_final,
	.setkey		= polyval_setkey,
	.descsize	= sizeof(struct polyval_desc_ctx),
	.base		= {
		.cra_name		= "polyval",
		.cra_driver_name	= "polyval-clmulni",
		.cra_priority		= 200,
		.cra_blocksize		= POLYVAL_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct polyval_ctx),
		.cra_module		= THIS_MODULE,
	},
};

static const struct x86_cpu_id pcmul_cpu_id[] = {
	X86_MATCH_FEATURE(X86_FEATURE_PCLMULQDQ, NULL), /* Pickle-Mickle-Duck */
	{}
};
MODULE_DEVICE_TABLE(x86cpu, pcmul_cpu_id);

static int __init polyval_clmulni_mod_init(void)
{
	if (!x86_match_cpu(pcmul_cpu_id))
		return -ENODEV;

	return crypto_register_shash(&polyval_alg);
}

static void __exit polyval_clmulni_mod_exit(void)
{
	crypto_unregister_shash(&polyval_alg);
}

module_init(polyval_clmulni_mod_init);
module_exit(polyval_clmulni_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("POLYVAL hash function accelerated by PCLMULQDQ-NI");
MODULE_ALIAS_CRYPTO("polyval");
MODULE_ALIAS_CRYPTO("polyval-clmulni");
