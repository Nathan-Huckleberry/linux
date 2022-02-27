// SPDX-License-Identifier: GPL-2.0-only
/*
 * Accelerated POLYVAL implementation with ARMv8 Crypto Extension
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
 * This implementation of POLYVAL uses montgomery multiplication accelerated by
 * ARMv8 Crypto Extension instructions to implement the finite field operations.
 *
 */

#include <crypto/algapi.h>
#include <crypto/cryptd.h>
#include <crypto/gf128mul.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cpufeature.h>
#include <asm/neon.h>
#include <asm/simd.h>
#include <asm/unaligned.h>

#define POLYVAL_BLOCK_SIZE	16
#define POLYVAL_DIGEST_SIZE	16
#define NUM_PRECOMPUTE_POWERS	8

struct polyval_async_ctx {
	struct cryptd_ahash *cryptd_tfm;
};

struct polyval_ctx {
	be128 key_powers[NUM_PRECOMPUTE_POWERS];
};

struct polyval_desc_ctx {
	u8 buffer[POLYVAL_BLOCK_SIZE];
	u32 bytes;
};

asmlinkage void pmull_polyval_update(const u8 *in, const struct polyval_ctx
				     *ctx, size_t nblocks, u8 *accumulator);
asmlinkage void pmull_polyval_mul(u8 *op1, const u8 *op2);

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

	BUILD_BUG_ON(sizeof(u128) != POLYVAL_BLOCK_SIZE);

	memcpy(&ctx->key_powers[NUM_PRECOMPUTE_POWERS-1], key, sizeof(be128));

	kernel_neon_begin();
	for (i = NUM_PRECOMPUTE_POWERS-2; i >= 0; i--) {
		memcpy(&ctx->key_powers[i], key, sizeof(be128));
		pmull_polyval_mul((u8 *)&ctx->key_powers[i],
				  (u8 *)&ctx->key_powers[i+1]);
	}
	kernel_neon_end();

	return 0;
}

static int polyval_update(struct shash_desc *desc,
			 const u8 *src, unsigned int srclen)
{
	struct polyval_desc_ctx *dctx = shash_desc_ctx(desc);
	struct polyval_ctx *ctx = crypto_shash_ctx(desc->tfm);
	u8 *dst = dctx->buffer;
	u8 *pos;
	unsigned int nblocks;
	unsigned int n;

	kernel_neon_begin();
	if (dctx->bytes) {
		n = min(srclen, dctx->bytes);
		pos = dst + POLYVAL_BLOCK_SIZE - dctx->bytes;

		dctx->bytes -= n;
		srclen -= n;

		while (n--)
			*pos++ ^= *src++;

		if (!dctx->bytes)
			pmull_polyval_mul(dst,
				(u8 *)&ctx->key_powers[NUM_PRECOMPUTE_POWERS-1]);
	}

	nblocks = srclen/POLYVAL_BLOCK_SIZE;
	pmull_polyval_update(src, ctx, nblocks, dst);
	srclen -= nblocks*POLYVAL_BLOCK_SIZE;
	kernel_neon_end();

	if (srclen) {
		dctx->bytes = POLYVAL_BLOCK_SIZE - srclen;
		src += nblocks*POLYVAL_BLOCK_SIZE;
		pos = dst;
		while (srclen--)
			*pos++ ^= *src++;
	}

	return 0;
}

static int polyval_final(struct shash_desc *desc, u8 *dst)
{
	struct polyval_desc_ctx *dctx = shash_desc_ctx(desc);
	struct polyval_ctx *ctx = crypto_shash_ctx(desc->tfm);
	u8 *buf = dctx->buffer;

	if (dctx->bytes) {
		kernel_neon_begin();
		pmull_polyval_mul(buf,
			(u8 *)&ctx->key_powers[NUM_PRECOMPUTE_POWERS-1]);
		kernel_neon_end();
	}

	dctx->bytes = 0;
	memcpy(dst, buf, POLYVAL_BLOCK_SIZE);

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
		.cra_name		= "__polyval",
		.cra_driver_name	= "__polyval-ce",
		.cra_priority		= 0,
		.cra_flags		= CRYPTO_ALG_INTERNAL,
		.cra_blocksize		= POLYVAL_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct polyval_ctx),
		.cra_module		= THIS_MODULE,
	},
};

static int polyval_async_init(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct polyval_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct cryptd_ahash *cryptd_tfm = ctx->cryptd_tfm;
	struct shash_desc *desc = cryptd_shash_desc(cryptd_req);
	struct crypto_shash *child = cryptd_ahash_child(cryptd_tfm);

	desc->tfm = child;
	return crypto_shash_init(desc);
}

static int polyval_async_update(struct ahash_request *req)
{
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct polyval_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct cryptd_ahash *cryptd_tfm = ctx->cryptd_tfm;
	struct shash_desc *desc;

	if (!crypto_simd_usable() ||
	    (in_atomic() && cryptd_ahash_queued(cryptd_tfm))) {
		memcpy(cryptd_req, req, sizeof(*req));
		ahash_request_set_tfm(cryptd_req, &cryptd_tfm->base);
		return crypto_ahash_update(cryptd_req);
	}
	desc = cryptd_shash_desc(cryptd_req);

	return shash_ahash_update(req, desc);
}

static int polyval_async_final(struct ahash_request *req)
{
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct polyval_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct cryptd_ahash *cryptd_tfm = ctx->cryptd_tfm;
	struct shash_desc *desc;

	if (!crypto_simd_usable() ||
	    (in_atomic() && cryptd_ahash_queued(cryptd_tfm))) {
		memcpy(cryptd_req, req, sizeof(*req));
		ahash_request_set_tfm(cryptd_req, &cryptd_tfm->base);
		return crypto_ahash_final(cryptd_req);
	}
	desc = cryptd_shash_desc(cryptd_req);

	return crypto_shash_final(desc, req->result);
}

static int polyval_async_import(struct ahash_request *req, const void *in)
{
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct shash_desc *desc = cryptd_shash_desc(cryptd_req);
	struct polyval_desc_ctx *dctx = shash_desc_ctx(desc);

	polyval_async_init(req);
	memcpy(dctx, in, sizeof(*dctx));
	return 0;

}

static int polyval_async_export(struct ahash_request *req, void *out)
{
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct shash_desc *desc = cryptd_shash_desc(cryptd_req);
	struct polyval_desc_ctx *dctx = shash_desc_ctx(desc);

	memcpy(out, dctx, sizeof(*dctx));
	return 0;

}

static int polyval_async_digest(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct polyval_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct cryptd_ahash *cryptd_tfm = ctx->cryptd_tfm;
	struct shash_desc *desc;
	struct crypto_shash *child;

	if (!crypto_simd_usable() ||
	    (in_atomic() && cryptd_ahash_queued(cryptd_tfm))) {
		memcpy(cryptd_req, req, sizeof(*req));
		ahash_request_set_tfm(cryptd_req, &cryptd_tfm->base);
		return crypto_ahash_digest(cryptd_req);
	}
	desc = cryptd_shash_desc(cryptd_req);
	child = cryptd_ahash_child(cryptd_tfm);

	desc->tfm = child;
	return shash_ahash_digest(req, desc);
}

static int polyval_async_setkey(struct crypto_ahash *tfm, const u8 *key,
			      unsigned int keylen)
{
	struct polyval_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct crypto_ahash *child = &ctx->cryptd_tfm->base;

	crypto_ahash_clear_flags(child, CRYPTO_TFM_REQ_MASK);
	crypto_ahash_set_flags(child, crypto_ahash_get_flags(tfm)
			       & CRYPTO_TFM_REQ_MASK);
	return crypto_ahash_setkey(child, key, keylen);
}

static int polyval_async_init_tfm(struct crypto_tfm *tfm)
{
	struct cryptd_ahash *cryptd_tfm;
	struct polyval_async_ctx *ctx = crypto_tfm_ctx(tfm);

	cryptd_tfm = cryptd_alloc_ahash("__polyval-ce",
					CRYPTO_ALG_INTERNAL,
					CRYPTO_ALG_INTERNAL);
	if (IS_ERR(cryptd_tfm))
		return PTR_ERR(cryptd_tfm);
	ctx->cryptd_tfm = cryptd_tfm;
	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct ahash_request) +
				 crypto_ahash_reqsize(&cryptd_tfm->base));

	return 0;
}

static void polyval_async_exit_tfm(struct crypto_tfm *tfm)
{
	struct polyval_async_ctx *ctx = crypto_tfm_ctx(tfm);

	cryptd_free_ahash(ctx->cryptd_tfm);
}

static struct ahash_alg polyval_async_alg = {
	.init		= polyval_async_init,
	.update		= polyval_async_update,
	.final		= polyval_async_final,
	.setkey		= polyval_async_setkey,
	.digest		= polyval_async_digest,
	.export		= polyval_async_export,
	.import		= polyval_async_import,
	.halg = {
		.digestsize	= POLYVAL_DIGEST_SIZE,
		.statesize = sizeof(struct polyval_desc_ctx),
		.base = {
			.cra_name		= "polyval",
			.cra_driver_name	= "polyval-clmulni",
			.cra_priority		= 200,
			.cra_ctxsize		= sizeof(struct polyval_async_ctx),
			.cra_flags		= CRYPTO_ALG_ASYNC,
			.cra_blocksize		= POLYVAL_BLOCK_SIZE,
			.cra_module		= THIS_MODULE,
			.cra_init		= polyval_async_init_tfm,
			.cra_exit		= polyval_async_exit_tfm,
		},
	},
};

static int __init polyval_ce_mod_init(void)
{
	int err;

	if (!cpu_have_named_feature(ASIMD))
		return -ENODEV;

	if (!cpu_have_named_feature(PMULL))
		return -ENODEV;

	err = crypto_register_shash(&polyval_alg);
	if (err)
		goto err_out;
	err = crypto_register_ahash(&polyval_async_alg);
	if (err)
		goto err_shash;

	return 0;

err_shash:
	crypto_unregister_shash(&polyval_alg);
err_out:
	return err;
}

static void __exit polyval_ce_mod_exit(void)
{
	crypto_unregister_ahash(&polyval_async_alg);
	crypto_unregister_shash(&polyval_alg);
}

static const struct cpu_feature polyval_cpu_feature[] = {
	{ cpu_feature(PMULL) }, { }
};
MODULE_DEVICE_TABLE(cpu, polyval_cpu_feature);

module_init(polyval_ce_mod_init);
module_exit(polyval_ce_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("POLYVAL hash function accelerated by ARMv8 Crypto Extension");
MODULE_ALIAS_CRYPTO("polyval");
