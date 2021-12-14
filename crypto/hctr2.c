// SPDX-License-Identifier: GPL-2.0
/*
 * HCTR2 length-preserving encryption mode
 *
 * Copyright 2021 Google LLC
 */


/*
 * HCTR2 is a length-preserving encryption mode that is efficient on
 * processors with instructions to accelerate aes and carryless
 * multiplication, e.g. x86 processors with AES-NI and CLMUL, and ARM
 * processors with the ARMv8 crypto extensions.
 *
 * For more details, see the paper: Length-preserving encryption with HCTR2
 * (https://eprint.iacr.org/2021/1441.pdf)
 */

#include <crypto/internal/cipher.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/polyval.h>
#include <crypto/scatterwalk.h>
#include <linux/module.h>

#define BLOCKCIPHER_BLOCK_SIZE		16

/*
 * The specification allows variable-length tweaks, but Linux's crypto API
 * currently only allows algorithms to support a single length.  The "natural"
 * tweak length for HCTR2 is 16, since that fits into one POLYVAL block for
 * the best performance.  But longer tweaks are useful for fscrypt, to avoid
 * needing to derive per-file keys.  So instead we use two blocks, or 32 bytes.
 */
#define TWEAK_SIZE		32

struct hctr2_instance_ctx {
	struct crypto_cipher_spawn blockcipher_spawn;
	struct crypto_skcipher_spawn xctr_spawn;
	struct crypto_shash_spawn polyval_spawn;
};

struct hctr2_tfm_ctx {
	struct crypto_cipher *blockcipher;
	struct crypto_skcipher *xctr;
	struct crypto_shash *polyval;
	u8 L[BLOCKCIPHER_BLOCK_SIZE];
	int hashed_tweak_offset;
	/*
	 * This struct is allocated with extra space for two exported hash
	 * digests.  Since the digest length is not known at compile-time, we
	 * can't add them to the struct directly.
	 *
	 * hashed_tweaklen_even;
	 * hashed_tweaklen_odd;
	 */
};

struct hctr2_request_ctx {
	u8 first_block[BLOCKCIPHER_BLOCK_SIZE];
	u8 xctr_iv[BLOCKCIPHER_BLOCK_SIZE];
	struct scatterlist *bulk_part_dst;
	struct scatterlist *bulk_part_src;
	struct scatterlist sg_src[2];
	struct scatterlist sg_dst[2];
	/* Sub-requests, must be last */
	union {
		struct shash_desc hash_desc;
		struct skcipher_request xctr_req;
	} u;
	/*
	 * This struct is allocated with extra space for one exported hash
	 * digest.  Since the digest length is not known at compile-time, we
	 * can't add it to the struct directly.
	 *
	 * hashed_tweak;
	 */
};

static inline u8 *hctr2_hashed_tweaklen(const struct hctr2_tfm_ctx *tctx,
					bool odd)
{
	u8 *p = (u8 *)tctx + sizeof(*tctx);

	if (odd) /* For messages not a multiple of block length */
		p += crypto_shash_statesize(tctx->polyval);
	return p;
}

static inline u8 *hctr2_hashed_tweak(const struct hctr2_tfm_ctx *tctx,
				     struct hctr2_request_ctx *rctx)
{
	return (u8 *)rctx + tctx->hashed_tweak_offset;
}

/*
 * HCTR2 requires hashing values based off the tweak length.  Since the kernel
 * implementation only supports 32-byte tweaks, we can precompute these when
 * setting the key.  This allows us to avoid an extra block of hashing during
 * every encryption.
 *
 * These precomputed hashes are stored in hctr2_tfm_ctx.
 *
 * If the message length is a multiple of the blocksize, we use H(tweak_len * 2
 * + 2).  If the message length is not a multiple of the blocksize, we use
 * H(tweak_len * 2 + 3).
 */
static int hctr2_hash_tweaklens(struct hctr2_tfm_ctx *tctx)
{
	SHASH_DESC_ON_STACK(shash, tfm->polyval);
	__le64 tweak_length_block[2];
	int err;

	shash->tfm = tctx->polyval;
	memset(tweak_length_block, 0, sizeof(tweak_length_block));

	tweak_length_block[0] = cpu_to_le64(TWEAK_SIZE * 8 * 2 + 2);
	err = crypto_shash_init(shash);
	if (err)
		return err;
	err = crypto_shash_update(shash, (u8 *)tweak_length_block,
				  POLYVAL_BLOCK_SIZE);
	if (err)
		return err;
	err = crypto_shash_export(shash, hctr2_hashed_tweaklen(tctx, true));
	if (err)
		return err;

	tweak_length_block[0] = cpu_to_le64(TWEAK_SIZE * 8 * 2 + 3);
	err = crypto_shash_init(shash);
	if (err)
		return err;
	err = crypto_shash_update(shash, (u8 *)tweak_length_block,
				  POLYVAL_BLOCK_SIZE);
	if (err)
		return err;
	return crypto_shash_export(shash, hctr2_hashed_tweaklen(tctx, false));
}

static int hctr2_setkey(struct crypto_skcipher *tfm, const u8 *key,
			unsigned int keylen)
{
	struct hctr2_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	u8 hbar[BLOCKCIPHER_BLOCK_SIZE];
	int err;

	crypto_cipher_clear_flags(tctx->blockcipher, CRYPTO_TFM_REQ_MASK);
	crypto_cipher_set_flags(tctx->blockcipher,
				crypto_skcipher_get_flags(tfm) &
				CRYPTO_TFM_REQ_MASK);
	err = crypto_cipher_setkey(tctx->blockcipher, key, keylen);
	if (err)
		return err;

	crypto_skcipher_clear_flags(tctx->xctr, CRYPTO_TFM_REQ_MASK);
	crypto_skcipher_set_flags(tctx->xctr,
				  crypto_skcipher_get_flags(tfm) &
				  CRYPTO_TFM_REQ_MASK);
	err = crypto_skcipher_setkey(tctx->xctr, key, keylen);
	if (err)
		return err;

	memset(tctx->L, 0, sizeof(tctx->L));
	memset(hbar, 0, sizeof(hbar));
	tctx->L[0] = 0x01;
	crypto_cipher_encrypt_one(tctx->blockcipher, tctx->L, tctx->L);
	crypto_cipher_encrypt_one(tctx->blockcipher, hbar, hbar);

	crypto_shash_clear_flags(tctx->polyval, CRYPTO_TFM_REQ_MASK);
	crypto_shash_set_flags(tctx->polyval, crypto_skcipher_get_flags(tfm) &
			       CRYPTO_TFM_REQ_MASK);
	err = crypto_shash_setkey(tctx->polyval, hbar, BLOCKCIPHER_BLOCK_SIZE);
	if (err)
		return err;
	memzero_explicit(hbar, sizeof(hbar));

	return hctr2_hash_tweaklens(tctx);
}

static int hctr2_hash_tweak(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct hctr2_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	struct hctr2_request_ctx *rctx = skcipher_request_ctx(req);
	struct shash_desc *hash_desc = &rctx->u.hash_desc;
	int err;
	bool odd = req->cryptlen % POLYVAL_BLOCK_SIZE == 0;

	hash_desc->tfm = tctx->polyval;
	err = crypto_shash_import(hash_desc, hctr2_hashed_tweaklen(tctx, odd));
	if (err)
		return err;
	err = crypto_shash_update(hash_desc, req->iv, TWEAK_SIZE);
	if (err)
		return err;

	// Store the hashed tweak, since we need it when computing both
	// H(T || N) and H(T || V).
	return crypto_shash_export(hash_desc, hctr2_hashed_tweak(tctx, rctx));
}

static int hctr2_hash_message(struct skcipher_request *req,
			      struct scatterlist *sgl,
			      u8 digest[POLYVAL_DIGEST_SIZE])
{
	u8 padding[BLOCKCIPHER_BLOCK_SIZE];
	struct hctr2_request_ctx *rctx = skcipher_request_ctx(req);
	struct shash_desc *hash_desc = &rctx->u.hash_desc;
	const unsigned int bulk_len = req->cryptlen - BLOCKCIPHER_BLOCK_SIZE;
	struct sg_mapping_iter miter;
	unsigned int remainder = bulk_len % BLOCKCIPHER_BLOCK_SIZE;
	int err, i;
	int n = 0;

	sg_miter_start(&miter, sgl, sg_nents(sgl),
		       SG_MITER_FROM_SG | SG_MITER_ATOMIC);
	for (i = 0; i < bulk_len; i += n) {
		sg_miter_next(&miter);
		n = min_t(unsigned int, miter.length, bulk_len - i);
		err = crypto_shash_update(hash_desc, miter.addr, n);
		if (err)
			break;
	}
	sg_miter_stop(&miter);

	if (err)
		return err;

	if (remainder) {
		memset(padding, 0, BLOCKCIPHER_BLOCK_SIZE);
		padding[0] = 0x01;
		err = crypto_shash_update(hash_desc, padding,
					  BLOCKCIPHER_BLOCK_SIZE - remainder);
		if (err)
			return err;
	}
	return crypto_shash_final(hash_desc, digest);
}

static int hctr2_finish(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct hctr2_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	struct hctr2_request_ctx *rctx = skcipher_request_ctx(req);
	u8 digest[POLYVAL_DIGEST_SIZE];
	struct shash_desc *hash_desc = &rctx->u.hash_desc;
	int err;

	// U = UU ^ H(T || V)
	// or M = MM ^ H(T || N)
	hash_desc->tfm = tctx->polyval;
	err = crypto_shash_import(hash_desc, hctr2_hashed_tweak(tctx, rctx));
	if (err)
		return err;
	err = hctr2_hash_message(req, rctx->bulk_part_dst, digest);
	if (err)
		return err;
	crypto_xor(rctx->first_block, digest, BLOCKCIPHER_BLOCK_SIZE);

	// Copy U (or M) into dst scatterlist
	scatterwalk_map_and_copy(rctx->first_block, req->dst,
				 0, BLOCKCIPHER_BLOCK_SIZE, 1);
	return 0;
}

static void hctr2_xctr_done(struct crypto_async_request *areq,
				    int err)
{
	struct skcipher_request *req = areq->data;

	if (!err)
		err = hctr2_finish(req);

	skcipher_request_complete(req, err);
}

static int hctr2_crypt(struct skcipher_request *req, bool enc)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct hctr2_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	struct hctr2_request_ctx *rctx = skcipher_request_ctx(req);
	u8 digest[POLYVAL_DIGEST_SIZE];
	int bulk_len = req->cryptlen - BLOCKCIPHER_BLOCK_SIZE;
	int err;

	// Requests must be at least one block
	if (req->cryptlen < BLOCKCIPHER_BLOCK_SIZE)
		return -EINVAL;

	// Copy M (or U) into a temporary buffer
	scatterwalk_map_and_copy(rctx->first_block, req->src,
				 0, BLOCKCIPHER_BLOCK_SIZE, 0);

	// Create scatterlists for N and V
	rctx->bulk_part_src = scatterwalk_ffwd(rctx->sg_src, req->src,
					       BLOCKCIPHER_BLOCK_SIZE);
	rctx->bulk_part_dst = scatterwalk_ffwd(rctx->sg_dst, req->dst,
					       BLOCKCIPHER_BLOCK_SIZE);

	// MM = M ^ H(T || N)
	// or UU = U ^ H(T || V)
	err = hctr2_hash_tweak(req);
	if (err)
		return err;
	err = hctr2_hash_message(req, rctx->bulk_part_src, digest);
	if (err)
		return err;
	crypto_xor(digest, rctx->first_block, BLOCKCIPHER_BLOCK_SIZE);

	// UU = E(MM)
	// or MM = D(UU)
	if (enc)
		crypto_cipher_encrypt_one(tctx->blockcipher, rctx->first_block,
					  digest);
	else
		crypto_cipher_decrypt_one(tctx->blockcipher, rctx->first_block,
					  digest);

	// S = MM ^ UU ^ L
	crypto_xor(digest, rctx->first_block, BLOCKCIPHER_BLOCK_SIZE);
	crypto_xor_cpy(rctx->xctr_iv, digest, tctx->L, BLOCKCIPHER_BLOCK_SIZE);

	// V = XCTR(S, N)
	// or N = XCTR(S, V)
	skcipher_request_set_tfm(&rctx->u.xctr_req, tctx->xctr);
	skcipher_request_set_crypt(&rctx->u.xctr_req, rctx->bulk_part_src,
				   rctx->bulk_part_dst, bulk_len,
				   rctx->xctr_iv);
	skcipher_request_set_callback(&rctx->u.xctr_req,
				      req->base.flags,
				      hctr2_xctr_done, req);
	return crypto_skcipher_encrypt(&rctx->u.xctr_req) ?:
		hctr2_finish(req);
}

static int hctr2_encrypt(struct skcipher_request *req)
{
	return hctr2_crypt(req, true);
}

static int hctr2_decrypt(struct skcipher_request *req)
{
	return hctr2_crypt(req, false);
}

static int hctr2_init_tfm(struct crypto_skcipher *tfm)
{
	struct skcipher_instance *inst = skcipher_alg_instance(tfm);
	struct hctr2_instance_ctx *ictx = skcipher_instance_ctx(inst);
	struct hctr2_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);
	struct crypto_skcipher *xctr;
	struct crypto_cipher *blockcipher;
	struct crypto_shash *polyval;
	unsigned int subreq_size;
	int err;

	xctr = crypto_spawn_skcipher(&ictx->xctr_spawn);
	if (IS_ERR(xctr))
		return PTR_ERR(xctr);

	blockcipher = crypto_spawn_cipher(&ictx->blockcipher_spawn);
	if (IS_ERR(blockcipher)) {
		err = PTR_ERR(blockcipher);
		goto err_free_xctr;
	}

	polyval = crypto_spawn_shash(&ictx->polyval_spawn);
	if (IS_ERR(polyval)) {
		err = PTR_ERR(polyval);
		goto err_free_blockcipher;
	}

	tctx->xctr = xctr;
	tctx->blockcipher = blockcipher;
	tctx->polyval = polyval;

	BUILD_BUG_ON(offsetofend(struct hctr2_request_ctx, u) !=
				 sizeof(struct hctr2_request_ctx));
	subreq_size = max(sizeof_field(struct hctr2_request_ctx, u.hash_desc) +
			  crypto_shash_statesize(polyval), sizeof_field(struct
			  hctr2_request_ctx, u.xctr_req) +
			  crypto_skcipher_reqsize(xctr));

	tctx->hashed_tweak_offset = offsetof(struct hctr2_request_ctx, u) +
				    subreq_size;
	crypto_skcipher_set_reqsize(tfm, tctx->hashed_tweak_offset +
				    crypto_shash_statesize(polyval));
	return 0;

err_free_blockcipher:
	crypto_free_cipher(blockcipher);
err_free_xctr:
	crypto_free_skcipher(xctr);
	return err;
}

static void hctr2_exit_tfm(struct crypto_skcipher *tfm)
{
	struct hctr2_tfm_ctx *tctx = crypto_skcipher_ctx(tfm);

	crypto_free_cipher(tctx->blockcipher);
	crypto_free_skcipher(tctx->xctr);
	crypto_free_shash(tctx->polyval);
}

static void hctr2_free_instance(struct skcipher_instance *inst)
{
	struct hctr2_instance_ctx *ictx = skcipher_instance_ctx(inst);

	crypto_drop_cipher(&ictx->blockcipher_spawn);
	crypto_drop_skcipher(&ictx->xctr_spawn);
	crypto_drop_shash(&ictx->polyval_spawn);
	kfree(inst);
}

/*
 * Check for a supported set of inner algorithms.
 * See the comment at the beginning of this file.
 */
static bool hctr2_supported_algorithms(struct skcipher_alg *xctr_alg,
				       struct crypto_alg *blockcipher_alg,
				       struct shash_alg *polyval_alg)
{
	if (strncmp(xctr_alg->base.cra_name, "xctr(", 4) != 0)
		return false;

	if (blockcipher_alg->cra_blocksize != BLOCKCIPHER_BLOCK_SIZE)
		return false;

	if (strcmp(polyval_alg->base.cra_name, "polyval") != 0)
		return false;

	return true;
}

static int hctr2_create_common(struct crypto_template *tmpl,
			       struct rtattr **tb,
			       const char *xctr_name,
			       const char *polyval_name)
{
	u32 mask;
	struct skcipher_instance *inst;
	struct hctr2_instance_ctx *ictx;
	struct skcipher_alg *xctr_alg;
	struct crypto_alg *blockcipher_alg;
	struct shash_alg *polyval_alg;
	char blockcipher_name[CRYPTO_MAX_ALG_NAME];
	int len;
	int err;

	err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_SKCIPHER, &mask);
	if (err)
		return err;

	inst = kzalloc(sizeof(*inst) + sizeof(*ictx), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;
	ictx = skcipher_instance_ctx(inst);

	/* Stream cipher, xctr(block_cipher) */
	err = crypto_grab_skcipher(&ictx->xctr_spawn,
				   skcipher_crypto_instance(inst),
				   xctr_name, 0, mask);
	if (err)
		goto err_free_inst;
	xctr_alg = crypto_spawn_skcipher_alg(&ictx->xctr_spawn);

	if (!strncmp(xctr_alg->base.cra_name, "xctr(", 5)) {
		len = strscpy(blockcipher_name, xctr_name + 5,
			    sizeof(blockcipher_name));

		if (len < 1)
			return -EINVAL;

		if (blockcipher_name[len - 1] != ')')
			return -EINVAL;

		blockcipher_name[len - 1] = 0;
	} else
		return -EINVAL;


	/* Block cipher, e.g. "aes" */
	err = crypto_grab_cipher(&ictx->blockcipher_spawn,
				 skcipher_crypto_instance(inst),
				 blockcipher_name, 0, mask);
	if (err)
		goto err_free_inst;
	blockcipher_alg = crypto_spawn_cipher_alg(&ictx->blockcipher_spawn);

	/* Polyval ε-∆U hash function */
	err = crypto_grab_shash(&ictx->polyval_spawn,
				skcipher_crypto_instance(inst),
				polyval_name, 0, mask);
	if (err)
		goto err_free_inst;
	polyval_alg = crypto_spawn_shash_alg(&ictx->polyval_spawn);

	/* Check the set of algorithms */
	if (!hctr2_supported_algorithms(xctr_alg, blockcipher_alg,
					polyval_alg)) {
		pr_warn("Unsupported HCTR2 instantiation: (%s,%s,%s)\n",
			xctr_alg->base.cra_name, blockcipher_alg->cra_name,
			polyval_alg->base.cra_name);
		err = -EINVAL;
		goto err_free_inst;
	}

	/* Instance fields */

	err = -ENAMETOOLONG;
	if (snprintf(inst->alg.base.cra_name, CRYPTO_MAX_ALG_NAME, "hctr2(%s)",
		     blockcipher_alg->cra_name) >= CRYPTO_MAX_ALG_NAME)
		goto err_free_inst;
	if (snprintf(inst->alg.base.cra_driver_name, CRYPTO_MAX_ALG_NAME,
		     "hctr2_base(%s,%s)",
		     xctr_alg->base.cra_driver_name,
		     polyval_alg->base.cra_driver_name) >= CRYPTO_MAX_ALG_NAME)
		goto err_free_inst;

	inst->alg.base.cra_blocksize = BLOCKCIPHER_BLOCK_SIZE;
	inst->alg.base.cra_ctxsize = sizeof(struct hctr2_tfm_ctx) +
				     polyval_alg->statesize * 2;
	inst->alg.base.cra_alignmask = xctr_alg->base.cra_alignmask |
				       polyval_alg->base.cra_alignmask;
	/*
	 * The hash function is called twice, so it is weighted higher than the
	 * xctr and blockcipher.
	 */
	inst->alg.base.cra_priority = (2 * xctr_alg->base.cra_priority +
				       4 * polyval_alg->base.cra_priority +
				       blockcipher_alg->cra_priority) / 7;

	inst->alg.setkey = hctr2_setkey;
	inst->alg.encrypt = hctr2_encrypt;
	inst->alg.decrypt = hctr2_decrypt;
	inst->alg.init = hctr2_init_tfm;
	inst->alg.exit = hctr2_exit_tfm;
	inst->alg.min_keysize = crypto_skcipher_alg_min_keysize(xctr_alg);
	inst->alg.max_keysize = crypto_skcipher_alg_max_keysize(xctr_alg);
	inst->alg.ivsize = TWEAK_SIZE;

	inst->free = hctr2_free_instance;

	err = skcipher_register_instance(tmpl, inst);
	if (err) {
err_free_inst:
		hctr2_free_instance(inst);
	}
	return err;
}

static int hctr2_create_base(struct crypto_template *tmpl, struct rtattr **tb)
{
	const char *xctr_name;
	const char *polyval_name;

	xctr_name = crypto_attr_alg_name(tb[1]);
	if (IS_ERR(xctr_name))
		return PTR_ERR(xctr_name);

	polyval_name = crypto_attr_alg_name(tb[2]);
	if (IS_ERR(polyval_name))
		return PTR_ERR(polyval_name);

	return hctr2_create_common(tmpl, tb, xctr_name, polyval_name);
}

static int hctr2_create(struct crypto_template *tmpl, struct rtattr **tb)
{
	const char *blockcipher_name;
	char xctr_name[CRYPTO_MAX_ALG_NAME];

	blockcipher_name = crypto_attr_alg_name(tb[1]);
	if (IS_ERR(blockcipher_name))
		return PTR_ERR(blockcipher_name);

	if (snprintf(xctr_name, CRYPTO_MAX_ALG_NAME, "xctr(%s)",
		    blockcipher_name) >= CRYPTO_MAX_ALG_NAME)
		return -ENAMETOOLONG;

	return hctr2_create_common(tmpl, tb, xctr_name, "polyval");
}

/* hctr2(blockcipher_name) */
/* hctr2_base(xctr_name, polyval_name) */
static struct crypto_template hctr2_tmpls[] = {
	{
		.name = "hctr2_base",
		.create = hctr2_create_base,
		.module = THIS_MODULE,
	}, {
		.name = "hctr2",
		.create = hctr2_create,
		.module = THIS_MODULE,
	}
};

static int __init hctr2_module_init(void)
{
	return crypto_register_templates(hctr2_tmpls, ARRAY_SIZE(hctr2_tmpls));
}

static void __exit hctr2_module_exit(void)
{
	return crypto_unregister_templates(hctr2_tmpls,
					   ARRAY_SIZE(hctr2_tmpls));
}

subsys_initcall(hctr2_module_init);
module_exit(hctr2_module_exit);

MODULE_DESCRIPTION("HCTR2 length-preserving encryption mode");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("hctr2");
MODULE_IMPORT_NS(CRYPTO_INTERNAL);
