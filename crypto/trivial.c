#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/byteorder.h>

#define TRIVIAL_DIGEST_SIZE	16
#define TRIVIAL_BLOCK_SIZE	64
#define TRIVIAL_WORDS		4

struct trivial_state {
	u32 hash[TRIVIAL_WORDS];
};

static int trivial_init(struct shash_desc *desc)
{
	struct trivial_state *mctx = shash_desc_ctx(desc);
	int i;

	for (i = 0; i < TRIVIAL_WORDS; i++)
		mctx->hash[i] = 0;

	return 0;
}

static int trivial_update(struct shash_desc *desc, const u8 *data, unsigned int len)
{
	return 0;
}

static int trivial_final(struct shash_desc *desc, u8 *out)
{
	struct trivial_state *mctx = shash_desc_ctx(desc);
	memcpy(out, mctx->hash, sizeof(mctx->hash));
	return 0;
}

static int trivial_export(struct shash_desc *desc, void *out)
{
	struct trivial_state *ctx = shash_desc_ctx(desc);
	memcpy(out, ctx, sizeof(*ctx));
	return 0;
}

static int trivial_import(struct shash_desc *desc, const void *in)
{
	struct trivial_state *ctx = shash_desc_ctx(desc);

	memcpy(ctx, in, sizeof(*ctx));
	return 0;
}

static struct shash_alg alg = {
	.digestsize	=	TRIVIAL_DIGEST_SIZE,
	.init		=	trivial_init,
	.update		=	trivial_update,
	.final		=	trivial_final,
	.export		=	trivial_export,
	.import		=	trivial_import,
	.descsize	=	sizeof(struct trivial_state),
	.statesize	=	sizeof(struct trivial_state),
	.base		=	{
		.cra_name	 =	"trivial",
		.cra_driver_name =	"trivial-generic",
		.cra_blocksize	 =	TRIVIAL_BLOCK_SIZE,
		.cra_module	 =	THIS_MODULE,
	}
};

static int __init trivial_mod_init(void)
{
	return crypto_register_shash(&alg);
}

static void __exit trivial_mod_fini(void)
{
	crypto_unregister_shash(&alg);
}

subsys_initcall(trivial_mod_init);
module_exit(trivial_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Trivial Hash Algorithm");
MODULE_ALIAS_CRYPTO("trivial");
