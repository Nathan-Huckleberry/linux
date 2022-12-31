#include <linux/device-mapper.h>
#include <linux/module.h>

#define DM_MSG_PREFIX "passthrough"

struct passthrough_params {
	struct dm_dev *dev;
	sector_t start;
};

static int passthrough_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct passthrough_params *params;
	unsigned long long start;
	char *end;

	if (argc != 2) {
		ti->error = "Invalid number of arguments";
		return -EINVAL;
	}

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (!params) {
		ti->error = "Cannot allocate target parameters";
		return -ENOMEM;
	}

	start = simple_strtoull(argv[1], &end, 10);
	if (*end) {
		ti->error = "Invalid start parameter";
		goto err;
	}
	params->start = start;

	if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &params->dev)) {
		ti->error = "Device lookup failed";
		goto err;
	}

	ti->private = params;
	return 0;

err:
	kfree(params);
	return -EINVAL;
}

static int passthrough_map(struct dm_target *ti, struct bio *bio)
{
	struct passthrough_params *params = ti->private;

	bio_set_dev(bio, params->dev->bdev);
	bio->bi_iter.bi_sector += params->start;

	submit_bio_noacct(bio);

	return DM_MAPIO_SUBMITTED;
}

static void passthrough_dtr(struct dm_target *ti)
{
	struct passthrough_params *params = ti->private;

	dm_put_device(ti, params->dev);
	kfree(params);
}

static struct target_type passthrough_target = {
	.name = "passthrough",
	.features = DM_TARGET_IMMUTABLE,
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = passthrough_ctr,
	.dtr = passthrough_dtr,
	.map = passthrough_map
};

static int __init dm_passthrough_init(void)
{
	int r;

	r = dm_register_target(&passthrough_target);
	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void __exit dm_passthrough_exit(void)
{
	dm_unregister_target(&passthrough_target);
}

module_init(dm_passthrough_init);
module_exit(dm_passthrough_exit);

MODULE_AUTHOR("Nathan Huckleberry <nhuck@google.com>");
MODULE_DESCRIPTION("Pass-through dm target for benchmarking");
MODULE_LICENSE("GPL");
