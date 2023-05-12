// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Microsoft Corporation.
 *
 * Author: Sangho Lee <Sangho.Lee@microsoft.com>
 *
 */
#ifndef DM_VERITY_APRON_H
#define DM_VERITY_APRON_H

#include <linux/dm-kcopyd.h>
#include <linux/rbtree.h>
#include <linux/time.h>
#include "dm-verity.h"

#define DM_VERITY_OPT_APRON_DEV	"apron_device"
#define DM_VERITY_OPT_APRON_BLOCKS	"apron_blocks"
#define DM_VERITY_OPT_APRON_START	"apron_start"
#define DM_VERITY_OPT_APRON_METADEV	"apron_meta_device"
#define DM_VERITY_OPT_APRON_META_SIZE "apron_meta_size"
#define DM_VERITY_OPT_APRON_NO_BGD	"apron_no_bgd"
#define DM_VERITY_OPT_APRON_DISCONN	"apron_disconn"
#define DM_VERITY_APRON_FETCHED	"apron_fetched"

/* configuration */
struct dm_verity_apron {
	struct dm_verity *v; /* parent dm_verity */
	struct dm_dev *dev;	/* apron device */
	struct dm_dev *meta_dev; /* apron metadata device */
	struct dm_bufio_client *bufio;		/* for apron data access */
	struct dm_bufio_client *data_bufio;	/* for target data access */
	struct dm_bufio_client *meta_bufio;	/* for apron metadata access */
	sector_t start;		/* apron data start in blocks */
	size_t meta_size;	/* metadata device size */
	mempool_t output_pool;	/* mempool for output */
	mempool_t bgd_copy_pool;	/* mempool for background copy */
	struct kmem_cache *cache;	/* cache for buffers */

	atomic64_t fetched;	/* number of fetched blocks */

	unsigned long *fetched_blocks;	/* bitmap for fetched blocks */
	unsigned long *changed_blocks; /* bitmap for changed/updated blocks */

	/* red-black trees for block map and reverse map */
	struct rb_root block_map_tree;
	struct rb_root block_revmap_tree;
	spinlock_t tree_lock;

	struct workqueue_struct *wq;
	struct work_struct update_worker;
	struct work_struct recovery_worker;
	struct work_struct duplicate_worker;
	struct delayed_work waker;	/* wake up update or recovery worker */
	struct delayed_work cleaner;	/* clean up apron module */

	struct dm_kcopyd_client *kcopyd_client;

	atomic_t ios_in_flight;
	sector_t copy_block_offset, changed_block_offset;
	size_t blocks_to_copy;

	unsigned long flags;

#ifdef DM_VERITY_APRON_STAT
	u64 stat_verify;
	u64 stat_dupcheck;
	u64 stat_lookup;
	u64 stat_all;
#endif
};

/* dm-verity-apron flags */
#define DM_APRON_BGD_COPY_DISABLED 0
#define DM_APRON_BGD_COPY_NEEDED 1
#define DM_APRON_BGD_COPY_IN_PROGRESS 2
#define DM_APRON_BGD_COPY_DONE 3
#define DM_APRON_UPDATE_IN_PROGRESS 4
#define DM_APRON_PREFETCH_NEEDED 5
#define DM_APRON_DISCONN_ENABLED 6
#define DM_APRON_DUPLICATE_NEEDED 7
#define DM_APRON_DUPLICATE_IN_PROGRESS 8
#define DM_APRON_DUPLICATE_DONE 9

/* per-bio data */
struct dm_verity_apron_io {
	u8 *output;	/* buffer for fetched output */
	size_t output_pos;
};

#define CONFIG_DM_VERITY_APRON
#ifdef CONFIG_DM_VERITY_APRON

/* each feature parameter requires a value */
#define DM_VERITY_OPTS_APRON	11

extern bool verity_apron_is_enabled(struct dm_verity *v);

extern int verity_apron_fetch(struct dm_verity *v, struct dm_verity_io *io,
			     enum verity_block_type type, sector_t block,
			     u8 *dest, struct bvec_iter *iter);

extern unsigned verity_apron_status_table(struct dm_verity *v, unsigned sz,
					char *result, unsigned maxlen);

extern void verity_apron_finish_io(struct dm_verity_io *io);
extern void verity_apron_init_io(struct dm_verity_io *io);

extern bool verity_is_apron_opt_arg(const char *arg_name);
extern int verity_apron_parse_opt_args(struct dm_arg_set *as,
				     struct dm_verity *v, unsigned *argc,
				     const char *arg_name);

extern void verity_apron_dtr(struct dm_verity *v);
extern void verity_apron_bgd_dtr(struct dm_verity *v);

extern int verity_apron_ctr_alloc(struct dm_verity *v);
extern int verity_apron_ctr(struct dm_verity *v);

#else

#define DM_VERITY_OPTS_apron	0

static inline bool verity_apron_is_enabled(struct dm_verity *v)
{
	return false;
}

static inline int verity_apron_fetch(struct dm_verity *v,
				    struct dm_verity_io *io,
				    enum verity_block_type type,
				    sector_t block, u8 *dest,
				    struct bvec_iter *iter)
{
	return -EOPNOTSUPP;
}

static inline unsigned verity_apron_status_table(struct dm_verity *v,
					       unsigned sz, char *result,
					       unsigned maxlen)
{
	return sz;
}

static inline void verity_apron_finish_io(struct dm_verity_io *io)
{
}

static inline void verity_apron_init_io(struct dm_verity_io *io)
{
}

static inline bool verity_is_apron_opt_arg(const char *arg_name)
{
	return false;
}

static inline int verity_apron_parse_opt_args(struct dm_arg_set *as,
					    struct dm_verity *v,
					    unsigned *argc,
					    const char *arg_name)
{
	return -EINVAL;
}

static inline void verity_apron_dtr(struct dm_verity *v)
{
}

static inline void verity_apron_bgd_dtr(struct dm_verity *v)
{
}

static inline int verity_apron_ctr_alloc(struct dm_verity *v)
{
	return 0;
}

static inline int verity_apron_ctr(struct dm_verity *v)
{
	return 0;
}

#endif /* CONFIG_DM_VERITY_APRON */
#endif /* DM_VERITY_APRON_H */
