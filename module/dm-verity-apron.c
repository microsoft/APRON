/*
 * Copyright Microsoft Corporation 
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include <linux/device-mapper.h>
#include <linux/verification.h>
#include <keys/user-type.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include "dm-verity-fec.h"
#include "dm-verity-apron.h"

#define ON_DEMAND_STORE
/* #define READ_AHEAD */

#define DM_MSG_PREFIX	"apron"

#define METADATA_BLOCK_SIZE 4096
#define MIN_COPY_BLOCKS 1
#define MAX_COPY_BLOCKS 1024

#define COMMIT_PERIOD HZ /* 1 sec */
#define CLEAN_DELAY (5*HZ)

#define MSG_RECOVERY_START "recovery started"
#define MSG_RECOVERY_DONE "recovery done"
#define MSG_UPDATE_START "update started"
#define MSG_UPDATE_DONE "update done"
#define MSG_DUPLICATE_DONE "duplication done"
#define MSG_CLEAN_APRON "clean up apron module"

DECLARE_DM_KCOPYD_THROTTLE_WITH_MODULE_PARM(verity_apron_throttle,
	"A percentage of time allocated for background fetching");

struct apron_copy_info {
	struct dm_verity_apron *apron;
	sector_t start;
	size_t count;
};

static struct apron_copy_info *rci_dummy = NULL;

struct blkpair {
	struct rb_node node;
	int first;
	int second;
};

/*
 * If apron device has been configured, returns true.
 */
bool verity_apron_is_enabled(struct dm_verity *v)
{
	return v->apron && v->apron->dev;
}

/*
 * Return a pointer to dm_verity_apron_io after dm_verity_io, its variable
 * length fields, and dm_verity_fec_io.
 */
static inline struct dm_verity_apron_io *apron_io(struct dm_verity_io *io)
{
	/* TODO: extend dm_verity_io to support both FEC and apron together */
	return (struct dm_verity_apron_io *) verity_io_digest_end(io->v, io);
}

static int apron_bv_copy(struct dm_verity *v, struct dm_verity_io *io,
		      u8 *data, size_t len)
{
	struct dm_verity_apron_io *sio = apron_io(io);

	memcpy(data, &sio->output[sio->output_pos], len);
	sio->output_pos += len;

	return 0;
}

static inline void wake_update_worker(struct dm_verity_apron *s)
{
	queue_work(s->wq, &s->update_worker);
}

static inline void wake_recovery_worker(struct dm_verity_apron *s)
{
	queue_work(s->wq, &s->recovery_worker);
}

static inline void wake_duplicate_worker(struct dm_verity_apron *r)
{
	queue_work(r->wq, &r->duplicate_worker);
}

static void do_waker(struct work_struct *work)
{
	struct dm_verity_apron *r = container_of(to_delayed_work(work), typeof(*r),
			waker);

	if (test_bit(DM_APRON_BGD_COPY_NEEDED, &r->flags)) {
		if (!test_bit(DM_APRON_BGD_COPY_IN_PROGRESS, &r->flags)) {
			set_bit(DM_APRON_BGD_COPY_IN_PROGRESS, &r->flags);
			wake_recovery_worker(r);
		}
	} else if (test_bit(DM_APRON_DUPLICATE_NEEDED, &r->flags)) {
		if (!test_bit(DM_APRON_DUPLICATE_IN_PROGRESS, &r->flags)) {
			set_bit(DM_APRON_DUPLICATE_IN_PROGRESS, &r->flags);
			wake_duplicate_worker(r);
		}
	} else if (r->changed_blocks) {
		if (!test_bit(DM_APRON_UPDATE_IN_PROGRESS, &r->flags) &&
				!test_bit(DM_APRON_BGD_COPY_DONE, &r->flags)) {
			set_bit(DM_APRON_UPDATE_IN_PROGRESS, &r->flags);
			wake_update_worker(r);
		}
	}
}

#ifdef CONFIG_PROC_FS
static u64 fetched_final = 0;

static int proc_apron_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%llu\n", fetched_final);
	return 0;
}
#endif

static void do_clean_apron(struct work_struct *work)
{
	struct dm_verity_apron *r = container_of(to_delayed_work(work), typeof(*r),
			cleaner);
	struct dm_verity *v = r->v;

	DMWARN(MSG_CLEAN_APRON);

#ifdef CONFIG_PROC_FS
	fetched_final = atomic64_read(&v->apron->fetched);
	proc_create_single("verity-apron", 0, NULL, proc_apron_show);
#endif

	atomic_inc(&v->apron_done);
}

enum dupstate {
	NOT_DUPLICATED = 0,
	DUPLICATED = 1,
	DUPLICATED_STORED = 2,
};

static enum dupstate is_duplicated_block(struct dm_verity_apron *r,
		int block, sector_t *remapped)
{
	struct rb_node *node = r->block_map_tree.rb_node;
	struct blkpair *bp, *bpr;

	while (node) {
		bp = rb_entry(node, struct blkpair, node);

		if (block < bp->first)
			node = node->rb_left;
		else if (block > bp->first)
			node = node->rb_right;
		else
			break;
	}
	if (node == NULL)
		return NOT_DUPLICATED;

	spin_lock(&r->tree_lock);
	node = r->block_revmap_tree.rb_node;
	while (node) {
		bpr = rb_entry(node, struct blkpair, node);

		if (bp->second < bpr->first)
			node = node->rb_left;
		else if (bp->second > bpr->first)
			node = node->rb_right;
		else
			break;
	}
	spin_unlock(&r->tree_lock);

	if (node == NULL)
		return DUPLICATED;

	if (remapped)
		*remapped = bpr->second;

	return DUPLICATED_STORED;
}

static void update_block_map(struct dm_verity_apron *r, int block)
{
	struct rb_node *node = r->block_map_tree.rb_node;
	struct rb_node **new = NULL, *parent = NULL;
	struct blkpair *bp, *bpr;

	while (node) {
		bp = rb_entry(node, struct blkpair, node);

		if (block < bp->first)
			node = node->rb_left;
		else if (block > bp->first)
			node = node->rb_right;
		else
			break;
	}
	if (node == NULL)
		return;

	bpr = kmalloc(sizeof(struct blkpair), GFP_NOIO);
	if (!bpr) {
		r->v->ti->error = "Cannot allocate memory";
		return;
	}
	bpr->first = bp->second;
	bpr->second = block;

	spin_lock(&r->tree_lock);
	new = &(r->block_revmap_tree.rb_node);
	while (*new) {
		bp = rb_entry(*new, struct blkpair, node);
		parent = *new;

		if (bpr->first < bp->first)
			new = &((*new)->rb_left);
		else if (bpr->first > bp->first)
			new = &((*new)->rb_right);
		else {
			kfree(bpr);
			spin_unlock(&r->tree_lock);
			return;
		}
	}

	rb_link_node(&bpr->node, parent, new);
	rb_insert_color(&bpr->node, &r->block_revmap_tree);
	spin_unlock(&r->tree_lock);
}

static void insert_block_pair(struct dm_verity_apron *r,
		int block1, int block2)
{
	struct rb_node **new = &(r->block_map_tree.rb_node), *parent = NULL;
	struct blkpair *bp, *this;

	while (*new) {
		this = rb_entry(*new, struct blkpair, node);
		parent = *new;
		if (block1 < this->first)
			new = &((*new)->rb_left);
		else if (block1 > this->first)
			new = &((*new)->rb_right);
		else
			return;
	}

	bp = kmalloc(sizeof(struct blkpair), GFP_NOIO);
	if (!bp) {
		r->v->ti->error = "Cannot allocate memory";
		return;
	}
	bp->first = block1;
	bp->second = block2;

	rb_link_node(&bp->node, parent, new);
	rb_insert_color(&bp->node, &r->block_map_tree);
}

static void verity_apron_kcopyd_callback(int read_err, unsigned long write_err,
		void *context)
{
	struct apron_copy_info *rci = (struct apron_copy_info *) context;
	struct dm_verity_apron *r = rci->apron;
	size_t i;

	if (rci->count) {
		atomic64_add(rci->count, &r->fetched);
		for (i = 0; i < rci->count; i++) {
			set_bit(rci->start + i, r->fetched_blocks);
			update_block_map(r, (int)(rci->start + i));
		}
	}

	if (test_bit(DM_APRON_BGD_COPY_NEEDED, &r->flags))
		clear_bit(DM_APRON_BGD_COPY_IN_PROGRESS, &r->flags);

	if (test_bit(DM_APRON_DUPLICATE_NEEDED, &r->flags))
		clear_bit(DM_APRON_DUPLICATE_IN_PROGRESS, &r->flags);

	if (r->changed_blocks)
		clear_bit(DM_APRON_UPDATE_IN_PROGRESS, &r->flags);

	if (atomic_read(&r->ios_in_flight)) {
		r->blocks_to_copy = MIN_COPY_BLOCKS;
		goto out;
	}

	if (test_bit(DM_APRON_BGD_COPY_NEEDED, &r->flags)) {
		if (!test_bit(DM_APRON_BGD_COPY_IN_PROGRESS, &r->flags)) {
			set_bit(DM_APRON_BGD_COPY_IN_PROGRESS, &r->flags);
			cancel_work_sync(&r->update_worker);
			cancel_delayed_work_sync(&r->waker);
			wake_recovery_worker(r);
		}
	} else if (test_bit(DM_APRON_DUPLICATE_NEEDED, &r->flags)) {
		if (!test_bit(DM_APRON_DUPLICATE_IN_PROGRESS, &r->flags)) {
			set_bit(DM_APRON_DUPLICATE_IN_PROGRESS, &r->flags);
			cancel_work_sync(&r->update_worker);
			cancel_delayed_work_sync(&r->waker);
			wake_duplicate_worker(r);
		}
	} else if (r->changed_blocks) {
		if (!test_bit(DM_APRON_UPDATE_IN_PROGRESS, &r->flags) &&
				!test_bit(DM_APRON_BGD_COPY_DONE, &r->flags)) {
			set_bit(DM_APRON_UPDATE_IN_PROGRESS, &r->flags);
			cancel_delayed_work_sync(&r->waker);
			wake_update_worker(r);
		}
	}

out:
	if (rci != rci_dummy)
		mempool_free(rci, &r->bgd_copy_pool);
}

static void delete_block_map(struct dm_verity_apron *r)
{
	struct rb_node *node, *next;
	struct blkpair *bp;

	node = rb_first(&r->block_map_tree);
	while (node) {
		bp = rb_entry(node, struct blkpair, node);
		next = rb_next(node);
		rb_erase(node, &r->block_map_tree);
		kfree(bp);
		node = next;
	}
	r->block_map_tree = RB_ROOT;

	node = rb_first(&r->block_revmap_tree);
	while (node) {
		bp = rb_entry(node, struct blkpair, node);
		next = rb_next(node);
		rb_erase(node, &r->block_map_tree);
		kfree(bp);
		node = next;
	}
	r->block_revmap_tree = RB_ROOT;
}

static int read_verify_block(struct dm_verity *v, struct dm_verity_io *io,
		sector_t block)
{
	struct dm_verity_apron *s = v->apron;
	struct dm_buffer *dbuf = NULL;
	u8 *bdbuf;
	int r;
	bool is_zero;

	r = verity_hash_for_block(v, io, block,
			verity_io_want_digest(v, io), &is_zero);
	if (unlikely(r < 0))
		goto out;

	if (is_zero) {
		set_bit(block, s->fetched_blocks);
		return 0;
	}

	bdbuf = dm_bufio_read(s->data_bufio, v->data_start + block, &dbuf);
	if (IS_ERR(bdbuf)) {
		DMERR("%s: read failed (block %llu): %ld",
			s->dev->name,
			(unsigned long long)block,
			PTR_ERR(bdbuf));
		goto out;
	}

	r = verity_hash(v, verity_io_hash_req(v, io), bdbuf,
			1 << v->data_dev_block_bits, verity_io_real_digest(v, io));
	dm_bufio_release(dbuf);

	if (unlikely(r < 0))
		goto out;

	if (!memcmp(verity_io_real_digest(v, io), verity_io_want_digest(v, io),
			v->digest_size))
		return 0;
	else
		return 1;

out:
	return -1;
}

static void do_update_worker(struct work_struct *work)
{
	struct dm_verity_apron *s = container_of(work, typeof(*s), update_worker);
	struct dm_verity *v = s->v;
	struct dm_io_region from, dest;
	struct apron_copy_info *rci = NULL;
	sector_t first_changed, b;
	unsigned from_block_size, dest_block_size, data_size;

	if (!s->changed_blocks)
		return;

	if (s->changed_block_offset == 0)
		DMWARN(MSG_UPDATE_START);

	s->changed_block_offset = find_next_bit(s->changed_blocks, v->data_blocks,
			s->changed_block_offset);

	if (s->changed_block_offset >= v->data_blocks) {
		DMWARN(MSG_UPDATE_DONE);
		kvfree(s->changed_blocks);
		s->changed_blocks = NULL;
		return;
	}

	first_changed = s->changed_block_offset;
	for (b = first_changed + 1; b < v->data_blocks; b++) {
		if (!test_bit(b, s->changed_blocks))
			break;
	}
	s->changed_block_offset = b;

	from_block_size = bdev_logical_block_size(s->dev->bdev);
	dest_block_size = bdev_logical_block_size(v->data_dev->bdev);
	data_size = 1 << v->data_dev_block_bits;

	from.bdev = s->dev->bdev;
	from.sector = (s->start + first_changed) * data_size / from_block_size;
	from.count = (s->changed_block_offset - first_changed) * data_size / from_block_size;

	dest.bdev = v->data_dev->bdev;
	dest.sector = (v->data_start + first_changed) * data_size / dest_block_size;
	dest.count = from.count * from_block_size / dest_block_size;

	rci = mempool_alloc(&s->bgd_copy_pool, GFP_NOIO);
	rci->apron = s;
	rci->start = first_changed;
	rci->count = s->changed_block_offset - first_changed;

	dm_kcopyd_copy(s->kcopyd_client, &from, 1, &dest, 0,
			verity_apron_kcopyd_callback, rci);
}

static void do_recovery_worker(struct work_struct *work)
{
	struct dm_verity_apron *s = container_of(work, typeof(*s), recovery_worker);
	struct dm_verity *v = s->v;
	struct dm_verity_io *io;
	struct dm_io_region from, dest;
	struct apron_copy_info *rci = NULL;
	sector_t first_invalid, first_unknown, verify_bound;
	unsigned from_block_size, dest_block_size, data_size;
	int i, r;
#ifdef DM_VERITY_APRON_STAT
	ktime_t start, start0;
#endif

	if (!test_bit(DM_APRON_BGD_COPY_NEEDED, &s->flags))
		return;
#ifdef DM_VERITY_APRON_STAT
	start0 = ktime_get();
#endif

	io = kzalloc(v->ti->per_io_data_size, GFP_KERNEL);
	if (!io) {
		v->ti->error = "Cannot allocate memory";
		goto out;
	}

	/* find the next invalid block */
#ifdef DM_VERITY_APRON_STAT
	start = ktime_get();
#endif
	first_unknown = find_next_zero_bit(s->fetched_blocks, v->data_blocks,
			s->copy_block_offset);
#ifdef DM_VERITY_APRON_STAT
	s->stat_lookup += ktime_to_us(ktime_sub(ktime_get(), start));
#endif
	while (first_unknown < v->data_blocks) {
#ifdef DM_VERITY_APRON_STAT
		start = ktime_get();
#endif
		if (is_duplicated_block(s, (int)first_unknown, NULL) != DUPLICATED_STORED) {
#ifdef DM_VERITY_APRON_STAT
			s->stat_dupcheck += ktime_to_us(ktime_sub(ktime_get(), start));
#endif
			break;
		}
		else {
#ifdef DM_VERITY_APRON_STAT
			start = ktime_get();
#endif
			first_unknown = find_next_zero_bit(s->fetched_blocks, v->data_blocks,
					first_unknown + 1);
#ifdef DM_VERITY_APRON_STAT
			s->stat_lookup += ktime_to_us(ktime_sub(ktime_get(), start));
#endif
		}
	}
	if (first_unknown >= v->data_blocks) {
		s->copy_block_offset = v->data_blocks;
		goto out;
	}

	for (i = 1; i < s->blocks_to_copy && first_unknown + i < v->data_blocks; i++) {
		if (test_bit(first_unknown + i, s->fetched_blocks))
			break;
	}
	if (i == s->blocks_to_copy && s->blocks_to_copy < MAX_COPY_BLOCKS)
		s->blocks_to_copy <<= 1;

	verify_bound = first_unknown + i;
	if (verify_bound > v->data_blocks)
		verify_bound = v->data_blocks;

	dm_bufio_prefetch(s->data_bufio, v->data_start + first_unknown,
			verify_bound - first_unknown);

	for (s->copy_block_offset = first_unknown;
			s->copy_block_offset < verify_bound; (s->copy_block_offset)++) {
		if (v->validated_blocks &&
				likely(test_bit(v->data_start + s->copy_block_offset, v->validated_blocks)))
			continue;

#ifdef DM_VERITY_APRON_STAT
		start = ktime_get();
#endif
		if (is_duplicated_block(s, (int)s->copy_block_offset, NULL) ==
				DUPLICATED_STORED) {
#ifdef DM_VERITY_APRON_STAT
			s->stat_dupcheck += ktime_to_us(ktime_sub(ktime_get(), start));
#endif
			continue;
		}

#ifdef DM_VERITY_APRON_STAT
		start = ktime_get();
#endif
		r = read_verify_block(v, io, v->data_start + s->copy_block_offset);
#ifdef DM_VERITY_APRON_STAT
		s->stat_verify += ktime_to_us(ktime_sub(ktime_get(), start));
#endif
		if (unlikely(r < 0))
			goto out;
		else if (!r)
			set_bit(s->copy_block_offset, s->fetched_blocks);
		else
			break;
	}

	if (s->copy_block_offset == verify_bound) {
		if (verify_bound >= v->data_blocks)
			s->copy_block_offset = v->data_blocks;
		else
			verity_apron_kcopyd_callback(0, 0, rci_dummy); /* yield */
		goto out;
	}

	first_invalid = s->copy_block_offset;
	(s->copy_block_offset)++;

	/* find the next valid block */
	for (; s->copy_block_offset < verify_bound; (s->copy_block_offset)++) {
		if (v->validated_blocks &&
				likely(test_bit(v->data_start + s->copy_block_offset, v->validated_blocks)))
			break;

#ifdef DM_VERITY_APRON_STAT
		start = ktime_get();
#endif
		if (is_duplicated_block(s, (int)s->copy_block_offset, NULL) ==
				DUPLICATED_STORED) {
#ifdef DM_VERITY_APRON_STAT
			s->stat_dupcheck += ktime_to_us(ktime_sub(ktime_get(), start));
#endif
			break;
		}

#ifdef DM_VERITY_APRON_STAT
		start = ktime_get();
#endif
		r = read_verify_block(v, io, v->data_start + s->copy_block_offset);
#ifdef DM_VERITY_APRON_STAT
		s->stat_verify += ktime_to_us(ktime_sub(ktime_get(), start));
#endif
		if (unlikely(r < 0))
			goto out;
		else if (!r) {
			set_bit(s->copy_block_offset, s->fetched_blocks);
#ifndef READ_AHEAD
			break;
#else
			if (s->copy_block_offset + 1 < verify_bound) {
				r = read_verify_block(v, io, v->data_start + s->copy_block_offset + 1);
				if (unlikely(r < 0))
					goto out;
				else if (!r) {
					set_bit(s->copy_block_offset + 1, s->fetched_blocks);
					break;
				}
			}
#endif
		}
	}

	from_block_size = bdev_logical_block_size(s->dev->bdev);
	dest_block_size = bdev_logical_block_size(v->data_dev->bdev);
	data_size = 1 << v->data_dev_block_bits;

	/* copy an array of invalid blocks */
	/* TODO: dm_kcopyd_copy works only when the block sizes of source and
	 * destination devices are the same. Use 512 B of block size for now for NBD
	 * (bad for performance). Consider how to support different block sizes
	 * (revise dm_kcopyd or use a different mechanism). */
	from.bdev = s->dev->bdev;
	from.sector = (s->start + first_invalid) * data_size / from_block_size;
	from.count = (s->copy_block_offset - first_invalid) * data_size / from_block_size;

	dest.bdev = v->data_dev->bdev;
	dest.sector = (v->data_start + first_invalid) * data_size / dest_block_size;
	dest.count = from.count * from_block_size / dest_block_size;

	rci = mempool_alloc(&s->bgd_copy_pool, GFP_NOIO);
	rci->apron = s;
	rci->start = first_invalid;
	rci->count = s->copy_block_offset - first_invalid;

	dm_kcopyd_copy(s->kcopyd_client, &from, 1, &dest, 0,
			verity_apron_kcopyd_callback, rci);

out:
	kfree(io);

	if (s->copy_block_offset >= v->data_blocks) {
		DMWARN(MSG_RECOVERY_DONE);
		clear_bit(DM_APRON_BGD_COPY_NEEDED, &s->flags);
		set_bit(DM_APRON_BGD_COPY_DONE, &s->flags);

		set_bit(DM_APRON_DUPLICATE_NEEDED, &s->flags);
		s->copy_block_offset = 0;

		verity_apron_kcopyd_callback(0, 0, rci_dummy);
	}
#ifdef DM_VERITY_APRON_STAT
	s->stat_all += ktime_to_us(ktime_sub(ktime_get(), start0));
#endif
}

static void do_duplicate_worker(struct work_struct *work)
{
	struct dm_verity_apron *s = container_of(work, typeof(*s), duplicate_worker);
	struct dm_verity *v = s->v;
	struct dm_io_region from, dest;
	struct apron_copy_info *rci = NULL;
	sector_t invalid, remapped, remapped_next;
	size_t count;
	enum dupstate ds;
	unsigned block_size, data_size;

	if (!test_bit(DM_APRON_DUPLICATE_NEEDED, &s->flags))
		return;

	invalid = find_next_zero_bit(s->fetched_blocks, v->data_blocks,
			s->copy_block_offset);
	if (invalid >= v->data_blocks) {
		s->copy_block_offset = invalid;
		goto out;
	}
	BUG_ON(is_duplicated_block(s, (int)invalid, &remapped) != DUPLICATED_STORED);

	for (count = 1; invalid + count < v->data_blocks; count++) {
		if (test_bit(invalid + count, s->fetched_blocks))
			break;

		ds = is_duplicated_block(s, (int)(invalid + count), &remapped_next);
		if (ds != DUPLICATED_STORED || remapped + count != remapped_next)
			break;
	}

	block_size = bdev_logical_block_size(v->data_dev->bdev);
	data_size = 1 << v->data_dev_block_bits;

	from.bdev = v->data_dev->bdev;
	from.sector = (v->data_start + remapped) * data_size / block_size;
	from.count = count * data_size / block_size;

	dest.bdev = v->data_dev->bdev;
	dest.sector = (v->data_start + invalid) * data_size / block_size;
	dest.count = from.count;

	rci = mempool_alloc(&s->bgd_copy_pool, GFP_NOIO);
	rci->apron = s;
	rci->start = invalid;
	rci->count = count;

	dm_kcopyd_copy(s->kcopyd_client, &from, 1, &dest, 0,
			verity_apron_kcopyd_callback, rci);
	s->copy_block_offset = invalid + 1;

out:
	if (s->copy_block_offset >= v->data_blocks) {
		DMWARN(MSG_DUPLICATE_DONE);
		clear_bit(DM_APRON_DUPLICATE_NEEDED, &s->flags);
		set_bit(DM_APRON_DUPLICATE_DONE, &s->flags);

#ifdef DM_VERITY_APRON_STAT
		DMWARN("stat.verify %llu", s->stat_verify);
		DMWARN("stat.dupcheck %llu", s->stat_dupcheck);
		DMWARN("stat.lookup %llu", s->stat_lookup);
		DMWARN("stat.all %llu", s->stat_all);
#endif

		if (test_bit(DM_APRON_DISCONN_ENABLED, &v->apron->flags))
			queue_delayed_work(s->wq, &s->cleaner, CLEAN_DELAY);
	}
}

/*
 * Correct errors in a block by fetching a corresponding block from
 * a apron device. Copies fetched block to dest if non-NULL,
 * otherwise to a bio_vec starting from iter.
 */
int verity_apron_fetch(struct dm_verity *v, struct dm_verity_io *io,
		      enum verity_block_type type, sector_t block, u8 *dest,
		      struct bvec_iter *iter)
{
	int r;
	struct dm_buffer *buf = NULL;
	struct dm_verity_apron_io *sio = apron_io(io);
	u8 *bbuf;
	enum dupstate ds;
	sector_t remapped;
#ifdef ON_DEMAND_STORE
	struct dm_buffer *dbuf;
	u8 *bdbuf;
#endif

	if (!verity_apron_is_enabled(v))
		return -EOPNOTSUPP;

	if (type == DM_VERITY_BLOCK_TYPE_METADATA)
		block = block - v->hash_start + v->data_blocks;

	if (!sio->output)
		sio->output = mempool_alloc(&v->apron->output_pool, GFP_NOIO);

	ds = is_duplicated_block(v->apron, (int)block, &remapped);
	if (ds == DUPLICATED_STORED) {
		bbuf = dm_bufio_read(v->apron->data_bufio,
				v->data_start + remapped, &buf);
		if (IS_ERR(bbuf)) {
			DMERR("%s: read failed (block %llu): %ld",
				v->data_dev->name,
				(unsigned long long)(v->data_start + remapped),
				PTR_ERR(bbuf));
			return PTR_ERR(bbuf);
		}
		memcpy(sio->output, bbuf, 1 << v->data_dev_block_bits);
		dm_bufio_release(buf);
		buf = NULL;

		r = verity_hash(v, verity_io_hash_req(v, io), sio->output,
				1 << v->data_dev_block_bits, verity_io_real_digest(v, io));
		if (unlikely(r < 0))
			goto done;

		if (memcmp(verity_io_real_digest(v, io), verity_io_want_digest(v, io),
			   v->digest_size)) {
			ds = DUPLICATED; /* TODO? avoid this potential timing issue */
		}
	}

	if (ds != DUPLICATED_STORED) {
		bbuf = dm_bufio_read(v->apron->bufio, v->apron->start + block, &buf);
		if (IS_ERR(bbuf)) {
			DMERR("%s: read failed (block %llu): %ld",
				v->apron->dev->name,
				(unsigned long long)(v->apron->start + block),
				PTR_ERR(bbuf));
			return PTR_ERR(bbuf);
		}
		memcpy(sio->output, bbuf, 1 << v->data_dev_block_bits);
		dm_bufio_release(buf);
		buf = NULL;

		/* Always re-validate the corrected block against the expected hash */
		r = verity_hash(v, verity_io_hash_req(v, io), sio->output,
				1 << v->data_dev_block_bits, verity_io_real_digest(v, io));
		if (unlikely(r < 0))
			goto done;

		if (memcmp(verity_io_real_digest(v, io), verity_io_want_digest(v, io),
			   v->digest_size)) {
			DMERR_LIMIT("%s: fetched invalid block", v->data_dev->name);
			r = -EILSEQ;
			goto done;
		}
	}

	if (dest)
		memcpy(dest, sio->output, 1 << v->data_dev_block_bits);
	else if (iter) {
		sio->output_pos = 0;
		r = verity_for_bv_block(v, io, iter, apron_bv_copy);
	}

#ifdef ON_DEMAND_STORE
	if (test_bit(DM_APRON_BGD_COPY_DISABLED, &v->apron->flags)) {
		bdbuf = dm_bufio_new(v->apron->data_bufio, v->data_start + block,
				&dbuf);
		if (IS_ERR(bdbuf)) {
			DMERR("%s: read failed (block %llu): %ld",
				v->data_dev->name,
				(unsigned long long)block,
				PTR_ERR(bdbuf));
			r = PTR_ERR(bdbuf);
			goto done;
		}
		memcpy(bdbuf, sio->output, 1 << v->data_dev_block_bits);
		dm_bufio_mark_buffer_dirty(dbuf);
		dm_bufio_write_dirty_buffers_async(v->apron->data_bufio);
		dm_bufio_release(dbuf);

		atomic64_inc(&v->apron->fetched);
		set_bit(block, v->apron->fetched_blocks);

		update_block_map(v->apron, (int)block);
	}
#endif

	if (!test_bit(DM_APRON_BGD_COPY_DISABLED, &v->apron->flags) &&
			!test_bit(DM_APRON_BGD_COPY_DONE, &v->apron->flags) &&
			!test_bit(DM_APRON_BGD_COPY_NEEDED, &v->apron->flags)) {
		set_bit(DM_APRON_BGD_COPY_NEEDED, &v->apron->flags);
		DMWARN(MSG_RECOVERY_START);
	}
	set_bit(DM_APRON_PREFETCH_NEEDED, &v->apron->flags);

done:
	if (buf)
		dm_bufio_release(buf);
	return r;
}

/*
 * Clean up per-bio data.
 */
void verity_apron_finish_io(struct dm_verity_io *io)
{
	struct dm_verity_apron *r = io->v->apron;
	struct dm_verity_apron_io *rio = apron_io(io);

	if (!verity_apron_is_enabled(io->v))
		return;

	if (rio->output) {
		mempool_free(rio->output, &r->output_pool);
		rio->output = NULL;
	}

	atomic_dec(&r->ios_in_flight);
	if (atomic_read(&r->ios_in_flight))
		return;

	queue_delayed_work(r->wq, &r->waker, COMMIT_PERIOD);
}

/*
 * Initialize per-bio data.
 */
void verity_apron_init_io(struct dm_verity_io *io)
{
	struct dm_verity_apron_io *sio = apron_io(io);
	if (!verity_apron_is_enabled(io->v))
		return;

	sio->output = NULL;
	atomic_inc(&io->v->apron->ios_in_flight);
}

/*
 * Append feature arguments and values to the status table.
 */
unsigned verity_apron_status_table(struct dm_verity *v, unsigned sz,
				 char *result, unsigned maxlen)
{
	if (!verity_apron_is_enabled(v))
		return sz;

	DMEMIT(" " DM_VERITY_OPT_APRON_DEV " %s "
	       DM_VERITY_OPT_APRON_START " %llu "
	       DM_VERITY_OPT_APRON_METADEV " %s "
	       DM_VERITY_OPT_APRON_NO_BGD " %d "
	       DM_VERITY_OPT_APRON_DISCONN " %d "
	       DM_VERITY_APRON_FETCHED " %lld ",
	       v->apron->dev->name,
	       (unsigned long long)v->apron->start,
	       v->apron->meta_dev ? v->apron->meta_dev->name : NULL,
	       test_bit(DM_APRON_BGD_COPY_DISABLED, &v->apron->flags),
	       test_bit(DM_APRON_DISCONN_ENABLED, &v->apron->flags),
	       atomic64_read(&v->apron->fetched));

	return sz;
}

void verity_apron_bgd_dtr(struct dm_verity *v)
{
	struct dm_verity_apron *s = v->apron;

	if (!verity_apron_is_enabled(v))
		return;

	cancel_work_sync(&s->update_worker);
	cancel_work_sync(&s->recovery_worker);
	cancel_work_sync(&s->duplicate_worker);
	cancel_delayed_work_sync(&s->waker);
	cancel_delayed_work_sync(&s->cleaner);

	if (s->kcopyd_client)
		dm_kcopyd_client_destroy(s->kcopyd_client);
	if (s->wq)
		destroy_workqueue(s->wq);
}

void verity_apron_dtr(struct dm_verity *v)
{
	struct dm_verity_apron *s = v->apron;

	if (!verity_apron_is_enabled(v))
		goto out;

	if (rci_dummy)
		mempool_free(rci_dummy, &s->bgd_copy_pool);

	mempool_exit(&s->output_pool);
	mempool_exit(&s->bgd_copy_pool);
	kmem_cache_destroy(s->cache);

	if (s->data_bufio)
		dm_bufio_client_destroy(s->data_bufio);
	if (s->bufio)
		dm_bufio_client_destroy(s->bufio);
	if (s->meta_bufio)
		dm_bufio_client_destroy(s->meta_bufio);

	if (s->dev) {
		dm_put_device(v->ti, s->dev);
		s->dev = NULL;
	}
	if (s->meta_dev)
		dm_put_device(v->ti, s->meta_dev);

	if (s->fetched_blocks)
		kvfree(s->fetched_blocks);
	if (s->changed_blocks)
		kvfree(s->changed_blocks);

	delete_block_map(s);
out:
	kfree(s);
	v->apron = NULL;
}

bool verity_is_apron_opt_arg(const char *arg_name)
{
	return (!strcasecmp(arg_name, DM_VERITY_OPT_APRON_DEV) ||
		!strcasecmp(arg_name, DM_VERITY_OPT_APRON_METADEV) ||
		!strcasecmp(arg_name, DM_VERITY_OPT_APRON_META_SIZE) ||
		!strcasecmp(arg_name, DM_VERITY_OPT_APRON_NO_BGD) ||
		!strcasecmp(arg_name, DM_VERITY_OPT_APRON_START));
}

int verity_apron_parse_opt_args(struct dm_arg_set *as, struct dm_verity *v,
			      unsigned *argc, const char *arg_name)
{
	int r;
	struct dm_target *ti = v->ti;
	const char *arg_value;
	unsigned long long num_ll;
	char dummy;

	/* argument without value */
	if (!strcasecmp(arg_name, DM_VERITY_OPT_APRON_NO_BGD)) {
		set_bit(DM_APRON_BGD_COPY_DISABLED, &v->apron->flags);
		return 0;
	}

	if (!*argc) {
		ti->error = "apron feature arguments require a value";
		return -EINVAL;
	}

	arg_value = dm_shift_arg(as);
	(*argc)--;

	if (!strcasecmp(arg_name, DM_VERITY_OPT_APRON_DEV)) {
		r = dm_get_device(ti, arg_value, FMODE_READ, &v->apron->dev);
		if (r) {
			ti->error = "apron device lookup failed";
			return r;
		}
	} else if (!strcasecmp(arg_name, DM_VERITY_OPT_APRON_START)) {
		if (sscanf(arg_value, "%llu%c", &num_ll, &dummy) != 1 ||
		    ((sector_t)(num_ll << (v->data_dev_block_bits - SECTOR_SHIFT)) >>
		     (v->data_dev_block_bits - SECTOR_SHIFT) != num_ll)) {
			ti->error = "Invalid " DM_VERITY_OPT_APRON_START;
			return -EINVAL;
		}
		v->apron->start = num_ll;
	} else if (!strcasecmp(arg_name, DM_VERITY_OPT_APRON_META_SIZE)) {
		if (sscanf(arg_value, "%llu%c", &num_ll, &dummy) != 1) {
			ti->error = "Invalid " DM_VERITY_OPT_APRON_META_SIZE;
			return -EINVAL;
		}
		v->apron->meta_size = num_ll;
	} else if (!strcasecmp(arg_name, DM_VERITY_OPT_APRON_METADEV)) {
		r = dm_get_device(ti, arg_value, FMODE_READ, &v->apron->meta_dev);
		if (r) {
			ti->error = "apron metadata device lookup failed";
			return r;
		}
	} else {
		ti->error = "Unrecognized verity apron feature request";
		return -EINVAL;
	}

	return 0;
}

/*
 * Allocate dm_verity_apron for v->apron. Must be called before
 * verity_apron_ctr.
 */
int verity_apron_ctr_alloc(struct dm_verity *v)
{
	struct dm_verity_apron *s;

	s = kzalloc(sizeof(struct dm_verity_apron), GFP_KERNEL);
	if (!s) {
		v->ti->error = "Cannot allocate apron structure";
		return -ENOMEM;
	}
	v->apron = s;

	return 0;
}

/*
 * Validate arguments and preallocate memory. Must be called after arguments
 * have been parsed using verity_apron_parse_opt_args.
 */
int verity_apron_ctr(struct dm_verity *v)
{
	struct dm_verity_apron *s = v->apron;
	struct dm_target *ti = v->ti;
	struct dm_buffer *mbuf = NULL;
	u8 *bmbuf;
	int block1, block2; /* TODO: use sector_t */
	int i, j;
	int ret;

	/* TODO: extend dm_verity_io to support both FEC and apron together */
	if (verity_fec_is_enabled(v)) {
		ti->error = "Cannot use FEC and apron together";
		return -EINVAL;
	}

	if (!verity_apron_is_enabled(v)) {
		verity_apron_dtr(v);
		return 0;
	}

	s->v = v;

	s->bufio = dm_bufio_client_create(s->dev->bdev,
					  1 << v->data_dev_block_bits,
					  1, 0, NULL, NULL);
	if (IS_ERR(s->bufio)) {
		ti->error = "Cannot initialize apron bufio client";
		return PTR_ERR(s->bufio);
	}

	if (dm_bufio_get_device_size(s->bufio) < v->data_blocks) {
		ti->error = "apron device is too small";
		return -E2BIG;
	}

	s->data_bufio = dm_bufio_client_create(v->data_dev->bdev,
					       1 << v->data_dev_block_bits,
					       1, 0, NULL, NULL);
	if (IS_ERR(s->data_bufio)) {
		ti->error = "Cannot initialize apron data bufio client";
		return PTR_ERR(s->data_bufio);
	}

	if (s->meta_dev) {
		s->meta_bufio = dm_bufio_client_create(s->meta_dev->bdev,
						       METADATA_BLOCK_SIZE,
						       1, 0, NULL, NULL);
		if (IS_ERR(s->meta_bufio)) {
			ti->error = "Cannot initialize apron metadata bufio client";
			return PTR_ERR(s->meta_bufio);
		}

#if 0
		s->changed_blocks = kvcalloc(BITS_TO_LONGS(v->data_blocks),
				sizeof(unsigned long), GFP_KERNEL);
		if (!s->changed_blocks) {
			ti->error = "failed to allocate bitset for changed blocks";
			return -ENOMEM;
		}
#endif
	}

	s->cache = KMEM_CACHE(apron_copy_info, 0);
	if (!s->cache) {
		ti->error = "Cannot create apron buffer cache";
		return -ENOMEM;
	}

	/* Preallocate an output buffer for each thread */
	ret = mempool_init_kmalloc_pool(&s->output_pool, num_online_cpus(),
					1 << v->data_dev_block_bits);
	if (ret) {
		ti->error = "Cannot allocate apron output pool";
		return ret;
	}

	/* Preallocate a background copy buffer */
	ret = mempool_init_slab_pool(&s->bgd_copy_pool, num_online_cpus(), s->cache);
	if (ret) {
		ti->error = "Cannot allocate apron output pool";
		return ret;
	}

	rci_dummy = mempool_alloc(&s->bgd_copy_pool, GFP_NOIO);
	rci_dummy->apron = s;
	rci_dummy->start = rci_dummy->count = 0;

	if (dm_bufio_get_device_size(s->data_bufio) < v->data_blocks) {
		ti->error = "Data device is too small";
		return -E2BIG;
	}

	/* Reserve space for our per-bio data */
	ti->per_io_data_size += sizeof(struct dm_verity_apron_io);

	s->wq = alloc_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM, 0);
	if (!s->wq) {
		ti->error = "Failed to allocate workqueue";
		return -ENOMEM;
	}

	s->kcopyd_client = dm_kcopyd_client_create(&dm_kcopyd_throttle);
	if (IS_ERR(s->kcopyd_client)) {
		return PTR_ERR(s->kcopyd_client);
	}

	INIT_WORK(&v->apron->update_worker, do_update_worker);
	INIT_WORK(&v->apron->recovery_worker, do_recovery_worker);
	INIT_WORK(&v->apron->duplicate_worker, do_duplicate_worker);
	INIT_DELAYED_WORK(&v->apron->waker, do_waker);
	INIT_DELAYED_WORK(&v->apron->cleaner, do_clean_apron);

	s->fetched_blocks = kvcalloc(BITS_TO_LONGS(v->data_blocks),
				       sizeof(unsigned long),
				       GFP_KERNEL);
	if (!s->fetched_blocks) {
		ti->error = "failed to allocate bitset for fetched blocks";
		return -ENOMEM;
	}

	/* load metadata */
	if (s->meta_dev) {
#if 0
		dm_bufio_prefetch(s->meta_bufio, 0,
				v->data_blocks / METADATA_BLOCK_SIZE / 8 + \
				s->meta_size / METADATA_BLOCK_SIZE + 1);

		for (i = 0; i < v->data_blocks / METADATA_BLOCK_SIZE / 8; i++) {
			bmbuf = dm_bufio_read(s->meta_bufio, i, &mbuf);
			memcpy((u8*)s->changed_blocks + METADATA_BLOCK_SIZE * i, bmbuf,
					METADATA_BLOCK_SIZE);
			dm_bufio_release(mbuf);
		}
#endif
		dm_bufio_prefetch(s->meta_bufio, 0, s->meta_size / METADATA_BLOCK_SIZE + 1);

		s->block_map_tree = RB_ROOT;
		s->block_revmap_tree = RB_ROOT;

		block1 = block2 = 0;
//		for (; block1 != -1; i++) {
		for (i = 0; block1 != -1; i++) {
			bmbuf = dm_bufio_read(s->meta_bufio, i, &mbuf);
			for (j = 0; j < METADATA_BLOCK_SIZE; j += 2*sizeof(int)) {
				memcpy(&block1, bmbuf + j, sizeof(int));
				if (block1 == -1)
					break;
				memcpy(&block2, bmbuf + j + sizeof(int), sizeof(int));

				insert_block_pair(s, (int)block1, (int)block2);
			}
			dm_bufio_release(mbuf);
		}
	}

	s->blocks_to_copy = MIN_COPY_BLOCKS;

#ifdef DM_VERITY_APRON_STAT
	s->stat_verify = 0;
	s->stat_dupcheck = 0;
	s->stat_lookup = 0;
	s->stat_all = 0;
#endif

	return 0;
}
