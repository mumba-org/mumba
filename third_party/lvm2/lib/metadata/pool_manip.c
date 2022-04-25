/*
 * Copyright (C) 2013-2014 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * This file holds common pool functions.
 */

#include "lib.h"
#include "activate.h"
#include "locking.h"
#include "metadata.h"
#include "segtype.h"
#include "lv_alloc.h"
#include "defaults.h"
#include "dev-type.h"
#include "display.h"
#include "toolcontext.h"

int attach_pool_metadata_lv(struct lv_segment *pool_seg,
			    struct logical_volume *metadata_lv)
{
	if (!seg_is_pool(pool_seg)) {
		log_error(INTERNAL_ERROR
			  "Unable to attach pool metadata LV to %s segtype.",
			  lvseg_name(pool_seg));
		return 0;
	}
	pool_seg->metadata_lv = metadata_lv;
	metadata_lv->status |= seg_is_thin_pool(pool_seg) ?
		THIN_POOL_METADATA : CACHE_POOL_METADATA;
	lv_set_hidden(metadata_lv);

	return add_seg_to_segs_using_this_lv(metadata_lv, pool_seg);
}

int detach_pool_metadata_lv(struct lv_segment *pool_seg, struct logical_volume **metadata_lv)
{
	struct logical_volume *lv = pool_seg->metadata_lv;

	if (!lv ||
	    !lv_is_pool_metadata(lv) ||
	    !remove_seg_from_segs_using_this_lv(lv, pool_seg)) {
		log_error(INTERNAL_ERROR "Logical volume %s is not valid pool.",
			  display_lvname(pool_seg->lv));
		return 0;
	}

	lv_set_visible(lv);
	lv->status &= ~(THIN_POOL_METADATA | CACHE_POOL_METADATA);
	*metadata_lv = lv;
	pool_seg->metadata_lv = NULL;

	return 1;
}

int attach_pool_data_lv(struct lv_segment *pool_seg,
			struct logical_volume *pool_data_lv)
{
	if (!seg_is_pool(pool_seg)) {
		log_error(INTERNAL_ERROR
			  "Unable to attach pool data LV to %s segtype.",
			  lvseg_name(pool_seg));
		return 0;
	}

	if (!set_lv_segment_area_lv(pool_seg, 0, pool_data_lv,
				    0, seg_is_thin_pool(pool_seg) ?
				    THIN_POOL_DATA : CACHE_POOL_DATA))
		return_0;

	pool_seg->lv->status |= seg_is_thin_pool(pool_seg) ?
		THIN_POOL : CACHE_POOL;
	lv_set_hidden(pool_data_lv);

	return 1;
}

int attach_pool_lv(struct lv_segment *seg,
		   struct logical_volume *pool_lv,
		   struct logical_volume *origin,
		   struct logical_volume *merge_lv)
{
	if (!seg_is_thin_volume(seg) && !seg_is_cache(seg)) {
		log_error(INTERNAL_ERROR "Unable to attach pool to %s/%s"
			  " that is not cache or thin volume.",
			  pool_lv->vg->name, seg->lv->name);
		return 0;
	}

	seg->pool_lv = pool_lv;
	seg->origin = origin;
	seg->lv->status |= seg_is_cache(seg) ? CACHE : THIN_VOLUME;

	if (seg_is_cache(seg))
		lv_set_hidden(pool_lv); /* Used cache-pool is hidden */

	if (origin && !add_seg_to_segs_using_this_lv(origin, seg))
		return_0;

	if (!add_seg_to_segs_using_this_lv(pool_lv, seg))
		return_0;

	if (merge_lv) {
		if (origin != merge_lv) {
			if (!add_seg_to_segs_using_this_lv(merge_lv, seg))
				return_0;
		}

		init_snapshot_merge(seg, merge_lv);
	}

	return 1;
}

int detach_pool_lv(struct lv_segment *seg)
{
	struct lv_thin_message *tmsg, *tmp;
	struct seg_list *sl, *tsl;
	int no_update = 0;

	if (!seg->pool_lv) {
		log_error(INTERNAL_ERROR
			  "No pool associated with %s LV, %s.",
			  lvseg_name(seg), seg->lv->name);
		return 0;
	}

	if (seg_is_cache(seg)) {
		if (!remove_seg_from_segs_using_this_lv(seg->pool_lv, seg))
			return_0;
		seg->lv->status &= ~CACHE;
		lv_set_visible(seg->pool_lv);
		seg->pool_lv = NULL;
		return 1;
	}

	if (!lv_is_thin_pool(seg->pool_lv)) {
		log_error(INTERNAL_ERROR
			  "Cannot detach pool from LV %s.",
			  seg->lv->name);
		return 0;
	}

	/* Drop any message referencing removed segment */
	dm_list_iterate_items_safe(tmsg, tmp, &(first_seg(seg->pool_lv)->thin_messages)) {
		switch (tmsg->type) {
		case DM_THIN_MESSAGE_CREATE_SNAP:
		case DM_THIN_MESSAGE_CREATE_THIN:
			if (tmsg->u.lv == seg->lv) {
				log_debug_metadata("Discarding message for LV %s.",
						   tmsg->u.lv->name);
				dm_list_del(&tmsg->list);
				no_update = 1; /* Replacing existing */
			}
			break;
		case DM_THIN_MESSAGE_DELETE:
			if (tmsg->u.delete_id == seg->device_id) {
				log_error(INTERNAL_ERROR "Trying to delete %u again.",
					  tmsg->u.delete_id);
				return 0;
			}
			break;
		default:
			log_error(INTERNAL_ERROR "Unsupported message type %u.", tmsg->type);
			break;
		}
	}

	if (!detach_thin_external_origin(seg))
		return_0;

	if (!attach_pool_message(first_seg(seg->pool_lv),
				 DM_THIN_MESSAGE_DELETE,
				 NULL, seg->device_id, no_update))
		return_0;

	if (!remove_seg_from_segs_using_this_lv(seg->pool_lv, seg))
		return_0;

	if (seg->origin &&
	    !remove_seg_from_segs_using_this_lv(seg->origin, seg))
		return_0;

	/* If thin origin, remove it from related thin snapshots */
	/*
	 * TODO: map removal of origin as snapshot lvconvert --merge?
	 * i.e. rename thin snapshot to origin thin origin
	 */
	dm_list_iterate_items_safe(sl, tsl, &seg->lv->segs_using_this_lv) {
		if (!seg_is_thin_volume(sl->seg) ||
		    (seg->lv != sl->seg->origin))
			continue;

		if (!remove_seg_from_segs_using_this_lv(seg->lv, sl->seg))
			return_0;
		/* Thin snapshot is now regular thin volume */
		sl->seg->origin = NULL;
	}

	seg->lv->status &= ~THIN_VOLUME;
	seg->pool_lv = NULL;
	seg->origin = NULL;

	return 1;
}

struct lv_segment *find_pool_seg(const struct lv_segment *seg)
{
	struct lv_segment *pool_seg = NULL;
	struct seg_list *sl;

	dm_list_iterate_items(sl, &seg->lv->segs_using_this_lv) {
		/* Needs to be he only item in list */
		if (lv_is_pending_delete(sl->seg->lv))
			continue;

		if (pool_seg) {
			log_error("%s is referenced by more then one segments (%s, %s).",
				  display_lvname(seg->lv), display_lvname(pool_seg->lv),
				  display_lvname(sl->seg->lv));
			return NULL; /* More then one segment */
		}

		pool_seg = sl->seg;
	}

	if (!pool_seg) {
		log_error("Pool segment not found for %s.", display_lvname(seg->lv));
		return NULL;
	}

	if ((lv_is_thin_type(seg->lv) && !seg_is_pool(pool_seg))) {
		log_error("%s on %s is not a %s pool segment",
			  pool_seg->lv->name, seg->lv->name,
			  lv_is_thin_type(seg->lv) ? "thin" : "cache");
		return NULL;
	}

	return pool_seg;
}

int validate_pool_chunk_size(struct cmd_context *cmd,
			     const struct segment_type *segtype,
			     uint32_t chunk_size)
{
	uint32_t min_size, max_size;
	const char *name;
	int r = 1;

	if (segtype_is_cache(segtype) || segtype_is_cache_pool(segtype)) {
		min_size = DM_CACHE_MIN_DATA_BLOCK_SIZE;
		max_size = DM_CACHE_MAX_DATA_BLOCK_SIZE;
		name = "Cache";
	} else if (segtype_is_thin(segtype)) {
		min_size = DM_THIN_MIN_DATA_BLOCK_SIZE;
		max_size = DM_THIN_MAX_DATA_BLOCK_SIZE;
		name = "Thin";
	} else {
		log_error(INTERNAL_ERROR "Cannot validate chunk size of "
			  "%s segtype.", segtype->name);
		return 0;
	}

	if ((chunk_size < min_size) || (chunk_size > max_size)) {
		log_error("%s pool chunk size %s is not in the range %s to %s.",
			  name, display_size(cmd, chunk_size),
			  display_size(cmd, min_size),
			  display_size(cmd, max_size));
		r = 0;
	}

	if (chunk_size & (min_size - 1)) {
		log_error("%s pool chunk size %s must be a multiple of %s.",
			  name, display_size(cmd, chunk_size),
			  display_size(cmd, min_size));
		r = 0;
	}

	return r;
}

/* Greatest common divisor */
static unsigned long _gcd(unsigned long n1, unsigned long n2)
{
	unsigned long remainder;

	do {
		remainder = n1 % n2;
		n1 = n2;
		n2 = remainder;
	} while (n2);

	return n1;
}

/* Least common multiple */
static unsigned long _lcm(unsigned long n1, unsigned long n2)
{
	if (!n1 || !n2)
		return 0;
	return (n1 * n2) / _gcd(n1, n2);
}

int recalculate_pool_chunk_size_with_dev_hints(struct logical_volume *pool_lv,
					       int passed_args,
					       int chunk_size_calc_policy)
{
	struct logical_volume *pool_data_lv;
	struct lv_segment *seg;
	struct physical_volume *pv;
	struct cmd_context *cmd = pool_lv->vg->cmd;
	unsigned long previous_hint = 0, hint = 0;
	uint32_t default_chunk_size;
	uint32_t min_chunk_size, max_chunk_size;

	if (passed_args & PASS_ARG_CHUNK_SIZE)
		return 1;

	if (lv_is_thin_pool(pool_lv)) {
		if (find_config_tree_int(cmd, allocation_thin_pool_chunk_size_CFG, NULL))
			return 1;
		min_chunk_size = DM_THIN_MIN_DATA_BLOCK_SIZE;
		max_chunk_size = DM_THIN_MAX_DATA_BLOCK_SIZE;
		default_chunk_size = get_default_allocation_thin_pool_chunk_size_CFG(cmd, NULL);
	} else if (lv_is_cache_pool(pool_lv)) {
		if (find_config_tree_int(cmd, allocation_cache_pool_chunk_size_CFG, NULL))
			return 1;
		min_chunk_size = DM_CACHE_MIN_DATA_BLOCK_SIZE;
		max_chunk_size = DM_CACHE_MAX_DATA_BLOCK_SIZE;
		default_chunk_size = get_default_allocation_cache_pool_chunk_size_CFG(cmd, NULL);
	} else {
		log_error(INTERNAL_ERROR "%s is not a pool logical volume.", display_lvname(pool_lv));
		return 0;
	}

	pool_data_lv = seg_lv(first_seg(pool_lv), 0);
	dm_list_iterate_items(seg, &pool_data_lv->segments) {
		switch (seg_type(seg, 0)) {
		case AREA_PV:
			pv = seg_pv(seg, 0);
			if (chunk_size_calc_policy == THIN_CHUNK_SIZE_CALC_METHOD_PERFORMANCE)
				hint = dev_optimal_io_size(cmd->dev_types, pv_dev(pv));
			else
				hint = dev_minimum_io_size(cmd->dev_types, pv_dev(pv));
			if (!hint)
				continue;

			if (previous_hint)
				hint = _lcm(previous_hint, hint);
			previous_hint = hint;
			break;
		case AREA_LV:
			/* FIXME: hint for stacked (raid) LVs - estimate geometry from LV ?? */
		default:
			break;
		}
	}

	if (!hint)
		log_debug_alloc("No usable device hint found while recalculating "
				"pool chunk size for %s.", display_lvname(pool_lv));
	else if ((hint < min_chunk_size) || (hint > max_chunk_size))
		log_debug_alloc("Calculated chunk size %s for pool %s "
				"is out of allowed range (%s-%s).",
				display_size(cmd, hint), display_lvname(pool_lv),
				display_size(cmd, min_chunk_size),
				display_size(cmd, max_chunk_size));
	else
		first_seg(pool_lv)->chunk_size =
			(hint >= default_chunk_size) ? hint : default_chunk_size;

	return 1;
}

int update_pool_params(const struct segment_type *segtype,
		       struct volume_group *vg, unsigned target_attr,
		       int passed_args, uint32_t pool_data_extents,
		       uint32_t *pool_metadata_extents,
		       int *chunk_size_calc_policy, uint32_t *chunk_size,
		       thin_discards_t *discards, int *zero)
{
	if (segtype_is_cache_pool(segtype) || segtype_is_cache(segtype)) {
		if (!update_cache_pool_params(segtype, vg, target_attr, passed_args,
					      pool_data_extents, pool_metadata_extents,
					      chunk_size_calc_policy, chunk_size))
			return_0;
	} else if (!update_thin_pool_params(segtype, vg, target_attr, passed_args,
					    pool_data_extents, pool_metadata_extents,
					    chunk_size_calc_policy, chunk_size,
					    discards, zero)) /* thin-pool */
			return_0;

	if ((uint64_t) *chunk_size > (uint64_t) pool_data_extents * vg->extent_size) {
		log_error("Size of %s data volume cannot be smaller than chunk size %s.",
			  segtype->name, display_size(vg->cmd, *chunk_size));
		return 0;
	}

	log_verbose("Using pool metadata size %s.",
		    display_size(vg->cmd, (uint64_t)*pool_metadata_extents * vg->extent_size));

	return 1;
}

int create_pool(struct logical_volume *pool_lv,
		const struct segment_type *segtype,
		struct alloc_handle *ah, uint32_t stripes, uint32_t stripe_size)
{
	const struct segment_type *striped;
	struct logical_volume *meta_lv, *data_lv;
	struct lv_segment *seg;
	char name[NAME_LEN];
	int r;

	if (pool_lv->le_count) {
		log_error(INTERNAL_ERROR "Pool %s already has extents.",
			  pool_lv->name);
		return 0;
	}

	if (dm_snprintf(name, sizeof(name), "%s_%s", pool_lv->name,
			(segtype_is_cache_pool(segtype)) ?
			"cmeta" : "tmeta") < 0) {
		log_error("Name of logical volume %s is too long to be a pool name.",
			  display_lvname(pool_lv));
		return 0;
	}

	/* LV is not yet a pool, so it's extension from lvcreate */
	if (!(striped = get_segtype_from_string(pool_lv->vg->cmd, "striped")))
		return_0;

	if (activation() && striped->ops->target_present &&
	    !striped->ops->target_present(pool_lv->vg->cmd, NULL, NULL)) {
		log_error("%s: Required device-mapper target(s) not "
			  "detected in your kernel.", striped->name);
		return 0;
	}

	/* Metadata segment */
	if (!lv_add_segment(ah, stripes, 1, pool_lv, striped, 1, 0, 0))
		return_0;

	if (!activation())
		log_warn("WARNING: Pool %s is created without initialization.",
			 pool_lv->name);
	else if (!test_mode()) {
		if (!vg_write(pool_lv->vg) || !vg_commit(pool_lv->vg))
			return_0;

		/*
		 * If killed here, only the VISIBLE striped pool LV is left
		 * and user could easily remove it.
		 *
		 * FIXME: implement lazy clearing when activation is disabled
		 */
		/*
		 * pool_lv is a new LV so the VG lock protects us
		 * Pass in LV_TEMPORARY flag, since device is activated purely for wipe
		 * and later it is either deactivated (in cluster)
		 * or directly converted to invisible device via suspend/resume
		 */
		pool_lv->status |= LV_TEMPORARY;
		if (!activate_lv_local(pool_lv->vg->cmd, pool_lv)) {
			log_error("Aborting. Failed to activate pool metadata %s.",
				  display_lvname(pool_lv));
			goto bad;
		}
		/* Clear 4KB of pool metadata device. */
		if (!(r = wipe_lv(pool_lv, (struct wipe_params) { .do_zero = 1 }))) {
			log_error("Aborting. Failed to wipe pool metadata %s.",
				  display_lvname(pool_lv));
		}
		pool_lv->status &= ~LV_TEMPORARY;
		/* Deactivates cleared metadata LV */
		if (!deactivate_lv_local(pool_lv->vg->cmd, pool_lv)) {
			log_error("Aborting. Could not deactivate pool metadata %s.",
				  display_lvname(pool_lv));
			return 0;
		}
		if (!r)
			goto bad;
	}

	if (!(meta_lv = lv_create_empty(name, NULL, LVM_READ | LVM_WRITE,
					ALLOC_INHERIT, pool_lv->vg)))
		goto_bad;

	if (!move_lv_segments(meta_lv, pool_lv, 0, 0))
		goto_bad;

	/* Pool data segment */
	if (!lv_add_segment(ah, 0, stripes, pool_lv, striped, stripe_size, 0, 0))
		goto_bad;

	if (!(data_lv = insert_layer_for_lv(pool_lv->vg->cmd, pool_lv,
					    pool_lv->status,
					    (segtype_is_cache_pool(segtype)) ?
					    "_cdata" : "_tdata")))
		goto_bad;

	seg = first_seg(pool_lv);
	/* Drop reference as attach_pool_data_lv() takes it again */
	if (!remove_seg_from_segs_using_this_lv(data_lv, seg))
		goto_bad;

	seg->segtype = segtype; /* Set as thin_pool or cache_pool segment */

	if (!attach_pool_data_lv(seg, data_lv))
		goto_bad;

	if (!attach_pool_metadata_lv(seg, meta_lv))
		goto_bad;

	return 1;

bad:
	if (activation()) {
		/* Without activation there was no intermediate commit */
		if (!lv_remove(pool_lv) ||
		    !vg_write(pool_lv->vg) || !vg_commit(pool_lv->vg))
			log_error("Manual intervention may be required to "
				  "remove abandoned LV(s) before retrying.");
	}

	return 0;
}

struct logical_volume *alloc_pool_metadata(struct logical_volume *pool_lv,
					   const char *name, uint32_t read_ahead,
					   uint32_t stripes, uint32_t stripe_size,
					   uint32_t extents, alloc_policy_t alloc,
					   struct dm_list *pvh)
{
	struct logical_volume *metadata_lv;
	/* FIXME: Make lvm2api usable */
	struct lvcreate_params lvc = {
		.activate = CHANGE_ALY,
		.alloc = alloc,
		.extents = extents,
		.major = -1,
		.minor = -1,
		.permission = LVM_READ | LVM_WRITE,
		.pvh = pvh,
		.read_ahead = read_ahead,
		.stripe_size = stripe_size,
		.stripes = stripes,
		.tags = DM_LIST_HEAD_INIT(lvc.tags),
		.temporary = 1,
		.zero = 1,
	};

	if (!(lvc.segtype = get_segtype_from_string(pool_lv->vg->cmd, "striped")))
		return_0;

	/* FIXME: allocate properly space for metadata_lv */

	if (!(metadata_lv = lv_create_single(pool_lv->vg, &lvc)))
		return_0;

	if (!lv_rename_update(pool_lv->vg->cmd, metadata_lv, name, 0))
		return_0;

	return metadata_lv;
}

static struct logical_volume *_alloc_pool_metadata_spare(struct volume_group *vg,
							 uint32_t extents,
							 struct dm_list *pvh)
{
	struct logical_volume *lv;

	/* FIXME: Make lvm2api usable */
	struct lvcreate_params lp = {
		.activate = CHANGE_ALY,
		.alloc = ALLOC_INHERIT,
		.extents = extents,
		.major = -1,
		.minor = -1,
		.permission = LVM_READ | LVM_WRITE,
		.pvh = pvh ? : &vg->pvs,
		.read_ahead = DM_READ_AHEAD_AUTO,
		.stripes = 1,
		.tags = DM_LIST_HEAD_INIT(lp.tags),
		.temporary = 1,
		.zero = 1,
	};

	if (!(lp.segtype = get_segtype_from_string(vg->cmd, "striped")))
		return_0;

	/* FIXME: Maybe using silent mode ? */
	log_verbose("Preparing pool metadata spare volume for Volume group %s.", vg->name);
	if (!(lv = lv_create_single(vg, &lp)))
		return_0;

	/* Spare LV should not be active */
	if (!deactivate_lv_local(vg->cmd, lv)) {
		log_error("Unable to deactivate pool metadata spare LV. "
			  "Manual intervention required.");
		return 0;
	}

	if (!vg_set_pool_metadata_spare(lv))
		return_0;

	return lv;
}

/*
 * Create/resize pool metadata spare LV
 * Caller does vg_write(), vg_commit() with pool creation
 * extents is 0, max size is determined
 */
int handle_pool_metadata_spare(struct volume_group *vg, uint32_t extents,
			       struct dm_list *pvh, int poolmetadataspare)
{
	struct logical_volume *lv = vg->pool_metadata_spare_lv;
	uint32_t seg_mirrors;
	struct lv_segment *seg;
	const struct lv_list *lvl;

	if (!extents)
		/* Find maximal size of metadata LV */
		dm_list_iterate_items(lvl, &vg->lvs)
			if (lv_is_pool_metadata(lvl->lv) &&
			    (lvl->lv->le_count > extents))
				extents = lvl->lv->le_count;

	if (!poolmetadataspare) {
		/* TODO: Not showing when lvm.conf would define 'n' ? */
		if (DEFAULT_POOL_METADATA_SPARE && extents)
			/* Warn if there would be any user */
			log_warn("WARNING: recovery of pools without pool "
				 "metadata spare LV is not automated.");
		return 1;
	}

	if (!lv) {
		if (!_alloc_pool_metadata_spare(vg, extents, pvh))
			return_0;

		return 1;
	}

	seg = last_seg(lv);
	seg_mirrors = lv_mirror_count(lv);

	/* Check spare LV is big enough and preserve segtype */
	if ((lv->le_count < extents) && seg &&
	    !lv_extend(lv, seg->segtype,
		       seg->area_count / seg_mirrors,
		       seg->stripe_size,
		       seg_mirrors,
		       seg->region_size,
		       extents - lv->le_count,
		       pvh, lv->alloc, 0))
		return_0;

	return 1;
}

int vg_set_pool_metadata_spare(struct logical_volume *lv)
{
	char new_name[NAME_LEN];
	struct volume_group *vg = lv->vg;

	if (vg->pool_metadata_spare_lv) {
		if (vg->pool_metadata_spare_lv == lv)
			return 1;
		if (!vg_remove_pool_metadata_spare(vg))
			return_0;
	}

	if (dm_snprintf(new_name, sizeof(new_name), "%s_pmspare", lv->name) < 0) {
		log_error("Can't create pool metadata spare. Name of pool LV "
			  "%s is too long.", lv->name);
		return 0;
	}

	log_verbose("Renaming %s as pool metadata spare volume %s.", lv->name, new_name);
	if (!lv_rename_update(vg->cmd, lv, new_name, 0))
		return_0;

	lv_set_hidden(lv);
	lv->status |= POOL_METADATA_SPARE;
	vg->pool_metadata_spare_lv = lv;

	return 1;
}

int vg_remove_pool_metadata_spare(struct volume_group *vg)
{
	char new_name[NAME_LEN];
	char *c;

	struct logical_volume *lv = vg->pool_metadata_spare_lv;

	if (!(lv->status & POOL_METADATA_SPARE)) {
		log_error(INTERNAL_ERROR "LV %s is not pool metadata spare.",
			  lv->name);
		return 0;
	}

	vg->pool_metadata_spare_lv = NULL;
	lv->status &= ~POOL_METADATA_SPARE;
	lv_set_visible(lv);

	/* Cut off suffix _pmspare */
	(void) dm_strncpy(new_name, lv->name, sizeof(new_name));
	if (!(c = strchr(new_name, '_'))) {
		log_error(INTERNAL_ERROR "LV %s has no suffix for pool metadata spare.",
			  new_name);
		return 0;
	}
	*c = 0;

	/* If the name is in use, generate new lvol%d */
	if (find_lv_in_vg(vg, new_name) &&
	    !generate_lv_name(vg, "lvol%d", new_name, sizeof(new_name))) {
		log_error("Failed to generate unique name for "
			  "pool metadata spare logical volume.");
		return 0;
	}

	log_print_unless_silent("Renaming existing pool metadata spare "
				"logical volume \"%s/%s\" to \"%s/%s\".",
                                vg->name, lv->name, vg->name, new_name);

	if (!lv_rename_update(vg->cmd, lv, new_name, 0))
		return_0;

	/* To display default warning */
	(void) handle_pool_metadata_spare(vg, 0, 0, 0);

	return 1;
}
