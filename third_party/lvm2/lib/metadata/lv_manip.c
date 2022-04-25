/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2014 Red Hat, Inc. All rights reserved.
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

#include "lib.h"
#include "metadata.h"
#include "locking.h"
#include "pv_map.h"
#include "lvm-string.h"
#include "toolcontext.h"
#include "lv_alloc.h"
#include "pv_alloc.h"
#include "display.h"
#include "segtype.h"
#include "archiver.h"
#include "activate.h"
#include "str_list.h"
#include "defaults.h"
#include "lvm-exec.h"
#include "lvm-signal.h"
#include "memlock.h"
#include "lvmlockd.h"

typedef enum {
	PREFERRED,
	USE_AREA,
	NEXT_PV,
	NEXT_AREA
} area_use_t;

/* FIXME: remove RAID_METADATA_AREA_LEN macro after defining 'raid_log_extents'*/
#define RAID_METADATA_AREA_LEN 1

/* FIXME These ended up getting used differently from first intended.  Refactor. */
/* Only one of A_CONTIGUOUS_TO_LVSEG, A_CLING_TO_LVSEG, A_CLING_TO_ALLOCED may be set */
#define A_CONTIGUOUS_TO_LVSEG	0x01	/* Must be contiguous to an existing segment */
#define A_CLING_TO_LVSEG	0x02	/* Must use same disks as existing LV segment */
#define A_CLING_TO_ALLOCED	0x04	/* Must use same disks as already-allocated segment */

#define A_CLING_BY_TAGS		0x08	/* Must match tags against existing segment */
#define A_CAN_SPLIT		0x10
#define A_AREA_COUNT_MATCHES	0x20	/* Existing lvseg has same number of areas as new segment */

#define A_POSITIONAL_FILL	0x40	/* Slots are positional and filled using PREFERRED */
#define A_PARTITION_BY_TAGS	0x80	/* No allocated area may share any tag with any other */

/*
 * Constant parameters during a single allocation attempt.
 */
struct alloc_parms {
	alloc_policy_t alloc;
	unsigned flags;		/* Holds A_* */
	struct lv_segment *prev_lvseg;
	uint32_t extents_still_needed;
};

/*
 * Holds varying state of each allocation attempt.
 */
struct alloc_state {
	const struct alloc_parms *alloc_parms;
	struct pv_area_used *areas;
	uint32_t areas_size;
	uint32_t log_area_count_still_needed;	/* Number of areas still needing to be allocated for the log */
	uint32_t allocated;	/* Total number of extents allocated so far */
	uint32_t num_positional_areas;	/* Number of parallel allocations that must be contiguous/cling */
};

struct lv_names {
	const char *old;
	const char *new;
};

struct pv_and_int {
	struct physical_volume *pv;
	int *i;
};

enum {
	LV_TYPE_UNKNOWN,
	LV_TYPE_PUBLIC,
	LV_TYPE_PRIVATE,
	LV_TYPE_LINEAR,
	LV_TYPE_STRIPED,
	LV_TYPE_MIRROR,
	LV_TYPE_RAID,
	LV_TYPE_THIN,
	LV_TYPE_CACHE,
	LV_TYPE_SPARSE,
	LV_TYPE_ORIGIN,
	LV_TYPE_THINORIGIN,
	LV_TYPE_MULTITHINORIGIN,
	LV_TYPE_THICKORIGIN,
	LV_TYPE_MULTITHICKORIGIN,
	LV_TYPE_CACHEORIGIN,
	LV_TYPE_EXTTHINORIGIN,
	LV_TYPE_MULTIEXTTHINORIGIN,
	LV_TYPE_SNAPSHOT,
	LV_TYPE_THINSNAPSHOT,
	LV_TYPE_THICKSNAPSHOT,
	LV_TYPE_PVMOVE,
	LV_TYPE_IMAGE,
	LV_TYPE_LOG,
	LV_TYPE_METADATA,
	LV_TYPE_POOL,
	LV_TYPE_DATA,
	LV_TYPE_SPARE,
	LV_TYPE_VIRTUAL,
	LV_TYPE_RAID1,
	LV_TYPE_RAID10,
	LV_TYPE_RAID4,
	LV_TYPE_RAID5,
	LV_TYPE_RAID5_LA,
	LV_TYPE_RAID5_RA,
	LV_TYPE_RAID5_LS,
	LV_TYPE_RAID5_RS,
	LV_TYPE_RAID6,
	LV_TYPE_RAID6_ZR,
	LV_TYPE_RAID6_NR,
	LV_TYPE_RAID6_NC,
};

static const char *_lv_type_names[] = {
	[LV_TYPE_UNKNOWN] =				"unknown",
	[LV_TYPE_PUBLIC] =				"public",
	[LV_TYPE_PRIVATE] =				"private",
	[LV_TYPE_LINEAR] =				"linear",
	[LV_TYPE_STRIPED] =				"striped",
	[LV_TYPE_MIRROR] =				"mirror",
	[LV_TYPE_RAID] =				"raid",
	[LV_TYPE_THIN] =				"thin",
	[LV_TYPE_CACHE] =				"cache",
	[LV_TYPE_SPARSE] =				"sparse",
	[LV_TYPE_ORIGIN] =				"origin",
	[LV_TYPE_THINORIGIN] =				"thinorigin",
	[LV_TYPE_MULTITHINORIGIN] =			"multithinorigin",
	[LV_TYPE_THICKORIGIN] =				"thickorigin",
	[LV_TYPE_MULTITHICKORIGIN] =			"multithickorigin",
	[LV_TYPE_CACHEORIGIN] =				"cacheorigin",
	[LV_TYPE_EXTTHINORIGIN] =			"extthinorigin",
	[LV_TYPE_MULTIEXTTHINORIGIN] =			"multiextthinorigin",
	[LV_TYPE_SNAPSHOT] =				"snapshot",
	[LV_TYPE_THINSNAPSHOT] =			"thinsnapshot",
	[LV_TYPE_THICKSNAPSHOT] =			"thicksnapshot",
	[LV_TYPE_PVMOVE] =				"pvmove",
	[LV_TYPE_IMAGE] =				"image",
	[LV_TYPE_LOG] =					"log",
	[LV_TYPE_METADATA] =				"metadata",
	[LV_TYPE_POOL] =				"pool",
	[LV_TYPE_DATA] =				"data",
	[LV_TYPE_SPARE] =				"spare",
	[LV_TYPE_VIRTUAL] =				"virtual",
	[LV_TYPE_RAID1] =				SEG_TYPE_NAME_RAID1,
	[LV_TYPE_RAID10] =				SEG_TYPE_NAME_RAID10,
	[LV_TYPE_RAID4] =				SEG_TYPE_NAME_RAID4,
	[LV_TYPE_RAID5] =				SEG_TYPE_NAME_RAID5,
	[LV_TYPE_RAID5_LA] =				SEG_TYPE_NAME_RAID5_LA,
	[LV_TYPE_RAID5_RA] =				SEG_TYPE_NAME_RAID5_RA,
	[LV_TYPE_RAID5_LS] =				SEG_TYPE_NAME_RAID5_LS,
	[LV_TYPE_RAID5_RS] =				SEG_TYPE_NAME_RAID5_RS,
	[LV_TYPE_RAID6] =				SEG_TYPE_NAME_RAID6,
	[LV_TYPE_RAID6_ZR] =				SEG_TYPE_NAME_RAID6_ZR,
	[LV_TYPE_RAID6_NR] =				SEG_TYPE_NAME_RAID6_NR,
	[LV_TYPE_RAID6_NC] =				SEG_TYPE_NAME_RAID6_NC,
};

static int _lv_layout_and_role_mirror(struct dm_pool *mem,
				      const struct logical_volume *lv,
				      struct dm_list *layout,
				      struct dm_list *role,
				      int *public_lv)
{
	int top_level = 0;

	/* non-top-level LVs */
	if (lv_is_mirror_image(lv)) {
		if (!str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_MIRROR]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_IMAGE]))
			goto_bad;
	} else if (lv_is_mirror_log(lv)) {
		if (!str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_MIRROR]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_LOG]))
			goto_bad;
		if (lv_is_mirrored(lv) &&
		    !str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_MIRROR]))
			goto_bad;
	} else if (lv_is_pvmove(lv)) {
		if (!str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_PVMOVE]) ||
		    !str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_MIRROR]))
			goto_bad;
	} else
		top_level = 1;


	if (!top_level) {
		*public_lv = 0;
		return 1;
	}

	/* top-level LVs */
	if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_MIRROR]))
		goto_bad;

	return 1;
bad:
	return 0;
}

static int _lv_layout_and_role_raid(struct dm_pool *mem,
				    const struct logical_volume *lv,
				    struct dm_list *layout,
				    struct dm_list *role,
				    int *public_lv)
{
	int top_level = 0;
	const char *seg_name;

	/* non-top-level LVs */
	if (lv_is_raid_image(lv)) {
		if (!str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_RAID]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_IMAGE]))
			goto_bad;
	} else if (lv_is_raid_metadata(lv)) {
		if (!str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_RAID]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_METADATA]))
			goto_bad;
	} else if (lv_is_pvmove(lv)) {
		if (!str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_PVMOVE]) ||
		    !str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID]))
			goto_bad;
	} else
		top_level = 1;

	if (!top_level) {
		*public_lv = 0;
		return 1;
	}

	/* top-level LVs */
	if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID]))
		goto_bad;

	seg_name = first_seg(lv)->segtype->name;

	if (!strcmp(seg_name, SEG_TYPE_NAME_RAID1)) {
		if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID1]))
			goto_bad;
	} else if (!strcmp(seg_name, SEG_TYPE_NAME_RAID10)) {
		if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID10]))
			goto_bad;
	} else if (!strcmp(seg_name, SEG_TYPE_NAME_RAID4)) {
		if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID4]))
			goto_bad;
	} else if (!strncmp(seg_name, SEG_TYPE_NAME_RAID5, strlen(SEG_TYPE_NAME_RAID5))) {
		if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID5]))
			goto_bad;

		if (!strcmp(seg_name, SEG_TYPE_NAME_RAID5_LA)) {
			if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID5_LA]))
				goto_bad;
		} else if (!strcmp(seg_name, SEG_TYPE_NAME_RAID5_RA)) {
			if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID5_RA]))
				goto_bad;
		} else if (!strcmp(seg_name, SEG_TYPE_NAME_RAID5_LS)) {
			if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID5_LS]))
				goto_bad;
		} else if (!strcmp(seg_name, SEG_TYPE_NAME_RAID5_RS)) {
			if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID5_RS]))
				goto_bad;
		}
	} else if (!strncmp(seg_name, SEG_TYPE_NAME_RAID6, strlen(SEG_TYPE_NAME_RAID6))) {
		if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID6]))
			goto_bad;

		if (!strcmp(seg_name, SEG_TYPE_NAME_RAID6_ZR)) {
			if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID6_ZR]))
				goto_bad;
		} else if (!strcmp(seg_name, SEG_TYPE_NAME_RAID6_NR)) {
			if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID6_NR]))
				goto_bad;
		} else if (!strcmp(seg_name, SEG_TYPE_NAME_RAID6_NC)) {
			if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_RAID6_NC]))
				goto_bad;
		}
	}

	return 1;
bad:
	return 0;
}

static int _lv_layout_and_role_thin(struct dm_pool *mem,
				    const struct logical_volume *lv,
				    struct dm_list *layout,
				    struct dm_list *role,
				    int *public_lv)
{
	int top_level = 0;
	unsigned snap_count;
	struct lv_segment *seg;

	/* non-top-level LVs */
	if (lv_is_thin_pool_metadata(lv)) {
		if (!str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_THIN]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_POOL]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_METADATA]))
			goto_bad;
	} else if (lv_is_thin_pool_data(lv)) {
		if (!str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_THIN]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_POOL]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_DATA]))
			goto_bad;
	} else
		top_level = 1;

	if (!top_level) {
		*public_lv = 0;
		return 1;
	}

	/* top-level LVs */
	if (lv_is_thin_volume(lv)) {
		if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_THIN]) ||
		    !str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_SPARSE]))
			goto_bad;
		if (lv_is_thin_origin(lv, &snap_count)) {
			if (!str_list_add(mem, role, _lv_type_names[LV_TYPE_ORIGIN]) ||
			    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_THINORIGIN]))
				goto_bad;
			if (snap_count > 1 &&
			    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_MULTITHINORIGIN]))
				goto_bad;
		}
		if ((seg = first_seg(lv)) && (seg->origin || seg->external_lv))
			if (!str_list_add(mem, role, _lv_type_names[LV_TYPE_SNAPSHOT]) ||
			    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_THINSNAPSHOT]))
				goto_bad;
	} else if (lv_is_thin_pool(lv)) {
		if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_THIN]) ||
		    !str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_POOL]))
			goto_bad;
		*public_lv = 0;
	}

	if (lv_is_external_origin(lv)) {
		if (!str_list_add(mem, role, _lv_type_names[LV_TYPE_ORIGIN]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_EXTTHINORIGIN]))
			goto_bad;
		if (lv->external_count > 1 &&
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_MULTIEXTTHINORIGIN]))
			goto_bad;
	}

	return 1;
bad:
	return 0;
}

static int _lv_layout_and_role_cache(struct dm_pool *mem,
				     const struct logical_volume *lv,
				     struct dm_list *layout,
				     struct dm_list *role,
				     int *public_lv)
{
	int top_level = 0;

	/* non-top-level LVs */
	if (lv_is_cache_pool_metadata(lv)) {
		if (!str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_CACHE]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_POOL]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_METADATA]))
			goto_bad;
	} else if (lv_is_cache_pool_data(lv)) {
		if (!str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_CACHE]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_POOL]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_DATA]))
			goto_bad;
		if (lv_is_cache(lv) &&
		    !str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_CACHE]))
			goto_bad;
	} else if (lv_is_cache_origin(lv)) {
		if (!str_list_add(mem, role, _lv_type_names[LV_TYPE_CACHE]) ||
		    !str_list_add(mem, role, _lv_type_names[LV_TYPE_ORIGIN]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_CACHEORIGIN]))
			goto_bad;
		if (lv_is_cache(lv) &&
		    !str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_CACHE]))
			goto_bad;
	} else
		top_level = 1;

	if (!top_level) {
		*public_lv = 0;
		return 1;
	}

	/* top-level LVs */
	if (lv_is_cache(lv) &&
	    !str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_CACHE]))
		goto_bad;
	else if (lv_is_cache_pool(lv)) {
		if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_CACHE]) ||
		    !str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_POOL]))
			goto_bad;
		*public_lv = 0;
	}

	return 1;
bad:
	return 0;
}

static int _lv_layout_and_role_thick_origin_snapshot(struct dm_pool *mem,
						     const struct logical_volume *lv,
						     struct dm_list *layout,
						     struct dm_list *role,
						     int *public_lv)
{
	if (lv_is_origin(lv)) {
		if (!str_list_add(mem, role, _lv_type_names[LV_TYPE_ORIGIN]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_THICKORIGIN]))
			goto_bad;
		/*
		 * Thin volumes are also marked with virtual flag, but we don't show "virtual"
		 * layout for thin LVs as they have their own keyword for layout - "thin"!
		 * So rule thin LVs out here!
		 */
		if (lv_is_virtual(lv) && !lv_is_thin_volume(lv)) {
			if (!str_list_add_no_dup_check(mem, layout, _lv_type_names[LV_TYPE_VIRTUAL]))
				goto_bad;
			*public_lv = 0;
		}
		if (lv->origin_count > 1 &&
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_MULTITHICKORIGIN]))
			goto_bad;
	} else if (lv_is_cow(lv)) {
		if (!str_list_add(mem, role, _lv_type_names[LV_TYPE_SNAPSHOT]) ||
		    !str_list_add_no_dup_check(mem, role, _lv_type_names[LV_TYPE_THICKSNAPSHOT]))
			goto_bad;
	}

	return 1;
bad:
	return 0;
}

int lv_layout_and_role(struct dm_pool *mem, const struct logical_volume *lv,
		       struct dm_list **layout, struct dm_list **role) {
	int linear, striped;
	struct lv_segment *seg;
	int public_lv = 1;

	*layout = *role = NULL;

	if (!(*layout = str_list_create(mem))) {
		log_error("LV layout list allocation failed");
		return 0;
	}

	if (!(*role = str_list_create(mem))) {
		log_error("LV role list allocation failed");
		goto bad;
	}

	/* Mirrors and related */
	if ((lv_is_mirror_type(lv) || lv_is_pvmove(lv)) &&
	    !_lv_layout_and_role_mirror(mem, lv, *layout, *role, &public_lv))
		goto_bad;

	/* RAIDs and related */
	if (lv_is_raid_type(lv) &&
	    !_lv_layout_and_role_raid(mem, lv, *layout, *role, &public_lv))
		goto_bad;

	/* Thins and related */
	if ((lv_is_thin_type(lv) || lv_is_external_origin(lv)) &&
	    !_lv_layout_and_role_thin(mem, lv, *layout, *role, &public_lv))
		goto_bad;

	/* Caches and related */
	if ((lv_is_cache_type(lv) || lv_is_cache_origin(lv)) &&
	    !_lv_layout_and_role_cache(mem, lv, *layout, *role, &public_lv))
		goto_bad;

	/* Pool-specific */
	if (lv_is_pool_metadata_spare(lv)) {
		if (!str_list_add_no_dup_check(mem, *role, _lv_type_names[LV_TYPE_POOL]) ||
		    !str_list_add_no_dup_check(mem, *role, _lv_type_names[LV_TYPE_SPARE]))
			goto_bad;
		public_lv = 0;
	}

	/* Old-style origins/snapshots, virtual origins */
	if (!_lv_layout_and_role_thick_origin_snapshot(mem, lv, *layout, *role, &public_lv))
		goto_bad;

	/*
	 * If layout not yet determined, it must be either
	 * linear or striped or mixture of these two.
	 */
	if (dm_list_empty(*layout)) {
		linear = striped = 0;
		dm_list_iterate_items(seg, &lv->segments) {
			if (seg_is_linear(seg))
				linear = 1;
			else if (seg_is_striped(seg))
				striped = 1;
			else {
				/*
				 * This should not happen but if it does
				 * we'll see that there's "unknown" layout
				 * present. This means we forgot to detect
				 * the role above and we need add proper
				 * detection for such role!
				 */
				log_warn(INTERNAL_ERROR "WARNING: Failed to properly detect "
					 "layout and role for LV %s/%s.",
					 lv->vg->name, lv->name);
			}
		}

		if (linear &&
		    !str_list_add_no_dup_check(mem, *layout, _lv_type_names[LV_TYPE_LINEAR]))
			goto_bad;

		if (striped &&
		    !str_list_add_no_dup_check(mem, *layout, _lv_type_names[LV_TYPE_STRIPED]))
			goto_bad;

		if (!linear && !striped &&
		    !str_list_add_no_dup_check(mem, *layout, _lv_type_names[LV_TYPE_UNKNOWN]))
			goto_bad;
	}

	/* finally, add either 'public' or 'private' role to the LV */
	if (public_lv) {
		if (!str_list_add_h_no_dup_check(mem, *role, _lv_type_names[LV_TYPE_PUBLIC]))
			goto_bad;
	} else {
		if (!str_list_add_h_no_dup_check(mem, *role, _lv_type_names[LV_TYPE_PRIVATE]))
			goto_bad;
	}

	return 1;
bad:
	dm_pool_free(mem, *layout);

	return 0;
}

static int _lv_is_on_pv(struct logical_volume *lv, void *data)
{
	int *is_on_pv = ((struct pv_and_int *)data)->i;
	struct physical_volume *pv = ((struct pv_and_int *)data)->pv;
	uint32_t s;
	struct physical_volume *pv2;
	struct lv_segment *seg;

	if (!lv || !(first_seg(lv)))
		return_0;

	/*
	 * If the LV has already been found to be on the PV, then
	 * we don't need to continue checking - just return.
	 */
	if (*is_on_pv)
		return 1;

	dm_list_iterate_items(seg, &lv->segments) {
		for (s = 0; s < seg->area_count; s++) {
			if (seg_type(seg, s) != AREA_PV)
				continue;

			pv2 = seg_pv(seg, s);
			if (id_equal(&pv->id, &pv2->id)) {
				*is_on_pv = 1;
				return 1;
			}
			if (pv->dev && pv2->dev &&
			    (pv->dev->dev == pv2->dev->dev)) {
				*is_on_pv = 1;
				return 1;
			}
		}
	}

	return 1;
}

/*
 * lv_is_on_pv
 * @lv:
 * @pv:
 *
 * If any of the component devices of the LV are on the given PV, 1
 * is returned; otherwise 0.  For example if one of the images of a RAID
 * (or its metadata device) is on the PV, 1 would be returned for the
 * top-level LV.
 * If you wish to check the images themselves, you should pass them.
 *
 * Returns: 1 if LV (or part of LV) is on PV, 0 otherwise
 */
int lv_is_on_pv(struct logical_volume *lv, struct physical_volume *pv)
{
	int is_on_pv = 0;
	struct pv_and_int context = { pv, &is_on_pv };

	if (!_lv_is_on_pv(lv, &context) ||
	    !for_each_sub_lv(lv, _lv_is_on_pv, &context))
		/* Failure only happens if bad arguments are passed */
		log_error(INTERNAL_ERROR "for_each_sub_lv failure.");

	log_debug_metadata("%s is %son %s", lv->name,
			   is_on_pv ? "" : "not ", pv_dev_name(pv));
	return is_on_pv;
}

/*
 * lv_is_on_pvs
 * @lv
 * @pvs
 *
 * Returns 1 if the LV (or part of the LV) is on any of the pvs
 * in the list, 0 otherwise.
 */
int lv_is_on_pvs(struct logical_volume *lv, struct dm_list *pvs)
{
	struct pv_list *pvl;

	dm_list_iterate_items(pvl, pvs)
		if (lv_is_on_pv(lv, pvl->pv))
			return 1;

	return 0;
}

struct dm_list_and_mempool {
	struct dm_list *list;
	struct dm_pool *mem;
};
static int _get_pv_list_for_lv(struct logical_volume *lv, void *data)
{
	int dup_found;
	uint32_t s;
	struct pv_list *pvl;
	struct lv_segment *seg;
	struct dm_list *pvs = ((struct dm_list_and_mempool *)data)->list;
	struct dm_pool *mem = ((struct dm_list_and_mempool *)data)->mem;

	dm_list_iterate_items(seg, &lv->segments) {
		for (s = 0; s < seg->area_count; s++) {
			dup_found = 0;

			if (seg_type(seg, s) != AREA_PV)
				continue;

			/* do not add duplicates */
			dm_list_iterate_items(pvl, pvs)
				if (pvl->pv == seg_pv(seg, s))
					dup_found = 1;

			if (dup_found)
				continue;

			if (!(pvl = dm_pool_zalloc(mem, sizeof(*pvl)))) {
				log_error("Failed to allocate memory");
				return 0;
			}

			pvl->pv = seg_pv(seg, s);
			log_debug_metadata("  %s/%s uses %s", lv->vg->name,
					   lv->name, pv_dev_name(pvl->pv));

			dm_list_add(pvs, &pvl->list);
		}
	}

	return 1;
}

/*
 * get_pv_list_for_lv
 * @mem - mempool to allocate the list from.
 * @lv
 * @pvs - The list to add pv_list items to.
 *
 * 'pvs' is filled with 'pv_list' items for PVs that compose the LV.
 * If the 'pvs' list already has items in it, duplicates will not be
 * added.  So, it is safe to repeatedly call this function for different
 * LVs and build up a list of PVs for them all.
 *
 * Memory to create the list is obtained from the mempool provided.
 *
 * Returns: 1 on success, 0 on error
 */
int get_pv_list_for_lv(struct dm_pool *mem,
		       struct logical_volume *lv, struct dm_list *pvs)
{
	struct dm_list_and_mempool context = { pvs, mem };

	log_debug_metadata("Generating list of PVs that %s/%s uses:",
			   lv->vg->name, lv->name);

	if (!_get_pv_list_for_lv(lv, &context))
		return_0;

	return for_each_sub_lv(lv, &_get_pv_list_for_lv, &context);
}

/*
 * get_default_region_size
 * @cmd
 *
 * 'mirror_region_size' and 'raid_region_size' are effectively the same thing.
 * However, "raid" is more inclusive than "mirror", so the name has been
 * changed.  This function checks for the old setting and warns the user if
 * it is being overridden by the new setting (i.e. warn if both settings are
 * present).
 *
 * Note that the config files give defaults in kiB terms, but we
 * return the value in terms of sectors.
 *
 * Returns: default region_size in sectors
 */
static int _get_default_region_size(struct cmd_context *cmd)
{
	int mrs, rrs;

	/*
	 * 'mirror_region_size' is the old setting.  It is overridden
	 * by the new setting, 'raid_region_size'.
	 */
	mrs = 2 * find_config_tree_int(cmd, activation_mirror_region_size_CFG, NULL);
	rrs = 2 * find_config_tree_int(cmd, activation_raid_region_size_CFG, NULL);

	if (!mrs && !rrs)
		return DEFAULT_RAID_REGION_SIZE * 2;

	if (!mrs)
		return rrs;

	if (!rrs)
		return mrs;

	if (mrs != rrs)
		log_verbose("Overriding default 'mirror_region_size' setting"
			    " with 'raid_region_size' setting of %u kiB",
			    rrs / 2);

	return rrs;
}

static int _round_down_pow2(int r)
{
	/* Set all bits to the right of the leftmost set bit */
	r |= (r >> 1);
	r |= (r >> 2);
	r |= (r >> 4);
	r |= (r >> 8);
	r |= (r >> 16);

	/* Pull out the leftmost set bit */
	return r & ~(r >> 1);
}

int get_default_region_size(struct cmd_context *cmd)
{
	int region_size = _get_default_region_size(cmd);

	if (region_size & (region_size - 1)) {
		region_size = _round_down_pow2(region_size);
		log_verbose("Reducing mirror region size to %u kiB (power of 2).",
			    region_size / 2);
	}

	return region_size;
}

int add_seg_to_segs_using_this_lv(struct logical_volume *lv,
				  struct lv_segment *seg)
{
	struct seg_list *sl;

	dm_list_iterate_items(sl, &lv->segs_using_this_lv) {
		if (sl->seg == seg) {
			sl->count++;
			return 1;
		}
	}

	log_very_verbose("Adding %s:%" PRIu32 " as an user of %s",
			 seg->lv->name, seg->le, lv->name);

	if (!(sl = dm_pool_zalloc(lv->vg->vgmem, sizeof(*sl)))) {
		log_error("Failed to allocate segment list");
		return 0;
	}

	sl->count = 1;
	sl->seg = seg;
	dm_list_add(&lv->segs_using_this_lv, &sl->list);

	return 1;
}

int remove_seg_from_segs_using_this_lv(struct logical_volume *lv,
				       struct lv_segment *seg)
{
	struct seg_list *sl;

	dm_list_iterate_items(sl, &lv->segs_using_this_lv) {
		if (sl->seg != seg)
			continue;
		if (sl->count > 1)
			sl->count--;
		else {
			log_very_verbose("%s:%" PRIu32 " is no longer a user "
					 "of %s", seg->lv->name, seg->le,
					 lv->name);
			dm_list_del(&sl->list);
		}
		return 1;
	}

	log_error(INTERNAL_ERROR "Segment %s:%u is not a user of %s.",
                  seg->lv->name, seg->le, lv->name);
	return 0;
}

/*
 * This is a function specialized for the common case where there is
 * only one segment which uses the LV.
 * e.g. the LV is a layer inserted by insert_layer_for_lv().
 *
 * In general, walk through lv->segs_using_this_lv.
 */
struct lv_segment *get_only_segment_using_this_lv(const struct logical_volume *lv)
{
	struct seg_list *sl;

	if (!lv) {
		log_error(INTERNAL_ERROR "get_only_segment_using_this_lv() called with NULL LV.");
		return NULL;
	}

	dm_list_iterate_items(sl, &lv->segs_using_this_lv) {
		/* Needs to be he only item in list */
		if (!dm_list_end(&lv->segs_using_this_lv, &sl->list))
			break;

		if (sl->count != 1) {
			log_error("%s is expected to have only one segment using it, "
				  "while %s:%" PRIu32 " uses it %d times.",
				  display_lvname(lv), sl->seg->lv->name, sl->seg->le, sl->count);
			return NULL;
		}

		return sl->seg;
	}

	log_error("%s is expected to have only one segment using it, while it has %d.",
		  display_lvname(lv), dm_list_size(&lv->segs_using_this_lv));

	return NULL;
}

/*
 * PVs used by a segment of an LV
 */
struct seg_pvs {
	struct dm_list list;

	struct dm_list pvs;	/* struct pv_list */

	uint32_t le;
	uint32_t len;
};

static struct seg_pvs *_find_seg_pvs_by_le(struct dm_list *list, uint32_t le)
{
	struct seg_pvs *spvs;

	dm_list_iterate_items(spvs, list)
		if (le >= spvs->le && le < spvs->le + spvs->len)
			return spvs;

	return NULL;
}

/*
 * Find first unused LV number.
 */
uint32_t find_free_lvnum(struct logical_volume *lv)
{
	int lvnum_used[MAX_RESTRICTED_LVS + 1] = { 0 };
	uint32_t i = 0;
	struct lv_list *lvl;
	int lvnum;

	dm_list_iterate_items(lvl, &lv->vg->lvs) {
		lvnum = lvnum_from_lvid(&lvl->lv->lvid);
		if (lvnum <= MAX_RESTRICTED_LVS)
			lvnum_used[lvnum] = 1;
	}

	while (lvnum_used[i])
		i++;

	/* FIXME What if none are free? */

	return i;
}

dm_percent_t copy_percent(const struct logical_volume *lv)
{
	uint32_t numerator = 0u, denominator = 0u;
	struct lv_segment *seg;

	dm_list_iterate_items(seg, &lv->segments) {
		denominator += seg->area_len;

	/* FIXME Generalise name of 'extents_copied' field */
		if ((seg_is_raid(seg) || seg_is_mirrored(seg)) &&
		    (seg->area_count > 1))
			numerator += seg->extents_copied;
		else
			numerator += seg->area_len;
	}

	return denominator ? dm_make_percent( numerator, denominator ) : 100.0;
}

/*
 * All lv_segments get created here.
 */
struct lv_segment *alloc_lv_segment(const struct segment_type *segtype,
				    struct logical_volume *lv,
				    uint32_t le, uint32_t len,
				    uint64_t status,
				    uint32_t stripe_size,
				    struct logical_volume *log_lv,
				    uint32_t area_count,
				    uint32_t area_len,
				    uint32_t chunk_size,
				    uint32_t region_size,
				    uint32_t extents_copied,
				    struct lv_segment *pvmove_source_seg)
{
	struct lv_segment *seg;
	struct dm_pool *mem = lv->vg->vgmem;
	uint32_t areas_sz = area_count * sizeof(*seg->areas);

	if (!segtype) {
		log_error(INTERNAL_ERROR "alloc_lv_segment: Missing segtype.");
		return NULL;
	}

	if (!(seg = dm_pool_zalloc(mem, sizeof(*seg))))
		return_NULL;

	if (!(seg->areas = dm_pool_zalloc(mem, areas_sz))) {
		dm_pool_free(mem, seg);
		return_NULL;
	}

	if (segtype_is_raid(segtype) &&
	    !(seg->meta_areas = dm_pool_zalloc(mem, areas_sz))) {
		dm_pool_free(mem, seg); /* frees everything alloced since seg */
		return_NULL;
	}

	seg->segtype = segtype;
	seg->lv = lv;
	seg->le = le;
	seg->len = len;
	seg->status = status;
	seg->stripe_size = stripe_size;
	seg->area_count = area_count;
	seg->area_len = area_len;
	seg->chunk_size = chunk_size;
	seg->region_size = region_size;
	seg->extents_copied = extents_copied;
	seg->pvmove_source_seg = pvmove_source_seg;
	dm_list_init(&seg->tags);
	dm_list_init(&seg->thin_messages);

	if (log_lv && !attach_mirror_log(seg, log_lv))
		return_NULL;

	if (segtype_is_mirror(segtype))
		lv->status |= MIRROR;

	if (segtype_is_mirrored(segtype))
		lv->status |= MIRRORED;

	return seg;
}

struct lv_segment *alloc_snapshot_seg(struct logical_volume *lv,
				      uint64_t status, uint32_t old_le_count)
{
	struct lv_segment *seg;
	const struct segment_type *segtype;

	segtype = get_segtype_from_string(lv->vg->cmd, "snapshot");
	if (!segtype) {
		log_error("Failed to find snapshot segtype");
		return NULL;
	}

	if (!(seg = alloc_lv_segment(segtype, lv, old_le_count,
				     lv->le_count - old_le_count, status, 0,
				     NULL, 0, lv->le_count - old_le_count,
				     0, 0, 0, NULL))) {
		log_error("Couldn't allocate new snapshot segment.");
		return NULL;
	}

	dm_list_add(&lv->segments, &seg->list);
	lv->status |= VIRTUAL;

	return seg;
}

static int _release_and_discard_lv_segment_area(struct lv_segment *seg, uint32_t s,
						uint32_t area_reduction, int with_discard)
{
	struct lv_segment *cache_seg;

	if (seg_type(seg, s) == AREA_UNASSIGNED)
		return 1;

	if (seg_type(seg, s) == AREA_PV) {
		if (with_discard && !discard_pv_segment(seg_pvseg(seg, s), area_reduction))
			return_0;

		if (!release_pv_segment(seg_pvseg(seg, s), area_reduction))
			return_0;

		if (seg->area_len == area_reduction)
			seg_type(seg, s) = AREA_UNASSIGNED;

		return 1;
	}

	if (lv_is_mirror_image(seg_lv(seg, s)) ||
	    lv_is_thin_pool_data(seg_lv(seg, s)) ||
	    lv_is_cache_pool_data(seg_lv(seg, s))) {
		if (!lv_reduce(seg_lv(seg, s), area_reduction))
			return_0; /* FIXME: any upper level reporting */
		return 1;
	}

	if (seg_is_cache_pool(seg) &&
	    !dm_list_empty(&seg->lv->segs_using_this_lv)) {
		if (!(cache_seg = get_only_segment_using_this_lv(seg->lv)))
			return_0;

		if (!lv_cache_remove(cache_seg->lv))
			return_0;
	}

	if (lv_is_raid_image(seg_lv(seg, s))) {
		/*
		 * FIXME: Use lv_reduce not lv_remove
		 *  We use lv_remove for now, because I haven't figured out
		 *  why lv_reduce won't remove the LV.
		lv_reduce(seg_lv(seg, s), area_reduction);
		*/
		if (area_reduction != seg->area_len) {
			log_error("Unable to reduce RAID LV - operation not implemented.");
			return_0;
		} else {
			if (!lv_remove(seg_lv(seg, s))) {
				log_error("Failed to remove RAID image %s",
					  seg_lv(seg, s)->name);
				return 0;
			}
		}

		/* Remove metadata area if image has been removed */
		if (area_reduction == seg->area_len) {
			if (!lv_reduce(seg_metalv(seg, s),
				       seg_metalv(seg, s)->le_count)) {
				log_error("Failed to remove RAID meta-device %s",
					  seg_metalv(seg, s)->name);
				return 0;
			}
		}
		return 1;
	}

	if (area_reduction == seg->area_len) {
		log_very_verbose("Remove %s:%" PRIu32 "[%" PRIu32 "] from "
				 "the top of LV %s:%" PRIu32,
				 seg->lv->name, seg->le, s,
				 seg_lv(seg, s)->name, seg_le(seg, s));

		if (!remove_seg_from_segs_using_this_lv(seg_lv(seg, s), seg))
			return_0;
		seg_lv(seg, s) = NULL;
		seg_le(seg, s) = 0;
		seg_type(seg, s) = AREA_UNASSIGNED;
	}

	return 1;
}

int release_and_discard_lv_segment_area(struct lv_segment *seg, uint32_t s, uint32_t area_reduction)
{
	return _release_and_discard_lv_segment_area(seg, s, area_reduction, 1);
}

int release_lv_segment_area(struct lv_segment *seg, uint32_t s, uint32_t area_reduction)
{
	return _release_and_discard_lv_segment_area(seg, s, area_reduction, 0);
}

/*
 * Move a segment area from one segment to another
 */
int move_lv_segment_area(struct lv_segment *seg_to, uint32_t area_to,
			 struct lv_segment *seg_from, uint32_t area_from)
{
	struct physical_volume *pv;
	struct logical_volume *lv;
	uint32_t pe, le;

	switch (seg_type(seg_from, area_from)) {
	case AREA_PV:
		pv = seg_pv(seg_from, area_from);
		pe = seg_pe(seg_from, area_from);

		if (!release_lv_segment_area(seg_from, area_from, seg_from->area_len))
			return_0;

		if (!release_lv_segment_area(seg_to, area_to, seg_to->area_len))
			return_0;

		if (!set_lv_segment_area_pv(seg_to, area_to, pv, pe))
			return_0;

		break;

	case AREA_LV:
		lv = seg_lv(seg_from, area_from);
		le = seg_le(seg_from, area_from);

		if (!release_lv_segment_area(seg_from, area_from, seg_from->area_len))
			return_0;

		if (!release_lv_segment_area(seg_to, area_to, seg_to->area_len))
			return_0;

		if (!set_lv_segment_area_lv(seg_to, area_to, lv, le, 0))
			return_0;

		break;

	case AREA_UNASSIGNED:
		if (!release_lv_segment_area(seg_to, area_to, seg_to->area_len))
			return_0;
	}

	return 1;
}

/*
 * Link part of a PV to an LV segment.
 */
int set_lv_segment_area_pv(struct lv_segment *seg, uint32_t area_num,
			   struct physical_volume *pv, uint32_t pe)
{
	seg->areas[area_num].type = AREA_PV;

	if (!(seg_pvseg(seg, area_num) =
	      assign_peg_to_lvseg(pv, pe, seg->area_len, seg, area_num)))
		return_0;

	return 1;
}

/*
 * Link one LV segment to another.  Assumes sizes already match.
 */
int set_lv_segment_area_lv(struct lv_segment *seg, uint32_t area_num,
			   struct logical_volume *lv, uint32_t le,
			   uint64_t status)
{
	log_very_verbose("Stack %s:%" PRIu32 "[%" PRIu32 "] on LV %s:%" PRIu32,
			 seg->lv->name, seg->le, area_num, lv->name, le);

	if (status & RAID_META) {
		seg->meta_areas[area_num].type = AREA_LV;
		seg_metalv(seg, area_num) = lv;
		if (le) {
			log_error(INTERNAL_ERROR "Meta le != 0");
			return 0;
		}
		seg_metale(seg, area_num) = 0;
	} else {
		seg->areas[area_num].type = AREA_LV;
		seg_lv(seg, area_num) = lv;
		seg_le(seg, area_num) = le;
	}
	lv->status |= status;

	if (!add_seg_to_segs_using_this_lv(lv, seg))
		return_0;

	return 1;
}

/*
 * Prepare for adding parallel areas to an existing segment.
 */
static int _lv_segment_add_areas(struct logical_volume *lv,
				 struct lv_segment *seg,
				 uint32_t new_area_count)
{
	struct lv_segment_area *newareas;
	uint32_t areas_sz = new_area_count * sizeof(*newareas);

	if (!(newareas = dm_pool_zalloc(lv->vg->cmd->mem, areas_sz)))
		return_0;

	memcpy(newareas, seg->areas, seg->area_count * sizeof(*seg->areas));

	seg->areas = newareas;
	seg->area_count = new_area_count;

	return 1;
}

/*
 * Reduce the size of an lv_segment.  New size can be zero.
 */
static int _lv_segment_reduce(struct lv_segment *seg, uint32_t reduction)
{
	uint32_t area_reduction, s;

	/* Caller must ensure exact divisibility */
	if (seg_is_striped(seg)) {
		if (reduction % seg->area_count) {
			log_error("Segment extent reduction %" PRIu32
				  " not divisible by #stripes %" PRIu32,
				  reduction, seg->area_count);
			return 0;
		}
		area_reduction = (reduction / seg->area_count);
	} else
		area_reduction = reduction;

	for (s = 0; s < seg->area_count; s++)
		if (!release_and_discard_lv_segment_area(seg, s, area_reduction))
			return_0;

	seg->len -= reduction;
	seg->area_len -= area_reduction;

	return 1;
}

/*
 * Entry point for all LV reductions in size.
 */
static int _lv_reduce(struct logical_volume *lv, uint32_t extents, int delete)
{
	struct lv_segment *seg;
	uint32_t count = extents;
	uint32_t reduction;
	struct logical_volume *pool_lv;

	if (lv_is_merging_origin(lv)) {
		log_debug_metadata("Dropping snapshot merge of %s to removed origin %s.",
				   find_snapshot(lv)->lv->name, lv->name);
		clear_snapshot_merge(lv);
	}

	dm_list_iterate_back_items(seg, &lv->segments) {
		if (!count)
			break;

		if (seg->len <= count) {
			if (seg->merge_lv) {
				log_debug_metadata("Dropping snapshot merge of removed %s to origin %s.",
						   seg->lv->name, seg->merge_lv->name);
				clear_snapshot_merge(seg->merge_lv);
			}

			/* remove this segment completely */
			/* FIXME Check this is safe */
			if (seg->log_lv && !lv_remove(seg->log_lv))
				return_0;

			if (seg->metadata_lv && !lv_remove(seg->metadata_lv))
				return_0;

			/* Remove cache origin only when removing (not on lv_empty()) */
			if (delete && seg_is_cache(seg)) {
				if (lv_is_pending_delete(seg->lv)) {
					/* Just dropping reference on origin when pending delete */
					if (!remove_seg_from_segs_using_this_lv(seg_lv(seg, 0), seg))
						return_0;
					seg_lv(seg, 0) = NULL;
					seg_le(seg, 0) = 0;
					seg_type(seg, 0) = AREA_UNASSIGNED;
					if (seg->pool_lv && !detach_pool_lv(seg))
						return_0;
				} else if (!lv_remove(seg_lv(seg, 0)))
					return_0;
			}

			if ((pool_lv = seg->pool_lv)) {
				if (!detach_pool_lv(seg))
					return_0;
				/* When removing cached LV, remove pool as well */
				if (seg_is_cache(seg) && !lv_remove(pool_lv))
					return_0;
			}

			dm_list_del(&seg->list);
			reduction = seg->len;
		} else
			reduction = count;

		if (!_lv_segment_reduce(seg, reduction))
			return_0;
		count -= reduction;
	}

	lv->le_count -= extents;
	lv->size = (uint64_t) lv->le_count * lv->vg->extent_size;

	if (!delete)
		return 1;

	if (lv == lv->vg->pool_metadata_spare_lv) {
		lv->status &= ~POOL_METADATA_SPARE;
		lv->vg->pool_metadata_spare_lv = NULL;
	}

	/* Remove the LV if it is now empty */
	if (!lv->le_count && !unlink_lv_from_vg(lv))
		return_0;
	else if (lv->vg->fid->fmt->ops->lv_setup &&
		   !lv->vg->fid->fmt->ops->lv_setup(lv->vg->fid, lv))
		return_0;

	return 1;
}

/*
 * Empty an LV.
 */
int lv_empty(struct logical_volume *lv)
{
	return _lv_reduce(lv, lv->le_count, 0);
}

/*
 * Empty an LV and add error segment.
 */
int replace_lv_with_error_segment(struct logical_volume *lv)
{
	uint32_t len = lv->le_count;

	if (len && !lv_empty(lv))
		return_0;

	/* Minimum size required for a table. */
	if (!len)
		len = 1;

	/*
	 * Since we are replacing the whatever-was-there with
	 * an error segment, we should also clear any flags
	 * that suggest it is anything other than "error".
	 */
	/* FIXME Check for other flags that need removing */
	lv->status &= ~(MIRROR|MIRRORED|PVMOVE|LOCKED);

	/* FIXME Check for any attached LVs that will become orphans e.g. mirror logs */

	if (!lv_add_virtual_segment(lv, 0, len, get_segtype_from_string(lv->vg->cmd, "error")))
		return_0;

	return 1;
}

int lv_refresh_suspend_resume(struct cmd_context *cmd, struct logical_volume *lv)
{
	if (!cmd->partial_activation && (lv->status & PARTIAL_LV)) {
		log_error("Refusing refresh of partial LV %s."
			  " Use '--activationmode partial' to override.",
			  display_lvname(lv));
		return 0;
	}

	if (!suspend_lv(cmd, lv)) {
		log_error("Failed to suspend %s.", display_lvname(lv));
		return 0;
	}

	if (!resume_lv(cmd, lv)) {
		log_error("Failed to reactivate %s.", display_lvname(lv));
		return 0;
	}

	return 1;
}

/*
 * Remove given number of extents from LV.
 */
int lv_reduce(struct logical_volume *lv, uint32_t extents)
{
	return _lv_reduce(lv, extents, 1);
}

/*
 * Completely remove an LV.
 */
int lv_remove(struct logical_volume *lv)
{

	if (!lv_reduce(lv, lv->le_count))
		return_0;

	return 1;
}

/*
 * A set of contiguous physical extents allocated
 */
struct alloced_area {
	struct dm_list list;

	struct physical_volume *pv;
	uint32_t pe;
	uint32_t len;
};

/*
 * Details of an allocation attempt
 */
struct alloc_handle {
	struct cmd_context *cmd;
	struct dm_pool *mem;

	alloc_policy_t alloc;		/* Overall policy */
	int approx_alloc;                /* get as much as possible up to new_extents */
	uint32_t new_extents;		/* Number of new extents required */
	uint32_t area_count;		/* Number of parallel areas */
	uint32_t parity_count;   /* Adds to area_count, but not area_multiple */
	uint32_t area_multiple;		/* seg->len = area_len * area_multiple */
	uint32_t log_area_count;	/* Number of parallel logs */
	uint32_t metadata_area_count;   /* Number of parallel metadata areas */
	uint32_t log_len;		/* Length of log/metadata_area */
	uint32_t region_size;		/* Mirror region size */
	uint32_t total_area_len;	/* Total number of parallel extents */

	unsigned maximise_cling;
	unsigned mirror_logs_separate;	/* Force mirror logs on separate PVs? */

	/*
	 * RAID devices require a metadata area that accompanies each
	 * device.  During initial creation, it is best to look for space
	 * that is new_extents + log_len and then split that between two
	 * allocated areas when found.  'alloc_and_split_meta' indicates
	 * that this is the desired dynamic.
	 *
	 * This same idea is used by cache LVs to get the metadata device
	 * and data device allocated together.
	 */
	unsigned alloc_and_split_meta;
	unsigned split_metadata_is_allocated;	/* Metadata has been allocated */

	const struct dm_config_node *cling_tag_list_cn;

	struct dm_list *parallel_areas;	/* PVs to avoid */

	/*
	 * Contains area_count lists of areas allocated to data stripes
	 * followed by log_area_count lists of areas allocated to log stripes.
	 */
	struct dm_list alloced_areas[0];
};

static uint32_t _calc_area_multiple(const struct segment_type *segtype,
				    const uint32_t area_count,
				    const uint32_t stripes)
{
	if (!area_count)
		return 1;

	/* Striped */
	if (segtype_is_striped(segtype))
		return area_count;

	/* Parity RAID (e.g. RAID 4/5/6) */
	if (segtype_is_raid(segtype) && segtype->parity_devs) {
		/*
		 * As articulated in _alloc_init, we can tell by
		 * the area_count whether a replacement drive is
		 * being allocated; and if this is the case, then
		 * there is no area_multiple that should be used.
		 */
		if (area_count <= segtype->parity_devs)
			return 1;
		return area_count - segtype->parity_devs;
	}

	/*
	 * RAID10 - only has 2-way mirror right now.
	 *          If we are to move beyond 2-way RAID10, then
	 *          the 'stripes' argument will always need to
	 *          be given.
	 */
	if (!strcmp(segtype->name, _lv_type_names[LV_TYPE_RAID10])) {
		if (!stripes)
			return area_count / 2;
		return stripes;
	}

	/* Mirrored stripes */
	if (stripes)
		return stripes;

	/* Mirrored */
	return 1;
}

/*
 * Returns log device size in extents, algorithm from kernel code
 */
#define BYTE_SHIFT 3
static uint32_t mirror_log_extents(uint32_t region_size, uint32_t pe_size, uint32_t area_len)
{
	size_t area_size, bitset_size, log_size, region_count;

	area_size = (size_t)area_len * pe_size;
	region_count = dm_div_up(area_size, region_size);

	/* Work out how many "unsigned long"s we need to hold the bitset. */
	bitset_size = dm_round_up(region_count, sizeof(uint32_t) << BYTE_SHIFT);
	bitset_size >>= BYTE_SHIFT;

	/* Log device holds both header and bitset. */
	log_size = dm_round_up((MIRROR_LOG_OFFSET << SECTOR_SHIFT) + bitset_size, 1 << SECTOR_SHIFT);
	log_size >>= SECTOR_SHIFT;
	log_size = dm_div_up(log_size, pe_size);

	/*
	 * Kernel requires a mirror to be at least 1 region large.  So,
	 * if our mirror log is itself a mirror, it must be at least
	 * 1 region large.  This restriction may not be necessary for
	 * non-mirrored logs, but we apply the rule anyway.
	 *
	 * (The other option is to make the region size of the log
	 * mirror smaller than the mirror it is acting as a log for,
	 * but that really complicates things.  It's much easier to
	 * keep the region_size the same for both.)
	 */
	return (log_size > (region_size / pe_size)) ? log_size :
		(region_size / pe_size);
}

/* Is there enough total space or should we give up immediately? */
static int _sufficient_pes_free(struct alloc_handle *ah, struct dm_list *pvms,
				uint32_t allocated, uint32_t extents_still_needed)
{
	uint32_t area_extents_needed = (extents_still_needed - allocated) * ah->area_count / ah->area_multiple;
	uint32_t parity_extents_needed = (extents_still_needed - allocated) * ah->parity_count / ah->area_multiple;
	uint32_t metadata_extents_needed = (ah->alloc_and_split_meta) ? 0 : ah->metadata_area_count * RAID_METADATA_AREA_LEN; /* One each */
	uint32_t total_extents_needed = area_extents_needed + parity_extents_needed + metadata_extents_needed;
	uint32_t free_pes = pv_maps_size(pvms);

	if (total_extents_needed > free_pes) {
		log_error("Insufficient free space: %" PRIu32 " extents needed,"
			  " but only %" PRIu32 " available",
			  total_extents_needed, free_pes);
		return 0;
	}

	return 1;
}

/* For striped mirrors, all the areas are counted, through the mirror layer */
static uint32_t _stripes_per_mimage(struct lv_segment *seg)
{
	struct lv_segment *last_lvseg;

	if (seg_is_mirrored(seg) && seg->area_count && seg_type(seg, 0) == AREA_LV) {
		last_lvseg = dm_list_item(dm_list_last(&seg_lv(seg, 0)->segments), struct lv_segment);
		if (seg_is_striped(last_lvseg))
			return last_lvseg->area_count;
	}

	return 1;
}

static void _init_alloc_parms(struct alloc_handle *ah,
			      struct alloc_parms *alloc_parms,
			      alloc_policy_t alloc,
			      struct lv_segment *prev_lvseg, unsigned can_split,
			      uint32_t allocated, uint32_t extents_still_needed)
{
	alloc_parms->alloc = alloc;
	alloc_parms->prev_lvseg = prev_lvseg;
	alloc_parms->flags = 0;
	alloc_parms->extents_still_needed = extents_still_needed;

	/*
	 * Only attempt contiguous/cling allocation to previous segment
	 * areas if the number of areas matches.
	 */
	if (alloc_parms->prev_lvseg &&
	    ((ah->area_count + ah->parity_count) == prev_lvseg->area_count)) {
		alloc_parms->flags |= A_AREA_COUNT_MATCHES;

		/* Are there any preceding segments we must follow on from? */
		if (alloc_parms->alloc == ALLOC_CONTIGUOUS) {
			alloc_parms->flags |= A_CONTIGUOUS_TO_LVSEG;
			alloc_parms->flags |= A_POSITIONAL_FILL;
		} else if ((alloc_parms->alloc == ALLOC_CLING) ||
			   (alloc_parms->alloc == ALLOC_CLING_BY_TAGS)) {
			alloc_parms->flags |= A_CLING_TO_LVSEG;
			alloc_parms->flags |= A_POSITIONAL_FILL;
		}
	} else
		/*
		 * A cling allocation that follows a successful contiguous
		 * allocation must use the same PVs (or else fail).
		 */
		if ((alloc_parms->alloc == ALLOC_CLING) ||
		    (alloc_parms->alloc == ALLOC_CLING_BY_TAGS)) {
			alloc_parms->flags |= A_CLING_TO_ALLOCED;
			alloc_parms->flags |= A_POSITIONAL_FILL;
		}

	if (alloc_parms->alloc == ALLOC_CLING_BY_TAGS)
		alloc_parms->flags |= A_CLING_BY_TAGS;

	if (!(alloc_parms->alloc & A_POSITIONAL_FILL) &&
	    (alloc_parms->alloc == ALLOC_CONTIGUOUS) &&
	    ah->cling_tag_list_cn)
		alloc_parms->flags |= A_PARTITION_BY_TAGS;

	/*
	 * For normal allocations, if any extents have already been found 
	 * for allocation, prefer to place further extents on the same disks as
	 * have already been used.
	 */
	if (ah->maximise_cling &&
	    (alloc_parms->alloc == ALLOC_NORMAL) &&
	    (allocated != alloc_parms->extents_still_needed))
		alloc_parms->flags |= A_CLING_TO_ALLOCED;

	if (can_split)
		alloc_parms->flags |= A_CAN_SPLIT;
}

static int _log_parallel_areas(struct dm_pool *mem, struct dm_list *parallel_areas)
{
	struct seg_pvs *spvs;
	struct pv_list *pvl;
	char *pvnames;

	if (!parallel_areas)
		return 1;

	dm_list_iterate_items(spvs, parallel_areas) {
		if (!dm_pool_begin_object(mem, 256)) {
			log_error("dm_pool_begin_object failed");
			return 0;
		}

		dm_list_iterate_items(pvl, &spvs->pvs) {
			if (!dm_pool_grow_object(mem, pv_dev_name(pvl->pv), strlen(pv_dev_name(pvl->pv)))) {
				log_error("dm_pool_grow_object failed");
				dm_pool_abandon_object(mem);
				return 0;
			}
			if (!dm_pool_grow_object(mem, " ", 1)) {
				log_error("dm_pool_grow_object failed");
				dm_pool_abandon_object(mem);
				return 0;
			}
		}

		if (!dm_pool_grow_object(mem, "\0", 1)) {
			log_error("dm_pool_grow_object failed");
			dm_pool_abandon_object(mem);
			return 0;
		}

		pvnames = dm_pool_end_object(mem);
		log_debug_alloc("Parallel PVs at LE %" PRIu32 " length %" PRIu32 ": %s",
				spvs->le, spvs->len, pvnames);
		dm_pool_free(mem, pvnames);
	}

	return 1;
}

static int _setup_alloced_segment(struct logical_volume *lv, uint64_t status,
				  uint32_t area_count,
				  uint32_t stripe_size,
				  const struct segment_type *segtype,
				  struct alloced_area *aa,
				  uint32_t region_size)
{
	uint32_t s, extents, area_multiple;
	struct lv_segment *seg;

	area_multiple = _calc_area_multiple(segtype, area_count, 0);

	if (!(seg = alloc_lv_segment(segtype, lv, lv->le_count,
				     aa[0].len * area_multiple,
				     status, stripe_size, NULL,
				     area_count,
				     aa[0].len, 0u, region_size, 0u, NULL))) {
		log_error("Couldn't allocate new LV segment.");
		return 0;
	}

	for (s = 0; s < area_count; s++)
		if (!set_lv_segment_area_pv(seg, s, aa[s].pv, aa[s].pe))
			return_0;

	dm_list_add(&lv->segments, &seg->list);

	extents = aa[0].len * area_multiple;
	lv->le_count += extents;
	lv->size += (uint64_t) extents *lv->vg->extent_size;

	return 1;
}

static int _setup_alloced_segments(struct logical_volume *lv,
				   struct dm_list *alloced_areas,
				   uint32_t area_count,
				   uint64_t status,
				   uint32_t stripe_size,
				   const struct segment_type *segtype,
				   uint32_t region_size)
{
	struct alloced_area *aa;

	dm_list_iterate_items(aa, &alloced_areas[0]) {
		if (!_setup_alloced_segment(lv, status, area_count,
					    stripe_size, segtype, aa,
					    region_size))
			return_0;
	}

	return 1;
}

/*
 * This function takes a list of pv_areas and adds them to allocated_areas.
 * If the complete area is not needed then it gets split.
 * The part used is removed from the pv_map so it can't be allocated twice.
 */
static int _alloc_parallel_area(struct alloc_handle *ah, uint32_t max_to_allocate,
				struct alloc_state *alloc_state, uint32_t ix_log_offset)
{
	uint32_t area_len, len;
	uint32_t s, smeta;
	uint32_t ix_log_skip = 0; /* How many areas to skip in middle of array to reach log areas */
	uint32_t total_area_count;
	struct alloced_area *aa;
	struct pv_area *pva;

	total_area_count = ah->area_count + ah->parity_count + alloc_state->log_area_count_still_needed;
	if (!total_area_count) {
		log_warn(INTERNAL_ERROR "_alloc_parallel_area called without any allocation to do.");
		return 1;
	}

	area_len = max_to_allocate / ah->area_multiple;

	/* Reduce area_len to the smallest of the areas */
	for (s = 0; s < ah->area_count + ah->parity_count; s++)
		if (area_len > alloc_state->areas[s].used)
			area_len = alloc_state->areas[s].used;

	len = (ah->alloc_and_split_meta && !ah->split_metadata_is_allocated) ? total_area_count * 2 : total_area_count;
	len *= sizeof(*aa);
	if (!(aa = dm_pool_alloc(ah->mem, len))) {
		log_error("alloced_area allocation failed");
		return 0;
	}

	/*
	 * Areas consists of area_count areas for data stripes, then
	 * ix_log_skip areas to skip, then log_area_count areas to use for the
	 * log, then some areas too small for the log.
	 */
	len = area_len;
	for (s = 0; s < total_area_count; s++) {
		if (s == (ah->area_count + ah->parity_count)) {
			ix_log_skip = ix_log_offset - ah->area_count;
			len = ah->log_len;
		}

		pva = alloc_state->areas[s + ix_log_skip].pva;
		if (ah->alloc_and_split_meta && !ah->split_metadata_is_allocated) {
			/*
			 * The metadata area goes at the front of the allocated
			 * space for now, but could easily go at the end (or
			 * middle!).
			 *
			 * Even though we split these two from the same
			 * allocation, we store the images at the beginning
			 * of the areas array and the metadata at the end.
			 */
			smeta = s + ah->area_count + ah->parity_count;
			aa[smeta].pv = pva->map->pv;
			aa[smeta].pe = pva->start;
			aa[smeta].len = ah->log_len;

			log_debug_alloc("Allocating parallel metadata area %" PRIu32
					" on %s start PE %" PRIu32
					" length %" PRIu32 ".",
					(smeta - (ah->area_count + ah->parity_count)),
					pv_dev_name(aa[smeta].pv), aa[smeta].pe,
					ah->log_len);

			consume_pv_area(pva, ah->log_len);
			dm_list_add(&ah->alloced_areas[smeta], &aa[smeta].list);
		}
		aa[s].len = (ah->alloc_and_split_meta && !ah->split_metadata_is_allocated) ? len - ah->log_len : len;
		/* Skip empty allocations */
		if (!aa[s].len)
			continue;

		aa[s].pv = pva->map->pv;
		aa[s].pe = pva->start;

		log_debug_alloc("Allocating parallel area %" PRIu32
				" on %s start PE %" PRIu32 " length %" PRIu32 ".",
				s, pv_dev_name(aa[s].pv), aa[s].pe, aa[s].len);

		consume_pv_area(pva, aa[s].len);

		dm_list_add(&ah->alloced_areas[s], &aa[s].list);
	}

	/* Only need to alloc metadata from the first batch */
	if (ah->alloc_and_split_meta)
		ah->split_metadata_is_allocated = 1;

	ah->total_area_len += area_len;

	alloc_state->allocated += area_len * ah->area_multiple;

	return 1;
}

/*
 * Call fn for each AREA_PV used by the LV segment at lv:le of length *max_seg_len.
 * If any constituent area contains more than one segment, max_seg_len is
 * reduced to cover only the first.
 * fn should return 0 on error, 1 to continue scanning or >1 to terminate without error.
 * In the last case, this function passes on the return code.
 * FIXME I think some callers are expecting this to check all PV segments used by an LV.
 */
static int _for_each_pv(struct cmd_context *cmd, struct logical_volume *lv,
			uint32_t le, uint32_t len, struct lv_segment *seg,
			uint32_t *max_seg_len,
			uint32_t first_area, uint32_t max_areas,
			int top_level_area_index,
			int only_single_area_segments,
			int (*fn)(struct cmd_context *cmd,
				  struct pv_segment *peg, uint32_t s,
				  void *data),
			void *data)
{
	uint32_t s;
	uint32_t remaining_seg_len, area_len, area_multiple;
	uint32_t stripes_per_mimage = 1;
	int r = 1;

	if (!seg && !(seg = find_seg_by_le(lv, le))) {
		log_error("Failed to find segment for %s extent %" PRIu32,
			  lv->name, le);
		return 0;
	}

	/* Remaining logical length of segment */
	remaining_seg_len = seg->len - (le - seg->le);

	if (remaining_seg_len > len)
		remaining_seg_len = len;

	if (max_seg_len && *max_seg_len > remaining_seg_len)
		*max_seg_len = remaining_seg_len;

	area_multiple = _calc_area_multiple(seg->segtype, seg->area_count, 0);
	area_len = remaining_seg_len / area_multiple ? : 1;

	/* For striped mirrors, all the areas are counted, through the mirror layer */
	if (top_level_area_index == -1)
		stripes_per_mimage = _stripes_per_mimage(seg);

	for (s = first_area;
	     s < seg->area_count && (!max_areas || s <= max_areas);
	     s++) {
		if (seg_type(seg, s) == AREA_LV) {
			if (!(r = _for_each_pv(cmd, seg_lv(seg, s),
					       seg_le(seg, s) +
					       (le - seg->le) / area_multiple,
					       area_len, NULL, max_seg_len, 0,
					       (stripes_per_mimage == 1) && only_single_area_segments ? 1U : 0U,
					       (top_level_area_index != -1) ? top_level_area_index : (int) (s * stripes_per_mimage),
					       only_single_area_segments, fn,
					       data)))
				stack;
		} else if (seg_type(seg, s) == AREA_PV)
			if (!(r = fn(cmd, seg_pvseg(seg, s), top_level_area_index != -1 ? (uint32_t) top_level_area_index + s : s, data)))
				stack;
		if (r != 1)
			return r;
	}

	/* FIXME only_single_area_segments used as workaround to skip log LV - needs new param? */
	if (!only_single_area_segments && seg_is_mirrored(seg) && seg->log_lv) {
		if (!(r = _for_each_pv(cmd, seg->log_lv, 0, seg->log_lv->le_count, NULL,
				       NULL, 0, 0, 0, only_single_area_segments,
				       fn, data)))
			stack;
		if (r != 1)
			return r;
	}

	/* FIXME Add snapshot cow, thin meta etc. */

/*
	if (!only_single_area_segments && !max_areas && seg_is_raid(seg)) {
		for (s = first_area; s < seg->area_count; s++) {
			if (seg_metalv(seg, s))
				if (!(r = _for_each_pv(cmd, seg_metalv(seg, s), 0, seg_metalv(seg, s)->le_count, NULL,
						       NULL, 0, 0, 0, 0, fn, data)))
					stack;
			if (r != 1)
				return r;
		}
	}
*/

	return 1;
}

static int _comp_area(const void *l, const void *r)
{
	const struct pv_area_used *lhs = (const struct pv_area_used *) l;
	const struct pv_area_used *rhs = (const struct pv_area_used *) r;

	if (lhs->used < rhs->used)
		return 1;

	else if (lhs->used > rhs->used)
		return -1;

	return 0;
}

/*
 * Search for pvseg that matches condition
 */
struct pv_match {
	int (*condition)(struct pv_match *pvmatch, struct pv_segment *pvseg, struct pv_area *pva);

	struct alloc_handle *ah;
	struct alloc_state *alloc_state;
	struct pv_area *pva;
	const struct dm_config_node *cling_tag_list_cn;
	int s;	/* Area index of match */
};

/*
 * Is PV area on the same PV?
 */
static int _is_same_pv(struct pv_match *pvmatch __attribute((unused)), struct pv_segment *pvseg, struct pv_area *pva)
{
	if (pvseg->pv != pva->map->pv)
		return 0;

	return 1;
}

/*
 * Does PV area have a tag listed in allocation/cling_tag_list that 
 * matches EITHER a tag of the PV of the existing segment OR a tag in pv_tags?
 * If tags_list_str is set, then instead we generate a list of matching tags for printing.
 */
static int _match_pv_tags(const struct dm_config_node *cling_tag_list_cn,
			  struct physical_volume *pv1, uint32_t pv1_start_pe, uint32_t area_num,
			  struct physical_volume *pv2, struct dm_list *pv_tags, unsigned validate_only,
			  struct dm_pool *mem, const char **tags_list_str)
{
	const struct dm_config_value *cv;
	const char *str;
	const char *tag_matched;
	struct dm_list *tags_to_match = tags_list_str ? NULL : pv_tags ? : &pv2->tags;
	struct dm_str_list *sl;
	unsigned first_tag = 1;

	if (tags_list_str && !dm_pool_begin_object(mem, 256)) {
		log_error("PV tags string allocation failed");
		return 0;
	}

	for (cv = cling_tag_list_cn->v; cv; cv = cv->next) {
		if (cv->type != DM_CFG_STRING) {
			if (validate_only)
				log_warn("WARNING: Ignoring invalid string in config file entry "
					 "allocation/cling_tag_list");
			continue;
		}
		str = cv->v.str;
		if (!*str) {
			if (validate_only)
				log_warn("WARNING: Ignoring empty string in config file entry "
					 "allocation/cling_tag_list");
			continue;
		}

		if (*str != '@') {
			if (validate_only)
				log_warn("WARNING: Ignoring string not starting with @ in config file entry "
					 "allocation/cling_tag_list: %s", str);
			continue;
		}

		str++;

		if (!*str) {
			if (validate_only)
				log_warn("WARNING: Ignoring empty tag in config file entry "
					 "allocation/cling_tag_list");
			continue;
		}

		if (validate_only)
			continue;

		/* Wildcard matches any tag against any tag. */
		if (!strcmp(str, "*")) {
			if (tags_list_str) {
				dm_list_iterate_items(sl, &pv1->tags) {
					if (!first_tag && !dm_pool_grow_object(mem, ",", 0)) {
						dm_pool_abandon_object(mem);
						log_error("PV tags string extension failed.");
						return 0;
					}
					first_tag = 0;
					if (!dm_pool_grow_object(mem, sl->str, 0)) {
						dm_pool_abandon_object(mem);
						log_error("PV tags string extension failed.");
						return 0;
					}
				}
				continue;
			}
			if (!str_list_match_list(&pv1->tags, tags_to_match, &tag_matched))
				continue;
			else {
				if (!pv_tags)
					log_debug_alloc("Matched allocation PV tag %s on existing %s with free space on %s.",
							tag_matched, pv_dev_name(pv1), pv_dev_name(pv2));
				else
					log_debug_alloc("Eliminating allocation area %" PRIu32 " at PV %s start PE %" PRIu32
							" from consideration: PV tag %s already used.",
							area_num, pv_dev_name(pv1), pv1_start_pe, tag_matched);
				return 1;
			}
		}

		if (!str_list_match_item(&pv1->tags, str) ||
		    (tags_to_match && !str_list_match_item(tags_to_match, str)))
			continue;
		else {
			if (tags_list_str) {
				if (!first_tag && !dm_pool_grow_object(mem, ",", 0)) {
					dm_pool_abandon_object(mem);
					log_error("PV tags string extension failed.");
					return 0;
				}
				first_tag = 0;
				if (!dm_pool_grow_object(mem, str, 0)) {
					dm_pool_abandon_object(mem);
					log_error("PV tags string extension failed.");
					return 0;
				}
				continue;
			}
			if (!pv_tags)
				log_debug_alloc("Matched allocation PV tag %s on existing %s with free space on %s.",
						str, pv_dev_name(pv1), pv_dev_name(pv2));
			else
				log_debug_alloc("Eliminating allocation area %" PRIu32 " at PV %s start PE %" PRIu32
						" from consideration: PV tag %s already used.",
						area_num, pv_dev_name(pv1), pv1_start_pe, str);
			return 1;
		}
	}

	if (tags_list_str) {
		if (!dm_pool_grow_object(mem, "\0", 1)) {
			dm_pool_abandon_object(mem);
			log_error("PV tags string extension failed.");
			return 0;
		}
		*tags_list_str = dm_pool_end_object(mem);
		return 1;
	}

	return 0;
}

static int _validate_tag_list(const struct dm_config_node *cling_tag_list_cn)
{
	return _match_pv_tags(cling_tag_list_cn, NULL, 0, 0, NULL, NULL, 1, NULL, NULL);
}

static const char *_tags_list_str(struct alloc_handle *ah, struct physical_volume *pv1)
{
	const char *tags_list_str;

	if (!_match_pv_tags(ah->cling_tag_list_cn, pv1, 0, 0, NULL, NULL, 0, ah->mem, &tags_list_str))
		return_NULL;

	return tags_list_str;
}

/*
 * Does PV area have a tag listed in allocation/cling_tag_list that
 * matches a tag in the pv_tags list?
 */
static int _pv_has_matching_tag(const struct dm_config_node *cling_tag_list_cn,
				struct physical_volume *pv1, uint32_t pv1_start_pe, uint32_t area_num,
				struct dm_list *pv_tags)
{
	return _match_pv_tags(cling_tag_list_cn, pv1, pv1_start_pe, area_num, NULL, pv_tags, 0, NULL, NULL);
}

/*
 * Does PV area have a tag listed in allocation/cling_tag_list that 
 * matches a tag of the PV of the existing segment?
 */
static int _pvs_have_matching_tag(const struct dm_config_node *cling_tag_list_cn,
				  struct physical_volume *pv1, struct physical_volume *pv2)
{
	return _match_pv_tags(cling_tag_list_cn, pv1, 0, 0, pv2, NULL, 0, NULL, NULL);
}

static int _has_matching_pv_tag(struct pv_match *pvmatch, struct pv_segment *pvseg, struct pv_area *pva)
{
	return _pvs_have_matching_tag(pvmatch->cling_tag_list_cn, pvseg->pv, pva->map->pv);
}

/*
 * Is PV area contiguous to PV segment?
 */
static int _is_contiguous(struct pv_match *pvmatch __attribute((unused)), struct pv_segment *pvseg, struct pv_area *pva)
{
	if (pvseg->pv != pva->map->pv)
		return 0;

	if (pvseg->pe + pvseg->len != pva->start)
		return 0;

	return 1;
}

static void _reserve_area(struct alloc_handle *ah, struct alloc_state *alloc_state, struct pv_area *pva,
			  uint32_t required, uint32_t ix_pva, uint32_t unreserved)
{
	struct pv_area_used *area_used = &alloc_state->areas[ix_pva];
	const char *pv_tag_list = NULL;

	if (ah->cling_tag_list_cn)
		pv_tag_list = _tags_list_str(ah, pva->map->pv);

	log_debug_alloc("%s allocation area %" PRIu32 " %s %s start PE %" PRIu32
			" length %" PRIu32 " leaving %" PRIu32 "%s%s.",
			area_used->pva ? "Changing   " : "Considering", 
			ix_pva, area_used->pva ? "to" : "as", 
			dev_name(pva->map->pv->dev), pva->start, required, unreserved,
			pv_tag_list ? " with PV tags: " : "",
			pv_tag_list ? : "");

	if (pv_tag_list)
		dm_pool_free(ah->mem, (void *)pv_tag_list);

	area_used->pva = pva;
	area_used->used = required;
}

static int _reserve_required_area(struct alloc_handle *ah, struct alloc_state *alloc_state, struct pv_area *pva,
				  uint32_t required, uint32_t ix_pva, uint32_t unreserved)
{
	uint32_t s;

	/* Expand areas array if needed after an area was split. */
	if (ix_pva >= alloc_state->areas_size) {
		alloc_state->areas_size *= 2;
		if (!(alloc_state->areas = dm_realloc(alloc_state->areas, sizeof(*alloc_state->areas) * (alloc_state->areas_size)))) {
			log_error("Memory reallocation for parallel areas failed.");
			return 0;
		}
		for (s = alloc_state->areas_size / 2; s < alloc_state->areas_size; s++)
			alloc_state->areas[s].pva = NULL;
	}

	_reserve_area(ah, alloc_state, pva, required, ix_pva, unreserved);

	return 1;
}

static int _is_condition(struct cmd_context *cmd __attribute__((unused)),
			 struct pv_segment *pvseg, uint32_t s,
			 void *data)
{
	struct pv_match *pvmatch = data;
	int positional = pvmatch->alloc_state->alloc_parms->flags & A_POSITIONAL_FILL;

	if (positional && pvmatch->alloc_state->areas[s].pva)
		return 1;	/* Area already assigned */

	if (!pvmatch->condition(pvmatch, pvseg, pvmatch->pva))
		return 1;	/* Continue */

	if (positional && (s >= pvmatch->alloc_state->num_positional_areas))
		return 1;

	/* FIXME The previous test should make this one redundant. */
	if (positional && (s >= pvmatch->alloc_state->areas_size))
		return 1;

	/*
	 * Only used for cling and contiguous policies (which only make one allocation per PV)
	 * so it's safe to say all the available space is used.
	 */
	if (positional)
		_reserve_required_area(pvmatch->ah, pvmatch->alloc_state, pvmatch->pva, pvmatch->pva->count, s, 0);

	return 2;	/* Finished */
}

/*
 * Is pva on same PV as any existing areas?
 */
static int _check_cling(struct alloc_handle *ah,
			const struct dm_config_node *cling_tag_list_cn,
			struct lv_segment *prev_lvseg, struct pv_area *pva,
			struct alloc_state *alloc_state)
{
	struct pv_match pvmatch;
	int r;
	uint32_t le, len;

	pvmatch.ah = ah;
	pvmatch.condition = cling_tag_list_cn ? _has_matching_pv_tag : _is_same_pv;
	pvmatch.alloc_state = alloc_state;
	pvmatch.pva = pva;
	pvmatch.cling_tag_list_cn = cling_tag_list_cn;

	if (ah->maximise_cling) {
		/* Check entire LV */
		le = 0;
		len = prev_lvseg->le + prev_lvseg->len;
	} else {
		/* Only check 1 LE at end of previous LV segment */
		le = prev_lvseg->le + prev_lvseg->len - 1;
		len = 1;
	}

	/* FIXME Cope with stacks by flattening */
	if (!(r = _for_each_pv(ah->cmd, prev_lvseg->lv, le, len, NULL, NULL,
			       0, 0, -1, 1,
			       _is_condition, &pvmatch)))
		stack;

	if (r != 2)
		return 0;

	return 1;
}

/*
 * Is pva contiguous to any existing areas or on the same PV?
 */
static int _check_contiguous(struct alloc_handle *ah,
			     struct lv_segment *prev_lvseg, struct pv_area *pva,
			     struct alloc_state *alloc_state)
{
	struct pv_match pvmatch;
	int r;

	pvmatch.ah = ah;
	pvmatch.condition = _is_contiguous;
	pvmatch.alloc_state = alloc_state;
	pvmatch.pva = pva;
	pvmatch.cling_tag_list_cn = NULL;

	/* FIXME Cope with stacks by flattening */
	if (!(r = _for_each_pv(ah->cmd, prev_lvseg->lv,
			       prev_lvseg->le + prev_lvseg->len - 1, 1, NULL, NULL,
			       0, 0, -1, 1,
			       _is_condition, &pvmatch)))
		stack;

	if (r != 2)
		return 0;

	return 1;
}

/*
 * Is pva on same PV as any areas already used in this allocation attempt?
 */
static int _check_cling_to_alloced(struct alloc_handle *ah, const struct dm_config_node *cling_tag_list_cn,
				   struct pv_area *pva, struct alloc_state *alloc_state)
{
	unsigned s;
	struct alloced_area *aa;
	int positional = alloc_state->alloc_parms->flags & A_POSITIONAL_FILL;

	/*
	 * Ignore log areas.  They are always allocated whole as part of the
	 * first allocation.  If they aren't yet set, we know we've nothing to do.
	 */
	if (alloc_state->log_area_count_still_needed)
		return 0;

	for (s = 0; s < ah->area_count; s++) {
		if (positional && alloc_state->areas[s].pva)
			continue;	/* Area already assigned */
		dm_list_iterate_items(aa, &ah->alloced_areas[s]) {
			if ((!cling_tag_list_cn && (pva->map->pv == aa[0].pv)) ||
			    (cling_tag_list_cn && _pvs_have_matching_tag(cling_tag_list_cn, pva->map->pv, aa[0].pv))) {
				if (positional)
					_reserve_required_area(ah, alloc_state, pva, pva->count, s, 0);
				return 1;
			}
		}
	}

	return 0;
}

static int _pv_is_parallel(struct physical_volume *pv, struct dm_list *parallel_pvs)
{
	struct pv_list *pvl;

	dm_list_iterate_items(pvl, parallel_pvs)
		if (pv == pvl->pv)
			return 1;

	return 0;
}

/*
 * Decide whether or not to try allocation from supplied area pva.
 * alloc_state->areas may get modified.
 */
static area_use_t _check_pva(struct alloc_handle *ah, struct pv_area *pva, uint32_t still_needed,
			     struct alloc_state *alloc_state,
			     unsigned already_found_one, unsigned iteration_count, unsigned log_iteration_count)
{
	const struct alloc_parms *alloc_parms = alloc_state->alloc_parms;
	unsigned s;

	/* Skip fully-reserved areas (which are not currently removed from the list). */
	if (!pva->unreserved)
		return NEXT_AREA;

	/* FIXME Should this test be removed? */
	if (iteration_count)
		/*
		* Don't use an area twice.
		*/
		for (s = 0; s < alloc_state->areas_size; s++)
			if (alloc_state->areas[s].pva == pva)
				return NEXT_AREA;

	/* If maximise_cling is set, perform several checks, otherwise perform exactly one. */
	if (!iteration_count && !log_iteration_count && alloc_parms->flags & (A_CONTIGUOUS_TO_LVSEG | A_CLING_TO_LVSEG | A_CLING_TO_ALLOCED)) {
		/* Contiguous? */
		if (((alloc_parms->flags & A_CONTIGUOUS_TO_LVSEG) ||
		     (ah->maximise_cling && (alloc_parms->flags & A_AREA_COUNT_MATCHES))) &&
		    _check_contiguous(ah, alloc_parms->prev_lvseg, pva, alloc_state))
			goto found;

		/* Try next area on same PV if looking for contiguous space */
		if (alloc_parms->flags & A_CONTIGUOUS_TO_LVSEG)
			return NEXT_AREA;

		/* Cling to prev_lvseg? */
		if (((alloc_parms->flags & A_CLING_TO_LVSEG) ||
		     (ah->maximise_cling && (alloc_parms->flags & A_AREA_COUNT_MATCHES))) &&
		    _check_cling(ah, NULL, alloc_parms->prev_lvseg, pva, alloc_state))
			/* If this PV is suitable, use this first area */
			goto found;

		/* Cling_to_alloced? */
		if ((alloc_parms->flags & A_CLING_TO_ALLOCED) &&
		    _check_cling_to_alloced(ah, NULL, pva, alloc_state))
			goto found;

		/* Cling_by_tags? */
		if (!(alloc_parms->flags & A_CLING_BY_TAGS) || !ah->cling_tag_list_cn)
			return NEXT_PV;

		if ((alloc_parms->flags & A_AREA_COUNT_MATCHES)) {
			if (_check_cling(ah, ah->cling_tag_list_cn, alloc_parms->prev_lvseg, pva, alloc_state))
				goto found;
		} else if (_check_cling_to_alloced(ah, ah->cling_tag_list_cn, pva, alloc_state))
			goto found;

		/* All areas on this PV give same result so pointless checking more */
		return NEXT_PV;
	}

	/* Normal/Anywhere */

	/* Is it big enough on its own? */
	if (pva->unreserved * ah->area_multiple < still_needed &&
	    ((!(alloc_parms->flags & A_CAN_SPLIT) && !ah->log_area_count) ||
	     (already_found_one && alloc_parms->alloc != ALLOC_ANYWHERE)))
		return NEXT_PV;

found:
	if (alloc_parms->flags & A_POSITIONAL_FILL)
		return PREFERRED;

	return USE_AREA;
}

/*
 * Decide how many extents we're trying to obtain from a given area.
 * Removes the extents from further consideration.
 */
static uint32_t _calc_required_extents(struct alloc_handle *ah, struct pv_area *pva, unsigned ix_pva, uint32_t max_to_allocate, alloc_policy_t alloc)
{
	uint32_t required = max_to_allocate / ah->area_multiple;

	/*
	 * Update amount unreserved - effectively splitting an area 
	 * into two or more parts.  If the whole stripe doesn't fit,
	 * reduce amount we're looking for.
	 */
	if (alloc == ALLOC_ANYWHERE) {
		if (ix_pva >= ah->area_count + ah->parity_count)
			required = ah->log_len;
	} else if (required < ah->log_len)
		required = ah->log_len;

	if (required >= pva->unreserved) {
		required = pva->unreserved;
		pva->unreserved = 0;
	} else {
		pva->unreserved -= required;
		reinsert_changed_pv_area(pva);
	}

	return required;
}

static void _clear_areas(struct alloc_state *alloc_state)
{
	uint32_t s;

	alloc_state->num_positional_areas = 0;

	for (s = 0; s < alloc_state->areas_size; s++)
		alloc_state->areas[s].pva = NULL;
}

static void _reset_unreserved(struct dm_list *pvms)
{
	struct pv_map *pvm;
	struct pv_area *pva;

	dm_list_iterate_items(pvm, pvms)
		dm_list_iterate_items(pva, &pvm->areas)
			if (pva->unreserved != pva->count) {
				pva->unreserved = pva->count;
				reinsert_changed_pv_area(pva);
			}
}

static void _report_needed_allocation_space(struct alloc_handle *ah,
					    struct alloc_state *alloc_state,
					    struct dm_list *pvms)
{
	const char *metadata_type;
	uint32_t parallel_areas_count, parallel_area_size;
	uint32_t metadata_count, metadata_size;

	parallel_area_size = ah->new_extents - alloc_state->allocated;
	parallel_area_size /= ah->area_multiple;
	parallel_area_size -= (ah->alloc_and_split_meta && !ah->split_metadata_is_allocated) ? ah->log_len : 0;

	parallel_areas_count = ah->area_count + ah->parity_count;

	metadata_size = ah->log_len;
	if (ah->alloc_and_split_meta) {
		metadata_type = "metadata area";
		metadata_count = parallel_areas_count;
		if (ah->split_metadata_is_allocated)
			metadata_size = 0;
	} else {
		metadata_type = "mirror log";
		metadata_count = alloc_state->log_area_count_still_needed;
	}

	log_debug_alloc("Still need %s%" PRIu32 " total extents from %" PRIu32 " remaining (%" PRIu32 " positional slots):",
			ah->approx_alloc ? "up to " : "",
			parallel_area_size * parallel_areas_count + metadata_size * metadata_count, pv_maps_size(pvms),
			alloc_state->num_positional_areas);
	log_debug_alloc("  %" PRIu32 " (%" PRIu32 " data/%" PRIu32
			" parity) parallel areas of %" PRIu32 " extents each",
			parallel_areas_count, ah->area_count, ah->parity_count, parallel_area_size);
	log_debug_alloc("  %" PRIu32 " %s%s of %" PRIu32 " extents each",
			metadata_count, metadata_type,
			(metadata_count == 1) ? "" : "s",
			metadata_size);
}

/* Work through the array, removing any entries with tags already used by previous areas. */
static int _limit_to_one_area_per_tag(struct alloc_handle *ah, struct alloc_state *alloc_state,
				      uint32_t ix_log_offset, unsigned *ix)
{
	uint32_t	s = 0, u = 0;
	DM_LIST_INIT(pv_tags);

	while (s < alloc_state->areas_size && alloc_state->areas[s].pva) {
		/* Start again with an empty tag list when we reach the log devices */
		if (u == ix_log_offset)
			dm_list_init(&pv_tags);
		if (!_pv_has_matching_tag(ah->cling_tag_list_cn, alloc_state->areas[s].pva->map->pv, alloc_state->areas[s].pva->start, s, &pv_tags)) {
			/* The comparison fn will ignore any non-cling tags so just add everything */
			if (!str_list_add_list(ah->mem, &pv_tags, &alloc_state->areas[s].pva->map->pv->tags))
				return_0;

			if (s != u)
				alloc_state->areas[u] = alloc_state->areas[s];

			u++;
		} else
			(*ix)--;	/* One area removed */

		s++;
	}

	alloc_state->areas[u].pva = NULL;

	return 1;
}

/*
 * Returns 1 regardless of whether any space was found, except on error.
 */
static int _find_some_parallel_space(struct alloc_handle *ah,
				     struct dm_list *pvms, struct alloc_state *alloc_state,
				     struct dm_list *parallel_pvs, uint32_t max_to_allocate)
{
	const struct alloc_parms *alloc_parms = alloc_state->alloc_parms;
	unsigned ix = 0;
	unsigned last_ix;
	struct pv_map *pvm;
	struct pv_area *pva;
	unsigned preferred_count = 0;
	unsigned already_found_one;
	unsigned ix_log_offset; /* Offset to start of areas to use for log */
	unsigned too_small_for_log_count; /* How many too small for log? */
	unsigned iteration_count = 0; /* cling_to_alloced may need 2 iterations */
	unsigned log_iteration_count = 0; /* extra iteration for logs on data devices */
	struct alloced_area *aa;
	uint32_t s;
	uint32_t devices_needed = ah->area_count + ah->parity_count;
	uint32_t required;

	_clear_areas(alloc_state);
	_reset_unreserved(pvms);

	/* num_positional_areas holds the number of parallel allocations that must be contiguous/cling */
	/* These appear first in the array, so it is also the offset to the non-preferred allocations */
	/* At most one of A_CONTIGUOUS_TO_LVSEG, A_CLING_TO_LVSEG or A_CLING_TO_ALLOCED may be set */
	if (!(alloc_parms->flags & A_POSITIONAL_FILL))
		alloc_state->num_positional_areas = 0;
	else if (alloc_parms->flags & (A_CONTIGUOUS_TO_LVSEG | A_CLING_TO_LVSEG))
		alloc_state->num_positional_areas = _stripes_per_mimage(alloc_parms->prev_lvseg) * alloc_parms->prev_lvseg->area_count;
	else if (alloc_parms->flags & A_CLING_TO_ALLOCED)
		alloc_state->num_positional_areas = ah->area_count;

	if (alloc_parms->alloc == ALLOC_NORMAL || (alloc_parms->flags & A_CLING_TO_ALLOCED))
		log_debug_alloc("Cling_to_allocated is %sset",
				alloc_parms->flags & A_CLING_TO_ALLOCED ? "" : "not ");

	if (alloc_parms->flags & A_POSITIONAL_FILL)
		log_debug_alloc("%u preferred area(s) to be filled positionally.", alloc_state->num_positional_areas);
	else
		log_debug_alloc("Areas to be sorted and filled sequentially.");

	_report_needed_allocation_space(ah, alloc_state, pvms);

	/* ix holds the number of areas found on other PVs */
	do {
		if (log_iteration_count) {
			log_debug_alloc("Found %u areas for %" PRIu32 " parallel areas and %" PRIu32 " log areas so far.", ix, devices_needed, alloc_state->log_area_count_still_needed);
		} else if (iteration_count)
			log_debug_alloc("Filled %u out of %u preferred areas so far.", preferred_count, alloc_state->num_positional_areas);

		/*
		 * Provide for escape from the loop if no progress is made.
		 * This should not happen: ALLOC_ANYWHERE should be able to use
		 * all available space. (If there aren't enough extents, the code
		 * should not reach this point.)
		 */
		last_ix = ix;

		/*
		 * Put the smallest area of each PV that is at least the
		 * size we need into areas array.  If there isn't one
		 * that fits completely and we're allowed more than one
		 * LV segment, then take the largest remaining instead.
		 */
		dm_list_iterate_items(pvm, pvms) {
			/* PV-level checks */
			if (dm_list_empty(&pvm->areas))
				continue;	/* Next PV */

			if (alloc_parms->alloc != ALLOC_ANYWHERE) {
				/* Don't allocate onto the log PVs */
				if (ah->log_area_count)
					dm_list_iterate_items(aa, &ah->alloced_areas[ah->area_count])
						for (s = 0; s < ah->log_area_count; s++)
							if (!aa[s].pv)
								goto next_pv;

				/* FIXME Split into log and non-log parallel_pvs and only check the log ones if log_iteration? */
				/* (I've temporatily disabled the check.) */
				/* Avoid PVs used by existing parallel areas */
				if (!log_iteration_count && parallel_pvs && _pv_is_parallel(pvm->pv, parallel_pvs))
					goto next_pv;

				/*
				 * Avoid PVs already set aside for log.  
				 * We only reach here if there were enough PVs for the main areas but
				 * not enough for the logs.
				 */
				if (log_iteration_count) {
					for (s = devices_needed; s < ix + alloc_state->num_positional_areas; s++)
						if (alloc_state->areas[s].pva && alloc_state->areas[s].pva->map->pv == pvm->pv)
							goto next_pv;
				/* On a second pass, avoid PVs already used in an uncommitted area */
				} else if (iteration_count)
					for (s = 0; s < devices_needed; s++)
						if (alloc_state->areas[s].pva && alloc_state->areas[s].pva->map->pv == pvm->pv)
							goto next_pv;
			}

			already_found_one = 0;
			/* First area in each list is the largest */
			dm_list_iterate_items(pva, &pvm->areas) {
				/*
				 * There are two types of allocations, which can't be mixed at present:
				 *
				 * PREFERRED are stored immediately in a specific parallel slot.
				 *   This is only used if the A_POSITIONAL_FILL flag is set.
				 *   This requires the number of slots to match, so if comparing with
				 *   prev_lvseg then A_AREA_COUNT_MATCHES must be set.
				 *
				 * USE_AREA are stored for later, then sorted and chosen from.
				 */
				switch(_check_pva(ah, pva, max_to_allocate, 
						  alloc_state, already_found_one, iteration_count, log_iteration_count)) {

				case PREFERRED:
					preferred_count++;
					/* Fall through */

				case NEXT_PV:
					goto next_pv;

				case NEXT_AREA:
					continue;

				case USE_AREA:
					/*
					 * Except with ALLOC_ANYWHERE, replace first area with this
					 * one which is smaller but still big enough.
					 */
					if (!already_found_one ||
					    alloc_parms->alloc == ALLOC_ANYWHERE) {
						ix++;
						already_found_one = 1;
					}

					/* Reserve required amount of pva */
					required = _calc_required_extents(ah, pva, ix + alloc_state->num_positional_areas - 1, max_to_allocate, alloc_parms->alloc);
					if (!_reserve_required_area(ah, alloc_state, pva, required, ix + alloc_state->num_positional_areas - 1, pva->unreserved))
						return_0;
				}

			}

		next_pv:
			/* With ALLOC_ANYWHERE we ignore further PVs once we have at least enough areas */
			/* With cling and contiguous we stop if we found a match for *all* the areas */
			/* FIXME Rename these variables! */
			if ((alloc_parms->alloc == ALLOC_ANYWHERE &&
			    ix + alloc_state->num_positional_areas >= devices_needed + alloc_state->log_area_count_still_needed) ||
			    (preferred_count == alloc_state->num_positional_areas &&
			     (alloc_state->num_positional_areas == devices_needed + alloc_state->log_area_count_still_needed)))
				break;
		}
	} while ((alloc_parms->alloc == ALLOC_ANYWHERE && last_ix != ix && ix < devices_needed + alloc_state->log_area_count_still_needed) ||
		/* With cling_to_alloced and normal, if there were gaps in the preferred areas, have a second iteration */
		 (alloc_parms->alloc == ALLOC_NORMAL && preferred_count &&
		  (preferred_count < alloc_state->num_positional_areas || alloc_state->log_area_count_still_needed) &&
		  (alloc_parms->flags & A_CLING_TO_ALLOCED) && !iteration_count++) ||
		/* Extra iteration needed to fill log areas on PVs already used? */
		 (alloc_parms->alloc == ALLOC_NORMAL && preferred_count == alloc_state->num_positional_areas && !ah->mirror_logs_separate &&
		  (ix + preferred_count >= devices_needed) &&
		  (ix + preferred_count < devices_needed + alloc_state->log_area_count_still_needed) && !log_iteration_count++));

	/* Non-zero ix means at least one USE_AREA was returned */
	if (preferred_count < alloc_state->num_positional_areas && !(alloc_parms->flags & A_CLING_TO_ALLOCED) && !ix)
		return 1;

	if (ix + preferred_count < devices_needed + alloc_state->log_area_count_still_needed)
		return 1;

	/* Sort the areas so we allocate from the biggest */
	if (log_iteration_count) {
		if (ix > devices_needed + 1) {
			log_debug_alloc("Sorting %u log areas", ix - devices_needed);
			qsort(alloc_state->areas + devices_needed, ix - devices_needed, sizeof(*alloc_state->areas),
			      _comp_area);
		}
	} else if (ix > 1) {
		log_debug_alloc("Sorting %u areas", ix);
		qsort(alloc_state->areas + alloc_state->num_positional_areas, ix, sizeof(*alloc_state->areas),
		      _comp_area);
	}

	/* If there are gaps in our preferred areas, fill them from the sorted part of the array */
	if (preferred_count && preferred_count != alloc_state->num_positional_areas) {
		for (s = 0; s < devices_needed; s++)
			if (!alloc_state->areas[s].pva) {
				alloc_state->areas[s].pva = alloc_state->areas[alloc_state->num_positional_areas].pva;
				alloc_state->areas[s].used = alloc_state->areas[alloc_state->num_positional_areas].used;
				alloc_state->areas[alloc_state->num_positional_areas++].pva = NULL;
			}
	}

	/*
	 * First time around, if there's a log, allocate it on the
	 * smallest device that has space for it.
	 */
	too_small_for_log_count = 0;
	ix_log_offset = 0;

	/* FIXME This logic is due to its heritage and can be simplified! */
	if (alloc_state->log_area_count_still_needed) {
		/* How many areas are too small for the log? */
		while (too_small_for_log_count < alloc_state->num_positional_areas + ix &&
		       (*(alloc_state->areas + alloc_state->num_positional_areas + ix - 1 -
			  too_small_for_log_count)).used < ah->log_len)
			too_small_for_log_count++;
		ix_log_offset = alloc_state->num_positional_areas + ix - too_small_for_log_count - ah->log_area_count;
	}

	if (ix + alloc_state->num_positional_areas < devices_needed +
	    (alloc_state->log_area_count_still_needed ? alloc_state->log_area_count_still_needed +
				    too_small_for_log_count : 0))
		return 1;

	/*
	 * FIXME We should change the code to do separate calls for the log allocation 
	 * and the data allocation so that _limit_to_one_area_per_tag doesn't have to guess
	 * where the split is going to occur.
	 */

	/*
	 * This code covers the initial allocation - after that there is something to 'cling' to
	 * and we shouldn't get this far.
	 * alloc_state->num_positional_areas is assumed to be 0 with A_PARTITION_BY_TAGS.
	 *
	 * FIXME Consider a second attempt with A_PARTITION_BY_TAGS if, for example, the largest area
	 * had all the tags set, but other areas don't.
	 */
	if ((alloc_parms->flags & A_PARTITION_BY_TAGS) && !alloc_state->num_positional_areas) {
		if (!_limit_to_one_area_per_tag(ah, alloc_state, ix_log_offset, &ix))
			return_0;

		/* Recalculate log position because we might have removed some areas from consideration */
		if (alloc_state->log_area_count_still_needed) {
			/* How many areas are too small for the log? */
			too_small_for_log_count = 0;
			while (too_small_for_log_count < ix &&
			       (*(alloc_state->areas + ix - 1 - too_small_for_log_count)).pva &&
			       (*(alloc_state->areas + ix - 1 - too_small_for_log_count)).used < ah->log_len)
				too_small_for_log_count++;
			if (ix < too_small_for_log_count + ah->log_area_count)
				return 1;
			ix_log_offset = ix - too_small_for_log_count - ah->log_area_count;
		}

		if (ix < devices_needed +
		    (alloc_state->log_area_count_still_needed ? alloc_state->log_area_count_still_needed +
					    too_small_for_log_count : 0))
			return 1;
	}

	/*
	 * Finally add the space identified to the list of areas to be used.
	 */
	if (!_alloc_parallel_area(ah, max_to_allocate, alloc_state, ix_log_offset))
		return_0;

	/*
	 * Log is always allocated first time.
	 */
	alloc_state->log_area_count_still_needed = 0;

	return 1;
}

/*
 * Choose sets of parallel areas to use, respecting any constraints 
 * supplied in alloc_parms.
 */
static int _find_max_parallel_space_for_one_policy(struct alloc_handle *ah, struct alloc_parms *alloc_parms,
						   struct dm_list *pvms, struct alloc_state *alloc_state)
{
	uint32_t max_tmp;
	uint32_t max_to_allocate;	/* Maximum extents to allocate this time */
	uint32_t old_allocated;
	uint32_t next_le;
	struct seg_pvs *spvs;
	struct dm_list *parallel_pvs;

	alloc_state->alloc_parms = alloc_parms;

	/* FIXME This algorithm needs a lot of cleaning up! */
	/* FIXME anywhere doesn't find all space yet */
	do {
		parallel_pvs = NULL;
		max_to_allocate = alloc_parms->extents_still_needed - alloc_state->allocated;

		/*
		 * If there are existing parallel PVs, avoid them and reduce
		 * the maximum we can allocate in one go accordingly.
		 */
		if (ah->parallel_areas) {
			next_le = (alloc_parms->prev_lvseg ? alloc_parms->prev_lvseg->le + alloc_parms->prev_lvseg->len : 0) + alloc_state->allocated / ah->area_multiple;
			dm_list_iterate_items(spvs, ah->parallel_areas) {
				if (next_le >= spvs->le + spvs->len)
					continue;

				max_tmp = max_to_allocate +
					alloc_state->allocated;

				/*
				 * Because a request that groups metadata and
				 * data together will be split, we must adjust
				 * the comparison accordingly.
				 */
				if (ah->alloc_and_split_meta && !ah->split_metadata_is_allocated)
					max_tmp -= ah->log_len;
				if (max_tmp > (spvs->le + spvs->len) * ah->area_multiple) {
					max_to_allocate = (spvs->le + spvs->len) * ah->area_multiple - alloc_state->allocated;
					max_to_allocate += (ah->alloc_and_split_meta && !ah->split_metadata_is_allocated) ? ah->log_len : 0;
				}
				parallel_pvs = &spvs->pvs;
				break;
			}
		}

		old_allocated = alloc_state->allocated;

		if (!_find_some_parallel_space(ah, pvms, alloc_state, parallel_pvs, max_to_allocate))
			return_0;

		/*
		 * For ALLOC_CLING, if the number of areas matches and maximise_cling is
		 * set we allow two passes, first with A_POSITIONAL_FILL then without.
		 *
		 * If we didn't allocate anything this time with ALLOC_NORMAL and had
		 * A_CLING_TO_ALLOCED set, try again without it.
		 *
		 * For ALLOC_NORMAL, if we did allocate something without the
		 * flag set, set it and continue so that further allocations
		 * remain on the same disks where possible.
		 */
		if (old_allocated == alloc_state->allocated) {
			if (ah->maximise_cling && ((alloc_parms->alloc == ALLOC_CLING) || (alloc_parms->alloc == ALLOC_CLING_BY_TAGS)) &&
			    (alloc_parms->flags & A_CLING_TO_LVSEG) && (alloc_parms->flags & A_POSITIONAL_FILL))
				alloc_parms->flags &= ~A_POSITIONAL_FILL;
			else if ((alloc_parms->alloc == ALLOC_NORMAL) && (alloc_parms->flags & A_CLING_TO_ALLOCED))
				alloc_parms->flags &= ~A_CLING_TO_ALLOCED;
			else
				break;	/* Give up */
		} else if (ah->maximise_cling && alloc_parms->alloc == ALLOC_NORMAL &&
			   !(alloc_parms->flags & A_CLING_TO_ALLOCED))
			alloc_parms->flags |= A_CLING_TO_ALLOCED;
	} while ((alloc_parms->alloc != ALLOC_CONTIGUOUS) && alloc_state->allocated != alloc_parms->extents_still_needed && (alloc_parms->flags & A_CAN_SPLIT) && (!ah->approx_alloc || pv_maps_size(pvms)));

	return 1;
}

/*
 * Allocate several segments, each the same size, in parallel.
 * If mirrored_pv and mirrored_pe are supplied, it is used as
 * the first area, and additional areas are allocated parallel to it.
 */
static int _allocate(struct alloc_handle *ah,
		     struct volume_group *vg,
		     struct logical_volume *lv,
		     unsigned can_split,
		     struct dm_list *allocatable_pvs)
{
	uint32_t old_allocated;
	struct lv_segment *prev_lvseg = NULL;
	int r = 0;
	struct dm_list *pvms;
	alloc_policy_t alloc;
	struct alloc_parms alloc_parms;
	struct alloc_state alloc_state;

	alloc_state.allocated = lv ? lv->le_count : 0;

	if (alloc_state.allocated >= ah->new_extents && !ah->log_area_count) {
		log_warn("_allocate called with no work to do!");
		return 1;
	}

        if (ah->area_multiple > 1 &&
            (ah->new_extents - alloc_state.allocated) % ah->area_multiple) {
		log_error("Number of extents requested (%d) needs to be divisible by %d.",
			  ah->new_extents - alloc_state.allocated,
			  ah->area_multiple);
		return 0;
	}

	alloc_state.log_area_count_still_needed = ah->log_area_count;

	if (ah->alloc == ALLOC_CONTIGUOUS)
		can_split = 0;

	if (lv && !dm_list_empty(&lv->segments))
		prev_lvseg = dm_list_item(dm_list_last(&lv->segments),
				       struct lv_segment);
	/*
	 * Build the sets of available areas on the pv's.
	 */
	if (!(pvms = create_pv_maps(ah->mem, vg, allocatable_pvs)))
		return_0;

	if (!_log_parallel_areas(ah->mem, ah->parallel_areas))
		stack;

	alloc_state.areas_size = dm_list_size(pvms);
	if (alloc_state.areas_size &&
	    alloc_state.areas_size < (ah->area_count + ah->parity_count + ah->log_area_count)) {
		if (ah->alloc != ALLOC_ANYWHERE && ah->mirror_logs_separate) {
			log_error("Not enough PVs with free space available "
				  "for parallel allocation.");
			log_error("Consider --alloc anywhere if desperate.");
			return 0;
		}
		alloc_state.areas_size = ah->area_count + ah->parity_count + ah->log_area_count;
	}

	/* Upper bound if none of the PVs in prev_lvseg is in pvms */
	/* FIXME Work size out properly */
	if (prev_lvseg)
		alloc_state.areas_size += _stripes_per_mimage(prev_lvseg) * prev_lvseg->area_count;

	/* Allocate an array of pv_areas to hold the largest space on each PV */
	if (!(alloc_state.areas = dm_malloc(sizeof(*alloc_state.areas) * alloc_state.areas_size))) {
		log_error("Couldn't allocate areas array.");
		return 0;
	}

	/*
	 * cling includes implicit cling_by_tags
	 * but it does nothing unless the lvm.conf setting is present.
	 */
	if (ah->alloc == ALLOC_CLING)
		ah->alloc = ALLOC_CLING_BY_TAGS;

	/* Attempt each defined allocation policy in turn */
	for (alloc = ALLOC_CONTIGUOUS; alloc <= ah->alloc; alloc++) {
		/* Skip cling_by_tags if no list defined */
		if (alloc == ALLOC_CLING_BY_TAGS && !ah->cling_tag_list_cn)
			continue;
		old_allocated = alloc_state.allocated;
		log_debug_alloc("Trying allocation using %s policy.", get_alloc_string(alloc));

		if (!ah->approx_alloc && !_sufficient_pes_free(ah, pvms, alloc_state.allocated, ah->new_extents))
			goto_out;

		_init_alloc_parms(ah, &alloc_parms, alloc, prev_lvseg,
				  can_split, alloc_state.allocated,
				  ah->new_extents);

		if (!_find_max_parallel_space_for_one_policy(ah, &alloc_parms, pvms, &alloc_state))
			goto_out;

		if ((alloc_state.allocated == ah->new_extents &&
		     !alloc_state.log_area_count_still_needed) ||
		    (!can_split && (alloc_state.allocated != old_allocated)))
			break;
	}

	if (alloc_state.allocated != ah->new_extents) {
		if (!ah->approx_alloc) {
			log_error("Insufficient suitable %sallocatable extents "
				  "for logical volume %s: %u more required",
				  can_split ? "" : "contiguous ",
				  lv ? lv->name : "",
				  (ah->new_extents - alloc_state.allocated) *
				  ah->area_count / ah->area_multiple);
			goto out;
		}
		if (!alloc_state.allocated) {
			log_error("Insufficient suitable %sallocatable extents "
				  "found for logical volume %s.",
				  can_split ? "" : "contiguous ",
				  lv ? lv->name : "");
			goto out;
		}
		log_verbose("Found fewer %sallocatable extents "
			    "for logical volume %s than requested: using %" PRIu32 " extents (reduced by %u).",
			    can_split ? "" : "contiguous ",
			    lv ? lv->name : "",
			    alloc_state.allocated,
			    (ah->new_extents - alloc_state.allocated) * ah->area_count / ah->area_multiple);
		ah->new_extents = alloc_state.allocated;
	}

	if (alloc_state.log_area_count_still_needed) {
		log_error("Insufficient free space for log allocation "
			  "for logical volume %s.",
			  lv ? lv->name : "");
		goto out;
	}

	r = 1;

      out:
	dm_free(alloc_state.areas);
	return r;
}

int lv_add_virtual_segment(struct logical_volume *lv, uint64_t status,
			   uint32_t extents, const struct segment_type *segtype)
{
	struct lv_segment *seg;

	if (!dm_list_empty(&lv->segments) &&
	    (seg = last_seg(lv)) && (seg->segtype == segtype)) {
		seg->area_len += extents;
		seg->len += extents;
	} else {
		if (!(seg = alloc_lv_segment(segtype, lv, lv->le_count, extents,
					     status, 0, NULL, 0,
					     extents, 0, 0, 0, NULL))) {
			log_error("Couldn't allocate new %s segment.", segtype->name);
			return 0;
		}
		lv->status |= VIRTUAL;
		dm_list_add(&lv->segments, &seg->list);
	}

	lv->le_count += extents;
	lv->size += (uint64_t) extents *lv->vg->extent_size;

	return 1;
}

/*
 * Preparation for a specific allocation attempt
 * stripes and mirrors refer to the parallel areas used for data.
 * If log_area_count > 1 it is always mirrored (not striped).
 */
static struct alloc_handle *_alloc_init(struct cmd_context *cmd,
					struct dm_pool *mem,
					const struct segment_type *segtype,
					alloc_policy_t alloc, int approx_alloc,
					uint32_t existing_extents,
					uint32_t new_extents,
					uint32_t mirrors,
					uint32_t stripes,
					uint32_t metadata_area_count,
					uint32_t extent_size,
					uint32_t region_size,
					struct dm_list *parallel_areas)
{
	struct alloc_handle *ah;
	uint32_t s, area_count, alloc_count, parity_count, total_extents;
	size_t size = 0;

	/* FIXME Caller should ensure this */
	if (mirrors && !stripes)
		stripes = 1;

	if (segtype_is_virtual(segtype))
		area_count = 0;
	else if (mirrors > 1)
		area_count = mirrors * stripes;
	else
		area_count = stripes;

	size = sizeof(*ah);

	/*
	 * It is a requirement that RAID 4/5/6 are created with a number of
	 * stripes that is greater than the number of parity devices.  (e.g
	 * RAID4/5 must have at least 2 stripes and RAID6 must have at least
	 * 3.)  It is also a constraint that, when replacing individual devices
	 * in a RAID 4/5/6 array, no more devices can be replaced than
	 * there are parity devices.  (Otherwise, there would not be enough
	 * redundancy to maintain the array.)  Understanding these two
	 * constraints allows us to infer whether the caller of this function
	 * is intending to allocate an entire array or just replacement
	 * component devices.  In the former case, we must account for the
	 * necessary parity_count.  In the later case, we do not need to
	 * account for the extra parity devices because the array already
	 * exists and they only want replacement drives.
	 */
	parity_count = (area_count <= segtype->parity_devs) ? 0 : segtype->parity_devs;
	alloc_count = area_count + parity_count;
	if (segtype_is_raid(segtype) && metadata_area_count)
		/* RAID has a meta area for each device */
		alloc_count *= 2;
	else
		/* mirrors specify their exact log count */
		alloc_count += metadata_area_count;

	size += sizeof(ah->alloced_areas[0]) * alloc_count;

	if (!(ah = dm_pool_zalloc(mem, size))) {
		log_error("allocation handle allocation failed");
		return NULL;
	}

	ah->cmd = cmd;

	if (segtype_is_virtual(segtype))
		return ah;

	if (!(area_count + metadata_area_count)) {
		log_error(INTERNAL_ERROR "_alloc_init called for non-virtual segment with no disk space.");
		return NULL;
	}

	if (!(ah->mem = dm_pool_create("allocation", 1024))) {
		log_error("allocation pool creation failed");
		return NULL;
	}

	ah->area_count = area_count;
	ah->parity_count = parity_count;
	ah->region_size = region_size;
	ah->alloc = alloc;

	/*
	 * For the purposes of allocation, area_count and parity_count are
	 * kept separately.  However, the 'area_count' field in an
	 * lv_segment includes both; and this is what '_calc_area_multiple'
	 * is calculated from.  So, we must pass in the total count to get
	 * a correct area_multiple.
	 */
	ah->area_multiple = _calc_area_multiple(segtype, area_count + parity_count, stripes);
	//FIXME: s/mirror_logs_separate/metadata_separate/ so it can be used by others?
	ah->mirror_logs_separate = find_config_tree_bool(cmd, allocation_mirror_logs_require_separate_pvs_CFG, NULL);

	if (mirrors || stripes)
		total_extents = new_extents;
	else
		total_extents = 0;

	if (segtype_is_raid(segtype)) {
		if (metadata_area_count) {
			if (metadata_area_count != area_count)
				log_error(INTERNAL_ERROR
					  "Bad metadata_area_count");
			ah->metadata_area_count = area_count;
			ah->alloc_and_split_meta = 1;

			ah->log_len = RAID_METADATA_AREA_LEN;

			/*
			 * We need 'log_len' extents for each
			 * RAID device's metadata_area
			 */
			total_extents += (ah->log_len * ah->area_multiple);
		} else {
			ah->log_area_count = 0;
			ah->log_len = 0;
		}
	} else if (segtype_is_thin_pool(segtype)) {
		/*
		 * thin_pool uses ah->region_size to
		 * pass metadata size in extents
		 */
		ah->log_len = ah->region_size;
		ah->log_area_count = metadata_area_count;
		ah->region_size = 0;
		ah->mirror_logs_separate =
			find_config_tree_bool(cmd, allocation_thin_pool_metadata_require_separate_pvs_CFG, NULL);
	} else if (segtype_is_cache_pool(segtype)) {
		/*
		 * Like thin_pool, cache_pool uses ah->region_size to
		 * pass metadata size in extents
		 */
		ah->log_len = ah->region_size;
		/* use metadata_area_count, not log_area_count */
		ah->metadata_area_count = metadata_area_count;
		ah->region_size = 0;
		ah->mirror_logs_separate =
			find_config_tree_bool(cmd, allocation_cache_pool_metadata_require_separate_pvs_CFG, NULL);
		if (!ah->mirror_logs_separate) {
			ah->alloc_and_split_meta = 1;
			total_extents += ah->log_len;
		}
	} else {
		ah->log_area_count = metadata_area_count;
		ah->log_len = !metadata_area_count ? 0 :
			mirror_log_extents(ah->region_size, extent_size,
					   (existing_extents + total_extents) / ah->area_multiple);
	}

	log_debug("Adjusted allocation request to %" PRIu32 " logical extents. Existing size %" PRIu32 ". New size %" PRIu32 ".",
		  total_extents, existing_extents, total_extents + existing_extents);

	if (mirrors || stripes)
		total_extents += existing_extents;

	ah->new_extents = total_extents;

	for (s = 0; s < alloc_count; s++)
		dm_list_init(&ah->alloced_areas[s]);

	ah->parallel_areas = parallel_areas;

	if ((ah->cling_tag_list_cn = find_config_tree_array(cmd, allocation_cling_tag_list_CFG, NULL)))
		(void) _validate_tag_list(ah->cling_tag_list_cn);

	ah->maximise_cling = find_config_tree_bool(cmd, allocation_maximise_cling_CFG, NULL);

	ah->approx_alloc = approx_alloc;

	return ah;
}

void alloc_destroy(struct alloc_handle *ah)
{
	if (ah->mem)
		dm_pool_destroy(ah->mem);
}

/*
 * Entry point for all extent allocations.
 */
struct alloc_handle *allocate_extents(struct volume_group *vg,
				      struct logical_volume *lv,
				      const struct segment_type *segtype,
				      uint32_t stripes,
				      uint32_t mirrors, uint32_t log_count,
				      uint32_t region_size, uint32_t extents,
				      struct dm_list *allocatable_pvs,
				      alloc_policy_t alloc, int approx_alloc,
				      struct dm_list *parallel_areas)
{
	struct alloc_handle *ah;

	if (segtype_is_virtual(segtype)) {
		log_error("allocate_extents does not handle virtual segments");
		return NULL;
	}

	if (!allocatable_pvs) {
		log_error(INTERNAL_ERROR "Missing allocatable pvs.");
		return NULL;
	}

	if (vg->fid->fmt->ops->segtype_supported &&
	    !vg->fid->fmt->ops->segtype_supported(vg->fid, segtype)) {
		log_error("Metadata format (%s) does not support required "
			  "LV segment type (%s).", vg->fid->fmt->name,
			  segtype->name);
		log_error("Consider changing the metadata format by running "
			  "vgconvert.");
		return NULL;
	}

	if (alloc >= ALLOC_INHERIT)
		alloc = vg->alloc;

	if (!(ah = _alloc_init(vg->cmd, vg->vgmem, segtype, alloc, approx_alloc,
			       lv ? lv->le_count : 0, extents, mirrors, stripes, log_count,
			       vg->extent_size, region_size,
			       parallel_areas)))
		return_NULL;

	if (!_allocate(ah, vg, lv, 1, allocatable_pvs)) {
		alloc_destroy(ah);
		return_NULL;
	}

	return ah;
}

/*
 * Add new segments to an LV from supplied list of areas.
 */
int lv_add_segment(struct alloc_handle *ah,
		   uint32_t first_area, uint32_t num_areas,
		   struct logical_volume *lv,
		   const struct segment_type *segtype,
		   uint32_t stripe_size,
		   uint64_t status,
		   uint32_t region_size)
{
	if (!segtype) {
		log_error("Missing segtype in lv_add_segment().");
		return 0;
	}

	if (segtype_is_virtual(segtype)) {
		log_error("lv_add_segment cannot handle virtual segments");
		return 0;
	}

	if ((status & MIRROR_LOG) && !dm_list_empty(&lv->segments)) {
		log_error("Log segments can only be added to an empty LV");
		return 0;
	}

	if (!_setup_alloced_segments(lv, &ah->alloced_areas[first_area],
				     num_areas, status,
				     stripe_size, segtype,
				     region_size))
		return_0;

	if ((segtype->flags & SEG_CAN_SPLIT) && !lv_merge_segments(lv)) {
		log_error("Couldn't merge segments after extending "
			  "logical volume.");
		return 0;
	}

	if (lv->vg->fid->fmt->ops->lv_setup &&
	    !lv->vg->fid->fmt->ops->lv_setup(lv->vg->fid, lv))
		return_0;

	return 1;
}

/*
 * "mirror" segment type doesn't support split.
 * So, when adding mirrors to linear LV segment, first split it,
 * then convert it to "mirror" and add areas.
 */
static struct lv_segment *_convert_seg_to_mirror(struct lv_segment *seg,
						 uint32_t region_size,
						 struct logical_volume *log_lv)
{
	struct lv_segment *newseg;
	uint32_t s;

	if (!seg_is_striped(seg)) {
		log_error("Can't convert non-striped segment to mirrored.");
		return NULL;
	}

	if (seg->area_count > 1) {
		log_error("Can't convert striped segment with multiple areas "
			  "to mirrored.");
		return NULL;
	}

	if (!(newseg = alloc_lv_segment(get_segtype_from_string(seg->lv->vg->cmd, "mirror"),
					seg->lv, seg->le, seg->len,
					seg->status, seg->stripe_size,
					log_lv,
					seg->area_count, seg->area_len,
					seg->chunk_size, region_size,
					seg->extents_copied, NULL))) {
		log_error("Couldn't allocate converted LV segment");
		return NULL;
	}

	for (s = 0; s < seg->area_count; s++)
		if (!move_lv_segment_area(newseg, s, seg, s))
			return_NULL;

	seg->pvmove_source_seg = NULL; /* Not maintained after allocation */

	dm_list_add(&seg->list, &newseg->list);
	dm_list_del(&seg->list);

	return newseg;
}

/*
 * Add new areas to mirrored segments
 */
int lv_add_segmented_mirror_image(struct alloc_handle *ah,
				  struct logical_volume *lv, uint32_t le,
				  uint32_t region_size)
{
	char *image_name;
	struct alloced_area *aa;
	struct lv_segment *seg, *new_seg;
	uint32_t current_le = le;
	uint32_t s;
	struct segment_type *segtype;
	struct logical_volume *orig_lv, *copy_lv;

	if (!lv_is_pvmove(lv)) {
		log_error(INTERNAL_ERROR
			  "Non-pvmove LV, %s, passed as argument", lv->name);
		return 0;
	}

	if (seg_type(first_seg(lv), 0) != AREA_PV) {
		log_error(INTERNAL_ERROR
			  "Bad segment type for first segment area");
		return 0;
	}

	/*
	 * If the allocator provided two or more PV allocations for any
	 * single segment of the original LV, that LV segment must be
	 * split up to match.
	 */
	dm_list_iterate_items(aa, &ah->alloced_areas[0]) {
		if (!(seg = find_seg_by_le(lv, current_le))) {
			log_error("Failed to find segment for %s extent %"
				  PRIu32, lv->name, current_le);
			return 0;
		}

		/* Allocator assures aa[0].len <= seg->area_len */
		if (aa[0].len < seg->area_len) {
			if (!lv_split_segment(lv, seg->le + aa[0].len)) {
				log_error("Failed to split segment at %s "
					  "extent %" PRIu32, lv->name, le);
				return 0;
			}
		}
		current_le += seg->area_len;
	}

	current_le = le;

	if (!insert_layer_for_lv(lv->vg->cmd, lv, PVMOVE, "_mimage_0")) {
		log_error("Failed to build pvmove LV-type mirror, %s",
			  lv->name);
		return 0;
	}
	orig_lv = seg_lv(first_seg(lv), 0);
	if (!(image_name = dm_pool_strdup(lv->vg->vgmem, orig_lv->name)))
		return_0;
	image_name[strlen(image_name) - 1] = '1';

	if (!(copy_lv = lv_create_empty(image_name, NULL,
					orig_lv->status,
					ALLOC_INHERIT, lv->vg)))
		return_0;

	if (!lv_add_mirror_lvs(lv, &copy_lv, 1, MIRROR_IMAGE, region_size))
		return_0;

	if (!(segtype = get_segtype_from_string(lv->vg->cmd, "striped")))
		return_0;

	dm_list_iterate_items(aa, &ah->alloced_areas[0]) {
		if (!(seg = find_seg_by_le(orig_lv, current_le))) {
			log_error("Failed to find segment for %s extent %"
				  PRIu32, lv->name, current_le);
			return 0;
		}

		if (!(new_seg = alloc_lv_segment(segtype, copy_lv,
						 seg->le, seg->len, PVMOVE, 0,
						 NULL, 1, seg->len,
						 0, 0, 0, NULL)))
			return_0;

		for (s = 0; s < ah->area_count; s++) {
			if (!set_lv_segment_area_pv(new_seg, s,
						    aa[s].pv, aa[s].pe))
				return_0;
		}

		dm_list_add(&copy_lv->segments, &new_seg->list);

		current_le += seg->area_len;
		copy_lv->le_count += seg->area_len;
	}
	lv->status |= MIRRORED;

	/* FIXME: add log */

	if (lv->vg->fid->fmt->ops->lv_setup &&
	    !lv->vg->fid->fmt->ops->lv_setup(lv->vg->fid, lv))
		return_0;

	return 1;
}

/*
 * Add new areas to mirrored segments
 */
int lv_add_mirror_areas(struct alloc_handle *ah,
			struct logical_volume *lv, uint32_t le,
			uint32_t region_size)
{
	struct alloced_area *aa;
	struct lv_segment *seg;
	uint32_t current_le = le;
	uint32_t s, old_area_count, new_area_count;

	dm_list_iterate_items(aa, &ah->alloced_areas[0]) {
		if (!(seg = find_seg_by_le(lv, current_le))) {
			log_error("Failed to find segment for %s extent %"
				  PRIu32, lv->name, current_le);
			return 0;
		}

		/* Allocator assures aa[0].len <= seg->area_len */
		if (aa[0].len < seg->area_len) {
			if (!lv_split_segment(lv, seg->le + aa[0].len)) {
				log_error("Failed to split segment at %s "
					  "extent %" PRIu32, lv->name, le);
				return 0;
			}
		}

		if (!seg_is_mirrored(seg) &&
		    (!(seg = _convert_seg_to_mirror(seg, region_size, NULL))))
			return_0;

		old_area_count = seg->area_count;
		new_area_count = old_area_count + ah->area_count;

		if (!_lv_segment_add_areas(lv, seg, new_area_count))
			return_0;

		for (s = 0; s < ah->area_count; s++) {
			if (!set_lv_segment_area_pv(seg, s + old_area_count,
						    aa[s].pv, aa[s].pe))
				return_0;
		}

		current_le += seg->area_len;
	}

	lv->status |= MIRRORED;

	if (lv->vg->fid->fmt->ops->lv_setup &&
	    !lv->vg->fid->fmt->ops->lv_setup(lv->vg->fid, lv))
		return_0;

	return 1;
}

/*
 * Add mirror image LVs to mirrored segments
 */
int lv_add_mirror_lvs(struct logical_volume *lv,
		      struct logical_volume **sub_lvs,
		      uint32_t num_extra_areas,
		      uint64_t status, uint32_t region_size)
{
	struct lv_segment *seg;
	uint32_t old_area_count, new_area_count;
	uint32_t m;
	struct segment_type *mirror_segtype;

	seg = first_seg(lv);

	if (dm_list_size(&lv->segments) != 1 || seg_type(seg, 0) != AREA_LV) {
		log_error("Mirror layer must be inserted before adding mirrors");
		return 0;
	}

	mirror_segtype = get_segtype_from_string(lv->vg->cmd, "mirror");
	if (seg->segtype != mirror_segtype)
		if (!(seg = _convert_seg_to_mirror(seg, region_size, NULL)))
			return_0;

	if (region_size && region_size != seg->region_size) {
		log_error("Conflicting region_size");
		return 0;
	}

	old_area_count = seg->area_count;
	new_area_count = old_area_count + num_extra_areas;

	if (!_lv_segment_add_areas(lv, seg, new_area_count)) {
		log_error("Failed to allocate widened LV segment for %s.",
			  lv->name);
		return 0;
	}

	for (m = 0; m < old_area_count; m++)
		seg_lv(seg, m)->status |= status;

	for (m = old_area_count; m < new_area_count; m++) {
		if (!set_lv_segment_area_lv(seg, m, sub_lvs[m - old_area_count],
					    0, status))
			return_0;
		lv_set_hidden(sub_lvs[m - old_area_count]);
	}

	lv->status |= MIRRORED;

	return 1;
}

/*
 * Turn an empty LV into a mirror log.
 *
 * FIXME: Mirrored logs are built inefficiently.
 * A mirrored log currently uses the same layout that a mirror
 * LV uses.  The mirror layer sits on top of AREA_LVs which form the
 * legs, rather on AREA_PVs.  This is done to allow re-use of the
 * various mirror functions to also handle the mirrored LV that makes
 * up the log.
 *
 * If we used AREA_PVs under the mirror layer of a log, we could
 * assemble it all at once by calling 'lv_add_segment' with the
 * appropriate segtype (mirror/stripe), like this:
 *	lv_add_segment(ah, ah->area_count, ah->log_area_count,
 *		       log_lv, segtype, 0, MIRROR_LOG, 0);
 *
 * For now, we use the same mechanism to build a mirrored log as we
 * do for building a mirrored LV: 1) create initial LV, 2) add a
 * mirror layer, and 3) add the remaining copy LVs
 */
int lv_add_log_segment(struct alloc_handle *ah, uint32_t first_area,
		       struct logical_volume *log_lv, uint64_t status)
{

	return lv_add_segment(ah, ah->area_count + first_area, 1, log_lv,
			      get_segtype_from_string(log_lv->vg->cmd,
						      "striped"),
			      0, status, 0);
}

static int _lv_insert_empty_sublvs(struct logical_volume *lv,
				   const struct segment_type *segtype,
				   uint32_t stripe_size, uint32_t region_size,
				   uint32_t devices)
{
	struct logical_volume *sub_lv;
	uint32_t i;
	uint64_t sub_lv_status = 0;
	const char *layer_name;
	size_t len = strlen(lv->name) + 32;
	char img_name[len];
	struct lv_segment *mapseg;

	if (lv->le_count || !dm_list_empty(&lv->segments)) {
		log_error(INTERNAL_ERROR
			  "Non-empty LV passed to _lv_insert_empty_sublv");
		return 0;
	}

	if (segtype_is_raid(segtype)) {
		lv->status |= RAID;
		sub_lv_status = RAID_IMAGE;
		layer_name = "rimage";
	} else if (segtype_is_mirrored(segtype)) {
		lv->status |= MIRRORED;
		sub_lv_status = MIRROR_IMAGE;
		layer_name = "mimage";
	} else
		return_0;

	/*
	 * First, create our top-level segment for our top-level LV
	 */
	if (!(mapseg = alloc_lv_segment(segtype, lv, 0, 0, lv->status,
					stripe_size, NULL,
					devices, 0, 0, region_size, 0, NULL))) {
		log_error("Failed to create mapping segment for %s", lv->name);
		return 0;
	}

	/*
	 * Next, create all of our sub_lv's and link them in.
	 */
	for (i = 0; i < devices; i++) {
		/* Data LVs */
		if (devices > 1) {
			if (dm_snprintf(img_name, len, "%s_%s_%u",
					lv->name, layer_name, i) < 0)
				return_0;
		} else {
			if (dm_snprintf(img_name, len, "%s_%s",
					lv->name, layer_name) < 0)
				return_0;
		}

		/* FIXME Should use ALLOC_INHERIT here and inherit from parent LV */
		if (!(sub_lv = lv_create_empty(img_name, NULL,
					 LVM_READ | LVM_WRITE,
					 lv->alloc, lv->vg)))
			return_0;

		if (!set_lv_segment_area_lv(mapseg, i, sub_lv, 0, sub_lv_status))
			return_0;

		/* Metadata LVs for raid */
		if (segtype_is_raid(segtype)) {
			if (dm_snprintf(img_name, len, "%s_rmeta_%u", lv->name, i) < 0)
				return_0;
		} else
			continue;

		/* FIXME Should use ALLOC_INHERIT here and inherit from parent LV */
		if (!(sub_lv = lv_create_empty(img_name, NULL,
					       LVM_READ | LVM_WRITE,
					       lv->alloc, lv->vg)))
			return_0;

		if (!set_lv_segment_area_lv(mapseg, i, sub_lv, 0, RAID_META))
				return_0;
	}

	dm_list_add(&lv->segments, &mapseg->list);

	return 1;
}

static int _lv_extend_layered_lv(struct alloc_handle *ah,
				 struct logical_volume *lv,
				 uint32_t extents, uint32_t first_area,
				 uint32_t stripes, uint32_t stripe_size)
{
	const struct segment_type *segtype;
	struct logical_volume *sub_lv, *meta_lv;
	struct lv_segment *seg;
	uint32_t fa, s;
	int clear_metadata = 0;

	segtype = get_segtype_from_string(lv->vg->cmd, "striped");

	/*
	 * The component devices of a "striped" LV all go in the same
	 * LV.  However, RAID has an LV for each device - making the
	 * 'stripes' and 'stripe_size' parameters meaningless.
	 */
	if (seg_is_raid(first_seg(lv))) {
		stripes = 1;
		stripe_size = 0;
	}

	seg = first_seg(lv);
	for (fa = first_area, s = 0; s < seg->area_count; s++) {
		if (is_temporary_mirror_layer(seg_lv(seg, s))) {
			if (!_lv_extend_layered_lv(ah, seg_lv(seg, s), extents,
						   fa, stripes, stripe_size))
				return_0;
			fa += lv_mirror_count(seg_lv(seg, s));
			continue;
		}

		sub_lv = seg_lv(seg, s);
		if (!lv_add_segment(ah, fa, stripes, sub_lv, segtype,
				    stripe_size, sub_lv->status, 0)) {
			log_error("Aborting. Failed to extend %s in %s.",
				  sub_lv->name, lv->name);
			return 0;
		}

		/* Extend metadata LVs only on initial creation */
		if (seg_is_raid(seg) && !lv->le_count) {
			if (!seg->meta_areas) {
				log_error("No meta_areas for RAID type");
				return 0;
			}

			meta_lv = seg_metalv(seg, s);
			if (!lv_add_segment(ah, fa + seg->area_count, 1,
					    meta_lv, segtype, 0,
					    meta_lv->status, 0)) {
				log_error("Failed to extend %s in %s.",
					  meta_lv->name, lv->name);
				return 0;
			}
			lv_set_visible(meta_lv);
			clear_metadata = 1;
		}

		fa += stripes;
	}

	if (clear_metadata) {
		/*
		 * We must clear the metadata areas upon creation.
		 */
		if (!vg_write(lv->vg) || !vg_commit(lv->vg))
			return_0;

		for (s = 0; s < seg->area_count; s++) {
			meta_lv = seg_metalv(seg, s);

			if (test_mode()) {
				lv_set_hidden(meta_lv);
				continue;
			}

			/* For clearing, simply activate locally */
			if (!activate_lv_local(meta_lv->vg->cmd, meta_lv)) {
				log_error("Failed to activate %s/%s for clearing",
					  meta_lv->vg->name, meta_lv->name);
				return 0;
			}

			log_verbose("Clearing metadata area of %s/%s",
				    meta_lv->vg->name, meta_lv->name);
			/*
			 * Rather than wiping meta_lv->size, we can simply
			 * wipe '1' to remove the superblock of any previous
			 * RAID devices.  It is much quicker.
			 */
			if (!wipe_lv(meta_lv, (struct wipe_params)
				     { .do_zero = 1, .zero_sectors = 1 })) {
				log_error("Failed to zero %s/%s",
					  meta_lv->vg->name, meta_lv->name);
				return 0;
			}

			if (!deactivate_lv(meta_lv->vg->cmd, meta_lv)) {
				log_error("Failed to deactivate %s/%s",
					  meta_lv->vg->name, meta_lv->name);
				return 0;
			}
			lv_set_hidden(meta_lv);
		}
	}

	seg->area_len += extents;
	seg->len += extents;
	lv->le_count += extents;
	lv->size += (uint64_t) extents * lv->vg->extent_size;

	/*
	 * The MD bitmap is limited to being able to track 2^21 regions.
	 * The region_size must be adjusted to meet that criteria.
	 */
	while (seg_is_raid(seg) && (seg->region_size < (lv->size / (1 << 21)))) {
		seg->region_size *= 2;
		log_very_verbose("Adjusting RAID region_size from %uS to %uS"
				 " to support large LV size",
				 seg->region_size/2, seg->region_size);
	}

	return 1;
}

/*
 * Entry point for single-step LV allocation + extension.
 * Extents is the number of logical extents to append to the LV unless
 * approx_alloc is set when it is an upper limit for the total number of
 * extents to use from the VG.
 *
 * FIXME The approx_alloc raid/stripe conversion should be performed
 * before calling this function.
 */
int lv_extend(struct logical_volume *lv,
	      const struct segment_type *segtype,
	      uint32_t stripes, uint32_t stripe_size,
	      uint32_t mirrors, uint32_t region_size,
	      uint32_t extents,
	      struct dm_list *allocatable_pvs, alloc_policy_t alloc,
	      int approx_alloc)
{
	int r = 1;
	int log_count = 0;
	struct alloc_handle *ah;
	uint32_t sub_lv_count;
	uint32_t old_extents;
	uint32_t new_extents;	/* Total logical size after extension. */

	log_very_verbose("Adding segment of type %s to LV %s.", segtype->name, lv->name);

	if (segtype_is_virtual(segtype))
		return lv_add_virtual_segment(lv, 0u, extents, segtype);

	if (!lv->le_count && segtype_is_pool(segtype)) {
		/*
		 * Pool allocations treat the metadata device like a mirror log.
		 */
		/* FIXME Support striped metadata pool */
		log_count = 1;
	} else if (segtype_is_raid(segtype) && !lv->le_count)
		log_count = mirrors * stripes;
	/* FIXME log_count should be 1 for mirrors */

	if (!(ah = allocate_extents(lv->vg, lv, segtype, stripes, mirrors,
				    log_count, region_size, extents,
				    allocatable_pvs, alloc, approx_alloc, NULL)))
		return_0;

	new_extents = ah->new_extents;
	if (segtype_is_raid(segtype))
		new_extents -= ah->log_len * ah->area_multiple;

	if (segtype_is_pool(segtype)) {
		if (!(r = create_pool(lv, segtype, ah, stripes, stripe_size)))
			stack;
	} else if (!segtype_is_mirrored(segtype) && !segtype_is_raid(segtype)) {
		if (!(r = lv_add_segment(ah, 0, ah->area_count, lv, segtype,
					 stripe_size, 0u, 0)))
			stack;
	} else {
		/*
		 * For RAID, all the devices are AREA_LV.
		 * However, for 'mirror on stripe' using non-RAID targets,
		 * the mirror legs are AREA_LV while the stripes underneath
		 * are AREA_PV.
		 */
		if (segtype_is_raid(segtype))
			sub_lv_count = mirrors * stripes + segtype->parity_devs;
		else
			sub_lv_count = mirrors;

		old_extents = lv->le_count;

		if (!lv->le_count &&
		    !(r = _lv_insert_empty_sublvs(lv, segtype, stripe_size,
						  region_size, sub_lv_count))) {
			log_error("Failed to insert layer for %s", lv->name);
			goto out;
		}

		if (!(r = _lv_extend_layered_lv(ah, lv, new_extents - lv->le_count, 0,
						stripes, stripe_size)))
			goto_out;

		/*
		 * If we are expanding an existing mirror, we can skip the
		 * resync of the extension if the LV is currently in-sync
		 * and the LV has the LV_NOTSYNCED flag set.
		 */
		if (old_extents &&
		    segtype_is_mirrored(segtype) &&
		    (lv->status & LV_NOTSYNCED)) {
			dm_percent_t sync_percent = DM_PERCENT_INVALID;

			if (!lv_is_active_locally(lv)) {
				log_error("%s/%s is not active locally."
					  "  Unable to get sync percent.",
					  lv->vg->name, lv->name);
				/* FIXME Support --force */
				if (yes_no_prompt("Do full resync of extended "
						  "portion of %s/%s?  [y/n]: ",
						  lv->vg->name, lv->name) == 'n') {
					r = 0;
					goto_out;
				}
				goto out;
			}

			if (!(r = lv_mirror_percent(lv->vg->cmd, lv, 0,
						    &sync_percent, NULL))) {
				log_error("Failed to get sync percent for %s/%s",
					  lv->vg->name, lv->name);
				goto out;
			} else if (sync_percent == DM_PERCENT_100) {
				log_verbose("Skipping initial resync for "
					    "extended portion of %s/%s",
					    lv->vg->name, lv->name);
				init_mirror_in_sync(1);
				lv->status |= LV_NOTSYNCED;
			} else {
				log_error("%s/%s cannot be extended while"
					  " it is recovering.",
					  lv->vg->name, lv->name);
				r = 0;
				goto out;
			}
		}
	}

out:
	alloc_destroy(ah);
	return r;
}

/*
 * Minimal LV renaming function.
 * Metadata transaction should be made by caller.
 * Assumes new_name is allocated from cmd->mem pool.
 */
static int _rename_single_lv(struct logical_volume *lv, char *new_name)
{
	struct volume_group *vg = lv->vg;

	if (find_lv_in_vg(vg, new_name)) {
		log_error("Logical volume \"%s\" already exists in "
			  "volume group \"%s\"", new_name, vg->name);
		return 0;
	}

	if (lv_is_locked(lv)) {
		log_error("Cannot rename locked LV %s", lv->name);
		return 0;
	}

	lv->name = new_name;

	return 1;
}

/*
 * Rename sub LV.
 * 'lv_name_old' and 'lv_name_new' are old and new names of the main LV.
 */
static int _rename_sub_lv(struct logical_volume *lv,
			  const char *lv_name_old, const char *lv_name_new)
{
	const char *suffix;
	char *new_name;
	size_t len;

	/*
	 * A sub LV name starts with lv_name_old + '_'.
	 * The suffix follows lv_name_old and includes '_'.
	 */
	len = strlen(lv_name_old);
	if (strncmp(lv->name, lv_name_old, len) || lv->name[len] != '_') {
		log_error("Cannot rename \"%s\": name format not recognized "
			  "for internal LV \"%s\"",
			  lv_name_old, lv->name);
		return 0;
	}
	suffix = lv->name + len;

	/*
	 * Compose a new name for sub lv:
	 *   e.g. new name is "lvol1_mlog"
	 *	if the sub LV is "lvol0_mlog" and
	 *	a new name for main LV is "lvol1"
	 */
	len = strlen(lv_name_new) + strlen(suffix) + 1;
	new_name = dm_pool_alloc(lv->vg->vgmem, len);
	if (!new_name) {
		log_error("Failed to allocate space for new name");
		return 0;
	}
	if (dm_snprintf(new_name, len, "%s%s", lv_name_new, suffix) < 0) {
		log_error("Failed to create new name");
		return 0;
	}

	if (!validate_name(new_name)) {
		log_error("Cannot rename \"%s\". New logical volume name \"%s\" is invalid.",
			  lv->name, new_name);
		return 0;
	}

	/* Rename it */
	return _rename_single_lv(lv, new_name);
}

/* Callback for for_each_sub_lv */
static int _rename_cb(struct logical_volume *lv, void *data)
{
	struct lv_names *lv_names = (struct lv_names *) data;

	return _rename_sub_lv(lv, lv_names->old, lv_names->new);
}

/*
 * Loop down sub LVs and call fn for each.
 * fn is responsible to log necessary information on failure.
 */
static int _for_each_sub_lv(struct logical_volume *lv, int skip_pools,
			    int (*fn)(struct logical_volume *lv, void *data),
			    void *data)
{
	struct logical_volume *org;
	struct lv_segment *seg;
	uint32_t s;

	if (lv_is_cow(lv) && lv_is_virtual_origin(org = origin_from_cow(lv))) {
		if (!fn(org, data))
			return_0;
		if (!for_each_sub_lv(org, fn, data))
			return_0;
	}

	dm_list_iterate_items(seg, &lv->segments) {
		if (seg->log_lv) {
			if (!fn(seg->log_lv, data))
				return_0;
			if (!for_each_sub_lv(seg->log_lv, fn, data))
				return_0;
		}

		if (seg->metadata_lv) {
			if (!fn(seg->metadata_lv, data))
				return_0;
			if (!for_each_sub_lv(seg->metadata_lv, fn, data))
				return_0;
		}

		if (seg->pool_lv && !skip_pools) {
			if (!fn(seg->pool_lv, data))
				return_0;
			if (!for_each_sub_lv(seg->pool_lv, fn, data))
				return_0;
		}

		for (s = 0; s < seg->area_count; s++) {
			if (seg_type(seg, s) != AREA_LV)
				continue;
			if (!fn(seg_lv(seg, s), data))
				return_0;
			if (!for_each_sub_lv(seg_lv(seg, s), fn, data))
				return_0;
		}

		if (!seg_is_raid(seg))
			continue;

		/* RAID has meta_areas */
		for (s = 0; s < seg->area_count; s++) {
			if (seg_metatype(seg, s) != AREA_LV)
				continue;
			if (!fn(seg_metalv(seg, s), data))
				return_0;
			if (!for_each_sub_lv(seg_metalv(seg, s), fn, data))
				return_0;
		}
	}

	return 1;
}

int for_each_sub_lv(struct logical_volume *lv,
		    int (*fn)(struct logical_volume *lv, void *data),
		    void *data)
{
	return _for_each_sub_lv(lv, 0, fn, data);
}

int for_each_sub_lv_except_pools(struct logical_volume *lv,
				 int (*fn)(struct logical_volume *lv, void *data),
				 void *data)
{
	return _for_each_sub_lv(lv, 1, fn, data);
}

/*
 * Core of LV renaming routine.
 * VG must be locked by caller.
 */
int lv_rename_update(struct cmd_context *cmd, struct logical_volume *lv,
		     const char *new_name, int update_mda)
{
	struct volume_group *vg = lv->vg;
	struct lv_names lv_names = { .old = lv->name };

	/* rename is not allowed on sub LVs */
	if (!lv_is_visible(lv)) {
		log_error("Cannot rename internal LV \"%s\".", lv->name);
		return 0;
	}

	if (find_lv_in_vg(vg, new_name)) {
		log_error("Logical volume \"%s\" already exists in "
			  "volume group \"%s\"", new_name, vg->name);
		return 0;
	}

	if (lv_is_locked(lv)) {
		log_error("Cannot rename locked LV %s", lv->name);
		return 0;
	}

	/*
	 * The lvmlockd LV lock is only acquired here to ensure the LV is not
	 * active on another host.  This requests a transient LV lock.
	 * If the LV is active, a persistent LV lock already exists in
	 * lvmlockd, and the transient lock request does nothing.
	 * If the LV is not active, then no LV lock exists and the transient
	 * lock request acquires the LV lock (or fails).  The transient lock
	 * is automatically released when the command exits.
	 */
	if (!lockd_lv(cmd, lv, "ex", 0))
		return_0;

	if (update_mda && !archive(vg))
		return_0;

	if (!(lv_names.new = dm_pool_strdup(cmd->mem, new_name))) {
		log_error("Failed to allocate space for new name.");
		return 0;
	}

	/* rename sub LVs */
	if (!for_each_sub_lv_except_pools(lv, _rename_cb, (void *) &lv_names))
		return_0;

	/* rename main LV */
	lv->name = lv_names.new;

	if (lv_is_cow(lv))
		lv = origin_from_cow(lv);

	if (update_mda && !lv_update_and_reload(lv))
		return_0;

	return 1;
}

/*
 * Core of LV renaming routine.
 * VG must be locked by caller.
 */
int lv_rename(struct cmd_context *cmd, struct logical_volume *lv,
	      const char *new_name)
{
	return lv_rename_update(cmd, lv, new_name, 1);
}

/*
 * Core lv resize code
 */

#define SIZE_BUF 128

/* TODO: unify stripe size validation across source code */
static int _validate_stripesize(struct cmd_context *cmd,
				const struct volume_group *vg,
				struct lvresize_params *lp)
{

	if ( lp->ac_stripesize_value > STRIPE_SIZE_LIMIT * 2) {
		log_error("Stripe size cannot be larger than %s",
			  display_size(cmd, (uint64_t) STRIPE_SIZE_LIMIT));
		return 0;
	}

	if (!(vg->fid->fmt->features & FMT_SEGMENTS))
		log_warn("Varied stripesize not supported. Ignoring.");
	else if (lp->ac_stripesize_value > vg->extent_size) {
		log_print_unless_silent("Reducing stripe size %s to maximum, "
					"physical extent size %s",
					display_size(cmd, lp->ac_stripesize_value),
					display_size(cmd, vg->extent_size));
		lp->stripe_size = vg->extent_size;
	} else
		lp->stripe_size = lp->ac_stripesize_value;

	if (lp->stripe_size & (lp->stripe_size - 1)) {
		log_error("Stripe size must be power of 2");
		return 0;
	}

	return 1;
}

static int _request_confirmation(struct cmd_context *cmd,
				 const struct volume_group *vg,
				 const struct logical_volume *lv,
				 const struct lvresize_params *lp)
{
	struct lvinfo info = { 0 };

	if (!lv_info(cmd, lv, 0, &info, 1, 0) && driver_version(NULL, 0)) {
		log_error("lv_info failed: aborting");
		return 0;
	}

	if (lp->resizefs) {
		if (!info.exists) {
			log_error("Logical volume %s must be activated "
				  "before resizing filesystem", lp->lv_name);
			return 0;
		}
		return 1;
	}

	if (!info.exists)
		return 1;

	log_warn("WARNING: Reducing active%s logical volume to %s",
		 info.open_count ? " and open" : "",
		 display_size(cmd, (uint64_t) lp->extents * vg->extent_size));

	log_warn("THIS MAY DESTROY YOUR DATA (filesystem etc.)");

	if (!lp->ac_force) {
		if (yes_no_prompt("Do you really want to reduce %s? [y/n]: ",
				  lp->lv_name) == 'n') {
			log_error("Logical volume %s NOT reduced", lp->lv_name);
			return 0;
		}
		if (sigint_caught())
			return_0;
	}

	return 1;
}

enum fsadm_cmd_e { FSADM_CMD_CHECK, FSADM_CMD_RESIZE };
#define FSADM_CMD "fsadm"
#define FSADM_CMD_MAX_ARGS 6
#define FSADM_CHECK_FAILS_FOR_MOUNTED 3 /* shell exist status code */

/*
 * FSADM_CMD --dry-run --verbose --force check lv_path
 * FSADM_CMD --dry-run --verbose --force resize lv_path size
 */
static int _fsadm_cmd(struct cmd_context *cmd,
		      const struct volume_group *vg,
		      const struct lvresize_params *lp,
		      enum fsadm_cmd_e fcmd,
		      int *status)
{
	char lv_path[PATH_MAX];
	char size_buf[SIZE_BUF];
	const char *argv[FSADM_CMD_MAX_ARGS + 2];
	unsigned i = 0;

	argv[i++] = FSADM_CMD;

	if (test_mode())
		argv[i++] = "--dry-run";

	if (verbose_level() >= _LOG_NOTICE)
		argv[i++] = "--verbose";

	if (lp->ac_force)
		argv[i++] = "--force";

	argv[i++] = (fcmd == FSADM_CMD_RESIZE) ? "resize" : "check";

	if (status)
		*status = -1;

	if (dm_snprintf(lv_path, sizeof(lv_path), "%s%s/%s", cmd->dev_dir,
			vg->name, lp->lv_name) < 0) {
		log_error("Couldn't create LV path for %s", lp->lv_name);
		return 0;
	}

	argv[i++] = lv_path;

	if (fcmd == FSADM_CMD_RESIZE) {
		if (dm_snprintf(size_buf, sizeof(size_buf), FMTu64 "K",
				(uint64_t) lp->extents * (vg->extent_size / 2)) < 0) {
			log_error("Couldn't generate new LV size string");
			return 0;
		}

		argv[i++] = size_buf;
	}

	argv[i] = NULL;

	return exec_cmd(cmd, argv, status, 1);
}

static int _adjust_policy_params(struct cmd_context *cmd,
				 struct logical_volume *lv, struct lvresize_params *lp)
{
	dm_percent_t percent;
	int policy_threshold, policy_amount;

	if (lv_is_thin_pool(lv)) {
		policy_threshold =
			find_config_tree_int(cmd, activation_thin_pool_autoextend_threshold_CFG,
					     lv_config_profile(lv)) * DM_PERCENT_1;
		policy_amount =
			find_config_tree_int(cmd, activation_thin_pool_autoextend_percent_CFG,
					     lv_config_profile(lv));
		if (!policy_amount && policy_threshold < DM_PERCENT_100) {
			log_error("Can't extend thin pool %s, autoextend is set to 0%%.",
				  display_lvname(lv));
			return 0;
		}
	} else {
		policy_threshold =
			find_config_tree_int(cmd, activation_snapshot_autoextend_threshold_CFG, NULL) * DM_PERCENT_1;
		policy_amount =
			find_config_tree_int(cmd, activation_snapshot_autoextend_percent_CFG, NULL);
	}

	if (policy_threshold >= DM_PERCENT_100)
		return 1; /* nothing to do */

	if (!lv_is_active_locally(lv)) {
		log_error("Can't read state of locally inactive LV %s.",
			  display_lvname(lv));
		return 0;
	}

	if (lv_is_thin_pool(lv)) {
		if (!lv_thin_pool_percent(lv, 1, &percent))
			return_0;
		if ((DM_PERCENT_0 < percent && percent <= DM_PERCENT_100) &&
		    (percent > policy_threshold)) {
			if (!thin_pool_feature_supported(lv, THIN_FEATURE_METADATA_RESIZE)) {
				log_error_once("Online metadata resize for %s/%s is not supported.",
					       lv->vg->name, lv->name);
				return 0;
			}
			lp->poolmetadatasize = (first_seg(lv)->metadata_lv->size *
						policy_amount + 99) / 100;
			lp->poolmetadatasign = SIGN_PLUS;
		}

		if (!lv_thin_pool_percent(lv, 0, &percent))
			return_0;
		if (!(DM_PERCENT_0 < percent && percent <= DM_PERCENT_100) ||
		    percent <= policy_threshold)
			return 1;
	} else {
		if (!lv_snapshot_percent(lv, &percent))
			return_0;
		if (!(DM_PERCENT_0 < percent && percent <= DM_PERCENT_100) || percent <= policy_threshold)
		return 1; /* nothing to do */
	}

	lp->extents = policy_amount;
	lp->sizeargs = (lp->extents) ? 1 : 0;

	return 1;
}

static uint32_t lvseg_get_stripes(struct lv_segment *seg, uint32_t *stripesize)
{
	uint32_t s;
	struct lv_segment *seg_mirr;

	/* If segment mirrored, check if images are striped */
	if (seg_is_mirrored(seg))
		for (s = 0; s < seg->area_count; s++) {
			if (seg_type(seg, s) != AREA_LV)
				continue;
			seg_mirr = first_seg(seg_lv(seg, s));

			if (seg_is_striped(seg_mirr)) {
				seg = seg_mirr;
				break;
			}
		}


	if (seg_is_striped(seg)) {
		*stripesize = seg->stripe_size;
		return seg->area_count;
	}

	*stripesize = 0;
	return 0;
}

static int _lvresize_poolmetadata_prepare(struct cmd_context *cmd,
					  struct lvresize_params *lp,
					  const struct logical_volume *pool_lv)
{
	uint32_t extents;
	struct logical_volume *lv = first_seg(pool_lv)->metadata_lv;
	struct volume_group *vg = pool_lv->vg;

	lp->poolmetadataextents = 0;

	if (!thin_pool_feature_supported(pool_lv, THIN_FEATURE_METADATA_RESIZE)) {
		log_error("Support for online metadata resize not detected.");
		return 0;
	}

	if (lp->poolmetadatasize % vg->extent_size) {
		lp->poolmetadatasize += vg->extent_size -
			(lp->poolmetadatasize % vg->extent_size);
		log_print_unless_silent("Rounding pool metadata size to boundary between physical extents: %s",
					display_size(cmd, lp->poolmetadatasize));
	}

	if (!(extents = extents_from_size(vg->cmd, lp->poolmetadatasize,
					  vg->extent_size)))
		return_0;

	if (lp->poolmetadatasign == SIGN_PLUS) {
		if (extents >= (MAX_EXTENT_COUNT - lv->le_count)) {
			log_error("Unable to extend %s by %u extents, exceeds limit (%u).",
				  lv->name, lv->le_count, MAX_EXTENT_COUNT);
			return 0;
		}
		extents += lv->le_count;
	}

	if ((uint64_t)extents * vg->extent_size > DM_THIN_MAX_METADATA_SIZE) {
		log_print_unless_silent("Rounding size to maximum supported size 16GiB "
					"for metadata volume %s.", lv->name);
		extents = (DM_THIN_MAX_METADATA_SIZE + vg->extent_size - 1) /
			vg->extent_size;
	}

	/* FIXME Split here and move validation code earlier alongside rest of validation code */
	if (extents == lv->le_count) {
		log_print_unless_silent("Metadata volume %s has already %s.",
					lv->name, display_size(cmd, lv->size));
		return 2;
	}

	lp->poolmetadataextents = extents;

	return 1;
}

static int _lvresize_poolmetadata(struct cmd_context *cmd, struct volume_group *vg,
				  struct lvresize_params *lp,
				  const struct logical_volume *pool_lv,
				  struct dm_list *pvh)
{
	struct logical_volume *lv = first_seg(pool_lv)->metadata_lv;
	alloc_policy_t alloc = lp->ac_alloc ?: lv->alloc;
	struct lv_segment *mseg = last_seg(lv);
	uint32_t seg_mirrors = lv_mirror_count(lv);

	if (!archive(vg))
		return_0;

	log_print_unless_silent("Extending logical volume %s to %s.",
				lv->name,
				display_size(cmd, (uint64_t) lp->poolmetadataextents *
					     vg->extent_size));
	if (!lv_extend(lv,
		       mseg->segtype,
		       mseg->area_count / seg_mirrors,
		       mseg->stripe_size,
		       seg_mirrors,
		       mseg->region_size,
		       lp->poolmetadataextents - lv->le_count,
		       pvh, alloc, 0))
		return_0;

	return 1;
}

static int _lvresize_check_lv(struct cmd_context *cmd, struct logical_volume *lv, 
			      struct lvresize_params *lp)
{
	struct volume_group *vg = lv->vg;

	if (lv_is_external_origin(lv)) {
		/*
		 * Since external-origin can be activated read-only,
		 * there is no way to use extended areas.
		 */
		log_error("Cannot resize external origin \"%s\".", lv->name);
		return 0;
	}

	if (lv_is_raid_image(lv) || lv_is_raid_metadata(lv)) {
		log_error("Cannot resize a RAID %s directly",
			  (lv->status & RAID_IMAGE) ? "image" :
			  "metadata area");
		return 0;
	}

	if (lv_is_raid_with_tracking(lv)) {
		log_error("Cannot resize %s while it is tracking a split image",
			  lv->name);
		return 0;
	}

	if (lp->ac_stripes) {
		if (vg->fid->fmt->features & FMT_SEGMENTS)
			lp->stripes = lp->ac_stripes_value;
		else
			log_warn("Varied striping not supported. Ignoring.");
	}

	if (lp->ac_mirrors) {
		if (vg->fid->fmt->features & FMT_SEGMENTS)
			lp->mirrors = lp->ac_mirrors_value;
		else
			log_warn("Mirrors not supported. Ignoring.");
	}

	if (lp->ac_stripesize && !_validate_stripesize(cmd, vg, lp))
		return_0;

	if (lp->ac_policy && !lv_is_cow(lv) && !lv_is_thin_pool(lv)) {
		log_error("Policy-based resize is supported only for snapshot and thin pool volumes.");
		return 0;
	}

	/* FIXME: use a status flag instead of the name "lvmlock". */

	if (!lv_is_visible(lv) && !lv_is_thin_pool_metadata(lv) && strcmp(lv->name, "lvmlock")) {
		log_error("Can't resize internal logical volume %s", lv->name);
		return 0;
	}

	if (lv_is_locked(lv)) {
		log_error("Can't resize locked LV %s", lv->name);
		return 0;
	}

	if (lv_is_converting(lv)) {
		log_error("Can't resize %s while lvconvert in progress", lv->name);
		return 0;
	}

	if (!lv_is_thin_pool(lv) && lp->poolmetadatasize) {
		log_error("--poolmetadatasize can be used only with thin pools.");
		return 0;
	}

	return 1;
}

static int _lvresize_adjust_size(struct cmd_context *cmd, struct logical_volume *lv, 
				 struct lvresize_params *lp)
{
	struct volume_group *vg = lv->vg;

	/*
	 * First adjust to an exact multiple of extent size.
	 * When extending by a relative amount we round that amount up.
	 * When reducing by a relative amount we remove at most that amount.
	 * When changing to an absolute size, we round that size up.
	 */
	if (lp->size) {
		if (lp->size % vg->extent_size) {
			if (lp->sign == SIGN_MINUS)
				lp->size -= lp->size % vg->extent_size;
			else
				lp->size += vg->extent_size -
				    (lp->size % vg->extent_size);

			log_print_unless_silent("Rounding size to boundary between physical extents: %s",
						display_size(cmd, lp->size));
		}

		lp->extents = lp->size / vg->extent_size;
	}

	return 1;
}

/*
 * If percent options were used, convert them into actual numbers of extents.
 */
static int _lvresize_extents_from_percent(struct logical_volume *lv, struct lvresize_params *lp,
					  struct dm_list *pvh)
{
	struct volume_group *vg = lv->vg;
	uint32_t pv_extent_count;
	uint32_t old_extents = lp->extents;

	switch (lp->percent) {
		case PERCENT_VG:
			lp->extents = percent_of_extents(lp->extents, vg->extent_count,
							 (lp->sign != SIGN_MINUS));
			break;
		case PERCENT_FREE:
			lp->extents = percent_of_extents(lp->extents, vg->free_count,
							 (lp->sign != SIGN_MINUS));
			break;
		case PERCENT_LV:
			lp->extents = percent_of_extents(lp->extents, lv->le_count,
							 (lp->sign != SIGN_MINUS));
			break;
		case PERCENT_PVS:
			if (lp->argc) {
				pv_extent_count = pv_list_extents_free(pvh);
				lp->extents = percent_of_extents(lp->extents, pv_extent_count,
								 (lp->sign != SIGN_MINUS));
			} else
				lp->extents = percent_of_extents(lp->extents, vg->extent_count,
								 (lp->sign != SIGN_MINUS));
			break;
		case PERCENT_ORIGIN:
			if (!lv_is_cow(lv)) {
				log_error("Specified LV does not have an origin LV.");
				return 0;
			}
			lp->extents = percent_of_extents(lp->extents, origin_from_cow(lv)->le_count,
							 (lp->sign != SIGN_MINUS));
			break;
		case PERCENT_NONE:
			return 1;	/* Nothing to do */
		default:
			log_error(INTERNAL_ERROR "Unsupported percent type %u.", lp->percent);
			return 0;
	}

	if (lp->percent == PERCENT_VG || lp->percent == PERCENT_FREE || lp->percent == PERCENT_PVS)
		lp->extents_are_pes = 1;

	if (lp->sign == SIGN_NONE && (lp->percent == PERCENT_VG || lp->percent == PERCENT_FREE || lp->percent == PERCENT_PVS))
		lp->approx_alloc = 1;

	if (lp->sign == SIGN_PLUS && lp->percent == PERCENT_FREE)
		lp->approx_alloc = 1;

	log_verbose("Converted %" PRIu32 "%%%s into %s%" PRIu32 " %s extents.", old_extents, get_percent_string(lp->percent),
		    lp->approx_alloc ? "at most " : "", lp->extents, lp->extents_are_pes ? "physical" : "logical");

	return 1;
}

static int _add_pes(struct logical_volume *lv, void *data)
{
	uint32_t *pe_total = data;
	struct lv_segment *seg;
	uint32_t s;

	dm_list_iterate_items(seg, &lv->segments) {
		for (s = 0; s < seg->area_count; s++) {
			if (seg_type(seg, s) != AREA_PV)
				continue;

			*pe_total += seg_pvseg(seg, s)->len;
		}
	}

	return 1;
}

static uint32_t _lv_pe_count(struct logical_volume *lv)
{
	uint32_t pe_total = 0;

	/* Top-level LV first */
	if (!_add_pes(lv, &pe_total))
		stack;

	/* Any sub-LVs */
	if (!for_each_sub_lv(lv, _add_pes, &pe_total))
		stack;

	return pe_total;
}

/* FIXME Avoid having variables like lp->extents mean different things at different places */
static int _lvresize_adjust_extents(struct cmd_context *cmd, struct logical_volume *lv, 
				    struct lvresize_params *lp, struct dm_list *pvh)
{
	struct volume_group *vg = lv->vg;
	uint32_t logical_extents_used = 0;
	uint32_t physical_extents_used = 0;
	uint32_t seg_stripes = 0, seg_stripesize = 0;
	uint32_t seg_mirrors = 0;
	struct lv_segment *seg, *mirr_seg;
	uint32_t sz, str;
	uint32_t seg_logical_extents;
	uint32_t seg_physical_extents;
	uint32_t area_multiple;
	uint32_t stripesize_extents;
	uint32_t size_rest;
	uint32_t existing_logical_extents = lv->le_count;
	uint32_t existing_physical_extents, saved_existing_physical_extents;
	uint32_t seg_size = 0;
	uint32_t new_extents;
	int reducing = 0;

	if (!_lvresize_extents_from_percent(lv, lp, pvh))
		return_0;

	if (lv_is_thin_pool(lv))
		/* Manipulate the thin data layer underneath */
		lv = seg_lv(first_seg(lv), 0);

	/* Use segment type of last segment */
	lp->segtype = last_seg(lv)->segtype;

	/* FIXME Support LVs with mixed segment types */
	if (lp->segtype != get_segtype_from_string(cmd, lp->ac_type ? : lp->segtype->name)) {
		log_error("VolumeType does not match (%s)", lp->segtype->name);
		return 0;
	}

	/* For virtual devices, just pretend the physical size matches. */
	existing_physical_extents = saved_existing_physical_extents = _lv_pe_count(lv);
	if (!existing_physical_extents) {
		existing_physical_extents = lv->le_count;
		lp->extents_are_pes = 0;
	}

	/* Initial decision on whether we are extending or reducing */
	if (lp->sign == SIGN_MINUS ||
	    (lp->sign == SIGN_NONE && 
	     ((lp->extents_are_pes && lp->extents < existing_physical_extents) ||
	      (!lp->extents_are_pes && lp->extents < existing_logical_extents))))
		reducing = 1;

	/* If extending, find properties of last segment */
	if (!reducing) {
		mirr_seg = last_seg(lv);
		seg_mirrors = seg_is_mirrored(mirr_seg) ? lv_mirror_count(mirr_seg->lv) : 0;

		if (!lp->ac_mirrors && seg_mirrors) {
			log_print_unless_silent("Extending %" PRIu32 " mirror images.", seg_mirrors);
			lp->mirrors = seg_mirrors;
		}

		if ((lp->ac_mirrors || seg_mirrors) &&
		    (lp->mirrors != seg_mirrors)) {
			log_error("Cannot vary number of mirrors in LV yet.");
			return 0;
		}

		if (!strcmp(mirr_seg->segtype->name, _lv_type_names[LV_TYPE_RAID10])) {
			/* FIXME Warn if command line values are being overridden? */
			lp->stripes = mirr_seg->area_count / seg_mirrors;
			lp->stripe_size = mirr_seg->stripe_size;
		} else if (!(lp->stripes == 1 || (lp->stripes > 1 && lp->stripe_size))) {
			/* If extending, find stripes, stripesize & size of last segment */
			/* FIXME Don't assume mirror seg will always be AREA_LV */
			/* FIXME We will need to support resize for metadata LV as well,
			 *       and data LV could be any type (i.e. mirror)) */
			dm_list_iterate_items(seg, seg_mirrors ? &seg_lv(mirr_seg, 0)->segments : &lv->segments) {
				/* Allow through "striped" and RAID 4/5/6/10 */
				if (!seg_is_striped(seg) &&
				    (!seg_is_raid(seg) || seg_is_mirrored(seg)) &&
				    strcmp(seg->segtype->name, _lv_type_names[LV_TYPE_RAID10]))
					continue;
	
				sz = seg->stripe_size;
				str = seg->area_count - lp->segtype->parity_devs;
	
				if ((seg_stripesize && seg_stripesize != sz &&
				     sz && !lp->stripe_size) ||
				    (seg_stripes && seg_stripes != str && !lp->stripes)) {
					log_error("Please specify number of "
						  "stripes (-i) and stripesize (-I)");
					return 0;
				}
	
				seg_stripesize = sz;
				seg_stripes = str;
			}
	
			if (!lp->stripes)
				lp->stripes = seg_stripes;
			else if (seg_is_raid(first_seg(lv)) &&
				 (lp->stripes != seg_stripes)) {
				log_error("Unable to extend \"%s\" segment type with different number of stripes.",
					  lvseg_name(first_seg(lv)));
				return 0;
			}
	
			if (!lp->stripe_size && lp->stripes > 1) {
				if (seg_stripesize) {
					log_print_unless_silent("Using stripesize of last segment %s",
								display_size(cmd, (uint64_t) seg_stripesize));
					lp->stripe_size = seg_stripesize;
				} else {
					lp->stripe_size =
						find_config_tree_int(cmd, metadata_stripesize_CFG, NULL) * 2;
					log_print_unless_silent("Using default stripesize %s",
								display_size(cmd, (uint64_t) lp->stripe_size));
				}
			}
		}

		/* Determine the amount to extend by */
		if (lp->sign == SIGN_PLUS)
			seg_size = lp->extents;
		else if (lp->extents_are_pes)
			seg_size = lp->extents - existing_physical_extents;
		else
			seg_size = lp->extents - existing_logical_extents;

		/* Convert PEs to LEs */
		if (lp->extents_are_pes && !seg_is_striped(last_seg(lv)) && !seg_is_virtual(last_seg(lv))) {
			area_multiple = _calc_area_multiple(last_seg(lv)->segtype, last_seg(lv)->area_count, 0);
			seg_size = seg_size * area_multiple / (last_seg(lv)->area_count - last_seg(lv)->segtype->parity_devs);
			seg_size = (seg_size / area_multiple) * area_multiple;
		}
	}

	/* If reducing, find stripes, stripesize & size of last segment */
	if (reducing) {
		if (lp->stripes || lp->stripe_size || lp->mirrors)
			log_print_unless_silent("Ignoring stripes, stripesize and mirrors "
						"arguments when reducing.");

		if (lp->sign == SIGN_MINUS) 
			if (lp->extents_are_pes) {
				if (lp->extents >= existing_physical_extents) {
					log_error("Unable to reduce %s below 1 extent.", lp->lv_name);
					return 0;
				}
				new_extents = existing_physical_extents - lp->extents;
			} else {
				new_extents = existing_logical_extents - lp->extents;
				if (lp->extents >= existing_logical_extents) {
					log_error("Unable to reduce %s below 1 extent.", lp->lv_name);
					return 0;
				}
			}
		else
			new_extents = lp->extents;

		dm_list_iterate_items(seg, &lv->segments) {
			seg_logical_extents = seg->len;
			seg_physical_extents = seg->area_len * seg->area_count;	/* FIXME Also metadata, cow etc. */

			/* Check for underlying stripe sizes */
			seg_stripes = lvseg_get_stripes(seg, &seg_stripesize);

			if (seg_is_mirrored(seg))
				seg_mirrors = lv_mirror_count(seg->lv);
			else
				seg_mirrors = 0;

			/* Have we reached the final segment of the new LV? */
			if (lp->extents_are_pes) {
				if (new_extents <= physical_extents_used + seg_physical_extents) {
					seg_size = new_extents - physical_extents_used;
					if (seg_mirrors)
						seg_size /= seg_mirrors;
					lp->extents = logical_extents_used + seg_size;
					break;
				}
			} else if (new_extents <= logical_extents_used + seg_logical_extents) {
				seg_size = new_extents - logical_extents_used;
				lp->extents = new_extents;
				break;
			}

			logical_extents_used += seg_logical_extents;
			physical_extents_used += seg_physical_extents;
		}

		lp->stripe_size = seg_stripesize;
		lp->stripes = seg_stripes;
		lp->mirrors = seg_mirrors;
	}

	if (lp->stripes > 1 && !lp->stripe_size) {
		log_error("Stripesize for striped segment should not be 0!");
		return 0;
	}

	if (!reducing) {
		if (seg_size >= (MAX_EXTENT_COUNT - existing_logical_extents)) {
			log_error("Unable to extend %s by %u logical extents: exceeds limit (%u).",
				  lp->lv_name, seg_size, MAX_EXTENT_COUNT);
			return 0;
		}
		lp->extents = existing_logical_extents + seg_size;

		/* Don't allow a cow to grow larger than necessary. */
		if (lv_is_cow(lv)) {
			logical_extents_used = cow_max_extents(origin_from_cow(lv), find_snapshot(lv)->chunk_size);
			if (logical_extents_used < lp->extents) {
				log_print_unless_silent("Reached maximum COW size %s (%" PRIu32 " extents).",
							display_size(vg->cmd, (uint64_t) vg->extent_size * logical_extents_used),
							logical_extents_used);
				lp->extents = logical_extents_used;	// CHANGES lp->extents
				seg_size = lp->extents - existing_logical_extents;	// Recalculate
				if (lp->extents == existing_logical_extents) {
					/* Signal that normal resizing is not required */
					lp->sizeargs = 0;
					return 1;
				}
			}
		}
	} 

	/* At this point, lp->extents should hold the correct NEW logical size required. */

	if (!lp->extents) {
		log_error("New size of 0 not permitted");
		return 0;
	}

	if (lp->extents == existing_logical_extents) {
		if (lp->poolmetadatasize || lp->ac_policy) {
			/* Signal that normal resizing is not required */
			lp->sizeargs = 0;
			return 1;
		}

		if (!lp->resizefs) {
			log_error("New size (%d extents) matches existing size "
				  "(%d extents)", lp->extents, existing_logical_extents);
			return 0;
		}
		lp->resize = LV_EXTEND; /* lets pretend zero size extension */
	}

	/* Perform any rounding to produce complete stripes. */
	if (lp->stripes > 1) {
		if (lp->stripe_size < STRIPE_SIZE_MIN) {
			log_error("Invalid stripe size %s",
				  display_size(cmd, (uint64_t) lp->stripe_size));
			return 0;
		}

		if (!(stripesize_extents = lp->stripe_size / vg->extent_size))
			stripesize_extents = 1;

		size_rest = seg_size % (lp->stripes * stripesize_extents);
		/* Round toward the original size. */
		if (size_rest &&
		    ((lp->extents < existing_logical_extents) ||
		     !lp->percent ||
		     (vg->free_count >= (lp->extents - existing_logical_extents - size_rest +
					 (lp->stripes * stripesize_extents))))) {
			log_print_unless_silent("Rounding size (%d extents) up to stripe "
						"boundary size for segment (%d extents)",
						lp->extents, lp->extents - size_rest +
						(lp->stripes * stripesize_extents));
			lp->extents = lp->extents - size_rest +
				      (lp->stripes * stripesize_extents);
		} else if (size_rest) {
			log_print_unless_silent("Rounding size (%d extents) down to stripe "
						"boundary size for segment (%d extents)",
						lp->extents, lp->extents - size_rest);
			lp->extents = lp->extents - size_rest;
		}
	}

	/* Final sanity checking */
	if (lp->extents < existing_logical_extents) {
		if (lp->resize == LV_EXTEND) {
			log_error("New size given (%d extents) not larger "
				  "than existing size (%d extents)",
				  lp->extents, existing_logical_extents);
			return 0;
		}
		lp->resize = LV_REDUCE;
	} else if (lp->extents > existing_logical_extents) {
		if (lp->resize == LV_REDUCE) {
			log_error("New size given (%d extents) not less than "
				  "existing size (%d extents)", lp->extents,
				  existing_logical_extents);
			return 0;
		}
		lp->resize = LV_EXTEND;
	} else if ((lp->extents == existing_logical_extents) && !lp->ac_policy) {
		if (!lp->resizefs) {
			log_error("New size (%d extents) matches existing size "
				  "(%d extents)", lp->extents, existing_logical_extents);
			return 0;
		}
		lp->resize = LV_EXTEND;
	}

	/*
	 * Has the user specified that they would like the additional
	 * extents of a mirror not to have an initial sync?
	 */
	if ((lp->extents > existing_logical_extents)) {
		if (seg_is_mirrored(first_seg(lv)) && lp->ac_no_sync)
			lv->status |= LV_NOTSYNCED;
	}

	log_debug("New size for %s: %" PRIu32 ". Existing logical extents: %" PRIu32 " / physical extents: %" PRIu32 ".",
		  display_lvname(lv), lp->extents, existing_logical_extents, saved_existing_physical_extents);

	return 1;
}

static int _lvresize_check_type(struct cmd_context *cmd, const struct logical_volume *lv,
				struct lvresize_params *lp)
{
	if (lv_is_origin(lv)) {
		if (lp->resize == LV_REDUCE) {
			log_error("Snapshot origin volumes cannot be reduced "
				  "in size yet.");
			return 0;
		}

		if (lv_is_active(lv)) {
			log_error("Snapshot origin volumes can be resized "
				  "only while inactive: try lvchange -an");
			return 0;
		}
	}

	if (lv_is_thin_pool(lv)) {
		if (lp->resize == LV_REDUCE) {
			log_error("Thin pool volumes cannot be reduced in size yet.");
			return 0;
		}
	}

	if ((lp->resize == LV_REDUCE) && lv_is_thin_pool_metadata(lv)) {
		log_error("Thin pool metadata volumes cannot be reduced.");
		return 0;
	}

	if (lv_is_thin_volume(lv) && first_seg(lv)->external_lv &&
	    (lp->resize == LV_EXTEND)) {
		/* Validate thin target supports bigger size of thin volume then external origin */
		if (first_seg(lv)->external_lv->size <= lv->size &&
		    !thin_pool_feature_supported(first_seg(lv)->pool_lv, THIN_FEATURE_EXTERNAL_ORIGIN_EXTEND)) {
			log_error("Thin target does not support external origin smaller then thin volume.");
			return 0;
		}
	}

	return 1;
}

static struct logical_volume *_lvresize_volume(struct cmd_context *cmd,
					       struct logical_volume *lv,
					       struct lvresize_params *lp,
					       struct dm_list *pvh)
{
	struct volume_group *vg = lv->vg;
	struct logical_volume *lock_lv = NULL;
	struct lv_segment *seg = NULL;
	uint32_t old_extents;
	int status;
	alloc_policy_t alloc;

	if (lv_is_thin_pool(lv)) {
		if (lp->resizefs) {
			log_print_unless_silent("Ignoring --resizefs as thin pool volumes do not have filesystem.");
			lp->resizefs = 0;
		}
		lock_lv = lv;
		seg = first_seg(lv);
		/* Switch to layered LV resizing */
		lv = seg_lv(seg, 0);
	}
	alloc = lp->ac_alloc ?: lv->alloc;

	if ((lp->resize == LV_REDUCE) && lp->argc)
		log_print_unless_silent("Ignoring PVs on command line when reducing.");

	/* Request confirmation before operations that are often mistakes. */
	if ((lp->resizefs || (lp->resize == LV_REDUCE)) &&
	    !_request_confirmation(cmd, vg, lv, lp))
		return_NULL;

	if (lp->resizefs) {
		if (!lp->nofsck &&
		    !_fsadm_cmd(cmd, vg, lp, FSADM_CMD_CHECK, &status)) {
			if (status != FSADM_CHECK_FAILS_FOR_MOUNTED) {
				log_error("Filesystem check failed.");
				return NULL;
			}
			/* some filesystems supports online resize */
		}

		/* FIXME forks here */
		if ((lp->resize == LV_REDUCE) &&
		    !_fsadm_cmd(cmd, vg, lp, FSADM_CMD_RESIZE, NULL)) {
			log_error("Filesystem resize failed.");
			return NULL;
		}
	}

	if (!archive(vg))
		return_NULL;

	old_extents = lv->le_count;
	log_verbose("%sing logical volume %s to %s%s",
		    (lp->resize == LV_REDUCE) ? "Reduc" : "Extend",
		    display_lvname(lv), lp->approx_alloc ? "up to " : "",
		    display_size(cmd, (uint64_t) lp->extents * vg->extent_size));

	if (lp->resize == LV_REDUCE) {
		if (!lv_reduce(lv, lv->le_count - lp->extents))
			return_NULL;
	} else if ((lp->extents > lv->le_count) && /* Ensure we extend */
		   !lv_extend(lv, lp->segtype,
			      lp->stripes, lp->stripe_size,
			      lp->mirrors, first_seg(lv)->region_size,
			      lp->extents - lv->le_count,
			      pvh, alloc, lp->approx_alloc))
		return_NULL;
	else if (!pool_check_overprovisioning(lv))
		return_NULL;

	if (old_extents == lv->le_count)
		log_print_unless_silent("Size of logical volume %s unchanged from %s (%" PRIu32 " extents).",
					display_lvname(lv),
					display_size(cmd, (uint64_t) old_extents * vg->extent_size), old_extents);
	else
		log_print_unless_silent("Size of logical volume %s changed from %s (%" PRIu32 " extents) to %s (%" PRIu32 " extents).",
					display_lvname(lv),
					display_size(cmd, (uint64_t) old_extents * vg->extent_size), old_extents,
					display_size(cmd, (uint64_t) lv->le_count * vg->extent_size), lv->le_count);

	if (lock_lv) {
		/* Update thin pool segment from the layered LV */
		seg->area_len = lv->le_count;
		seg->len = lv->le_count;
		lock_lv->le_count = lv->le_count;
		lock_lv->size = lv->size;
	/* If thin metadata, must suspend thin pool */
	} else if (lv_is_thin_pool_metadata(lv)) {
		if (!(lock_lv = find_pool_lv(lv)))
			return_NULL;
	/* If snapshot, must suspend all associated devices */
	} else if (lv_is_cow(lv))
		lock_lv = origin_from_cow(lv);
	else
		lock_lv = lv;

	return lock_lv;
}

int lv_resize_prepare(struct cmd_context *cmd, struct logical_volume *lv, 
		      struct lvresize_params *lp, struct dm_list *pvh)
{
	if (!_lvresize_check_lv(cmd, lv, lp))
		return_0;

	if (lp->ac_policy && !_adjust_policy_params(cmd, lv, lp))
		return_0;

	if (!_lvresize_adjust_size(cmd, lv, lp))
		return_0;

	if (lp->sizeargs && !_lvresize_adjust_extents(cmd, lv, lp, pvh))
		return_0;

	if ((lp->extents == lv->le_count) && lp->ac_policy) {
		/* Nothing to do. */
		lp->sizeargs = 0;
		lp->poolmetadatasize = 0;
	}

	if (lp->sizeargs && !_lvresize_check_type(cmd, lv, lp))
		return_0;

	if (lp->poolmetadatasize &&
	    !_lvresize_poolmetadata_prepare(cmd, lp, lv))
		return_0;

	return 1;
}

/* lv_resize_prepare MUST be called before this */
int lv_resize(struct cmd_context *cmd, struct logical_volume *lv, 
	      struct lvresize_params *lp, struct dm_list *pvh)
{
	struct volume_group *vg = lv->vg;
	struct logical_volume *lock_lv = NULL;
	int inactive = 0;

	if (lv_is_cache_type(lv)) {
		log_error("Unable to resize logical volumes of cache type.");
		return 0;
	}

	/*
	 * If the LV is locked from activation, this lock call is a no-op.
	 * Otherwise, this acquires a transient lock on the lv (not PERSISTENT).
	 */
	if (!lockd_lv(cmd, lv, "ex", 0))
		return_0;

	if (lp->sizeargs &&
	    !(lock_lv = _lvresize_volume(cmd, lv, lp, pvh)))
		return_0;

	if (lp->poolmetadataextents) {
		if (!_lvresize_poolmetadata(cmd, vg, lp, lv, pvh))
			return_0;
		lock_lv = lv;
	}

	if (!lock_lv)
		return 1; /* Nothing to do */

	if (lv_is_thin_pool(lock_lv) &&
	    pool_is_active(lock_lv) &&
	    !lv_is_active(lock_lv)) {
		/*
		 * Active 'hidden' -tpool can be waiting for resize, but the
		 * pool LV itself might be inactive.
		 * Here plain suspend/resume would not work.
		 * So active temporarily pool LV (with on disk metadata)
		 * then use suspend and resume and deactivate pool LV,
		 * instead of searching for an active thin volume.
		 */
		inactive = 1;
		if (!activate_lv_excl(cmd, lock_lv)) {
			log_error("Failed to activate %s.", display_lvname(lock_lv));
			return 0;
		}
	}

	/* store vg on disk(s) */
	if (!lv_update_and_reload(lock_lv))
		goto_bad;

	if (lv_is_cow_covering_origin(lv))
		if (!monitor_dev_for_events(cmd, lv, 0, 0))
			stack;

	if (lv_is_thin_pool(lock_lv)) {
		/* Update lvm pool metadata (drop messages). */
		if (!update_pool_lv(lock_lv, 0))
			goto_bad;

		backup(vg);

		if (inactive && !deactivate_lv(cmd, lock_lv)) {
			log_error("Problem deactivating %s.", display_lvname(lock_lv));
			return 0;
		}
	}

	log_print_unless_silent("Logical volume %s successfully resized.", lp->lv_name);

	if (lp->resizefs && (lp->resize == LV_EXTEND) &&
	    !_fsadm_cmd(cmd, vg, lp, FSADM_CMD_RESIZE, NULL))
		return_0;

	return 1;
bad:
	if (inactive && !deactivate_lv(cmd, lock_lv))
		log_error("Problem deactivating %s.", lock_lv->name);

	return 0;
}

char *generate_lv_name(struct volume_group *vg, const char *format,
		       char *buffer, size_t len)
{
	struct lv_list *lvl;
	int high = -1, i;

	dm_list_iterate_items(lvl, &vg->lvs) {
		if (sscanf(lvl->lv->name, format, &i) != 1)
			continue;

		if (i > high)
			high = i;
	}

	if (dm_snprintf(buffer, len, format, high + 1) < 0)
		return NULL;

	return buffer;
}

int vg_max_lv_reached(struct volume_group *vg)
{
	if (!vg->max_lv)
		return 0;

	if (vg->max_lv > vg_visible_lvs(vg))
		return 0;

	log_verbose("Maximum number of logical volumes (%u) reached "
		    "in volume group %s", vg->max_lv, vg->name);

	return 1;
}

struct logical_volume *alloc_lv(struct dm_pool *mem)
{
	struct logical_volume *lv;

	if (!(lv = dm_pool_zalloc(mem, sizeof(*lv)))) {
		log_error("Unable to allocate logical volume structure");
		return NULL;
	}

	dm_list_init(&lv->snapshot_segs);
	dm_list_init(&lv->segments);
	dm_list_init(&lv->tags);
	dm_list_init(&lv->segs_using_this_lv);
	dm_list_init(&lv->rsites);

	return lv;
}

/*
 * Create a new empty LV.
 */
struct logical_volume *lv_create_empty(const char *name,
				       union lvid *lvid,
				       uint64_t status,
				       alloc_policy_t alloc,
				       struct volume_group *vg)
{
	struct format_instance *fi = vg->fid;
	struct logical_volume *lv;
	char dname[NAME_LEN];

	if (vg_max_lv_reached(vg))
		stack;

	if (strstr(name, "%d") &&
	    !(name = generate_lv_name(vg, name, dname, sizeof(dname)))) {
		log_error("Failed to generate unique name for the new "
			  "logical volume");
		return NULL;
	} else if (find_lv_in_vg(vg, name)) {
		log_error("Unable to create LV %s in Volume Group %s: "
			  "name already in use.", name, vg->name);
		return NULL;
	}

	log_verbose("Creating logical volume %s", name);

	if (!(lv = alloc_lv(vg->vgmem)))
		return_NULL;

	if (!(lv->name = dm_pool_strdup(vg->vgmem, name)))
		goto_bad;

	lv->status = status;
	lv->alloc = alloc;
	lv->read_ahead = vg->cmd->default_settings.read_ahead;
	lv->major = -1;
	lv->minor = -1;
	lv->size = UINT64_C(0);
	lv->le_count = 0;

	if (lvid)
		lv->lvid = *lvid;

	if (!link_lv_to_vg(vg, lv))
		goto_bad;

	if (!lv_set_creation(lv, NULL, 0))
		goto_bad;
 
	if (fi->fmt->ops->lv_setup && !fi->fmt->ops->lv_setup(fi, lv))
		goto_bad;

	if (vg->fid->fmt->features & FMT_CONFIG_PROFILE)
		lv->profile = vg->cmd->profile_params->global_metadata_profile;
 
	return lv;
bad:
	dm_pool_free(vg->vgmem, lv);
	return NULL;
}

static int _add_pvs(struct cmd_context *cmd, struct pv_segment *peg,
		    uint32_t s __attribute__((unused)), void *data)
{
	struct seg_pvs *spvs = (struct seg_pvs *) data;
	struct pv_list *pvl;

	/* Don't add again if it's already on list. */
	if (find_pv_in_pv_list(&spvs->pvs, peg->pv))
		return 1;

	if (!(pvl = dm_pool_alloc(cmd->mem, sizeof(*pvl)))) {
		log_error("pv_list allocation failed");
		return 0;
	}

	pvl->pv = peg->pv;

	dm_list_add(&spvs->pvs, &pvl->list);

	return 1;
}

/*
 * build_parallel_areas_from_lv
 * @lv
 * @use_pvmove_parent_lv
 * @create_single_list
 *
 * For each segment in an LV, create a list of PVs used by the segment.
 * Thus, the returned list is really a list of segments (seg_pvs)
 * containing a list of PVs that are in use by that segment.
 *
 * use_pvmove_parent_lv:  For pvmove we use the *parent* LV so we can
 *                        pick up stripes & existing mirrors etc.
 * create_single_list  :  Instead of creating a list of segments that
 *                        each contain a list of PVs, return a list
 *                        containing just one segment (i.e. seg_pvs)
 *                        that contains a list of all the PVs used by
 *                        the entire LV and all it's segments.
 */
struct dm_list *build_parallel_areas_from_lv(struct logical_volume *lv,
					     unsigned use_pvmove_parent_lv,
					     unsigned create_single_list)
{
	struct cmd_context *cmd = lv->vg->cmd;
	struct dm_list *parallel_areas;
	struct seg_pvs *spvs = NULL;
	uint32_t current_le = 0;
	uint32_t raid_multiple;
	struct lv_segment *seg = first_seg(lv);

	if (!(parallel_areas = dm_pool_alloc(cmd->mem, sizeof(*parallel_areas)))) {
		log_error("parallel_areas allocation failed");
		return NULL;
	}

	dm_list_init(parallel_areas);

	do {
		if (!spvs || !create_single_list) {
			if (!(spvs = dm_pool_zalloc(cmd->mem, sizeof(*spvs)))) {
				log_error("allocation failed");
				return NULL;
			}

			dm_list_init(&spvs->pvs);
			dm_list_add(parallel_areas, &spvs->list);
		}
		spvs->le = current_le;
		spvs->len = lv->le_count - current_le;

		if (use_pvmove_parent_lv &&
		    !(seg = find_seg_by_le(lv, current_le))) {
			log_error("Failed to find segment for %s extent %" PRIu32,
				  lv->name, current_le);
			return 0;
		}

		/* Find next segment end */
		/* FIXME Unnecessary nesting! */
		if (!_for_each_pv(cmd, use_pvmove_parent_lv ? seg->pvmove_source_seg->lv : lv,
				  use_pvmove_parent_lv ? seg->pvmove_source_seg->le : current_le,
				  use_pvmove_parent_lv ? spvs->len * _calc_area_multiple(seg->pvmove_source_seg->segtype, seg->pvmove_source_seg->area_count, 0) : spvs->len,
				  use_pvmove_parent_lv ? seg->pvmove_source_seg : NULL,
				  &spvs->len,
				  0, 0, -1, 0, _add_pvs, (void *) spvs))
			return_NULL;

		current_le = spvs->le + spvs->len;
		raid_multiple = (seg->segtype->parity_devs) ?
			seg->area_count - seg->segtype->parity_devs : 1;
	} while ((current_le * raid_multiple) < lv->le_count);

	if (create_single_list) {
		spvs->le = 0;
		spvs->len = lv->le_count;
	}

	/*
	 * FIXME:  Merge adjacent segments with identical PV lists
	 * (avoids need for contiguous allocation attempts between
	 * successful allocations)
	 */

	return parallel_areas;
}

int link_lv_to_vg(struct volume_group *vg, struct logical_volume *lv)
{
	struct lv_list *lvl;

	if (vg_max_lv_reached(vg))
		stack;

	if (!(lvl = dm_pool_zalloc(vg->vgmem, sizeof(*lvl))))
		return_0;

	lvl->lv = lv;
	lv->vg = vg;
	dm_list_add(&vg->lvs, &lvl->list);
	lv->status &= ~LV_REMOVED;

	return 1;
}

int unlink_lv_from_vg(struct logical_volume *lv)
{
	struct lv_list *lvl;

	if (!(lvl = find_lv_in_vg(lv->vg, lv->name)))
		return_0;

	dm_list_move(&lv->vg->removed_lvs, &lvl->list);
	lv->status |= LV_REMOVED;

	return 1;
}

void lv_set_visible(struct logical_volume *lv)
{
	if (lv_is_visible(lv))
		return;

	lv->status |= VISIBLE_LV;

	log_debug_metadata("LV %s in VG %s is now visible.",  lv->name, lv->vg->name);
}

void lv_set_hidden(struct logical_volume *lv)
{
	if (!lv_is_visible(lv))
		return;

	lv->status &= ~VISIBLE_LV;

	log_debug_metadata("LV %s in VG %s is now hidden.",  lv->name, lv->vg->name);
}

int lv_remove_single(struct cmd_context *cmd, struct logical_volume *lv,
		     force_t force, int suppress_remove_message)
{
	struct volume_group *vg;
	struct logical_volume *format1_origin = NULL;
	int format1_reload_required = 0;
	int visible;
	struct logical_volume *pool_lv = NULL;
	struct logical_volume *lock_lv = lv;
	struct lv_segment *cache_seg = NULL;
	int ask_discard;
	struct lv_list *lvl;
	struct seg_list *sl;
	int is_last_pool = lv_is_pool(lv);

	vg = lv->vg;

	if (!vg_check_status(vg, LVM_WRITE))
		return_0;

	if (lv_is_origin(lv)) {
		log_error("Can't remove logical volume \"%s\" under snapshot",
			  lv->name);
		return 0;
	}

	if (lv_is_external_origin(lv)) {
		log_error("Can't remove external origin logical volume \"%s\".",
			  lv->name);
		return 0;
	}

	if (lv_is_mirror_image(lv)) {
		log_error("Can't remove logical volume %s used by a mirror",
			  lv->name);
		return 0;
	}

	if (lv_is_mirror_log(lv)) {
		log_error("Can't remove logical volume %s used as mirror log",
			  lv->name);
		return 0;
	}

	if (lv_is_raid_metadata(lv) || lv_is_raid_image(lv)) {
		log_error("Can't remove logical volume %s used as RAID device",
			  lv->name);
		return 0;
	}

	if (lv_is_thin_pool_data(lv) || lv_is_thin_pool_metadata(lv) ||
	    lv_is_cache_pool_data(lv) || lv_is_cache_pool_metadata(lv)) {
		log_error("Can't remove logical volume %s used by a pool.",
			  lv->name);
		return 0;
	} else if (lv_is_thin_volume(lv)) {
		pool_lv = first_seg(lv)->pool_lv;
		lock_lv = pool_lv;
	}

	if (lv_is_locked(lv)) {
		log_error("Can't remove locked LV %s", lv->name);
		return 0;
	}

	if (!lockd_lv(cmd, lock_lv, "ex", LDLV_PERSISTENT))
		return_0;

	/* FIXME Ensure not referred to by another existing LVs */
	ask_discard = find_config_tree_bool(cmd, devices_issue_discards_CFG, NULL);

	if (!lv_is_cache_pool(lv) && /* cache pool cannot be active */
	    lv_is_active(lv)) {
		if (!lv_check_not_in_use(lv))
			return_0;

		if ((force == PROMPT) &&
		    !lv_is_pending_delete(lv) &&
		    lv_is_visible(lv) &&
		    lv_is_active(lv)) {
			if (yes_no_prompt("Do you really want to remove%s active "
					  "%slogical volume %s? [y/n]: ",
					  ask_discard ? " and DISCARD" : "",
					  vg_is_clustered(vg) ? "clustered " : "",
					  lv->name) == 'n') {
				log_error("Logical volume %s not removed", lv->name);
				return 0;
			} else {
				ask_discard = 0;
			}
		}
	}

	if ((force == PROMPT) && ask_discard &&
	    yes_no_prompt("Do you really want to remove and DISCARD "
			  "logical volume %s? [y/n]: ",
			  lv->name) == 'n') {
		log_error("Logical volume %s not removed", lv->name);
		return 0;
	}

	if (lv_is_cache(lv) && !lv_is_pending_delete(lv)) {
		if (!lv_remove_single(cmd, first_seg(lv)->pool_lv, force,
				      suppress_remove_message)) {
			if (force < DONT_PROMPT_OVERRIDE) {
				log_error("Failed to uncache %s.", display_lvname(lv));
				return 0;
			}
			/* Proceed with -ff */
			log_print_unless_silent("Ignoring uncache failure of %s.",
						display_lvname(lv));
		}
		is_last_pool = 1;
	}

	/* Used cache pool or COW cannot be activated */
	if ((!lv_is_cache_pool(lv) || dm_list_empty(&lv->segs_using_this_lv)) &&
	    !lv_is_cow(lv) &&
	    !deactivate_lv(cmd, lv)) {
		/* FIXME Review and fix the snapshot error paths! */
		log_error("Unable to deactivate logical volume %s.",
			  display_lvname(lv));
		return 0;
	}

	if (!archive(vg))
		return 0;

	/* Clear thin pool stacked messages */
	if (pool_lv && !pool_has_message(first_seg(pool_lv), lv, 0) &&
	    !update_pool_lv(pool_lv, 1)) {
		if (force < DONT_PROMPT_OVERRIDE) {
			log_error("Failed to update pool %s.", display_lvname(pool_lv));
			return 0;
		}
		log_print_unless_silent("Ignoring update failure of pool %s.",
					display_lvname(pool_lv));
		pool_lv = NULL; /* Do not retry */
	}

	/* When referenced by the LV with pending delete flag, remove this deleted LV first */
	dm_list_iterate_items(sl, &lv->segs_using_this_lv)
		if (lv_is_pending_delete(sl->seg->lv) && !lv_remove(sl->seg->lv)) {
			log_error("Error releasing logical volume %s with pending delete.",
				  display_lvname(sl->seg->lv));
			return 0;
		}

	if (lv_is_cow(lv)) {
		/* Old format1 code */
		if (!(lv->vg->fid->fmt->features & FMT_MDAS))
			format1_origin = origin_from_cow(lv);

		log_verbose("Removing snapshot %s", lv->name);
		/* vg_remove_snapshot() will preload origin/former snapshots */
		if (!vg_remove_snapshot(lv))
			return_0;

		if (!deactivate_lv(cmd, lv)) {
			/* FIXME Review and fix the snapshot error paths! */
			log_error("Unable to deactivate logical volume %s.",
				  display_lvname(lv));
			return 0;
		}
	}

	if (lv_is_cache_pool(lv)) {
		/* Cache pool removal drops cache layer
		 * If the cache pool is not linked, we can simply remove it. */
		if (!dm_list_empty(&lv->segs_using_this_lv)) {
			if (!(cache_seg = get_only_segment_using_this_lv(lv)))
				return_0;
			/* TODO: polling */
			if (!lv_cache_remove(cache_seg->lv))
				return_0;
		}
	}

	visible = lv_is_visible(lv);

	log_verbose("Releasing logical volume \"%s\"", lv->name);
	if (!lv_remove(lv)) {
		log_error("Error releasing logical volume \"%s\"", lv->name);
		return 0;
	}

	if (is_last_pool && vg->pool_metadata_spare_lv) {
		/* When removed last pool, also remove the spare */
		dm_list_iterate_items(lvl, &vg->lvs)
			if (lv_is_pool_metadata(lvl->lv)) {
				is_last_pool = 0;
				break;
			}
		if (is_last_pool) {
			/* This is purely internal LV volume, no question */
			if (!deactivate_lv(cmd, vg->pool_metadata_spare_lv)) {
				log_error("Unable to deactivate spare logical volume %s.",
					  display_lvname(vg->pool_metadata_spare_lv));
				return 0;
			}
			if (!lv_remove(vg->pool_metadata_spare_lv))
				return_0;
		}
	}

	/*
	 * Old format1 code: If no snapshots left reload without -real.
	 */
	if (format1_origin && !lv_is_origin(format1_origin)) {
		log_warn("WARNING: Support for snapshots with old LVM1-style metadata is deprecated.");
		log_warn("WARNING: Please use lvconvert to update to lvm2 metadata at your convenience.");
		format1_reload_required = 1;
	}

	/* store it on disks */
	if (!vg_write(vg) || !vg_commit(vg))
		return_0;

	/* format1 */
	if (format1_reload_required) {
		if (!suspend_lv(cmd, format1_origin))
			log_error("Failed to refresh %s without snapshot.", format1_origin->name);

		if (!resume_lv(cmd, format1_origin)) {
			log_error("Failed to resume %s.", format1_origin->name);
			return 0;
		}
	}

	/* Release unneeded blocks in thin pool */
	/* TODO: defer when multiple LVs relased at once */
	if (pool_lv && !update_pool_lv(pool_lv, 1)) {
		if (force < DONT_PROMPT_OVERRIDE) {
			log_error("Failed to update pool %s.", display_lvname(pool_lv));
			return 0;
		}
		log_print_unless_silent("Ignoring update failure of pool %s.",
					display_lvname(pool_lv));
	}

	backup(vg);

	lockd_lv(cmd, lock_lv, "un", LDLV_PERSISTENT);
	lockd_free_lv(cmd, vg, lv->name, &lv->lvid.id[1], lv->lock_args);

	if (!suppress_remove_message && visible)
		log_print_unless_silent("Logical volume \"%s\" successfully removed", lv->name);

	return 1;
}

static int _lv_remove_segs_using_this_lv(struct cmd_context *cmd, struct logical_volume *lv,
					 const force_t force, unsigned level,
					 const char *lv_type)
{
	struct seg_list *sl;

	if ((force == PROMPT) &&
	    yes_no_prompt("Removing %s \"%s\" will remove %u dependent volume(s). "
			  "Proceed? [y/n]: ", lv_type, lv->name,
			  dm_list_size(&lv->segs_using_this_lv)) == 'n') {
			log_error("Logical volume \"%s\" not removed.", lv->name);
			return 0;
		}
	/*
	 * Not using _safe iterator here - since we may delete whole subtree
	 * (similar as process_each_lv_in_vg())
	 * the code is roughly equivalent to this:
	 *
	 * while (!dm_list_empty(&lv->segs_using_this_lv))
	 * 	dm_list_iterate_items(sl, &lv->segs_using_this_lv)
	 * 		break;
	 */
	dm_list_iterate_items(sl, &lv->segs_using_this_lv)
		if (!lv_remove_with_dependencies(cmd, sl->seg->lv,
						 force, level + 1))
			return_0;

	return 1;
}
/*
 * remove LVs with its dependencies - LV leaf nodes should be removed first
 */
int lv_remove_with_dependencies(struct cmd_context *cmd, struct logical_volume *lv,
				const force_t force, unsigned level)
{
	dm_percent_t snap_percent;
	struct dm_list *snh, *snht;
	struct lvinfo info;
	struct lv_list *lvl;
	struct logical_volume *origin;

	if (lv_is_cow(lv)) {
		/*
		 * A merging snapshot cannot be removed directly unless
		 * it has been invalidated or failed merge removal is requested.
		 */
		if (lv_is_merging_cow(lv) && !level) {
			if (lv_info(lv->vg->cmd, lv, 0, &info, 1, 0) &&
			    info.exists && info.live_table) {
				if (!lv_snapshot_percent(lv, &snap_percent)) {
					log_error("Failed to obtain merging snapshot progress percentage for logical volume %s.",
						  lv->name);
					return 0;
				}
				if ((snap_percent != DM_PERCENT_INVALID) &&
				     (snap_percent != LVM_PERCENT_MERGE_FAILED)) {
					log_error("Can't remove merging snapshot logical volume \"%s\"",
						  lv->name);
					return 0;
				} else if ((snap_percent == LVM_PERCENT_MERGE_FAILED) &&
					 (force == PROMPT) &&
					 yes_no_prompt("Removing snapshot \"%s\" that failed to merge may leave origin \"%s\" inconsistent. "
						       "Proceed? [y/n]: ", lv->name, origin_from_cow(lv)->name) == 'n')
                                        goto no_remove;
			}
		} else if (!level && lv_is_virtual_origin(origin = origin_from_cow(lv)))
			/* If this is a sparse device, remove its origin too. */
			/* Stacking is not supported */
			lv = origin;
	}

	if (lv_is_origin(lv)) {
		/* Remove snapshot LVs first */
		if ((force == PROMPT) &&
		    /* Active snapshot already needs to confirm each active LV */
		    !lv_is_active(lv) &&
		    yes_no_prompt("Removing origin %s will also remove %u "
				  "snapshots(s). Proceed? [y/n]: ",
				  lv->name, lv->origin_count) == 'n')
			goto no_remove;

		dm_list_iterate_safe(snh, snht, &lv->snapshot_segs)
			if (!lv_remove_with_dependencies(cmd, dm_list_struct_base(snh, struct lv_segment,
										  origin_list)->cow,
							 force, level + 1))
				return_0;
	}

	if (lv_is_merging_origin(lv)) {
		if (!deactivate_lv(cmd, lv)) {
			log_error("Unable to fully deactivate merging origin \"%s\".",
				  lv->name);
			return 0;
		}
		if (!lv_remove_with_dependencies(cmd, find_snapshot(lv)->lv,
						 force, level + 1)) {
			log_error("Unable to remove merging origin \"%s\".",
				  lv->name);
			return 0;
		}
	}

	if (!level && lv_is_merging_thin_snapshot(lv)) {
		/* Merged snapshot LV is no longer available for the user */
		log_error("Unable to remove \"%s\", volume is merged to \"%s\".",
			  lv->name, first_seg(lv)->merge_lv->name);
		return 0;
	}

	if (lv_is_external_origin(lv) &&
	    !_lv_remove_segs_using_this_lv(cmd, lv, force, level, "external origin"))
		return_0;

	if (lv_is_used_thin_pool(lv) &&
	    !_lv_remove_segs_using_this_lv(cmd, lv, force, level, "pool"))
		return_0;

	if (lv_is_pool_metadata_spare(lv) &&
	    (force == PROMPT)) {
		dm_list_iterate_items(lvl, &lv->vg->lvs)
			if (lv_is_pool_metadata(lvl->lv)) {
				if (yes_no_prompt("Removal of pool metadata spare logical volume"
						  " \"%s\" disables automatic recovery attempts"
						  " after damage to a thin or cache pool."
						  " Proceed? [y/n]: ", lv->name) == 'n')
					goto no_remove;
				break;
			}
	}

	return lv_remove_single(cmd, lv, force, 0);

no_remove:
	log_error("Logical volume \"%s\" not removed.", lv->name);

	return 0;
}

static int _lv_update_and_reload(struct logical_volume *lv, int origin_only)
{
	struct volume_group *vg = lv->vg;
	int do_backup = 0, r = 0;
	const struct logical_volume *lock_lv = lv_lock_holder(lv);

	log_very_verbose("Updating logical volume %s on disk(s).",
			 display_lvname(lock_lv));

	if (!vg_write(vg))
		return_0;

	if (!(origin_only ? suspend_lv_origin(vg->cmd, lock_lv) : suspend_lv(vg->cmd, lock_lv))) {
		log_error("Failed to lock logical volume %s.",
			  display_lvname(lock_lv));
		vg_revert(vg);
	} else if (!(r = vg_commit(vg)))
		stack; /* !vg_commit() has implict vg_revert() */
	else
		do_backup = 1;

	log_very_verbose("Updating logical volume %s in kernel.",
			 display_lvname(lock_lv));

	if (!(origin_only ? resume_lv_origin(vg->cmd, lock_lv) : resume_lv(vg->cmd, lock_lv))) {
		log_error("Problem reactivating logical volume %s.",
			  display_lvname(lock_lv));
		r = 0;
	}

	if (do_backup)
		backup(vg);

	return r;
}

int lv_update_and_reload(struct logical_volume *lv)
{
        return _lv_update_and_reload(lv, 0);
}

int lv_update_and_reload_origin(struct logical_volume *lv)
{
        return _lv_update_and_reload(lv, 1);
}

/*
 * insert_layer_for_segments_on_pv() inserts a layer segment for a segment area.
 * However, layer modification could split the underlying layer segment.
 * This function splits the parent area according to keep the 1:1 relationship
 * between the parent area and the underlying layer segment.
 * Since the layer LV might have other layers below, build_parallel_areas()
 * is used to find the lowest-level segment boundaries.
 */
static int _split_parent_area(struct lv_segment *seg, uint32_t s,
			      struct dm_list *layer_seg_pvs)
{
	uint32_t parent_area_len, parent_le, layer_le;
	uint32_t area_multiple;
	struct seg_pvs *spvs;

	if (seg_is_striped(seg))
		area_multiple = seg->area_count;
	else
		area_multiple = 1;

	parent_area_len = seg->area_len;
	parent_le = seg->le;
	layer_le = seg_le(seg, s);

	while (parent_area_len > 0) {
		/* Find the layer segment pointed at */
		if (!(spvs = _find_seg_pvs_by_le(layer_seg_pvs, layer_le))) {
			log_error("layer segment for %s:%" PRIu32 " not found",
				  seg->lv->name, parent_le);
			return 0;
		}

		if (spvs->le != layer_le) {
			log_error("Incompatible layer boundary: "
				  "%s:%" PRIu32 "[%" PRIu32 "] on %s:%" PRIu32,
				  seg->lv->name, parent_le, s,
				  seg_lv(seg, s)->name, layer_le);
			return 0;
		}

		if (spvs->len < parent_area_len) {
			parent_le += spvs->len * area_multiple;
			if (!lv_split_segment(seg->lv, parent_le))
				return_0;
		}

		parent_area_len -= spvs->len;
		layer_le += spvs->len;
	}

	return 1;
}

/*
 * Split the parent LV segments if the layer LV below it is splitted.
 */
int split_parent_segments_for_layer(struct cmd_context *cmd,
				    struct logical_volume *layer_lv)
{
	struct lv_list *lvl;
	struct logical_volume *parent_lv;
	struct lv_segment *seg;
	uint32_t s;
	struct dm_list *parallel_areas;

	if (!(parallel_areas = build_parallel_areas_from_lv(layer_lv, 0, 0)))
		return_0;

	/* Loop through all LVs except itself */
	dm_list_iterate_items(lvl, &layer_lv->vg->lvs) {
		parent_lv = lvl->lv;
		if (parent_lv == layer_lv)
			continue;

		/* Find all segments that point at the layer LV */
		dm_list_iterate_items(seg, &parent_lv->segments) {
			for (s = 0; s < seg->area_count; s++) {
				if (seg_type(seg, s) != AREA_LV ||
				    seg_lv(seg, s) != layer_lv)
					continue;

				if (!_split_parent_area(seg, s, parallel_areas))
					return_0;
			}
		}
	}

	return 1;
}

/* Remove a layer from the LV */
int remove_layers_for_segments(struct cmd_context *cmd,
			       struct logical_volume *lv,
			       struct logical_volume *layer_lv,
			       uint64_t status_mask, struct dm_list *lvs_changed)
{
	struct lv_segment *seg, *lseg;
	uint32_t s;
	int lv_changed = 0;
	struct lv_list *lvl;

	log_very_verbose("Removing layer %s for segments of %s",
			 layer_lv->name, lv->name);

	/* Find all segments that point at the temporary mirror */
	dm_list_iterate_items(seg, &lv->segments) {
		for (s = 0; s < seg->area_count; s++) {
			if (seg_type(seg, s) != AREA_LV ||
			    seg_lv(seg, s) != layer_lv)
				continue;

			/* Find the layer segment pointed at */
			if (!(lseg = find_seg_by_le(layer_lv, seg_le(seg, s)))) {
				log_error("Layer segment found: %s:%" PRIu32,
					  layer_lv->name, seg_le(seg, s));
				return 0;
			}

			/* Check the segment params are compatible */
			if (!seg_is_striped(lseg) || lseg->area_count != 1) {
				log_error("Layer is not linear: %s:%" PRIu32,
					  layer_lv->name, lseg->le);
				return 0;
			}
			if ((lseg->status & status_mask) != status_mask) {
				log_error("Layer status does not match: "
					  "%s:%" PRIu32 " status: 0x%" PRIx64 "/0x%" PRIx64,
					  layer_lv->name, lseg->le,
					  lseg->status, status_mask);
				return 0;
			}
			if (lseg->le != seg_le(seg, s) ||
			    lseg->area_len != seg->area_len) {
				log_error("Layer boundary mismatch: "
					  "%s:%" PRIu32 "-%" PRIu32 " on "
					  "%s:%" PRIu32 " / "
					  FMTu32 "-" FMTu32 " / ",
					  lv->name, seg->le, seg->area_len,
					  layer_lv->name, seg_le(seg, s),
					  lseg->le, lseg->area_len);
				return 0;
			}

			if (!move_lv_segment_area(seg, s, lseg, 0))
				return_0;

			/* Replace mirror with error segment */
			if (!(lseg->segtype =
			      get_segtype_from_string(lv->vg->cmd, "error"))) {
				log_error("Missing error segtype");
				return 0;
			}
			lseg->area_count = 0;

			/* First time, add LV to list of LVs affected */
			if (!lv_changed && lvs_changed) {
				if (!(lvl = dm_pool_alloc(cmd->mem, sizeof(*lvl)))) {
					log_error("lv_list alloc failed");
					return 0;
				}
				lvl->lv = lv;
				dm_list_add(lvs_changed, &lvl->list);
				lv_changed = 1;
			}
		}
	}
	if (lv_changed && !lv_merge_segments(lv))
		stack;

	return 1;
}

/* Remove a layer */
int remove_layers_for_segments_all(struct cmd_context *cmd,
				   struct logical_volume *layer_lv,
				   uint64_t status_mask,
				   struct dm_list *lvs_changed)
{
	struct lv_list *lvl;
	struct logical_volume *lv1;

	/* Loop through all LVs except the temporary mirror */
	dm_list_iterate_items(lvl, &layer_lv->vg->lvs) {
		lv1 = lvl->lv;
		if (lv1 == layer_lv)
			continue;

		if (!remove_layers_for_segments(cmd, lv1, layer_lv,
						status_mask, lvs_changed))
			return_0;
	}

	if (!lv_empty(layer_lv))
		return_0;

	return 1;
}

int move_lv_segments(struct logical_volume *lv_to,
		     struct logical_volume *lv_from,
		     uint64_t set_status, uint64_t reset_status)
{
	const uint64_t MOVE_BITS = (RAID | MIRROR | THIN_VOLUME);
	struct lv_segment *seg;

	dm_list_iterate_items(seg, &lv_to->segments)
		if (seg->origin) {
			log_error("Can't move snapshot segment.");
			return 0;
		}

	dm_list_init(&lv_to->segments);
	dm_list_splice(&lv_to->segments, &lv_from->segments);

	dm_list_iterate_items(seg, &lv_to->segments) {
		seg->lv = lv_to;
		seg->status &= ~reset_status;
		seg->status |= set_status;
	}

	/*
	 * Move LV status bits for selected types with their segments
	 * i.e. when inserting layer to cache LV, we move raid segments
	 * to a new place, thus 'raid' LV property now belongs to this LV.
	 *
	 * Bits should match to those which appears after read from disk.
	 */
	lv_to->status |= lv_from->status & MOVE_BITS;
	lv_from->status &= ~MOVE_BITS;

	lv_to->le_count = lv_from->le_count;
	lv_to->size = lv_from->size;

	lv_from->le_count = 0;
	lv_from->size = 0;

	return 1;
}

/* Remove a layer from the LV */
int remove_layer_from_lv(struct logical_volume *lv,
			 struct logical_volume *layer_lv)
{
	static const char _suffixes[][8] = { "_tdata", "_cdata", "_corig" };
	struct logical_volume *parent_lv;
	struct lv_segment *parent_seg;
	struct segment_type *segtype;
	struct lv_names lv_names;
	int r;

	log_very_verbose("Removing layer %s for %s", layer_lv->name, lv->name);

	if (!(parent_seg = get_only_segment_using_this_lv(layer_lv))) {
		log_error("Failed to find layer %s in %s",
			  layer_lv->name, lv->name);
		return 0;
	}
	parent_lv = parent_seg->lv;
	if (parent_lv != lv) {
		log_error(INTERNAL_ERROR "Wrong layer %s in %s",
			  layer_lv->name, lv->name);
		return 0;
	}

	/*
	 * Before removal, the layer should be cleaned up,
	 * i.e. additional segments and areas should have been removed.
	 */
	if (dm_list_size(&parent_lv->segments) != 1 ||
	    parent_seg->area_count != 1 ||
	    seg_type(parent_seg, 0) != AREA_LV ||
	    layer_lv != seg_lv(parent_seg, 0) ||
	    parent_lv->le_count != layer_lv->le_count)
		return_0;

	if (!lv_empty(parent_lv))
		return_0;

	if (!move_lv_segments(parent_lv, layer_lv, 0, 0))
		return_0;

	/* Replace the empty layer with error segment */
	if (!(segtype = get_segtype_from_string(lv->vg->cmd, "error")))
		return_0;
	if (!lv_add_virtual_segment(layer_lv, 0, parent_lv->le_count, segtype))
		return_0;

	/*
	 * recuresively rename sub LVs
	 *   currently supported only for thin data layer
	 *   FIXME: without strcmp it breaks mirrors....
	 */
	if (!strstr(layer_lv->name, "_mimage"))
		for (r = 0; r < DM_ARRAY_SIZE(_suffixes); ++r)
			if (strstr(layer_lv->name, _suffixes[r]) == 0) {
				lv_names.old = layer_lv->name;
				lv_names.new = parent_lv->name;
				if (!for_each_sub_lv(parent_lv, _rename_cb, (void *) &lv_names))
					return_0;
				break;
			}

	return 1;
}

/*
 * Create and insert a linear LV "above" lv_where.
 * After the insertion, a new LV named lv_where->name + suffix is created
 * and all segments of lv_where is moved to the new LV.
 * lv_where will have a single segment which maps linearly to the new LV.
 */
struct logical_volume *insert_layer_for_lv(struct cmd_context *cmd,
					   struct logical_volume *lv_where,
					   uint64_t status,
					   const char *layer_suffix)
{
	static const char _suffixes[][8] = { "_tdata", "_cdata", "_corig" };
	int r;
	char name[NAME_LEN];
	struct dm_str_list *sl;
	struct logical_volume *layer_lv;
	struct segment_type *segtype;
	struct lv_segment *mapseg;
	struct lv_names lv_names;
	unsigned exclusive = 0;

	/* create an empty layer LV */
	if (dm_snprintf(name, sizeof(name), "%s%s", lv_where->name, layer_suffix) < 0) {
		log_error("Layered name is too long. Please use shorter LV name.");
		return NULL;
	}

	if (!(layer_lv = lv_create_empty(name, NULL,
					 /* Preserve read-only flag */
					 LVM_READ | (lv_where->status & LVM_WRITE),
					 ALLOC_INHERIT, lv_where->vg))) {
		log_error("Creation of layer LV failed");
		return NULL;
	}

	if (lv_is_active_exclusive_locally(lv_where))
		exclusive = 1;

	if (lv_is_active(lv_where) && strstr(name, "_mimagetmp")) {
		log_very_verbose("Creating transient LV %s for mirror conversion in VG %s.", name, lv_where->vg->name);

		segtype = get_segtype_from_string(cmd, "error");

		if (!lv_add_virtual_segment(layer_lv, 0, lv_where->le_count, segtype)) {
			log_error("Creation of transient LV %s for mirror conversion in VG %s failed.", name, lv_where->vg->name);
			return NULL;
		}

		/* Temporary tags for activation of the transient LV */
		dm_list_iterate_items(sl, &lv_where->tags)
			if (!str_list_add(cmd->mem, &layer_lv->tags, sl->str)) {
				log_error("Aborting.  Unable to tag"
					  " transient mirror layer.");
				return NULL;
			}

		if (!vg_write(lv_where->vg)) {
			log_error("Failed to write intermediate VG %s metadata for mirror conversion.", lv_where->vg->name);
			return NULL;
		}

		if (!vg_commit(lv_where->vg)) {
			log_error("Failed to commit intermediate VG %s metadata for mirror conversion.", lv_where->vg->name);
			return NULL;
		}

		if (exclusive)
			r = activate_lv_excl(cmd, layer_lv);
		else
			r = activate_lv(cmd, layer_lv);

		if (!r) {
			log_error("Failed to resume transient LV"
				  " %s for mirror conversion in VG %s.",
				  name, lv_where->vg->name);
			return NULL;
		}

		/* Remove the temporary tags */
		dm_list_iterate_items(sl, &lv_where->tags)
			str_list_del(&layer_lv->tags, sl->str);
	}

	log_very_verbose("Inserting layer %s for %s",
			 layer_lv->name, lv_where->name);

	if (!move_lv_segments(layer_lv, lv_where, 0, 0))
		return_NULL;

	if (!(segtype = get_segtype_from_string(cmd, "striped")))
		return_NULL;

	/* allocate a new linear segment */
	if (!(mapseg = alloc_lv_segment(segtype, lv_where, 0, layer_lv->le_count,
					status, 0, NULL, 1, layer_lv->le_count,
					0, 0, 0, NULL)))
		return_NULL;

	/* map the new segment to the original underlying are */
	if (!set_lv_segment_area_lv(mapseg, 0, layer_lv, 0, 0))
		return_NULL;

	/* add the new segment to the layer LV */
	dm_list_add(&lv_where->segments, &mapseg->list);
	lv_where->le_count = layer_lv->le_count;
	lv_where->size = (uint64_t) lv_where->le_count * lv_where->vg->extent_size;

	/*
	 * recuresively rename sub LVs
	 *   currently supported only for thin data layer
	 *   FIXME: without strcmp it breaks mirrors....
	 */
	for (r = 0; r < DM_ARRAY_SIZE(_suffixes); ++r)
		if (strcmp(layer_suffix, _suffixes[r]) == 0) {
			lv_names.old = lv_where->name;
			lv_names.new = layer_lv->name;
			if (!for_each_sub_lv(layer_lv, _rename_cb, (void *) &lv_names))
				return_NULL;
			break;
		}

	return layer_lv;
}

/*
 * Extend and insert a linear layer LV beneath the source segment area.
 */
static int _extend_layer_lv_for_segment(struct logical_volume *layer_lv,
					struct lv_segment *seg, uint32_t s,
					uint64_t status)
{
	struct lv_segment *mapseg;
	struct segment_type *segtype;
	struct physical_volume *src_pv = seg_pv(seg, s);
	uint32_t src_pe = seg_pe(seg, s);

	if (seg_type(seg, s) != AREA_PV && seg_type(seg, s) != AREA_LV)
		return_0;

	if (!(segtype = get_segtype_from_string(layer_lv->vg->cmd, "striped")))
		return_0;

	/* FIXME Incomplete message? Needs more context */
	log_very_verbose("Inserting %s:%" PRIu32 "-%" PRIu32 " of %s/%s",
			 pv_dev_name(src_pv),
			 src_pe, src_pe + seg->area_len - 1,
			 seg->lv->vg->name, seg->lv->name);

	/* allocate a new segment */
	if (!(mapseg = alloc_lv_segment(segtype, layer_lv, layer_lv->le_count,
					seg->area_len, status, 0,
					NULL, 1, seg->area_len, 0, 0, 0, seg)))
		return_0;

	/* map the new segment to the original underlying are */
	if (!move_lv_segment_area(mapseg, 0, seg, s))
		return_0;

	/* add the new segment to the layer LV */
	dm_list_add(&layer_lv->segments, &mapseg->list);
	layer_lv->le_count += seg->area_len;
	layer_lv->size += (uint64_t) seg->area_len * layer_lv->vg->extent_size;

	/* map the original area to the new segment */
	if (!set_lv_segment_area_lv(seg, s, layer_lv, mapseg->le, 0))
		return_0;

	return 1;
}

/*
 * Match the segment area to PEs in the pvl
 * (the segment area boundary should be aligned to PE ranges by
 *  _adjust_layer_segments() so that there is no partial overlap.)
 */
static int _match_seg_area_to_pe_range(struct lv_segment *seg, uint32_t s,
				       struct pv_list *pvl)
{
	struct pe_range *per;
	uint32_t pe_start, per_end;

	if (!pvl)
		return 1;

	if (seg_type(seg, s) != AREA_PV || seg_dev(seg, s) != pvl->pv->dev)
		return 0;

	pe_start = seg_pe(seg, s);

	/* Do these PEs match to any of the PEs in pvl? */
	dm_list_iterate_items(per, pvl->pe_ranges) {
		per_end = per->start + per->count - 1;

		if ((pe_start < per->start) || (pe_start > per_end))
			continue;

		/* FIXME Missing context in this message - add LV/seg details */
		log_debug_alloc("Matched PE range %s:%" PRIu32 "-%" PRIu32 " against "
				"%s %" PRIu32 " len %" PRIu32, dev_name(pvl->pv->dev),
				per->start, per_end, dev_name(seg_dev(seg, s)),
				seg_pe(seg, s), seg->area_len);

		return 1;
	}

	return 0;
}

/*
 * For each segment in lv_where that uses a PV in pvl directly,
 * split the segment if it spans more than one underlying PV.
 */
static int _align_segment_boundary_to_pe_range(struct logical_volume *lv_where,
					       struct pv_list *pvl)
{
	struct lv_segment *seg;
	struct pe_range *per;
	uint32_t pe_start, pe_end, per_end, stripe_multiplier, s;

	if (!pvl)
		return 1;

	/* Split LV segments to match PE ranges */
	dm_list_iterate_items(seg, &lv_where->segments) {
		for (s = 0; s < seg->area_count; s++) {
			if (seg_type(seg, s) != AREA_PV ||
			    seg_dev(seg, s) != pvl->pv->dev)
				continue;

			/* Do these PEs match with the condition? */
			dm_list_iterate_items(per, pvl->pe_ranges) {
				pe_start = seg_pe(seg, s);
				pe_end = pe_start + seg->area_len - 1;
				per_end = per->start + per->count - 1;

				/* No overlap? */
				if ((pe_end < per->start) ||
				    (pe_start > per_end))
					continue;

				if (seg_is_striped(seg))
					stripe_multiplier = seg->area_count;
				else
					stripe_multiplier = 1;

				if ((per->start != pe_start &&
				     per->start > pe_start) &&
				    !lv_split_segment(lv_where, seg->le +
						      (per->start - pe_start) *
						      stripe_multiplier))
					return_0;

				if ((per_end != pe_end &&
				     per_end < pe_end) &&
				    !lv_split_segment(lv_where, seg->le +
						      (per_end - pe_start + 1) *
						      stripe_multiplier))
					return_0;
			}
		}
	}

	return 1;
}

/*
 * Scan lv_where for segments on a PV in pvl, and for each one found
 * append a linear segment to lv_layer and insert it between the two.
 *
 * If pvl is empty, a layer is placed under the whole of lv_where.
 * If the layer is inserted, lv_where is added to lvs_changed.
 */
int insert_layer_for_segments_on_pv(struct cmd_context *cmd,
				    struct logical_volume *lv_where,
				    struct logical_volume *layer_lv,
				    uint64_t status,
				    struct pv_list *pvl,
				    struct dm_list *lvs_changed)
{
	struct lv_segment *seg;
	struct lv_list *lvl;
	int lv_used = 0;
	uint32_t s;

	log_very_verbose("Inserting layer %s for segments of %s on %s",
			 layer_lv->name, lv_where->name,
			 pvl ? pv_dev_name(pvl->pv) : "any");

	if (!_align_segment_boundary_to_pe_range(lv_where, pvl))
		return_0;

	/* Work through all segments on the supplied PV */
	dm_list_iterate_items(seg, &lv_where->segments) {
		for (s = 0; s < seg->area_count; s++) {
			if (!_match_seg_area_to_pe_range(seg, s, pvl))
				continue;

			/* First time, add LV to list of LVs affected */
			if (!lv_used && lvs_changed) {
				if (!(lvl = dm_pool_alloc(cmd->mem, sizeof(*lvl)))) {
					log_error("lv_list alloc failed");
					return 0;
				}
				lvl->lv = lv_where;
				dm_list_add(lvs_changed, &lvl->list);
				lv_used = 1;
			}

			if (!_extend_layer_lv_for_segment(layer_lv, seg, s,
							  status)) {
				log_error("Failed to insert segment in layer "
					  "LV %s under %s:%" PRIu32 "-%" PRIu32,
					  layer_lv->name, lv_where->name,
					  seg->le, seg->le + seg->len);
				return 0;
			}
		}
	}

	return 1;
}

/*
 * Initialize the LV with 'value'.
 */
int wipe_lv(struct logical_volume *lv, struct wipe_params wp)
{
	struct device *dev;
	char name[PATH_MAX];
	uint64_t zero_sectors;

	if (!wp.do_zero && !wp.do_wipe_signatures)
		/* nothing to do */
		return 1;

	/* Wait until devices are available */
	if (!sync_local_dev_names(lv->vg->cmd)) {
		log_error("Failed to sync local devices before wiping LV %s.",
			  display_lvname(lv));
		return 0;
	}

	if (!lv_is_active_locally(lv)) {
		log_error("Volume \"%s/%s\" is not active locally.",
			  lv->vg->name, lv->name);
		return 0;
	}

	/*
	 * FIXME:
	 * <clausen> also, more than 4k
	 * <clausen> say, reiserfs puts it's superblock 32k in, IIRC
	 * <ejt_> k, I'll drop a fixme to that effect
	 *	   (I know the device is at least 4k, but not 32k)
	 */
	if (dm_snprintf(name, sizeof(name), "%s%s/%s", lv->vg->cmd->dev_dir,
			lv->vg->name, lv->name) < 0) {
		log_error("Name too long - device not cleared (%s)", lv->name);
		return 0;
	}

	if (!(dev = dev_cache_get(name, NULL))) {
		log_error("%s: not found: device not cleared", name);
		return 0;
	}

	if (!dev_open_quiet(dev))
		return_0;

	if (wp.do_wipe_signatures) {
		log_verbose("Wiping known signatures on logical volume \"%s/%s\"",
			     lv->vg->name, lv->name);
		if (!wipe_known_signatures(lv->vg->cmd, dev, name, 0,
					   TYPE_DM_SNAPSHOT_COW,
					   wp.yes, wp.force, NULL))
			stack;
	}

	if (wp.do_zero) {
		zero_sectors = wp.zero_sectors ? : UINT64_C(4096) >> SECTOR_SHIFT;

		if (zero_sectors > lv->size)
			zero_sectors = lv->size;

		log_verbose("Initializing %s of logical volume \"%s/%s\" with value %d.",
			    display_size(lv->vg->cmd, zero_sectors),
			    lv->vg->name, lv->name, wp.zero_value);

		if (!dev_set(dev, UINT64_C(0), (size_t) zero_sectors << SECTOR_SHIFT, wp.zero_value))
			stack;
	}

	dev_flush(dev);

	if (!dev_close_immediate(dev))
		stack;

	lv->status &= ~LV_NOSCAN;

	return 1;
}

static struct logical_volume *_create_virtual_origin(struct cmd_context *cmd,
						     struct volume_group *vg,
						     const char *lv_name,
						     uint32_t permission,
						     uint64_t voriginextents)
{
	const struct segment_type *segtype;
	char vorigin_name[NAME_LEN];
	struct logical_volume *lv;

	if (!(segtype = get_segtype_from_string(cmd, "zero"))) {
		log_error("Zero segment type for virtual origin not found");
		return NULL;
	}

	if (dm_snprintf(vorigin_name, sizeof(vorigin_name), "%s_vorigin", lv_name) < 0) {
		log_error("Virtual origin name is too long.");
		return NULL;
	}

	if (!(lv = lv_create_empty(vorigin_name, NULL, permission,
				   ALLOC_INHERIT, vg)))
		return_NULL;

	if (!lv_extend(lv, segtype, 1, 0, 1, 0, voriginextents,
		       NULL, ALLOC_INHERIT, 0))
		return_NULL;

	return lv;
}

/*
 * Automatically set ACTIVATION_SKIP flag for the LV supplied - this
 * is default behaviour. If override_default is set, then override
 * the default behaviour and add/clear the flag based on 'add_skip' arg
 * supplied instead.
 */
void lv_set_activation_skip(struct logical_volume *lv, int override_default,
			    int add_skip)
{
	int skip = 0;

	/* override default behaviour */
	if (override_default)
		skip = add_skip;
	/* default behaviour */
	else if (lv->vg->cmd->auto_set_activation_skip) {
		 /* skip activation for thin snapshots by default */
		if (lv_is_thin_volume(lv) && first_seg(lv)->origin)
			skip = 1;
	}

	if (skip)
		lv->status |= LV_ACTIVATION_SKIP;
	else
		lv->status &= ~LV_ACTIVATION_SKIP;
}

/*
 * Get indication whether the LV should be skipped during activation
 * based on the ACTIVATION_SKIP flag (deactivation is never skipped!).
 * If 'override_lv_skip_flag' is set, then override it based on the value
 * of the 'skip' arg supplied instead.
 */
int lv_activation_skip(struct logical_volume *lv, activation_change_t activate,
		       int override_lv_skip_flag)
{
	if (!(lv->status & LV_ACTIVATION_SKIP) ||
	    !is_change_activating(activate) || /* Do not skip deactivation */
	    override_lv_skip_flag)
		return 0;

	log_verbose("ACTIVATION_SKIP flag set for LV %s/%s, skipping activation.",
		    lv->vg->name, lv->name);
	return 1;
}

static int _should_wipe_lv(struct lvcreate_params *lp,
			   struct logical_volume *lv, int warn)
{
	/* Unzeroable segment */
	if (first_seg(lv)->segtype->flags & SEG_CANNOT_BE_ZEROED)
		return 0;

	/* Thin snapshot need not to be zeroed */
	/* Thin pool with zeroing doesn't need zeroing or wiping */
	if (lv_is_thin_volume(lv) &&
	    (first_seg(lv)->origin ||
	     first_seg(first_seg(lv)->pool_lv)->zero_new_blocks))
		return 0;

	/* Cannot zero read-only volume */
	if ((lv->status & LVM_WRITE) &&
	    (lp->zero || lp->wipe_signatures))
		return 1;

	if (warn && (!lp->zero || !(lv->status & LVM_WRITE)))
		log_warn("WARNING: Logical volume %s not zeroed.",
			 display_lvname(lv));
	if (warn && (!lp->wipe_signatures || !(lv->status & LVM_WRITE)))
		log_verbose("Signature wiping on logical volume %s not requested.",
			    display_lvname(lv));

	return 0;
}

/* Check if VG metadata supports needed features */
static int _vg_check_features(struct volume_group *vg,
			      struct lvcreate_params *lp)
{
	uint32_t features = vg->fid->fmt->features;

	if (vg_max_lv_reached(vg)) {
		log_error("Maximum number of logical volumes (%u) reached "
			  "in volume group %s", vg->max_lv, vg->name);
		return 0;
	}

	if (!(features & FMT_SEGMENTS) &&
	    (seg_is_cache(lp) ||
	     seg_is_cache_pool(lp) ||
	     seg_is_mirrored(lp) ||
	     seg_is_raid(lp) ||
	     seg_is_thin(lp))) {
		log_error("Metadata does not support %s segments.",
			  lp->segtype->name);
		return 0;
	}

	if (!(features & FMT_TAGS) && !dm_list_empty(&lp->tags)) {
		log_error("Volume group %s does not support tags.", vg->name);
		return 0;
	}

	if ((features & FMT_RESTRICTED_READAHEAD) &&
	    lp->read_ahead != DM_READ_AHEAD_AUTO &&
	    lp->read_ahead != DM_READ_AHEAD_NONE &&
	    (lp->read_ahead < 2 || lp->read_ahead > 120)) {
		log_error("Metadata only supports readahead values between 2 and 120.");
		return 0;
	}

	/* Need to check the vg's format to verify this - the cmd format isn't setup properly yet */
	if (!(features & FMT_UNLIMITED_STRIPESIZE) &&
	    (lp->stripes > 1) && (lp->stripe_size > STRIPE_SIZE_MAX)) {
		log_error("Stripe size may not exceed %s.",
			  display_size(vg->cmd, (uint64_t) STRIPE_SIZE_MAX));
		return 0;
	}

	return 1;
}

/* Thin notes:
 * If lp->thin OR lp->activate is AY*, activate the pool if not already active.
 * If lp->thin, create thin LV within the pool - as a snapshot if lp->snapshot.
 *   If lp->activate is AY*, activate it.
 *   If lp->activate was AN* and the pool was originally inactive, deactivate it.
 */
static struct logical_volume *_lv_create_an_lv(struct volume_group *vg,
					       struct lvcreate_params *lp,
					       const char *new_lv_name)
{
	struct cmd_context *cmd = vg->cmd;
	uint32_t size_rest, size;
	uint64_t status = lp->permission | VISIBLE_LV;
	const struct segment_type *create_segtype = lp->segtype;
	struct logical_volume *lv, *origin_lv = NULL;
	struct logical_volume *pool_lv = NULL;
	struct logical_volume *tmp_lv;
	struct lv_segment *seg, *pool_seg;
	int thin_pool_was_active = -1; /* not scanned, inactive, active */

	if (new_lv_name && find_lv_in_vg(vg, new_lv_name)) {
		log_error("Logical volume \"%s\" already exists in "
			  "volume group \"%s\"", new_lv_name, vg->name);
		return NULL;
	}

	if (!_vg_check_features(vg, lp))
		return_NULL;

	if (!activation()) {
		if (seg_is_cache(lp) ||
		    seg_is_mirror(lp) ||
		    seg_is_raid(lp) ||
		    seg_is_thin(lp) ||
		    lp->snapshot) {
			/*
			 * FIXME: For thin pool add some code to allow delayed
			 * initialization of empty thin pool volume.
			 * i.e. using some LV flag, fake message,...
			 * and testing for metadata pool header signature?
			 */
			log_error("Can't create %s without using "
				  "device-mapper kernel driver.",
				  lp->segtype->name);
			return NULL;
		}
		/* Does LV need to be zeroed? */
		if (lp->zero && !seg_is_thin(lp)) {
			log_error("Can't wipe start of new LV without using "
				  "device-mapper kernel driver.");
			return NULL;
		}
	}

	if (lp->stripe_size > vg->extent_size) {
		if (seg_is_raid(lp) && (vg->extent_size < STRIPE_SIZE_MIN)) {
			/*
			 * FIXME: RAID will simply fail to load the table if
			 *        this is the case, but we should probably
			 *        honor the stripe minimum for regular stripe
			 *        volumes as well.  Avoiding doing that now
			 *        only to minimize the change.
			 */
			log_error("The extent size in volume group %s is too "
				  "small to support striped RAID volumes.",
				  vg->name);
			return NULL;
		}

		log_print_unless_silent("Reducing requested stripe size %s to maximum, "
					"physical extent size %s.",
					display_size(cmd, (uint64_t) lp->stripe_size),
					display_size(cmd, (uint64_t) vg->extent_size));
		lp->stripe_size = vg->extent_size;
	}

	if ((size_rest = lp->extents % lp->stripes)) {
		log_print_unless_silent("Rounding size (%d extents) up to stripe boundary "
					"size (%d extents).", lp->extents,
					lp->extents - size_rest + lp->stripes);
		lp->extents = lp->extents - size_rest + lp->stripes;
	}

	if (!lp->extents && !seg_is_thin_volume(lp)) {
		log_error(INTERNAL_ERROR "Unable to create new logical volume with no extents.");
		return_NULL;
	}

	if ((seg_is_pool(lp) || seg_is_cache(lp)) &&
	    ((uint64_t)lp->extents * vg->extent_size < lp->chunk_size)) {
		log_error("Unable to create %s smaller than 1 chunk.",
			  lp->segtype->name);
		return NULL;
	}

	if ((lp->alloc != ALLOC_ANYWHERE) && (lp->stripes > dm_list_size(lp->pvh))) {
		log_error("Number of stripes (%u) must not exceed "
			  "number of physical volumes (%d)", lp->stripes,
			  dm_list_size(lp->pvh));
		return NULL;
	}

	if (seg_is_pool(lp))
		status |= LVM_WRITE; /* Pool is always writable */
	else if (seg_is_cache(lp) || seg_is_thin_volume(lp)) {
		/* Resolve pool volume */
		if (!lp->pool_name) {
			/* Should be already checked */
			log_error(INTERNAL_ERROR "Cannot create %s volume without %s pool.",
				  lp->segtype->name, lp->segtype->name);
			return NULL;
		}

		if (!(pool_lv = find_lv(vg, lp->pool_name))) {
			log_error("Couldn't find volume %s in Volume group %s.",
				  lp->pool_name, vg->name);
			return NULL;
		}

		if (lv_is_locked(pool_lv)) {
			log_error("Cannot use locked pool volume %s.",
				  display_lvname(pool_lv));
			return NULL;
		}

		/* Validate volume size to to aling on chunk for small extents */
		/* Cache chunk size is always set */
		size = seg_is_cache(lp) ? lp->chunk_size : first_seg(pool_lv)->chunk_size;
		if (size > vg->extent_size) {
			/* Align extents on chunk boundary size */
			size = ((uint64_t)vg->extent_size * lp->extents + size - 1) /
				size * size / vg->extent_size;
			if (size != lp->extents) {
				log_print_unless_silent("Rounding size (%d extents) up to chunk boundary "
							"size (%d extents).", lp->extents, size);
				lp->extents = size;
			}
		}

		if (seg_is_thin_volume(lp) &&
		    lv_is_new_thin_pool(pool_lv)) {
			thin_pool_was_active = lv_is_active(pool_lv);
			if (!check_new_thin_pool(pool_lv))
				return_NULL;
			/* New pool is now inactive */
		}

		if (seg_is_cache(lp) &&
		    !wipe_cache_pool(pool_lv))
			return_NULL;
	}

	/* Resolve origin volume */
	if (lp->origin_name &&
	    !(origin_lv = find_lv(vg, lp->origin_name))) {
		log_error("Origin volume %s not found in Volume group %s.",
			  lp->origin_name, vg->name);
		return NULL;
	}

	if (origin_lv && seg_is_cache_pool(lp)) {
		/* Converting exiting origin and creating cache pool */
		if (!validate_lv_cache_create_origin(origin_lv))
			return_NULL;

		if (origin_lv->size < lp->chunk_size) {
			log_error("Caching of origin cache volume smaller then chunk size is unsupported.");
			return NULL;
		}

		/* Validate cache origin is exclusively active */
		if (vg_is_clustered(origin_lv->vg) &&
		    locking_is_clustered() &&
		    locking_supports_remote_queries() &&
		    lv_is_active(origin_lv) &&
		    !lv_is_active_exclusive(origin_lv)) {
			log_error("Cannot cache not exclusively active origin volume %s.",
				  display_lvname(origin_lv));
			return NULL;
		}
	} else if (seg_is_cache(lp)) {
		if (!pool_lv) {
			log_error(INTERNAL_ERROR "Pool LV for cache is missing.");
			return NULL;
		}
		if (!lv_is_cache_pool(pool_lv)) {
			log_error("Logical volume %s is not a cache pool.",
				  display_lvname(pool_lv));
			return NULL;
		}
		/* Create cache origin for cache pool */
		/* FIXME Eventually support raid/mirrors with -m */
		if (!(create_segtype = get_segtype_from_string(vg->cmd, "striped")))
			return_0;
	} else if (seg_is_mirrored(lp) || seg_is_raid(lp)) {
		if (is_change_activating(lp->activate) && (lp->activate != CHANGE_AEY) &&
		    vg_is_clustered(vg) && seg_is_mirrored(lp) && !seg_is_raid(lp) &&
		    !cluster_mirror_is_available(vg->cmd)) {
			log_error("Shared cluster mirrors are not available.");
			return NULL;
		}

		/* FIXME This will not pass cluster lock! */
		init_mirror_in_sync(lp->nosync);

		if (lp->nosync) {
			log_warn("WARNING: New %s won't be synchronised. "
				 "Don't read what you didn't write!",
				 lp->segtype->name);
			status |= LV_NOTSYNCED;
		}

		lp->region_size = adjusted_mirror_region_size(vg->extent_size,
							      lp->extents,
							      lp->region_size, 0,
							      vg_is_clustered(vg));
	} else if (pool_lv && seg_is_thin_volume(lp)) {
		if (!lv_is_thin_pool(pool_lv)) {
			log_error("Logical volume %s is not a thin pool.",
				  display_lvname(pool_lv));
			return NULL;
		}

		if (origin_lv) {
			if (lv_is_locked(origin_lv)) {
				log_error("Snapshots of locked devices are not supported.");
				return NULL;
			}

			lp->virtual_extents = origin_lv->le_count;

			/*
			 * Check if using 'external origin' or the 'normal' snapshot
			 * within the same thin pool
			 */
			if (first_seg(origin_lv)->pool_lv != pool_lv) {
				if (!pool_supports_external_origin(first_seg(pool_lv), origin_lv))
					return_NULL;
				if (origin_lv->status & LVM_WRITE) {
					log_error("Cannot use writable LV as the external origin.");
					return NULL; /* FIXME conversion for inactive */
				}
				if (lv_is_active(origin_lv) && !lv_is_external_origin(origin_lv)) {
					log_error("Cannot use active LV for the external origin.");
					return NULL; /* We can't be sure device is read-only */
				}
			}
		}
	} else if (lp->snapshot) {
		if (!lp->virtual_extents) {
			if (!origin_lv) {
				log_error("Couldn't find origin volume '%s'.",
					  lp->origin_name);
				return NULL;
			}
			if (lv_is_virtual_origin(origin_lv)) {
				log_error("Can't share virtual origins. "
					  "Use --virtualsize.");
				return NULL;
			}
			if (lv_is_cow(origin_lv)) {
				log_error("Snapshots of snapshots are not "
					  "supported yet.");
				return NULL;
			}
			if (lv_is_locked(origin_lv)) {
				log_error("Snapshots of locked devices are not supported.");
				return NULL;
			}
			if (lv_is_merging_origin(origin_lv)) {
				log_error("Snapshots of an origin that has a "
					  "merging snapshot is not supported");
				return NULL;
			}

			if (lv_is_cache_type(origin_lv)) {
				log_error("Snapshots of cache type volume %s "
					  "is not supported.", display_lvname(origin_lv));
				return NULL;
			}

			if (lv_is_thin_type(origin_lv) && !lv_is_thin_volume(origin_lv)) {
				log_error("Snapshots of thin pool %sdevices "
					  "are not supported.",
					  lv_is_thin_pool_data(origin_lv) ? "data " :
					  lv_is_thin_pool_metadata(origin_lv) ?
					  "metadata " : "");
				return NULL;
			}

			if (lv_is_mirror_type(origin_lv)) {
				log_warn("WARNING: Snapshots of mirrors can deadlock under rare device failures.");
				log_warn("WARNING: Consider using the raid1 mirror type to avoid this.");
				log_warn("WARNING: See global/mirror_segtype_default in lvm.conf.");
			}

			if (vg_is_clustered(vg) && lv_is_active(origin_lv) &&
			    !lv_is_active_exclusive_locally(origin_lv)) {
				log_error("%s must be active exclusively to"
					  " create snapshot", origin_lv->name);
				return NULL;
			}
		}

		if (!cow_has_min_chunks(vg, lp->extents, lp->chunk_size))
			return_NULL;

		/* The snapshot segment gets created later */
		if (!(create_segtype = get_segtype_from_string(cmd, "striped")))
			return_NULL;

		/* Must zero cow */
		status |= LVM_WRITE;
		lp->zero = 1;
		lp->wipe_signatures = 0;
	}

	if (!seg_is_virtual(lp) && !lp->approx_alloc &&
	    (vg->free_count < lp->extents)) {
		log_error("Volume group \"%s\" has insufficient free space "
			  "(%u extents): %u required.",
			  vg->name, vg->free_count, lp->extents);
		return NULL;
	}

	if (!archive(vg))
		return_NULL;


	if (pool_lv && seg_is_thin_volume(lp)) {
		/* Ensure all stacked messages are submitted */
		if ((pool_is_active(pool_lv) || is_change_activating(lp->activate)) &&
		    !update_pool_lv(pool_lv, 1))
			return_NULL;
	}

	if (!(lv = lv_create_empty(new_lv_name ? : "lvol%d", NULL,
				   status, lp->alloc, vg)))
		return_NULL;

	if (lp->read_ahead != lv->read_ahead) {
		lv->read_ahead = lp->read_ahead;
		log_debug_metadata("Setting read ahead sectors %u.", lv->read_ahead);
	}

	if (!seg_is_pool(lp) && lp->minor >= 0) {
		lv->major = lp->major;
		lv->minor = lp->minor;
		lv->status |= FIXED_MINOR;
		log_debug_metadata("Setting device number to (%d, %d).",
				   lv->major, lv->minor);
	}

	/*
	 * The specific LV may not use a lock.  lockd_init_lv() sets
	 * lv->lock_args to NULL if this LV does not use its own lock.
	 */

	if (!lockd_init_lv(vg->cmd, vg, lv, lp))
		return_NULL;

	dm_list_splice(&lv->tags, &lp->tags);

	if (!lv_extend(lv, create_segtype,
		       lp->stripes, lp->stripe_size,
		       lp->mirrors,
		       seg_is_pool(lp) ? lp->pool_metadata_extents : lp->region_size,
		       seg_is_thin_volume(lp) ? lp->virtual_extents : lp->extents,
		       lp->pvh, lp->alloc, lp->approx_alloc))
		return_NULL;

	/* Unlock memory if possible */
	memlock_unlock(vg->cmd);

	if (seg_is_cache_pool(lp) || seg_is_cache(lp)) {
		if (!cache_set_mode(first_seg(lv), lp->cache_mode)) {
			stack;
			goto revert_new_lv;
		}

		if (!cache_set_policy(first_seg(lv), lp->policy_name, lp->policy_settings)) {
			stack;
			goto revert_new_lv;
		}

		pool_lv = pool_lv ? : lv;
		if (lp->chunk_size) {
			first_seg(pool_lv)->chunk_size = lp->chunk_size;
			/* TODO: some calc_policy solution for cache ? */
			if (!recalculate_pool_chunk_size_with_dev_hints(pool_lv, lp->passed_args,
									THIN_CHUNK_SIZE_CALC_METHOD_GENERIC)) {
				stack;
				goto revert_new_lv;
			}
		}
	} else if (seg_is_raid(lp)) {
		first_seg(lv)->min_recovery_rate = lp->min_recovery_rate;
		first_seg(lv)->max_recovery_rate = lp->max_recovery_rate;
	} else if (seg_is_thin_pool(lp)) {
		first_seg(lv)->chunk_size = lp->chunk_size;
		first_seg(lv)->zero_new_blocks = lp->zero ? 1 : 0;
		first_seg(lv)->discards = lp->discards;
		/* FIXME: use lowwatermark  via lvm.conf global for all thinpools ? */
		first_seg(lv)->low_water_mark = 0;
		if (!recalculate_pool_chunk_size_with_dev_hints(lv, lp->passed_args,
								lp->thin_chunk_size_calc_policy)) {
			stack;
			goto revert_new_lv;
		}
		if (lp->error_when_full)
			lv->status |= LV_ERROR_WHEN_FULL;
	} else if (pool_lv && seg_is_thin_volume(lp)) {
		seg = first_seg(lv);
		pool_seg = first_seg(pool_lv);
		if (!(seg->device_id = get_free_pool_device_id(pool_seg)))
			return_NULL;
		seg->transaction_id = pool_seg->transaction_id;
		if (origin_lv && lv_is_thin_volume(origin_lv) &&
		    (first_seg(origin_lv)->pool_lv == pool_lv)) {
			/* For thin snapshot pool must match */
			if (!attach_pool_lv(seg, pool_lv, origin_lv, NULL))
				return_NULL;
			/* Use the same external origin */
			if (!attach_thin_external_origin(seg, first_seg(origin_lv)->external_lv))
				return_NULL;
		} else {
			if (!attach_pool_lv(seg, pool_lv, NULL, NULL))
				return_NULL;
			/* If there is an external origin... */
			if (!attach_thin_external_origin(seg, origin_lv))
				return_NULL;
		}

		if (!attach_pool_message(pool_seg, DM_THIN_MESSAGE_CREATE_THIN, lv, 0, 0))
			return_NULL;
	}

	if (!pool_check_overprovisioning(lv))
		return_NULL;

	/* FIXME Log allocation and attachment should have happened inside lv_extend. */
	if (lp->log_count &&
	    !seg_is_raid(first_seg(lv)) && seg_is_mirrored(first_seg(lv))) {
		if (!add_mirror_log(cmd, lv, lp->log_count,
				    first_seg(lv)->region_size,
				    lp->pvh, lp->alloc)) {
			stack;
			goto revert_new_lv;
		}
	}

	lv_set_activation_skip(lv, lp->activation_skip & ACTIVATION_SKIP_SET,
			       lp->activation_skip & ACTIVATION_SKIP_SET_ENABLED);
	/*
	 * Check for autoactivation.
	 * If the LV passes the auto activation filter, activate
	 * it just as if CHANGE_AY was used, CHANGE_AN otherwise.
	 */
	if (lp->activate == CHANGE_AAY)
		lp->activate = lv_passes_auto_activation_filter(cmd, lv)
			? CHANGE_ALY : CHANGE_ALN;

	if (lv_activation_skip(lv, lp->activate, lp->activation_skip & ACTIVATION_SKIP_IGNORE))
		lp->activate = CHANGE_AN;

	/* store vg on disk(s) */
	if (!vg_write(vg) || !vg_commit(vg))
		/* Pool created metadata LV, but better avoid recover when vg_write/commit fails */
		return_NULL;

	backup(vg);

	if (test_mode()) {
		log_verbose("Test mode: Skipping activation, zeroing and signature wiping.");
		goto out;
	}

	/* Do not scan this LV until properly zeroed/wiped. */
	if (_should_wipe_lv(lp, lv, 0))
		lv->status |= LV_NOSCAN;

	if (lp->temporary)
		lv->status |= LV_TEMPORARY;

	if (seg_is_cache(lp)) {
		/* FIXME Support remote exclusive activation? */
		/* Not yet 'cache' LV, it is stripe volume for wiping */
		if (is_change_activating(lp->activate) &&
		    !activate_lv_excl_local(cmd, lv)) {
			log_error("Aborting. Failed to activate LV %s locally exclusively.",
				  display_lvname(lv));
			goto revert_new_lv;
		}
	} else if (lv_is_cache_pool(lv)) {
		/* Cache pool cannot be actived and zeroed */
		log_very_verbose("Cache pool is prepared.");
	} else if (lv_is_thin_volume(lv)) {
		/* For snapshot, suspend active thin origin first */
		if (origin_lv && lv_is_active(origin_lv) && lv_is_thin_volume(origin_lv)) {
			if (!suspend_lv_origin(cmd, origin_lv)) {
				log_error("Failed to suspend thin snapshot origin %s/%s.",
					  origin_lv->vg->name, origin_lv->name);
				goto revert_new_lv;
			}
			if (!resume_lv_origin(cmd, origin_lv)) { /* deptree updates thin-pool */
				log_error("Failed to resume thin snapshot origin %s/%s.",
					  origin_lv->vg->name, origin_lv->name);
				goto revert_new_lv;
			}
			/* At this point remove pool messages, snapshot is active */
			if (!update_pool_lv(pool_lv, 0)) {
				stack;
				goto revert_new_lv;
			}
		}
		if (!dm_list_empty(&first_seg(pool_lv)->thin_messages)) {
			/* Send message so that table preload knows new thin */
			if (!lv_is_active(pool_lv)) {
				/* Avoid multiple thin-pool activations in this case */
				if (thin_pool_was_active < 0)
					thin_pool_was_active = 0;
				if (!activate_lv_excl(cmd, pool_lv)) {
					log_error("Failed to activate thin pool %s.",
						  display_lvname(pool_lv));
					goto revert_new_lv;
				}
				if (!lv_is_active(pool_lv)) {
					log_error("Cannot activate thin pool %s, perhaps skipped in lvm.conf volume_list?",
						  display_lvname(pool_lv));
					return 0;
				}
			}
			/* Keep thin pool active until thin volume is activated */
			if (!update_pool_lv(pool_lv, 1)) {
				stack;
				goto revert_new_lv;
			}
		}
		backup(vg);

		if (!lv_active_change(cmd, lv, lp->activate, 0)) {
			log_error("Failed to activate thin %s.", lv->name);
			goto deactivate_and_revert_new_lv;
		}

		/* Restore inactive state if needed */
		if (!thin_pool_was_active &&
		    !deactivate_lv(cmd, pool_lv)) {
			log_error("Failed to deactivate thin pool %s.",
				  display_lvname(pool_lv));
			return NULL;
		}
	} else if (lp->snapshot) {
		lv->status |= LV_TEMPORARY;
		if (!activate_lv_local(cmd, lv)) {
			log_error("Aborting. Failed to activate snapshot "
				  "exception store.");
			goto revert_new_lv;
		}
		lv->status &= ~LV_TEMPORARY;
	} else if (!lv_active_change(cmd, lv, lp->activate, 0)) {
		log_error("Failed to activate new LV.");
		goto deactivate_and_revert_new_lv;
	}

	if (_should_wipe_lv(lp, lv, 1)) {
		if (!wipe_lv(lv, (struct wipe_params)
			     {
				     .do_zero = lp->zero,
				     .do_wipe_signatures = lp->wipe_signatures,
				     .yes = lp->yes,
				     .force = lp->force
			     })) {
			log_error("Aborting. Failed to wipe %s.", lp->snapshot
				  ? "snapshot exception store" : "start of new LV");
			goto deactivate_and_revert_new_lv;
		}
	}

	if (seg_is_cache(lp) || (origin_lv && lv_is_cache_pool(lv))) {
		/* Finish cache conversion magic */
		if (origin_lv) {
			/* Convert origin to cached LV */
			if (!(tmp_lv = lv_cache_create(lv, origin_lv))) {
				/* FIXME Do a better revert */
				log_error("Aborting. Leaving cache pool %s and uncached origin volume %s.",
					  display_lvname(lv), display_lvname(origin_lv));
				return NULL;
			}
		} else {
			if (!(tmp_lv = lv_cache_create(pool_lv, lv))) {
				/* 'lv' still keeps created new LV */
				stack;
				goto deactivate_and_revert_new_lv;
			}
		}
		lv = tmp_lv;

		if (!cache_set_mode(first_seg(lv), lp->cache_mode))
			return_NULL; /* revert? */

		if (!cache_set_policy(first_seg(lv), lp->policy_name, lp->policy_settings))
			return_NULL; /* revert? */

		cache_check_for_warns(first_seg(lv));

		if (!lv_update_and_reload(lv)) {
			/* FIXME Do a better revert */
			log_error("Aborting. Manual intervention required.");
			return NULL; /* FIXME: revert */
		}
	} else if (lp->snapshot) {
		/* Deactivate zeroed COW, avoid any race usage */
		if (!deactivate_lv(cmd, lv)) {
			log_error("Aborting. Couldn't deactivate snapshot COW area %s.",
				  display_lvname(lv));
			goto deactivate_and_revert_new_lv; /* Let's retry on error path */
		}

		/* Get in sync with deactivation, before reusing LV as snapshot */
		if (!sync_local_dev_names(lv->vg->cmd)) {
			log_error("Failed to sync local devices before creating snapshot using %s.",
				  display_lvname(lv));
			goto revert_new_lv;
		}

		/* Create zero origin volume for spare snapshot */
		if (lp->virtual_extents &&
		    !(origin_lv = _create_virtual_origin(cmd, vg, lv->name,
							 lp->permission,
							 lp->virtual_extents)))
			goto revert_new_lv;

		/* Reset permission after zeroing */
		if (!(lp->permission & LVM_WRITE))
			lv->status &= ~LVM_WRITE;

		/*
		 * COW LV is activated via implicit activation of origin LV
		 * Only the snapshot origin holds the LV lock in cluster
		 */
		if (!vg_add_snapshot(origin_lv, lv, NULL,
				     origin_lv->le_count, lp->chunk_size)) {
			log_error("Couldn't create snapshot.");
			goto deactivate_and_revert_new_lv;
		}

		if (lp->virtual_extents) {
			/* Store vg on disk(s) */
			if (!vg_write(vg) || !vg_commit(vg))
				return_NULL; /* Metadata update fails, deep troubles */

			backup(vg);
			/*
			 * FIXME We do not actually need snapshot-origin as an active device,
			 * as virtual origin is already 'hidden' private device without
			 * vg/lv links. As such it is not supposed to be used by any user.
			 * Also it would save one dm table entry, but it needs quite a few
			 * changes in the libdm/lvm2 code base to support it.
			 */

			/* Activate spare snapshot once it is a complete LV */
			if (!lv_active_change(cmd, origin_lv, lp->activate, 1)) {
				log_error("Failed to activate sparce volume %s.",
					  display_lvname(origin_lv));
				return NULL;
			}
		} else if (!lv_update_and_reload(origin_lv)) {
			log_error("Aborting. Manual intervention required.");
			return NULL; /* FIXME: revert */
		}
	}
out:
	return lv;

deactivate_and_revert_new_lv:
	if (!deactivate_lv(cmd, lv)) {
		log_error("Unable to deactivate failed new LV %s. "
			  "Manual intervention required.",  display_lvname(lv));
		return NULL;
	}

revert_new_lv:
	lockd_free_lv(vg->cmd, vg, lp->lv_name, &lv->lvid.id[1], lp->lock_args);

	/* FIXME Better to revert to backup of metadata? */
	if (!lv_remove(lv) || !vg_write(vg) || !vg_commit(vg))
		log_error("Manual intervention may be required to remove "
			  "abandoned LV(s) before retrying.");
	else
		backup(vg);

	return NULL;
}

struct logical_volume *lv_create_single(struct volume_group *vg,
					struct lvcreate_params *lp)
{
	const struct segment_type *segtype;
	struct logical_volume *lv;

	/* Create pool first if necessary */
	if (lp->create_pool && !seg_is_pool(lp)) {
		segtype = lp->segtype;
		if (seg_is_thin_volume(lp)) {
			if (!(lp->segtype = get_segtype_from_string(vg->cmd, "thin-pool")))
				return_NULL;

			if (!(lv = _lv_create_an_lv(vg, lp, lp->pool_name)))
				return_NULL;
		} else if (seg_is_cache(lp)) {
			if (!lp->origin_name) {
				/* Until we have --pooldatasize we are lost */
				log_error(INTERNAL_ERROR "Unsupported creation of cache and cache pool volume.");
				return NULL;
			}
			/* origin_name is defined -> creates cache LV with new cache pool */
			if (!(lp->segtype = get_segtype_from_string(vg->cmd, "cache-pool")))
				return_NULL;

			if (!(lv = _lv_create_an_lv(vg, lp, lp->pool_name)))
				return_NULL;

			if (lv_is_cache(lv)) {
				/* Here it's been converted via lvcreate */
				log_print_unless_silent("Logical volume %s is now cached.",
							display_lvname(lv));
				return lv;
			}

			log_error(INTERNAL_ERROR "Logical volume is not cache %s.",
				  display_lvname(lv));
			return NULL;
		} else {
			log_error(INTERNAL_ERROR "Creation of pool for unsupported segment type %s.",
				  lp->segtype->name);
			return NULL;
		}
		lp->pool_name = lv->name;
		lp->segtype = segtype;
	}

	if (!(lv = _lv_create_an_lv(vg, lp, lp->lv_name)))
		return_NULL;

	if (lp->temporary)
		log_verbose("Temporary logical volume \"%s\" created.", lv->name);
	else
		log_print_unless_silent("Logical volume \"%s\" created.", lv->name);

	return lv;
}
