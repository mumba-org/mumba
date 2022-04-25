/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2011 Red Hat, Inc. All rights reserved.
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
#include "locking.h"
#include "locking_types.h"
#include "lvm-string.h"
#include "activate.h"
#include "toolcontext.h"
#include "memlock.h"
#include "defaults.h"
#include "lvmcache.h"
#include "lvm-signal.h"

#include <assert.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

static struct locking_type _locking;

static int _vg_lock_count = 0;		/* Number of locks held */
static int _vg_write_lock_held = 0;	/* VG write lock held? */
static int _blocking_supported = 0;

typedef enum {
        LV_NOOP,
        LV_SUSPEND,
        LV_RESUME
} lv_operation_t;

static void _lock_memory(struct cmd_context *cmd, lv_operation_t lv_op)
{
	if (!(_locking.flags & LCK_PRE_MEMLOCK))
		return;

	if (lv_op == LV_SUSPEND)
		critical_section_inc(cmd, "locking for suspend");
}

static void _unlock_memory(struct cmd_context *cmd, lv_operation_t lv_op)
{
	if (!(_locking.flags & LCK_PRE_MEMLOCK))
		return;

	if (lv_op == LV_RESUME)
		critical_section_dec(cmd, "unlocking on resume");
}

static void _unblock_signals(void)
{
	/* Don't unblock signals while any locks are held */
	if (!_vg_lock_count)
		unblock_signals();
}

void reset_locking(void)
{
	int was_locked = _vg_lock_count;

	_vg_lock_count = 0;
	_vg_write_lock_held = 0;

	if (_locking.reset_locking)
		_locking.reset_locking();

	if (was_locked)
		_unblock_signals();

	memlock_reset();
}

static void _update_vg_lock_count(const char *resource, uint32_t flags)
{
	/* Ignore locks not associated with updating VG metadata */
	if ((flags & LCK_SCOPE_MASK) != LCK_VG ||
	    (flags & LCK_CACHE) ||
	    !strcmp(resource, VG_GLOBAL))
		return;

	if ((flags & LCK_TYPE_MASK) == LCK_UNLOCK)
		_vg_lock_count--;
	else
		_vg_lock_count++;

	/* We don't bother to reset this until all VG locks are dropped */
	if ((flags & LCK_TYPE_MASK) == LCK_WRITE)
		_vg_write_lock_held = 1;
	else if (!_vg_lock_count)
		_vg_write_lock_held = 0;
}

/*
 * Select a locking type
 * type: locking type; if < 0, then read config tree value
 */
int init_locking(int type, struct cmd_context *cmd, int suppress_messages)
{
	if (getenv("LVM_SUPPRESS_LOCKING_FAILURE_MESSAGES"))
		suppress_messages = 1;

	if (type < 0)
		type = find_config_tree_int(cmd, global_locking_type_CFG, NULL);

	_blocking_supported = find_config_tree_bool(cmd, global_wait_for_locks_CFG, NULL);

	switch (type) {
	case 0:
		init_no_locking(&_locking, cmd, suppress_messages);
		log_warn_suppress(suppress_messages,
			"WARNING: Locking disabled. Be careful! "
			"This could corrupt your metadata.");
		return 1;

	case 1:
		log_very_verbose("%sFile-based locking selected.",
				 _blocking_supported ? "" : "Non-blocking ");

		if (!init_file_locking(&_locking, cmd, suppress_messages)) {
			log_error_suppress(suppress_messages,
					   "File-based locking initialisation failed.");
			break;
		}
		return 1;

#ifdef HAVE_LIBDL
	case 2:
		if (!is_static()) {
			log_very_verbose("External locking selected.");
			if (init_external_locking(&_locking, cmd, suppress_messages))
				return 1;
		}
		if (!find_config_tree_bool(cmd, global_fallback_to_clustered_locking_CFG, NULL)) {
			log_error_suppress(suppress_messages, "External locking initialisation failed.");
			break;
		}
#endif

#ifdef CLUSTER_LOCKING_INTERNAL
		log_very_verbose("Falling back to internal clustered locking.");
		/* Fall through */

	case 3:
		log_very_verbose("Cluster locking selected.");
		if (!init_cluster_locking(&_locking, cmd, suppress_messages)) {
			log_error_suppress(suppress_messages,
					   "Internal cluster locking initialisation failed.");
			break;
		}
		return 1;
#endif

	case 4:
		log_verbose("Read-only locking selected. "
			    "Only read operations permitted.");
		if (!init_readonly_locking(&_locking, cmd, suppress_messages))
			break;
		return 1;

	case 5:
		init_dummy_locking(&_locking, cmd, suppress_messages);
		log_verbose("Locking disabled for read-only access.");
		return 1;

	default:
		log_error("Unknown locking type requested.");
		return 0;
	}

	if ((type == 2 || type == 3) &&
	    find_config_tree_bool(cmd, global_fallback_to_local_locking_CFG, NULL)) {
		log_warn_suppress(suppress_messages, "WARNING: Falling back to local file-based locking.");
		log_warn_suppress(suppress_messages,
				  "Volume Groups with the clustered attribute will "
				  "be inaccessible.");
		if (init_file_locking(&_locking, cmd, suppress_messages))
			return 1;
		else
			log_error_suppress(suppress_messages,
					   "File-based locking initialisation failed.");
	}

	if (!ignorelockingfailure())
		return 0;

	log_verbose("Locking disabled - only read operations permitted.");
	init_readonly_locking(&_locking, cmd, suppress_messages);

	return 1;
}

void fin_locking(void)
{
	_locking.fin_locking();
}

/*
 * Does the LVM1 driver know of this VG name?
 */
int check_lvm1_vg_inactive(struct cmd_context *cmd, const char *vgname)
{
	struct stat info;
	char path[PATH_MAX];

	/* We'll allow operations on orphans */
	if (!is_real_vg(vgname))
		return 1;

	/* LVM1 is only present in 2.4 kernels. */
	if (strncmp(cmd->kernel_vsn, "2.4.", 4))
		return 1;

	if (dm_snprintf(path, sizeof(path), "%s/lvm/VGs/%s", cmd->proc_dir,
			 vgname) < 0) {
		log_error("LVM1 proc VG pathname too long for %s", vgname);
		return 0;
	}

	if (stat(path, &info) == 0) {
		log_error("%s exists: Is the original LVM driver using "
			  "this volume group?", path);
		return 0;
	} else if (errno != ENOENT && errno != ENOTDIR) {
		log_sys_error("stat", path);
		return 0;
	}

	return 1;
}

/*
 * VG locking is by VG name.
 * FIXME This should become VG uuid.
 */
static int _lock_vol(struct cmd_context *cmd, const char *resource,
		     uint32_t flags, lv_operation_t lv_op, const struct logical_volume *lv)
{
	uint32_t lck_type = flags & LCK_TYPE_MASK;
	uint32_t lck_scope = flags & LCK_SCOPE_MASK;
	int ret = 0;

	block_signals(flags);
	_lock_memory(cmd, lv_op);

	assert(resource);

	if (!*resource) {
		log_error(INTERNAL_ERROR "Use of P_orphans is deprecated.");
		goto out;
	}

	if ((is_orphan_vg(resource) || is_global_vg(resource)) && (flags & LCK_CACHE)) {
		log_error(INTERNAL_ERROR "P_%s referenced", resource);
		goto out;
	}

	if (cmd->metadata_read_only && lck_type == LCK_WRITE &&
	    strcmp(resource, VG_GLOBAL)) {
		log_error("Operation prohibited while global/metadata_read_only is set.");
		goto out;
	}

	if ((ret = _locking.lock_resource(cmd, resource, flags, lv))) {
		if (lck_scope == LCK_VG && !(flags & LCK_CACHE)) {
			if (lck_type != LCK_UNLOCK)
				lvmcache_lock_vgname(resource, lck_type == LCK_READ);
			dev_reset_error_count(cmd);
		}

		_update_vg_lock_count(resource, flags);
	} else
		stack;

	/* If unlocking, always remove lock from lvmcache even if operation failed. */
	if (lck_scope == LCK_VG && !(flags & LCK_CACHE) && lck_type == LCK_UNLOCK) {
		lvmcache_unlock_vgname(resource);
		if (!ret)
			_update_vg_lock_count(resource, flags);
	}
out:
	_unlock_memory(cmd, lv_op);
	_unblock_signals();

	return ret;
}

int lock_vol(struct cmd_context *cmd, const char *vol, uint32_t flags, const struct logical_volume *lv)
{
	char resource[258] __attribute__((aligned(8)));
	lv_operation_t lv_op;
	int lck_type = flags & LCK_TYPE_MASK;

	switch (flags & (LCK_SCOPE_MASK | LCK_TYPE_MASK)) {
		case LCK_LV_SUSPEND:
				lv_op = LV_SUSPEND;
				break;
		case LCK_LV_RESUME:
				lv_op = LV_RESUME;
				break;
		default:	lv_op = LV_NOOP;
	}


	if (flags == LCK_NONE) {
		log_debug_locking(INTERNAL_ERROR "%s: LCK_NONE lock requested", vol);
		return 1;
	}

	switch (flags & LCK_SCOPE_MASK) {
	case LCK_ACTIVATION:
		break;
	case LCK_VG:
		if (!_blocking_supported)
			flags |= LCK_NONBLOCK;

		/* Global VG_ORPHANS lock covers all orphan formats. */
		if (is_orphan_vg(vol))
			vol = VG_ORPHANS;
		/* VG locks alphabetical, ORPHAN lock last */
		if ((lck_type != LCK_UNLOCK) &&
		    !(flags & LCK_CACHE) &&
		    !lvmcache_verify_lock_order(vol))
			return_0;

		/* Lock VG to change on-disk metadata. */
		/* If LVM1 driver knows about the VG, it can't be accessed. */
		if (!check_lvm1_vg_inactive(cmd, vol))
			return_0;
		break;
	case LCK_LV:
		/* All LV locks are non-blocking. */
		flags |= LCK_NONBLOCK;
		break;
	default:
		log_error("Unrecognised lock scope: %d",
			  flags & LCK_SCOPE_MASK);
		return 0;
	}

	strncpy(resource, vol, sizeof(resource) - 1);
	resource[sizeof(resource) - 1] = '\0';

	if (!_lock_vol(cmd, resource, flags, lv_op, lv))
		return_0;

	/*
	 * If a real lock was acquired (i.e. not LCK_CACHE),
	 * perform an immediate unlock unless LCK_HOLD was requested.
	 */
	if ((lck_type == LCK_NULL) || (lck_type == LCK_UNLOCK) ||
	    (flags & (LCK_CACHE | LCK_HOLD)))
		return 1;

	if (!_lock_vol(cmd, resource, (flags & ~LCK_TYPE_MASK) | LCK_UNLOCK, lv_op, lv))
		return_0;

	return 1;
}

/* Unlock list of LVs */
int resume_lvs(struct cmd_context *cmd, struct dm_list *lvs)
{
	struct lv_list *lvl;
	int r = 1;

	dm_list_iterate_items(lvl, lvs)
		if (!resume_lv(cmd, lvl->lv)) {
			r = 0;
			stack;
		}

	return r;
}

/* Unlock and revert list of LVs */
int revert_lvs(struct cmd_context *cmd, struct dm_list *lvs)
{
	struct lv_list *lvl;
	int r = 1;

	dm_list_iterate_items(lvl, lvs)
		if (!revert_lv(cmd, lvl->lv)) {
			r = 0;
			stack;
		}

	return r;
}
/*
 * Lock a list of LVs.
 * On failure to lock any LV, calls vg_revert() if vg_to_revert is set and 
 * then unlocks any LVs on the list already successfully locked.
 */
int suspend_lvs(struct cmd_context *cmd, struct dm_list *lvs,
		struct volume_group *vg_to_revert)
{
	struct lv_list *lvl;

	dm_list_iterate_items(lvl, lvs) {
		if (!suspend_lv(cmd, lvl->lv)) {
			log_error("Failed to suspend %s", lvl->lv->name);
			if (vg_to_revert)
				vg_revert(vg_to_revert);
			/*
			 * FIXME Should be
			 * 	dm_list_uniterate(lvh, lvs, &lvl->list) {
			 *	lvl = dm_list_item(lvh, struct lv_list);
			 * but revert would need fixing to use identical tree deps first.
			 */
			dm_list_iterate_items(lvl, lvs)
				if (!revert_lv(cmd, lvl->lv))
					stack;

			return 0;
		}
	}

	return 1;
}

/*
 * First try to activate exclusively locally.
 * Then if the VG is clustered and the LV is not yet active (e.g. due to 
 * an activation filter) try activating on remote nodes.
 */
int activate_lv_excl(struct cmd_context *cmd, struct logical_volume *lv) 
{
	/* Non-clustered VGs are only activated locally. */
	if (!vg_is_clustered(lv->vg))
		return activate_lv_excl_local(cmd, lv);

	if (lv_is_active_exclusive_locally(lv))
		return 1;

	if (!activate_lv_excl_local(cmd, lv))
		return_0;

	if (lv_is_active_exclusive(lv))
		return 1;

	/* FIXME Deal with error return codes. */
	if (!activate_lv_excl_remote(cmd, lv))
		return_0;

	return 1;
}

/* Lock a list of LVs */
int activate_lvs(struct cmd_context *cmd, struct dm_list *lvs, unsigned exclusive)
{
	struct dm_list *lvh;
	struct lv_list *lvl;

	dm_list_iterate_items(lvl, lvs) {
		if (!exclusive && !lv_is_active_exclusive(lvl->lv)) {
			if (!activate_lv(cmd, lvl->lv)) {
				log_error("Failed to activate %s", lvl->lv->name);
				return 0;
			}
		} else if (!activate_lv_excl(cmd, lvl->lv)) {
			log_error("Failed to activate %s", lvl->lv->name);
			dm_list_uniterate(lvh, lvs, &lvl->list) {
				lvl = dm_list_item(lvh, struct lv_list);
				if (!activate_lv(cmd, lvl->lv))
					stack;
			}
			return 0;
		}
	}

	return 1;
}

int vg_write_lock_held(void)
{
	return _vg_write_lock_held;
}

int locking_is_clustered(void)
{
	return (_locking.flags & LCK_CLUSTERED) ? 1 : 0;
}

int locking_supports_remote_queries(void)
{
	return (_locking.flags & LCK_SUPPORTS_REMOTE_QUERIES) ? 1 : 0;
}

int remote_lock_held(const char *vol, int *exclusive)
{
	int mode = LCK_NULL;

	if (!locking_is_clustered())
		return 0;

	if (!_locking.query_resource)
		return -1;

	/*
	 * If an error occured, expect that volume is active
	 */
	if (!_locking.query_resource(vol, &mode)) {
		stack;
		return 1;
	}

	if (exclusive)
		*exclusive = (mode == LCK_EXCL);

	return mode == LCK_NULL ? 0 : 1;
}

int sync_local_dev_names(struct cmd_context* cmd)
{
	memlock_unlock(cmd);

	return lock_vol(cmd, VG_SYNC_NAMES, LCK_VG_SYNC_LOCAL, NULL);
}

int sync_dev_names(struct cmd_context* cmd)
{
	memlock_unlock(cmd);

	return lock_vol(cmd, VG_SYNC_NAMES, LCK_VG_SYNC, NULL);
}
