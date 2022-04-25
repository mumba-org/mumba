/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.  
 * Copyright (C) 2004-2012 Red Hat, Inc. All rights reserved.
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

#ifndef LVM_ACTIVATE_H
#define LVM_ACTIVATE_H

#include "metadata-exported.h"

struct lvinfo {
	int exists;
	int suspended;
	unsigned int open_count;
	int major;
	int minor;
	int read_only;
	int live_table;
	int inactive_table;
	uint32_t read_ahead;
};

typedef enum {
	SEG_STATUS_NONE,
	SEG_STATUS_CACHE,
	SEG_STATUS_RAID,
	SEG_STATUS_SNAPSHOT,
	SEG_STATUS_THIN,
	SEG_STATUS_THIN_POOL,
	SEG_STATUS_UNKNOWN
} lv_seg_status_type_t;

struct lv_seg_status {
	struct dm_pool *mem;			/* input */
	const struct lv_segment *seg;		/* input */
	lv_seg_status_type_t type;		/* output */
	union {
		struct dm_status_cache *cache;
		struct dm_status_raid *raid;
		struct dm_status_snapshot *snapshot;
		struct dm_status_thin *thin;
		struct dm_status_thin_pool *thin_pool;
	};
};

struct lv_with_info_and_seg_status {
	const struct logical_volume *lv;	/* input */
	int info_ok;
	struct lvinfo info;			/* output */
	int seg_part_of_lv;			/* output */
	struct lv_seg_status seg_status;	/* input/output, see lv_seg_status */
};

struct lv_activate_opts {
	int exclusive;
	int origin_only;
	int no_merging;
	int send_messages;
	int skip_in_use;
	unsigned revert;
	unsigned read_only;
	unsigned noscan;	/* Mark this LV to avoid its scanning. This also
				   directs udev to use proper udev flag to avoid
				   any scanning in udev. This udev flag is automatically
				   dropped in udev db on any spurious event that follows. */
	unsigned temporary;	/* Mark this LV as temporary. It means, the LV
				 * is created, used and deactivated within single
				 * LVM command execution. Such LVs are mostly helper
				 * LVs to do some action or cleanup before the proper
				 * LV is created. This also directs udev to use proper
				 * set of flags to avoid any scanning in udev. These udev
				 * flags are persistent in udev db for any spurious event
				 * that follows. */
};

void set_activation(int activation, int silent);
int activation(void);

int driver_version(char *version, size_t size);
int library_version(char *version, size_t size);
int lvm1_present(struct cmd_context *cmd);

int module_present(struct cmd_context *cmd, const char *target_name);
int target_present(struct cmd_context *cmd, const char *target_name,
		   int use_modprobe);
int target_version(const char *target_name, uint32_t *maj,
		   uint32_t *min, uint32_t *patchlevel);
int lvm_dm_prefix_check(int major, int minor, const char *prefix);
int list_segment_modules(struct dm_pool *mem, const struct lv_segment *seg,
			 struct dm_list *modules);
int list_lv_modules(struct dm_pool *mem, const struct logical_volume *lv,
		    struct dm_list *modules);

void activation_release(void);
void activation_exit(void);

/* int lv_suspend(struct cmd_context *cmd, const char *lvid_s); */
int lv_suspend_if_active(struct cmd_context *cmd, const char *lvid_s, unsigned origin_only, unsigned exclusive,
			 const struct logical_volume *lv_ondisk, const struct logical_volume *lv_incore);
int lv_resume(struct cmd_context *cmd, const char *lvid_s, unsigned origin_only, const struct logical_volume *lv);
int lv_resume_if_active(struct cmd_context *cmd, const char *lvid_s,
			unsigned origin_only, unsigned exclusive, unsigned revert, const struct logical_volume *lv);
int lv_activate(struct cmd_context *cmd, const char *lvid_s, int exclusive,
		int noscan, int temporary, const struct logical_volume *lv);
int lv_activate_with_filter(struct cmd_context *cmd, const char *lvid_s, int exclusive,
			    int noscan, int temporary, const struct logical_volume *lv);
int lv_deactivate(struct cmd_context *cmd, const char *lvid_s, const struct logical_volume *lv);

int lv_mknodes(struct cmd_context *cmd, const struct logical_volume *lv);

/*
 * Returns 1 if info structure has been populated, else 0 on failure.
 * When lvinfo* is NULL, it returns 1 if the device is locally active, 0 otherwise.
 */
int lv_info(struct cmd_context *cmd, const struct logical_volume *lv, int use_layer,
	    struct lvinfo *info, int with_open_count, int with_read_ahead);
int lv_info_by_lvid(struct cmd_context *cmd, const char *lvid_s, int use_layer,
		    struct lvinfo *info, int with_open_count, int with_read_ahead);

/*
 * Returns 1 if lv_seg_status structure has been populated,
 * else 0 on failure or if device not active locally.
 */
int lv_status(struct cmd_context *cmd, const struct lv_segment *lv_seg,
	      int use_layer, struct lv_seg_status *lv_seg_status);

/*
 * Returns 1 if lv_info_and_seg_status structure has been populated,
 * else 0 on failure or if device not active locally.
 *
 * lv_info_with_seg_status is the same as calling lv_info and then lv_status,
 * but this fn tries to do that with one ioctl if possible.
 */
int lv_info_with_seg_status(struct cmd_context *cmd, const struct logical_volume *lv,
			    const struct lv_segment *lv_seg, int use_layer,
			    struct lv_with_info_and_seg_status *status,
			    int with_open_count, int with_read_ahead);

int lv_check_not_in_use(const struct logical_volume *lv);

/*
 * Returns 1 if activate_lv has been set: 1 = activate; 0 = don't.
 */
int lv_activation_filter(struct cmd_context *cmd, const char *lvid_s,
			 int *activate_lv, const struct logical_volume *lv);
/*
 * Checks against the auto_activation_volume_list and
 * returns 1 if the LV should be activated, 0 otherwise.
 */
int lv_passes_auto_activation_filter(struct cmd_context *cmd, struct logical_volume *lv);

int lv_check_transient(struct logical_volume *lv);
/*
 * Returns 1 if percent has been set, else 0.
 */
int lv_snapshot_percent(const struct logical_volume *lv, dm_percent_t *percent);
int lv_mirror_percent(struct cmd_context *cmd, const struct logical_volume *lv,
		      int wait, dm_percent_t *percent, uint32_t *event_nr);
int lv_raid_percent(const struct logical_volume *lv, dm_percent_t *percent);
int lv_raid_dev_health(const struct logical_volume *lv, char **dev_health);
int lv_raid_mismatch_count(const struct logical_volume *lv, uint64_t *cnt);
int lv_raid_sync_action(const struct logical_volume *lv, char **sync_action);
int lv_raid_message(const struct logical_volume *lv, const char *msg);
int lv_cache_status(const struct logical_volume *lv,
		    struct lv_status_cache **status);
int lv_thin_pool_percent(const struct logical_volume *lv, int metadata,
			 dm_percent_t *percent);
int lv_thin_percent(const struct logical_volume *lv, int mapped,
		    dm_percent_t *percent);
int lv_thin_pool_transaction_id(const struct logical_volume *lv,
				uint64_t *transaction_id);
int lv_thin_device_id(const struct logical_volume *lv, uint32_t *device_id);

/*
 * Return number of LVs in the VG that are active.
 */
int lvs_in_vg_activated(const struct volume_group *vg);
int lvs_in_vg_opened(const struct volume_group *vg);

int lv_is_active(const struct logical_volume *lv);
int lv_is_active_locally(const struct logical_volume *lv);
int lv_is_active_but_not_locally(const struct logical_volume *lv);
int lv_is_active_exclusive(const struct logical_volume *lv);
int lv_is_active_exclusive_locally(const struct logical_volume *lv);
int lv_is_active_exclusive_remotely(const struct logical_volume *lv);

int lv_has_target_type(struct dm_pool *mem, const struct logical_volume *lv,
		       const char *layer, const char *target_type);

int monitor_dev_for_events(struct cmd_context *cmd, const struct logical_volume *lv,
			   const struct lv_activate_opts *laopts, int do_reg);

#ifdef DMEVENTD
#  include "libdevmapper-event.h"
char *get_monitor_dso_path(struct cmd_context *cmd, const char *libpath);
int target_registered_with_dmeventd(struct cmd_context *cmd, const char *libpath,
				    const struct logical_volume *lv, int *pending);
int target_register_events(struct cmd_context *cmd, const char *dso, const struct logical_volume *lv,
			    int evmask __attribute__((unused)), int set, int timeout);
#endif

int add_linear_area_to_dtree(struct dm_tree_node *node, uint64_t size,
			     uint32_t extent_size, int use_linear_target,
			     const char *vgname, const char *lvname);

/*
 * Returns 1 if PV has a dependency tree that uses anything in VG.
 */
int pv_uses_vg(struct physical_volume *pv,
	       struct volume_group *vg);

struct dev_usable_check_params {
	unsigned int check_empty:1;
	unsigned int check_blocked:1;
	unsigned int check_suspended:1;
	unsigned int check_error_target:1;
	unsigned int check_reserved:1;
};

/*
 * Returns 1 if mapped device is not suspended, blocked or
 * is using a reserved name.
 */
int device_is_usable(struct device *dev, struct dev_usable_check_params check);

/*
 * Declaration moved here from fs.h to keep header fs.h hidden
 */
void fs_unlock(void);

#endif
