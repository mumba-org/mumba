/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2009 Red Hat, Inc. All rights reserved.
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

#include "tools.h"

int vgcreate(struct cmd_context *cmd, int argc, char **argv)
{
	struct vgcreate_params vp_new;
	struct vgcreate_params vp_def;
	struct volume_group *vg;
	const char *tag;
	const char *clustered_message = "";
	char *vg_name;
	struct pvcreate_params pp;
	struct arg_value_group_list *current_group;

	if (!argc) {
		log_error("Please provide volume group name and "
			  "physical volumes");
		return EINVALID_CMD_LINE;
	}

	vg_name = argv[0];
	argc--;
	argv++;

	pvcreate_params_set_defaults(&pp);
	if (!pvcreate_params_validate(cmd, argc, &pp)) {
		return EINVALID_CMD_LINE;
	}

	if (!vgcreate_params_set_defaults(cmd, &vp_def, NULL))
		return EINVALID_CMD_LINE;
	vp_def.vg_name = vg_name;
	if (!vgcreate_params_set_from_args(cmd, &vp_new, &vp_def))
		return EINVALID_CMD_LINE;

	if (!vgcreate_params_validate(cmd, &vp_new))
	    return EINVALID_CMD_LINE;

	/*
	 * Needed to change the global VG namespace,
	 * and to change the set of orphan PVs.
	 */
	if (!lockd_gl_create(cmd, "ex", vp_new.lock_type))
		return ECMD_FAILED;

	lvmcache_seed_infos_from_lvmetad(cmd);

	/* Create the new VG */
	vg = vg_create(cmd, vp_new.vg_name);
	if (vg_read_error(vg)) {
		if (vg_read_error(vg) == FAILED_EXIST)
			log_error("A volume group called %s already exists.", vp_new.vg_name);
		else
			log_error("Can't get lock for %s.", vp_new.vg_name);
		release_vg(vg);
		return ECMD_FAILED;
	}

	if (vg->fid->fmt->features & FMT_CONFIG_PROFILE)
		vg->profile = vg->cmd->profile_params->global_metadata_profile;

	if (!vg_set_extent_size(vg, vp_new.extent_size) ||
	    !vg_set_max_lv(vg, vp_new.max_lv) ||
	    !vg_set_max_pv(vg, vp_new.max_pv) ||
	    !vg_set_alloc_policy(vg, vp_new.alloc) ||
	    !vg_set_clustered(vg, vp_new.clustered) ||
	    !vg_set_system_id(vg, vp_new.system_id) ||
	    !vg_set_mda_copies(vg, vp_new.vgmetadatacopies))
		goto bad_orphan;

	if (!lock_vol(cmd, VG_ORPHANS, LCK_VG_WRITE, NULL)) {
		log_error("Can't get lock for orphan PVs");
		goto bad_orphan;
	}

	/* attach the pv's */
	if (!vg_extend(vg, argc, (const char* const*)argv, &pp))
		goto_bad;

	if (vp_new.max_lv != vg->max_lv)
		log_warn("WARNING: Setting maxlogicalvolumes to %d "
			 "(0 means unlimited)", vg->max_lv);

	if (vp_new.max_pv != vg->max_pv)
		log_warn("WARNING: Setting maxphysicalvolumes to %d "
			 "(0 means unlimited)", vg->max_pv);

	if (arg_count(cmd, addtag_ARG)) {
		dm_list_iterate_items(current_group, &cmd->arg_value_groups) {
			if (!grouped_arg_is_set(current_group->arg_values, addtag_ARG))
				continue;

			if (!(tag = grouped_arg_str_value(current_group->arg_values, addtag_ARG, NULL))) {
				log_error("Failed to get tag");
				goto bad;
			}

			if (!vg_change_tag(vg, tag, 1))
				goto_bad;
		}
	}

	if (vg_is_clustered(vg))
		clustered_message = "Clustered ";
	else if (locking_is_clustered())
		clustered_message = "Non-clustered ";

	if (!archive(vg))
		goto_bad;

	/* Store VG on disk(s) */
	if (!vg_write(vg) || !vg_commit(vg))
		goto_bad;

	/*
	 * The VG is initially written without lock_type set, i.e. it starts as
	 * a local VG.  lockd_init_vg() then writes the VG a second time with
	 * both lock_type and lock_args set.
	 */
	if (!lockd_init_vg(cmd, vg, vp_new.lock_type, 0)) {
		log_error("Failed to initialize lock args for lock type %s",
			  vp_new.lock_type);
		vg_remove_pvs(vg);
		vg_remove_direct(vg);
		goto_bad;
	}

	unlock_vg(cmd, VG_ORPHANS);
	unlock_vg(cmd, vp_new.vg_name);

	backup(vg);

	log_print_unless_silent("%s%colume group \"%s\" successfully created%s%s",
				clustered_message, *clustered_message ? 'v' : 'V', vg->name,
				vg->system_id ? " with system ID " : "", vg->system_id ? : "");

	/*
	 * Start the VG lockspace because it will likely be used right away.
	 * Optionally wait for the start to complete so the VG can be fully
	 * used after this command completes (otherwise, the VG can only be
	 * read without locks until the lockspace is done starting.)
	 */
	if (is_lockd_type(vg->lock_type)) {
		const char *start_opt = arg_str_value(cmd, lockopt_ARG, NULL);

		if (!lockd_start_vg(cmd, vg, 1)) {
			log_error("Failed to start locking");
			goto out;
		}

		lockd_gl(cmd, "un", 0);

		if (!start_opt || !strcmp(start_opt, "wait")) {
			/* It is OK if the user does Ctrl-C to cancel the wait. */
			log_print_unless_silent("Starting locking.  Waiting until locks are ready...");
			lockd_start_wait(cmd);

		} else if (!strcmp(start_opt, "nowait")) {
			log_print_unless_silent("Starting locking.  VG is read-only until locks are ready.");
		}

	}
out:
	release_vg(vg);
	return ECMD_PROCESSED;

bad:
	unlock_vg(cmd, VG_ORPHANS);
bad_orphan:
	release_vg(vg);
	unlock_vg(cmd, vp_new.vg_name);
	return ECMD_FAILED;
}
