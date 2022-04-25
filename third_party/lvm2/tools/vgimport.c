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

static int vgimport_single(struct cmd_context *cmd,
			   const char *vg_name,
			   struct volume_group *vg,
			   struct processing_handle *handle __attribute__((unused)))
{
	struct pv_list *pvl;
	struct physical_volume *pv;

	if (!vg_is_exported(vg)) {
		log_error("Volume group \"%s\" is not exported", vg_name);
		goto bad;
	}

	if (vg_status(vg) & PARTIAL_VG) {
		log_error("Volume group \"%s\" is partially missing", vg_name);
		goto bad;
	}

	if (!archive(vg))
		goto_bad;

	vg->status &= ~EXPORTED_VG;

	if (!is_lockd_type(vg->lock_type))
		vg->system_id = cmd->system_id ? dm_pool_strdup(vg->vgmem, cmd->system_id) : NULL;

	dm_list_iterate_items(pvl, &vg->pvs) {
		pv = pvl->pv;
		pv->status &= ~EXPORTED_VG;
	}

	if (!vg_write(vg) || !vg_commit(vg))
		goto_bad;

	backup(vg);

	log_print_unless_silent("Volume group \"%s\" successfully imported", vg->name);

	return ECMD_PROCESSED;

bad:
	return ECMD_FAILED;
}

int vgimport(struct cmd_context *cmd, int argc, char **argv)
{
	if (!argc && !arg_count(cmd, all_ARG) && !arg_is_set(cmd, select_ARG)) {
		log_error("Please supply volume groups or -S for selection or use -a for all.");
		return EINVALID_CMD_LINE;
	}

	if (arg_count(cmd, all_ARG) && (argc || arg_is_set(cmd, select_ARG))) {
		log_error("No arguments permitted when using -a for all.");
		return EINVALID_CMD_LINE;
	}

	if (arg_count(cmd, force_ARG)) {
		/*
		 * The volume group cannot be repaired unless it is first
		 * imported.  If we don't allow the user a way to import the
		 * VG while it is 'partial', then we will have created a
		 * circular dependency.
		 *
		 * The reason we don't just simply set 'handles_missing_pvs'
		 * by default is that we want to guard against the case
		 * where the user simply forgot to move one or more disks in
		 * the VG before running 'vgimport'.
		 */
		log_warn("WARNING: Volume groups with missing PVs will be imported with --force.");
		cmd->handles_missing_pvs = 1;
	}

	/*
	 * Rescan devices and update lvmetad.  lvmetad may hold a copy of the
	 * VG from before it was exported, if it was exported by another host.
	 * We need to reread it to see that it's been exported before we can
	 * import it.
	 */
	if (lvmetad_active() && !lvmetad_pvscan_all_devs(cmd, NULL)) {
		log_error("Failed to scan devices.");
		return ECMD_FAILED;
	}

	return process_each_vg(cmd, argc, argv,
			       READ_FOR_UPDATE | READ_ALLOW_EXPORTED,
			       NULL,
			       &vgimport_single);
}
