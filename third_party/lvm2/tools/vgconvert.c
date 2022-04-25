/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2007 Red Hat, Inc. All rights reserved.
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

static int vgconvert_single(struct cmd_context *cmd, const char *vg_name,
			    struct volume_group *vg,
			    struct processing_handle *handle __attribute__((unused)))
{
	struct physical_volume *pv, *existing_pv;
	struct pvcreate_restorable_params rp;
	struct logical_volume *lv;
	struct lv_list *lvl;
	int pvmetadatacopies = 0;
	uint64_t pvmetadatasize = 0;
	struct pv_list *pvl;
	int change_made = 0;
	struct lvinfo info;
	int active = 0;

	if (!vg_check_status(vg, LVM_WRITE | EXPORTED_VG))
		return_ECMD_FAILED;

	if (vg->fid->fmt == cmd->fmt) {
		log_error("Volume group \"%s\" already uses format %s",
			  vg_name, cmd->fmt->name);
		return ECMD_FAILED;
	}

	if (cmd->fmt->features & FMT_MDAS) {
		if (arg_sign_value(cmd, metadatasize_ARG, SIGN_NONE) == SIGN_MINUS) {
			log_error("Metadata size may not be negative");
			return EINVALID_CMD_LINE;
		}

		pvmetadatasize = arg_uint64_value(cmd, metadatasize_ARG,
						  UINT64_C(0));
		if (!pvmetadatasize)
			pvmetadatasize =
			    find_config_tree_int(cmd, metadata_pvmetadatasize_CFG, NULL);

		pvmetadatacopies = arg_int_value(cmd, pvmetadatacopies_ARG, -1);
		if (pvmetadatacopies < 0)
			pvmetadatacopies =
			    find_config_tree_int(cmd, metadata_pvmetadatacopies_CFG, NULL);
	}

	if (cmd->fmt->features & FMT_BAS) {
		if (arg_sign_value(cmd, bootloaderareasize_ARG, SIGN_NONE) == SIGN_MINUS) {
			log_error("Bootloader area size may not be negative");
			return EINVALID_CMD_LINE;
		}

		rp.ba_size = arg_uint64_value(cmd, bootloaderareasize_ARG, UINT64_C(0));
	}

	if (!vg_check_new_extent_size(cmd->fmt, vg->extent_size))
		return_ECMD_FAILED;

	if (!archive(vg)) {
		log_error("Archive of \"%s\" metadata failed.", vg_name);
		return ECMD_FAILED;
	}

	/* Set PV/LV limit if converting from unlimited metadata format */
	if (vg->fid->fmt->features & FMT_UNLIMITED_VOLS &&
	    !(cmd->fmt->features & FMT_UNLIMITED_VOLS)) {
		if (!vg->max_lv)
			vg->max_lv = 255;
		if (!vg->max_pv)
			vg->max_pv = 255;
	}

	/* If converting to restricted lvid, check if lvid is compatible */
	if (!(vg->fid->fmt->features & FMT_RESTRICTED_LVIDS) &&
	    cmd->fmt->features & FMT_RESTRICTED_LVIDS)
		dm_list_iterate_items(lvl, &vg->lvs)
			if (!lvid_in_restricted_range(&lvl->lv->lvid)) {
				log_error("Logical volume %s lvid format is"
					  " incompatible with requested"
					  " metadata format.", lvl->lv->name);
				return ECMD_FAILED;
			}

	/* New-style system ID supported? */ 
	if (vg->system_id && *vg->system_id && (cmd->fmt->features & FMT_SYSTEMID_ON_PVS)) {
		log_error("Unable to convert VG %s while it has a system ID set (%s).", vg->name,
			  vg->system_id);
		return ECMD_FAILED;
	}

	/* Attempt to change any LVIDs that are too big */
	if (cmd->fmt->features & FMT_RESTRICTED_LVIDS) {
		dm_list_iterate_items(lvl, &vg->lvs) {
			lv = lvl->lv;
			if (lv->status & SNAPSHOT)
				continue;
			if (lvnum_from_lvid(&lv->lvid) < MAX_RESTRICTED_LVS)
				continue;
			if (lv_info(cmd, lv, 0, &info, 0, 0) && info.exists) {
				log_error("Logical volume %s must be "
					  "deactivated before conversion.",
					   lv->name);
				active++;
				continue;
			}
			lvid_from_lvnum(&lv->lvid, &lv->vg->id, find_free_lvnum(lv));

		}
	}

	if (active)
		return_ECMD_FAILED;

	dm_list_iterate_items(pvl, &vg->pvs) {
		existing_pv = pvl->pv;

		rp.id = existing_pv->id;
		rp.idp = &rp.id;
		rp.pe_start = pv_pe_start(existing_pv);
		rp.extent_count = pv_pe_count(existing_pv);
		rp.extent_size = pv_pe_size(existing_pv);

		/* pe_end = pv_pe_count(existing_pv) * pv_pe_size(existing_pv) + pe_start - 1; */

		if (!(pv = pv_create(cmd, pv_dev(existing_pv),
				     0, 0, 0,
				     arg_int64_value(cmd, labelsector_ARG,
						     DEFAULT_LABELSECTOR),
				     pvmetadatacopies, pvmetadatasize, 0, &rp))) {
			log_error("Failed to setup physical volume \"%s\"",
				  pv_dev_name(existing_pv));
			if (change_made)
				log_error("Use pvcreate and vgcfgrestore to "
					  "repair from archived metadata.");
			return ECMD_FAILED;
		}

		/* Need to revert manually if it fails after this point */
		change_made = 1;

		log_verbose("Set up physical volume for \"%s\" with %" PRIu64
			    " available sectors", pv_dev_name(pv), pv_size(pv));

		/* Wipe existing label first */
		if (!label_remove(pv_dev(pv))) {
			log_error("Failed to wipe existing label on %s",
				  pv_dev_name(pv));
			log_error("Use pvcreate and vgcfgrestore to repair "
				  "from archived metadata.");
			return ECMD_FAILED;
		}

		log_very_verbose("Writing physical volume data to disk \"%s\"",
				 pv_dev_name(pv));
		if (!(pv_write(cmd, pv, 0))) {
			log_error("Failed to write physical volume \"%s\"",
				  pv_dev_name(pv));
			log_error("Use pvcreate and vgcfgrestore to repair "
				  "from archived metadata.");
			return ECMD_FAILED;
		}
		log_verbose("Physical volume \"%s\" successfully created",
			    pv_dev_name(pv));
	}

	log_verbose("Deleting existing metadata for VG %s", vg_name);
	if (!vg_remove_mdas(vg)) {
		log_error("Removal of existing metadata for %s failed.",
			  vg_name);
		log_error("Use pvcreate and vgcfgrestore to repair "
			  "from archived metadata.");
		return ECMD_FAILED;
	}

	/* FIXME Cache the label format change so we don't have to skip this */
	if (test_mode()) {
		log_verbose("Test mode: Skipping metadata writing for VG %s in"
			    " format %s", vg_name, cmd->fmt->name);
		return ECMD_PROCESSED;
	}

	log_verbose("Writing metadata for VG %s using format %s", vg_name,
		    cmd->fmt->name);
	if (!backup_restore_vg(cmd, vg, 0)) {
		log_error("Conversion failed for volume group %s.", vg_name);
		log_error("Use pvcreate and vgcfgrestore to repair from "
			  "archived metadata.");
		return ECMD_FAILED;
	}
	log_print_unless_silent("Volume group %s successfully converted", vg_name);

	backup(vg);

	return ECMD_PROCESSED;
}

int vgconvert(struct cmd_context *cmd, int argc, char **argv)
{
	if (!argc) {
		log_error("Please enter volume group(s)");
		return EINVALID_CMD_LINE;
	}

	if (arg_is_set(cmd, metadatatype_ARG) && lvmetad_used()) {
		log_error("lvmetad must be disabled to change metadata types.");
		return EINVALID_CMD_LINE;
	}

	if (arg_int_value(cmd, labelsector_ARG, 0) >= LABEL_SCAN_SECTORS) {
		log_error("labelsector must be less than %lu",
			  LABEL_SCAN_SECTORS);
		return EINVALID_CMD_LINE;
	}

	if (arg_count(cmd, metadatacopies_ARG)) {
		log_error("Invalid option --metadatacopies, "
			  "use --pvmetadatacopies instead.");
		return EINVALID_CMD_LINE;
	}
	if (!(cmd->fmt->features & FMT_MDAS) &&
	    (arg_count(cmd, pvmetadatacopies_ARG) ||
	     arg_count(cmd, metadatasize_ARG))) {
		log_error("Metadata parameters only apply to text format");
		return EINVALID_CMD_LINE;
	}

	if (arg_count(cmd, pvmetadatacopies_ARG) &&
	    arg_int_value(cmd, pvmetadatacopies_ARG, -1) > 2) {
		log_error("Metadatacopies may only be 0, 1 or 2");
		return EINVALID_CMD_LINE;
	}

	if (!(cmd->fmt->features & FMT_BAS) &&
		arg_count(cmd, bootloaderareasize_ARG)) {
		log_error("Bootloader area parameters only apply to text format");
		return EINVALID_CMD_LINE;
	}

	return process_each_vg(cmd, argc, argv, READ_FOR_UPDATE, NULL,
			       &vgconvert_single);
}
