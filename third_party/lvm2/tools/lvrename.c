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

/*
 * lvrename command implementation.
 * Check arguments and call lv_rename() to execute the request.
 */
int lvrename(struct cmd_context *cmd, int argc, char **argv)
{
	size_t maxlen;
	char *lv_name_old, *lv_name_new;
	const char *vg_name, *vg_name_new, *vg_name_old;
	char *st;
	struct volume_group *vg;
	struct lv_list *lvl;
	uint32_t lockd_state = 0;
	int r = ECMD_FAILED;

	if (argc == 3) {
		vg_name = skip_dev_dir(cmd, argv[0], NULL);
		lv_name_old = argv[1];
		lv_name_new = argv[2];
		if (strchr(lv_name_old, '/') &&
		    (vg_name_old = extract_vgname(cmd, lv_name_old)) &&
		    strcmp(vg_name_old, vg_name)) {
			log_error("Please use a single volume group name "
				  "(\"%s\" or \"%s\")", vg_name, vg_name_old);
			return EINVALID_CMD_LINE;
		}
	} else if (argc == 2) {
		lv_name_old = argv[0];
		lv_name_new = argv[1];
		vg_name = extract_vgname(cmd, lv_name_old);
	} else {
		log_error("Old and new logical volume names required");
		return EINVALID_CMD_LINE;
	}

	if (!validate_name(vg_name)) {
		log_error("Please provide a valid volume group name");
		return EINVALID_CMD_LINE;
	}

	if (strchr(lv_name_new, '/') &&
	    (vg_name_new = extract_vgname(cmd, lv_name_new)) &&
	    strcmp(vg_name, vg_name_new)) {
		log_error("Logical volume names must "
			  "have the same volume group (\"%s\" or \"%s\")",
			  vg_name, vg_name_new);
		return EINVALID_CMD_LINE;
	}

	if ((st = strrchr(lv_name_old, '/')))
		lv_name_old = st + 1;

	if ((st = strrchr(lv_name_new, '/')))
		lv_name_new = st + 1;

	/* Check sanity of new name */
	maxlen = NAME_LEN - strlen(vg_name) - 3;
	if (strlen(lv_name_new) > maxlen) {
		log_error("New logical volume name \"%s\" may not exceed %"
			  PRIsize_t " characters.", lv_name_new, maxlen);
		return EINVALID_CMD_LINE;
	}

	if (!*lv_name_new) {
		log_error("New logical volume name may not be blank");
		return EINVALID_CMD_LINE;
	}

	if (!apply_lvname_restrictions(lv_name_new)) {
		stack;
		return EINVALID_CMD_LINE;
	}

	if (!validate_name(lv_name_new)) {
		log_error("New logical volume name \"%s\" is invalid",
			  lv_name_new);
		return EINVALID_CMD_LINE;
	}

	if (!strcmp(lv_name_old, lv_name_new)) {
		log_error("Old and new logical volume names must differ");
		return EINVALID_CMD_LINE;
	}

	if (!lockd_vg(cmd, vg_name, "ex", 0, &lockd_state))
		return_ECMD_FAILED;

	log_verbose("Checking for existing volume group \"%s\"", vg_name);
	vg = vg_read_for_update(cmd, vg_name, NULL, 0, lockd_state);
	if (vg_read_error(vg)) {
		release_vg(vg);
		return_ECMD_FAILED;
	}

	if (!(lvl = find_lv_in_vg(vg, lv_name_old))) {
		log_error("Existing logical volume \"%s\" not found in "
			  "volume group \"%s\"", lv_name_old, vg_name);
		goto bad;
	}

	if (lv_is_raid_image(lvl->lv) || lv_is_raid_metadata(lvl->lv)) {
		log_error("Cannot rename a RAID %s directly",
			  lv_is_raid_image(lvl->lv) ? "image" :
			  "metadata area");
		goto bad;
	}

	if (lv_is_raid_with_tracking(lvl->lv)) {
		log_error("Cannot rename %s while it is tracking a split image",
			  lvl->lv->name);
		goto bad;
	}

	if (!lv_rename(cmd, lvl->lv, lv_name_new))
		goto_bad;

	log_print_unless_silent("Renamed \"%s\" to \"%s\" in volume group \"%s\"",
				lv_name_old, lv_name_new, vg_name);

	r = ECMD_PROCESSED;
bad:
	unlock_and_release_vg(cmd, vg, vg_name);
	return r;
}
