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

static int _pvdisplay_single(struct cmd_context *cmd,
			     struct volume_group *vg,
			     struct physical_volume *pv,
			     struct processing_handle *handle __attribute__((unused)))
{
	const char *pv_name = pv_dev_name(pv);
	int ret = ECMD_PROCESSED;
	uint64_t size;

	if (is_orphan(pv))
		size = pv_size(pv);
	else
		size = (uint64_t)(pv_pe_count(pv) - pv_pe_alloc_count(pv)) *
			pv_pe_size(pv);

	if (arg_count(cmd, short_ARG)) {
		log_print("Device \"%s\" has a capacity of %s", pv_name,
			  display_size(cmd, size));
		goto out;
	}

	if (pv_status(pv) & EXPORTED_VG)
		log_print_unless_silent("Physical volume \"%s\" of volume group \"%s\" "
					"is exported", pv_name, pv_vg_name(pv));

	if (is_orphan(pv))
		log_print_unless_silent("\"%s\" is a new physical volume of \"%s\"",
					pv_name, display_size(cmd, size));

	if (arg_count(cmd, colon_ARG)) {
		pvdisplay_colons(pv);
		goto out;
	}

	pvdisplay_full(cmd, pv, NULL);

	if (arg_count(cmd, maps_ARG))
		pvdisplay_segments(pv);

out:
	return ret;
}

int pvdisplay(struct cmd_context *cmd, int argc, char **argv)
{
	int lock_global = 0;
	int ret;

	if (arg_count(cmd, columns_ARG)) {
		if (arg_count(cmd, colon_ARG) || arg_count(cmd, maps_ARG) ||
		    arg_count(cmd, short_ARG)) {
			log_error("Incompatible options selected");
			return EINVALID_CMD_LINE;
		}
		return pvs(cmd, argc, argv);
	}

	if (arg_count(cmd, aligned_ARG) ||
	    arg_count(cmd, all_ARG) ||
	    arg_count(cmd, binary_ARG) ||
	    arg_count(cmd, noheadings_ARG) ||
	    arg_count(cmd, options_ARG) ||
	    arg_count(cmd, separator_ARG) ||
	    arg_count(cmd, sort_ARG) ||
	    arg_count(cmd, unbuffered_ARG)) {
		log_error("Incompatible options selected");
		return EINVALID_CMD_LINE;
	}

	if (arg_count(cmd, colon_ARG) && arg_count(cmd, maps_ARG)) {
		log_error("Option -c not allowed with option -m");
		return EINVALID_CMD_LINE;
	}

	if (arg_count(cmd, colon_ARG) && arg_count(cmd, short_ARG)) {
		log_error("Option -c is not allowed with option -s");
		return EINVALID_CMD_LINE;
	}

	/*
	 * If the lock_type is LCK_VG_READ (used only in reporting commands),
	 * we lock VG_GLOBAL to enable use of metadata cache.
	 * This can pause alongide pvscan or vgscan process for a while.
	 */
	if (!lvmetad_active()) {
		lock_global = 1;
		if (!lock_vol(cmd, VG_GLOBAL, LCK_VG_READ, NULL)) {
			log_error("Unable to obtain global lock.");
			return ECMD_FAILED;
		}
	}

	ret = process_each_pv(cmd, argc, argv, NULL, 0, NULL,
			      _pvdisplay_single);

	if (lock_global)
		unlock_vg(cmd, VG_GLOBAL);

	return ret;
}
