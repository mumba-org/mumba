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

#include "tools.h"

static int _lvdisplay_single(struct cmd_context *cmd, struct logical_volume *lv,
			     struct processing_handle *handle __attribute__ ((unused)))
{
	if (!arg_count(cmd, all_ARG) && !lv_is_visible(lv))
		return ECMD_PROCESSED;

	if (arg_count(cmd, colon_ARG))
		lvdisplay_colons(lv);
	else {
		lvdisplay_full(cmd, lv, NULL);
		if (arg_count(cmd, maps_ARG))
			lvdisplay_segments(lv);
	}

	return ECMD_PROCESSED;
}

int lvdisplay(struct cmd_context *cmd, int argc, char **argv)
{
	if (arg_count(cmd, columns_ARG)) {
		if (arg_count(cmd, colon_ARG) || arg_count(cmd, maps_ARG)) {
			log_error("Incompatible options selected");
			return EINVALID_CMD_LINE;
		}
		return lvs(cmd, argc, argv);
	}

	if (arg_count(cmd, aligned_ARG) ||
	    arg_count(cmd, binary_ARG) ||
	    arg_count(cmd, noheadings_ARG) ||
	    arg_count(cmd, options_ARG) ||
	    arg_count(cmd, separator_ARG) ||
	    arg_count(cmd, sort_ARG) ||
	    arg_count(cmd, unbuffered_ARG)) {
		log_error("Incompatible options selected.");
		return EINVALID_CMD_LINE;
	}

	if (arg_count(cmd, colon_ARG) && arg_count(cmd, maps_ARG)) {
		log_error("Options -c and -m are incompatible.");
		return EINVALID_CMD_LINE;
	}

	return process_each_lv(cmd, argc, argv, 0, NULL, &_lvdisplay_single);
}
