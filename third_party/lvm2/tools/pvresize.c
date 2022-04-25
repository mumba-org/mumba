/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2005 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005 Zak Kipling. All rights reserved.
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

struct pvresize_params {
	uint64_t new_size;

	unsigned done;
	unsigned total;
};

static int _pvresize_single(struct cmd_context *cmd,
			    struct volume_group *vg,
			    struct physical_volume *pv,
			    struct processing_handle *handle)
{
	struct pvresize_params *params = (struct pvresize_params *) handle->custom_handle;

	if (!params) {
		log_error(INTERNAL_ERROR "Invalid resize params.");
		return ECMD_FAILED;
	}
	params->total++;

	/*
	 * Needed to change a property on an orphan PV.
	 * i.e. the global lock is only needed for orphans.
	 * Convert sh to ex.
	 */
	if (is_orphan(pv) && !lockd_gl(cmd, "ex", 0))
		return_ECMD_FAILED;

	if (!pv_resize_single(cmd, vg, pv, params->new_size))
		return_ECMD_FAILED;

	params->done++;

	return ECMD_PROCESSED;
}

int pvresize(struct cmd_context *cmd, int argc, char **argv)
{
	struct pvresize_params params;
	struct processing_handle *handle = NULL;
	int ret;

	if (!argc) {
		log_error("Please supply physical volume(s)");
		ret = EINVALID_CMD_LINE;
		goto out;
	}

	if (arg_sign_value(cmd, physicalvolumesize_ARG, SIGN_NONE) == SIGN_MINUS) {
		log_error("Physical volume size may not be negative");
		ret = EINVALID_CMD_LINE;
		goto out;
	}

	params.new_size = arg_uint64_value(cmd, physicalvolumesize_ARG,
					   UINT64_C(0));

	params.done = 0;
	params.total = 0;

	if (!(handle = init_processing_handle(cmd))) {
		log_error("Failed to initialize processing handle.");
		ret = ECMD_FAILED;
		goto out;
	}

	handle->custom_handle = &params;

	ret = process_each_pv(cmd, argc, argv, NULL, READ_FOR_UPDATE, handle,
			      _pvresize_single);

	log_print_unless_silent("%d physical volume(s) resized / %d physical volume(s) "
				"not resized", params.done, params.total - params.done);
out:
	destroy_processing_handle(cmd, handle);
	return ret;
}
