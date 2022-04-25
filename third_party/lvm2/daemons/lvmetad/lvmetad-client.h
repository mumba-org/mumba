/*
 * Copyright (C) 2011-2012 Red Hat, Inc.
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

#ifndef _LVM_LVMETAD_CLIENT_H
#define _LVM_LVMETAD_CLIENT_H

#include "daemon-client.h"

#define LVMETAD_SOCKET DEFAULT_RUN_DIR "/lvmetad.socket"

struct volume_group;

/* Different types of replies we may get from lvmetad. */

typedef struct {
	daemon_reply r;
	const char **uuids; /* NULL terminated array */
} lvmetad_uuidlist;

typedef struct {
	daemon_reply r;
	struct dm_config_tree *cft;
} lvmetad_vg;

/* Get a list of VG UUIDs that match a given VG name. */
lvmetad_uuidlist lvmetad_lookup_vgname(daemon_handle h, const char *name);

/* Get the metadata of a single VG, identified by UUID. */
lvmetad_vg lvmetad_get_vg(daemon_handle h, const char *uuid);

/*
 * Add and remove PVs on demand. Udev-driven systems will use this interface
 * instead of scanning.
 */
daemon_reply lvmetad_add_pv(daemon_handle h, const char *pv_uuid, const char *mda_content);
daemon_reply lvmetad_remove_pv(daemon_handle h, const char *pv_uuid);

/* Trigger a full disk scan, throwing away all caches. XXX do we eventually want
 * this? Probably not yet, anyway.
 *     daemon_reply lvmetad_rescan(daemon_handle h);
 */

/*
 * Update the version of metadata of a volume group. The VG has to be locked for
 * writing for this, and the VG metadata here has to match whatever has been
 * written to the disk (under this lock). This initially avoids the requirement
 * for lvmetad to write to disk (in later revisions, lvmetad_supersede_vg may
 * also do the writing, or we probably add another function to do that).
 */
daemon_reply lvmetad_supersede_vg(daemon_handle h, struct volume_group *vg);

/* Wrappers to open/close connection */

static inline daemon_handle lvmetad_open(const char *socket)
{
	daemon_info lvmetad_info = {
		.path = "lvmetad",
		.socket = socket ?: LVMETAD_SOCKET,
		.protocol = "lvmetad",
		.protocol_version = 1,
		.autostart = 0
	};

	return daemon_open(lvmetad_info);
}

static inline void lvmetad_close(daemon_handle h)
{
	return daemon_close(h);
}

#endif
