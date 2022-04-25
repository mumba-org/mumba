/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc. All rights reserved.
 *
 * This file is part of the device-mapper userspace tools.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LIB_DMTARGETS_H
#define LIB_DMTARGETS_H

#include <inttypes.h>
#include <sys/types.h>

struct dm_ioctl;

struct target {
	uint64_t start;
	uint64_t length;
	char *type;
	char *params;

	struct target *next;
};

struct dm_task {
	int type;
	char *dev_name;
	char *mangled_dev_name;

	struct target *head, *tail;

	int read_only;
	uint32_t event_nr;
	int major;
	int minor;
	int allow_default_major_fallback;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	uint32_t read_ahead;
	uint32_t read_ahead_flags;
	union {
		struct dm_ioctl *v4;
	} dmi;
	char *newname;
	char *message;
	char *geometry;
	uint64_t sector;
	int no_flush;
	int no_open_count;
	int skip_lockfs;
	int query_inactive_table;
	int suppress_identical_reload;
	dm_add_node_t add_node;
	uint64_t existing_table_size;
	int cookie_set;
	int new_uuid;
	int secure_data;
	int retry_remove;
	int deferred_remove;
	int enable_checks;
	int expected_errno;
	int ioctl_errno;

	int record_timestamp;

	char *uuid;
	char *mangled_uuid;
};

struct cmd_data {
	const char *name;
	const unsigned cmd;
	const int version[3];
};

int dm_check_version(void);
uint64_t dm_task_get_existing_table_size(struct dm_task *dmt);

#endif
