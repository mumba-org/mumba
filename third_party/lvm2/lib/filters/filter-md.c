/*
 * Copyright (C) 2004 Luca Berra
 * Copyright (C) 2004-2006 Red Hat, Inc. All rights reserved.
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

#include "lib.h"
#include "filter.h"

#ifdef __linux__

#define MSG_SKIPPING "%s: Skipping md component device"

static int _ignore_md(struct dev_filter *f __attribute__((unused)),
		      struct device *dev)
{
	int ret;
	
	if (!md_filtering())
		return 1;
	
	ret = dev_is_md(dev, NULL);

	if (ret == 1) {
		if (dev->ext.src == DEV_EXT_NONE)
			log_debug_devs(MSG_SKIPPING, dev_name(dev));
		else
			log_debug_devs(MSG_SKIPPING " [%s:%p]", dev_name(dev),
					dev_ext_name(dev), dev->ext.handle);
		return 0;
	}

	if (ret < 0) {
		log_debug_devs("%s: Skipping: error in md component detection",
			       dev_name(dev));
		return 0;
	}

	return 1;
}

static void _destroy(struct dev_filter *f)
{
	if (f->use_count)
		log_error(INTERNAL_ERROR "Destroying md filter while in use %u times.", f->use_count);

	dm_free(f);
}

struct dev_filter *md_filter_create(struct dev_types *dt)
{
	struct dev_filter *f;

	if (!(f = dm_zalloc(sizeof(*f)))) {
		log_error("md filter allocation failed");
		return NULL;
	}

	f->passes_filter = _ignore_md;
	f->destroy = _destroy;
	f->use_count = 0;
	f->private = dt;

	log_debug_devs("MD filter initialised.");

	return f;
}

#else

struct dev_filter *md_filter_create(struct dev_types *dt)
{
	return NULL;
}

#endif
