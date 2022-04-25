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

#include "lib.h"
#include "btree.h"
#include "config.h"
#include "toolcontext.h"

#ifdef UDEV_SYNC_SUPPORT
#include <libudev.h>
#endif
#include <unistd.h>
#include <sys/param.h>
#include <dirent.h>

struct dev_iter {
	struct btree_iter *current;
	struct dev_filter *filter;
};

struct dir_list {
	struct dm_list list;
	char dir[0];
};

static struct {
	struct dm_pool *mem;
	struct dm_hash_table *names;
	struct btree *devices;
	struct dm_regex *preferred_names_matcher;
	const char *dev_dir;

	int has_scanned;
	struct dm_list dirs;
	struct dm_list files;

} _cache;

#define _zalloc(x) dm_pool_zalloc(_cache.mem, (x))
#define _free(x) dm_pool_free(_cache.mem, (x))
#define _strdup(x) dm_pool_strdup(_cache.mem, (x))

static int _insert(const char *path, const struct stat *info,
		   int rec, int check_with_udev_db);

/* Setup non-zero members of passed zeroed 'struct device' */
static void _dev_init(struct device *dev, int max_error_count)
{
	dev->phys_block_size = -1;
	dev->block_size = -1;
	dev->fd = -1;
	dev->read_ahead = -1;
	dev->max_error_count = max_error_count;

	dev->ext.enabled = 0;
	dev->ext.src = DEV_EXT_NONE;

	dm_list_init(&dev->aliases);
	dm_list_init(&dev->open_list);
}

void dev_destroy_file(struct device *dev)
{
	if (!(dev->flags & DEV_ALLOCED))
		return;

	dm_free((void *) dm_list_item(dev->aliases.n, struct dm_str_list)->str);
	dm_free(dev->aliases.n);
	dm_free(dev);
}

struct device *dev_create_file(const char *filename, struct device *dev,
			       struct dm_str_list *alias, int use_malloc)
{
	int allocate = !dev;

	if (allocate) {
		if (use_malloc) {
			if (!(dev = dm_zalloc(sizeof(*dev)))) {
				log_error("struct device allocation failed");
				return NULL;
			}
			if (!(alias = dm_zalloc(sizeof(*alias)))) {
				log_error("struct dm_str_list allocation failed");
				dm_free(dev);
				return NULL;
			}
			if (!(alias->str = dm_strdup(filename))) {
				log_error("filename strdup failed");
				dm_free(dev);
				dm_free(alias);
				return NULL;
			}
		} else {
			if (!(dev = _zalloc(sizeof(*dev)))) {
				log_error("struct device allocation failed");
				return NULL;
			}
			if (!(alias = _zalloc(sizeof(*alias)))) {
				log_error("struct dm_str_list allocation failed");
				_free(dev);
				return NULL;
			}
			if (!(alias->str = _strdup(filename))) {
				log_error("filename strdup failed");
				return NULL;
			}
		}
	} else if (!(alias->str = dm_strdup(filename))) {
		log_error("filename strdup failed");
		return NULL;
	}

	_dev_init(dev, NO_DEV_ERROR_COUNT_LIMIT);
	dev->flags = DEV_REGULAR | ((use_malloc) ? DEV_ALLOCED : 0);
	dm_list_add(&dev->aliases, &alias->list);

	return dev;
}

static struct device *_dev_create(dev_t d)
{
	struct device *dev;

	if (!(dev = _zalloc(sizeof(*dev)))) {
		log_error("struct device allocation failed");
		return NULL;
	}

	_dev_init(dev, dev_disable_after_error_count());
	dev->dev = d;

	return dev;
}

void dev_set_preferred_name(struct dm_str_list *sl, struct device *dev)
{
	/*
	 * Don't interfere with ordering specified in config file.
	 */
	if (_cache.preferred_names_matcher)
		return;

	log_debug_devs("%s: New preferred name", sl->str);
	dm_list_del(&sl->list);
	dm_list_add_h(&dev->aliases, &sl->list);
}

/*
 * Check whether path0 or path1 contains the subpath. The path that
 * *does not* contain the subpath wins (return 0 or 1). If both paths
 * contain the subpath, return -1. If none of them contains the subpath,
 * return -2.
 */
static int _builtin_preference(const char *path0, const char *path1,
			       size_t skip_prefix_count, const char *subpath)
{
	size_t subpath_len;
	int r0, r1;

	subpath_len = strlen(subpath);

	r0 = !strncmp(path0 + skip_prefix_count, subpath, subpath_len);
	r1 = !strncmp(path1 + skip_prefix_count, subpath, subpath_len);

	if (!r0 && r1)
		/* path0 does not have the subpath - it wins */
		return 0;
	else if (r0 && !r1)
		/* path1 does not have the subpath - it wins */
		return 1;
	else if (r0 && r1)
		/* both of them have the subpath */
		return -1;

	/* no path has the subpath */
	return -2;
}

static int _apply_builtin_path_preference_rules(const char *path0, const char *path1)
{
	size_t devdir_len;
	int r;

	devdir_len = strlen(_cache.dev_dir);

	if (!strncmp(path0, _cache.dev_dir, devdir_len) &&
	    !strncmp(path1, _cache.dev_dir, devdir_len)) {
		/*
		 * We're trying to achieve the ordering:
		 *	/dev/block/ < /dev/dm-* < /dev/disk/ < /dev/mapper/ < anything else
		 */

		/* Prefer any other path over /dev/block/ path. */
		if ((r = _builtin_preference(path0, path1, devdir_len, "block/")) >= -1)
			return r;

		/* Prefer any other path over /dev/dm-* path. */
		if ((r = _builtin_preference(path0, path1, devdir_len, "dm-")) >= -1)
			return r;

		/* Prefer any other path over /dev/disk/ path. */
		if ((r = _builtin_preference(path0, path1, devdir_len, "disk/")) >= -1)
			return r;

		/* Prefer any other path over /dev/mapper/ path. */
		if ((r = _builtin_preference(path0, path1, 0, dm_dir())) >= -1)
			return r;
	}

	return -1;
}

/* Return 1 if we prefer path1 else return 0 */
static int _compare_paths(const char *path0, const char *path1)
{
	int slash0 = 0, slash1 = 0;
	int m0, m1;
	const char *p;
	char p0[PATH_MAX], p1[PATH_MAX];
	char *s0, *s1;
	struct stat stat0, stat1;
	int r;

	/*
	 * FIXME Better to compare patterns one-at-a-time against all names.
	 */
	if (_cache.preferred_names_matcher) {
		m0 = dm_regex_match(_cache.preferred_names_matcher, path0);
		m1 = dm_regex_match(_cache.preferred_names_matcher, path1);

		if (m0 != m1) {
			if (m0 < 0)
				return 1;
			if (m1 < 0)
				return 0;
			if (m0 < m1)
				return 1;
			if (m1 < m0)
				return 0;
		}
	}

	/* Apply built-in preference rules first. */
	if ((r = _apply_builtin_path_preference_rules(path0, path1)) >= 0)
		return r;

	/* Return the path with fewer slashes */
	for (p = path0; p++; p = (const char *) strchr(p, '/'))
		slash0++;

	for (p = path1; p++; p = (const char *) strchr(p, '/'))
		slash1++;

	if (slash0 < slash1)
		return 0;
	if (slash1 < slash0)
		return 1;

	strncpy(p0, path0, sizeof(p0) - 1);
	p0[sizeof(p0) - 1] = '\0';
	strncpy(p1, path1, sizeof(p1) - 1);
	p1[sizeof(p1) - 1] = '\0';
	s0 = p0 + 1;
	s1 = p1 + 1;

	/*
	 * If we reach here, both paths are the same length.
	 * Now skip past identical path components.
	 */
	while (*s0 && *s0 == *s1)
		s0++, s1++;

	/* We prefer symlinks - they exist for a reason!
	 * So we prefer a shorter path before the first symlink in the name.
	 * FIXME Configuration option to invert this? */
	while (s0) {
		s0 = strchr(s0, '/');
		s1 = strchr(s1, '/');
		if (s0) {
			*s0 = '\0';
			*s1 = '\0';
		}
		if (lstat(p0, &stat0)) {
			log_sys_very_verbose("lstat", p0);
			return 1;
		}
		if (lstat(p1, &stat1)) {
			log_sys_very_verbose("lstat", p1);
			return 0;
		}
		if (S_ISLNK(stat0.st_mode) && !S_ISLNK(stat1.st_mode))
			return 0;
		if (!S_ISLNK(stat0.st_mode) && S_ISLNK(stat1.st_mode))
			return 1;
		if (s0) {
			*s0++ = '/';
			*s1++ = '/';
		}
	}

	/* ASCII comparison */
	if (strcmp(path0, path1) < 0)
		return 0;
	else
		return 1;
}

static int _add_alias(struct device *dev, const char *path)
{
	struct dm_str_list *sl = _zalloc(sizeof(*sl));
	struct dm_str_list *strl;
	const char *oldpath;
	int prefer_old = 1;

	if (!sl)
		return_0;

	/* Is name already there? */
	dm_list_iterate_items(strl, &dev->aliases) {
		if (!strcmp(strl->str, path)) {
			log_debug_devs("%s: Already in device cache", path);
			return 1;
		}
	}

	sl->str = path;

	if (!dm_list_empty(&dev->aliases)) {
		oldpath = dm_list_item(dev->aliases.n, struct dm_str_list)->str;
		prefer_old = _compare_paths(path, oldpath);
		log_debug_devs("%s: Aliased to %s in device cache%s (%d:%d)",
			       path, oldpath, prefer_old ? "" : " (preferred name)",
			       (int) MAJOR(dev->dev), (int) MINOR(dev->dev));

	} else
		log_debug_devs("%s: Added to device cache (%d:%d)", path,
			       (int) MAJOR(dev->dev), (int) MINOR(dev->dev));

	if (prefer_old)
		dm_list_add(&dev->aliases, &sl->list);
	else
		dm_list_add_h(&dev->aliases, &sl->list);

	return 1;
}

/*
 * Either creates a new dev, or adds an alias to
 * an existing dev.
 */
static int _insert_dev(const char *path, dev_t d)
{
	struct device *dev;
	static dev_t loopfile_count = 0;
	int loopfile = 0;
	char *path_copy;

	/* Generate pretend device numbers for loopfiles */
	if (!d) {
		if (dm_hash_lookup(_cache.names, path))
			return 1;
		d = ++loopfile_count;
		loopfile = 1;
	}

	/* is this device already registered ? */
	if (!(dev = (struct device *) btree_lookup(_cache.devices,
						   (uint32_t) d))) {
		/* create new device */
		if (loopfile) {
			if (!(dev = dev_create_file(path, NULL, NULL, 0)))
				return_0;
		} else if (!(dev = _dev_create(d)))
			return_0;

		if (!(btree_insert(_cache.devices, (uint32_t) d, dev))) {
			log_error("Couldn't insert device into binary tree.");
			_free(dev);
			return 0;
		}
	}

	if (!(path_copy = dm_pool_strdup(_cache.mem, path))) {
		log_error("Failed to duplicate path string.");
		return 0;
	}

	if (!loopfile && !_add_alias(dev, path_copy)) {
		log_error("Couldn't add alias to dev cache.");
		return 0;
	}

	if (!dm_hash_insert(_cache.names, path_copy, dev)) {
		log_error("Couldn't add name to hash in dev cache.");
		return 0;
	}

	return 1;
}

static char *_join(const char *dir, const char *name)
{
	size_t len = strlen(dir) + strlen(name) + 2;
	char *r = dm_malloc(len);
	if (r)
		snprintf(r, len, "%s/%s", dir, name);

	return r;
}

/*
 * Get rid of extra slashes in the path string.
 */
static void _collapse_slashes(char *str)
{
	char *ptr;
	int was_slash = 0;

	for (ptr = str; *ptr; ptr++) {
		if (*ptr == '/') {
			if (was_slash)
				continue;

			was_slash = 1;
		} else
			was_slash = 0;
		*str++ = *ptr;
	}

	*str = *ptr;
}

static int _insert_dir(const char *dir)
{
	int n, dirent_count, r = 1;
	struct dirent **dirent;
	char *path;

	dirent_count = scandir(dir, &dirent, NULL, alphasort);
	if (dirent_count > 0) {
		for (n = 0; n < dirent_count; n++) {
			if (dirent[n]->d_name[0] == '.') {
				free(dirent[n]);
				continue;
			}

			if (!(path = _join(dir, dirent[n]->d_name)))
				return_0;

			_collapse_slashes(path);
			r &= _insert(path, NULL, 1, 0);
			dm_free(path);

			free(dirent[n]);
		}
		free(dirent);
	}

	return r;
}

static int _insert_file(const char *path)
{
	struct stat info;

	if (stat(path, &info) < 0) {
		log_sys_very_verbose("stat", path);
		return 0;
	}

	if (!S_ISREG(info.st_mode)) {
		log_debug_devs("%s: Not a regular file", path);
		return 0;
	}

	if (!_insert_dev(path, 0))
		return_0;

	return 1;
}

#ifdef UDEV_SYNC_SUPPORT

static int _device_in_udev_db(const dev_t d)
{
	struct udev *udev;
	struct udev_device *udev_device;

	if (!(udev = udev_get_library_context()))
		return_0;

	if ((udev_device = udev_device_new_from_devnum(udev, 'b', d))) {
		udev_device_unref(udev_device);
		return 1;
	}

	return 0;
}

static int _insert_udev_dir(struct udev *udev, const char *dir)
{
	struct udev_enumerate *udev_enum = NULL;
	struct udev_list_entry *device_entry, *symlink_entry;
	const char *entry_name, *node_name, *symlink_name;
	struct udev_device *device;
	int r = 1;

	if (!(udev_enum = udev_enumerate_new(udev)))
		goto bad;

	if (udev_enumerate_add_match_subsystem(udev_enum, "block") ||
	    udev_enumerate_scan_devices(udev_enum))
		goto bad;

	/*
	 * Report any missing information as "log_very_verbose" only, do not
	 * report it as a "warning" or "error" - the record could be removed
	 * by the time we ask for more info (node name, symlink name...).
	 * Whatever removes *any* block device in the system (even unrelated
	 * to our operation), we would have a warning/error on output then.
	 * That could be misleading. If there's really any problem with missing
	 * information from udev db, we can still have a look at the verbose log.
	 */
	udev_list_entry_foreach(device_entry, udev_enumerate_get_list_entry(udev_enum)) {
		entry_name = udev_list_entry_get_name(device_entry);

		if (!(device = udev_device_new_from_syspath(udev, entry_name))) {
			log_very_verbose("udev failed to return a device for entry %s.",
					 entry_name);
			continue;
		}

		if (!(node_name = udev_device_get_devnode(device)))
			log_very_verbose("udev failed to return a device node for entry %s.",
					 entry_name);
		else
			r &= _insert(node_name, NULL, 0, 0);

		udev_list_entry_foreach(symlink_entry, udev_device_get_devlinks_list_entry(device)) {
			if (!(symlink_name = udev_list_entry_get_name(symlink_entry)))
				log_very_verbose("udev failed to return a symlink name for entry %s.",
						 entry_name);
			else
				r &= _insert(symlink_name, NULL, 0, 0);
		}

		udev_device_unref(device);
	}

	udev_enumerate_unref(udev_enum);
	return r;

bad:
	log_error("Failed to enumerate udev device list.");
	udev_enumerate_unref(udev_enum);
	return 0;
}

static void _insert_dirs(struct dm_list *dirs)
{
	struct dir_list *dl;
	struct udev *udev;
	int with_udev;

	with_udev = obtain_device_list_from_udev() &&
		    (udev = udev_get_library_context());

	dm_list_iterate_items(dl, &_cache.dirs) {
		if (with_udev) {
			if (!_insert_udev_dir(udev, dl->dir))
				log_debug_devs("%s: Failed to insert devices from "
					       "udev-managed directory to device "
					       "cache fully", dl->dir);
		}
		else if (!_insert_dir(dl->dir))
			log_debug_devs("%s: Failed to insert devices to "
				       "device cache fully", dl->dir);
	}
}

#else	/* UDEV_SYNC_SUPPORT */

static int _device_in_udev_db(const dev_t d)
{
	return 0;
}

static void _insert_dirs(struct dm_list *dirs)
{
	struct dir_list *dl;

	dm_list_iterate_items(dl, &_cache.dirs)
		_insert_dir(dl->dir);
}

#endif	/* UDEV_SYNC_SUPPORT */

static int _insert(const char *path, const struct stat *info,
		   int rec, int check_with_udev_db)
{
	struct stat tinfo;

	if (!info) {
		if (stat(path, &tinfo) < 0) {
			log_sys_very_verbose("stat", path);
			return 0;
		}
		info = &tinfo;
	}

	if (check_with_udev_db && !_device_in_udev_db(info->st_rdev)) {
		log_very_verbose("%s: Not in udev db", path);
		return 0;
	}

	if (S_ISDIR(info->st_mode)) {	/* add a directory */
		/* check it's not a symbolic link */
		if (lstat(path, &tinfo) < 0) {
			log_sys_very_verbose("lstat", path);
			return 0;
		}

		if (S_ISLNK(tinfo.st_mode)) {
			log_debug_devs("%s: Symbolic link to directory", path);
			return 1;
		}

		if (rec && !_insert_dir(path))
			return_0;
	} else {		/* add a device */
		if (!S_ISBLK(info->st_mode)) {
			log_debug_devs("%s: Not a block device", path);
			return 1;
		}

		if (!_insert_dev(path, info->st_rdev))
			return_0;
	}

	return 1;
}

static void _full_scan(int dev_scan)
{
	struct dir_list *dl;

	if (_cache.has_scanned && !dev_scan)
		return;

	_insert_dirs(&_cache.dirs);

	dm_list_iterate_items(dl, &_cache.files)
		_insert_file(dl->dir);

	_cache.has_scanned = 1;
	init_full_scan_done(1);
}

int dev_cache_has_scanned(void)
{
	return _cache.has_scanned;
}

void dev_cache_scan(int do_scan)
{
	if (!do_scan)
		_cache.has_scanned = 1;
	else
		_full_scan(1);
}

static int _init_preferred_names(struct cmd_context *cmd)
{
	const struct dm_config_node *cn;
	const struct dm_config_value *v;
	struct dm_pool *scratch = NULL;
	const char **regex;
	unsigned count = 0;
	int i, r = 0;

	_cache.preferred_names_matcher = NULL;

	if (!(cn = find_config_tree_array(cmd, devices_preferred_names_CFG, NULL)) ||
	    cn->v->type == DM_CFG_EMPTY_ARRAY) {
		log_very_verbose("devices/preferred_names %s: "
				 "using built-in preferences",
				 cn && cn->v->type == DM_CFG_EMPTY_ARRAY ? "is empty"
									 : "not found in config");
		return 1;
	}

	for (v = cn->v; v; v = v->next) {
		if (v->type != DM_CFG_STRING) {
			log_error("preferred_names patterns must be enclosed in quotes");
			return 0;
		}

		count++;
	}

	if (!(scratch = dm_pool_create("preferred device name matcher", 1024)))
		return_0;

	if (!(regex = dm_pool_alloc(scratch, sizeof(*regex) * count))) {
		log_error("Failed to allocate preferred device name "
			  "pattern list.");
		goto out;
	}

	for (v = cn->v, i = count - 1; v; v = v->next, i--) {
		if (!(regex[i] = dm_pool_strdup(scratch, v->v.str))) {
			log_error("Failed to allocate a preferred device name "
				  "pattern.");
			goto out;
		}
	}

	if (!(_cache.preferred_names_matcher =
		dm_regex_create(_cache.mem, regex, count))) {
		log_error("Preferred device name pattern matcher creation failed.");
		goto out;
	}

	r = 1;

out:
	dm_pool_destroy(scratch);

	return r;
}

int dev_cache_init(struct cmd_context *cmd)
{
	_cache.names = NULL;
	_cache.has_scanned = 0;

	if (!(_cache.mem = dm_pool_create("dev_cache", 10 * 1024)))
		return_0;

	if (!(_cache.names = dm_hash_create(128))) {
		dm_pool_destroy(_cache.mem);
		_cache.mem = 0;
		return_0;
	}

	if (!(_cache.devices = btree_create(_cache.mem))) {
		log_error("Couldn't create binary tree for dev-cache.");
		goto bad;
	}

	if (!(_cache.dev_dir = _strdup(cmd->dev_dir))) {
		log_error("strdup dev_dir failed.");
		goto bad;
	}

	dm_list_init(&_cache.dirs);
	dm_list_init(&_cache.files);

	if (!_init_preferred_names(cmd))
		goto_bad;

	return 1;

      bad:
	dev_cache_exit();
	return 0;
}

/*
 * Returns number of devices still open.
 */
static int _check_for_open_devices(int close_immediate)
{
	struct device *dev;
	struct dm_hash_node *n;
	int num_open = 0;

	dm_hash_iterate(n, _cache.names) {
		dev = (struct device *) dm_hash_get_data(_cache.names, n);
		if (dev->fd >= 0) {
			log_error("Device '%s' has been left open (%d remaining references).",
				  dev_name(dev), dev->open_count);
			num_open++;
			if (close_immediate)
				dev_close_immediate(dev);
		}
	}

	return num_open;
}

/*
 * Returns number of devices left open.
 */
int dev_cache_check_for_open_devices(void)
{
	return _check_for_open_devices(0);
}

int dev_cache_exit(void)
{
	int num_open = 0;

	if (_cache.names)
		if ((num_open = _check_for_open_devices(1)) > 0)
			log_error(INTERNAL_ERROR "%d device(s) were left open and have been closed.", num_open);

	if (_cache.preferred_names_matcher)
		_cache.preferred_names_matcher = NULL;

	if (_cache.mem) {
		dm_pool_destroy(_cache.mem);
		_cache.mem = NULL;
	}

	if (_cache.names) {
		dm_hash_destroy(_cache.names);
		_cache.names = NULL;
	}

	_cache.devices = NULL;
	_cache.has_scanned = 0;
	dm_list_init(&_cache.dirs);
	dm_list_init(&_cache.files);

	return (!num_open);
}

int dev_cache_add_dir(const char *path)
{
	struct dir_list *dl;
	struct stat st;

	if (stat(path, &st)) {
		log_warn("Ignoring %s: %s.", path, strerror(errno));
		/* But don't fail */
		return 1;
	}

	if (!S_ISDIR(st.st_mode)) {
		log_warn("Ignoring %s: Not a directory.", path);
		return 1;
	}

	if (!(dl = _zalloc(sizeof(*dl) + strlen(path) + 1))) {
		log_error("dir_list allocation failed");
		return 0;
	}

	strcpy(dl->dir, path);
	dm_list_add(&_cache.dirs, &dl->list);
	return 1;
}

int dev_cache_add_loopfile(const char *path)
{
	struct dir_list *dl;
	struct stat st;

	if (stat(path, &st)) {
		log_warn("Ignoring %s: %s.", path, strerror(errno));
		/* But don't fail */
		return 1;
	}

	if (!S_ISREG(st.st_mode)) {
		log_warn("Ignoring %s: Not a regular file.", path);
		return 1;
	}

	if (!(dl = _zalloc(sizeof(*dl) + strlen(path) + 1))) {
		log_error("dir_list allocation failed for file");
		return 0;
	}

	strcpy(dl->dir, path);
	dm_list_add(&_cache.files, &dl->list);
	return 1;
}

/* Check cached device name is still valid before returning it */
/* This should be a rare occurrence */
/* set quiet if the cache is expected to be out-of-date */
/* FIXME Make rest of code pass/cache struct device instead of dev_name */
const char *dev_name_confirmed(struct device *dev, int quiet)
{
	struct stat buf;
	const char *name;
	int r;

	if ((dev->flags & DEV_REGULAR))
		return dev_name(dev);

	while ((r = stat(name = dm_list_item(dev->aliases.n,
					  struct dm_str_list)->str, &buf)) ||
	       (buf.st_rdev != dev->dev)) {
		if (r < 0) {
			if (quiet)
				log_sys_debug("stat", name);
			else
				log_sys_error("stat", name);
		}
		if (quiet)
			log_debug_devs("Path %s no longer valid for device(%d,%d)",
				       name, (int) MAJOR(dev->dev),
				       (int) MINOR(dev->dev));
		else
			log_warn("Path %s no longer valid for device(%d,%d)",
				 name, (int) MAJOR(dev->dev),
				 (int) MINOR(dev->dev));

		/* Remove the incorrect hash entry */
		dm_hash_remove(_cache.names, name);

		/* Leave list alone if there isn't an alternative name */
		/* so dev_name will always find something to return. */
		/* Otherwise add the name to the correct device. */
		if (dm_list_size(&dev->aliases) > 1) {
			dm_list_del(dev->aliases.n);
			if (!r)
				_insert(name, &buf, 0, obtain_device_list_from_udev());
			continue;
		}

		/* Scanning issues this inappropriately sometimes. */
		log_debug_devs("Aborting - please provide new pathname for what "
			       "used to be %s", name);
		return NULL;
	}

	return dev_name(dev);
}

struct device *dev_cache_get(const char *name, struct dev_filter *f)
{
	struct stat buf;
	struct device *d = (struct device *) dm_hash_lookup(_cache.names, name);
	int info_available = 0;

	if (d && (d->flags & DEV_REGULAR))
		return d;

	/* If the entry's wrong, remove it */
	if (stat(name, &buf) < 0) {
		if (d)
			dm_hash_remove(_cache.names, name);
		log_sys_very_verbose("stat", name);
		d = NULL;
	} else
		info_available = 1;

	if (d && (buf.st_rdev != d->dev)) {
		dm_hash_remove(_cache.names, name);
		d = NULL;
	}

	if (!d) {
		_insert(name, info_available ? &buf : NULL, 0, obtain_device_list_from_udev());
		d = (struct device *) dm_hash_lookup(_cache.names, name);
		if (!d) {
			_full_scan(0);
			d = (struct device *) dm_hash_lookup(_cache.names, name);
		}
	}

	if (!d || (f && !(d->flags & DEV_REGULAR) && !(f->passes_filter(f, d))))
		return NULL;

	log_debug_devs("Using %s", dev_name(d));
	return d;
}

static struct device *_dev_cache_seek_devt(dev_t dev)
{
	struct device *d = NULL;
	struct dm_hash_node *n = dm_hash_get_first(_cache.names);
	while (n) {
		d = dm_hash_get_data(_cache.names, n);
		if (d->dev == dev)
			return d;
		n = dm_hash_get_next(_cache.names, n);
	}
	return NULL;
}

/*
 * TODO This is very inefficient. We probably want a hash table indexed by
 * major:minor for keys to speed up these lookups.
 */
struct device *dev_cache_get_by_devt(dev_t dev, struct dev_filter *f)
{
	char path[PATH_MAX];
	const char *sysfs_dir;
	struct stat info;
	struct device *d = _dev_cache_seek_devt(dev);

	if (d && (d->flags & DEV_REGULAR))
		return d;

	if (!d) {
		sysfs_dir = dm_sysfs_dir();
		if (sysfs_dir && *sysfs_dir) {
			/* First check if dev is sysfs to avoid useless scan */
			if (dm_snprintf(path, sizeof(path), "%s/dev/block/%d:%d",
					sysfs_dir, (int)MAJOR(dev), (int)MINOR(dev)) < 0) {
				log_error("dm_snprintf partition failed.");
				return NULL;
			}

			if (lstat(path, &info)) {
				log_debug("No sysfs entry for %d:%d.",
					  (int)MAJOR(dev), (int)MINOR(dev));
				return NULL;
			}
		}

		_full_scan(0);
		d = _dev_cache_seek_devt(dev);
	}

	return (d && (!f || (d->flags & DEV_REGULAR) ||
		      f->passes_filter(f, d))) ? d : NULL;
}

struct dev_iter *dev_iter_create(struct dev_filter *f, int dev_scan)
{
	struct dev_iter *di = dm_malloc(sizeof(*di));

	if (!di) {
		log_error("dev_iter allocation failed");
		return NULL;
	}

	if (dev_scan && !trust_cache()) {
		/* Flag gets reset between each command */
		if (!full_scan_done()) {
			if (f && f->wipe) {
				f->wipe(f); /* might call _full_scan(1) */
				if (!full_scan_done())
					_full_scan(1);
			} else
				_full_scan(1);
		}
	} else
		_full_scan(0);

	di->current = btree_first(_cache.devices);
	di->filter = f;
	if (di->filter)
		di->filter->use_count++;

	return di;
}

void dev_iter_destroy(struct dev_iter *iter)
{
	if (iter->filter)
		iter->filter->use_count--;
	dm_free(iter);
}

static struct device *_iter_next(struct dev_iter *iter)
{
	struct device *d = btree_get_data(iter->current);
	iter->current = btree_next(iter->current);
	return d;
}

struct device *dev_iter_get(struct dev_iter *iter)
{
	while (iter->current) {
		struct device *d = _iter_next(iter);
		if (!iter->filter || (d->flags & DEV_REGULAR) ||
		    iter->filter->passes_filter(iter->filter, d)) {
			log_debug_devs("Using %s", dev_name(d));
			return d;
		}
	}

	return NULL;
}

void dev_reset_error_count(struct cmd_context *cmd)
{
	struct dev_iter iter;

	if (!_cache.devices)
		return;

	iter.current = btree_first(_cache.devices);
	while (iter.current)
		_iter_next(&iter)->error_count = 0;
}

int dev_fd(struct device *dev)
{
	return dev->fd;
}

const char *dev_name(const struct device *dev)
{
	return (dev && dev->aliases.n) ? dm_list_item(dev->aliases.n, struct dm_str_list)->str :
	    "unknown device";
}
