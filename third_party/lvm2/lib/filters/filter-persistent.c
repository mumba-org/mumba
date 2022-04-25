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
#include "filter.h"
#include "config.h"
#include "lvm-file.h"

struct pfilter {
	char *file;
	struct dm_hash_table *devices;
	struct dev_filter *real;
	struct timespec ctime;
	struct dev_types *dt;
};

/*
 * The hash table holds one of these two states
 * against each entry.
 */
#define PF_BAD_DEVICE ((void *) 1)
#define PF_GOOD_DEVICE ((void *) 2)

static int _init_hash(struct pfilter *pf)
{
	if (pf->devices)
		dm_hash_destroy(pf->devices);

	if (!(pf->devices = dm_hash_create(128)))
		return_0;

	return 1;
}

static void _persistent_filter_wipe(struct dev_filter *f)
{
	struct pfilter *pf = (struct pfilter *) f->private;

	log_verbose("Wiping cache of LVM-capable devices");
	dm_hash_wipe(pf->devices);

	/* Trigger complete device scan */
	dev_cache_scan(1);
}

static int _read_array(struct pfilter *pf, struct dm_config_tree *cft,
		       const char *path, void *data)
{
	const struct dm_config_node *cn;
	const struct dm_config_value *cv;

	if (!(cn = dm_config_find_node(cft->root, path))) {
		log_very_verbose("Couldn't find %s array in '%s'",
				 path, pf->file);
		return 0;
	}

	/*
	 * iterate through the array, adding
	 * devices as we go.
	 */
	for (cv = cn->v; cv; cv = cv->next) {
		if (cv->type != DM_CFG_STRING) {
			log_verbose("Devices array contains a value "
				    "which is not a string ... ignoring");
			continue;
		}

		if (!dm_hash_insert(pf->devices, cv->v.str, data))
			log_verbose("Couldn't add '%s' to filter ... ignoring",
				    cv->v.str);
		/* Populate dev_cache ourselves */
		dev_cache_get(cv->v.str, NULL);
	}
	return 1;
}

int persistent_filter_load(struct dev_filter *f, struct dm_config_tree **cft_out)
{
	struct pfilter *pf = (struct pfilter *) f->private;
	struct dm_config_tree *cft;
	struct stat info;
	int r = 0;

	if (obtain_device_list_from_udev()) {
		if (!stat(pf->file, &info)) {
			log_very_verbose("Obtaining device list from udev. "
					 "Removing obsolete %s.",
					 pf->file);
			if (unlink(pf->file) < 0 && errno != EROFS)
				log_sys_error("unlink", pf->file);
		}
		return 1;
	}

	if (!stat(pf->file, &info))
		lvm_stat_ctim(&pf->ctime, &info);
	else {
		log_very_verbose("%s: stat failed: %s", pf->file,
				 strerror(errno));
		return_0;
	}

	if (!(cft = config_open(CONFIG_FILE_SPECIAL, pf->file, 1)))
		return_0;

	if (!config_file_read(cft))
		goto_out;

	_read_array(pf, cft, "persistent_filter_cache/valid_devices",
		    PF_GOOD_DEVICE);
	/* We don't gain anything by holding invalid devices */
	/* _read_array(pf, cft, "persistent_filter_cache/invalid_devices",
	   PF_BAD_DEVICE); */

	/* Did we find anything? */
	if (dm_hash_get_num_entries(pf->devices)) {
		/* We populated dev_cache ourselves */
		dev_cache_scan(0);
		r = 1;
	}

	log_very_verbose("Loaded persistent filter cache from %s", pf->file);

      out:
	if (r && cft_out)
		*cft_out = cft;
	else
		config_destroy(cft);
	return r;
}

static void _write_array(struct pfilter *pf, FILE *fp, const char *path,
			 void *data)
{
	void *d;
	int first = 1;
	char buf[2 * PATH_MAX];
	struct dm_hash_node *n;

	for (n = dm_hash_get_first(pf->devices); n;
	     n = dm_hash_get_next(pf->devices, n)) {
		d = dm_hash_get_data(pf->devices, n);

		if (d != data)
			continue;

		if (!first)
			fprintf(fp, ",\n");
		else {
			fprintf(fp, "\t%s=[\n", path);
			first = 0;
		}

		dm_escape_double_quotes(buf, dm_hash_get_key(pf->devices, n));
		fprintf(fp, "\t\t\"%s\"", buf);
	}

	if (!first)
		fprintf(fp, "\n\t]\n");
}

static int _persistent_filter_dump(struct dev_filter *f, int merge_existing)
{
	struct pfilter *pf;
	char *tmp_file;
	struct stat info, info2;
	struct timespec ts;
	struct dm_config_tree *cft = NULL;
	FILE *fp;
	int lockfd;
	int r = 0;

	if (obtain_device_list_from_udev())
		return 1;

	if (!f)
		return_0;
	pf = (struct pfilter *) f->private;

	if (!dm_hash_get_num_entries(pf->devices)) {
		log_very_verbose("Internal persistent device cache empty "
				 "- not writing to %s", pf->file);
		return 1;
	}
	if (!dev_cache_has_scanned()) {
		log_very_verbose("Device cache incomplete - not writing "
				 "to %s", pf->file);
		return 0;
	}

	log_very_verbose("Dumping persistent device cache to %s", pf->file);

	while (1) {
		if ((lockfd = fcntl_lock_file(pf->file, F_WRLCK, 0)) < 0)
			return_0;

		/*
		 * Ensure we locked the file we expected
		 */
		if (fstat(lockfd, &info)) {
			log_sys_error("fstat", pf->file);
			goto out;
		}
		if (stat(pf->file, &info2)) {
			log_sys_error("stat", pf->file);
			goto out;
		}

		if (is_same_inode(info, info2))
			break;
	
		fcntl_unlock_file(lockfd);
	}

	/*
	 * If file contents changed since we loaded it, merge new contents
	 */
	lvm_stat_ctim(&ts, &info);
	if (merge_existing && timespeccmp(&ts, &pf->ctime, !=))
		/* Keep cft open to avoid losing lock */
		persistent_filter_load(f, &cft);

	tmp_file = alloca(strlen(pf->file) + 5);
	sprintf(tmp_file, "%s.tmp", pf->file);

	if (!(fp = fopen(tmp_file, "w"))) {
		/* EACCES has been reported over NFS */
		if (errno != EROFS && errno != EACCES)
			log_sys_error("fopen", tmp_file);
		goto out;
	}

	fprintf(fp, "# This file is automatically maintained by lvm.\n\n");
	fprintf(fp, "persistent_filter_cache {\n");

	_write_array(pf, fp, "valid_devices", PF_GOOD_DEVICE);
	/* We don't gain anything by remembering invalid devices */
	/* _write_array(pf, fp, "invalid_devices", PF_BAD_DEVICE); */

	fprintf(fp, "}\n");
	if (lvm_fclose(fp, tmp_file))
		goto_out;

	if (rename(tmp_file, pf->file))
		log_error("%s: rename to %s failed: %s", tmp_file, pf->file,
			  strerror(errno));

	r = 1;

out:
	fcntl_unlock_file(lockfd);

	if (cft)
		config_destroy(cft);

	return r;
}

static int _lookup_p(struct dev_filter *f, struct device *dev)
{
	struct pfilter *pf = (struct pfilter *) f->private;
	void *l = dm_hash_lookup(pf->devices, dev_name(dev));
	struct dm_str_list *sl;

	/* Cached BAD? */
	if (l == PF_BAD_DEVICE) {
		log_debug_devs("%s: Skipping (cached)", dev_name(dev));
		return 0;
	}

	/* Test dm devices every time, so cache them as GOOD. */
	if (MAJOR(dev->dev) == pf->dt->device_mapper_major) {
		if (!l)
			dm_list_iterate_items(sl, &dev->aliases)
				if (!dm_hash_insert(pf->devices, sl->str, PF_GOOD_DEVICE)) {
					log_error("Failed to hash device to filter.");
					return 0;
				}
		return pf->real->passes_filter(pf->real, dev);
	}

	/* Uncached */
	if (!l) {
		l = pf->real->passes_filter(pf->real, dev) ?  PF_GOOD_DEVICE : PF_BAD_DEVICE;

		dm_list_iterate_items(sl, &dev->aliases)
			if (!dm_hash_insert(pf->devices, sl->str, l)) {
				log_error("Failed to hash alias to filter.");
				return 0;
			}
	}

	return (l == PF_BAD_DEVICE) ? 0 : 1;
}

static void _persistent_destroy(struct dev_filter *f)
{
	struct pfilter *pf = (struct pfilter *) f->private;

	if (f->use_count)
		log_error(INTERNAL_ERROR "Destroying persistent filter while in use %u times.", f->use_count);

	dm_hash_destroy(pf->devices);
	dm_free(pf->file);
	pf->real->destroy(pf->real);
	dm_free(pf);
	dm_free(f);
}

struct dev_filter *persistent_filter_create(struct dev_types *dt,
					    struct dev_filter *real,
					    const char *file)
{
	struct pfilter *pf;
	struct dev_filter *f = NULL;
	struct stat info;

	if (!(pf = dm_zalloc(sizeof(*pf)))) {
		log_error("Allocation of persistent filter failed.");
		return NULL;
	}

	pf->dt = dt;

	if (!(pf->file = dm_strdup(file))) {
		log_error("Filename duplication for persistent filter failed.");
		goto bad;
	}

	pf->real = real;

	if (!(_init_hash(pf))) {
		log_error("Couldn't create hash table for persistent filter.");
		goto bad;
	}

	if (!(f = dm_zalloc(sizeof(*f)))) {
		log_error("Allocation of device filter for persistent filter failed.");
		goto bad;
	}

	/* Only merge cache file before dumping it if it changed externally. */
	if (!stat(pf->file, &info))
		lvm_stat_ctim(&pf->ctime, &info);

	f->passes_filter = _lookup_p;
	f->destroy = _persistent_destroy;
	f->use_count = 0;
	f->private = pf;
	f->wipe = _persistent_filter_wipe;
	f->dump = _persistent_filter_dump;

	log_debug_devs("Persistent filter initialised.");

	return f;

      bad:
	dm_free(pf->file);
	if (pf->devices)
		dm_hash_destroy(pf->devices);
	dm_free(pf);
	dm_free(f);
	return NULL;
}
