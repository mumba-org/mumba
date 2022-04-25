/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2012 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005-2007 NEC Corporation
 *
 * This file is part of the device-mapper userspace tools.
 *
 * It includes tree drawing code based on pstree: http://psmisc.sourceforge.net/
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "tool.h"

#include "dm-logging.h"

#include <ctype.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <locale.h>
#include <langinfo.h>
#include <time.h>

#include <fcntl.h>
#include <sys/stat.h>

#ifdef UDEV_SYNC_SUPPORT
#  include <sys/types.h>
#  include <sys/ipc.h>
#  include <sys/sem.h>
#  include <libudev.h>
#endif

/* FIXME Unused so far */
#undef HAVE_SYS_STATVFS_H

#ifdef HAVE_SYS_STATVFS_H
#  include <sys/statvfs.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_TIMERFD_H
# include <sys/timerfd.h>
#endif

#ifdef HAVE_TERMIOS_H
#  include <termios.h>
#endif

#ifdef HAVE_GETOPTLONG
#  include <getopt.h>
#  define GETOPTLONG_FN(a, b, c, d, e) getopt_long((a), (b), (c), (d), (e))
#  define OPTIND_INIT 0
#else
struct option {
};
extern int optind;
extern char *optarg;
#  define GETOPTLONG_FN(a, b, c, d, e) getopt((a), (b), (c))
#  define OPTIND_INIT 1
#endif

#ifndef TEMP_FAILURE_RETRY
# define TEMP_FAILURE_RETRY(expression) \
  (__extension__					\
    ({ long int __result;				\
       do __result = (long int) (expression);		\
       while (__result == -1L && errno == EINTR);	\
       __result; }))
#endif

#ifdef __linux__
#  include "kdev_t.h"
#else
#  define MAJOR(x) major((x))
#  define MINOR(x) minor((x))
#  define MKDEV(x,y) makedev((x),(y))
#endif

#define LINE_SIZE 4096
#define ARGS_MAX 256
#define LOOP_TABLE_SIZE (PATH_MAX + 255)

#define DEFAULT_DM_DEV_DIR "/dev/"

#define DM_DEV_DIR_ENV_VAR_NAME "DM_DEV_DIR"
#define DM_UDEV_COOKIE_ENV_VAR_NAME "DM_UDEV_COOKIE"

/* FIXME Should be imported */
#ifndef DM_MAX_TYPE_NAME
#  define DM_MAX_TYPE_NAME 16
#endif

/* FIXME Should be elsewhere */
#define SECTOR_SHIFT 9L

#define err(msg, x...) fprintf(stderr, msg "\n", ##x)

/* program_id used for dmstats-managed statistics regions */
#define DM_STATS_PROGRAM_ID "dmstats"

/*
 * Basic commands this code implments.
 */
typedef enum {
	DMSETUP_CMD = 0,
	LOSETUP_CMD = 1,
	DMLOSETUP_CMD = 2,
	DMSTATS_CMD = 3,
	DMSETUP_STATS_CMD = 4,
	DEVMAP_NAME_CMD = 5
} cmd_name_t;

typedef enum {
	DMSETUP_TYPE = 0,
	LOSETUP_TYPE = 1,
	STATS_TYPE = 2,
	DEVMAP_NAME_TYPE = 3
} cmd_type_t;

#define DMSETUP_CMD_NAME "dmsetup"
#define LOSETUP_CMD_NAME "losetup"
#define DMLOSETUP_CMD_NAME "dmlosetup"
#define DMSTATS_CMD_NAME "dmstats"
#define DMSETUP_STATS_CMD_NAME "dmsetup stats"
#define DEVMAP_NAME_CMD_NAME "devmap_name"

static const struct {
	cmd_name_t command;
	const char name[14];
	cmd_type_t type;
} _base_commands[] = {
	{ DMSETUP_CMD, DMSETUP_CMD_NAME, DMSETUP_TYPE },
	{ LOSETUP_CMD, LOSETUP_CMD_NAME, LOSETUP_TYPE },
	{ DMLOSETUP_CMD, DMLOSETUP_CMD_NAME, LOSETUP_TYPE },
	{ DMSTATS_CMD, DMSTATS_CMD_NAME, STATS_TYPE },
	{ DMSETUP_STATS_CMD, DMSETUP_STATS_CMD_NAME, STATS_TYPE },
	{ DEVMAP_NAME_CMD, DEVMAP_NAME_CMD_NAME, DEVMAP_NAME_TYPE },
};

static const int _num_base_commands = DM_ARRAY_SIZE(_base_commands);

/*
 * We have only very simple switches ATM.
 */
enum {
	READ_ONLY = 0,
	ADD_NODE_ON_CREATE_ARG,
	ADD_NODE_ON_RESUME_ARG,
	ALL_DEVICES_ARG,
	ALL_PROGRAMS_ARG,
	ALL_REGIONS_ARG,
	AREAS_ARG,
	AREA_SIZE_ARG,
	AUX_DATA_ARG,
	BOUNDS_ARG,
	CHECKS_ARG,
	CLEAR_ARG,
	COLS_ARG,
	COUNT_ARG,
	DEFERRED_ARG,
	SELECT_ARG,
	EXEC_ARG,
	FORCE_ARG,
	GID_ARG,
	HELP_ARG,
	HISTOGRAM_ARG,
	INACTIVE_ARG,
	INTERVAL_ARG,
	LENGTH_ARG,
	MANGLENAME_ARG,
	MAJOR_ARG,
	MINOR_ARG,
	MODE_ARG,
	NAMEPREFIXES_ARG,
	NOFLUSH_ARG,
	NOHEADINGS_ARG,
	NOLOCKFS_ARG,
	NOOPENCOUNT_ARG,
	NOSUFFIX_ARG,
	NOTABLE_ARG,
	NOTIMESUFFIX_ARG,
	UDEVCOOKIE_ARG,
	NOUDEVRULES_ARG,
	NOUDEVSYNC_ARG,
	OPTIONS_ARG,
	PRECISE_ARG,
	PROGRAM_ID_ARG,
	RAW_ARG,
	READAHEAD_ARG,
	REGION_ID_ARG,
	RELATIVE_ARG,
	RETRY_ARG,
	ROWS_ARG,
	SEPARATOR_ARG,
	SETUUID_ARG,
	SHOWKEYS_ARG,
	SORT_ARG,
	START_ARG,
	TABLE_ARG,
	TARGET_ARG,
	SEGMENTS_ARG,
	TREE_ARG,
	UID_ARG,
	UNBUFFERED_ARG,
	UNITS_ARG,
	UNQUOTED_ARG,
	UUID_ARG,
	VERBOSE_ARG,
	VERIFYUDEV_ARG,
	VERSION_ARG,
	YES_ARG,
	NUM_SWITCHES
};

typedef enum {
	DR_TASK = 1,
	DR_INFO = 2,
	DR_DEPS = 4,
	DR_TREE = 8,	/* Complete dependency tree required */
	DR_NAME = 16,
	DR_STATS = 32,  /* Requires populated stats handle. */
	DR_STATS_META = 64, /* Requires listed stats handle. */
} report_type_t;

typedef enum {
	DN_DEVNO,	/* Major and minor number pair */
	DN_BLK,		/* Block device name (e.g. dm-0) */
	DN_MAP		/* Map name (for dm devices only, equal to DN_BLK otherwise) */
} dev_name_t;

static cmd_name_t _base_command = DMSETUP_CMD;	/* Default command is 'dmsetup' */
static cmd_type_t _base_command_type = DMSETUP_TYPE;
static int _switches[NUM_SWITCHES];
static int _int_args[NUM_SWITCHES];
static char *_string_args[NUM_SWITCHES];
static int _num_devices;
static char *_uuid;
static char *_table;
static char *_target;
static char *_command_to_exec;		/* --exec <command> */
static const char *_command;		/* dmsetup <command> */
static uint32_t _read_ahead_flags;
static uint32_t _udev_cookie;
static int _udev_only;
static struct dm_tree *_dtree;
static struct dm_report *_report;
static report_type_t _report_type;
static dev_name_t _dev_name_type;
static uint32_t _count = 1; /* count of repeating reports */
static struct dm_timestamp *_initial_timestamp = NULL;
static uint64_t _disp_factor = 512; /* display sizes in sectors */
static char _disp_units = 's';
const char *_program_id = DM_STATS_PROGRAM_ID; /* program_id used for reports. */
static int _stats_report_by_areas = 1; /* output per-area info for stats reports. */

/* report timekeeping */
static struct dm_timestamp *_cycle_timestamp = NULL;
static uint64_t _interval = 0; /* configured interval in nsecs */
static uint64_t _new_interval = 0; /* flag top-of-interval */
static uint64_t _last_interval = 0; /* approx. measured interval in nsecs */
static int _timer_fd = -1; /* timerfd file descriptor. */

/* Invalid fd value used to signal end-of-reporting. */
#define TIMER_STOPPED -2

#define NSEC_PER_USEC	UINT64_C(1000)
#define NSEC_PER_MSEC	UINT64_C(1000000)
#define NSEC_PER_SEC	UINT64_C(1000000000)

/*
 * Commands
 */

struct command;
#define CMD_ARGS const struct command *cmd, const char *subcommand, int argc, char **argv, struct dm_names *names, int multiple_devices
typedef int (*command_fn) (CMD_ARGS);

struct command {
	const char *name;
	const char *help;
	int min_args;
	int max_args;
	int repeatable_cmd;	/* Repeat to process device list? */
	int has_subcommands;	/* Command implements sub-commands. */
	command_fn fn;
};

static int _parse_line(struct dm_task *dmt, char *buffer, const char *file,
		       int line)
{
	char ttype[LINE_SIZE], *ptr, *comment;
	unsigned long long start, size;
	int n;

	/* trim trailing space */
	for (ptr = buffer + strlen(buffer) - 1; ptr >= buffer; ptr--)
		if (!isspace((int) *ptr))
			break;
	ptr++;
	*ptr = '\0';

	/* trim leading space */
	for (ptr = buffer; *ptr && isspace((int) *ptr); ptr++)
		;

	if (!*ptr || *ptr == '#')
		return 1;

	if (sscanf(ptr, "%llu %llu %s %n",
		   &start, &size, ttype, &n) < 3) {
		err("Invalid format on line %d of table %s", line, file);
		return 0;
	}

	ptr += n;
	if ((comment = strchr(ptr, (int) '#')))
		*comment = '\0';

	if (!dm_task_add_target(dmt, start, size, ttype, ptr))
		return_0;

	return 1;
}

static int _parse_file(struct dm_task *dmt, const char *file)
{
	char *buffer = NULL;
	size_t buffer_size = 0;
	FILE *fp;
	int r = 0, line = 0;

	/* one-line table on cmdline */
	if (_table)
		return _parse_line(dmt, _table, "", ++line);

	/* OK for empty stdin */
	if (file) {
		if (!(fp = fopen(file, "r"))) {
			err("Couldn't open '%s' for reading", file);
			return 0;
		}
	} else
		fp = stdin;

#ifndef HAVE_GETLINE
	buffer_size = LINE_SIZE;
	if (!(buffer = dm_malloc(buffer_size))) {
		err("Failed to malloc line buffer.");
		return 0;
	}

	while (fgets(buffer, (int) buffer_size, fp))
#else
	while (getline(&buffer, &buffer_size, fp) > 0)
#endif
		if (!_parse_line(dmt, buffer, file ? : "on stdin", ++line))
			goto_out;

	r = 1;

out:
	memset(buffer, 0, buffer_size);
#ifndef HAVE_GETLINE
	dm_free(buffer);
#else
	free(buffer);
#endif
	if (file && fclose(fp))
		fprintf(stderr, "%s: fclose failed: %s", file, strerror(errno));

	return r;
}

struct dm_split_name {
	char *subsystem;
	char *vg_name;
	char *lv_name;
	char *lv_layer;
};

struct dmsetup_report_obj {
	struct dm_task *task;
	struct dm_info *info;
	struct dm_task *deps_task;
	struct dm_tree_node *tree_node;
	struct dm_split_name *split_name;
	struct dm_stats *stats;
};

static int _task_run(struct dm_task *dmt)
{
	int r;
	uint64_t delta;

	if (_initial_timestamp)
		dm_task_set_record_timestamp(dmt);

	r = dm_task_run(dmt);

	if (_initial_timestamp) {
		delta = dm_timestamp_delta(dm_task_get_ioctl_timestamp(dmt), _initial_timestamp);
		log_debug("Timestamp: %7" PRIu64 ".%09" PRIu64 " seconds", delta / NSEC_PER_SEC, delta % NSEC_PER_SEC);
	}

	return r;
}

static struct dm_task *_get_deps_task(int major, int minor)
{
	struct dm_task *dmt;
	struct dm_info info;

	if (!(dmt = dm_task_create(DM_DEVICE_DEPS)))
		return_NULL;

	if (!dm_task_set_major(dmt, major) ||
	    !dm_task_set_minor(dmt, minor))
		goto_bad;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_bad;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_bad;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_bad;

	if (!_task_run(dmt))
		goto_bad;

	if (!dm_task_get_info(dmt, &info))
		goto_bad;

	if (!info.exists)
		goto_bad;

	return dmt;

bad:
	dm_task_destroy(dmt);
	return NULL;
}

static char *_extract_uuid_prefix(const char *uuid, const int separator)
{
	char *ptr = NULL;
	char *uuid_prefix = NULL;
	size_t len;

	if (uuid)
		ptr = strchr(uuid, separator);

	len = ptr ? ptr - uuid : 0;
	if (!(uuid_prefix = dm_malloc(len + 1))) {
		log_error("Failed to allocate memory to extract uuid prefix.");
		return NULL;
	}

	if (uuid)
		memcpy(uuid_prefix, uuid, len);

	uuid_prefix[len] = '\0';

	return uuid_prefix;
}

static struct dm_split_name *_get_split_name(const char *uuid, const char *name,
					     int separator)
{
	struct dm_split_name *split_name;

	if (!(split_name = dm_malloc(sizeof(*split_name)))) {
		log_error("Failed to allocate memory to split device name "
			  "into components.");
		return NULL;
	}

	if (!(split_name->subsystem = _extract_uuid_prefix(uuid, separator))) {
		dm_free(split_name);
		return_NULL;
	}

	split_name->vg_name = split_name->lv_name =
	    split_name->lv_layer = (char *) "";

	if (!strcmp(split_name->subsystem, "LVM") &&
	    (!(split_name->vg_name = dm_strdup(name)) ||
	     !dm_split_lvm_name(NULL, NULL, &split_name->vg_name,
				&split_name->lv_name, &split_name->lv_layer)))
		log_error("Failed to allocate memory to split LVM name "
			  "into components.");

	return split_name;
}

static void _destroy_split_name(struct dm_split_name *split_name)
{
	/*
	 * lv_name and lv_layer are allocated within the same block
	 * of memory as vg_name so don't need to be freed separately.
	 */
	if (!strcmp(split_name->subsystem, "LVM"))
		dm_free(split_name->vg_name);

	dm_free(split_name->subsystem);
	dm_free(split_name);
}

/*
 * Stats clock:
 *
 * Use either Linux timerfds or usleep to implement the reporting
 * interval wait.
 *
 *  _start_timer()   - Start the timer running.
 *  _do_timer_wait() - Wait until the beginning of the next interval.
 *
 *  _update_interval_times() - Update timestamps and interval estimate.
 */

/*
 * Return the current interval number counting upwards from one.
 */
static uint64_t _interval_num(void)
{
	return 1 + (uint64_t) _int_args[COUNT_ARG] - _count;
}

#ifdef HAVE_SYS_TIMERFD_H
static int _start_timerfd_timer(void)
{
	struct itimerspec interval_timer;
	time_t secs;
	long nsecs;

	log_debug("Using timerfd for interval timekeeping.");

	/* timer running? */
	if (_timer_fd != -1)
		return 1;

	memset(&interval_timer, 0, sizeof(interval_timer));

	/* Use CLOCK_MONOTONIC to avoid warp on RTC adjustments. */
	if ((_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)) < 0) {
		log_error("Could not create timer: %s", strerror(errno));
		return 0;
	}

	secs = (time_t) _interval / NSEC_PER_SEC;
	nsecs = (long) _interval % NSEC_PER_SEC;

	/* Must set interval and value to create an armed periodic timer. */
	interval_timer.it_interval.tv_sec = secs;
	interval_timer.it_interval.tv_nsec = nsecs;
	interval_timer.it_value.tv_sec = secs;
	interval_timer.it_value.tv_nsec = nsecs;

	log_debug("Setting interval timer to: " FMTu64 "s %ldns", (uint64_t)secs, nsecs);
	if (timerfd_settime(_timer_fd, 0, &interval_timer, NULL)) {
		log_error("Could not set interval timer: %s", strerror(errno));
		return 0;
	}
	return 1;
}

static int _do_timerfd_wait(void)
{
	uint64_t expired;
	ssize_t bytes;

	if (_timer_fd < 0)
		return_0;

	/* read on timerfd returns a uint64_t in host byte order. */
	bytes = read(_timer_fd, &expired, sizeof(expired));

	if (bytes < 0) {
		/* EBADF from invalid timerfd or EINVAL from too small buffer. */
		log_error("Interval timer wait failed: %s",
			  strerror(errno));
		return 0;
	}

	/* read(2) on a timerfd descriptor is guaranteed to return 8 bytes. */
	if (bytes != 8)
		log_error("Unexpected byte count on timerfd read: " FMTssize_t, bytes);

	/* FIXME: attempt to rebase clock? */
	if (expired > 1)
		log_warn("WARNING: Try increasing --interval ("FMTu64
			 " missed timer events).", expired - 1);

	/* Signal that a new interval has begun. */
	_new_interval = 1;

	/* Final interval? */
	if (_count == 2) {
		if (close(_timer_fd))
			stack;
		/* Tell _update_interval_times() to shut down. */
		_timer_fd = TIMER_STOPPED;
	}

	return 1;
}

static int _start_timer(void)
{
	return _start_timerfd_timer();
}

static int _do_timer_wait(void)
{
	return _do_timerfd_wait();
}

#else /* !HAVE_SYS_TIMERFD_H */
static int _start_usleep_timer(void)
{
	log_debug("Using usleep for interval timekeeping.");
	return 1;
}

static int _do_usleep_wait(void)
{
	static struct dm_timestamp *_last_sleep, *_now = NULL;
	uint64_t this_interval;
	int64_t delta_t;

	/*
	 * Report clock: compensate for time spent in userspace and stats
	 * message ioctls by keeping track of the last wake time and
	 * adjusting the sleep interval accordingly.
	 */
	if (!_last_sleep && !_now) {
		if (!(_last_sleep = dm_timestamp_alloc()))
			return_0;
		if (!(_now = dm_timestamp_alloc()))
			return_0;
		dm_timestamp_get(_now);
		this_interval = _interval;
		log_error("Using "FMTu64" as first interval.", this_interval);
	} else {
		dm_timestamp_get(_now);
		delta_t = dm_timestamp_delta(_now, _last_sleep);
		log_debug("Interval timer delta_t: "FMTi64, delta_t);

		/* FIXME: usleep timer drift over large counts. */

		/* adjust for time spent populating and reporting */
		this_interval = 2 * _interval - delta_t;
		log_debug("Using "FMTu64" as interval.", this_interval);
	}

	/* Signal that a new interval has begun. */
	_new_interval = 1;
	dm_timestamp_copy(_last_sleep, _now);

	if (usleep(this_interval / NSEC_PER_USEC)) {
		if (errno == EINTR)
			log_error("Report interval interrupted by signal.");
		if (errno == EINVAL)
			log_error("Report interval too short.");
		return_0;
	}

	if (_count == 2) {
		dm_timestamp_destroy(_last_sleep);
		dm_timestamp_destroy(_now);
	}

	return 1;
}

static int _start_timer(void)
{
	return _start_usleep_timer();
}

static int _do_timer_wait(void)
{
	return _do_usleep_wait();
}

#endif /* HAVE_SYS_TIMERFD_H */

static int _update_interval_times(void)
{
	static struct dm_timestamp *this_timestamp = NULL;
	uint64_t delta_t, interval_num = _interval_num();
	int r = 0;

	/*
	 * Clock shutdown for exit - nothing to do.
	 */
	if (_timer_fd == TIMER_STOPPED && !_cycle_timestamp)
		return 1;

	/*
         * Current timestamp. If _new_interval is set this is used as
         * the new cycle start timestamp.
	 */
	if (!this_timestamp) {
		if (!(this_timestamp = dm_timestamp_alloc()))
			return_0;
	}

	/*
	 * Take cycle timstamp as close as possible to ioctl return.
	 *
	 * FIXME: use per-region timestamp deltas for interval estimate.
	 */
	if (!dm_timestamp_get(this_timestamp))
		goto_out;

	/*
	 * Stats clock: maintain a single timestamp taken just after the
	 * call to dm_stats_populate() and take a delta between the current
	 * and last value to determine the sampling interval.
	 *
	 * A new interval is started when the _new_interval flag is set
	 * on return from _do_report_wait().
	 *
	 * The first interval is treated as a special case: since the
	 * time since the last clear of the counters is unknown (no
	 * previous timestamp exists) the duration is assumed to be the
	 * configured value.
	 */
	if (_cycle_timestamp)
		/* Current delta_t: time from start of cycle to now. */
		delta_t = dm_timestamp_delta(this_timestamp, _cycle_timestamp);
	else {
		_cycle_timestamp = dm_timestamp_alloc();
		if (!_cycle_timestamp) {
			log_error("Could not allocate timestamp object.");
			goto out;
		}

		/* Pretend we have the configured interval. */
		delta_t = _interval;

		/* start the first cycle */
		log_debug("Beginning first interval");
		_new_interval = 1;
	}

	log_debug("Interval     #%-4"PRIu64"     time delta: %12"
		  PRIu64"ns", interval_num, delta_t);

	if (_new_interval) {
		/* Update timestamp and interval and clear _new_interval */
		dm_timestamp_copy(_cycle_timestamp, this_timestamp);
		_last_interval = delta_t;
		_new_interval = 0;

		/*
		 * Log interval duration and current error.
		 */
		log_debug("Interval     #%-5"PRIu64"   current err: %12"PRIi64"ns",
			  interval_num, ((int64_t)_last_interval - (int64_t)_interval));
		log_debug("End interval #%-9"PRIu64"  duration: %12"PRIu64"ns",
			  interval_num, _last_interval);
	}

	r = 1;

out:
	if (!r || _timer_fd == TIMER_STOPPED) {
		/* The _cycle_timestamp has not yet been allocated if we
		 * fail to obtain this_timestamp on the first interval.
		 */
		if (_cycle_timestamp)
			dm_timestamp_destroy(_cycle_timestamp);
		dm_timestamp_destroy(this_timestamp);

		/* Clear timestamp pointers to signal shutdown. */
		_cycle_timestamp = this_timestamp = NULL;
	}
	return r;
}

static int _display_info_cols(struct dm_task *dmt, struct dm_info *info)
{
	struct dmsetup_report_obj obj;

	int r = 0;

	if (!info->exists) {
		fprintf(stderr, "Device does not exist.\n");
		return 0;
	}

	obj.task = dmt;
	obj.info = info;
	obj.deps_task = NULL;
	obj.split_name = NULL;
	obj.stats = NULL;

	if (_report_type & DR_TREE)
		if (!(obj.tree_node = dm_tree_find_node(_dtree, info->major, info->minor))) {
			log_error("Cannot find node %d:%d.", info->major, info->minor);
			goto out;
		}

	if (_report_type & DR_DEPS)
		if (!(obj.deps_task = _get_deps_task(info->major, info->minor))) {
			log_error("Cannot get deps for %d:%d.", info->major, info->minor);
			goto out;
		}

	if (_report_type & DR_NAME)
		if (!(obj.split_name = _get_split_name(dm_task_get_uuid(dmt),
						       dm_task_get_name(dmt), '-')))
			goto_out;

	/*
	 * Obtain statistics for the current reporting object and set
	 * the interval estimate used for stats rate conversion.
	 */
	if (_report_type & DR_STATS) {
		if (!(obj.stats = dm_stats_create(DM_STATS_PROGRAM_ID)))
			goto_out;

		dm_stats_bind_devno(obj.stats, info->major, info->minor);

		if (!dm_stats_populate(obj.stats, _program_id, DM_STATS_REGIONS_ALL))
			goto_out;

		/* Update timestamps and handle end-of-interval accounting. */
		_update_interval_times();

		log_debug("Adjusted sample interval duration: %12"PRIu64"ns", _last_interval);
		/* use measured approximation for calculations */
		dm_stats_set_sampling_interval_ns(obj.stats, _last_interval);
	}

	/* Only a dm_stats_list is needed for DR_STATS_META reports. */
	if (!obj.stats && (_report_type & DR_STATS_META)) {
		if (!(obj.stats = dm_stats_create(DM_STATS_PROGRAM_ID)))
			goto_out;

		dm_stats_bind_devno(obj.stats, info->major, info->minor);

		if (!dm_stats_list(obj.stats, _program_id))
			goto_out;

		/* No regions to report */
		if (!dm_stats_get_nr_regions(obj.stats))
			goto_out;
	}

	/*
	 * Walk any statistics regions contained in the current
	 * reporting object: for objects with a NULL stats handle,
	 * or a handle containing no registered regions, this loop
	 * always executes exactly once.
	 */
	dm_stats_walk_do(obj.stats) {
		if (!dm_report_object(_report, &obj))
			goto_out;
		if (_stats_report_by_areas)
			dm_stats_walk_next(obj.stats);
		else
			dm_stats_walk_next_region(obj.stats);
	} dm_stats_walk_while(obj.stats);
	r = 1;

out:
	if (obj.deps_task)
		dm_task_destroy(obj.deps_task);
	if (obj.split_name)
		_destroy_split_name(obj.split_name);
	if (obj.stats)
		dm_stats_destroy(obj.stats);
	return r;
}

static void _display_info_long(struct dm_task *dmt, struct dm_info *info)
{
	const char *uuid;
	uint32_t read_ahead;

	if (!info->exists) {
		fprintf(stderr, "Device does not exist.\n");
		return;
	}

	printf("Name:              %s\n", dm_task_get_name(dmt));

	printf("State:             %s%s%s\n",
	       info->suspended ? "SUSPENDED" : "ACTIVE",
	       info->read_only ? " (READ-ONLY)" : "",
	       info->deferred_remove ? " (DEFERRED REMOVE)" : "");

	/* FIXME Old value is being printed when it's being changed. */
	if (dm_task_get_read_ahead(dmt, &read_ahead))
		printf("Read Ahead:        %" PRIu32 "\n", read_ahead);

	if (!info->live_table && !info->inactive_table)
		printf("Tables present:    None\n");
	else
		printf("Tables present:    %s%s%s\n",
		       info->live_table ? "LIVE" : "",
		       info->live_table && info->inactive_table ? " & " : "",
		       info->inactive_table ? "INACTIVE" : "");

	if (info->open_count != -1)
		printf("Open count:        %d\n", info->open_count);

	printf("Event number:      %" PRIu32 "\n", info->event_nr);
	printf("Major, minor:      %d, %d\n", info->major, info->minor);

	if (info->target_count != -1)
		printf("Number of targets: %d\n", info->target_count);

	if ((uuid = dm_task_get_uuid(dmt)) && *uuid)
		printf("UUID: %s\n", uuid);

	printf("\n");
}

static int _display_info(struct dm_task *dmt)
{
	struct dm_info info;

	if (!dm_task_get_info(dmt, &info))
		return_0;

	if (!_switches[COLS_ARG])
		_display_info_long(dmt, &info);
	else
		/* FIXME return code */
		_display_info_cols(dmt, &info);

	return info.exists ? 1 : 0;
}

static int _set_task_device(struct dm_task *dmt, const char *name, int optional)
{
	if (name) {
		if (!dm_task_set_name(dmt, name))
			return_0;
	} else if (_switches[UUID_ARG]) {
		if (!dm_task_set_uuid(dmt, _uuid))
			return_0;
	} else if (_switches[MAJOR_ARG] && _switches[MINOR_ARG]) {
		if (!dm_task_set_major(dmt, _int_args[MAJOR_ARG]) ||
		    !dm_task_set_minor(dmt, _int_args[MINOR_ARG]))
			return_0;
	} else if (!optional) {
		fprintf(stderr, "No device specified.\n");
		return 0;
	}

	return 1;
}

static int _set_task_add_node(struct dm_task *dmt)
{
	if (!dm_task_set_add_node(dmt, DEFAULT_DM_ADD_NODE))
		return_0;

	if (_switches[ADD_NODE_ON_RESUME_ARG] &&
	    !dm_task_set_add_node(dmt, DM_ADD_NODE_ON_RESUME))
		return_0;

	if (_switches[ADD_NODE_ON_CREATE_ARG] &&
	    !dm_task_set_add_node(dmt, DM_ADD_NODE_ON_CREATE))
		return_0;

	return 1;
}

static int _load(CMD_ARGS)
{
	int r = 0;
	struct dm_task *dmt;
	const char *file = NULL;
	const char *name = NULL;

	if (_switches[NOTABLE_ARG]) {
		err("--notable only available when creating new device\n");
		return 0;
	}

	if (!_switches[UUID_ARG] && !_switches[MAJOR_ARG]) {
		if (!argc) {
			err("Please specify device.\n");
			return 0;
		}
		name = argv[0];
		argc--;
		argv++;
	} else if (argc > 1) {
		err("Too many command line arguments.\n");
		return 0;
	}

	if (argc == 1)
		file = argv[0];

	if (!(dmt = dm_task_create(DM_DEVICE_RELOAD)))
		return_0;

	if (!_set_task_device(dmt, name, 0))
		goto_out;

	if (!_switches[NOTABLE_ARG] && !_parse_file(dmt, file))
		goto_out;

	if (_switches[READ_ONLY] && !dm_task_set_ro(dmt))
		goto_out;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_task_run(dmt))
		goto_out;

	r = 1;

	if (_switches[VERBOSE_ARG])
		r = _display_info(dmt);

out:
	dm_task_destroy(dmt);

	return r;
}

static int _create(CMD_ARGS)
{
	int r = 0;
	struct dm_task *dmt;
	const char *file = NULL;
	uint32_t cookie = 0;
	uint16_t udev_flags = 0;

	if (argc == 2)
		file = argv[1];

	if (!(dmt = dm_task_create(DM_DEVICE_CREATE)))
		return_0;

	if (!dm_task_set_name(dmt, argv[0]))
		goto_out;

	if (_switches[UUID_ARG] && !dm_task_set_uuid(dmt, _uuid))
		goto_out;

	if (!_switches[NOTABLE_ARG] && !_parse_file(dmt, file))
		goto_out;

	if (_switches[READ_ONLY] && !dm_task_set_ro(dmt))
		goto_out;

	if (_switches[MAJOR_ARG] && !dm_task_set_major(dmt, _int_args[MAJOR_ARG]))
		goto_out;

	if (_switches[MINOR_ARG] && !dm_task_set_minor(dmt, _int_args[MINOR_ARG]))
		goto_out;

	if (_switches[UID_ARG] && !dm_task_set_uid(dmt, _int_args[UID_ARG]))
		goto_out;

	if (_switches[GID_ARG] && !dm_task_set_gid(dmt, _int_args[GID_ARG]))
		goto_out;

	if (_switches[MODE_ARG] && !dm_task_set_mode(dmt, _int_args[MODE_ARG]))
		goto_out;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_out;

	if (_switches[READAHEAD_ARG] &&
	    !dm_task_set_read_ahead(dmt, _int_args[READAHEAD_ARG],
				    _read_ahead_flags))
		goto_out;

	if (_switches[NOTABLE_ARG])
		dm_udev_set_sync_support(0);

	if (_switches[NOUDEVRULES_ARG])
		udev_flags |= DM_UDEV_DISABLE_DM_RULES_FLAG |
			      DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_set_task_add_node(dmt))
		goto_out;

	if (_udev_cookie)
		cookie = _udev_cookie;

	if (_udev_only)
		udev_flags |= DM_UDEV_DISABLE_LIBRARY_FALLBACK;

	if (!dm_task_set_cookie(dmt, &cookie, udev_flags) ||
	    !_task_run(dmt))
		goto_out;

	r = 1;

out:
	if (!_udev_cookie)
		(void) dm_udev_wait(cookie);

	if (r && _switches[VERBOSE_ARG])
		r = _display_info(dmt);

	dm_task_destroy(dmt);

	return r;
}

static int _do_rename(const char *name, const char *new_name, const char *new_uuid) {
	int r = 0;
	struct dm_task *dmt;
	uint32_t cookie = 0;
	uint16_t udev_flags = 0;

	if (!(dmt = dm_task_create(DM_DEVICE_RENAME)))
		return_0;

	/* FIXME Kernel doesn't support uuid or device number here yet */
	if (!_set_task_device(dmt, name, 0))
		goto_out;

	if (new_uuid) {
		if (!dm_task_set_newuuid(dmt, new_uuid))
			goto_out;
	} else if (!new_name || !dm_task_set_newname(dmt, new_name))
		goto_out;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (_switches[NOUDEVRULES_ARG])
		udev_flags |= DM_UDEV_DISABLE_DM_RULES_FLAG |
			      DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG;

	if (_udev_cookie)
		cookie = _udev_cookie;

	if (_udev_only)
		udev_flags |= DM_UDEV_DISABLE_LIBRARY_FALLBACK;

	if (!dm_task_set_cookie(dmt, &cookie, udev_flags) ||
	    !_task_run(dmt))
		goto_out;

	r = 1;

out:
	if (!_udev_cookie)
		(void) dm_udev_wait(cookie);

	dm_task_destroy(dmt);

	return r;
}

static int _rename(CMD_ARGS)
{
	const char *name = (argc == 2) ? argv[0] : NULL;

	return _switches[SETUUID_ARG] ? _do_rename(name, NULL, argv[argc - 1]) :
					_do_rename(name, argv[argc - 1], NULL);

}

static int _message(CMD_ARGS)
{
	int r = 0, i;
	size_t sz = 1;
	struct dm_task *dmt;
	char *str;
	const char *response;
	uint64_t sector;
	char *endptr;

	if (!(dmt = dm_task_create(DM_DEVICE_TARGET_MSG)))
		return_0;

	if (_switches[UUID_ARG] || _switches[MAJOR_ARG]) {
		if (!_set_task_device(dmt, NULL, 0))
			goto_out;
	} else {
		if (!_set_task_device(dmt, argv[0], 0))
			goto_out;
		argc--;
		argv++;
	}

	sector = strtoull(argv[0], &endptr, 10);
	if (*endptr || endptr == argv[0]) {
		err("invalid sector");
		goto out;
	}
	if (!dm_task_set_sector(dmt, sector))
		goto_out;

	argc--;
	argv++;

	if (argc <= 0)
		err("No message supplied.\n");

	for (i = 0; i < argc; i++)
		sz += strlen(argv[i]) + 1;

	if (!(str = dm_zalloc(sz))) {
		err("message string allocation failed");
		goto out;
	}

	for (i = 0; i < argc; i++) {
		if (i)
			strcat(str, " ");
		strcat(str, argv[i]);
	}

	i = dm_task_set_message(dmt, str);

	dm_free(str);

	if (!i)
		goto_out;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_task_run(dmt))
		goto_out;

	if ((response = dm_task_get_message_response(dmt))) {
		if (!*response || response[strlen(response) - 1] == '\n')
			fputs(response, stdout);
		else
			puts(response);
	}

	r = 1;

out:
	dm_task_destroy(dmt);

	return r;
}

static int _setgeometry(CMD_ARGS)
{
	int r = 0;
	struct dm_task *dmt;

	if (!(dmt = dm_task_create(DM_DEVICE_SET_GEOMETRY)))
		return_0;

	if (_switches[UUID_ARG] || _switches[MAJOR_ARG]) {
		if (!_set_task_device(dmt, NULL, 0))
			goto_out;
	} else {
		if (!_set_task_device(dmt, argv[0], 0))
			goto_out;
		argc--;
		argv++;
	}

	if (!dm_task_set_geometry(dmt, argv[0], argv[1], argv[2], argv[3]))
		goto_out;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	/* run the task */
	if (!_task_run(dmt))
		goto_out;

	r = 1;

out:
	dm_task_destroy(dmt);

	return r;
}

static int _splitname(CMD_ARGS)
{
	struct dmsetup_report_obj obj = { NULL };
	int r;

	if (!(obj.split_name = _get_split_name((argc == 2) ? argv[1] : "LVM",
					       argv[0], '\0')))
		return_0;

	r = dm_report_object(_report, &obj);
	_destroy_split_name(obj.split_name);

	return r;
}

static uint32_t _get_cookie_value(const char *str_value)
{
	unsigned long int value;
	char *p;

	errno = 0;
	if (!(value = strtoul(str_value, &p, 0)) ||
	    *p ||
	    (value == ULONG_MAX && errno == ERANGE) ||
	    value > 0xFFFFFFFF) {
		err("Incorrect cookie value");
		return 0;
	}
	else
		return (uint32_t) value;
}

static int _udevflags(CMD_ARGS)
{
	uint32_t cookie;
	uint16_t flags;
	int i;
	static const char *dm_flag_names[] = {"DISABLE_DM_RULES",
					      "DISABLE_SUBSYSTEM_RULES",
					      "DISABLE_DISK_RULES",
					      "DISABLE_OTHER_RULES",
					      "LOW_PRIORITY",
					      "DISABLE_LIBRARY_FALLBACK",
					      "PRIMARY_SOURCE",
					       0};

	if (!(cookie = _get_cookie_value(argv[0])))
		return_0;

	flags = cookie >> DM_UDEV_FLAGS_SHIFT;

	for (i = 0; i < DM_UDEV_FLAGS_SHIFT; i++)
		if (1 << i & flags) {
			if (i < DM_UDEV_FLAGS_SHIFT / 2 && dm_flag_names[i])
				printf("DM_UDEV_%s_FLAG='1'\n", dm_flag_names[i]);
			else if (i < DM_UDEV_FLAGS_SHIFT / 2)
				/*
				 * This is just a fallback. Each new DM flag
				 * should have its symbolic name assigned.
				 */
				printf("DM_UDEV_FLAG%d='1'\n", i);
			else
				/*
				 * We can't assign symbolic names to subsystem
				 * flags. Their semantics vary based on the
				 * subsystem that is currently used.
				 */
				printf("DM_SUBSYSTEM_UDEV_FLAG%d='1'\n",
					i - DM_UDEV_FLAGS_SHIFT / 2);
		}

	return 1;
}

static int _udevcomplete(CMD_ARGS)
{
	uint32_t cookie;

	if (!(cookie = _get_cookie_value(argv[0])))
		return_0;

	/*
	 * Strip flags from the cookie and use cookie magic instead.
	 * If the cookie has non-zero prefix and the base is zero then
	 * this one carries flags to control udev rules only and it is
	 * not meant to be for notification. Return with success in this
	 * situation.
	 */
	if (!(cookie &= ~DM_UDEV_FLAGS_MASK))
		return 1;

	cookie |= DM_COOKIE_MAGIC << DM_UDEV_FLAGS_SHIFT;

	return dm_udev_complete(cookie);
}

#ifndef UDEV_SYNC_SUPPORT
static const char _cmd_not_supported[] = "Command not supported. Recompile with \"--enable-udev_sync\" to enable.";

static int _udevcreatecookie(CMD_ARGS)
{
	log_error(_cmd_not_supported);

	return 0;
}

static int _udevreleasecookie(CMD_ARGS)
{
	log_error(_cmd_not_supported);

	return 0;
}

static int _udevcomplete_all(CMD_ARGS)
{
	log_error(_cmd_not_supported);

	return 0;
}

static int _udevcookies(CMD_ARGS)
{
	log_error(_cmd_not_supported);

	return 0;
}

#else	/* UDEV_SYNC_SUPPORT */
static int _set_up_udev_support(const char *dev_dir)
{
	int dirs_diff;
	const char *env;
	size_t len = strlen(dev_dir), udev_dir_len = strlen(DM_UDEV_DEV_DIR);

	if (_switches[NOUDEVSYNC_ARG])
		dm_udev_set_sync_support(0);

	if (!_udev_cookie) {
		env = getenv(DM_UDEV_COOKIE_ENV_VAR_NAME);
		if (env && *env && (_udev_cookie = _get_cookie_value(env)))
			log_debug("Using udev transaction 0x%08" PRIX32
				  " defined by %s environment variable.",
				   _udev_cookie,
				   DM_UDEV_COOKIE_ENV_VAR_NAME);
	}
	else if (_switches[UDEVCOOKIE_ARG])
		log_debug("Using udev transaction 0x%08" PRIX32
			  " defined by --udevcookie option.",
			  _udev_cookie);

	/*
	 * Normally, there's always a fallback action by libdevmapper if udev
	 * has not done its job correctly, e.g. the nodes were not created.
	 * If using udev transactions by specifying existing cookie value,
	 * we need to disable node creation by libdevmapper completely,
	 * disabling any fallback actions, since any synchronisation happens
	 * at the end of the transaction only. We need to do this to prevent
	 * races between udev and libdevmapper but only in case udev "dev path"
	 * is the same as "dev path" used by libdevmapper.
	 */


	/*
	 * DM_UDEV_DEV_DIR always has '/' at its end.
	 * If the dev_dir does not have it, be sure
	 * to make the right comparison without the '/' char!
	 */
	if (dev_dir[len - 1] != '/')
		udev_dir_len--;

	dirs_diff = udev_dir_len != len ||
		    strncmp(DM_UDEV_DEV_DIR, dev_dir, len);
	_udev_only = !dirs_diff && (_udev_cookie || !_switches[VERIFYUDEV_ARG]);

	if (dirs_diff) {
		log_debug("The path %s used for creating device nodes that is "
			  "set via DM_DEV_DIR environment variable differs from "
			  "the path %s that is used by udev. All warnings "
			  "about udev not working correctly while processing "
			  "particular nodes will be suppressed. These nodes "
			  "and symlinks will be managed in each directory "
			  "separately.", dev_dir, DM_UDEV_DEV_DIR);
		dm_udev_set_checking(0);
	}

	return 1;
}

static int _udevcreatecookie(CMD_ARGS)
{
	uint32_t cookie;

	if (!dm_udev_create_cookie(&cookie))
		return_0;

	if (cookie)
		printf("0x%08" PRIX32 "\n", cookie);

	return 1;
}

static int _udevreleasecookie(CMD_ARGS)
{
	if (argv[0] && !(_udev_cookie = _get_cookie_value(argv[0])))
		return_0;

	if (!_udev_cookie) {
		log_error("No udev transaction cookie given.");
		return 0;
	}

	return dm_udev_wait(_udev_cookie);
}

__attribute__((format(printf, 1, 2)))
static char _yes_no_prompt(const char *prompt, ...)
{
	int c = 0, ret = 0;
	va_list ap;

	do {
		if (c == '\n' || !c) {
			va_start(ap, prompt);
			vprintf(prompt, ap);
			va_end(ap);
		}

		if ((c = getchar()) == EOF) {
			ret = 'n';
			break;
		}

		c = tolower(c);
		if ((c == 'y') || (c == 'n'))
			ret = c;
	} while (!ret || c != '\n');

	if (c != '\n')
		printf("\n");

	return ret;
}

static int _udevcomplete_all(CMD_ARGS)
{
	int max_id, id, sid;
	struct seminfo sinfo;
	struct semid_ds sdata;
	int counter = 0;
	int skipped = 0;
	unsigned age = 0;
	time_t t;

	if (argc == 1 && (sscanf(argv[0], "%u", &age) != 1)) {
		log_error("Failed to read age_in_minutes parameter.");
		return 0;
	}

	if (!_switches[YES_ARG]) {
		log_warn("This operation will destroy all semaphores %s%.0d%swith keys "
			 "that have a prefix %" PRIu16 " (0x%" PRIx16 ").",
			 age ? "older than " : "", age, age ? " minutes " : "",
			 DM_COOKIE_MAGIC, DM_COOKIE_MAGIC);

		if (_yes_no_prompt("Do you really want to continue? [y/n]: ") == 'n') {
			log_print("Semaphores with keys prefixed by %" PRIu16
				  " (0x%" PRIx16 ") NOT destroyed.",
				  DM_COOKIE_MAGIC, DM_COOKIE_MAGIC);
			return 1;
		}
	}

	if ((max_id = semctl(0, 0, SEM_INFO, &sinfo)) < 0) {
		log_sys_error("semctl", "SEM_INFO");
		return 0;
	}

	for (id = 0; id <= max_id; id++) {
		if ((sid = semctl(id, 0, SEM_STAT, &sdata)) < 0)
			continue;

		if (sdata.sem_perm.__key >> 16 == DM_COOKIE_MAGIC) {
			t = time(NULL);

			if (sdata.sem_ctime + age * 60 > t ||
			    sdata.sem_otime + age * 60 > t) {
				skipped++;
				continue;
			}
			if (semctl(sid, 0, IPC_RMID, 0) < 0) {
				log_error("Could not cleanup notification semaphore "
					  "with semid %d and cookie value "
					  FMTu32 " (0x" FMTx32 ")", sid,
					  sdata.sem_perm.__key, sdata.sem_perm.__key);
				continue;
			}

			counter++;
		}
	}

	log_print("%d semaphores with keys prefixed by "
		  FMTu16 " (0x" FMTx16 ") destroyed. %d skipped.",
		  counter, DM_COOKIE_MAGIC, DM_COOKIE_MAGIC, skipped);

	return 1;
}

static int _udevcookies(CMD_ARGS)
{
	int max_id, id, sid;
	struct seminfo sinfo;
	struct semid_ds sdata;
	int val;
	char otime_str[26], ctime_str[26];
	char *otimes, *ctimes;

	if ((max_id = semctl(0, 0, SEM_INFO, &sinfo)) < 0) {
		log_sys_error("sem_ctl", "SEM_INFO");
		return 0;
	}

	printf("Cookie       Semid      Value      Last semop time           Last change time\n");

	for (id = 0; id <= max_id; id++) {
		if ((sid = semctl(id, 0, SEM_STAT, &sdata)) < 0)
			continue;

		if (sdata.sem_perm.__key >> 16 == DM_COOKIE_MAGIC) {
			if ((val = semctl(sid, 0, GETVAL)) < 0) {
				log_error("semid %d: sem_ctl failed for "
					  "cookie 0x%" PRIx32 ": %s",
					  sid, sdata.sem_perm.__key,
					  strerror(errno));
				continue;
			}

			if ((otimes = ctime_r((const time_t *) &sdata.sem_otime, (char *)&otime_str)))
				otime_str[strlen(otimes)-1] = '\0';
			if ((ctimes = ctime_r((const time_t *) &sdata.sem_ctime, (char *)&ctime_str)))
				ctime_str[strlen(ctimes)-1] = '\0';

			printf("0x%-10x %-10d %-10d %s  %s\n", sdata.sem_perm.__key,
				sid, val, otimes ? : "unknown",
				ctimes? : "unknown");
		}
	}

	return 1;
}
#endif	/* UDEV_SYNC_SUPPORT */

static int _version(CMD_ARGS)
{
	char version[80];

	if (dm_get_library_version(version, sizeof(version)))
		printf("Library version:   %s\n", version);

	if (!dm_driver_version(version, sizeof(version)))
		return_0;

	printf("Driver version:    %s\n", version);

	/* don't output column headings for 'dmstats version'. */
	if (_report) {
		dm_report_free(_report);
		_report = NULL;
	}

	return 1;
}

static int _simple(int task, const char *name, uint32_t event_nr, int display)
{
	uint32_t cookie = 0;
	uint16_t udev_flags = 0;
	int udev_wait_flag = task == DM_DEVICE_RESUME ||
			     task == DM_DEVICE_REMOVE;
	int r = 0;

	struct dm_task *dmt;

	if (!(dmt = dm_task_create(task)))
		return_0;

	if (!_set_task_device(dmt, name, 0))
		goto_out;

	if (event_nr && !dm_task_set_event_nr(dmt, event_nr))
		goto_out;

	if (_switches[NOFLUSH_ARG] && !dm_task_no_flush(dmt))
		goto_out;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_out;

	if (_switches[NOLOCKFS_ARG] && !dm_task_skip_lockfs(dmt))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	/* FIXME: needs to coperate with udev */
	if (!_set_task_add_node(dmt))
		goto_out;

	if (_switches[READAHEAD_ARG] &&
	    !dm_task_set_read_ahead(dmt, _int_args[READAHEAD_ARG],
				    _read_ahead_flags))
		goto_out;

	if (_switches[NOUDEVRULES_ARG])
		udev_flags |= DM_UDEV_DISABLE_DM_RULES_FLAG |
			      DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG;

	if (_udev_cookie)
		cookie = _udev_cookie;

	if (_udev_only)
		udev_flags |= DM_UDEV_DISABLE_LIBRARY_FALLBACK;

	if (udev_wait_flag && !dm_task_set_cookie(dmt, &cookie, udev_flags))
		goto_out;

	if (_switches[RETRY_ARG] && task == DM_DEVICE_REMOVE)
		dm_task_retry_remove(dmt);

	if (_switches[DEFERRED_ARG] && (task == DM_DEVICE_REMOVE || task == DM_DEVICE_REMOVE_ALL))
		dm_task_deferred_remove(dmt);

	r = _task_run(dmt);

out:
	if (!_udev_cookie && udev_wait_flag)
		(void) dm_udev_wait(cookie);

	if (r && display && _switches[VERBOSE_ARG])
		r = _display_info(dmt);

	dm_task_destroy(dmt);

	return r;
}

static int _suspend(CMD_ARGS)
{
	return _simple(DM_DEVICE_SUSPEND, argc ? argv[0] : NULL, 0, 1);
}

static int _resume(CMD_ARGS)
{
	return _simple(DM_DEVICE_RESUME, argc ? argv[0] : NULL, 0, 1);
}

static int _clear(CMD_ARGS)
{
	return _simple(DM_DEVICE_CLEAR, argc ? argv[0] : NULL, 0, 1);
}

static int _wait(CMD_ARGS)
{
	const char *name = NULL;

	if (!_switches[UUID_ARG] && !_switches[MAJOR_ARG]) {
		if (!argc) {
			err("No device specified.");
			return 0;
		}
		name = argv[0];
		argc--, argv++;
	}

	return _simple(DM_DEVICE_WAITEVENT, name,
		       (argc) ? (uint32_t) atoi(argv[argc - 1]) : 0, 1);
}

static int _process_all(const struct command *cmd, const char *subcommand, int argc, char **argv, int silent,
			int (*fn) (CMD_ARGS))
{
	int r = 1;
	struct dm_names *names;
	unsigned next = 0;

	struct dm_task *dmt;

	if (!(dmt = dm_task_create(DM_DEVICE_LIST)))
		return_0;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_task_run(dmt)) {
		r = 0;
		goto_out;
	}

	if (!(names = dm_task_get_names(dmt))) {
		r = 0;
		goto_out;
	}

	if (!names->dev) {
		if (!silent)
			printf("No devices found\n");
		goto out;
	}

	do {
		names = (struct dm_names *)((char *) names + next);
		if (!fn(cmd, subcommand, argc, argv, names, 1))
			r = 0;
		next = names->next;
	} while (next);

out:
	dm_task_destroy(dmt);
	return r;
}

static uint64_t _get_device_size(const char *name)
{
	uint64_t start, length, size = UINT64_C(0);
	struct dm_info info;
	char *target_type, *params;
	struct dm_task *dmt;
	void *next = NULL;

	if (!(dmt = dm_task_create(DM_DEVICE_TABLE)))
		return_0;

	if (!_set_task_device(dmt, name, 0))
		goto_out;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_task_run(dmt))
		goto_out;

	if (!dm_task_get_info(dmt, &info) || !info.exists)
		goto_out;

	do {
		next = dm_get_next_target(dmt, next, &start, &length,
					  &target_type, &params);
		size += length;
	} while (next);

out:
	dm_task_destroy(dmt);
	return size;
}

static int _error_device(CMD_ARGS)
{
	struct dm_task *dmt;
	const char *name;
	uint64_t size;
	int r = 0;

	name = names ? names->name : argv[0];

	size = _get_device_size(name);

	if (!(dmt = dm_task_create(DM_DEVICE_RELOAD)))
		return_0;

	if (!_set_task_device(dmt, name, 0))
		goto_bad;

	if (!dm_task_add_target(dmt, UINT64_C(0), size, "error", ""))
		goto_bad;

	if (_switches[READ_ONLY] && !dm_task_set_ro(dmt))
		goto_bad;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_bad;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_bad;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_bad;

	if (!_task_run(dmt))
		goto_bad;

	if (!_simple(DM_DEVICE_RESUME, name, 0, 0)) {
		_simple(DM_DEVICE_CLEAR, name, 0, 0);
		goto_bad;
	}

	r = 1;

bad:
	dm_task_destroy(dmt);
	return r;
}

static int _remove(CMD_ARGS)
{
	if (_switches[FORCE_ARG] && argc) {
		/*
		 * 'remove --force' option is doing 2 operations on the same device
		 * this is not compatible with the use of --udevcookie/DM_UDEV_COOKIE.
		 * Udevd collision could be partially avoided with --retry.
		 */
		if (_udev_cookie)
			log_warn("WARNING: Use of cookie and --force is not compatible.");
		(void) _error_device(cmd, NULL, argc, argv, NULL, 0);
	}

	return _simple(DM_DEVICE_REMOVE, argc ? argv[0] : NULL, 0, 0);
}

static int _count_devices(CMD_ARGS)
{
	_num_devices++;

	return 1;
}

static int _remove_all(CMD_ARGS)
{
	int r;

	/* Remove all closed devices */
	r =  _simple(DM_DEVICE_REMOVE_ALL, "", 0, 0) | dm_mknodes(NULL);

	if (!_switches[FORCE_ARG])
		return r;

	_num_devices = 0;
	r |= _process_all(cmd, NULL, argc, argv, 1, _count_devices);

	/* No devices left? */
	if (!_num_devices)
		return r;

	r |= _process_all(cmd, NULL, argc, argv, 1, _error_device);
	r |= _simple(DM_DEVICE_REMOVE_ALL, "", 0, 0) | dm_mknodes(NULL);

	_num_devices = 0;
	r |= _process_all(cmd, NULL, argc, argv, 1, _count_devices);
	if (!_num_devices)
		return r;

	fprintf(stderr, "Unable to remove %d device(s).\n", _num_devices);

	return r;
}

static void _display_dev(struct dm_task *dmt, const char *name)
{
	struct dm_info info;

	if (dm_task_get_info(dmt, &info))
		printf("%s\t(%u, %u)\n", name, info.major, info.minor);
}

static int _mknodes(CMD_ARGS)
{
	return dm_mknodes(argc ? argv[0] : NULL);
}

static int _exec_command(const char *name)
{
	int n;
	static char path[PATH_MAX];
	static char *args[ARGS_MAX + 1];
	static int argc = 0;
	char *c;
	pid_t pid;

	if (argc < 0)
		return_0;

	if (!dm_mknodes(name))
		return_0;

	n = snprintf(path, sizeof(path), "%s/%s", dm_dir(), name);
	if (n < 0 || n > (int) sizeof(path) - 1)
		return_0;

	if (!argc) {
		c = _command_to_exec;
		while (argc < ARGS_MAX) {
			while (*c && isspace(*c))
				c++;
			if (!*c)
				break;
			args[argc++] = c;
			while (*c && !isspace(*c))
				c++;
			if (*c)
				*c++ = '\0';
		}

		if (!argc) {
			argc = -1;
			return_0;
		}

		if (argc == ARGS_MAX) {
			err("Too many args to --exec\n");
			argc = -1;
			return 0;
		}

		args[argc++] = path;
		args[argc] = NULL;
	}

	if (!(pid = fork())) {
		execvp(args[0], args);
		_exit(127);
	} else if (pid < (pid_t) 0)
		return 0;

	TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0));

	return 1;
}

static int _status(CMD_ARGS)
{
	int r = 0;
	struct dm_task *dmt;
	void *next = NULL;
	uint64_t start, length;
	char *target_type = NULL;
	char *params, *c;
	int cmdno;
	const char *name = NULL;
	int matched = 0;
	int ls_only = 0;
	struct dm_info info;

	if (names)
		name = names->name;
	else {
		if (!argc && !_switches[UUID_ARG] && !_switches[MAJOR_ARG])
			return _process_all(cmd, NULL, argc, argv, 0, _status);
		name = argv[0];
	}

	if (!strcmp(cmd->name, "table"))
		cmdno = DM_DEVICE_TABLE;
	else
		cmdno = DM_DEVICE_STATUS;

	if (!strcmp(cmd->name, "ls"))
		ls_only = 1;

	if (!(dmt = dm_task_create(cmdno)))
		return_0;

	if (!_set_task_device(dmt, name, 0))
		goto_out;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (_switches[NOFLUSH_ARG] && !dm_task_no_flush(dmt))
		goto_out;

	if (!_task_run(dmt))
		goto_out;

	if (!dm_task_get_info(dmt, &info) || !info.exists)
		goto_out;

	if (!name)
		name = dm_task_get_name(dmt);

	/* Fetch targets and print 'em */
	do {
		next = dm_get_next_target(dmt, next, &start, &length,
					  &target_type, &params);
		/* Skip if target type doesn't match */
		if (_switches[TARGET_ARG] &&
		    (!target_type || strcmp(target_type, _target)))
			continue;
		if (ls_only) {
			if (!_switches[EXEC_ARG] || !_command_to_exec ||
			    _switches[VERBOSE_ARG])
				_display_dev(dmt, name);
			next = NULL;
		} else if (!_switches[EXEC_ARG] || !_command_to_exec ||
			   _switches[VERBOSE_ARG]) {
			if (!matched && _switches[VERBOSE_ARG])
				_display_info(dmt);
			if (multiple_devices && !_switches[VERBOSE_ARG])
				printf("%s: ", name);
			if (target_type) {
				/* Suppress encryption key */
				if (!_switches[SHOWKEYS_ARG] &&
				    cmdno == DM_DEVICE_TABLE &&
				    !strcmp(target_type, "crypt")) {
					c = params;
					while (*c && *c != ' ')
						c++;
					if (*c)
						c++;
					while (*c && *c != ' ')
						*c++ = '0';
				}
				printf(FMTu64 " " FMTu64 " %s %s",
				       start, length, target_type, params);
			}
			printf("\n");
		}
		matched = 1;
	} while (next);

	if (multiple_devices && _switches[VERBOSE_ARG] && matched && !ls_only)
		printf("\n");

	if (matched && _switches[EXEC_ARG] && _command_to_exec && !_exec_command(name))
		goto_out;

	r = 1;

out:
	dm_task_destroy(dmt);
	return r;
}

/* Show target names and their version numbers */
static int _targets(CMD_ARGS)
{
	int r = 0;
	struct dm_task *dmt;
	struct dm_versions *target;
	struct dm_versions *last_target;

	if (!(dmt = dm_task_create(DM_DEVICE_LIST_VERSIONS)))
		return_0;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_task_run(dmt))
		goto_out;

	target = dm_task_get_versions(dmt);

	/* Fetch targets and print 'em */
	do {
		last_target = target;

		printf("%-16s v%d.%d.%d\n", target->name, target->version[0],
		       target->version[1], target->version[2]);

		target = (struct dm_versions *)((char *) target + target->next);
	} while (last_target != target);

	r = 1;

out:
	dm_task_destroy(dmt);
	return r;
}

static int _info(CMD_ARGS)
{
	int r = 0;

	struct dm_task *dmt;
	char *name = NULL;

	if (names)
		name = names->name;
	else {
		if (!argc && !_switches[UUID_ARG] && !_switches[MAJOR_ARG])
			return _process_all(cmd, NULL, argc, argv, 0, _info);
		name = argv[0];
	}

	if (!(dmt = dm_task_create(DM_DEVICE_INFO)))
		return_0;

	if (!_set_task_device(dmt, name, 0))
		goto_out;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_task_run(dmt))
		goto_out;

	r = _display_info(dmt);

out:
	dm_task_destroy(dmt);
	return r;
}

static int _deps(CMD_ARGS)
{
	int r = 0;
	uint32_t i;
	struct dm_deps *deps;
	struct dm_task *dmt;
	struct dm_info info;
	char *name = NULL;
	char dev_name[PATH_MAX];
	int major, minor;

	if (names)
		name = names->name;
	else {
		if (!argc && !_switches[UUID_ARG] && !_switches[MAJOR_ARG])
			return _process_all(cmd, NULL, argc, argv, 0, _deps);
		name = argv[0];
	}

	if (!(dmt = dm_task_create(DM_DEVICE_DEPS)))
		return_0;

	if (!_set_task_device(dmt, name, 0))
		goto_out;

	if (_switches[NOOPENCOUNT_ARG] && !dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[INACTIVE_ARG] && !dm_task_query_inactive_table(dmt))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_task_run(dmt))
		goto_out;

	if (!dm_task_get_info(dmt, &info))
		goto_out;

	if (!(deps = dm_task_get_deps(dmt)))
		goto_out;

	if (!info.exists) {
		printf("Device does not exist.\n");
		r = 1;
		goto out;
	}

	if (_switches[VERBOSE_ARG])
		_display_info(dmt);

	if (multiple_devices && !_switches[VERBOSE_ARG])
		printf("%s: ", name);
	printf("%d dependencies\t:", deps->count);

	for (i = 0; i < deps->count; i++) {
		major = (int) MAJOR(deps->device[i]);
		minor = (int) MINOR(deps->device[i]);

		if ((_dev_name_type == DN_BLK || _dev_name_type == DN_MAP) &&
		    dm_device_get_name(major, minor, _dev_name_type == DN_BLK,
				       dev_name, PATH_MAX))
			printf(" (%s)", dev_name);
		else
			printf(" (%d, %d)", major, minor);
	}
	printf("\n");

	if (multiple_devices && _switches[VERBOSE_ARG])
		printf("\n");

	r = 1;

out:
	dm_task_destroy(dmt);
	return r;
}

static int _display_name(CMD_ARGS)
{
	char dev_name[PATH_MAX];

	if (!names)
		return 1;

	if ((_dev_name_type == DN_BLK || _dev_name_type == DN_MAP) &&
	    dm_device_get_name((int) MAJOR(names->dev), (int) MINOR(names->dev),
			       _dev_name_type == DN_BLK, dev_name, PATH_MAX))
		printf("%s\t(%s)\n", names->name, dev_name);
	else
		printf("%s\t(%d:%d)\n", names->name,
					(int) MAJOR(names->dev),
					(int) MINOR(names->dev));

	return 1;
}

/*
 * Tree drawing code
 */

enum {
	TR_DEVICE=0,	/* display device major:minor number */
	TR_BLKDEVNAME,	/* display device kernel name */
	TR_TABLE,
	TR_STATUS,
	TR_ACTIVE,
	TR_RW,
	TR_OPENCOUNT,
	TR_UUID,
	TR_COMPACT,
	TR_TRUNCATE,
	TR_BOTTOMUP,
	NUM_TREEMODE,
};

static int _tree_switches[NUM_TREEMODE];

#define TR_PRINT_ATTRIBUTE ( _tree_switches[TR_ACTIVE] || \
			     _tree_switches[TR_RW] || \
			     _tree_switches[TR_OPENCOUNT] || \
			     _tree_switches[TR_UUID] )

#define TR_PRINT_TARGETS ( _tree_switches[TR_TABLE] || \
			   _tree_switches[TR_STATUS] )

/* Compact - fewer newlines */
#define TR_PRINT_COMPACT (_tree_switches[TR_COMPACT] && \
			  !TR_PRINT_ATTRIBUTE && \
			  !TR_PRINT_TARGETS)

/* FIXME Get rid of this */
#define MAX_DEPTH 100

/* Drawing character definition from pstree */
/* [pstree comment] UTF-8 defines by Johan Myreen, updated by Ben Winslow */
#define UTF_V	"\342\224\202"	/* U+2502, Vertical line drawing char */
#define UTF_VR	"\342\224\234"	/* U+251C, Vertical and right */
#define UTF_H	"\342\224\200"	/* U+2500, Horizontal */
#define UTF_UR	"\342\224\224"	/* U+2514, Up and right */
#define UTF_HD	"\342\224\254"	/* U+252C, Horizontal and down */

#define VT_BEG	"\033(0\017"	/* use graphic chars */
#define VT_END	"\033(B"	/* back to normal char set */
#define VT_V	"x"		/* see UTF definitions above */
#define VT_VR	"t"
#define VT_H	"q"
#define VT_UR	"m"
#define VT_HD	"w"

static struct {
	const char *empty_2;	/*    */
	const char *branch_2;	/* |- */
	const char *vert_2;	/* |  */
	const char *last_2;	/* `- */
	const char *single_3;	/* --- */
	const char *first_3;	/* -+- */
}
_tsym_ascii = {
	"  ",
	"|-",
	"| ",
	"`-",
	"---",
	"-+-"
},
_tsym_utf = {
	"  ",
	UTF_VR UTF_H,
	UTF_V " ",
	UTF_UR UTF_H,
	UTF_H UTF_H UTF_H,
	UTF_H UTF_HD UTF_H
},
_tsym_vt100 = {
	"  ",
	VT_BEG VT_VR VT_H VT_END,
	VT_BEG VT_V VT_END " ",
	VT_BEG VT_UR VT_H VT_END,
	VT_BEG VT_H VT_H VT_H VT_END,
	VT_BEG VT_H VT_HD VT_H VT_END
},
*_tsym = &_tsym_ascii;

/*
 * Tree drawing functions.
 */
/* FIXME Get rid of these statics - use dynamic struct */
/* FIXME Explain what these vars are for */
static int _tree_width[MAX_DEPTH], _tree_more[MAX_DEPTH];
static int _termwidth = 80;	/* Maximum output width */
static int _cur_x = 1;		/* Current horizontal output position */
static char _last_char = 0;

static void _out_char(const unsigned c)
{
	/* Only first UTF-8 char counts */
	_cur_x += ((c & 0xc0) != 0x80);

	if (!_tree_switches[TR_TRUNCATE]) {
		putchar((int) c);
		return;
	}

	/* Truncation? */
	if (_cur_x <= _termwidth)
		putchar((int) c);

	if (_cur_x == _termwidth + 1 && ((c & 0xc0) != 0x80)) {
		if (_last_char || (c & 0x80)) {
			putchar('.');
			putchar('.');
			putchar('.');
		} else {
			_last_char = c;
			_cur_x--;
		}
	}
}

static void _out_string(const char *str)
{
	while (*str)
		_out_char((unsigned char) *str++);
}

/* non-negative integers only */
static unsigned _out_int(unsigned num)
{
	unsigned digits = 0;
	unsigned divi;

	if (!num) {
		_out_char('0');
		return 1;
	}

	/* non zero case */
	for (divi = 1; num / divi; divi *= 10)
		digits++;

	for (divi /= 10; divi; divi /= 10)
		_out_char('0' + (num / divi) % 10);

	return digits;
}

static void _out_newline(void)
{
	if (_last_char && _cur_x == _termwidth)
		putchar(_last_char);
	_last_char = 0;
	putchar('\n');
	_cur_x = 1;
}

static void _out_prefix(unsigned depth)
{
	unsigned x, d;

	for (d = 0; d < depth; d++) {
		for (x = _tree_width[d] + 1; x > 0; x--)
			_out_char(' ');

		_out_string(d == depth - 1 ?
				!_tree_more[depth] ? _tsym->last_2 : _tsym->branch_2
			   : _tree_more[d + 1] ?
				_tsym->vert_2 : _tsym->empty_2);
	}
}

/*
 * Display tree
 */
static void _display_tree_attributes(struct dm_tree_node *node)
{
	int attr = 0;
	const char *uuid;
	const struct dm_info *info;

	uuid = dm_tree_node_get_uuid(node);
	info = dm_tree_node_get_info(node);

	if (!info->exists)
		return;

	if (_tree_switches[TR_ACTIVE]) {
		_out_string(attr++ ? ", " : " [");
		_out_string(info->suspended ? "SUSPENDED" : "ACTIVE");
	}

	if (_tree_switches[TR_RW]) {
		_out_string(attr++ ? ", " : " [");
		_out_string(info->read_only ? "RO" : "RW");
	}

	if (_tree_switches[TR_OPENCOUNT]) {
		_out_string(attr++ ? ", " : " [");
		(void) _out_int((unsigned) info->open_count);
	}

	if (_tree_switches[TR_UUID]) {
		_out_string(attr++ ? ", " : " [");
		_out_string(uuid && *uuid ? uuid : "");
	}

	if (attr)
		_out_char(']');
}

/* FIXME Display table or status line. (Disallow both?) */
static void _display_tree_targets(struct dm_tree_node *node, unsigned depth)
{
}

static void _display_tree_node(struct dm_tree_node *node, unsigned depth,
			       unsigned first_child __attribute__((unused)),
			       unsigned last_child, unsigned has_children)
{
	int offset;
	const char *name;
	const struct dm_info *info;
	int first_on_line = 0;
	char dev_name[PATH_MAX];

	/* Sub-tree for targets has 2 more depth */
	if (depth + 2 > MAX_DEPTH)
		return;

	name = dm_tree_node_get_name(node);

	if ((!name || !*name) &&
	    (!_tree_switches[TR_DEVICE] && !_tree_switches[TR_BLKDEVNAME]))
		return;

	/* Indicate whether there are more nodes at this depth */
	_tree_more[depth] = !last_child;
	_tree_width[depth] = 0;

	if (_cur_x == 1)
		first_on_line = 1;

	if (!TR_PRINT_COMPACT || first_on_line)
		_out_prefix(depth);

	/* Remember the starting point for compact */
	offset = _cur_x;

	if (TR_PRINT_COMPACT && !first_on_line)
		_out_string(_tree_more[depth] ? _tsym->first_3 : _tsym->single_3);

	/* display node */
	if (name)
		_out_string(name);

	info = dm_tree_node_get_info(node);

	if (_tree_switches[TR_BLKDEVNAME] &&
	    dm_device_get_name(info->major, info->minor, 1, dev_name, PATH_MAX)) {
		_out_string(name ? " <" : "<");
		_out_string(dev_name);
		_out_char('>');
	}

	if (_tree_switches[TR_DEVICE]) {
		_out_string(name ? " (" : "(");
		(void) _out_int(info->major);
		_out_char(':');
		(void) _out_int(info->minor);
		_out_char(')');
	}

	/* display additional info */
	if (TR_PRINT_ATTRIBUTE)
		_display_tree_attributes(node);

	if (TR_PRINT_COMPACT)
		_tree_width[depth] = _cur_x - offset;

	if (!TR_PRINT_COMPACT || !has_children)
		_out_newline();

	if (TR_PRINT_TARGETS) {
		_tree_more[depth + 1] = has_children;
		_display_tree_targets(node, depth + 2);
	}
}

/*
 * Walk the dependency tree
 */
static void _display_tree_walk_children(struct dm_tree_node *node,
					unsigned depth)
{
	struct dm_tree_node *child, *next_child;
	void *handle = NULL;
	uint32_t inverted = _tree_switches[TR_BOTTOMUP];
	unsigned first_child = 1;
	unsigned has_children;

	next_child = dm_tree_next_child(&handle, node, inverted);

	while ((child = next_child)) {
		next_child = dm_tree_next_child(&handle, node, inverted);
		has_children =
		    dm_tree_node_num_children(child, inverted) ? 1 : 0;

		_display_tree_node(child, depth, first_child,
				   next_child ? 0U : 1U, has_children);

		if (has_children)
			_display_tree_walk_children(child, depth + 1);

		first_child = 0;
	}
}

static int _add_dep(CMD_ARGS)
{
	if (names &&
	    !dm_tree_add_dev(_dtree, (unsigned) MAJOR(names->dev), (unsigned) MINOR(names->dev)))
		return_0;

	return 1;
}

/*
 * Create and walk dependency tree
 */
static int _build_whole_deptree(const struct command *cmd)
{
	if (_dtree)
		return 1;

	if (!(_dtree = dm_tree_create()))
		return_0;

	if (!_process_all(cmd, NULL, 0, NULL, 0, _add_dep))
		return_0;

	return 1;
}

static int _display_tree(CMD_ARGS)
{
	if (!_build_whole_deptree(cmd))
		return_0;

	_display_tree_walk_children(dm_tree_find_node(_dtree, 0, 0), 0);

	return 1;
}

/*
 * Report device information
 */

/* dm specific display functions */

static int _int32_disp(struct dm_report *rh,
		       struct dm_pool *mem __attribute__((unused)),
		       struct dm_report_field *field, const void *data,
		       void *private __attribute__((unused)))
{
	const int32_t value = *(const int32_t *)data;

	return dm_report_field_int32(rh, field, &value);
}

static int _uint32_disp(struct dm_report *rh,
			struct dm_pool *mem __attribute__((unused)),
			struct dm_report_field *field, const void *data,
			void *private __attribute__((unused)))
{
	const uint32_t value = *(const int32_t *)data;

	return dm_report_field_uint32(rh, field, &value);
}

static int _show_units(void)
{
	/* --nosuffix overrides --units */
	if (_switches[NOSUFFIX_ARG])
		return_0;

	return (_int_args[UNITS_ARG]) ? 1 : 0;
}

static int _dm_name_disp(struct dm_report *rh,
			 struct dm_pool *mem __attribute__((unused)),
			 struct dm_report_field *field, const void *data,
			 void *private __attribute__((unused)))
{
	const char *name = dm_task_get_name((const struct dm_task *) data);

	return dm_report_field_string(rh, field, &name);
}

static int _dm_mangled_name_disp(struct dm_report *rh,
				 struct dm_pool *mem __attribute__((unused)),
				 struct dm_report_field *field, const void *data,
				 void *private __attribute__((unused)))
{
	char *name;
	int r = 0;

	if ((name = dm_task_get_name_mangled((const struct dm_task *) data))) {
		r = dm_report_field_string(rh, field, (const char * const *) &name);
		dm_free(name);
	}

	return r;
}

static int _dm_unmangled_name_disp(struct dm_report *rh,
				   struct dm_pool *mem __attribute__((unused)),
				   struct dm_report_field *field, const void *data,
				   void *private __attribute__((unused)))
{
	char *name;
	int r = 0;

	if ((name = dm_task_get_name_unmangled((const struct dm_task *) data))) {
		r = dm_report_field_string(rh, field, (const char * const *) &name);
		dm_free(name);
	}

	return r;
}

static int _dm_uuid_disp(struct dm_report *rh,
			 struct dm_pool *mem __attribute__((unused)),
			 struct dm_report_field *field,
			 const void *data, void *private __attribute__((unused)))
{
	const char *uuid = dm_task_get_uuid((const struct dm_task *) data);

	if (!uuid || !*uuid)
		uuid = "";

	return dm_report_field_string(rh, field, &uuid);
}

static int _dm_mangled_uuid_disp(struct dm_report *rh,
				 struct dm_pool *mem __attribute__((unused)),
				 struct dm_report_field *field,
				 const void *data, void *private __attribute__((unused)))
{
	char *uuid;
	int r = 0;

	if ((uuid = dm_task_get_uuid_mangled((const struct dm_task *) data))) {
		r = dm_report_field_string(rh, field, (const char * const *) &uuid);
		dm_free(uuid);
	}

	return r;
}

static int _dm_unmangled_uuid_disp(struct dm_report *rh,
				   struct dm_pool *mem __attribute__((unused)),
				   struct dm_report_field *field,
				   const void *data, void *private __attribute__((unused)))
{
	char *uuid;
	int r = 0;

	if ((uuid = dm_task_get_uuid_unmangled((const struct dm_task *) data))) {
		r = dm_report_field_string(rh, field, (const char * const *) &uuid);
		dm_free(uuid);
	}

	return r;
}

static int _dm_read_ahead_disp(struct dm_report *rh,
			       struct dm_pool *mem __attribute__((unused)),
			       struct dm_report_field *field, const void *data,
			       void *private __attribute__((unused)))
{
	uint32_t value;

	if (!dm_task_get_read_ahead((const struct dm_task *) data, &value))
		value = 0;

	return dm_report_field_uint32(rh, field, &value);
}

static int _dm_blk_name_disp(struct dm_report *rh,
			     struct dm_pool *mem __attribute__((unused)),
			     struct dm_report_field *field, const void *data,
			     void *private __attribute__((unused)))
{
	char dev_name[PATH_MAX];
	const char *s = dev_name;
	const struct dm_info *info = data;

	if (!dm_device_get_name(info->major, info->minor, 1, dev_name, PATH_MAX)) {
		log_error("Could not resolve block device name for %d:%d.",
			  info->major, info->minor);
		return 0;
	}

	return dm_report_field_string(rh, field, &s);
}

static int _dm_info_status_disp(struct dm_report *rh,
				struct dm_pool *mem __attribute__((unused)),
				struct dm_report_field *field, const void *data,
				void *private __attribute__((unused)))
{
	char buf[5];
	const char *s = buf;
	const struct dm_info *info = data;

	buf[0] = info->live_table ? 'L' : '-';
	buf[1] = info->inactive_table ? 'I' : '-';
	buf[2] = info->suspended ? 's' : '-';
	buf[3] = info->read_only ? 'r' : 'w';
	buf[4] = '\0';

	return dm_report_field_string(rh, field, &s);
}

static int _dm_info_table_loaded_disp(struct dm_report *rh,
				      struct dm_pool *mem __attribute__((unused)),
				      struct dm_report_field *field,
				      const void *data,
				      void *private __attribute__((unused)))
{
	const struct dm_info *info = data;

	if (info->live_table) {
		if (info->inactive_table)
			dm_report_field_set_value(field, "Both", NULL);
		else
			dm_report_field_set_value(field, "Live", NULL);
		return 1;
	}

	if (info->inactive_table)
		dm_report_field_set_value(field, "Inactive", NULL);
	else
		dm_report_field_set_value(field, "None", NULL);

	return 1;
}

static int _dm_info_suspended_disp(struct dm_report *rh,
				   struct dm_pool *mem __attribute__((unused)),
				   struct dm_report_field *field,
				   const void *data,
				   void *private __attribute__((unused)))
{
	const struct dm_info *info = data;

	if (info->suspended)
		dm_report_field_set_value(field, "Suspended", NULL);
	else
		dm_report_field_set_value(field, "Active", NULL);

	return 1;
}

static int _dm_info_read_only_disp(struct dm_report *rh,
				   struct dm_pool *mem __attribute__((unused)),
				   struct dm_report_field *field,
				   const void *data,
				   void *private __attribute__((unused)))
{
	const struct dm_info *info = data;

	if (info->read_only)
		dm_report_field_set_value(field, "Read-only", NULL);
	else
		dm_report_field_set_value(field, "Writeable", NULL);

	return 1;
}


static int _dm_info_devno_disp(struct dm_report *rh, struct dm_pool *mem,
			       struct dm_report_field *field, const void *data,
			       void *private)
{
	char buf[PATH_MAX], *repstr;
	const struct dm_info *info = data;

	if (!dm_pool_begin_object(mem, 8)) {
		log_error("dm_pool_begin_object failed");
		return 0;
	}

	if (private) {
		if (!dm_device_get_name(info->major, info->minor,
					1, buf, PATH_MAX)) {
			stack;
			goto out_abandon;
		}
	}
	else {
		if (dm_snprintf(buf, sizeof(buf), "%d:%d",
				info->major, info->minor) < 0) {
			log_error("dm_pool_alloc failed");
			goto out_abandon;
		}
	}

	if (!dm_pool_grow_object(mem, buf, strlen(buf) + 1)) {
		log_error("dm_pool_grow_object failed");
		goto out_abandon;
	}

	repstr = dm_pool_end_object(mem);
	dm_report_field_set_value(field, repstr, repstr);
	return 1;

      out_abandon:
	dm_pool_abandon_object(mem);
	return 0;
}

static int _dm_tree_names(struct dm_report *rh, struct dm_pool *mem,
			  struct dm_report_field *field, const void *data,
			  void *private, unsigned inverted)
{
	const struct dm_tree_node *node = data;
	struct dm_tree_node *parent;
	void *t = NULL;
	const char *name;
	int first_node = 1;
	char *repstr;

	if (!dm_pool_begin_object(mem, 16)) {
		log_error("dm_pool_begin_object failed");
		return 0;
	}

	while ((parent = dm_tree_next_child(&t, node, inverted))) {
		name = dm_tree_node_get_name(parent);
		if (!name || !*name)
			continue;
		if (!first_node && !dm_pool_grow_object(mem, ",", 1)) {
			log_error("dm_pool_grow_object failed");
			goto out_abandon;
		}
		if (!dm_pool_grow_object(mem, name, 0)) {
			log_error("dm_pool_grow_object failed");
			goto out_abandon;
		}
		if (first_node)
			first_node = 0;
	}

	if (!dm_pool_grow_object(mem, "\0", 1)) {
		log_error("dm_pool_grow_object failed");
		goto out_abandon;
	}

	repstr = dm_pool_end_object(mem);
	dm_report_field_set_value(field, repstr, repstr);
	return 1;

      out_abandon:
	dm_pool_abandon_object(mem);
	return 0;
}

static int _dm_deps_names_disp(struct dm_report *rh,
				      struct dm_pool *mem,
				      struct dm_report_field *field,
				      const void *data, void *private)
{
	return _dm_tree_names(rh, mem, field, data, private, 0);
}

static int _dm_tree_parents_names_disp(struct dm_report *rh,
				       struct dm_pool *mem,
				       struct dm_report_field *field,
				       const void *data, void *private)
{
	return _dm_tree_names(rh, mem, field, data, private, 1);
}

static int _dm_tree_parents_devs_disp(struct dm_report *rh, struct dm_pool *mem,
				      struct dm_report_field *field,
				      const void *data, void *private)
{
	const struct dm_tree_node *node = data;
	struct dm_tree_node *parent;
	void *t = NULL;
	const struct dm_info *info;
	int first_node = 1;
	char buf[DM_MAX_TYPE_NAME], *repstr;

	if (!dm_pool_begin_object(mem, 16)) {
		log_error("dm_pool_begin_object failed");
		return 0;
	}

	while ((parent = dm_tree_next_child(&t, node, 1))) {
		info = dm_tree_node_get_info(parent);
		if (!info->major && !info->minor)
			continue;
		if (!first_node && !dm_pool_grow_object(mem, ",", 1)) {
			log_error("dm_pool_grow_object failed");
			goto out_abandon;
		}
		if (dm_snprintf(buf, sizeof(buf), "%d:%d",
				info->major, info->minor) < 0) {
			log_error("dm_snprintf failed");
			goto out_abandon;
		}
		if (!dm_pool_grow_object(mem, buf, 0)) {
			log_error("dm_pool_grow_object failed");
			goto out_abandon;
		}
		if (first_node)
			first_node = 0;
	}

	if (!dm_pool_grow_object(mem, "\0", 1)) {
		log_error("dm_pool_grow_object failed");
		goto out_abandon;
	}

	repstr = dm_pool_end_object(mem);
	dm_report_field_set_value(field, repstr, repstr);
	return 1;

      out_abandon:
	dm_pool_abandon_object(mem);
	return 0;
}

static int _dm_tree_parents_count_disp(struct dm_report *rh,
				       struct dm_pool *mem,
				       struct dm_report_field *field,
				       const void *data, void *private)
{
	const struct dm_tree_node *node = data;
	int num_parent = dm_tree_node_num_children(node, 1);

	return dm_report_field_int(rh, field, &num_parent);
}

static int _dm_deps_disp_common(struct dm_report *rh, struct dm_pool*mem,
				struct dm_report_field *field, const void *data,
				void *private, int disp_blk_dev_names)
{
	const struct dm_deps *deps = data;
	char buf[PATH_MAX], *repstr;
	int major, minor;
	unsigned i;

	if (!dm_pool_begin_object(mem, 16)) {
		log_error("dm_pool_begin_object failed");
		return 0;
	}

	for (i = 0; i < deps->count; i++) {
		major = (int) MAJOR(deps->device[i]);
		minor = (int) MINOR(deps->device[i]);

		if (disp_blk_dev_names) {
			if (!dm_device_get_name(major, minor, 1, buf, PATH_MAX)) {
				log_error("Could not resolve block device "
					  "name for %d:%d.", major, minor);
				goto out_abandon;
			}
		}
		else if (dm_snprintf(buf, sizeof(buf), "%d:%d",
				     major, minor) < 0) {
			log_error("dm_snprintf failed");
			goto out_abandon;
		}

		if (!dm_pool_grow_object(mem, buf, 0)) {
			log_error("dm_pool_grow_object failed");
			goto out_abandon;
		}

		if (i + 1 < deps->count && !dm_pool_grow_object(mem, ",", 1)) {
			log_error("dm_pool_grow_object failed");
			goto out_abandon;
		}
	}

	if (!dm_pool_grow_object(mem, "\0", 1)) {
		log_error("dm_pool_grow_object failed");
		goto out_abandon;
	}

	repstr = dm_pool_end_object(mem);
	dm_report_field_set_value(field, repstr, repstr);
	return 1;

      out_abandon:
	dm_pool_abandon_object(mem);
	return 0;
}

static int _dm_deps_disp(struct dm_report *rh, struct dm_pool *mem,
			 struct dm_report_field *field, const void *data,
			 void *private)
{
	return _dm_deps_disp_common(rh, mem, field, data, private, 0);
}

static int _dm_deps_blk_names_disp(struct dm_report *rh, struct dm_pool *mem,
				   struct dm_report_field *field,
				   const void *data, void *private)
{
	return _dm_deps_disp_common(rh, mem, field, data, private, 1);
}

static int _dm_subsystem_disp(struct dm_report *rh,
			       struct dm_pool *mem __attribute__((unused)),
			       struct dm_report_field *field, const void *data,
			       void *private __attribute__((unused)))
{
	return dm_report_field_string(rh, field, (const char *const *) data);
}

static int _dm_vg_name_disp(struct dm_report *rh,
			     struct dm_pool *mem __attribute__((unused)),
			     struct dm_report_field *field, const void *data,
			     void *private __attribute__((unused)))
{

	return dm_report_field_string(rh, field, (const char *const *) data);
}

static int _dm_lv_name_disp(struct dm_report *rh,
			     struct dm_pool *mem __attribute__((unused)),
			     struct dm_report_field *field, const void *data,
			     void *private __attribute__((unused)))

{
	return dm_report_field_string(rh, field, (const char *const *) data);
}

static int _dm_lv_layer_name_disp(struct dm_report *rh,
				   struct dm_pool *mem __attribute__((unused)),
				   struct dm_report_field *field, const void *data,
				   void *private __attribute__((unused)))

{
	return dm_report_field_string(rh, field, (const char *const *) data);
}

/**
 * All _dm_stats_*_disp functions for basic counters are identical:
 * obtain the value for the current region and area and pass it to
 * dm_report_field_uint64().
 */
#define MK_STATS_COUNTER_DISP_FN(counter)					  \
static int _dm_stats_ ## counter ## _disp(struct dm_report *rh,			  \
				 struct dm_pool *mem __attribute__((unused)),	  \
				 struct dm_report_field *field, const void *data, \
				 void *private __attribute__((unused)))		  \
{										  \
	const struct dm_stats *dms = (const struct dm_stats *) data;		  \
	uint64_t value = dm_stats_get_ ## counter(dms, DM_STATS_REGION_CURRENT,   \
						  DM_STATS_AREA_CURRENT);         \
	return dm_report_field_uint64(rh, field, &value);			  \
}

MK_STATS_COUNTER_DISP_FN(reads)
MK_STATS_COUNTER_DISP_FN(reads_merged)
MK_STATS_COUNTER_DISP_FN(read_sectors)
MK_STATS_COUNTER_DISP_FN(read_nsecs)
MK_STATS_COUNTER_DISP_FN(writes)
MK_STATS_COUNTER_DISP_FN(writes_merged)
MK_STATS_COUNTER_DISP_FN(write_sectors)
MK_STATS_COUNTER_DISP_FN(write_nsecs)
MK_STATS_COUNTER_DISP_FN(io_in_progress)
MK_STATS_COUNTER_DISP_FN(io_nsecs)
MK_STATS_COUNTER_DISP_FN(weighted_io_nsecs)
MK_STATS_COUNTER_DISP_FN(total_read_nsecs)
MK_STATS_COUNTER_DISP_FN(total_write_nsecs)
#undef MK_STATS_COUNTER_DISP_FN

static int _dm_stats_region_id_disp(struct dm_report *rh,
				    struct dm_pool *mem __attribute__((unused)),
				    struct dm_report_field *field, const void *data,
				    void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	uint64_t region_id = dm_stats_get_current_region(dms);
	return dm_report_field_uint64(rh, field, &region_id);
}

static int _dm_stats_region_start_disp(struct dm_report *rh,
				       struct dm_pool *mem __attribute__((unused)),
				       struct dm_report_field *field, const void *data,
				       void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	uint64_t region_start;
	const char *repstr;
	double *sortval;
	char units = _disp_units;
	uint64_t factor = _disp_factor;

	if (!dm_stats_get_current_region_start(dms, &region_start))
		return_0;

	if (!(repstr = dm_size_to_string(mem, region_start, units, 1, factor,
					 _show_units(), DM_SIZE_UNIT)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = (double) region_start;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_region_len_disp(struct dm_report *rh,
					struct dm_pool *mem __attribute__((unused)),
					struct dm_report_field *field, const void *data,
					void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	uint64_t region_length;
	const char *repstr;
	double *sortval;
	char units = _disp_units;
	uint64_t factor = _disp_factor;

	if (!dm_stats_get_current_region_len(dms, &region_length))
		return_0;

	if (!(repstr = dm_size_to_string(mem, region_length, units, 1, factor,
					 _show_units(), DM_SIZE_UNIT)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = (double) region_length;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_area_id_disp(struct dm_report *rh,
				  struct dm_pool *mem __attribute__((unused)),
				  struct dm_report_field *field, const void *data,
				  void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	uint64_t area_id = dm_stats_get_current_area(dms);
	return dm_report_field_uint64(rh, field, &area_id);
}

static int _dm_stats_area_start_disp(struct dm_report *rh,
				     struct dm_pool *mem __attribute__((unused)),
				     struct dm_report_field *field, const void *data,
				     void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	uint64_t area_start;
	const char *repstr;
	double *sortval;
	char units = _disp_units;
	uint64_t factor = _disp_factor;

	if (!dm_stats_get_current_area_start(dms, &area_start))
		return_0;

	if (!(repstr = dm_size_to_string(mem, area_start, units, 1, factor,
					 _show_units(), DM_SIZE_UNIT)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = (double) area_start;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_area_offset_disp(struct dm_report *rh,
				      struct dm_pool *mem __attribute__((unused)),
				      struct dm_report_field *field, const void *data,
				      void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	uint64_t area_offset;
	const char *repstr;
	double *sortval;
	char units = _disp_units;
	uint64_t factor = _disp_factor;

	if (!dm_stats_get_current_area_offset(dms, &area_offset))
		return_0;

	if (!(repstr = dm_size_to_string(mem, area_offset, units, 1, factor,
					 _show_units(), DM_SIZE_UNIT)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = (double) area_offset;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_area_len_disp(struct dm_report *rh,
				      struct dm_pool *mem __attribute__((unused)),
				      struct dm_report_field *field, const void *data,
				      void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	uint64_t area_len;
	const char *repstr;
	double *sortval;
	char units = _disp_units;
	uint64_t factor = _disp_factor;

	if (!dm_stats_get_current_area_len(dms, &area_len))
		return_0;

	if (!(repstr = dm_size_to_string(mem, area_len, units, 1, factor,
					 _show_units(), DM_SIZE_UNIT)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = (double) area_len;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_area_count_disp(struct dm_report *rh,
				     struct dm_pool *mem __attribute__((unused)),
				     struct dm_report_field *field, const void *data,
				     void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	uint64_t area_count, region;

	region = dm_stats_get_current_region(dms);
	if (!(area_count = dm_stats_get_region_nr_areas(dms, region)))
		return_0;

	return dm_report_field_uint64(rh, field, &area_count);
}

static int _dm_stats_program_id_disp(struct dm_report *rh,
				     struct dm_pool *mem __attribute__((unused)),
				     struct dm_report_field *field, const void *data,
				     void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	const char *program_id;
	if (!(program_id = dm_stats_get_current_region_program_id(dms)))
		return_0;
	return dm_report_field_string(rh, field, (const char * const *) &program_id);
}

static int _dm_stats_aux_data_disp(struct dm_report *rh,
				     struct dm_pool *mem __attribute__((unused)),
				     struct dm_report_field *field, const void *data,
				     void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	const char *aux_data;
	if (!(aux_data = dm_stats_get_current_region_aux_data(dms)))
		return_0;
	return dm_report_field_string(rh, field, (const char * const *) &aux_data);
}

static int _dm_stats_precise_disp(struct dm_report *rh,
				  struct dm_pool *mem __attribute__((unused)),
				  struct dm_report_field *field, const void *data,
				  void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	int precise;
	precise = dm_stats_get_current_region_precise_timestamps(dms);
	return dm_report_field_int(rh, field, (const int *) &precise);
}

static const char *_get_histogram_string(const struct dm_stats *dms, int rel,
					 int vals, int bounds)
{
	const struct dm_histogram *dmh;
	int flags = 0, width = (_switches[NOHEADINGS_ARG]) ? -1 : 0;

	if (!(dmh = dm_stats_get_histogram(dms, DM_STATS_REGION_CURRENT,
					   DM_STATS_AREA_CURRENT)))
		return ""; /* No histogram. */

	flags |= (vals) ? DM_HISTOGRAM_VALUES
			: 0;

	flags |= bounds;

	flags |= (rel) ? DM_HISTOGRAM_PERCENT
			: 0;

	flags |= (_switches[NOTIMESUFFIX_ARG]) ? 0 : DM_HISTOGRAM_SUFFIX;

	/* FIXME: make unit conversion optional. */
	return dm_histogram_to_string(dmh, -1, width, flags);
}

static int _stats_hist_count_disp(struct dm_report *rh,
				  struct dm_report_field *field, const void *data,
				  int bounds)
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	const char *histogram;

	histogram = _get_histogram_string(dms, 0, 1, bounds); /* counts */

	if (!histogram)
		return_0;

	return dm_report_field_string(rh, field, (const char * const *) &histogram);
}

static int _dm_stats_hist_count_disp(struct dm_report *rh,
				     struct dm_pool *mem __attribute__((unused)),
				     struct dm_report_field *field, const void *data,
				     void *private __attribute__((unused)))
{
	return _stats_hist_count_disp(rh, field, data, 0);
}

static int _dm_stats_hist_count_bounds_disp(struct dm_report *rh,
					    struct dm_pool *mem __attribute__((unused)),
					    struct dm_report_field *field, const void *data,
					    void *private __attribute__((unused)))
{
	return _stats_hist_count_disp(rh, field, data, DM_HISTOGRAM_BOUNDS_LOWER);
}

static int _dm_stats_hist_count_ranges_disp(struct dm_report *rh,
					    struct dm_pool *mem __attribute__((unused)),
					    struct dm_report_field *field, const void *data,
					    void *private __attribute__((unused)))
{
	return _stats_hist_count_disp(rh, field, data, DM_HISTOGRAM_BOUNDS_RANGE);
}

static int _stats_hist_percent_disp(struct dm_report *rh,
				    struct dm_report_field *field, const void *data,
				    int bounds)
{

	/* FIXME: configurable to-string options. */
	const struct dm_stats *dms = (const struct dm_stats *) data;
	const char *histogram;

	histogram = _get_histogram_string(dms, 1, 1, bounds); /* relative values */

	if (!histogram)
		return_0;

	return dm_report_field_string(rh, field, (const char * const *) &histogram);
}

static int _dm_stats_hist_percent_disp(struct dm_report *rh,
				       struct dm_pool *mem __attribute__((unused)),
				       struct dm_report_field *field, const void *data,
				       void *private __attribute__((unused)))
{
	return _stats_hist_percent_disp(rh, field, data, 0);
}

static int _dm_stats_hist_percent_bounds_disp(struct dm_report *rh,
					      struct dm_pool *mem __attribute__((unused)),
					      struct dm_report_field *field, const void *data,
					      void *private __attribute__((unused)))
{
	return _stats_hist_percent_disp(rh, field, data, DM_HISTOGRAM_BOUNDS_LOWER);
}

static int _dm_stats_hist_percent_ranges_disp(struct dm_report *rh,
					      struct dm_pool *mem __attribute__((unused)),
					      struct dm_report_field *field, const void *data,
					      void *private __attribute__((unused)))
{
	return _stats_hist_percent_disp(rh, field, data, DM_HISTOGRAM_BOUNDS_RANGE);
}

static int _stats_hist_bounds_disp(struct dm_report *rh,
				   struct dm_report_field *field, const void *data,
				   int bounds)
{
	/* FIXME: configurable to-string options. */
	const struct dm_stats *dms = (const struct dm_stats *) data;
	const char *histogram;

	histogram = _get_histogram_string(dms, 0, 0, bounds);

	if (!histogram)
		return_0;

	return dm_report_field_string(rh, field, (const char * const *) &histogram);
}

static int _dm_stats_hist_bounds_disp(struct dm_report *rh,
				      struct dm_pool *mem __attribute__((unused)),
				      struct dm_report_field *field, const void *data,
				      void *private __attribute__((unused)))
{
	return _stats_hist_bounds_disp(rh, field, data, DM_HISTOGRAM_BOUNDS_LOWER);
}

static int _dm_stats_hist_ranges_disp(struct dm_report *rh,
				      struct dm_pool *mem __attribute__((unused)),
				      struct dm_report_field *field, const void *data,
				      void *private __attribute__((unused)))
{
	return _stats_hist_bounds_disp(rh, field, data, DM_HISTOGRAM_BOUNDS_RANGE);
}

static int _dm_stats_hist_bins_disp(struct dm_report *rh,
				   struct dm_pool *mem __attribute__((unused)),
				   struct dm_report_field *field, const void *data,
				   void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	int bins;
	bins = dm_stats_get_region_nr_histogram_bins(dms, DM_STATS_REGION_CURRENT);
	return dm_report_field_int(rh, field, (const int *) &bins);
}

static int _dm_stats_rrqm_disp(struct dm_report *rh,
			       struct dm_pool *mem __attribute__((unused)),
			       struct dm_report_field *field, const void *data,
			       void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	char buf[64];
	char *repstr;
	double *sortval, rrqm;

	if (!dm_stats_get_rd_merges_per_sec(dms, &rrqm,
					    DM_STATS_REGION_CURRENT,
					    DM_STATS_AREA_CURRENT))
		return_0;

	if (!dm_snprintf(buf, sizeof(buf), "%.2f", rrqm))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = rrqm;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;

}

static int _dm_stats_wrqm_disp(struct dm_report *rh,
			       struct dm_pool *mem __attribute__((unused)),
			       struct dm_report_field *field, const void *data,
			       void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	char buf[64];
	char *repstr;
	double *sortval, wrqm;

	if (!dm_stats_get_wr_merges_per_sec(dms, &wrqm,
					    DM_STATS_REGION_CURRENT,
					    DM_STATS_AREA_CURRENT))
		return_0;

	if (!dm_snprintf(buf, sizeof(buf), "%.2f", wrqm))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = wrqm;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;

}

static int _dm_stats_rs_disp(struct dm_report *rh,
			       struct dm_pool *mem __attribute__((unused)),
			       struct dm_report_field *field, const void *data,
			       void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	char buf[64];
	char *repstr;
	double *sortval, rs;

	if (!dm_stats_get_reads_per_sec(dms, &rs,
					DM_STATS_REGION_CURRENT,
					DM_STATS_AREA_CURRENT))
		return_0;

	if (!dm_snprintf(buf, sizeof(buf), "%.2f", rs))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = rs;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;

}

static int _dm_stats_ws_disp(struct dm_report *rh,
			     struct dm_pool *mem __attribute__((unused)),
			     struct dm_report_field *field, const void *data,
			     void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	char buf[64];
	char *repstr;
	double *sortval, ws;

	if (!dm_stats_get_writes_per_sec(dms, &ws,
					 DM_STATS_REGION_CURRENT,
					 DM_STATS_AREA_CURRENT))
		return_0;

	if (!dm_snprintf(buf, sizeof(buf), "%.2f", ws))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = ws;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;

}

static int _dm_stats_read_secs_disp(struct dm_report *rh,
				    struct dm_pool *mem __attribute__((unused)),
				    struct dm_report_field *field, const void *data,
				    void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	const char *repstr;
	double *sortval, rsec;
	char units = _disp_units;
	uint64_t factor = _disp_factor;

	if (!dm_stats_get_read_sectors_per_sec(dms, &rsec,
					       DM_STATS_REGION_CURRENT,
					       DM_STATS_AREA_CURRENT))
		return_0;

	if (!(repstr = dm_size_to_string(mem, (uint64_t) rsec, units, 1,
					 factor, _show_units(), DM_SIZE_UNIT)))

		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = rsec;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_write_secs_disp(struct dm_report *rh,
				     struct dm_pool *mem __attribute__((unused)),
				     struct dm_report_field *field, const void *data,
				     void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	const char *repstr;
	double *sortval, wsec;
	char units = _disp_units;
	uint64_t factor = _disp_factor;

	if (!dm_stats_get_write_sectors_per_sec(dms, &wsec,
						DM_STATS_REGION_CURRENT,
						DM_STATS_AREA_CURRENT))
		return_0;

	if (!(repstr = dm_size_to_string(mem, (uint64_t) wsec, units, 1,
					 factor, _show_units(), DM_SIZE_UNIT)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = wsec;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_arqsz_disp(struct dm_report *rh,
				struct dm_pool *mem __attribute__((unused)),
				struct dm_report_field *field, const void *data,
				void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	const char *repstr;
	double *sortval, arqsz;
	char units = _disp_units;
	uint64_t factor = _disp_factor;

	if (!dm_stats_get_average_request_size(dms, &arqsz,
					       DM_STATS_REGION_CURRENT,
					       DM_STATS_AREA_CURRENT))
		return_0;


	if (!(repstr = dm_size_to_string(mem, (uint64_t) arqsz, units, 1,
					 factor, _show_units(), DM_SIZE_UNIT)))

		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = arqsz;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_qusz_disp(struct dm_report *rh,
			       struct dm_pool *mem __attribute__((unused)),
			       struct dm_report_field *field, const void *data,
			       void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	char buf[64];
	char *repstr;
	double *sortval, qusz;

	if (!dm_stats_get_average_queue_size(dms, &qusz,
					     DM_STATS_REGION_CURRENT,
					     DM_STATS_AREA_CURRENT))
		return_0;

	if (!dm_snprintf(buf, sizeof(buf), "%.2f", qusz))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = qusz;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_await_disp(struct dm_report *rh,
				struct dm_pool *mem __attribute__((unused)),
				struct dm_report_field *field, const void *data,
				void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	char buf[64];
	char *repstr;
	double *sortval, await;

	if (!dm_stats_get_average_wait_time(dms, &await,
					    DM_STATS_REGION_CURRENT,
					    DM_STATS_AREA_CURRENT))
		return_0;

	/* FIXME: make scale configurable */
	/* display in msecs */
	await /= NSEC_PER_MSEC;

	if (!dm_snprintf(buf, sizeof(buf), "%.2f", await))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = await;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_r_await_disp(struct dm_report *rh,
				  struct dm_pool *mem __attribute__((unused)),
				  struct dm_report_field *field, const void *data,
				  void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	char buf[64];
	char *repstr;
	double *sortval, r_await;

	if (!dm_stats_get_average_rd_wait_time(dms, &r_await,
					       DM_STATS_REGION_CURRENT,
					       DM_STATS_AREA_CURRENT))
		return_0;

	/* FIXME: make scale configurable */
	/* display in msecs */
	r_await /= NSEC_PER_MSEC;

	if (!dm_snprintf(buf, sizeof(buf), "%.2f", r_await))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = r_await;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_w_await_disp(struct dm_report *rh,
				  struct dm_pool *mem __attribute__((unused)),
				  struct dm_report_field *field, const void *data,
				  void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	char buf[64];
	char *repstr;
	double *sortval, w_await;

	if (!dm_stats_get_average_wr_wait_time(dms, &w_await,
					       DM_STATS_REGION_CURRENT,
					       DM_STATS_AREA_CURRENT))
		return_0;

	/* FIXME: make scale configurable */
	/* display in msecs */
	w_await /= NSEC_PER_MSEC;

	if (!dm_snprintf(buf, sizeof(buf), "%.2f", w_await))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = w_await;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_tput_disp(struct dm_report *rh,
			       struct dm_pool *mem __attribute__((unused)),
			       struct dm_report_field *field, const void *data,
			       void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	char buf[64];
	char *repstr;
	double *sortval, tput;

	if (!dm_stats_get_throughput(dms, &tput,
				     DM_STATS_REGION_CURRENT,
				     DM_STATS_AREA_CURRENT))
		return_0;

	if (!dm_snprintf(buf, sizeof(buf), "%.2f", tput))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = tput;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static int _dm_stats_svctm_disp(struct dm_report *rh,
				struct dm_pool *mem __attribute__((unused)),
				struct dm_report_field *field, const void *data,
				void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	char buf[64];
	char *repstr;
	double *sortval, svctm;

	if (!dm_stats_get_service_time(dms, &svctm,
				       DM_STATS_REGION_CURRENT,
				       DM_STATS_AREA_CURRENT))
		return_0;

	/* FIXME: make scale configurable */
	/* display in msecs */
	svctm /= NSEC_PER_MSEC;

	if (!dm_snprintf(buf, sizeof(buf), "%.2f", svctm))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	if (!(sortval = dm_pool_alloc(mem, sizeof(uint64_t))))
		return_0;

	*sortval = svctm;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;

}

static int _dm_stats_util_disp(struct dm_report *rh,
			       struct dm_pool *mem __attribute__((unused)),
			       struct dm_report_field *field, const void *data,
			       void *private __attribute__((unused)))
{
	const struct dm_stats *dms = (const struct dm_stats *) data;
	dm_percent_t util;

	if (!dm_stats_get_utilization(dms, &util,
				      DM_STATS_REGION_CURRENT,
				      DM_STATS_AREA_CURRENT))
		return_0;

	dm_report_field_percent(rh, field, &util);
	return 1;
}

static int _dm_stats_sample_interval_ns_disp(struct dm_report *rh,
					     struct dm_pool *mem __attribute__((unused)),
					     struct dm_report_field *field, const void *data,
					     void *private __attribute__((unused)))
{
	/* FIXME: use internal interval estimate when supported by libdm */
	return dm_report_field_uint64(rh, field, &_last_interval);
}

static int _dm_stats_sample_interval_disp(struct dm_report *rh,
					  struct dm_pool *mem __attribute__((unused)),
					  struct dm_report_field *field, const void *data,
					  void *private __attribute__((unused)))
{
	char buf[64];
	char *repstr;
	double *sortval;

	if (!(sortval = dm_pool_alloc(mem, sizeof(*sortval))))
		return_0;

	*sortval = (double)_last_interval / (double) NSEC_PER_SEC;

	if (!dm_snprintf(buf, sizeof(buf), "%2.6f", *sortval))
		return_0;

	if (!(repstr = dm_pool_strdup(mem, buf)))
		return_0;

	dm_report_field_set_value(field, repstr, sortval);
	return 1;
}

static void *_task_get_obj(void *obj)
{
	return ((struct dmsetup_report_obj *)obj)->task;
}

static void *_info_get_obj(void *obj)
{
	return ((struct dmsetup_report_obj *)obj)->info;
}

static void *_deps_get_obj(void *obj)
{
	return dm_task_get_deps(((struct dmsetup_report_obj *)obj)->deps_task);
}

static void *_tree_get_obj(void *obj)
{
	return ((struct dmsetup_report_obj *)obj)->tree_node;
}

static void *_split_name_get_obj(void *obj)
{
	return ((struct dmsetup_report_obj *)obj)->split_name;
}

static void *_stats_get_obj(void *obj)
{
	return ((struct dmsetup_report_obj *)obj)->stats;
}

static const struct dm_report_object_type _report_types[] = {
	{ DR_TASK, "Mapped Device Name", "name_", _task_get_obj },
	{ DR_INFO, "Mapped Device Information", "info_", _info_get_obj },
	{ DR_DEPS, "Mapped Device Relationship Information", "deps_", _deps_get_obj },
	{ DR_TREE, "Mapped Device Relationship Information", "tree_", _tree_get_obj },
	{ DR_NAME, "Mapped Device Name Components", "splitname_", _split_name_get_obj },
	{ DR_STATS, "Mapped Device Statistics","stats_", _stats_get_obj },
	{ DR_STATS_META, "Mapped Device Statistics Region Information","region_", _stats_get_obj },
	{ 0, "", "", NULL }
};

/* Column definitions */
/* N.B. Field names must not contain the substring 'help' as this will disable --count. */
#define OFFSET_OF(strct, field) (((char*)&((struct strct*)0)->field) - (char*)0)
#define STR (DM_REPORT_FIELD_TYPE_STRING)
#define NUM (DM_REPORT_FIELD_TYPE_NUMBER)
#define SIZ (DM_REPORT_FIELD_TYPE_SIZE)
#define TIM (DM_REPORT_FIELD_TYPE_TIME)
#define FIELD_O(type, strct, sorttype, head, field, width, func, id, desc) {DR_ ## type, sorttype, OFFSET_OF(strct, field), width, id, head, &_ ## func ## _disp, desc},
#define FIELD_F(type, sorttype, head, width, func, id, desc) {DR_ ## type, sorttype, 0, width, id, head, &_ ## func ## _disp, desc},

static const struct dm_report_field_type _report_fields[] = {
/* *INDENT-OFF* */
FIELD_F(TASK, STR, "Name", 16, dm_name, "name", "Name of mapped device.")
FIELD_F(TASK, STR, "MangledName", 16, dm_mangled_name, "mangled_name", "Mangled name of mapped device.")
FIELD_F(TASK, STR, "UnmangledName", 16, dm_unmangled_name, "unmangled_name", "Unmangled name of mapped device.")
FIELD_F(TASK, STR, "UUID", 32, dm_uuid, "uuid", "Unique (optional) identifier for mapped device.")
FIELD_F(TASK, STR, "MangledUUID", 32, dm_mangled_uuid, "mangled_uuid", "Mangled unique (optional) identifier for mapped device.")
FIELD_F(TASK, STR, "UnmangledUUID", 32, dm_unmangled_uuid, "unmangled_uuid", "Unmangled unique (optional) identifier for mapped device.")

/* FIXME Next one should be INFO */
FIELD_F(TASK, NUM, "RAhead", 6, dm_read_ahead, "read_ahead", "Read ahead value.")

FIELD_F(INFO, STR, "BlkDevName", 16, dm_blk_name, "blkdevname", "Name of block device.")
FIELD_F(INFO, STR, "Stat", 4, dm_info_status, "attr", "(L)ive, (I)nactive, (s)uspended, (r)ead-only, read-(w)rite.")
FIELD_F(INFO, STR, "Tables", 6, dm_info_table_loaded, "tables_loaded", "Which of the live and inactive table slots are filled.")
FIELD_F(INFO, STR, "Suspended", 9, dm_info_suspended, "suspended", "Whether the device is suspended.")
FIELD_F(INFO, STR, "Read-only", 9, dm_info_read_only, "readonly", "Whether the device is read-only or writeable.")
FIELD_F(INFO, STR, "DevNo", 5, dm_info_devno, "devno", "Device major and minor numbers")
FIELD_O(INFO, dm_info, NUM, "Maj", major, 3, int32, "major", "Block device major number.")
FIELD_O(INFO, dm_info, NUM, "Min", minor, 3, int32, "minor", "Block device minor number.")
FIELD_O(INFO, dm_info, NUM, "Open", open_count, 4, int32, "open", "Number of references to open device, if requested.")
FIELD_O(INFO, dm_info, NUM, "Targ", target_count, 4, int32, "segments", "Number of segments in live table, if present.")
FIELD_O(INFO, dm_info, NUM, "Event", event_nr, 6, uint32, "events", "Number of most recent event.")

FIELD_O(DEPS, dm_deps, NUM, "#Devs", count, 5, int32, "device_count", "Number of devices used by this one.")
FIELD_F(TREE, STR, "DevNamesUsed", 16, dm_deps_names, "devs_used", "List of names of mapped devices used by this one.")
FIELD_F(DEPS, STR, "DevNosUsed", 16, dm_deps, "devnos_used", "List of device numbers of devices used by this one.")
FIELD_F(DEPS, STR, "BlkDevNamesUsed", 16, dm_deps_blk_names, "blkdevs_used", "List of names of block devices used by this one.")

FIELD_F(TREE, NUM, "#Refs", 5, dm_tree_parents_count, "device_ref_count", "Number of mapped devices referencing this one.")
FIELD_F(TREE, STR, "RefNames", 8, dm_tree_parents_names, "names_using_dev", "List of names of mapped devices using this one.")
FIELD_F(TREE, STR, "RefDevNos", 9, dm_tree_parents_devs, "devnos_using_dev", "List of device numbers of mapped devices using this one.")

FIELD_O(NAME, dm_split_name, STR, "Subsys", subsystem, 6, dm_subsystem, "subsystem", "Userspace subsystem responsible for this device.")
FIELD_O(NAME, dm_split_name, STR, "VG", vg_name, 4, dm_vg_name, "vg_name", "LVM Volume Group name.")
FIELD_O(NAME, dm_split_name, STR, "LV", lv_name, 4, dm_lv_name, "lv_name", "LVM Logical Volume name.")
FIELD_O(NAME, dm_split_name, STR, "LVLayer", lv_layer, 7, dm_lv_layer_name, "lv_layer", "LVM device layer.")

/* basic stats counters */
FIELD_F(STATS, NUM, "#Reads", 6, dm_stats_reads, "read_count", "Count of reads completed.")
FIELD_F(STATS, NUM, "#RdMrgs", 7, dm_stats_reads_merged, "reads_merged_count", "Count of read requests merged.")
FIELD_F(STATS, NUM, "#RdSectors", 10, dm_stats_read_sectors, "read_sector_count", "Count of sectors read.")
FIELD_F(STATS, NUM, "AccRdTime", 11, dm_stats_read_nsecs, "read_time", "Accumulated duration of all read requests (ns).")
FIELD_F(STATS, NUM, "#Writes", 7, dm_stats_writes, "write_count", "Count of writes completed.")
FIELD_F(STATS, NUM, "#WrMrgs", 7, dm_stats_writes_merged, "writes_merged_count", "Count of write requests merged.")
FIELD_F(STATS, NUM, "#WrSectors", 10, dm_stats_write_sectors, "write_sector_count", "Count of sectors written.")
FIELD_F(STATS, NUM, "AccWrTime", 11, dm_stats_write_nsecs, "write_time", "Accumulated duration of all writes (ns).")
FIELD_F(STATS, NUM, "#InProg", 7, dm_stats_io_in_progress, "in_progress_count", "Count of requests currently in progress.")
FIELD_F(STATS, NUM, "IoTicks", 7, dm_stats_io_nsecs, "io_ticks", "Nanoseconds spent servicing requests.")
FIELD_F(STATS, NUM, "QueueTicks", 10, dm_stats_weighted_io_nsecs, "queue_ticks", "Total nanoseconds spent in queue.")
FIELD_F(STATS, NUM, "RdTicks", 7, dm_stats_total_read_nsecs, "read_ticks", "Nanoseconds spent servicing reads.")
FIELD_F(STATS, NUM, "WrTicks", 7, dm_stats_total_write_nsecs, "write_ticks", "Nanoseconds spent servicing writes.")

/* Stats derived metrics */
FIELD_F(STATS, NUM, "RMrg/s", 6, dm_stats_rrqm, "reads_merged_per_sec", "Read requests merged per second.")
FIELD_F(STATS, NUM, "WMrg/s", 6, dm_stats_wrqm, "writes_merged_per_sec", "Write requests merged per second.")
FIELD_F(STATS, NUM, "R/s", 3, dm_stats_rs, "reads_per_sec", "Reads per second.")
FIELD_F(STATS, NUM, "W/s", 3, dm_stats_ws, "writes_per_sec", "Writes per second.")
FIELD_F(STATS, NUM, "RSz/s", 5, dm_stats_read_secs, "read_size_per_sec", "Size of data read per second.")
FIELD_F(STATS, NUM, "WSz/s", 5, dm_stats_write_secs, "write_size_per_sec", "Size of data written per second.")
FIELD_F(STATS, NUM, "AvgRqSz", 7, dm_stats_arqsz, "avg_request_size", "Average request size.")
FIELD_F(STATS, NUM, "QSize", 5, dm_stats_qusz, "queue_size", "Average queue size.")
FIELD_F(STATS, NUM, "AWait", 5, dm_stats_await, "await", "Averate wait time.")
FIELD_F(STATS, NUM, "RdAWait", 7, dm_stats_r_await, "read_await", "Averate read wait time.")
FIELD_F(STATS, NUM, "WrAWait", 7, dm_stats_w_await, "write_await", "Averate write wait time.")
FIELD_F(STATS, NUM, "Throughput", 10, dm_stats_tput, "throughput", "Throughput.")
FIELD_F(STATS, NUM, "SvcTm", 5, dm_stats_svctm, "service_time", "Service time.")
FIELD_F(STATS, NUM, "Util%", 5, dm_stats_util, "util", "Utilization.")

/* Histogram fields */
FIELD_F(STATS, STR, "Histogram Counts", 16, dm_stats_hist_count, "hist_count", "Latency histogram counts.")
FIELD_F(STATS, STR, "Histogram Counts", 16, dm_stats_hist_count_bounds, "hist_count_bounds", "Latency histogram counts with bin boundaries.")
FIELD_F(STATS, STR, "Histogram Counts", 16, dm_stats_hist_count_ranges, "hist_count_ranges", "Latency histogram counts with bin ranges.")
FIELD_F(STATS, STR, "Histogram%", 10, dm_stats_hist_percent, "hist_percent", "Relative latency histogram.")
FIELD_F(STATS, STR, "Histogram%", 10, dm_stats_hist_percent_bounds, "hist_percent_bounds", "Relative latency histogram with bin boundaries.")
FIELD_F(STATS, STR, "Histogram%", 10, dm_stats_hist_percent_ranges, "hist_percent_ranges", "Relative latency histogram with bin ranges.")

/* Stats interval duration estimates */
FIELD_F(STATS, NUM, "IntervalNs", 10, dm_stats_sample_interval_ns, "interval_ns", "Sampling interval in nanoseconds.")
FIELD_F(STATS, NUM, "Interval", 8, dm_stats_sample_interval, "interval", "Sampling interval.")

/* Stats report meta-fields */
FIELD_F(STATS_META, NUM, "RgID", 4, dm_stats_region_id, "region_id", "Region ID.")
FIELD_F(STATS_META, SIZ, "RgStart", 5, dm_stats_region_start, "region_start", "Region start.")
FIELD_F(STATS_META, SIZ, "RgSize", 5, dm_stats_region_len, "region_len", "Region length.")
FIELD_F(STATS_META, NUM, "ArID", 4, dm_stats_area_id, "area_id", "Area ID.")
FIELD_F(STATS_META, SIZ, "ArStart", 7, dm_stats_area_start, "area_start", "Area offset from start of device.")
FIELD_F(STATS_META, SIZ, "ArSize", 6, dm_stats_area_len, "area_len", "Area length.")
FIELD_F(STATS_META, SIZ, "ArOff", 5, dm_stats_area_offset, "area_offset", "Area offset from start of region.")
FIELD_F(STATS_META, NUM, "#Areas", 6, dm_stats_area_count, "area_count", "Area count.")
FIELD_F(STATS_META, STR, "ProgID", 6, dm_stats_program_id, "program_id", "Program ID.")
FIELD_F(STATS_META, STR, "AuxDat", 6, dm_stats_aux_data, "aux_data", "Auxiliary data.")
FIELD_F(STATS_META, STR, "Precise", 7, dm_stats_precise, "precise", "Set if nanosecond precision counters are enabled.")
FIELD_F(STATS_META, STR, "#Bins", 9, dm_stats_hist_bins, "hist_bins", "The number of histogram bins configured.")
FIELD_F(STATS_META, STR, "Histogram Bounds", 16, dm_stats_hist_bounds, "hist_bounds", "Latency histogram bin boundaries.")
FIELD_F(STATS_META, STR, "Histogram Ranges", 16, dm_stats_hist_ranges, "hist_ranges", "Latency histogram bin ranges.")
{0, 0, 0, 0, "", "", NULL, NULL},
/* *INDENT-ON* */
};

#undef FIELD_O
#undef FIELD_F

#undef STR
#undef NUM
#undef SIZ

static const char *default_report_options = "name,major,minor,attr,open,segments,events,uuid";
static const char *splitname_report_options = "vg_name,lv_name,lv_layer";

/* Stats counters & derived metrics. */
#define RD_COUNTERS "read_count,reads_merged_count,read_sector_count,read_time,read_ticks"
#define WR_COUNTERS "write_count,writes_merged_count,write_sector_count,write_time,write_ticks"
#define IO_COUNTERS "in_progress_count,io_ticks,queue_ticks"
#define COUNTERS RD_COUNTERS "," WR_COUNTERS "," IO_COUNTERS

#define METRICS "reads_merged_per_sec,writes_merged_per_sec,"	\
		"reads_per_sec,writes_per_sec,"			\
		"read_size_per_sec,write_size_per_sec,"		\
		"avg_request_size,queue_size,util,"		\
		"await,read_await,write_await"

/* Device, region and area metadata. */
#define STATS_DEV_INFO "name,region_id"
#define STATS_AREA_INFO "area_id,area_start,area_len"
#define STATS_AREA_INFO_FULL STATS_DEV_INFO ",region_start,region_len,area_count,area_id,area_start,area_len"
#define STATS_REGION_INFO STATS_DEV_INFO ",region_start,region_len,area_count,area_len"

/* Minimal set of fields for histogram report. */
#define STATS_HIST STATS_REGION_INFO ",util,await"

/* Default stats report options. */
static const char *_stats_default_report_options = STATS_DEV_INFO "," STATS_AREA_INFO "," METRICS;
static const char *_stats_raw_report_options = STATS_DEV_INFO "," STATS_AREA_INFO "," COUNTERS;
static const char *_stats_list_options = STATS_REGION_INFO ",program_id";
static const char *_stats_area_list_options = STATS_AREA_INFO_FULL ",program_id";
static const char *_stats_hist_list_options = STATS_REGION_INFO ",hist_bins,hist_bounds";
static const char *_stats_hist_area_list_options = STATS_AREA_INFO_FULL ",hist_bins,hist_bounds";
static const char *_stats_hist_options = STATS_HIST ",hist_count_bounds";
static const char *_stats_hist_relative_options = STATS_HIST ",hist_percent_bounds";

static int _report_init(const struct command *cmd, const char *subcommand)
{
	char *options = (char *) default_report_options;
	char *opt_fields = NULL; /* optional fields from command line */
	const char *keys = "";
	const char *separator = " ";
	const char *selection = NULL;
	int aligned = 1, headings = 1, buffered = 1, field_prefixes = 0;
	int quoted = 1, columns_as_rows = 0;
	uint32_t flags = 0;
	size_t len = 0;
	int r = 0;

	if (cmd && !strcmp(cmd->name, "splitname")) {
		options = (char *) splitname_report_options;
		_report_type |= DR_NAME;
	}

	if (cmd && !strcmp(cmd->name, "stats")) {
		_report_type |= DR_STATS_META;
		if (!strcmp(subcommand, "list")) {
			if (!_switches[HISTOGRAM_ARG])
				options = (char *) ((_switches[VERBOSE_ARG])
						    ? _stats_area_list_options
						    : _stats_list_options);
			else
				options = (char *) ((_switches[VERBOSE_ARG])
						    ? _stats_hist_area_list_options
						    : _stats_hist_list_options);
		} else {
			if (_switches[HISTOGRAM_ARG])
				options = (char *) ((_switches[RELATIVE_ARG])
						    ? _stats_hist_relative_options
						    : _stats_hist_options);
			else
				options = (char *) ((!_switches[RAW_ARG])
						    ? _stats_default_report_options
						    : _stats_raw_report_options);
			_report_type |= DR_STATS;
		}
	}

	if (cmd && !strcmp(cmd->name, "list")) {
		options = (char *) _stats_list_options;
		_report_type |= DR_STATS_META;
	}

	/* emulate old dmsetup behaviour */
	if (_switches[NOHEADINGS_ARG]) {
		separator = ":";
		aligned = 0;
		headings = 0;
	}

	if (_switches[UNBUFFERED_ARG])
		buffered = 0;

	if (_switches[ROWS_ARG])
		columns_as_rows = 1;

	if (_switches[UNQUOTED_ARG])
		quoted = 0;

	if (_switches[NAMEPREFIXES_ARG]) {
		aligned = 0;
		field_prefixes = 1;
	}

	if (_switches[OPTIONS_ARG] && _string_args[OPTIONS_ARG]) {
		/* Count & interval forbidden for help. */
		/* FIXME Detect "help" correctly and exit */
		if (strstr(_string_args[OPTIONS_ARG], "help")) {
			_switches[COUNT_ARG] = 0;
			_count = 1;
			_switches[INTERVAL_ARG] = 0;
			headings = 0;
		}

		if (*_string_args[OPTIONS_ARG] != '+')
			options = _string_args[OPTIONS_ARG];
		else {
			char *tmpopts;
			opt_fields = _string_args[OPTIONS_ARG] + 1;
			len = strlen(options) + strlen(opt_fields) + 2;
			if (!(tmpopts = dm_malloc(len))) {
				err("Failed to allocate option string.");
				return 0;
			}
			if (dm_snprintf(tmpopts, len, "%s,%s",
					options, opt_fields) < 0) {
				dm_free(tmpopts);
				return 0;
			}
			options = tmpopts;
		}
	}

	if (_switches[SORT_ARG] && _string_args[SORT_ARG]) {
		keys = _string_args[SORT_ARG];
		buffered = 1;
		if (cmd && (!strcmp(cmd->name, "status") || !strcmp(cmd->name, "table"))) {
			err("--sort is not yet supported with status and table");
			goto out;
		}
	}

	if (_switches[SEPARATOR_ARG] && _string_args[SEPARATOR_ARG]) {
		separator = _string_args[SEPARATOR_ARG];
		aligned = 0;
	}

	if (_switches[SELECT_ARG] && _string_args[SELECT_ARG])
		selection = _string_args[SELECT_ARG];

	if (aligned)
		flags |= DM_REPORT_OUTPUT_ALIGNED;

	if (buffered)
		flags |= DM_REPORT_OUTPUT_BUFFERED;

	if (headings)
		flags |= DM_REPORT_OUTPUT_HEADINGS;

	if (field_prefixes)
		flags |= DM_REPORT_OUTPUT_FIELD_NAME_PREFIX;

	if (!quoted)
		flags |= DM_REPORT_OUTPUT_FIELD_UNQUOTED;

	if (columns_as_rows)
		flags |= DM_REPORT_OUTPUT_COLUMNS_AS_ROWS;

	if (!(_report = dm_report_init_with_selection(&_report_type, _report_types,
				_report_fields, options, separator, flags, keys,
				selection, NULL, NULL)))
		goto_out;

	if ((_report_type & DR_TREE) && !_build_whole_deptree(cmd)) {
		err("Internal device dependency tree creation failed.");
		goto out;
	}

	if (!_switches[INTERVAL_ARG])
		_int_args[INTERVAL_ARG] = 1; /* 1s default. */

	_interval = NSEC_PER_SEC * (uint64_t) _int_args[INTERVAL_ARG];

	if (field_prefixes)
		dm_report_set_output_field_name_prefix(_report, "dm_");

	r = 1;

out:
	if (len)
		dm_free(options);

	return r;
}

/*
 * List devices
 */
static int _ls(CMD_ARGS)
{
	if ((_switches[TARGET_ARG] && _target) ||
	    (_switches[EXEC_ARG] && _command_to_exec))
		return _status(cmd, NULL, argc, argv, NULL, 0);
	else if ((_switches[TREE_ARG]))
		return _display_tree(cmd, NULL, 0, NULL, NULL, 0);
	else
		return _process_all(cmd, NULL, argc, argv, 0, _display_name);
}

static int _mangle(CMD_ARGS)
{
	const char *name, *uuid;
	char *new_name = NULL, *new_uuid = NULL;
	struct dm_task *dmt;
	struct dm_info info;
	int r = 0;
	int target_format;

	if (names)
		name = names->name;
	else {
		if (!argc && !_switches[UUID_ARG] && !_switches[MAJOR_ARG])
			return _process_all(cmd, NULL, argc, argv, 0, _mangle);
		name = argv[0];
	}

	if (!(dmt = dm_task_create(DM_DEVICE_STATUS)))
		return_0;

	if (!(_set_task_device(dmt, name, 0)))
		goto_out;

	if (!_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_task_run(dmt))
		goto_out;

	if (!dm_task_get_info(dmt, &info) || !info.exists)
		goto_out;

	uuid = dm_task_get_uuid(dmt);

	target_format = _switches[MANGLENAME_ARG] ? _int_args[MANGLENAME_ARG]
						  : DEFAULT_DM_NAME_MANGLING;

	if (target_format == DM_STRING_MANGLING_AUTO) {
		if (strstr(name, "\\x5cx")) {
			log_error("The name \"%s\" seems to be mangled more than once. "
				  "Manual intervention required to rename the device.", name);
			goto out;
		}
		if (strstr(uuid, "\\x5cx")) {
			log_error("The UUID \"%s\" seems to be mangled more than once. "
				  "Manual intervention required to correct the device UUID.", uuid);
			goto out;
		}
	}

	if (target_format == DM_STRING_MANGLING_NONE) {
		if (!(new_name = dm_task_get_name_unmangled(dmt)))
			goto_out;
		if (!(new_uuid = dm_task_get_uuid_unmangled(dmt)))
			goto_out;
	}
	else {
		if (!(new_name = dm_task_get_name_mangled(dmt)))
			goto_out;
		if (!(new_uuid = dm_task_get_uuid_mangled(dmt)))
			goto_out;
	}

	/* We can't rename the UUID, the device must be reactivated manually. */
	if (strcmp(uuid, new_uuid)) {
		log_error("%s: %s: UUID in incorrect form. ", name, uuid);
		log_error("Unable to change device UUID. The device must be deactivated first.");
		r = 0;
		goto out;
	}

	/* Nothing to do if the name is in correct form already. */
	if (!strcmp(name, new_name)) {
		log_print("%s: %s: name %salready in correct form", name,
			  *uuid ? uuid : "[no UUID]", *uuid ? "and UUID " : "");
		r = 1;
		goto out;
	}
	else
		log_print("%s: renaming to %s", name, new_name);

	/* Rename to correct form of the name. */
	r = _do_rename(name, new_name, NULL);

out:
	dm_free(new_name);
	dm_free(new_uuid);
	dm_task_destroy(dmt);
	return r;
}

static int _stats(CMD_ARGS);
static int _bind_stats_device(struct dm_stats *dms, const char *name)
{
	if (name && !dm_stats_bind_name(dms, name))
		return_0;
	else if (_switches[UUID_ARG] && !dm_stats_bind_uuid(dms, _uuid))
		return_0;
	else if (_switches[MAJOR_ARG] && _switches[MINOR_ARG]
		 && !dm_stats_bind_devno(dms, _int_args[MAJOR_ARG],
					 _int_args[MINOR_ARG]))
		return_0;

	return 1;
}

static int _stats_clear_regions(struct dm_stats *dms, uint64_t region_id)
{
	int allregions = (region_id == DM_STATS_REGIONS_ALL);

	if (!dm_stats_list(dms, NULL))
		return_0;

	if (!dm_stats_get_nr_regions(dms))
		return 1;

	dm_stats_walk_do(dms) {
		if (allregions)
			region_id = dm_stats_get_current_region(dms);

		if (!dm_stats_region_present(dms, region_id)) {
			log_error("No such region: %"PRIu64".", region_id);
			return 0;
		}
		if (!dm_stats_clear_region(dms, region_id)) {
			log_error("Clearing statistics region %"PRIu64" failed.",
				  region_id);
			return 0;
		}
		log_info("Cleared statistics region %"PRIu64".", region_id);
		dm_stats_walk_next_region(dms);
	} dm_stats_walk_while(dms);

	return 1;
}

static int _stats_clear(CMD_ARGS)
{
	struct dm_stats *dms;
	uint64_t region_id;
	char *name = NULL;
	int allregions = _switches[ALL_REGIONS_ARG];

	/* clear does not use a report */
	if (_report) {
		dm_report_free(_report);
		_report = NULL;
	}

	if (!_switches[REGION_ID_ARG] && !_switches[ALL_REGIONS_ARG]) {
		err("Please specify a --regionid or use --allregions.");
		return 0;
	}

	if (names)
		name = names->name;
	else {
		if (!argc && !_switches[UUID_ARG] && !_switches[MAJOR_ARG])
			return _process_all(cmd, subcommand, argc, argv, 0, _stats_clear);
		name = argv[0];
	}

	region_id = (allregions) ? DM_STATS_REGIONS_ALL
		     : (uint64_t) _int_args[REGION_ID_ARG];

	dms = dm_stats_create(DM_STATS_PROGRAM_ID);

	if (!_bind_stats_device(dms, name))
		goto_out;

	if (!_stats_clear_regions(dms, region_id))
		goto_out;

	dm_stats_destroy(dms);
	return 1;

out:
	dm_stats_destroy(dms);
	return 0;
}

static uint64_t _factor_from_units(char *argptr, char *unit_type)
{
	return dm_units_to_factor(argptr, unit_type, 0, NULL);
}

/**
 * Parse a start, length, or area size argument in bytes from a string
 * using optional units as supported by _factor_from_units().
 */
static int _size_from_string(char *argptr, uint64_t *size, const char *name)
{
	uint64_t factor;
	char *endptr = NULL, unit_type;
	if (!argptr)
		return_0;

	*size = strtoull(argptr, &endptr, 10);
	if (endptr == argptr) {
		*size = 0;
		log_error("Invalid %s argument: \"%s\"",
			  name, (*argptr) ? argptr : "");
		return 0;
	}

	if (*endptr == '\0') {
		*size *= 512;
		return 1;
	}

	factor = _factor_from_units(endptr, &unit_type);
	if (factor)
		*size *= factor;

	return 1;
}

/*
 * FIXME: expose this from libdm-stats
 */
static uint64_t _nr_areas_from_step(uint64_t len, int64_t step)
{
	/* Default is one area. */
	if (!step || !len)
		return 1;

	/* --areas */
	if (step < 0)
		return (uint64_t)(-step);

	/* --areasize - cast step to unsigned as it cannot be -ve here. */
	return (len / (step ? : len)) + !!(len % (uint64_t) step);
}

/*
 * Create a single region starting at start and spanning len sectors,
 * or, if the segments argument is no-zero create one region for each
 * segment present in the mapped device. Passing zero for segments,
 * start, and length will create a single segment spanning the whole
 * device.
 */
static int _do_stats_create_regions(struct dm_stats *dms,
				    const char *name, uint64_t start,
				    uint64_t len, int64_t step,
				    int segments,
				    const char *program_id,
				    const char *aux_data)
{
	uint64_t this_start = 0, this_len = len, region_id = UINT64_C(0);
	const char *devname = NULL, *histogram = _string_args[BOUNDS_ARG];
	int r = 0, precise = _switches[PRECISE_ARG];
	struct dm_histogram *bounds = NULL; /* histogram bounds */
	char *target_type, *params; /* unused */
	struct dm_task *dmt;
	struct dm_info info;
	void *next = NULL;

	if (histogram && !(bounds = dm_histogram_bounds_from_string(histogram)))
		return_0;

	if (!(dmt = dm_task_create(DM_DEVICE_TABLE))) {
		dm_histogram_bounds_destroy(bounds);
		dm_stats_destroy(dms);
		return_0;
	}

	if (!_set_task_device(dmt, name, 0))
		goto_out;

	if (!dm_task_no_open_count(dmt))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_task_run(dmt))
		goto_out;

	if (!dm_task_get_info(dmt, &info) || !info.exists)
		goto_out;

	if (!(devname = dm_task_get_name(dmt)))
		goto_out;

	do {
		uint64_t segment_start, segment_len;
		next = dm_get_next_target(dmt, next, &segment_start, &segment_len,
					  &target_type, &params);

		/* Accumulate whole-device size for nr_areas calculation. */
		if (!segments && !len)
			this_len += segment_len;

		/* Segments or whole-device. */
		if (segments || !next) {
			/*
			 * this_start and this_len hold the start and length in
			 * sectors of the to-be-created region: this is either the
			 * segment start/len (for --segments), the value of the
			 * --start/--length arguments, or 0/0 for a default
			 *  whole-device region).
			 */
			this_start = (segments) ? segment_start : start;
			this_len = (segments) ? segment_len : this_len;
			if (!dm_stats_create_region(dms, &region_id,
						    this_start, this_len, step,
						    precise, bounds,
						    program_id, aux_data)) {
				log_error("%s: Could not create statistics region.",
					  devname);
				goto out;
			}

			printf("%s: Created new region with "FMTu64" area(s) as "
			       "region ID "FMTu64"\n", devname,
			       _nr_areas_from_step(this_len, step), region_id);
		}
	} while (next);
	r = 1;

out:
	dm_task_destroy(dmt);
	dm_stats_destroy(dms);
	dm_histogram_bounds_destroy(bounds);
	return r;
}

static int _stats_create(CMD_ARGS)
{
	struct dm_stats *dms;
	const char *name, *aux_data = "", *program_id = DM_STATS_PROGRAM_ID;
	uint64_t start = 0, len = 0, areas = 0, area_size = 0;
	int64_t step = 0;

	/* create does not use a report */
	if (_report) {
		dm_report_free(_report);
		_report = NULL;
	}

	if (_switches[ALL_REGIONS_ARG]) {
		log_error("Cannot use --allregions with create.");
		return 0;
	}

	if (_switches[ALL_PROGRAMS_ARG]) {
		log_error("Cannot use --allprograms with create.");
		return 0;
	}

	if (_switches[AREAS_ARG] && _switches[AREA_SIZE_ARG]) {
		log_error("Please specify one of --areas and --areasize.");
		return 0;
	}

	if (_switches[PROGRAM_ID_ARG]
	    && !strlen(_string_args[PROGRAM_ID_ARG]) && !_switches[FORCE_ARG]) {
		log_error("Creating a region with no program "
			  "id requires --force.");
			return 0;
	}

	if (names)
		name = names->name;
	else {
		if (!argc && !_switches[UUID_ARG] && !_switches[MAJOR_ARG]) {
			if (!_switches[ALL_DEVICES_ARG]) {
				log_error("Please specify device(s) or use "
					  "--alldevices.");
				return 0;
			}
			return _process_all(cmd, subcommand, argc, argv, 0, _stats_create);
		}
		name = argv[0];
	}

	if (_switches[AREAS_ARG])
		areas = (uint64_t) _int_args[AREAS_ARG];

	if (_switches[AREA_SIZE_ARG])
		if (!_size_from_string(_string_args[AREA_SIZE_ARG],
				       &area_size, "areasize"))
			return_0;

	areas = (areas) ? areas : 1;
	/* bytes to sectors or -(areas): promote to signed before conversion */
	step = (area_size) ? ((int64_t) area_size / 512) : -((int64_t) areas);

	if (_switches[START_ARG]) {
		if (!_size_from_string(_string_args[START_ARG],
				       &start, "start"))
			return_0;
	}

	/* bytes to sectors */
	start /= 512;

	if (_switches[LENGTH_ARG]) {
		if (!_size_from_string(_string_args[LENGTH_ARG],
				       &len, "length"))
			return_0;
	}

	/* bytes to sectors */
	len /= 512;

	if (_switches[PROGRAM_ID_ARG])
		program_id = _string_args[PROGRAM_ID_ARG];
	if (!strlen(program_id) && !_switches[FORCE_ARG])
		program_id = DM_STATS_PROGRAM_ID;

	if (_switches[AUX_DATA_ARG])
		aux_data = _string_args[AUX_DATA_ARG];

	dms = dm_stats_create(DM_STATS_PROGRAM_ID);
	if (!_bind_stats_device(dms, name))
		goto_bad;

	if (_switches[PRECISE_ARG]) {
		if (!dm_stats_driver_supports_precise()) {
			log_error("Using --precise requires driver version "
				  "4.32.0 or later.");
			goto bad;
		}
	}

	if (_switches[BOUNDS_ARG]) {
		if (!dm_stats_driver_supports_histogram()) {
			log_error("Using --bounds requires driver version "
				  "4.32.0 or later.");
			goto bad;
		}
	}

	if (!strlen(program_id))
		/* force creation of a region with no id */
		dm_stats_set_program_id(dms, 1, NULL);

	return _do_stats_create_regions(dms, name, start, len, step,
					_switches[SEGMENTS_ARG],
					program_id, aux_data);

bad:
	dm_stats_destroy(dms);
	return 0;
}

static int _stats_delete(CMD_ARGS)
{
	struct dm_stats *dms;
	uint64_t region_id;
	char *name = NULL;
	const char *program_id = DM_STATS_PROGRAM_ID;
	int allregions = _switches[ALL_REGIONS_ARG];
	int r = 0;

	/* delete does not use a report */
	if (_report) {
		dm_report_free(_report);
		_report = NULL;
	}

	if (!_switches[REGION_ID_ARG] && !allregions) {
		err("Please specify a --regionid or use --allregions.");
		return 0;
	}

	if (names)
		name = names->name;
	else {
		if (!argc && !_switches[UUID_ARG] && !_switches[MAJOR_ARG]) {
			if (!_switches[ALL_DEVICES_ARG]) {
				log_error("Please specify device(s) or use "
					  "--alldevices.");
				return 0;
			}
			return _process_all(cmd, subcommand, argc, argv, 0, _stats_delete);
		}
		name = argv[0];
	}

	if (_switches[ALL_PROGRAMS_ARG])
		program_id = DM_STATS_ALL_PROGRAMS;

	region_id = (uint64_t) _int_args[REGION_ID_ARG];

	dms = dm_stats_create(program_id);

	if (!_bind_stats_device(dms, name))
		goto_out;

	if (allregions && !dm_stats_list(dms, program_id))
		goto_out;

	if (allregions && !dm_stats_get_nr_regions(dms)) {
		/* no regions present */
		r = 1;
		goto out;
	}

	dm_stats_walk_do(dms) {
		if (_switches[ALL_REGIONS_ARG])
			region_id = dm_stats_get_current_region(dms);
		if (!dm_stats_delete_region(dms, region_id)) {
			log_error("Could not delete statistics region.");
			goto out;
		}
		log_info("Deleted statistics region %" PRIu64, region_id);
		dm_stats_walk_next_region(dms);
	} dm_stats_walk_while(dms);

	r = 1;

out:
	dm_stats_destroy(dms);
	return r;
}

static int _stats_print(CMD_ARGS)
{
	struct dm_stats *dms;
	char *name, *stbuff = NULL;
	uint64_t region_id;
	unsigned clear = (unsigned) _switches[CLEAR_ARG];
	int allregions = _switches[ALL_REGIONS_ARG];
	int r = 0;

	/* print does not use a report */
	if (_report) {
		dm_report_free(_report);
		_report = NULL;
	}

	if (!_switches[REGION_ID_ARG] && !allregions) {
		err("Please specify a --regionid or use --allregions.");
		return 0;
	}

	if (names)
		name = names->name;
	else {
		if (!argc && !_switches[UUID_ARG] && !_switches[MAJOR_ARG])
			return _process_all(cmd, subcommand, argc, argv, 0, _stats_print);
		name = argv[0];
	}

	region_id = (uint64_t) _int_args[REGION_ID_ARG];

	dms = dm_stats_create(DM_STATS_PROGRAM_ID);

	if (!_bind_stats_device(dms, name))
		goto_out;

	if (!dm_stats_list(dms, NULL))
		goto_out;

	if (allregions && !dm_stats_get_nr_regions(dms)) {
		r = 1;
		goto out;
	}

	dm_stats_walk_do(dms) {
		if (_switches[ALL_REGIONS_ARG])
			region_id = dm_stats_get_current_region(dms);

		if (!dm_stats_region_present(dms, region_id)) {
			log_error("No such region: %"PRIu64".", region_id);
			goto out;
		}

		/*FIXME: line control for large regions */
		if (!(stbuff = dm_stats_print_region(dms, region_id, 0, 0, clear))) {
			log_error("Could not print statistics region.");
			goto out;
		}

		printf("%s", stbuff);

		dm_stats_buffer_destroy(dms, stbuff);
		dm_stats_walk_next_region(dms);

	} dm_stats_walk_while(dms);

	r = 1;

out:
	dm_stats_destroy(dms);
	return r;
}

static int _stats_report(CMD_ARGS)
{
	int r = 0;

	struct dm_task *dmt;
	char *name = NULL;

	if (_switches[PROGRAM_ID_ARG])
		_program_id = _string_args[PROGRAM_ID_ARG];

	if (_switches[ALL_PROGRAMS_ARG])
		_program_id = "";

	if (!_switches[VERBOSE_ARG] && !strcmp(subcommand, "list"))
		_stats_report_by_areas = 0;

	if (names)
		name = names->name;
	else {
		if (!argc && !_switches[UUID_ARG] && !_switches[MAJOR_ARG])
			return _process_all(cmd, subcommand, argc, argv, 0, _info);
		name = argv[0];
	}

	if (!(dmt = dm_task_create(DM_DEVICE_INFO)))
		return_0;

	if (!_set_task_device(dmt, name, 0))
		goto_out;

	if (_switches[CHECKS_ARG] && !dm_task_enable_checks(dmt))
		goto_out;

	if (!_task_run(dmt))
		goto_out;

	r = _display_info(dmt);

out:
	dm_task_destroy(dmt);

	if (!r && _report) {
		dm_report_free(_report);
		_report = NULL;
	}

	return r;
}

/*
 * Command dispatch tables and usage.
 */
static int _stats_help(CMD_ARGS);

/*
 * dmsetup stats <cmd> [options] [device_name]
 * dmstats <cmd> [options] [device_name]
 *
 *    clear [--regionid id] <device_name>
 *    create [--areas nr_areas] [--areasize size]
 *           [ [--start start] [--length len] | [--segments]]
 *           [--auxdata data] [--programid id] [<device_name>]
 *    delete [--regionid] <device_name>
 *    delete_all [--programid id]
 *    list [--programid id] [<device_name>]
 *    print [--clear] [--programid id] [--regionid id] [<device_name>]
 *    report [--interval seconds] [--count count] [--units units] [--regionid id]
 *           [--programid id] [<device>]
 */

#define AREA_OPTS "[--areas <nr_areas>] [--areasize <size>] "
#define CREATE_OPTS "[--start <start> [--length <len>]]\n\t\t" AREA_OPTS
#define ID_OPTS "[--programid <id>] [--auxdata <data> ] "
#define SELECT_OPTS "[--programid <id>] [--regionid <id>] "
#define PRINT_OPTS "[--clear] " SELECT_OPTS
#define REPORT_OPTS "[--interval <seconds>] [--count <cnt>]\n\t\t[--units <u>]" SELECT_OPTS

static struct command _stats_subcommands[] = {
	{"help", "", 0, 0, 0, 0, _stats_help},
	{"clear", "--regionid <id> [<device>]", 0, -1, 1, 0, _stats_clear},
	{"create", CREATE_OPTS "\n\t\t" ID_OPTS "[<device>]", 0, -1, 1, 0, _stats_create},
	{"delete", "--regionid <id> <device>", 1, -1, 1, 0, _stats_delete},
	{"list", "[--programid <id>] [<device>]", 0, -1, 1, 0, _stats_report},
	{"print", PRINT_OPTS "[<device>]", 0, -1, 1, 0, _stats_print},
	{"report", REPORT_OPTS "[<device>]", 0, -1, 1, 0, _stats_report},
	{"version", "", 0, -1, 1, 0, _version},
	{NULL, NULL, 0, 0, 0, 0, NULL}
};

#undef AREA_OPTS
#undef CREATE_OPTS
#undef ID_OPTS
#undef PRINT_OPTS
#undef REPORT_OPTS
#undef SELECT_OPTS

static int _dmsetup_help(CMD_ARGS);

static struct command _dmsetup_commands[] = {
	{"help", "[-c|-C|--columns]", 0, 0, 0, 0, _dmsetup_help},
	{"create", "<dev_name>\n"
	  "\t    [-j|--major <major> -m|--minor <minor>]\n"
	  "\t    [-U|--uid <uid>] [-G|--gid <gid>] [-M|--mode <octal_mode>]\n"
	  "\t    [-u|uuid <uuid>] [{--addnodeonresume|--addnodeoncreate}]\n"
	  "\t    [--notable | --table <table> | <table_file>]", 1, 2, 0, 0, _create},
	{"remove", "[-f|--force] [--deferred] <device>", 0, -1, 1, 0, _remove},
	{"remove_all", "[-f|--force]", 0, 0, 0, 0, _remove_all},
	{"suspend", "[--noflush] <device>", 0, -1, 1, 0, _suspend},
	{"resume", "<device> [{--addnodeonresume|--addnodeoncreate}]", 0, -1, 1, 0, _resume},
	{"load", "<device> [<table_file>]", 0, 2, 0, 0, _load},
	{"clear", "<device>", 0, -1, 1, 0, _clear},
	{"reload", "<device> [<table_file>]", 0, 2, 0, 0, _load},
	{"wipe_table", "<device>", 1, -1, 1, 0, _error_device},
	{"rename", "<device> [--setuuid] <new_name_or_uuid>", 1, 2, 0, 0, _rename},
	{"message", "<device> <sector> <message>", 2, -1, 0, 0, _message},
	{"ls", "[--target <target_type>] [--exec <command>] [-o options] [--tree]", 0, 0, 0, 0, _ls},
	{"info", "[<device>]", 0, -1, 1, 0, _info},
	{"deps", "[-o options] [<device>]", 0, -1, 1, 0, _deps},
	{"stats", "<command> [<options>] [<devices>]", 1, -1, 1, 1, _stats},
	{"status", "[<device>] [--noflush] [--target <target_type>]", 0, -1, 1, 0, _status},
	{"table", "[<device>] [--target <target_type>] [--showkeys]", 0, -1, 1, 0, _status},
	{"wait", "<device> [<event_nr>] [--noflush]", 0, 2, 0, 0, _wait},
	{"mknodes", "[<device>]", 0, -1, 1, 0, _mknodes},
	{"mangle", "[<device>]", 0, -1, 1, 0, _mangle},
	{"udevcreatecookie", "", 0, 0, 0, 0, _udevcreatecookie},
	{"udevreleasecookie", "[<cookie>]", 0, 1, 0, 0, _udevreleasecookie},
	{"udevflags", "<cookie>", 1, 1, 0, 0, _udevflags},
	{"udevcomplete", "<cookie>", 1, 1, 0, 0, _udevcomplete},
	{"udevcomplete_all", "<age_in_minutes>", 0, 1, 0, 0, _udevcomplete_all},
	{"udevcookies", "", 0, 0, 0, 0, _udevcookies},
	{"targets", "", 0, 0, 0, 0, _targets},
	{"version", "", 0, 0, 0, 0, _version},
	{"setgeometry", "<device> <cyl> <head> <sect> <start>", 5, 5, 0, 0, _setgeometry},
	{"splitname", "<device> [<subsystem>]", 1, 2, 0, 0, _splitname},
	{NULL, NULL, 0, 0, 0, 0, NULL}
};

/*
 * Usage and help text.
 */

static void _devmap_name_usage(FILE *out)
{
	fprintf(out, "Usage: " DEVMAP_NAME_CMD_NAME " <major> <minor>\n\n");
}

static void _stats_usage(FILE *out)
{
	int i;

	fprintf(out, "Usage:\n\n");
	fprintf(out, "%s\n", _base_commands[_base_command].name);
	fprintf(out, "        [-h|--help]\n");
	fprintf(out, "        [-v|--verbose [-v|--verbose ...]]\n");
	fprintf(out, "        [--areas <nr_areas>] [--areasize <size>]\n");
	fprintf(out, "        [--auxdata <data>] [--clear]\n");
	fprintf(out, "        [--count <count>] [--interval <seconds>]\n");
	fprintf(out, "        [-o <fields>] [-O|--sort <sort_fields>]\n");
	fprintf(out, "	      [--programid <id>]\n");
	fprintf(out, "        [--start <start>] [--length <length>]\n");
	fprintf(out, "        [--segments] [--units <units>]\n\n");

	for (i = 0; _stats_subcommands[i].name; i++)
		fprintf(out, "\t%s %s\n", _stats_subcommands[i].name, _stats_subcommands[i].help);

	fprintf(out, "<device> may be device name or -u <uuid> or "
		     "-j <major> -m <minor>\n");
	fprintf(out, "<fields> are comma-separated.  Use 'help -c' for list.\n");
	fprintf(out, "\n");
}

static void _dmsetup_usage(FILE *out)
{
	int i;

	fprintf(out, "Usage:\n\n");
	fprintf(out, "%s\n"
		"        [--version] [-h|--help [-c|-C|--columns]]\n"
		"        [-v|--verbose [-v|--verbose ...]]\n"
		"        [--checks] [--manglename <mangling_mode>]\n"
		"        [-r|--readonly] [--noopencount] [--nolockfs] [--inactive]\n"
		"        [--udevcookie [cookie]] [--noudevrules] [--noudevsync] [--verifyudev]\n"
		"        [-y|--yes] [--readahead [+]<sectors>|auto|none] [--retry]\n"
		"        [-c|-C|--columns] [-o <fields>] [-O|--sort <sort_fields>]\n"
		"        [-S|--select <selection>] [--nameprefixes] [--noheadings]\n"
		"        [--separator <separator>]\n\n",
		_base_commands[_base_command].name);

	for (i = 0; _dmsetup_commands[i].name; i++)
		fprintf(out, "\t%s %s\n", _dmsetup_commands[i].name, _dmsetup_commands[i].help);

	fprintf(out, "\n<device> may be device name or -u <uuid> or "
		     "-j <major> -m <minor>\n");
	fprintf(out, "<mangling_mode> is one of 'none', 'auto' and 'hex'.\n");
	fprintf(out, "<fields> are comma-separated.  Use 'help -c' for list.\n");
	fprintf(out, "Table_file contents may be supplied on stdin.\n");
	fprintf(out, "Options are: devno, devname, blkdevname.\n");
	fprintf(out, "Tree specific options are: ascii, utf, vt100; compact, inverted, notrunc;\n"
		     "                           blkdevname, [no]device, active, open, rw and uuid.\n");
	fprintf(out, "\n");
}

static void _losetup_usage(FILE *out)
{
	fprintf(out, "Usage:\n\n");
	fprintf(out, "%s [-d|-a] [-e encryption] "
		     "[-o offset] [-f|loop_device] [file]\n\n",
		     _base_commands[_base_command].name);
}

static void _usage(FILE *out)
{
	switch (_base_commands[_base_command].type) {
	case DMSETUP_TYPE:
		return _dmsetup_usage(out);
	case LOSETUP_TYPE:
		return _losetup_usage(out);
	case STATS_TYPE:
		return _stats_usage(out);
	case DEVMAP_NAME_TYPE:
		return _devmap_name_usage(out);
	}
}

static int _stats_help(CMD_ARGS)
{
	_usage(stderr);

	if (_switches[COLS_ARG] || (argc && !strcmp(argv[0], "report"))) {
		_switches[OPTIONS_ARG] = 1;
		_string_args[OPTIONS_ARG] = (char *) "help";
		_switches[SORT_ARG] = 0;

		if (_report) {
			dm_report_free(_report);
			_report = NULL;
		}

		(void) _report_init(cmd, "help");
		if (_report) {
			dm_report_free(_report);
			_report = NULL;
		}
	}

	return 1;
}

static int _dmsetup_help(CMD_ARGS)
{
	_usage(stderr);

	if (_switches[COLS_ARG]) {
		_switches[OPTIONS_ARG] = 1;
		_string_args[OPTIONS_ARG] = (char *) "help";
		_switches[SORT_ARG] = 0;

		if (_report) {
			dm_report_free(_report);
			_report = NULL;
		}
		(void) _report_init(cmd, "");
		if (_report) {
			dm_report_free(_report);
			_report = NULL;
		}
	}

	return 1;
}

static const struct command *_find_command(const struct command *commands,
					   const char *name)
{
	int i;

	for (i = 0; commands[i].name; i++)
		if (!strcmp(commands[i].name, name))
			return commands + i;

	return NULL;
}

static const struct command *_find_dmsetup_command(const char *name)
{
	return _find_command(_dmsetup_commands, name);
}

static const struct command *_find_stats_subcommand(const char *name)
{
	return _find_command(_stats_subcommands, name);
}

static int _stats(CMD_ARGS)
{
	const struct command *stats_cmd;

	if (!(stats_cmd = _find_stats_subcommand(subcommand))) {
		log_error("Unknown stats command.");
		_stats_help(stats_cmd, NULL, argc, argv, NULL, multiple_devices);
		return 0;
	}

	if (_switches[ALL_PROGRAMS_ARG] && _switches[PROGRAM_ID_ARG]) {
		log_error("Please supply one of --allprograms and --programid");
		return 0;
	}

	if (_switches[ALL_REGIONS_ARG] && _switches[REGION_ID_ARG]) {
		log_error("Please supply one of --allregions and --regionid");
		return 0;
	}

	/*
	 * Pass the sub-command through to allow a single function to be
	 * used to implement several distinct sub-commands (e.g. 'report'
	 * and 'list' share a single implementation.
	 */
	if (!stats_cmd->fn(stats_cmd, subcommand, argc, argv, NULL,
			   multiple_devices))
		return_0;

	return 1;
}

static int _process_tree_options(const char *options)
{
	const char *s, *end;
	struct winsize winsz;
	size_t len;

	/* Symbol set default */
	if (!strcmp(nl_langinfo(CODESET), "UTF-8"))
		_tsym = &_tsym_utf;
	else
		_tsym = &_tsym_ascii;

	/* Default */
	_tree_switches[TR_DEVICE] = 1;
	_tree_switches[TR_TRUNCATE] = 1;

	/* parse */
	for (s = options; s && *s; s++) {
		len = 0;
		for (end = s; *end && *end != ','; end++, len++)
			;
		if (!strncmp(s, "device", len))
			_tree_switches[TR_DEVICE] = 1;
		else if (!strncmp(s, "blkdevname", len))
			_tree_switches[TR_BLKDEVNAME] = 1;
		else if (!strncmp(s, "nodevice", len))
			_tree_switches[TR_DEVICE] = 0;
		else if (!strncmp(s, "status", len))
			_tree_switches[TR_STATUS] = 1;
		else if (!strncmp(s, "table", len))
			_tree_switches[TR_TABLE] = 1;
		else if (!strncmp(s, "active", len))
			_tree_switches[TR_ACTIVE] = 1;
		else if (!strncmp(s, "open", len))
			_tree_switches[TR_OPENCOUNT] = 1;
		else if (!strncmp(s, "uuid", len))
			_tree_switches[TR_UUID] = 1;
		else if (!strncmp(s, "rw", len))
			_tree_switches[TR_RW] = 1;
		else if (!strncmp(s, "utf", len))
			_tsym = &_tsym_utf;
		else if (!strncmp(s, "vt100", len))
			_tsym = &_tsym_vt100;
		else if (!strncmp(s, "ascii", len))
			_tsym = &_tsym_ascii;
		else if (!strncmp(s, "inverted", len))
			_tree_switches[TR_BOTTOMUP] = 1;
		else if (!strncmp(s, "compact", len))
			_tree_switches[TR_COMPACT] = 1;
		else if (!strncmp(s, "notrunc", len))
			_tree_switches[TR_TRUNCATE] = 0;
		else {
			fprintf(stderr, "Tree options not recognised: %s\n", s);
			return 0;
		}
		if (!*end)
			break;
		s = end;
	}

	/* Truncation doesn't work well with vt100 drawing char */
	if (_tsym != &_tsym_vt100)
		if (ioctl(1, (unsigned long) TIOCGWINSZ, &winsz) >= 0 && winsz.ws_col > 3)
			_termwidth = winsz.ws_col - 3;

	return 1;
}

/*
 * Returns the full absolute path, or NULL if the path could
 * not be resolved.
 */
static char *_get_abspath(const char *path)
{
	char *_path;

#ifdef HAVE_CANONICALIZE_FILE_NAME
	_path = canonicalize_file_name(path);
#else
	/* FIXME Provide alternative */
	log_error(INTERNAL_ERROR "Unimplemented _get_abspath.");
	_path = NULL;
#endif
	return _path;
}

static char *parse_loop_device_name(const char *dev, const char *dev_dir)
{
	char *buf;
	char *device = NULL;

	if (!(buf = dm_malloc(PATH_MAX)))
		return_NULL;

	if (dev[0] == '/') {
		if (!(device = _get_abspath(dev)))
			goto_bad;

		if (strncmp(device, dev_dir, strlen(dev_dir)))
			goto_bad;

		/* If dev_dir does not end in a slash, ensure that the
		   following byte in the device string is "/".  */
		if (dev_dir[strlen(dev_dir) - 1] != '/' &&
		    device[strlen(dev_dir)] != '/')
			goto_bad;

		if (!dm_strncpy(buf, strrchr(device, '/') + 1, PATH_MAX))
			goto_bad;
		dm_free(device);
	} else {
		/* check for device number */
		if (strncmp(dev, "loop", sizeof("loop") - 1))
			goto_bad;

		if (!dm_strncpy(buf, dev, PATH_MAX))
			goto_bad;
	}

	return buf;
bad:
	dm_free(device);
	dm_free(buf);

	return NULL;
}

/*
 *  create a table for a mapped device using the loop target.
 */
static int _loop_table(char *table, size_t tlen, char *file,
		       char *dev __attribute__((unused)), off_t off)
{
	struct stat fbuf;
	off_t size, sectors;
	int fd = -1;
#ifdef HAVE_SYS_STATVFS_H
	struct statvfs fsbuf;
	off_t blksize;
#endif

	if (!_switches[READ_ONLY])
		fd = open(file, O_RDWR);

	if (fd < 0) {
		_switches[READ_ONLY]++;
		fd = open(file, O_RDONLY);
	}

	if (fd < 0)
		goto_bad;

	if (fstat(fd, &fbuf))
		goto_bad;

	size = (fbuf.st_size - off);
	sectors = size >> SECTOR_SHIFT;

	if (_switches[VERBOSE_ARG])
		fprintf(stderr, LOSETUP_CMD_NAME ": set loop size to %llukB "
			"(%llu sectors)\n", (long long unsigned) sectors >> 1,
			(long long unsigned) sectors);

#ifdef HAVE_SYS_STATVFS_H
	if (fstatvfs(fd, &fsbuf))
		goto_bad;

	/* FIXME Fragment size currently unused */
	blksize = fsbuf.f_frsize;
#endif

	if (close(fd))
		log_sys_error("close", file);

	if (dm_snprintf(table, tlen, "%llu %llu loop %s %llu\n", 0ULL,
			(long long unsigned)sectors, file, (long long unsigned)off) < 0)
		return_0;

	if (_switches[VERBOSE_ARG] > 1)
		fprintf(stderr, "Table: %s\n", table);

	return 1;

bad:
	if (fd > -1 && close(fd))
		log_sys_error("close", file);

	return_0;
}

static int _process_losetup_switches(const char *base, int *argcp, char ***argvp,
				     const char *dev_dir)
{
	int c;
	int encrypt_loop = 0, delete = 0, find = 0, show_all = 0;
	char *device_name = NULL;
	char *loop_file = NULL;
	off_t offset = 0;

#ifdef HAVE_GETOPTLONG
	static struct option long_options[] = {
		{0, 0, 0, 0}
	};
#endif

	optarg = 0;
	optind = OPTIND_INIT;
	while ((c = GETOPTLONG_FN(*argcp, *argvp, "ade:fo:v",
				  long_options, NULL)) != -1 ) {
		if (c == ':' || c == '?')
			return_0;
		if (c == 'a')
			show_all++;
		if (c == 'd')
			delete++;
		if (c == 'e')
			encrypt_loop++;
		if (c == 'f')
			find++;
		if (c == 'o')
			offset = atoi(optarg);
		if (c == 'v')
			_switches[VERBOSE_ARG]++;
	}

	*argvp += optind ;
	*argcp -= optind ;

	if (encrypt_loop){
		fprintf(stderr, "%s: Sorry, cryptoloop is not yet implemented "
				"in this version.\n", base);
		return 0;
	}

	if (show_all) {
		fprintf(stderr, "%s: Sorry, show all is not yet implemented "
				"in this version.\n", base);
		return 0;
	}

	if (find) {
		fprintf(stderr, "%s: Sorry, find is not yet implemented "
				"in this version.\n", base);
		if (!*argcp)
			return 0;
	}

	if (!*argcp) {
		fprintf(stderr, "%s: Please specify loop_device.\n", base);
		_usage(stderr);
		return 0;
	}

	if (!(device_name = parse_loop_device_name((*argvp)[0], dev_dir))) {
		fprintf(stderr, "%s: Could not parse loop_device %s\n",
			base, (*argvp)[0]);
		_usage(stderr);
		return 0;
	}

	if (delete) {
		*argcp = 1;

		(*argvp)[0] = device_name;
		_command = "remove";

		return 1;
	}

	if (*argcp != 2) {
		fprintf(stderr, "%s: Too few arguments\n", base);
		_usage(stderr);
		dm_free(device_name);
		return 0;
	}

	/* FIXME move these to make them available to native dmsetup */
	if (!(loop_file = _get_abspath((*argvp)[(find) ? 0 : 1]))) {
		fprintf(stderr, "%s: Could not parse loop file name %s\n",
			base, (*argvp)[1]);
		_usage(stderr);
		dm_free(device_name);
		return 0;
	}

	_table = dm_malloc(LOOP_TABLE_SIZE);
	if (!_table ||
	    !_loop_table(_table, (size_t) LOOP_TABLE_SIZE, loop_file, device_name, offset)) {
		fprintf(stderr, "Could not build device-mapper table for %s\n", (*argvp)[0]);
		dm_free(device_name);
		return 0;
	}
	_switches[TABLE_ARG]++;

	_command = "create";
	(*argvp)[0] = device_name ;
	*argcp = 1;

	return 1;
}

static int _process_options(const char *options)
{
	const char *s, *end;
	size_t len;

	/* Tree options are processed separately. */
	if (_switches[TREE_ARG])
		return _process_tree_options(_string_args[OPTIONS_ARG]);

	/* Column options are processed separately by _report_init (called later). */
	if (_switches[COLS_ARG])
		return 1;

	/* No options specified. */
	if (!_switches[OPTIONS_ARG])
		return 1;

	/* Set defaults. */
	_dev_name_type = DN_DEVNO;

	/* Parse. */
	for (s = options; s && *s; s++) {
		len = 0;
		for (end = s; *end && *end != ','; end++, len++)
			;
		if (!strncmp(s, "devno", len))
			_dev_name_type = DN_DEVNO;
		else if (!strncmp(s, "blkdevname", len))
			_dev_name_type = DN_BLK;
		else if (!strncmp(s, "devname", len))
			_dev_name_type = DN_MAP;
		else {
			fprintf(stderr, "Option not recognised: %s\n", s);
			return 0;
		}

		if (!*end)
			break;
		s = end;
	}

	return 1;
}

static int _process_switches(int *argcp, char ***argvp, const char *dev_dir)
{
	const char *base;
	char *namebase, *s;
	static int ind;
	int c, r, i;

#ifdef HAVE_GETOPTLONG
	static struct option long_options[] = {
		{"readonly", 0, &ind, READ_ONLY},
		{"alldevices", 0, &ind, ALL_DEVICES_ARG},
		{"allprograms", 0, &ind, ALL_PROGRAMS_ARG},
		{"allregions", 0, &ind, ALL_REGIONS_ARG},
		{"areas", 1, &ind, AREAS_ARG},
		{"areasize", 1, &ind, AREA_SIZE_ARG},
		{"auxdata", 1, &ind, AUX_DATA_ARG},
		{"bounds", 1, &ind, BOUNDS_ARG},
		{"checks", 0, &ind, CHECKS_ARG},
		{"clear", 0, &ind, CLEAR_ARG},
		{"columns", 0, &ind, COLS_ARG},
		{"count", 1, &ind, COUNT_ARG},
		{"deferred", 0, &ind, DEFERRED_ARG},
		{"select", 1, &ind, SELECT_ARG},
		{"exec", 1, &ind, EXEC_ARG},
		{"force", 0, &ind, FORCE_ARG},
		{"gid", 1, &ind, GID_ARG},
		{"help", 0, &ind, HELP_ARG},
		{"histogram", 0, &ind, HISTOGRAM_ARG},
		{"inactive", 0, &ind, INACTIVE_ARG},
		{"interval", 1, &ind, INTERVAL_ARG},
		{"length", 1, &ind, LENGTH_ARG},
		{"manglename", 1, &ind, MANGLENAME_ARG},
		{"major", 1, &ind, MAJOR_ARG},
		{"minor", 1, &ind, MINOR_ARG},
		{"mode", 1, &ind, MODE_ARG},
		{"nameprefixes", 0, &ind, NAMEPREFIXES_ARG},
		{"noflush", 0, &ind, NOFLUSH_ARG},
		{"noheadings", 0, &ind, NOHEADINGS_ARG},
		{"nolockfs", 0, &ind, NOLOCKFS_ARG},
		{"noopencount", 0, &ind, NOOPENCOUNT_ARG},
		{"nosuffix", 0, &ind, NOSUFFIX_ARG},
		{"notable", 0, &ind, NOTABLE_ARG},
		{"notimesuffix", 0, &ind, NOTIMESUFFIX_ARG},
		{"udevcookie", 1, &ind, UDEVCOOKIE_ARG},
		{"noudevrules", 0, &ind, NOUDEVRULES_ARG},
		{"noudevsync", 0, &ind, NOUDEVSYNC_ARG},
		{"options", 1, &ind, OPTIONS_ARG},
		{"precise", 0, &ind, PRECISE_ARG},
		{"programid", 1, &ind, PROGRAM_ID_ARG},
		{"raw", 0, &ind, RAW_ARG},
		{"readahead", 1, &ind, READAHEAD_ARG},
		{"regionid", 1, &ind, REGION_ID_ARG},
		{"relative", 0, &ind, RELATIVE_ARG},
		{"retry", 0, &ind, RETRY_ARG},
		{"rows", 0, &ind, ROWS_ARG},
		{"segments", 0, &ind, SEGMENTS_ARG},
		{"separator", 1, &ind, SEPARATOR_ARG},
		{"setuuid", 0, &ind, SETUUID_ARG},
		{"showkeys", 0, &ind, SHOWKEYS_ARG},
		{"sort", 1, &ind, SORT_ARG},
		{"start", 1, &ind, START_ARG},
		{"table", 1, &ind, TABLE_ARG},
		{"target", 1, &ind, TARGET_ARG},
		{"tree", 0, &ind, TREE_ARG},
		{"uid", 1, &ind, UID_ARG},
		{"units", 1, &ind, UNITS_ARG},
		{"uuid", 1, &ind, UUID_ARG},
		{"unbuffered", 0, &ind, UNBUFFERED_ARG},
		{"unquoted", 0, &ind, UNQUOTED_ARG},
		{"verbose", 1, &ind, VERBOSE_ARG},
		{"verifyudev", 0, &ind, VERIFYUDEV_ARG},
		{"version", 0, &ind, VERSION_ARG},
		{"yes", 0, &ind, YES_ARG},
		{"addnodeonresume", 0, &ind, ADD_NODE_ON_RESUME_ARG},
		{"addnodeoncreate", 0, &ind, ADD_NODE_ON_CREATE_ARG},
		{0, 0, 0, 0}
	};
#else
	struct option long_options;
#endif

	/*
	 * Zero all the index counts.
	 */
	memset(&_switches, 0, sizeof(_switches));
	memset(&_int_args, 0, sizeof(_int_args));
	_read_ahead_flags = 0;

	if (!(namebase = strdup((*argvp)[0]))) {
		fprintf(stderr, "Failed to duplicate name.\n");
		return 0;
	}

	base = dm_basename(namebase);

	i = 0;
	do {
		if (!strcmp(base, _base_commands[i].name)) {
			_base_command = _base_commands[i].command;
			_base_command_type = _base_commands[i].type;
			break;
		}
	} while (++i < _num_base_commands);

	free(namebase);

	if (_base_command_type == DEVMAP_NAME_TYPE) {
		_switches[COLS_ARG]++;
		_switches[NOHEADINGS_ARG]++;
		_switches[OPTIONS_ARG]++;
		_switches[MAJOR_ARG]++;
		_switches[MINOR_ARG]++;
		_string_args[OPTIONS_ARG] = (char *) "name";

		if (*argcp == 3) {
			_int_args[MAJOR_ARG] = atoi((*argvp)[1]);
			_int_args[MINOR_ARG] = atoi((*argvp)[2]);
			*argcp -= 2;
			*argvp += 2;
		} else if ((*argcp == 2) &&
			   (2 == sscanf((*argvp)[1], "%i:%i",
					&_int_args[MAJOR_ARG],
					&_int_args[MINOR_ARG]))) {
			*argcp -= 1;
			*argvp += 1;
		} else {
			_usage(stderr);
			return 0;
		}

		_command = "info";
		(*argvp)++;
		(*argcp)--;

		return 1;
	}

	if (_base_command_type == LOSETUP_TYPE) {
		r = _process_losetup_switches(_base_commands[_base_command].name, argcp, argvp, dev_dir);
		return r;
	}

	optarg = 0;
	optind = OPTIND_INIT;
	while ((ind = -1, c = GETOPTLONG_FN(*argcp, *argvp, "cCfG:hj:m:M:no:O:rS:u:U:vy",
					    long_options, NULL)) != -1) {
		if (ind == ALL_DEVICES_ARG)
			_switches[ALL_DEVICES_ARG]++;
		if (ind == ALL_PROGRAMS_ARG)
			_switches[ALL_PROGRAMS_ARG]++;
		if (ind == ALL_REGIONS_ARG)
			_switches[ALL_REGIONS_ARG]++;
		if (ind == AREAS_ARG) {
			_switches[AREAS_ARG]++;
			_int_args[AREAS_ARG] = atoi(optarg);
		}
		if (ind == AREA_SIZE_ARG) {
			_switches[AREA_SIZE_ARG]++;
			_string_args[AREA_SIZE_ARG] = optarg;
		}
		if (ind == AUX_DATA_ARG) {
			_switches[AUX_DATA_ARG]++;
			_string_args[AUX_DATA_ARG] = optarg;
		}
		if (c == ':' || c == '?')
			return_0;
		if (c == 'h' || ind == HELP_ARG)
			_switches[HELP_ARG]++;
		if (ind == BOUNDS_ARG) {
			_switches[BOUNDS_ARG]++;
			_string_args[BOUNDS_ARG] = optarg;
		}
		if (ind == CLEAR_ARG)
			_switches[CLEAR_ARG]++;
		if (c == 'c' || c == 'C' || ind == COLS_ARG)
			_switches[COLS_ARG]++;
		if (c == 'f' || ind == FORCE_ARG)
			_switches[FORCE_ARG]++;
		if (c == 'r' || ind == READ_ONLY)
			_switches[READ_ONLY]++;
		if (ind == HISTOGRAM_ARG)
			_switches[HISTOGRAM_ARG]++;
		if (ind == LENGTH_ARG) {
			_switches[LENGTH_ARG]++;
			_string_args[LENGTH_ARG] = optarg;
		}
		if (c == 'j' || ind == MAJOR_ARG) {
			_switches[MAJOR_ARG]++;
			_int_args[MAJOR_ARG] = atoi(optarg);
		}
		if (c == 'm' || ind == MINOR_ARG) {
			_switches[MINOR_ARG]++;
			_int_args[MINOR_ARG] = atoi(optarg);
		}
		if (ind == NOSUFFIX_ARG)
			_switches[NOSUFFIX_ARG]++;
		if (c == 'n' || ind == NOTABLE_ARG)
			_switches[NOTABLE_ARG]++;
		if (ind == NOTIMESUFFIX_ARG)
			_switches[NOTIMESUFFIX_ARG]++;
		if (c == 'o' || ind == OPTIONS_ARG) {
			_switches[OPTIONS_ARG]++;
			_string_args[OPTIONS_ARG] = optarg;
		}
		if (ind == PROGRAM_ID_ARG) {
			_switches[PROGRAM_ID_ARG]++;
			_string_args[PROGRAM_ID_ARG] = optarg;
		}
		if (ind == PRECISE_ARG)
			_switches[PRECISE_ARG]++;
		if (ind == RAW_ARG)
			_switches[RAW_ARG]++;
		if (ind == REGION_ID_ARG) {
			_switches[REGION_ID_ARG]++;
			_int_args[REGION_ID_ARG] = atoi(optarg);
		}
		if (ind == RELATIVE_ARG)
			_switches[RELATIVE_ARG]++;
		if (ind == SEPARATOR_ARG) {
			_switches[SEPARATOR_ARG]++;
			_string_args[SEPARATOR_ARG] = optarg;
		}
		if (ind == UNITS_ARG) {
			_switches[UNITS_ARG]++;
			_string_args[UNITS_ARG] = optarg;
		}
		if (c == 'O' || ind == SORT_ARG) {
			_switches[SORT_ARG]++;
			_string_args[SORT_ARG] = optarg;
		}
		if (c == 'S' || ind == SELECT_ARG) {
			_switches[SELECT_ARG]++;
			_string_args[SELECT_ARG] = optarg;
		}
		if (ind == START_ARG) {
			_switches[START_ARG]++;
			_string_args[START_ARG] = optarg;
		}
		if (c == 'v' || ind == VERBOSE_ARG)
			_switches[VERBOSE_ARG]++;
		if (c == 'u' || ind == UUID_ARG) {
			_switches[UUID_ARG]++;
			_uuid = optarg;
		}
		if (c == 'y' || ind == YES_ARG)
			_switches[YES_ARG]++;
		if (ind == ADD_NODE_ON_RESUME_ARG)
			_switches[ADD_NODE_ON_RESUME_ARG]++;
		if (ind == ADD_NODE_ON_CREATE_ARG)
			_switches[ADD_NODE_ON_CREATE_ARG]++;
		if (ind == CHECKS_ARG)
			_switches[CHECKS_ARG]++;
		if (ind == COUNT_ARG) {
			_switches[COUNT_ARG]++;
			_int_args[COUNT_ARG] = atoi(optarg);
			if (_int_args[COUNT_ARG] < 0) {
				log_error("Count must be zero or greater.");
				return 0;
			}
		}
		if (ind == UDEVCOOKIE_ARG) {
			_switches[UDEVCOOKIE_ARG]++;
			_udev_cookie = _get_cookie_value(optarg);
		}
		if (ind == NOUDEVRULES_ARG)
			_switches[NOUDEVRULES_ARG]++;
		if (ind == NOUDEVSYNC_ARG)
			_switches[NOUDEVSYNC_ARG]++;
		if (ind == VERIFYUDEV_ARG)
			_switches[VERIFYUDEV_ARG]++;
		if (c == 'G' || ind == GID_ARG) {
			_switches[GID_ARG]++;
			_int_args[GID_ARG] = atoi(optarg);
		}
		if (c == 'U' || ind == UID_ARG) {
			_switches[UID_ARG]++;
			_int_args[UID_ARG] = atoi(optarg);
		}
		if (c == 'M' || ind == MODE_ARG) {
			_switches[MODE_ARG]++;
			/* FIXME Accept modes as per chmod */
			_int_args[MODE_ARG] = (int) strtol(optarg, NULL, 8);
		}
		if (ind == DEFERRED_ARG)
			_switches[DEFERRED_ARG]++;
		if (ind == EXEC_ARG) {
			_switches[EXEC_ARG]++;
			_command_to_exec = optarg;
		}
		if (ind == TARGET_ARG) {
			_switches[TARGET_ARG]++;
			_target = optarg;
		}
		if (ind == SEGMENTS_ARG)
			_switches[SEGMENTS_ARG]++;
		if (ind == INACTIVE_ARG)
		       _switches[INACTIVE_ARG]++;
		if (ind == INTERVAL_ARG) {
			_switches[INTERVAL_ARG]++;
			_int_args[INTERVAL_ARG] = atoi(optarg);
			if (_int_args[INTERVAL_ARG] <= 0) {
				log_error("Interval must be a positive integer.");
				return 0;
			}
		}
		if (ind == MANGLENAME_ARG) {
			_switches[MANGLENAME_ARG]++;
			if (!strcasecmp(optarg, "none"))
				_int_args[MANGLENAME_ARG] = DM_STRING_MANGLING_NONE;
			else if (!strcasecmp(optarg, "auto"))
				_int_args[MANGLENAME_ARG] = DM_STRING_MANGLING_AUTO;
			else if (!strcasecmp(optarg, "hex"))
				_int_args[MANGLENAME_ARG] = DM_STRING_MANGLING_HEX;
			else {
				log_error("Unknown name mangling mode");
				return 0;
			}
			dm_set_name_mangling_mode((dm_string_mangling_t) _int_args[MANGLENAME_ARG]);
		}
		if (ind == NAMEPREFIXES_ARG)
			_switches[NAMEPREFIXES_ARG]++;
		if (ind == NOFLUSH_ARG)
			_switches[NOFLUSH_ARG]++;
		if (ind == NOHEADINGS_ARG)
			_switches[NOHEADINGS_ARG]++;
		if (ind == NOLOCKFS_ARG)
			_switches[NOLOCKFS_ARG]++;
		if (ind == NOOPENCOUNT_ARG)
			_switches[NOOPENCOUNT_ARG]++;
		if (ind == READAHEAD_ARG) {
			_switches[READAHEAD_ARG]++;
			if (!strcasecmp(optarg, "auto"))
				_int_args[READAHEAD_ARG] = DM_READ_AHEAD_AUTO;
			else if (!strcasecmp(optarg, "none"))
				_int_args[READAHEAD_ARG] = DM_READ_AHEAD_NONE;
			else {
				for (s = optarg; isspace(*s); s++)
					;
				if (*s == '+')
					_read_ahead_flags = DM_READ_AHEAD_MINIMUM_FLAG;
				_int_args[READAHEAD_ARG] = atoi(optarg);
				if (_int_args[READAHEAD_ARG] < -1) {
					log_error("Negative read ahead value "
						  "(%d) is not understood.",
						  _int_args[READAHEAD_ARG]);
					return 0;
				}
			}
		}
		if (ind == RETRY_ARG)
			_switches[RETRY_ARG]++;
		if (ind == ROWS_ARG)
			_switches[ROWS_ARG]++;
		if (ind == SETUUID_ARG)
			_switches[SETUUID_ARG]++;
		if (ind == SHOWKEYS_ARG)
			_switches[SHOWKEYS_ARG]++;
		if (ind == TABLE_ARG) {
			_switches[TABLE_ARG]++;
			if (!(_table = dm_strdup(optarg))) {
				log_error("Could not allocate memory for table string.");
				return 0;
			}
		}
		if (ind == TREE_ARG)
			_switches[TREE_ARG]++;
		if (ind == UNQUOTED_ARG)
			_switches[UNQUOTED_ARG]++;
		if (ind == VERSION_ARG)
			_switches[VERSION_ARG]++;
	}

	if (_switches[VERBOSE_ARG] > 1) {
		dm_log_init_verbose(_switches[VERBOSE_ARG] - 1);
		if (_switches[VERBOSE_ARG] > 2) {
			if (!(_initial_timestamp = dm_timestamp_alloc()))
				stack;
			else if (!dm_timestamp_get(_initial_timestamp))
				stack;
			else
				log_debug("Timestamp:       0.000000000 seconds");
		}
	}

	if ((_switches[MAJOR_ARG] && !_switches[MINOR_ARG]) ||
	    (!_switches[MAJOR_ARG] && _switches[MINOR_ARG])) {
		fprintf(stderr, "Please specify both major number and "
				"minor number.\n");
		return 0;
	}

	if (_switches[TABLE_ARG] && _switches[NOTABLE_ARG]) {
		fprintf(stderr, "--table and --notable are incompatible.\n");
		return 0;
	}

	if (_switches[ADD_NODE_ON_RESUME_ARG] && _switches[ADD_NODE_ON_CREATE_ARG]) {
		fprintf(stderr, "--addnodeonresume and --addnodeoncreate are incompatible.\n");
		return 0;
	}

	*argvp += optind;
	*argcp -= optind;

	if (!*argcp)
		_command = NULL;
	else if (!strcmp((*argvp)[0], "stats")) {
		_base_command = DMSETUP_STATS_CMD;
		_base_command_type = STATS_TYPE;
		_command = "stats";
		(*argvp)++;
		(*argcp)--;
	} else if (_base_command == DMSTATS_CMD) {
		_command = "stats";
	} else if (*argcp) {
		_command = (*argvp)[0];
		(*argvp)++;
		(*argcp)--;
	}

	return 1;
}

static int _perform_command_for_all_repeatable_args(CMD_ARGS)
{
	do {
		if (!cmd->fn(cmd, subcommand, argc, argv++, NULL, multiple_devices)) {
			fprintf(stderr, "Command failed\n");
			return 0;
		}
	} while (cmd->repeatable_cmd && argc-- > 1);

	return 1;
}

static int _do_report_wait(void)
{
	return _do_timer_wait();
}

int main(int argc, char **argv)
{
	int ret = 1, r;
	const char *dev_dir;
	const struct command *cmd;
	const char *subcommand = NULL;
	int multiple_devices;

	(void) setlocale(LC_ALL, "");

	dev_dir = getenv (DM_DEV_DIR_ENV_VAR_NAME);
	if (dev_dir && *dev_dir) {
		if (!dm_set_dev_dir(dev_dir)) {
			fprintf(stderr, "Invalid DM_DEV_DIR environment variable value.\n");
			goto out;
		}
	} else
		dev_dir = DEFAULT_DM_DEV_DIR;

	if (!_process_switches(&argc, &argv, dev_dir)) {
		fprintf(stderr, "Couldn't process command line.\n");
		goto out;
	}

	if (_switches[HELP_ARG]) {
		switch (_base_command_type) {
		case STATS_TYPE:
			if ((cmd = _find_stats_subcommand("help")))
				goto doit;
			goto unknown;
		default:
			if ((cmd = _find_dmsetup_command("help")))
				goto doit;
			goto unknown;
		}
	}

	if (_switches[VERSION_ARG]) {
		switch (_base_command_type) {
		case STATS_TYPE:
			if ((cmd = _find_stats_subcommand("version")))
				goto doit;
			goto unknown;
		default:
			if ((cmd = _find_dmsetup_command("version")))
				goto doit;
			goto unknown;
		}
	}

	if (!_command) {
		_usage(stderr);
		goto out;
	}

	if (!(cmd = _find_dmsetup_command(_command))) {
unknown:
		fprintf(stderr, "Unknown command\n");
		_usage(stderr);
		goto out;
	}

	if (argc < cmd->min_args ||
	    (cmd->max_args >= 0 && argc > cmd->max_args)) {
		fprintf(stderr, "Incorrect number of arguments\n");
		_usage(stderr);
		goto out;
	}

	if (!_switches[COLS_ARG] && !strcmp(cmd->name, "splitname"))
		_switches[COLS_ARG]++;

	if (!strcmp(cmd->name, "stats")) {
		_switches[COLS_ARG]++;
		if (!_switches[UNITS_ARG]) {
			_switches[UNITS_ARG]++;
			_string_args[UNITS_ARG] = (char *) "h";
		}
	}

	if (!strcmp(cmd->name, "mangle"))
		dm_set_name_mangling_mode(DM_STRING_MANGLING_NONE);

	if (!_process_options(_string_args[OPTIONS_ARG])) {
		fprintf(stderr, "Couldn't process command line.\n");
		goto out;
	}

#ifdef UDEV_SYNC_SUPPORT
	if (!_set_up_udev_support(dev_dir))
		goto_out;
#endif

	/*
	 * Extract subcommand?
	 * dmsetup <command> <subcommand> [args...]
	 */
	if (cmd->has_subcommands) {
		subcommand = argv[0];
		argc--, argv++;
	} else
		subcommand = (char *) "";

	if (_switches[COLS_ARG] && !_report_init(cmd, subcommand))
		goto_out;

	if (_switches[COUNT_ARG])
		_count = ((uint32_t)_int_args[COUNT_ARG]) ? : UINT32_MAX;
	else if (_switches[INTERVAL_ARG])
		_count = UINT32_MAX;

	if (_switches[UNITS_ARG]) {
		_disp_factor = _factor_from_units(_string_args[UNITS_ARG],
						  &_disp_units);
		if (!_disp_factor) {
			log_error("Invalid --units argument.");
			goto out;
		}
	}

	/* Start interval timer. */
	if (_count > 1)
		if (!_start_timer())
			goto_out;

doit:
	multiple_devices = (cmd->repeatable_cmd && argc != 1 &&
			    (argc || (!_switches[UUID_ARG] && !_switches[MAJOR_ARG])));

	do {
		r = _perform_command_for_all_repeatable_args(cmd, subcommand, argc, argv, NULL, multiple_devices);
		if (_report) {
			/* only output headings for repeating reports */
			if (_int_args[COUNT_ARG] != 1 && !dm_report_is_empty(_report))
				dm_report_column_headings(_report);
			dm_report_output(_report);

			if (_count > 1 && r) {
				printf("\n");
				/* wait for --interval and update timestamps */
				if (!_do_report_wait())
					goto_out;
			}
		}

		if (!r)
			goto_out;
	} while (--_count);

	/* Success */
	ret = 0;

out:
	if (_report)
		dm_report_free(_report);

	if (_dtree)
		dm_tree_free(_dtree);

	dm_free(_table);

	if (_initial_timestamp)
		dm_timestamp_destroy(_initial_timestamp);

	return ret;
}
