/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2012 Red Hat, Inc. All rights reserved.
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

#include "lvm2cmdline.h"
#include "label.h"
#include "lvm-version.h"
#include "lvmlockd.h"

#include "stub.h"
#include "last-path-component.h"

#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/resource.h>
#include <dirent.h>
#include <paths.h>
#include <locale.h>

#ifdef HAVE_VALGRIND
#include <valgrind.h>
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

/*
 * Table of valid switches
 */
static struct arg_props _arg_props[ARG_COUNT + 1] = {
#define arg(a, b, c, d, e) {b, "", "--" c, d, e},
#include "args.h"
#undef arg
};

static struct cmdline_context _cmdline;

/* Command line args */
unsigned arg_count(const struct cmd_context *cmd, int a)
{
	return cmd->arg_values[a].count;
}

unsigned grouped_arg_count(const struct arg_values *av, int a)
{
	return av[a].count;
}

unsigned arg_is_set(const struct cmd_context *cmd, int a)
{
	return arg_count(cmd, a) ? 1 : 0;
}

int arg_from_list_is_set(const struct cmd_context *cmd, const char *err_found, ...)
{
	int arg;
	va_list ap;

	va_start(ap, err_found);
	while ((arg = va_arg(ap, int)) != -1 && !arg_count(cmd, arg))
		/* empty */;
	va_end(ap);

	if (arg == -1)
		return 0;

	if (err_found)
		log_error("%s %s.", arg_long_option_name(arg), err_found);

	return 1;
}

int arg_outside_list_is_set(const struct cmd_context *cmd, const char *err_found, ...)
{
	int i, arg;
	va_list ap;

	for (i = 0; i < ARG_COUNT; ++i) {
		switch (i) {
		/* skip common options */
		case commandprofile_ARG:
		case config_ARG:
		case debug_ARG:
		case driverloaded_ARG:
		case help2_ARG:
		case help_ARG:
		case profile_ARG:
		case quiet_ARG:
		case verbose_ARG:
		case version_ARG:
		case yes_ARG:
			continue;
		}
		if (!arg_count(cmd, i))
			continue; /* unset */
		va_start(ap, err_found);
		while (((arg = va_arg(ap, int)) != -1) && (arg != i))
			/* empty */;
		va_end(ap);

		if (arg == i)
			continue; /* set and in list */

		if (err_found)
			log_error("Option %s %s.", arg_long_option_name(i), err_found);

		return 1;
	}

	return 0;
}

int arg_from_list_is_negative(const struct cmd_context *cmd, const char *err_found, ...)
{
	int arg, ret = 0;
	va_list ap;

	va_start(ap, err_found);
	while ((arg = va_arg(ap, int)) != -1)
		if (arg_sign_value(cmd, arg, SIGN_NONE) == SIGN_MINUS) {
			if (err_found)
				log_error("%s %s.", arg_long_option_name(arg), err_found);
			ret = 1;
		}
	va_end(ap);

	return ret;
}

int arg_from_list_is_zero(const struct cmd_context *cmd, const char *err_found, ...)
{
	int arg, ret = 0;
	va_list ap;

	va_start(ap, err_found);
	while ((arg = va_arg(ap, int)) != -1)
		if (arg_is_set(cmd, arg) &&
		    !arg_int_value(cmd, arg, 0)) {
			if (err_found)
				log_error("%s %s.", arg_long_option_name(arg), err_found);
			ret = 1;
		}
	va_end(ap);

	return ret;
}

unsigned grouped_arg_is_set(const struct arg_values *av, int a)
{
	return grouped_arg_count(av, a) ? 1 : 0;
}

const char *arg_long_option_name(int a)
{
	return _cmdline.arg_props[a].long_arg;
}

const char *arg_value(const struct cmd_context *cmd, int a)
{
	return cmd->arg_values[a].value;
}

const char *arg_str_value(const struct cmd_context *cmd, int a, const char *def)
{
	return arg_count(cmd, a) ? cmd->arg_values[a].value : def;
}

const char *grouped_arg_str_value(const struct arg_values *av, int a, const char *def)
{
	return grouped_arg_count(av, a) ? av[a].value : def;
}

int32_t grouped_arg_int_value(const struct arg_values *av, int a, const int32_t def)
{
	return grouped_arg_count(av, a) ? av[a].i_value : def;
}

int32_t first_grouped_arg_int_value(const struct cmd_context *cmd, int a, const int32_t def)
{
	struct arg_value_group_list *current_group;
	struct arg_values *av;

	dm_list_iterate_items(current_group, &cmd->arg_value_groups) {
		av = current_group->arg_values;
		if (grouped_arg_count(av, a))
			return grouped_arg_int_value(av, a, def);
	}

	return def;
}

int32_t arg_int_value(const struct cmd_context *cmd, int a, const int32_t def)
{
	return (_cmdline.arg_props[a].flags & ARG_GROUPABLE) ?
		first_grouped_arg_int_value(cmd, a, def) : (arg_count(cmd, a) ? cmd->arg_values[a].i_value : def);
}

uint32_t arg_uint_value(const struct cmd_context *cmd, int a, const uint32_t def)
{
	return arg_count(cmd, a) ? cmd->arg_values[a].ui_value : def;
}

int64_t arg_int64_value(const struct cmd_context *cmd, int a, const int64_t def)
{
	return arg_count(cmd, a) ? cmd->arg_values[a].i64_value : def;
}

uint64_t arg_uint64_value(const struct cmd_context *cmd, int a, const uint64_t def)
{
	return arg_count(cmd, a) ? cmd->arg_values[a].ui64_value : def;
}

/* No longer used.
const void *arg_ptr_value(struct cmd_context *cmd, int a, const void *def)
{
	return arg_count(cmd, a) ? cmd->arg_values[a].ptr : def;
}
*/

sign_t arg_sign_value(const struct cmd_context *cmd, int a, const sign_t def)
{
	return arg_count(cmd, a) ? cmd->arg_values[a].sign : def;
}

percent_type_t arg_percent_value(const struct cmd_context *cmd, int a, const percent_type_t def)
{
	return arg_count(cmd, a) ? cmd->arg_values[a].percent : def;
}

int arg_count_increment(struct cmd_context *cmd, int a)
{
	return cmd->arg_values[a].count++;
}

int yes_no_arg(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	av->sign = SIGN_NONE;
	av->percent = PERCENT_NONE;

	if (!strcmp(av->value, "y")) {
		av->i_value = 1;
		av->ui_value = 1;
	}

	else if (!strcmp(av->value, "n")) {
		av->i_value = 0;
		av->ui_value = 0;
	}

	else
		return 0;

	return 1;
}

int activation_arg(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	av->sign = SIGN_NONE;
	av->percent = PERCENT_NONE;

	if (!strcmp(av->value, "e") || !strcmp(av->value, "ey") ||
	    !strcmp(av->value, "ye")) {
		av->i_value = CHANGE_AEY;
		av->ui_value = CHANGE_AEY;
	}

	else if (!strcmp(av->value, "s") || !strcmp(av->value, "sy") ||
		 !strcmp(av->value, "ys")) {
		av->i_value = CHANGE_ASY;
		av->ui_value = CHANGE_ASY;
	}

	else if (!strcmp(av->value, "y")) {
		av->i_value = CHANGE_AY;
		av->ui_value = CHANGE_AY;
	}

	else if (!strcmp(av->value, "a") || !strcmp(av->value, "ay") ||
		 !strcmp(av->value, "ya")) {
		av->i_value = CHANGE_AAY;
		av->ui_value = CHANGE_AAY;
	}

	else if (!strcmp(av->value, "n") || !strcmp(av->value, "en") ||
		 !strcmp(av->value, "ne")) {
		av->i_value = CHANGE_AN;
		av->ui_value = CHANGE_AN;
	}

	else if (!strcmp(av->value, "ln") || !strcmp(av->value, "nl")) {
		av->i_value = CHANGE_ALN;
		av->ui_value = CHANGE_ALN;
	}

	else if (!strcmp(av->value, "ly") || !strcmp(av->value, "yl")) {
		av->i_value = CHANGE_ALY;
		av->ui_value = CHANGE_ALY;
	}

	else
		return 0;

	return 1;
}

int discards_arg(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	thin_discards_t discards;

	if (!set_pool_discards(&discards, av->value))
		return_0;

	av->i_value = discards;
	av->ui_value = discards;

	return 1;
}

int mirrorlog_arg(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	int log_count;

	if (!set_mirror_log_count(&log_count, av->value))
		return_0;

	av->i_value = log_count;
	av->ui_value = log_count;

	return 1;
}

int metadatatype_arg(struct cmd_context *cmd, struct arg_values *av)
{
	return get_format_by_name(cmd, av->value) ? 1 : 0;
}

static int _get_int_arg(struct arg_values *av, char **ptr)
{
	char *val;
	unsigned long long v;

	av->percent = PERCENT_NONE;

	val = av->value;
	switch (*val) {
	case '+':
		av->sign = SIGN_PLUS;
		val++;
		break;
	case '-':
		av->sign = SIGN_MINUS;
		val++;
		break;
	default:
		av->sign = SIGN_NONE;
	}

	if (!isdigit(*val))
		return 0;

	errno = 0;
	v = strtoull(val, ptr, 10);

	if (*ptr == val || errno)
		return 0;

	av->i_value = (int32_t) v;
	av->ui_value = (uint32_t) v;
	av->i64_value = (int64_t) v;
	av->ui64_value = (uint64_t) v;

	return 1;
}

static int _get_percent_arg(struct arg_values *av, const char *ptr)
{
	if (!strcasecmp(ptr, "V") || !strcasecmp(ptr, "VG"))
		av->percent = PERCENT_VG;
	else if (!strcasecmp(ptr, "L") || !strcasecmp(ptr, "LV"))
		av->percent = PERCENT_LV;
	else if (!strcasecmp(ptr, "P") || !strcasecmp(ptr, "PV") ||
		 !strcasecmp(ptr, "PVS"))
		av->percent = PERCENT_PVS;
	else if (!strcasecmp(ptr, "F") || !strcasecmp(ptr, "FR") ||
		 !strcasecmp(ptr, "FREE"))
		av->percent = PERCENT_FREE;
	else if (!strcasecmp(ptr, "O") || !strcasecmp(ptr, "OR") ||
		 !strcasecmp(ptr, "ORIGIN"))
		av->percent = PERCENT_ORIGIN;
	else {
		log_error("Specified %%%s is unknown.", ptr);
		return 0;
	}

	return 1;
}

/* Size stored in sectors */
static int _size_arg(struct cmd_context *cmd __attribute__((unused)),
		     struct arg_values *av, int factor, int percent)
{
	char *ptr;
	int i;
	static const char *suffixes = "kmgtpebs";
	char *val;
	double v;
	uint64_t v_tmp, adjustment;

	av->percent = PERCENT_NONE;

	val = av->value;
	switch (*val) {
	case '+':
		av->sign = SIGN_PLUS;
		val++;
		break;
	case '-':
		av->sign = SIGN_MINUS;
		val++;
		break;
	default:
		av->sign = SIGN_NONE;
	}

	if (!isdigit(*val))
		return 0;

	v = strtod(val, &ptr);

	if (*ptr == '.') {
		/*
		 * Maybe user has non-C locale with different decimal point ?
		 * Lets be toleran and retry with standard C locales
		 */
		if (setlocale(LC_ALL, "C")) {
			v = strtod(val, &ptr);
			setlocale(LC_ALL, "");
		}
	}

	if (ptr == val)
		return 0;

	if (percent && *ptr == '%') {
		if (!_get_percent_arg(av, ++ptr))
			return_0;
		if ((uint64_t) v >= UINT32_MAX) {
			log_error("Percentage is too big (>=%d%%).", UINT32_MAX);
			return 0;
		}
	} else if (*ptr) {
		for (i = strlen(suffixes) - 1; i >= 0; i--)
			if (suffixes[i] == tolower((int) *ptr))
				break;

		if (i < 0) {
			return 0;
		} else if (i == 7) {
			/* v is already in sectors */
			;
		} else if (i == 6) {
			/* bytes */
			v_tmp = (uint64_t) v;
			adjustment = v_tmp % 512;
			if (adjustment) {
				v_tmp += (512 - adjustment);
				log_error("Size is not a multiple of 512. "
					  "Try using %"PRIu64" or %"PRIu64".",
					  v_tmp - 512, v_tmp);
				return 0;
			}
			v /= 512;
		} else {
			/* all other units: kmgtpe */
			while (i-- > 0)
				v *= 1024;
			v *= 2;
		}
	} else
		v *= factor;

	if ((uint64_t) v >= (UINT64_MAX >> SECTOR_SHIFT)) {
		log_error("Size is too big (>=16EiB).");
		return 0;
	}
	av->i_value = (int32_t) v;
	av->ui_value = (uint32_t) v;
	av->i64_value = (int64_t) v;
	av->ui64_value = (uint64_t) v;

	return 1;
}

int size_kb_arg(struct cmd_context *cmd, struct arg_values *av)
{
	return _size_arg(cmd, av, 2, 0);
}

int size_mb_arg(struct cmd_context *cmd, struct arg_values *av)
{
	return _size_arg(cmd, av, 2048, 0);
}

int size_mb_arg_with_percent(struct cmd_context *cmd, struct arg_values *av)
{
	return _size_arg(cmd, av, 2048, 1);
}

int int_arg(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	char *ptr;

	if (!_get_int_arg(av, &ptr) || (*ptr) || (av->sign == SIGN_MINUS))
		return 0;

	return 1;
}

int int_arg_with_sign(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	char *ptr;

	if (!_get_int_arg(av, &ptr) || (*ptr))
		return 0;

	return 1;
}

int int_arg_with_sign_and_percent(struct cmd_context *cmd __attribute__((unused)),
				  struct arg_values *av)
{
	char *ptr;

	if (!_get_int_arg(av, &ptr))
		return 0;

	if (!*ptr)
		return 1;

	if (*ptr++ != '%')
		return 0;

	if (!_get_percent_arg(av, ptr))
		return_0;

	if (av->ui64_value >= UINT32_MAX) {
		log_error("Percentage is too big (>=%d%%).", UINT32_MAX);
		return 0;
	}

	return 1;
}

int string_arg(struct cmd_context *cmd __attribute__((unused)),
	       struct arg_values *av __attribute__((unused)))
{
	return 1;
}

int tag_arg(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	char *pos = av->value;

	if (*pos == '@')
		pos++;

	if (!validate_tag(pos))
		return 0;

	av->value = pos;

	return 1;
}

int permission_arg(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	av->sign = SIGN_NONE;

	if ((!strcmp(av->value, "rw")) || (!strcmp(av->value, "wr")))
		av->ui_value = LVM_READ | LVM_WRITE;

	else if (!strcmp(av->value, "r"))
		av->ui_value = LVM_READ;

	else
		return 0;

	return 1;
}

int alloc_arg(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	alloc_policy_t alloc;

	av->sign = SIGN_NONE;

	alloc = get_alloc_from_string(av->value);
	if (alloc == ALLOC_INVALID)
		return 0;

	av->ui_value = (uint32_t) alloc;

	return 1;
}

int locktype_arg(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	lock_type_t lock_type;

	av->sign = SIGN_NONE;

	lock_type = get_lock_type_from_string(av->value);
	if (lock_type == LOCK_TYPE_INVALID)
		return 0;

	return 1;
}

int segtype_arg(struct cmd_context *cmd, struct arg_values *av)
{
	struct segment_type *segtype;
	const char *str = (!strcmp(av->value, "linear")) ? "striped" : av->value;

	if (!(segtype = get_segtype_from_string(cmd, str)))
		return_0;

	return (!segtype_is_unknown(segtype)) ? 1 : 0;
}

/*
 * Positive integer, zero or "auto".
 */
int readahead_arg(struct cmd_context *cmd __attribute__((unused)), struct arg_values *av)
{
	if (!strcasecmp(av->value, "auto")) {
		av->ui_value = DM_READ_AHEAD_AUTO;
		return 1;
	}

	if (!strcasecmp(av->value, "none")) {
		av->ui_value = DM_READ_AHEAD_NONE;
		return 1;
	}

	if (!_size_arg(cmd, av, 1, 0))
		return 0;

	if (av->sign == SIGN_MINUS)
		return 0;

	return 1;
}

/*
 * Non-zero, positive integer, "all", or "unmanaged"
 */
int metadatacopies_arg(struct cmd_context *cmd, struct arg_values *av)
{
	if (!strncmp(cmd->command->name, "vg", 2)) {
		if (!strcasecmp(av->value, "all")) {
			av->ui_value = VGMETADATACOPIES_ALL;
			return 1;
		}

		if (!strcasecmp(av->value, "unmanaged")) {
			av->ui_value = VGMETADATACOPIES_UNMANAGED;
			return 1;
		}
	}

	return int_arg(cmd, av);
}

static void __alloc(int size)
{
	if (!(_cmdline.commands = dm_realloc(_cmdline.commands, sizeof(*_cmdline.commands) * size))) {
		log_fatal("Couldn't allocate memory.");
		exit(ECMD_FAILED);
	}

	_cmdline.commands_size = size;
}

static void _alloc_command(void)
{
	if (!_cmdline.commands_size)
		__alloc(32);

	if (_cmdline.commands_size <= _cmdline.num_commands)
		__alloc(2 * _cmdline.commands_size);
}

static void _create_new_command(const char *name, command_fn command,
				unsigned flags,
				const char *desc, const char *usagestr,
				int nargs, int *args)
{
	struct command *nc;

	_alloc_command();

	nc = _cmdline.commands + _cmdline.num_commands++;

	nc->name = name;
	nc->desc = desc;
	nc->usage = usagestr;
	nc->fn = command;
	nc->flags = flags;
	nc->num_args = nargs;
	nc->valid_args = args;
}

static void _register_command(const char *name, command_fn fn, const char *desc,
			      unsigned flags, const char *usagestr, ...)
{
	int nargs = 0, i;
	int *args;
	va_list ap;

	/* count how many arguments we have */
	va_start(ap, usagestr);
	while (va_arg(ap, int) >= 0)
		 nargs++;
	va_end(ap);

	/* allocate space for them */
	if (!(args = dm_malloc(sizeof(*args) * nargs))) {
		log_fatal("Out of memory.");
		exit(ECMD_FAILED);
	}

	/* fill them in */
	va_start(ap, usagestr);
	for (i = 0; i < nargs; i++)
		args[i] = va_arg(ap, int);
	va_end(ap);

	/* enter the command in the register */
	_create_new_command(name, fn, flags, desc, usagestr, nargs, args);
}

void lvm_register_commands(void)
{
#define xx(a, b, c, d...) _register_command(# a, a, b, c, ## d, \
					    driverloaded_ARG, \
					    debug_ARG, help_ARG, help2_ARG, \
					    version_ARG, verbose_ARG, \
					    yes_ARG, \
					    quiet_ARG, config_ARG, \
					    commandprofile_ARG, \
					    profile_ARG, -1);
#include "commands.h"
#undef xx
}

static struct command *_find_command(const char *name)
{
	int i;
	const char *base;

	base = last_path_component(name);

	for (i = 0; i < _cmdline.num_commands; i++) {
		if (!strcmp(base, _cmdline.commands[i].name))
			break;
	}

	if (i >= _cmdline.num_commands)
		return 0;

	return _cmdline.commands + i;
}

static void _short_usage(const char *name)
{
	log_error("Run `%s --help' for more information.", name);
}

static int _usage(const char *name)
{
	struct command *com = _find_command(name);

	if (!com) {
		log_print("%s: no such command.", name);
		return 0;
	}

	log_print("%s: %s\n\n%s", com->name, com->desc, com->usage);
	return 1;
}

/*
 * Sets up the short and long argument.  If there
 * is no short argument then the index of the
 * argument in the the_args array is set as the
 * long opt value.  Yuck.  Of course this means we
 * can't have more than 'a' long arguments.
 */
static void _add_getopt_arg(int arg, char **ptr, struct option **o)
{
	struct arg_props *a = _cmdline.arg_props + arg;

	if (a->short_arg) {
		*(*ptr)++ = a->short_arg;

		if (a->fn)
			*(*ptr)++ = ':';
	}
#ifdef HAVE_GETOPTLONG
	if (*(a->long_arg + 2)) {
		(*o)->name = a->long_arg + 2;
		(*o)->has_arg = a->fn ? 1 : 0;
		(*o)->flag = NULL;
		if (a->short_arg)
			(*o)->val = a->short_arg;
		else
			(*o)->val = arg + 128;
		(*o)++;
	}
#endif
}

static int _find_arg(struct command *com, int opt)
{
	struct arg_props *a;
	int i, arg;

	for (i = 0; i < com->num_args; i++) {
		arg = com->valid_args[i];
		a = _cmdline.arg_props + arg;

		/*
		 * opt should equal either the
		 * short arg, or the index into
		 * the_args.
		 */
		if ((a->short_arg && (opt == a->short_arg)) ||
		    (!a->short_arg && (opt == (arg + 128))))
			return arg;
	}

	return -1;
}

static int _process_command_line(struct cmd_context *cmd, int *argc,
				 char ***argv)
{
	int i, opt, arg;
	char str[((ARG_COUNT + 1) * 2) + 1], *ptr = str;
	struct option opts[ARG_COUNT + 1], *o = opts;
	struct arg_props *a;
	struct arg_values *av;
	struct arg_value_group_list *current_group = NULL;

	if (!(cmd->arg_values = dm_pool_zalloc(cmd->mem, sizeof(*cmd->arg_values) * ARG_COUNT))) {
		log_fatal("Unable to allocate memory for command line arguments.");
		return 0;
	}

	/* fill in the short and long opts */
	for (i = 0; i < cmd->command->num_args; i++)
		_add_getopt_arg(cmd->command->valid_args[i], &ptr, &o);

	*ptr = '\0';
	memset(o, 0, sizeof(*o));

	/* initialise getopt_long & scan for command line switches */
	optarg = 0;
	optind = OPTIND_INIT;
	while ((opt = GETOPTLONG_FN(*argc, *argv, str, opts, NULL)) >= 0) {

		if (opt == '?')
			return 0;

		if ((arg = _find_arg(cmd->command, opt)) < 0) {
			log_fatal("Unrecognised option.");
			return 0;
		}

		a = _cmdline.arg_props + arg;

		av = &cmd->arg_values[arg];

		if (a->flags & ARG_GROUPABLE) {
			/* Start a new group of arguments the first time or if a non-countable argument is repeated. */
			if (!current_group || (current_group->arg_values[arg].count && !(a->flags & ARG_COUNTABLE))) {
				/* FIXME Reduce size including only groupable args */
				if (!(current_group = dm_pool_zalloc(cmd->mem, sizeof(struct arg_value_group_list) + sizeof(*cmd->arg_values) * ARG_COUNT))) {
					log_fatal("Unable to allocate memory for command line arguments.");
					return 0;
				}

				dm_list_add(&cmd->arg_value_groups, &current_group->list);
			}
			/* Maintain total argument count as well as count within each group */
			av->count++;
			av = &current_group->arg_values[arg];
		}

		if (av->count && !(a->flags & ARG_COUNTABLE)) {
			log_error("Option%s%c%s%s may not be repeated.",
				  a->short_arg ? " -" : "",
				  a->short_arg ? : ' ',
				  (a->short_arg && a->long_arg) ?
				  "/" : "", a->long_arg ? : "");
			return 0;
		}

		if (a->fn) {
			if (!optarg) {
				log_error("Option requires argument.");
				return 0;
			}

			av->value = optarg;

			if (!a->fn(cmd, av)) {
				log_error("Invalid argument for %s: %s", a->long_arg, optarg);
				return 0;
			}
		}

		av->count++;
	}

	*argc -= optind;
	*argv += optind;
	return 1;
}

static void _copy_arg_values(struct arg_values *av, int oldarg, int newarg)
{
	const struct arg_values *old = av + oldarg;
	struct arg_values *new = av + newarg;

	new->count = old->count;
	new->value = old->value;
	new->i_value = old->i_value;
	new->ui_value = old->ui_value;
	new->i64_value = old->i64_value;
	new->ui64_value = old->ui64_value;
	new->sign = old->sign;
}

static int _merge_synonym(struct cmd_context *cmd, int oldarg, int newarg)
{
	struct arg_values *av;
	struct arg_value_group_list *current_group;

	if (arg_count(cmd, oldarg) && arg_count(cmd, newarg)) {
		log_error("%s and %s are synonyms.  Please only supply one.",
			  _cmdline.arg_props[oldarg].long_arg, _cmdline.arg_props[newarg].long_arg);
		return 0;
	}

	/* Not groupable? */
	if (!(_cmdline.arg_props[oldarg].flags & ARG_GROUPABLE)) {
		if (arg_count(cmd, oldarg))
			_copy_arg_values(cmd->arg_values, oldarg, newarg);
		return 1;
	}

	if (arg_count(cmd, oldarg))
		cmd->arg_values[newarg].count = cmd->arg_values[oldarg].count;

	/* Groupable */
	dm_list_iterate_items(current_group, &cmd->arg_value_groups) {
		av = current_group->arg_values;
		if (!grouped_arg_count(av, oldarg))
			continue;
		_copy_arg_values(av, oldarg, newarg);
	}

	return 1;
}

int systemid(struct cmd_context *cmd __attribute__((unused)),
	     int argc __attribute__((unused)),
	     char **argv __attribute__((unused)))
{
	log_print("system ID: %s", cmd->system_id ? : "");

	return ECMD_PROCESSED;
}

int version(struct cmd_context *cmd __attribute__((unused)),
	    int argc __attribute__((unused)),
	    char **argv __attribute__((unused)))
{
	char vsn[80];

	log_print("LVM version:     %s", LVM_VERSION);
	if (library_version(vsn, sizeof(vsn)))
		log_print("Library version: %s", vsn);
	if (driver_version(vsn, sizeof(vsn)))
		log_print("Driver version:  %s", vsn);

	return ECMD_PROCESSED;
}

static int _get_settings(struct cmd_context *cmd)
{
	const char *activation_mode;

	cmd->current_settings = cmd->default_settings;

	if (arg_count(cmd, debug_ARG))
		cmd->current_settings.debug = _LOG_FATAL +
		    (arg_count(cmd, debug_ARG) - 1);

	if (arg_count(cmd, verbose_ARG))
		cmd->current_settings.verbose = arg_count(cmd, verbose_ARG);

	if (arg_count(cmd, quiet_ARG)) {
		cmd->current_settings.debug = 0;
		cmd->current_settings.verbose = 0;
		cmd->current_settings.silent = (arg_count(cmd, quiet_ARG) > 1) ? 1 : 0;
	}

	if (arg_count(cmd, test_ARG))
		cmd->current_settings.test = arg_count(cmd, test_ARG);

	if (arg_count(cmd, driverloaded_ARG)) {
		cmd->current_settings.activation =
		    arg_int_value(cmd, driverloaded_ARG,
				  cmd->default_settings.activation);
	}

	cmd->current_settings.archive = arg_int_value(cmd, autobackup_ARG, cmd->current_settings.archive);
	cmd->current_settings.backup = arg_int_value(cmd, autobackup_ARG, cmd->current_settings.backup);
	cmd->current_settings.cache_vgmetadata = cmd->command->flags & CACHE_VGMETADATA ? 1 : 0;

	if (arg_count(cmd, readonly_ARG)) {
		cmd->current_settings.activation = 0;
		cmd->current_settings.archive = 0;
		cmd->current_settings.backup = 0;
	}

	if (cmd->command->flags & LOCKD_VG_SH)
		cmd->lockd_vg_default_sh = 1;

	cmd->partial_activation = 0;
	cmd->degraded_activation = 0;
	activation_mode = find_config_tree_str(cmd, activation_mode_CFG, NULL);
	if (!activation_mode)
		activation_mode = DEFAULT_ACTIVATION_MODE;

	if (arg_count(cmd, activationmode_ARG)) {
		activation_mode = arg_str_value(cmd, activationmode_ARG,
						activation_mode);

		/* complain only if the two arguments conflict */
		if (arg_count(cmd, partial_ARG) &&
		    strcmp(activation_mode, "partial")) {
			log_error("--partial and --activationmode are mutually"
				  " exclusive arguments");
			return EINVALID_CMD_LINE;
		}
	} else if (arg_count(cmd, partial_ARG))
		activation_mode = "partial";

	if (!strcmp(activation_mode, "partial")) {
		cmd->partial_activation = 1;
		log_warn("PARTIAL MODE. Incomplete logical volumes will be processed.");
	} else if (!strcmp(activation_mode, "degraded"))
		cmd->degraded_activation = 1;
	else if (strcmp(activation_mode, "complete")) {
		log_error("Invalid activation mode given.");
		return EINVALID_CMD_LINE;
	}

	if (arg_count(cmd, ignorelockingfailure_ARG) || arg_count(cmd, sysinit_ARG))
		init_ignorelockingfailure(1);
	else
		init_ignorelockingfailure(0);

	cmd->ignore_clustered_vgs = arg_is_set(cmd, ignoreskippedcluster_ARG);
	cmd->include_foreign_vgs = arg_is_set(cmd, foreign_ARG) ? 1 : 0;
	cmd->include_shared_vgs = arg_is_set(cmd, shared_ARG) ? 1 : 0;

	/*
	 * This is set to zero by process_each which wants to print errors
	 * itself rather than having them printed in vg_read.
	 */
	cmd->vg_read_print_access_error = 1;
		
	if (!arg_count(cmd, sysinit_ARG))
		lvmetad_connect_or_warn();

	if (arg_count(cmd, nosuffix_ARG))
		cmd->current_settings.suffix = 0;

	if (arg_count(cmd, units_ARG))
		if (!(cmd->current_settings.unit_factor =
		      dm_units_to_factor(arg_str_value(cmd, units_ARG, ""),
					 &cmd->current_settings.unit_type, 1, NULL))) {
			log_error("Invalid units specification");
			return EINVALID_CMD_LINE;
		}

	if (arg_count(cmd, binary_ARG))
		cmd->report_binary_values_as_numeric = 1;

	if (arg_count(cmd, trustcache_ARG)) {
		if (arg_count(cmd, all_ARG)) {
			log_error("--trustcache is incompatible with --all");
			return EINVALID_CMD_LINE;
		}
		init_trust_cache(1);
		log_warn("WARNING: Cache file of PVs will be trusted.  "
			  "New devices holding PVs may get ignored.");
	} else
		init_trust_cache(0);

	if (arg_count(cmd, noudevsync_ARG))
		cmd->current_settings.udev_sync = 0;

	/* Handle synonyms */
	if (!_merge_synonym(cmd, resizable_ARG, resizeable_ARG) ||
	    !_merge_synonym(cmd, allocation_ARG, allocatable_ARG) ||
	    !_merge_synonym(cmd, allocation_ARG, resizeable_ARG) ||
	    !_merge_synonym(cmd, virtualoriginsize_ARG, virtualsize_ARG) ||
	    !_merge_synonym(cmd, available_ARG, activate_ARG) ||
	    !_merge_synonym(cmd, raidsyncaction_ARG, syncaction_ARG) ||
	    !_merge_synonym(cmd, raidwritemostly_ARG, writemostly_ARG) ||
	    !_merge_synonym(cmd, raidminrecoveryrate_ARG, minrecoveryrate_ARG) ||
	    !_merge_synonym(cmd, raidmaxrecoveryrate_ARG, maxrecoveryrate_ARG) ||
	    !_merge_synonym(cmd, raidwritebehind_ARG, writebehind_ARG))
		return EINVALID_CMD_LINE;

	if ((!strncmp(cmd->command->name, "pv", 2) &&
	    !_merge_synonym(cmd, metadatacopies_ARG, pvmetadatacopies_ARG)) ||
	    (!strncmp(cmd->command->name, "vg", 2) &&
	     !_merge_synonym(cmd, metadatacopies_ARG, vgmetadatacopies_ARG)))
		return EINVALID_CMD_LINE;

	/* Zero indicates success */
	return 0;
}

static int _process_common_commands(struct cmd_context *cmd)
{
	if (arg_count(cmd, help_ARG) || arg_count(cmd, help2_ARG)) {
		_usage(cmd->command->name);
		return ECMD_PROCESSED;
	}

	if (arg_count(cmd, version_ARG)) {
		return version(cmd, 0, (char **) NULL);
	}

	/* Zero indicates it's OK to continue processing this command */
	return 0;
}

static void _display_help(void)
{
	int i;

	log_error("Available lvm commands:");
	log_error("Use 'lvm help <command>' for more information");
	log_error(" ");

	for (i = 0; i < _cmdline.num_commands; i++) {
		struct command *com = _cmdline.commands + i;

		log_error("%-16.16s%s", com->name, com->desc);
	}
}

int help(struct cmd_context *cmd __attribute__((unused)), int argc, char **argv)
{
	int ret = ECMD_PROCESSED;

	if (!argc)
		_display_help();
	else {
		int i;
		for (i = 0; i < argc; i++)
			if (!_usage(argv[i]))
				ret = EINVALID_CMD_LINE;
	}

	return ret;
}

static void _apply_settings(struct cmd_context *cmd)
{
	init_debug(cmd->current_settings.debug);
	init_debug_classes_logged(cmd->default_settings.debug_classes);
	init_verbose(cmd->current_settings.verbose + VERBOSE_BASE_LEVEL);
	init_silent(cmd->current_settings.silent);
	init_test(cmd->current_settings.test);
	init_full_scan_done(0);
	init_mirror_in_sync(0);
	init_dmeventd_monitor(DEFAULT_DMEVENTD_MONITOR);

	init_msg_prefix(cmd->default_settings.msg_prefix);
	init_cmd_name(cmd->default_settings.cmd_name);

	archive_enable(cmd, cmd->current_settings.archive);
	backup_enable(cmd, cmd->current_settings.backup);

	set_activation(cmd->current_settings.activation, cmd->metadata_read_only);

	cmd->fmt = get_format_by_name(cmd, arg_str_value(cmd, metadatatype_ARG,
				      cmd->current_settings.fmt_name));

	cmd->handles_missing_pvs = 0;
}

static const char *_copy_command_line(struct cmd_context *cmd, int argc, char **argv)
{
	int i, space;

	/*
	 * Build up the complete command line, used as a
	 * description for backups.
	 */
	if (!dm_pool_begin_object(cmd->mem, 128))
		goto_bad;

	for (i = 0; i < argc; i++) {
		space = strchr(argv[i], ' ') ? 1 : 0;

		if (space && !dm_pool_grow_object(cmd->mem, "'", 1))
			goto_bad;

		if (!dm_pool_grow_object(cmd->mem, argv[i], strlen(argv[i])))
			goto_bad;

		if (space && !dm_pool_grow_object(cmd->mem, "'", 1))
			goto_bad;

		if (i < (argc - 1))
			if (!dm_pool_grow_object(cmd->mem, " ", 1))
				goto_bad;
	}

	/*
	 * Terminate.
	 */
	if (!dm_pool_grow_object(cmd->mem, "\0", 1))
		goto_bad;

	return dm_pool_end_object(cmd->mem);

      bad:
	log_error("Couldn't copy command line.");
	dm_pool_abandon_object(cmd->mem);
	return NULL;
}

static int _prepare_profiles(struct cmd_context *cmd)
{
	static const char COMMAND_PROFILE_ENV_VAR_NAME[] = "LVM_COMMAND_PROFILE";
	static const char _cmd_profile_arg_preferred_over_env_var_msg[] = "Giving "
				"preference to command profile specified on command "
				"line over the one specified via environment variable.";
	static const char _failed_to_add_profile_msg[] = "Failed to add %s %s.";
	static const char _failed_to_apply_profile_msg[] = "Failed to apply %s %s.";
	static const char _command_profile_source_name[] = "command profile";
	static const char _metadata_profile_source_name[] = "metadata profile";
	static const char _setting_global_profile_msg[] = "Setting global %s \"%s\".";

	const char *env_cmd_profile_name = NULL;
	const char *name;
	struct profile *profile;
	config_source_t source;
	const char *source_name;

	/* Check whether default global command profile is set via env. var. */
	if ((env_cmd_profile_name = getenv(COMMAND_PROFILE_ENV_VAR_NAME))) {
		if (!*env_cmd_profile_name)
			env_cmd_profile_name = NULL;
		else
			log_debug("Command profile '%s' requested via "
				  "environment variable.",
				   env_cmd_profile_name);
	}

	if (!arg_count(cmd, profile_ARG) &&
	    !arg_count(cmd, commandprofile_ARG) &&
	    !arg_count(cmd, metadataprofile_ARG) &&
	    !env_cmd_profile_name)
		/* nothing to do */
		return 1;

	if (arg_count(cmd, profile_ARG)) {
		/*
		 * If --profile is used with dumpconfig, it's used
		 * to dump the profile without the profile being applied.
		 */
		if (!strcmp(cmd->command->name, "dumpconfig") ||
		    !strcmp(cmd->command->name, "lvmconfig") ||
		    !strcmp(cmd->command->name, "config"))
			return 1;

		/*
		 * If --profile is used with lvcreate/lvchange/vgchange,
		 * it's recognized as shortcut to --metadataprofile.
		 * The --commandprofile is assumed otherwise.
		 */
		if (!strcmp(cmd->command->name, "lvcreate") ||
		    !strcmp(cmd->command->name, "vgcreate") ||
		    !strcmp(cmd->command->name, "lvchange") ||
		    !strcmp(cmd->command->name, "vgchange")) {
			if (arg_count(cmd, metadataprofile_ARG)) {
				log_error("Only one of --profile or "
					  " --metadataprofile allowed.");
				return 0;
			}
			source = CONFIG_PROFILE_METADATA;
			source_name = _metadata_profile_source_name;
		}
		else {
			if (arg_count(cmd, commandprofile_ARG)) {
				log_error("Only one of --profile or "
					  "--commandprofile allowed.");
				return 0;
			}
			/*
			 * Prefer command profile specified on command
			 * line over the profile specified via
			 * COMMAND_PROFILE_ENV_VAR_NAME env. var.
			 */
			if (env_cmd_profile_name) {
				log_debug(_cmd_profile_arg_preferred_over_env_var_msg);
				env_cmd_profile_name = NULL;
			}
			source = CONFIG_PROFILE_COMMAND;
			source_name = _command_profile_source_name;
		}

		name = arg_str_value(cmd, profile_ARG, NULL);

		if (!(profile = add_profile(cmd, name, source))) {
			log_error(_failed_to_add_profile_msg, source_name, name);
			return 0;
		}

		if (source == CONFIG_PROFILE_COMMAND) {
			log_debug(_setting_global_profile_msg, _command_profile_source_name, profile->name);
			cmd->profile_params->global_command_profile = profile;
		} else if (source == CONFIG_PROFILE_METADATA) {
			log_debug(_setting_global_profile_msg, _metadata_profile_source_name, profile->name);
			/* This profile will override any VG/LV-based profile if present */
			cmd->profile_params->global_metadata_profile = profile;
		}

		if (!override_config_tree_from_profile(cmd, profile)) {
			log_error(_failed_to_apply_profile_msg, source_name, name);
			return 0;
		}

	}

	if (arg_count(cmd, commandprofile_ARG) || env_cmd_profile_name) {
		if (arg_count(cmd, commandprofile_ARG)) {
			/*
			 * Prefer command profile specified on command
			 * line over the profile specified via
			 * COMMAND_PROFILE_ENV_VAR_NAME env. var.
			 */
			if (env_cmd_profile_name)
				log_debug(_cmd_profile_arg_preferred_over_env_var_msg);
			name = arg_str_value(cmd, commandprofile_ARG, NULL);
		} else
			name = env_cmd_profile_name;
		source_name = _command_profile_source_name;

		if (!(profile = add_profile(cmd, name, CONFIG_PROFILE_COMMAND))) {
			log_error(_failed_to_add_profile_msg, source_name, name);
			return 0;
		}
		if (!override_config_tree_from_profile(cmd, profile)) {
			log_error(_failed_to_apply_profile_msg, source_name, name);
			return 0;
		}

		log_debug(_setting_global_profile_msg, _command_profile_source_name, profile->name);
		cmd->profile_params->global_command_profile = profile;
	}


	if (arg_count(cmd, metadataprofile_ARG)) {
		name = arg_str_value(cmd, metadataprofile_ARG, NULL);
		source_name = _metadata_profile_source_name;

		if (!(profile = add_profile(cmd, name, CONFIG_PROFILE_METADATA))) {
			log_error(_failed_to_add_profile_msg, source_name, name);
			return 0;
		}
		if (!override_config_tree_from_profile(cmd, profile)) {
			log_error(_failed_to_apply_profile_msg, source_name, name);
			return 0;
		}

		log_debug(_setting_global_profile_msg, _metadata_profile_source_name, profile->name);
		cmd->profile_params->global_metadata_profile = profile;
	}

	if (!process_profilable_config(cmd))
		return_0;

	return 1;
}

static int _init_lvmlockd(struct cmd_context *cmd)
{
	const char *lvmlockd_socket;
	int use_lvmlockd = find_config_tree_bool(cmd, global_use_lvmlockd_CFG, NULL);

	if (use_lvmlockd && arg_count(cmd, nolocking_ARG)) {
		/* --nolocking is only allowed with vgs/lvs/pvs commands */
		cmd->lockd_gl_disable = 1;
		cmd->lockd_vg_disable = 1;
		cmd->lockd_lv_disable = 1;
		return 1;
	}

	if (use_lvmlockd && locking_is_clustered()) {
		log_error("ERROR: configuration setting use_lvmlockd cannot be used with clustered locking_type 3.");
		return 0;
	}

	lvmlockd_disconnect(); /* start over when tool context is refreshed */
	lvmlockd_socket = getenv("LVM_LVMLOCKD_SOCKET");
	if (!lvmlockd_socket)
		lvmlockd_socket = DEFAULT_RUN_DIR "/lvmlockd.socket";

	lvmlockd_set_socket(lvmlockd_socket);
	lvmlockd_set_use(use_lvmlockd);
	if (use_lvmlockd) {
		lvmlockd_init(cmd);
		lvmlockd_connect();
	}

	return 1;
}

static int _cmd_no_meta_proc(struct cmd_context *cmd)
{
	return cmd->command->flags & NO_METADATA_PROCESSING;
}

int lvm_run_command(struct cmd_context *cmd, int argc, char **argv)
{
	struct dm_config_tree *config_string_cft;
	struct dm_config_tree *config_profile_command_cft, *config_profile_metadata_cft;
	int ret = 0;
	int locking_type;
	int monitoring;
	char *arg_new, *arg;
	int i;
	int skip_hyphens;
	int refresh_done = 0;

	init_error_message_produced(0);

	/* each command should start out with sigint flag cleared */
	sigint_clear();

	/* eliminate '-' from all options starting with -- */
	for (i = 1; i < argc; i++) {

		arg = argv[i];

		if (*arg++ != '-' || *arg++ != '-')
			continue;

		/* If we reach "--" then stop. */
		if (!*arg)
			break;

		arg_new = arg;
		skip_hyphens = 1;
		while (*arg) {
			/* If we encounter '=', stop any further hyphen removal. */
			if (*arg == '=')
				skip_hyphens = 0;

			/* Do we need to keep the next character? */
			if (*arg != '-' || !skip_hyphens) {
				if (arg_new != arg)
					*arg_new = *arg;
				++arg_new;
			}
			arg++;
		}

		/* Terminate a shortened arg */
		if (arg_new != arg)
			*arg_new = '\0';
	}

	if (!(cmd->cmd_line = _copy_command_line(cmd, argc, argv)))
		return_ECMD_FAILED;

	log_debug("Parsing: %s", cmd->cmd_line);

	if (!(cmd->command = _find_command(argv[0])))
		return ENO_SUCH_CMD;

	if (!_process_command_line(cmd, &argc, &argv)) {
		log_error("Error during parsing of command line.");
		return EINVALID_CMD_LINE;
	}

	set_cmd_name(cmd->command->name);

	if (arg_count(cmd, backgroundfork_ARG)) {
		if (!become_daemon(cmd, 1)) {
			/* parent - quit immediately */
			ret = ECMD_PROCESSED;
			goto out;
		}
	}

	if (arg_count(cmd, config_ARG))
		if (!override_config_tree_from_string(cmd, arg_str_value(cmd, config_ARG, ""))) {
			ret = EINVALID_CMD_LINE;
			goto_out;
		}

	if (arg_count(cmd, config_ARG) || !cmd->initialized.config || config_files_changed(cmd)) {
		/* Reinitialise various settings inc. logging, filters */
		if (!refresh_toolcontext(cmd)) {
			if ((config_string_cft = remove_config_tree_by_source(cmd, CONFIG_STRING)))
				dm_config_destroy(config_string_cft);
			log_error("Updated config file invalid. Aborting.");
			return ECMD_FAILED;
		}
		refresh_done = 1;
	}

	if (!_prepare_profiles(cmd))
		return_ECMD_FAILED;

	if (!cmd->initialized.connections && !_cmd_no_meta_proc(cmd) && !init_connections(cmd))
		return_ECMD_FAILED;

	/* Note: Load persistent cache only if we haven't refreshed toolcontext!
	 *       If toolcontext has been refreshed, it means config has changed
	 *       and we can't rely on persistent cache anymore.
	 */
	if (!cmd->initialized.filters && !_cmd_no_meta_proc(cmd) && !init_filters(cmd, !refresh_done))
		return_ECMD_FAILED;

	if (arg_count(cmd, readonly_ARG))
		cmd->metadata_read_only = 1;

	if ((ret = _get_settings(cmd)))
		goto_out;
	_apply_settings(cmd);
	if (cmd->degraded_activation)
		log_debug("DEGRADED MODE. Incomplete RAID LVs will be processed.");

	if (!get_activation_monitoring_mode(cmd, &monitoring))
		goto_out;
	init_dmeventd_monitor(monitoring);

	log_debug("Processing: %s", cmd->cmd_line);
	log_debug("system ID: %s", cmd->system_id ? : "");

#ifdef O_DIRECT_SUPPORT
	log_debug("O_DIRECT will be used");
#endif

	if ((ret = _process_common_commands(cmd))) {
		if (ret != ECMD_PROCESSED)
			stack;
		goto out;
	}

	if (cmd->metadata_read_only &&
	    !(cmd->command->flags & PERMITTED_READ_ONLY)) {
		log_error("%s: Command not permitted while global/metadata_read_only "
			  "is set.", cmd->cmd_line);
		goto out;
	}

	if (_cmd_no_meta_proc(cmd))
		locking_type = 0;
	else if (arg_count(cmd, readonly_ARG)) {
		if (find_config_tree_bool(cmd, global_use_lvmlockd_CFG, NULL)) {
			/*
			 * FIXME: we could use locking_type 5 here if that didn't
			 * cause CLUSTERED to be set, which conflicts with using lvmlockd.
			 */
			locking_type = 1;
			cmd->lockd_gl_disable = 1;
			cmd->lockd_vg_disable = 1;
			cmd->lockd_lv_disable = 1;
		} else {
			locking_type = 5;
		}

		if (lvmetad_used()) {
			lvmetad_set_active(cmd, 0);
			log_verbose("Disabling use of lvmetad because read-only is set.");
		}
	} else if (arg_count(cmd, nolocking_ARG))
		locking_type = 0;
	else
		locking_type = -1;

	if (!init_locking(locking_type, cmd, _cmd_no_meta_proc(cmd) || arg_count(cmd, sysinit_ARG))) {
		ret = ECMD_FAILED;
		goto_out;
	}

	if (!_cmd_no_meta_proc(cmd) && !_init_lvmlockd(cmd)) {
		ret = ECMD_FAILED;
		goto_out;
	}

	/*
	 * Other hosts might have changed foreign VGs so enforce a rescan
	 * before processing any command using them.
	 */
	if (cmd->include_foreign_vgs && lvmetad_used() &&
	    !lvmetad_pvscan_foreign_vgs(cmd, NULL)) {
		log_error("Failed to scan devices.");
		return ECMD_FAILED;
	}

	/*
	 * FIXME Break up into multiple functions.
	 */
	ret = cmd->command->fn(cmd, argc, argv);

	lvmlockd_disconnect();
	fin_locking();

      out:
	if (test_mode()) {
		log_verbose("Test mode: Wiping internal cache");
		lvmcache_destroy(cmd, 1, 0);
	}

	if ((config_string_cft = remove_config_tree_by_source(cmd, CONFIG_STRING)))
		dm_config_destroy(config_string_cft);

	config_profile_command_cft = remove_config_tree_by_source(cmd, CONFIG_PROFILE_COMMAND);
	config_profile_metadata_cft = remove_config_tree_by_source(cmd, CONFIG_PROFILE_METADATA);
	cmd->profile_params->global_metadata_profile = NULL;

	if (config_string_cft || config_profile_command_cft || config_profile_metadata_cft) {
		/* Move this? */
		if (!refresh_toolcontext(cmd))
			stack;
	}

	if (ret == EINVALID_CMD_LINE && !_cmdline.interactive)
		_short_usage(cmd->command->name);

	log_debug("Completed: %s", cmd->cmd_line);

	cmd->current_settings = cmd->default_settings;
	_apply_settings(cmd);

	/*
	 * free off any memory the command used.
	 */
	dm_list_init(&cmd->arg_value_groups);
	dm_pool_empty(cmd->mem);

	reset_lvm_errno(1);
	reset_log_duplicated();

	return ret;
}

int lvm_return_code(int ret)
{
	unlink_log_file(ret);

	return (ret == ECMD_PROCESSED ? 0 : ret);
}

int lvm_split(char *str, int *argc, char **argv, int max)
{
	char *b = str, *e;
	char quote = 0;
	*argc = 0;

	while (*b) {
		while (*b && isspace(*b))
			b++;

		if ((!*b) || (*b == '#'))
			break;

		if (*b == '\'' || *b == '"') {
			quote = *b;
			b++;
		}

		e = b;
		while (*e && (quote ? *e != quote : !isspace(*e)))
			e++;

		argv[(*argc)++] = b;
		if (!*e)
			break;
		*e++ = '\0';
		quote = 0;
		b = e;
		if (*argc == max)
			break;
	}

	return *argc;
}

/* Make sure we have always valid filedescriptors 0,1,2 */
static int _check_standard_fds(void)
{
	int err = is_valid_fd(STDERR_FILENO);

	if (!is_valid_fd(STDIN_FILENO) &&
	    !(stdin = fopen(_PATH_DEVNULL, "r"))) {
		if (err)
			perror("stdin stream open");
		else
			printf("stdin stream open: %s\n",
			       strerror(errno));
		return 0;
	}

	if (!is_valid_fd(STDOUT_FILENO) &&
	    !(stdout = fopen(_PATH_DEVNULL, "w"))) {
		if (err)
			perror("stdout stream open");
		/* else no stdout */
		return 0;
	}

	if (!is_valid_fd(STDERR_FILENO) &&
	    !(stderr = fopen(_PATH_DEVNULL, "w"))) {
		printf("stderr stream open: %s\n",
		       strerror(errno));
		return 0;
	}

	return 1;
}

static const char *_get_cmdline(pid_t pid)
{
	static char _proc_cmdline[32];
	char buf[256];
	int fd, n = 0;

	snprintf(buf, sizeof(buf), DEFAULT_PROC_DIR "/%u/cmdline", pid);
	/* FIXME Use generic read code. */
	if ((fd = open(buf, O_RDONLY)) >= 0) {
		if ((n = read(fd, _proc_cmdline, sizeof(_proc_cmdline) - 1)) < 0) {
			log_sys_error("read", buf);
			n = 0;
		}
		if (close(fd))
			log_sys_error("close", buf);
	}
	_proc_cmdline[n] = '\0';

	return _proc_cmdline;
}

static const char *_get_filename(int fd)
{
	static char filename[PATH_MAX];
	char buf[32];	/* Assumes short DEFAULT_PROC_DIR */
	int size;

	snprintf(buf, sizeof(buf), DEFAULT_PROC_DIR "/self/fd/%u", fd);

	if ((size = readlink(buf, filename, sizeof(filename) - 1)) == -1)
		filename[0] = '\0';
	else
		filename[size] = '\0';

	return filename;
}

static void _close_descriptor(int fd, unsigned suppress_warnings,
			      const char *command, pid_t ppid,
			      const char *parent_cmdline)
{
	int r;
	const char *filename;

	/* Ignore bad file descriptors */
	if (!is_valid_fd(fd))
		return;

	if (!suppress_warnings)
		filename = _get_filename(fd);

	r = close(fd);
	if (suppress_warnings)
		return;

	if (!r)
		fprintf(stderr, "File descriptor %d (%s) leaked on "
			"%s invocation.", fd, filename, command);
	else if (errno == EBADF)
		return;
	else
		fprintf(stderr, "Close failed on stray file descriptor "
			"%d (%s): %s", fd, filename, strerror(errno));

	fprintf(stderr, " Parent PID %" PRIpid_t ": %s\n", ppid, parent_cmdline);
}

static int _close_stray_fds(const char *command)
{
#ifndef VALGRIND_POOL
	struct rlimit rlim;
	int fd;
	unsigned suppress_warnings = 0;
	pid_t ppid = getppid();
	const char *parent_cmdline = _get_cmdline(ppid);
	static const char _fd_dir[] = DEFAULT_PROC_DIR "/self/fd";
	struct dirent *dirent;
	DIR *d;

#ifdef HAVE_VALGRIND
	if (RUNNING_ON_VALGRIND) {
		log_debug("Skipping close of descriptors within valgrind execution.");
		return 1;
	}
#endif

	if (getenv("LVM_SUPPRESS_FD_WARNINGS"))
		suppress_warnings = 1;

	if (!(d = opendir(_fd_dir))) {
		if (errno != ENOENT) {
			log_sys_error("opendir", _fd_dir);
			return 0; /* broken system */
		}

		/* Path does not exist, use the old way */
		if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
			log_sys_error("getrlimit", "RLIMIT_NOFILE");
			return 1;
		}

		for (fd = 3; fd < (int)rlim.rlim_cur; fd++)
			_close_descriptor(fd, suppress_warnings, command, ppid,
					  parent_cmdline);
		return 1;
	}

	while ((dirent = readdir(d))) {
		fd = atoi(dirent->d_name);
		if (fd > 2 && fd != dirfd(d))
			_close_descriptor(fd, suppress_warnings,
					  command, ppid, parent_cmdline);
	}

	if (closedir(d))
		log_sys_error("closedir", _fd_dir);
#endif

	return 1;
}

struct cmd_context *init_lvm(unsigned set_connections, unsigned set_filters)
{
	struct cmd_context *cmd;

	if (!udev_init_library_context())
		stack;

	/*
	 * It's not necessary to use name mangling for LVM:
	 *   - the character set used for LV names is subset of udev character set
	 *   - when we check other devices (e.g. device_is_usable fn), we use major:minor, not dm names
	 */
	dm_set_name_mangling_mode(DM_STRING_MANGLING_NONE);

	if (!(cmd = create_toolcontext(0, NULL, 1, 0,
			set_connections, set_filters))) {
		udev_fin_library_context();
		return_NULL;
	}

	_cmdline.arg_props = &_arg_props[0];

	if (stored_errno()) {
		destroy_toolcontext(cmd);
		udev_fin_library_context();
		return_NULL;
	}

	return cmd;
}

static void _fin_commands(void)
{
	int i;

	for (i = 0; i < _cmdline.num_commands; i++)
		dm_free(_cmdline.commands[i].valid_args);

	dm_free(_cmdline.commands);

	_cmdline.commands = NULL;
	_cmdline.num_commands = 0;
	_cmdline.commands_size = 0;
}

void lvm_fin(struct cmd_context *cmd)
{
	_fin_commands();
	destroy_toolcontext(cmd);
	udev_fin_library_context();
}

static int _run_script(struct cmd_context *cmd, int argc, char **argv)
{
	FILE *script;

	char buffer[CMD_LEN];
	int ret = 0;
	int magic_number = 0;
	char *script_file = argv[0];

	if ((script = fopen(script_file, "r")) == NULL)
		return ENO_SUCH_CMD;

	while (fgets(buffer, sizeof(buffer), script) != NULL) {
		if (!magic_number) {
			if (buffer[0] == '#' && buffer[1] == '!')
				magic_number = 1;
			else {
				ret = ENO_SUCH_CMD;
				break;
			}
		}
		if ((strlen(buffer) == sizeof(buffer) - 1)
		    && (buffer[sizeof(buffer) - 1] - 2 != '\n')) {
			buffer[50] = '\0';
			log_error("Line too long (max 255) beginning: %s",
				  buffer);
			ret = EINVALID_CMD_LINE;
			break;
		}
		if (lvm_split(buffer, &argc, argv, MAX_ARGS) == MAX_ARGS) {
			buffer[50] = '\0';
			log_error("Too many arguments: %s", buffer);
			ret = EINVALID_CMD_LINE;
			break;
		}
		if (!argc)
			continue;
		if (!strcmp(argv[0], "quit") || !strcmp(argv[0], "exit"))
			break;
		ret = lvm_run_command(cmd, argc, argv);
		if (ret != ECMD_PROCESSED) {
			if (!error_message_produced()) {
				log_debug(INTERNAL_ERROR "Failed command did not use log_error");
				log_error("Command failed with status code %d.", ret);
			}
			break;
		}
	}

	if (fclose(script))
		log_sys_error("fclose", script_file);

	return ret;
}

/*
 * Determine whether we should fall back and exec the equivalent LVM1 tool
 */
static int _lvm1_fallback(struct cmd_context *cmd)
{
	char vsn[80];
	int dm_present;

	if (!find_config_tree_bool(cmd, global_fallback_to_lvm1_CFG, NULL) ||
	    strncmp(cmd->kernel_vsn, "2.4.", 4))
		return 0;

	log_suppress(1);
	dm_present = driver_version(vsn, sizeof(vsn));
	log_suppress(0);

	if (dm_present || !lvm1_present(cmd))
		return 0;

	return 1;
}

static void _exec_lvm1_command(char **argv)
{
	char path[PATH_MAX];

	if (dm_snprintf(path, sizeof(path), "%s.lvm1", argv[0]) < 0) {
		log_error("Failed to create LVM1 tool pathname");
		return;
	}

	execvp(path, argv);
	log_sys_error("execvp", path);
}

static void _nonroot_warning(void)
{
	if (getuid() || geteuid())
		log_warn("WARNING: Running as a non-root user. Functionality may be unavailable.");
}

int lvm2_main(int argc, char **argv)
{
	const char *base;
	int ret, alias = 0;
	struct cmd_context *cmd;

	if (!argv)
		return -1;

	base = last_path_component(argv[0]);
	if (strcmp(base, "lvm") && strcmp(base, "lvm.static") &&
	    strcmp(base, "initrd-lvm"))
		alias = 1;

	if (!_check_standard_fds())
		return -1;

	if (!_close_stray_fds(base))
		return -1;

	if (is_static() && strcmp(base, "lvm.static") &&
	    path_exists(LVM_PATH) &&
	    !getenv("LVM_DID_EXEC")) {
		if (setenv("LVM_DID_EXEC", base, 1))
			log_sys_error("setenv", "LVM_DID_EXEC");
		if (execvp(LVM_PATH, argv) == -1)
			log_sys_error("execvp", LVM_PATH);
		if (unsetenv("LVM_DID_EXEC"))
			log_sys_error("unsetenv", "LVM_DID_EXEC");
	}

	/* "version" command is simple enough so it doesn't need any complex init */
	if (!alias && argc > 1 && !strcmp(argv[1], "version"))
		return lvm_return_code(version(NULL, argc, argv));

	if (!(cmd = init_lvm(0, 0)))
		return -1;

	cmd->argv = argv;
	lvm_register_commands();

	if (_lvm1_fallback(cmd)) {
		/* Attempt to run equivalent LVM1 tool instead */
		if (!alias) {
			argv++;
			argc--;
		}
		if (!argc) {
			log_error("Falling back to LVM1 tools, but no "
				  "command specified.");
			ret = ECMD_FAILED;
			goto out;
		}
		_exec_lvm1_command(argv);
		ret = ECMD_FAILED;
		goto_out;
	}
#ifdef READLINE_SUPPORT
	if (!alias && argc == 1) {
		_nonroot_warning();
		ret = lvm_shell(cmd, &_cmdline);
		goto out;
	}
#endif

	if (!alias) {
		if (argc < 2) {
			log_fatal("Please supply an LVM command.");
			_display_help();
			ret = EINVALID_CMD_LINE;
			goto out;
		}

		argc--;
		argv++;
	}

	_nonroot_warning();
	ret = lvm_run_command(cmd, argc, argv);
	if ((ret == ENO_SUCH_CMD) && (!alias))
		ret = _run_script(cmd, argc, argv);
	if (ret == ENO_SUCH_CMD)
		log_error("No such command.  Try 'help'.");

	if ((ret != ECMD_PROCESSED) && !error_message_produced()) {
		log_debug(INTERNAL_ERROR "Failed command did not use log_error");
		log_error("Command failed with status code %d.", ret);
	}

      out:
	lvm_fin(cmd);
	return lvm_return_code(ret);
}
