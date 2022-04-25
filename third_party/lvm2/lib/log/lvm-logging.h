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

#ifndef _LVM_LOGGING_H
#define _LVM_LOGGING_H

void print_log(int level, const char *file, int line, int dm_errno_or_class,
	       const char *format, ...)
    __attribute__ ((format(printf, 5, 6)));

#define LOG_LINE(l, x...) \
    print_log(l, __FILE__, __LINE__ , 0, ## x)

#define LOG_LINE_WITH_ERRNO(l, e, x...) \
    print_log(l, __FILE__, __LINE__ , e, ## x)

#define LOG_LINE_WITH_CLASS(l, c, x...) \
    print_log(l, __FILE__, __LINE__ , c, ## x)

#include "log.h"

typedef void (*lvm2_log_fn_t) (int level, const char *file, int line,
			       int dm_errno_or_class, const char *message);

void init_log_fn(lvm2_log_fn_t log_fn);

void init_indent(int indent);
void init_msg_prefix(const char *prefix);

void init_log_file(const char *log_file, int append);
void unlink_log_file(int ret);
void init_log_direct(const char *log_file, int append);
void init_log_while_suspended(int log_while_suspended);
void init_abort_on_internal_errors(int fatal);

void fin_log(void);
void release_log_memory(void);
void reset_log_duplicated(void);

void init_syslog(int facility);
void fin_syslog(void);

int error_message_produced(void);
void reset_lvm_errno(int store_errmsg);
int stored_errno(void);
const char *stored_errmsg(void);
const char *stored_errmsg_with_clear(void);

/* Suppress messages to stdout/stderr (1) or everywhere (2) */
/* Returns previous setting */
int log_suppress(int suppress);

/* Suppress messages to syslog */
void syslog_suppress(int suppress);

#endif
