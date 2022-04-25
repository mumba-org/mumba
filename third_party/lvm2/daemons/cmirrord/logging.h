/*
 * Copyright (C) 2004-2009 Red Hat, Inc. All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _LVM_CLOG_LOGGING_H
#define _LVM_CLOG_LOGGING_H

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include "configure.h"
#include <stdio.h>
#include <stdint.h>
#include <syslog.h>

/* SHORT_UUID - print last 8 chars of a string */
#define SHORT_UUID(x) (strlen(x) > 8) ? ((x) + (strlen(x) - 8)) : (x)

extern const char *__rq_types_off_by_one[];
#define RQ_TYPE(x) __rq_types_off_by_one[(x) - 1]

extern int log_tabbing;
extern int log_is_open;
extern int log_membership_change;
extern int log_checkpoint;
extern int log_resend_requests;

#define LOG_OPEN(ident, option, facility) do { \
		openlog(ident, option, facility); \
		log_is_open = 1;		  \
	} while (0)

#define LOG_CLOSE(void) do { \
		log_is_open = 0; \
		closelog();	 \
	} while (0)

#define LOG_OUTPUT(level, f, arg...) do {				\
		int __i;						\
		char __buffer[16];					\
		FILE *fp = (level > LOG_NOTICE) ? stderr : stdout;	\
		if (log_is_open) {					\
			for (__i = 0; (__i < log_tabbing) && (__i < 15); __i++) \
				__buffer[__i] = '\t';			\
			__buffer[__i] = '\0';				\
			syslog(level, "%s" f "\n", __buffer, ## arg);	\
		} else {						\
			for (__i = 0; __i < log_tabbing; __i++)		\
				fprintf(fp, "\t");			\
			fprintf(fp, f "\n", ## arg);			\
		}							\
	} while (0)


#ifdef DEBUG
#define LOG_DBG(f, arg...) LOG_OUTPUT(LOG_DEBUG, f, ## arg)
#else /* DEBUG */
#define LOG_DBG(f, arg...) do {} while (0)
#endif /* DEBUG */

#define LOG_COND(__X, f, arg...) do {\
		if (__X) { 	     \
			LOG_OUTPUT(LOG_NOTICE, f, ## arg); \
		} \
	} while (0)
#define LOG_PRINT(f, arg...) LOG_OUTPUT(LOG_NOTICE, f, ## arg)
#define LOG_ERROR(f, arg...) LOG_OUTPUT(LOG_ERR, f, ## arg)

#endif /* _LVM_CLOG_LOGGING_H */
