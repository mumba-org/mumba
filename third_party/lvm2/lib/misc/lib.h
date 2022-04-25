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

/*
 * This file must be included first by every library source file.
 */
#ifndef _LVM_LIB_H
#define _LVM_LIB_H

#include "configure.h"

#define _REENTRANT
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

/*
 * Symbol export control macros
 *
 *   DM_EXPORT_SYMBOL(func,ver)
 *   DM_EXPORT_SYMBOL_BASE(func,ver)
 *
 * For functions that have multiple implementations these macros control
 * symbol export and versioning.
 *
 * Function definitions that exist in only one version never need to use
 * these macros.
 *
 * Backwards compatible implementations must include a version tag of
 * the form "_v1_02_104" as a suffix to the function name and use the
 * macro DM_EXPORT_SYMBOL to export the function and bind it to the
 * specified version string.
 *
 * Since versioning is only available when compiling with GCC the entire
 * compatibility version should be enclosed in '#if defined(__GNUC__)',
 * for example:
 *
 *   int dm_foo(int bar)
 *   {
 *     return bar;
 *   }
 *
 *   #if defined(__GNUC__)
 *   // Backward compatible dm_foo() version 1.02.104
 *   int dm_foo_v1_02_104(void);
 *   int dm_foo_v1_02_104(void)
 *   {
 *     return 0;
 *   }
 *   DM_EXPORT_SYMBOL(dm_foo,1_02_104)
 *   #endif
 *
 * A prototype for the compatibility version is required as these
 * functions must not be declared static.
 *
 * The DM_EXPORT_SYMBOL_BASE macro is only used to export the base
 * versions of library symbols prior to the introduction of symbol
 * versioning: it must never be used for new symbols.
 */
#if defined(__GNUC__)
#define DM_EXPORT_SYMBOL(func, ver) \
	__asm__(".symver " #func "_v" #ver ", " #func "@DM_" #ver )
#define DM_EXPORT_SYMBOL_BASE(func) \
	__asm__(".symver " #func "_base, " #func "@Base" )
#else
#define DM_EXPORT_SYMBOL(func, ver)
#define DM_EXPORT_SYMBOL_BASE(func)
#endif


#include "intl.h"
#include "libdevmapper.h"
#include "util.h"

#ifdef DM
#  include "dm-logging.h"
#else
#  include "lvm-logging.h"
#  include "lvm-globals.h"
#  include "lvm-wrappers.h"
#endif

#include <unistd.h>

#endif
