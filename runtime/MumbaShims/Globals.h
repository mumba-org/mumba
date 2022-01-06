// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_GLOBALS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_GLOBALS_H_

#ifdef __cplusplus
#define EXTERN_ extern "C"
#else
#define EXTERN_
#endif

#define EXPORT EXTERN_ __attribute__((__visibility__("default")))


#if defined(ANDROID)
#define OS_ANDROID 1
#elif defined(__APPLE__)
// only include TargetConditions after testing ANDROID as some android builds
// on mac don't have this header available and it's not needed unless the target
// is really mac/ios.
#include <TargetConditionals.h>
#define OS_MACOSX 1
#if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
#define OS_IOS 1
#endif  // defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
#elif defined(__linux__)
#define OS_LINUX 1
// include a system header to pull in features.h for glibc/uclibc macros.
//#include <unistd.h>
#if defined(__GLIBC__) && !defined(__UCLIBC__)
// we really are using glibc, not uClibc pretending to be glibc
#define LIBC_GLIBC 1
#endif
#elif defined(_WIN32)
#define OS_WIN 1
#define TOOLKIT_VIEWS 1
#elif defined(__FreeBSD__)
#define OS_FREEBSD 1
#elif defined(__OpenBSD__)
#define OS_OPENBSD 1
#elif defined(__sun)
#define OS_SOLARIS 1
#elif defined(__QNXNTO__)
#define OS_QNX 1
#else
#error Please add support for your platform in build/build_config.h
#endif

#if defined(USE_OPENSSL_ERTS) && defined(USE_NSS_ERTS)
#error Cannot use both OpenSSL and NSS for certificates
#endif

// For access to standard BSD features, use OS_BSD instead of a
// more specific macro.
#if defined(OS_FREEBSD) || defined(OS_OPENBSD)
#define OS_BSD 1
#endif

// For access to standard POSIXish features, use OS_POSIX instead of a
// more specific macro.
#if defined(OS_MACOSX) || defined(OS_LINUX) || defined(OS_FREEBSD) ||     \
    defined(OS_OPENBSD) || defined(OS_SOLARIS) || defined(OS_ANDROID) ||  \
    defined(OS_NACL) || defined(OS_QNX)
#define OS_POSIX 1
#endif

// Use tcmalloc
#if (defined(OS_WIN) || defined(OS_LINUX) || defined(OS_ANDROID)) && \
    !defined(NO_TCMALLOC)
#define USE_TCMALLOC 1
#endif

// Compiler detection.
#if defined(__GNUC__)
#define COMPILER_GCC 1
#elif defined(_MSC_VER)
#define COMPILER_MSVC 1
#else
#error Please add support for your compiler in build/build_config.h
#endif

// Processor architecture detection.  For more info on what's defined, see:
//   http://msdn.microsoft.com/en-us/library/b0084kay.aspx
//   http://www.agner.org/optimize/calling_conventions.pdf
//   or with gcc, run: "echo | gcc -E -dM -"
#if defined(_M_X64) || defined(__x86_64__)
#define ARCH_PU_X86_FAMILY 1
#define ARCH_PU_X86_64 1
#define ARCH_PU_64_BITS 1
#define ARCH_PU_LITTLE_ENDIAN 1
#elif defined(_M_IX86) || defined(__i386__)
#define ARCH_PU_X86_FAMILY 1
#define ARCH_PU_X86 1
#define ARCH_PU_32_BITS 1
#define ARCH_PU_LITTLE_ENDIAN 1
#elif defined(__ARMEL__)
#define ARCH_PU_ARM_FAMILY 1
#define ARCH_PU_ARMEL 1
#define ARCH_PU_32_BITS 1
#define ARCH_PU_LITTLE_ENDIAN 1
#elif defined(__aarch64__)
#define ARCH_PU_ARM_FAMILY 1
#define ARCH_PU_ARM64 1
#define ARCH_PU_64_BITS 1
#define ARCH_PU_LITTLE_ENDIAN 1
#elif defined(__pnacl__)
#define ARCH_PU_32_BITS 1
#define ARCH_PU_LITTLE_ENDIAN 1
#elif defined(__MIPSEL__)
#if defined(__LP64__)
#define ARCH_PU_MIPS64_FAMILY 1
#define ARCH_PU_MIPS64EL 1
#define ARCH_PU_64_BITS 1
#define ARCH_PU_LITTLE_ENDIAN 1
#else
#define ARCH_PU_MIPS_FAMILY 1
#define ARCH_PU_MIPSEL 1
#define ARCH_PU_32_BITS 1
#define ARCH_PU_LITTLE_ENDIAN 1
#endif
#else
#error Please add support for your architecture in build/build_config.h
#endif

// Type detection for wchar_t.
#if defined(OS_WIN)
#define WCHAR_T_IS_UTF16
#elif defined(OS_POSIX) && defined(COMPILER_GCC) && \
    defined(__WCHAR_MAX__) && \
    (__WCHAR_MAX__ == 0x7fffffff || __WCHAR_MAX__ == 0xffffffff)
#define WCHAR_T_IS_UTF32
#elif defined(OS_POSIX) && defined(COMPILER_GCC) && \
    defined(__WCHAR_MAX__) && \
    (__WCHAR_MAX__ == 0x7fff || __WCHAR_MAX__ == 0xffff)
// On Posix, we'll detect short wchar_t, but projects aren't guaranteed to
// compile in this mode (in particular, Chrome doesn't). This is intended for
// other projects using base who manage their own dependencies and make sure
// short wchar works for them.
#define WCHAR_T_IS_UTF16
#else
#error Please add support for your compiler in build/build_config.h
#endif

// the swift compiler is having trouble following the includes of stdint.h
// so unfortunatelly we need to set this here
// #ifndef _BITS_STDINT_INTN_H
// typedef signed char int8_t;
// typedef unsigned char uint8_t;
// typedef signed short int int16_t;
// typedef unsigned short int uint16_t;
// typedef signed int int32_t;
// typedef unsigned int uint32_t;
// //#if defined(OS_WIN)
// #if ARCH_PU_64_BITS
// typedef __int64 int64_t;
// typedef unsigned __int64 uint64_t;
// #else
// typedef signed long long int int64_t;
// typedef unsigned long long int uint64_t;
// #endif
// typedef unsigned long size_t;
// //#endif // OS_WIN
// #endif // #ifndef _STDINT_H

#ifndef size_t
typedef unsigned long size_t;
#endif

#ifndef UINT_MAX
#define UINT_MAX 4294967295U
#endif

#endif
