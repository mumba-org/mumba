// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_POSIX_SHIMS_H_
#define MUMBA_KIT_POSIX_SHIMS_H_

#include "globals.h"

EXPORT int posix_fcntl(int fd, int command, int flags);
EXPORT int posix_pipe2(int fds[2], int flags);
EXPORT int posix_read(int fd, char* buf, size_t size);
EXPORT int posix_write(int fd, char* buf, size_t size);
EXPORT int posix_close(int fd);
#if defined(OS_LINUX)
EXPORT int posix_prctl1(int option, unsigned long arg2);
EXPORT int posix_prctl1p(int option, const void* arg2);
EXPORT int posix_prctl2(int option, unsigned long arg2, unsigned long arg3);
EXPORT int posix_prctl3(int option, unsigned long arg2, unsigned long arg3,
                        unsigned long arg4);                                              
EXPORT int posix_prctl4(int option, unsigned long arg2, unsigned long arg3,
                       unsigned long arg4, unsigned long arg5);

EXPORT int posix_get_thread_id();
#endif

#endif
