// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "../include/posix.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

int posix_prctl1(int option, unsigned long arg2) {
 return prctl(option, arg2);
}

int posix_prctl1p(int option, const void* arg2) {
  return prctl(option, arg2);
}

int posix_prctl2(int option, unsigned long arg2, unsigned long arg3) {
 return prctl(option, arg2, arg3);
}

int posix_prctl3(int option, unsigned long arg2, unsigned long arg3,
                        unsigned long arg4) {
 return prctl(option, arg2, arg3, arg4);
}

int posix_prctl4(int option, unsigned long arg2, unsigned long arg3,
                unsigned long arg4, unsigned long arg5) {
  return prctl(option, arg2, arg3, arg4, arg5);
}

int posix_get_thread_id() {
  return syscall(__NR_gettid);
}