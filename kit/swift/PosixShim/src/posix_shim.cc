// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "../include/posix.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>

int posix_fcntl(int fd, int command, int flags) {
  return fcntl(fd, command, flags);
}

int posix_pipe2(int fds[2], int flags) {
  int rc = pipe(fds);
  fcntl(fds[0], F_SETFL, flags);
  fcntl(fds[1], F_SETFL, flags);
  return rc;
}

int posix_read(int fd, char* buf, size_t size) {
  return HANDLE_EINTR(read(fd, buf, size));
}

int posix_write(int fd, char* buf, size_t size) {
  return HANDLE_EINTR(write(fd, buf, size));
}

int posix_close(int fd) {
  return close(fd);
}