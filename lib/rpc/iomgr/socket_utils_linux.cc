/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "rpc/iomgr/port.h"

#ifdef GRPC_LINUX_SOCKETUTILS

#include "rpc/iomgr/sockaddr.h"
#include "rpc/iomgr/socket_utils_posix.h"

#include <rpc/support/log.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

int grpc_accept4(int sockfd, grpc_resolved_address* resolved_addr, int nonblock,
                 int cloexec) {
  int flags = 0;
  GPR_ASSERT(sizeof(socklen_t) <= sizeof(size_t));
  GPR_ASSERT(resolved_addr->len <= (socklen_t)-1);
  flags |= nonblock ? SOCK_NONBLOCK : 0;
  flags |= cloexec ? SOCK_CLOEXEC : 0;
  return accept4(sockfd, (struct sockaddr*)resolved_addr->addr,
                 (socklen_t*)&resolved_addr->len, flags);
}

int grpc_accept(int sockfd, grpc_resolved_address* resolved_addr, int nonblock,
                int cloexec) {
  int fd, flags;
  GPR_ASSERT(sizeof(socklen_t) <= sizeof(size_t));
  GPR_ASSERT(resolved_addr->len <= (socklen_t)-1);
  fd = accept(sockfd, (struct sockaddr*)resolved_addr->addr,
              (socklen_t*)&resolved_addr->len);
  if (fd >= 0) {
    if (nonblock) {
      flags = fcntl(fd, F_GETFL, 0);
      if (flags < 0) goto close_and_error;
      if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) goto close_and_error;
    }
    if (cloexec) {
      flags = fcntl(fd, F_GETFD, 0);
      if (flags < 0) goto close_and_error;
      if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) goto close_and_error;
    }
  }
  return fd;

close_and_error:
  close(fd);
  return -1;
}

#endif
