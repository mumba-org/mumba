/*
 *
 * Copyright 2016 gRPC authors.
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

#ifdef GRPC_POSIX_WAKEUP_FD

#include "rpc/iomgr/wakeup_fd_cv.h"

#include <errno.h>
#include <string.h>

#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/sync.h>
#include <rpc/support/thd.h>
#include <rpc/support/time.h>
#include <rpc/support/useful.h>

#define MAX_TABLE_RESIZE 256

extern cv_fd_table g_cvfds;

static grpc_error* cv_fd_init(grpc_wakeup_fd* fd_info) {
  unsigned int i, newsize;
  int idx;
  gpr_mu_lock(&g_cvfds.mu);
  if (!g_cvfds.free_fds) {
    newsize = GPR_MIN(g_cvfds.size * 2, g_cvfds.size + MAX_TABLE_RESIZE);
    g_cvfds.cvfds =
        (fd_node*)gpr_realloc(g_cvfds.cvfds, sizeof(fd_node) * newsize);
    for (i = g_cvfds.size; i < newsize; i++) {
      g_cvfds.cvfds[i].is_set = 0;
      g_cvfds.cvfds[i].cvs = nullptr;
      g_cvfds.cvfds[i].next_free = g_cvfds.free_fds;
      g_cvfds.free_fds = &g_cvfds.cvfds[i];
    }
    g_cvfds.size = newsize;
  }

  idx = (int)(g_cvfds.free_fds - g_cvfds.cvfds);
  g_cvfds.free_fds = g_cvfds.free_fds->next_free;
  g_cvfds.cvfds[idx].cvs = nullptr;
  g_cvfds.cvfds[idx].is_set = 0;
  fd_info->read_fd = GRPC_IDX_TO_FD(idx);
  fd_info->write_fd = -1;
  gpr_mu_unlock(&g_cvfds.mu);
  return GRPC_ERROR_NONE;
}

static grpc_error* cv_fd_wakeup(grpc_wakeup_fd* fd_info) {
  cv_node* cvn;
  gpr_mu_lock(&g_cvfds.mu);
  g_cvfds.cvfds[GRPC_FD_TO_IDX(fd_info->read_fd)].is_set = 1;
  cvn = g_cvfds.cvfds[GRPC_FD_TO_IDX(fd_info->read_fd)].cvs;
  while (cvn) {
    gpr_cv_signal(cvn->cv);
    cvn = cvn->next;
  }
  gpr_mu_unlock(&g_cvfds.mu);
  return GRPC_ERROR_NONE;
}

static grpc_error* cv_fd_consume(grpc_wakeup_fd* fd_info) {
  gpr_mu_lock(&g_cvfds.mu);
  g_cvfds.cvfds[GRPC_FD_TO_IDX(fd_info->read_fd)].is_set = 0;
  gpr_mu_unlock(&g_cvfds.mu);
  return GRPC_ERROR_NONE;
}

static void cv_fd_destroy(grpc_wakeup_fd* fd_info) {
  if (fd_info->read_fd == 0) {
    return;
  }
  gpr_mu_lock(&g_cvfds.mu);
  // Assert that there are no active pollers
  GPR_ASSERT(!g_cvfds.cvfds[GRPC_FD_TO_IDX(fd_info->read_fd)].cvs);
  g_cvfds.cvfds[GRPC_FD_TO_IDX(fd_info->read_fd)].next_free = g_cvfds.free_fds;
  g_cvfds.free_fds = &g_cvfds.cvfds[GRPC_FD_TO_IDX(fd_info->read_fd)];
  gpr_mu_unlock(&g_cvfds.mu);
}

static int cv_check_availability(void) { return 1; }

const grpc_wakeup_fd_vtable grpc_cv_wakeup_fd_vtable = {
    cv_fd_init, cv_fd_consume, cv_fd_wakeup, cv_fd_destroy,
    cv_check_availability};

#endif /* GRPC_POSIX_WAKUP_FD */
