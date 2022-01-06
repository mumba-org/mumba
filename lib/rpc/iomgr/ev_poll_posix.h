/*
 *
 * Copyright 2015-2016 gRPC authors.
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

#ifndef GRPC_CORE_LIB_IOMGR_EV_POLL_POSIX_H
#define GRPC_CORE_LIB_IOMGR_EV_POLL_POSIX_H

#include "rpc/iomgr/ev_posix.h"

typedef struct grpc_cached_wakeup_fd {
  grpc_wakeup_fd fd;
  struct grpc_cached_wakeup_fd* next;
} grpc_cached_wakeup_fd;

struct grpc_pollset_worker {
  grpc_cached_wakeup_fd* wakeup_fd;
  int reevaluate_polling_on_wakeup;
  int kicked_specifically;
  struct grpc_pollset_worker* next;
  struct grpc_pollset_worker* prev;
};

struct grpc_pollset {
  gpr_mu mu;
  grpc_pollset_worker root_worker;
  int shutting_down;
  int called_shutdown;
  int kicked_without_pollers;
  grpc_closure* shutdown_done;
  grpc_closure_list idle_jobs;
  int pollset_set_count;
  /* all polled fds */
  size_t fd_count;
  size_t fd_capacity;
  grpc_fd** fds;
  /* Local cache of eventfds for workers */
  grpc_cached_wakeup_fd* local_wakeup_cache;
};

const grpc_event_engine_vtable* grpc_init_poll_posix(bool explicit_request);
const grpc_event_engine_vtable* grpc_init_poll_cv_posix(bool explicit_request);

#endif /* GRPC_CORE_LIB_IOMGR_EV_POLL_POSIX_H */
