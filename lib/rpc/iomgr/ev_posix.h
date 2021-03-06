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

#ifndef GRPC_CORE_LIB_IOMGR_EV_POSIX_H
#define GRPC_CORE_LIB_IOMGR_EV_POSIX_H

#include <poll.h>

#include "rpc/debug/trace.h"
#include "rpc/iomgr/exec_ctx.h"
#include "rpc/iomgr/pollset.h"
#include "rpc/iomgr/pollset_set.h"
#include "rpc/iomgr/wakeup_fd_posix.h"

GRPCAPI extern grpc_core::TraceFlag grpc_polling_trace; /* Disabled by default */

typedef struct grpc_fd grpc_fd;

typedef struct grpc_event_engine_vtable {
  size_t pollset_size;

  grpc_fd* (*fd_create)(int fd, const char* name);
  int (*fd_wrapped_fd)(grpc_fd* fd);
  void (*fd_orphan)(grpc_exec_ctx* exec_ctx, grpc_fd* fd, grpc_closure* on_done,
                    int* release_fd, bool already_closed, const char* reason);
  void (*fd_shutdown)(grpc_exec_ctx* exec_ctx, grpc_fd* fd, grpc_error* why);
  void (*fd_notify_on_read)(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                            grpc_closure* closure);
  void (*fd_notify_on_write)(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                             grpc_closure* closure);
  bool (*fd_is_shutdown)(grpc_fd* fd);
  grpc_pollset* (*fd_get_read_notifier_pollset)(grpc_exec_ctx* exec_ctx,
                                                grpc_fd* fd);

  void (*pollset_init)(grpc_pollset* pollset, gpr_mu** mu);
  void (*pollset_shutdown)(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                           grpc_closure* closure);
  void (*pollset_destroy)(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset);
  grpc_error* (*pollset_work)(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                              grpc_pollset_worker** worker,
                              grpc_millis deadline);
  grpc_error* (*pollset_kick)(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                              grpc_pollset_worker* specific_worker);
  void (*pollset_add_fd)(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                         struct grpc_fd* fd);

  grpc_pollset_set* (*pollset_set_create)(void);
  void (*pollset_set_destroy)(grpc_exec_ctx* exec_ctx,
                              grpc_pollset_set* pollset_set);
  void (*pollset_set_add_pollset)(grpc_exec_ctx* exec_ctx,
                                  grpc_pollset_set* pollset_set,
                                  grpc_pollset* pollset);
  void (*pollset_set_del_pollset)(grpc_exec_ctx* exec_ctx,
                                  grpc_pollset_set* pollset_set,
                                  grpc_pollset* pollset);
  void (*pollset_set_add_pollset_set)(grpc_exec_ctx* exec_ctx,
                                      grpc_pollset_set* bag,
                                      grpc_pollset_set* item);
  void (*pollset_set_del_pollset_set)(grpc_exec_ctx* exec_ctx,
                                      grpc_pollset_set* bag,
                                      grpc_pollset_set* item);
  void (*pollset_set_add_fd)(grpc_exec_ctx* exec_ctx,
                             grpc_pollset_set* pollset_set, grpc_fd* fd);
  void (*pollset_set_del_fd)(grpc_exec_ctx* exec_ctx,
                             grpc_pollset_set* pollset_set, grpc_fd* fd);

  void (*shutdown_engine)(void);
} grpc_event_engine_vtable;

GRPCAPI void grpc_event_engine_init(void);
GRPCAPI void grpc_event_engine_shutdown(void);

/* Return the name of the poll strategy */
GRPCAPI const char* grpc_get_poll_strategy_name();

/* Create a wrapped file descriptor.
   Requires fd is a non-blocking file descriptor.
   This takes ownership of closing fd. */
GRPCAPI grpc_fd* grpc_fd_create(int fd, const char* name);

/* Return the wrapped fd, or -1 if it has been released or closed. */
GRPCAPI int grpc_fd_wrapped_fd(grpc_fd* fd);

/* Releases fd to be asynchronously destroyed.
   on_done is called when the underlying file descriptor is definitely close()d.
   If on_done is NULL, no callback will be made.
   If release_fd is not NULL, it's set to fd and fd will not be closed.
   Requires: *fd initialized; no outstanding notify_on_read or
   notify_on_write.
   MUST NOT be called with a pollset lock taken */
GRPCAPI void grpc_fd_orphan(grpc_exec_ctx* exec_ctx, grpc_fd* fd, grpc_closure* on_done,
                    int* release_fd, bool already_closed, const char* reason);

/* Has grpc_fd_shutdown been called on an fd? */
GRPCAPI bool grpc_fd_is_shutdown(grpc_fd* fd);

/* Cause any current and future callbacks to fail. */
GRPCAPI void grpc_fd_shutdown(grpc_exec_ctx* exec_ctx, grpc_fd* fd, grpc_error* why);

/* Register read interest, causing read_cb to be called once when fd becomes
   readable, on deadline specified by deadline, or on shutdown triggered by
   grpc_fd_shutdown.
   read_cb will be called with read_cb_arg when *fd becomes readable.
   read_cb is Called with status of GRPC_CALLBACK_SUCCESS if readable,
   GRPC_CALLBACK_TIMED_OUT if the call timed out,
   and CANCELLED if the call was cancelled.

   Requires:This method must not be called before the read_cb for any previous
   call runs. Edge triggered events are used whenever they are supported by the
   underlying platform. This means that users must drain fd in read_cb before
   calling notify_on_read again. Users are also expected to handle spurious
   events, i.e read_cb is called while nothing can be readable from fd  */
GRPCAPI void grpc_fd_notify_on_read(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                            grpc_closure* closure);

/* Exactly the same semantics as above, except based on writable events.  */
GRPCAPI void grpc_fd_notify_on_write(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                             grpc_closure* closure);

/* Return the read notifier pollset from the fd */
GRPCAPI grpc_pollset* grpc_fd_get_read_notifier_pollset(grpc_exec_ctx* exec_ctx,
                                                grpc_fd* fd);

/* pollset_posix functions */

/* Add an fd to a pollset */
GRPCAPI void grpc_pollset_add_fd(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                         struct grpc_fd* fd);

/* pollset_set_posix functions */

GRPCAPI void grpc_pollset_set_add_fd(grpc_exec_ctx* exec_ctx,
                             grpc_pollset_set* pollset_set, grpc_fd* fd);
GRPCAPI void grpc_pollset_set_del_fd(grpc_exec_ctx* exec_ctx,
                             grpc_pollset_set* pollset_set, grpc_fd* fd);

/* override to allow tests to hook poll() usage */
typedef int (*grpc_poll_function_type)(struct pollfd*, nfds_t, int);
extern grpc_poll_function_type grpc_poll_function;

/* WARNING: The following two functions should be used for testing purposes
 * ONLY */
void grpc_set_event_engine_test_only(const grpc_event_engine_vtable*);
const grpc_event_engine_vtable* grpc_get_event_engine_test_only();

#endif /* GRPC_CORE_LIB_IOMGR_EV_POSIX_H */
