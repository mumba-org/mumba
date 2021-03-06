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

#ifdef GRPC_POSIX_SOCKET

#include "rpc/iomgr/ev_posix.h"

#include <string.h>

#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>
#include <rpc/support/useful.h>

#include "rpc/debug/trace.h"
#include "rpc/iomgr/ev_epoll1_linux.h"
#include "rpc/iomgr/ev_epollex_linux.h"
#include "rpc/iomgr/ev_epollsig_linux.h"
#include "rpc/iomgr/ev_poll_posix.h"
#include "rpc/support/env.h"

grpc_core::TraceFlag grpc_polling_trace(false,
                                        "polling"); /* Disabled by default */
grpc_core::DebugOnlyTraceFlag grpc_trace_fd_refcount(false, "fd_refcount");

/** Default poll() function - a pointer so that it can be overridden by some
 *  tests */
grpc_poll_function_type grpc_poll_function = poll;

grpc_wakeup_fd grpc_global_wakeup_fd;

static const grpc_event_engine_vtable* g_event_engine;
static const char* g_poll_strategy_name = nullptr;

typedef const grpc_event_engine_vtable* (*event_engine_factory_fn)(
    bool explicit_request);

typedef struct {
  const char* name;
  event_engine_factory_fn factory;
} event_engine_factory;

namespace {

grpc_poll_function_type real_poll_function;

int dummy_poll(struct pollfd fds[], nfds_t nfds, int timeout) {
  if (timeout == 0) {
    return real_poll_function(fds, nfds, 0);
  } else {
    gpr_log(GPR_ERROR, "Attempted a blocking poll when declared non-polling.");
    GPR_ASSERT(false);
    return -1;
  }
}

const grpc_event_engine_vtable* init_non_polling(bool explicit_request) {
  if (!explicit_request) {
    return nullptr;
  }
  // return the simplest engine as a dummy but also override the poller
  auto* ret = grpc_init_poll_posix(explicit_request);
  real_poll_function = grpc_poll_function;
  grpc_poll_function = dummy_poll;

  return ret;
}
}  // namespace

static const event_engine_factory g_factories[] = {
    {"epollex", grpc_init_epollex_linux},   {"epoll1", grpc_init_epoll1_linux},
    {"epollsig", grpc_init_epollsig_linux}, {"poll", grpc_init_poll_posix},
    {"poll-cv", grpc_init_poll_cv_posix},   {"none", init_non_polling},
};

static void add(const char* beg, const char* end, char*** ss, size_t* ns) {
  size_t n = *ns;
  size_t np = n + 1;
  char* s;
  size_t len;
  GPR_ASSERT(end >= beg);
  len = (size_t)(end - beg);
  s = (char*)gpr_malloc(len + 1);
  memcpy(s, beg, len);
  s[len] = 0;
  *ss = (char**)gpr_realloc(*ss, sizeof(char**) * np);
  (*ss)[n] = s;
  *ns = np;
}

static void split(const char* s, char*** ss, size_t* ns) {
  const char* c = strchr(s, ',');
  if (c == nullptr) {
    add(s, s + strlen(s), ss, ns);
  } else {
    add(s, c, ss, ns);
    split(c + 1, ss, ns);
  }
}

static bool is(const char* want, const char* have) {
  return 0 == strcmp(want, "all") || 0 == strcmp(want, have);
}

static void try_engine(const char* engine) {
  for (size_t i = 0; i < GPR_ARRAY_SIZE(g_factories); i++) {
    if (is(engine, g_factories[i].name)) {
      if ((g_event_engine = g_factories[i].factory(
               0 == strcmp(engine, g_factories[i].name)))) {
        g_poll_strategy_name = g_factories[i].name;
        gpr_log(GPR_DEBUG, "Using polling engine: %s", g_factories[i].name);
        return;
      }
    }
  }
}

/* This should be used for testing purposes ONLY */
void grpc_set_event_engine_test_only(
    const grpc_event_engine_vtable* ev_engine) {
  g_event_engine = ev_engine;
}

const grpc_event_engine_vtable* grpc_get_event_engine_test_only() {
  return g_event_engine;
}

/* Call this only after calling grpc_event_engine_init() */
const char* grpc_get_poll_strategy_name() { return g_poll_strategy_name; }

void grpc_event_engine_init(void) {
  char* s = gpr_getenv("GRPC_POLL_STRATEGY");
  if (s == nullptr) {
    //s = gpr_strdup("all");
    s = gpr_strdup("epollex");
  }

  char** strings = nullptr;
  size_t nstrings = 0;
  split(s, &strings, &nstrings);

  for (size_t i = 0; g_event_engine == nullptr && i < nstrings; i++) {
    try_engine(strings[i]);
  }

  for (size_t i = 0; i < nstrings; i++) {
    gpr_free(strings[i]);
  }
  gpr_free(strings);

  if (g_event_engine == nullptr) {
    gpr_log(GPR_ERROR, "No event engine could be initialized from %s", s);
    abort();
  }
  gpr_free(s);
}

void grpc_event_engine_shutdown(void) {
  g_event_engine->shutdown_engine();
  g_event_engine = nullptr;
}

grpc_fd* grpc_fd_create(int fd, const char* name) {
  return g_event_engine->fd_create(fd, name);
}

int grpc_fd_wrapped_fd(grpc_fd* fd) {
  return g_event_engine->fd_wrapped_fd(fd);
}

void grpc_fd_orphan(grpc_exec_ctx* exec_ctx, grpc_fd* fd, grpc_closure* on_done,
                    int* release_fd, bool already_closed, const char* reason) {
  g_event_engine->fd_orphan(exec_ctx, fd, on_done, release_fd, already_closed,
                            reason);
}

void grpc_fd_shutdown(grpc_exec_ctx* exec_ctx, grpc_fd* fd, grpc_error* why) {
  g_event_engine->fd_shutdown(exec_ctx, fd, why);
}

bool grpc_fd_is_shutdown(grpc_fd* fd) {
  return g_event_engine->fd_is_shutdown(fd);
}

void grpc_fd_notify_on_read(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                            grpc_closure* closure) {
  g_event_engine->fd_notify_on_read(exec_ctx, fd, closure);
}

void grpc_fd_notify_on_write(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                             grpc_closure* closure) {
  g_event_engine->fd_notify_on_write(exec_ctx, fd, closure);
}

size_t grpc_pollset_size(void) { return g_event_engine->pollset_size; }

void grpc_pollset_init(grpc_pollset* pollset, gpr_mu** mu) {
  g_event_engine->pollset_init(pollset, mu);
}

void grpc_pollset_shutdown(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                           grpc_closure* closure) {
  g_event_engine->pollset_shutdown(exec_ctx, pollset, closure);
}

void grpc_pollset_destroy(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset) {
  g_event_engine->pollset_destroy(exec_ctx, pollset);
}

grpc_error* grpc_pollset_work(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                              grpc_pollset_worker** worker,
                              grpc_millis deadline) {
  return g_event_engine->pollset_work(exec_ctx, pollset, worker, deadline);
}

grpc_error* grpc_pollset_kick(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                              grpc_pollset_worker* specific_worker) {
  return g_event_engine->pollset_kick(exec_ctx, pollset, specific_worker);
}

void grpc_pollset_add_fd(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                         struct grpc_fd* fd) {
  g_event_engine->pollset_add_fd(exec_ctx, pollset, fd);
}

grpc_pollset_set* grpc_pollset_set_create(void) {
  return g_event_engine->pollset_set_create();
}

void grpc_pollset_set_destroy(grpc_exec_ctx* exec_ctx,
                              grpc_pollset_set* pollset_set) {
  g_event_engine->pollset_set_destroy(exec_ctx, pollset_set);
}

void grpc_pollset_set_add_pollset(grpc_exec_ctx* exec_ctx,
                                  grpc_pollset_set* pollset_set,
                                  grpc_pollset* pollset) {
  g_event_engine->pollset_set_add_pollset(exec_ctx, pollset_set, pollset);
}

void grpc_pollset_set_del_pollset(grpc_exec_ctx* exec_ctx,
                                  grpc_pollset_set* pollset_set,
                                  grpc_pollset* pollset) {
  g_event_engine->pollset_set_del_pollset(exec_ctx, pollset_set, pollset);
}

void grpc_pollset_set_add_pollset_set(grpc_exec_ctx* exec_ctx,
                                      grpc_pollset_set* bag,
                                      grpc_pollset_set* item) {
  g_event_engine->pollset_set_add_pollset_set(exec_ctx, bag, item);
}

void grpc_pollset_set_del_pollset_set(grpc_exec_ctx* exec_ctx,
                                      grpc_pollset_set* bag,
                                      grpc_pollset_set* item) {
  g_event_engine->pollset_set_del_pollset_set(exec_ctx, bag, item);
}

void grpc_pollset_set_add_fd(grpc_exec_ctx* exec_ctx,
                             grpc_pollset_set* pollset_set, grpc_fd* fd) {
  g_event_engine->pollset_set_add_fd(exec_ctx, pollset_set, fd);
}

void grpc_pollset_set_del_fd(grpc_exec_ctx* exec_ctx,
                             grpc_pollset_set* pollset_set, grpc_fd* fd) {
  g_event_engine->pollset_set_del_fd(exec_ctx, pollset_set, fd);
}

#endif  // GRPC_POSIX_SOCKET
