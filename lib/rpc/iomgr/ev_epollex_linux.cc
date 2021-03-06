/*
 *
 * Copyright 2017 gRPC authors.
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

#include <rpc/support/log.h>

/* This polling engine is only relevant on linux kernels supporting epoll() */
#ifdef GRPC_LINUX_EPOLL

#include "rpc/iomgr/ev_epollex_linux.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>

#include <rpc/support/alloc.h>
#include <rpc/support/string_util.h>
#include <rpc/support/tls.h>
#include <rpc/support/useful.h>

#include "rpc/debug/stats.h"
#include "rpc/iomgr/block_annotate.h"
#include "rpc/iomgr/iomgr_internal.h"
#include "rpc/iomgr/is_epollexclusive_available.h"
#include "rpc/iomgr/lockfree_event.h"
#include "rpc/iomgr/sys_epoll_wrapper.h"
#include "rpc/iomgr/timer.h"
#include "rpc/iomgr/wakeup_fd_posix.h"
#include "rpc/profiling/timers.h"
#include "rpc/support/manual_constructor.h"
#include "rpc/support/spinlock.h"

// debug aid: create workers on the heap (allows asan to spot
// use-after-destruction)
//#define GRPC_EPOLLEX_CREATE_WORKERS_ON_HEAP 1

#define MAX_EPOLL_EVENTS 100
#define MAX_EPOLL_EVENTS_HANDLED_EACH_POLL_CALL 5

grpc_core::DebugOnlyTraceFlag grpc_trace_pollable_refcount(false,
                                                           "pollable_refcount");

/*******************************************************************************
 * pollable Declarations
 */

typedef enum { PO_MULTI, PO_FD, PO_EMPTY } pollable_type;

typedef struct pollable pollable;

/// A pollable is something that can be polled: it has an epoll set to poll on,
/// and a wakeup fd for kicks
/// There are three broad types:
///  - PO_EMPTY - the empty pollable, used before file descriptors are added to
///               a pollset
///  - PO_FD - a pollable containing only one FD - used to optimize single-fd
///            pollsets (which are common with synchronous api usage)
///  - PO_MULTI - a pollable containing many fds
struct pollable {
  pollable_type type;  // immutable
  gpr_refcount refs;

  int epfd;
  grpc_wakeup_fd wakeup;

  // only for type fd... one ref to the owner fd
  grpc_fd* owner_fd;

  grpc_pollset_set* pollset_set;
  pollable* next;
  pollable* prev;

  gpr_mu mu;
  grpc_pollset_worker* root_worker;

  int event_cursor;
  int event_count;
  struct epoll_event events[MAX_EPOLL_EVENTS];
};

static const char* pollable_type_string(pollable_type t) {
  switch (t) {
    case PO_MULTI:
      return "pollset";
    case PO_FD:
      return "fd";
    case PO_EMPTY:
      return "empty";
  }
  return "<invalid>";
}

static char* pollable_desc(pollable* p) {
  char* out;
  gpr_asprintf(&out, "type=%s epfd=%d wakeup=%d", pollable_type_string(p->type),
               p->epfd, p->wakeup.read_fd);
  return out;
}

/// Shared empty pollable - used by pollset to poll on until the first fd is
/// added
static pollable* g_empty_pollable;

static grpc_error* pollable_create(pollable_type type, pollable** p);
#ifdef NDEBUG
static pollable* pollable_ref(pollable* p);
static void pollable_unref(pollable* p);
#define POLLABLE_REF(p, r) pollable_ref(p)
#define POLLABLE_UNREF(p, r) pollable_unref(p)
#else
static pollable* pollable_ref(pollable* p, int line, const char* reason);
static void pollable_unref(pollable* p, int line, const char* reason);
#define POLLABLE_REF(p, r) pollable_ref((p), __LINE__, (r))
#define POLLABLE_UNREF(p, r) pollable_unref((p), __LINE__, (r))
#endif

/*******************************************************************************
 * Fd Declarations
 */

struct grpc_fd {
  int fd;
  /* refst format:
       bit 0    : 1=Active / 0=Orphaned
       bits 1-n : refcount
     Ref/Unref by two to avoid altering the orphaned bit */
  gpr_atm refst;

  gpr_mu orphan_mu;

  gpr_mu pollable_mu;
  pollable* pollable_obj;

  grpc_core::ManualConstructor<grpc_core::LockfreeEvent> read_closure;
  grpc_core::ManualConstructor<grpc_core::LockfreeEvent> write_closure;

  struct grpc_fd* freelist_next;
  grpc_closure* on_done_closure;

  /* The pollset that last noticed that the fd is readable. The actual type
   * stored in this is (grpc_pollset *) */
  gpr_atm read_notifier_pollset;

  grpc_iomgr_object iomgr_object;
};

static void fd_global_init(void);
static void fd_global_shutdown(void);

/*******************************************************************************
 * Pollset Declarations
 */

typedef struct {
  grpc_pollset_worker* next;
  grpc_pollset_worker* prev;
} pwlink;

typedef enum { PWLINK_POLLABLE = 0, PWLINK_POLLSET, PWLINK_COUNT } pwlinks;

struct grpc_pollset_worker {
  bool kicked;
  bool initialized_cv;
#ifndef NDEBUG
  // debug aid: which thread started this worker
  pid_t originator;
#endif
  gpr_cv cv;
  grpc_pollset* pollset;
  pollable* pollable_obj;

  pwlink links[PWLINK_COUNT];
};

struct grpc_pollset {
  gpr_mu mu;
  pollable* active_pollable;
  bool kicked_without_poller;
  grpc_closure* shutdown_closure;
  grpc_pollset_worker* root_worker;
  int containing_pollset_set_count;
};

/*******************************************************************************
 * Pollset-set Declarations
 */

struct grpc_pollset_set {
  gpr_refcount refs;
  gpr_mu mu;
  grpc_pollset_set* parent;

  size_t pollset_count;
  size_t pollset_capacity;
  grpc_pollset** pollsets;

  size_t fd_count;
  size_t fd_capacity;
  grpc_fd** fds;
};

/*******************************************************************************
 * Common helpers
 */

static bool append_error(grpc_error** composite, grpc_error* error,
                         const char* desc) {
  if (error == GRPC_ERROR_NONE) return true;
  if (*composite == GRPC_ERROR_NONE) {
    *composite = GRPC_ERROR_CREATE_FROM_COPIED_STRING(desc);
  }
  *composite = grpc_error_add_child(*composite, error);
  return false;
}

/*******************************************************************************
 * Fd Definitions
 */

/* We need to keep a freelist not because of any concerns of malloc performance
 * but instead so that implementations with multiple threads in (for example)
 * epoll_wait deal with the race between pollset removal and incoming poll
 * notifications.
 *
 * The problem is that the poller ultimately holds a reference to this
 * object, so it is very difficult to know when is safe to free it, at least
 * without some expensive synchronization.
 *
 * If we keep the object freelisted, in the worst case losing this race just
 * becomes a spurious read notification on a reused fd.
 */

static grpc_fd* fd_freelist = nullptr;
static gpr_mu fd_freelist_mu;

#ifndef NDEBUG
#define REF_BY(fd, n, reason) ref_by(fd, n, reason, __FILE__, __LINE__)
#define UNREF_BY(ec, fd, n, reason) \
  unref_by(ec, fd, n, reason, __FILE__, __LINE__)
static void ref_by(grpc_fd* fd, int n, const char* reason, const char* file,
                   int line) {
  if (grpc_trace_fd_refcount.enabled()) {
    gpr_log(GPR_DEBUG,
            "FD %d %p   ref %d %" PRIdPTR " -> %" PRIdPTR " [%s; %s:%d]",
            fd->fd, fd, n, gpr_atm_no_barrier_load(&fd->refst),
            gpr_atm_no_barrier_load(&fd->refst) + n, reason, file, line);
  }
#else
#define REF_BY(fd, n, reason) ref_by(fd, n)
#define UNREF_BY(ec, fd, n, reason) unref_by(ec, fd, n)
static void ref_by(grpc_fd* fd, int n) {
#endif
  GPR_ASSERT(gpr_atm_no_barrier_fetch_add(&fd->refst, n) > 0);
}

static void fd_destroy(grpc_exec_ctx* exec_ctx, void* arg, grpc_error* error) {
  grpc_fd* fd = (grpc_fd*)arg;
  /* Add the fd to the freelist */
  grpc_iomgr_unregister_object(&fd->iomgr_object);
  POLLABLE_UNREF(fd->pollable_obj, "fd_pollable");
  gpr_mu_destroy(&fd->pollable_mu);
  gpr_mu_destroy(&fd->orphan_mu);
  gpr_mu_lock(&fd_freelist_mu);
  fd->freelist_next = fd_freelist;
  fd_freelist = fd;

  fd->read_closure->DestroyEvent();
  fd->write_closure->DestroyEvent();

  gpr_mu_unlock(&fd_freelist_mu);
}

#ifndef NDEBUG
static void unref_by(grpc_exec_ctx* exec_ctx, grpc_fd* fd, int n,
                     const char* reason, const char* file, int line) {
  if (grpc_trace_fd_refcount.enabled()) {
    gpr_log(GPR_DEBUG,
            "FD %d %p unref %d %" PRIdPTR " -> %" PRIdPTR " [%s; %s:%d]",
            fd->fd, fd, n, gpr_atm_no_barrier_load(&fd->refst),
            gpr_atm_no_barrier_load(&fd->refst) - n, reason, file, line);
  }
#else
static void unref_by(grpc_exec_ctx* exec_ctx, grpc_fd* fd, int n) {
#endif
  gpr_atm old = gpr_atm_full_fetch_add(&fd->refst, -n);
  if (old == n) {
    GRPC_CLOSURE_SCHED(
        exec_ctx,
        GRPC_CLOSURE_CREATE(fd_destroy, fd, grpc_schedule_on_exec_ctx),
        GRPC_ERROR_NONE);
  } else {
    GPR_ASSERT(old > n);
  }
}

static void fd_global_init(void) { gpr_mu_init(&fd_freelist_mu); }

static void fd_global_shutdown(void) {
  gpr_mu_lock(&fd_freelist_mu);
  gpr_mu_unlock(&fd_freelist_mu);
  while (fd_freelist != nullptr) {
    grpc_fd* fd = fd_freelist;
    fd_freelist = fd_freelist->freelist_next;
    gpr_free(fd);
  }
  gpr_mu_destroy(&fd_freelist_mu);
}

static grpc_fd* fd_create(int fd, const char* name) {
  grpc_fd* new_fd = nullptr;

  gpr_mu_lock(&fd_freelist_mu);
  if (fd_freelist != nullptr) {
    new_fd = fd_freelist;
    fd_freelist = fd_freelist->freelist_next;
  }
  gpr_mu_unlock(&fd_freelist_mu);

  if (new_fd == nullptr) {
    new_fd = (grpc_fd*)gpr_malloc(sizeof(grpc_fd));
    new_fd->read_closure.Init();
    new_fd->write_closure.Init();
  }

  gpr_mu_init(&new_fd->pollable_mu);
  gpr_mu_init(&new_fd->orphan_mu);
  new_fd->pollable_obj = nullptr;
  gpr_atm_rel_store(&new_fd->refst, (gpr_atm)1);
  new_fd->fd = fd;
  new_fd->read_closure->InitEvent();
  new_fd->write_closure->InitEvent();
  gpr_atm_no_barrier_store(&new_fd->read_notifier_pollset, (gpr_atm)NULL);

  new_fd->freelist_next = nullptr;
  new_fd->on_done_closure = nullptr;

  char* fd_name;
  gpr_asprintf(&fd_name, "%s fd=%d", name, fd);
  grpc_iomgr_register_object(&new_fd->iomgr_object, fd_name);
#ifndef NDEBUG
  if (grpc_trace_fd_refcount.enabled()) {
    gpr_log(GPR_DEBUG, "FD %d %p create %s", fd, new_fd, fd_name);
  }
#endif
  gpr_free(fd_name);
  return new_fd;
}

static int fd_wrapped_fd(grpc_fd* fd) {
  int ret_fd = fd->fd;
  return (gpr_atm_acq_load(&fd->refst) & 1) ? ret_fd : -1;
}

static void fd_orphan(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                      grpc_closure* on_done, int* release_fd,
                      bool already_closed, const char* reason) {
  bool is_fd_closed = already_closed;

  gpr_mu_lock(&fd->orphan_mu);

  fd->on_done_closure = on_done;

  /* If release_fd is not NULL, we should be relinquishing control of the file
     descriptor fd->fd (but we still own the grpc_fd structure). */
  if (release_fd != nullptr) {
    *release_fd = fd->fd;
  } else if (!is_fd_closed) {
    close(fd->fd);
    is_fd_closed = true;
  }

  if (!is_fd_closed) {
    gpr_log(GPR_DEBUG, "TODO: handle fd removal?");
  }

  /* Remove the active status but keep referenced. We want this grpc_fd struct
     to be alive (and not added to freelist) until the end of this function */
  REF_BY(fd, 1, reason);

  GRPC_CLOSURE_SCHED(exec_ctx, fd->on_done_closure, GRPC_ERROR_NONE);

  gpr_mu_unlock(&fd->orphan_mu);

  UNREF_BY(exec_ctx, fd, 2, reason); /* Drop the reference */
}

static grpc_pollset* fd_get_read_notifier_pollset(grpc_exec_ctx* exec_ctx,
                                                  grpc_fd* fd) {
  gpr_atm notifier = gpr_atm_acq_load(&fd->read_notifier_pollset);
  return (grpc_pollset*)notifier;
}

static bool fd_is_shutdown(grpc_fd* fd) {
  return fd->read_closure->IsShutdown();
}

/* Might be called multiple times */
static void fd_shutdown(grpc_exec_ctx* exec_ctx, grpc_fd* fd, grpc_error* why) {
  if (fd->read_closure->SetShutdown(exec_ctx, GRPC_ERROR_REF(why))) {
    shutdown(fd->fd, SHUT_RDWR);
    fd->write_closure->SetShutdown(exec_ctx, GRPC_ERROR_REF(why));
  }
  GRPC_ERROR_UNREF(why);
}

static void fd_notify_on_read(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                              grpc_closure* closure) {
  fd->read_closure->NotifyOn(exec_ctx, closure);
}

static void fd_notify_on_write(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                               grpc_closure* closure) {
  fd->write_closure->NotifyOn(exec_ctx, closure);
}

/*******************************************************************************
 * Pollable Definitions
 */

static grpc_error* pollable_create(pollable_type type, pollable** p) {
  *p = nullptr;

  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd == -1) {
    return GRPC_OS_ERROR(errno, "epoll_create1");
  }
  *p = (pollable*)gpr_malloc(sizeof(**p));
  grpc_error* err = grpc_wakeup_fd_init(&(*p)->wakeup);
  if (err != GRPC_ERROR_NONE) {
    close(epfd);
    gpr_free(*p);
    *p = nullptr;
    return err;
  }
  struct epoll_event ev;
  ev.events = (uint32_t)(EPOLLIN | EPOLLET);
  ev.data.ptr = (void*)(1 | (intptr_t) & (*p)->wakeup);
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, (*p)->wakeup.read_fd, &ev) != 0) {
    err = GRPC_OS_ERROR(errno, "epoll_ctl");
    close(epfd);
    grpc_wakeup_fd_destroy(&(*p)->wakeup);
    gpr_free(*p);
    *p = nullptr;
    return err;
  }

  (*p)->type = type;
  gpr_ref_init(&(*p)->refs, 1);
  gpr_mu_init(&(*p)->mu);
  (*p)->epfd = epfd;
  (*p)->owner_fd = nullptr;
  (*p)->pollset_set = nullptr;
  (*p)->next = (*p)->prev = *p;
  (*p)->root_worker = nullptr;
  (*p)->event_cursor = 0;
  (*p)->event_count = 0;
  return GRPC_ERROR_NONE;
}

#ifdef NDEBUG
static pollable* pollable_ref(pollable* p) {
#else
static pollable* pollable_ref(pollable* p, int line, const char* reason) {
  if (grpc_trace_pollable_refcount.enabled()) {
    int r = (int)gpr_atm_no_barrier_load(&p->refs.count);
    gpr_log(__FILE__, line, GPR_LOG_SEVERITY_DEBUG,
            "POLLABLE:%p   ref %d->%d %s", p, r, r + 1, reason);
  }
#endif
  gpr_ref(&p->refs);
  return p;
}

#ifdef NDEBUG
static void pollable_unref(pollable* p) {
#else
static void pollable_unref(pollable* p, int line, const char* reason) {
  if (p == nullptr) return;
  if (grpc_trace_pollable_refcount.enabled()) {
    int r = (int)gpr_atm_no_barrier_load(&p->refs.count);
    gpr_log(__FILE__, line, GPR_LOG_SEVERITY_DEBUG,
            "POLLABLE:%p unref %d->%d %s", p, r, r - 1, reason);
  }
#endif
  if (p != nullptr && gpr_unref(&p->refs)) {
    close(p->epfd);
    grpc_wakeup_fd_destroy(&p->wakeup);
    gpr_free(p);
  }
}

static grpc_error* pollable_add_fd(pollable* p, grpc_fd* fd) {
  grpc_error* error = GRPC_ERROR_NONE;
  static const char* err_desc = "pollable_add_fd";
  const int epfd = p->epfd;

  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG, "add fd %p (%d) to pollable %p", fd, fd->fd, p);
  }

  struct epoll_event ev_fd;
  ev_fd.events = (uint32_t)(EPOLLET | EPOLLIN | EPOLLOUT | EPOLLEXCLUSIVE);
  ev_fd.data.ptr = fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd->fd, &ev_fd) != 0) {
    switch (errno) {
      case EEXIST:
        break;
      default:
        append_error(&error, GRPC_OS_ERROR(errno, "epoll_ctl"), err_desc);
    }
  }

  return error;
}

/*******************************************************************************
 * Pollset Definitions
 */

GPR_TLS_DECL(g_current_thread_pollset);
GPR_TLS_DECL(g_current_thread_worker);

/* Global state management */
static grpc_error* pollset_global_init(void) {
  gpr_tls_init(&g_current_thread_pollset);
  gpr_tls_init(&g_current_thread_worker);
  return pollable_create(PO_EMPTY, &g_empty_pollable);
}

static void pollset_global_shutdown(void) {
  POLLABLE_UNREF(g_empty_pollable, "g_empty_pollable");
  gpr_tls_destroy(&g_current_thread_pollset);
  gpr_tls_destroy(&g_current_thread_worker);
}

/* pollset->mu must be held while calling this function */
static void pollset_maybe_finish_shutdown(grpc_exec_ctx* exec_ctx,
                                          grpc_pollset* pollset) {
  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG,
            "PS:%p (pollable:%p) maybe_finish_shutdown sc=%p (target:!NULL) "
            "rw=%p (target:NULL) cpsc=%d (target:0)",
            pollset, pollset->active_pollable, pollset->shutdown_closure,
            pollset->root_worker, pollset->containing_pollset_set_count);
  }
  if (pollset->shutdown_closure != nullptr && pollset->root_worker == nullptr &&
      pollset->containing_pollset_set_count == 0) {
    GRPC_CLOSURE_SCHED(exec_ctx, pollset->shutdown_closure, GRPC_ERROR_NONE);
    pollset->shutdown_closure = nullptr;
  }
}

/* pollset->mu must be held before calling this function,
 * pollset->active_pollable->mu & specific_worker->pollable_obj->mu must not be
 * held */
static grpc_error* kick_one_worker(grpc_exec_ctx* exec_ctx,
                                   grpc_pollset_worker* specific_worker) {
  pollable* p = specific_worker->pollable_obj;
  grpc_core::mu_guard lock(&p->mu);
  GPR_ASSERT(specific_worker != nullptr);
  if (specific_worker->kicked) {
    if (grpc_polling_trace.enabled()) {
      gpr_log(GPR_DEBUG, "PS:%p kicked_specific_but_already_kicked", p);
    }
    GRPC_STATS_INC_POLLSET_KICKED_AGAIN(exec_ctx);
    return GRPC_ERROR_NONE;
  }
  if (gpr_tls_get(&g_current_thread_worker) == (intptr_t)specific_worker) {
    if (grpc_polling_trace.enabled()) {
      gpr_log(GPR_DEBUG, "PS:%p kicked_specific_but_awake", p);
    }
    GRPC_STATS_INC_POLLSET_KICK_OWN_THREAD(exec_ctx);
    specific_worker->kicked = true;
    return GRPC_ERROR_NONE;
  }
  if (specific_worker == p->root_worker) {
    GRPC_STATS_INC_POLLSET_KICK_WAKEUP_FD(exec_ctx);
    if (grpc_polling_trace.enabled()) {
      gpr_log(GPR_DEBUG, "PS:%p kicked_specific_via_wakeup_fd", p);
    }
    specific_worker->kicked = true;
    grpc_error* error = grpc_wakeup_fd_wakeup(&p->wakeup);
    return error;
  }
  if (specific_worker->initialized_cv) {
    GRPC_STATS_INC_POLLSET_KICK_WAKEUP_CV(exec_ctx);
    if (grpc_polling_trace.enabled()) {
      gpr_log(GPR_DEBUG, "PS:%p kicked_specific_via_cv", p);
    }
    specific_worker->kicked = true;
    gpr_cv_signal(&specific_worker->cv);
    return GRPC_ERROR_NONE;
  }
  // we can get here during end_worker after removing specific_worker from the
  // pollable list but before removing it from the pollset list
  return GRPC_ERROR_NONE;
}

static grpc_error* pollset_kick(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                                grpc_pollset_worker* specific_worker) {
  GRPC_STATS_INC_POLLSET_KICK(exec_ctx);
  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG,
            "PS:%p kick %p tls_pollset=%p tls_worker=%p pollset.root_worker=%p",
            pollset, specific_worker,
            (void*)gpr_tls_get(&g_current_thread_pollset),
            (void*)gpr_tls_get(&g_current_thread_worker), pollset->root_worker);
  }
  if (specific_worker == nullptr) {
    if (gpr_tls_get(&g_current_thread_pollset) != (intptr_t)pollset) {
      if (pollset->root_worker == nullptr) {
        if (grpc_polling_trace.enabled()) {
          gpr_log(GPR_DEBUG, "PS:%p kicked_any_without_poller", pollset);
        }
        GRPC_STATS_INC_POLLSET_KICKED_WITHOUT_POLLER(exec_ctx);
        pollset->kicked_without_poller = true;
        return GRPC_ERROR_NONE;
      } else {
        // We've been asked to kick a poller, but we haven't been told which one
        // ... any will do
        // We look at the pollset worker list because:
        // 1. the pollable list may include workers from other pollers, so we'd
        //    need to do an O(N) search
        // 2. we'd additionally need to take the pollable lock, which we've so
        //    far avoided
        // Now, we would prefer to wake a poller in cv_wait, and not in
        // epoll_wait (since the latter would imply the need to do an additional
        // wakeup)
        // We know that if a worker is at the root of a pollable, it's (likely)
        // also the root of a pollset, and we know that if a worker is NOT at
        // the root of a pollset, it's (likely) not at the root of a pollable,
        // so we take our chances and choose the SECOND worker enqueued against
        // the pollset as a worker that's likely to be in cv_wait
        return kick_one_worker(
            exec_ctx, pollset->root_worker->links[PWLINK_POLLSET].next);
      }
    } else {
      if (grpc_polling_trace.enabled()) {
        gpr_log(GPR_DEBUG, "PS:%p kicked_any_but_awake", pollset);
      }
      GRPC_STATS_INC_POLLSET_KICK_OWN_THREAD(exec_ctx);
      return GRPC_ERROR_NONE;
    }
  } else {
    return kick_one_worker(exec_ctx, specific_worker);
  }
}

static grpc_error* pollset_kick_all(grpc_exec_ctx* exec_ctx,
                                    grpc_pollset* pollset) {
  grpc_error* error = GRPC_ERROR_NONE;
  const char* err_desc = "pollset_kick_all";
  grpc_pollset_worker* w = pollset->root_worker;
  if (w != nullptr) {
    do {
      GRPC_STATS_INC_POLLSET_KICK(exec_ctx);
      append_error(&error, kick_one_worker(exec_ctx, w), err_desc);
      w = w->links[PWLINK_POLLSET].next;
    } while (w != pollset->root_worker);
  }
  return error;
}

static void pollset_init(grpc_pollset* pollset, gpr_mu** mu) {
  gpr_mu_init(&pollset->mu);
  pollset->active_pollable = POLLABLE_REF(g_empty_pollable, "pollset");
  *mu = &pollset->mu;
}

static int poll_deadline_to_millis_timeout(grpc_exec_ctx* exec_ctx,
                                           grpc_millis millis) {
  if (millis == GRPC_MILLIS_INF_FUTURE) return -1;
  grpc_millis delta = millis - grpc_exec_ctx_now(exec_ctx);
  if (delta > INT_MAX)
    return INT_MAX;
  else if (delta < 0)
    return 0;
  else
    return (int)delta;
}

static void fd_become_readable(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                               grpc_pollset* notifier) {
  fd->read_closure->SetReady(exec_ctx);

  /* Note, it is possible that fd_become_readable might be called twice with
     different 'notifier's when an fd becomes readable and it is in two epoll
     sets (This can happen briefly during polling island merges). In such cases
     it does not really matter which notifer is set as the read_notifier_pollset
     (They would both point to the same polling island anyway) */
  /* Use release store to match with acquire load in fd_get_read_notifier */
  gpr_atm_rel_store(&fd->read_notifier_pollset, (gpr_atm)notifier);
}

static void fd_become_writable(grpc_exec_ctx* exec_ctx, grpc_fd* fd) {
  fd->write_closure->SetReady(exec_ctx);
}

static grpc_error* fd_get_or_become_pollable(grpc_fd* fd, pollable** p) {
  gpr_mu_lock(&fd->pollable_mu);
  grpc_error* error = GRPC_ERROR_NONE;
  static const char* err_desc = "fd_get_or_become_pollable";
  if (fd->pollable_obj == nullptr) {
    if (append_error(&error, pollable_create(PO_FD, &fd->pollable_obj),
                     err_desc)) {
      fd->pollable_obj->owner_fd = fd;
      if (!append_error(&error, pollable_add_fd(fd->pollable_obj, fd),
                        err_desc)) {
        POLLABLE_UNREF(fd->pollable_obj, "fd_pollable");
        fd->pollable_obj = nullptr;
      }
    }
  }
  if (error == GRPC_ERROR_NONE) {
    GPR_ASSERT(fd->pollable_obj != nullptr);
    *p = POLLABLE_REF(fd->pollable_obj, "pollset");
  } else {
    GPR_ASSERT(fd->pollable_obj == nullptr);
    *p = nullptr;
  }
  gpr_mu_unlock(&fd->pollable_mu);
  return error;
}

/* pollset->po.mu lock must be held by the caller before calling this */
static void pollset_shutdown(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                             grpc_closure* closure) {
  GPR_ASSERT(pollset->shutdown_closure == nullptr);
  pollset->shutdown_closure = closure;
  GRPC_LOG_IF_ERROR("pollset_shutdown", pollset_kick_all(exec_ctx, pollset));
  pollset_maybe_finish_shutdown(exec_ctx, pollset);
}

static grpc_error* pollable_process_events(grpc_exec_ctx* exec_ctx,
                                           grpc_pollset* pollset,
                                           pollable* pollable_obj, bool drain) {
  static const char* err_desc = "pollset_process_events";
  grpc_error* error = GRPC_ERROR_NONE;
  for (int i = 0; (drain || i < MAX_EPOLL_EVENTS_HANDLED_EACH_POLL_CALL) &&
                  pollable_obj->event_cursor != pollable_obj->event_count;
       i++) {
    int n = pollable_obj->event_cursor++;
    struct epoll_event* ev = &pollable_obj->events[n];
    void* data_ptr = ev->data.ptr;
    if (1 & (intptr_t)data_ptr) {
      if (grpc_polling_trace.enabled()) {
        gpr_log(GPR_DEBUG, "PS:%p got pollset_wakeup %p", pollset, data_ptr);
      }
      append_error(&error,
                   grpc_wakeup_fd_consume_wakeup(
                       (grpc_wakeup_fd*)((~(intptr_t)1) & (intptr_t)data_ptr)),
                   err_desc);
    } else {
      grpc_fd* fd = (grpc_fd*)data_ptr;
      bool cancel = (ev->events & (EPOLLERR | EPOLLHUP)) != 0;
      bool read_ev = (ev->events & (EPOLLIN | EPOLLPRI)) != 0;
      bool write_ev = (ev->events & EPOLLOUT) != 0;
      if (grpc_polling_trace.enabled()) {
        gpr_log(GPR_DEBUG,
                "PS:%p got fd %p: cancel=%d read=%d "
                "write=%d",
                pollset, fd, cancel, read_ev, write_ev);
      }
      if (read_ev || cancel) {
        fd_become_readable(exec_ctx, fd, pollset);
      }
      if (write_ev || cancel) {
        fd_become_writable(exec_ctx, fd);
      }
    }
  }

  return error;
}

/* pollset_shutdown is guaranteed to be called before pollset_destroy. */
static void pollset_destroy(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset) {
  POLLABLE_UNREF(pollset->active_pollable, "pollset");
  pollset->active_pollable = nullptr;
}

static grpc_error* pollable_epoll(grpc_exec_ctx* exec_ctx, pollable* p,
                                  grpc_millis deadline) {
  int timeout = poll_deadline_to_millis_timeout(exec_ctx, deadline);

  if (grpc_polling_trace.enabled()) {
    char* desc = pollable_desc(p);
    gpr_log(GPR_DEBUG, "POLLABLE:%p[%s] poll for %dms", p, desc, timeout);
    gpr_free(desc);
  }

  if (timeout != 0) {
    GRPC_SCHEDULING_START_BLOCKING_REGION;
  }
  int r;
  do {
    GRPC_STATS_INC_SYSCALL_POLL(exec_ctx);
    r = epoll_wait(p->epfd, p->events, MAX_EPOLL_EVENTS, timeout);
  } while (r < 0 && errno == EINTR);
  if (timeout != 0) {
    GRPC_SCHEDULING_END_BLOCKING_REGION_WITH_EXEC_CTX(exec_ctx);
  }

  if (r < 0) return GRPC_OS_ERROR(errno, "epoll_wait");

  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG, "POLLABLE:%p got %d events", p, r);
  }

  p->event_cursor = 0;
  p->event_count = r;

  return GRPC_ERROR_NONE;
}

/* Return true if first in list */
static bool worker_insert(grpc_pollset_worker** root_worker,
                          grpc_pollset_worker* worker, pwlinks link) {
  if (*root_worker == nullptr) {
    *root_worker = worker;
    worker->links[link].next = worker->links[link].prev = worker;
    return true;
  } else {
    worker->links[link].next = *root_worker;
    worker->links[link].prev = worker->links[link].next->links[link].prev;
    worker->links[link].next->links[link].prev = worker;
    worker->links[link].prev->links[link].next = worker;
    return false;
  }
}

/* returns the new root IFF the root changed */
typedef enum { WRR_NEW_ROOT, WRR_EMPTIED, WRR_REMOVED } worker_remove_result;

static worker_remove_result worker_remove(grpc_pollset_worker** root_worker,
                                          grpc_pollset_worker* worker,
                                          pwlinks link) {
  if (worker == *root_worker) {
    if (worker == worker->links[link].next) {
      *root_worker = nullptr;
      return WRR_EMPTIED;
    } else {
      *root_worker = worker->links[link].next;
      worker->links[link].prev->links[link].next = worker->links[link].next;
      worker->links[link].next->links[link].prev = worker->links[link].prev;
      return WRR_NEW_ROOT;
    }
  } else {
    worker->links[link].prev->links[link].next = worker->links[link].next;
    worker->links[link].next->links[link].prev = worker->links[link].prev;
    return WRR_REMOVED;
  }
}

/* Return true if this thread should poll */
static bool begin_worker(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                         grpc_pollset_worker* worker,
                         grpc_pollset_worker** worker_hdl,
                         grpc_millis deadline) {
  bool do_poll = (pollset->shutdown_closure == nullptr);
  if (worker_hdl != nullptr) *worker_hdl = worker;
  worker->initialized_cv = false;
  worker->kicked = false;
  worker->pollset = pollset;
  worker->pollable_obj =
      POLLABLE_REF(pollset->active_pollable, "pollset_worker");
  worker_insert(&pollset->root_worker, worker, PWLINK_POLLSET);
  gpr_mu_lock(&worker->pollable_obj->mu);
  if (!worker_insert(&worker->pollable_obj->root_worker, worker,
                     PWLINK_POLLABLE)) {
    worker->initialized_cv = true;
    gpr_cv_init(&worker->cv);
    gpr_mu_unlock(&pollset->mu);
    if (grpc_polling_trace.enabled() &&
        worker->pollable_obj->root_worker != worker) {
      gpr_log(GPR_DEBUG, "PS:%p wait %p w=%p for %dms", pollset,
              worker->pollable_obj, worker,
              poll_deadline_to_millis_timeout(exec_ctx, deadline));
    }
    while (do_poll && worker->pollable_obj->root_worker != worker) {
      if (gpr_cv_wait(&worker->cv, &worker->pollable_obj->mu,
                      grpc_millis_to_timespec(deadline, GPR_CLOCK_REALTIME))) {
        if (grpc_polling_trace.enabled()) {
          gpr_log(GPR_DEBUG, "PS:%p timeout_wait %p w=%p", pollset,
                  worker->pollable_obj, worker);
        }
        do_poll = false;
      } else if (worker->kicked) {
        if (grpc_polling_trace.enabled()) {
          gpr_log(GPR_DEBUG, "PS:%p wakeup %p w=%p", pollset,
                  worker->pollable_obj, worker);
        }
        do_poll = false;
      } else if (grpc_polling_trace.enabled() &&
                 worker->pollable_obj->root_worker != worker) {
        gpr_log(GPR_DEBUG, "PS:%p spurious_wakeup %p w=%p", pollset,
                worker->pollable_obj, worker);
      }
    }
    grpc_exec_ctx_invalidate_now(exec_ctx);
  } else {
    gpr_mu_unlock(&pollset->mu);
  }
  gpr_mu_unlock(&worker->pollable_obj->mu);

  return do_poll;
}

static void end_worker(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                       grpc_pollset_worker* worker,
                       grpc_pollset_worker** worker_hdl) {
  gpr_mu_lock(&pollset->mu);
  gpr_mu_lock(&worker->pollable_obj->mu);
  switch (worker_remove(&worker->pollable_obj->root_worker, worker,
                        PWLINK_POLLABLE)) {
    case WRR_NEW_ROOT: {
      // wakeup new poller
      grpc_pollset_worker* new_root = worker->pollable_obj->root_worker;
      GPR_ASSERT(new_root->initialized_cv);
      gpr_cv_signal(&new_root->cv);
      break;
    }
    case WRR_EMPTIED:
      if (pollset->active_pollable != worker->pollable_obj) {
        // pollable no longer being polled: flush events
        pollable_process_events(exec_ctx, pollset, worker->pollable_obj, true);
      }
      break;
    case WRR_REMOVED:
      break;
  }
  gpr_mu_unlock(&worker->pollable_obj->mu);
  POLLABLE_UNREF(worker->pollable_obj, "pollset_worker");
  if (worker_remove(&pollset->root_worker, worker, PWLINK_POLLSET) ==
      WRR_EMPTIED) {
    pollset_maybe_finish_shutdown(exec_ctx, pollset);
  }
  if (worker->initialized_cv) {
    gpr_cv_destroy(&worker->cv);
  }
}

#ifndef NDEBUG
static long gettid(void) { return syscall(__NR_gettid); }
#endif

/* pollset->mu lock must be held by the caller before calling this.
   The function pollset_work() may temporarily release the lock (pollset->po.mu)
   during the course of its execution but it will always re-acquire the lock and
   ensure that it is held by the time the function returns */
static grpc_error* pollset_work(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                                grpc_pollset_worker** worker_hdl,
                                grpc_millis deadline) {
#ifdef GRPC_EPOLLEX_CREATE_WORKERS_ON_HEAP
  grpc_pollset_worker* worker =
      (grpc_pollset_worker*)gpr_malloc(sizeof(*worker));
#define WORKER_PTR (worker)
#else
  grpc_pollset_worker worker;
#define WORKER_PTR (&worker)
#endif
#ifndef NDEBUG
  WORKER_PTR->originator = gettid();
#endif
  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG,
            "PS:%p work hdl=%p worker=%p now=%" PRIdPTR " deadline=%" PRIdPTR
            " kwp=%d pollable=%p",
            pollset, worker_hdl, WORKER_PTR, grpc_exec_ctx_now(exec_ctx),
            deadline, pollset->kicked_without_poller, pollset->active_pollable);
  }
  static const char* err_desc = "pollset_work";
  grpc_error* error = GRPC_ERROR_NONE;
  if (pollset->kicked_without_poller) {
    pollset->kicked_without_poller = false;
  } else {
    if (begin_worker(exec_ctx, pollset, WORKER_PTR, worker_hdl, deadline)) {
      gpr_tls_set(&g_current_thread_pollset, (intptr_t)pollset);
      gpr_tls_set(&g_current_thread_worker, (intptr_t)WORKER_PTR);
      if (WORKER_PTR->pollable_obj->event_cursor ==
          WORKER_PTR->pollable_obj->event_count) {
        append_error(
            &error,
            pollable_epoll(exec_ctx, WORKER_PTR->pollable_obj, deadline),
            err_desc);
      }
      append_error(&error,
                   pollable_process_events(exec_ctx, pollset,
                                           WORKER_PTR->pollable_obj, false),
                   err_desc);
      grpc_exec_ctx_flush(exec_ctx);
      gpr_tls_set(&g_current_thread_pollset, 0);
      gpr_tls_set(&g_current_thread_worker, 0);
    }
    end_worker(exec_ctx, pollset, WORKER_PTR, worker_hdl);
  }
#ifdef GRPC_EPOLLEX_CREATE_WORKERS_ON_HEAP
  gpr_free(worker);
#endif
#undef WORKER_PTR
  return error;
}

static grpc_error* pollset_transition_pollable_from_empty_to_fd_locked(
    grpc_exec_ctx* exec_ctx, grpc_pollset* pollset, grpc_fd* fd) {
  static const char* err_desc = "pollset_transition_pollable_from_empty_to_fd";
  grpc_error* error = GRPC_ERROR_NONE;
  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG,
            "PS:%p add fd %p (%d); transition pollable from empty to fd",
            pollset, fd, fd->fd);
  }
  append_error(&error, pollset_kick_all(exec_ctx, pollset), err_desc);
  POLLABLE_UNREF(pollset->active_pollable, "pollset");
  append_error(&error, fd_get_or_become_pollable(fd, &pollset->active_pollable),
               err_desc);
  return error;
}

static grpc_error* pollset_transition_pollable_from_fd_to_multi_locked(
    grpc_exec_ctx* exec_ctx, grpc_pollset* pollset, grpc_fd* and_add_fd) {
  static const char* err_desc = "pollset_transition_pollable_from_fd_to_multi";
  grpc_error* error = GRPC_ERROR_NONE;
  if (grpc_polling_trace.enabled()) {
    gpr_log(
        GPR_DEBUG,
        "PS:%p add fd %p (%d); transition pollable from fd %p to multipoller",
        pollset, and_add_fd, and_add_fd ? and_add_fd->fd : -1,
        pollset->active_pollable->owner_fd);
  }
  append_error(&error, pollset_kick_all(exec_ctx, pollset), err_desc);
  grpc_fd* initial_fd = pollset->active_pollable->owner_fd;
  POLLABLE_UNREF(pollset->active_pollable, "pollset");
  pollset->active_pollable = nullptr;
  if (append_error(&error, pollable_create(PO_MULTI, &pollset->active_pollable),
                   err_desc)) {
    append_error(&error, pollable_add_fd(pollset->active_pollable, initial_fd),
                 err_desc);
    if (and_add_fd != nullptr) {
      append_error(&error,
                   pollable_add_fd(pollset->active_pollable, and_add_fd),
                   err_desc);
    }
  }
  return error;
}

/* expects pollsets locked, flag whether fd is locked or not */
static grpc_error* pollset_add_fd_locked(grpc_exec_ctx* exec_ctx,
                                         grpc_pollset* pollset, grpc_fd* fd) {
  grpc_error* error = GRPC_ERROR_NONE;
  pollable* po_at_start =
      POLLABLE_REF(pollset->active_pollable, "pollset_add_fd");
  switch (pollset->active_pollable->type) {
    case PO_EMPTY:
      /* empty pollable --> single fd pollable */
      error = pollset_transition_pollable_from_empty_to_fd_locked(exec_ctx,
                                                                  pollset, fd);
      break;
    case PO_FD:
      gpr_mu_lock(&po_at_start->owner_fd->orphan_mu);
      if ((gpr_atm_no_barrier_load(&pollset->active_pollable->owner_fd->refst) &
           1) == 0) {
        error = pollset_transition_pollable_from_empty_to_fd_locked(
            exec_ctx, pollset, fd);
      } else {
        /* fd --> multipoller */
        error = pollset_transition_pollable_from_fd_to_multi_locked(
            exec_ctx, pollset, fd);
      }
      gpr_mu_unlock(&po_at_start->owner_fd->orphan_mu);
      break;
    case PO_MULTI:
      error = pollable_add_fd(pollset->active_pollable, fd);
      break;
  }
  if (error != GRPC_ERROR_NONE) {
    POLLABLE_UNREF(pollset->active_pollable, "pollset");
    pollset->active_pollable = po_at_start;
  } else {
    POLLABLE_UNREF(po_at_start, "pollset_add_fd");
  }
  return error;
}

static grpc_error* pollset_as_multipollable_locked(grpc_exec_ctx* exec_ctx,
                                                   grpc_pollset* pollset,
                                                   pollable** pollable_obj) {
  grpc_error* error = GRPC_ERROR_NONE;
  pollable* po_at_start =
      POLLABLE_REF(pollset->active_pollable, "pollset_as_multipollable");
  switch (pollset->active_pollable->type) {
    case PO_EMPTY:
      POLLABLE_UNREF(pollset->active_pollable, "pollset");
      error = pollable_create(PO_MULTI, &pollset->active_pollable);
      break;
    case PO_FD:
      gpr_mu_lock(&po_at_start->owner_fd->orphan_mu);
      if ((gpr_atm_no_barrier_load(&pollset->active_pollable->owner_fd->refst) &
           1) == 0) {
        POLLABLE_UNREF(pollset->active_pollable, "pollset");
        error = pollable_create(PO_MULTI, &pollset->active_pollable);
      } else {
        error = pollset_transition_pollable_from_fd_to_multi_locked(
            exec_ctx, pollset, nullptr);
      }
      gpr_mu_unlock(&po_at_start->owner_fd->orphan_mu);
      break;
    case PO_MULTI:
      break;
  }
  if (error != GRPC_ERROR_NONE) {
    POLLABLE_UNREF(pollset->active_pollable, "pollset");
    pollset->active_pollable = po_at_start;
    *pollable_obj = nullptr;
  } else {
    *pollable_obj = POLLABLE_REF(pollset->active_pollable, "pollset_set");
    POLLABLE_UNREF(po_at_start, "pollset_as_multipollable");
  }
  return error;
}

static void pollset_add_fd(grpc_exec_ctx* exec_ctx, grpc_pollset* pollset,
                           grpc_fd* fd) {
  gpr_mu_lock(&pollset->mu);
  grpc_error* error = pollset_add_fd_locked(exec_ctx, pollset, fd);
  gpr_mu_unlock(&pollset->mu);
  GRPC_LOG_IF_ERROR("pollset_add_fd", error);
}

/*******************************************************************************
 * Pollset-set Definitions
 */

static grpc_pollset_set* pss_lock_adam(grpc_pollset_set* pss) {
  gpr_mu_lock(&pss->mu);
  while (pss->parent != nullptr) {
    gpr_mu_unlock(&pss->mu);
    pss = pss->parent;
    gpr_mu_lock(&pss->mu);
  }
  return pss;
}

static grpc_pollset_set* pollset_set_create(void) {
  grpc_pollset_set* pss = (grpc_pollset_set*)gpr_zalloc(sizeof(*pss));
  gpr_mu_init(&pss->mu);
  gpr_ref_init(&pss->refs, 1);
  return pss;
}

static void pollset_set_unref(grpc_exec_ctx* exec_ctx, grpc_pollset_set* pss) {
  if (pss == nullptr) return;
  if (!gpr_unref(&pss->refs)) return;
  pollset_set_unref(exec_ctx, pss->parent);
  gpr_mu_destroy(&pss->mu);
  for (size_t i = 0; i < pss->pollset_count; i++) {
    gpr_mu_lock(&pss->pollsets[i]->mu);
    if (0 == --pss->pollsets[i]->containing_pollset_set_count) {
      pollset_maybe_finish_shutdown(exec_ctx, pss->pollsets[i]);
    }
    gpr_mu_unlock(&pss->pollsets[i]->mu);
  }
  for (size_t i = 0; i < pss->fd_count; i++) {
    UNREF_BY(exec_ctx, pss->fds[i], 2, "pollset_set");
  }
  gpr_free(pss->pollsets);
  gpr_free(pss->fds);
  gpr_free(pss);
}

static void pollset_set_add_fd(grpc_exec_ctx* exec_ctx, grpc_pollset_set* pss,
                               grpc_fd* fd) {
  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG, "PSS:%p: add fd %p (%d)", pss, fd, fd->fd);
  }
  grpc_error* error = GRPC_ERROR_NONE;
  static const char* err_desc = "pollset_set_add_fd";
  pss = pss_lock_adam(pss);
  for (size_t i = 0; i < pss->pollset_count; i++) {
    append_error(&error, pollable_add_fd(pss->pollsets[i]->active_pollable, fd),
                 err_desc);
  }
  if (pss->fd_count == pss->fd_capacity) {
    pss->fd_capacity = GPR_MAX(pss->fd_capacity * 2, 8);
    pss->fds =
        (grpc_fd**)gpr_realloc(pss->fds, pss->fd_capacity * sizeof(*pss->fds));
  }
  REF_BY(fd, 2, "pollset_set");
  pss->fds[pss->fd_count++] = fd;
  gpr_mu_unlock(&pss->mu);

  GRPC_LOG_IF_ERROR(err_desc, error);
}

static void pollset_set_del_fd(grpc_exec_ctx* exec_ctx, grpc_pollset_set* pss,
                               grpc_fd* fd) {
  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG, "PSS:%p: del fd %p", pss, fd);
  }
  pss = pss_lock_adam(pss);
  size_t i;
  for (i = 0; i < pss->fd_count; i++) {
    if (pss->fds[i] == fd) {
      UNREF_BY(exec_ctx, fd, 2, "pollset_set");
      break;
    }
  }
  GPR_ASSERT(i != pss->fd_count);
  for (; i < pss->fd_count - 1; i++) {
    pss->fds[i] = pss->fds[i + 1];
  }
  pss->fd_count--;
  gpr_mu_unlock(&pss->mu);
}

static void pollset_set_del_pollset(grpc_exec_ctx* exec_ctx,
                                    grpc_pollset_set* pss, grpc_pollset* ps) {
  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG, "PSS:%p: del pollset %p", pss, ps);
  }
  pss = pss_lock_adam(pss);
  size_t i;
  for (i = 0; i < pss->pollset_count; i++) {
    if (pss->pollsets[i] == ps) {
      break;
    }
  }
  GPR_ASSERT(i != pss->pollset_count);
  for (; i < pss->pollset_count - 1; i++) {
    pss->pollsets[i] = pss->pollsets[i + 1];
  }
  pss->pollset_count--;
  gpr_mu_unlock(&pss->mu);
  gpr_mu_lock(&ps->mu);
  if (0 == --ps->containing_pollset_set_count) {
    pollset_maybe_finish_shutdown(exec_ctx, ps);
  }
  gpr_mu_unlock(&ps->mu);
}

// add all fds to pollables, and output a new array of unorphaned out_fds
// assumes pollsets are multipollable
static grpc_error* add_fds_to_pollsets(grpc_exec_ctx* exec_ctx, grpc_fd** fds,
                                       size_t fd_count, grpc_pollset** pollsets,
                                       size_t pollset_count,
                                       const char* err_desc, grpc_fd** out_fds,
                                       size_t* out_fd_count) {
  grpc_error* error = GRPC_ERROR_NONE;
  for (size_t i = 0; i < fd_count; i++) {
    gpr_mu_lock(&fds[i]->orphan_mu);
    if ((gpr_atm_no_barrier_load(&fds[i]->refst) & 1) == 0) {
      gpr_mu_unlock(&fds[i]->orphan_mu);
      UNREF_BY(exec_ctx, fds[i], 2, "pollset_set");
    } else {
      for (size_t j = 0; j < pollset_count; j++) {
        append_error(&error,
                     pollable_add_fd(pollsets[j]->active_pollable, fds[i]),
                     err_desc);
      }
      gpr_mu_unlock(&fds[i]->orphan_mu);
      out_fds[(*out_fd_count)++] = fds[i];
    }
  }
  return error;
}

static void pollset_set_add_pollset(grpc_exec_ctx* exec_ctx,
                                    grpc_pollset_set* pss, grpc_pollset* ps) {
  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG, "PSS:%p: add pollset %p", pss, ps);
  }
  grpc_error* error = GRPC_ERROR_NONE;
  static const char* err_desc = "pollset_set_add_pollset";
  pollable* pollable_obj = nullptr;
  gpr_mu_lock(&ps->mu);
  if (!GRPC_LOG_IF_ERROR(err_desc, pollset_as_multipollable_locked(
                                       exec_ctx, ps, &pollable_obj))) {
    GPR_ASSERT(pollable_obj == nullptr);
    gpr_mu_unlock(&ps->mu);
    return;
  }
  ps->containing_pollset_set_count++;
  gpr_mu_unlock(&ps->mu);
  pss = pss_lock_adam(pss);
  size_t initial_fd_count = pss->fd_count;
  pss->fd_count = 0;
  append_error(&error,
               add_fds_to_pollsets(exec_ctx, pss->fds, initial_fd_count, &ps, 1,
                                   err_desc, pss->fds, &pss->fd_count),
               err_desc);
  if (pss->pollset_count == pss->pollset_capacity) {
    pss->pollset_capacity = GPR_MAX(pss->pollset_capacity * 2, 8);
    pss->pollsets = (grpc_pollset**)gpr_realloc(
        pss->pollsets, pss->pollset_capacity * sizeof(*pss->pollsets));
  }
  pss->pollsets[pss->pollset_count++] = ps;
  gpr_mu_unlock(&pss->mu);
  POLLABLE_UNREF(pollable_obj, "pollset_set");

  GRPC_LOG_IF_ERROR(err_desc, error);
}

static void pollset_set_add_pollset_set(grpc_exec_ctx* exec_ctx,
                                        grpc_pollset_set* a,
                                        grpc_pollset_set* b) {
  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG, "PSS: merge (%p, %p)", a, b);
  }
  grpc_error* error = GRPC_ERROR_NONE;
  static const char* err_desc = "pollset_set_add_fd";
  for (;;) {
    if (a == b) {
      // pollset ancestors are the same: nothing to do
      return;
    }
    if (a > b) {
      GPR_SWAP(grpc_pollset_set*, a, b);
    }
    gpr_mu* a_mu = &a->mu;
    gpr_mu* b_mu = &b->mu;
    gpr_mu_lock(a_mu);
    gpr_mu_lock(b_mu);
    if (a->parent != nullptr) {
      a = a->parent;
    } else if (b->parent != nullptr) {
      b = b->parent;
    } else {
      break;  // exit loop, both pollsets locked
    }
    gpr_mu_unlock(a_mu);
    gpr_mu_unlock(b_mu);
  }
  // try to do the least copying possible
  // TODO(ctiller): there's probably a better heuristic here
  const size_t a_size = a->fd_count + a->pollset_count;
  const size_t b_size = b->fd_count + b->pollset_count;
  if (b_size > a_size) {
    GPR_SWAP(grpc_pollset_set*, a, b);
  }
  if (grpc_polling_trace.enabled()) {
    gpr_log(GPR_DEBUG, "PSS: parent %p to %p", b, a);
  }
  gpr_ref(&a->refs);
  b->parent = a;
  if (a->fd_capacity < a->fd_count + b->fd_count) {
    a->fd_capacity = GPR_MAX(2 * a->fd_capacity, a->fd_count + b->fd_count);
    a->fds = (grpc_fd**)gpr_realloc(a->fds, a->fd_capacity * sizeof(*a->fds));
  }
  size_t initial_a_fd_count = a->fd_count;
  a->fd_count = 0;
  append_error(
      &error,
      add_fds_to_pollsets(exec_ctx, a->fds, initial_a_fd_count, b->pollsets,
                          b->pollset_count, "merge_a2b", a->fds, &a->fd_count),
      err_desc);
  append_error(
      &error,
      add_fds_to_pollsets(exec_ctx, b->fds, b->fd_count, a->pollsets,
                          a->pollset_count, "merge_b2a", a->fds, &a->fd_count),
      err_desc);
  if (a->pollset_capacity < a->pollset_count + b->pollset_count) {
    a->pollset_capacity =
        GPR_MAX(2 * a->pollset_capacity, a->pollset_count + b->pollset_count);
    a->pollsets = (grpc_pollset**)gpr_realloc(
        a->pollsets, a->pollset_capacity * sizeof(*a->pollsets));
  }
  if (b->pollset_count > 0) {
    memcpy(a->pollsets + a->pollset_count, b->pollsets,
           b->pollset_count * sizeof(*b->pollsets));
  }
  a->pollset_count += b->pollset_count;
  gpr_free(b->fds);
  gpr_free(b->pollsets);
  b->fds = nullptr;
  b->pollsets = nullptr;
  b->fd_count = b->fd_capacity = b->pollset_count = b->pollset_capacity = 0;
  gpr_mu_unlock(&a->mu);
  gpr_mu_unlock(&b->mu);
}

static void pollset_set_del_pollset_set(grpc_exec_ctx* exec_ctx,
                                        grpc_pollset_set* bag,
                                        grpc_pollset_set* item) {}

/*******************************************************************************
 * Event engine binding
 */

static void shutdown_engine(void) {
  fd_global_shutdown();
  pollset_global_shutdown();
}

static const grpc_event_engine_vtable vtable = {
    sizeof(grpc_pollset),

    fd_create,
    fd_wrapped_fd,
    fd_orphan,
    fd_shutdown,
    fd_notify_on_read,
    fd_notify_on_write,
    fd_is_shutdown,
    fd_get_read_notifier_pollset,

    pollset_init,
    pollset_shutdown,
    pollset_destroy,
    pollset_work,
    pollset_kick,
    pollset_add_fd,

    pollset_set_create,
    pollset_set_unref,  // destroy ==> unref 1 public ref
    pollset_set_add_pollset,
    pollset_set_del_pollset,
    pollset_set_add_pollset_set,
    pollset_set_del_pollset_set,
    pollset_set_add_fd,
    pollset_set_del_fd,

    shutdown_engine,
};

const grpc_event_engine_vtable* grpc_init_epollex_linux(
    bool explicitly_requested) {
  if (!explicitly_requested) {
    return nullptr;
  }

  if (!grpc_has_wakeup_fd()) {
    gpr_log(GPR_ERROR, "Skipping epollex because of no wakeup fd.");
    return nullptr;
  }

  if (!grpc_is_epollexclusive_available()) {
    gpr_log(GPR_INFO, "Skipping epollex because it is not supported.");
    return nullptr;
  }

  fd_global_init();

  if (!GRPC_LOG_IF_ERROR("pollset_global_init", pollset_global_init())) {
    pollset_global_shutdown();
    fd_global_shutdown();
    return nullptr;
  }

  return &vtable;
}

#else /* defined(GRPC_LINUX_EPOLL) */
#if defined(GRPC_POSIX_SOCKET)
#include "rpc/iomgr/ev_epollex_linux.h"
/* If GRPC_LINUX_EPOLL is not defined, it means epoll is not available. Return
 * NULL */
const grpc_event_engine_vtable* grpc_init_epollex_linux(
    bool explicitly_requested) {
  gpr_log(GPR_ERROR,
          "Skipping epollex becuase GRPC_LINUX_EPOLL is not defined.");
  return NULL;
}
#endif /* defined(GRPC_POSIX_SOCKET) */

#endif /* !defined(GRPC_LINUX_EPOLL) */
