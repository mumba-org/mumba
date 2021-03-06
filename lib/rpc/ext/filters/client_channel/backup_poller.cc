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

#include "rpc/ext/filters/client_channel/backup_poller.h"

#include <rpc/grpc.h>
#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/sync.h>
#include "rpc/ext/filters/client_channel/client_channel.h"
#include "rpc/iomgr/error.h"
#include "rpc/iomgr/pollset.h"
#include "rpc/iomgr/timer.h"
#include "rpc/support/env.h"
#include "rpc/support/string.h"
#include "rpc/surface/channel.h"
#include "rpc/surface/completion_queue.h"

#define DEFAULT_POLL_INTERVAL_MS 5000

typedef struct backup_poller {
  grpc_timer polling_timer;
  grpc_closure run_poller_closure;
  grpc_closure shutdown_closure;
  gpr_mu* pollset_mu;
  grpc_pollset* pollset;  // guarded by pollset_mu
  bool shutting_down;     // guarded by pollset_mu
  gpr_refcount refs;
  gpr_refcount shutdown_refs;
} backup_poller;

static gpr_once g_once = GPR_ONCE_INIT;
static gpr_mu g_poller_mu;
static backup_poller* g_poller = nullptr;  // guarded by g_poller_mu
// g_poll_interval_ms is set only once at the first time
// grpc_client_channel_start_backup_polling() is called, after that it is
// treated as const.
static int g_poll_interval_ms = DEFAULT_POLL_INTERVAL_MS;

static void init_globals() {
  gpr_mu_init(&g_poller_mu);
  char* env = gpr_getenv("GRPC_CLIENT_CHANNEL_BACKUP_POLL_INTERVAL_MS");
  if (env != nullptr) {
    int poll_interval_ms = gpr_parse_nonnegative_int(env);
    if (poll_interval_ms == -1) {
      gpr_log(GPR_ERROR,
              "Invalid GRPC_CLIENT_CHANNEL_BACKUP_POLL_INTERVAL_MS: %s, "
              "default value %d will be used.",
              env, g_poll_interval_ms);
    } else {
      g_poll_interval_ms = poll_interval_ms;
    }
  }
  gpr_free(env);
}

static void backup_poller_shutdown_unref(grpc_exec_ctx* exec_ctx,
                                         backup_poller* p) {
  if (gpr_unref(&p->shutdown_refs)) {
    grpc_pollset_destroy(exec_ctx, p->pollset);
    gpr_free(p->pollset);
    gpr_free(p);
  }
}

static void done_poller(grpc_exec_ctx* exec_ctx, void* arg, grpc_error* error) {
  backup_poller_shutdown_unref(exec_ctx, (backup_poller*)arg);
}

static void g_poller_unref(grpc_exec_ctx* exec_ctx) {
  if (gpr_unref(&g_poller->refs)) {
    gpr_mu_lock(&g_poller_mu);
    backup_poller* p = g_poller;
    g_poller = nullptr;
    gpr_mu_unlock(&g_poller_mu);
    gpr_mu_lock(p->pollset_mu);
    p->shutting_down = true;
    grpc_pollset_shutdown(exec_ctx, p->pollset,
                          GRPC_CLOSURE_INIT(&p->shutdown_closure, done_poller,
                                            p, grpc_schedule_on_exec_ctx));
    gpr_mu_unlock(p->pollset_mu);
    grpc_timer_cancel(exec_ctx, &p->polling_timer);
  }
}

static void run_poller(grpc_exec_ctx* exec_ctx, void* arg, grpc_error* error) {
  backup_poller* p = (backup_poller*)arg;
  if (error != GRPC_ERROR_NONE) {
    // if (error != GRPC_ERROR_CANCELLED) {
    //   GRPC_LOG_IF_ERROR("run_poller", GRPC_ERROR_REF(error));
    // }
    backup_poller_shutdown_unref(exec_ctx, p);
    return;
  }
  gpr_mu_lock(p->pollset_mu);
  if (p->shutting_down) {
    gpr_mu_unlock(p->pollset_mu);
    backup_poller_shutdown_unref(exec_ctx, p);
    return;
  }
  grpc_error* err = grpc_pollset_work(exec_ctx, p->pollset, nullptr,
                                      grpc_exec_ctx_now(exec_ctx));
  gpr_mu_unlock(p->pollset_mu);
  GRPC_LOG_IF_ERROR("Run client channel backup poller", err);
  grpc_timer_init(exec_ctx, &p->polling_timer,
                  grpc_exec_ctx_now(exec_ctx) + g_poll_interval_ms,
                  &p->run_poller_closure);
}

void grpc_client_channel_start_backup_polling(
    grpc_exec_ctx* exec_ctx, grpc_pollset_set* interested_parties) {
  gpr_once_init(&g_once, init_globals);
  if (g_poll_interval_ms == 0) {
    return;
  }
  gpr_mu_lock(&g_poller_mu);
  if (g_poller == nullptr) {
    g_poller = (backup_poller*)gpr_zalloc(sizeof(backup_poller));
    g_poller->pollset = (grpc_pollset*)gpr_zalloc(grpc_pollset_size());
    g_poller->shutting_down = false;
    grpc_pollset_init(g_poller->pollset, &g_poller->pollset_mu);
    gpr_ref_init(&g_poller->refs, 0);
    // one for timer cancellation, one for pollset shutdown
    gpr_ref_init(&g_poller->shutdown_refs, 2);
    GRPC_CLOSURE_INIT(&g_poller->run_poller_closure, run_poller, g_poller,
                      grpc_schedule_on_exec_ctx);
    grpc_timer_init(exec_ctx, &g_poller->polling_timer,
                    grpc_exec_ctx_now(exec_ctx) + g_poll_interval_ms,
                    &g_poller->run_poller_closure);
  }

  gpr_ref(&g_poller->refs);
  /* Get a reference to g_poller->pollset before releasing g_poller_mu to make
   * TSAN happy. Otherwise, reading from g_poller (i.e g_poller->pollset) after
   * releasing the lock and setting g_poller to NULL in g_poller_unref() is
   * being flagged as a data-race by TSAN */
  grpc_pollset* pollset = g_poller->pollset;
  gpr_mu_unlock(&g_poller_mu);

  grpc_pollset_set_add_pollset(exec_ctx, interested_parties, pollset);
}

void grpc_client_channel_stop_backup_polling(
    grpc_exec_ctx* exec_ctx, grpc_pollset_set* interested_parties) {
  if (g_poll_interval_ms == 0) {
    return;
  }
  grpc_pollset_set_del_pollset(exec_ctx, interested_parties, g_poller->pollset);
  g_poller_unref(exec_ctx);
}
