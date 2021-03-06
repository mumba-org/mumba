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

#include <rpc/support/port_platform.h>

#include "rpc/iomgr/iomgr.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>
#include <rpc/support/sync.h>
#include <rpc/support/thd.h>
#include <rpc/support/useful.h>

#include "rpc/iomgr/exec_ctx.h"
#include "rpc/iomgr/executor.h"
#include "rpc/iomgr/iomgr_internal.h"
#include "rpc/iomgr/network_status_tracker.h"
#include "rpc/iomgr/timer.h"
#include "rpc/iomgr/timer_manager.h"
#include "rpc/support/env.h"
#include "rpc/support/string.h"

static gpr_mu g_mu;
static gpr_cv g_rcv;
static int g_shutdown;
static grpc_iomgr_object g_root_object;

void grpc_iomgr_init(grpc_exec_ctx* exec_ctx) {
  g_shutdown = 0;
  gpr_mu_init(&g_mu);
  gpr_cv_init(&g_rcv);
  grpc_exec_ctx_global_init();
  grpc_executor_init(exec_ctx);
  grpc_timer_list_init(exec_ctx);
  g_root_object.next = g_root_object.prev = &g_root_object;
  g_root_object.name = (char*)"root";
  grpc_network_status_init();
  grpc_iomgr_platform_init();
}

void grpc_iomgr_start(grpc_exec_ctx* exec_ctx) { grpc_timer_manager_init(); }

static size_t count_objects(void) {
  grpc_iomgr_object* obj;
  size_t n = 0;
  for (obj = g_root_object.next; obj != &g_root_object; obj = obj->next) {
    n++;
  }
  return n;
}

static void dump_objects(const char* kind) {
  grpc_iomgr_object* obj;
  for (obj = g_root_object.next; obj != &g_root_object; obj = obj->next) {
    gpr_log(GPR_DEBUG, "%s OBJECT: %s %p", kind, obj->name, obj);
  }
}

void grpc_iomgr_shutdown(grpc_exec_ctx* exec_ctx) {
  gpr_timespec shutdown_deadline = gpr_time_add(
      gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_seconds(10, GPR_TIMESPAN));
  gpr_timespec last_warning_time = gpr_now(GPR_CLOCK_REALTIME);

  grpc_timer_manager_shutdown();
  grpc_iomgr_platform_flush();
  grpc_executor_shutdown(exec_ctx);

  gpr_mu_lock(&g_mu);
  g_shutdown = 1;
  while (g_root_object.next != &g_root_object) {
    if (gpr_time_cmp(
            gpr_time_sub(gpr_now(GPR_CLOCK_REALTIME), last_warning_time),
            gpr_time_from_seconds(1, GPR_TIMESPAN)) >= 0) {
      if (g_root_object.next != &g_root_object) {
        gpr_log(GPR_DEBUG,
                "Waiting for %" PRIuPTR " iomgr objects to be destroyed",
                count_objects());
      }
      last_warning_time = gpr_now(GPR_CLOCK_REALTIME);
    }
    exec_ctx->now_is_valid = true;
    exec_ctx->now = GRPC_MILLIS_INF_FUTURE;
    if (grpc_timer_check(exec_ctx, nullptr) == GRPC_TIMERS_FIRED) {
      gpr_mu_unlock(&g_mu);
      grpc_exec_ctx_flush(exec_ctx);
      grpc_iomgr_platform_flush();
      gpr_mu_lock(&g_mu);
      continue;
    }
    if (g_root_object.next != &g_root_object) {
      if (grpc_iomgr_abort_on_leaks()) {
        gpr_log(GPR_DEBUG,
                "Failed to free %" PRIuPTR
                " iomgr objects before shutdown deadline: "
                "memory leaks are likely",
                count_objects());
        dump_objects("LEAKED");
        abort();
      }
      gpr_timespec short_deadline = gpr_time_add(
          gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_millis(100, GPR_TIMESPAN));
      if (gpr_cv_wait(&g_rcv, &g_mu, short_deadline)) {
        if (gpr_time_cmp(gpr_now(GPR_CLOCK_REALTIME), shutdown_deadline) > 0) {
          if (g_root_object.next != &g_root_object) {
            gpr_log(GPR_DEBUG,
                    "Failed to free %" PRIuPTR
                    " iomgr objects before shutdown deadline: "
                    "memory leaks are likely",
                    count_objects());
            dump_objects("LEAKED");
          }
          break;
        }
      }
    }
  }
  gpr_mu_unlock(&g_mu);

  grpc_timer_list_shutdown(exec_ctx);
  grpc_exec_ctx_flush(exec_ctx);

  /* ensure all threads have left g_mu */
  gpr_mu_lock(&g_mu);
  gpr_mu_unlock(&g_mu);

  grpc_iomgr_platform_shutdown();
  grpc_exec_ctx_global_shutdown();
  grpc_network_status_shutdown();
  gpr_mu_destroy(&g_mu);
  gpr_cv_destroy(&g_rcv);
}

void grpc_iomgr_register_object(grpc_iomgr_object* obj, const char* name) {
  obj->name = gpr_strdup(name);
  gpr_mu_lock(&g_mu);
  obj->next = &g_root_object;
  obj->prev = g_root_object.prev;
  obj->next->prev = obj->prev->next = obj;
  gpr_mu_unlock(&g_mu);
}

void grpc_iomgr_unregister_object(grpc_iomgr_object* obj) {
  gpr_mu_lock(&g_mu);
  obj->next->prev = obj->prev;
  obj->prev->next = obj->next;
  gpr_cv_signal(&g_rcv);
  gpr_mu_unlock(&g_mu);
  gpr_free(obj->name);
}

bool grpc_iomgr_abort_on_leaks(void) {
  char* env = gpr_getenv("GRPC_ABORT_ON_LEAKS");
  bool should_we = gpr_is_true(env);
  gpr_free(env);
  return should_we;
}
