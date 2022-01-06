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

#include <limits.h>
#include <memory.h>

#include <rpc/fork.h>
#include <rpc/grpc.h>
#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/time.h>
#include "rpc/channel/channel_stack.h"
#include "rpc/channel/connected_channel.h"
#include "rpc/channel/handshaker_registry.h"
#include "rpc/debug/stats.h"
#include "rpc/debug/trace.h"
#include "rpc/http/parser.h"
#include "rpc/iomgr/call_combiner.h"
#include "rpc/iomgr/combiner.h"
#include "rpc/iomgr/executor.h"
#include "rpc/iomgr/iomgr.h"
#include "rpc/iomgr/resource_quota.h"
#include "rpc/iomgr/timer_manager.h"
#include "rpc/profiling/timers.h"
#include "rpc/slice/slice_internal.h"
#include "rpc/support/fork.h"
#include "rpc/support/thd_internal.h"
#include "rpc/surface/alarm_internal.h"
#include "rpc/surface/api_trace.h"
#include "rpc/surface/call.h"
#include "rpc/surface/channel_init.h"
#include "rpc/surface/completion_queue.h"
#include "rpc/surface/init.h"
#include "rpc/surface/lame_client.h"
#include "rpc/surface/server.h"
#include "rpc/transport/bdp_estimator.h"
#include "rpc/transport/connectivity_state.h"
#include "rpc/transport/transport_impl.h"

/* (generated) built in registry of plugins */
extern void grpc_register_built_in_plugins(void);

#define MAX_PLUGINS 128

static gpr_once g_basic_init = GPR_ONCE_INIT;
static gpr_mu g_init_mu;
static int g_initializations;

static void do_basic_init(void) {
  gpr_log_verbosity_init();
  grpc_fork_support_init();
  gpr_mu_init(&g_init_mu);
  grpc_register_built_in_plugins();
  grpc_cq_global_init();
  g_initializations = 0;
  grpc_fork_handlers_auto_register();
}

static bool append_filter(grpc_exec_ctx* exec_ctx,
                          grpc_channel_stack_builder* builder, void* arg) {
  return grpc_channel_stack_builder_append_filter(
      builder, (const grpc_channel_filter*)arg, nullptr, nullptr);
}

static bool prepend_filter(grpc_exec_ctx* exec_ctx,
                           grpc_channel_stack_builder* builder, void* arg) {
  return grpc_channel_stack_builder_prepend_filter(
      builder, (const grpc_channel_filter*)arg, nullptr, nullptr);
}

static void register_builtin_channel_init() {
  grpc_channel_init_register_stage(GRPC_CLIENT_SUBCHANNEL,
                                   GRPC_CHANNEL_INIT_BUILTIN_PRIORITY,
                                   grpc_add_connected_filter, nullptr);
  grpc_channel_init_register_stage(GRPC_CLIENT_DIRECT_CHANNEL,
                                   GRPC_CHANNEL_INIT_BUILTIN_PRIORITY,
                                   grpc_add_connected_filter, nullptr);
  grpc_channel_init_register_stage(GRPC_SERVER_CHANNEL,
                                   GRPC_CHANNEL_INIT_BUILTIN_PRIORITY,
                                   grpc_add_connected_filter, nullptr);
  grpc_channel_init_register_stage(GRPC_CLIENT_LAME_CHANNEL,
                                   GRPC_CHANNEL_INIT_BUILTIN_PRIORITY,
                                   append_filter, (void*)&grpc_lame_filter);
  grpc_channel_init_register_stage(GRPC_SERVER_CHANNEL, INT_MAX, prepend_filter,
                                   (void*)&grpc_server_top_filter);
}

typedef struct grpc_plugin {
  void (*init)();
  void (*destroy)();
} grpc_plugin;

static grpc_plugin g_all_of_the_plugins[MAX_PLUGINS];
static int g_number_of_plugins = 0;

void grpc_register_plugin(void (*init)(void), void (*destroy)(void)) {
  GRPC_API_TRACE("grpc_register_plugin(init=%p, destroy=%p)", 2,
                 ((void*)(intptr_t)init, (void*)(intptr_t)destroy));
  GPR_ASSERT(g_number_of_plugins != MAX_PLUGINS);
  g_all_of_the_plugins[g_number_of_plugins].init = init;
  g_all_of_the_plugins[g_number_of_plugins].destroy = destroy;
  g_number_of_plugins++;
}

void grpc_init(void) {
  int i;
  gpr_once_init(&g_basic_init, do_basic_init);

  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  gpr_mu_lock(&g_init_mu);
  if (++g_initializations == 1) {
    gpr_time_init();
    gpr_thd_init();
    grpc_stats_init();
    grpc_slice_intern_init();
    grpc_mdctx_global_init();
    grpc_channel_init_init();
    grpc_security_pre_init();
    grpc_iomgr_init(&exec_ctx);
    gpr_timers_global_init();
    grpc_handshaker_factory_registry_init();
    grpc_security_init();
    for (i = 0; i < g_number_of_plugins; i++) {
      if (g_all_of_the_plugins[i].init != nullptr) {
        g_all_of_the_plugins[i].init();
      }
    }
    /* register channel finalization AFTER all plugins, to ensure that it's run
     * at the appropriate time */
    grpc_register_security_filters();
    register_builtin_channel_init();
    grpc_tracer_init("GRPC_TRACE");
    /* no more changes to channel init pipelines */
    grpc_channel_init_finalize();
    grpc_iomgr_start(&exec_ctx);
  }
  gpr_mu_unlock(&g_init_mu);
  grpc_exec_ctx_finish(&exec_ctx);
  GRPC_API_TRACE("grpc_init(void)", 0, ());
}

void grpc_shutdown(void) {
  int i;
  GRPC_API_TRACE("grpc_shutdown(void)", 0, ());
  grpc_exec_ctx exec_ctx =
      GRPC_EXEC_CTX_INITIALIZER(0, grpc_never_ready_to_finish, nullptr);
  gpr_mu_lock(&g_init_mu);
  if (--g_initializations == 0) {
    grpc_executor_shutdown(&exec_ctx);
    grpc_timer_manager_set_threading(false);  // shutdown timer_manager thread
    for (i = g_number_of_plugins; i >= 0; i--) {
      if (g_all_of_the_plugins[i].destroy != nullptr) {
        g_all_of_the_plugins[i].destroy();
      }
    }
    grpc_iomgr_shutdown(&exec_ctx);
    gpr_timers_global_destroy();
    grpc_tracer_shutdown();
    grpc_mdctx_global_shutdown(&exec_ctx);
    grpc_handshaker_factory_registry_shutdown(&exec_ctx);
    grpc_slice_intern_shutdown();
    grpc_stats_shutdown();
  }
  gpr_mu_unlock(&g_init_mu);
  grpc_exec_ctx_finish(&exec_ctx);
}

int grpc_is_initialized(void) {
  int r;
  gpr_once_init(&g_basic_init, do_basic_init);
  gpr_mu_lock(&g_init_mu);
  r = g_initializations > 0;
  gpr_mu_unlock(&g_init_mu);
  return r;
}
