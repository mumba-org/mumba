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

#ifndef GRPC_CORE_LIB_SURFACE_CALL_H
#define GRPC_CORE_LIB_SURFACE_CALL_H

#include "rpc/channel/channel_stack.h"
#include "rpc/channel/context.h"
#include "rpc/surface/api_trace.h"

#include <rpc/grpc.h>
#include <rpc/impl/codegen/compression_types.h>

typedef void (*grpc_ioreq_completion_func)(grpc_exec_ctx* exec_ctx,
                                           grpc_call* call, int success,
                                           void* user_data);

typedef struct grpc_call_create_args {
  grpc_channel* channel;

  grpc_call* parent;
  uint32_t propagation_mask;

  grpc_completion_queue* cq;
  /* if not NULL, it'll be used in lieu of cq */
  grpc_pollset_set* pollset_set_alternative;

  const void* server_transport_data;

  grpc_mdelem* add_initial_metadata;
  size_t add_initial_metadata_count;

  grpc_millis send_deadline;
} grpc_call_create_args;

/* Create a new call based on \a args.
   Regardless of success or failure, always returns a valid new call into *call
   */
GRPCAPI grpc_error* grpc_call_create(grpc_exec_ctx* exec_ctx,
                             const grpc_call_create_args* args,
                             grpc_call** call);

GRPCAPI void grpc_call_set_completion_queue(grpc_exec_ctx* exec_ctx, grpc_call* call,
                                    grpc_completion_queue* cq);

#ifndef NDEBUG
GRPCAPI void grpc_call_internal_ref(grpc_call* call, const char* reason);
GRPCAPI void grpc_call_internal_unref(grpc_exec_ctx* exec_ctx, grpc_call* call,
                              const char* reason);
#define GRPC_CALL_INTERNAL_REF(call, reason) \
  grpc_call_internal_ref(call, reason)
#define GRPC_CALL_INTERNAL_UNREF(exec_ctx, call, reason) \
  grpc_call_internal_unref(exec_ctx, call, reason)
#else
GRPCAPI void grpc_call_internal_ref(grpc_call* call);
GRPCAPI void grpc_call_internal_unref(grpc_exec_ctx* exec_ctx, grpc_call* call);
#define GRPC_CALL_INTERNAL_REF(call, reason) grpc_call_internal_ref(call)
#define GRPC_CALL_INTERNAL_UNREF(exec_ctx, call, reason) \
  grpc_call_internal_unref(exec_ctx, call)
#endif

GRPCAPI grpc_call_stack* grpc_call_get_call_stack(grpc_call* call);

GRPCAPI grpc_call_error grpc_call_start_batch_and_execute(grpc_exec_ctx* exec_ctx,
                                                  grpc_call* call,
                                                  const grpc_op* ops,
                                                  size_t nops,
                                                  grpc_closure* closure);

/* Given the top call_element, get the call object. */
GRPCAPI grpc_call* grpc_call_from_top_element(grpc_call_element* surface_element);

GRPCAPI void grpc_call_log_batch(const char* file, int line, gpr_log_severity severity,
                         grpc_call* call, const grpc_op* ops, size_t nops,
                         void* tag);

/* Set a context pointer.
   No thread safety guarantees are made wrt this value. */
/* TODO(#9731): add exec_ctx to destroy */
GRPCAPI void grpc_call_context_set(grpc_call* call, grpc_context_index elem,
                           void* value, void (*destroy)(void* value));
/* Get a context pointer. */
GRPCAPI void* grpc_call_context_get(grpc_call* call, grpc_context_index elem);

#define GRPC_CALL_LOG_BATCH(sev, call, ops, nops, tag) \
  if (grpc_api_trace.enabled()) grpc_call_log_batch(sev, call, ops, nops, tag)

GRPCAPI uint8_t grpc_call_is_client(grpc_call* call);

/* Return an appropriate compression algorithm for the requested compression \a
 * level in the context of \a call. */
GRPCAPI grpc_compression_algorithm grpc_call_compression_for_level(
    grpc_call* call, grpc_compression_level level);

extern grpc_core::TraceFlag grpc_call_error_trace;
extern grpc_core::TraceFlag grpc_compression_trace;

GRPCAPI void grpc_call_set_sending_message(grpc_call* call, bool sending_message);
GRPCAPI bool grpc_call_is_sending_message(grpc_call* call);

#endif /* GRPC_CORE_LIB_SURFACE_CALL_H */
