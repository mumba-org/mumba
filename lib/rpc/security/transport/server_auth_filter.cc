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

#include <string.h>

#include <rpc/support/alloc.h>
#include <rpc/support/log.h>

#include "rpc/security/context/security_context.h"
#include "rpc/security/credentials/credentials.h"
#include "rpc/security/transport/auth_filters.h"
#include "rpc/slice/slice_internal.h"

typedef enum {
  STATE_INIT = 0,
  STATE_DONE,
  STATE_CANCELLED,
} async_state;

typedef struct filter_call_data {
  grpc_call_combiner* call_combiner;
  grpc_call_stack* owning_call;
  grpc_transport_stream_op_batch* recv_initial_metadata_batch;
  grpc_closure* original_recv_initial_metadata_ready;
  grpc_closure recv_initial_metadata_ready;
  grpc_metadata_array md;
  const grpc_metadata* consumed_md;
  size_t num_consumed_md;
  grpc_auth_context* auth_context;
  grpc_closure cancel_closure;
  gpr_atm state;  // async_state
} filter_call_data;

typedef struct filter_channel_data {
  grpc_auth_context* auth_context;
  grpc_server_credentials* creds;
} filter_channel_data;

static grpc_metadata_array metadata_batch_to_md_array(
    const grpc_metadata_batch* batch) {
  grpc_linked_mdelem* l;
  grpc_metadata_array result;
  grpc_metadata_array_init(&result);
  for (l = batch->list.head; l != nullptr; l = l->next) {
    grpc_metadata* usr_md = nullptr;
    grpc_mdelem md = l->md;
    grpc_slice key = GRPC_MDKEY(md);
    grpc_slice value = GRPC_MDVALUE(md);
    if (result.count == result.capacity) {
      result.capacity = GPR_MAX(result.capacity + 8, result.capacity * 2);
      result.metadata = (grpc_metadata*)gpr_realloc(
          result.metadata, result.capacity * sizeof(grpc_metadata));
    }
    usr_md = &result.metadata[result.count++];
    usr_md->key = grpc_slice_ref_internal(key);
    usr_md->value = grpc_slice_ref_internal(value);
  }
  return result;
}

static grpc_filtered_mdelem remove_consumed_md(grpc_exec_ctx* exec_ctx,
                                               void* user_data,
                                               grpc_mdelem md) {
  grpc_call_element* elem = (grpc_call_element*)user_data;
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  size_t i;
  for (i = 0; i < calld->num_consumed_md; i++) {
    const grpc_metadata* consumed_md = &calld->consumed_md[i];
    if (grpc_slice_eq(GRPC_MDKEY(md), consumed_md->key) &&
        grpc_slice_eq(GRPC_MDVALUE(md), consumed_md->value))
      return GRPC_FILTERED_REMOVE();
  }
  return GRPC_FILTERED_MDELEM(md);
}

static void on_md_processing_done_inner(grpc_exec_ctx* exec_ctx,
                                        grpc_call_element* elem,
                                        const grpc_metadata* consumed_md,
                                        size_t num_consumed_md,
                                        const grpc_metadata* response_md,
                                        size_t num_response_md,
                                        grpc_error* error) {
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  grpc_transport_stream_op_batch* batch = calld->recv_initial_metadata_batch;
  /* TODO(jboeuf): Implement support for response_md. */
  if (response_md != nullptr && num_response_md > 0) {
    gpr_log(GPR_INFO,
            "response_md in auth metadata processing not supported for now. "
            "Ignoring...");
  }
  if (error == GRPC_ERROR_NONE) {
    calld->consumed_md = consumed_md;
    calld->num_consumed_md = num_consumed_md;
    error = grpc_metadata_batch_filter(
        exec_ctx, batch->payload->recv_initial_metadata.recv_initial_metadata,
        remove_consumed_md, elem, "Response metadata filtering error");
  }
  GRPC_CLOSURE_SCHED(exec_ctx, calld->original_recv_initial_metadata_ready,
                     error);
}

// Called from application code.
static void on_md_processing_done(
    void* user_data, const grpc_metadata* consumed_md, size_t num_consumed_md,
    const grpc_metadata* response_md, size_t num_response_md,
    grpc_status_code status, const char* error_details) {
  grpc_call_element* elem = (grpc_call_element*)user_data;
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  // If the call was not cancelled while we were in flight, process the result.
  if (gpr_atm_full_cas(&calld->state, (gpr_atm)STATE_INIT,
                       (gpr_atm)STATE_DONE)) {
    grpc_error* error = GRPC_ERROR_NONE;
    if (status != GRPC_STATUS_OK) {
      if (error_details == nullptr) {
        error_details = "Authentication metadata processing failed.";
      }
      error = grpc_error_set_int(
          GRPC_ERROR_CREATE_FROM_COPIED_STRING(error_details),
          GRPC_ERROR_INT_GRPC_STATUS, status);
    }
    on_md_processing_done_inner(&exec_ctx, elem, consumed_md, num_consumed_md,
                                response_md, num_response_md, error);
  }
  // Clean up.
  for (size_t i = 0; i < calld->md.count; i++) {
    grpc_slice_unref_internal(&exec_ctx, calld->md.metadata[i].key);
    grpc_slice_unref_internal(&exec_ctx, calld->md.metadata[i].value);
  }
  grpc_metadata_array_destroy(&calld->md);
  GRPC_CALL_STACK_UNREF(&exec_ctx, calld->owning_call, "server_auth_metadata");
  grpc_exec_ctx_finish(&exec_ctx);
}

static void cancel_call(grpc_exec_ctx* exec_ctx, void* arg, grpc_error* error) {
  grpc_call_element* elem = (grpc_call_element*)arg;
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  // If the result was not already processed, invoke the callback now.
  if (error != GRPC_ERROR_NONE &&
      gpr_atm_full_cas(&calld->state, (gpr_atm)STATE_INIT,
                       (gpr_atm)STATE_CANCELLED)) {
    on_md_processing_done_inner(exec_ctx, elem, nullptr, 0, nullptr, 0,
                                GRPC_ERROR_REF(error));
  }
  GRPC_CALL_STACK_UNREF(exec_ctx, calld->owning_call, "cancel_call");
}

static void recv_initial_metadata_ready(grpc_exec_ctx* exec_ctx, void* arg,
                                        grpc_error* error) {
  grpc_call_element* elem = (grpc_call_element*)arg;
  filter_channel_data* chand = (filter_channel_data*)elem->channel_data;
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  grpc_transport_stream_op_batch* batch = calld->recv_initial_metadata_batch;
  if (error == GRPC_ERROR_NONE) {
    if (chand->creds != nullptr && chand->creds->processor.process != nullptr) {
      // We're calling out to the application, so we need to make sure
      // to drop the call combiner early if we get cancelled.
      GRPC_CALL_STACK_REF(calld->owning_call, "cancel_call");
      GRPC_CLOSURE_INIT(&calld->cancel_closure, cancel_call, elem,
                        grpc_schedule_on_exec_ctx);
      grpc_call_combiner_set_notify_on_cancel(exec_ctx, calld->call_combiner,
                                              &calld->cancel_closure);
      GRPC_CALL_STACK_REF(calld->owning_call, "server_auth_metadata");
      calld->md = metadata_batch_to_md_array(
          batch->payload->recv_initial_metadata.recv_initial_metadata);
      chand->creds->processor.process(
          chand->creds->processor.state, calld->auth_context,
          calld->md.metadata, calld->md.count, on_md_processing_done, elem);
      return;
    }
  }
  GRPC_CLOSURE_RUN(exec_ctx, calld->original_recv_initial_metadata_ready,
                   GRPC_ERROR_REF(error));
}

static void auth_start_transport_stream_op_batch(
    grpc_exec_ctx* exec_ctx, grpc_call_element* elem,
    grpc_transport_stream_op_batch* batch) {
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  if (batch->recv_initial_metadata) {
    // Inject our callback.
    calld->recv_initial_metadata_batch = batch;
    calld->original_recv_initial_metadata_ready =
        batch->payload->recv_initial_metadata.recv_initial_metadata_ready;
    batch->payload->recv_initial_metadata.recv_initial_metadata_ready =
        &calld->recv_initial_metadata_ready;
  }
  grpc_call_next_op(exec_ctx, elem, batch);
}

/* Constructor for filter_call_data */
static grpc_error* init_call_elem(grpc_exec_ctx* exec_ctx,
                                  grpc_call_element* elem,
                                  const grpc_call_element_args* args) {
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  filter_channel_data* chand = (filter_channel_data*)elem->channel_data;
  calld->call_combiner = args->call_combiner;
  calld->owning_call = args->call_stack;
  GRPC_CLOSURE_INIT(&calld->recv_initial_metadata_ready,
                    recv_initial_metadata_ready, elem,
                    grpc_schedule_on_exec_ctx);
  // Create server security context.  Set its auth context from channel
  // data and save it in the call context.
  grpc_server_security_context* server_ctx =
      grpc_server_security_context_create();
  server_ctx->auth_context = grpc_auth_context_create(chand->auth_context);
  calld->auth_context = server_ctx->auth_context;
  if (args->context[GRPC_CONTEXT_SECURITY].value != nullptr) {
    args->context[GRPC_CONTEXT_SECURITY].destroy(
        args->context[GRPC_CONTEXT_SECURITY].value);
  }
  args->context[GRPC_CONTEXT_SECURITY].value = server_ctx;
  args->context[GRPC_CONTEXT_SECURITY].destroy =
      grpc_server_security_context_destroy;
  return GRPC_ERROR_NONE;
}

/* Destructor for filter_call_data */
static void destroy_call_elem(grpc_exec_ctx* exec_ctx, grpc_call_element* elem,
                              const grpc_call_final_info* final_info,
                              grpc_closure* ignored) {}

/* Constructor for filter_channel_data */
static grpc_error* init_channel_elem(grpc_exec_ctx* exec_ctx,
                                     grpc_channel_element* elem,
                                     grpc_channel_element_args* args) {
  GPR_ASSERT(!args->is_last);
  filter_channel_data* chand = (filter_channel_data*)elem->channel_data;
  grpc_auth_context* auth_context =
      grpc_find_auth_context_in_args(args->channel_args);
  GPR_ASSERT(auth_context != nullptr);
  chand->auth_context =
      GRPC_AUTH_CONTEXT_REF(auth_context, "server_auth_filter");
  grpc_server_credentials* creds =
      grpc_find_server_credentials_in_args(args->channel_args);
  chand->creds = grpc_server_credentials_ref(creds);
  return GRPC_ERROR_NONE;
}

/* Destructor for channel data */
static void destroy_channel_elem(grpc_exec_ctx* exec_ctx,
                                 grpc_channel_element* elem) {
  filter_channel_data* chand = (filter_channel_data*)elem->channel_data;
  GRPC_AUTH_CONTEXT_UNREF(chand->auth_context, "server_auth_filter");
  grpc_server_credentials_unref(exec_ctx, chand->creds);
}

const grpc_channel_filter grpc_server_auth_filter = {
    auth_start_transport_stream_op_batch,
    grpc_channel_next_op,
    sizeof(filter_call_data),
    init_call_elem,
    grpc_call_stack_ignore_set_pollset_or_pollset_set,
    destroy_call_elem,
    sizeof(filter_channel_data),
    init_channel_elem,
    destroy_channel_elem,
    grpc_channel_next_get_info,
    "server-auth"};
