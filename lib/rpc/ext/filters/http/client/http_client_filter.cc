/*
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

#include "rpc/ext/filters/http/client/http_client_filter.h"
#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>
#include <string.h>
#include "rpc/profiling/timers.h"
#include "rpc/slice/b64.h"
#include "rpc/slice/percent_encoding.h"
#include "rpc/slice/slice_internal.h"
#include "rpc/slice/slice_string_helpers.h"
#include "rpc/support/string.h"
#include "rpc/transport/static_metadata.h"
#include "rpc/transport/transport_impl.h"

#define EXPECTED_CONTENT_TYPE "application/grpc"
#define EXPECTED_CONTENT_TYPE_LENGTH sizeof(EXPECTED_CONTENT_TYPE) - 1

/* default maximum size of payload eligable for GET request */
static const size_t kMaxPayloadSizeForGet = 2048;

typedef struct filter_call_data {
  grpc_call_combiner* call_combiner;
  // State for handling send_initial_metadata ops.
  grpc_linked_mdelem method;
  grpc_linked_mdelem scheme;
  grpc_linked_mdelem authority;
  grpc_linked_mdelem te_trailers;
  grpc_linked_mdelem content_type;
  grpc_linked_mdelem user_agent;
  // State for handling recv_initial_metadata ops.
  grpc_metadata_batch* recv_initial_metadata;
  grpc_closure* original_recv_initial_metadata_ready;
  grpc_closure recv_initial_metadata_ready;
  // State for handling recv_trailing_metadata ops.
  grpc_metadata_batch* recv_trailing_metadata;
  grpc_closure* original_recv_trailing_metadata_on_complete;
  grpc_closure recv_trailing_metadata_on_complete;
  // State for handling send_message ops.
  grpc_transport_stream_op_batch* send_message_batch;
  size_t send_message_bytes_read;
  grpc_byte_stream_cache send_message_cache;
  grpc_caching_byte_stream send_message_caching_stream;
  grpc_closure on_send_message_next_done;
  grpc_closure* original_send_message_on_complete;
  grpc_closure send_message_on_complete;
} filter_call_data;

typedef struct filter_channel_data {
  grpc_mdelem static_scheme;
  grpc_mdelem user_agent;
  size_t max_payload_size_for_get;
} filter_channel_data;

static grpc_error* client_filter_incoming_metadata(grpc_exec_ctx* exec_ctx,
                                                   grpc_call_element* elem,
                                                   grpc_metadata_batch* b) {
  if (b->idx.named.status != nullptr) {
    if (grpc_mdelem_eq(b->idx.named.status->md, GRPC_MDELEM_STATUS_200)) {
      grpc_metadata_batch_remove(exec_ctx, b, b->idx.named.status);
    } else {
      char* val = grpc_dump_slice(GRPC_MDVALUE(b->idx.named.status->md),
                                  GPR_DUMP_ASCII);
      char* msg;
      gpr_asprintf(&msg, "Received http2 header with status: %s", val);
      grpc_error* e = grpc_error_set_str(
          grpc_error_set_int(
              grpc_error_set_str(
                  GRPC_ERROR_CREATE_FROM_STATIC_STRING(
                      "Received http2 :status header with non-200 OK status"),
                  GRPC_ERROR_STR_VALUE, grpc_slice_from_copied_string(val)),
              GRPC_ERROR_INT_GRPC_STATUS, GRPC_STATUS_CANCELLED),
          GRPC_ERROR_STR_GRPC_MESSAGE, grpc_slice_from_copied_string(msg));
      gpr_free(val);
      gpr_free(msg);
      return e;
    }
  }

  if (b->idx.named.grpc_message != nullptr) {
    grpc_slice pct_decoded_msg = grpc_permissive_percent_decode_slice(
        GRPC_MDVALUE(b->idx.named.grpc_message->md));
    if (grpc_slice_is_equivalent(pct_decoded_msg,
                                 GRPC_MDVALUE(b->idx.named.grpc_message->md))) {
      grpc_slice_unref_internal(exec_ctx, pct_decoded_msg);
    } else {
      grpc_metadata_batch_set_value(exec_ctx, b->idx.named.grpc_message,
                                    pct_decoded_msg);
    }
  }

  if (b->idx.named.content_type != nullptr) {
    if (!grpc_mdelem_eq(b->idx.named.content_type->md,
                        GRPC_MDELEM_CONTENT_TYPE_APPLICATION_SLASH_GRPC)) {
      if (grpc_slice_buf_start_eq(GRPC_MDVALUE(b->idx.named.content_type->md),
                                  EXPECTED_CONTENT_TYPE,
                                  EXPECTED_CONTENT_TYPE_LENGTH) &&
          (GRPC_SLICE_START_PTR(GRPC_MDVALUE(
               b->idx.named.content_type->md))[EXPECTED_CONTENT_TYPE_LENGTH] ==
               '+' ||
           GRPC_SLICE_START_PTR(GRPC_MDVALUE(
               b->idx.named.content_type->md))[EXPECTED_CONTENT_TYPE_LENGTH] ==
               ';')) {
        /* Although the C implementation doesn't (currently) generate them,
           any custom +-suffix is explicitly valid. */
        /* TODO(klempner): We should consider preallocating common values such
           as +proto or +json, or at least stashing them if we see them. */
        /* TODO(klempner): Should we be surfacing this to application code? */
      } else {
        /* TODO(klempner): We're currently allowing this, but we shouldn't
           see it without a proxy so log for now. */
        char* val = grpc_dump_slice(GRPC_MDVALUE(b->idx.named.content_type->md),
                                    GPR_DUMP_ASCII);
        gpr_log(GPR_INFO, "Unexpected content-type '%s'", val);
        gpr_free(val);
      }
    }
    grpc_metadata_batch_remove(exec_ctx, b, b->idx.named.content_type);
  }

  return GRPC_ERROR_NONE;
}

static void recv_initial_metadata_ready(grpc_exec_ctx* exec_ctx,
                                        void* user_data, grpc_error* error) {
  grpc_call_element* elem = (grpc_call_element*)user_data;
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  if (error == GRPC_ERROR_NONE) {
    error = client_filter_incoming_metadata(exec_ctx, elem,
                                            calld->recv_initial_metadata);
  } else {
    GRPC_ERROR_REF(error);
  }
  GRPC_CLOSURE_RUN(exec_ctx, calld->original_recv_initial_metadata_ready,
                   error);
}

static void recv_trailing_metadata_on_complete(grpc_exec_ctx* exec_ctx,
                                               void* user_data,
                                               grpc_error* error) {
  grpc_call_element* elem = (grpc_call_element*)user_data;
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  if (error == GRPC_ERROR_NONE) {
    error = client_filter_incoming_metadata(exec_ctx, elem,
                                            calld->recv_trailing_metadata);
  } else {
    GRPC_ERROR_REF(error);
  }
  GRPC_CLOSURE_RUN(exec_ctx, calld->original_recv_trailing_metadata_on_complete,
                   error);
}

static void send_message_on_complete(grpc_exec_ctx* exec_ctx, void* arg,
                                     grpc_error* error) {
  grpc_call_element* elem = (grpc_call_element*)arg;
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  grpc_byte_stream_cache_destroy(exec_ctx, &calld->send_message_cache);
  GRPC_CLOSURE_RUN(exec_ctx, calld->original_send_message_on_complete,
                   GRPC_ERROR_REF(error));
}

// Pulls a slice from the send_message byte stream, updating
// calld->send_message_bytes_read.
static grpc_error* pull_slice_from_send_message(grpc_exec_ctx* exec_ctx,
                                                filter_call_data* calld) {
  grpc_slice incoming_slice;
  grpc_error* error = grpc_byte_stream_pull(
      exec_ctx, &calld->send_message_caching_stream.base, &incoming_slice);
  if (error == GRPC_ERROR_NONE) {
    calld->send_message_bytes_read += GRPC_SLICE_LENGTH(incoming_slice);
    grpc_slice_unref_internal(exec_ctx, incoming_slice);
  }
  return error;
}

// Reads as many slices as possible from the send_message byte stream.
// Upon successful return, if calld->send_message_bytes_read ==
// calld->send_message_caching_stream.base.length, then we have completed
// reading from the byte stream; otherwise, an async read has been dispatched
// and on_send_message_next_done() will be invoked when it is complete.
static grpc_error* read_all_available_send_message_data(grpc_exec_ctx* exec_ctx,
                                                        filter_call_data* calld) {
  while (grpc_byte_stream_next(exec_ctx,
                               &calld->send_message_caching_stream.base,
                               ~(size_t)0, &calld->on_send_message_next_done)) {
    grpc_error* error = pull_slice_from_send_message(exec_ctx, calld);
    if (error != GRPC_ERROR_NONE) return error;
    if (calld->send_message_bytes_read ==
        calld->send_message_caching_stream.base.length) {
      break;
    }
  }
  return GRPC_ERROR_NONE;
}

// Async callback for grpc_byte_stream_next().
static void on_send_message_next_done(grpc_exec_ctx* exec_ctx, void* arg,
                                      grpc_error* error) {
  grpc_call_element* elem = (grpc_call_element*)arg;
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  if (error != GRPC_ERROR_NONE) {
    grpc_transport_stream_op_batch_finish_with_failure(
        exec_ctx, calld->send_message_batch, error, calld->call_combiner);
    return;
  }
  error = pull_slice_from_send_message(exec_ctx, calld);
  if (error != GRPC_ERROR_NONE) {
    grpc_transport_stream_op_batch_finish_with_failure(
        exec_ctx, calld->send_message_batch, error, calld->call_combiner);
    return;
  }
  // There may or may not be more to read, but we don't care.  If we got
  // here, then we know that all of the data was not available
  // synchronously, so we were not able to do a cached call.  Instead,
  // we just reset the byte stream and then send down the batch as-is.
  grpc_caching_byte_stream_reset(&calld->send_message_caching_stream);
  grpc_call_next_op(exec_ctx, elem, calld->send_message_batch);
}

static char* slice_buffer_to_string(grpc_slice_buffer* slice_buffer) {
  char* payload_bytes = (char*)gpr_malloc(slice_buffer->length + 1);
  size_t offset = 0;
  for (size_t i = 0; i < slice_buffer->count; ++i) {
    memcpy(payload_bytes + offset,
           GRPC_SLICE_START_PTR(slice_buffer->slices[i]),
           GRPC_SLICE_LENGTH(slice_buffer->slices[i]));
    offset += GRPC_SLICE_LENGTH(slice_buffer->slices[i]);
  }
  *(payload_bytes + offset) = '\0';
  return payload_bytes;
}

// Modifies the path entry in the batch's send_initial_metadata to
// append the base64-encoded query for a GET request.
static grpc_error* update_path_for_get(grpc_exec_ctx* exec_ctx,
                                       grpc_call_element* elem,
                                       grpc_transport_stream_op_batch* batch) {
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  grpc_slice path_slice =
      GRPC_MDVALUE(batch->payload->send_initial_metadata.send_initial_metadata
                       ->idx.named.path->md);
  /* sum up individual component's lengths and allocate enough memory to
   * hold combined path+query */
  size_t estimated_len = GRPC_SLICE_LENGTH(path_slice);
  estimated_len++; /* for the '?' */
  estimated_len += grpc_base64_estimate_encoded_size(
      batch->payload->send_message.send_message->length, true /* url_safe */,
      false /* multi_line */);
  grpc_slice path_with_query_slice = GRPC_SLICE_MALLOC(estimated_len);
  /* memcopy individual pieces into this slice */
  char* write_ptr = (char*)GRPC_SLICE_START_PTR(path_with_query_slice);
  char* original_path = (char*)GRPC_SLICE_START_PTR(path_slice);
  memcpy(write_ptr, original_path, GRPC_SLICE_LENGTH(path_slice));
  write_ptr += GRPC_SLICE_LENGTH(path_slice);
  *write_ptr++ = '?';
  char* payload_bytes =
      slice_buffer_to_string(&calld->send_message_cache.cache_buffer);
  grpc_base64_encode_core((char*)write_ptr, payload_bytes,
                          batch->payload->send_message.send_message->length,
                          true /* url_safe */, false /* multi_line */);
  gpr_free(payload_bytes);
  /* remove trailing unused memory and add trailing 0 to terminate string */
  char* t = (char*)GRPC_SLICE_START_PTR(path_with_query_slice);
  /* safe to use strlen since base64_encode will always add '\0' */
  path_with_query_slice =
      grpc_slice_sub_no_ref(path_with_query_slice, 0, strlen(t));
  /* substitute previous path with the new path+query */
  grpc_mdelem mdelem_path_and_query =
      grpc_mdelem_from_slices(exec_ctx, GRPC_MDSTR_PATH, path_with_query_slice);
  grpc_metadata_batch* b =
      batch->payload->send_initial_metadata.send_initial_metadata;
  return grpc_metadata_batch_substitute(exec_ctx, b, b->idx.named.path,
                                        mdelem_path_and_query);
}

static void remove_if_present(grpc_exec_ctx* exec_ctx,
                              grpc_metadata_batch* batch,
                              grpc_metadata_batch_callouts_index idx) {
  if (batch->idx.array[idx] != nullptr) {
    grpc_metadata_batch_remove(exec_ctx, batch, batch->idx.array[idx]);
  }
}

static void hc_start_transport_stream_op_batch(
    grpc_exec_ctx* exec_ctx, grpc_call_element* elem,
    grpc_transport_stream_op_batch* batch) {
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  filter_channel_data* channeld = (filter_channel_data*)elem->channel_data;
  GPR_TIMER_BEGIN("hc_start_transport_stream_op_batch", 0);

  if (batch->recv_initial_metadata) {
    /* substitute our callback for the higher callback */
    calld->recv_initial_metadata =
        batch->payload->recv_initial_metadata.recv_initial_metadata;
    calld->original_recv_initial_metadata_ready =
        batch->payload->recv_initial_metadata.recv_initial_metadata_ready;
    batch->payload->recv_initial_metadata.recv_initial_metadata_ready =
        &calld->recv_initial_metadata_ready;
  }

  if (batch->recv_trailing_metadata) {
    /* substitute our callback for the higher callback */
    calld->recv_trailing_metadata =
        batch->payload->recv_trailing_metadata.recv_trailing_metadata;
    calld->original_recv_trailing_metadata_on_complete = batch->on_complete;
    batch->on_complete = &calld->recv_trailing_metadata_on_complete;
  }

  grpc_error* error = GRPC_ERROR_NONE;
  bool batch_will_be_handled_asynchronously = false;
  if (batch->send_initial_metadata) {
    // Decide which HTTP VERB to use. We use GET if the request is marked
    // cacheable, and the operation contains both initial metadata and send
    // message, and the payload is below the size threshold, and all the data
    // for this request is immediately available.
    grpc_mdelem method = GRPC_MDELEM_METHOD_POST;
    if (batch->send_message &&
        (batch->payload->send_initial_metadata.send_initial_metadata_flags &
         GRPC_INITIAL_METADATA_CACHEABLE_REQUEST) &&
        batch->payload->send_message.send_message->length <
            channeld->max_payload_size_for_get) {
      calld->send_message_bytes_read = 0;
      grpc_byte_stream_cache_init(&calld->send_message_cache,
                                  batch->payload->send_message.send_message);
      grpc_caching_byte_stream_init(&calld->send_message_caching_stream,
                                    &calld->send_message_cache);
      batch->payload->send_message.send_message =
          &calld->send_message_caching_stream.base;
      calld->original_send_message_on_complete = batch->on_complete;
      batch->on_complete = &calld->send_message_on_complete;
      calld->send_message_batch = batch;
      error = read_all_available_send_message_data(exec_ctx, calld);
      if (error != GRPC_ERROR_NONE) goto done;
      // If all the data has been read, then we can use GET.
      if (calld->send_message_bytes_read ==
          calld->send_message_caching_stream.base.length) {
        method = GRPC_MDELEM_METHOD_GET;
        error = update_path_for_get(exec_ctx, elem, batch);
        if (error != GRPC_ERROR_NONE) goto done;
        batch->send_message = false;
        grpc_byte_stream_destroy(exec_ctx,
                                 &calld->send_message_caching_stream.base);
      } else {
        // Not all data is available.  The batch will be sent down
        // asynchronously in on_send_message_next_done().
        batch_will_be_handled_asynchronously = true;
        // Fall back to POST.
        gpr_log(GPR_DEBUG,
                "Request is marked Cacheable but not all data is available.  "
                "Falling back to POST");
      }
    } else if (batch->payload->send_initial_metadata
                   .send_initial_metadata_flags &
               GRPC_INITIAL_METADATA_IDEMPOTENT_REQUEST) {
      method = GRPC_MDELEM_METHOD_PUT;
    }

    remove_if_present(
        exec_ctx, batch->payload->send_initial_metadata.send_initial_metadata,
        GRPC_BATCH_METHOD);
    remove_if_present(
        exec_ctx, batch->payload->send_initial_metadata.send_initial_metadata,
        GRPC_BATCH_SCHEME);
    remove_if_present(
        exec_ctx, batch->payload->send_initial_metadata.send_initial_metadata,
        GRPC_BATCH_TE);
    remove_if_present(
        exec_ctx, batch->payload->send_initial_metadata.send_initial_metadata,
        GRPC_BATCH_CONTENT_TYPE);
    remove_if_present(
        exec_ctx, batch->payload->send_initial_metadata.send_initial_metadata,
        GRPC_BATCH_USER_AGENT);

    /* Send : prefixed headers, which have to be before any application
       layer headers. */
    error = grpc_metadata_batch_add_head(
        exec_ctx, batch->payload->send_initial_metadata.send_initial_metadata,
        &calld->method, method);
    if (error != GRPC_ERROR_NONE) goto done;
    error = grpc_metadata_batch_add_head(
        exec_ctx, batch->payload->send_initial_metadata.send_initial_metadata,
        &calld->scheme, channeld->static_scheme);
    if (error != GRPC_ERROR_NONE) goto done;
    error = grpc_metadata_batch_add_tail(
        exec_ctx, batch->payload->send_initial_metadata.send_initial_metadata,
        &calld->te_trailers, GRPC_MDELEM_TE_TRAILERS);
    if (error != GRPC_ERROR_NONE) goto done;
    error = grpc_metadata_batch_add_tail(
        exec_ctx, batch->payload->send_initial_metadata.send_initial_metadata,
        &calld->content_type, GRPC_MDELEM_CONTENT_TYPE_APPLICATION_SLASH_GRPC);
    if (error != GRPC_ERROR_NONE) goto done;
    error = grpc_metadata_batch_add_tail(
        exec_ctx, batch->payload->send_initial_metadata.send_initial_metadata,
        &calld->user_agent, GRPC_MDELEM_REF(channeld->user_agent));
    if (error != GRPC_ERROR_NONE) goto done;
  }

done:
  if (error != GRPC_ERROR_NONE) {
    grpc_transport_stream_op_batch_finish_with_failure(
        exec_ctx, calld->send_message_batch, error, calld->call_combiner);
  } else if (!batch_will_be_handled_asynchronously) {
    grpc_call_next_op(exec_ctx, elem, batch);
  }
  GPR_TIMER_END("hc_start_transport_stream_op_batch", 0);
}

/* Constructor for filter_call_data */
static grpc_error* init_call_elem(grpc_exec_ctx* exec_ctx,
                                  grpc_call_element* elem,
                                  const grpc_call_element_args* args) {
  filter_call_data* calld = (filter_call_data*)elem->call_data;
  calld->call_combiner = args->call_combiner;
  GRPC_CLOSURE_INIT(&calld->recv_initial_metadata_ready,
                    recv_initial_metadata_ready, elem,
                    grpc_schedule_on_exec_ctx);
  GRPC_CLOSURE_INIT(&calld->recv_trailing_metadata_on_complete,
                    recv_trailing_metadata_on_complete, elem,
                    grpc_schedule_on_exec_ctx);
  GRPC_CLOSURE_INIT(&calld->send_message_on_complete, send_message_on_complete,
                    elem, grpc_schedule_on_exec_ctx);
  GRPC_CLOSURE_INIT(&calld->on_send_message_next_done,
                    on_send_message_next_done, elem, grpc_schedule_on_exec_ctx);
  return GRPC_ERROR_NONE;
}

/* Destructor for filter_call_data */
static void destroy_call_elem(grpc_exec_ctx* exec_ctx, grpc_call_element* elem,
                              const grpc_call_final_info* final_info,
                              grpc_closure* ignored) {}

static grpc_mdelem scheme_from_args(const grpc_channel_args* args) {
  unsigned i;
  size_t j;
  grpc_mdelem valid_schemes[] = {GRPC_MDELEM_SCHEME_HTTP,
                                 GRPC_MDELEM_SCHEME_HTTPS};
  if (args != nullptr) {
    for (i = 0; i < args->num_args; ++i) {
      if (args->args[i].type == GRPC_ARG_STRING &&
          strcmp(args->args[i].key, GRPC_ARG_HTTP2_SCHEME) == 0) {
        for (j = 0; j < GPR_ARRAY_SIZE(valid_schemes); j++) {
          if (0 == grpc_slice_str_cmp(GRPC_MDVALUE(valid_schemes[j]),
                                      args->args[i].value.string)) {
            return valid_schemes[j];
          }
        }
      }
    }
  }
  return GRPC_MDELEM_SCHEME_HTTP;
}

static size_t max_payload_size_from_args(const grpc_channel_args* args) {
  if (args != nullptr) {
    for (size_t i = 0; i < args->num_args; ++i) {
      if (0 == strcmp(args->args[i].key, GRPC_ARG_MAX_PAYLOAD_SIZE_FOR_GET)) {
        if (args->args[i].type != GRPC_ARG_INTEGER) {
          gpr_log(GPR_ERROR, "%s: must be an integer",
                  GRPC_ARG_MAX_PAYLOAD_SIZE_FOR_GET);
        } else {
          return (size_t)args->args[i].value.integer;
        }
      }
    }
  }
  return kMaxPayloadSizeForGet;
}

static grpc_slice user_agent_from_args(const grpc_channel_args* args,
                                       const char* transport_name) {
  gpr_strvec v;
  size_t i;
  int is_first = 1;
  char* tmp;
  grpc_slice result;

  gpr_strvec_init(&v);

  for (i = 0; args && i < args->num_args; i++) {
    if (0 == strcmp(args->args[i].key, GRPC_ARG_PRIMARY_USER_AGENT_STRING)) {
      if (args->args[i].type != GRPC_ARG_STRING) {
        gpr_log(GPR_ERROR, "Channel argument '%s' should be a string",
                GRPC_ARG_PRIMARY_USER_AGENT_STRING);
      } else {
        if (!is_first) gpr_strvec_add(&v, gpr_strdup(" "));
        is_first = 0;
        gpr_strvec_add(&v, gpr_strdup(args->args[i].value.string));
      }
    }
  }

  gpr_asprintf(&tmp, "%sgrpc-c/%s (%s; %s; %s)", is_first ? "" : " ",
               grpc_version_string(), GPR_PLATFORM_STRING, transport_name,
               grpc_g_stands_for());
  is_first = 0;
  gpr_strvec_add(&v, tmp);

  for (i = 0; args && i < args->num_args; i++) {
    if (0 == strcmp(args->args[i].key, GRPC_ARG_SECONDARY_USER_AGENT_STRING)) {
      if (args->args[i].type != GRPC_ARG_STRING) {
        gpr_log(GPR_ERROR, "Channel argument '%s' should be a string",
                GRPC_ARG_SECONDARY_USER_AGENT_STRING);
      } else {
        if (!is_first) gpr_strvec_add(&v, gpr_strdup(" "));
        is_first = 0;
        gpr_strvec_add(&v, gpr_strdup(args->args[i].value.string));
      }
    }
  }

  tmp = gpr_strvec_flatten(&v, nullptr);
  gpr_strvec_destroy(&v);
  result = grpc_slice_intern(grpc_slice_from_static_string(tmp));
  gpr_free(tmp);

  return result;
}

/* Constructor for filter_channel_data */
static grpc_error* init_channel_elem(grpc_exec_ctx* exec_ctx,
                                     grpc_channel_element* elem,
                                     grpc_channel_element_args* args) {
  filter_channel_data* chand = (filter_channel_data*)elem->channel_data;
  GPR_ASSERT(!args->is_last);
  GPR_ASSERT(args->optional_transport != nullptr);
  chand->static_scheme = scheme_from_args(args->channel_args);
  chand->max_payload_size_for_get =
      max_payload_size_from_args(args->channel_args);
  chand->user_agent = grpc_mdelem_from_slices(
      exec_ctx, GRPC_MDSTR_USER_AGENT,
      user_agent_from_args(args->channel_args,
                           args->optional_transport->vtable->name));
  return GRPC_ERROR_NONE;
}

/* Destructor for channel data */
static void destroy_channel_elem(grpc_exec_ctx* exec_ctx,
                                 grpc_channel_element* elem) {
  filter_channel_data* chand = (filter_channel_data*)elem->channel_data;
  GRPC_MDELEM_UNREF(exec_ctx, chand->user_agent);
}

const grpc_channel_filter grpc_http_client_filter = {
    hc_start_transport_stream_op_batch,
    grpc_channel_next_op,
    sizeof(filter_call_data),
    init_call_elem,
    grpc_call_stack_ignore_set_pollset_or_pollset_set,
    destroy_call_elem,
    sizeof(filter_channel_data),
    init_channel_elem,
    destroy_channel_elem,
    grpc_channel_next_get_info,
    "http-client"};
