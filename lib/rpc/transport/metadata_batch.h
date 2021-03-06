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

#ifndef GRPC_CORE_LIB_TRANSPORT_METADATA_BATCH_H
#define GRPC_CORE_LIB_TRANSPORT_METADATA_BATCH_H

#include <stdbool.h>

#include <rpc/grpc.h>
#include <rpc/slice.h>
#include <rpc/support/port_platform.h>
#include <rpc/support/time.h>
#include "rpc/transport/metadata.h"
#include "rpc/transport/static_metadata.h"

typedef struct grpc_linked_mdelem {
  grpc_mdelem md;
  struct grpc_linked_mdelem* next;
  struct grpc_linked_mdelem* prev;
  void* reserved;
} grpc_linked_mdelem;

typedef struct grpc_mdelem_list {
  size_t count;
  size_t default_count;  // Number of default keys.
  grpc_linked_mdelem* head;
  grpc_linked_mdelem* tail;
} grpc_mdelem_list;

typedef struct grpc_metadata_batch {
  /** Metadata elements in this batch */
  grpc_mdelem_list list;
  grpc_metadata_batch_callouts idx;
  /** Used to calculate grpc-timeout at the point of sending,
      or GRPC_MILLIS_INF_FUTURE if this batch does not need to send a
      grpc-timeout */
  grpc_millis deadline;
} grpc_metadata_batch;

GRPCAPI void grpc_metadata_batch_init(grpc_metadata_batch* batch);
GRPCAPI void grpc_metadata_batch_destroy(grpc_exec_ctx* exec_ctx,
                                 grpc_metadata_batch* batch);
GRPCAPI void grpc_metadata_batch_clear(grpc_exec_ctx* exec_ctx,
                               grpc_metadata_batch* batch);
GRPCAPI bool grpc_metadata_batch_is_empty(grpc_metadata_batch* batch);

/* Returns the transport size of the batch. */
GRPCAPI size_t grpc_metadata_batch_size(grpc_metadata_batch* batch);

/** Remove \a storage from the batch, unreffing the mdelem contained */
GRPCAPI void grpc_metadata_batch_remove(grpc_exec_ctx* exec_ctx,
                                        grpc_metadata_batch* batch,
                                        grpc_linked_mdelem* storage);

/** Substitute a new mdelem for an old value */
GRPCAPI grpc_error* grpc_metadata_batch_substitute(grpc_exec_ctx* exec_ctx,
                                                   grpc_metadata_batch* batch,
                                                   grpc_linked_mdelem* storage,
                                                   grpc_mdelem new_value);

GRPCAPI void grpc_metadata_batch_set_value(grpc_exec_ctx* exec_ctx,
                                   grpc_linked_mdelem* storage,
                                   grpc_slice value);

/** Add \a storage to the beginning of \a batch. storage->md is
    assumed to be valid.
    \a storage is owned by the caller and must survive for the
    lifetime of batch. This usually means it should be around
    for the lifetime of the call. */
GRPCAPI grpc_error* grpc_metadata_batch_link_head(
    grpc_exec_ctx* exec_ctx, grpc_metadata_batch* batch,
    grpc_linked_mdelem* storage) GRPC_MUST_USE_RESULT;
/** Add \a storage to the end of \a batch. storage->md is
    assumed to be valid.
    \a storage is owned by the caller and must survive for the
    lifetime of batch. This usually means it should be around
    for the lifetime of the call. */
GRPCAPI grpc_error* grpc_metadata_batch_link_tail(
    grpc_exec_ctx* exec_ctx, grpc_metadata_batch* batch,
    grpc_linked_mdelem* storage) GRPC_MUST_USE_RESULT;

/** Add \a elem_to_add as the first element in \a batch, using
    \a storage as backing storage for the linked list element.
    \a storage is owned by the caller and must survive for the
    lifetime of batch. This usually means it should be around
    for the lifetime of the call.
    Takes ownership of \a elem_to_add */
GRPCAPI grpc_error* grpc_metadata_batch_add_head(
    grpc_exec_ctx* exec_ctx, grpc_metadata_batch* batch,
    grpc_linked_mdelem* storage, grpc_mdelem elem_to_add) GRPC_MUST_USE_RESULT;
/** Add \a elem_to_add as the last element in \a batch, using
    \a storage as backing storage for the linked list element.
    \a storage is owned by the caller and must survive for the
    lifetime of batch. This usually means it should be around
    for the lifetime of the call.
    Takes ownership of \a elem_to_add */
GRPCAPI grpc_error* grpc_metadata_batch_add_tail(
    grpc_exec_ctx* exec_ctx, grpc_metadata_batch* batch,
    grpc_linked_mdelem* storage, grpc_mdelem elem_to_add) GRPC_MUST_USE_RESULT;

GRPCAPI grpc_error* grpc_attach_md_to_error(grpc_error* src, grpc_mdelem md);

typedef struct {
  grpc_error* error;
  grpc_mdelem md;
} grpc_filtered_mdelem;

#define GRPC_FILTERED_ERROR(error) \
  { (error), GRPC_MDNULL }
#define GRPC_FILTERED_MDELEM(md) \
  { GRPC_ERROR_NONE, (md) }
#define GRPC_FILTERED_REMOVE() \
  { GRPC_ERROR_NONE, GRPC_MDNULL }

typedef grpc_filtered_mdelem (*grpc_metadata_batch_filter_func)(
    grpc_exec_ctx* exec_ctx, void* user_data, grpc_mdelem elem);
GRPCAPI grpc_error* grpc_metadata_batch_filter(
    grpc_exec_ctx* exec_ctx, grpc_metadata_batch* batch,
    grpc_metadata_batch_filter_func func, void* user_data,
    const char* composite_error_string) GRPC_MUST_USE_RESULT;

#ifndef NDEBUG
GRPCAPI void grpc_metadata_batch_assert_ok(grpc_metadata_batch* comd);
#else
#define grpc_metadata_batch_assert_ok(comd) \
  do {                                      \
  } while (0)
#endif

#endif /* GRPC_CORE_LIB_TRANSPORT_METADATA_BATCH_H */
