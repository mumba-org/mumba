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

#ifndef GRPC_CORE_LIB_TRANSPORT_METADATA_H
#define GRPC_CORE_LIB_TRANSPORT_METADATA_H

#include <rpc/grpc.h>
#include <rpc/slice.h>
#include <rpc/support/useful.h>

#include "rpc/iomgr/exec_ctx.h"

extern grpc_core::DebugOnlyTraceFlag grpc_trace_metadata;

/* This file provides a mechanism for tracking metadata through the grpc stack.
   It's not intended for consumption outside of the library.

   Metadata is tracked in the context of a grpc_mdctx. For the time being there
   is one of these per-channel, avoiding cross channel interference with memory
   use and lock contention.

   The context tracks unique strings (grpc_mdstr) and pairs of strings
   (grpc_mdelem). Any of these objects can be checked for equality by comparing
   their pointers. These objects are reference counted.

   grpc_mdelem can additionally store a (non-NULL) user data pointer. This
   pointer is intended to be used to cache semantic meaning of a metadata
   element. For example, an OAuth token may cache the credentials it represents
   and the time at which it expires in the mdelem user data.

   Combining this metadata cache and the hpack compression table allows us to
   simply lookup complete preparsed objects quickly, incurring a few atomic
   ops per metadata element on the fast path.

   grpc_mdelem instances MAY live longer than their refcount implies, and are
   garbage collected periodically, meaning cached data can easily outlive a
   single request.

   STATIC METADATA: in static_metadata.h we declare a set of static metadata.
   These mdelems and mdstrs are available via pre-declared code generated macros
   and are available to code anywhere between grpc_init() and grpc_shutdown().
   They are not refcounted, but can be passed to _ref and _unref functions
   declared here - in which case those functions are effectively no-ops. */

/* Forward declarations */
typedef struct grpc_mdelem grpc_mdelem;

/* if changing this, make identical changes in:
   - interned_metadata, allocated_metadata in metadata.c
   - grpc_metadata in grpc_types.h */
typedef struct grpc_mdelem_data {
  const grpc_slice key;
  const grpc_slice value;
  /* there is a private part to this in metadata.c */
} grpc_mdelem_data;

/* GRPC_MDELEM_STORAGE_* enum values that can be treated as interned always have
   this bit set in their integer value */
#define GRPC_MDELEM_STORAGE_INTERNED_BIT 1

typedef enum {
  /* memory pointed to by grpc_mdelem::payload is owned by an external system */
  GRPC_MDELEM_STORAGE_EXTERNAL = 0,
  /* memory pointed to by grpc_mdelem::payload is interned by the metadata
     system */
  GRPC_MDELEM_STORAGE_INTERNED = GRPC_MDELEM_STORAGE_INTERNED_BIT,
  /* memory pointed to by grpc_mdelem::payload is allocated by the metadata
     system */
  GRPC_MDELEM_STORAGE_ALLOCATED = 2,
  /* memory is in the static metadata table */
  GRPC_MDELEM_STORAGE_STATIC = 2 | GRPC_MDELEM_STORAGE_INTERNED_BIT,
} grpc_mdelem_data_storage;

struct grpc_mdelem {
  /* a grpc_mdelem_data* generally, with the two lower bits signalling memory
     ownership as per grpc_mdelem_data_storage */
  uintptr_t payload;
};

#define GRPC_MDELEM_DATA(md) ((grpc_mdelem_data*)((md).payload & ~(uintptr_t)3))
#define GRPC_MDELEM_STORAGE(md) \
  ((grpc_mdelem_data_storage)((md).payload & (uintptr_t)3))
#ifdef __cplusplus
#define GRPC_MAKE_MDELEM(data, storage) \
  (grpc_mdelem{((uintptr_t)(data)) | ((uintptr_t)storage)})
#else
#define GRPC_MAKE_MDELEM(data, storage) \
  ((grpc_mdelem){((uintptr_t)(data)) | ((uintptr_t)storage)})
#endif
#define GRPC_MDELEM_IS_INTERNED(md)          \
  ((grpc_mdelem_data_storage)((md).payload & \
                              (uintptr_t)GRPC_MDELEM_STORAGE_INTERNED_BIT))

/* Unrefs the slices. */
GRPCAPI grpc_mdelem grpc_mdelem_from_slices(grpc_exec_ctx* exec_ctx, grpc_slice key,
                                    grpc_slice value);

/* Cheaply convert a grpc_metadata to a grpc_mdelem; may use the grpc_metadata
   object as backing storage (so lifetimes should align) */
GRPCAPI grpc_mdelem grpc_mdelem_from_grpc_metadata(grpc_exec_ctx* exec_ctx,
                                           grpc_metadata* metadata);

/* Does not unref the slices; if a new non-interned mdelem is needed, allocates
   one if compatible_external_backing_store is NULL, or uses
   compatible_external_backing_store if it is non-NULL (in which case it's the
   users responsibility to ensure that it outlives usage) */
GRPCAPI grpc_mdelem grpc_mdelem_create(
    grpc_exec_ctx* exec_ctx, grpc_slice key, grpc_slice value,
    grpc_mdelem_data* compatible_external_backing_store);

GRPCAPI bool grpc_mdelem_eq(grpc_mdelem a, grpc_mdelem b);

GRPCAPI size_t grpc_mdelem_get_size_in_hpack_table(grpc_mdelem elem,
                                           bool use_true_binary_metadata);

/* Mutator and accessor for grpc_mdelem user data. The destructor function
   is used as a type tag and is checked during user_data fetch. */
GRPCAPI void* grpc_mdelem_get_user_data(grpc_mdelem md, void (*if_destroy_func)(void*));
GRPCAPI void* grpc_mdelem_set_user_data(grpc_mdelem md, void (*destroy_func)(void*),
                                void* user_data);

#ifndef NDEBUG
#define GRPC_MDELEM_REF(s) grpc_mdelem_ref((s), __FILE__, __LINE__)
#define GRPC_MDELEM_UNREF(exec_ctx, s) \
  grpc_mdelem_unref((exec_ctx), (s), __FILE__, __LINE__)
GRPCAPI grpc_mdelem grpc_mdelem_ref(grpc_mdelem md, const char* file, int line);
GRPCAPI void grpc_mdelem_unref(grpc_exec_ctx* exec_ctx, grpc_mdelem md,
                       const char* file, int line);
#else
#define GRPC_MDELEM_REF(s) grpc_mdelem_ref((s))
#define GRPC_MDELEM_UNREF(exec_ctx, s) grpc_mdelem_unref((exec_ctx), (s))
GRPCAPI grpc_mdelem grpc_mdelem_ref(grpc_mdelem md);
GRPCAPI void grpc_mdelem_unref(grpc_exec_ctx* exec_ctx, grpc_mdelem md);
#endif

#define GRPC_MDKEY(md) (GRPC_MDELEM_DATA(md)->key)
#define GRPC_MDVALUE(md) (GRPC_MDELEM_DATA(md)->value)

#define GRPC_MDNULL GRPC_MAKE_MDELEM(NULL, GRPC_MDELEM_STORAGE_EXTERNAL)
#define GRPC_MDISNULL(md) (GRPC_MDELEM_DATA(md) == NULL)

/* We add 32 bytes of padding as per RFC-7540 section 6.5.2. */
#define GRPC_MDELEM_LENGTH(e)                                                  \
  (GRPC_SLICE_LENGTH(GRPC_MDKEY((e))) + GRPC_SLICE_LENGTH(GRPC_MDVALUE((e))) + \
   32)

#define GRPC_MDSTR_KV_HASH(k_hash, v_hash) (GPR_ROTL((k_hash), 2) ^ (v_hash))

GRPCAPI void grpc_mdctx_global_init(void);
GRPCAPI void grpc_mdctx_global_shutdown(grpc_exec_ctx* exec_ctx);

#endif /* GRPC_CORE_LIB_TRANSPORT_METADATA_H */
