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

#ifndef GRPC_CORE_LIB_CHANNEL_CHANNEL_ARGS_H
#define GRPC_CORE_LIB_CHANNEL_CHANNEL_ARGS_H

#include <rpc/compression.h>
#include <rpc/grpc.h>
#include "rpc/iomgr/socket_mutator.h"
#include <rpc/impl/codegen/port_platform.h>

// Channel args are intentionally immutable, to avoid the need for locking.

/** Copy the arguments in \a src into a new instance */
GRPCAPI grpc_channel_args* grpc_channel_args_copy(const grpc_channel_args* src);

/** Copy the arguments in \a src into a new instance, stably sorting keys */
GRPCAPI grpc_channel_args* grpc_channel_args_normalize(const grpc_channel_args* src);

/** Copy the arguments in \a src and append \a to_add. If \a to_add is NULL, it
 * is equivalent to calling \a grpc_channel_args_copy. */
GRPCAPI grpc_channel_args* grpc_channel_args_copy_and_add(const grpc_channel_args* src,
                                                  const grpc_arg* to_add,
                                                  size_t num_to_add);

/** Copies the arguments in \a src except for those whose keys are in
    \a to_remove. */
GRPCAPI grpc_channel_args* grpc_channel_args_copy_and_remove(
    const grpc_channel_args* src, const char** to_remove, size_t num_to_remove);

/** Copies the arguments from \a src except for those whose keys are in
    \a to_remove and appends the arguments in \a to_add. */
GRPCAPI grpc_channel_args* grpc_channel_args_copy_and_add_and_remove(
    const grpc_channel_args* src, const char** to_remove, size_t num_to_remove,
    const grpc_arg* to_add, size_t num_to_add);

/** Perform the union of \a a and \a b, prioritizing \a a entries */
GRPCAPI grpc_channel_args* grpc_channel_args_union(const grpc_channel_args* a,
                                           const grpc_channel_args* b);

/** Destroy arguments created by \a grpc_channel_args_copy */
GRPCAPI void grpc_channel_args_destroy(grpc_exec_ctx* exec_ctx, grpc_channel_args* a);

/** Returns the compression algorithm set in \a a. */
GRPCAPI grpc_compression_algorithm grpc_channel_args_get_compression_algorithm(
    const grpc_channel_args* a);

/** Returns the stream compression algorithm set in \a a. */
GRPCAPI grpc_stream_compression_algorithm
  grpc_channel_args_get_stream_compression_algorithm(const grpc_channel_args* a);

/** Returns a channel arg instance with compression enabled. If \a a is
 * non-NULL, its args are copied. N.B. GRPC_COMPRESS_NONE disables compression
 * for the channel. */
GRPCAPI grpc_channel_args* grpc_channel_args_set_compression_algorithm(
    grpc_channel_args* a, grpc_compression_algorithm algorithm);

/** Returns a channel arg instance with stream compression enabled. If \a a is
 * non-NULL, its args are copied. N.B. GRPC_STREAM_COMPRESS_NONE disables
 * stream compression for the channel. If a value other than
 * GRPC_STREAM_COMPRESS_NONE is set, it takes precedence over message-wise
 * compression algorithms. */
GRPCAPI grpc_channel_args* grpc_channel_args_set_stream_compression_algorithm(
    grpc_channel_args* a, grpc_stream_compression_algorithm algorithm);

/** Sets the support for the given compression algorithm. By default, all
 * compression algorithms are enabled. It's an error to disable an algorithm set
 * by grpc_channel_args_set_compression_algorithm.
 *
 * Returns an instance with the updated algorithm states. The \a a pointer is
 * modified to point to the returned instance (which may be different from the
 * input value of \a a). */
GRPCAPI grpc_channel_args* grpc_channel_args_compression_algorithm_set_state(
    grpc_exec_ctx* exec_ctx, grpc_channel_args** a,
    grpc_compression_algorithm algorithm, int enabled);

/** Sets the support for the given stream compression algorithm. By default, all
 * stream compression algorithms are enabled. It's an error to disable an
 * algorithm set by grpc_channel_args_set_stream_compression_algorithm.
 *
 * Returns an instance with the updated algorithm states. The \a a pointer is
 * modified to point to the returned instance (which may be different from the
 * input value of \a a). */
GRPCAPI grpc_channel_args* grpc_channel_args_stream_compression_algorithm_set_state(
    grpc_exec_ctx* exec_ctx, grpc_channel_args** a,
    grpc_stream_compression_algorithm algorithm, int enabled);

/** Returns the bitset representing the support state (true for enabled, false
 * for disabled) for compression algorithms.
 *
 * The i-th bit of the returned bitset corresponds to the i-th entry in the
 * grpc_compression_algorithm enum. */
GRPCAPI uint32_t grpc_channel_args_compression_algorithm_get_states(
    const grpc_channel_args* a);

/** Returns the bitset representing the support state (true for enabled, false
 * for disabled) for stream compression algorithms.
 *
 * The i-th bit of the returned bitset corresponds to the i-th entry in the
 * grpc_stream_compression_algorithm enum. */
GRPCAPI uint32_t grpc_channel_args_stream_compression_algorithm_get_states(
    const grpc_channel_args* a);

GRPCAPI int grpc_channel_args_compare(const grpc_channel_args* a,
                              const grpc_channel_args* b);

/** Returns a channel arg instance with socket mutator added. The socket mutator
 * will perform its mutate_fd method on all file descriptors used by the
 * channel.
 * If \a a is non-MULL, its args are copied. */
GRPCAPI grpc_channel_args* grpc_channel_args_set_socket_mutator(
    grpc_channel_args* a, grpc_socket_mutator* mutator);

/** Returns the value of argument \a name from \a args, or NULL if not found. */
GRPCAPI const grpc_arg* grpc_channel_args_find(const grpc_channel_args* args,
                                       const char* name);

GRPCAPI bool grpc_channel_args_want_minimal_stack(const grpc_channel_args* args);

typedef struct grpc_integer_options {
  int default_value;  // Return this if value is outside of expected bounds.
  int min_value;
  int max_value;
} grpc_integer_options;

/** Returns the value of \a arg, subject to the contraints in \a options. */
GRPCAPI int grpc_channel_arg_get_integer(const grpc_arg* arg,
                                 const grpc_integer_options options);

GRPCAPI bool grpc_channel_arg_get_bool(const grpc_arg* arg, bool default_value);

// Helpers for creating channel args.
GRPCAPI grpc_arg grpc_channel_arg_string_create(char* name, char* value);
GRPCAPI grpc_arg grpc_channel_arg_integer_create(char* name, int value);
GRPCAPI grpc_arg grpc_channel_arg_pointer_create(char* name, void* value,
                                         const grpc_arg_pointer_vtable* vtable);

#endif /* GRPC_CORE_LIB_CHANNEL_CHANNEL_ARGS_H */
