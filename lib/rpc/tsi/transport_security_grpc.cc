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

#include "rpc/tsi/transport_security_grpc.h"

/* This method creates a tsi_zero_copy_grpc_protector object.  */
tsi_result tsi_handshaker_result_create_zero_copy_grpc_protector(
    grpc_exec_ctx* exec_ctx, const tsi_handshaker_result* self,
    size_t* max_output_protected_frame_size,
    tsi_zero_copy_grpc_protector** protector) {
  if (exec_ctx == nullptr || self == nullptr || self->vtable == nullptr ||
      protector == nullptr) {
    return TSI_INVALID_ARGUMENT;
  }
  if (self->vtable->create_zero_copy_grpc_protector == nullptr) {
    return TSI_UNIMPLEMENTED;
  }
  return self->vtable->create_zero_copy_grpc_protector(
      exec_ctx, self, max_output_protected_frame_size, protector);
}

/* --- tsi_zero_copy_grpc_protector common implementation. ---

   Calls specific implementation after state/input validation. */

tsi_result tsi_zero_copy_grpc_protector_protect(
    grpc_exec_ctx* exec_ctx, tsi_zero_copy_grpc_protector* self,
    grpc_slice_buffer* unprotected_slices,
    grpc_slice_buffer* protected_slices) {
  if (exec_ctx == nullptr || self == nullptr || self->vtable == nullptr ||
      unprotected_slices == nullptr || protected_slices == nullptr) {
    return TSI_INVALID_ARGUMENT;
  }
  if (self->vtable->protect == nullptr) return TSI_UNIMPLEMENTED;
  return self->vtable->protect(exec_ctx, self, unprotected_slices,
                               protected_slices);
}

tsi_result tsi_zero_copy_grpc_protector_unprotect(
    grpc_exec_ctx* exec_ctx, tsi_zero_copy_grpc_protector* self,
    grpc_slice_buffer* protected_slices,
    grpc_slice_buffer* unprotected_slices) {
  if (exec_ctx == nullptr || self == nullptr || self->vtable == nullptr ||
      protected_slices == nullptr || unprotected_slices == nullptr) {
    return TSI_INVALID_ARGUMENT;
  }
  if (self->vtable->unprotect == nullptr) return TSI_UNIMPLEMENTED;
  return self->vtable->unprotect(exec_ctx, self, protected_slices,
                                 unprotected_slices);
}

void tsi_zero_copy_grpc_protector_destroy(grpc_exec_ctx* exec_ctx,
                                          tsi_zero_copy_grpc_protector* self) {
  if (self == nullptr) return;
  self->vtable->destroy(exec_ctx, self);
}
