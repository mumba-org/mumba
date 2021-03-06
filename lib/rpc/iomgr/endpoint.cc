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

#include "rpc/iomgr/endpoint.h"

void grpc_endpoint_read(grpc_exec_ctx* exec_ctx, grpc_endpoint* ep,
                        grpc_slice_buffer* slices, grpc_closure* cb) {
  ep->vtable->read(exec_ctx, ep, slices, cb);
}

void grpc_endpoint_write(grpc_exec_ctx* exec_ctx, grpc_endpoint* ep,
                         grpc_slice_buffer* slices, grpc_closure* cb) {
  ep->vtable->write(exec_ctx, ep, slices, cb);
}

void grpc_endpoint_add_to_pollset(grpc_exec_ctx* exec_ctx, grpc_endpoint* ep,
                                  grpc_pollset* pollset) {
  ep->vtable->add_to_pollset(exec_ctx, ep, pollset);
}

void grpc_endpoint_add_to_pollset_set(grpc_exec_ctx* exec_ctx,
                                      grpc_endpoint* ep,
                                      grpc_pollset_set* pollset_set) {
  ep->vtable->add_to_pollset_set(exec_ctx, ep, pollset_set);
}

void grpc_endpoint_delete_from_pollset_set(grpc_exec_ctx* exec_ctx,
                                           grpc_endpoint* ep,
                                           grpc_pollset_set* pollset_set) {
  ep->vtable->delete_from_pollset_set(exec_ctx, ep, pollset_set);
}

void grpc_endpoint_shutdown(grpc_exec_ctx* exec_ctx, grpc_endpoint* ep,
                            grpc_error* why) {
  ep->vtable->shutdown(exec_ctx, ep, why);
}

void grpc_endpoint_destroy(grpc_exec_ctx* exec_ctx, grpc_endpoint* ep) {
  ep->vtable->destroy(exec_ctx, ep);
}

char* grpc_endpoint_get_peer(grpc_endpoint* ep) {
  return ep->vtable->get_peer(ep);
}

int grpc_endpoint_get_fd(grpc_endpoint* ep) { return ep->vtable->get_fd(ep); }

grpc_resource_user* grpc_endpoint_get_resource_user(grpc_endpoint* ep) {
  return ep->vtable->get_resource_user(ep);
}
