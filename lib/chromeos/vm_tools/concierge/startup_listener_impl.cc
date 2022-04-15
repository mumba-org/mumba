// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/startup_listener_impl.h"

#include <inttypes.h>
#include <string.h>

#include <base/logging.h>

namespace vm_tools {
namespace concierge {

grpc::Status StartupListenerImpl::VmReady(grpc::ServerContext* ctx,
                                          const vm_tools::EmptyMessage* request,
                                          vm_tools::EmptyMessage* response) {
  uint64_t cid = 0;
  if (sscanf(ctx->peer().c_str(), "vsock:%" PRIu64, &cid) != 1) {
    LOG(WARNING) << "Failed to parse peer address " << ctx->peer();
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Invalid peer for StartupListener");
  }

  base::AutoLock lock(vm_lock_);
  auto iter = pending_vms_.find(cid);
  if (iter == pending_vms_.end()) {
    LOG(ERROR) << "Received VmReady from vm with unknown context id: " << cid;
    return grpc::Status(grpc::FAILED_PRECONDITION, "VM is not known");
  }

  iter->second->Signal();
  pending_vms_.erase(iter);

  return grpc::Status::OK;
}

void StartupListenerImpl::AddPendingVm(uint32_t cid,
                                       base::WaitableEvent* event) {
  base::AutoLock lock(vm_lock_);

  pending_vms_[cid] = event;
}

void StartupListenerImpl::RemovePendingVm(uint32_t cid) {
  base::AutoLock lock(vm_lock_);

  pending_vms_.erase(cid);
}

}  // namespace concierge
}  // namespace vm_tools
