// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_STARTUP_LISTENER_IMPL_H_
#define VM_TOOLS_CONCIERGE_STARTUP_LISTENER_IMPL_H_

#include <stdint.h>

#include <map>

#include <base/synchronization/lock.h>
#include <base/synchronization/waitable_event.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/vm_host.grpc.pb.h>

namespace vm_tools {
namespace concierge {

// Listens for VMs to announce that they are ready before signaling the
// WaitableEvent associated with that VM.
class StartupListenerImpl final : public vm_tools::StartupListener::Service {
 public:
  StartupListenerImpl() = default;
  StartupListenerImpl(const StartupListenerImpl&) = delete;
  StartupListenerImpl& operator=(const StartupListenerImpl&) = delete;

  ~StartupListenerImpl() override = default;

  // StartupListener overrides.
  grpc::Status VmReady(grpc::ServerContext* ctx,
                       const vm_tools::EmptyMessage* request,
                       vm_tools::EmptyMessage* response) override;

  // Add the VM with the vsock context id |cid| to the set of VMs that have
  // been started but have not checked in as ready yet.
  void AddPendingVm(uint32_t cid, base::WaitableEvent* event);

  // Remove the WaitableEvent associated with |cid|.
  void RemovePendingVm(uint32_t cid);

 private:
  // VMs that have been started but have not checked in as being ready yet.
  std::map<uint32_t, base::WaitableEvent*> pending_vms_;

  // Lock to protect |pending_vms_|.
  base::Lock vm_lock_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_STARTUP_LISTENER_IMPL_H_
