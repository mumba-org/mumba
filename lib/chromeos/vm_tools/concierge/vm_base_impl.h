// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VM_BASE_IMPL_H_
#define VM_TOOLS_CONCIERGE_VM_BASE_IMPL_H_

#include "vm_tools/concierge/vm_interface.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_split.h>
#include <brillo/process/process.h>
#include <chromeos/patchpanel/dbus/client.h>

#include "vm_tools/concierge/seneschal_server_proxy.h"

namespace patchpanel {
class Client;
}

namespace vm_tools {
namespace concierge {

// A base class implementing common features that are shared with ArcVm,
// PluginVm and TerminaVm
class VmBaseImpl : public VmInterface {
 public:
  VmBaseImpl(std::unique_ptr<patchpanel::Client> network_client,
             std::unique_ptr<SeneschalServerProxy> seneschal_server_proxy,
             base::FilePath runtime_dir,
             VmMemoryId vm_memory_id);

  VmBaseImpl(std::unique_ptr<patchpanel::Client> network_client,
             uint32_t vsock_cid,
             std::unique_ptr<SeneschalServerProxy> seneschal_server_proxy,
             std::string cros_vm_socket,
             base::FilePath runtime_dir,
             VmMemoryId vm_memory_id);

  VmBaseImpl(const VmBaseImpl&) = delete;
  VmBaseImpl& operator=(const VmBaseImpl&) = delete;

  // The pid of the child process.
  pid_t pid() { return process_.pid(); }

  // VmInterface overrides.
  base::Optional<BalloonStats> GetBalloonStats() override;
  void SetBalloonSize(int64_t byte_size) override;
  const std::unique_ptr<BalloonPolicyInterface>& GetBalloonPolicy(
      const MemoryMargins& margins, const std::string& vm) override;

  bool AttachUsbDevice(uint8_t bus,
                       uint8_t addr,
                       uint16_t vid,
                       uint16_t pid,
                       int fd,
                       UsbControlResponse* response) override;
  bool DetachUsbDevice(uint8_t port, UsbControlResponse* response) override;
  bool ListUsbDevice(std::vector<UsbDevice>* devices) override;
  void MakeRtVcpu() override;

 protected:
  // Adjusts the amount of CPU the VM processes are allowed to use.
  static bool SetVmCpuRestriction(CpuRestrictionState cpu_restriction_state,
                                  const char* cpu_cgroup);

  // Starts |process_| with |args|. Returns true iff started successfully.
  bool StartProcess(base::StringPairs args);

  std::string GetVmSocketPath() const;

  void RunCrosvmCommand(const std::string& command) const;

  // The 9p server managed by seneschal that provides access to shared files for
  // this VM. Returns 0 if there is no seneschal server associated with this
  // VM.
  uint32_t seneschal_server_handle() const;

  // DBus client for the networking service.
  std::unique_ptr<patchpanel::Client> network_client_;

  // Runtime directory for this VM.
  // TODO(abhishekbh): Try to move this to private.
  base::ScopedTempDir runtime_dir_;

  // Handle to the VM process.
  brillo::ProcessImpl process_;

  // Proxy to the server providing shared directory access for this VM.
  std::unique_ptr<SeneschalServerProxy> seneschal_server_proxy_;

  // Virtual socket context id to be used when communicating with this VM.
  uint32_t vsock_cid_ = 0;

  // Balloon policy with its state.
  std::unique_ptr<BalloonPolicyInterface> balloon_policy_;

  // Id to identify the VM for memory management.
  VmMemoryId vm_memory_id_;

 private:
  void HandleSuspendImminent() override;
  void HandleSuspendDone() override;

  // Name of the socket to communicate to the crosvm binary.
  const std::string cros_vm_socket_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_VM_BASE_IMPL_H_
