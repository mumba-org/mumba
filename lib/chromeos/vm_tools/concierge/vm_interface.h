// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VM_INTERFACE_H_
#define VM_TOOLS_CONCIERGE_VM_INTERFACE_H_

#include <stdint.h>
#include <unistd.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <vm_concierge/proto_bindings/concierge_service.pb.h>

#include "vm_tools/concierge/balloon_policy.h"
#include "vm_tools/concierge/usb_control.h"

namespace vm_tools {
namespace concierge {

// See VmInterface.Info.vm_memory_id
typedef uint32_t VmMemoryId;

// Represents a single instance of a virtual machine.
class VmInterface {
 public:
  // The current status of the VM.
  enum class Status {
    STARTING,
    RUNNING,
    STOPPED,
  };

  // Information about a virtual machine.
  struct Info {
    // The IPv4 address in network-byte order.
    uint32_t ipv4_address;

    // The pid of the main crosvm process for the VM.
    pid_t pid;

    // The vsock context id for the VM, if one exists.  Must be set to 0 if
    // there is no vsock context id.
    uint32_t cid;

    // ID for identifying a VM in the context of managing memory. This field is
    // valid for all VMs. On non-manaTEE systems, this is set by concierge. On
    // manaTEE, it is specified by the manatee memory service, and it specifies
    // the balloon control socket that this VM's crosvm instance should connect
    // to - /run/mms_control_%d.sock.
    VmMemoryId vm_memory_id;

    // The handle for the 9P server managed by seneschal on behalf of this VM
    // if one exists, 0 otherwise.
    uint32_t seneschal_server_handle;

    // Token assigned to the VM when registering with permission service.
    // Used to identify the VM to service providers and fetching set of
    // permissions granted to the VM.
    std::string permission_token;

    // The current status of the VM.
    Status status;

    // Type of the VM.
    VmInfo::VmType type;
  };

  // Classes that implement this interface *MUST* exit as quickly as possible
  // once their destructor is called.
  virtual ~VmInterface() = default;

  // Suspends the VM.
  void Suspend() {
    HandleSuspendImminent();
    suspended_ = true;
  }

  // Resumes the VM.
  void Resume() {
    HandleSuspendDone();
    suspended_ = false;
  }

  bool IsSuspended() { return suspended_; }

  // Shuts down the VM. Returns true if the VM was successfully shut down and
  // false otherwise.
  virtual bool Shutdown() = 0;

  // Information about the VM.
  virtual Info GetInfo() = 0;

  // Returns balloon stats info retrieved from virtio-balloon device.
  virtual base::Optional<BalloonStats> GetBalloonStats() = 0;

  // Resize the balloon size.
  virtual void SetBalloonSize(int64_t byte_size) = 0;

  // Get the virtio_balloon sizing policy for this VM.
  virtual const std::unique_ptr<BalloonPolicyInterface>& GetBalloonPolicy(
      const MemoryMargins& margins, const std::string& vm) = 0;

  // Attach an usb device at host bus:addr, with vid, pid and an opened fd.
  virtual bool AttachUsbDevice(uint8_t bus,
                               uint8_t addr,
                               uint16_t vid,
                               uint16_t pid,
                               int fd,
                               UsbControlResponse* response) = 0;

  // Detach the usb device at guest port.
  virtual bool DetachUsbDevice(uint8_t port, UsbControlResponse* response) = 0;

  // List all usb devices attached to guest.
  virtual bool ListUsbDevice(std::vector<UsbDevice>* devices) = 0;

  // Returns true if this VM depends on external signals for suspend and resume.
  // The D-Bus suspend/resume messages from powerd, SuspendImminent and
  // SuspendDone will not be propagated to this VM. Otherwise,
  // HandleSuspendImminent and HandleSuspendDone will be invoked when these
  // messages received.
  virtual bool UsesExternalSuspendSignals() { return false; }

  // Update resolv.conf data.
  virtual bool SetResolvConfig(
      const std::vector<std::string>& nameservers,
      const std::vector<std::string>& search_domains) = 0;

  // Perform necessary cleanup when host network changes.
  virtual void HostNetworkChanged() {}

  // Set the guest time to the current time as given by gettimeofday.
  virtual bool SetTime(std::string* failure_reason) = 0;

  // Get enterprise reporting information. Also sets the
  // response fields for success and failure_reason.
  virtual bool GetVmEnterpriseReportingInfo(
      GetVmEnterpriseReportingInfoResponse* response) = 0;

  // Notes that TremplinStartedSignal has been received for the VM.
  virtual void SetTremplinStarted() = 0;

  // Notes that guest agent is running in the VM.
  virtual void VmToolsStateChanged(bool running) = 0;

  // Initiate a disk resize operation for the VM.
  // |new_size| is the requested size in bytes.
  virtual vm_tools::concierge::DiskImageStatus ResizeDisk(
      uint64_t new_size, std::string* failure_reason) = 0;

  // Get the status of the most recent ResizeDisk operation.
  virtual vm_tools::concierge::DiskImageStatus GetDiskResizeStatus(
      std::string* failure_reason) = 0;

  // Get the smallest valid resize parameter for this disk,
  // or 0 for unknown.
  virtual uint64_t GetMinDiskSize() { return 0; }

  // Get the space that is available/unallocated on the disk,
  // or 0 for unknown.
  virtual uint64_t GetAvailableDiskSpace() { return 0; }

  // Notes that SetVmId() has been called for the VM.
  virtual void VmIdChanged() {}

  // Makes RT vCPU for the VM.
  virtual void MakeRtVcpu() = 0;

 private:
  // Handle the device going to suspend.
  virtual void HandleSuspendImminent() = 0;

  // Handle the device resuming from a suspend.
  virtual void HandleSuspendDone() = 0;

  // Whether the VM is currently suspended.
  bool suspended_ = false;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_VM_INTERFACE_H_
