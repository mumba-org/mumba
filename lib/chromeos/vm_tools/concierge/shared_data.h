// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_SHARED_DATA_H_
#define VM_TOOLS_CONCIERGE_SHARED_DATA_H_

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/system/sys_info.h>

#include "vm_tools/concierge/service.h"

namespace vm_tools {
namespace concierge {

// Maximum number of extra disks to be mounted inside the VM.
constexpr int kMaxExtraDisks = 10;

// Cryptohome root base path.
constexpr char kCryptohomeRoot[] = "/run/daemon-store";

// crosvm directory name.
constexpr char kCrosvmDir[] = "crosvm";

// Plugin VM directory name.
constexpr char kPluginVmDir[] = "pvm";

// Path to the runtime directory used by VMs.
constexpr char kRuntimeDir[] = "/run/vm";

// Only allow hex digits in the cryptohome id.
constexpr char kValidCryptoHomeCharacters[] = "abcdefABCDEF0123456789";

// Gets the path to the file given the name, user id, location, and extension.
std::optional<base::FilePath> GetFilePathFromName(
    const std::string& cryptohome_id,
    const std::string& vm_name,
    StorageLocation storage_location,
    const std::string& extension,
    bool create_parent_dir);

bool GetPluginDirectory(const base::FilePath& prefix,
                        const std::string& extension,
                        const std::string& vm_id,
                        bool create,
                        base::FilePath* path_out);

bool GetPluginIsoDirectory(const std::string& vm_id,
                           const std::string& cryptohome_id,
                           bool create,
                           base::FilePath* path_out);

void SendDbusResponse(dbus::ExportedObject::ResponseSender response_sender,
                      dbus::MethodCall* method_call,
                      const vm_tools::concierge::StartVmResponse& response);

template <class StartXXRequest,
          int64_t (Service::*GetVmMemory)(const StartXXRequest&),
          StartVmResponse (Service::*StartVm)(
              StartXXRequest, std::unique_ptr<dbus::MessageReader>, VmMemoryId)>
void Service::StartVmHelper(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  auto reader = std::make_unique<dbus::MessageReader>(method_call);

  StartXXRequest request;
  StartVmResponse response;
  // We change to a success status later if necessary.
  response.set_status(VM_STATUS_FAILURE);

  if (!reader->PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse StartVmRequest from message";
    response.set_failure_reason("Unable to parse protobuf");
    SendDbusResponse(std::move(response_sender), method_call, response);
    return;
  }

  // Check the CPU count.
  if (request.cpus() > base::SysInfo::NumberOfProcessors()) {
    LOG(ERROR) << "Invalid number of CPUs: " << request.cpus();
    response.set_failure_reason("Invalid CPU count");
    SendDbusResponse(std::move(response_sender), method_call, response);
    return;
  }

  // Make sure the VM has a name.
  if (request.name().empty()) {
    LOG(ERROR) << "Ignoring request with empty name";
    response.set_failure_reason("Missing VM name");
    SendDbusResponse(std::move(response_sender), method_call, response);
    return;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter != vms_.end()) {
    LOG(INFO) << "VM with requested name is already running";

    VmInterface::Info vm = iter->second->GetInfo();

    VmInfo* vm_info = response.mutable_vm_info();
    vm_info->set_ipv4_address(vm.ipv4_address);
    vm_info->set_pid(vm.pid);
    vm_info->set_cid(vm.cid);
    vm_info->set_seneschal_server_handle(vm.seneschal_server_handle);
    vm_info->set_vm_type(vm.type);
    switch (vm.status) {
      case VmInterface::Status::STARTING: {
        response.set_status(VM_STATUS_STARTING);
        break;
      }
      case VmInterface::Status::RUNNING: {
        response.set_status(VM_STATUS_RUNNING);
        break;
      }
      default: {
        response.set_status(VM_STATUS_UNKNOWN);
        break;
      }
    }
    response.set_success(true);

    SendDbusResponse(std::move(response_sender), method_call, response);
    return;
  }

  VmId vm_id(request.owner_id(), request.name());
  auto op_iter = std::find_if(
      disk_image_ops_.begin(), disk_image_ops_.end(), [&vm_id](auto& info) {
        return info.op->vm_id() == vm_id &&
               info.op->status() == DISK_STATUS_IN_PROGRESS;
      });
  if (op_iter != disk_image_ops_.end()) {
    LOG(INFO) << "A disk operation for the VM is in progress";

    response.set_status(VM_STATUS_DISK_OP_IN_PROGRESS);
    response.set_failure_reason("A disk operation for the VM is in progress");
    response.set_success(false);

    SendDbusResponse(std::move(response_sender), method_call, response);
    return;
  }

  if (!USE_CROSVM_SIBLINGS) {
    response = (this->*StartVm)(std::move(request), std::move(reader),
                                next_vm_memory_id_++);
    SendDbusResponse(std::move(response_sender), method_call, response);
    return;
  }

  if (GetVmMemory == nullptr) {
    LOG(ERROR) << "Unable to determine required memory";
    response.set_failure_reason("Memory size unspecified");
    SendDbusResponse(std::move(response_sender), method_call, response);
    return;
  }
  auto resp_ptr = std::make_unique<StartVmResponse>();
  // Setting this to true here allows send_resp to determine if a failure
  // originated in do_launch or somewhere in mms_.
  resp_ptr->set_success(true);

  auto do_launch = [](base::WeakPtr<Service> service, StartXXRequest request,
                      std::unique_ptr<dbus::MessageReader> reader,
                      StartVmResponse* response,
                      VmMemoryId vm_memory_id) -> bool {
    if (!service) {
      LOG(ERROR) << "Service destroyed";
      response->set_failure_reason("Service destroyed");
      response->set_success(false);
    } else {
      *response = (service.get()->*StartVm)(std::move(request),
                                            std::move(reader), vm_memory_id);
    }
    return response->success();
  };
  auto do_stop = [](base::WeakPtr<Service> service, VmId vm_id) {
    LOG(ERROR) << "Stopping VM";
    if (service) {
      // This should only happen if the VM in question dies during
      // startup, in which case the crash handling should clean it
      // up. However, stop it anyway just in case. At worst, this
      // should just result in some extra error logs.
      service->StopVm(vm_id, VM_EXITED);
    }
  };
  auto send_resp = [](dbus::ExportedObject::ResponseSender response_sender,
                      dbus::MethodCall* method_call,
                      std::unique_ptr<StartVmResponse> response, bool success) {
    if (!success) {
      response->clear_vm_info();
      response->set_status(VM_STATUS_FAILURE);
      if (response->success()) {
        response->set_failure_reason("Manatee memory service failure");
        response->set_success(false);
      }
    }
    SendDbusResponse(std::move(response_sender), method_call, *response);
    return;
  };

  // |response_sender| owns the unique_ptr which the raw |method_call| raw ptr
  // refers to, so it is safe to pass objects which reference the raw ptr to
  // other callbacks, since |send_resp_cb| is always invoked last. Also,
  // |launch_cb| is only invoked if |stop_cb| has not yet been invoked, so the
  // raw resp_ptr is safe.
  auto launch_cb =
      base::BindOnce(do_launch, weak_ptr_factory_.GetWeakPtr(),
                     std::move(request), std::move(reader), resp_ptr.get());
  auto stop_cb = base::BindOnce(do_stop, weak_ptr_factory_.GetWeakPtr(), vm_id);
  auto send_resp_cb = base::BindOnce(send_resp, std::move(response_sender),
                                     method_call, std::move(resp_ptr));
  mms_->LaunchVm((this->*GetVmMemory)(request), std::move(launch_cb),
                 std::move(stop_cb), std::move(send_resp_cb));
}

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_SHARED_DATA_H_
