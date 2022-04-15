// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <crosvm/qcow_utils.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>
#include <vm_concierge/proto_bindings/concierge_service.pb.h>
#include <vboot/crossystem.h>

#include "vm_tools/common/naming.h"

using std::string;
using vm_tools::concierge::StorageLocation;

namespace {

constexpr int kDefaultTimeoutMs = 80 * 1000;
// Extra long timeout for backing up a VM disk image.
constexpr int kExportDiskTimeoutMs = 15 * 60 * 1000;

constexpr char kImageTypeQcow2[] = "qcow2";
constexpr char kImageTypeRaw[] = "raw";
constexpr char kImageTypeAuto[] = "auto";
constexpr int64_t kMinimumDiskSize = 1ll * 1024 * 1024 * 1024;  // 1 GiB
constexpr char kRemovableMediaRoot[] = "/media/removable";
constexpr char kStorageCryptohomeRoot[] = "cryptohome-root";
constexpr char kStorageCryptohomePluginVm[] = "cryptohome-pluginvm";

constexpr char kCgroupTermina[] = "termina";
constexpr char kCgroupPluginVm[] = "pluginvm";
constexpr char kCgroupArcVm[] = "arcvm";
constexpr char kCpuForeground[] = "foreground";
constexpr char kCpuBackground[] = "background";

// Cryptohome user base path.
constexpr char kCryptohomeUser[] = "/home/user";

// Downloads directory for a user.
constexpr char kDownloadsDir[] = "Downloads";

// Base address for the plugin VM subnet.
constexpr uint32_t kPluginBaseAddress = 0x64735c80;  // 100.115.92.128

// Mac address to assign to plugin VMs.
constexpr uint8_t kPluginVmMacAddress[] = {0x42, 0x02, 0x1f, 0xf4, 0x2d, 0xb0};

// Path to the ARCVM fstab file.
constexpr char kDefaultArcVmFstab[] = "/run/arcvm/host_generated/fstab";

// Converts an IPv4 address in network byte order into a string.
void IPv4AddressToString(uint32_t addr, string* address) {
  CHECK(address);

  char buf[INET_ADDRSTRLEN];
  struct in_addr in = {
      .s_addr = addr,
  };
  if (inet_ntop(AF_INET, &in, buf, sizeof(buf)) == nullptr) {
    PLOG(WARNING) << "Failed to convert " << addr << " into a string";
    return;
  }

  *address = buf;
}

bool StringToStorageLocation(const string& str, StorageLocation* location) {
  if (str == kStorageCryptohomeRoot) {
    *location = vm_tools::concierge::STORAGE_CRYPTOHOME_ROOT;
  } else if (str == kStorageCryptohomePluginVm) {
    *location = vm_tools::concierge::STORAGE_CRYPTOHOME_PLUGINVM;
  } else {
    return false;
  }
  return true;
}

int LogVmStatus(const string& vm_name,
                const vm_tools::concierge::StartVmResponse& response) {
  int ret = -1;
  std::string status;
  switch (response.status()) {
    case vm_tools::concierge::VM_STATUS_RUNNING:
      status = "Running";
      ret = 0;
      break;
    case vm_tools::concierge::VM_STATUS_STARTING:
      status = "Starting";
      ret = 0;
      break;
    case vm_tools::concierge::VM_STATUS_FAILURE:
      status = "Failure";
      break;
    default:
      status = "Unknown";
      break;
  }

  LOG(INFO) << "Vm state for '" << vm_name << "'"
            << " is now " << status;

  if (ret != 0) {
    LOG(ERROR) << "Failed to start VM: " << response.failure_reason();
    return ret;
  }

  vm_tools::concierge::VmInfo vm_info = response.vm_info();
  string address;
  IPv4AddressToString(vm_info.ipv4_address(), &address);

  LOG(INFO) << "Started " << vm_name << " VM with";
  LOG(INFO) << "    ip address: " << address;
  LOG(INFO) << "    vsock cid:  " << vm_info.cid();
  LOG(INFO) << "    process id: " << vm_info.pid();
  LOG(INFO) << "    seneschal server handle: "
            << vm_info.seneschal_server_handle();

  return ret;
}

static bool ParseExtraDisks(vm_tools::concierge::StartVmRequest* request,
                            string extra_disks) {
  for (base::StringPiece disk :
       base::SplitStringPiece(extra_disks, ":", base::TRIM_WHITESPACE,
                              base::SPLIT_WANT_NONEMPTY)) {
    std::vector<base::StringPiece> tokens = base::SplitStringPiece(
        disk, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);

    // disk path[,writable[,mount target,fstype[,flags[,data]]]]
    if (tokens.empty()) {
      LOG(ERROR) << "Disk description is empty";
      return false;
    }

    vm_tools::concierge::DiskImage* disk_image = request->add_disks();
    disk_image->set_path(tokens[0].data(), tokens[0].size());
    disk_image->set_do_mount(false);

    if (tokens.size() > 1) {
      int writable = 0;
      if (!base::StringToInt(tokens[1], &writable)) {
        LOG(ERROR) << "Unable to parse writable token: " << tokens[1];
        return false;
      }

      disk_image->set_writable(writable != 0);
    }

    if (tokens.size() > 2) {
      if (tokens.size() == 3) {
        LOG(ERROR) << "Missing fstype for " << disk;
        return false;
      }
      disk_image->set_mount_point(tokens[2].data(), tokens[2].size());
      disk_image->set_fstype(tokens[3].data(), tokens[3].size());
      disk_image->set_do_mount(true);
    }

    if (tokens.size() > 4) {
      uint64_t flags;
      if (!base::HexStringToUInt64(tokens[4], &flags)) {
        LOG(ERROR) << "Unable to parse flags: " << tokens[5];
        return false;
      }

      disk_image->set_flags(flags);
    }

    if (tokens.size() > 5) {
      // Unsplit the rest of the string since data is comma-separated.
      disk_image->set_data(base::JoinString(
          base::make_span(tokens.begin() + 5, tokens.end()), ","));
    }

    if (!base::PathExists(base::FilePath(disk_image->path()))) {
      LOG(ERROR) << "Extra disk path does not exist: " << disk_image->path();
      return false;
    }

    char flag_buf[20];
    snprintf(flag_buf, sizeof(flag_buf), "0x%" PRIx64, disk_image->flags());

    LOG(INFO) << "Disk " << disk_image->path();
    LOG(INFO) << "    mnt point: " << disk_image->mount_point();
    LOG(INFO) << "    type:      " << disk_image->fstype();
    LOG(INFO) << "    flags:     " << flag_buf;
    LOG(INFO) << "    data:      " << disk_image->data();
    LOG(INFO) << "    writable:  " << disk_image->writable();
    LOG(INFO) << "    do_mount:  " << disk_image->do_mount();
  }

  return true;
}

bool IsDevModeEnabled() {
  return VbGetSystemPropertyInt("cros_debug") == 1;
}

int StartVm(dbus::ObjectProxy* proxy,
            string owner_id,
            string name,
            string kernel,
            string initrd,
            string rootfs,
            string extra_disks,
            bool untrusted,
            bool writable_rootfs) {
  if (name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  if (kernel.empty()) {
    LOG(ERROR) << "--kernel is required";
    return -1;
  }

  if (rootfs.empty()) {
    LOG(ERROR) << "--rootfs is required";
    return -1;
  }

  if (!base::PathExists(base::FilePath(kernel))) {
    LOG(ERROR) << kernel << " does not exist";
    return -1;
  }

  if (!initrd.empty()) {
    if (!base::PathExists(base::FilePath(initrd))) {
      LOG(ERROR) << initrd << " does not exist";
      return -1;
    }
  }

  if (!base::PathExists(base::FilePath(rootfs))) {
    LOG(ERROR) << rootfs << " does not exist";
    return -1;
  }

  if (untrusted && !IsDevModeEnabled()) {
    LOG(ERROR) << "Untrusted VMs are only allowed in developer mode";
    return -1;
  }

  if (initrd.empty()) {
    LOG(INFO) << "Starting VM " << name << " with kernel " << kernel
              << " and rootfs " << rootfs;
  } else {
    LOG(INFO) << "Starting VM " << name << " with kernel " << kernel
              << ", initrd " << initrd << " and rootfs " << rootfs;
  }

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kStartVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::StartVmRequest request;
  request.set_owner_id(std::move(owner_id));
  request.set_name(std::move(name));

  request.mutable_vm()->set_kernel(std::move(kernel));
  request.mutable_vm()->set_initrd(std::move(initrd));
  request.mutable_vm()->set_rootfs(std::move(rootfs));

  if (!ParseExtraDisks(&request, extra_disks)) {
    return -1;
  }

  request.set_run_as_untrusted(untrusted);
  request.set_writable_rootfs(writable_rootfs);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StartVmRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::StartVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  return LogVmStatus(request.name(), response);
}

int StopVm(dbus::ObjectProxy* proxy, string owner_id, string name) {
  if (name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  LOG(INFO) << "Stopping VM " << name;

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kStopVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::StopVmRequest request;
  request.set_owner_id(std::move(owner_id));
  request.set_name(std::move(name));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StopVmRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::StopVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to stop VM: " << response.failure_reason();
    return -1;
  }

  LOG(INFO) << "Done";
  return 0;
}

int StopAllVms(dbus::ObjectProxy* proxy) {
  LOG(INFO) << "Stopping all VMs";

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kStopAllVmsMethod);

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  LOG(INFO) << "Done";
  return 0;
}

std::optional<vm_tools::concierge::VmInfo> GetVmInfoInternal(
    dbus::ObjectProxy* proxy, string owner_id, string name) {
  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kGetVmInfoMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::GetVmInfoRequest request;
  request.set_owner_id(std::move(owner_id));
  request.set_name(std::move(name));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode GetVmInfo protobuf";
    return std::nullopt;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return std::nullopt;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::GetVmInfoResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return std::nullopt;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to get VM info";
    return std::nullopt;
  }

  return std::make_optional(response.vm_info());
}

int SuspendVm(dbus::ObjectProxy* proxy, string owner_id, string name) {
  if (name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  LOG(INFO) << "Suspending VM " << name;

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kSuspendVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::SuspendVmRequest request;
  request.set_owner_id(std::move(owner_id));
  request.set_name(std::move(name));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode SuspendVmRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::SuspendVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to suspend VM: " << response.failure_reason();
    return -1;
  }

  LOG(INFO) << "Done";
  return 0;
}

int ResumeVm(dbus::ObjectProxy* proxy, string owner_id, string name) {
  if (name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  LOG(INFO) << "Resuming VM " << name;

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kResumeVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::ResumeVmRequest request;
  request.set_owner_id(std::move(owner_id));
  request.set_name(std::move(name));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ResumeVmRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::ResumeVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to resume VM: " << response.failure_reason();
    return -1;
  }

  LOG(INFO) << "Done";
  return 0;
}

int GetVmInfo(dbus::ObjectProxy* proxy, string owner_id, string name) {
  LOG(INFO) << "Getting VM info";

  auto vm_info = GetVmInfoInternal(proxy, owner_id, name);
  if (!vm_info.has_value())
    return -1;
  string address;
  IPv4AddressToString(vm_info->ipv4_address(), &address);

  LOG(INFO) << "VM:                      " << name;
  LOG(INFO) << "IPv4 address:            " << address;
  LOG(INFO) << "pid:                     " << vm_info->pid();
  LOG(INFO) << "vsock cid:               " << vm_info->cid();
  LOG(INFO) << "seneschal server handle: "
            << vm_info->seneschal_server_handle();
  LOG(INFO) << "Done";
  return 0;
}

int GetVmCid(dbus::ObjectProxy* proxy, string owner_id, string name) {
  auto vm_info = GetVmInfoInternal(proxy, owner_id, name);
  if (!vm_info.has_value())
    return -1;
  const std::string cid = base::StringPrintf("%" PRId64 "\n", vm_info->cid());
  return base::WriteFileDescriptor(STDOUT_FILENO, cid) ? 0 : -1;
}

int CreateDiskImage(dbus::ObjectProxy* proxy,
                    string cryptohome_id,
                    string vm_name,
                    uint64_t disk_size,
                    string image_type,
                    StorageLocation storage_location,
                    string source_name,
                    const std::vector<string>& params,
                    string* result_path) {
  if (cryptohome_id.empty()) {
    LOG(ERROR) << "Cryptohome id cannot be empty";
    return -1;
  } else if (vm_name.empty()) {
    LOG(ERROR) << "VM name cannot be empty";
    return -1;
  }

  LOG(INFO) << "Creating disk image";

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kCreateDiskImageMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::CreateDiskImageRequest request;

  base::ScopedFD source_fd;
  if (!source_name.empty()) {
    base::FilePath source_path = base::FilePath(kCryptohomeUser)
                                     .Append(cryptohome_id)
                                     .Append(kDownloadsDir)
                                     .Append(source_name);
    if (!base::PathExists(source_path)) {
      LOG(ERROR) << "Source media does not exist";
      return -1;
    }

    source_fd.reset(HANDLE_EINTR(open(source_path.value().c_str(), O_RDONLY)));
    if (!source_fd.is_valid()) {
      LOG(ERROR) << "Failed opening source media "
                 << source_path.MaybeAsASCII();
      return -1;
    }

    struct stat st;
    if (fstat(source_fd.get(), &st) == 0) {
      // stat's block size is always 512 bytes.
      request.set_source_size(st.st_blocks * 512);
    }
  }

  request.set_cryptohome_id(std::move(cryptohome_id));
  request.set_vm_name(std::move(vm_name));
  request.set_disk_size(std::move(disk_size));

  if (image_type == kImageTypeRaw) {
    request.set_image_type(vm_tools::concierge::DISK_IMAGE_RAW);
  } else if (image_type == kImageTypeQcow2) {
    request.set_image_type(vm_tools::concierge::DISK_IMAGE_QCOW2);
  } else if (image_type == kImageTypeAuto) {
    request.set_image_type(vm_tools::concierge::DISK_IMAGE_AUTO);
  } else {
    LOG(ERROR) << "'" << image_type << "' is not a valid disk image type";
    return -1;
  }

  request.set_storage_location(storage_location);

  for (const string& param : params) {
    request.add_params(param);
  }

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode CreateDiskImageRequest protobuf";
    return -1;
  }

  if (source_fd.is_valid()) {
    writer.AppendFileDescriptor(source_fd.get());
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::CreateDiskImageResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  switch (response.status()) {
    case vm_tools::concierge::DISK_STATUS_EXISTS:
      LOG(INFO) << "Disk image already exists: " << response.disk_path();
      break;
    case vm_tools::concierge::DISK_STATUS_CREATED:
      LOG(INFO) << "Disk image created: " << response.disk_path();
      break;
    case vm_tools::concierge::DISK_STATUS_IN_PROGRESS:
      LOG(INFO) << "Disk image being created: " << response.disk_path() << " ("
                << response.command_uuid() << ")";
      break;
    default:
      LOG(ERROR) << "Failed to create disk image: "
                 << response.failure_reason();
      return -1;
  }

  if (result_path)
    *result_path = response.disk_path();

  return 0;
}

int DestroyDiskImage(dbus::ObjectProxy* proxy,
                     string cryptohome_id,
                     string name) {
  if (cryptohome_id.empty()) {
    LOG(ERROR) << "Cryptohome id cannot be empty";
    return -1;
  } else if (name.empty()) {
    LOG(ERROR) << "Name cannot be empty";
    return -1;
  }

  LOG(INFO) << "Destroying disk image";

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kDestroyDiskImageMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::DestroyDiskImageRequest request;
  request.set_cryptohome_id(std::move(cryptohome_id));
  request.set_vm_name(std::move(name));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode DestroyDiskImageRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::DestroyDiskImageResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (response.status() != vm_tools::concierge::DISK_STATUS_DESTROYED &&
      response.status() != vm_tools::concierge::DISK_STATUS_DOES_NOT_EXIST) {
    LOG(ERROR) << "Failed to destroy disk image: " << response.failure_reason();
    return -1;
  }

  return 0;
}

int ExportDiskImage(dbus::ObjectProxy* proxy,
                    string cryptohome_id,
                    string vm_name,
                    string export_name,
                    string removable_media) {
  if (cryptohome_id.empty()) {
    LOG(ERROR) << "Cryptohome id cannot be empty";
    return -1;
  }
  if (vm_name.empty()) {
    LOG(ERROR) << "Name cannot be empty";
    return -1;
  }
  if (export_name.empty()) {
    LOG(ERROR) << "Export name cannot be empty";
    return -1;
  }

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kExportDiskImageMethod);
  dbus::MessageWriter writer(&method_call);

  base::FilePath export_disk_path;
  if (!removable_media.empty()) {
    export_disk_path = base::FilePath(kRemovableMediaRoot)
                           .Append(removable_media)
                           .Append(export_name);
  } else {
    export_disk_path = base::FilePath(kCryptohomeUser)
                           .Append(cryptohome_id)
                           .Append(kDownloadsDir)
                           .Append(export_name);
  }
  if (export_disk_path.ReferencesParent()) {
    LOG(ERROR) << "Invalid export image path";
    return -1;
  }
  if (base::PathExists(export_disk_path)) {
    LOG(ERROR) << "Export disk image already exists, refusing to overwrite it.";
    return -1;
  }

  base::ScopedFD disk_fd(HANDLE_EINTR(open(
      export_disk_path.value().c_str(), O_CREAT | O_RDWR | O_NOFOLLOW, 0600)));
  if (!disk_fd.is_valid()) {
    LOG(ERROR) << "Failed opening export file "
               << export_disk_path.MaybeAsASCII();
    return -1;
  }

  vm_tools::concierge::ExportDiskImageRequest request;
  request.set_cryptohome_id(std::move(cryptohome_id));
  request.set_vm_name(std::move(vm_name));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ExportDiskImageRequest protobuf";
    return -1;
  }
  writer.AppendFileDescriptor(disk_fd.get());

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kExportDiskTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::ExportDiskImageResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  switch (response.status()) {
    case vm_tools::concierge::DISK_STATUS_CREATED:
      break;

    case vm_tools::concierge::DISK_STATUS_IN_PROGRESS:
      LOG(INFO) << "Exporting disk image to "
                << export_disk_path.MaybeAsASCII();
      break;

    default:
      LOG(ERROR) << "Failed to import disk image: "
                 << response.failure_reason();
      return -1;
  }

  return 0;
}

int ImportDiskImage(dbus::ObjectProxy* proxy,
                    string cryptohome_id,
                    string vm_name,
                    string import_name,
                    StorageLocation storage_location,
                    string removable_media) {
  if (cryptohome_id.empty()) {
    LOG(ERROR) << "Cryptohome id cannot be empty";
    return -1;
  }
  if (vm_name.empty()) {
    LOG(ERROR) << "Name cannot be empty";
    return -1;
  }
  if (import_name.empty()) {
    LOG(ERROR) << "Import name cannot be empty";
    return -1;
  }

  base::FilePath import_disk_path;
  if (!removable_media.empty()) {
    import_disk_path = base::FilePath(kRemovableMediaRoot)
                           .Append(removable_media)
                           .Append(import_name);
  } else {
    import_disk_path = base::FilePath(kCryptohomeUser)
                           .Append(cryptohome_id)
                           .Append(kDownloadsDir)
                           .Append(import_name);
  }
  if (import_disk_path.ReferencesParent()) {
    LOG(ERROR) << "Invalid removable_vm_path";
    return -1;
  }
  if (!base::PathExists(import_disk_path)) {
    LOG(ERROR) << "Import disk image does not exist.";
    return -1;
  }

  base::ScopedFD disk_fd(
      HANDLE_EINTR(open(import_disk_path.value().c_str(), O_RDONLY)));
  if (!disk_fd.is_valid()) {
    LOG(ERROR) << "Failed opening import file "
               << import_disk_path.MaybeAsASCII();
    return -1;
  }

  vm_tools::concierge::ImportDiskImageRequest request;
  request.set_cryptohome_id(std::move(cryptohome_id));
  request.set_vm_name(std::move(vm_name));
  request.set_storage_location(storage_location);

  struct stat st;
  if (fstat(disk_fd.get(), &st) == 0) {
    // stat's block size is always 512 bytes.
    request.set_source_size(st.st_blocks * 512);
  }

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kImportDiskImageMethod);
  dbus::MessageWriter writer(&method_call);
  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ImportDiskImageRequest protobuf";
    return -1;
  }
  writer.AppendFileDescriptor(disk_fd.get());

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::ImportDiskImageResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  switch (response.status()) {
    case vm_tools::concierge::DISK_STATUS_CREATED:
      break;

    case vm_tools::concierge::DISK_STATUS_IN_PROGRESS:
      LOG(INFO) << "Importing disk image from "
                << import_disk_path.MaybeAsASCII();
      break;

    default:
      LOG(ERROR) << "Failed to import disk image: "
                 << response.failure_reason();
      return -1;
  }

  return 0;
}

int ListDiskImages(dbus::ObjectProxy* proxy,
                   string cryptohome_id,
                   StorageLocation storage_location) {
  if (cryptohome_id.empty()) {
    LOG(ERROR) << "Cryptohome id cannot be empty";
    return -1;
  }

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kListVmDisksMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::ListVmDisksRequest request;
  request.set_cryptohome_id(std::move(cryptohome_id));
  request.set_storage_location(storage_location);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ListVmDisksRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::ListVmDisksResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed list VM disks: " << response.failure_reason();
    return -1;
  }

  for (const auto& image : response.images()) {
    std::cout << "Name: " << image.name() << " Size: " << image.size()
              << std::endl;
  }
  std::cout << "Total Size (bytes): " << response.total_size() << std::endl;
  return 0;
}

int CreateExternalDiskImage(string removable_media,
                            string name,
                            uint64_t disk_size) {
  if (disk_size < kMinimumDiskSize) {
    LOG(ERROR) << "Disk size must be greater than one megabyte";
    return -1;
  }
  if (removable_media.empty() || name.empty()) {
    LOG(ERROR) << "Both --removable_media and --name are required.";
    return -1;
  }

  base::FilePath media_path =
      base::FilePath(kRemovableMediaRoot).Append(removable_media);
  base::FilePath disk_path = media_path.Append(name);

  if (disk_path.ReferencesParent() || !base::DirectoryExists(media_path)) {
    LOG(ERROR) << "Invalid Removable Media path";
    return -1;
  }

  return create_qcow_with_size(disk_path.value().c_str(), disk_size);
}

int StartTerminaVm(dbus::ObjectProxy* proxy,
                   string name,
                   string cryptohome_id,
                   string removable_media,
                   string image_name,
                   string image_type,
                   string extra_disks) {
  if (name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  LOG(INFO) << "Starting Termina VM '" << name << "'";

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kStartVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::StartVmRequest request;
  request.set_start_termina(true);

  if (!cryptohome_id.empty()) {
    uint64_t disk_size = 0;  // Let concierge choose the disk size.

    string disk_path;
    if (CreateDiskImage(proxy, cryptohome_id, name, disk_size, image_type,
                        vm_tools::concierge::STORAGE_CRYPTOHOME_ROOT, "", {},
                        &disk_path) != 0) {
      return -1;
    }

    vm_tools::concierge::DiskImage* disk_image = request.add_disks();
    disk_image->set_path(std::move(disk_path));
    disk_image->set_writable(true);
    disk_image->set_do_mount(false);

    request.set_owner_id(std::move(cryptohome_id));
    request.set_name(std::move(name));
    if (!ParseExtraDisks(&request, extra_disks)) {
      return -1;
    }

    if (!writer.AppendProtoAsArrayOfBytes(request)) {
      LOG(ERROR) << "Failed to encode StartVmRequest protobuf";
      return -1;
    }
  } else if (!removable_media.empty()) {
    if (image_name.empty()) {
      LOG(ERROR) << "start: --image_name is required with --removable_media";
      return -1;
    }
    base::FilePath disk_path = base::FilePath(kRemovableMediaRoot)
                                   .Append(removable_media)
                                   .Append(image_name);
    if (disk_path.ReferencesParent()) {
      LOG(ERROR) << "Invalid removable_vm_path";
      return -1;
    }
    base::ScopedFD disk_fd(
        HANDLE_EINTR(open(disk_path.value().c_str(), O_RDWR | O_NOFOLLOW)));
    if (!disk_fd.is_valid()) {
      LOG(ERROR) << "Failed opening VM disk state";
      return -1;
    }

    request.set_name(std::move(name));
    request.mutable_fds()->Add(
        vm_tools::concierge::StartVmRequest_FdType_STORAGE);
    if (!ParseExtraDisks(&request, extra_disks)) {
      return -1;
    }

    if (!writer.AppendProtoAsArrayOfBytes(request)) {
      LOG(ERROR) << "Failed to encode StartVmRequest protobuf";
      return -1;
    }
    writer.AppendFileDescriptor(disk_fd.get());
  } else {
    LOG(ERROR) << "either --removable_vm_path or --cryptohome_id is required";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::StartVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  return LogVmStatus(request.name(), response);
}

int StartPluginVm(dbus::ObjectProxy* proxy,
                  string name,
                  const std::vector<string>& params,
                  string cryptohome_id) {
  if (name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  LOG(INFO) << "Starting plugin VM '" << name << "'";

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kStartPluginVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::StartPluginVmRequest request;
  request.set_name(std::move(name));
  request.set_owner_id(std::move(cryptohome_id));
  request.set_cpus(base::SysInfo::NumberOfProcessors());

  // Add 2 to the base address because the network id cannot be used and the
  // first address is the gateway.
  request.set_guest_ipv4_address(htonl(kPluginBaseAddress + 2));
  request.set_host_mac_address(
      reinterpret_cast<const char*>(kPluginVmMacAddress),
      sizeof(kPluginVmMacAddress));

  for (const string& param : params) {
    request.add_params(param);
  }

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StartVmRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::StartVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  return LogVmStatus(request.name(), response);
}

int StartArcVm(dbus::ObjectProxy* proxy,
               string cryptohome_id,
               string name,
               string kernel,
               string rootfs,
               string fstab,
               string extra_disks,
               const std::vector<string>& params) {
  constexpr char arcvm_prefix[] = "/opt/google/vms/android";

  if (cryptohome_id.empty()) {
    LOG(ERROR) << "--cryptohome_id is required";
    return -1;
  }

  if (name.empty()) {
    name = "arcvm";
    LOG(INFO) << "using default name " << name;
  }

  if (kernel.empty()) {
    kernel = base::StringPrintf("%s/vmlinux", arcvm_prefix);
    LOG(INFO) << "using default kernel " << kernel;
  }

  if (rootfs.empty()) {
    rootfs = base::StringPrintf("%s/system.raw.img", arcvm_prefix);
    LOG(INFO) << "using default rootfs " << rootfs;
  }

  if (fstab.empty()) {
    fstab = kDefaultArcVmFstab;
    if (base::PathExists(base::FilePath(fstab))) {
      LOG(INFO) << "using default fstab " << fstab;
    } else {
      LOG(ERROR) << fstab << " does not exist";
      return -1;
    }
  }

  if (extra_disks.empty()) {
    std::string disk_name = vm_tools::GetEncodedName(name);
    extra_disks = base::StringPrintf(
        "/home/root/%s/crosvm/%s.img,1:%s/vendor.raw.img,0",
        cryptohome_id.c_str(), disk_name.c_str(), arcvm_prefix);
    LOG(INFO) << "using default extra_disks " << extra_disks;
  }

  if (!base::PathExists(base::FilePath(kernel))) {
    LOG(ERROR) << kernel << " does not exist";
    return -1;
  }

  if (!base::PathExists(base::FilePath(rootfs))) {
    LOG(ERROR) << rootfs << " does not exist";
    return -1;
  }

  LOG(INFO) << "Starting ARCVM " << name << " with kernel " << kernel
            << " and rootfs " << rootfs;

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kStartArcVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::StartArcVmRequest request;
  request.set_owner_id(std::move(cryptohome_id));
  request.set_name(std::move(name));
  request.set_fstab(std::move(fstab));
  request.set_cpus(base::SysInfo::NumberOfProcessors());

  request.mutable_vm()->set_kernel(std::move(kernel));
  request.mutable_vm()->set_rootfs(std::move(rootfs));

  {
    vm_tools::concierge::StartVmRequest vm_request;
    if (!ParseExtraDisks(&vm_request, extra_disks)) {
      return -1;
    }
    for (const auto& disk : vm_request.disks()) {
      *request.add_disks() = disk;
    }
  }

  for (const string& param : params) {
    request.add_params(param);
  }

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StartVmRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::StartVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  return LogVmStatus(request.name(), response);
}

int SyncVmTimes(dbus::ObjectProxy* proxy) {
  LOG(INFO) << "Setting VM times";

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kSyncVmTimesMethod);

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::SyncVmTimesResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }
  LOG(INFO) << "Sent " << response.requests() << " set time requests with "
            << response.failures() << " failures.";
  if (response.failure_reason_size() != 0) {
    LOG(INFO) << "Failure info: ";
    for (const string& msg : response.failure_reason()) {
      LOG(INFO) << msg;
    }
  }
  // 0 if all succeeded else -(# of failures).
  return -response.failures();
}

int AttachUsbDevice(dbus::ObjectProxy* proxy,
                    string vm_name,
                    string owner_id,
                    int32_t bus_number,
                    int32_t port_number,
                    int32_t vendor_id,
                    int32_t product_id) {
  if (vm_name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  std::string path =
      base::StringPrintf("/dev/bus/usb/%03d/%03d", bus_number, port_number);
  base::ScopedFD fd(HANDLE_EINTR(open(path.c_str(), O_RDWR | O_CLOEXEC)));
  if (!fd.is_valid()) {
    LOG(ERROR) << "Failed to open USB device file, are you root?";
    return -1;
  }

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kAttachUsbDeviceMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::AttachUsbDeviceRequest request;
  request.set_vm_name(vm_name);
  request.set_owner_id(owner_id);
  request.set_bus_number(bus_number);
  request.set_port_number(port_number);
  request.set_vendor_id(vendor_id);
  request.set_product_id(product_id);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode AttachUsbDeviceRequest protobuf";
    return -1;
  }

  writer.AppendFileDescriptor(fd.get());

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::AttachUsbDeviceResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "AttachUsbDeviceRequest failed: " << response.reason();
    return -1;
  } else {
    LOG(INFO) << "USB device attached to guest port " << response.guest_port();
    return 0;
  }
}

int DetachUsbDevice(dbus::ObjectProxy* proxy,
                    string vm_name,
                    string owner_id,
                    int32_t guest_port) {
  if (vm_name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kDetachUsbDeviceMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::DetachUsbDeviceRequest request;
  request.set_vm_name(vm_name);
  request.set_owner_id(owner_id);
  request.set_guest_port(guest_port);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode DetachUsbDeviceRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::DetachUsbDeviceResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "DetachUsbDeviceRequest failed: " << response.reason();
    return -1;
  } else {
    LOG(INFO) << "USB device detached from guest";
    return 0;
  }
}

int ListUsbDevices(dbus::ObjectProxy* proxy, string vm_name, string owner_id) {
  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kListUsbDeviceMethod);
  if (vm_name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::ListUsbDeviceRequest request;
  request.set_vm_name(vm_name);
  request.set_owner_id(owner_id);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ListUsbDeviceRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::ListUsbDeviceResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to list USB devices";
    return -1;
  } else {
    LOG(INFO) << "Guest Port\tVendor ID\tProduct ID\tDevice Name";
    for (int i = 0; i < response.usb_devices_size(); i++) {
      auto& usb_device = response.usb_devices(i);
      LOG(INFO) << usb_device.guest_port() << "\t" << usb_device.vendor_id()
                << "\t" << usb_device.product_id() << "\t"
                << usb_device.device_name();
    }
    return 0;
  }
}

int GetEnterpriseReportingInfo(dbus::ObjectProxy* proxy,
                               string vm_name,
                               string owner_id) {
  if (vm_name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  if (owner_id.empty()) {
    LOG(ERROR) << "--cryptohome_id is required";
    return -1;
  }

  LOG(INFO) << "Get VM enterprise reporting info.";
  dbus::MethodCall method_call(
      vm_tools::concierge::kVmConciergeInterface,
      vm_tools::concierge::kGetVmEnterpriseReportingInfoMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::GetVmEnterpriseReportingInfoRequest request;
  request.set_vm_name(vm_name);
  request.set_owner_id(owner_id);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode GetEnterpriseReportingInfo protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::GetVmEnterpriseReportingInfoResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "Could not retrieve kernel version: "
               << response.failure_reason();
    return -1;
  }

  LOG(INFO) << "Kernel version: " << response.vm_kernel_version();
  return 0;
}

int SetVmCpuRestriction(dbus::ObjectProxy* proxy,
                        std::string cgroup,
                        std::string restriction) {
  if (cgroup.empty()) {
    LOG(ERROR) << "--cgroup is required";
    return -1;
  }
  if (restriction.empty()) {
    LOG(ERROR) << "--restriction is required";
    return -1;
  }

  LOG(INFO) << "Set VM CPU restriction.";
  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kSetVmCpuRestrictionMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::SetVmCpuRestrictionRequest request;

  if (cgroup == kCgroupTermina) {
    request.set_cpu_cgroup(vm_tools::concierge::CPU_CGROUP_TERMINA);
  } else if (cgroup == kCgroupPluginVm) {
    request.set_cpu_cgroup(vm_tools::concierge::CPU_CGROUP_PLUGINVM);
  } else if (cgroup == kCgroupArcVm) {
    request.set_cpu_cgroup(vm_tools::concierge::CPU_CGROUP_ARCVM);
  } else {
    LOG(ERROR) << "Unknown cgroup. Specify " << kCgroupTermina << ", "
               << kCgroupPluginVm << ", or " << kCgroupArcVm;
    return -1;
  }

  if (restriction == kCpuForeground) {
    request.set_cpu_restriction_state(
        vm_tools::concierge::CPU_RESTRICTION_FOREGROUND);
  } else if (restriction == kCpuBackground) {
    request.set_cpu_restriction_state(
        vm_tools::concierge::CPU_RESTRICTION_BACKGROUND);
  } else {
    LOG(ERROR) << "Unknown restriction. Specify " << kCpuForeground << " or "
               << kCpuBackground;
    return -1;
  }

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode SetVmCpuRestrictionRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::SetVmCpuRestrictionResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "Could not set VM CPU restriction";
    return -1;
  }

  LOG(INFO) << "Successfully set VM CPU restriction";
  return 0;
}

int ReclaimVmMemory(dbus::ObjectProxy* proxy, string vm_name, string owner_id) {
  if (vm_name.empty()) {
    LOG(ERROR) << "--name is required";
    return -1;
  }

  if (owner_id.empty()) {
    LOG(ERROR) << "--cryptohome_id is required";
    return -1;
  }

  LOG(INFO) << "Reclaim VM memory.";
  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kReclaimVmMemoryMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::ReclaimVmMemoryRequest request;
  request.set_name(vm_name);
  request.set_owner_id(owner_id);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ReclaimVmMemoryRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::ReclaimVmMemoryResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "Could not reclaim VM memory: " << response.failure_reason();
    return -1;
  }

  LOG(INFO) << "Successfully reclaimed VM memory.";
  return 0;
}

int ArcVmCompleteBoot(dbus::ObjectProxy* proxy, string owner_id) {
  if (owner_id.empty()) {
    LOG(ERROR) << "--cryptohome_id is required";
    return -1;
  }

  LOG(INFO) << "ARCVM Complete boot.";
  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kArcVmCompleteBootMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::ArcVmCompleteBootRequest request;
  request.set_owner_id(owner_id);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ArcVmCompleteBootRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::ArcVmCompleteBootResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (response.result() !=
      vm_tools::concierge::ArcVmCompleteBootResult::SUCCESS) {
    LOG(ERROR) << "Could not complete ARCVM boot, ArcVmCompleteBootResult: "
               << response.result();
    return -1;
  }

  LOG(INFO) << "Successfully completed ARCVM boot.";
  return 0;
}

int ListVms(dbus::ObjectProxy* proxy, string owner_id) {
  if (owner_id.empty()) {
    LOG(ERROR) << "--cryptohome_id is required";
    return -1;
  }

  LOG(INFO) << "List VMs.";
  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kListVmsMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::ListVmsRequest request;
  request.set_owner_id(owner_id);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ListVmsRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::ListVmsResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  for (const auto& vm : response.vms()) {
    const auto& vm_info = vm.vm_info();
    string address;
    IPv4AddressToString(vm_info.ipv4_address(), &address);

    std::cout << std::endl
              << "VM:                        " << vm.name() << std::endl
              << "  owner_id:                " << vm.owner_id() << std::endl
              << "  IPv4 address:            " << address << std::endl
              << "  pid:                     " << vm_info.pid() << std::endl
              << "  vsock cid:               " << vm_info.cid() << std::endl
              << "  seneschal server handle: "
              << vm_info.seneschal_server_handle() << std::endl
              << "  permission_token:        " << vm_info.permission_token()
              << std::endl
              << "  type:                    "
              << vm_tools::concierge::VmInfo_VmType_Name(vm_info.vm_type())
              << std::endl
              << "  status:                  "
              << vm_tools::concierge::VmStatus_Name(vm.status()) << std::endl;
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit;

  // Operations.
  DEFINE_bool(start, false, "Start a VM");
  DEFINE_bool(stop, false, "Stop a running VM");
  DEFINE_bool(stop_all, false, "Stop all running VMs");
  DEFINE_bool(suspend, false, "Suspend a running VM");
  DEFINE_bool(resume, false, "Resume a running VM");
  DEFINE_bool(get_vm_info, false, "Get info for the given VM");
  DEFINE_bool(get_vm_cid, false, "Get vsock cid for the given VM");
  DEFINE_bool(create_disk, false, "Create a disk image");
  DEFINE_bool(create_external_disk, false,
              "Create a disk image on removable media");
  DEFINE_bool(destroy_disk, false, "Destroy a disk image");
  DEFINE_bool(export_disk, false, "Export a disk image from a VM");
  DEFINE_bool(import_disk, false, "Import a disk image for a VM");
  DEFINE_bool(list_disks, false, "List disk images");
  DEFINE_bool(start_termina_vm, false,
              "Start a termina VM with a default config");
  DEFINE_bool(start_plugin_vm, false, "Start a plugin VM");
  DEFINE_bool(start_arc_vm, false, "Start an ARCVM");
  DEFINE_bool(launch_application, false,
              "Launches an application in a container");
  DEFINE_bool(get_icon, false, "Get an app icon from a container within a VM");
  DEFINE_bool(sync_time, false, "Update VM times");
  DEFINE_bool(attach_usb, false, "Attach a USB device to a VM");
  DEFINE_bool(detach_usb, false, "Detach a USB device from a VM");
  DEFINE_bool(list_usb_devices, false, "List all USB devices attached to a VM");
  DEFINE_bool(get_vm_enterprise_reporting_info, false,
              "Enterprise reporting info for the given VM");
  DEFINE_bool(set_vm_cpu_restriction, false, "Set VM CPU restriction");
  DEFINE_bool(reclaim_vm_memory, false, "Reclaim VM memory");
  DEFINE_bool(list_vms, false, "List VMs");
  DEFINE_bool(arcvm_complete_boot, false, "Complete ARCVM Boot");

  // Parameters.
  DEFINE_string(kernel, "", "Path to the VM kernel");
  DEFINE_string(initrd, "", "Path to the VM initrd");
  DEFINE_string(rootfs, "", "Path to the VM rootfs");
  DEFINE_string(name, "", "Name to assign to the VM");
  DEFINE_string(export_name, "", "Name to give the exported disk image");
  DEFINE_string(import_name, "", "Name of the VM image to import");
  DEFINE_string(extra_disks, "",
                "Additional disk images to be mounted inside the VM");
  DEFINE_string(container_name, "", "Name of the container within the VM");
  DEFINE_string(removable_media, "", "Name of the removable media to use");
  DEFINE_string(image_name, "", "Name of the file on removable media to use");
  DEFINE_string(android_fstab, "", "Path to the Android fstab");
  DEFINE_bool(untrusted, false,
              "Allow untrusted VM. Only respected in developer mode");
  DEFINE_bool(writable_rootfs, true, "Make the rootfs writable");

  // create_disk parameters.
  DEFINE_string(cryptohome_id, "", "User cryptohome id");
  DEFINE_uint64(disk_size, 0, "Size of the disk image to create");
  DEFINE_string(image_type, "auto", "Disk image type");
  DEFINE_string(storage_location, "cryptohome-root",
                "Location to store the disk image");
  DEFINE_string(source_name, "",
                "Name of source media associated with the new VM image");

  // USB parameters.
  DEFINE_int32(bus_number, -1, "USB bus number");
  DEFINE_int32(port_number, -1, "USB port number");
  DEFINE_int32(vendor_id, -1, "USB vendor ID");
  DEFINE_int32(product_id, -1, "USB product ID");
  DEFINE_int32(guest_port, -1, "Guest USB port allocated to device");

  // set_vm_cpu_restriction parameters
  DEFINE_string(cgroup, "", "Cgroup to update");
  DEFINE_string(restriction, "", "The CPU restriction to apply");

  brillo::FlagHelper::Init(argc, argv, "vm_concierge client tool");
  brillo::InitLog(brillo::kLogToStderrIfTty);

  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(std::move(opts)));

  if (!bus->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
    return -1;
  }

  dbus::ObjectProxy* proxy = bus->GetObjectProxy(
      vm_tools::concierge::kVmConciergeServiceName,
      dbus::ObjectPath(vm_tools::concierge::kVmConciergeServicePath));
  if (!proxy) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::concierge::kVmConciergeServiceName;
    return -1;
  }

  // The standard says that bool to int conversion is implicit and that
  // false => 0 and true => 1.
  // clang-format off
  if (FLAGS_start + FLAGS_stop + FLAGS_stop_all + FLAGS_suspend + FLAGS_resume +
      FLAGS_get_vm_info + FLAGS_get_vm_cid + FLAGS_create_disk +
      FLAGS_create_external_disk + FLAGS_start_termina_vm + FLAGS_destroy_disk +
      FLAGS_export_disk + FLAGS_import_disk + FLAGS_list_disks +
      FLAGS_sync_time + FLAGS_attach_usb + FLAGS_detach_usb +
      FLAGS_list_usb_devices + FLAGS_start_plugin_vm + FLAGS_start_arc_vm +
      FLAGS_get_vm_enterprise_reporting_info +
      FLAGS_set_vm_cpu_restriction + FLAGS_reclaim_vm_memory + FLAGS_list_vms +
      FLAGS_arcvm_complete_boot != 1) {
    // clang-format on
    LOG(ERROR)
        << "Exactly one of --start, --stop, --stop_all, --suspend, --resume, "
        << "--get_vm_info, --get_vm_cid, --create_disk, "
        << "--create_external_disk, --destroy_disk, --export_disk, "
        << "--import_disk --list_disks, --start_termina_vm, --sync_time, "
        << "--attach_usb, --detach_usb, "
        << "--list_usb_devices, --start_plugin_vm, --start_arc_vm, "
        << "--get_vm_enterprise_reporting_info, --set_vm_cpu_restriction, "
        << "--reclaim_vm_memory, --arcvm_complete_boot, or --list_vms "
        << "must be provided";
    return -1;
  }

  StorageLocation storage_location;
  if (!StringToStorageLocation(FLAGS_storage_location, &storage_location)) {
    LOG(ERROR) << "'" << FLAGS_storage_location
               << "' is not a valid storage location";
    return -1;
  }

  if (FLAGS_start) {
    return StartVm(proxy, std::move(FLAGS_cryptohome_id), std::move(FLAGS_name),
                   std::move(FLAGS_kernel), std::move(FLAGS_initrd),
                   std::move(FLAGS_rootfs), std::move(FLAGS_extra_disks),
                   FLAGS_untrusted, FLAGS_writable_rootfs);
  } else if (FLAGS_stop) {
    return StopVm(proxy, std::move(FLAGS_cryptohome_id), std::move(FLAGS_name));
  } else if (FLAGS_stop_all) {
    return StopAllVms(proxy);
  } else if (FLAGS_suspend) {
    return SuspendVm(proxy, std::move(FLAGS_cryptohome_id),
                     std::move(FLAGS_name));
  } else if (FLAGS_resume) {
    return ResumeVm(proxy, std::move(FLAGS_cryptohome_id),
                    std::move(FLAGS_name));
  } else if (FLAGS_get_vm_info) {
    return GetVmInfo(proxy, std::move(FLAGS_cryptohome_id),
                     std::move(FLAGS_name));
  } else if (FLAGS_get_vm_cid) {
    return GetVmCid(proxy, std::move(FLAGS_cryptohome_id),
                    std::move(FLAGS_name));
  } else if (FLAGS_create_disk) {
    return CreateDiskImage(
        proxy, std::move(FLAGS_cryptohome_id), std::move(FLAGS_name),
        FLAGS_disk_size, std::move(FLAGS_image_type), storage_location,
        std::move(FLAGS_source_name),
        base::CommandLine::ForCurrentProcess()->GetArgs(), nullptr);
  } else if (FLAGS_create_external_disk) {
    return CreateExternalDiskImage(std::move(FLAGS_removable_media),
                                   std::move(FLAGS_name),
                                   std::move(FLAGS_disk_size));
  } else if (FLAGS_destroy_disk) {
    return DestroyDiskImage(proxy, std::move(FLAGS_cryptohome_id),
                            std::move(FLAGS_name));
  } else if (FLAGS_export_disk) {
    return ExportDiskImage(proxy, std::move(FLAGS_cryptohome_id),
                           std::move(FLAGS_name), std::move(FLAGS_export_name),
                           std::move(FLAGS_removable_media));
  } else if (FLAGS_import_disk) {
    return ImportDiskImage(proxy, std::move(FLAGS_cryptohome_id),
                           std::move(FLAGS_name), std::move(FLAGS_import_name),
                           storage_location, std::move(FLAGS_removable_media));
  } else if (FLAGS_list_disks) {
    return ListDiskImages(proxy, std::move(FLAGS_cryptohome_id),
                          storage_location);
  } else if (FLAGS_start_termina_vm) {
    return StartTerminaVm(
        proxy, std::move(FLAGS_name), std::move(FLAGS_cryptohome_id),
        std::move(FLAGS_removable_media), std::move(FLAGS_image_name),
        std::move(FLAGS_image_type), std::move(FLAGS_extra_disks));
  } else if (FLAGS_start_plugin_vm) {
    return StartPluginVm(proxy, std::move(FLAGS_name),
                         base::CommandLine::ForCurrentProcess()->GetArgs(),
                         std::move(FLAGS_cryptohome_id));
  } else if (FLAGS_start_arc_vm) {
    return StartArcVm(proxy, std::move(FLAGS_cryptohome_id),
                      std::move(FLAGS_name), std::move(FLAGS_kernel),
                      std::move(FLAGS_rootfs), std::move(FLAGS_android_fstab),
                      std::move(FLAGS_extra_disks),
                      base::CommandLine::ForCurrentProcess()->GetArgs());
  } else if (FLAGS_sync_time) {
    return SyncVmTimes(proxy);
  } else if (FLAGS_attach_usb) {
    return AttachUsbDevice(
        proxy, std::move(FLAGS_name), std::move(FLAGS_cryptohome_id),
        FLAGS_bus_number, FLAGS_port_number, FLAGS_vendor_id, FLAGS_product_id);
  } else if (FLAGS_detach_usb) {
    return DetachUsbDevice(proxy, std::move(FLAGS_name),
                           std::move(FLAGS_cryptohome_id), FLAGS_guest_port);
  } else if (FLAGS_list_usb_devices) {
    return ListUsbDevices(proxy, std::move(FLAGS_name),
                          std::move(FLAGS_cryptohome_id));
  } else if (FLAGS_get_vm_enterprise_reporting_info) {
    return GetEnterpriseReportingInfo(proxy, std::move(FLAGS_name),
                                      std::move(FLAGS_cryptohome_id));
  } else if (FLAGS_set_vm_cpu_restriction) {
    return SetVmCpuRestriction(proxy, std::move(FLAGS_cgroup),
                               std::move(FLAGS_restriction));
  } else if (FLAGS_reclaim_vm_memory) {
    return ReclaimVmMemory(proxy, std::move(FLAGS_name),
                           std::move(FLAGS_cryptohome_id));
  } else if (FLAGS_list_vms) {
    return ListVms(proxy, std::move(FLAGS_cryptohome_id));
  } else if (FLAGS_arcvm_complete_boot) {
    return ArcVmCompleteBoot(proxy, std::move(FLAGS_cryptohome_id));
  }

  // Unreachable.
  return 0;
}
