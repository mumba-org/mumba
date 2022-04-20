// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/service.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <google/protobuf/repeated_field.h>
#include <grp.h>
#include <linux/capability.h>
#include <net/route.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <algorithm>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/base64url.h>
#include <base/bind.h>
#include <base/callback.h>
#include <base/callback_helpers.h>
//#include <base/check.h>
//#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/format_macros.h>
#include <base/guid.h>
#include <base/hash/md5.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/memory/ref_counted.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <base/synchronization/waitable_event.h>
#include <base/system/sys_info.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/thread_task_runner_handle.h>
#include <base/time/time.h>
#include <base/version.h>
#include <brillo/dbus/dbus_proxy_util.h>
#include <brillo/files/safe_fd.h>
#include <chromeos/constants/vm_tools.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <crosvm/qcow_utils.h>
#include <dbus/object_proxy.h>
#include <manatee/dbus-proxies.h>
#include <vboot/crossystem.h>
#include <vm_cicerone/proto_bindings/cicerone_service.pb.h>
#include <vm_concierge/proto_bindings/concierge_service.pb.h>
#include <vm_protos/proto_bindings/vm_guest.pb.h>

#include "vm_tools/common/naming.h"
#include "vm_tools/concierge/arc_vm.h"
#include "vm_tools/concierge/dlc_helper.h"
#include "vm_tools/concierge/future.h"
#include "vm_tools/concierge/plugin_vm.h"
#include "vm_tools/concierge/plugin_vm_helper.h"
#include "vm_tools/concierge/seneschal_server_proxy.h"
#include "vm_tools/concierge/shared_data.h"
#include "vm_tools/concierge/ssh_keys.h"
#include "vm_tools/concierge/vm_builder.h"
#include "vm_tools/concierge/vm_launch_interface.h"
#include "vm_tools/concierge/vm_permission_interface.h"
#include "vm_tools/concierge/vmplugin_dispatcher_interface.h"

using std::string;

namespace vm_tools {
namespace concierge {

namespace {

// Default path to VM kernel image and rootfs.
constexpr char kVmDefaultPath[] = "/run/imageloader/cros-termina";

// Name of the VM kernel image.
constexpr char kVmKernelName[] = "vm_kernel";

// Name of the VM rootfs image.
constexpr char kVmRootfsName[] = "vm_rootfs.img";

// Name of the VM tools image to be mounted at kToolsMountPath.
constexpr char kVmToolsDiskName[] = "vm_tools.img";

// Filesystem location to mount VM tools image.
constexpr char kToolsMountPath[] = "/opt/google/cros-containers";

// Filesystem type of VM tools image.
constexpr char kToolsFsType[] = "ext4";

// The VM instance name of Arcvm
constexpr char kArcVmName[] = "arcvm";

// How long we should wait for a VM to start up.
// While this timeout might be high, it's meant to be a final failure point, not
// the lower bound of how long it takes.  On a loaded system (like extracting
// large compressed files), it could take 10 seconds to boot.
constexpr base::TimeDelta kVmStartupDefaultTimeout = base::Seconds(30);

// crosvm log directory name.
constexpr char kCrosvmLogDir[] = "log";

// crosvm gpu cache directory name.
constexpr char kCrosvmGpuCacheDir[] = "gpucache";

// Path to system boot_id file.
constexpr char kBootIdFile[] = "/proc/sys/kernel/random/boot_id";

// Extended attribute indicating that user has picked a disk size and it should
// not be resized.
constexpr char kDiskImageUserChosenSizeXattr[] =
    "user.crostini.user_chosen_size";

// File extension for raw disk types
constexpr char kRawImageExtension[] = ".img";

// File extension for qcow2 disk types
constexpr char kQcowImageExtension[] = ".qcow2";

// File extension for Plugin VMs disk types
constexpr char kPluginVmImageExtension[] = ".pvm";

// Valid file extensions for disk images
constexpr const char* kDiskImageExtensions[] = {kRawImageExtension,
                                                kQcowImageExtension, nullptr};

// Valid file extensions for Plugin VM images
constexpr const char* kPluginVmImageExtensions[] = {kPluginVmImageExtension,
                                                    nullptr};

// Default name to use for a container.
constexpr char kDefaultContainerName[] = "penguin";

constexpr uint64_t kMinimumDiskSize = 1ll * 1024 * 1024 * 1024;  // 1 GiB
constexpr uint64_t kDiskSizeMask = ~4095ll;  // Round to disk block size.

// vmlog_forwarder relies on creating a socket for crosvm to receive log
// messages. Socket paths may only be 108 character long. Further, while Linux
// actually allows for 108 non-null bytes to be used, the rust interface to bind
// only allows for 107, with the last byte always being null.
//
// We can abbreviate the directories in the path by opening the target directory
// and using /proc/self/fd/ to access it, but this still uses up
// 21 + (fd digits) characters on the prefix and file extension. This leaves us
// with 86 - (fd digits) characters for the base64 encoding of the VM
// name. Base64 always produces encoding that are a multiple of 4 digits long,
// so we can either allow for 63/84 characters before/after encoding, or
// 60/80. The first will break if our file descriptor numbers ever go above 99,
// which seems unlikely but not impossible. We can definitely be sure they won't
// go above 99,999, however.
constexpr int kMaxVmNameLength = 60;

constexpr uint64_t kDefaultIoLimit = 1024 * 1024;  // 1 Mib

// How often we should broadcast state of a disk operation (import or export).
constexpr base::TimeDelta kDiskOpReportInterval = base::Seconds(15);

// The minimum kernel version of the host which supports untrusted VMs or a
// trusted VM with nested VM support.
constexpr KernelVersionAndMajorRevision
    kMinKernelVersionForUntrustedAndNestedVM = std::make_pair(4, 19);

// The minimum kernel version of the host which supports virtio-pmem.
constexpr KernelVersionAndMajorRevision kMinKernelVersionForVirtioPmem =
    std::make_pair(4, 4);

// File path that reports the L1TF vulnerability status.
constexpr const char kL1TFFilePath[] =
    "/sys/devices/system/cpu/vulnerabilities/l1tf";

// File path that reports the MDS vulnerability status.
constexpr const char kMDSFilePath[] =
    "/sys/devices/system/cpu/vulnerabilities/mds";

constexpr gid_t kCrosvmUGid = 299;

// Needs to be const as libfeatures does pointers checking.
const Feature kArcVmInitialThrottleFeature{"CrOSLateBootArcVmInitialThrottle",
                                           FEATURE_DISABLED_BY_DEFAULT};

// Used with the |IsUntrustedVMAllowed| function.
struct UntrustedVMCheckResult {
  UntrustedVMCheckResult(bool untrusted_vm_allowed, bool skip_host_checks)
      : untrusted_vm_allowed(untrusted_vm_allowed),
        skip_host_checks(skip_host_checks) {}

  // Is an untrusted VM allowed on the host.
  bool untrusted_vm_allowed;

  // Should checking for security patches on the host be skipped while starting
  // untrusted VMs.
  bool skip_host_checks;
};

// Passes |method_call| to |handler| and passes the response to
// |response_sender|. If |handler| returns NULL, an empty response is created
// and sent.
void HandleSynchronousDBusMethodCall(
    base::Callback<std::unique_ptr<dbus::Response>(dbus::MethodCall*)> handler,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  std::unique_ptr<dbus::Response> response = handler.Run(method_call);
  if (!response)
    response = dbus::Response::FromMethodCall(method_call);
  std::move(response_sender).Run(std::move(response));
}

void HandleAsynchronousDBusMethodCall(
    base::Callback<void(dbus::MethodCall*,
                        dbus::ExportedObject::ResponseSender)> handler,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  handler.Run(method_call, std::move(response_sender));
}

// Posted to a grpc thread to startup a listener service. Puts a copy of
// the pointer to the grpc server in |server_copy| and then signals |event|.
// It will listen on the address specified in |listener_address|.
void RunListenerService(grpc::Service* listener,
                        const std::string& listener_address,
                        base::WaitableEvent* event,
                        std::shared_ptr<grpc::Server>* server_copy) {
  // Build the grpc server.
  grpc::ServerBuilder builder;
  builder.AddListeningPort(listener_address, grpc::InsecureServerCredentials());
  builder.RegisterService(listener);

  std::shared_ptr<grpc::Server> server(builder.BuildAndStart().release());

  *server_copy = server;
  event->Signal();

  if (server) {
    server->Wait();
  }
}

// Sets up a gRPC listener service by starting the |grpc_thread| and posting the
// main task to run for the thread. |listener_address| should be the address the
// gRPC server is listening on. A copy of the pointer to the server is put in
// |server_copy|. Returns true if setup & started successfully, false otherwise.
bool SetupListenerService(base::Thread* grpc_thread,
                          grpc::Service* listener_impl,
                          const std::string& listener_address,
                          std::shared_ptr<grpc::Server>* server_copy) {
  // Start the grpc thread.
  if (!grpc_thread->Start()) {
    LOG(ERROR) << "Failed to start grpc thread";
    return false;
  }

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool ret = grpc_thread->task_runner()->PostTask(
      FROM_HERE, base::Bind(&RunListenerService, listener_impl,
                            listener_address, &event, server_copy));
  if (!ret) {
    LOG(ERROR) << "Failed to post server startup task to grpc thread";
    return false;
  }

  // Wait for the VM grpc server to start.
  event.Wait();

  if (!server_copy) {
    LOG(ERROR) << "grpc server failed to start";
    return false;
  }

  return true;
}

// Converts an IPv4 address to a string. The result will be stored in |str|
// on success.
bool IPv4AddressToString(const uint32_t address, std::string* str) {
  CHECK(str);

  char result[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, result, sizeof(result)) != result) {
    return false;
  }
  *str = std::string(result);
  return true;
}

// Get the path to the latest available cros-termina component.
base::FilePath GetLatestVMPath() {
  base::FilePath component_dir(kVmDefaultPath);
  base::FileEnumerator dir_enum(component_dir, false,
                                base::FileEnumerator::DIRECTORIES);

  base::Version latest_version("0");
  base::FilePath latest_path;

  for (base::FilePath path = dir_enum.Next(); !path.empty();
       path = dir_enum.Next()) {
    base::Version version(path.BaseName().value());
    if (!version.IsValid())
      continue;

    if (version > latest_version) {
      latest_version = version;
      latest_path = path;
    }
  }

  return latest_path;
}

// Gets the path to a VM disk given the name, user id, and location.
bool GetDiskPathFromName(
    const std::string& vm_name,
    const std::string& cryptohome_id,
    StorageLocation storage_location,
    bool create_parent_dir,
    base::FilePath* path_out,
    enum DiskImageType preferred_image_type = DiskImageType::DISK_IMAGE_AUTO) {
  switch (storage_location) {
    case STORAGE_CRYPTOHOME_ROOT: {
      const auto qcow2_path =
          GetFilePathFromName(cryptohome_id, vm_name, storage_location,
                              kQcowImageExtension, create_parent_dir);
      if (!qcow2_path) {
        if (create_parent_dir)
          LOG(ERROR) << "Failed to get qcow2 path";
        return false;
      }
      const auto raw_path =
          GetFilePathFromName(cryptohome_id, vm_name, storage_location,
                              kRawImageExtension, create_parent_dir);
      if (!raw_path) {
        if (create_parent_dir)
          LOG(ERROR) << "Failed to get raw path";
        return false;
      }

      const bool qcow2_exists = base::PathExists(*qcow2_path);
      const bool raw_exists = base::PathExists(*raw_path);

      // This scenario (both <name>.img and <name>.qcow2 exist) should never
      // happen. It is prevented by the later checks in this function.
      // However, in case it does happen somehow (e.g. user manually created
      // files in dev mode), bail out, since we can't tell which one the user
      // wants.
      if (qcow2_exists && raw_exists) {
        LOG(ERROR) << "Both qcow2 and raw variants of " << vm_name
                   << " already exist.";
        return false;
      }

      // Return the path to an existing image of any type, if one exists.
      // If not, generate a path based on the preferred image type.
      if (qcow2_exists) {
        *path_out = *qcow2_path;
      } else if (raw_exists) {
        *path_out = *raw_path;
      } else if (preferred_image_type == DISK_IMAGE_QCOW2) {
        *path_out = *qcow2_path;
      } else if (preferred_image_type == DISK_IMAGE_RAW ||
                 preferred_image_type == DISK_IMAGE_AUTO) {
        *path_out = *raw_path;
      } else {
        LOG(ERROR) << "Unknown image type " << preferred_image_type;
        return false;
      }
      return true;
    }
    case STORAGE_CRYPTOHOME_PLUGINVM: {
      const auto plugin_path =
          GetFilePathFromName(cryptohome_id, vm_name, storage_location,
                              kPluginVmImageExtension, create_parent_dir);
      if (!plugin_path) {
        if (create_parent_dir)
          LOG(ERROR) << "failed to get plugin path";
        return false;
      }
      *path_out = *plugin_path;
      return true;
    }
    default:
      LOG(ERROR) << "Unknown storage location type";
      return false;
  }
}

bool CheckVmExists(const std::string& vm_name,
                   const std::string& cryptohome_id,
                   base::FilePath* out_path = nullptr,
                   StorageLocation* storage_location = nullptr) {
  for (int l = StorageLocation_MIN; l <= StorageLocation_MAX; l++) {
    StorageLocation location = static_cast<StorageLocation>(l);
    base::FilePath disk_path;
    if (GetDiskPathFromName(vm_name, cryptohome_id, location,
                            false, /* create_parent_dir */
                            &disk_path) &&
        base::PathExists(disk_path)) {
      if (out_path) {
        *out_path = disk_path;
      }
      if (storage_location) {
        *storage_location = location;
      }
      return true;
    }
  }

  return false;
}

// Returns the desired size of VM disks, which is 90% of the available space
// (excluding the space already taken up by the disk).
uint64_t CalculateDesiredDiskSize(base::FilePath disk_location,
                                  uint64_t current_usage) {
  uint64_t free_space =
      base::SysInfo::AmountOfFreeDiskSpace(disk_location.DirName());
  free_space += current_usage;
  uint64_t disk_size = ((free_space * 9) / 10) & kDiskSizeMask;

  return std::max(disk_size, kMinimumDiskSize);
}

// Returns true if the disk size was specified by the user and should not be
// automatically resized.
bool IsDiskUserChosenSize(std::string disk_path) {
  return getxattr(disk_path.c_str(), kDiskImageUserChosenSizeXattr, NULL, 0) >=
         0;
}

// Mark a disk with an xattr indicating its size has been chosen by the user.
bool SetUserChosenSizeAttr(const base::ScopedFD& fd) {
  // The xattr value doesn't matter, only its existence.
  // Store something human-readable for debugging.
  constexpr char val[] = "1";
  return fsetxattr(fd.get(), kDiskImageUserChosenSizeXattr, val, sizeof(val),
                   0) == 0;
}

void FormatDiskImageStatus(const DiskImageOperation* op,
                           DiskImageStatusResponse* status) {
  status->set_status(op->status());
  status->set_command_uuid(op->uuid());
  status->set_failure_reason(op->failure_reason());
  status->set_progress(op->GetProgress());
}

uint64_t GetFileUsage(const base::FilePath& path) {
  struct stat st;
  if (stat(path.value().c_str(), &st) == 0) {
    // Use the st_blocks value to get the space usage (as in 'du') of the file.
    // st_blocks is always in units of 512 bytes, regardless of the underlying
    // filesystem and block device block size.
    return st.st_blocks * 512;
  }
  return 0;
}

// Returns the current kernel version. If there is a failure to retrieve the
// version it returns <INT_MIN, INT_MIN>.
KernelVersionAndMajorRevision GetKernelVersion() {
  struct utsname buf;
  if (uname(&buf))
    return std::make_pair(INT_MIN, INT_MIN);

  // Parse uname result in the form of x.yy.zzz. The parsed data should be in
  // the expected format.
  std::vector<base::StringPiece> versions = base::SplitStringPiece(
      buf.release, ".", base::WhitespaceHandling::TRIM_WHITESPACE,
      base::SplitResult::SPLIT_WANT_ALL);
  DCHECK_EQ(versions.size(), 3);
  DCHECK(!versions[0].empty());
  DCHECK(!versions[1].empty());
  int version;
  bool result = base::StringToInt(versions[0], &version);
  DCHECK(result);
  int major_revision;
  result = base::StringToInt(versions[1], &major_revision);
  DCHECK(result);
  return std::make_pair(version, major_revision);
}

// vm_name should always be less then kMaxVmNameLength characters long.
base::FilePath GetVmLogPath(const std::string& owner_id,
                            const std::string& vm_name,
                            bool log_to_cryptohome = true) {
  if (!log_to_cryptohome) {
    return base::FilePath();
  }
  std::string encoded_vm_name = GetEncodedName(vm_name);

  base::FilePath path = base::FilePath(kCryptohomeRoot)
                            .Append(kCrosvmDir)
                            .Append(owner_id)
                            .Append(kCrosvmLogDir)
                            .Append(encoded_vm_name)
                            .AddExtension(".lsock");

  base::FilePath parent_dir = path.DirName();
  if (!base::DirectoryExists(parent_dir)) {
    base::File::Error dir_error;
    if (!base::CreateDirectoryAndGetError(parent_dir, &dir_error)) {
      LOG(ERROR) << "Failed to create crosvm log directory in " << parent_dir
                 << ": " << base::File::ErrorToString(dir_error);
      return base::FilePath();
    }
  }
  return path;
}

// Returns a hash string that is safe to use as a filename.
std::string GetMd5HashForFilename(const std::string& str) {
  std::string result;
  base::MD5Digest digest;
  base::MD5Sum(str.data(), str.size(), &digest);
  base::StringPiece hash_piece(reinterpret_cast<char*>(&digest.a[0]),
                               sizeof(digest.a));
  // Note, we can not have '=' symbols in this path or it will break crosvm's
  // commandline argument parsing, so we use OMIT_PADDING.
  base::Base64UrlEncode(hash_piece, base::Base64UrlEncodePolicy::OMIT_PADDING,
                        &result);
  return result;
}

base::FilePath GetVmGpuCachePath(const std::string& owner_id,
                                 const std::string& vm_name) {
  std::string vm_dir;
  // Note, we can not have '=' symbols in this path or it will break crosvm's
  // commandline argument parsing, so we use OMIT_PADDING.
  base::Base64UrlEncode(vm_name, base::Base64UrlEncodePolicy::OMIT_PADDING,
                        &vm_dir);

  std::string bootid_dir;
  CHECK(base::ReadFileToString(base::FilePath(kBootIdFile), &bootid_dir));
  bootid_dir = GetMd5HashForFilename(bootid_dir);

  return base::FilePath(kCryptohomeRoot)
      .Append(kCrosvmDir)
      .Append(owner_id)
      .Append(kCrosvmGpuCacheDir)
      .Append(bootid_dir)
      .Append(vm_dir);
}

bool IsDevModeEnabled() {
  return VbGetSystemPropertyInt("cros_debug") == 1;
}

// Returns whether the VM is trusted or untrusted based on the source image,
// whether we're passing custom kernel args, the host kernel version and a
// flag passed down by the user.
bool IsUntrustedVM(bool run_as_untrusted,
                   bool is_trusted_image,
                   bool has_custom_kernel_params,
                   KernelVersionAndMajorRevision host_kernel_version) {
  // Nested virtualization is enabled for all kernels >=
  // |kMinKernelVersionForUntrustedAndNestedVM|. This means that even with a
  // trusted image the VM started will essentially be untrusted.
  if (host_kernel_version >= kMinKernelVersionForUntrustedAndNestedVM)
    return true;

  // Any untrusted image definitely results in an unstrusted VM.
  if (!is_trusted_image)
    return true;

  // Arbitrary kernel params cannot be trusted.
  if (has_custom_kernel_params)
    return true;

  if (run_as_untrusted)
    return true;

  return false;
}

// Returns whether an untrusted VM is allowed on the host and whether checking
// for security patches while starting the untrusted VM should be skipped.
UntrustedVMCheckResult IsUntrustedVMAllowed(
    bool run_as_untrusted, KernelVersionAndMajorRevision host_kernel_version) {
  // For host >= |kMinKernelVersionForUntrustedAndNestedVM| untrusted VMs are
  // always allowed. But the host still needs to be checked for vulnerabilities,
  // even in developer mode. This is done because it'd be a huge error to not
  // have required security patches on these kernels regardless of dev or
  // production mode.
  if (host_kernel_version >= kMinKernelVersionForUntrustedAndNestedVM) {
    return UntrustedVMCheckResult(true /* untrusted_vm_allowed */,
                                  false /* skip_host_checks */);
  }

  // On lower kernel versions |run_as_untrusted| is only respected in developer
  // mode. The user wants to start the VM irrespective of the host's kernel
  // version or security mitigation state. In this mode, allow untrusted VMs
  // without any restrictions on the host having security mitigations.
  if (run_as_untrusted && IsDevModeEnabled()) {
    return UntrustedVMCheckResult(true /* untrusted_vm_allowed */,
                                  true /* skip_host_checks */);
  }

  // Lower kernel version are deemed insecure to handle untrusted VMs.
  // Note: |skip_host_checks| is redundant in this scenario as
  // |untrusted_vm_allowed| is set to false.
  return UntrustedVMCheckResult(false /* untrusted_vm_allowed */,
                                false /* skip_host_checks  */);
}

// Clears close-on-exec flag for a file descriptor to pass it to a subprocess
// such as crosvm. Returns a failure reason on failure.
string RemoveCloseOnExec(int raw_fd) {
  int flags = fcntl(raw_fd, F_GETFD);
  if (flags == -1) {
    return "Failed to get flags for passed fd";
  }

  flags &= ~FD_CLOEXEC;
  if (fcntl(raw_fd, F_SETFD, flags) == -1) {
    return "Failed to clear close-on-exec flag for fd";
  }

  return "";
}

// Reclaims memory of the crosvm process with |pid| by writing "shmem" to
// /proc/<pid>/reclaim. Since this function may block 10 seconds or more, do
// not call on the main thread.
std::unique_ptr<dbus::Response> ReclaimVmMemoryInternal(
    pid_t pid, std::unique_ptr<dbus::Response> dbus_response) {
  dbus::MessageWriter writer(dbus_response.get());
  ReclaimVmMemoryResponse response;
  response.set_success(false);

  const std::string path = base::StringPrintf("/proc/%d/reclaim", pid);
  const std::string value = "shmem";
  base::ScopedFD fd(
      HANDLE_EINTR(open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW)));
  if (!fd.is_valid()) {
    LOG(ERROR) << "Failed to open " << path;
    response.set_failure_reason("Failed to open /proc filesystem");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  if (HANDLE_EINTR(write(fd.get(), value.c_str(), value.size())) !=
      value.size()) {
    PLOG(ERROR) << "Failed to write to " << path;
    response.set_failure_reason("Failed to write to /proc filesystem");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  LOG(INFO) << "Successfully reclaimed VM memory. PID=" << pid;

  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

// Determines what classification type this VM has. Classifications are roughly
// related to products, and the classification broadly determines what features
// are available to a given VM.
//
// TODO(b/213090722): Determining a VM's type based on its properties like this
// is undesirable. Instead we should provide the type in the request, and
// determine its properties from that.
VmInfo::VmType ClassifyVm(const StartVmRequest& request) {
  if (request.vm().dlc_id() == "borealis-dlc")
    return VmInfo::BOREALIS;
  if (request.start_termina())
    return VmInfo::TERMINA;
  return VmInfo::UNKNOWN;
}

}  // namespace

base::Optional<int64_t> Service::GetAvailableMemory() {
  dbus::MethodCall method_call(resource_manager::kResourceManagerInterface,
                               resource_manager::kGetAvailableMemoryKBMethod);
  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, resource_manager_service_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to get available memory size from resourced";
    return std::nullopt;
  }
  dbus::MessageReader reader(dbus_response.get());
  uint64_t available_kb;
  if (!reader.PopUint64(&available_kb)) {
    LOG(ERROR)
        << "Failed to read available memory size from the D-Bus response";
    return std::nullopt;
  }
  return available_kb * KIB;
}

base::Optional<int64_t> Service::GetForegroundAvailableMemory() {
  dbus::MethodCall method_call(
      resource_manager::kResourceManagerInterface,
      resource_manager::kGetForegroundAvailableMemoryKBMethod);
  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, resource_manager_service_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR)
        << "Failed to get foreground available memory size from resourced";
    return std::nullopt;
  }
  dbus::MessageReader reader(dbus_response.get());
  uint64_t available_kb;
  if (!reader.PopUint64(&available_kb)) {
    LOG(ERROR) << "Failed to read foreground available memory size from the "
                  "D-Bus response";
    return std::nullopt;
  }
  return available_kb * KIB;
}

base::Optional<MemoryMargins> Service::GetMemoryMargins() {
  dbus::MethodCall method_call(resource_manager::kResourceManagerInterface,
                               resource_manager::kGetMemoryMarginsKBMethod);
  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, resource_manager_service_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to get critical margin size from resourced";
    return std::nullopt;
  }
  dbus::MessageReader reader(dbus_response.get());
  MemoryMargins margins;
  if (!reader.PopUint64(&margins.critical)) {
    LOG(ERROR)
        << "Failed to read available critical margin from the D-Bus response";
    return std::nullopt;
  }
  if (!reader.PopUint64(&margins.moderate)) {
    LOG(ERROR)
        << "Failed to read available moderate margin from the D-Bus response";
    return std::nullopt;
  }
  margins.critical *= KIB;
  margins.moderate *= KIB;
  return margins;
}

base::Optional<resource_manager::GameMode> Service::GetGameMode() {
  dbus::MethodCall method_call(resource_manager::kResourceManagerInterface,
                               resource_manager::kGetGameModeMethod);
  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, resource_manager_service_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to get geme mode from resourced";
    return std::nullopt;
  }
  dbus::MessageReader reader(dbus_response.get());
  uint8_t game_mode;
  if (!reader.PopByte(&game_mode)) {
    LOG(ERROR) << "Failed to read game mode from the D-Bus response";
    return std::nullopt;
  }
  return static_cast<resource_manager::GameMode>(game_mode);
}

static base::Optional<std::string> GameModeToForegroundVmName(
    resource_manager::GameMode game_mode) {
  using resource_manager::GameMode;
  if (game_mode == GameMode::BOREALIS) {
    return "borealis";
  }
  if (game_mode == GameMode::OFF) {
    return std::nullopt;
  }
  LOG(ERROR) << "Unexpected game mode value " << static_cast<int>(game_mode);
  return std::nullopt;
}

// Runs balloon policy against each VM to balance memory.
// This will be called periodically by balloon_resizing_timer_.
void Service::RunBalloonPolicy() {
  // TODO(b/191946183): Design and migrate to a new D-Bus API
  // that is less chatty for implementing balloon logic.
  if (!memory_margins_) {
    // Lazily initialize memory_margins_. Done here so we don't delay VM startup
    // with a D-Bus call.
    memory_margins_ = GetMemoryMargins();
    if (!memory_margins_) {
      LOG(ERROR) << "Failed to get ChromeOS memory margins, stopping balloon "
                 << "policy";
      balloon_resizing_timer_.Stop();
      return;
    }
  }

  std::vector<std::pair<uint32_t, BalloonStats>> balloon_stats;
  std::vector<uint32_t> ids;
  for (auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    if (!vm->GetBalloonPolicy(*memory_margins_, vm_entry.first.name())) {
      // Skip VMs that don't have a memory policy. It may just not be ready
      // yet.
      continue;
    }
    if (!USE_CROSVM_SIBLINGS) {
      auto stats_opt = vm->GetBalloonStats();
      if (stats_opt) {
        balloon_stats.emplace_back(vm->GetInfo().vm_memory_id, *stats_opt);
      }
    } else {
      ids.emplace_back(vm->GetInfo().vm_memory_id);
    }
  }

  if (!USE_CROSVM_SIBLINGS) {
    FinishBalloonPolicy(std::move(balloon_stats));
  } else {
    mms_->GetBalloonStats(ids, base::BindOnce(&Service::FinishBalloonPolicy,
                                              weak_ptr_factory_.GetWeakPtr()));
  }
}

void Service::FinishBalloonPolicy(TaggedBalloonStats stats) {
  const auto available_memory = GetAvailableMemory();
  if (!available_memory.has_value()) {
    return;
  }
  const auto game_mode = GetGameMode();
  if (!game_mode.has_value()) {
    return;
  }
  base::Optional<int64_t> foreground_available_memory;
  if (*game_mode != resource_manager::GameMode::OFF) {
    // foreground_available_memory is only used when the game mode is enabled.
    foreground_available_memory = GetForegroundAvailableMemory();
    if (!foreground_available_memory.has_value()) {
      return;
    }
  }

  TaggedMemoryMiBDeltas deltas;
  const auto foreground_vm_name = GameModeToForegroundVmName(*game_mode);
  for (auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    if (vm->IsSuspended()) {
      // Skip suspended VMs since there is no effect.
      continue;
    }
    auto stats_iter = std::find_if(
        stats.begin(), stats.end(),
        [&vm](auto& pair) { return pair.first == vm->GetInfo().vm_memory_id; });
    if (stats_iter == stats.end()) {
      // Stats not available. Skip running policies.
      continue;
    }
    BalloonStats stats = stats_iter->second;
    const std::unique_ptr<BalloonPolicyInterface>& policy =
        vm->GetBalloonPolicy(*memory_margins_, vm_entry.first.name());

    // Switch available memory for this VM based on the current game mode.
    bool is_in_game_mode = foreground_vm_name.has_value() &&
                           vm_entry.first.name() == foreground_vm_name;
    const int64_t available_memory_for_vm =
        is_in_game_mode ? *foreground_available_memory : *available_memory;

    int64_t delta = policy->ComputeBalloonDelta(
        stats, available_memory_for_vm, is_in_game_mode, vm_entry.first.name());

    if (!USE_CROSVM_SIBLINGS) {
      int64_t target = std::max(INT64_C(0), stats.balloon_actual + delta);
      if (target != stats.balloon_actual) {
        vm->SetBalloonSize(target);
      }
    } else {
      if (delta)
        deltas.emplace_back(vm->GetInfo().vm_memory_id, delta);
    }
  }

  if (USE_CROSVM_SIBLINGS && !deltas.empty()) {
    mms_->RebalanceMemory(std::move(deltas), base::BindOnce([](bool success) {
                            if (!success)
                              LOG(ERROR) << "Failed to fully rebalance memory";
                          }));
  }
}

bool Service::ListVmDisksInLocation(const string& cryptohome_id,
                                    StorageLocation location,
                                    const string& lookup_name,
                                    ListVmDisksResponse* response) {
  base::FilePath image_dir;
  base::FileEnumerator::FileType file_type = base::FileEnumerator::FILES;
  const char* const* allowed_ext = kDiskImageExtensions;
  switch (location) {
    case STORAGE_CRYPTOHOME_ROOT:
      image_dir = base::FilePath(kCryptohomeRoot)
                      .Append(kCrosvmDir)
                      .Append(cryptohome_id);
      break;

    case STORAGE_CRYPTOHOME_PLUGINVM:
      image_dir = base::FilePath(kCryptohomeRoot)
                      .Append(kPluginVmDir)
                      .Append(cryptohome_id);
      file_type = base::FileEnumerator::DIRECTORIES;
      allowed_ext = kPluginVmImageExtensions;
      break;

    default:
      response->set_success(false);
      response->set_failure_reason("Unsupported storage location for images");
      return false;
  }

  if (!base::DirectoryExists(image_dir)) {
    // No directory means no VMs, return the empty response.
    return true;
  }

  uint64_t total_size = 0;
  base::FileEnumerator dir_enum(image_dir, false, file_type);
  for (base::FilePath path = dir_enum.Next(); !path.empty();
       path = dir_enum.Next()) {
    string extension = path.BaseName().Extension();
    bool allowed = false;
    for (auto p = allowed_ext; *p; p++) {
      if (extension == *p) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      continue;
    }

    base::FilePath bare_name = path.BaseName().RemoveExtension();
    if (bare_name.empty()) {
      continue;
    }
    std::string image_name = GetDecodedName(bare_name.value());
    if (image_name.empty()) {
      continue;
    }
    if (!lookup_name.empty() && lookup_name != image_name) {
      continue;
    }

    uint64_t size = dir_enum.GetInfo().IsDirectory()
                        ? ComputeDirectorySize(path)
                        : GetFileUsage(path);
    total_size += size;

    uint64_t min_size;
    uint64_t available_space;
    auto iter = FindVm(cryptohome_id, image_name);
    if (iter == vms_.end()) {
      // VM may not be running - in this case, we can't determine min_size or
      // available_space, so report 0 for unknown.
      min_size = 0;
      available_space = 0;
    } else {
      min_size = iter->second->GetMinDiskSize();
      available_space = iter->second->GetAvailableDiskSpace();
    }

    enum DiskImageType image_type = DiskImageType::DISK_IMAGE_AUTO;
    if (extension == kRawImageExtension) {
      image_type = DiskImageType::DISK_IMAGE_RAW;
    } else if (extension == kQcowImageExtension) {
      image_type = DiskImageType::DISK_IMAGE_QCOW2;
    } else if (extension == kPluginVmImageExtension) {
      image_type = DiskImageType::DISK_IMAGE_PLUGINVM;
    }

    VmDiskInfo* image = response->add_images();
    image->set_name(std::move(image_name));
    image->set_storage_location(location);
    image->set_size(size);
    image->set_min_size(min_size);
    image->set_available_space(available_space);
    image->set_image_type(image_type);
    image->set_user_chosen_size(IsDiskUserChosenSize(path.value()));
    image->set_path(path.value());
  }

  response->set_total_size(response->total_size() + total_size);
  return true;
}

std::unique_ptr<Service> Service::Create(base::Closure quit_closure) {
  auto service = base::WrapUnique(new Service(std::move(quit_closure)));

  if (!service->Init()) {
    service.reset();
  }

  return service;
}

Service::Service(base::Closure quit_closure)
    : next_seneschal_server_port_(kFirstSeneschalServerPort),
      quit_closure_(std::move(quit_closure)),
      host_kernel_version_(GetKernelVersion()),
      weak_ptr_factory_(this) {}

Service::~Service() {
  if (grpc_server_vm_) {
    grpc_server_vm_->Shutdown();
  }
}

void Service::OnSignalReadable() {
  struct signalfd_siginfo siginfo;
  if (read(signal_fd_.get(), &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
    PLOG(ERROR) << "Failed to read from signalfd";
    return;
  }

  if (siginfo.ssi_signo == SIGCHLD) {
    HandleChildExit();
  } else if (siginfo.ssi_signo == SIGTERM) {
    HandleSigterm();
  } else {
    LOG(ERROR) << "Received unknown signal from signal fd: "
               << strsignal(siginfo.ssi_signo);
  }
}

bool Service::Init() {
  // It's not possible to ask minijail to set up a user namespace and switch to
  // a non-0 uid/gid, or to set up supplemental groups. Concierge needs both
  // supplemental groups and to run as a user whose id is unchanged from the
  // root namespace (dbus authentication requires this), so we configure this
  // here.
  if (setresuid(kCrosvmUGid, kCrosvmUGid, kCrosvmUGid) < 0) {
    PLOG(ERROR) << "Failed to set uid to crosvm";
    return false;
  }
  if (setresgid(kCrosvmUGid, kCrosvmUGid, kCrosvmUGid) < 0) {
    PLOG(ERROR) << "Failed to set gid to crosvm";
    return false;
  }
  // Ideally we would just call initgroups("crosvm") here, but internally glibc
  // interprets EINVAL as signaling that the list of supplemental groups is too
  // long and truncates the list, when it could also indicate that some of the
  // gids are unmapped in the current namespace. Instead we look up the groups
  // ourselves so we can log a useful error if the mapping is wrong.
  int ngroups = 0;
  getgrouplist("crosvm", kCrosvmUGid, nullptr, &ngroups);
  std::vector<gid_t> groups(ngroups);
  if (getgrouplist("crosvm", kCrosvmUGid, groups.data(), &ngroups) < 0) {
    PLOG(ERROR) << "Failed to get supplemental groups for user crosvm";
    return false;
  }
  if (setgroups(ngroups, groups.data()) < 0) {
    PLOG(ERROR)
        << "Failed to set supplemental groups. This probably means you have "
           "added user crosvm to groups that are not mapped in the concierge "
           "user namespace and need to update vm_concierge.conf.";
    return false;
  }

  // Change the umask so that the runtime directory for each VM will get the
  // right permissions.
  umask(002);

  // Set up the signalfd for receiving SIGCHLD and SIGTERM.
  // This applies to all threads created afterwards.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGTERM);

  // Restore process' "dumpable" flag so that /proc will be writable.
  // We need it to properly set up jail for Plugin VM helper process.
  if (prctl(PR_SET_DUMPABLE, 1) < 0) {
    PLOG(ERROR) << "Failed to set PR_SET_DUMPABLE";
    return false;
  }

  signal_fd_.reset(signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));
  if (!signal_fd_.is_valid()) {
    PLOG(ERROR) << "Failed to create signalfd";
    return false;
  }

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      signal_fd_.get(),
      base::BindRepeating(&Service::OnSignalReadable, base::Unretained(this)));
  if (!watcher_) {
    LOG(ERROR) << "Failed to watch signalfd";
    return false;
  }

  // Now block signals from the normal signal handling path so that we will get
  // them via the signalfd.
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
    PLOG(ERROR) << "Failed to block signals via sigprocmask";
    return false;
  }

  if (!dbus_thread_.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOG(ERROR) << "Failed to start dbus thread";
    return false;
  }

  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  opts.dbus_task_runner = dbus_thread_.task_runner();
  bus_ = new dbus::Bus(std::move(opts));

  if (!AsyncNoReject(dbus_thread_.task_runner(),
                     base::BindOnce(
                         [](scoped_refptr<dbus::Bus> bus) {
                           if (!bus->Connect()) {
                             LOG(ERROR) << "Failed to connect to system bus";
                             return false;
                           }
                           return true;
                         },
                         bus_))
           .Get()
           .val) {
    return false;
  }

  exported_object_ =
      bus_->GetExportedObject(dbus::ObjectPath(kVmConciergeServicePath));
  if (!exported_object_) {
    LOG(ERROR) << "Failed to export " << kVmConciergeServicePath << " object";
    return false;
  }

  untrusted_vm_utils_ = std::make_unique<UntrustedVMUtils>(
      base::FilePath(kL1TFFilePath), base::FilePath(kMDSFilePath));

  dlcservice_client_ = std::make_unique<DlcHelper>(bus_);
  vm_launch_interface_ = std::make_unique<VmLaunchInterface>(bus_);

  using ServiceMethod =
      std::unique_ptr<dbus::Response> (Service::*)(dbus::MethodCall*);
  static const std::map<const char*, ServiceMethod> kServiceMethods = {
      {kStopVmMethod, &Service::StopVm},
      {kStopAllVmsMethod, &Service::StopAllVms},
      {kSuspendVmMethod, &Service::SuspendVm},
      {kResumeVmMethod, &Service::ResumeVm},
      {kGetVmInfoMethod, &Service::GetVmInfo},
      {kGetVmEnterpriseReportingInfoMethod,
       &Service::GetVmEnterpriseReportingInfo},
      {kArcVmCompleteBootMethod, &Service::ArcVmCompleteBoot},
      {kAdjustVmMethod, &Service::AdjustVm},
      {kCreateDiskImageMethod, &Service::CreateDiskImage},
      {kDestroyDiskImageMethod, &Service::DestroyDiskImage},
      {kResizeDiskImageMethod, &Service::ResizeDiskImage},
      {kExportDiskImageMethod, &Service::ExportDiskImage},
      {kImportDiskImageMethod, &Service::ImportDiskImage},
      {kDiskImageStatusMethod, &Service::CheckDiskImageStatus},
      {kCancelDiskImageMethod, &Service::CancelDiskImageOperation},
      {kListVmDisksMethod, &Service::ListVmDisks},
      {kGetContainerSshKeysMethod, &Service::GetContainerSshKeys},
      {kSyncVmTimesMethod, &Service::SyncVmTimes},
      {kAttachUsbDeviceMethod, &Service::AttachUsbDevice},
      {kDetachUsbDeviceMethod, &Service::DetachUsbDevice},
      {kListUsbDeviceMethod, &Service::ListUsbDevices},
      {kGetDnsSettingsMethod, &Service::GetDnsSettings},
      {kSetVmCpuRestrictionMethod, &Service::SetVmCpuRestriction},
      {kSetVmIdMethod, &Service::SetVmId},
      {kListVmsMethod, &Service::ListVms},
  };

  using AsyncServiceMethod = void (Service::*)(
      dbus::MethodCall*, dbus::ExportedObject::ResponseSender);
  static const std::map<const char*, AsyncServiceMethod> kAsyncServiceMethods =
      {
          {kReclaimVmMemoryMethod, &Service::ReclaimVmMemory},
          {kStartVmMethod,
           &Service::StartVmHelper<StartVmRequest, &Service::GetVmMemoryMiB,
                                   &Service::StartVm>},
          // TODO(b/220235105): Query pvm memsize and then make the return
          // type a plain int64_t.
          {kStartPluginVmMethod,
           &Service::StartVmHelper<StartPluginVmRequest, nullptr,
                                   &Service::StartPluginVm>},
          {kStartArcVmMethod,
           &Service::StartVmHelper<StartArcVmRequest,
                                   &Service::GetArcVmMemoryMiB,
                                   &Service::StartArcVm>},
      };

  if (!AsyncNoReject(
           dbus_thread_.task_runner(),
           base::BindOnce(
               [](Service* service, dbus::ExportedObject* exported_object_,
                  scoped_refptr<dbus::Bus> bus) {
                 for (const auto& iter : kServiceMethods) {
                   bool ret = exported_object_->ExportMethodAndBlock(
                       kVmConciergeInterface, iter.first,
                       base::Bind(
                           &HandleSynchronousDBusMethodCall,
                           base::Bind(iter.second, base::Unretained(service))));
                   if (!ret) {
                     LOG(ERROR) << "Failed to export method " << iter.first;
                     return false;
                   }
                 }
                 for (const auto& iter : kAsyncServiceMethods) {
                   bool ret = exported_object_->ExportMethodAndBlock(
                       kVmConciergeInterface, iter.first,
                       base::Bind(
                           &HandleAsynchronousDBusMethodCall,
                           base::Bind(iter.second, base::Unretained(service))));
                   if (!ret) {
                     LOG(ERROR)
                         << "Failed to export async method " << iter.first;
                     return false;
                   }
                 }

                 if (!bus->RequestOwnershipAndBlock(
                         kVmConciergeServiceName, dbus::Bus::REQUIRE_PRIMARY)) {
                   LOG(ERROR) << "Failed to take ownership of "
                              << kVmConciergeServiceName;
                   return false;
                 }

                 return true;
               },
               base::Unretained(this), base::Unretained(exported_object_),
               bus_))
           .Get()
           .val) {
    return false;
  }

  // Set up the D-Bus client for shill.
  shill_client_ = std::make_unique<ShillClient>(bus_);
  shill_client_->RegisterResolvConfigChangedHandler(base::Bind(
      &Service::OnResolvConfigChanged, weak_ptr_factory_.GetWeakPtr()));
  shill_client_->RegisterDefaultServiceChangedHandler(
      base::Bind(&Service::OnDefaultNetworkServiceChanged,
                 weak_ptr_factory_.GetWeakPtr()));

  // Set up the D-Bus client for powerd and register suspend/resume handlers.
  power_manager_client_ = std::make_unique<PowerManagerClient>(bus_);
  power_manager_client_->RegisterSuspendDelay(
      base::Bind(&Service::HandleSuspendImminent,
                 weak_ptr_factory_.GetWeakPtr()),
      base::Bind(&Service::HandleSuspendDone, weak_ptr_factory_.GetWeakPtr()));

  // Get the D-Bus proxy for communicating with cicerone.
  cicerone_service_proxy_ = bus_->GetObjectProxy(
      vm_tools::cicerone::kVmCiceroneServiceName,
      dbus::ObjectPath(vm_tools::cicerone::kVmCiceroneServicePath));
  if (!cicerone_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::cicerone::kVmCiceroneServiceName;
    return false;
  }
  cicerone_service_proxy_->ConnectToSignal(
      vm_tools::cicerone::kVmCiceroneServiceName,
      vm_tools::cicerone::kTremplinStartedSignal,
      base::Bind(&Service::OnTremplinStartedSignal,
                 weak_ptr_factory_.GetWeakPtr()),
      base::Bind(&Service::OnSignalConnected, weak_ptr_factory_.GetWeakPtr()));

  // Get the D-Bus proxy for communicating with seneschal.
  seneschal_service_proxy_ = bus_->GetObjectProxy(
      vm_tools::seneschal::kSeneschalServiceName,
      dbus::ObjectPath(vm_tools::seneschal::kSeneschalServicePath));
  if (!seneschal_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::seneschal::kSeneschalServiceName;
    return false;
  }

  // Get the D-Bus proxy for communicating with Plugin VM dispatcher.
  vm_permission_service_proxy_ = vm_permission::GetServiceProxy(bus_);
  if (!vm_permission_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for VM permission service";
    return false;
  }

  // Get the D-Bus proxy for communicating with Plugin VM dispatcher.
  vmplugin_service_proxy_ = pvm::dispatcher::GetServiceProxy(bus_);
  if (!vmplugin_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for Plugin VM dispatcher service";
    return false;
  }
  pvm::dispatcher::RegisterVmToolsChangedCallbacks(
      vmplugin_service_proxy_,
      base::Bind(&Service::OnVmToolsStateChangedSignal,
                 weak_ptr_factory_.GetWeakPtr()),
      base::Bind(&Service::OnSignalConnected, weak_ptr_factory_.GetWeakPtr()));

  // Get the D-Bus proxy for communicating with resource manager.
  resource_manager_service_proxy_ = bus_->GetObjectProxy(
      resource_manager::kResourceManagerServiceName,
      dbus::ObjectPath(resource_manager::kResourceManagerServicePath));
  if (!resource_manager_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << resource_manager::kResourceManagerServiceName;
    return false;
  }

  platform_features_ = feature::PlatformFeatures::New(bus_);

  // Setup & start the gRPC listener services.
  if (!SetupListenerService(
          &grpc_thread_vm_, &startup_listener_,
          base::StringPrintf("vsock:%u:%u", VMADDR_CID_ANY,
                             vm_tools::kDefaultStartupListenerPort),
          &grpc_server_vm_)) {
    LOG(ERROR) << "Failed to setup/startup the VM grpc server";
    return false;
  }

  if (!reclaim_thread_.Start()) {
    LOG(ERROR) << "Failed to start memory reclaim thread";
    return false;
  }

  balloon_resizing_timer_.Start(FROM_HERE, base::Seconds(1), this,
                                &Service::RunBalloonPolicy);

  if (USE_CROSVM_SIBLINGS) {
    auto dugong_client =
        std::make_unique<org::chromium::ManaTEEInterfaceProxy>(bus_);
    if (!dugong_client) {
      LOG(ERROR) << "Failed to connect to manatee client";
      return false;
    }

    base::ScopedFD fd =
        AsyncNoReject(
            dbus_thread_.task_runner(),
            base::BindOnce(
                [](std::unique_ptr<org::chromium::ManaTEEInterfaceProxy>
                       client) {
                  base::ScopedFD fd;
                  brillo::ErrorPtr err;
                  if (!client->GetManateeMemoryServiceSocket(&fd, &err)) {
                    LOG(ERROR) << "Failed to get manatee memory service socket "
                               << err->GetMessage();
                    return base::ScopedFD();
                  }
                  return fd;
                },
                std::move(dugong_client)))
            .Get()
            .val;
    if (!fd.is_valid()) {
      return false;
    }

    mms_ = ManateeMemoryService::Create(std::move(fd));
    if (!mms_) {
      LOG(ERROR) << "Failed to connect to manatee memory service";
      return false;
    }
  }

  return true;
}

void Service::HandleChildExit() {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  // We can't just rely on the information in the siginfo structure because
  // more than one child may have exited but only one SIGCHLD will be
  // generated.
  while (true) {
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    if (pid <= 0) {
      if (pid == -1 && errno != ECHILD) {
        PLOG(ERROR) << "Unable to reap child processes";
      }
      break;
    }

    if (WIFEXITED(status)) {
      if (WEXITSTATUS(status) != 0) {
        LOG(INFO) << "Process " << pid << " exited with status "
                  << WEXITSTATUS(status);
      }
    } else if (WIFSIGNALED(status)) {
      LOG(INFO) << "Process " << pid << " killed by signal " << WTERMSIG(status)
                << (WCOREDUMP(status) ? " (core dumped)" : "");
    } else {
      LOG(WARNING) << "Unknown exit status " << status << " for process "
                   << pid;
    }

    // See if this is a process we launched.
    auto iter = std::find_if(vms_.begin(), vms_.end(), [=](auto& pair) {
      VmInterface::Info info = pair.second->GetInfo();
      return pid == info.pid;
    });

    if (iter != vms_.end()) {
      if (USE_CROSVM_SIBLINGS) {
        // Notify HMS that the VM has exited.
        mms_->RemoveVm(iter->second->GetInfo().vm_memory_id);
      }

      // Notify that the VM has exited.
      NotifyVmStopped(iter->first, iter->second->GetInfo().cid, VM_EXITED);

      // Now remove it from the vm list.
      vms_.erase(iter);
    }
  }
}

void Service::HandleSigterm() {
  LOG(INFO) << "Shutting down due to SIGTERM";

  StopAllVmsImpl(SERVICE_SHUTDOWN);
  base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, quit_closure_);
}

StartVmResponse Service::StartVm(StartVmRequest request,
                                 std::unique_ptr<dbus::MessageReader> reader,
                                 VmMemoryId vm_memory_id) {
  LOG(INFO) << "Received StartVm request";
  StartVmResponse response;
  response.set_status(VM_STATUS_FAILURE);

  VmInfo::VmType classification = ClassifyVm(request);
  VmInfo* vm_info = response.mutable_vm_info();
  vm_info->set_vm_type(classification);

  base::Optional<base::ScopedFD> kernel_fd, rootfs_fd, initrd_fd, storage_fd,
      bios_fd;
  for (const auto& fdType : request.fds()) {
    base::ScopedFD fd;
    if (!reader->PopFileDescriptor(&fd)) {
      std::stringstream ss;
      ss << "failed to get a " << StartVmRequest_FdType_Name(fdType) << " FD";
      LOG(ERROR) << ss.str();
      response.set_failure_reason(ss.str());
      return response;
    }
    switch (fdType) {
      case StartVmRequest_FdType_KERNEL:
        kernel_fd = std::move(fd);
        break;
      case StartVmRequest_FdType_ROOTFS:
        rootfs_fd = std::move(fd);
        break;
      case StartVmRequest_FdType_INITRD:
        initrd_fd = std::move(fd);
        break;
      case StartVmRequest_FdType_STORAGE:
        storage_fd = std::move(fd);
        break;
      case StartVmRequest_FdType_BIOS:
        bios_fd = std::move(fd);
        break;
      default:
        LOG(WARNING) << "received request with unknown FD type " << fdType
                     << ". Ignoring.";
    }
  }

  // Make sure we have our signal connected if starting a Termina VM.
  if (classification == VmInfo::TERMINA &&
      !is_tremplin_started_signal_connected_) {
    LOG(ERROR) << "Can't start Termina VM without TremplinStartedSignal";
    response.set_failure_reason("TremplinStartedSignal not connected");
    return response;
  }

  if (request.disks_size() > kMaxExtraDisks) {
    LOG(ERROR) << "Rejecting request with " << request.disks_size()
               << " extra disks";
    response.set_failure_reason("Too many extra disks");
    return response;
  }

  // Exists just to keep FDs around for crosvm to inherit
  std::vector<brillo::SafeFD> owned_fds;
  auto root_fd = brillo::SafeFD::Root();

  if (brillo::SafeFD::IsError(root_fd.second)) {
    LOG(ERROR) << "Could not open root directory: "
               << static_cast<int>(root_fd.second);
    response.set_failure_reason("Could not open root directory");
    return response;
  }

  string failure_reason;
  VMImageSpec image_spec =
      GetImageSpec(request.vm(), kernel_fd, rootfs_fd, initrd_fd, bios_fd,
                   classification == VmInfo::TERMINA, &failure_reason);
  if (!failure_reason.empty()) {
    LOG(ERROR) << "Failed to get image paths: " << failure_reason;
    response.set_failure_reason("Failed to get image paths: " + failure_reason);
    return response;
  }

  if (!image_spec.kernel.empty()) {
    failure_reason = ConvertToFdBasedPath(root_fd.first, &image_spec.kernel,
                                          O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Missing VM kernel path: " << image_spec.kernel.value();
      response.set_failure_reason("Kernel path does not exist");
      return response;
    }
  }

  if (!image_spec.bios.empty()) {
    failure_reason = ConvertToFdBasedPath(root_fd.first, &image_spec.bios,
                                          O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Missing VM BIOS path: " << image_spec.bios.value();
      response.set_failure_reason("BIOS path does not exist");
      return response;
    }
  }

  if (image_spec.kernel.empty() && image_spec.bios.empty()) {
    LOG(ERROR) << "neither a kernel nor a BIOS were provided";
    response.set_failure_reason("neither a kernel nor a BIOS were provided");
    return response;
  }

  if (!image_spec.initrd.empty()) {
    failure_reason = ConvertToFdBasedPath(root_fd.first, &image_spec.initrd,
                                          O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Missing VM initrd path: " << image_spec.initrd.value();
      response.set_failure_reason("Initrd path does not exist");
      return response;
    }
  }

  if (!image_spec.rootfs.empty()) {
    failure_reason = ConvertToFdBasedPath(
        root_fd.first, &image_spec.rootfs,
        request.writable_rootfs() ? O_RDWR : O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Missing VM rootfs path: " << image_spec.rootfs.value();
      response.set_failure_reason("Rootfs path does not exist");
      return response;
    }
  }

  const bool is_untrusted_vm =
      IsUntrustedVM(request.run_as_untrusted(), image_spec.is_trusted_image,
                    !request.kernel_params().empty(), host_kernel_version_);
  if (is_untrusted_vm) {
    const auto untrusted_vm_check_result =
        IsUntrustedVMAllowed(request.run_as_untrusted(), host_kernel_version_);
    if (!untrusted_vm_check_result.untrusted_vm_allowed) {
      std::stringstream ss;
      ss << "Untrusted VMs are not allowed: "
         << "the host kernel version (" << host_kernel_version_.first << "."
         << host_kernel_version_.second << ") must be newer than or equal to "
         << kMinKernelVersionForUntrustedAndNestedVM.first << "."
         << kMinKernelVersionForUntrustedAndNestedVM.second
         << ", or the device must be in the developer mode";
      LOG(ERROR) << ss.str();
      response.set_failure_reason(ss.str());
      return response;
    }

    // For untrusted VMs -
    // Check if l1tf and mds mitigations are present on the host. Skip the
    // checks if untrusted VMs are requested in developer mode on insecure
    // kernels. This is done to support testing by developers.
    if (!untrusted_vm_check_result.skip_host_checks) {
      switch (untrusted_vm_utils_->CheckUntrustedVMMitigationStatus()) {
        // If the host kernel version isn't supported or the host doesn't have
        // l1tf and mds mitigations then fail to start an untrusted VM.
        case UntrustedVMUtils::MitigationStatus::VULNERABLE: {
          LOG(ERROR) << "Host vulnerable against untrusted VM";
          response.set_failure_reason("Host vulnerable against untrusted VM");
          return response;
        }

        // At this point SMT should not be a security issue. As
        // |kMinKernelVersionForUntrustedAndNestedVM| has security patches to
        // make nested VMs co-exist securely with SMT.
        case UntrustedVMUtils::MitigationStatus::VULNERABLE_DUE_TO_SMT_ENABLED:
        case UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE:
          break;
      }
    }
  }

  // Track the next available virtio-blk device name.
  // Assume that the rootfs filesystem was assigned /dev/pmem0 if
  // pmem is used, /dev/vda otherwise.
  // Assume every subsequent image was assigned a letter in alphabetical order
  // starting from 'b'.
  bool use_pmem = host_kernel_version_ >= kMinKernelVersionForVirtioPmem &&
                  USE_PMEM_DEVICE_FOR_ROOTFS;
  string rootfs_device = use_pmem ? "/dev/pmem0" : "/dev/vda";
  unsigned char disk_letter = use_pmem ? 'a' : 'b';
  std::vector<Disk> disks;

  // In newer components, the /opt/google/cros-containers directory
  // is split into its own disk image(vm_tools.img).  Detect whether it exists
  // to keep compatibility with older components with only vm_rootfs.img.
  string tools_device;
  if (base::PathExists(image_spec.tools_disk)) {
    failure_reason = ConvertToFdBasedPath(root_fd.first, &image_spec.tools_disk,
                                          O_RDONLY, owned_fds);
    if (!failure_reason.empty()) {
      LOG(ERROR) << "Could not open tools_disk file";
      response.set_failure_reason(failure_reason);
      return response;
    }
    disks.push_back(
        Disk(std::move(image_spec.tools_disk), false /* writable */));
    tools_device = base::StringPrintf("/dev/vd%c", disk_letter++);
  }

  if (request.disks().size() == 0) {
    LOG(ERROR) << "Missing required stateful disk";
    response.set_failure_reason("Missing required stateful disk");
    return response;
  }

  // Assume the stateful device is the first disk in the request.
  string stateful_device = base::StringPrintf("/dev/vd%c", disk_letter);

  auto stateful_path = base::FilePath(request.disks()[0].path());
  int64_t stateful_size = -1;
  if (!base::GetFileSize(stateful_path, &stateful_size)) {
    LOG(ERROR) << "Could not determine stateful disk size";
    response.set_failure_reason(
        "Internal error: unable to determine stateful disk size");
    return response;
  }

  for (const auto& disk : request.disks()) {
    Disk::Config config{};
    config.writable = disk.writable();
    config.sparse = !IsDiskUserChosenSize(disk.path());

    auto path = base::FilePath(disk.path());
    failure_reason = ConvertToFdBasedPath(
        root_fd.first, &path, config.writable ? O_RDWR : O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Could not open disk file";
      response.set_failure_reason(failure_reason);
      return response;
    }

    disks.push_back(Disk(path, config));
  }

  // Check if an opened storage image was passed over D-BUS.
  if (storage_fd.has_value()) {
    // We only allow untrusted VMs to mount extra storage.
    if (!is_untrusted_vm) {
      LOG(ERROR) << "storage fd passed for a trusted VM";

      response.set_failure_reason("storage fd is passed for a trusted VM");
      return response;
    }

    int raw_fd = storage_fd.value().get();
    string failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason.empty()) {
      LOG(ERROR) << "failed to remove close-on-exec flag: " << failure_reason;
      response.set_failure_reason(
          "failed to get a path for extra storage disk: " + failure_reason);
      return response;
    }

    disks.push_back(Disk(base::FilePath(kProcFileDescriptorsPath)
                             .Append(base::NumberToString(raw_fd)),
                         true /* writable */));
  }

  // Create the runtime directory.
  base::FilePath runtime_dir;
  if (!base::CreateTemporaryDirInDir(base::FilePath(kRuntimeDir), "vm.",
                                     &runtime_dir)) {
    PLOG(ERROR) << "Unable to create runtime directory for VM";

    response.set_failure_reason(
        "Internal error: unable to create runtime directory");
    return response;
  }

  if (request.name().size() > kMaxVmNameLength) {
    LOG(ERROR) << "VM name is too long";

    response.set_failure_reason("VM name is too long");
    return response;
  }
  base::FilePath log_path = GetVmLogPath(request.owner_id(), request.name());

  if (request.enable_vulkan() && !request.enable_gpu()) {
    LOG(ERROR) << "Vulkan enabled without GPU";
    response.set_failure_reason("Vulkan enabled without GPU");
    return response;
  }

  if (request.enable_big_gl() && !request.enable_gpu()) {
    LOG(ERROR) << "Big GL enabled without GPU";
    response.set_failure_reason("Big GL enabled without GPU");
    return response;
  }

  // Enable the render server for Vulkan.
  const bool enable_render_server = request.enable_vulkan();

  VMGpuCacheSpec gpu_cache_spec;
  if (request.enable_gpu()) {
    gpu_cache_spec = PrepareVmGpuCachePaths(request.owner_id(), request.name(),
                                            enable_render_server);
  }

  // Allocate resources for the VM.
  uint32_t vsock_cid = vsock_cid_pool_.Allocate();
  if (vsock_cid == 0) {
    LOG(ERROR) << "Unable to allocate vsock context id";

    response.set_failure_reason("Unable to allocate vsock cid");
    return response;
  }
  vm_info->set_cid(vsock_cid);

  std::unique_ptr<patchpanel::Client> network_client =
      patchpanel::Client::New(bus_);
  if (!network_client) {
    LOG(ERROR) << "Unable to open networking service client";

    response.set_failure_reason("Unable to open network service client");
    return response;
  }

  uint32_t seneschal_server_port = next_seneschal_server_port_++;
  std::unique_ptr<SeneschalServerProxy> server_proxy =
      SeneschalServerProxy::CreateVsockProxy(bus_, seneschal_service_proxy_,
                                             seneschal_server_port, vsock_cid,
                                             {}, {});
  if (!server_proxy) {
    LOG(ERROR) << "Unable to start shared directory server";

    response.set_failure_reason("Unable to start shared directory server");
    return response;
  }

  uint32_t seneschal_server_handle = server_proxy->handle();
  vm_info->set_seneschal_server_handle(seneschal_server_handle);

  // Associate a WaitableEvent with this VM.  This needs to happen before
  // starting the VM to avoid a race where the VM reports that it's ready
  // before it gets added as a pending VM.
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  startup_listener_.AddPendingVm(vsock_cid, &event);

  // Start the VM and build the response.
  VmFeatures features{
      .gpu = request.enable_gpu(),
      .vulkan = request.enable_vulkan(),
      .big_gl = request.enable_big_gl(),
      .render_server = enable_render_server,
      .software_tpm = request.software_tpm(),
      .audio_capture = request.enable_audio_capture(),
  };

  std::vector<std::string> params(
      std::make_move_iterator(request.mutable_kernel_params()->begin()),
      std::make_move_iterator(request.mutable_kernel_params()->end()));
  features.kernel_params = std::move(params);

  // We use _SC_NPROCESSORS_ONLN here rather than
  // base::SysInfo::NumberOfProcessors() so that offline CPUs are not counted.
  // Also, |untrusted_vm_utils_| may disable SMT leading to cores being
  // disabled. Hence, only allocate the lower of (available cores, cpus
  // allocated by the user).
  const int32_t cpus =
      request.cpus() == 0
          ? sysconf(_SC_NPROCESSORS_ONLN)
          : std::min(static_cast<int32_t>(sysconf(_SC_NPROCESSORS_ONLN)),
                     static_cast<int32_t>(request.cpus()));

  // Notify VmLogForwarder that a vm is starting up.
  VmId vm_id(request.owner_id(), request.name());
  SendVmStartingUpSignal(vm_id, *vm_info);

  VmBuilder vm_builder;
  vm_builder.SetKernel(std::move(image_spec.kernel))
      .SetBios(std::move(image_spec.bios))
      .SetInitrd(std::move(image_spec.initrd))
      .SetCpus(cpus)
      .AppendDisks(std::move(disks))
      .EnableSmt(false /* enable */)
      .SetGpuCachePath(std::move(gpu_cache_spec.device))
      .SetRenderServerCachePath(std::move(gpu_cache_spec.render_server));
  if (!image_spec.rootfs.empty()) {
    vm_builder.SetRootfs({.device = std::move(rootfs_device),
                          .path = std::move(image_spec.rootfs),
                          .writable = request.writable_rootfs()});
  }

  if (request.vm().wayland_server().empty()) {
    std::string wayland_server =
        vm_launch_interface_->GetWaylandSocketForVm(vm_id, classification);
    // Prevent certain VMs from running without a secure server.
    //
    // TODO(b/212636975): All VMs should use this, not just special ones.
    if (classification == VmInfo::BOREALIS && wayland_server.empty()) {
      response.set_failure_reason(
          "Borealis VMs must have a secure wayland server. Likely borealis is "
          "disabled.");
      LOG(ERROR) << response.failure_reason();
      return response;
    }
    vm_builder.SetWaylandSocket(std::move(wayland_server));
  } else {
    vm_builder.SetWaylandSocket(request.vm().wayland_server());
  }

  // Group the CPUs by their physical package ID to determine CPU cluster
  // layout.
  std::vector<std::vector<std::string>> cpu_clusters;
  std::map<int32_t, std::vector<std::string>> cpu_capacity_groups;
  std::vector<std::string> cpu_capacity;
  for (int32_t cpu = 0; cpu < cpus; cpu++) {
    auto physical_package_id = GetCpuPackageId(cpu);
    if (physical_package_id) {
      CHECK_GE(*physical_package_id, 0);
      if (*physical_package_id + 1 > cpu_clusters.size())
        cpu_clusters.resize(*physical_package_id + 1);
      cpu_clusters[*physical_package_id].push_back(std::to_string(cpu));
    }

    auto capacity = GetCpuCapacity(cpu);
    if (capacity) {
      CHECK_GE(*capacity, 0);
      cpu_capacity.push_back(base::StringPrintf("%d=%d", cpu, *capacity));
      auto group = cpu_capacity_groups.find(*capacity);
      if (group != cpu_capacity_groups.end()) {
        group->second.push_back(std::to_string(cpu));
      } else {
        auto g = {std::to_string(cpu)};
        cpu_capacity_groups.insert({*capacity, g});
      }
    }
  }

  base::Optional<std::string> cpu_affinity =
      GetCpuAffinityFromClusters(cpu_clusters, cpu_capacity_groups);
  if (cpu_affinity) {
    vm_builder.AppendCustomParam("--cpu-affinity", *cpu_affinity);
  }

  if (!cpu_capacity.empty()) {
    vm_builder.AppendCustomParam("--cpu-capacity",
                                 base::JoinString(cpu_capacity, ","));
  }

  if (!cpu_clusters.empty()) {
    for (const auto& cluster : cpu_clusters) {
      auto cpu_list = base::JoinString(cluster, ",");
      vm_builder.AppendCustomParam("--cpu-cluster", cpu_list);
    }
  }

  if (USE_CROSVM_SIBLINGS) {
    vm_builder.SetVmMemoryId(vm_memory_id);
  }

  auto vm = TerminaVm::Create(
      vsock_cid, std::move(network_client), std::move(server_proxy),
      std::move(runtime_dir), vm_memory_id, std::move(log_path),
      std::move(stateful_device), std::move(stateful_size),
      GetVmMemoryMiB(request), features, vm_permission_service_proxy_, bus_,
      vm_id, classification, std::move(vm_builder));
  if (!vm) {
    LOG(ERROR) << "Unable to start VM";

    startup_listener_.RemovePendingVm(vsock_cid);
    response.set_failure_reason("Unable to start VM");
    return response;
  }

  // Wait for the VM to finish starting up and for maitre'd to signal that it's
  // ready.
  base::TimeDelta timeout = kVmStartupDefaultTimeout;
  if (request.timeout() != 0) {
    timeout = base::Seconds(request.timeout());
  }
  if (!event.TimedWait(timeout)) {
    LOG(ERROR) << "VM failed to start in " << timeout.InSeconds() << " seconds";

    startup_listener_.RemovePendingVm(vsock_cid);
    response.set_failure_reason("VM failed to start in time");
    return response;
  }

  // maitre'd is ready.  Finish setting up the VM.
  if (!vm->ConfigureNetwork(nameservers_, search_domains_)) {
    LOG(ERROR) << "Failed to configure VM network";

    response.set_failure_reason("Failed to configure VM network");
    return response;
  }

  // Mount the tools disk if it exists.
  if (!tools_device.empty()) {
    if (!vm->Mount(tools_device, kToolsMountPath, kToolsFsType, MS_RDONLY,
                   "")) {
      LOG(ERROR) << "Failed to mount tools disk";
      response.set_failure_reason("Failed to mount tools disk");
      return response;
    }
  }

  // Do all the mounts.
  for (const auto& disk : request.disks()) {
    string src = base::StringPrintf("/dev/vd%c", disk_letter++);

    if (!disk.do_mount())
      continue;

    uint64_t flags = disk.flags();
    if (!disk.writable()) {
      flags |= MS_RDONLY;
    }
    if (!vm->Mount(std::move(src), disk.mount_point(), disk.fstype(), flags,
                   disk.data())) {
      LOG(ERROR) << "Failed to mount " << disk.path() << " -> "
                 << disk.mount_point();

      response.set_failure_reason("Failed to mount extra disk");
      return response;
    }
  }

  // Mount the 9p server.
  if (!vm->Mount9P(seneschal_server_port, "/mnt/shared")) {
    LOG(ERROR) << "Failed to mount shared directory";

    response.set_failure_reason("Failed to mount shared directory");
    return response;
  }

  // Determine the VM token. Termina doesnt use a VM token because it has
  // per-container tokens.
  std::string vm_token = "";
  if (!request.start_termina())
    vm_token = base::GenerateGUID();

  // Notify cicerone that we have started a VM.
  // We must notify cicerone now before calling StartTermina, but we will only
  // send the VmStartedSignal on success.
  NotifyCiceroneOfVmStarted(vm_id, vm->cid(), vm->GetInfo().pid, vm_token);

  vm_tools::StartTerminaResponse::MountResult mount_result =
      vm_tools::StartTerminaResponse::UNKNOWN;
  int64_t free_bytes = -1;
  // Allow untrusted VMs to have privileged containers.
  if (request.start_termina() &&
      !StartTermina(vm.get(), is_untrusted_vm /* allow_privileged_containers */,
                    request.features(), &failure_reason, &mount_result,
                    &free_bytes)) {
    response.set_failure_reason(std::move(failure_reason));
    response.set_mount_result((StartVmResponse::MountResult)mount_result);
    return response;
  }
  response.set_mount_result((StartVmResponse::MountResult)mount_result);
  if (free_bytes >= 0) {
    response.set_free_bytes(free_bytes);
    response.set_free_bytes_has_value(true);
  }

  if (!vm_token.empty() &&
      !vm->ConfigureContainerGuest(vm_token, &failure_reason)) {
    failure_reason =
        "Failed to configure the container guest: " + failure_reason;
    // TODO(b/162562622): This request is temporarily non-fatal. Once we are
    // satisfied that the maitred changes have been completed, we will make this
    // failure fatal.
    LOG(WARNING) << failure_reason;
  }

  LOG(INFO) << "Started VM with pid " << vm->pid();

  // Mount an extra disk in the VM. We mount them after calling StartTermina
  // because /mnt/external is set up there.
  if (storage_fd.has_value()) {
    const string external_disk_path =
        base::StringPrintf("/dev/vd%c", disk_letter++);

    // To support multiple extra disks in the future easily, we use integers for
    // names of mount points. Since we support only one extra disk for now,
    // |target_dir| is always "0".
    if (!vm->MountExternalDisk(std::move(external_disk_path),
                               /* target_dir= */ "0")) {
      LOG(ERROR) << "Failed to mount " << external_disk_path;

      response.set_failure_reason("Failed to mount extra disk");
      return response;
    }
  }

  response.set_success(true);
  response.set_status(request.start_termina() ? VM_STATUS_STARTING
                                              : VM_STATUS_RUNNING);
  vm_info->set_ipv4_address(vm->IPv4Address());
  vm_info->set_pid(vm->pid());
  vm_info->set_permission_token(vm->PermissionToken());

  SendVmStartedSignal(vm_id, *vm_info, response.status());

  vms_[vm_id] = std::move(vm);
  return response;
}

int64_t Service::GetVmMemoryMiB(const StartVmRequest& request) {
  return ::vm_tools::concierge::GetVmMemoryMiB();
}

std::unique_ptr<dbus::Response> Service::StopVm(dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received StopVm request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  StopVmRequest request;
  StopVmResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse StopVmRequest from message";

    response.set_failure_reason("Unable to parse protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  VmId vm_id(request.owner_id(), request.name());

  if (!StopVm(vm_id, STOP_VM_REQUESTED)) {
    LOG(ERROR) << "Unable to shut down VM";
    response.set_failure_reason("Unable to shut down VM");
  } else {
    response.set_success(true);
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

bool Service::StopVm(const VmId& vm_id, VmStopReason reason) {
  auto iter = FindVm(vm_id);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    // This is not an error to Chrome
    return true;
  }

  // Notify that we are about to stop a VM.
  NotifyVmStopping(iter->first, iter->second->GetInfo().cid);

  if (!iter->second->Shutdown()) {
    return false;
  }

  if (USE_CROSVM_SIBLINGS) {
    mms_->RemoveVm(iter->second->GetInfo().vm_memory_id);
  }

  // Notify that we have stopped a VM.
  NotifyVmStopped(iter->first, iter->second->GetInfo().cid, reason);

  vms_.erase(iter);
  return true;
}

// Wrapper to destroy VM in another thread
class VMDelegate : public base::PlatformThread::Delegate {
 public:
  VMDelegate() = default;
  ~VMDelegate() override = default;
  VMDelegate& operator=(VMDelegate&& other) = default;
  explicit VMDelegate(const Service&) = delete;
  VMDelegate& operator=(const Service&) = delete;
  explicit VMDelegate(std::unique_ptr<VmInterface> vm) : vm_(std::move(vm)) {}
  void ThreadMain() override { vm_.reset(); }

 private:
  std::unique_ptr<VmInterface> vm_;
};

std::unique_ptr<dbus::Response> Service::StopAllVms(
    dbus::MethodCall* method_call) {
  StopAllVmsImpl(STOP_ALL_VMS_REQUESTED);
  return nullptr;
}

void Service::StopAllVmsImpl(VmStopReason reason) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received StopAllVms request";

  struct ThreadContext {
    base::PlatformThreadHandle handle;
    uint32_t cid;
    base::Optional<uint32_t> vm_memory_id;
    VMDelegate delegate;
  };
  std::vector<ThreadContext> ctxs(vms_.size());

  // Spawn a thread for each VM to shut it down.
  int i = 0;
  for (auto& iter : vms_) {
    ThreadContext& ctx = ctxs[i++];

    // Copy out cid from the VM object, as we will need it after the VM has been
    // destroyed.
    ctx.cid = iter.second->GetInfo().cid;
    ctx.vm_memory_id = iter.second->GetInfo().vm_memory_id;

    // Notify that we are about to stop a VM.
    NotifyVmStopping(iter.first, ctx.cid);

    // The VM will be destructred in the new thread, stopping it normally (and
    // then forcibly) it if it hasn't stopped yet.
    //
    // Would you just take a lambda function? Why do we need the Delegate?...
    ctx.delegate = VMDelegate(std::move(iter.second));
    base::PlatformThread::Create(0, &ctx.delegate, &ctx.handle);
  }

  i = 0;
  for (auto& iter : vms_) {
    ThreadContext& ctx = ctxs[i++];
    base::PlatformThread::Join(ctx.handle);

    if (USE_CROSVM_SIBLINGS) {
      // Notify HMS that the VM has exited.
      mms_->RemoveVm(*ctx.vm_memory_id);
    }

    // Notify that we have stopped a VM.
    NotifyVmStopped(iter.first, ctx.cid, reason);
  }

  vms_.clear();

  if (!ctxs.empty()) {
    LOG(INFO) << "Stopped all Vms";
  }
}

std::unique_ptr<dbus::Response> Service::SuspendVm(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received SuspendVm request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  SuspendVmRequest request;
  SuspendVmResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse SuspendVmRequest from message";

    response.set_failure_reason("Unable to parse protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    // This is not an error to Chrome
    response.set_success(true);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto& vm = iter->second;
  if (!vm->UsesExternalSuspendSignals()) {
    LOG(ERROR) << "Received D-Bus suspend request for " << iter->first
               << " but it does not use external suspend signals.";

    response.set_failure_reason(
        "VM does not support external suspend signals.");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  vm->Suspend();

  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);

  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ResumeVm(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ResumeVm request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ResumeVmRequest request;
  ResumeVmResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ResumeVmRequest from message";

    response.set_failure_reason("Unable to parse protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    // This is not an error to Chrome
    response.set_success(true);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto& vm = iter->second;
  if (!vm->UsesExternalSuspendSignals()) {
    LOG(ERROR) << "Received D-Bus resume request for " << iter->first
               << " but it does not use external suspend signals.";

    response.set_failure_reason(
        "VM does not support external suspend signals.");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  vm->Resume();

  string failure_reason;
  if (vm->SetTime(&failure_reason)) {
    LOG(INFO) << "Successfully set VM clock in " << iter->first << ".";
  } else {
    LOG(ERROR) << "Failed to set VM clock in " << iter->first << ": "
               << failure_reason;
  }

  vm->SetResolvConfig(nameservers_, search_domains_);

  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);

  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::GetVmInfo(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received GetVmInfo request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  GetVmInfoRequest request;
  GetVmInfoResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse GetVmInfoRequest from message";

    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";

    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VmInterface::Info vm = iter->second->GetInfo();

  VmInfo* vm_info = response.mutable_vm_info();
  vm_info->set_ipv4_address(vm.ipv4_address);
  vm_info->set_pid(vm.pid);
  vm_info->set_cid(vm.cid);
  vm_info->set_seneschal_server_handle(vm.seneschal_server_handle);
  vm_info->set_permission_token(vm.permission_token);
  vm_info->set_vm_type(vm.type);

  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);

  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::GetVmEnterpriseReportingInfo(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received GetVmEnterpriseReportingInfo request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  GetVmEnterpriseReportingInfoRequest request;
  GetVmEnterpriseReportingInfoResponse response;

  response.set_success(false);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    const std::string error_message =
        "Unable to parse GetVmEnterpriseReportingInfo from message";
    LOG(ERROR) << error_message;
    response.set_failure_reason(error_message);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto iter = FindVm(request.owner_id(), request.vm_name());
  if (iter == vms_.end()) {
    const std::string error_message = "Requested VM does not exist";
    LOG(ERROR) << error_message;
    response.set_failure_reason(error_message);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // failure_reason and success will be set by GetVmEnterpriseReportingInfo.
  if (!iter->second->GetVmEnterpriseReportingInfo(&response)) {
    LOG(ERROR) << "Failed to get VM enterprise reporting info";
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

// Performs necessary steps to complete the boot of the VM.
// Returns true on success, or false if the VM does not exist.
bool Service::OnVmBootComplete(const std::string& owner_id,
                               const std::string& name) {
  auto iter = FindVm(owner_id, name);
  if (iter == vms_.end()) {
    return false;
  }

  // Create the RT v-Cpu for the VM now that boot is complete
  auto& vm = iter->second;
  vm->MakeRtVcpu();

  return true;
}

std::unique_ptr<dbus::Response> Service::ArcVmCompleteBoot(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ArcVmCompleteBoot request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ArcVmCompleteBootRequest request;
  ArcVmCompleteBootResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ArcVmCompleteBootRequest from message";
    response.set_result(ArcVmCompleteBootResult::BAD_REQUEST);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (!OnVmBootComplete(request.owner_id(), kArcVmName)) {
    LOG(ERROR) << "Unable to locate ArcVm instance";
    response.set_result(ArcVmCompleteBootResult::ARCVM_NOT_FOUND);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  response.set_result(ArcVmCompleteBootResult::SUCCESS);
  writer.AppendProtoAsArrayOfBytes(response);

  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::AdjustVm(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received AdjustVm request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  AdjustVmRequest request;
  AdjustVmResponse response;

  response.set_success(false);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    const std::string error_message =
        "Unable to parse AdjustVmRequest from message";
    LOG(ERROR) << error_message;
    response.set_failure_reason(error_message);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  StorageLocation location;
  if (!CheckVmExists(request.name(), request.owner_id(), nullptr, &location)) {
    response.set_failure_reason("Requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::vector<string> params(
      std::make_move_iterator(request.mutable_params()->begin()),
      std::make_move_iterator(request.mutable_params()->end()));

  string failure_reason;
  bool success = false;
  if (request.operation() == "pvm.shared-profile") {
    if (location != STORAGE_CRYPTOHOME_PLUGINVM) {
      failure_reason = "Operation is not supported for the VM";
    } else {
      success = pvm::helper::ToggleSharedProfile(
          bus_, vmplugin_service_proxy_,
          VmId(request.owner_id(), request.name()), std::move(params),
          &failure_reason);
    }
  } else if (request.operation() == "memsize") {
    if (params.size() != 1) {
      failure_reason = "Incorrect number of arguments for 'memsize' operation";
    } else if (location != STORAGE_CRYPTOHOME_PLUGINVM) {
      failure_reason = "Operation is not supported for the VM";
    } else {
      success =
          pvm::helper::SetMemorySize(bus_, vmplugin_service_proxy_,
                                     VmId(request.owner_id(), request.name()),
                                     std::move(params), &failure_reason);
    }
  } else if (request.operation() == "rename") {
    if (params.size() != 1) {
      failure_reason = "Incorrect number of arguments for 'rename' operation";
    } else if (params[0].empty()) {
      failure_reason = "New name can not be empty";
    } else if (CheckVmExists(params[0], request.owner_id())) {
      failure_reason = "VM with such name already exists";
    } else if (location != STORAGE_CRYPTOHOME_PLUGINVM) {
      failure_reason = "Operation is not supported for the VM";
    } else {
      success = RenamePluginVm(request.owner_id(), request.name(), params[0],
                               &failure_reason);
    }
  } else {
    failure_reason = "Unrecognized operation";
  }

  response.set_success(success);
  response.set_failure_reason(failure_reason);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::SyncVmTimes(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received SyncVmTimes request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageWriter writer(dbus_response.get());

  SyncVmTimesResponse response;
  int failures = 0;
  int requests = 0;
  for (auto& vm_entry : vms_) {
    requests++;
    string failure_reason;
    if (!vm_entry.second->SetTime(&failure_reason)) {
      failures++;
      response.add_failure_reason(std::move(failure_reason));
    }
  }
  response.set_requests(requests);
  response.set_failures(failures);

  writer.AppendProtoAsArrayOfBytes(response);

  return dbus_response;
}

bool Service::StartTermina(TerminaVm* vm,
                           bool allow_privileged_containers,
                           const google::protobuf::RepeatedField<int>& features,
                           string* failure_reason,
                           vm_tools::StartTerminaResponse::MountResult* result,
                           int64_t* out_free_bytes) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  DCHECK(result);
  LOG(INFO) << "Starting Termina-specific services";

  std::string dst_addr;
  IPv4AddressToString(vm->ContainerSubnet(), &dst_addr);
  size_t prefix_length = vm->ContainerPrefixLength();

  std::string container_subnet_cidr =
      base::StringPrintf("%s/%zu", dst_addr.c_str(), prefix_length);

  string error;
  vm_tools::StartTerminaResponse response;
  if (!vm->StartTermina(std::move(container_subnet_cidr),
                        allow_privileged_containers, features, &error,
                        &response)) {
    failure_reason->assign(error);
    return false;
  }

  if (response.mount_result() ==
      vm_tools::StartTerminaResponse::PARTIAL_DATA_LOSS) {
    LOG(ERROR) << "Possible data loss from filesystem corruption detected";
  }

  *result = response.mount_result();
  if (response.free_bytes_has_value()) {
    *out_free_bytes = response.free_bytes();
  }

  return true;
}

std::unique_ptr<dbus::Response> Service::CreateDiskImage(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received CreateDiskImage request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  CreateDiskImageRequest request;
  CreateDiskImageResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse CreateDiskImageRequest from message";
    response.set_status(DISK_STATUS_FAILED);
    response.set_failure_reason("Unable to parse CreateImageDiskRequest");

    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  base::FilePath disk_path;
  StorageLocation disk_location;
  if (CheckVmExists(request.vm_name(), request.cryptohome_id(), &disk_path,
                    &disk_location)) {
    if (disk_location != request.storage_location()) {
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason(
          "VM/disk with same name already exists in another storage location");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }

    if (disk_location == STORAGE_CRYPTOHOME_PLUGINVM) {
      // We do not support extending Plugin VM images.
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Plugin VM with such name already exists");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }

    struct stat st;
    if (stat(disk_path.value().c_str(), &st) < 0) {
      PLOG(ERROR) << "stat() of existing VM image failed for "
                  << disk_path.value();
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason(
          "internal error: image exists but stat() failed");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }

    uint64_t current_size = st.st_size;
    uint64_t current_usage = st.st_blocks * 512ull;
    LOG(INFO) << "Found existing disk at " << disk_path.value()
              << " with current size " << current_size << " and usage "
              << current_usage;

    // Automatically extend existing disk images if disk_size was not specified.
    if (request.disk_size() == 0) {
      // If the user.crostini.user_chosen_size xattr exists, don't resize the
      // disk. (The value stored in the xattr is ignored; only its existence
      // matters.)
      if (IsDiskUserChosenSize(disk_path.value())) {
        LOG(INFO) << "Disk image has " << kDiskImageUserChosenSizeXattr
                  << " xattr - keeping existing size " << current_size;
      } else {
        uint64_t disk_size = CalculateDesiredDiskSize(disk_path, current_usage);
        if (disk_size > current_size) {
          LOG(INFO) << "Expanding disk image from " << current_size << " to "
                    << disk_size;
          if (expand_disk_image(disk_path.value().c_str(), disk_size) != 0) {
            // If expanding the disk failed, continue with a warning.
            // Currently, raw images can be resized, and qcow2 images cannot.
            LOG(WARNING) << "Failed to expand disk image " << disk_path.value();
          }
        } else {
          LOG(INFO) << "Current size " << current_size
                    << " is already at least requested size " << disk_size
                    << " - not expanding";
        }
      }
    }

    response.set_status(DISK_STATUS_EXISTS);
    response.set_disk_path(disk_path.value());
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (!GetDiskPathFromName(request.vm_name(), request.cryptohome_id(),
                           request.storage_location(),
                           true, /* create_parent_dir */
                           &disk_path, request.image_type())) {
    response.set_status(DISK_STATUS_FAILED);
    response.set_failure_reason("Failed to create vm image");
    writer.AppendProtoAsArrayOfBytes(response);

    return dbus_response;
  }

  if (request.storage_location() == STORAGE_CRYPTOHOME_PLUGINVM) {
    // Get the FD to fill with disk image data.
    base::ScopedFD in_fd;
    if (!reader.PopFileDescriptor(&in_fd)) {
      LOG(ERROR) << "CreateDiskImage: no fd found";
      response.set_failure_reason("no source fd found");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }

    // Get the name of directory for ISO images. Do not create it - it will be
    // created by the PluginVmCreateOperation code.
    base::FilePath iso_dir;
    if (!GetPluginIsoDirectory(request.vm_name(), request.cryptohome_id(),
                               false /* create */, &iso_dir)) {
      LOG(ERROR) << "Unable to determine directory for ISOs";

      response.set_failure_reason("Unable to determine ISO directory");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }

    std::vector<string> params(
        std::make_move_iterator(request.mutable_params()->begin()),
        std::make_move_iterator(request.mutable_params()->end()));

    auto op = PluginVmCreateOperation::Create(
        std::move(in_fd), iso_dir, request.source_size(),
        VmId(request.cryptohome_id(), request.vm_name()), std::move(params));

    response.set_disk_path(disk_path.value());
    response.set_status(op->status());
    response.set_command_uuid(op->uuid());
    response.set_failure_reason(op->failure_reason());

    if (op->status() == DISK_STATUS_IN_PROGRESS) {
      std::string uuid = op->uuid();
      disk_image_ops_.emplace_back(DiskOpInfo(std::move(op)));
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE,
          base::Bind(&Service::RunDiskImageOperation,
                     weak_ptr_factory_.GetWeakPtr(), std::move(uuid)));
    }

    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  uint64_t disk_size = request.disk_size()
                           ? request.disk_size()
                           : CalculateDesiredDiskSize(disk_path, 0);

  if (request.image_type() == DISK_IMAGE_RAW ||
      request.image_type() == DISK_IMAGE_AUTO) {
    LOG(INFO) << "Creating raw disk at: " << disk_path.value() << " size "
              << disk_size;
    base::ScopedFD fd(
        open(disk_path.value().c_str(), O_CREAT | O_NONBLOCK | O_WRONLY, 0600));
    if (!fd.is_valid()) {
      PLOG(ERROR) << "Failed to create raw disk";
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Failed to create raw disk file");
      writer.AppendProtoAsArrayOfBytes(response);

      return dbus_response;
    }

    if (request.disk_size() != 0) {
      LOG(INFO)
          << "Disk size specified in request; creating user-chosen-size image";
      if (!SetUserChosenSizeAttr(fd)) {
        PLOG(ERROR) << "Failed to set user_chosen_size xattr";
        unlink(disk_path.value().c_str());
        response.set_status(DISK_STATUS_FAILED);
        response.set_failure_reason("Failed to set user_chosen_size xattr");
        writer.AppendProtoAsArrayOfBytes(response);

        return dbus_response;
      }

      LOG(INFO) << "Preallocating user-chosen-size raw disk image";
      if (fallocate(fd.get(), 0, 0, disk_size) != 0) {
        PLOG(ERROR) << "Failed to allocate raw disk";
        unlink(disk_path.value().c_str());
        response.set_status(DISK_STATUS_FAILED);
        response.set_failure_reason("Failed to allocate raw disk file");
        writer.AppendProtoAsArrayOfBytes(response);

        return dbus_response;
      }

      LOG(INFO) << "Disk image preallocated";
      response.set_status(DISK_STATUS_CREATED);
      response.set_disk_path(disk_path.value());
      writer.AppendProtoAsArrayOfBytes(response);

      return dbus_response;
    }

    LOG(INFO) << "Creating sparse raw disk image";
    int ret = ftruncate(fd.get(), disk_size);
    if (ret != 0) {
      PLOG(ERROR) << "Failed to truncate raw disk";
      unlink(disk_path.value().c_str());
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Failed to truncate raw disk file");
      writer.AppendProtoAsArrayOfBytes(response);

      return dbus_response;
    }

    response.set_status(DISK_STATUS_CREATED);
    response.set_disk_path(disk_path.value());
    writer.AppendProtoAsArrayOfBytes(response);

    return dbus_response;
  }

  LOG(INFO) << "Creating qcow2 disk at: " << disk_path.value() << " size "
            << disk_size;
  int ret = create_qcow_with_size(disk_path.value().c_str(), disk_size);
  if (ret != 0) {
    LOG(ERROR) << "Failed to create qcow2 disk image: " << strerror(ret);
    response.set_status(DISK_STATUS_FAILED);
    response.set_failure_reason("Failed to create qcow2 disk image");
    writer.AppendProtoAsArrayOfBytes(response);

    return dbus_response;
  }

  response.set_disk_path(disk_path.value());
  response.set_status(DISK_STATUS_CREATED);
  writer.AppendProtoAsArrayOfBytes(response);

  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::DestroyDiskImage(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received DestroyDiskImage request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  DestroyDiskImageRequest request;
  DestroyDiskImageResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse DestroyDiskImageRequest from message";
    response.set_status(DISK_STATUS_FAILED);
    response.set_failure_reason("Unable to parse DestroyDiskRequest");

    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Stop the associated VM if it is still running.
  auto iter = FindVm(request.cryptohome_id(), request.vm_name());
  if (iter != vms_.end()) {
    LOG(INFO) << "Shutting down VM";

    if (!StopVm(VmId(request.cryptohome_id(), request.vm_name()),
                DESTROY_DISK_IMAGE_REQUESTED)) {
      LOG(ERROR) << "Unable to shut down VM";

      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Unable to shut down VM");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }
  }

  base::FilePath disk_path;
  StorageLocation location;
  if (!CheckVmExists(request.vm_name(), request.cryptohome_id(), &disk_path,
                     &location)) {
    response.set_status(DISK_STATUS_DOES_NOT_EXIST);
    response.set_failure_reason("No such image");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (!EraseGuestSshKeys(request.cryptohome_id(), request.vm_name())) {
    // Don't return a failure here, just log an error because this is only a
    // side effect and not what the real request is about.
    LOG(ERROR) << "Failed removing guest SSH keys for VM " << request.vm_name();
  }

  if (location == STORAGE_CRYPTOHOME_PLUGINVM) {
    // Plugin VMs need to be unregistered before we can delete them.
    VmId vm_id(request.cryptohome_id(), request.vm_name());
    bool registered;
    if (!pvm::dispatcher::IsVmRegistered(bus_, vmplugin_service_proxy_, vm_id,
                                         &registered)) {
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason(
          "failed to check Plugin VM registration status");
      writer.AppendProtoAsArrayOfBytes(response);

      return dbus_response;
    }

    if (registered &&
        !pvm::dispatcher::UnregisterVm(bus_, vmplugin_service_proxy_, vm_id)) {
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("failed to unregister Plugin VM");
      writer.AppendProtoAsArrayOfBytes(response);

      return dbus_response;
    }

    base::FilePath iso_dir;
    if (GetPluginIsoDirectory(vm_id.name(), vm_id.owner_id(),
                              false /* create */, &iso_dir) &&
        base::PathExists(iso_dir) && !base::DeletePathRecursively(iso_dir)) {
      LOG(ERROR) << "Unable to remove ISO directory for " << vm_id.name();

      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Unable to remove ISO directory");
      writer.AppendProtoAsArrayOfBytes(response);

      return dbus_response;
    }

    // Delete GPU shader disk cache.
    base::FilePath gpu_cache_path =
        GetVmGpuCachePath(request.cryptohome_id(), request.vm_name());
    if (!base::DeletePathRecursively(gpu_cache_path)) {
      LOG(ERROR) << "Failed to remove GPU cache for VM: " << gpu_cache_path;
    }
  }

  bool delete_result = (location == STORAGE_CRYPTOHOME_PLUGINVM)
                           ? base::DeletePathRecursively(disk_path)
                           : base::DeleteFile(disk_path);
  if (!delete_result) {
    response.set_status(DISK_STATUS_FAILED);
    response.set_failure_reason("Disk removal failed");
    writer.AppendProtoAsArrayOfBytes(response);

    return dbus_response;
  }

  response.set_status(DISK_STATUS_DESTROYED);
  writer.AppendProtoAsArrayOfBytes(response);

  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ResizeDiskImage(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ResizeDiskImage request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ResizeDiskImageRequest request;
  ResizeDiskImageResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ResizeDiskImageRequest from message";
    response.set_status(DISK_STATUS_FAILED);
    response.set_failure_reason("Unable to parse ResizeDiskImageRequest");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  base::FilePath disk_path;
  StorageLocation location;
  if (!CheckVmExists(request.vm_name(), request.cryptohome_id(), &disk_path,
                     &location)) {
    response.set_status(DISK_STATUS_DOES_NOT_EXIST);
    response.set_failure_reason("Resize image doesn't exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto size = request.disk_size() & kDiskSizeMask;
  if (size != request.disk_size()) {
    LOG(INFO) << "Rounded requested disk size from " << request.disk_size()
              << " to " << size;
  }

  auto op = VmResizeOperation::Create(
      VmId(request.cryptohome_id(), request.vm_name()), location, disk_path,
      size, base::Bind(&Service::ResizeDisk, weak_ptr_factory_.GetWeakPtr()),
      base::Bind(&Service::ProcessResize, weak_ptr_factory_.GetWeakPtr()));

  response.set_status(op->status());
  response.set_command_uuid(op->uuid());
  response.set_failure_reason(op->failure_reason());

  if (op->status() == DISK_STATUS_IN_PROGRESS) {
    std::string uuid = op->uuid();
    disk_image_ops_.emplace_back(DiskOpInfo(std::move(op)));
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&Service::RunDiskImageOperation,
                              weak_ptr_factory_.GetWeakPtr(), std::move(uuid)));
  } else if (op->status() == DISK_STATUS_RESIZED) {
    DiskImageStatus status = DISK_STATUS_RESIZED;
    std::string failure_reason;
    FinishResize(request.cryptohome_id(), request.vm_name(), location, &status,
                 &failure_reason);
    if (status != DISK_STATUS_RESIZED) {
      response.set_status(status);
      response.set_failure_reason(failure_reason);
    }
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

void Service::ResizeDisk(const std::string& owner_id,
                         const std::string& vm_name,
                         StorageLocation location,
                         uint64_t new_size,
                         DiskImageStatus* status,
                         std::string* failure_reason) {
  auto iter = FindVm(owner_id, vm_name);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Unable to find VM " << vm_name;
    *failure_reason = "No such image";
    *status = DISK_STATUS_DOES_NOT_EXIST;
    return;
  }

  *status = iter->second->ResizeDisk(new_size, failure_reason);
}

void Service::ProcessResize(const std::string& owner_id,
                            const std::string& vm_name,
                            StorageLocation location,
                            uint64_t target_size,
                            DiskImageStatus* status,
                            std::string* failure_reason) {
  auto iter = FindVm(owner_id, vm_name);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Unable to find VM " << vm_name;
    *failure_reason = "No such image";
    *status = DISK_STATUS_DOES_NOT_EXIST;
    return;
  }

  *status = iter->second->GetDiskResizeStatus(failure_reason);

  if (*status == DISK_STATUS_RESIZED) {
    FinishResize(owner_id, vm_name, location, status, failure_reason);
  }
}

void Service::FinishResize(const std::string& owner_id,
                           const std::string& vm_name,
                           StorageLocation location,
                           DiskImageStatus* status,
                           std::string* failure_reason) {
  base::FilePath disk_path;
  if (!GetDiskPathFromName(vm_name, owner_id, location,
                           false, /* create_parent_dir */
                           &disk_path)) {
    LOG(ERROR) << "Failed to get disk path after resize";
    *failure_reason = "Failed to get disk path after resize";
    *status = DISK_STATUS_FAILED;
    return;
  }

  base::ScopedFD fd(
      open(disk_path.value().c_str(), O_CREAT | O_NONBLOCK | O_WRONLY, 0600));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to open disk image";
    *failure_reason = "Failed to open disk image";
    *status = DISK_STATUS_FAILED;
    return;
  }

  // This disk now has a user-chosen size by virtue of being resized.
  if (!SetUserChosenSizeAttr(fd)) {
    LOG(ERROR) << "Failed to set user-chosen size xattr";
    *failure_reason = "Failed to set user-chosen size xattr";
    *status = DISK_STATUS_FAILED;
    return;
  }
}

std::unique_ptr<dbus::Response> Service::ExportDiskImage(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ExportDiskImage request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ExportDiskImageResponse response;
  response.set_status(DISK_STATUS_FAILED);

  ExportDiskImageRequest request;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ExportDiskImageRequest from message";
    response.set_failure_reason("Unable to parse ExportDiskRequest");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  base::FilePath disk_path;
  StorageLocation location;
  if (!CheckVmExists(request.vm_name(), request.cryptohome_id(), &disk_path,
                     &location)) {
    response.set_status(DISK_STATUS_DOES_NOT_EXIST);
    response.set_failure_reason("Export image doesn't exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Get the FD to fill with disk image data.
  base::ScopedFD storage_fd;
  if (!reader.PopFileDescriptor(&storage_fd)) {
    LOG(ERROR) << "export: no fd found";
    response.set_failure_reason("export: no fd found");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  base::ScopedFD digest_fd;
  if (request.generate_sha256_digest() &&
      !reader.PopFileDescriptor(&digest_fd)) {
    LOG(ERROR) << "export: no digest fd found";
    response.set_failure_reason("export: no digest fd found");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  ArchiveFormat fmt;
  switch (location) {
    case STORAGE_CRYPTOHOME_ROOT:
      fmt = ArchiveFormat::TAR_GZ;
      break;
    case STORAGE_CRYPTOHOME_PLUGINVM:
      fmt = ArchiveFormat::ZIP;
      break;
    default:
      LOG(ERROR) << "Unsupported location for source image";
      response.set_failure_reason("Unsupported location for image");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
  }

  VmId vm_id(request.cryptohome_id(), request.vm_name());

  if (!request.force()) {
    if (FindVm(vm_id) != vms_.end()) {
      LOG(ERROR) << "VM is currently running";
      response.set_failure_reason("VM is currently running");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }

    // For Parallels VMs we want to be sure that the VM is shut down, not
    // merely suspended, to have consistent export.
    if (location == STORAGE_CRYPTOHOME_PLUGINVM) {
      bool is_shut_down;
      if (!pvm::dispatcher::IsVmShutDown(bus_, vmplugin_service_proxy_, vm_id,
                                         &is_shut_down)) {
        LOG(ERROR) << "Unable to query VM state";
        response.set_failure_reason("Unable to query VM state");
        writer.AppendProtoAsArrayOfBytes(response);
        return dbus_response;
      }
      if (!is_shut_down) {
        LOG(ERROR) << "VM is not shut down";
        response.set_failure_reason("VM needs to be shut down for exporting");
        writer.AppendProtoAsArrayOfBytes(response);
        return dbus_response;
      }
    }
  }

  auto op = VmExportOperation::Create(vm_id, disk_path, std::move(storage_fd),
                                      std::move(digest_fd), fmt);

  response.set_status(op->status());
  response.set_command_uuid(op->uuid());
  response.set_failure_reason(op->failure_reason());

  if (op->status() == DISK_STATUS_IN_PROGRESS) {
    std::string uuid = op->uuid();
    disk_image_ops_.emplace_back(DiskOpInfo(std::move(op)));
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&Service::RunDiskImageOperation,
                              weak_ptr_factory_.GetWeakPtr(), std::move(uuid)));
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ImportDiskImage(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ImportDiskImage request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ImportDiskImageResponse response;
  response.set_status(DISK_STATUS_FAILED);

  ImportDiskImageRequest request;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ImportDiskImageRequest from message";
    response.set_failure_reason("Unable to parse ImportDiskRequest");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (CheckVmExists(request.vm_name(), request.cryptohome_id())) {
    response.set_status(DISK_STATUS_EXISTS);
    response.set_failure_reason("VM/disk with such name already exists");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (request.storage_location() != STORAGE_CRYPTOHOME_PLUGINVM) {
    LOG(ERROR)
        << "Locations other than STORAGE_CRYPTOHOME_PLUGINVM are not supported";
    response.set_failure_reason("Unsupported location for image");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  base::FilePath disk_path;
  if (!GetDiskPathFromName(request.vm_name(), request.cryptohome_id(),
                           request.storage_location(),
                           true, /* create_parent_dir */
                           &disk_path)) {
    response.set_failure_reason("Failed to set up vm image name");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Get the FD to fill with disk image data.
  base::ScopedFD in_fd;
  if (!reader.PopFileDescriptor(&in_fd)) {
    LOG(ERROR) << "import: no fd found";
    response.set_failure_reason("import: no fd found");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto op = PluginVmImportOperation::Create(
      std::move(in_fd), disk_path, request.source_size(),
      VmId(request.cryptohome_id(), request.vm_name()), bus_,
      vmplugin_service_proxy_);

  response.set_status(op->status());
  response.set_command_uuid(op->uuid());
  response.set_failure_reason(op->failure_reason());

  if (op->status() == DISK_STATUS_IN_PROGRESS) {
    std::string uuid = op->uuid();
    disk_image_ops_.emplace_back(DiskOpInfo(std::move(op)));
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&Service::RunDiskImageOperation,
                              weak_ptr_factory_.GetWeakPtr(), std::move(uuid)));
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

void Service::RunDiskImageOperation(std::string uuid) {
  auto iter =
      std::find_if(disk_image_ops_.begin(), disk_image_ops_.end(),
                   [&uuid](auto& info) { return info.op->uuid() == uuid; });

  if (iter == disk_image_ops_.end()) {
    LOG(ERROR) << "RunDiskImageOperation called with unknown uuid";
    return;
  }

  if (iter->canceled) {
    // Operation was cancelled. Now that our posted task is running we can
    // remove it from the list and not reschedule ourselves.
    disk_image_ops_.erase(iter);
    return;
  }

  auto op = iter->op.get();
  op->Run(kDefaultIoLimit);
  if (base::TimeTicks::Now() - iter->last_report_time > kDiskOpReportInterval ||
      op->status() != DISK_STATUS_IN_PROGRESS) {
    LOG(INFO) << "Disk Image Operation: UUID=" << uuid
              << " progress: " << op->GetProgress()
              << " status: " << op->status();

    // Send the D-Bus signal out updating progress of the operation.
    DiskImageStatusResponse status;
    FormatDiskImageStatus(op, &status);
    dbus::Signal signal(kVmConciergeInterface, kDiskImageProgressSignal);
    dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(status);
    exported_object_->SendSignal(&signal);

    // Note the time we sent out the notification.
    iter->last_report_time = base::TimeTicks::Now();
  }

  if (op->status() == DISK_STATUS_IN_PROGRESS) {
    // Reschedule ourselves so we can execute next chunk of work.
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&Service::RunDiskImageOperation,
                              weak_ptr_factory_.GetWeakPtr(), std::move(uuid)));
  }
}

std::unique_ptr<dbus::Response> Service::CheckDiskImageStatus(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received DiskImageStatus request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  DiskImageStatusResponse response;
  response.set_status(DISK_STATUS_FAILED);

  DiskImageStatusRequest request;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse DiskImageStatusRequest from message";
    response.set_failure_reason("Unable to parse DiskImageStatusRequest");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Locate the pending command in the list.
  auto iter = std::find_if(disk_image_ops_.begin(), disk_image_ops_.end(),
                           [&request](auto& info) {
                             return info.op->uuid() == request.command_uuid();
                           });

  if (iter == disk_image_ops_.end() || iter->canceled) {
    LOG(ERROR) << "Unknown command uuid in DiskImageStatusRequest";
    response.set_failure_reason("Unknown command uuid");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto op = iter->op.get();
  FormatDiskImageStatus(op, &response);
  writer.AppendProtoAsArrayOfBytes(response);

  // Erase operation form the list if it is no longer in progress.
  if (op->status() != DISK_STATUS_IN_PROGRESS) {
    disk_image_ops_.erase(iter);
  }

  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::CancelDiskImageOperation(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received CancelDiskImage request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  CancelDiskImageResponse response;
  response.set_success(false);

  CancelDiskImageRequest request;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse CancelDiskImageRequest from message";
    response.set_failure_reason("Unable to parse CancelDiskImageRequest");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Locate the pending command in the list.
  auto iter = std::find_if(disk_image_ops_.begin(), disk_image_ops_.end(),
                           [&request](auto& info) {
                             return info.op->uuid() == request.command_uuid();
                           });

  if (iter == disk_image_ops_.end()) {
    LOG(ERROR) << "Unknown command uuid in CancelDiskImageRequest";
    response.set_failure_reason("Unknown command uuid");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto op = iter->op.get();
  if (op->status() != DISK_STATUS_IN_PROGRESS) {
    response.set_failure_reason("Command is no longer in progress");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Mark the operation as canceled. We can't erase it from the list right
  // away as there is a task posted for it. The task will erase this operation
  // when it gets to run.
  iter->canceled = true;

  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ListVmDisks(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ListVmDisksRequest request;
  ListVmDisksResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ListVmDisksRequest from message";
    response.set_success(false);
    response.set_failure_reason("Unable to parse ListVmDisksRequest");

    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  response.set_success(true);
  response.set_total_size(0);

  for (int location = StorageLocation_MIN; location <= StorageLocation_MAX;
       location++) {
    if (request.all_locations() || location == request.storage_location()) {
      if (!ListVmDisksInLocation(request.cryptohome_id(),
                                 static_cast<StorageLocation>(location),
                                 request.vm_name(), &response)) {
        break;
      }
    }
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::GetContainerSshKeys(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received GetContainerSshKeys request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ContainerSshKeysRequest request;
  ContainerSshKeysResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ContainerSshKeysRequest from message";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (request.cryptohome_id().empty()) {
    LOG(ERROR) << "Cryptohome ID is not set in ContainerSshKeysRequest";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto iter = FindVm(request.cryptohome_id(), request.vm_name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();
  response.set_container_public_key(GetGuestSshPublicKey(
      request.cryptohome_id(), request.vm_name(), container_name));
  response.set_container_private_key(GetGuestSshPrivateKey(
      request.cryptohome_id(), request.vm_name(), container_name));
  response.set_host_public_key(GetHostSshPublicKey(request.cryptohome_id()));
  response.set_host_private_key(GetHostSshPrivateKey(request.cryptohome_id()));
  response.set_hostname(base::StringPrintf(
      "%s.%s.linux.test", container_name.c_str(), request.vm_name().c_str()));
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::AttachUsbDevice(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received AttachUsbDevice request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  AttachUsbDeviceRequest request;
  AttachUsbDeviceResponse response;
  base::ScopedFD fd;

  response.set_success(false);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse AttachUsbDeviceRequest from message";
    response.set_reason("Unable to parse protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (!reader.PopFileDescriptor(&fd)) {
    LOG(ERROR) << "Unable to parse file descriptor from dbus message";
    response.set_reason("Unable to parse file descriptor");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto iter = FindVm(request.owner_id(), request.vm_name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM " << request.vm_name() << " does not exist";
    response.set_reason("Requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (request.bus_number() > 0xFF) {
    LOG(ERROR) << "Bus number out of valid range " << request.bus_number();
    response.set_reason("Invalid bus number");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (request.port_number() > 0xFF) {
    LOG(ERROR) << "Port number out of valid range " << request.port_number();
    response.set_reason("Invalid port number");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (request.vendor_id() > 0xFFFF) {
    LOG(ERROR) << "Vendor ID out of valid range " << request.vendor_id();
    response.set_reason("Invalid vendor ID");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (request.product_id() > 0xFFFF) {
    LOG(ERROR) << "Product ID out of valid range " << request.product_id();
    response.set_reason("Invalid product ID");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  UsbControlResponse usb_response;
  if (!iter->second->AttachUsbDevice(
          request.bus_number(), request.port_number(), request.vendor_id(),
          request.product_id(), fd.get(), &usb_response)) {
    LOG(ERROR) << "Failed to attach USB device: " << usb_response.reason;
    response.set_reason(std::move(usb_response.reason));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  response.set_success(true);
  response.set_guest_port(usb_response.port);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::DetachUsbDevice(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received DetachUsbDevice request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  DetachUsbDeviceRequest request;
  DetachUsbDeviceResponse response;

  response.set_success(false);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse DetachUsbDeviceRequest from message";
    response.set_reason("Unable to parse protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto iter = FindVm(request.owner_id(), request.vm_name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    response.set_reason("Requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (request.guest_port() > 0xFF) {
    LOG(ERROR) << "Guest port number out of valid range "
               << request.guest_port();
    response.set_reason("Invalid guest port number");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  UsbControlResponse usb_response;
  if (!iter->second->DetachUsbDevice(request.guest_port(), &usb_response)) {
    LOG(ERROR) << "Failed to detach USB device";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ListUsbDevices(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ListUsbDevices request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ListUsbDeviceRequest request;
  ListUsbDeviceResponse response;

  response.set_success(false);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ListUsbDeviceRequest from message";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto iter = FindVm(request.owner_id(), request.vm_name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::vector<UsbDevice> usb_list;
  if (!iter->second->ListUsbDevice(&usb_list)) {
    LOG(ERROR) << "Failed to list USB devices";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  for (auto usb : usb_list) {
    UsbDeviceMessage* usb_proto = response.add_usb_devices();
    usb_proto->set_guest_port(usb.port);
    usb_proto->set_vendor_id(usb.vid);
    usb_proto->set_product_id(usb.pid);
  }
  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

void Service::ComposeDnsResponse(dbus::MessageWriter* writer) {
  DnsSettings dns_settings;
  for (const auto& server : nameservers_) {
    dns_settings.add_nameservers(server);
  }
  for (const auto& domain : search_domains_) {
    dns_settings.add_search_domains(domain);
  }
  writer->AppendProtoAsArrayOfBytes(dns_settings);
}

std::unique_ptr<dbus::Response> Service::GetDnsSettings(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received GetDnsSettings request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageWriter writer(dbus_response.get());
  ComposeDnsResponse(&writer);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::SetVmCpuRestriction(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  VLOG(3) << "Received SetVmCpuRestriction request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  SetVmCpuRestrictionRequest request;
  SetVmCpuRestrictionResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse SetVmCpuRestrictionRequest from message";
    response.set_success(false);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  bool initial_throttle = false, success = false;
  const CpuRestrictionState state = request.cpu_restriction_state();
  switch (request.cpu_cgroup()) {
    case CPU_CGROUP_TERMINA:
      success = TerminaVm::SetVmCpuRestriction(state);
      break;
    case CPU_CGROUP_PLUGINVM:
      success = PluginVm::SetVmCpuRestriction(state);
      break;
    case CPU_CGROUP_ARCVM:
      initial_throttle =
          platform_features_->IsEnabledBlocking(kArcVmInitialThrottleFeature);
      success = ArcVm::SetVmCpuRestriction(state, initial_throttle);
      break;
    default:
      LOG(ERROR) << "Unknown cpu_group";
      break;
  }

  response.set_success(success);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::SetVmId(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received SetVmId request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  SetVmIdRequest request;
  SetVmIdResponse response;

  response.set_success(false);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse SetVmIdRequest from message";
    response.set_failure_reason("Unable to parse SetVmIdRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto iter = FindVm(request.src_owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    response.set_failure_reason("Requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto vm = std::move(iter->second);
  auto cid = vm->GetInfo().cid;
  auto old_id = iter->first;
  vms_.erase(iter);
  VmId new_id(request.dest_owner_id(), request.name());
  vms_[new_id] = std::move(vm);
  vms_[new_id]->VmIdChanged();

  SendVmIdChangedSignal(new_id, old_id, cid);

  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ListVms(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ListVms request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ListVmsRequest request;
  ListVmsResponse response;

  response.set_success(false);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ListVmsRequest from message";
    response.set_failure_reason("Unable to parse ListVmsRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  for (const auto& vm_entry : vms_) {
    const auto& id = vm_entry.first;
    const auto& vm = vm_entry.second;

    if (id.owner_id() != request.owner_id()) {
      continue;
    }

    VmInterface::Info info = vm->GetInfo();
    ExtendedVmInfo* proto = response.add_vms();
    VmInfo* proto_info = proto->mutable_vm_info();
    proto->set_name(id.name());
    proto->set_owner_id(id.owner_id());
    proto_info->set_ipv4_address(info.ipv4_address);
    proto_info->set_pid(info.pid);
    proto_info->set_cid(info.cid);
    proto_info->set_seneschal_server_handle(info.seneschal_server_handle);
    proto_info->set_vm_type(info.type);
    // The vms_ member only contains VMs with running crosvm instances. So the
    // STOPPED case below should not be possible.
    switch (info.status) {
      case VmInterface::Status::STARTING: {
        proto->set_status(VM_STATUS_STARTING);
        break;
      }
      case VmInterface::Status::RUNNING: {
        proto->set_status(VM_STATUS_RUNNING);
        break;
      }
      case VmInterface::Status::STOPPED: {
        NOTREACHED();
        proto->set_status(VM_STATUS_STOPPED);
        break;
      }
    }
  }
  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

void Service::ReclaimVmMemory(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ReclaimVmMemory request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  ReclaimVmMemoryRequest request;
  ReclaimVmMemoryResponse response;
  response.set_success(false);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ReclaimVmMemoryRequest from message";
    response.set_failure_reason(
        "Unable to parse ReclaimVmMemoryRequest from message");
    dbus::MessageWriter writer(dbus_response.get());
    writer.AppendProtoAsArrayOfBytes(response);
    std::move(response_sender).Run(std::move(dbus_response));
    return;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    response.set_failure_reason("Requested VM does not exist");
    dbus::MessageWriter writer(dbus_response.get());
    writer.AppendProtoAsArrayOfBytes(response);
    std::move(response_sender).Run(std::move(dbus_response));
    return;
  }

  const pid_t pid = iter->second->GetInfo().pid;
  reclaim_thread_.task_runner()->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(&ReclaimVmMemoryInternal, pid, std::move(dbus_response)),
      base::BindOnce(&Service::OnReclaimVmMemory,
                     weak_ptr_factory_.GetWeakPtr(),
                     std::move(response_sender)));
}

void Service::OnReclaimVmMemory(
    dbus::ExportedObject::ResponseSender response_sender,
    std::unique_ptr<dbus::Response> dbus_response) {
  DCHECK(dbus_response);
  std::move(response_sender).Run(std::move(dbus_response));
}

void Service::OnResolvConfigChanged(std::vector<string> nameservers,
                                    std::vector<string> search_domains) {
  if (nameservers_ == nameservers && search_domains_ == search_domains) {
    // Only update guests if the nameservers and search domains changed.
    return;
  }

  nameservers_ = std::move(nameservers);
  search_domains_ = std::move(search_domains);

  for (auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    if (vm->IsSuspended()) {
      // The VM is currently suspended and will not respond to RPCs.
      // SetResolvConfig() will be called when the VM resumes.
      continue;
    }
    vm->SetResolvConfig(nameservers_, search_domains_);
  }

  // Broadcast DnsSettingsChanged signal so Plugin VM dispatcher is aware as
  // well.
  dbus::Signal signal(kVmConciergeInterface, kDnsSettingsChangedSignal);
  dbus::MessageWriter writer(&signal);
  ComposeDnsResponse(&writer);
  exported_object_->SendSignal(&signal);
}

void Service::OnDefaultNetworkServiceChanged() {
  for (auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    if (vm->IsSuspended()) {
      continue;
    }
    vm->HostNetworkChanged();
  }
}

void Service::NotifyCiceroneOfVmStarted(const VmId& vm_id,
                                        uint32_t cid,
                                        pid_t pid,
                                        std::string vm_token) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kNotifyVmStartedMethod);
  dbus::MessageWriter writer(&method_call);
  vm_tools::cicerone::NotifyVmStartedRequest request;
  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name(vm_id.name());
  request.set_cid(cid);
  request.set_vm_token(std::move(vm_token));
  request.set_pid(pid);
  writer.AppendProtoAsArrayOfBytes(request);
  if (!brillo::dbus_utils::CallDBusMethod(
          bus_, cicerone_service_proxy_, &method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT)) {
    LOG(ERROR) << "Failed notifying cicerone of VM startup";
  }
}

void Service::SendVmStartedSignal(const VmId& vm_id,
                                  const vm_tools::concierge::VmInfo& vm_info,
                                  vm_tools::concierge::VmStatus status) {
  dbus::Signal signal(kVmConciergeInterface, kVmStartedSignal);
  vm_tools::concierge::ExtendedVmInfo proto;
  proto.set_owner_id(vm_id.owner_id());
  proto.set_name(vm_id.name());
  proto.mutable_vm_info()->CopyFrom(vm_info);
  proto.set_status(status);
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
}

void Service::SendVmStartingUpSignal(
    const VmId& vm_id, const vm_tools::concierge::VmInfo& vm_info) {
  dbus::Signal signal(kVmConciergeInterface, kVmStartingUpSignal);
  vm_tools::concierge::ExtendedVmInfo proto;
  proto.set_owner_id(vm_id.owner_id());
  proto.set_name(vm_id.name());
  proto.mutable_vm_info()->CopyFrom(vm_info);
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
}

void Service::NotifyVmStopping(const VmId& vm_id, int64_t cid) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  // Notify cicerone.
  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kNotifyVmStoppingMethod);
  dbus::MessageWriter writer(&method_call);
  vm_tools::cicerone::NotifyVmStoppingRequest request;
  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name(vm_id.name());
  writer.AppendProtoAsArrayOfBytes(request);
  if (!brillo::dbus_utils::CallDBusMethod(
          bus_, cicerone_service_proxy_, &method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT)) {
    LOG(ERROR) << "Failed notifying cicerone of stopping VM";
  }
}

void Service::NotifyVmStopped(const VmId& vm_id,
                              int64_t cid,
                              VmStopReason reason) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  // Notify cicerone.
  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kNotifyVmStoppedMethod);
  dbus::MessageWriter writer(&method_call);
  vm_tools::cicerone::NotifyVmStoppedRequest request;
  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name(vm_id.name());
  writer.AppendProtoAsArrayOfBytes(request);
  if (!brillo::dbus_utils::CallDBusMethod(
          bus_, cicerone_service_proxy_, &method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT)) {
    LOG(ERROR) << "Failed notifying cicerone of VM stopped";
  }

  // Send the D-Bus signal out to notify everyone that we have stopped a VM.
  dbus::Signal signal(kVmConciergeInterface, kVmStoppedSignal);
  vm_tools::concierge::VmStoppedSignal proto;
  proto.set_owner_id(vm_id.owner_id());
  proto.set_name(vm_id.name());
  proto.set_cid(cid);
  proto.set_reason(reason);
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
}

void Service::SendVmIdChangedSignal(const VmId& id,
                                    const VmId& prev_id,
                                    int64_t cid) {
  dbus::Signal signal(kVmConciergeInterface, kVmIdChangedSignal);
  vm_tools::concierge::VmIdChangedSignal proto;
  proto.set_owner_id(id.owner_id());
  proto.set_name(id.name());
  proto.set_cid(cid);
  proto.set_prev_owner_id(prev_id.owner_id());
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
}

std::string Service::GetContainerToken(const VmId& vm_id,
                                       const std::string& container_name) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kGetContainerTokenMethod);
  dbus::MessageWriter writer(&method_call);
  vm_tools::cicerone::ContainerTokenRequest request;
  vm_tools::cicerone::ContainerTokenResponse response;
  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name(vm_id.name());
  request.set_container_name(container_name);
  writer.AppendProtoAsArrayOfBytes(request);
  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethod(
          bus_, cicerone_service_proxy_, &method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed getting container token from cicerone";
    return "";
  }
  dbus::MessageReader reader(dbus_response.get());
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed parsing proto response";
    return "";
  }
  return response.container_token();
}

void Service::OnTremplinStartedSignal(dbus::Signal* signal) {
  DCHECK_EQ(signal->GetInterface(), vm_tools::cicerone::kVmCiceroneInterface);
  DCHECK_EQ(signal->GetMember(), vm_tools::cicerone::kTremplinStartedSignal);

  vm_tools::cicerone::TremplinStartedSignal tremplin_started_signal;
  dbus::MessageReader reader(signal);
  if (!reader.PopArrayOfBytesAsProto(&tremplin_started_signal)) {
    LOG(ERROR) << "Failed to parse TremplinStartedSignal from DBus Signal";
    return;
  }

  auto iter = FindVm(tremplin_started_signal.owner_id(),
                     tremplin_started_signal.vm_name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Received signal from an unknown vm."
               << VmId(tremplin_started_signal.owner_id(),
                       tremplin_started_signal.vm_name());
    return;
  }
  LOG(INFO) << "Received TremplinStartedSignal for " << iter->first;
  iter->second->SetTremplinStarted();
}

void Service::OnVmToolsStateChangedSignal(dbus::Signal* signal) {
  string owner_id, vm_name;
  bool running;
  if (!pvm::dispatcher::ParseVmToolsChangedSignal(signal, &owner_id, &vm_name,
                                                  &running)) {
    return;
  }

  auto iter = FindVm(owner_id, vm_name);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Received signal from an unknown vm "
               << VmId(owner_id, vm_name);
    return;
  }
  LOG(INFO) << "Received VmToolsStateChangedSignal for " << iter->first;
  iter->second->VmToolsStateChanged(running);
}

void Service::OnSignalConnected(const std::string& interface_name,
                                const std::string& signal_name,
                                bool is_connected) {
  if (!is_connected) {
    LOG(ERROR) << "Failed to connect to interface name: " << interface_name
               << " for signal " << signal_name;
  } else {
    LOG(INFO) << "Connected to interface name: " << interface_name
              << " for signal " << signal_name;
  }

  if (interface_name == vm_tools::cicerone::kVmCiceroneInterface) {
    DCHECK_EQ(signal_name, vm_tools::cicerone::kTremplinStartedSignal);
    is_tremplin_started_signal_connected_ = is_connected;
  }
}

void Service::HandleSuspendImminent() {
  for (const auto& pair : vms_) {
    auto& vm = pair.second;
    if (vm->UsesExternalSuspendSignals()) {
      continue;
    }
    vm->Suspend();
  }
}

void Service::HandleSuspendDone() {
  for (const auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    if (vm->UsesExternalSuspendSignals()) {
      continue;
    }

    vm->Resume();

    string failure_reason;
    if (!vm->SetTime(&failure_reason)) {
      LOG(ERROR) << "Failed to set VM clock in " << vm_entry.first << ": "
                 << failure_reason;
    }

    vm->SetResolvConfig(nameservers_, search_domains_);
  }
}

Service::VmMap::iterator Service::FindVm(const VmId& vm_id) {
  return vms_.find(vm_id);
}

Service::VmMap::iterator Service::FindVm(const std::string& owner_id,
                                         const std::string& vm_name) {
  return vms_.find(VmId(owner_id, vm_name));
}

base::FilePath Service::GetVmImagePath(const std::string& dlc_id,
                                       std::string* failure_reason) {
  DCHECK(failure_reason);
  base::Optional<std::string> dlc_root =
      AsyncNoReject(bus_->GetDBusTaskRunner(),
                    base::BindOnce(
                        [](DlcHelper* dlc_helper, const std::string& dlc_id,
                           std::string* out_failure_reason) {
                          return dlc_helper->GetRootPath(dlc_id,
                                                         out_failure_reason);
                        },
                        dlcservice_client_.get(), dlc_id, failure_reason))
          .Get()
          .val;
  if (!dlc_root.has_value()) {
    // On an error, failure_reason will be set by GetRootPath().
    return {};
  }
  return base::FilePath(dlc_root.value());
}

Service::VMImageSpec Service::GetImageSpec(
    const vm_tools::concierge::VirtualMachineSpec& vm,
    const base::Optional<base::ScopedFD>& kernel_fd,
    const base::Optional<base::ScopedFD>& rootfs_fd,
    const base::Optional<base::ScopedFD>& initrd_fd,
    const base::Optional<base::ScopedFD>& bios_fd,
    bool is_termina,
    string* failure_reason) {
  DCHECK(failure_reason);
  DCHECK(failure_reason->empty());

  // A VM image is trusted when both:
  // 1) This daemon (or a trusted daemon) chooses the kernel and rootfs path.
  // 2) The chosen VM is a first-party VM.
  // In practical terms this is true iff we are booting termina without
  // specifying kernel and rootfs image.
  bool is_trusted_image = is_termina;

  base::FilePath kernel, rootfs, initrd, bios;
  if (kernel_fd.has_value()) {
    // User-chosen kernel is untrusted.
    is_trusted_image = false;

    int raw_fd = kernel_fd.value().get();
    *failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason->empty())
      return {};
    kernel = base::FilePath(kProcFileDescriptorsPath)
                 .Append(base::NumberToString(raw_fd));
  } else {
    kernel = base::FilePath(vm.kernel());
  }

  if (rootfs_fd.has_value()) {
    // User-chosen rootfs is untrusted.
    is_trusted_image = false;

    int raw_fd = rootfs_fd.value().get();
    *failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason->empty())
      return {};
    rootfs = base::FilePath(kProcFileDescriptorsPath)
                 .Append(base::NumberToString(raw_fd));
  } else {
    rootfs = base::FilePath(vm.rootfs());
  }

  if (initrd_fd.has_value()) {
    // User-chosen initrd is untrusted.
    is_trusted_image = false;

    int raw_fd = initrd_fd.value().get();
    *failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason->empty())
      return {};
    initrd = base::FilePath(kProcFileDescriptorsPath)
                 .Append(base::NumberToString(raw_fd));
  } else {
    initrd = base::FilePath(vm.initrd());
  }

  if (bios_fd.has_value()) {
    // User-chosen bios is untrusted.
    is_trusted_image = false;

    int raw_fd = bios_fd.value().get();
    *failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason->empty())
      return {};
    bios = base::FilePath(kProcFileDescriptorsPath)
               .Append(base::NumberToString(raw_fd));
  }

  base::FilePath vm_path;
  // As a legacy fallback, use the component rather than the DLC.
  //
  // TODO(crbug/953544): remove this once we no longer distribute termina as a
  // component.
  if (vm.dlc_id().empty() && is_termina) {
    vm_path = GetLatestVMPath();
    if (vm_path.empty()) {
      *failure_reason = "Termina component is not loaded";
      return {};
    }
  } else if (!vm.dlc_id().empty()) {
    vm_path = GetVmImagePath(vm.dlc_id(), failure_reason);
    if (vm_path.empty())
      return {};
  }

  // Pull in the DLC-provided files if requested.
  if (!kernel_fd.has_value() && !vm_path.empty())
    kernel = vm_path.Append(kVmKernelName);
  if (!rootfs_fd.has_value() && !vm_path.empty())
    rootfs = vm_path.Append(kVmRootfsName);

  base::FilePath tools_disk;
  if (!vm.tools_dlc_id().empty()) {
    base::FilePath tools_disk_path =
        GetVmImagePath(vm.tools_dlc_id(), failure_reason);
    if (tools_disk_path.empty())
      return {};
    tools_disk = tools_disk_path.Append(kVmToolsDiskName);
  }
  if (tools_disk.empty() && !vm_path.empty())
    tools_disk = vm_path.Append(kVmToolsDiskName);

  return VMImageSpec{
      .kernel = std::move(kernel),
      .initrd = std::move(initrd),
      .rootfs = std::move(rootfs),
      .bios = std::move(bios),
      .tools_disk = std::move(tools_disk),
      .is_trusted_image = is_trusted_image,
  };
}

Service::VMGpuCacheSpec Service::PrepareVmGpuCachePaths(
    const std::string& owner_id,
    const std::string& vm_name,
    bool enable_render_server) {
  base::FilePath cache_path = GetVmGpuCachePath(owner_id, vm_name);
  base::FilePath bootid_path = cache_path.DirName();
  base::FilePath base_path = bootid_path.DirName();

  base::FilePath cache_device_path = cache_path.Append("device");
  base::FilePath cache_render_server_path =
      enable_render_server ? cache_path.Append("render_server")
                           : base::FilePath();

  const base::FilePath* cache_subdir_paths[] = {&cache_device_path,
                                                &cache_render_server_path};

  base::AutoLock guard(cache_mutex_);

  // In order to always provide an empty GPU shader cache on each boot, we hash
  // the boot_id and erase the whole GPU cache if a directory matching the
  // current boot_id is not found.
  // For example:
  // VM cache dir: /run/daemon-store/crosvm/<uid>/gpucache/<bootid>/<vmid>/
  // Boot dir: /run/daemon-store/crosvm/<uid>/gpucache/<bootid>/
  // Base dir: /run/daemon-store/crosvm/<uid>/gpucache/
  // If Boot dir exists we know another VM has already created a fresh base
  // dir during this boot. Otherwise, we erase Base dir to wipe out any
  // previous Boot dir.
  if (!base::DirectoryExists(bootid_path)) {
    if (!base::DeletePathRecursively(base_path)) {
      LOG(ERROR) << "Failed to delete gpu cache directory: " << base_path
                 << " shader caching will be disabled.";
      return VMGpuCacheSpec{};
    }
  }

  for (const base::FilePath* path : cache_subdir_paths) {
    if (path->empty()) {
      continue;
    }

    if (!base::DirectoryExists(*path)) {
      base::File::Error dir_error;
      if (!base::CreateDirectoryAndGetError(*path, &dir_error)) {
        LOG(ERROR) << "Failed to create crosvm gpu cache directory in " << *path
                   << ": " << base::File::ErrorToString(dir_error);
        base::DeletePathRecursively(cache_path);
        return VMGpuCacheSpec{};
      }
    }
  }

  return VMGpuCacheSpec{.device = std::move(cache_device_path),
                        .render_server = std::move(cache_render_server_path)};
}

}  // namespace concierge
}  // namespace vm_tools
