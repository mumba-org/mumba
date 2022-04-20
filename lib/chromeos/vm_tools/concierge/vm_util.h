// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VM_UTIL_H_
#define VM_TOOLS_CONCIERGE_VM_UTIL_H_

#include <sys/types.h>

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/string_split.h>
#include <base/strings/string_piece.h>
#include <base/time/time.h>
#include <base/values.h>
#include <brillo/files/safe_fd.h>
#include <brillo/process/process.h>
#include <vm_tools/concierge/usb_control.h>
#include <vm_tools/concierge/balloon_policy.h>

namespace base {
class FilePath;
}  // namespace base

namespace vm_tools {
namespace concierge {

// Path to process file descriptors.
constexpr char kProcFileDescriptorsPath[] = "/proc/self/fd/";

class Disk {
 public:
  struct Config {
    bool writable{false};
    base::Optional<bool> sparse;
    base::Optional<bool> o_direct;
    base::Optional<size_t> block_size;
  };

  Disk(base::FilePath path, bool writable);
  Disk(base::FilePath path, const Config& config);
  Disk(const Disk&) = delete;
  Disk& operator=(const Disk&) = delete;
  Disk(Disk&&);
  virtual ~Disk();

  // Gets the command line argument that needs to be passed to crosvm
  // corresponding to this disk.
  base::StringPairs GetCrosvmArgs() const;

  void EnableODirect(bool enable);
  void SetBlockSize(size_t block_size);

 private:
  // Path to the disk image on the host.
  base::FilePath path_;

  // Whether the disk should be writable by the VM.
  bool writable_;

  // Whether the disk should allow sparse file operations (discard) by the VM.
  base::Optional<bool> sparse_;

  // Whether the disk access should be done with O_DIRECT by the VM.
  base::Optional<bool> o_direct_;

  // Block size.
  base::Optional<size_t> block_size_;
};

// Path to the crosvm binary.
extern const char kCrosvmBin[];

// Calculates the amount of memory to give the virtual machine, in MiB.
// Currently configured to provide 75% of system memory. This is deliberately
// over provisioned with the expectation that we will use the balloon driver to
// reduce the actual memory footprint.
int64_t GetVmMemoryMiB();

// Retrieves the physical package ID for |cpu| from the topology information in
// sysfs.
base::Optional<int32_t> GetCpuPackageId(int32_t cpu);

// Retrieves the CPU capacity property for |cpu| from sysfs.
base::Optional<int32_t> GetCpuCapacity(int32_t cpu);

// Calculate an appropriate CPU affinity setting based on the host system's
// CPU clusters and capacity. CPUs will be grouped based on cluster if multiple
// clusters exist, or based on groupings of equal CPU capacity if more than one
// such grouping exists. Otherwise, |nullopt| will be returned.
base::Optional<std::string> GetCpuAffinityFromClusters(
    const std::vector<std::vector<std::string>>& cpu_clusters,
    const std::map<int32_t, std::vector<std::string>>& cpu_capacity_groups);

// Puts the current process in a CPU cgroup specificed by |cpu_cgroup|, and
// then calls SetPgid(). This function can be called as brillo::ProcessImpl's
// PreExecCallback.
bool SetUpCrosvmProcess(const base::FilePath& cpu_cgroup);

// Sets the pgid of the current process to its pid.  This is needed because
// crosvm assumes that only it and its children are in the same process group
// and indiscriminately sends a SIGKILL if it needs to shut them down. This
// function can be called as brillo::ProcessImpl's PreExecCallback.
bool SetPgid();

// Waits for the |pid| to exit.  Returns true if |pid| successfully exited and
// false if it did not exit in time.
bool WaitForChild(pid_t child, base::TimeDelta timeout);

// Returns true if a process with |pid| exists.
bool CheckProcessExists(pid_t pid);

// Runs a crosvm subcommand.
void RunCrosvmCommand(std::initializer_list<std::string> args);
void RunCrosvmCommand(std::string command, std::string socket_path);

// Returns balloon stats info retrieved from virtio-balloon device.
base::Optional<BalloonStats> GetBalloonStats(std::string socket_path);

// Parses balloon stats info from a JSON value.
base::Optional<BalloonStats> ParseBalloonStats(const base::Value& balloon_stats);

// Attaches an usb device at host |bus|:|addr|, with |vid|, |pid| and an
// opened |fd|.
bool AttachUsbDevice(std::string socket_path,
                     uint8_t bus,
                     uint8_t addr,
                     uint16_t vid,
                     uint16_t pid,
                     int fd,
                     UsbControlResponse* response);

// Detaches the usb device at guest |port|.
bool DetachUsbDevice(std::string socket_path,
                     uint8_t port,
                     UsbControlResponse* response);

// Lists all usb devices attached to guest.
bool ListUsbDevice(std::string socket_path, std::vector<UsbDevice>* devices);

// Resizes the disk identified by |disk_index| to |new_size| in bytes.
bool CrosvmDiskResize(std::string socket_path,
                      int disk_index,
                      uint64_t new_size);

// Updates |cpu_cgroup|'s cpu.shares to |cpu_shares|.
bool UpdateCpuShares(const base::FilePath& cpu_cgroup, int cpu_shares);

// Updates |cpu_cgroup|'s cpu.cfs_quota_us and cpu.cfs_period_us
// based on |percent|.
bool UpdateCpuQuota(const base::FilePath& cpu_cgroup, int percent);

// Convert file path into fd path
// This will open the file and append SafeFD into provided container
std::string ConvertToFdBasedPath(brillo::SafeFD& parent_fd,
                                 base::FilePath* in_out_path,
                                 int flags,
                                 std::vector<brillo::SafeFD>& fd_storage);

class CustomParametersForDev {
 public:
  // By default this class would do nothing.
  CustomParametersForDev() = default;

  // Allow custom parameters on development devices with arcvm_dev.conf.
  // Loads custom parameters from a string. Please check
  // vm_tools/init/arcvm_dev.conf for the list of supported directives.
  explicit CustomParametersForDev(const std::string& data);

  // Apply the parsed result of configuration files to |args| as a vector of
  // string pairs.
  void Apply(base::StringPairs* args);

  base::Optional<const std::string> ObtainSpecialParameter(
      const std::string& key);

 private:
  // Command line parameter prefix to crosvm to remove.
  std::vector<std::string> prefix_to_remove_{};
  // Command line parameters to crosvm to add.
  base::StringPairs params_to_add_{};
  // Other special handling.
  std::map<std::string, std::string> special_parameters_{};
  bool initialized_{false};
};

// Creates shared data parameter for crovm.
std::string CreateSharedDataParam(const base::FilePath& data_dir,
                                  const std::string& tag,
                                  bool enable_caches,
                                  bool ascii_casefold,
                                  bool posix_acl,
                                  const std::vector<uid_t>& privileged_uids);

class ArcVmCPUTopology {
 public:
  ArcVmCPUTopology(uint32_t num_cpus, uint32_t num_rt_cpus);
  ~ArcVmCPUTopology() = default;

  ArcVmCPUTopology(const ArcVmCPUTopology&) = delete;
  ArcVmCPUTopology& operator=(const ArcVmCPUTopology&) = delete;

  void CreateCPUAffinity();

  bool IsSymmetricCPU();

  uint32_t NumCPUs();
  uint32_t NumRTCPUs();
  void SetNumRTCPUs(uint32_t num_rt_cpus);
  const std::string& AffinityMask();
  const std::string& RTCPUMask();
  const std::string& NonRTCPUMask();
  const std::string& CapacityMask();
  const std::vector<std::string>& PackageMask();

  // Unit Testing crud
  void AddCpuToCapacityGroupForTesting(uint32_t cpu, uint32_t capacity);
  void AddCpuToPackageGroupForTesting(uint32_t cpu, uint32_t package);
  void CreateCPUAffinityForTesting();

 private:
  void CreateTopology();
  void CreateAffinity();

  // Total number of CPUs VM will be configured with
  uint32_t num_cpus_;
  // Number of RT CPUs
  uint32_t num_rt_cpus_;
  // CPU mask for RT CPUs
  std::string rt_cpu_mask_;
  // CPU mask for non RT CPUs
  std::string non_rt_cpu_mask_;
  // CPU affinity
  std::string affinity_mask_;
  // A set of RT CPUs
  std::set<uint32_t> rt_cpus_;
  // CPU capacity grouping
  std::map<uint32_t, std::vector<uint32_t>> capacity_;
  // CPU package grouping
  std::map<uint32_t, std::vector<uint32_t>> package_;
  // CPU capacity mask
  std::string capacity_mask_;
  // CPU package mask
  std::vector<std::string> package_mask_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_VM_UTIL_H_
