// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VM_BUILDER_H_
#define VM_TOOLS_CONCIERGE_VM_BUILDER_H_

#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_split.h>
#include <dbus/object_proxy.h>

#include "vm_tools/concierge/vm_interface.h"
#include "vm_tools/concierge/vm_util.h"

namespace vm_tools {
namespace concierge {

class VmBuilder {
 public:
  // Contains the rootfs device and path.
  struct Rootfs {
    std::string device;
    base::FilePath path;
    bool writable;
  };

  // Audio device type enumeration.
  enum class AudioDeviceType {
    kAC97,
    kVirtio,
  };

  VmBuilder();
  VmBuilder(VmBuilder&&);
  VmBuilder& operator=(VmBuilder&& other);
  VmBuilder(const VmBuilder&) = delete;
  VmBuilder& operator=(const VmBuilder&) = delete;
  ~VmBuilder();

  VmBuilder& SetKernel(base::FilePath kernel);
  VmBuilder& SetInitrd(base::FilePath initrd);
  VmBuilder& SetBios(base::FilePath bios);
  VmBuilder& SetRootfs(const struct Rootfs& rootfs);
  VmBuilder& SetCpus(int32_t cpus);
  VmBuilder& SetVsockCid(uint32_t vsock_cid);
  VmBuilder& AppendDisks(std::vector<Disk> disks);
  VmBuilder& SetMemory(const std::string& memory_in_mb);
  VmBuilder& SetBalloonBias(const std::string& balloon_bias_mib);

  VmBuilder& SetSyslogTag(const std::string& syslog_tag);
  VmBuilder& SetSocketPath(const std::string& socket_path);
  VmBuilder& AppendTapFd(base::ScopedFD tap_fd);
  VmBuilder& AppendKernelParam(const std::string& param);
  VmBuilder& AppendAudioDevice(const AudioDeviceType type,
                               const std::string& params);
  VmBuilder& AppendSerialDevice(const std::string& device);
  VmBuilder& AppendSharedDir(const std::string& shared_dir);
  VmBuilder& AppendCustomParam(const std::string& key,
                               const std::string& value);

  // Instructs this VM to use a wayland socket, if the empty string is provided
  // the default path to the socket will be used, otherwise |socket| will be the
  // path.
  VmBuilder& SetWaylandSocket(const std::string& socket = "");
  VmBuilder& AddExtraWaylandSocket(const std::string& socket);

  VmBuilder& EnableGpu(bool enable);
  VmBuilder& EnableVulkan(bool enable);
  // Make virglrenderer use Big GL instead of the default GLES.
  VmBuilder& EnableBigGl(bool enable);
  // Offload Vulkan use to isolated virglrenderer render server
  VmBuilder& EnableRenderServer(bool enable);
  VmBuilder& SetGpuCachePath(base::FilePath gpu_cache_path);
  VmBuilder& SetGpuCacheSize(std::string gpu_cache_size_str);
  VmBuilder& SetRenderServerCachePath(base::FilePath render_server_cache_path);
  VmBuilder& SetRenderServerCacheSize(std::string render_server_cache_size_str);

  VmBuilder& EnableSoftwareTpm(bool enable);
  VmBuilder& EnableVideoDecoder(bool enable);
  VmBuilder& EnableVideoEncoder(bool enable);
  VmBuilder& EnableBattery(bool enable);
  VmBuilder& EnableSmt(bool enable);
  VmBuilder& EnableDelayRt(bool enable);
  VmBuilder& EnablePerVmCoreScheduling(bool enable);

  // Override flags for O_DIRECT for already appended disks.
  VmBuilder& EnableODirect(bool enable);
  // Override block size for already appended disks.
  VmBuilder& SetBlockSize(size_t block_size);

  VmBuilder& SetVmMemoryId(VmMemoryId id);

  // Builds the command line required to start a VM.
  base::StringPairs BuildVmArgs() const;

 private:
  base::FilePath kernel_;
  base::FilePath initrd_;
  base::FilePath bios_;
  std::optional<Rootfs> rootfs_;
  int32_t cpus_ = 0;
  std::optional<uint32_t> vsock_cid_;
  std::string memory_in_mib_;
  std::string balloon_bias_mib_;

  std::string syslog_tag_;
  std::string vm_socket_path_;

  bool enable_gpu_ = false;
  bool enable_vulkan_ = false;
  bool enable_big_gl_ = false;
  bool enable_render_server_ = false;
  base::FilePath gpu_cache_path_;
  std::string gpu_cache_size_str_;
  base::FilePath render_server_cache_path_;
  std::string render_server_cache_size_str_;

  bool enable_software_tpm_ = false;
  bool enable_video_decoder_ = false;
  bool enable_video_encoder_ = false;
  bool enable_battery_ = false;
  std::optional<bool> enable_smt_ = false;
  bool enable_delay_rt_ = false;
  bool enable_per_vm_core_scheduling_ = false;

  std::vector<Disk> disks_;
  std::vector<std::string> kernel_params_;
  std::vector<base::ScopedFD> tap_fds_;

  struct AudioDevice {
    AudioDeviceType type;
    std::string params;
  };
  std::vector<AudioDevice> audio_devices_;
  std::vector<std::string> serial_devices_;
  std::vector<std::string> wayland_sockets_;
  std::vector<std::string> shared_dirs_;
  std::vector<std::vector<int32_t>> cpu_clusters_;

  std::optional<VmMemoryId> vm_memory_id_;

  base::StringPairs custom_params_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_VM_BUILDER_H_
