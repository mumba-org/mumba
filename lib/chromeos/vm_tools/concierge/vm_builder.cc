// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vm_builder.h"

#include <optional>
#include <string>
#include <utility>

#include <base/strings/string_util.h>
#include <base/logging.h>

#include "vm_tools/concierge/vm_util.h"

namespace vm_tools {
namespace concierge {
namespace {
// Path to the default wayland socket.
constexpr char kWaylandSocket[] = "/run/chrome/wayland-0";
constexpr char kVirglRenderServerPath[] = "/usr/libexec/virgl_render_server";
}  // namespace

VmBuilder::VmBuilder() = default;

VmBuilder::VmBuilder(VmBuilder&&) = default;

VmBuilder& VmBuilder::operator=(VmBuilder&& other) = default;

VmBuilder::~VmBuilder() = default;

VmBuilder& VmBuilder::SetKernel(base::FilePath kernel) {
  kernel_ = std::move(kernel);
  return *this;
}

VmBuilder& VmBuilder::SetInitrd(base::FilePath initrd) {
  initrd_ = std::move(initrd);
  return *this;
}

VmBuilder& VmBuilder::SetBios(base::FilePath bios) {
  bios_ = std::move(bios);
  return *this;
}

VmBuilder& VmBuilder::SetRootfs(const struct Rootfs& rootfs) {
  rootfs_ = rootfs;
  return *this;
}

VmBuilder& VmBuilder::SetCpus(int32_t cpus) {
  cpus_ = cpus;
  return *this;
}

VmBuilder& VmBuilder::SetVsockCid(uint32_t vsock_cid) {
  vsock_cid_ = vsock_cid;
  return *this;
}

VmBuilder& VmBuilder::AppendDisks(std::vector<Disk> disks) {
  disks_ = std::move(disks);
  return *this;
}

VmBuilder& VmBuilder::SetMemory(const std::string& memory_in_mb) {
  memory_in_mib_ = memory_in_mb;
  return *this;
}

VmBuilder& VmBuilder::SetBalloonBias(const std::string& balloon_bias_mib) {
  balloon_bias_mib_ = balloon_bias_mib;
  return *this;
}

VmBuilder& VmBuilder::SetSyslogTag(const std::string& syslog_tag) {
  syslog_tag_ = syslog_tag;
  return *this;
}

VmBuilder& VmBuilder::SetSocketPath(const std::string& socket_path) {
  vm_socket_path_ = socket_path;
  return *this;
}

VmBuilder& VmBuilder::AppendTapFd(base::ScopedFD fd) {
  tap_fds_.push_back(std::move(fd));
  return *this;
}

VmBuilder& VmBuilder::AppendKernelParam(const std::string& param) {
  kernel_params_.push_back(param);
  return *this;
}

VmBuilder& VmBuilder::AppendAudioDevice(const AudioDeviceType type,
                                        const std::string& params) {
  audio_devices_.push_back(AudioDevice{.type = type, .params = params});
  return *this;
}

VmBuilder& VmBuilder::AppendSerialDevice(const std::string& device) {
  serial_devices_.push_back(device);
  return *this;
}

VmBuilder& VmBuilder::SetWaylandSocket(const std::string& socket) {
  // The "true" socket, which is the visual one, must be set first.
  DCHECK(wayland_sockets_.empty());
  if (socket.empty()) {
    // We want the empty string to mean "use the default socket", since that is
    // the behaviour we want if the user does not set the wayland socket in the
    // VirtualMachineSpec proto.
    wayland_sockets_.push_back(kWaylandSocket);
  } else {
    wayland_sockets_.push_back(socket);
  }
  return *this;
}

VmBuilder& VmBuilder::AddExtraWaylandSocket(const std::string& socket) {
  // Additional sockets must only be added after the "true" socket, since the
  // first socket provided to the VM will always be interpreted as the visual
  // one.
  DCHECK(!wayland_sockets_.empty());
  wayland_sockets_.push_back(socket);
  return *this;
}

VmBuilder& VmBuilder::AppendSharedDir(const std::string& shared_dir) {
  shared_dirs_.push_back(shared_dir);
  return *this;
}

VmBuilder& VmBuilder::AppendCustomParam(const std::string& key,
                                        const std::string& value) {
  custom_params_.emplace_back(key, value);
  return *this;
}

VmBuilder& VmBuilder::EnableGpu(bool enable) {
  enable_gpu_ = enable;
  return *this;
}

VmBuilder& VmBuilder::EnableVulkan(bool enable) {
  enable_vulkan_ = enable;
  return *this;
}

VmBuilder& VmBuilder::EnableBigGl(bool enable) {
#if USE_BIG_GL
  enable_big_gl_ = enable;
#else
  LOG_IF(WARNING, enable) << "Big GL is not supported on this board";
  enable_big_gl_ = false;
#endif
  return *this;
}

VmBuilder& VmBuilder::EnableRenderServer(bool enable) {
  enable_render_server_ = enable;
  return *this;
}

VmBuilder& VmBuilder::SetGpuCachePath(base::FilePath gpu_cache_path) {
  gpu_cache_path_ = std::move(gpu_cache_path);
  return *this;
}

VmBuilder& VmBuilder::SetGpuCacheSize(std::string gpu_cache_size_str) {
  gpu_cache_size_str_ = std::move(gpu_cache_size_str);
  return *this;
}

VmBuilder& VmBuilder::SetRenderServerCachePath(
    base::FilePath render_server_cache_path) {
  render_server_cache_path_ = std::move(render_server_cache_path);
  return *this;
}

VmBuilder& VmBuilder::SetRenderServerCacheSize(
    std::string render_server_cache_size_str) {
  render_server_cache_size_str_ = std::move(render_server_cache_size_str);
  return *this;
}

VmBuilder& VmBuilder::EnableSoftwareTpm(bool enable) {
  enable_software_tpm_ = enable;
  return *this;
}

VmBuilder& VmBuilder::EnableVideoDecoder(bool enable) {
  enable_video_decoder_ = enable;
  return *this;
}

VmBuilder& VmBuilder::EnableVideoEncoder(bool enable) {
  enable_video_encoder_ = enable;
  return *this;
}

VmBuilder& VmBuilder::EnableBattery(bool enable) {
  enable_battery_ = enable;
  return *this;
}

VmBuilder& VmBuilder::EnableSmt(bool enable) {
  enable_smt_ = enable;
  return *this;
}

VmBuilder& VmBuilder::EnableDelayRt(bool enable) {
  enable_delay_rt_ = enable;
  return *this;
}

VmBuilder& VmBuilder::EnablePerVmCoreScheduling(bool enable) {
  enable_per_vm_core_scheduling_ = enable;
  return *this;
}

VmBuilder& VmBuilder::EnableODirect(bool enable) {
  for (auto& d : disks_) {
    d.EnableODirect(enable);
  }
  return *this;
}

VmBuilder& VmBuilder::SetBlockSize(size_t block_size) {
  for (auto& d : disks_) {
    d.SetBlockSize(block_size);
  }
  return *this;
}

VmBuilder& VmBuilder::SetVmMemoryId(VmMemoryId vm_memory_id) {
  vm_memory_id_ = std::make_optional(vm_memory_id);
  return *this;
}

base::StringPairs VmBuilder::BuildVmArgs() const {
  base::StringPairs args = {{kCrosvmBin, "run"}};

  args.emplace_back("--cpus", std::to_string(cpus_));

  if (!memory_in_mib_.empty())
    args.emplace_back("--mem", memory_in_mib_);

  if (!balloon_bias_mib_.empty())
    args.emplace_back("--balloon_bias_mib", balloon_bias_mib_);

  for (const auto& tap_fd : tap_fds_)
    args.emplace_back("--tap-fd", std::to_string(tap_fd.get()));

  if (vsock_cid_.has_value())
    args.emplace_back("--cid", std::to_string(vsock_cid_.value()));

  if (!vm_socket_path_.empty())
    args.emplace_back("--socket", vm_socket_path_);

  for (const auto& w : wayland_sockets_)
    args.emplace_back("--wayland-sock", w);

  for (const auto& s : serial_devices_)
    args.emplace_back("--serial", s);

  if (!syslog_tag_.empty())
    args.emplace_back("--syslog-tag", syslog_tag_);

  if (enable_smt_.has_value()) {
    if (!enable_smt_.value())
      args.emplace_back("--no-smt", "");
  }

  if (enable_delay_rt_)
    args.emplace_back("--delay-rt", "");

  if (enable_per_vm_core_scheduling_)
    args.emplace_back("--per-vm-core-scheduling", "");

  if (kernel_params_.size() > 0)
    args.emplace_back("--params", base::JoinString(kernel_params_, " "));

  if (rootfs_.has_value()) {
    const auto& rootfs = rootfs_.value();
    if (rootfs.device.find("pmem") != std::string::npos) {
      if (rootfs.writable) {
        args.emplace_back("--rw-pmem-device", rootfs.path.value());
      } else {
        args.emplace_back("--pmem-device", rootfs.path.value());
      }
      // TODO(davidriley): Re-add rootflags=dax once guest kernel has fix for
      // b/169339326.
      args.emplace_back("--params", "root=/dev/pmem0 ro");
    } else {
      if (rootfs.writable) {
        args.emplace_back("--rwroot", rootfs.path.value());
      } else {
        args.emplace_back("--root", rootfs.path.value());
      }
    }
  }

  for (const auto& dev : audio_devices_) {
    switch (dev.type) {
      case AudioDeviceType::kAC97:
        args.emplace_back("--ac97", dev.params);
        break;
      case AudioDeviceType::kVirtio:
        args.emplace_back("--cras-snd", dev.params);
        break;
    }
  }

  for (const auto& d : disks_) {
    auto disk_args = d.GetCrosvmArgs();
    args.insert(std::end(args), std::begin(disk_args), std::end(disk_args));
  }

  if (enable_gpu_) {
    std::string gpu_arg = "--gpu=vulkan=";
    gpu_arg += enable_vulkan_ ? "true" : "false";
    if (enable_big_gl_) {
      gpu_arg += ",gles=false";
    }
    if (!gpu_cache_path_.empty()) {
      gpu_arg += ",cache-path=" + gpu_cache_path_.value();
    }
    if (!gpu_cache_size_str_.empty()) {
      gpu_arg += ",cache-size=" + gpu_cache_size_str_;
    }
    args.emplace_back(gpu_arg, "");

    if (enable_render_server_) {
      std::string render_server_arg = "--gpu-render-server=path=";
      render_server_arg += kVirglRenderServerPath;
      if (!render_server_cache_path_.empty()) {
        render_server_arg += ",cache-path=" + render_server_cache_path_.value();
      }
      if (!render_server_cache_size_str_.empty()) {
        render_server_arg += ",cache-size=" + render_server_cache_size_str_;
      }
      args.emplace_back(render_server_arg, "");
    }
  }

  if (enable_software_tpm_)
    args.emplace_back("--software-tpm", "");

  if (enable_video_decoder_)
    args.emplace_back("--video-decoder", "");

  if (enable_video_encoder_)
    args.emplace_back("--video-encoder", "");

  if (enable_battery_)
    args.emplace_back("--battery", "");

  for (const auto& shared_dir : shared_dirs_)
    args.emplace_back("--shared-dir", shared_dir);

  for (const auto& custom_param : custom_params_)
    args.emplace_back(custom_param.first, custom_param.second);

  if (!initrd_.empty())
    args.emplace_back("-i", initrd_.value());

  if (!bios_.empty())
    args.emplace_back("--bios", bios_.value());

  if (vm_memory_id_) {
    std::string mms_control_socket = "/run/mms_control_";
    mms_control_socket += std::to_string(*vm_memory_id_);
    mms_control_socket += ".sock";
    args.emplace_back("--balloon-control", mms_control_socket);
  }

  // Kernel should be at the end.
  if (!kernel_.empty())
    args.emplace_back(kernel_.value(), "");

  return args;
}

}  // namespace concierge
}  // namespace vm_tools
