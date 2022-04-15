// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// There are several methods to use lvm2 constructs from C or C++ code:
// - liblvm2app (deprecated) is a natural interface to creating and using
//   lvm2 construct objects and performing operations on them. However, the
//   deprecation of this library renders its use a non-starter.
// - executing the command line utilities directly.
// - liblvm2cmd provides an interface to run lvm2 commands without the
//   indirection of another process execution. While this is faster, the output
//   collection mechanism for liblvm2cmd relies on overriding the logging
//   function.
// - lvmdbusd is a daemon (written in Python) with a D-Bus interface which
//   exec()s the relevant commands. However, this library is additionally
//   intended to be used in situations where D-Bus may or may not be running.
//
// To strike a balance between speed and usability, the following class uses
// liblvm2cmd for commands without output (eg. pvcreate, vgcreate ...) and
// uses a process invocation for the rest.

#include "brillo/blkdev_utils/lvm.h"

#include <optional>

#include <base/logging.h>

namespace brillo {

LogicalVolumeManager::LogicalVolumeManager()
    : LogicalVolumeManager(std::make_shared<LvmCommandRunner>()) {}

LogicalVolumeManager::LogicalVolumeManager(
    std::shared_ptr<LvmCommandRunner> lvm)
    : lvm_(lvm) {}

bool LogicalVolumeManager::ValidatePhysicalVolume(
    const base::FilePath& device_path, std::string* volume_group_name) {
  std::string output;

  if (!lvm_->RunProcess({"/sbin/pvdisplay", "-C", "--reportformat", "json",
                         device_path.value()},
                        &output)) {
    LOG(ERROR) << "Failed to get output from pvdisplay";
    return false;
  }

  std::optional<base::Value> pv_dictionary =
      lvm_->UnwrapReportContents(output, "pv");

  if (!pv_dictionary || !pv_dictionary->is_dict()) {
    LOG(ERROR) << "Failed to get report contents";
    return false;
  }

  const std::string* pv_name = pv_dictionary->FindStringKey("pv_name");
  if (!pv_name && *pv_name != device_path.value()) {
    LOG(ERROR) << "Mismatched value: expected: " << device_path
               << " actual: " << *pv_name;
    return false;
  }

  if (volume_group_name) {
    const std::string* vg_name = pv_dictionary->FindStringKey("vg_name");
    if (!vg_name) {
      LOG(ERROR) << "Failed to fetch volume group name";
      return false;
    }
    *volume_group_name = *vg_name;
  }

  return true;
}

std::optional<PhysicalVolume> LogicalVolumeManager::GetPhysicalVolume(
    const base::FilePath& device_path) {
  return ValidatePhysicalVolume(device_path, nullptr)
             ? std::make_optional(PhysicalVolume(device_path, lvm_))
             : std::nullopt;
}

std::optional<VolumeGroup> LogicalVolumeManager::GetVolumeGroup(
    const PhysicalVolume& pv) {
  std::string vg_name;
  return ValidatePhysicalVolume(pv.GetPath(), &vg_name)
             ? std::make_optional(VolumeGroup(vg_name, lvm_))
             : std::nullopt;
}

bool LogicalVolumeManager::ValidateLogicalVolume(const VolumeGroup& vg,
                                                 const std::string& lv_name,
                                                 bool is_thinpool) {
  std::string output;
  const std::string vg_name = vg.GetName();

  std::string pool_lv_check = is_thinpool ? "pool_lv=\"\"" : "pool_lv!=\"\"";

  if (!lvm_->RunProcess({"/sbin/lvdisplay", "-S", pool_lv_check, "-C",
                         "--reportformat", "json", vg_name + "/" + lv_name},
                        &output)) {
    LOG(ERROR) << "Failed to get output from lvdisplay";
    return false;
  }

  std::optional<base::Value> lv_dictionary =
      lvm_->UnwrapReportContents(output, "lv");

  if (!lv_dictionary || !lv_dictionary->is_dict()) {
    LOG(ERROR) << "Failed to get report contents";
    return false;
  }

  const std::string* output_lv_name = lv_dictionary->FindStringKey("lv_name");
  if (!output_lv_name && *output_lv_name != lv_name) {
    LOG(ERROR) << "Mismatched value: expected: " << lv_name
               << " actual: " << *output_lv_name;
    return false;
  }

  return true;
}

std::optional<Thinpool> LogicalVolumeManager::GetThinpool(
    const VolumeGroup& vg, const std::string& thinpool_name) {
  return ValidateLogicalVolume(vg, thinpool_name, true /* is_thinpool */)
             ? std::make_optional(Thinpool(thinpool_name, vg.GetName(), lvm_))
             : std::nullopt;
}

std::optional<LogicalVolume> LogicalVolumeManager::GetLogicalVolume(
    const VolumeGroup& vg, const std::string& lv_name) {
  return ValidateLogicalVolume(vg, lv_name, false /* is_thinpool */)
             ? std::make_optional(LogicalVolume(lv_name, vg.GetName(), lvm_))
             : std::nullopt;
}

std::vector<LogicalVolume> LogicalVolumeManager::ListLogicalVolumes(
    const VolumeGroup& vg) {
  std::string output;
  std::string vg_name = vg.GetName();
  std::vector<LogicalVolume> lv_vector;

  if (!lvm_->RunProcess({"/sbin/lvdisplay", "-S", "pool_lv!=\"\"", "-C",
                         "--reportformat", "json", vg_name},
                        &output)) {
    LOG(ERROR) << "Failed to get output from lvdisplay";
    return lv_vector;
  }

  std::optional<base::Value> lv_list = lvm_->UnwrapReportContents(output, "lv");
  if (!lv_list || !lv_list->is_list()) {
    LOG(ERROR) << "Failed to get report contents";
    return lv_vector;
  }

  for (const auto& lv_dictionary : lv_list->GetList()) {
    if (!lv_dictionary.is_dict()) {
      LOG(ERROR) << "Failed to get dictionary value for physical volume";
      continue;
    }

    const std::string* output_lv_name = lv_dictionary.FindStringKey("lv_name");
    if (!output_lv_name) {
      LOG(ERROR) << "Failed to get logical volume name";
      continue;
    }

    lv_vector.push_back(LogicalVolume(*output_lv_name, vg_name, lvm_));
  }

  return lv_vector;
}

std::optional<PhysicalVolume> LogicalVolumeManager::CreatePhysicalVolume(
    const base::FilePath& device_path) {
  return lvm_->RunCommand({"pvcreate", "-ff", "--yes", device_path.value()})
             ? std::make_optional(PhysicalVolume(device_path, lvm_))
             : std::nullopt;
}

std::optional<VolumeGroup> LogicalVolumeManager::CreateVolumeGroup(
    const PhysicalVolume& pv, const std::string& vg_name) {
  return lvm_->RunCommand(
             {"vgcreate", "-p", "1", vg_name, pv.GetPath().value()})
             ? std::make_optional(VolumeGroup(vg_name, lvm_))
             : std::nullopt;
}

std::optional<Thinpool> LogicalVolumeManager::CreateThinpool(
    const VolumeGroup& vg, const base::Value& config) {
  std::vector<std::string> cmd = {"lvcreate"};
  const std::string* size = config.FindStringKey("size");
  const std::string* metadata_size = config.FindStringKey("metadata_size");
  const std::string* name = config.FindStringKey("name");
  if (!size || !name || !metadata_size) {
    LOG(ERROR) << "Invalid configuration";
    return std::nullopt;
  }

  cmd.insert(cmd.end(),
             {"--size", *size + "M", "--poolmetadatasize", *metadata_size + "M",
              "--thinpool", *name, vg.GetName()});

  return lvm_->RunCommand(cmd)
             ? std::make_optional(Thinpool(*name, vg.GetName(), lvm_))
             : std::nullopt;
}

std::optional<LogicalVolume> LogicalVolumeManager::CreateLogicalVolume(
    const VolumeGroup& vg,
    const Thinpool& thinpool,
    const base::Value& config) {
  std::vector<std::string> cmd = {"lvcreate", "--thin"};
  const std::string* size = config.FindStringKey("size");
  const std::string* name = config.FindStringKey("name");
  if (!size || !name) {
    LOG(ERROR) << "Invalid configuration";
    return std::nullopt;
  }

  cmd.insert(cmd.end(), {"-V", *size + "M", "-n", *name, thinpool.GetName()});

  return lvm_->RunCommand(cmd)
             ? std::make_optional(LogicalVolume(*name, vg.GetName(), lvm_))
             : std::nullopt;
}

}  // namespace brillo
