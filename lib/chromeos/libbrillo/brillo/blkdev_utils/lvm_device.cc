// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/blkdev_utils/lvm_device.h"

#include <optional>
#include <utility>

// lvm2 has multiple options for managing LVM objects:
// - liblvm2app: deprecated.
// - liblvm2cmd: simple interface to directly parse cli commands into functions.
// - lvmdbusd: persistent daemon that can be reached via D-Bus.
//
// Since the logical/physical volume and volume group creation can occur during
// early boot when dbus is not available, the preferred solution is to use
// lvm2cmd.
#include <lvm2cmd.h>

#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/values.h>
#include <brillo/process/process.h>

namespace brillo {
namespace {

void LogLvmError(int rc, const std::string& cmd) {
  switch (rc) {
    case LVM2_COMMAND_SUCCEEDED:
      break;
    case LVM2_NO_SUCH_COMMAND:
      LOG(ERROR) << "Failed to run lvm2 command: no such command " << cmd;
      break;
    case LVM2_INVALID_PARAMETERS:
      LOG(ERROR) << "Failed to run lvm2 command: invalid parameters " << cmd;
      break;
    case LVM2_PROCESSING_FAILED:
      LOG(ERROR) << "Failed to run lvm2 command: processing failed " << cmd;
      break;
    default:
      LOG(ERROR) << "Failed to run lvm2 command: invalid return code " << cmd;
      break;
  }
}

// Fetch and validate size from report.
bool GetThinpoolSizeFromReportContents(const base::Value& report_contents,
                                       int64_t* size) {
  // Get thinpool size.
  const std::string* thinpool_size = report_contents.FindStringKey("lv_size");
  if (!thinpool_size) {
    LOG(ERROR) << "Failed to get thinpool size.";
    return false;
  }

  if (thinpool_size->empty()) {
    LOG(ERROR) << "Empty thinpool size string.";
    return false;
  }

  // Last character for size is always "B".
  if (thinpool_size->back() != 'B') {
    LOG(ERROR) << "Last character of thinpool size string should always be B.";
    return false;
  }

  // Use base::StringToInt64 to validate the returned size.
  if (!base::StringToInt64(
          base::StringPiece(thinpool_size->data(), thinpool_size->length() - 1),
          size)) {
    LOG(ERROR) << "Failed to convert thinpool size to a numeric value";
    return false;
  }

  return true;
}
}  // namespace

PhysicalVolume::PhysicalVolume(const base::FilePath& device_path,
                               std::shared_ptr<LvmCommandRunner> lvm)
    : device_path_(device_path), lvm_(lvm) {}

bool PhysicalVolume::Check() {
  if (device_path_.empty() || !lvm_)
    return false;

  return lvm_->RunCommand({"pvck", device_path_.value()});
}

bool PhysicalVolume::Repair() {
  if (device_path_.empty() || !lvm_)
    return false;

  return lvm_->RunCommand({"pvck", "--yes", device_path_.value()});
}

bool PhysicalVolume::Remove() {
  if (device_path_.empty() || !lvm_)
    return false;

  bool ret = lvm_->RunCommand({"pvremove", "-ff", device_path_.value()});
  device_path_ = base::FilePath();
  return ret;
}

VolumeGroup::VolumeGroup(const std::string& volume_group_name,
                         std::shared_ptr<LvmCommandRunner> lvm)
    : volume_group_name_(volume_group_name), lvm_(lvm) {}

bool VolumeGroup::Check() {
  if (volume_group_name_.empty() || !lvm_)
    return false;

  return lvm_->RunCommand({"vgck", GetPath().value()});
}

bool VolumeGroup::Repair() {
  if (volume_group_name_.empty() || !lvm_)
    return false;
  return lvm_->RunCommand({"vgck", "--yes", GetPath().value()});
}

base::FilePath VolumeGroup::GetPath() const {
  if (volume_group_name_.empty() || !lvm_)
    return base::FilePath();
  return base::FilePath("/dev").Append(volume_group_name_);
}

bool VolumeGroup::Activate() {
  if (volume_group_name_.empty() || !lvm_)
    return false;
  return lvm_->RunCommand({"vgchange", "-ay", volume_group_name_});
}

bool VolumeGroup::Deactivate() {
  if (volume_group_name_.empty() || !lvm_)
    return false;
  return lvm_->RunCommand({"vgchange", "-an", volume_group_name_});
}

bool VolumeGroup::Remove() {
  if (volume_group_name_.empty() || !lvm_)
    return false;
  bool ret = lvm_->RunCommand({"vgremove", "-f", volume_group_name_});
  volume_group_name_ = "";
  return ret;
}

LogicalVolume::LogicalVolume(const std::string& logical_volume_name,
                             const std::string& volume_group_name,
                             std::shared_ptr<LvmCommandRunner> lvm)
    : logical_volume_name_(logical_volume_name),
      volume_group_name_(volume_group_name),
      lvm_(lvm) {}

base::FilePath LogicalVolume::GetPath() {
  if (logical_volume_name_.empty() || !lvm_)
    return base::FilePath();
  return base::FilePath("/dev")
      .Append(volume_group_name_)
      .Append(logical_volume_name_);
}

bool LogicalVolume::Activate() {
  if (logical_volume_name_.empty() || !lvm_)
    return false;
  return lvm_->RunCommand({"lvchange", "-ay", GetName()});
}

bool LogicalVolume::Deactivate() {
  if (logical_volume_name_.empty() || !lvm_)
    return false;
  return lvm_->RunCommand({"lvchange", "-an", GetName()});
}

bool LogicalVolume::Remove() {
  if (volume_group_name_.empty() || !lvm_)
    return false;
  bool ret = lvm_->RunCommand({"lvremove", "--force", GetName()});
  logical_volume_name_ = "";
  volume_group_name_ = "";
  return ret;
}

Thinpool::Thinpool(const std::string& thinpool_name,
                   const std::string& volume_group_name,
                   std::shared_ptr<LvmCommandRunner> lvm)
    : thinpool_name_(thinpool_name),
      volume_group_name_(volume_group_name),
      lvm_(lvm) {}

bool Thinpool::Check() {
  if (thinpool_name_.empty() || !lvm_)
    return false;

  return lvm_->RunProcess({"thin_check", GetName()});
}

bool Thinpool::Repair() {
  if (thinpool_name_.empty() || !lvm_)
    return false;
  return lvm_->RunProcess({"lvconvert", "--repair", GetName()});
}

bool Thinpool::Activate() {
  if (thinpool_name_.empty() || !lvm_)
    return false;
  return lvm_->RunCommand({"lvchange", "-ay", GetName()});
}

bool Thinpool::Deactivate() {
  if (thinpool_name_.empty() || !lvm_)
    return false;
  return lvm_->RunCommand({"lvchange", "-an", GetName()});
}

bool Thinpool::Remove() {
  if (thinpool_name_.empty() || !lvm_)
    return false;

  bool ret = lvm_->RunCommand({"lvremove", "--force", GetName()});
  volume_group_name_ = "";
  thinpool_name_ = "";
  return ret;
}

bool Thinpool::GetTotalSpace(int64_t* size) {
  if (thinpool_name_.empty() || !lvm_)
    return false;

  std::string output;

  if (!lvm_->RunProcess(
          {"/sbin/lvdisplay", "-S", "pool_lv=\"\"", "-C", "--reportformat",
           "json", "--units", "b", volume_group_name_ + "/" + thinpool_name_},
          &output)) {
    LOG(ERROR) << "Failed to get output from lvdisplay.";
    return false;
  }

  std::optional<base::Value> report_contents =
      lvm_->UnwrapReportContents(output, "lv");

  if (!report_contents || !report_contents->is_dict()) {
    LOG(ERROR) << "Failed to get report contents.";
    return false;
  }

  return GetThinpoolSizeFromReportContents(*report_contents, size);
}

bool Thinpool::GetFreeSpace(int64_t* size) {
  if (thinpool_name_.empty() || !lvm_)
    return false;

  std::string output;

  if (!lvm_->RunProcess(
          {"/sbin/lvdisplay", "-S", "pool_lv=\"\"", "-C", "--reportformat",
           "json", "--units", "b", volume_group_name_ + "/" + thinpool_name_},
          &output)) {
    LOG(ERROR) << "Failed to get output from lvdisplay.";
    return false;
  }

  std::optional<base::Value> report_contents =
      lvm_->UnwrapReportContents(output, "lv");

  if (!report_contents || !report_contents->is_dict()) {
    LOG(ERROR) << "Failed to get report contents.";
    return false;
  }

  // Get the percentage of used data from the thinpool. The value is stored as a
  // string in the json.
  std::string* data_used_percent =
      report_contents->FindStringKey("data_percent");
  if (!data_used_percent) {
    LOG(ERROR) << "Failed to get percentage size of thinpool used.";
    return false;
  }

  double used_percent;
  if (!base::StringToDouble(*data_used_percent, &used_percent)) {
    LOG(ERROR) << "Failed to convert used percentage string to double.";
    return false;
  }

  int64_t total_size;
  if (!GetThinpoolSizeFromReportContents(*report_contents, &total_size)) {
    LOG(ERROR) << "Failed to get total thinpool size.";
    return false;
  }

  *size = static_cast<int64_t>((100.0 - used_percent) / 100.0 * total_size);

  return true;
}

LvmCommandRunner::LvmCommandRunner() {}

LvmCommandRunner::~LvmCommandRunner() {}

bool LvmCommandRunner::RunCommand(const std::vector<std::string>& cmd) {
  // lvm2_run() does not exec/fork a separate process, instead it parses the
  // command line and calls the relevant functions within liblvm2cmd directly.
  std::string lvm_cmd = base::JoinString(cmd, " ");
  int rc = lvm2_run(nullptr, lvm_cmd.c_str());
  LogLvmError(rc, lvm_cmd);

  return rc == LVM2_COMMAND_SUCCEEDED;
}

bool LvmCommandRunner::RunProcess(const std::vector<std::string>& cmd,
                                  std::string* output) {
  brillo::ProcessImpl lvm_process;
  for (auto arg : cmd)
    lvm_process.AddArg(arg);
  lvm_process.SetCloseUnusedFileDescriptors(true);

  if (output) {
    lvm_process.RedirectUsingMemory(STDOUT_FILENO);
  }

  if (lvm_process.Run() != 0) {
    PLOG(ERROR) << "Failed to run command";
    return false;
  }

  if (output) {
    *output = lvm_process.GetOutputString(STDOUT_FILENO);
  }

  return true;
}

// LVM reports are structured as:
//  {
//      "report": [
//          {
//              "lv": [
//                  {"lv_name":"foo", "vg_name":"bar", ...},
//                  {...}
//              ]
//          }
//      ]
//  }
//
// Common function to fetch the underlying dictionary (assume for now
// that the reports will be reporting just a single type (lv/vg/pv) for now).

std::optional<base::Value> LvmCommandRunner::UnwrapReportContents(
    const std::string& output, const std::string& key) {
  auto report = base::JSONReader::Read(output);
  if (!report || !report->is_dict()) {
    LOG(ERROR) << "Failed to get report as dictionary";
    return std::nullopt;
  }

  base::Value* report_list = report->FindListKey("report");
  if (!report_list) {
    LOG(ERROR) << "Failed to find 'report' list";
    return std::nullopt;
  }

  if (report_list->GetList().size() != 1) {
    LOG(ERROR) << "Unexpected size: " << report_list->GetList().size();
    return std::nullopt;
  }

  base::Value& report_dictionary = report_list->GetList()[0];
  if (!report_dictionary.is_dict()) {
    LOG(ERROR) << "Failed to find 'report' dictionary";
    return std::nullopt;
  }

  base::Value* key_list = report_dictionary.FindListKey(key);
  if (!key_list) {
    LOG(ERROR) << "Failed to find " << key << " list";
    return std::nullopt;
  }

  // If the list has just a single dictionary element, return it directly.
  if (key_list->GetList().size() == 1) {
    base::Value& key_dictionary = key_list->GetList()[0];
    if (!key_dictionary.is_dict()) {
      LOG(ERROR) << "Failed to get " << key << " dictionary";
      return std::nullopt;
    }
    return std::move(key_dictionary);
  }

  return std::move(*key_list);
}

}  // namespace brillo
