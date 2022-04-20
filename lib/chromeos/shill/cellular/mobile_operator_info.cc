// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mobile_operator_info.h"

#include <sstream>

#include "shill/cellular/mobile_operator_info_impl.h"
#include "shill/logging.h"

#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kCellular;
static std::string ObjectID(const MobileOperatorInfo* m) {
  return "(mobile_operator_info)";
}
}  // namespace Logging

// /////////////////////////////////////////////////////////////////////////////
// MobileOperatorInfo implementation note:
// MobileOperatorInfo simply forwards all operations to |impl_|.
// It also logs the functions/arguments/results at reasonable log levels. So the
// implementation need not leave a trace itself.

MobileOperatorInfo::MobileOperatorInfo(EventDispatcher* dispatcher,
                                       const std::string& info_owner)
    : impl_(new MobileOperatorInfoImpl(dispatcher, info_owner)) {}

MobileOperatorInfo::~MobileOperatorInfo() = default;

std::string MobileOperatorInfo::GetLogPrefix(const char* func) const {
  return impl_->info_owner() + ": " + func;
}

void MobileOperatorInfo::ClearDatabasePaths() {
  SLOG(this, 3) << GetLogPrefix(__func__);
  impl_->ClearDatabasePaths();
}

void MobileOperatorInfo::AddDatabasePath(const base::FilePath& absolute_path) {
  SLOG(this, 3) << GetLogPrefix(__func__) << "(" << absolute_path.value()
                << ")";
  impl_->AddDatabasePath(absolute_path);
}

bool MobileOperatorInfo::Init() {
  auto result = impl_->Init();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

void MobileOperatorInfo::AddObserver(MobileOperatorInfo::Observer* observer) {
  SLOG(this, 3) << GetLogPrefix(__func__);
  impl_->AddObserver(observer);
}

void MobileOperatorInfo::RemoveObserver(
    MobileOperatorInfo::Observer* observer) {
  SLOG(this, 3) << GetLogPrefix(__func__);
  impl_->RemoveObserver(observer);
}

bool MobileOperatorInfo::IsMobileNetworkOperatorKnown() const {
  auto result = impl_->IsMobileNetworkOperatorKnown();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

bool MobileOperatorInfo::IsMobileVirtualNetworkOperatorKnown() const {
  auto result = impl_->IsMobileVirtualNetworkOperatorKnown();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

const std::string& MobileOperatorInfo::uuid() const {
  const auto& result = impl_->uuid();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

const std::string& MobileOperatorInfo::operator_name() const {
  const auto& result = impl_->operator_name();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

const std::string& MobileOperatorInfo::country() const {
  const auto& result = impl_->country();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

const std::string& MobileOperatorInfo::mccmnc() const {
  const auto& result = impl_->mccmnc();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

const std::string& MobileOperatorInfo::sid() const {
  const auto& result = impl_->sid();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

const std::string& MobileOperatorInfo::nid() const {
  const auto& result = impl_->nid();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

const std::vector<std::string>& MobileOperatorInfo::mccmnc_list() const {
  const auto& result = impl_->mccmnc_list();
  if (SLOG_IS_ON(Cellular, 3)) {
    std::stringstream pp_result;
    for (const auto& mccmnc : result) {
      pp_result << mccmnc << " ";
    }
    SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << pp_result.str()
                  << "]";
  }
  return result;
}

const std::vector<std::string>& MobileOperatorInfo::sid_list() const {
  const auto& result = impl_->sid_list();
  if (SLOG_IS_ON(Cellular, 3)) {
    std::stringstream pp_result;
    for (const auto& sid : result) {
      pp_result << sid << " ";
    }
    SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << pp_result.str()
                  << "]";
  }
  return result;
}

const std::vector<MobileOperatorInfo::LocalizedName>&
MobileOperatorInfo::operator_name_list() const {
  const auto& result = impl_->operator_name_list();
  if (SLOG_IS_ON(Cellular, 3)) {
    std::stringstream pp_result;
    for (const auto& operator_name : result) {
      pp_result << "(" << operator_name.name << ", " << operator_name.language
                << ") ";
    }
    SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << pp_result.str()
                  << "]";
  }
  return result;
}

const std::vector<MobileOperatorInfo::MobileAPN>& MobileOperatorInfo::apn_list()
    const {
  const auto& result = impl_->apn_list();
  if (SLOG_IS_ON(Cellular, 3)) {
    std::stringstream pp_result;
    for (const auto& mobile_apn : result) {
      pp_result << "(apn: " << mobile_apn.apn
                << ", username: " << mobile_apn.username
                << ", password: " << mobile_apn.password;
      pp_result << ", operator_name_list: '";
      for (const auto& operator_name : mobile_apn.operator_name_list) {
        pp_result << "(" << operator_name.name << ", " << operator_name.language
                  << ") ";
      }
      pp_result << "') ";
    }
    SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << pp_result.str()
                  << "]";
  }
  return result;
}

const std::vector<MobileOperatorInfo::OnlinePortal>&
MobileOperatorInfo::olp_list() const {
  const auto& result = impl_->olp_list();
  if (SLOG_IS_ON(Cellular, 3)) {
    std::stringstream pp_result;
    for (const auto& olp : result) {
      pp_result << "(url: " << olp.url << ", method: " << olp.method
                << ", post_data: " << olp.post_data << ") ";
    }
    SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << pp_result.str()
                  << "]";
  }
  return result;
}

const std::string& MobileOperatorInfo::activation_code() const {
  const auto& result = impl_->activation_code();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

bool MobileOperatorInfo::requires_roaming() const {
  auto result = impl_->requires_roaming();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

int32_t MobileOperatorInfo::mtu() const {
  auto result = impl_->mtu();
  SLOG(this, 3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

void MobileOperatorInfo::UpdateIMSI(const std::string& imsi) {
  SLOG(this, 3) << GetLogPrefix(__func__) << "(" << imsi << ")";
  impl_->UpdateIMSI(imsi);
}

void MobileOperatorInfo::UpdateICCID(const std::string& iccid) {
  SLOG(this, 3) << GetLogPrefix(__func__) << "(" << iccid << ")";
  impl_->UpdateICCID(iccid);
}

void MobileOperatorInfo::UpdateMCCMNC(const std::string& mccmnc) {
  SLOG(this, 3) << GetLogPrefix(__func__) << "(" << mccmnc << ")";
  impl_->UpdateMCCMNC(mccmnc);
}

void MobileOperatorInfo::UpdateSID(const std::string& sid) {
  SLOG(this, 3) << GetLogPrefix(__func__) << "(" << sid << ")";
  impl_->UpdateSID(sid);
}

void MobileOperatorInfo::UpdateNID(const std::string& nid) {
  SLOG(this, 3) << GetLogPrefix(__func__) << "(" << nid << ")";
  impl_->UpdateNID(nid);
}

void MobileOperatorInfo::UpdateOperatorName(const std::string& operator_name) {
  SLOG(this, 3) << GetLogPrefix(__func__) << "(" << operator_name << ")";
  impl_->UpdateOperatorName(operator_name);
}

void MobileOperatorInfo::UpdateOnlinePortal(const std::string& url,
                                            const std::string& method,
                                            const std::string& post_data) {
  SLOG(this, 3) << GetLogPrefix(__func__) << "(" << url << ", " << method
                << ", " << post_data << ")";
  impl_->UpdateOnlinePortal(url, method, post_data);
}

void MobileOperatorInfo::UpdateRequiresRoaming(
    const MobileOperatorInfo* serving_operator_info) {
  impl_->UpdateRequiresRoaming(serving_operator_info);
  SLOG(this, 3) << GetLogPrefix(__func__)
                << "Updated requires_roaming: " << impl_->requires_roaming();
}

void MobileOperatorInfo::Reset() {
  SLOG(this, 3) << GetLogPrefix(__func__);
  impl_->Reset();
}

}  // namespace shill
