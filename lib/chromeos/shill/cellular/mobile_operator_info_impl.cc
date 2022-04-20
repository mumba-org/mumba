// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mobile_operator_info_impl.h"

#include <regex.h>

#include <memory>
#include <optional>
#include <utility>

#include <base/bind.h>
//#include <base/check.h>
//#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/service_constants.h>
#include <google/protobuf/repeated_field.h>

#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/protobuf_lite_streams.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kCellular;
static std::string ObjectID(const MobileOperatorInfoImpl* m) {
  return "(mobile_operator_info_impl)";
}
}  // namespace Logging

// static
const char MobileOperatorInfoImpl::kDefaultDatabasePath[] =
    "/usr/share/shill/serviceproviders.pbf";
// The exclusive-override db can be used to replace the default modb.
const char MobileOperatorInfoImpl::kExclusiveOverrideDatabasePath[] =
    "/usr/share/shill/serviceproviders-exclusive-override.pbf";
const int MobileOperatorInfoImpl::kMCCMNCMinLen = 5;

namespace {

// Wrap some low level functions from the GNU regex librarly.
std::string GetRegError(int code, const regex_t* compiled) {
  size_t length = regerror(code, compiled, nullptr, 0);
  std::vector<char> buffer(length);
  DCHECK_EQ(length, regerror(code, compiled, buffer.data(), length));
  return buffer.data();
}

std::string GetApnAuthentication(
    const shill::mobile_operator_db::MobileAPN& apn) {
  if (apn.has_authentication()) {
    switch (apn.authentication()) {
      case mobile_operator_db::MobileAPN_Authentication_PAP:
        return kApnAuthenticationPap;
      case mobile_operator_db::MobileAPN_Authentication_CHAP:
        return kApnAuthenticationChap;
      default:
        break;
    }
  }
  return std::string();
}

std::optional<std::string> GetIpType(
    const shill::mobile_operator_db::MobileAPN& apn) {
  if (!apn.has_ip_type()) {
    return kApnIpTypeV4;
  }

  switch (apn.ip_type()) {
    case mobile_operator_db::MobileAPN_IpType_UNKNOWN:
      return std::nullopt;
    case mobile_operator_db::MobileAPN_IpType_IPV4:
      return kApnIpTypeV4;
    case mobile_operator_db::MobileAPN_IpType_IPV6:
      return kApnIpTypeV6;
    case mobile_operator_db::MobileAPN_IpType_IPV4V6:
      return kApnIpTypeV4V6;
    default:
      return kApnIpTypeV4;
  }
}

}  // namespace

MobileOperatorInfoImpl::MobileOperatorInfoImpl(
    EventDispatcher* dispatcher,
    const std::string& info_owner,
    const base::FilePath& default_db_path,
    const base::FilePath& exclusive_override_db_path)
    : dispatcher_(dispatcher),
      info_owner_(info_owner),
      operator_code_type_(OperatorCodeType::kUnknown),
      current_mno_(nullptr),
      current_mvno_(nullptr),
      requires_roaming_(false),
      mtu_(IPConfig::kUndefinedMTU),
      user_olp_empty_(true),
      weak_ptr_factory_(this) {
  if (base::PathExists(exclusive_override_db_path))
    AddDatabasePath(exclusive_override_db_path);
  else
    AddDatabasePath(default_db_path);
}

MobileOperatorInfoImpl::MobileOperatorInfoImpl(EventDispatcher* dispatcher,
                                               const std::string& info_owner)
    : MobileOperatorInfoImpl::MobileOperatorInfoImpl(
          dispatcher,
          info_owner,
          base::FilePath(kDefaultDatabasePath),
          base::FilePath(kExclusiveOverrideDatabasePath)) {}

MobileOperatorInfoImpl::~MobileOperatorInfoImpl() = default;

void MobileOperatorInfoImpl::ClearDatabasePaths() {
  database_paths_.clear();
}

void MobileOperatorInfoImpl::AddDatabasePath(
    const base::FilePath& absolute_path) {
  database_paths_.push_back(absolute_path);
}

bool MobileOperatorInfoImpl::Init() {
  // |database_| is guaranteed to be set once |Init| is called.
  database_.reset(new shill::mobile_operator_db::MobileOperatorDB());

  bool found_databases = false;
  for (const auto& database_path : database_paths_) {
    const char* database_path_cstr = database_path.value().c_str();
    std::unique_ptr<google::protobuf::io::CopyingInputStreamAdaptor>
        database_stream;
    database_stream.reset(protobuf_lite_file_input_stream(database_path_cstr));
    if (!database_stream) {
      LOG(ERROR) << "Failed to read mobile operator database: "
                 << database_path_cstr;
      continue;
    }

    shill::mobile_operator_db::MobileOperatorDB database;
    if (!database.ParseFromZeroCopyStream(database_stream.get())) {
      LOG(ERROR) << "Could not parse mobile operator database: "
                 << database_path_cstr;
      continue;
    }
    SLOG(this, 1) << "Successfully loaded database: " << database_path_cstr;
    // Collate loaded databases into one as they're found.
    // TODO(pprabhu) This merge might be very costly. Determine if we need to
    // implement move semantics / bias the merge to use the largest database
    // as the base database and merge other databases into it.
    database_->MergeFrom(database);
    found_databases = true;
  }

  if (!found_databases) {
    LOG(ERROR) << "Could not read any mobile operator database. "
               << "Will not be able to determine MVNO.";
    return false;
  }

  PreprocessDatabase();
  return true;
}

void MobileOperatorInfoImpl::AddObserver(
    MobileOperatorInfo::Observer* observer) {
  observers_.AddObserver(observer);
}

void MobileOperatorInfoImpl::RemoveObserver(
    MobileOperatorInfo::Observer* observer) {
  observers_.RemoveObserver(observer);
}

bool MobileOperatorInfoImpl::IsMobileNetworkOperatorKnown() const {
  return (current_mno_ != nullptr);
}

bool MobileOperatorInfoImpl::IsMobileVirtualNetworkOperatorKnown() const {
  return (current_mvno_ != nullptr);
}

// ///////////////////////////////////////////////////////////////////////////
// Getters.
const std::string& MobileOperatorInfoImpl::info_owner() const {
  return info_owner_;
}

const std::string& MobileOperatorInfoImpl::uuid() const {
  return uuid_;
}

const std::string& MobileOperatorInfoImpl::operator_name() const {
  return operator_name_;
}

const std::string& MobileOperatorInfoImpl::country() const {
  return country_;
}

const std::string& MobileOperatorInfoImpl::mccmnc() const {
  return mccmnc_;
}

const std::string& MobileOperatorInfoImpl::MobileOperatorInfoImpl::sid() const {
  return sid_;
}

const std::string& MobileOperatorInfoImpl::nid() const {
  return (user_nid_ == "") ? nid_ : user_nid_;
}

const std::vector<std::string>& MobileOperatorInfoImpl::mccmnc_list() const {
  return mccmnc_list_;
}

const std::vector<std::string>& MobileOperatorInfoImpl::sid_list() const {
  return sid_list_;
}

const std::vector<MobileOperatorInfo::LocalizedName>&
MobileOperatorInfoImpl::operator_name_list() const {
  return operator_name_list_;
}

const std::vector<MobileOperatorInfo::MobileAPN>&
MobileOperatorInfoImpl::apn_list() const {
  return apn_list_;
}

const std::vector<MobileOperatorInfo::OnlinePortal>&
MobileOperatorInfoImpl::olp_list() const {
  return olp_list_;
}

const std::string& MobileOperatorInfoImpl::activation_code() const {
  return activation_code_;
}

bool MobileOperatorInfoImpl::requires_roaming() const {
  return requires_roaming_;
}

int32_t MobileOperatorInfoImpl::mtu() const {
  return mtu_;
}

// ///////////////////////////////////////////////////////////////////////////
// Functions used to notify this object of operator data changes.
void MobileOperatorInfoImpl::UpdateIMSI(const std::string& imsi) {
  bool operator_changed = false;
  if (user_imsi_ == imsi) {
    return;
  }

  SLOG(this, 1) << __func__ << ": " << imsi;
  user_imsi_ = imsi;

  if (!user_mccmnc_.empty()) {
    SLOG(this, 2) << __func__ << ": MCCMNC=" << user_mccmnc_;
    if (!base::StartsWith(imsi, user_mccmnc_,
                          base::CompareCase::INSENSITIVE_ASCII)) {
      LOG(WARNING) << "MCCMNC is not a substring of the IMSI.";
    }
  } else {
    // Attempt to determine the MNO from IMSI since MCCMNC is absent.
    AppendToCandidatesByMCCMNC(imsi.substr(0, kMCCMNCMinLen));
    AppendToCandidatesByMCCMNC(imsi.substr(0, kMCCMNCMinLen + 1));
    if (!candidates_by_operator_code_.empty()) {
      // We found some candidates using IMSI.
      operator_changed |= UpdateMNO();
    }
  }
  operator_changed |= UpdateMVNO();

  // No special notification should be sent for this property, since the object
  // does not expose |imsi| as a property at all.
  if (operator_changed) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorInfoImpl::UpdateICCID(const std::string& iccid) {
  if (user_iccid_ == iccid) {
    return;
  }

  SLOG(this, 1) << __func__ << ": " << iccid;
  user_iccid_ = iccid;
  // |iccid| is not an exposed property, so don't raise event for just this
  // property update.
  if (UpdateMVNO()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorInfoImpl::UpdateMCCMNC(const std::string& mccmnc) {
  if (user_mccmnc_ == mccmnc) {
    return;
  }

  SLOG(this, 3) << __func__ << ": " << mccmnc;
  user_mccmnc_ = mccmnc;
  HandleMCCMNCUpdate();
  candidates_by_operator_code_.clear();
  AppendToCandidatesByMCCMNC(mccmnc);

  // Always update M[V]NO, even if we found no candidates, since we might have
  // lost some candidates due to an incorrect MCCMNC.
  bool operator_changed = false;
  operator_changed |= UpdateMNO();
  operator_changed |= UpdateMVNO();
  if (operator_changed || ShouldNotifyPropertyUpdate()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorInfoImpl::UpdateSID(const std::string& sid) {
  if (user_sid_ == sid) {
    return;
  }

  SLOG(this, 3) << __func__ << ": " << sid;
  user_sid_ = sid;
  HandleSIDUpdate();
  candidates_by_operator_code_.clear();
  AppendToCandidatesBySID(sid);

  // Always update M[V]NO, even if we found no candidates, since we might have
  // lost some candidates due to an incorrect SID.
  bool operator_changed = false;
  operator_changed |= UpdateMNO();
  operator_changed |= UpdateMVNO();
  if (operator_changed || ShouldNotifyPropertyUpdate()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorInfoImpl::UpdateNID(const std::string& nid) {
  if (user_nid_ == nid) {
    return;
  }

  SLOG(this, 3) << __func__ << ": " << nid;
  user_nid_ = nid;
  if (UpdateMVNO() || ShouldNotifyPropertyUpdate()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorInfoImpl::UpdateOperatorName(
    const std::string& operator_name) {
  bool operator_changed = false;
  if (user_operator_name_ == operator_name) {
    return;
  }
  user_operator_name_ = operator_name;
  if (operator_name.empty()) {
    Reset();
    return;
  }

  SLOG(this, 2) << __func__ << ": " << operator_name;
  HandleOperatorNameUpdate();

  // We must update the candidates by name anyway.
  StringToMNOListMap::const_iterator cit =
      name_to_mnos_.find(NormalizeOperatorName(operator_name));
  candidates_by_name_.clear();
  if (cit != name_to_mnos_.end()) {
    candidates_by_name_ = cit->second;
    // We should never have inserted an empty vector into the map.
    DCHECK(!candidates_by_name_.empty());
  } else {
    LOG(INFO) << "Operator name [" << operator_name << "] "
              << "(Normalized: [" << NormalizeOperatorName(operator_name)
              << "]) does not match any MNO.";
  }

  operator_changed |= UpdateMNO();
  operator_changed |= UpdateMVNO();
  if (operator_changed || ShouldNotifyPropertyUpdate()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorInfoImpl::UpdateOnlinePortal(const std::string& url,
                                                const std::string& method,
                                                const std::string& post_data) {
  if (!user_olp_empty_ && user_olp_.url == url && user_olp_.method == method &&
      user_olp_.post_data == post_data) {
    return;
  }

  SLOG(this, 3) << __func__ << ": " << url;
  user_olp_empty_ = false;
  user_olp_.url = url;
  user_olp_.method = method;
  user_olp_.post_data = post_data;
  HandleOnlinePortalUpdate();

  // OnlinePortal is never used in deciding M[V]NO.
  if (ShouldNotifyPropertyUpdate()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorInfoImpl::Reset() {
  SLOG(this, 1) << __func__;
  bool should_notify = current_mno_ != nullptr || current_mvno_ != nullptr;

  current_mno_ = nullptr;
  current_mvno_ = nullptr;
  operator_code_type_ = OperatorCodeType::kUnknown;
  candidates_by_operator_code_.clear();
  candidates_by_name_.clear();

  ClearDBInformation();

  user_imsi_.clear();
  user_iccid_.clear();
  user_mccmnc_.clear();
  user_sid_.clear();
  user_nid_.clear();
  user_operator_name_.clear();
  user_olp_empty_ = true;
  user_olp_.url.clear();
  user_olp_.method.clear();
  user_olp_.post_data.clear();

  if (should_notify) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorInfoImpl::PreprocessDatabase() {
  SLOG(this, 3) << __func__;

  mccmnc_to_mnos_.clear();
  sid_to_mnos_.clear();
  name_to_mnos_.clear();

  const auto& mnos = database_->mno();
  for (const auto& mno : mnos) {
    // MobileNetworkOperator::data is a required field.
    DCHECK(mno.has_data());
    const auto& data = mno.data();

    const auto& mccmncs = data.mccmnc();
    for (const auto& mccmnc : mccmncs) {
      InsertIntoStringToMNOListMap(&mccmnc_to_mnos_, mccmnc, &mno);
    }

    const auto& sids = data.sid();
    for (const auto& sid : sids) {
      InsertIntoStringToMNOListMap(&sid_to_mnos_, sid, &mno);
    }

    const auto& localized_names = data.localized_name();
    for (const auto& localized_name : localized_names) {
      // LocalizedName::name is a required field.
      DCHECK(localized_name.has_name());
      InsertIntoStringToMNOListMap(
          &name_to_mnos_, NormalizeOperatorName(localized_name.name()), &mno);
    }
  }
}

// This function assumes that duplicate |values| are never inserted for the
// same |key|. If you do that, the function is too dumb to deduplicate the
// |value|s, and two copies will get stored.
void MobileOperatorInfoImpl::InsertIntoStringToMNOListMap(
    StringToMNOListMap* table,
    const std::string& key,
    const shill::mobile_operator_db::MobileNetworkOperator* value) {
  (*table)[key].push_back(value);
}

bool MobileOperatorInfoImpl::AppendToCandidatesByMCCMNC(
    const std::string& mccmnc) {
  // First check that we haven't determined candidates using SID.
  if (operator_code_type_ == OperatorCodeType::kSID) {
    LOG(WARNING) << "SID update will be overridden by the MCCMNC update for "
                    "determining MNO.";
    candidates_by_operator_code_.clear();
  }

  operator_code_type_ = OperatorCodeType::kMCCMNC;
  StringToMNOListMap::const_iterator cit = mccmnc_to_mnos_.find(mccmnc);
  if (cit == mccmnc_to_mnos_.end()) {
    LOG(WARNING) << "Unknown MCCMNC value [" << mccmnc << "].";
    return false;
  }

  // We should never have inserted an empty vector into the map.
  DCHECK(!cit->second.empty());
  for (const auto& mno : cit->second) {
    candidates_by_operator_code_.push_back(mno);
  }
  return true;
}

bool MobileOperatorInfoImpl::AppendToCandidatesBySID(const std::string& sid) {
  // First check that we haven't determined candidates using MCCMNC.
  if (operator_code_type_ == OperatorCodeType::kMCCMNC) {
    LOG(WARNING) << "MCCMNC update will be overriden by the SID update for "
                    "determining MNO.";
    candidates_by_operator_code_.clear();
  }

  operator_code_type_ = OperatorCodeType::kSID;
  StringToMNOListMap::const_iterator cit = sid_to_mnos_.find(sid);
  if (cit == sid_to_mnos_.end()) {
    LOG(WARNING) << "Unknown SID value [" << sid << "].";
    return false;
  }

  // We should never have inserted an empty vector into the map.
  DCHECK(!cit->second.empty());
  for (const auto& mno : cit->second) {
    candidates_by_operator_code_.push_back(mno);
  }
  return true;
}

std::string MobileOperatorInfoImpl::OperatorCodeString() const {
  switch (operator_code_type_) {
    case OperatorCodeType::kMCCMNC:
      return "MCCMNC";
    case OperatorCodeType::kSID:
      return "SID";
    case OperatorCodeType::kUnknown:
      return "UnknownOperatorCodeType";
  }
}

bool MobileOperatorInfoImpl::UpdateMNO() {
  SLOG(this, 3) << __func__;
  const shill::mobile_operator_db::MobileNetworkOperator* candidate = nullptr;

  // The only way |operator_code_type_| can be |OperatorCodeType::kUnknown| is
  // that we haven't received any operator_code updates yet.
  DCHECK(operator_code_type_ == OperatorCodeType::kMCCMNC ||
         operator_code_type_ == OperatorCodeType::kSID ||
         (user_mccmnc_.empty() && user_sid_.empty()));

  if (candidates_by_operator_code_.size() == 1) {
    candidate = candidates_by_operator_code_[0];
    if (!candidates_by_name_.empty()) {
      bool found_match = false;
      for (auto candidate_by_name : candidates_by_name_) {
        if (candidate_by_name == candidate) {
          found_match = true;
          break;
        }
      }
      if (!found_match) {
        const std::string& operator_code =
            (operator_code_type_ == OperatorCodeType::kMCCMNC) ? user_mccmnc_
                                                               : user_sid_;
        SLOG(this, 1) << "MNO determined by " << OperatorCodeString() << " ["
                      << operator_code
                      << "] does not match any suggested by name["
                      << user_operator_name_ << "]. " << OperatorCodeString()
                      << " overrides name!";
      }
    }
  } else if (candidates_by_operator_code_.size() > 1) {
    // Try to find an intersection of the two candidate lists. These lists
    // should be almost always of length 1. Simply iterate.
    for (auto candidate_by_mccmnc : candidates_by_operator_code_) {
      for (auto candidate_by_name : candidates_by_name_) {
        if (candidate_by_mccmnc == candidate_by_name) {
          candidate = candidate_by_mccmnc;
          break;
        }
      }
      if (candidate != nullptr) {
        break;
      }
    }
    if (candidate == nullptr) {
      const std::string& operator_code =
          (operator_code_type_ == OperatorCodeType::kMCCMNC) ? user_mccmnc_
                                                             : user_sid_;
      SLOG(this, 1) << "MNOs suggested by " << OperatorCodeString() << " ["
                    << operator_code
                    << "] are multiple and disjoint from those suggested "
                    << "by name[" << user_operator_name_ << "].";
      candidate = PickOneFromDuplicates(candidates_by_operator_code_);
    }
  } else {  // candidates_by_operator_code_.size() == 0
    // Special case: In case we had a *wrong* operator_code update, we want
    // to override the suggestions from |user_operator_name_|. We should not
    // determine an MNO in this case.
    if ((operator_code_type_ == OperatorCodeType::kMCCMNC &&
         !user_mccmnc_.empty()) ||
        (operator_code_type_ == OperatorCodeType::kSID && !user_sid_.empty())) {
      SLOG(this, 1) << "A non-matching " << OperatorCodeString() << " "
                    << "was reported by the user."
                    << "We fail the MNO match in this case.";
    } else if (candidates_by_name_.size() == 1) {
      candidate = candidates_by_name_[0];
    } else if (candidates_by_name_.size() > 1) {
      SLOG(this, 1) << "Multiple MNOs suggested by name[" << user_operator_name_
                    << "], and none by MCCMNC.";
      candidate = PickOneFromDuplicates(candidates_by_name_);
    } else {  // candidates_by_name_.size() == 0
      SLOG(this, 1) << "No candidates suggested.";
    }
  }

  if (candidate != current_mno_) {
    current_mno_ = candidate;
    RefreshDBInformation();
    return true;
  }
  return false;
}

bool MobileOperatorInfoImpl::UpdateMVNO() {
  SLOG(this, 3) << __func__;

  std::vector<const shill::mobile_operator_db::MobileVirtualNetworkOperator*>
      candidate_mvnos;
  for (const auto& mvno : database_->mvno()) {
    candidate_mvnos.push_back(&mvno);
  }
  if (current_mno_) {
    for (const auto& mvno : current_mno_->mvno()) {
      candidate_mvnos.push_back(&mvno);
    }
  }

  for (const auto* candidate_mvno : candidate_mvnos) {
    bool passed_all_filters = true;
    for (const auto& filter : candidate_mvno->mvno_filter()) {
      if (!FilterMatches(filter)) {
        passed_all_filters = false;
        break;
      }
    }
    if (passed_all_filters) {
      if (current_mvno_ == candidate_mvno) {
        return false;
      }
      current_mvno_ = candidate_mvno;
      RefreshDBInformation();
      return true;
    }
  }

  // We did not find any valid MVNO.
  if (current_mvno_ != nullptr) {
    current_mvno_ = nullptr;
    RefreshDBInformation();
    return true;
  }
  return false;
}

const shill::mobile_operator_db::MobileNetworkOperator*
MobileOperatorInfoImpl::PickOneFromDuplicates(
    const std::vector<const shill::mobile_operator_db::MobileNetworkOperator*>&
        duplicates) const {
  if (duplicates.empty())
    return nullptr;

  for (auto candidate : duplicates) {
    if (candidate->earmarked()) {
      SLOG(this, 2) << "Picking earmarked candidate: "
                    << candidate->data().uuid();
      return candidate;
    }
  }
  SLOG(this, 2) << "No earmarked candidate found. Choosing the first.";
  return duplicates[0];
}

bool MobileOperatorInfoImpl::FilterMatches(
    const shill::mobile_operator_db::Filter& filter) {
  DCHECK(filter.has_regex() || filter.range_size());
  std::string to_match;
  switch (filter.type()) {
    case mobile_operator_db::Filter_Type_IMSI:
      to_match = user_imsi_;
      break;
    case mobile_operator_db::Filter_Type_ICCID:
      to_match = user_iccid_;
      break;
    case mobile_operator_db::Filter_Type_SID:
      to_match = user_sid_;
      break;
    case mobile_operator_db::Filter_Type_OPERATOR_NAME:
      to_match = user_operator_name_;
      break;
    case mobile_operator_db::Filter_Type_MCCMNC:
      to_match = user_mccmnc_;
      break;
    default:
      SLOG(this, 1) << "Unknown filter type [" << filter.type() << "]";
      return false;
  }
  // |to_match| can be empty if we have no *user provided* information of the
  // correct type.
  if (to_match.empty()) {
    SLOG(this, 2) << "Nothing to match against (filter: " << filter.regex()
                  << ").";
    return false;
  }

  // Match against numerical ranges rather than a regular expression
  if (filter.range_size()) {
    DCHECK(!filter.has_regex());

    uint64_t match_value;
    if (!base::StringToUint64(to_match, &match_value)) {
      SLOG(this, 3) << "Need a number to match against a range (" << match_value
                    << ").";
      return false;
    }

    for (auto r : filter.range()) {
      if ((r.start() <= match_value) && (match_value <= r.end()))
        return true;
    }
    // No range is matching
    return false;
  }

  // Must use GNU regex implementation, since C++11 implementation is
  // incomplete.
  regex_t filter_regex;
  std::string filter_regex_str = filter.regex();

  // |regexec| matches the given regular expression to a substring of the
  // given query string. Ensure that |filter_regex_str| uses anchors to
  // accept only a full match.
  if (filter_regex_str.front() != '^') {
    filter_regex_str = "^" + filter_regex_str;
  }
  if (filter_regex_str.back() != '$') {
    filter_regex_str = filter_regex_str + "$";
  }

  int regcomp_error = regcomp(&filter_regex, filter_regex_str.c_str(),
                              REG_EXTENDED | REG_NOSUB);
  if (regcomp_error) {
    LOG(WARNING) << "Could not compile regex '" << filter.regex() << "'. "
                 << "Error returned: "
                 << GetRegError(regcomp_error, &filter_regex) << ". ";
    regfree(&filter_regex);
    return false;
  }

  int regexec_error = regexec(&filter_regex, to_match.c_str(), 0, nullptr, 0);
  if (regexec_error) {
    std::string error_string;
    error_string = GetRegError(regcomp_error, &filter_regex);
    SLOG(this, 2) << "Skipping because string '" << to_match << "' is not a "
                  << "match of regexp '" << filter.regex() << "'. "
                  << (error_string.empty() ? "" : "Error returned: ")
                  << error_string;
    regfree(&filter_regex);
    return false;
  } else {
    SLOG(this, 2) << "Regex '" << filter.regex() << "' matches '" << to_match
                  << "'.";
  }
  regfree(&filter_regex);
  return true;
}

void MobileOperatorInfoImpl::RefreshDBInformation() {
  ClearDBInformation();

  if (current_mno_ == nullptr) {
    return;
  }

  // |data| is a required field.
  DCHECK(current_mno_->has_data());
  SLOG(this, 2) << "Reloading MNO data.";
  ReloadData(current_mno_->data());

  if (current_mvno_ != nullptr) {
    // |data| is a required field.
    DCHECK(current_mvno_->has_data());
    SLOG(this, 2) << "Reloading MVNO data.";
    ReloadData(current_mvno_->data());
  }
}

void MobileOperatorInfoImpl::ClearDBInformation() {
  uuid_.clear();
  country_.clear();
  nid_.clear();
  mccmnc_list_.clear();
  HandleMCCMNCUpdate();
  sid_list_.clear();
  HandleSIDUpdate();
  operator_name_list_.clear();
  prioritizes_db_operator_name_ = false;
  HandleOperatorNameUpdate();
  apn_list_.clear();
  olp_list_.clear();
  raw_olp_list_.clear();
  HandleOnlinePortalUpdate();
  activation_code_.clear();
  requires_roaming_ = false;
  roaming_filter_list_.clear();
  mtu_ = IPConfig::kUndefinedMTU;
}

void MobileOperatorInfoImpl::ReloadData(
    const shill::mobile_operator_db::Data& data) {
  SLOG(this, 3) << __func__;
  // |uuid_| is *always* overwritten. An MNO and MVNO should not share the
  // |uuid_|.
  CHECK(data.has_uuid());
  uuid_ = data.uuid();

  if (data.has_country()) {
    country_ = data.country();
  }

  if (data.has_prioritizes_name()) {
    prioritizes_db_operator_name_ = data.prioritizes_name();
  }

  if (data.localized_name_size() > 0) {
    operator_name_list_.clear();
    for (const auto& localized_name : data.localized_name()) {
      operator_name_list_.push_back(
          {localized_name.name(), localized_name.language()});
    }
    HandleOperatorNameUpdate();
  }

  if (data.has_requires_roaming()) {
    requires_roaming_ = data.requires_roaming();
  }

  if (data.roaming_filter_size() > 0) {
    roaming_filter_list_.clear();
    for (const auto& filter : data.roaming_filter()) {
      roaming_filter_list_.push_back(filter);
    }
  }

  if (data.mtu()) {
    mtu_ = data.mtu();
  }

  if (data.olp_size() > 0) {
    raw_olp_list_.clear();
    // Copy the olp list so we can mutate it.
    for (const auto& olp : data.olp()) {
      raw_olp_list_.push_back(olp);
    }
    HandleOnlinePortalUpdate();
  }

  if (data.mccmnc_size() > 0) {
    mccmnc_list_.clear();
    for (const auto& mccmnc : data.mccmnc()) {
      mccmnc_list_.push_back(mccmnc);
    }
    HandleMCCMNCUpdate();
  }

  if (data.mobile_apn_size() > 0) {
    apn_list_.clear();
    for (const auto& apn_data : data.mobile_apn()) {
      MobileOperatorInfo::MobileAPN apn;
      apn.apn = apn_data.apn();
      apn.username = apn_data.username();
      apn.password = apn_data.password();
      for (const auto& localized_name : apn_data.localized_name()) {
        apn.operator_name_list.push_back(
            {localized_name.name(), localized_name.language()});
      }
      apn.authentication = GetApnAuthentication(apn_data);
      apn.is_attach_apn =
          apn_data.has_is_attach_apn() ? apn_data.is_attach_apn() : false;
      std::optional<std::string> ip_type = GetIpType(apn_data);
      if (!ip_type.has_value()) {
        LOG(INFO) << "Unknown IP type for APN \"" << apn_data.apn() << "\"";
        continue;
      }
      apn.ip_type = ip_type.value();

      apn_list_.push_back(std::move(apn));
    }
  }

  if (data.sid_size() > 0) {
    sid_list_.clear();
    for (const auto& sid : data.sid()) {
      sid_list_.push_back(sid);
    }
    HandleSIDUpdate();
  }

  if (data.has_activation_code()) {
    activation_code_ = data.activation_code();
  }
}

void MobileOperatorInfoImpl::HandleMCCMNCUpdate() {
  if (!user_mccmnc_.empty()) {
    bool append_to_list = true;
    for (const auto& mccmnc : mccmnc_list_) {
      append_to_list &= (user_mccmnc_ != mccmnc);
    }
    if (append_to_list) {
      mccmnc_list_.push_back(user_mccmnc_);
    }
  }

  if (!user_mccmnc_.empty()) {
    mccmnc_ = user_mccmnc_;
  } else if (!mccmnc_list_.empty()) {
    mccmnc_ = mccmnc_list_[0];
  } else {
    mccmnc_.clear();
  }
}

void MobileOperatorInfoImpl::HandleOperatorNameUpdate() {
  if (!user_operator_name_.empty()) {
    std::vector<MobileOperatorInfo::LocalizedName> localized_names;
    MobileOperatorInfo::LocalizedName localized_name{user_operator_name_, ""};
    localized_names.emplace_back(localized_name);
    for (auto it = operator_name_list_.begin();
         it != operator_name_list_.end();) {
      if (it->name == user_operator_name_) {
        localized_name = {user_operator_name_, it->language};
        localized_names.push_back(localized_name);
        operator_name_list_.erase(it);
      } else {
        it++;
      }
    }

    operator_name_list_.insert(
        (prioritizes_db_operator_name_ ? operator_name_list_.end()
                                       : operator_name_list_.begin()),
        localized_names.begin(), localized_names.end());
  }

  operator_name_ =
      operator_name_list_.empty() ? "" : operator_name_list_[0].name;
}

void MobileOperatorInfoImpl::HandleSIDUpdate() {
  if (!user_sid_.empty()) {
    bool append_user_sid = true;
    for (const auto& sid : sid_list_) {
      append_user_sid &= (user_sid_ != sid);
    }
    if (append_user_sid) {
      sid_list_.push_back(user_sid_);
    }
  }

  if (!user_sid_.empty()) {
    sid_ = user_sid_;
  } else if (!sid_list_.empty()) {
    sid_ = sid_list_[0];
  } else {
    sid_.clear();
  }
}

// Warning: Currently, an MCCMNC/SID update by itself does not result into
// recomputation of the |olp_list_|. This means that if the new MCCMNC/SID
// causes an online portal filter to match, we'll miss that.
// This won't be a problem if either the MNO or the MVNO changes, since data is
// reloaded then.
// This is a corner case that we don't expect to hit, since MCCMNC doesn't
// really change in a running system.
void MobileOperatorInfoImpl::HandleOnlinePortalUpdate() {
  // Always recompute |olp_list_|. We don't expect this list to be big.
  olp_list_.clear();
  for (const auto& raw_olp : raw_olp_list_) {
    if (!raw_olp.has_olp_filter() || FilterMatches(raw_olp.olp_filter())) {
      olp_list_.push_back(MobileOperatorInfo::OnlinePortal{
          raw_olp.url(), (raw_olp.method() == raw_olp.GET) ? "GET" : "POST",
          raw_olp.post_data()});
    }
  }
  if (!user_olp_empty_) {
    bool append_user_olp = true;
    for (const auto& olp : olp_list_) {
      append_user_olp &=
          (olp.url != user_olp_.url || olp.method != user_olp_.method ||
           olp.post_data != user_olp_.post_data);
    }
    if (append_user_olp) {
      olp_list_.push_back(user_olp_);
    }
  }
}

// When serving operator updates, filter it using |roaming_filter_list_|
// to decide if |requires_roaming_| is true or false.
void MobileOperatorInfoImpl::UpdateRequiresRoaming(
    const MobileOperatorInfo* serving_operator_info) {
  if (!serving_operator_info || serving_operator_info->mccmnc().empty())
    return;
  for (const auto& filter : roaming_filter_list_) {
    if (filter.type() != mobile_operator_db::Filter_Type_MCCMNC ||
        !filter.has_regex()) {
      continue;
    }
    regex_t roaming_mccmnc_regex;
    int regcomp_result = regcomp(&roaming_mccmnc_regex, filter.regex().c_str(),
                                 REG_EXTENDED | REG_NOSUB);
    if (regcomp_result != 0) {
      LOG(WARNING) << "Could not compile regex '" << filter.regex() << "'. ";
      regfree(&roaming_mccmnc_regex);
      continue;
    }
    int regexec_result =
        regexec(&roaming_mccmnc_regex, serving_operator_info->mccmnc().c_str(),
                0, nullptr, 0);
    regfree(&roaming_mccmnc_regex);
    requires_roaming_ = regexec_result == 0;
    if (requires_roaming_) {
      SLOG(this, 1)
          << "requires_roaming is updated to true due to roaming filtering";
      break;
    }
    SLOG(this, 2) << "Serving operator MCCMNC: "
                  << serving_operator_info->mccmnc()
                  << " filtering regex: " << filter.regex()
                  << " results, requires_roaming: " << requires_roaming_;
  }
}

void MobileOperatorInfoImpl::PostNotifyOperatorChanged() {
  SLOG(this, 3) << __func__;
  // If there was an outstanding task, it will get replaced.
  notify_operator_changed_task_.Reset(
      base::Bind(&MobileOperatorInfoImpl::NotifyOperatorChanged,
                 weak_ptr_factory_.GetWeakPtr()));
  dispatcher_->PostTask(FROM_HERE, notify_operator_changed_task_.callback());
}

void MobileOperatorInfoImpl::NotifyOperatorChanged() {
  for (MobileOperatorInfo::Observer& observer : observers_)
    observer.OnOperatorChanged();
}

bool MobileOperatorInfoImpl::ShouldNotifyPropertyUpdate() const {
  return IsMobileNetworkOperatorKnown() ||
         IsMobileVirtualNetworkOperatorKnown();
}

std::string MobileOperatorInfoImpl::NormalizeOperatorName(
    const std::string& name) const {
  auto result = base::ToLowerASCII(name);
  base::RemoveChars(result, base::kWhitespaceASCII, &result);
  return result;
}

}  // namespace shill
