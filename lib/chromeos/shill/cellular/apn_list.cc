// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/apn_list.h"

#include <tuple>

#include <base/containers/contains.h>
#include <chromeos/dbus/service_constants.h>

namespace shill {

void ApnList::AddApns(const std::vector<MobileOperatorInfo::MobileAPN>& apns,
                      ApnSource source) {
  for (const auto& mobile_apn : apns)
    AddApn(mobile_apn, source);
}

ApnList::ApnIndexKey ApnList::GetKey(
    const MobileOperatorInfo::MobileAPN& mobile_apn) {
  return std::make_tuple(mobile_apn.apn, mobile_apn.username,
                         mobile_apn.password, mobile_apn.authentication);
}

void ApnList::AddApn(const MobileOperatorInfo::MobileAPN& mobile_apn,
                     ApnSource source) {
  ApnList::ApnIndexKey index = GetKey(mobile_apn);
  if (!base::Contains(apn_index_, index)) {
    apn_dict_list_.emplace_back();
    apn_index_[index] = apn_dict_list_.size() - 1;
  }

  Stringmap& props = apn_dict_list_.at(apn_index_[index]);
  if (!mobile_apn.apn.empty())
    props[kApnProperty] = mobile_apn.apn;
  if (!mobile_apn.username.empty())
    props[kApnUsernameProperty] = mobile_apn.username;
  if (!mobile_apn.password.empty())
    props[kApnPasswordProperty] = mobile_apn.password;
  if (!mobile_apn.authentication.empty())
    props[kApnAuthenticationProperty] = mobile_apn.authentication;
  if (mobile_apn.is_attach_apn)
    props[kApnAttachProperty] = kApnAttachProperty;
  if (!mobile_apn.ip_type.empty())
    props[kApnIpTypeProperty] = mobile_apn.ip_type;

  // Find the first localized and non-localized name, if any.
  if (!mobile_apn.operator_name_list.empty())
    props[kApnNameProperty] = mobile_apn.operator_name_list[0].name;

  switch (source) {
    case ApnSource::kModb:
      props[cellular::kApnSource] = cellular::kApnSourceMoDb;
      break;
    case ApnSource::kModem:
      props[cellular::kApnSource] = cellular::kApnSourceModem;
      break;
  }
  for (const auto& lname : mobile_apn.operator_name_list) {
    if (!lname.language.empty())
      props[kApnLocalizedNameProperty] = lname.name;
  }
}

}  // namespace shill
