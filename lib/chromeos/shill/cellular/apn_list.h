// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_APN_LIST_H_
#define SHILL_CELLULAR_APN_LIST_H_

#include <map>
#include <string>
#include <tuple>
#include <vector>

#include "shill/cellular/cellular_consts.h"
#include "shill/cellular/mobile_operator_info.h"
#include "shill/data_types.h"

namespace shill {

class ApnList {
 public:
  ApnList() = default;
  ~ApnList() = default;

  enum class ApnSource { kModb, kModem };
  void AddApns(const std::vector<MobileOperatorInfo::MobileAPN>& apns,
               ApnSource source);

  const Stringmaps& GetList() { return apn_dict_list_; }

 private:
  using ApnIndexKey =
      std::tuple<std::string, std::string, std::string, std::string>;
  ApnIndexKey GetKey(const MobileOperatorInfo::MobileAPN& mobile_apn);

  void AddApn(const MobileOperatorInfo::MobileAPN& mobile_apn,
              ApnSource source);

  Stringmaps apn_dict_list_;
  std::map<ApnIndexKey, int> apn_index_;

  ApnList(const ApnList&) = delete;
  ApnList& operator=(const ApnList&) = delete;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_APN_LIST_H_
