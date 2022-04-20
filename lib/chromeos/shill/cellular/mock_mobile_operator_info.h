// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MOBILE_OPERATOR_INFO_H_
#define SHILL_CELLULAR_MOCK_MOBILE_OPERATOR_INFO_H_

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/cellular/mobile_operator_info.h"

namespace shill {

class MockMobileOperatorInfo : public MobileOperatorInfo {
 public:
  MockMobileOperatorInfo(EventDispatcher* dispatcher,
                         const std::string& info_owner);
  ~MockMobileOperatorInfo() override;

  MOCK_METHOD(bool, IsMobileNetworkOperatorKnown, (), (const, override));

  MOCK_METHOD(const std::string&, mccmnc, (), (const, override));
  MOCK_METHOD(const std::vector<MobileOperatorInfo::MobileAPN>&,
              apn_list,
              (),
              (const, override));
  MOCK_METHOD(const std::vector<MobileOperatorInfo::OnlinePortal>&,
              olp_list,
              (),
              (const, override));
  MOCK_METHOD(const std::string&, activation_code, (), (const, override));
  MOCK_METHOD(const std::string&, operator_name, (), (const, override));
  MOCK_METHOD(const std::string&, country, (), (const, override));
  MOCK_METHOD(const std::string&, uuid, (), (const, override));

  MOCK_METHOD(void, UpdateMCCMNC, (const std::string&), (override));
  MOCK_METHOD(void, UpdateSID, (const std::string&), (override));
  MOCK_METHOD(void, UpdateIMSI, (const std::string&), (override));
  MOCK_METHOD(void, UpdateNID, (const std::string&), (override));
  MOCK_METHOD(void, UpdateOperatorName, (const std::string&), (override));

 private:
  std::string empty_mccmnc_;
  std::vector<MobileOperatorInfo::MobileAPN> empty_apn_list_;
  std::vector<MobileOperatorInfo::OnlinePortal> empty_olp_list_;
  std::string empty_activation_code_;
  std::string empty_operator_name_;
  std::string empty_country_;
  std::string empty_uuid_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MOBILE_OPERATOR_INFO_H_
