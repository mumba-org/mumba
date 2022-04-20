// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <iostream>

#include <base/logging.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <brillo/flag_helper.h>

#include "shill/cellular/mobile_operator_info.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/test_event_dispatcher.h"

namespace shill {
class MyEventDispatcher : public shill::EventDispatcher {
 public:
  MyEventDispatcher() {}
  ~MyEventDispatcher() {}

  void DispatchForever() {}
  void DispatchPendingEvents() {}
  void PostDelayedTask(const base::Location& location,
                       base::OnceClosure task,
                       base::TimeDelta delay) {}
  void QuitDispatchForever() {}
};
}  // namespace shill

int main(int argc, char* argv[]) {
  DEFINE_string(mccmnc, "", "MCCMNC.");
  DEFINE_string(imsi, "", "IMSI.");
  DEFINE_string(iccid, "", "ICCID.");
  DEFINE_string(name, "", "Operator Name.");
  DEFINE_string(sid, "", "SID.");
  DEFINE_string(nid, "", "NID.");

  brillo::FlagHelper::Init(argc, argv, "cellular_mobile_operator_info_tester");

  shill::MyEventDispatcher dispatcher;
  std::unique_ptr<shill::MobileOperatorInfo> operator_info =
      std::make_unique<shill::MobileOperatorInfo>(&dispatcher, "tester");
  operator_info->ClearDatabasePaths();
  base::FilePath executable_path = base::FilePath(argv[0]).DirName();
  base::FilePath database_path =
      base::FilePath(executable_path).Append("serviceproviders.pbf");

  logging::SetMinLogLevel(logging::LOGGING_INFO);
  shill::ScopeLogger::GetInstance()->set_verbose_level(5);
  shill::ScopeLogger::GetInstance()->EnableScopesByName("cellular");

  operator_info->AddDatabasePath(database_path);
  operator_info->Init();

  if (!FLAGS_mccmnc.empty())
    operator_info->UpdateMCCMNC(FLAGS_mccmnc);

  operator_info->IsMobileNetworkOperatorKnown();

  if (!FLAGS_name.empty())
    operator_info->UpdateOperatorName(FLAGS_name);

  operator_info->IsMobileNetworkOperatorKnown();

  if (!FLAGS_iccid.empty())
    operator_info->UpdateICCID(FLAGS_iccid);

  operator_info->IsMobileNetworkOperatorKnown();

  if (!FLAGS_imsi.empty())
    operator_info->UpdateIMSI(FLAGS_imsi);

  operator_info->IsMobileNetworkOperatorKnown();

  if (!FLAGS_sid.empty())
    operator_info->UpdateSID(FLAGS_sid);

  operator_info->IsMobileNetworkOperatorKnown();

  if (!FLAGS_nid.empty())
    operator_info->UpdateNID(FLAGS_nid);

  // The following lines will print to cout because ScopeLogger is set to
  // level 5.
  std::cout << "\nMobileOperatorInfo values:"
            << "\n";
  operator_info->uuid();
  operator_info->operator_name();
  operator_info->country();
  operator_info->mccmnc();
  operator_info->sid();
  operator_info->nid();
  operator_info->requires_roaming();
  operator_info->apn_list();
  operator_info->IsMobileNetworkOperatorKnown();
  return 0;
}
