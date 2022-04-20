// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DEFAULT_PROFILE_H_
#define SHILL_DEFAULT_PROFILE_H_

#include <string>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/event_dispatcher.h"
#include "shill/manager.h"
#include "shill/profile.h"
#include "shill/refptr_types.h"
#include "shill/store/property_store.h"

namespace shill {

class DefaultProfile : public Profile {
 public:
  static const char kDefaultId[];

  // b/204261554: The property name in the D-Bus API which controls if the new
  // swanctl-based L2TPIPsecDriver should be used instead of the legacy one
  // based on ipsec script and stroke. This property will be deprecated and
  // removed when the migration is done.
  static constexpr char kUseSwanctlDriver[] = "UseSwanctlDriver";

  DefaultProfile(Manager* manager,
                 const base::FilePath& storage_directory,
                 const std::string& profile_id,
                 const ManagerProperties& manager_props);
  DefaultProfile(const DefaultProfile&) = delete;
  DefaultProfile& operator=(const DefaultProfile&) = delete;

  ~DefaultProfile() override;

  // Loads global configuration into manager properties.  This should
  // only be called by the Manager.
  virtual void LoadManagerProperties(ManagerProperties* manager_props);

  // Override the Profile superclass implementation to accept all Ethernet
  // services, since these should have an affinity for the default profile.
  bool ConfigureService(const ServiceRefPtr& service) override;

  // Persists profile information, as well as that of discovered devices
  // and bound services, to disk.
  // Returns true on success, false on failure.
  bool Save() override;

  // Inherited from Profile.
  bool UpdateDevice(const DeviceRefPtr& device) override;

  bool IsDefault() const override { return true; }

  bool GetUseSwanctlDriver(Error* error);

#if !defined(DISABLE_WIFI)
  bool GetFTEnabled(Error* error);
#endif  // DISABLE_WIFI

 private:
  friend class DefaultProfileTest;
  FRIEND_TEST(DefaultProfileTest, GetStoragePath);
  FRIEND_TEST(DefaultProfileTest, LoadManagerDefaultProperties);
  FRIEND_TEST(DefaultProfileTest, LoadManagerProperties);
  FRIEND_TEST(DefaultProfileTest, Save);

  static const char kStorageArpGateway[];
  static const char kStorageCheckPortalList[];
  static const char kStorageHostName[];
  static const char kStorageIgnoredDNSSearchPaths[];
  static const char kStorageName[];
  static const char kStorageNoAutoConnectTechnologies[];
  static const char kStorageProhibitedTechnologies[];
  static const char kStorageUseSwanctlDriver[];
  static const char kStorageDhcpHostname[];
#if !defined(DISABLE_WIFI)
  static const char kStorageWifiGlobalFTEnabled[];
#endif  // DISABLE_WIFI

  void HelpRegisterConstDerivedBool(const std::string& name,
                                    bool (DefaultProfile::*get)(Error* error));

  const std::string profile_id_;
  const ManagerProperties& props_;
};

}  // namespace shill

#endif  // SHILL_DEFAULT_PROFILE_H_
