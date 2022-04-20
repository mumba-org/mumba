// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_SERVICE_PROVIDER_H_
#define SHILL_CELLULAR_CELLULAR_SERVICE_PROVIDER_H_

#include <string>
#include <vector>

#include <base/callback.h>
#include <base/memory/weak_ptr.h>

#include "shill/cellular/cellular_service.h"
#include "shill/provider_interface.h"
#include "shill/refptr_types.h"

namespace shill {

class Error;
class KeyValueStore;
class Manager;

class CellularServiceProvider : public ProviderInterface {
 public:
  explicit CellularServiceProvider(Manager* manager);
  CellularServiceProvider(const CellularServiceProvider&) = delete;
  CellularServiceProvider& operator=(const CellularServiceProvider&) = delete;

  ~CellularServiceProvider() override;

  // ProviderInterface
  void CreateServicesFromProfile(const ProfileRefPtr& profile) override;
  ServiceRefPtr FindSimilarService(const KeyValueStore& args,
                                   Error* error) const override;
  ServiceRefPtr GetService(const KeyValueStore& args, Error* error) override;
  ServiceRefPtr CreateTemporaryService(const KeyValueStore& args,
                                       Error* error) override;
  ServiceRefPtr CreateTemporaryServiceFromProfile(const ProfileRefPtr& profile,
                                                  const std::string& entry_name,
                                                  Error* error) override;
  void Start() override;
  void Stop() override;

  // Loads the services matching |device|. Returns a service matching the
  // current device IMSI, creating one if necessary.
  CellularServiceRefPtr LoadServicesForDevice(Cellular* device);

  // Removes services (i.e. services not associated with |device|).
  void RemoveNonDeviceServices(Cellular* device);

  // Loads any existing services matching |eid| or |iccid|.
  void LoadServicesForSecondarySim(const std::string& eid,
                                   const std::string& iccid,
                                   const std::string& imsi,
                                   Cellular* device);

  // Calls SetDevice for all services when important device properties change.
  void UpdateServices(Cellular* device);

  // Removes all services.
  void RemoveServices();

  // Returns a service matching |iccid_| if available.
  CellularServiceRefPtr FindService(const std::string& iccid) const;

  // Called when the Service is Unloaded from the Profile. If the Service
  // ICCID is not associated with any SIM, removes the service and returns true.
  // Otherwise returns false.
  bool OnServiceUnloaded(const CellularServiceRefPtr& service);

  void set_profile_for_testing(ProfileRefPtr profile) { profile_ = profile; }

 private:
  friend class CellularServiceProviderTest;

  CellularServiceRefPtr LoadMatchingServicesFromProfile(
      const std::string& eid,
      const std::string& iccid,
      const std::string& imsi,
      Cellular* device);
  void AddService(CellularServiceRefPtr service);
  void RemoveService(CellularServiceRefPtr service);

  Manager* manager_;
  // Use a single profile for Cellular services. Set to the first (device)
  // profile when CreateServicesFromProfile is called. This prevents confusing
  // edge cases if CellularService entries are stored in both the default and
  // user profile. The SIM card itself can provide access security with a PIN.
  ProfileRefPtr profile_;
  std::vector<CellularServiceRefPtr> services_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_SERVICE_PROVIDER_H_
