// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STATIC_IP_PARAMETERS_H_
#define SHILL_STATIC_IP_PARAMETERS_H_

#include <string>
#include <vector>

#include <base/logging.h>

#include "shill/ipconfig.h"
#include "shill/store/key_value_store.h"
#include "shill/store/property_store.h"

namespace shill {
class StoreInterface;

// Holder for static IP parameters.  Includes methods for reading and
// displaying values over a control API, methods for loading and
// storing this to a persistent store, as well as applying these
// parameters to an IPConfig object.
class StaticIPParameters {
 public:
  static const char kConfigKeyPrefix[];
  static const char kSavedConfigKeyPrefix[];

  StaticIPParameters();
  StaticIPParameters(const StaticIPParameters&) = delete;
  StaticIPParameters& operator=(const StaticIPParameters&) = delete;

  virtual ~StaticIPParameters();

  // Take a property store and add static IP parameters to them.
  void PlumbPropertyStore(PropertyStore* store);

  // Load static IP parameters from a persistent store with id |storage_id|.
  // Return whether any property is changed.
  bool Load(const StoreInterface* storage, const std::string& storage_id);

  // Save static IP parameters to a persistent store with id |storage_id|.
  void Save(StoreInterface* storage, const std::string& storage_id);

  // Apply static IP parameters to an IPConfig properties object, and save
  // their original values.
  void ApplyTo(IPConfig::Properties* props);

  // Restore IP parameters from |saved_args_| to |props|, then clear
  // |saved_args_|.
  void RestoreTo(IPConfig::Properties* props);

  // Remove any saved parameters from a previous call to ApplyTo().
  void ClearSavedParameters();

  // Return whether configuration parameters contain an address property.
  bool ContainsAddress() const;

  // Return whether configuration parameters contain a namerservers property.
  bool ContainsNameServers() const;

  // Reset all states to defaults (e.g. when a service is unloaded).
  void Reset();

 private:
  friend class StaticIPParametersTest;
  FRIEND_TEST(DeviceTest, IPConfigUpdatedFailureWithStatic);

  struct Property {
    enum Type {
      kTypeInt32,
      kTypeString,
      // Properties of type "Strings" are stored as a comma-separated list
      // in the control interface and in the profile, but are stored as a
      // vector of strings in the IPConfig properties.
      kTypeStrings
    };

    const char* name;
    Type type;
  };

  static const Property kProperties[];

  // These functions try to retrieve the argument |property| out of the
  // KeyValueStore in |args_|.  If that value exists, overwrite |value_out|
  // with its contents, and save the previous value into |saved_args_|.
  void ApplyInt(const std::string& property, int32_t* value_out);
  void ApplyString(const std::string& property, std::string* value_out);
  void ApplyStrings(const std::string& property,
                    std::vector<std::string>* value_out);
  void RestoreStrings(const std::string& property,
                      std::vector<std::string>* value_out);
  void ParseRoutes(const std::vector<std::string>& route_list,
                   const std::string& gateway,
                   std::vector<IPConfig::Route>* value_out);
  void ApplyRoutes(IPConfig::Properties* props);
  void RestoreRoutes(IPConfig::Properties* props);

  KeyValueStore GetSavedIPConfig(Error* error);
  KeyValueStore GetStaticIPConfig(Error* error);
  bool SetStaticIP(const KeyValueStore& value, Error* error);

  KeyValueStore args_;
  KeyValueStore saved_args_;
};

}  // namespace shill

#endif  // SHILL_STATIC_IP_PARAMETERS_H_
