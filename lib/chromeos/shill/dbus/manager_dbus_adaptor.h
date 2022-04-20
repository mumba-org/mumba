// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MANAGER_DBUS_ADAPTOR_H_
#define SHILL_DBUS_MANAGER_DBUS_ADAPTOR_H_

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "dbus_bindings/org.chromium.flimflam.Manager.h"
#include "shill/adaptor_interfaces.h"
#include "shill/dbus/dbus_adaptor.h"
#include "shill/dbus/dbus_service_watcher.h"

namespace shill {

class DBusServiceWatcherFactory;
class Manager;

// Subclass of DBusAdaptor for Manager objects
// There is a 1:1 mapping between Manager and ManagerDBusAdaptor
// instances.  Furthermore, the Manager owns the ManagerDBusAdaptor
// and manages its lifetime, so we're OK with ManagerDBusAdaptor
// having a bare pointer to its owner manager.
class ManagerDBusAdaptor : public org::chromium::flimflam::ManagerAdaptor,
                           public org::chromium::flimflam::ManagerInterface,
                           public DBusAdaptor,
                           public ManagerAdaptorInterface {
 public:
  static const char kPath[];

  ManagerDBusAdaptor(const scoped_refptr<dbus::Bus>& adaptor_bus,
                     const scoped_refptr<dbus::Bus> proxy_bus,
                     Manager* manager);
  ManagerDBusAdaptor(const ManagerDBusAdaptor&) = delete;
  ManagerDBusAdaptor& operator=(const ManagerDBusAdaptor&) = delete;

  ~ManagerDBusAdaptor() override;

  // Implementation of ManagerAdaptorInterface.
  void RegisterAsync(
      const base::Callback<void(bool)>& completion_callback) override;
  const RpcIdentifier& GetRpcIdentifier() const override { return dbus_path(); }
  void EmitBoolChanged(const std::string& name, bool value) override;
  void EmitUintChanged(const std::string& name, uint32_t value) override;
  void EmitIntChanged(const std::string& name, int value) override;
  void EmitStringChanged(const std::string& name,
                         const std::string& value) override;
  void EmitStringsChanged(const std::string& name,
                          const std::vector<std::string>& value) override;
  void EmitKeyValueStoreChanged(const std::string& name,
                                const KeyValueStore& value) override;
  void EmitRpcIdentifierChanged(const std::string& name,
                                const RpcIdentifier& value) override;
  void EmitRpcIdentifierArrayChanged(const std::string& name,
                                     const RpcIdentifiers& value) override;

  // Implementation of Manager_adaptor
  bool GetProperties(brillo::ErrorPtr* error,
                     brillo::VariantDictionary* properties) override;
  bool SetProperty(brillo::ErrorPtr* error,
                   const std::string& name,
                   const brillo::Any& value) override;
  bool GetState(brillo::ErrorPtr* error, std::string* state) override;
  bool CreateProfile(brillo::ErrorPtr* error,
                     const std::string& name,
                     dbus::ObjectPath* profile_path) override;
  bool RemoveProfile(brillo::ErrorPtr* error, const std::string& name) override;
  bool PushProfile(brillo::ErrorPtr* error,
                   const std::string& name,
                   dbus::ObjectPath* profile_path) override;
  void SetNetworkThrottlingStatus(DBusMethodResponsePtr<> response,
                                  bool enabled,
                                  uint32_t upload_rate_kbits,
                                  uint32_t download_rate_kbits) override;
  bool InsertUserProfile(brillo::ErrorPtr* error,
                         const std::string& name,
                         const std::string& user_hash,
                         dbus::ObjectPath* profile_path) override;
  bool PopProfile(brillo::ErrorPtr* error, const std::string& name) override;
  bool PopAnyProfile(brillo::ErrorPtr* error) override;
  bool PopAllUserProfiles(brillo::ErrorPtr* error) override;
  bool RecheckPortal(brillo::ErrorPtr* error) override;
  bool RequestScan(brillo::ErrorPtr* error,
                   const std::string& technology) override;
  void EnableTechnology(DBusMethodResponsePtr<> response,
                        const std::string& technology_namer) override;
  void DisableTechnology(DBusMethodResponsePtr<> response,
                         const std::string& technology_name) override;
  bool GetService(brillo::ErrorPtr* error,
                  const brillo::VariantDictionary& args,
                  dbus::ObjectPath* service_path) override;
  bool ConfigureService(brillo::ErrorPtr* error,
                        const brillo::VariantDictionary& args,
                        dbus::ObjectPath* service_path) override;
  bool ConfigureServiceForProfile(brillo::ErrorPtr* error,
                                  const dbus::ObjectPath& profile_rpcid,
                                  const brillo::VariantDictionary& args,
                                  dbus::ObjectPath* service_path) override;
  bool FindMatchingService(brillo::ErrorPtr* error,
                           const brillo::VariantDictionary& args,
                           dbus::ObjectPath* service_path) override;
  bool GetDebugLevel(brillo::ErrorPtr* error, int32_t* level) override;
  bool SetDebugLevel(brillo::ErrorPtr* error, int32_t level) override;
  bool GetServiceOrder(brillo::ErrorPtr* error, std::string* order) override;
  bool SetServiceOrder(brillo::ErrorPtr* error,
                       const std::string& order) override;
  bool GetDebugTags(brillo::ErrorPtr* error, std::string* tags) override;
  bool SetDebugTags(brillo::ErrorPtr* error, const std::string& tags) override;
  bool ListDebugTags(brillo::ErrorPtr* error, std::string* tags) override;
  bool GetNetworksForGeolocation(brillo::ErrorPtr* error,
                                 brillo::VariantDictionary* networks) override;
  bool ScanAndConnectToBestServices(brillo::ErrorPtr* error) override;
  // TODO(b:206907629): Remove the D-Bus method when chrome is not calling it
  // anymore.
  bool ConnectToBestServices(brillo::ErrorPtr* error) override;
  bool CreateConnectivityReport(brillo::ErrorPtr* error) override;
  bool ClaimInterface(brillo::ErrorPtr* error,
                      dbus::Message* message,
                      const std::string& claimer_name,
                      const std::string& interface_name) override;
  bool ReleaseInterface(brillo::ErrorPtr* error,
                        dbus::Message* message,
                        const std::string& claimer_name,
                        const std::string& interface_name) override;
  bool SetDNSProxyAddresses(brillo::ErrorPtr* error,
                            const std::vector<std::string>& addresses) override;
  bool ClearDNSProxyAddresses(brillo::ErrorPtr* error) override;
  bool SetDNSProxyDOHProviders(
      brillo::ErrorPtr* error,
      const brillo::VariantDictionary& providers) override;
  bool AddPasspointCredentials(brillo::ErrorPtr* error,
                               const dbus::ObjectPath& profile_rpcid,
                               const brillo::VariantDictionary& args) override;
  bool RemovePasspointCredentials(
      brillo::ErrorPtr* error,
      const dbus::ObjectPath& profile_rpcid,
      const brillo::VariantDictionary& args) override;

 private:
  friend class ManagerDBusAdaptorTest;
  // Tests that require access to |watcher_for_device_claimer_|.
  FRIEND_TEST(ManagerDBusAdaptorTest, ClaimInterface);
  FRIEND_TEST(ManagerDBusAdaptorTest, OnDeviceClaimerVanished);
  FRIEND_TEST(ManagerDBusAdaptorTest, ReleaseInterface);

  void OnDeviceClaimerVanished();

  Manager* manager_;
  // We store a pointer to |proxy_bus_| in order to create a
  // DBusServiceWatcher objects.
  scoped_refptr<dbus::Bus> proxy_bus_;
  DBusServiceWatcherFactory* dbus_service_watcher_factory_;
  std::unique_ptr<DBusServiceWatcher> watcher_for_device_claimer_;
};

}  // namespace shill

#endif  // SHILL_DBUS_MANAGER_DBUS_ADAPTOR_H_
