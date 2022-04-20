// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/manager.h"

#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

//#include <base/check.h>
#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/scoped_refptr.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/patchpanel/dbus/fake_client.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/adaptor_interfaces.h"
#include "shill/dbus/dbus_control.h"
#include "shill/default_service_observer.h"
#include "shill/device_claimer.h"
#include "shill/ephemeral_profile.h"
#include "shill/error.h"
#include "shill/ethernet/mock_ethernet_provider.h"
#include "shill/geolocation_info.h"
#include "shill/logging.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_connection.h"
#include "shill/mock_control.h"
#include "shill/mock_device.h"
#include "shill/mock_device_info.h"
#include "shill/mock_log.h"
#include "shill/mock_metrics.h"
#include "shill/mock_power_manager.h"
#include "shill/mock_profile.h"
#include "shill/mock_resolver.h"
#include "shill/mock_service.h"
#include "shill/mock_throttler.h"
#include "shill/mock_virtual_device.h"
#include "shill/portal_detector.h"
#include "shill/resolver.h"
#include "shill/service_under_test.h"
#include "shill/store/fake_store.h"
#include "shill/store/key_file_store.h"
#include "shill/store/key_value_store.h"
#include "shill/store/property_store_test.h"
#include "shill/testing.h"
#include "shill/upstart/mock_upstart.h"
#include "shill/vpn/mock_vpn_service.h"

#if !defined(DISABLE_WIFI)
#include "shill/wifi/mock_wifi_provider.h"
#include "shill/wifi/mock_wifi_service.h"
#include "shill/wifi/wifi_service.h"
#endif  // DISABLE_WIFI

#if !defined(DISABLE_WIRED_8021X)
#include "shill/ethernet/mock_ethernet_eap_provider.h"
#endif  // DISABLE_WIRED_8021X

namespace shill {
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::ContainerEq;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::IsEmpty;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Ref;
using ::testing::Return;
using ::testing::ReturnNull;
using ::testing::ReturnRef;
using ::testing::ReturnRefOfCopy;
using ::testing::SaveArg;
using ::testing::StrEq;
using ::testing::StrictMock;
using ::testing::Test;
using ::testing::WithArg;
using ::testing::WithParamInterface;

class ManagerTest : public PropertyStoreTest {
 public:
  ManagerTest()
      : power_manager_(new MockPowerManager(control_interface())),
        device_info_(new NiceMock<MockDeviceInfo>(manager())),
        manager_adaptor_(new NiceMock<ManagerMockAdaptor>()),
        ethernet_provider_(new NiceMock<MockEthernetProvider>()),
#if !defined(DISABLE_WIRED_8021X)
        ethernet_eap_provider_(new NiceMock<MockEthernetEapProvider>()),
#endif  // DISABLE_WIRED_8021X
#if !defined(DISABLE_WIFI)
        wifi_provider_(new NiceMock<MockWiFiProvider>()),
#endif  // DISABLE_WIFI
        throttler_(new StrictMock<MockThrottler>()),
        upstart_(new NiceMock<MockUpstart>(control_interface())) {
    ON_CALL(*control_interface(), CreatePowerManagerProxy(_, _, _))
        .WillByDefault(ReturnNull());

    SetRunning(true);

    // Replace the manager's adaptor with a quieter one, and one
    // we can do EXPECT*() against.  Passes ownership.
    manager()->adaptor_.reset(manager_adaptor_);

    manager()->ethernet_provider_.reset(ethernet_provider_);

#if !defined(DISABLE_WIRED_8021X)
    // Replace the manager's Ethernet EAP provider with our mock.
    // Passes ownership.
    manager()->ethernet_eap_provider_.reset(ethernet_eap_provider_);
#endif  // DISABLE_WIRED_8021X

#if !defined(DISABLE_WIFI)
    // Replace the manager's WiFi provider with our mock.  Passes
    // ownership.
    manager()->wifi_provider_.reset(wifi_provider_);
#endif  // DISABLE_WIFI

    // Replace the manager's throttler with our mock.
    manager()->throttler_.reset(throttler_);

    // Update the manager's map from technology to provider.
    manager()->UpdateProviderMapping();

    // Replace the manager's upstart instance with our mock.  Passes
    // ownership.
    manager()->upstart_.reset(upstart_);

    // Replace the manager's resolver with our mock.
    manager()->resolver_ = &resolver_;
  }
  ~ManagerTest() override = default;

  void SetUp() override {
    mock_devices_.push_back(
        new NiceMock<MockDevice>(manager(), "null0", "addr0", 0));
    mock_devices_.push_back(
        new NiceMock<MockDevice>(manager(), "null1", "addr1", 1));
    mock_devices_.push_back(
        new NiceMock<MockDevice>(manager(), "null2", "addr2", 2));
    mock_devices_.push_back(
        new NiceMock<MockDevice>(manager(), "null3", "addr3", 3));

    auto client = std::make_unique<patchpanel::FakeClient>();
    patchpanel_client_ = client.get();
    manager()->patchpanel_client_ = std::move(client);
  }

  void TearDown() override { mock_devices_.clear(); }

  bool IsDeviceRegistered(const DeviceRefPtr& device, Technology tech) {
    auto devices = manager()->FilterByTechnology(tech);
    return (devices.size() == 1 && devices[0].get() == device.get());
  }
  bool ServiceOrderIs(ServiceRefPtr svc1, ServiceRefPtr svc2);

  void AdoptProfile(Manager* manager, ProfileRefPtr profile) {
    manager->profiles_.push_back(profile);
  }

  void SetRunning(bool running) { manager()->running_ = running; }

  ProfileRefPtr GetEphemeralProfile(Manager* manager) {
    return manager->ephemeral_profile_;
  }

  std::vector<ProfileRefPtr>& GetProfiles(Manager* manager) {
    return manager->profiles_;
  }

  Profile* CreateProfileForManager(Manager* manager) {
    Profile::Identifier id("rather", "irrelevant");
    auto storage = std::make_unique<FakeStore>();
    if (!storage->Open())
      return nullptr;
    Profile* profile(new Profile(manager, id, base::FilePath(), false));
    profile->SetStorageForTest(std::move(storage));
    return profile;  // Passes ownership of "profile".
  }

  bool CreateBackingStoreForService(base::ScopedTempDir* temp_dir,
                                    const std::string& user_identifier,
                                    const std::string& profile_identifier,
                                    const std::string& service_name) {
    std::unique_ptr<StoreInterface> store =
        CreateStore(Profile::GetFinalStoragePath(
            temp_dir->GetPath(),
            Profile::Identifier(user_identifier, profile_identifier)));
    return store->Open() &&
           store->SetString(service_name, "rather", "irrelevant") &&
           store->Close();
  }

  Error::Type TestCreateProfile(Manager* manager, const std::string& name) {
    Error error;
    std::string path;
    manager->CreateProfile(name, &path, &error);
    return error.type();
  }

  Error::Type TestPopAnyProfile(Manager* manager) {
    Error error;
    manager->PopAnyProfile(&error);
    return error.type();
  }

  Error::Type TestPopAllUserProfiles(Manager* manager) {
    Error error;
    manager->PopAllUserProfiles(&error);
    return error.type();
  }

  Error::Type TestPopProfile(Manager* manager, const std::string& name) {
    Error error;
    manager->PopProfile(name, &error);
    return error.type();
  }

  Error::Type TestPushProfile(Manager* manager, const std::string& name) {
    Error error;
    std::string path;
    manager->PushProfile(name, &path, &error);
    return error.type();
  }

  Error::Type TestInsertUserProfile(Manager* manager,
                                    const std::string& name,
                                    const std::string& user_hash) {
    Error error;
    std::string path;
    manager->InsertUserProfile(name, user_hash, &path, &error);
    return error.type();
  }

  scoped_refptr<MockProfile> AddNamedMockProfileToManager(
      Manager* manager, const RpcIdentifier& name) {
    scoped_refptr<MockProfile> profile(new MockProfile(manager, ""));
    EXPECT_CALL(*profile, GetRpcIdentifier())
        .WillRepeatedly(ReturnRefOfCopy(name));
    EXPECT_CALL(*profile, UpdateDevice(_)).WillRepeatedly(Return(false));
    AdoptProfile(manager, profile);
    return profile;
  }

  void AddMockProfileToManager(Manager* manager) {
    AddNamedMockProfileToManager(manager, RpcIdentifier("/"));
  }

  void CompleteServiceSort() {
    EXPECT_TRUE(IsSortServicesTaskPending());
    dispatcher()->DispatchPendingEvents();
    EXPECT_FALSE(IsSortServicesTaskPending());
  }

  bool IsSortServicesTaskPending() {
    return !manager()->sort_services_task_.IsCancelled();
  }

  const std::vector<ServiceRefPtr>& GetServices() {
    return manager()->services_;
  }

  void RefreshConnectionState() { manager()->RefreshConnectionState(); }

  RpcIdentifier GetDefaultServiceRpcIdentifier() {
    return manager()->GetDefaultServiceRpcIdentifier(nullptr);
  }

  bool SetIgnoredDNSSearchPaths(const std::string& search_paths, Error* error) {
    return manager()->SetIgnoredDNSSearchPaths(search_paths, error);
  }

  bool SetCheckPortalList(const std::string& check_portal_list, Error* error) {
    return manager()->SetCheckPortalList(check_portal_list, error);
  }

  bool SetPortalFallbackUrlsString(const std::string& urls, Error* error) {
    return manager()->SetPortalFallbackUrlsString(urls, error);
  }

  const std::string& GetIgnoredDNSSearchPaths() {
    return manager()->props_.ignored_dns_search_paths;
  }

  const std::vector<std::string>& GetPortalFallbackUrlsString() {
    return manager()->props_.portal_fallback_http_urls;
  }

  size_t GetDefaultServiceObserverCount() const {
    size_t count = 0;
    for (auto& observer : manager()->default_service_observers_) {
      (void)observer;
      ++count;
    }
    return count;
  }

  bool SetDNSProxyDOHProviders(const KeyValueStore& providers, Error* error) {
    return manager()->SetDNSProxyDOHProviders(providers, error);
  }

#if !defined(DISABLE_WIFI)
  WiFiServiceRefPtr ReleaseTempMockService() {
    // Take a reference to hold during this function.
    WiFiServiceRefPtr temp_service = temp_mock_service_;
    temp_mock_service_ = nullptr;
    return temp_service;
  }
#endif  // DISABLE_WIFI

  void VerifyPassiveMode() {
    EXPECT_NE(nullptr, manager()->device_claimer_);
    EXPECT_TRUE(manager()->device_claimer_->default_claimer());
  }

  void SelectServiceForDevice(scoped_refptr<MockService> service,
                              Connection* connection,
                              scoped_refptr<MockDevice> device) {
    manager()->RegisterDevice(device);
    device->set_selected_service_for_testing(service);
    EXPECT_CALL(*device, connection()).WillRepeatedly(Return(connection));
    if (service) {
      EXPECT_CALL(*service, HasActiveConnection())
          .WillRepeatedly(Return(connection != nullptr));
    }
  }

 protected:
  using MockServiceRefPtr = scoped_refptr<MockService>;

  class ServiceWatcher : public DefaultServiceObserver {
   public:
    MOCK_METHOD(void,
                OnDefaultLogicalServiceChanged,
                (const ServiceRefPtr& logical_service));
    MOCK_METHOD(void,
                OnDefaultPhysicalServiceChanged,
                (const ServiceRefPtr& physical_service));
  };

  class TerminationActionTest
      : public base::SupportsWeakPtr<TerminationActionTest> {
   public:
    static const char kActionName[];

    TerminationActionTest() : manager_(nullptr) {}
    TerminationActionTest(const TerminationActionTest&) = delete;
    TerminationActionTest& operator=(const TerminationActionTest&) = delete;

    virtual ~TerminationActionTest() = default;

    MOCK_METHOD(void, Done, (const Error&));

    void Action() { manager_->TerminationActionComplete("action"); }

    void set_manager(Manager* manager) { manager_ = manager; }

   private:
    Manager* manager_;
  };

  class DestinationVerificationTest
      : public base::SupportsWeakPtr<DestinationVerificationTest> {
   public:
    DestinationVerificationTest() = default;
    DestinationVerificationTest(const DestinationVerificationTest&) = delete;
    DestinationVerificationTest& operator=(const DestinationVerificationTest&) =
        delete;

    virtual ~DestinationVerificationTest() = default;

    MOCK_METHOD(void, ResultBoolCallbackStub, (const Error&, bool));
    MOCK_METHOD(void,
                ResultStringCallbackStub,
                (const Error&, const std::string&));

   private:
  };

  class DisableTechnologyReplyHandler
      : public base::SupportsWeakPtr<DisableTechnologyReplyHandler> {
   public:
    DisableTechnologyReplyHandler() = default;
    DisableTechnologyReplyHandler(const DisableTechnologyReplyHandler&) =
        delete;
    DisableTechnologyReplyHandler& operator=(
        const DisableTechnologyReplyHandler&) = delete;

    virtual ~DisableTechnologyReplyHandler() = default;

    MOCK_METHOD(void, ReportResult, (const Error&));

   private:
  };

  class ResultCallbackObserver {
   public:
    ResultCallbackObserver()
        : result_callback_(base::Bind(&ResultCallbackObserver::OnResultCallback,
                                      base::Unretained(this))) {}
    ResultCallbackObserver(const ResultCallbackObserver&) = delete;
    ResultCallbackObserver& operator=(const ResultCallbackObserver&) = delete;

    virtual ~ResultCallbackObserver() = default;

    MOCK_METHOD(void, OnResultCallback, (const Error&));

    const ResultCallback& result_callback() const { return result_callback_; }

   private:
    ResultCallback result_callback_;
  };

  void SetSuspending(bool suspending) {
    power_manager_->suspending_ = suspending;
  }

  void SetPowerManager() {
    manager()->set_power_manager(power_manager_.release());
  }

  HookTable* GetTerminationActions() {
    return &manager()->termination_actions_;
  }

  void OnSuspendImminent() { manager()->OnSuspendImminent(); }

  void OnDarkSuspendImminent() { manager()->OnDarkSuspendImminent(); }

  void OnSuspendDone() { manager()->OnSuspendDone(); }

  void OnSuspendActionsComplete(const Error& error) {
    manager()->OnSuspendActionsComplete(error);
  }

  std::vector<RpcIdentifier> EnumerateAvailableServices() {
    return manager()->EnumerateAvailableServices(nullptr);
  }

  std::vector<RpcIdentifier> EnumerateWatchedServices() {
    return manager()->EnumerateWatchedServices(nullptr);
  }

  MockServiceRefPtr MakeAutoConnectableService() {
    MockServiceRefPtr service = new NiceMock<MockService>(manager());
    service->SetAutoConnect(true);
    service->SetConnectable(true);
    return service;
  }

#if !defined(DISABLE_WIRED_8021X)
  void SetEapProviderService(const ServiceRefPtr& service) {
    ethernet_eap_provider_->set_service(service);
  }
#endif  // DISABLE_WIRED_8021X

  const std::vector<Technology>& GetTechnologyOrder() {
    return manager()->technology_order_;
  }

  bool HasService(const Manager& manager, const std::string& id) {
    for (const auto& service : manager.services_) {
      if (id == service->GetDBusObjectPathIdentifer())
        return true;
    }
    return false;
  }

  std::unique_ptr<MockPowerManager> power_manager_;
  std::vector<scoped_refptr<MockDevice>> mock_devices_;
  std::unique_ptr<MockDeviceInfo> device_info_;

#if !defined(DISABLE_WIFI)
  // This service is held for the manager, and given ownership in a mock
  // function.  This ensures that when the Manager takes ownership, there
  // is only one reference left.
  scoped_refptr<MockWiFiService> temp_mock_service_;
#endif  // DISABLE_WIFI

  // These pointers are owned by the manager, and only tracked here for
  // EXPECT*()
  ManagerMockAdaptor* manager_adaptor_;
  MockEthernetProvider* ethernet_provider_;
#if !defined(DISABLE_WIRED_8021X)
  MockEthernetEapProvider* ethernet_eap_provider_;
#endif  // DISABLE_WIRED_8021X
#if !defined(DISABLE_WIFI)
  MockWiFiProvider* wifi_provider_;
#endif  // DISABLE_WIFI
  MockThrottler* throttler_;
  MockUpstart* upstart_;
  MockResolver resolver_;
  patchpanel::FakeClient* patchpanel_client_;
};

const char ManagerTest::TerminationActionTest::kActionName[] = "action";

bool ManagerTest::ServiceOrderIs(ServiceRefPtr svc0, ServiceRefPtr svc1) {
  if (!manager()->sort_services_task_.IsCancelled()) {
    manager()->SortServicesTask();
  }
  return (svc0.get() == manager()->services_[0].get() &&
          svc1.get() == manager()->services_[1].get());
}

void SetErrorPermissionDenied(Error* error) {
  error->Populate(Error::kPermissionDenied);
}

void SetErrorSuccess(Error* error) {
  error->Reset();
}

TEST_F(ManagerTest, Contains) {
  EXPECT_TRUE(manager()->store().Contains(kStateProperty));
  EXPECT_FALSE(manager()->store().Contains(""));
}

TEST_F(ManagerTest, PassiveModeDeviceRegistration) {
  manager()->SetPassiveMode();
  VerifyPassiveMode();

  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));

  // Device not released, should not be registered.
  manager()->RegisterDevice(mock_devices_[0]);
  EXPECT_FALSE(IsDeviceRegistered(mock_devices_[0], Technology::kEthernet));

  // Device is released, should be registered.
  bool claimer_removed;
  Error error;
  manager()->ReleaseDevice("", mock_devices_[0]->link_name(), &claimer_removed,
                           &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_FALSE(claimer_removed);
  manager()->RegisterDevice(mock_devices_[0]);
  EXPECT_TRUE(IsDeviceRegistered(mock_devices_[0], Technology::kEthernet));
}

TEST_F(ManagerTest, DeviceRegistration) {
  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[1], technology())
      .WillByDefault(Return(Technology::kWiFi));
  ON_CALL(*mock_devices_[2], technology())
      .WillByDefault(Return(Technology::kCellular));

  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);

  EXPECT_TRUE(IsDeviceRegistered(mock_devices_[0], Technology::kEthernet));
  EXPECT_TRUE(IsDeviceRegistered(mock_devices_[1], Technology::kWiFi));
  EXPECT_TRUE(IsDeviceRegistered(mock_devices_[2], Technology::kCellular));
}

TEST_F(ManagerTest, DeviceRegistrationTriggersThrottler) {
  manager()->network_throttling_enabled_ = true;
  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[1], technology())
      .WillByDefault(Return(Technology::kWiFi));
  ON_CALL(*mock_devices_[2], technology())
      .WillByDefault(Return(Technology::kCellular));

  EXPECT_CALL(*throttler_, ThrottleInterfaces(_, _, _)).Times(1);
  EXPECT_CALL(*throttler_, ApplyThrottleToNewInterface(_)).Times(2);

  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);
}

TEST_F(ManagerTest, ManagerCallsThrottlerCorrectly) {
  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[1], technology())
      .WillByDefault(Return(Technology::kWiFi));
  ON_CALL(*mock_devices_[2], technology())
      .WillByDefault(Return(Technology::kCellular));

  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);

  int ulrate = 1024;
  int dlrate = 2048;
  ResultCallback fake;

  EXPECT_CALL(*throttler_, ThrottleInterfaces(_, ulrate, dlrate));
  manager()->SetNetworkThrottlingStatus(fake, true, ulrate, dlrate);
  EXPECT_CALL(*throttler_, DisableThrottlingOnAllInterfaces(_));
  manager()->SetNetworkThrottlingStatus(fake, false, ulrate, dlrate);
}

TEST_F(ManagerTest, DeviceRegistrationAndStart) {
  manager()->running_ = true;
  mock_devices_[0]->enabled_persistent_ = true;
  mock_devices_[1]->enabled_persistent_ = false;
  EXPECT_CALL(*mock_devices_[0], SetEnabled(true)).Times(1);
  EXPECT_CALL(*mock_devices_[1], SetEnabled(_)).Times(0);
  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
}

TEST_F(ManagerTest, DeviceRegistrationWithProfile) {
  MockProfile* profile = new MockProfile(manager(), "");
  DeviceRefPtr device_ref(mock_devices_[0].get());
  AdoptProfile(manager(), profile);  // Passes ownership.
  EXPECT_CALL(*profile, ConfigureDevice(device_ref));
  EXPECT_CALL(*profile, UpdateDevice(device_ref));
  manager()->RegisterDevice(mock_devices_[0]);
}

TEST_F(ManagerTest, DeviceDeregistration) {
  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[1], technology())
      .WillByDefault(Return(Technology::kWiFi));

  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);

  ASSERT_TRUE(IsDeviceRegistered(mock_devices_[0], Technology::kEthernet));
  ASSERT_TRUE(IsDeviceRegistered(mock_devices_[1], Technology::kWiFi));

  MockProfile* profile = new MockProfile(manager(), "");
  AdoptProfile(manager(), profile);  // Passes ownership.

  EXPECT_CALL(*mock_devices_[0], SetEnabled(false));
  EXPECT_CALL(*profile, UpdateDevice(DeviceRefPtr(mock_devices_[0])));
  manager()->DeregisterDevice(mock_devices_[0]);
  EXPECT_FALSE(IsDeviceRegistered(mock_devices_[0], Technology::kEthernet));

  EXPECT_CALL(*mock_devices_[1], SetEnabled(false));
  EXPECT_CALL(*profile, UpdateDevice(DeviceRefPtr(mock_devices_[1])));
  manager()->DeregisterDevice(mock_devices_[1]);
  EXPECT_FALSE(IsDeviceRegistered(mock_devices_[1], Technology::kWiFi));
}

TEST_F(ManagerTest, ServiceRegistration) {
  Manager manager(control_interface(), dispatcher(), metrics(), run_path(),
                  storage_path(), std::string());
  ProfileRefPtr profile(CreateProfileForManager(&manager));
  ASSERT_NE(nullptr, profile);
  AdoptProfile(&manager, profile);

  MockServiceRefPtr mock_service(new NiceMock<MockService>(&manager));
  MockServiceRefPtr mock_service2(new NiceMock<MockService>(&manager));

  RpcIdentifier service1_rpcid(mock_service->GetDBusObjectPathIdentifer());
  RpcIdentifier service2_rpcid(mock_service2->GetDBusObjectPathIdentifer());

  EXPECT_CALL(*mock_service, GetRpcIdentifier())
      .WillRepeatedly(ReturnRef(service1_rpcid));
  EXPECT_CALL(*mock_service2, GetRpcIdentifier())
      .WillRepeatedly(ReturnRef(service2_rpcid));
  // TODO(quiche): make this EXPECT_CALL work (crbug.com/203247)
  // EXPECT_CALL(*static_cast<ManagerMockAdaptor*>(manager.adaptor_.get()),
  //             EmitRpcIdentifierArrayChanged(kServicesProperty, _));

  manager.RegisterService(mock_service);
  manager.RegisterService(mock_service2);

  Error error;
  std::vector<RpcIdentifier> rpc_ids =
      manager.EnumerateAvailableServices(&error);
  std::set<RpcIdentifier> ids(rpc_ids.begin(), rpc_ids.end());
  EXPECT_EQ(2, ids.size());
  EXPECT_TRUE(base::Contains(ids, mock_service->GetRpcIdentifier()));
  EXPECT_TRUE(base::Contains(ids, mock_service2->GetRpcIdentifier()));

  EXPECT_TRUE(HasService(manager, service1_rpcid.value()));
  EXPECT_TRUE(HasService(manager, service2_rpcid.value()));

  manager.set_power_manager(power_manager_.release());
  manager.DeregisterService(mock_service);
  manager.DeregisterService(mock_service2);
  manager.Stop();
}

TEST_F(ManagerTest, RegisterKnownService) {
  Manager manager(control_interface(), dispatcher(), metrics(), run_path(),
                  storage_path(), std::string());
  ProfileRefPtr profile(CreateProfileForManager(&manager));
  ASSERT_NE(nullptr, profile);
  AdoptProfile(&manager, profile);
  {
    ServiceRefPtr service1(new ServiceUnderTest(&manager));
    ASSERT_TRUE(profile->AdoptService(service1));
    ASSERT_TRUE(profile->ContainsService(service1));
  }  // Force destruction of service1.

  ServiceRefPtr service2(new ServiceUnderTest(&manager));
  manager.RegisterService(service2);
  EXPECT_EQ(service2->profile(), profile);

  manager.set_power_manager(power_manager_.release());
  manager.DeregisterService(service2);
  manager.Stop();
}

TEST_F(ManagerTest, RegisterUnknownService) {
  Manager manager(control_interface(), dispatcher(), metrics(), run_path(),
                  storage_path(), std::string());
  ProfileRefPtr profile(CreateProfileForManager(&manager));
  ASSERT_NE(nullptr, profile);
  AdoptProfile(&manager, profile);
  {
    ServiceRefPtr service1(new ServiceUnderTest(&manager));
    ASSERT_TRUE(profile->AdoptService(service1));
    ASSERT_TRUE(profile->ContainsService(service1));
  }  // Force destruction of service1.
  MockServiceRefPtr mock_service2(new NiceMock<MockService>(&manager));
  EXPECT_CALL(*mock_service2, GetStorageIdentifier())
      .WillRepeatedly(Return(mock_service2->GetDBusObjectPathIdentifer()));
  manager.RegisterService(mock_service2);
  EXPECT_NE(mock_service2->profile(), profile);

  manager.set_power_manager(power_manager_.release());
  manager.DeregisterService(mock_service2);
  manager.Stop();
}

TEST_F(ManagerTest, DeregisterUnregisteredService) {
  // WiFi assumes that it can deregister a service that is not
  // registered.  (E.g. a hidden service can be deregistered when it
  // loses its last endpoint, and again when WiFi is Stop()-ed.)
  //
  // So test that doing so doesn't cause a crash.
  MockServiceRefPtr service = new NiceMock<MockService>(manager());
  manager()->DeregisterService(service);
}

TEST_F(ManagerTest, GetProperties) {
  AddMockProfileToManager(manager());
  {
    brillo::VariantDictionary props;
    Error error;
    std::string expected("portal_list");
    manager()->mutable_store()->SetStringProperty(kCheckPortalListProperty,
                                                  expected, &error);
    manager()->store().GetProperties(&props, &error);
    ASSERT_FALSE(props.find(kCheckPortalListProperty) == props.end());
    EXPECT_TRUE(
        props[kCheckPortalListProperty].IsTypeCompatible<std::string>());
    EXPECT_EQ(props[kCheckPortalListProperty].Get<std::string>(), expected);
  }
  {
    brillo::VariantDictionary props;
    Error error;
    bool expected = true;
    manager()->mutable_store()->SetBoolProperty(kArpGatewayProperty, expected,
                                                &error);
    manager()->store().GetProperties(&props, &error);
    ASSERT_FALSE(props.find(kArpGatewayProperty) == props.end());
    EXPECT_TRUE(props[kArpGatewayProperty].IsTypeCompatible<bool>());
    EXPECT_EQ(props[kArpGatewayProperty].Get<bool>(), expected);
  }
}

TEST_F(ManagerTest, GetDevicesProperty) {
  AddMockProfileToManager(manager());
  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  {
    brillo::VariantDictionary props;
    Error error;
    manager()->store().GetProperties(&props, &error);
    ASSERT_FALSE(props.find(kDevicesProperty) == props.end());
    EXPECT_TRUE(props[kDevicesProperty]
                    .IsTypeCompatible<std::vector<dbus::ObjectPath>>());
    std::vector<dbus::ObjectPath> devices =
        props[kDevicesProperty].Get<std::vector<dbus::ObjectPath>>();
    EXPECT_EQ(2, devices.size());
  }
}

TEST_F(ManagerTest, GetServicesProperty) {
  AddMockProfileToManager(manager());
  brillo::VariantDictionary props;
  Error error;
  manager()->store().GetProperties(&props, &error);
  ASSERT_FALSE(props.find(kServicesProperty) == props.end());
  EXPECT_TRUE(props[kServicesProperty]
                  .IsTypeCompatible<std::vector<dbus::ObjectPath>>());
}

TEST_F(ManagerTest, MoveService) {
  Manager manager(control_interface(), dispatcher(), metrics(), run_path(),
                  storage_path(), std::string());
  MockServiceRefPtr s2(new MockService(&manager));
  // Inject an actual profile, backed by a fake StoreInterface
  {
    Profile::Identifier id("irrelevant");
    ProfileRefPtr profile(new Profile(&manager, id, base::FilePath(), false));
    auto storage = std::make_unique<FakeStore>();
    storage->SetString(s2->GetStorageIdentifier(), "AnyKey", "AnyValue");
    profile->SetStorageForTest(std::move(storage));
    AdoptProfile(&manager, profile);
  }
  // Create a profile that already has |s2| in it.
  ProfileRefPtr profile(new EphemeralProfile(&manager));
  EXPECT_TRUE(profile->AdoptService(s2));

  // Now, move the Service |s2| to another profile.
  EXPECT_CALL(*s2, Save(_)).WillOnce(Return(true));
  ASSERT_TRUE(manager.MoveServiceToProfile(s2, manager.ActiveProfile()));

  // Force destruction of the original Profile, to ensure that the Service
  // is kept alive and populated with data.
  profile = nullptr;
  ASSERT_TRUE(manager.ActiveProfile()->ContainsService(s2));
  manager.set_power_manager(power_manager_.release());
  manager.Stop();
}

TEST_F(ManagerTest, LookupProfileByRpcIdentifier) {
  scoped_refptr<MockProfile> mock_profile(new MockProfile(manager(), ""));
  const RpcIdentifier kProfileName("profile0");
  EXPECT_CALL(*mock_profile, GetRpcIdentifier())
      .WillRepeatedly(ReturnRef(kProfileName));
  AdoptProfile(manager(), mock_profile);

  EXPECT_FALSE(manager()->LookupProfileByRpcIdentifier("foo"));
  ProfileRefPtr profile =
      manager()->LookupProfileByRpcIdentifier(kProfileName.value());
  EXPECT_EQ(mock_profile, profile);
}

TEST_F(ManagerTest, SetProfileForService) {
  scoped_refptr<MockProfile> profile0(new MockProfile(manager(), ""));
  RpcIdentifier profile_name0("profile0");
  EXPECT_CALL(*profile0, GetRpcIdentifier())
      .WillRepeatedly(ReturnRef(profile_name0));
  AdoptProfile(manager(), profile0);
  MockServiceRefPtr service(new MockService(manager()));
  EXPECT_FALSE(manager()->HasService(service));
  {
    Error error;
    EXPECT_CALL(*profile0, AdoptService(_)).WillOnce(Return(true));
    // Expect that setting the profile of a service that does not already
    // have one assigned does not cause a crash.
    manager()->SetProfileForService(service, "profile0", &error);
    EXPECT_TRUE(error.IsSuccess());
  }

  // The service should be registered as a side-effect of the profile being
  // set for this service.
  EXPECT_TRUE(manager()->HasService(service));

  // Since we have mocked Profile::AdoptServie() above, the service's
  // profile was not actually changed.  Do so explicitly now.
  service->set_profile(profile0);

  {
    Error error;
    manager()->SetProfileForService(service, "foo", &error);
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ("Unknown Profile foo requested for Service", error.message());
  }

  {
    Error error;
    manager()->SetProfileForService(service, profile_name0.value(), &error);
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ("Service is already connected to this profile", error.message());
  }

  scoped_refptr<MockProfile> profile1(new MockProfile(manager(), ""));
  RpcIdentifier profile_name1("profile1");
  EXPECT_CALL(*profile1, GetRpcIdentifier())
      .WillRepeatedly(ReturnRef(profile_name1));
  AdoptProfile(manager(), profile1);

  {
    Error error;
    EXPECT_CALL(*profile1, AdoptService(_)).WillOnce(Return(true));
    EXPECT_CALL(*profile0, AbandonService(_)).WillOnce(Return(true));
    manager()->SetProfileForService(service, profile_name1.value(), &error);
    EXPECT_TRUE(error.IsSuccess());
  }
}

TEST_F(ManagerTest, CreateProfile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  Manager manager(control_interface(), dispatcher(), metrics(), run_path(),
                  storage_path(), temp_dir.GetPath().value());

  // Invalid name should be rejected.
  EXPECT_EQ(Error::kInvalidArguments, TestCreateProfile(&manager, ""));

  // A profile with invalid characters in it should similarly be rejected.
  EXPECT_EQ(Error::kInvalidArguments,
            TestCreateProfile(&manager, "valid_profile"));

  // We should be able to create a machine profile.
  EXPECT_EQ(Error::kSuccess, TestCreateProfile(&manager, "valid"));

  // We should succeed in creating a valid user profile.  Verify the returned
  // path.
  const char kProfile[] = "~user/profile";
  {
    Error error;
    std::string path;
    ASSERT_TRUE(base::CreateDirectory(temp_dir.GetPath().Append("user")));
    manager.CreateProfile(kProfile, &path, &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ("/profile_rpc", path);
  }

  // We should fail in creating it a second time (already exists).
  EXPECT_EQ(Error::kAlreadyExists, TestCreateProfile(&manager, kProfile));
}

TEST_F(ManagerTest, PushPopProfile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  Manager manager(control_interface(), dispatcher(), metrics(), run_path(),
                  storage_path(), temp_dir.GetPath().value());
  std::vector<ProfileRefPtr>& profiles = GetProfiles(&manager);

  // Pushing an invalid profile should fail.
  EXPECT_EQ(Error::kInvalidArguments, TestPushProfile(&manager, ""));

  // Create and push a default profile. Should succeed.
  const char kDefaultProfile0[] = "default";
  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager, kDefaultProfile0));
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kDefaultProfile0));
  EXPECT_EQ(Error::kSuccess, TestPopProfile(&manager, kDefaultProfile0));

  // Pushing a default profile that does not exist on disk will _not_
  // fail, because we'll use temporary storage for it.
  const char kMissingDefaultProfile[] = "missingdefault";
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kMissingDefaultProfile));
  EXPECT_EQ(1, profiles.size());
  EXPECT_EQ(Error::kSuccess, TestPopProfile(&manager, kMissingDefaultProfile));
  EXPECT_EQ(0, profiles.size());

  const char kProfile0[] = "~user/profile0";
  const char kProfile1[] = "~user/profile1";
  ASSERT_TRUE(base::CreateDirectory(temp_dir.GetPath().Append("user")));

  // Create a couple of profiles.
  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager, kProfile0));
  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager, kProfile1));

  // Push these profiles on the stack.
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kProfile0));
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kProfile1));

  // Pushing a profile a second time should fail.
  EXPECT_EQ(Error::kAlreadyExists, TestPushProfile(&manager, kProfile0));
  EXPECT_EQ(Error::kAlreadyExists, TestPushProfile(&manager, kProfile1));

  Error error;
  // Active profile should be the last one we pushed.
  EXPECT_EQ(kProfile1, "~" + manager.ActiveProfile()->GetFriendlyName());

  // Make sure a profile name that doesn't exist fails.
  const char kProfile2Id[] = "profile2";
  const std::string kProfile2 = base::StringPrintf("~user/%s", kProfile2Id);
  EXPECT_EQ(Error::kNotFound, TestPushProfile(&manager, kProfile2));

  // Create a new service, with a specific storage name.
  MockServiceRefPtr service(new NiceMock<MockService>(&manager));
  const char kServiceName[] = "service_storage_name";
  EXPECT_CALL(*service, GetStorageIdentifier())
      .WillRepeatedly(Return(kServiceName));
  EXPECT_CALL(*service, Load(_)).WillRepeatedly(Return(true));

  // Add this service to the manager -- it should end up in the ephemeral
  // profile.
  manager.RegisterService(service);
  ASSERT_EQ(GetEphemeralProfile(&manager), service->profile());

  // Create storage for a profile that contains the service storage name.
  ASSERT_TRUE(CreateBackingStoreForService(&temp_dir, "user", kProfile2Id,
                                           kServiceName));

  // When we push the profile, the service should move away from the
  // ephemeral profile to this new profile since it has an entry for
  // this service.
  EXPECT_CALL(*service, ClearExplicitlyDisconnected());
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kProfile2));
  EXPECT_NE(GetEphemeralProfile(&manager), service->profile());
  EXPECT_EQ(kProfile2, "~" + service->profile()->GetFriendlyName());

  // Insert another profile that should supersede ownership of the service.
  const char kProfile3Id[] = "profile3";
  const std::string kProfile3 = base::StringPrintf("~user/%s", kProfile3Id);
  ASSERT_TRUE(CreateBackingStoreForService(&temp_dir, "user", kProfile3Id,
                                           kServiceName));
  // We don't verify this expectation inline, since this would clear other
  // recurring expectations on the service.
  EXPECT_CALL(*service, ClearExplicitlyDisconnected());
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kProfile3));
  EXPECT_EQ(kProfile3, "~" + service->profile()->GetFriendlyName());

  // Popping an invalid profile name should fail.
  EXPECT_EQ(Error::kInvalidArguments, TestPopProfile(&manager, "~"));

  // Popping an profile that is not at the top of the stack should fail.
  EXPECT_EQ(Error::kWrongState, TestPopProfile(&manager, kProfile0));

  // Popping the top profile should succeed.
  EXPECT_CALL(*service, ClearExplicitlyDisconnected());
  EXPECT_EQ(Error::kSuccess, TestPopProfile(&manager, kProfile3));

  // Moreover the service should have switched profiles to profile 2.
  EXPECT_EQ(kProfile2, "~" + service->profile()->GetFriendlyName());

  // Popping the top profile should succeed.
  EXPECT_CALL(*service, ClearExplicitlyDisconnected());
  EXPECT_EQ(Error::kSuccess, TestPopAnyProfile(&manager));

  // The service should now revert to the ephemeral profile.
  EXPECT_EQ(GetEphemeralProfile(&manager), service->profile());

  // Pop the remaining two profiles off the stack.
  EXPECT_CALL(*service, ClearExplicitlyDisconnected()).Times(2);
  EXPECT_EQ(Error::kSuccess, TestPopAnyProfile(&manager));
  EXPECT_EQ(Error::kSuccess, TestPopAnyProfile(&manager));
  Mock::VerifyAndClearExpectations(service.get());

  // Next pop should fail with "stack is empty".
  EXPECT_EQ(Error::kNotFound, TestPopAnyProfile(&manager));

  // The service is unused now, remove it to avoid setting useless expectations.
  manager.DeregisterService(service);

  const char kMachineProfile0[] = "machineprofile0";
  const char kMachineProfile1[] = "machineprofile1";
  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager, kMachineProfile0));
  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager, kMachineProfile1));

  // Should be able to push a machine profile.
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kMachineProfile0));

  // Should be able to push a user profile atop a machine profile.
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kProfile0));

  // Pushing a system-wide profile on top of a user profile should fail.
  EXPECT_EQ(Error::kInvalidArguments,
            TestPushProfile(&manager, kMachineProfile1));

  // However if we pop the user profile, we should be able stack another
  // machine profile on.
  EXPECT_EQ(Error::kSuccess, TestPopAnyProfile(&manager));
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kMachineProfile1));

  // Add two user profiles to the top of the stack.
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kProfile0));
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kProfile1));
  EXPECT_EQ(4, profiles.size());

  // PopAllUserProfiles should remove both user profiles, leaving the two
  // machine profiles.
  EXPECT_EQ(Error::kSuccess, TestPopAllUserProfiles(&manager));
  EXPECT_EQ(2, profiles.size());
  EXPECT_TRUE(profiles[0]->GetUser().empty());
  EXPECT_TRUE(profiles[1]->GetUser().empty());

  EXPECT_TRUE(manager.IsTechnologyAutoConnectDisabled(Technology::kCellular));
  EXPECT_FALSE(manager.IsTechnologyAutoConnectDisabled(Technology::kEthernet));
  EXPECT_FALSE(manager.IsTechnologyAutoConnectDisabled(Technology::kWiFi));

  // Use InsertUserProfile() instead.  Although a machine profile is valid
  // in this state, it cannot be added via InsertUserProfile.
  EXPECT_EQ(Error::kSuccess, TestPopProfile(&manager, kMachineProfile1));
  EXPECT_EQ(Error::kInvalidArguments,
            TestInsertUserProfile(&manager, kMachineProfile1, "machinehash1"));
  const char kUserHash0[] = "userhash0";
  const char kUserHash1[] = "userhash1";
  EXPECT_EQ(Error::kSuccess,
            TestInsertUserProfile(&manager, kProfile0, kUserHash0));

  EXPECT_FALSE(manager.IsTechnologyAutoConnectDisabled(Technology::kCellular));
  EXPECT_FALSE(manager.IsTechnologyAutoConnectDisabled(Technology::kEthernet));
  EXPECT_FALSE(manager.IsTechnologyAutoConnectDisabled(Technology::kWiFi));

  EXPECT_EQ(Error::kSuccess,
            TestInsertUserProfile(&manager, kProfile1, kUserHash1));

  EXPECT_FALSE(manager.IsTechnologyAutoConnectDisabled(Technology::kCellular));
  EXPECT_FALSE(manager.IsTechnologyAutoConnectDisabled(Technology::kEthernet));
  EXPECT_FALSE(manager.IsTechnologyAutoConnectDisabled(Technology::kWiFi));

  EXPECT_EQ(3, profiles.size());
  EXPECT_EQ(kUserHash0, profiles[1]->GetUserHash());
  EXPECT_EQ(kUserHash1, profiles[2]->GetUserHash());
}

TEST_F(ManagerTest, RemoveProfile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  Manager manager(control_interface(), dispatcher(), metrics(), run_path(),
                  storage_path(), temp_dir.GetPath().value());

  const char kProfile0[] = "profile0";
  base::FilePath profile_path(Profile::GetFinalStoragePath(
      base::FilePath(storage_path()), Profile::Identifier(kProfile0)));

  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager, kProfile0));
  ASSERT_TRUE(base::PathExists(profile_path));

  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kProfile0));

  // Remove should fail since the profile is still on the stack.
  {
    Error error;
    manager.RemoveProfile(kProfile0, &error);
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }

  // Profile path should still exist.
  EXPECT_TRUE(base::PathExists(profile_path));

  EXPECT_EQ(Error::kSuccess, TestPopAnyProfile(&manager));

  // This should succeed now that the profile is off the stack.
  {
    Error error;
    manager.RemoveProfile(kProfile0, &error);
    EXPECT_TRUE(error.IsSuccess());
  }

  // Profile path should no longer exist.
  EXPECT_FALSE(base::PathExists(profile_path));

  // Another remove succeeds, due to a foible in base::DeleteFile --
  // it is not an error to delete a file that does not exist.
  {
    Error error;
    manager.RemoveProfile(kProfile0, &error);
    EXPECT_TRUE(error.IsSuccess());
  }

  // Let's create an error case that will "work".  Create a non-empty
  // directory in the place of the profile pathname.
  ASSERT_TRUE(base::CreateDirectory(profile_path.Append("foo")));
  {
    Error error;
    manager.RemoveProfile(kProfile0, &error);
    EXPECT_EQ(Error::kOperationFailed, error.type());
  }
}

TEST_F(ManagerTest, RemoveService) {
  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));

  // Used in expectations which cannot accept a mock refptr.
  const ServiceRefPtr& service = mock_service;

  manager()->RegisterService(service);
  EXPECT_EQ(GetEphemeralProfile(manager()), service->profile());

  scoped_refptr<MockProfile> profile(
      new StrictMock<MockProfile>(manager(), ""));
  AdoptProfile(manager(), profile);

  // If service is ephemeral, it should be unloaded and left ephemeral.
  EXPECT_CALL(*profile, AbandonService(service)).Times(0);
  EXPECT_CALL(*profile, ConfigureService(service)).Times(0);
  EXPECT_CALL(*mock_service, Unload()).WillOnce(Return(false));
  manager()->RemoveService(service);
  Mock::VerifyAndClearExpectations(mock_service.get());
  Mock::VerifyAndClearExpectations(profile.get());
  EXPECT_EQ(GetEphemeralProfile(manager()), service->profile());
  EXPECT_TRUE(manager()->HasService(service));  // Since Unload() was false.

  // If service is not ephemeral and the Manager finds a profile to assign
  // the service to, the service should be re-parented.  Note that since we
  // are using a MockProfile, ConfigureService() never actually changes the
  // Service's profile.
  service->set_profile(profile);
  EXPECT_CALL(*profile, AbandonService(service));
  EXPECT_CALL(*profile, ConfigureService(service)).WillOnce(Return(true));
  EXPECT_CALL(*mock_service, Unload()).Times(0);
  manager()->RemoveService(service);
  Mock::VerifyAndClearExpectations(mock_service.get());
  Mock::VerifyAndClearExpectations(profile.get());
  EXPECT_TRUE(manager()->HasService(service));
  EXPECT_EQ(profile, service->profile());

  // If service becomes ephemeral since there is no profile to support it,
  // it should be unloaded.
  EXPECT_CALL(*profile, AbandonService(service));
  EXPECT_CALL(*profile, ConfigureService(service)).WillOnce(Return(false));
  EXPECT_CALL(*mock_service, Unload()).WillOnce(Return(true));
  manager()->RemoveService(service);
  EXPECT_FALSE(manager()->HasService(service));
}

TEST_F(ManagerTest, CreateDuplicateProfileWithMissingKeyfile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  Manager manager(control_interface(), dispatcher(), metrics(), run_path(),
                  storage_path(), temp_dir.GetPath().value());

  const char kProfile0[] = "profile0";
  base::FilePath profile_path(Profile::GetFinalStoragePath(
      base::FilePath(storage_path()), Profile::Identifier(kProfile0)));
  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager, kProfile0));
  ASSERT_TRUE(base::PathExists(profile_path));
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager, kProfile0));

  // Ensure that even if the backing filestore is removed, we still can't
  // create a profile twice.
  ASSERT_TRUE(base::DeleteFile(profile_path));
  EXPECT_EQ(Error::kAlreadyExists, TestCreateProfile(&manager, kProfile0));
}

TEST_F(ManagerTest, HandleProfileEntryDeletion) {
  MockServiceRefPtr s_not_in_profile(new NiceMock<MockService>(manager()));
  MockServiceRefPtr s_not_in_group(new NiceMock<MockService>(manager()));
  MockServiceRefPtr s_configure_fail(new NiceMock<MockService>(manager()));
  MockServiceRefPtr s_configure_succeed(new NiceMock<MockService>(manager()));

  std::string entry_name("entry_name");
  EXPECT_CALL(*ethernet_provider_, RefreshGenericEthernetService());
  EXPECT_CALL(*s_not_in_group, GetStorageIdentifier())
      .WillRepeatedly(Return("not_entry_name"));
  EXPECT_CALL(*s_configure_fail, GetStorageIdentifier())
      .WillRepeatedly(Return(entry_name));
  EXPECT_CALL(*s_configure_succeed, GetStorageIdentifier())
      .WillRepeatedly(Return(entry_name));

  manager()->RegisterService(s_not_in_profile);
  manager()->RegisterService(s_not_in_group);
  manager()->RegisterService(s_configure_fail);
  manager()->RegisterService(s_configure_succeed);

  scoped_refptr<MockProfile> profile0(
      new StrictMock<MockProfile>(manager(), ""));
  scoped_refptr<MockProfile> profile1(
      new StrictMock<MockProfile>(manager(), ""));

  s_not_in_group->set_profile(profile1);
  s_configure_fail->set_profile(profile1);
  s_configure_succeed->set_profile(profile1);

  AdoptProfile(manager(), profile0);
  AdoptProfile(manager(), profile1);

  CompleteServiceSort();

  // No services are a member of this profile.
  EXPECT_FALSE(manager()->HandleProfileEntryDeletion(profile0, entry_name));
  EXPECT_FALSE(IsSortServicesTaskPending());

  // No services that are members of this profile have this entry name.
  EXPECT_FALSE(manager()->HandleProfileEntryDeletion(profile1, ""));
  EXPECT_FALSE(IsSortServicesTaskPending());

  // Only services that are members of the profile and group will be abandoned.
  EXPECT_CALL(*profile1, AbandonService(IsRefPtrTo(s_not_in_profile.get())))
      .Times(0);
  EXPECT_CALL(*profile1, AbandonService(IsRefPtrTo(s_not_in_group.get())))
      .Times(0);
  EXPECT_CALL(*profile1, AbandonService(IsRefPtrTo(s_configure_fail.get())))
      .WillOnce(Return(true));
  EXPECT_CALL(*profile1, AbandonService(IsRefPtrTo(s_configure_succeed.get())))
      .WillOnce(Return(true));

  // Never allow services to re-join profile1.
  EXPECT_CALL(*profile1, ConfigureService(_)).WillRepeatedly(Return(false));

  // Only allow one of the members of the profile and group to successfully
  // join profile0.
  EXPECT_CALL(*profile0, ConfigureService(IsRefPtrTo(s_not_in_profile.get())))
      .Times(0);
  EXPECT_CALL(*profile0, ConfigureService(IsRefPtrTo(s_not_in_group.get())))
      .Times(0);
  EXPECT_CALL(*profile0, ConfigureService(IsRefPtrTo(s_configure_fail.get())))
      .WillOnce(Return(false));
  EXPECT_CALL(*profile0,
              ConfigureService(IsRefPtrTo(s_configure_succeed.get())))
      .WillOnce(Return(true));

  // Expect the failed-to-configure service to have Unload() called on it.
  EXPECT_CALL(*s_not_in_profile, Unload()).Times(0);
  EXPECT_CALL(*s_not_in_group, Unload()).Times(0);
  EXPECT_CALL(*s_configure_fail, Unload()).Times(1);
  EXPECT_CALL(*s_configure_succeed, Unload()).Times(0);

  EXPECT_TRUE(manager()->HandleProfileEntryDeletion(profile1, entry_name));
  EXPECT_TRUE(IsSortServicesTaskPending());

  EXPECT_EQ(GetEphemeralProfile(manager()), s_not_in_profile->profile());
  EXPECT_EQ(profile1, s_not_in_group->profile());
  EXPECT_EQ(GetEphemeralProfile(manager()), s_configure_fail->profile());

  // Since we are using a MockProfile, the profile does not actually change,
  // since ConfigureService was not actually called on the service.
  EXPECT_EQ(profile1, s_configure_succeed->profile());
}

TEST_F(ManagerTest, HandleProfileEntryDeletionWithUnload) {
  MockServiceRefPtr s_will_remove0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr s_will_remove1(new NiceMock<MockService>(manager()));
  MockServiceRefPtr s_will_not_remove0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr s_will_not_remove1(new NiceMock<MockService>(manager()));

  std::string entry_name("entry_name");
  EXPECT_CALL(*s_will_remove0, GetStorageIdentifier())
      .WillRepeatedly(Return(entry_name));
  EXPECT_CALL(*s_will_remove1, GetStorageIdentifier())
      .WillRepeatedly(Return(entry_name));
  EXPECT_CALL(*s_will_not_remove0, GetStorageIdentifier())
      .WillRepeatedly(Return(entry_name));
  EXPECT_CALL(*s_will_not_remove1, GetStorageIdentifier())
      .WillRepeatedly(Return(entry_name));

  manager()->RegisterService(s_will_remove0);
  CompleteServiceSort();
  manager()->RegisterService(s_will_not_remove0);
  CompleteServiceSort();
  manager()->RegisterService(s_will_remove1);
  CompleteServiceSort();
  manager()->RegisterService(s_will_not_remove1);
  CompleteServiceSort();

  // One for each service added above.
  ASSERT_EQ(4, GetServices().size());

  scoped_refptr<MockProfile> profile(
      new StrictMock<MockProfile>(manager(), ""));

  s_will_remove0->set_profile(profile);
  s_will_remove1->set_profile(profile);
  s_will_not_remove0->set_profile(profile);
  s_will_not_remove1->set_profile(profile);

  AdoptProfile(manager(), profile);

  // Deny any of the services re-entry to the profile.
  EXPECT_CALL(*profile, ConfigureService(_)).WillRepeatedly(Return(false));

  EXPECT_CALL(*profile, AbandonService(ServiceRefPtr(s_will_remove0)))
      .WillOnce(Return(true));
  EXPECT_CALL(*profile, AbandonService(ServiceRefPtr(s_will_remove1)))
      .WillOnce(Return(true));
  EXPECT_CALL(*profile, AbandonService(ServiceRefPtr(s_will_not_remove0)))
      .WillOnce(Return(true));
  EXPECT_CALL(*profile, AbandonService(ServiceRefPtr(s_will_not_remove1)))
      .WillOnce(Return(true));

  EXPECT_CALL(*s_will_remove0, Unload()).WillOnce(Return(true));
  EXPECT_CALL(*s_will_remove1, Unload()).WillOnce(Return(true));
  EXPECT_CALL(*s_will_not_remove0, Unload()).WillOnce(Return(false));
  EXPECT_CALL(*s_will_not_remove1, Unload()).WillOnce(Return(false));

  // This will cause all the profiles to be unloaded.
  EXPECT_FALSE(IsSortServicesTaskPending());
  EXPECT_TRUE(manager()->HandleProfileEntryDeletion(profile, entry_name));
  EXPECT_TRUE(IsSortServicesTaskPending());

  // 2 of the 4 services added above should have been unregistered and
  // removed, leaving 2.
  EXPECT_EQ(2, GetServices().size());
  EXPECT_EQ(s_will_not_remove0, GetServices()[0]);
  EXPECT_EQ(s_will_not_remove1, GetServices()[1]);
}

TEST_F(ManagerTest, PopProfileWithUnload) {
  MockServiceRefPtr s_will_remove0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr s_will_remove1(new NiceMock<MockService>(manager()));
  MockServiceRefPtr s_will_not_remove0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr s_will_not_remove1(new NiceMock<MockService>(manager()));

  manager()->RegisterService(s_will_remove0);
  CompleteServiceSort();
  manager()->RegisterService(s_will_not_remove0);
  CompleteServiceSort();
  manager()->RegisterService(s_will_remove1);
  CompleteServiceSort();
  manager()->RegisterService(s_will_not_remove1);
  CompleteServiceSort();

  // One for each service added above.
  ASSERT_EQ(4, GetServices().size());

  scoped_refptr<MockProfile> profile0(
      new StrictMock<MockProfile>(manager(), ""));
  scoped_refptr<MockProfile> profile1(
      new StrictMock<MockProfile>(manager(), ""));

  s_will_remove0->set_profile(profile1);
  s_will_remove1->set_profile(profile1);
  s_will_not_remove0->set_profile(profile1);
  s_will_not_remove1->set_profile(profile1);

  AdoptProfile(manager(), profile0);
  AdoptProfile(manager(), profile1);

  // Deny any of the services entry to profile0, so they will all be unloaded.
  EXPECT_CALL(*profile0, ConfigureService(_)).WillRepeatedly(Return(false));

  EXPECT_CALL(*s_will_remove0, Unload()).WillOnce(Return(true));
  EXPECT_CALL(*s_will_remove1, Unload()).WillOnce(Return(true));
  EXPECT_CALL(*s_will_not_remove0, Unload()).WillRepeatedly(Return(false));
  EXPECT_CALL(*s_will_not_remove1, Unload()).WillOnce(Return(false));

  // Ignore calls to Profile::GetRpcIdentifier because of emitted changes of the
  // profile list.
  EXPECT_CALL(*profile0, GetRpcIdentifier()).Times(AnyNumber());
  EXPECT_CALL(*profile1, GetRpcIdentifier()).Times(AnyNumber());

  // This will pop profile1, which should cause all our profiles to unload.
  Error error;
  manager()->PopAnyProfile(&error);
  EXPECT_TRUE(error.IsSuccess());
  CompleteServiceSort();

  // 2 of the 4 services added above should have been unregistered and
  // removed, leaving 2.
  EXPECT_EQ(2, GetServices().size());
  EXPECT_EQ(s_will_not_remove0, GetServices()[0]);
  EXPECT_EQ(s_will_not_remove1, GetServices()[1]);

  // Expect the unloaded services to lose their profile reference.
  EXPECT_FALSE(s_will_remove0->profile());
  EXPECT_FALSE(s_will_remove1->profile());

  // If we explicitly deregister a service, the effect should be the same
  // with respect to the profile reference.
  ASSERT_NE(nullptr, s_will_not_remove0->profile());
  manager()->DeregisterService(s_will_not_remove0);
  EXPECT_FALSE(s_will_not_remove0->profile());
}

TEST_F(ManagerTest, SetProperty) {
  {
    Error error;
    const bool arp_gateway = false;
    manager()->mutable_store()->SetAnyProperty(
        kArpGatewayProperty, brillo::Any(arp_gateway), &error);
    EXPECT_TRUE(error.IsSuccess());
  }
  {
    Error error;
    const std::string portal_list("wifi,cellular");
    manager()->mutable_store()->SetAnyProperty(
        kCheckPortalListProperty, brillo::Any(portal_list), &error);
    EXPECT_TRUE(error.IsSuccess());
  }
  // Attempt to write with value of wrong type should return InvalidArgs.
  {
    Error error;
    manager()->mutable_store()->SetAnyProperty(
        kCheckPortalListProperty, PropertyStoreTest::kBoolV, &error);
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }
  {
    Error error;
    manager()->mutable_store()->SetAnyProperty(
        kArpGatewayProperty, PropertyStoreTest::kStringV, &error);
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }
  // Attempt to write R/O property should return InvalidArgs.
  {
    Error error;
    manager()->mutable_store()->SetAnyProperty(
        kEnabledTechnologiesProperty, PropertyStoreTest::kStringsV, &error);
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }
}

TEST_F(ManagerTest, RequestScan) {
  {
    Error error;
    manager()->RegisterDevice(mock_devices_[0].get());
    manager()->RegisterDevice(mock_devices_[1].get());
    EXPECT_CALL(*mock_devices_[0], technology())
        .WillRepeatedly(Return(Technology::kWiFi));
    EXPECT_CALL(*mock_devices_[0], Scan(_, _));
    EXPECT_CALL(*mock_devices_[1], technology())
        .WillRepeatedly(Return(Technology::kUnknown));
    EXPECT_CALL(*mock_devices_[1], Scan(_, _)).Times(0);
    manager()->RequestScan(kTypeWifi, &error);
    manager()->DeregisterDevice(mock_devices_[0].get());
    manager()->DeregisterDevice(mock_devices_[1].get());
    Mock::VerifyAndClearExpectations(mock_devices_[0].get());
    Mock::VerifyAndClearExpectations(mock_devices_[1].get());

    manager()->RegisterDevice(mock_devices_[0].get());
    EXPECT_CALL(*mock_devices_[0], technology())
        .WillRepeatedly(Return(Technology::kWiFi));
    EXPECT_CALL(*mock_devices_[0], Scan(_, _));
    manager()->RequestScan(kTypeWifi, &error);
    manager()->DeregisterDevice(mock_devices_[0].get());
    Mock::VerifyAndClearExpectations(mock_devices_[0].get());

    manager()->RegisterDevice(mock_devices_[0].get());
    EXPECT_CALL(*mock_devices_[0], technology())
        .WillRepeatedly(Return(Technology::kUnknown));
    EXPECT_CALL(*mock_devices_[0], Scan(_, _)).Times(0);
    manager()->RequestScan(kTypeWifi, &error);
    manager()->DeregisterDevice(mock_devices_[0].get());
    Mock::VerifyAndClearExpectations(mock_devices_[0].get());
  }

  {
    Error error;
    manager()->RequestScan("bogus_device_type", &error);
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }
}

TEST_F(ManagerTest, GetServiceNoType) {
  KeyValueStore args;
  Error e;
  manager()->GetService(args, &e);
  EXPECT_EQ(Error::kInvalidArguments, e.type());
  EXPECT_EQ("must specify service type", e.message());
}

TEST_F(ManagerTest, GetServiceUnknownType) {
  KeyValueStore args;
  Error e;
  args.Set<std::string>(kTypeProperty, "NotANetworkTechnology");
  manager()->GetService(args, &e);
  EXPECT_EQ(Error::kTechnologyNotAvailable, e.type());
}

TEST_F(ManagerTest, GetServiceEthernet) {
  KeyValueStore args;
  Error e;
  EthernetServiceRefPtr service;
  args.Set<std::string>(kTypeProperty, kTypeEthernet);
  EXPECT_CALL(*ethernet_provider_, GetService(_, _))
      .WillRepeatedly(Return(service));
  manager()->GetService(args, &e);
  EXPECT_TRUE(e.IsSuccess());
}

#if !defined(DISABLE_WIRED_8021X)
TEST_F(ManagerTest, GetServiceEthernetEap) {
  KeyValueStore args;
  Error e;
  ServiceRefPtr service = new NiceMock<MockService>(manager());
  args.Set<std::string>(kTypeProperty, kTypeEthernetEap);
  SetEapProviderService(service);
  EXPECT_EQ(service, manager()->GetService(args, &e));
  EXPECT_TRUE(e.IsSuccess());
}
#endif  // DISABLE_WIRED_8021X

#if !defined(DISABLE_WIFI)
TEST_F(ManagerTest, GetServiceWifi) {
  KeyValueStore args;
  Error e;
  WiFiServiceRefPtr wifi_service;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  EXPECT_CALL(*wifi_provider_, GetService(_, _))
      .WillRepeatedly(Return(wifi_service));
  manager()->GetService(args, &e);
  EXPECT_TRUE(e.IsSuccess());
}
#endif  // DISABLE_WIFI

TEST_F(ManagerTest, GetServiceVPNUnknownType) {
  KeyValueStore args;
  Error e;
  args.Set<std::string>(kTypeProperty, kTypeVPN);
  scoped_refptr<MockProfile> profile(
      new StrictMock<MockProfile>(manager(), ""));
  AdoptProfile(manager(), profile);
  ServiceRefPtr service = manager()->GetService(args, &e);
  EXPECT_EQ(Error::kInvalidProperty, e.type());
  EXPECT_FALSE(service);
}

TEST_F(ManagerTest, ConfigureServiceWithInvalidProfile) {
  // Manager calls ActiveProfile() so we need at least one profile installed.
  scoped_refptr<MockProfile> profile(new NiceMock<MockProfile>(manager(), ""));
  AdoptProfile(manager(), profile);

  KeyValueStore args;
  args.Set<std::string>(kProfileProperty, "xxx");
  Error error;
  manager()->ConfigureService(args, &error);
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("Invalid profile name xxx", error.message());
}

TEST_F(ManagerTest, ConfigureServiceWithGetServiceFailure) {
  // Manager calls ActiveProfile() so we need at least one profile installed.
  scoped_refptr<MockProfile> profile(new NiceMock<MockProfile>(manager(), ""));
  AdoptProfile(manager(), profile);

  KeyValueStore args;
  Error error;
  manager()->ConfigureService(args, &error);
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("must specify service type", error.message());
}

#if !defined(DISABLE_WIFI)
// TODO(zqiu): Consider creating a TestProvider to provide generic services,
// (MockService) instead of using technology specific (wifi) services. This
// will remove the dependency for wifi from ConfigureXXX tests.
//
// A registered service in the ephemeral profile should be moved to the
// active profile as a part of configuration if no profile was explicitly
// specified.
TEST_F(ManagerTest, ConfigureRegisteredServiceWithoutProfile) {
  scoped_refptr<MockProfile> profile(new NiceMock<MockProfile>(manager(), ""));

  AdoptProfile(manager(), profile);  // This is now the active profile.

  const std::vector<uint8_t> ssid;
  scoped_refptr<MockWiFiService> service(new NiceMock<MockWiFiService>(
      manager(), wifi_provider_, ssid, "", kSecurityNone, false));

  manager()->RegisterService(service);
  service->set_profile(GetEphemeralProfile(manager()));

  EXPECT_CALL(*wifi_provider_, GetService(_, _)).WillOnce(Return(service));
  EXPECT_CALL(*profile, UpdateService(ServiceRefPtr(service.get())))
      .WillOnce(Return(true));
  EXPECT_CALL(*profile, AdoptService(ServiceRefPtr(service.get())))
      .WillOnce(Return(true));

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  Error error;
  manager()->ConfigureService(args, &error);
  EXPECT_TRUE(error.IsSuccess());
}

// If we configure a service that was already registered and explicitly
// specify a profile, it should be moved from the profile it was previously
// in to the specified profile if one was requested.
TEST_F(ManagerTest, ConfigureRegisteredServiceWithProfile) {
  scoped_refptr<MockProfile> profile0(new NiceMock<MockProfile>(manager(), ""));
  scoped_refptr<MockProfile> profile1(new NiceMock<MockProfile>(manager(), ""));

  const RpcIdentifier kProfileName0("profile0");
  const RpcIdentifier kProfileName1("profile1");

  EXPECT_CALL(*profile0, GetRpcIdentifier())
      .WillRepeatedly(ReturnRef(kProfileName0));
  EXPECT_CALL(*profile1, GetRpcIdentifier())
      .WillRepeatedly(ReturnRef(kProfileName1));

  AdoptProfile(manager(), profile0);
  AdoptProfile(manager(), profile1);  // profile1 is now the ActiveProfile.

  const std::vector<uint8_t> ssid;
  scoped_refptr<MockWiFiService> service(new NiceMock<MockWiFiService>(
      manager(), wifi_provider_, ssid, "", kSecurityNone, false));

  manager()->RegisterService(service);
  service->set_profile(profile1);

  EXPECT_CALL(*wifi_provider_, GetService(_, _)).WillOnce(Return(service));
  EXPECT_CALL(*profile0, LoadService(ServiceRefPtr(service.get())))
      .WillOnce(Return(true));
  EXPECT_CALL(*profile0, UpdateService(ServiceRefPtr(service.get())))
      .WillOnce(Return(true));
  EXPECT_CALL(*profile0, AdoptService(ServiceRefPtr(service.get())))
      .WillOnce(Return(true));
  EXPECT_CALL(*profile1, AbandonService(ServiceRefPtr(service.get())))
      .WillOnce(Return(true));

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kProfileProperty, kProfileName0.value());
  Error error;
  manager()->ConfigureService(args, &error);
  EXPECT_TRUE(error.IsSuccess());
  service->set_profile(nullptr);  // Breaks refcounting loop.
}

// If we configure a service that is already a member of the specified
// profile, the Manager should not call LoadService or AdoptService again
// on this service.
TEST_F(ManagerTest, ConfigureRegisteredServiceWithSameProfile) {
  scoped_refptr<MockProfile> profile0(new NiceMock<MockProfile>(manager(), ""));

  const RpcIdentifier kProfileName0("profile0");

  EXPECT_CALL(*profile0, GetRpcIdentifier())
      .WillRepeatedly(ReturnRef(kProfileName0));

  AdoptProfile(manager(), profile0);  // profile0 is now the ActiveProfile.

  const std::vector<uint8_t> ssid;
  scoped_refptr<MockWiFiService> service(new NiceMock<MockWiFiService>(
      manager(), wifi_provider_, ssid, "", kSecurityNone, false));

  manager()->RegisterService(service);
  service->set_profile(profile0);

  EXPECT_CALL(*wifi_provider_, GetService(_, _)).WillOnce(Return(service));
  EXPECT_CALL(*profile0, LoadService(ServiceRefPtr(service.get()))).Times(0);
  EXPECT_CALL(*profile0, UpdateService(ServiceRefPtr(service.get())))
      .WillOnce(Return(true));
  EXPECT_CALL(*profile0, AdoptService(ServiceRefPtr(service.get()))).Times(0);

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kProfileProperty, kProfileName0.value());
  Error error;
  manager()->ConfigureService(args, &error);
  EXPECT_TRUE(error.IsSuccess());
  service->set_profile(nullptr);  // Breaks refcounting loop.
}

// An unregistered service should remain unregistered, but its contents should
// be saved to the specified profile nonetheless.
TEST_F(ManagerTest, ConfigureUnregisteredServiceWithProfile) {
  scoped_refptr<MockProfile> profile0(new NiceMock<MockProfile>(manager(), ""));
  scoped_refptr<MockProfile> profile1(new NiceMock<MockProfile>(manager(), ""));

  const RpcIdentifier kProfileName0("profile0");
  const RpcIdentifier kProfileName1("profile1");

  EXPECT_CALL(*profile0, GetRpcIdentifier())
      .WillRepeatedly(ReturnRef(kProfileName0));
  EXPECT_CALL(*profile1, GetRpcIdentifier())
      .WillRepeatedly(ReturnRef(kProfileName1));

  AdoptProfile(manager(), profile0);
  AdoptProfile(manager(), profile1);  // profile1 is now the ActiveProfile.

  const std::vector<uint8_t> ssid;
  scoped_refptr<MockWiFiService> service(new NiceMock<MockWiFiService>(
      manager(), wifi_provider_, ssid, "", kSecurityNone, false));

  service->set_profile(profile1);

  EXPECT_CALL(*wifi_provider_, GetService(_, _)).WillOnce(Return(service));
  EXPECT_CALL(*profile0, UpdateService(ServiceRefPtr(service.get())))
      .WillOnce(Return(true));
  EXPECT_CALL(*profile0, AdoptService(_)).Times(0);
  EXPECT_CALL(*profile1, AdoptService(_)).Times(0);

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kProfileProperty, kProfileName0.value());
  Error error;
  manager()->ConfigureService(args, &error);
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(ManagerTest, ConfigureServiceForProfileWithNoType) {
  KeyValueStore args;
  Error error;
  ServiceRefPtr service =
      manager()->ConfigureServiceForProfile("", args, &error);
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("must specify service type", error.message());
  EXPECT_EQ(nullptr, service);
}

TEST_F(ManagerTest, ConfigureServiceForProfileWithWrongType) {
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, "UnknownType");
  Error error;
  ServiceRefPtr service =
      manager()->ConfigureServiceForProfile("", args, &error);
  EXPECT_EQ(Error::kTechnologyNotAvailable, error.type());
  EXPECT_EQ(nullptr, service);
}

TEST_F(ManagerTest, ConfigureServiceForProfileWithMissingProfile) {
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  Error error;
  ServiceRefPtr service =
      manager()->ConfigureServiceForProfile("/profile/foo", args, &error);
  EXPECT_EQ(Error::kNotFound, error.type());
  EXPECT_EQ("Profile specified was not found", error.message());
  EXPECT_EQ(nullptr, service);
}

TEST_F(ManagerTest, ConfigureServiceForProfileWithProfileMismatch) {
  const RpcIdentifier kProfileName0("profile0");
  const RpcIdentifier kProfileName1("profile1");
  scoped_refptr<MockProfile> profile0(
      AddNamedMockProfileToManager(manager(), kProfileName0));

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kProfileProperty, kProfileName1.value());
  Error error;
  ServiceRefPtr service = manager()->ConfigureServiceForProfile(
      kProfileName0.value(), args, &error);
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ(
      "Profile argument does not match that in "
      "the configuration arguments",
      error.message());
  EXPECT_EQ(nullptr, service);
}

TEST_F(ManagerTest,
       ConfigureServiceForProfileWithNoMatchingServiceFailGetService) {
  const RpcIdentifier kProfileName0("profile0");
  scoped_refptr<MockProfile> profile0(
      AddNamedMockProfileToManager(manager(), kProfileName0));
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kProfileProperty, kProfileName0.value());

  EXPECT_CALL(*wifi_provider_, FindSimilarService(_, _))
      .WillOnce(Return(WiFiServiceRefPtr()));
  EXPECT_CALL(*wifi_provider_, GetService(_, _))
      .WillOnce(Return(WiFiServiceRefPtr()));
  Error error;
  ServiceRefPtr service = manager()->ConfigureServiceForProfile(
      kProfileName0.value(), args, &error);
  // Since we didn't set the error in the GetService expectation above...
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(nullptr, service);
}

TEST_F(ManagerTest, ConfigureServiceForProfileCreateNewService) {
  const RpcIdentifier kProfileName0("profile0");
  scoped_refptr<MockProfile> profile0(
      AddNamedMockProfileToManager(manager(), kProfileName0));

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);

  scoped_refptr<MockWiFiService> mock_service(new NiceMock<MockWiFiService>(
      manager(), wifi_provider_, std::vector<uint8_t>(), kModeManaged,
      kSecurityNone, false));
  ServiceRefPtr mock_service_generic(mock_service.get());
  mock_service->set_profile(profile0);
  EXPECT_CALL(*wifi_provider_, FindSimilarService(_, _))
      .WillOnce(Return(WiFiServiceRefPtr()));
  EXPECT_CALL(*wifi_provider_, GetService(_, _)).WillOnce(Return(mock_service));
  EXPECT_CALL(*profile0, UpdateService(mock_service_generic))
      .WillOnce(Return(true));
  Error error;
  ServiceRefPtr service = manager()->ConfigureServiceForProfile(
      kProfileName0.value(), args, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(mock_service, service);
  mock_service->set_profile(nullptr);  // Breaks reference cycle.
}

TEST_F(ManagerTest, ConfigureServiceForProfileMatchingServiceByGUID) {
  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  const std::string kGUID = "a guid";
  mock_service->SetGuid(kGUID, nullptr);
  manager()->RegisterService(mock_service);
  ServiceRefPtr mock_service_generic(mock_service.get());

  const RpcIdentifier kProfileName("profile");
  scoped_refptr<MockProfile> profile(
      AddNamedMockProfileToManager(manager(), kProfileName));
  mock_service->set_profile(profile);

  EXPECT_CALL(*mock_service, technology())
      .WillOnce(Return(Technology::kCellular))
      .WillOnce(Return(Technology::kWiFi));

  EXPECT_CALL(*wifi_provider_, FindSimilarService(_, _)).Times(0);
  EXPECT_CALL(*wifi_provider_, GetService(_, _)).Times(0);
  EXPECT_CALL(*profile, AdoptService(mock_service_generic)).Times(0);

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kGuidProperty, kGUID);

  // The first attempt should fail because the service reports a technology
  // other than "WiFi".
  {
    Error error;
    ServiceRefPtr service = manager()->ConfigureServiceForProfile(
        kProfileName.value(), args, &error);
    EXPECT_EQ(nullptr, service);
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ("This GUID matches a non-wifi service", error.message());
  }

  EXPECT_CALL(*mock_service, Configure(_, _)).Times(1);
  EXPECT_CALL(*profile, UpdateService(mock_service_generic)).Times(1);

  {
    Error error;
    ServiceRefPtr service = manager()->ConfigureServiceForProfile(
        kProfileName.value(), args, &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(mock_service, service);
    EXPECT_EQ(profile, service->profile());
  }
  mock_service->set_profile(nullptr);  // Breaks reference cycle.
}

TEST_F(ManagerTest, ConfigureServiceForProfileMatchingServiceAndProfile) {
  const RpcIdentifier kProfileName("profile");
  scoped_refptr<MockProfile> profile(
      AddNamedMockProfileToManager(manager(), kProfileName));

  scoped_refptr<MockWiFiService> mock_service(new NiceMock<MockWiFiService>(
      manager(), wifi_provider_, std::vector<uint8_t>(), kModeManaged,
      kSecurityNone, false));
  mock_service->set_profile(profile);
  ServiceRefPtr mock_service_generic(mock_service.get());

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  EXPECT_CALL(*wifi_provider_, FindSimilarService(_, _))
      .WillOnce(Return(mock_service));
  EXPECT_CALL(*wifi_provider_, GetService(_, _)).Times(0);
  EXPECT_CALL(*profile, AdoptService(mock_service_generic)).Times(0);
  EXPECT_CALL(*mock_service, Configure(_, _)).Times(1);
  EXPECT_CALL(*profile, UpdateService(mock_service_generic)).Times(1);

  Error error;
  ServiceRefPtr service =
      manager()->ConfigureServiceForProfile(kProfileName.value(), args, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(mock_service, service);
  EXPECT_EQ(profile, service->profile());
  mock_service->set_profile(nullptr);  // Breaks reference cycle.
}

TEST_F(ManagerTest, ConfigureServiceForProfileMatchingServiceEphemeralProfile) {
  const RpcIdentifier kProfileName("profile");
  scoped_refptr<MockProfile> profile(
      AddNamedMockProfileToManager(manager(), kProfileName));

  scoped_refptr<MockWiFiService> mock_service(new NiceMock<MockWiFiService>(
      manager(), wifi_provider_, std::vector<uint8_t>(), kModeManaged,
      kSecurityNone, false));
  mock_service->set_profile(GetEphemeralProfile(manager()));
  ServiceRefPtr mock_service_generic(mock_service.get());

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  EXPECT_CALL(*wifi_provider_, FindSimilarService(_, _))
      .WillOnce(Return(mock_service));
  EXPECT_CALL(*wifi_provider_, GetService(_, _)).Times(0);
  EXPECT_CALL(*mock_service, Configure(_, _)).Times(1);
  EXPECT_CALL(*profile, UpdateService(mock_service_generic)).Times(1);

  Error error;
  ServiceRefPtr service =
      manager()->ConfigureServiceForProfile(kProfileName.value(), args, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(mock_service, service);
  EXPECT_EQ(profile, service->profile());
  mock_service->set_profile(nullptr);  // Breaks reference cycle.
}

TEST_F(ManagerTest, ConfigureServiceForProfileMatchingServicePrecedingProfile) {
  const RpcIdentifier kProfileName0("profile0");
  scoped_refptr<MockProfile> profile0(
      AddNamedMockProfileToManager(manager(), kProfileName0));
  const RpcIdentifier kProfileName1("profile1");
  scoped_refptr<MockProfile> profile1(
      AddNamedMockProfileToManager(manager(), kProfileName1));

  scoped_refptr<MockWiFiService> mock_service(new NiceMock<MockWiFiService>(
      manager(), wifi_provider_, std::vector<uint8_t>(), kModeManaged,
      kSecurityNone, false));
  manager()->RegisterService(mock_service);
  mock_service->set_profile(profile0);
  ServiceRefPtr mock_service_generic(mock_service.get());

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  EXPECT_CALL(*wifi_provider_, FindSimilarService(_, _))
      .WillOnce(Return(mock_service));
  EXPECT_CALL(*wifi_provider_, GetService(_, _)).Times(0);
  EXPECT_CALL(*profile0, AbandonService(_)).Times(0);
  EXPECT_CALL(*profile1, AdoptService(_)).Times(0);
  // This happens once to make the service loadable for the ConfigureService
  // below, and a second time after the service is modified.
  EXPECT_CALL(*profile1, ConfigureService(mock_service_generic)).Times(0);
  EXPECT_CALL(*wifi_provider_, CreateTemporaryService(_, _)).Times(0);
  EXPECT_CALL(*mock_service, Configure(_, _)).Times(1);
  EXPECT_CALL(*profile1, UpdateService(mock_service_generic)).Times(1);

  Error error;
  ServiceRefPtr service = manager()->ConfigureServiceForProfile(
      kProfileName1.value(), args, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(mock_service, service);
  mock_service->set_profile(nullptr);  // Breaks reference cycle.
}

TEST_F(ManagerTest,
       ConfigureServiceForProfileMatchingServiceProceedingProfile) {
  const RpcIdentifier kProfileName0("profile0");
  scoped_refptr<MockProfile> profile0(
      AddNamedMockProfileToManager(manager(), kProfileName0));
  const RpcIdentifier kProfileName1("profile1");
  scoped_refptr<MockProfile> profile1(
      AddNamedMockProfileToManager(manager(), kProfileName1));

  scoped_refptr<MockWiFiService> matching_service(
      new StrictMock<MockWiFiService>(manager(), wifi_provider_,
                                      std::vector<uint8_t>(), kModeManaged,
                                      kSecurityNone, false));
  matching_service->set_profile(profile1);

  // We need to get rid of our reference to this mock service as soon
  // as Manager::ConfigureServiceForProfile() takes a reference in its
  // call to WiFiProvider::CreateTemporaryService().  This way the
  // latter function can keep a DCHECK(service->HasOneRef() even in
  // unit tests.
  temp_mock_service_ = new NiceMock<MockWiFiService>(
      manager(), wifi_provider_, std::vector<uint8_t>(), kModeManaged,
      kSecurityNone, false);

  // Only hold a pointer here so we don't affect the refcount.
  MockWiFiService* mock_service_ptr = temp_mock_service_.get();

  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  EXPECT_CALL(*wifi_provider_, FindSimilarService(_, _))
      .WillOnce(Return(matching_service));
  EXPECT_CALL(*wifi_provider_, GetService(_, _)).Times(0);
  EXPECT_CALL(*profile1, AbandonService(_)).Times(0);
  EXPECT_CALL(*profile0, AdoptService(_)).Times(0);
  EXPECT_CALL(*wifi_provider_, CreateTemporaryService(_, _))
      .WillOnce(InvokeWithoutArgs(this, &ManagerTest::ReleaseTempMockService));
  EXPECT_CALL(*profile0, ConfigureService(IsRefPtrTo(mock_service_ptr)))
      .Times(1);
  EXPECT_CALL(*mock_service_ptr, Configure(_, _)).Times(1);
  EXPECT_CALL(*profile0, UpdateService(IsRefPtrTo(mock_service_ptr))).Times(1);

  Error error;
  ServiceRefPtr service = manager()->ConfigureServiceForProfile(
      kProfileName0.value(), args, &error);
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(Error::kNotFound, error.type());
  EXPECT_EQ("Temporary service configured but not usable", error.message());
  EXPECT_EQ(nullptr, service);
  EXPECT_EQ(profile1, matching_service->profile());
}
#endif  // DISABLE_WIFI

TEST_F(ManagerTest, FindMatchingService) {
  KeyValueStore args;
  {
    Error error;
    ServiceRefPtr service = manager()->FindMatchingService(args, &error);
    EXPECT_EQ(Error::kNotFound, error.type());
  }

  MockServiceRefPtr mock_service0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr mock_service1(new NiceMock<MockService>(manager()));
  manager()->RegisterService(mock_service0);
  manager()->RegisterService(mock_service1);
  EXPECT_CALL(*mock_service0, DoPropertiesMatch(_))
      .WillOnce(Return(true))
      .WillRepeatedly(Return(false));
  {
    Error error;
    EXPECT_EQ(mock_service0, manager()->FindMatchingService(args, &error));
    EXPECT_TRUE(error.IsSuccess());
  }
  EXPECT_CALL(*mock_service1, DoPropertiesMatch(_))
      .WillOnce(Return(true))
      .WillRepeatedly(Return(false));
  {
    Error error;
    EXPECT_EQ(mock_service1, manager()->FindMatchingService(args, &error));
    EXPECT_TRUE(error.IsSuccess());
  }
  {
    Error error;
    EXPECT_FALSE(manager()->FindMatchingService(args, &error));
    EXPECT_EQ(Error::kNotFound, error.type());
  }
}

TEST_F(ManagerTest, TechnologyOrder) {
  // If the Manager is not running, setting the technology order should not
  // lauch a service sorting task.
  SetRunning(false);
  Error error;
  manager()->SetTechnologyOrder("vpn,ethernet,wifi,cellular", &error);
  ASSERT_TRUE(error.IsSuccess());
  EXPECT_FALSE(IsSortServicesTaskPending());
  EXPECT_THAT(GetTechnologyOrder(),
              ElementsAre(Technology::kVPN, Technology::kEthernet,
                          Technology::kWiFi, Technology::kCellular));

  SetRunning(true);
  manager()->SetTechnologyOrder(
      std::string(kTypeEthernet) + "," + std::string(kTypeWifi), &error);
  EXPECT_TRUE(IsSortServicesTaskPending());
  ASSERT_TRUE(error.IsSuccess());
  EXPECT_EQ(manager()->GetTechnologyOrder(),
            std::string(kTypeEthernet) + "," + std::string(kTypeWifi));

  manager()->SetTechnologyOrder(
      std::string(kTypeEthernet) + "x," + std::string(kTypeWifi), &error);
  ASSERT_FALSE(error.IsSuccess());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ(std::string(kTypeEthernet) + "," + std::string(kTypeWifi),
            manager()->GetTechnologyOrder());
}

TEST_F(ManagerTest, ConnectionStatusCheck) {
  // Setup mock service.
  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  manager()->RegisterService(mock_service);

  // Device not connected.
  EXPECT_CALL(*mock_service, IsConnected(nullptr)).WillOnce(Return(false));
  EXPECT_CALL(*metrics(),
              NotifyDeviceConnectionStatus(Metrics::kConnectionStatusOffline));
  manager()->ConnectionStatusCheck();

  // Device connected, but not online.
  EXPECT_CALL(*mock_service, IsConnected(nullptr)).WillOnce(Return(true));
  EXPECT_CALL(*mock_service, IsOnline()).WillOnce(Return(false));
  EXPECT_CALL(*metrics(),
              NotifyDeviceConnectionStatus(Metrics::kConnectionStatusOnline))
      .Times(0);
  EXPECT_CALL(*metrics(), NotifyDeviceConnectionStatus(
                              Metrics::kConnectionStatusConnected));
  manager()->ConnectionStatusCheck();

  // Device connected and online.
  EXPECT_CALL(*mock_service, IsConnected(nullptr)).WillOnce(Return(true));
  EXPECT_CALL(*mock_service, IsOnline()).WillOnce(Return(true));
  EXPECT_CALL(*metrics(),
              NotifyDeviceConnectionStatus(Metrics::kConnectionStatusOnline));
  EXPECT_CALL(*metrics(), NotifyDeviceConnectionStatus(
                              Metrics::kConnectionStatusConnected));
  manager()->ConnectionStatusCheck();
}

TEST_F(ManagerTest, DevicePresenceStatusCheck) {
  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);

  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[1], technology())
      .WillByDefault(Return(Technology::kWiFi));
  ON_CALL(*mock_devices_[2], technology())
      .WillByDefault(Return(Technology::kEthernet));

  EXPECT_CALL(*metrics(), NotifyDevicePresenceStatus(
                              Technology(Technology::kEthernet), true));
  EXPECT_CALL(*metrics(),
              NotifyDevicePresenceStatus(Technology(Technology::kWiFi), true));
  EXPECT_CALL(*metrics(), NotifyDevicePresenceStatus(
                              Technology(Technology::kCellular), false));
  manager()->DevicePresenceStatusCheck();
}

TEST_F(ManagerTest, SortServicesWithConnection) {
  MockServiceRefPtr mock_service0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr mock_service1(new NiceMock<MockService>(manager()));

  // A single registered Service, without a connection.  The
  // DefaultService should be nullptr.  If a change notification is
  // generated, it should reference kNullPath.
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierChanged(kDefaultServiceProperty,
                                       DBusControl::NullRpcIdentifier()))
      .Times(AnyNumber());
  manager()->RegisterService(mock_service0);
  CompleteServiceSort();

  // Adding another Service, also without a connection, does not
  // change DefaultService.  Furthermore, we do not send a change
  // notification for DefaultService.
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierChanged(kDefaultServiceProperty, _))
      .Times(0);
  manager()->RegisterService(mock_service1);
  CompleteServiceSort();

  // An explicit sort doesn't change anything, and does not emit a
  // change notification for DefaultService.
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierChanged(kDefaultServiceProperty, _))
      .Times(0);
  manager()->SortServicesTask();
  EXPECT_TRUE(ServiceOrderIs(mock_service0, mock_service1));

  // Re-ordering the unconnected Services doesn't change
  // DefaultService, and (hence) does not emit a change notification
  // for DefaultService.
  mock_service1->SetPriority(1, nullptr);
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierChanged(kDefaultServiceProperty, _))
      .Times(0);
  manager()->SortServicesTask();
  EXPECT_TRUE(ServiceOrderIs(mock_service1, mock_service0));

  // Re-ordering the unconnected Services doesn't change
  // DefaultService, and (hence) does not emit a change notification
  // for DefaultService.
  mock_service1->SetPriority(0, nullptr);
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierChanged(kDefaultServiceProperty, _))
      .Times(0);
  manager()->SortServicesTask();
  EXPECT_TRUE(ServiceOrderIs(mock_service0, mock_service1));

  NiceMock<MockConnection> mock_connection0(device_info_.get());
  NiceMock<MockConnection> mock_connection1(device_info_.get());
  SelectServiceForDevice(mock_service0, &mock_connection0, mock_devices_[0]);
  SelectServiceForDevice(mock_service1, &mock_connection1, mock_devices_[1]);

  // Add an entry to the dns_servers() list to test the logic in
  // SortServicesTask() which figures out which connection owns the system
  // DNS configuration.
  std::vector<std::string> dns_servers;
  dns_servers.push_back("8.8.8.8");
  EXPECT_CALL(mock_connection0, dns_servers())
      .WillRepeatedly(ReturnRef(dns_servers));
  EXPECT_CALL(mock_connection1, dns_servers())
      .WillRepeatedly(ReturnRef(dns_servers));

  // If both Services have Connections, the DefaultService follows
  // from ServiceOrderIs.  We notify others of the change in
  // DefaultService.
  EXPECT_CALL(mock_connection0, SetUseDNS(true));
  EXPECT_CALL(mock_connection0, SetPriority(Connection::kDefaultPriority +
                                                Connection::kPriorityStep,
                                            true));
  EXPECT_CALL(mock_connection0,
              SetPriority(Connection::kDefaultPriority, true));
  EXPECT_CALL(mock_connection1, SetUseDNS(false));
  EXPECT_CALL(mock_connection1, SetPriority(Connection::kDefaultPriority +
                                                2 * Connection::kPriorityStep,
                                            false));
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierChanged(kDefaultServiceProperty, _));
  manager()->SortServicesTask();
  EXPECT_TRUE(ServiceOrderIs(mock_service0, mock_service1));

  ServiceWatcher service_watcher;
  manager()->AddDefaultServiceObserver(&service_watcher);

  // Changing the ordering causes the DefaultService to change, and
  // appropriate notifications are sent.
  mock_service1->SetPriority(1, nullptr);
  EXPECT_CALL(mock_connection0, SetUseDNS(false));
  EXPECT_CALL(mock_connection0, SetPriority(Connection::kDefaultPriority +
                                                2 * Connection::kPriorityStep,
                                            false));
  EXPECT_CALL(mock_connection1, SetUseDNS(true));
  EXPECT_CALL(mock_connection1, SetPriority(Connection::kDefaultPriority +
                                                Connection::kPriorityStep,
                                            true));
  EXPECT_CALL(mock_connection1,
              SetPriority(Connection::kDefaultPriority, true));
  EXPECT_CALL(service_watcher, OnDefaultLogicalServiceChanged(_));
  EXPECT_CALL(service_watcher, OnDefaultPhysicalServiceChanged(_));
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierChanged(kDefaultServiceProperty, _));
  manager()->SortServicesTask();
  EXPECT_TRUE(ServiceOrderIs(mock_service1, mock_service0));

  // Deregistering a DefaultServiceCallback works as expected.  (Later
  // code causes DefaultService changes, but we see no further calls
  // to |service_watcher|.)
  manager()->RemoveDefaultServiceObserver(&service_watcher);
  EXPECT_CALL(service_watcher, OnDefaultLogicalServiceChanged(_)).Times(0);
  EXPECT_CALL(service_watcher, OnDefaultPhysicalServiceChanged(_)).Times(0);

  // Deregistering the current DefaultService causes the other Service
  // to become default.  Appropriate notifications are sent.
  EXPECT_CALL(mock_connection0, SetUseDNS(true));
  EXPECT_CALL(mock_connection0, SetPriority(Connection::kDefaultPriority +
                                                Connection::kPriorityStep,
                                            true));
  EXPECT_CALL(mock_connection0,
              SetPriority(Connection::kDefaultPriority, true));
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierChanged(kDefaultServiceProperty, _));
  // So DeregisterService works.
  SelectServiceForDevice(nullptr, nullptr, mock_devices_[1]);
  manager()->DeregisterService(mock_service1);
  CompleteServiceSort();

  // Deregistering the only Service causes the DefaultService to become
  // nullptr.  Appropriate notifications are sent.
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierChanged(kDefaultServiceProperty, _));
  // So DeregisterService works.
  SelectServiceForDevice(nullptr, nullptr, mock_devices_[0]);
  manager()->DeregisterService(mock_service0);
  CompleteServiceSort();

  // An explicit sort doesn't change anything, and does not generate
  // an external notification.
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierChanged(kDefaultServiceProperty, _))
      .Times(0);
  manager()->SortServicesTask();
}

TEST_F(ManagerTest, UpdateDefaultServices) {
  EXPECT_EQ(GetDefaultServiceObserverCount(), 0);

  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  ServiceRefPtr service = mock_service;
  ServiceRefPtr null_service = nullptr;

  manager()->UpdateDefaultServices(null_service, null_service);

  ServiceWatcher service_watcher1;
  ServiceWatcher service_watcher2;
  manager()->AddDefaultServiceObserver(&service_watcher1);
  manager()->AddDefaultServiceObserver(&service_watcher2);

  EXPECT_CALL(service_watcher1, OnDefaultPhysicalServiceChanged(service));
  EXPECT_CALL(service_watcher2, OnDefaultPhysicalServiceChanged(service));
  manager()->UpdateDefaultServices(mock_service, mock_service);

  EXPECT_CALL(service_watcher1, OnDefaultPhysicalServiceChanged(null_service));
  EXPECT_CALL(service_watcher2, OnDefaultPhysicalServiceChanged(null_service));
  manager()->UpdateDefaultServices(null_service, null_service);

  manager()->RemoveDefaultServiceObserver(&service_watcher1);
  EXPECT_CALL(service_watcher1, OnDefaultLogicalServiceChanged(_)).Times(0);
  EXPECT_CALL(service_watcher1, OnDefaultPhysicalServiceChanged(_)).Times(0);
  EXPECT_CALL(service_watcher2, OnDefaultPhysicalServiceChanged(service));
  manager()->UpdateDefaultServices(mock_service, mock_service);
  EXPECT_EQ(GetDefaultServiceObserverCount(), 1);

  manager()->RemoveDefaultServiceObserver(&service_watcher2);
  EXPECT_CALL(service_watcher2, OnDefaultLogicalServiceChanged(_)).Times(0);
  EXPECT_CALL(service_watcher2, OnDefaultPhysicalServiceChanged(_)).Times(0);
  manager()->UpdateDefaultServices(null_service, null_service);

  EXPECT_EQ(GetDefaultServiceObserverCount(), 0);
}

TEST_F(ManagerTest, UpdateDefaultServicesWithDefaultServiceCallbacksRemoved) {
  EXPECT_EQ(GetDefaultServiceObserverCount(), 0);

  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  ServiceRefPtr service = mock_service;
  ServiceRefPtr null_service = nullptr;

  manager()->UpdateDefaultServices(null_service, null_service);

  // Register many callbacks where each callback simply deregisters itself from
  // Manager. This verifies that Manager::UpdateDefaultServices() can safely
  // iterate the container holding the callbacks while callbacks are removed
  // from the container during iteration.
  ServiceWatcher service_watchers[1000];
  for (auto& service_watcher : service_watchers) {
    manager()->AddDefaultServiceObserver(&service_watcher);
    EXPECT_CALL(service_watcher, OnDefaultPhysicalServiceChanged(service))
        .WillOnce(Invoke([this, &service_watcher](const ServiceRefPtr&) {
          manager()->RemoveDefaultServiceObserver(&service_watcher);
        }));
  }

  manager()->UpdateDefaultServices(mock_service, mock_service);
  EXPECT_EQ(GetDefaultServiceObserverCount(), 0);

  for (auto& service_watcher : service_watchers) {
    EXPECT_CALL(service_watcher, OnDefaultLogicalServiceChanged(_)).Times(0);
    EXPECT_CALL(service_watcher, OnDefaultPhysicalServiceChanged(_)).Times(0);
  }
  manager()->UpdateDefaultServices(null_service, null_service);
  EXPECT_EQ(GetDefaultServiceObserverCount(), 0);
}

TEST_F(ManagerTest, DefaultServiceStateChange) {
  MockServiceRefPtr mock_service0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr mock_service1(new NiceMock<MockService>(manager()));

  manager()->RegisterService(mock_service0);
  manager()->RegisterService(mock_service1);

  manager()->UpdateDefaultServices(mock_service0, mock_service0);

  // Changing the default service's state should notify both services.
  EXPECT_CALL(*mock_service0, OnDefaultServiceStateChanged(_));
  EXPECT_CALL(*mock_service1, OnDefaultServiceStateChanged(_));
  manager()->NotifyServiceStateChanged(mock_service0);
  Mock::VerifyAndClearExpectations(mock_service0.get());
  Mock::VerifyAndClearExpectations(mock_service1.get());

  // Changing the non-default service's state shouldn't notify anyone.
  EXPECT_CALL(*mock_service0, OnDefaultServiceStateChanged(_)).Times(0);
  EXPECT_CALL(*mock_service1, OnDefaultServiceStateChanged(_)).Times(0);
  manager()->NotifyServiceStateChanged(mock_service1);

  manager()->UpdateDefaultServices(nullptr, nullptr);

  manager()->DeregisterService(mock_service1);
  manager()->DeregisterService(mock_service0);
}

#if !defined(DISABLE_VPN)
TEST_F(ManagerTest, FindDeviceFromService) {
  MockServiceRefPtr not_selected_service(new MockService(manager()));
  MockServiceRefPtr selected_service(new MockService(manager()));
  scoped_refptr<MockVPNService> vpn_service(
      new MockVPNService(manager(), nullptr));
  scoped_refptr<MockVirtualDevice> vpn_device(
      new MockVirtualDevice(manager(), "ppp0", 123, Technology::kVPN));

  manager()->RegisterDevice(mock_devices_[0]);
  mock_devices_[0]->set_selected_service_for_testing(selected_service);
  vpn_service->device_ = vpn_device;

  EXPECT_EQ(nullptr, manager()->FindDeviceFromService(nullptr));
  EXPECT_EQ(nullptr, manager()->FindDeviceFromService(not_selected_service));
  EXPECT_EQ(mock_devices_[0],
            manager()->FindDeviceFromService(selected_service));
  EXPECT_EQ(vpn_device, manager()->FindDeviceFromService(vpn_service));
}
#endif

TEST_F(ManagerTest, UpdateDefaultServicesDNSProxy) {
  MockServiceRefPtr mock_service0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr mock_service1(new NiceMock<MockService>(manager()));

  manager()->RegisterService(mock_service0);
  manager()->RegisterService(mock_service1);

  EXPECT_CALL(*mock_service0, IsOnline)
      .WillOnce(Return(true))
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  manager()->UpdateDefaultServices(mock_service0, mock_service0);

  // Online -> offline should always force dns-proxy off.
  EXPECT_CALL(resolver_, SetDNSProxyAddresses(ElementsAre()))
      .WillOnce(Return(true));
  manager()->UpdateDefaultServices(mock_service0, mock_service0);

  // Offline -> online should push the dns-proxy info if set.
  manager()->props_.dns_proxy_addresses = {"100.115.92.100"};
  EXPECT_CALL(resolver_, SetDNSProxyAddresses(ElementsAre("100.115.92.100")))
      .WillOnce(Return(true));
  manager()->UpdateDefaultServices(mock_service0, mock_service0);

  // Switching from an online service to an offline one should force dns-proxy
  // off.
  EXPECT_CALL(*mock_service1, IsOnline).WillOnce(Return(false));
  EXPECT_CALL(resolver_, SetDNSProxyAddresses(ElementsAre()))
      .WillOnce(Return(true));
  manager()->UpdateDefaultServices(mock_service1, mock_service1);
}

TEST_F(ManagerTest, AvailableTechnologies) {
  mock_devices_.push_back(
      new NiceMock<MockDevice>(manager(), "null4", "addr4", 0));
  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);
  manager()->RegisterDevice(mock_devices_[3]);

  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[1], technology())
      .WillByDefault(Return(Technology::kWiFi));
  ON_CALL(*mock_devices_[2], technology())
      .WillByDefault(Return(Technology::kCellular));
  ON_CALL(*mock_devices_[3], technology())
      .WillByDefault(Return(Technology::kWiFi));

  std::set<std::string> expected_technologies;
  expected_technologies.insert(Technology(Technology::kEthernet).GetName());
  expected_technologies.insert(Technology(Technology::kWiFi).GetName());
  expected_technologies.insert(Technology(Technology::kCellular).GetName());
  Error error;
  std::vector<std::string> technologies =
      manager()->AvailableTechnologies(&error);

  EXPECT_THAT(std::set<std::string>(technologies.begin(), technologies.end()),
              ContainerEq(expected_technologies));
}

TEST_F(ManagerTest, ConnectedTechnologies) {
  MockServiceRefPtr connected_service1(new NiceMock<MockService>(manager()));
  MockServiceRefPtr connected_service2(new NiceMock<MockService>(manager()));
  MockServiceRefPtr disconnected_service1(new NiceMock<MockService>(manager()));
  MockServiceRefPtr disconnected_service2(new NiceMock<MockService>(manager()));

  ON_CALL(*connected_service1, IsConnected(nullptr))
      .WillByDefault(Return(true));
  ON_CALL(*connected_service2, IsConnected(nullptr))
      .WillByDefault(Return(true));

  manager()->RegisterService(connected_service1);
  manager()->RegisterService(connected_service2);
  manager()->RegisterService(disconnected_service1);
  manager()->RegisterService(disconnected_service2);

  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);
  manager()->RegisterDevice(mock_devices_[3]);

  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[1], technology())
      .WillByDefault(Return(Technology::kWiFi));
  ON_CALL(*mock_devices_[2], technology())
      .WillByDefault(Return(Technology::kCellular));
  ON_CALL(*mock_devices_[3], technology())
      .WillByDefault(Return(Technology::kWiFi));

  mock_devices_[0]->SelectService(connected_service1);
  mock_devices_[1]->SelectService(disconnected_service1);
  mock_devices_[2]->SelectService(disconnected_service2);
  mock_devices_[3]->SelectService(connected_service2);

  std::set<std::string> expected_technologies;
  expected_technologies.insert(Technology(Technology::kEthernet).GetName());
  expected_technologies.insert(Technology(Technology::kWiFi).GetName());
  Error error;

  std::vector<std::string> technologies =
      manager()->ConnectedTechnologies(&error);
  EXPECT_THAT(std::set<std::string>(technologies.begin(), technologies.end()),
              ContainerEq(expected_technologies));
}

TEST_F(ManagerTest, DefaultTechnology) {
  MockServiceRefPtr connected_service(new NiceMock<MockService>(manager()));
  MockServiceRefPtr disconnected_service(new NiceMock<MockService>(manager()));

  // Connected. WiFi.
  ON_CALL(*connected_service, IsConnected(nullptr)).WillByDefault(Return(true));
  ON_CALL(*connected_service, state())
      .WillByDefault(Return(Service::kStateConnected));
  ON_CALL(*connected_service, technology())
      .WillByDefault(Return(Technology::kWiFi));

  // Disconnected. Ethernet.
  ON_CALL(*disconnected_service, technology())
      .WillByDefault(Return(Technology::kEthernet));

  manager()->RegisterService(disconnected_service);
  CompleteServiceSort();
  Error error;
  EXPECT_THAT(manager()->DefaultTechnology(&error), StrEq(""));

  manager()->RegisterService(connected_service);
  CompleteServiceSort();
  // Connected service should be brought to the front now.
  std::string expected_technology = Technology(Technology::kWiFi).GetName();
  EXPECT_THAT(manager()->DefaultTechnology(&error), StrEq(expected_technology));
}

TEST_F(ManagerTest, Stop) {
  scoped_refptr<MockProfile> profile(new NiceMock<MockProfile>(manager(), ""));
  AdoptProfile(manager(), profile);
  manager()->RegisterDevice(mock_devices_[0]);

  // Register inactive Service.
  MockServiceRefPtr service1(new NiceMock<MockService>(manager()));
  manager()->RegisterService(service1);

  // Register active Service.
  MockServiceRefPtr service2(new NiceMock<MockService>(manager()));
  service2->SetState(Service::kStateAssociating);
  manager()->RegisterService(service2);

  SetPowerManager();
  EXPECT_TRUE(manager()->power_manager());
  EXPECT_CALL(*profile, UpdateDevice(DeviceRefPtr(mock_devices_[0].get())))
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_devices_[0], SetEnabled(false));
  EXPECT_CALL(*profile, Save()).WillOnce(Return(true));

  for (const auto& service : GetServices()) {
    EXPECT_FALSE(service->IsActive(nullptr));
  }

  manager()->DeregisterService(service1);
  manager()->DeregisterService(service2);
  manager()->DeregisterDevice(mock_devices_[0]);
  manager()->Stop();
  EXPECT_FALSE(manager()->power_manager());
}

TEST_F(ManagerTest, UpdateServiceConnected) {
  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  manager()->RegisterService(mock_service);
  EXPECT_FALSE(mock_service->retain_auto_connect());
  EXPECT_FALSE(mock_service->auto_connect());

  EXPECT_CALL(*mock_service, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_service, EnableAndRetainAutoConnect());
  manager()->UpdateService(mock_service);
}

TEST_F(ManagerTest, UpdateServiceConnectedPersistAutoConnect) {
  // This tests the case where the user connects to a service that is
  // currently associated with a profile.  We want to make sure that the
  // auto_connect flag is set and that the is saved to the current profile.
  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  manager()->RegisterService(mock_service);
  EXPECT_FALSE(mock_service->retain_auto_connect());
  EXPECT_FALSE(mock_service->auto_connect());

  scoped_refptr<MockProfile> profile(new MockProfile(manager(), ""));

  mock_service->set_profile(profile);
  EXPECT_CALL(*mock_service, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*profile,
              UpdateService(static_cast<ServiceRefPtr>(mock_service)));
  EXPECT_CALL(*mock_service, EnableAndRetainAutoConnect());
  manager()->UpdateService(mock_service);
  // This releases the ref on the mock profile.
  mock_service->set_profile(nullptr);
}

TEST_F(ManagerTest, UpdateServiceLogging) {
  ScopedMockLog log;
  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  std::string updated_message = base::StringPrintf(
      "Service %s updated;", mock_service->log_name().c_str());

  // An idle service should only be logged as not online.
  {
    EXPECT_CALL(*mock_service, state())
        .WillRepeatedly(Return(Service::kStateIdle));
    EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr("not online")));
    manager()->RegisterService(mock_service);
    CompleteServiceSort();
    manager()->UpdateService(mock_service);
    CompleteServiceSort();
  }

  // A service leaving the idle state should create a log message.
  {
    EXPECT_CALL(*mock_service, state())
        .WillRepeatedly(Return(Service::kStateAssociating));
    EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr(updated_message)))
        .Times(1);
    manager()->UpdateService(mock_service.get());
    CompleteServiceSort();
  }

  // A service in a non-idle state should not create a log message if its
  // state did not change.
  {
    EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr(updated_message)))
        .Times(0);
    manager()->UpdateService(mock_service);
    CompleteServiceSort();
  }

  // A service transitioning between two non-idle states should create
  // a log message.
  {
    EXPECT_CALL(*mock_service, state())
        .WillRepeatedly(Return(Service::kStateConnected));
    EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr(updated_message)))
        .Times(1);
    manager()->UpdateService(mock_service.get());
    CompleteServiceSort();
  }

  // A service transitioning from a non-idle state to idle should create
  // a log message.
  {
    EXPECT_CALL(*mock_service, state())
        .WillRepeatedly(Return(Service::kStateIdle));
    EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr(updated_message)))
        .Times(1);
    manager()->UpdateService(mock_service.get());
    CompleteServiceSort();
  }
}

TEST_F(ManagerTest, SaveSuccessfulService) {
  scoped_refptr<MockProfile> profile(
      new StrictMock<MockProfile>(manager(), ""));
  AdoptProfile(manager(), profile);
  MockServiceRefPtr service(new NiceMock<MockService>(manager()));

  // Re-cast this back to a ServiceRefPtr, so EXPECT arguments work correctly.
  ServiceRefPtr expect_service(service.get());

  EXPECT_CALL(*profile, ConfigureService(expect_service))
      .WillOnce(Return(false));
  manager()->RegisterService(service);

  EXPECT_CALL(*service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*service, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*profile, AdoptService(expect_service)).WillOnce(Return(true));
  manager()->UpdateService(service);
}

TEST_F(ManagerTest, UpdateDevice) {
  MockProfile* profile0 = new MockProfile(manager(), "");
  MockProfile* profile1 = new MockProfile(manager(), "");
  MockProfile* profile2 = new MockProfile(manager(), "");
  AdoptProfile(manager(), profile0);  // Passes ownership.
  AdoptProfile(manager(), profile1);  // Passes ownership.
  AdoptProfile(manager(), profile2);  // Passes ownership.
  DeviceRefPtr device_ref(mock_devices_[0].get());
  EXPECT_CALL(*profile0, UpdateDevice(device_ref)).Times(0);
  EXPECT_CALL(*profile1, UpdateDevice(device_ref)).WillOnce(Return(true));
  EXPECT_CALL(*profile2, UpdateDevice(device_ref)).WillOnce(Return(false));
  manager()->UpdateDevice(mock_devices_[0]);
}

TEST_F(ManagerTest, EnumerateProfiles) {
  std::vector<RpcIdentifier> profile_paths;
  profile_paths.reserve(10);
  std::vector<scoped_refptr<MockProfile>> profiles;
  for (size_t i = 0; i < 10; i++) {
    profiles.push_back(new MockProfile(manager(), ""));
    RpcIdentifier rpcid(base::StringPrintf("/profile/%zd", i));
    profile_paths.push_back(rpcid);
    AdoptProfile(manager(), profiles.back());
    EXPECT_CALL(*profiles.back(), GetRpcIdentifier())
        .WillRepeatedly(ReturnRef(profile_paths[i]));
  }

  Error error;
  std::vector<RpcIdentifier> returned_paths =
      manager()->EnumerateProfiles(&error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(profile_paths.size(), returned_paths.size());
  for (size_t i = 0; i < profile_paths.size(); i++) {
    EXPECT_EQ(profile_paths[i], returned_paths[i]);
  }
}

TEST_F(ManagerTest, AutoConnectOnRegister) {
  MockServiceRefPtr service = MakeAutoConnectableService();
  EXPECT_CALL(*service, AutoConnect());
  manager()->RegisterService(service);
  dispatcher()->DispatchPendingEvents();
}

TEST_F(ManagerTest, AutoConnectOnUpdate) {
  MockServiceRefPtr service1 = MakeAutoConnectableService();
  service1->SetPriority(1, nullptr);
  MockServiceRefPtr service2 = MakeAutoConnectableService();
  service2->SetPriority(2, nullptr);
  manager()->RegisterService(service1);
  manager()->RegisterService(service2);
  dispatcher()->DispatchPendingEvents();

  EXPECT_CALL(*service1, AutoConnect());
  EXPECT_CALL(*service2, state())
      .WillRepeatedly(Return(Service::kStateFailure));
  EXPECT_CALL(*service2, IsFailed()).WillRepeatedly(Return(true));
  EXPECT_CALL(*service2, IsConnected(nullptr)).WillRepeatedly(Return(false));
  manager()->UpdateService(service2);
  dispatcher()->DispatchPendingEvents();
}

TEST_F(ManagerTest, AutoConnectOnDeregister) {
  MockServiceRefPtr service1 = MakeAutoConnectableService();
  service1->SetPriority(1, nullptr);
  MockServiceRefPtr service2 = MakeAutoConnectableService();
  service2->SetPriority(2, nullptr);
  manager()->RegisterService(service1);
  manager()->RegisterService(service2);
  dispatcher()->DispatchPendingEvents();

  EXPECT_CALL(*service1, AutoConnect());
  manager()->DeregisterService(service2);
  dispatcher()->DispatchPendingEvents();
}

TEST_F(ManagerTest, AutoConnectOnSuspending) {
  MockServiceRefPtr service = MakeAutoConnectableService();
  SetSuspending(true);
  SetPowerManager();
  EXPECT_CALL(*service, AutoConnect()).Times(0);
  manager()->RegisterService(service);
  dispatcher()->DispatchPendingEvents();
}

TEST_F(ManagerTest, AutoConnectOnNotSuspending) {
  MockServiceRefPtr service = MakeAutoConnectableService();
  SetSuspending(false);
  SetPowerManager();
  EXPECT_CALL(*service, AutoConnect());
  manager()->RegisterService(service);
  dispatcher()->DispatchPendingEvents();
}

TEST_F(ManagerTest, AutoConnectWhileNotRunning) {
  SetRunning(false);
  MockServiceRefPtr service = MakeAutoConnectableService();
  EXPECT_CALL(*service, AutoConnect()).Times(0);
  manager()->RegisterService(service);
  dispatcher()->DispatchPendingEvents();
}

TEST_F(ManagerTest, Suspend) {
  MockServiceRefPtr service = MakeAutoConnectableService();
  SetPowerManager();
  EXPECT_CALL(*service, AutoConnect());
  manager()->RegisterService(service);
  manager()->RegisterDevice(mock_devices_[0]);
  dispatcher()->DispatchPendingEvents();

  EXPECT_CALL(*mock_devices_[0], OnBeforeSuspend(_));
  EXPECT_CALL(*service, OnBeforeSuspend(_));
  OnSuspendImminent();
  EXPECT_CALL(*service, AutoConnect()).Times(0);
  dispatcher()->DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(mock_devices_[0].get());

  EXPECT_CALL(*mock_devices_[0], OnAfterResume());
  EXPECT_CALL(*service, OnAfterResume());
  OnSuspendDone();
  EXPECT_CALL(*service, AutoConnect());
  dispatcher()->DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(mock_devices_[0].get());
}

TEST_F(ManagerTest, AddTerminationAction) {
  EXPECT_TRUE(GetTerminationActions()->IsEmpty());
  manager()->AddTerminationAction("action1", base::Closure());
  EXPECT_FALSE(GetTerminationActions()->IsEmpty());
  manager()->AddTerminationAction("action2", base::Closure());
}

TEST_F(ManagerTest, RemoveTerminationAction) {
  const char kKey1[] = "action1";
  const char kKey2[] = "action2";

  // Removing an action when the hook table is empty.
  EXPECT_TRUE(GetTerminationActions()->IsEmpty());
  manager()->RemoveTerminationAction("unknown");

  // Fill hook table with two items.
  manager()->AddTerminationAction(kKey1, base::Closure());
  EXPECT_FALSE(GetTerminationActions()->IsEmpty());
  manager()->AddTerminationAction(kKey2, base::Closure());

  // Removing an action that ends up with a non-empty hook table.
  manager()->RemoveTerminationAction(kKey1);
  EXPECT_FALSE(GetTerminationActions()->IsEmpty());

  // Removing the last action.
  manager()->RemoveTerminationAction(kKey2);
  EXPECT_TRUE(GetTerminationActions()->IsEmpty());
}

TEST_F(ManagerTest, RunTerminationActions) {
  TerminationActionTest test_action;
  const std::string kActionName = "action";

  EXPECT_CALL(test_action, Done(_));
  manager()->RunTerminationActions(
      base::Bind(&TerminationActionTest::Done, test_action.AsWeakPtr()));

  manager()->AddTerminationAction(
      TerminationActionTest::kActionName,
      base::Bind(&TerminationActionTest::Action, test_action.AsWeakPtr()));
  test_action.set_manager(manager());
  EXPECT_CALL(test_action, Done(_));
  manager()->RunTerminationActions(
      base::Bind(&TerminationActionTest::Done, test_action.AsWeakPtr()));
}

TEST_F(ManagerTest, OnSuspendImminentDevicesPresent) {
  EXPECT_CALL(*mock_devices_[0], OnBeforeSuspend(_));
  EXPECT_CALL(*mock_devices_[1], OnBeforeSuspend(_));
  EXPECT_CALL(*mock_devices_[2], OnBeforeSuspend(_));
  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);
  SetPowerManager();
  OnSuspendImminent();
}

TEST_F(ManagerTest, OnSuspendImminentNoDevicesPresent) {
  EXPECT_CALL(*power_manager_, ReportSuspendReadiness());
  SetPowerManager();
  OnSuspendImminent();
}

TEST_F(ManagerTest, OnDarkSuspendImminentDevicesPresent) {
  EXPECT_CALL(*mock_devices_[0], OnDarkResume(_));
  EXPECT_CALL(*mock_devices_[1], OnDarkResume(_));
  EXPECT_CALL(*mock_devices_[2], OnDarkResume(_));
  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);
  SetPowerManager();
  OnDarkSuspendImminent();
}

TEST_F(ManagerTest, OnDarkSuspendImminentNoDevicesPresent) {
  EXPECT_CALL(*power_manager_, ReportDarkSuspendReadiness());
  SetPowerManager();
  OnDarkSuspendImminent();
}

TEST_F(ManagerTest, OnSuspendActionsComplete) {
  Error error;
  EXPECT_CALL(*power_manager_, ReportSuspendReadiness());
  SetPowerManager();
  OnSuspendActionsComplete(error);
}

TEST_F(ManagerTest, RecheckPortal) {
  EXPECT_CALL(*mock_devices_[0], RequestPortalDetection())
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_devices_[1], RequestPortalDetection())
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_devices_[2], RequestPortalDetection())
      .WillOnce(Return(true));

  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);

  manager()->RecheckPortal(nullptr);
}

TEST_F(ManagerTest, RecheckPortalOnService) {
  MockServiceRefPtr service = new NiceMock<MockService>(manager());
  EXPECT_CALL(*mock_devices_[0], IsConnectedToService(IsRefPtrTo(service)))
      .WillOnce(Return(false));
  EXPECT_CALL(*mock_devices_[1], IsConnectedToService(IsRefPtrTo(service)))
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_devices_[1], RestartPortalDetection())
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_devices_[2], IsConnectedToService(_)).Times(0);

  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);

  manager()->RecheckPortalOnService(service);
}

TEST_F(ManagerTest, GetDefaultService) {
  EXPECT_EQ(nullptr, manager()->GetDefaultService());
  EXPECT_EQ(DBusControl::NullRpcIdentifier(), GetDefaultServiceRpcIdentifier());

  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  manager()->RegisterService(mock_service);
  EXPECT_EQ(nullptr, manager()->GetDefaultService());
  EXPECT_EQ(DBusControl::NullRpcIdentifier(), GetDefaultServiceRpcIdentifier());

  NiceMock<MockConnection> mock_connection(device_info_.get());
  SelectServiceForDevice(mock_service, &mock_connection, mock_devices_[0]);
  EXPECT_EQ(mock_service, manager()->GetDefaultService());
  EXPECT_EQ(mock_service->GetRpcIdentifier(), GetDefaultServiceRpcIdentifier());

  SelectServiceForDevice(nullptr, nullptr, mock_devices_[0]);
  manager()->DeregisterService(mock_service);
}

TEST_F(ManagerTest, GetServiceWithGUID) {
  MockServiceRefPtr mock_service0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr mock_service1(new NiceMock<MockService>(manager()));

  EXPECT_CALL(*mock_service0, Configure(_, _)).Times(0);
  EXPECT_CALL(*mock_service1, Configure(_, _)).Times(0);

  manager()->RegisterService(mock_service0);
  manager()->RegisterService(mock_service1);

  const std::string kGUID0 = "GUID0";
  const std::string kGUID1 = "GUID1";

  {
    Error error;
    ServiceRefPtr service = manager()->GetServiceWithGUID(kGUID0, &error);
    EXPECT_FALSE(error.IsSuccess());
    EXPECT_FALSE(service);
  }

  KeyValueStore args;
  args.Set<std::string>(kGuidProperty, kGUID1);

  {
    Error error;
    ServiceRefPtr service = manager()->GetService(args, &error);
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_FALSE(service);
  }

  mock_service0->SetGuid(kGUID0, nullptr);
  mock_service1->SetGuid(kGUID1, nullptr);

  {
    Error error;
    ServiceRefPtr service = manager()->GetServiceWithGUID(kGUID0, &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(mock_service0, service);
  }

  {
    Error error;
    EXPECT_CALL(*mock_service1, Configure(_, &error)).Times(1);
    ServiceRefPtr service = manager()->GetService(args, &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(mock_service1, service);
  }

  manager()->DeregisterService(mock_service0);
  manager()->DeregisterService(mock_service1);
}

TEST_F(ManagerTest, CalculateStateOffline) {
  EXPECT_FALSE(manager()->IsConnected());
  EXPECT_EQ("offline", manager()->CalculateState(nullptr));

  MockServiceRefPtr mock_service0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr mock_service1(new NiceMock<MockService>(manager()));

  EXPECT_CALL(*mock_service0, IsConnected(nullptr))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mock_service1, IsConnected(nullptr))
      .WillRepeatedly(Return(false));

  manager()->RegisterService(mock_service0);
  manager()->RegisterService(mock_service1);

  EXPECT_FALSE(manager()->IsConnected());
  EXPECT_EQ("offline", manager()->CalculateState(nullptr));

  manager()->DeregisterService(mock_service0);
  manager()->DeregisterService(mock_service1);
}

TEST_F(ManagerTest, CalculateStateOnline) {
  MockServiceRefPtr mock_service0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr mock_service1(new NiceMock<MockService>(manager()));

  EXPECT_CALL(*mock_service0, IsConnected(nullptr))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mock_service1, IsConnected(nullptr))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_service0, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  EXPECT_CALL(*mock_service1, state())
      .WillRepeatedly(Return(Service::kStateConnected));

  manager()->RegisterService(mock_service0);
  manager()->RegisterService(mock_service1);
  CompleteServiceSort();

  EXPECT_TRUE(manager()->IsConnected());
  EXPECT_EQ("online", manager()->CalculateState(nullptr));

  manager()->DeregisterService(mock_service0);
  manager()->DeregisterService(mock_service1);
}

TEST_F(ManagerTest, RefreshConnectionState) {
  EXPECT_CALL(*manager_adaptor_,
              EmitStringChanged(kConnectionStateProperty, kStateIdle));
  EXPECT_CALL(*upstart_, NotifyDisconnected());
  EXPECT_CALL(*upstart_, NotifyConnected()).Times(0);
  RefreshConnectionState();
  Mock::VerifyAndClearExpectations(manager_adaptor_);
  Mock::VerifyAndClearExpectations(upstart_);

  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  EXPECT_CALL(*manager_adaptor_, EmitStringChanged(kConnectionStateProperty, _))
      .Times(0);
  EXPECT_CALL(*upstart_, NotifyDisconnected()).Times(0);
  EXPECT_CALL(*upstart_, NotifyConnected());
  manager()->RegisterService(mock_service);
  RefreshConnectionState();

  NiceMock<MockConnection> mock_connection(device_info_.get());
  SelectServiceForDevice(mock_service, &mock_connection, mock_devices_[0]);
  EXPECT_CALL(*mock_service, state()).WillOnce(Return(Service::kStateIdle));
  RefreshConnectionState();

  Mock::VerifyAndClearExpectations(manager_adaptor_);
  EXPECT_CALL(*mock_service, state())
      .WillOnce(Return(Service::kStateNoConnectivity));
  EXPECT_CALL(*mock_service, IsConnected(nullptr)).WillOnce(Return(true));
  EXPECT_CALL(*manager_adaptor_, EmitStringChanged(kConnectionStateProperty,
                                                   kStateNoConnectivity));
  RefreshConnectionState();
  Mock::VerifyAndClearExpectations(manager_adaptor_);
  Mock::VerifyAndClearExpectations(upstart_);

  SelectServiceForDevice(nullptr, nullptr, mock_devices_[0]);
  manager()->DeregisterService(mock_service);

  EXPECT_CALL(*manager_adaptor_,
              EmitStringChanged(kConnectionStateProperty, kStateIdle));
  EXPECT_CALL(*upstart_, NotifyDisconnected());
  EXPECT_CALL(*upstart_, NotifyConnected()).Times(0);
  RefreshConnectionState();
}

TEST_F(ManagerTest, StartupPortalList) {
  // Simulate loading value from the default profile.
  const std::string kProfileValue("wifi,vpn");
  manager()->props_.check_portal_list = kProfileValue;

  EXPECT_EQ(kProfileValue, manager()->GetCheckPortalList(nullptr));
  EXPECT_TRUE(manager()->IsPortalDetectionEnabled(Technology::kWiFi));
  EXPECT_FALSE(manager()->IsPortalDetectionEnabled(Technology::kCellular));

  const std::string kStartupValue("cellular,ethernet");
  manager()->SetStartupPortalList(kStartupValue);
  // Ensure profile value is not overwritten, so when we save the default
  // profile, the correct value will still be written.
  EXPECT_EQ(kProfileValue, manager()->props_.check_portal_list);

  // However we should read back a different list.
  EXPECT_EQ(kStartupValue, manager()->GetCheckPortalList(nullptr));
  EXPECT_FALSE(manager()->IsPortalDetectionEnabled(Technology::kWiFi));
  EXPECT_TRUE(manager()->IsPortalDetectionEnabled(Technology::kCellular));

  const std::string kRuntimeValue("ppp");
  // Setting a runtime value over the control API should overwrite both
  // the profile value and what we read back.
  Error error;
  manager()->mutable_store()->SetStringProperty(kCheckPortalListProperty,
                                                kRuntimeValue, &error);
  ASSERT_TRUE(error.IsSuccess());
  EXPECT_EQ(kRuntimeValue, manager()->GetCheckPortalList(nullptr));
  EXPECT_EQ(kRuntimeValue, manager()->props_.check_portal_list);
  EXPECT_FALSE(manager()->IsPortalDetectionEnabled(Technology::kCellular));
  EXPECT_TRUE(manager()->IsPortalDetectionEnabled(Technology::kPPP));
}

TEST_F(ManagerTest, IsTechnologyAutoConnectDisabled) {
  const std::string kNoAutoConnectTechnologies("wifi,cellular");
  manager()->props_.no_auto_connect_technologies = kNoAutoConnectTechnologies;
  EXPECT_TRUE(manager()->IsTechnologyAutoConnectDisabled(Technology::kWiFi));
  EXPECT_TRUE(
      manager()->IsTechnologyAutoConnectDisabled(Technology::kCellular));
  EXPECT_FALSE(
      manager()->IsTechnologyAutoConnectDisabled(Technology::kEthernet));
}

TEST_F(ManagerTest, SetEnabledStateForTechnologyPersistentCheck) {
  DisableTechnologyReplyHandler disable_technology_reply_handler;
  ResultCallback disable_technology_callback(
      base::Bind(&DisableTechnologyReplyHandler::ReportResult,
                 disable_technology_reply_handler.AsWeakPtr()));
  EXPECT_CALL(disable_technology_reply_handler, ReportResult(_)).Times(2);
  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  manager()->RegisterDevice(mock_devices_[0]);

  EXPECT_CALL(*mock_devices_[0], SetEnabledPersistent(false, _, _))
      .WillOnce(WithArg<1>(Invoke(SetErrorSuccess)));
  manager()->SetEnabledStateForTechnology(kTypeEthernet, false, true,
                                          disable_technology_callback);

  EXPECT_CALL(*mock_devices_[0], SetEnabledNonPersistent(false, _, _))
      .WillOnce(WithArg<1>(Invoke(SetErrorSuccess)));
  manager()->SetEnabledStateForTechnology(kTypeEthernet, false, false,
                                          disable_technology_callback);
}

TEST_F(ManagerTest, SetEnabledStateForTechnology) {
  DisableTechnologyReplyHandler disable_technology_reply_handler;
  ResultCallback disable_technology_callback(
      base::Bind(&DisableTechnologyReplyHandler::ReportResult,
                 disable_technology_reply_handler.AsWeakPtr()));

  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[1], technology())
      .WillByDefault(Return(Technology::kCellular));
  ON_CALL(*mock_devices_[2], technology())
      .WillByDefault(Return(Technology::kWiFi));
  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);

  auto setup_expectations =
      [](std::vector<scoped_refptr<MockDevice>>& mock_devices,
         Technology::Type type, bool enable, bool persistent) {
        for (int i = 0; i < 3; i++) {
          if (mock_devices[i]->technology() == type) {
            if (persistent) {
              EXPECT_CALL(*mock_devices[i], SetEnabledPersistent(enable, _, _))
                  .WillOnce(WithArg<1>(Invoke(SetErrorSuccess)));
              EXPECT_CALL(*mock_devices[i],
                          SetEnabledNonPersistent(enable, _, _))
                  .Times(0);
            } else {
              EXPECT_CALL(*mock_devices[i], SetEnabledPersistent(enable, _, _))
                  .Times(0);
              EXPECT_CALL(*mock_devices[i],
                          SetEnabledNonPersistent(enable, _, _))
                  .WillOnce(WithArg<1>(Invoke(SetErrorSuccess)));
            }
          } else {
            EXPECT_CALL(*mock_devices[i], SetEnabledPersistent(enable, _, _))
                .Times(0);
            EXPECT_CALL(*mock_devices[i], SetEnabledNonPersistent(enable, _, _))
                .Times(0);
          }
        }
      };
  auto clear_expectations =
      [](std::vector<scoped_refptr<MockDevice>>& mock_devices) {
        for (int i = 0; i < 3; i++) {
          Mock::VerifyAndClearExpectations(mock_devices[i].get());
        }
      };

  // We have to do this annoying stuff because use of WithParamsInterface is
  // precluded by ManagerTest being a subclass of PropertyStoreTest, which
  // is a TestWithParam.
  std::vector<bool> bool_vals = {true, false};
  std::vector<Technology::Type> techs = {
      Technology::kEthernet, Technology::kCellular, Technology::kWiFi};
  for (Technology::Type type : techs) {
    for (bool enable : bool_vals) {
      for (bool persistent : bool_vals) {
        EXPECT_CALL(disable_technology_reply_handler,
                    ReportResult(IsSuccess()));
        setup_expectations(mock_devices_, type, enable, persistent);
        manager()->SetEnabledStateForTechnology(Technology(type).GetName(),
                                                enable, persistent,
                                                disable_technology_callback);
        Mock::VerifyAndClearExpectations(&disable_technology_reply_handler);
        clear_expectations(mock_devices_);
      }
    }
  }
}

TEST_F(ManagerTest, SetEnabledStatePropagatesError) {
  DisableTechnologyReplyHandler disable_technology_reply_handler;
  ResultCallback disable_technology_callback(
      base::Bind(&DisableTechnologyReplyHandler::ReportResult,
                 disable_technology_reply_handler.AsWeakPtr()));
  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[1], technology())
      .WillByDefault(Return(Technology::kEthernet));
  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);

  EXPECT_CALL(*mock_devices_[0], SetEnabledNonPersistent(true, _, _))
      .WillOnce(WithArg<1>(Invoke(SetErrorSuccess)));
  EXPECT_CALL(*mock_devices_[1], SetEnabledNonPersistent(true, _, _))
      .WillOnce(WithArg<1>(Invoke(SetErrorPermissionDenied)));

  EXPECT_CALL(disable_technology_reply_handler, ReportResult(IsFailure()));
  manager()->SetEnabledStateForTechnology(kTypeEthernet, true, false,
                                          disable_technology_callback);
}

TEST_F(ManagerTest, IgnoredSearchList) {
  std::vector<std::string> ignored_paths;

  const std::string kIgnored0 = "chromium.org";
  ignored_paths.push_back(kIgnored0);
  EXPECT_CALL(resolver_, set_ignored_search_list(ignored_paths));
  SetIgnoredDNSSearchPaths(kIgnored0, nullptr);
  EXPECT_EQ(kIgnored0, GetIgnoredDNSSearchPaths());

  const std::string kIgnored1 = "google.com";
  const std::string kIgnoredSum = kIgnored0 + "," + kIgnored1;
  ignored_paths.push_back(kIgnored1);
  EXPECT_CALL(resolver_, set_ignored_search_list(ignored_paths));
  SetIgnoredDNSSearchPaths(kIgnoredSum, nullptr);
  EXPECT_EQ(kIgnoredSum, GetIgnoredDNSSearchPaths());

  ignored_paths.clear();
  EXPECT_CALL(resolver_, set_ignored_search_list(ignored_paths));
  SetIgnoredDNSSearchPaths("", nullptr);
  EXPECT_EQ("", GetIgnoredDNSSearchPaths());
}

TEST_F(ManagerTest, PortalFallbackUrls) {
  const std::string kFallback0 = "http://fallback";
  const std::vector<std::string> kFallbackVec0 = {kFallback0};
  SetPortalFallbackUrlsString(kFallback0, nullptr);
  EXPECT_EQ(kFallbackVec0, GetPortalFallbackUrlsString());

  const std::string kFallback1 = "http://other";
  const std::string kFallbackSum = kFallback0 + "," + kFallback1;
  const std::vector<std::string> kFallbackVec1 = {kFallback0, kFallback1};
  SetPortalFallbackUrlsString(kFallbackSum, nullptr);
  EXPECT_EQ(kFallbackVec1, GetPortalFallbackUrlsString());

  SetPortalFallbackUrlsString("", nullptr);
  EXPECT_EQ(kFallbackVec1, GetPortalFallbackUrlsString());
}

TEST_F(ManagerTest, ServiceStateChangeEmitsServices) {
  // Test to make sure that every service state-change causes the
  // Manager to emit a new service list.
  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  EXPECT_CALL(*mock_service, state())
      .WillRepeatedly(Return(Service::kStateIdle));

  manager()->RegisterService(mock_service);
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierArrayChanged(kServiceCompleteListProperty, _))
      .Times(1);
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierArrayChanged(kServicesProperty, _))
      .Times(1);
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierArrayChanged(kServiceWatchListProperty, _))
      .Times(1);
  CompleteServiceSort();

  Mock::VerifyAndClearExpectations(manager_adaptor_);
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierArrayChanged(kServiceCompleteListProperty, _))
      .Times(1);
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierArrayChanged(kServicesProperty, _))
      .Times(1);
  EXPECT_CALL(*manager_adaptor_,
              EmitRpcIdentifierArrayChanged(kServiceWatchListProperty, _))
      .Times(1);
  manager()->UpdateService(mock_service.get());
  CompleteServiceSort();

  manager()->DeregisterService(mock_service);
}

TEST_F(ManagerTest, EnumerateServices) {
  MockServiceRefPtr mock_service(new NiceMock<MockService>(manager()));
  manager()->RegisterService(mock_service);

  EXPECT_CALL(*mock_service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*mock_service, IsVisible()).WillRepeatedly(Return(false));
  EXPECT_TRUE(EnumerateAvailableServices().empty());
  EXPECT_TRUE(EnumerateWatchedServices().empty());

  EXPECT_CALL(*mock_service, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  EXPECT_TRUE(EnumerateAvailableServices().empty());
  EXPECT_TRUE(EnumerateWatchedServices().empty());

  EXPECT_CALL(*mock_service, IsVisible()).WillRepeatedly(Return(true));
  static const Service::ConnectState kUnwatchedStates[] = {
      Service::kStateUnknown, Service::kStateIdle, Service::kStateFailure};
  for (auto unwatched_state : kUnwatchedStates) {
    EXPECT_CALL(*mock_service, state()).WillRepeatedly(Return(unwatched_state));
    EXPECT_FALSE(EnumerateAvailableServices().empty());
    EXPECT_TRUE(EnumerateWatchedServices().empty());
  }

  static const Service::ConnectState kWatchedStates[] = {
      Service::kStateAssociating,   Service::kStateConfiguring,
      Service::kStateConnected,     Service::kStateNoConnectivity,
      Service::kStateRedirectFound, Service::kStateOnline};
  for (auto watched_state : kWatchedStates) {
    EXPECT_CALL(*mock_service, state()).WillRepeatedly(Return(watched_state));
    EXPECT_FALSE(EnumerateAvailableServices().empty());
    EXPECT_FALSE(EnumerateWatchedServices().empty());
  }

  manager()->DeregisterService(mock_service);
}

TEST_F(ManagerTest, ConnectToBestServices) {
  MockServiceRefPtr wifi_service0(new NiceMock<MockService>(manager()));
  EXPECT_CALL(*wifi_service0, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  EXPECT_CALL(*wifi_service0, IsConnected(nullptr))
      .WillRepeatedly(Return(false));
  wifi_service0->SetConnectable(true);
  wifi_service0->SetAutoConnect(true);
  wifi_service0->SetSecurity(Service::kCryptoAes, true, true);
  EXPECT_CALL(*wifi_service0, technology())
      .WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(*wifi_service0, IsVisible()).WillRepeatedly(Return(false));
  EXPECT_CALL(*wifi_service0, explicitly_disconnected())
      .WillRepeatedly(Return(false));

  MockServiceRefPtr wifi_service1(new NiceMock<MockService>(manager()));
  EXPECT_CALL(*wifi_service1, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  EXPECT_CALL(*wifi_service1, IsVisible()).WillRepeatedly(Return(true));
  EXPECT_CALL(*wifi_service1, IsConnected(nullptr))
      .WillRepeatedly(Return(false));
  wifi_service1->SetAutoConnect(true);
  wifi_service1->SetConnectable(true);
  wifi_service1->SetSecurity(Service::kCryptoRc4, true, true);
  EXPECT_CALL(*wifi_service1, technology())
      .WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(*wifi_service1, explicitly_disconnected())
      .WillRepeatedly(Return(false));

  MockServiceRefPtr wifi_service2(new NiceMock<MockService>(manager()));
  EXPECT_CALL(*wifi_service2, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*wifi_service2, IsConnected(nullptr))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*wifi_service2, IsVisible()).WillRepeatedly(Return(true));
  wifi_service2->SetAutoConnect(true);
  wifi_service2->SetConnectable(true);
  wifi_service2->SetSecurity(Service::kCryptoNone, false, false);
  EXPECT_CALL(*wifi_service2, technology())
      .WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(*wifi_service2, explicitly_disconnected())
      .WillRepeatedly(Return(false));

  manager()->RegisterService(wifi_service0);
  manager()->RegisterService(wifi_service1);
  manager()->RegisterService(wifi_service2);

  CompleteServiceSort();
  EXPECT_TRUE(ServiceOrderIs(wifi_service2, wifi_service0));

  MockServiceRefPtr cellular_service0(new NiceMock<MockService>(manager()));
  EXPECT_CALL(*cellular_service0, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  EXPECT_CALL(*cellular_service0, IsConnected(nullptr))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*cellular_service0, IsVisible()).WillRepeatedly(Return(true));
  cellular_service0->SetAutoConnect(true);
  cellular_service0->SetConnectable(true);
  EXPECT_CALL(*cellular_service0, technology())
      .WillRepeatedly(Return(Technology::kCellular));
  EXPECT_CALL(*cellular_service0, explicitly_disconnected())
      .WillRepeatedly(Return(true));
  manager()->RegisterService(cellular_service0);

  MockServiceRefPtr cellular_service1(new NiceMock<MockService>(manager()));
  EXPECT_CALL(*cellular_service1, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*cellular_service1, IsConnected(nullptr))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*cellular_service1, IsVisible()).WillRepeatedly(Return(true));
  cellular_service1->SetAutoConnect(true);
  cellular_service1->SetConnectable(true);
  EXPECT_CALL(*cellular_service1, technology())
      .WillRepeatedly(Return(Technology::kCellular));
  EXPECT_CALL(*cellular_service1, explicitly_disconnected())
      .WillRepeatedly(Return(false));
  manager()->RegisterService(cellular_service1);

  MockServiceRefPtr vpn_service(new NiceMock<MockService>(manager()));
  EXPECT_CALL(*vpn_service, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  EXPECT_CALL(*vpn_service, IsConnected(nullptr)).WillRepeatedly(Return(false));
  EXPECT_CALL(*vpn_service, IsVisible()).WillRepeatedly(Return(true));
  vpn_service->SetAutoConnect(false);
  vpn_service->SetConnectable(true);
  EXPECT_CALL(*vpn_service, technology())
      .WillRepeatedly(Return(Technology::kVPN));
  manager()->RegisterService(vpn_service);

  // The connected services should be at the top.
  EXPECT_TRUE(ServiceOrderIs(wifi_service2, cellular_service1));

  EXPECT_CALL(*wifi_service0, Connect(_, _)).Times(0);  // Not visible.
  EXPECT_CALL(*wifi_service1, Connect(_, _));
  EXPECT_CALL(*wifi_service2, Connect(_, _)).Times(0);  // Lower prio.
  EXPECT_CALL(*cellular_service0, Connect(_, _))
      .Times(0);  // Explicitly disconnected.
  EXPECT_CALL(*cellular_service1, Connect(_, _)).Times(0);  // Is connected.
  EXPECT_CALL(*vpn_service, Connect(_, _)).Times(0);        // Not autoconnect.

  manager()->ConnectToBestServices(nullptr);
  dispatcher()->DispatchPendingEvents();

  // After this operation, since the Connect calls above are mocked and
  // no actual state changes have occurred, we should expect that the
  // service sorting order will not have changed.
  EXPECT_TRUE(ServiceOrderIs(wifi_service2, cellular_service1));
}

TEST_F(ManagerTest, CreateConnectivityReport) {
  // Add devices
  // WiFi
  auto wifi_device =
      base::MakeRefCounted<NiceMock<MockDevice>>(manager(), "null", "addr", 0);
  manager()->RegisterDevice(wifi_device);
  // Cell
  auto cell_device =
      base::MakeRefCounted<NiceMock<MockDevice>>(manager(), "null", "addr", 1);
  manager()->RegisterDevice(cell_device);
  // Ethernet
  auto eth_device =
      base::MakeRefCounted<NiceMock<MockDevice>>(manager(), "null", "addr", 3);
  manager()->RegisterDevice(eth_device);
  // VPN Device -- base device for a service that will not be connected
  auto vpn_device =
      base::MakeRefCounted<NiceMock<MockDevice>>(manager(), "null", "addr", 4);
  manager()->RegisterDevice(vpn_device);

  // Add service for multiple devices
  // WiFi
  MockServiceRefPtr wifi_service = new NiceMock<MockService>(manager());
  manager()->RegisterService(wifi_service);
  EXPECT_CALL(*wifi_service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*wifi_service, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*wifi_device, IsConnectedToService(_))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*wifi_device, IsConnectedToService(IsRefPtrTo(wifi_service)))
      .WillRepeatedly(Return(true));

  // Cell
  MockServiceRefPtr cell_service = new NiceMock<MockService>(manager());
  manager()->RegisterService(cell_service);
  EXPECT_CALL(*cell_service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*cell_service, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*cell_device, IsConnectedToService(_))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*cell_device, IsConnectedToService(IsRefPtrTo(cell_service)))
      .WillRepeatedly(Return(true));

  // Ethernet
  MockServiceRefPtr eth_service = new NiceMock<MockService>(manager());
  manager()->RegisterService(eth_service);
  EXPECT_CALL(*eth_service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*eth_service, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*eth_device, IsConnectedToService(_))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*eth_device, IsConnectedToService(IsRefPtrTo(eth_service)))
      .WillRepeatedly(Return(true));

  // VPN: Service exists but is not connected and will not trigger a
  // connectivity report.
  MockServiceRefPtr vpn_service = new NiceMock<MockService>(manager());
  manager()->RegisterService(vpn_service);
  EXPECT_CALL(*vpn_service, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  EXPECT_CALL(*vpn_service, IsConnected(nullptr)).WillRepeatedly(Return(false));

  EXPECT_CALL(*wifi_device, StartConnectivityTest()).WillOnce(Return(true));
  EXPECT_CALL(*cell_device, StartConnectivityTest()).WillOnce(Return(true));
  EXPECT_CALL(*eth_device, StartConnectivityTest()).WillOnce(Return(true));
  EXPECT_CALL(*vpn_device, StartConnectivityTest()).Times(0);
  manager()->CreateConnectivityReport(nullptr);
  dispatcher()->DispatchPendingEvents();
}

TEST_F(ManagerTest, IsProfileBefore) {
  scoped_refptr<MockProfile> profile0(new NiceMock<MockProfile>(manager(), ""));
  scoped_refptr<MockProfile> profile1(new NiceMock<MockProfile>(manager(), ""));

  AdoptProfile(manager(), profile0);
  AdoptProfile(manager(), profile1);  // profile1 is after profile0.
  EXPECT_TRUE(manager()->IsProfileBefore(profile0, profile1));
  EXPECT_FALSE(manager()->IsProfileBefore(profile1, profile0));

  // A few abnormal cases, but it's good to track their behavior.
  scoped_refptr<MockProfile> profile2(new NiceMock<MockProfile>(manager(), ""));
  EXPECT_TRUE(manager()->IsProfileBefore(profile0, profile2));
  EXPECT_TRUE(manager()->IsProfileBefore(profile1, profile2));
  EXPECT_FALSE(manager()->IsProfileBefore(profile2, profile0));
  EXPECT_FALSE(manager()->IsProfileBefore(profile2, profile1));
}

TEST_F(ManagerTest, GetLoadableProfileEntriesForService) {
  FakeStore storage0;
  FakeStore storage1;
  FakeStore storage2;

  scoped_refptr<MockProfile> profile0(new NiceMock<MockProfile>(manager(), ""));
  scoped_refptr<MockProfile> profile1(new NiceMock<MockProfile>(manager(), ""));
  scoped_refptr<MockProfile> profile2(new NiceMock<MockProfile>(manager(), ""));

  AdoptProfile(manager(), profile0);
  AdoptProfile(manager(), profile1);
  AdoptProfile(manager(), profile2);

  MockServiceRefPtr service(new NiceMock<MockService>(manager()));

  EXPECT_CALL(*profile0, GetConstStorage()).WillOnce(Return(&storage0));
  EXPECT_CALL(*profile1, GetConstStorage()).WillOnce(Return(&storage1));
  EXPECT_CALL(*profile2, GetConstStorage()).WillOnce(Return(&storage2));

  const std::string kEntry0("aluminum_crutch");
  const std::string kEntry2("rehashed_faces");

  EXPECT_CALL(*service, GetLoadableStorageIdentifier(Ref(storage0)))
      .WillOnce(Return(kEntry0));
  EXPECT_CALL(*service, GetLoadableStorageIdentifier(Ref(storage1)))
      .WillOnce(Return(""));
  EXPECT_CALL(*service, GetLoadableStorageIdentifier(Ref(storage2)))
      .WillOnce(Return(kEntry2));

  const RpcIdentifier kProfileRpc0("service_station");
  const RpcIdentifier kProfileRpc2("crystal_tiaras");

  EXPECT_CALL(*profile0, GetRpcIdentifier()).WillOnce(ReturnRef(kProfileRpc0));
  EXPECT_CALL(*profile1, GetRpcIdentifier()).Times(0);
  EXPECT_CALL(*profile2, GetRpcIdentifier()).WillOnce(ReturnRef(kProfileRpc2));

  std::map<RpcIdentifier, std::string> entries =
      manager()->GetLoadableProfileEntriesForService(service);
  EXPECT_EQ(2, entries.size());
  EXPECT_TRUE(base::Contains(entries, kProfileRpc0));
  EXPECT_TRUE(base::Contains(entries, kProfileRpc2));
  EXPECT_EQ(kEntry0, entries[kProfileRpc0]);
  EXPECT_EQ(kEntry2, entries[kProfileRpc2]);
}

#if !defined(DISABLE_WIFI)
TEST_F(ManagerTest, InitializeProfilesInformsProviders) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  Manager manager(control_interface(), dispatcher(), metrics(), run_path(),
                  storage_path(), temp_dir.GetPath().value());
  // Can't use |wifi_provider_|, because it's owned by the Manager
  // object in the fixture.
  MockWiFiProvider* wifi_provider = new NiceMock<MockWiFiProvider>();
  manager.wifi_provider_.reset(wifi_provider);  // pass ownership
  manager.UpdateProviderMapping();
  // Give manager a valid place to write the user profile list.
  manager.user_profile_list_path_ =
      temp_dir.GetPath().Append("user_profile_list");

  // With no user profiles, the WiFiProvider should be called once
  // (for the default profile).
  EXPECT_CALL(*wifi_provider, CreateServicesFromProfile(_));
  manager.InitializeProfiles();
  Mock::VerifyAndClearExpectations(wifi_provider);

  // With |n| user profiles, the WiFiProvider should be called |n+1|
  // times. First, create 2 user profiles...
  const char kProfile0[] = "~user/profile0";
  const char kProfile1[] = "~user/profile1";
  std::string profile_rpc_path;
  Error error;
  ASSERT_TRUE(base::CreateDirectory(temp_dir.GetPath().Append("user")));
  manager.CreateProfile(kProfile0, &profile_rpc_path, &error);
  manager.PushProfile(kProfile0, &profile_rpc_path, &error);
  manager.CreateProfile(kProfile1, &profile_rpc_path, &error);
  manager.PushProfile(kProfile1, &profile_rpc_path, &error);

  // ... then reset manager state ...
  manager.profiles_.clear();

  // ...then check that the WiFiProvider is notified about all three
  // profiles (one default, two user).
  EXPECT_CALL(*wifi_provider, CreateServicesFromProfile(_)).Times(3);
  manager.InitializeProfiles();
  Mock::VerifyAndClearExpectations(wifi_provider);
}
#endif  // DISABLE_WIFI

TEST_F(ManagerTest, InitializeProfilesHandlesDefaults) {
  base::ScopedTempDir temp_dir;
  std::unique_ptr<Manager> manager;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  // Instantiate a Manager with empty persistent storage. Check that
  // defaults are set.
  //
  // Note that we use the same directory for default and user profiles.
  // This doesn't affect the test results, because we don't push a
  // user profile.
  manager.reset(new Manager(control_interface(), dispatcher(), metrics(),
                            run_path(), temp_dir.GetPath().value(),
                            temp_dir.GetPath().value()));
  manager->InitializeProfiles();
  EXPECT_EQ(PortalDetector::kDefaultCheckPortalList,
            manager->props_.check_portal_list);
  EXPECT_EQ(Resolver::kDefaultIgnoredSearchList,
            manager->props_.ignored_dns_search_paths);
  EXPECT_EQ(PortalDetector::kDefaultHttpUrl, manager->props_.portal_http_url);
  EXPECT_EQ(PortalDetector::kDefaultHttpsUrl, manager->props_.portal_https_url);
  EXPECT_EQ(
      std::vector<std::string>(PortalDetector::kDefaultFallbackHttpUrls.begin(),
                               PortalDetector::kDefaultFallbackHttpUrls.end()),
      manager->props_.portal_fallback_http_urls);

  // Change one of the settings.
  static const std::string kCustomCheckPortalList = "fiber0";
  Error error;
  manager->SetCheckPortalList(kCustomCheckPortalList, &error);
  manager->profiles_[0]->Save();

  // Instantiate a new manager. It should have our settings for
  // check_portal_list, rather than the default.
  manager.reset(new Manager(control_interface(), dispatcher(), metrics(),
                            run_path(), temp_dir.GetPath().value(),
                            temp_dir.GetPath().value()));
  manager->InitializeProfiles();
  EXPECT_EQ(kCustomCheckPortalList, manager->props_.check_portal_list);

  // If we clear the persistent storage, we again get the default value.
  ASSERT_TRUE(temp_dir.Delete());
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  manager.reset(new Manager(control_interface(), dispatcher(), metrics(),
                            run_path(), temp_dir.GetPath().value(),
                            temp_dir.GetPath().value()));
  manager->InitializeProfiles();
  EXPECT_EQ(PortalDetector::kDefaultCheckPortalList,
            manager->props_.check_portal_list);
}

TEST_F(ManagerTest, ProfileStackChangeLogging) {
  base::ScopedTempDir temp_dir;
  std::unique_ptr<Manager> manager;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  manager.reset(new Manager(control_interface(), dispatcher(), metrics(),
                            run_path(), temp_dir.GetPath().value(),
                            temp_dir.GetPath().value()));

  ScopedMockLog log;
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr("1 profile(s)")));
  manager->InitializeProfiles();

  const char kProfile0[] = "~user/profile0";
  const char kProfile1[] = "~user/profile1";
  const char kProfile2[] = "~user/profile2";
  ASSERT_TRUE(base::CreateDirectory(temp_dir.GetPath().Append("user")));
  TestCreateProfile(manager.get(), kProfile0);
  TestCreateProfile(manager.get(), kProfile1);
  TestCreateProfile(manager.get(), kProfile2);

  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr("2 profile(s)")));
  TestPushProfile(manager.get(), kProfile0);

  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr("3 profile(s)")));
  TestInsertUserProfile(manager.get(), kProfile1, "not-so-random-string");

  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr("4 profile(s)")));
  TestInsertUserProfile(manager.get(), kProfile2, "very-random-string");

  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr("3 profile(s)")));
  TestPopProfile(manager.get(), kProfile2);

  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr("2 profile(s)")));
  TestPopAnyProfile(manager.get());

  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, HasSubstr("1 profile(s)")));
  TestPopAllUserProfiles(manager.get());
}

// Custom property setters should return false, and make no changes, if
// the new value is the same as the old value.
TEST_F(ManagerTest, CustomSetterNoopChange) {
  // SetCheckPortalList
  {
    static const std::string kCheckPortalList = "weird-device,weirder-device";
    Error error;
    // Set to known value.
    EXPECT_TRUE(SetCheckPortalList(kCheckPortalList, &error));
    EXPECT_TRUE(error.IsSuccess());
    // Set to same value.
    EXPECT_FALSE(SetCheckPortalList(kCheckPortalList, &error));
    EXPECT_TRUE(error.IsSuccess());
  }

  // SetIgnoredDNSSearchPaths
  {
    static const std::string kIgnoredPaths = "example.com,example.org";
    Error error;
    // Set to known value.
    EXPECT_CALL(resolver_, set_ignored_search_list(_));
    EXPECT_TRUE(SetIgnoredDNSSearchPaths(kIgnoredPaths, &error));
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(&resolver_);
    // Set to same value.
    EXPECT_CALL(resolver_, set_ignored_search_list(_)).Times(0);
    EXPECT_FALSE(SetIgnoredDNSSearchPaths(kIgnoredPaths, &error));
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(&resolver_);
  }
}

TEST_F(ManagerTest, GeoLocation) {
  EXPECT_TRUE(manager()->GetNetworksForGeolocation().empty());

  auto device = base::MakeRefCounted<NiceMock<MockDevice>>(manager(), "device",
                                                           "addr_1", 0);

  // Manager should ignore gelocation info from technologies it does not know.
  EXPECT_CALL(*device, technology())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(Technology::kEthernet));
  manager()->OnDeviceGeolocationInfoUpdated(device);
  EXPECT_TRUE(manager()->GetNetworksForGeolocation().empty());
  Mock::VerifyAndClearExpectations(device.get());

  // Manager should add WiFi geolocation info.
  EXPECT_CALL(*device, technology())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(*device, GetGeolocationObjects())
      .WillOnce(Return(std::vector<GeolocationInfo>()));
  manager()->OnDeviceGeolocationInfoUpdated(device);
  auto location_infos = manager()->GetNetworksForGeolocation();
  EXPECT_EQ(1, location_infos.size());
  EXPECT_TRUE(base::Contains(location_infos, kGeoWifiAccessPointsProperty));

  auto cellular_device = base::MakeRefCounted<NiceMock<MockDevice>>(
      manager(), "modem", "addr_2", 1);

  // Manager should inclusively add cellular info.
  EXPECT_CALL(*cellular_device, technology())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(Technology::kCellular));
  EXPECT_CALL(*cellular_device, GetGeolocationObjects())
      .WillOnce(Return(std::vector<GeolocationInfo>()));
  manager()->OnDeviceGeolocationInfoUpdated(cellular_device);
  location_infos = manager()->GetNetworksForGeolocation();
  EXPECT_EQ(2, location_infos.size());
  EXPECT_TRUE(base::Contains(location_infos, kGeoWifiAccessPointsProperty));
  EXPECT_TRUE(base::Contains(location_infos, kGeoCellTowersProperty));
}

TEST_F(ManagerTest, GeoLocation_MultipleDevicesOneTechnology) {
  EXPECT_TRUE(manager()->GetNetworksForGeolocation().empty());

  auto device_1 = base::MakeRefCounted<NiceMock<MockDevice>>(
      manager(), "device_1", "addr_1", 0);
  GeolocationInfo info_1;
  info_1["location"] = "abc";

  auto device_2 = base::MakeRefCounted<NiceMock<MockDevice>>(
      manager(), "device_2", "addr_2", 1);
  GeolocationInfo info_2;
  info_2["location"] = "def";

  // Make both devices WiFi technology and have geolocation info.
  EXPECT_CALL(*device_1, technology())
      .WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(*device_1, GetGeolocationObjects())
      .WillOnce(Return(std::vector<GeolocationInfo>{info_1}));
  manager()->OnDeviceGeolocationInfoUpdated(device_1);

  EXPECT_CALL(*device_2, technology())
      .WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(*device_2, GetGeolocationObjects())
      .WillOnce(Return(std::vector<GeolocationInfo>{info_2}));
  manager()->OnDeviceGeolocationInfoUpdated(device_2);

  auto location_infos = manager()->GetNetworksForGeolocation();
  EXPECT_EQ(1, location_infos.size());
  EXPECT_TRUE(base::Contains(location_infos, kGeoWifiAccessPointsProperty));

  // Check that both entries are in the list.
  EXPECT_EQ(2, location_infos[kGeoWifiAccessPointsProperty].size());
}

TEST_F(ManagerTest, GeoLocation_DeregisterDevice) {
  EXPECT_TRUE(manager()->GetNetworksForGeolocation().empty());

  auto device = base::MakeRefCounted<NiceMock<MockDevice>>(manager(), "device",
                                                           "addr_1", 0);
  manager()->RegisterDevice(device);

  EXPECT_CALL(*device, technology()).WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(*device, GetGeolocationObjects())
      .WillOnce(Return(std::vector<GeolocationInfo>()));
  manager()->OnDeviceGeolocationInfoUpdated(device);

  auto location_infos = manager()->GetNetworksForGeolocation();
  EXPECT_EQ(1, location_infos.size());
  EXPECT_TRUE(base::Contains(location_infos, kGeoWifiAccessPointsProperty));

  // When we deregister, the entries should go away.
  manager()->DeregisterDevice(device);
  location_infos = manager()->GetNetworksForGeolocation();
  EXPECT_EQ(0, location_infos.size());
}

TEST_F(ManagerTest, IsWifiIdle) {
  // No registered service.
  EXPECT_FALSE(manager()->IsWifiIdle());

  MockServiceRefPtr wifi_service(new MockService(manager()));
  MockServiceRefPtr cell_service(new MockService(manager()));

  manager()->RegisterService(wifi_service);
  manager()->RegisterService(cell_service);

  EXPECT_CALL(*wifi_service, technology())
      .WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(*cell_service, technology())
      .WillRepeatedly(Return(Technology::kCellular));

  // Cellular is connected.
  EXPECT_CALL(*cell_service, IsConnected(nullptr)).WillRepeatedly(Return(true));
  manager()->UpdateService(cell_service);

  // No wifi connection attempt.
  EXPECT_CALL(*wifi_service, IsConnecting()).WillRepeatedly(Return(false));
  EXPECT_CALL(*wifi_service, IsConnected(nullptr))
      .WillRepeatedly(Return(false));
  manager()->UpdateService(wifi_service);
  EXPECT_TRUE(manager()->IsWifiIdle());

  // Attempt wifi connection.
  Mock::VerifyAndClearExpectations(wifi_service.get());
  EXPECT_CALL(*wifi_service, technology())
      .WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(*wifi_service, IsConnecting()).WillRepeatedly(Return(true));
  EXPECT_CALL(*wifi_service, IsConnected(nullptr))
      .WillRepeatedly(Return(false));
  manager()->UpdateService(wifi_service);
  EXPECT_FALSE(manager()->IsWifiIdle());

  // wifi connected.
  Mock::VerifyAndClearExpectations(wifi_service.get());
  EXPECT_CALL(*wifi_service, technology())
      .WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(*wifi_service, IsConnecting()).WillRepeatedly(Return(false));
  EXPECT_CALL(*wifi_service, IsConnected(nullptr)).WillRepeatedly(Return(true));
  manager()->UpdateService(wifi_service);
  EXPECT_FALSE(manager()->IsWifiIdle());
}

TEST_F(ManagerTest, DetectMultiHomedDevices) {
  std::vector<std::unique_ptr<MockConnection>> mock_connections;
  std::vector<Connection*> device_connections;
  mock_devices_.push_back(
      new NiceMock<MockDevice>(manager(), "null4", "addr4", 0));
  mock_devices_.push_back(
      new NiceMock<MockDevice>(manager(), "null5", "addr5", 0));
  for (const auto& device : mock_devices_) {
    manager()->RegisterDevice(device);
    mock_connections.emplace_back(
        new NiceMock<MockConnection>(device_info_.get()));
    device_connections.emplace_back(mock_connections.back().get());
  }
  EXPECT_CALL(*mock_connections[1], GetSubnetName()).WillOnce(Return("1"));
  EXPECT_CALL(*mock_connections[2], GetSubnetName()).WillOnce(Return("2"));
  EXPECT_CALL(*mock_connections[3], GetSubnetName()).WillOnce(Return("1"));
  EXPECT_CALL(*mock_connections[4], GetSubnetName()).WillOnce(Return(""));
  EXPECT_CALL(*mock_connections[5], GetSubnetName()).WillOnce(Return(""));

  // Do not assign a connection to mock_devices_[0].
  EXPECT_CALL(*mock_devices_[1], connection())
      .WillRepeatedly(Return(mock_connections[1].get()));
  EXPECT_CALL(*mock_devices_[2], connection())
      .WillRepeatedly(Return(mock_connections[2].get()));
  EXPECT_CALL(*mock_devices_[3], connection())
      .WillRepeatedly(Return(mock_connections[3].get()));
  EXPECT_CALL(*mock_devices_[4], connection())
      .WillRepeatedly(Return(mock_connections[4].get()));
  EXPECT_CALL(*mock_devices_[5], connection())
      .WillRepeatedly(Return(mock_connections[5].get()));

  EXPECT_CALL(*mock_devices_[0], SetIsMultiHomed(false));
  EXPECT_CALL(*mock_devices_[1], SetIsMultiHomed(true));
  EXPECT_CALL(*mock_devices_[2], SetIsMultiHomed(false));
  EXPECT_CALL(*mock_devices_[3], SetIsMultiHomed(true));
  EXPECT_CALL(*mock_devices_[4], SetIsMultiHomed(false));
  EXPECT_CALL(*mock_devices_[5], SetIsMultiHomed(false));
  manager()->DetectMultiHomedDevices();
}

TEST_F(ManagerTest, IsTechnologyProhibited) {
  // Test initial state.
  EXPECT_EQ("", manager()->props_.prohibited_technologies);
  EXPECT_FALSE(manager()->IsTechnologyProhibited(Technology::kCellular));
  EXPECT_FALSE(manager()->IsTechnologyProhibited(Technology::kEthernet));

  Error smoke_error;
  EXPECT_FALSE(
      manager()->SetProhibitedTechnologies("smoke_signal", &smoke_error));
  EXPECT_EQ(Error::kInvalidArguments, smoke_error.type());

  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[1], technology())
      .WillByDefault(Return(Technology::kCellular));
  ON_CALL(*mock_devices_[2], technology())
      .WillByDefault(Return(Technology::kWiFi));

  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);

  // Registered devices of prohibited technology types should be disabled.
  EXPECT_CALL(*mock_devices_[0], SetEnabledNonPersistent(false, _, _));
  EXPECT_CALL(*mock_devices_[1], SetEnabledNonPersistent(false, _, _));
  EXPECT_CALL(*mock_devices_[2], SetEnabledNonPersistent(false, _, _)).Times(0);
  Error error;
  manager()->SetProhibitedTechnologies("cellular,ethernet", &error);
  EXPECT_TRUE(manager()->IsTechnologyProhibited(Technology::kEthernet));
  EXPECT_TRUE(manager()->IsTechnologyProhibited(Technology::kCellular));
  EXPECT_FALSE(manager()->IsTechnologyProhibited(Technology::kWiFi));
  Mock::VerifyAndClearExpectations(mock_devices_[0].get());
  Mock::VerifyAndClearExpectations(mock_devices_[1].get());
  Mock::VerifyAndClearExpectations(mock_devices_[2].get());

  // Newly registered devices should be disabled.
  mock_devices_.push_back(
      new NiceMock<MockDevice>(manager(), "null4", "addr4", 0));
  mock_devices_.push_back(
      new NiceMock<MockDevice>(manager(), "null5", "addr5", 0));
  ON_CALL(*mock_devices_[3], technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*mock_devices_[4], technology())
      .WillByDefault(Return(Technology::kCellular));
  ON_CALL(*mock_devices_[5], technology())
      .WillByDefault(Return(Technology::kWiFi));

  EXPECT_CALL(*mock_devices_[3], SetEnabledNonPersistent(false, _, _));
  EXPECT_CALL(*mock_devices_[4], SetEnabledNonPersistent(false, _, _));
  EXPECT_CALL(*mock_devices_[5], SetEnabledPersistent(false, _, _)).Times(0);

  manager()->RegisterDevice(mock_devices_[3]);
  manager()->RegisterDevice(mock_devices_[4]);
  manager()->RegisterDevice(mock_devices_[5]);
  Mock::VerifyAndClearExpectations(mock_devices_[3].get());
  Mock::VerifyAndClearExpectations(mock_devices_[4].get());
  Mock::VerifyAndClearExpectations(mock_devices_[5].get());

  // Calls to enable a non-prohibited technology should succeed.
  DisableTechnologyReplyHandler technology_reply_handler;
  ResultCallback enable_technology_callback(
      base::Bind(&DisableTechnologyReplyHandler::ReportResult,
                 technology_reply_handler.AsWeakPtr()));
  EXPECT_CALL(*mock_devices_[2], SetEnabledPersistent(true, _, _))
      .WillOnce(WithArg<1>(Invoke(SetErrorSuccess)));
  EXPECT_CALL(*mock_devices_[5], SetEnabledPersistent(true, _, _))
      .WillOnce(WithArg<1>(Invoke(SetErrorSuccess)));
  EXPECT_CALL(technology_reply_handler, ReportResult(IsSuccess()));
  manager()->SetEnabledStateForTechnology("wifi", true, true,
                                          enable_technology_callback);
  Mock::VerifyAndClearExpectations(&technology_reply_handler);

  // Calls to enable a prohibited technology should fail.
  EXPECT_CALL(*mock_devices_[0], SetEnabledPersistent(true, _, _)).Times(0);
  EXPECT_CALL(*mock_devices_[3], SetEnabledPersistent(true, _, _)).Times(0);
  EXPECT_CALL(technology_reply_handler,
              ReportResult(ErrorTypeIs(Error::kPermissionDenied)));
  manager()->SetEnabledStateForTechnology("ethernet", true, true,
                                          enable_technology_callback);
}

TEST_F(ManagerTest, ClaimBlockedDevice) {
  const std::string kClaimerName = "test_claimer";
  const std::string kDeviceName = "test_device";

  // Set blocked devices.
  std::vector<std::string> blocked_devices = {kDeviceName};
  manager()->SetBlockedDevices(blocked_devices);

  Error error;
  manager()->ClaimDevice(kClaimerName, kDeviceName, &error);
  EXPECT_TRUE(error.IsFailure());
  EXPECT_EQ("Not allowed to claim unmanaged device", error.message());
  // Verify device claimer is not created.
  EXPECT_EQ(nullptr, manager()->device_claimer_);
}

TEST_F(ManagerTest, ReleaseBlockedDevice) {
  const std::string kClaimerName = "test_claimer";
  const std::string kDeviceName = "test_device";

  // Set blocked devices.
  std::vector<std::string> blocked_devices = {kDeviceName};
  manager()->SetBlockedDevices(blocked_devices);

  Error error;
  bool claimer_removed;
  manager()->ReleaseDevice(kClaimerName, kDeviceName, &claimer_removed, &error);
  EXPECT_TRUE(error.IsFailure());
  EXPECT_FALSE(claimer_removed);
  EXPECT_EQ("Not allowed to release unmanaged device", error.message());
}

TEST_F(ManagerTest, BlockedDeviceIsNotManaged) {
  const std::string kDeviceName = "test_device";

  std::vector<std::string> blocked_devices = {kDeviceName};
  manager()->SetBlockedDevices(blocked_devices);
  EXPECT_FALSE(manager()->DeviceManagementAllowed(kDeviceName));
}

TEST_F(ManagerTest, NonBlockedDeviceIsManaged) {
  const std::string kDeviceName = "test_device";

  std::vector<std::string> blocked_devices = {"other_device"};
  manager()->SetBlockedDevices(blocked_devices);
  EXPECT_TRUE(manager()->DeviceManagementAllowed(kDeviceName));
}

TEST_F(ManagerTest, AllowedDeviceIsManaged) {
  const std::string kDeviceName = "test_device";

  std::vector<std::string> allowed_devices = {kDeviceName};
  manager()->SetAllowedDevices(allowed_devices);
  EXPECT_TRUE(manager()->DeviceManagementAllowed(kDeviceName));
}

TEST_F(ManagerTest, NonAllowedDeviceIsNotManaged) {
  const std::string kDeviceName = "test_device";

  std::vector<std::string> allowed_devices = {"other_device"};
  manager()->SetAllowedDevices(allowed_devices);
  EXPECT_FALSE(manager()->DeviceManagementAllowed(kDeviceName));
}

TEST_F(ManagerTest, DevicesIsManagedByDefault) {
  EXPECT_TRUE(manager()->DeviceManagementAllowed("test_device"));
}

TEST_F(ManagerTest, ClaimDeviceWithoutClaimer) {
  const char kClaimerName[] = "test_claimer1";
  const char kDeviceName[] = "test_device";

  // Claim device when device claimer doesn't exist yet.
  Error error;
  manager()->ClaimDevice(kClaimerName, kDeviceName, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_TRUE(manager()->device_info()->IsDeviceBlocked(kDeviceName));
  // Verify device claimer is created.
  EXPECT_NE(nullptr, manager()->device_claimer_);
}

TEST_F(ManagerTest, ClaimDeviceWithClaimer) {
  const char kClaimer1Name[] = "test_claimer1";
  const char kClaimer2Name[] = "test_claimer2";
  const char kDeviceName[] = "test_device";

  // Claim device with empty string name.
  const char kEmptyDeviceNameError[] = "Empty device name";
  Error error;
  manager()->ClaimDevice(kClaimer1Name, "", &error);
  EXPECT_EQ(std::string(kEmptyDeviceNameError), error.message());

  // Device claim succeed.
  error.Reset();
  manager()->ClaimDevice(kClaimer1Name, kDeviceName, &error);
  EXPECT_TRUE(error.IsSuccess());

  // Claimer mismatch, current implementation only allows one claimer at a time.
  const char kInvalidClaimerError[] =
      "Invalid claimer name test_claimer2. Claimer test_claimer1 already exist";
  error.Reset();
  manager()->ClaimDevice(kClaimer2Name, kDeviceName, &error);
  EXPECT_TRUE(error.IsFailure());
  EXPECT_EQ(std::string(kInvalidClaimerError), error.message());
}

TEST_F(ManagerTest, ClaimRegisteredDevice) {
  // Register a device to manager.
  ON_CALL(*mock_devices_[0], technology())
      .WillByDefault(Return(Technology::kWiFi));
  manager()->RegisterDevice(mock_devices_[0]);
  // Verify device is registered.
  EXPECT_TRUE(IsDeviceRegistered(mock_devices_[0], Technology::kWiFi));

  // Claim the registered device.
  Error error;
  manager()->ClaimDevice("claimer1", mock_devices_[0]->link_name(), &error);
  EXPECT_TRUE(error.IsSuccess());

  // Expect device to not be registered anymore.
  EXPECT_FALSE(IsDeviceRegistered(mock_devices_[0], Technology::kWiFi));
}

TEST_F(ManagerTest, ReleaseDeviceWithoutClaimer) {
  bool claimer_removed;
  Error error;
  manager()->ReleaseDevice("claimer1", "device1", &claimer_removed, &error);
  EXPECT_FALSE(claimer_removed);
  EXPECT_THAT(
      error, ErrorIs(Error::kInvalidArguments, "Device claimer doesn't exist"));
}

TEST_F(ManagerTest, ReleaseDeviceFromWrongClaimer) {
  const char kDeviceName[] = "device1";

  Error error;
  manager()->ClaimDevice("claimer1", kDeviceName, &error);
  EXPECT_TRUE(error.IsSuccess());

  bool claimer_removed;
  manager()->ReleaseDevice("claimer2", kDeviceName, &claimer_removed, &error);
  EXPECT_FALSE(claimer_removed);
  EXPECT_THAT(
      error,
      ErrorIs(Error::kInvalidArguments,
              "Invalid claimer name claimer2. Claimer claimer1 already exist"));
}

TEST_F(ManagerTest, ReleaseDeviceFromDefaultClaimer) {
  const char kDeviceName[] = "device1";

  manager()->SetPassiveMode();
  VerifyPassiveMode();

  Error error;
  manager()->ClaimDevice("", kDeviceName, &error);
  EXPECT_TRUE(error.IsSuccess());

  // Release a device with default claimer. Claimer should not be resetted.
  bool claimer_removed;
  manager()->ReleaseDevice("", kDeviceName, &claimer_removed, &error);
  EXPECT_FALSE(claimer_removed);
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(ManagerTest, ReleaseDeviceFromNonDefaultClaimer) {
  const char kClaimerName[] = "claimer1";
  const char kDevice1Name[] = "device1";
  const char kDevice2Name[] = "device2";

  Error error;
  manager()->ClaimDevice(kClaimerName, kDevice1Name, &error);
  EXPECT_TRUE(error.IsSuccess());
  manager()->ClaimDevice(kClaimerName, kDevice2Name, &error);
  EXPECT_TRUE(error.IsSuccess());

  bool claimer_removed;
  manager()->ReleaseDevice(kClaimerName, kDevice1Name, &claimer_removed,
                           &error);
  EXPECT_FALSE(claimer_removed);
  EXPECT_TRUE(error.IsSuccess());

  // Release last device with non-default claimer. Claimer should be resetted.
  manager()->ReleaseDevice(kClaimerName, kDevice2Name, &claimer_removed,
                           &error);
  EXPECT_TRUE(claimer_removed);
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(ManagerTest, GetEnabledDeviceWithTechnology) {
  auto ethernet_device = mock_devices_[0];
  auto wifi_device = mock_devices_[1];
  auto cellular_device = mock_devices_[2];
  ON_CALL(*ethernet_device, technology())
      .WillByDefault(Return(Technology::kEthernet));
  ON_CALL(*wifi_device, technology()).WillByDefault(Return(Technology::kWiFi));
  ON_CALL(*cellular_device, technology())
      .WillByDefault(Return(Technology::kCellular));
  ethernet_device->enabled_ = true;
  wifi_device->enabled_ = true;
  cellular_device->enabled_ = true;

  manager()->RegisterDevice(ethernet_device);
  manager()->RegisterDevice(wifi_device);
  manager()->RegisterDevice(cellular_device);

  EXPECT_EQ(ethernet_device,
            manager()->GetEnabledDeviceWithTechnology(Technology::kEthernet));
  EXPECT_EQ(wifi_device,
            manager()->GetEnabledDeviceWithTechnology(Technology::kWiFi));
  EXPECT_EQ(cellular_device,
            manager()->GetEnabledDeviceWithTechnology(Technology::kCellular));
}

TEST_F(ManagerTest, AcceptHostnameFrom) {
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("eth0"));
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("eth1"));
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("wlan0"));

  manager()->SetAcceptHostnameFrom("eth0");
  EXPECT_TRUE(manager()->ShouldAcceptHostnameFrom("eth0"));
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("eth1"));
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("wlan0"));

  manager()->SetAcceptHostnameFrom("eth1");
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("eth0"));
  EXPECT_TRUE(manager()->ShouldAcceptHostnameFrom("eth1"));
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("wlan0"));

  manager()->SetAcceptHostnameFrom("eth*");
  EXPECT_TRUE(manager()->ShouldAcceptHostnameFrom("eth0"));
  EXPECT_TRUE(manager()->ShouldAcceptHostnameFrom("eth1"));
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("wlan0"));

  manager()->SetAcceptHostnameFrom("wlan*");
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("eth0"));
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("eth1"));
  EXPECT_TRUE(manager()->ShouldAcceptHostnameFrom("wlan0"));

  manager()->SetAcceptHostnameFrom("ether*");
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("eth0"));
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("eth1"));
  EXPECT_FALSE(manager()->ShouldAcceptHostnameFrom("wlan0"));
}

TEST_F(ManagerTest, SetAlwaysOnVpnPackage) {
  const std::string kPackage = "com.example.test.vpn";
  EXPECT_EQ("", manager()->GetAlwaysOnVpnPackage(nullptr));

  // If the package is not changed, return false
  EXPECT_EQ(false, manager()->SetAlwaysOnVpnPackage("", nullptr));
  EXPECT_EQ("", manager()->GetAlwaysOnVpnPackage(nullptr));

  // If the package is not changed, return true
  EXPECT_EQ(true, manager()->SetAlwaysOnVpnPackage(kPackage, nullptr));
  EXPECT_EQ(kPackage, manager()->GetAlwaysOnVpnPackage(nullptr));

  EXPECT_EQ(false, manager()->SetAlwaysOnVpnPackage(kPackage, nullptr));
  EXPECT_EQ(kPackage, manager()->GetAlwaysOnVpnPackage(nullptr));

  EXPECT_EQ(true, manager()->SetAlwaysOnVpnPackage("", nullptr));
  EXPECT_EQ("", manager()->GetAlwaysOnVpnPackage(nullptr));
}

TEST_F(ManagerTest, ShouldBlackholeUserTraffic) {
  const std::string kRegistered = mock_devices_[0]->UniqueName();
  const std::string kUnregistered = mock_devices_[1]->UniqueName();

  manager()->RegisterDevice(mock_devices_[0]);

  const std::string kOnlinePackage = "com.example.test.vpn1";
  const std::string kOfflinePackage = "com.example.test.vpn2";
  const std::string kOtherPackage = "com.example.test.vpn3";

  MockServiceRefPtr online_service(new NiceMock<MockService>(manager()));
  MockServiceRefPtr offline_service(new NiceMock<MockService>(manager()));

  EXPECT_CALL(*online_service, IsOnline()).WillRepeatedly(Return(false));
  EXPECT_CALL(*online_service, IsAlwaysOnVpn(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(*online_service, IsAlwaysOnVpn(kOnlinePackage))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*offline_service, IsOnline()).WillRepeatedly(Return(false));
  EXPECT_CALL(*offline_service, IsAlwaysOnVpn(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(*offline_service, IsAlwaysOnVpn(kOfflinePackage))
      .WillRepeatedly(Return(true));
  manager()->RegisterService(online_service);
  manager()->RegisterService(offline_service);

  // No package set: no blackholing
  EXPECT_EQ(false, manager()->ShouldBlackholeUserTraffic(kRegistered));
  EXPECT_EQ(false, manager()->ShouldBlackholeUserTraffic(kUnregistered));

  // Package set, service is not online yet, blackhole all registered devices
  manager()->SetAlwaysOnVpnPackage(kOnlinePackage, nullptr);
  EXPECT_EQ(true, manager()->ShouldBlackholeUserTraffic(kRegistered));
  EXPECT_EQ(false, manager()->ShouldBlackholeUserTraffic(kUnregistered));

  // Service comes online, stop blackholing
  EXPECT_CALL(*online_service, IsOnline()).WillRepeatedly(Return(true));
  manager()->UpdateBlackholeUserTraffic();
  EXPECT_EQ(false, manager()->ShouldBlackholeUserTraffic(kRegistered));
  EXPECT_EQ(false, manager()->ShouldBlackholeUserTraffic(kUnregistered));

  // Set to a different package whose service is offline, resume blackholing
  manager()->SetAlwaysOnVpnPackage(kOfflinePackage, nullptr);
  EXPECT_EQ(true, manager()->ShouldBlackholeUserTraffic(kRegistered));
  EXPECT_EQ(false, manager()->ShouldBlackholeUserTraffic(kUnregistered));

  // Set to a different package which has no service, keep blackholing
  manager()->SetAlwaysOnVpnPackage(kOtherPackage, nullptr);
  EXPECT_EQ(true, manager()->ShouldBlackholeUserTraffic(kRegistered));
  EXPECT_EQ(false, manager()->ShouldBlackholeUserTraffic(kUnregistered));
}

TEST_F(ManagerTest, UpdateBlackholeUserTraffic) {
  manager()->RegisterDevice(mock_devices_[0]);

  const std::string kOnlinePackage = "com.example.test.vpn1";
  const std::string kOtherPackage = "com.example.test.vpn2";

  MockServiceRefPtr service(new NiceMock<MockService>(manager()));
  EXPECT_CALL(*service, IsOnline()).WillRepeatedly(Return(false));
  EXPECT_CALL(*service, IsAlwaysOnVpn(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(*service, IsAlwaysOnVpn(kOnlinePackage))
      .WillRepeatedly(Return(true));
  manager()->RegisterService(service);

  EXPECT_CALL(*mock_devices_[0], UpdateBlackholeUserTraffic()).Times(1);
  manager()->SetAlwaysOnVpnPackage(kOtherPackage, nullptr);

  EXPECT_CALL(*mock_devices_[0], UpdateBlackholeUserTraffic()).Times(0);
  manager()->SetAlwaysOnVpnPackage(kOnlinePackage, nullptr);

  EXPECT_CALL(*mock_devices_[0], UpdateBlackholeUserTraffic()).Times(0);
  manager()->UpdateBlackholeUserTraffic();

  EXPECT_CALL(*mock_devices_[0], UpdateBlackholeUserTraffic()).Times(1);
  EXPECT_CALL(*service, IsOnline()).WillRepeatedly(Return(true));
  manager()->UpdateBlackholeUserTraffic();

  EXPECT_CALL(*mock_devices_[0], UpdateBlackholeUserTraffic()).Times(1);
  manager()->SetAlwaysOnVpnPackage(kOtherPackage, nullptr);

  EXPECT_CALL(*mock_devices_[0], UpdateBlackholeUserTraffic()).Times(1);
  manager()->SetAlwaysOnVpnPackage("", nullptr);
}

TEST_F(ManagerTest, RefreshAllTrafficCountersTask) {
  patchpanel::TrafficCounter counter0, counter1;
  counter0.set_device(mock_devices_[0]->link_name());
  counter0.set_source(patchpanel::TrafficCounter::VPN);
  counter1.set_device(mock_devices_[2]->link_name());
  counter1.set_source(patchpanel::TrafficCounter::UPDATE_ENGINE);
  std::vector<patchpanel::TrafficCounter> counters{counter0, counter1};
  patchpanel_client_->set_stored_traffic_counters(counters);

  manager()->RegisterDevice(mock_devices_[0]);
  manager()->RegisterDevice(mock_devices_[1]);
  manager()->RegisterDevice(mock_devices_[2]);

  MockServiceRefPtr service0(new NiceMock<MockService>(manager()));
  MockServiceRefPtr service1(new NiceMock<MockService>(manager()));
  MockServiceRefPtr service2(new NiceMock<MockService>(manager()));

  mock_devices_[0]->SelectService(service0);
  mock_devices_[1]->SelectService(service1);
  mock_devices_[2]->SelectService(service2);

  manager()->RefreshAllTrafficCountersTask();

  EXPECT_EQ(1, service0->current_traffic_counters_.size());
  EXPECT_TRUE(service1->current_traffic_counters_.empty());
  EXPECT_EQ(1, service2->current_traffic_counters_.size());
}

TEST_F(ManagerTest, SetDNSProxyAddresses) {
  Error err;
  // Bad cases.
  EXPECT_FALSE(manager()->SetDNSProxyAddresses({"10.10.10.1"}, &err));
  EXPECT_TRUE(err.IsFailure());
  err.Reset();
  EXPECT_FALSE(manager()->SetDNSProxyAddresses({"1.1"}, &err));
  EXPECT_TRUE(err.IsFailure());
  err.Reset();
  EXPECT_FALSE(manager()->SetDNSProxyAddresses({"blah"}, &err));
  EXPECT_TRUE(err.IsFailure());
  err.Reset();
  EXPECT_FALSE(manager()->SetDNSProxyAddresses({"::g"}, &err));
  EXPECT_TRUE(err.IsFailure());
  err.Reset();

  // Good cases.
  manager()->last_default_physical_service_online_ = true;
  EXPECT_CALL(resolver_, SetDNSProxyAddresses(ElementsAre("100.115.92.100")));
  EXPECT_TRUE(manager()->SetDNSProxyAddresses({"100.115.92.100"}, &err));
  EXPECT_FALSE(err.IsFailure());
  err.Reset();
  // Unchanged.
  EXPECT_FALSE(manager()->SetDNSProxyAddresses({"100.115.92.100"}, &err));
  EXPECT_FALSE(err.IsFailure());
  err.Reset();
  // Update.
  EXPECT_CALL(resolver_,
              SetDNSProxyAddresses(ElementsAre("100.115.92.100", "::1")));
  EXPECT_TRUE(manager()->SetDNSProxyAddresses({"100.115.92.100", "::1"}, &err));
  EXPECT_FALSE(err.IsFailure());
  err.Reset();
  // Unchanged.
  EXPECT_FALSE(
      manager()->SetDNSProxyAddresses({"100.115.92.100", "::1"}, &err));
  EXPECT_FALSE(err.IsFailure());
  err.Reset();
  // Empty addresses clears.
  EXPECT_CALL(resolver_, SetDNSProxyAddresses(ElementsAre()));
  EXPECT_TRUE(manager()->SetDNSProxyAddresses({}, &err));
  // Clear.
  EXPECT_CALL(resolver_, SetDNSProxyAddresses(ElementsAre()));
  manager()->ClearDNSProxyAddresses();
}

TEST_F(ManagerTest, SetDNSProxyDOHProviders) {
  Error err;
  KeyValueStore providers;
  // Bad URL
  providers.Set("htps://bad.com", std::string("10.10.10.10"));
  EXPECT_FALSE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_TRUE(err.IsFailure());
  // Bad IPv4 addr
  providers.Clear();
  providers.Set("https://good.com", std::string("1000.10.10.10"));
  EXPECT_FALSE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_TRUE(err.IsFailure());
  providers.Clear();
  providers.Set("https://good.com",
                std::string("9.9.9.9, 1.1.1.1, 1000.10.10.10"));
  EXPECT_FALSE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_TRUE(err.IsFailure());
  providers.Clear();
  providers.Set("https://good.com", std::string("9.9.9.9, 1.1.1.1"));
  providers.Set("https://good2.com", std::string("8.8.8.8"));
  providers.Set("https://notsogood.com", std::string("8.8.8/8"));
  EXPECT_FALSE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_TRUE(err.IsFailure());
  // Bad IPv6 addr
  providers.Clear();
  providers.Set("https://good.com", std::string("::ffff:204.152.189.116z"));
  EXPECT_FALSE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_TRUE(err.IsFailure());
  providers.Clear();
  providers.Set(
      "https://good.com",
      std::string("fe80::4408:99ff:fed1:74ac,::ffff:204.152.189.116z"));
  EXPECT_FALSE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_TRUE(err.IsFailure());
  // NS not IP addr.
  providers.Clear();
  providers.Set("https://good.com", std::string("https://good.com"));
  EXPECT_FALSE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_TRUE(err.IsFailure());

  // Good URL, no value.
  providers.Clear();
  providers.Set("https://good.com", std::string(""));
  EXPECT_TRUE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  // URL w/ optional QP
  providers.Clear();
  providers.Set("https://dns64.dns.google/dns-query{?dns}",
                std::string("2001:4860:4860::64, 2001:4860:4860::6464"));
  EXPECT_TRUE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  // Good IPv4.
  providers.Clear();
  providers.Set("https://good.com", std::string("1.1.1.1"));
  EXPECT_TRUE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  providers.Clear();
  providers.Set("https://good.com", std::string("1.1.1.1,9.9.9.9"));
  EXPECT_TRUE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  providers.Clear();
  providers.Set("https://good.com", std::string("1.1.1.1,9.9.9.9"));
  providers.Set("https://good1.com", std::string("9.99.9.9"));
  providers.Set("https://good2.com",
                std::string("10.10.10.1   ,    192.168.1.1"));
  EXPECT_TRUE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  // Good IPv6.
  providers.Clear();
  providers.Set("https://good.com", std::string("fe80::4408:99ff:fed1:74ac"));
  EXPECT_TRUE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  providers.Clear();
  providers.Set(
      "https://good.com",
      std::string("fe80::4408:99ff:fed1:74ac, ::ffff:204.152.189.116"));
  EXPECT_TRUE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  providers.Clear();
  providers.Set("https://good.com", std::string("fe80::4408:99ff:fed1:74ac"));
  providers.Set("https://good1.com", std::string("::ffff:204.152.189.116"));
  EXPECT_TRUE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  // Both
  providers.Clear();
  providers.Set(
      "https://dns.google.com",
      std::string("8.8.8.8,8.8.4.4,2001:4860:4860::8888,2001:4860:4860::8844"));
  providers.Set(
      "https://chrome.cloudflare-dns.com",
      std::string("1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"));
  EXPECT_TRUE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  // Unchanged.
  EXPECT_FALSE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  // Empty.
  providers.Clear();
  EXPECT_TRUE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
  // Unchanged.
  EXPECT_FALSE(SetDNSProxyDOHProviders(providers, &err));
  EXPECT_FALSE(err.IsFailure());
}

#if !defined(DISABLE_WIRED_8021X) && !defined(DISABLE_WIFI)
TEST_F(ManagerTest, AddPasspointCredentials) {
  Error err;
  KeyValueStore properties;
  RpcIdentifier profile_rpcid("/a/mock/profile");
  MockProfile* profile = new MockProfile(manager(), "");
  AdoptProfile(manager(), profile);  // Passes ownership.

  // Attribute a RPC identifier to the mock profile.
  EXPECT_CALL(*profile, GetRpcIdentifier())
      .WillRepeatedly(ReturnRefOfCopy(profile_rpcid));

  // Can't add credentials to an invalid profile.
  manager()->AddPasspointCredentials(std::string(), properties, &err);
  EXPECT_TRUE(err.IsFailure());

  // Can't add credentials to the default profile.
  EXPECT_CALL(*profile, IsDefault()).WillOnce(Return(true));
  manager()->AddPasspointCredentials(profile_rpcid.value(), properties, &err);
  EXPECT_TRUE(err.IsFailure());

  // Good profile but invalid credentials fails.
  EXPECT_CALL(*profile, IsDefault()).WillOnce(Return(false));
  manager()->AddPasspointCredentials(profile_rpcid.value(), properties, &err);
  EXPECT_TRUE(err.IsFailure());

  // Get a correct dict for valid credentials
  properties.Set(kPasspointCredentialsDomainsProperty,
                 std::vector<std::string>{"example.com"});
  properties.Set(kPasspointCredentialsRealmProperty,
                 std::string("example.com"));
  properties.Set(kEapMethodProperty, std::string("TLS"));
  properties.Set(kEapCaCertPemProperty, std::vector<std::string>{"a PEM line"});
  properties.Set(kEapCertIdProperty, std::string("cert-id"));
  properties.Set(kEapKeyIdProperty, std::string("key-id"));
  properties.Set(kEapPinProperty, std::string("111111"));
  properties.Set(kEapIdentityProperty, std::string("a_user"));

  // A correct set of credentials is pushed to the profile but it refuses them.
  EXPECT_CALL(*profile, IsDefault()).WillOnce(Return(false));
  EXPECT_CALL(*profile, AdoptCredentials(_)).WillOnce(Return(false));
  manager()->AddPasspointCredentials(profile_rpcid.value(), properties, &err);
  EXPECT_TRUE(err.IsFailure());

  // A correct set of credentials is accepted.
  EXPECT_CALL(*profile, IsDefault()).WillOnce(Return(false));
  EXPECT_CALL(*profile, AdoptCredentials(_)).WillOnce(Return(true));
  EXPECT_CALL(*wifi_provider_, AddCredentials(_));
  manager()->AddPasspointCredentials(profile_rpcid.value(), properties, &err);
  EXPECT_TRUE(err.IsSuccess());
}
#endif  // !DISABLE_WIRED_8021X && !DISABLE_WIFI

}  // namespace shill
