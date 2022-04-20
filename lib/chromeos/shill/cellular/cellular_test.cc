// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular.h"

#include <linux/if.h>  // NOLINT - Needs typedefs from sys/socket.h.
#include <linux/netlink.h>
#include <sys/socket.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include <base/bind.h>
//#include <base/check.h>
//#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/memory/scoped_refptr.h>
#include <chromeos/dbus/service_constants.h>

extern "C" {
// A struct member in pppd.h has the name 'class'.
#define class class_num
// pppd.h defines a bool type.
#define bool pppd_bool_t
#include <pppd/pppd.h>
#undef bool
#undef class
}

#include "shill/cellular/cellular_bearer.h"
#include "shill/cellular/cellular_capability_3gpp.h"
#include "shill/cellular/cellular_consts.h"
#include "shill/cellular/cellular_service.h"
#include "shill/cellular/cellular_service_provider.h"
#include "shill/cellular/mock_cellular_service.h"
#include "shill/cellular/mock_mm1_modem_location_proxy.h"
#include "shill/cellular/mock_mm1_modem_modem3gpp_profile_manager_proxy.h"
#include "shill/cellular/mock_mm1_modem_modem3gpp_proxy.h"
#include "shill/cellular/mock_mm1_modem_modemcdma_proxy.h"
#include "shill/cellular/mock_mm1_modem_proxy.h"
#include "shill/cellular/mock_mm1_modem_signal_proxy.h"
#include "shill/cellular/mock_mm1_modem_simple_proxy.h"
#include "shill/cellular/mock_mobile_operator_info.h"
#include "shill/cellular/mock_modem_info.h"
#include "shill/dbus/dbus_properties_proxy.h"
#include "shill/dbus/fake_properties_proxy.h"
#include "shill/error.h"
#include "shill/manager.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_external_task.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_process_manager.h"
#include "shill/mock_profile.h"
#include "shill/net/mock_rtnl_handler.h"
#include "shill/network/mock_dhcp_controller.h"
#include "shill/network/mock_dhcp_provider.h"
#include "shill/ppp_device.h"
#include "shill/rpc_task.h"  // for RpcTaskDelegate
#include "shill/service.h"
#include "shill/store/fake_store.h"
#include "shill/store/property_store_test.h"
#include "shill/test_event_dispatcher.h"
#include "shill/testing.h"

using testing::_;
using testing::AnyNumber;
using testing::AtLeast;
using testing::DoAll;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;
using testing::SetArgPointee;
using testing::StrEq;

namespace shill {

namespace {
RpcIdentifier kTestBearerPath("/org/freedesktop/ModemManager1/Bearer/0");
constexpr char kUid[] = "uid";
constexpr char kIccid[] = "1234567890000";
}  // namespace

class MockPPPDevice : public PPPDevice {
 public:
  MockPPPDevice(Manager* manager, const std::string& ifname, int ifindex)
      : PPPDevice(manager, ifname, ifindex) {}
  MockPPPDevice(const MockPPPDevice&) = delete;
  MockPPPDevice& operator=(const MockPPPDevice&) = delete;
  ~MockPPPDevice() = default;

  MOCK_METHOD(void, DropConnection, (), (override));
  MOCK_METHOD(void, SelectService, (const ServiceRefPtr&), (override));
  MOCK_METHOD(void, SetServiceState, (Service::ConnectState), (override));
  MOCK_METHOD(void, SetServiceFailure, (Service::ConnectFailure), (override));
  MOCK_METHOD(void,
              SetServiceFailureSilent,
              (Service::ConnectFailure),
              (override));
  MOCK_METHOD(void, SetEnabled, (bool), (override));
  MOCK_METHOD(void,
              UpdateIPConfigFromPPP,
              ((const std::map<std::string, std::string>&), bool),
              (override));
};

class CellularPropertyTest : public PropertyStoreTest {
 public:
  CellularPropertyTest()
      : device_(new Cellular(manager(),
                             "usb0",
                             "00:01:02:03:04:05",
                             3,
                             Cellular::kType3gpp,
                             "",
                             RpcIdentifier(""))) {}

  ~CellularPropertyTest() { device_ = nullptr; }

 protected:
  CellularRefPtr device_;
};

TEST_F(CellularPropertyTest, Contains) {
  EXPECT_TRUE(device_->store().Contains(kNameProperty));
  EXPECT_FALSE(device_->store().Contains(""));
}

TEST_F(CellularPropertyTest, SetProperty) {
  {
    Error error;
    device_->mutable_store()->SetAnyProperty(
        kCellularPolicyAllowRoamingProperty, false, &error);
    EXPECT_TRUE(error.IsSuccess());
  }
  // Ensure that attempting to write a R/O property returns InvalidArgs error.
  {
    Error error;
    device_->mutable_store()->SetAnyProperty(
        kAddressProperty, PropertyStoreTest::kStringV, &error);
    EXPECT_TRUE(error.IsFailure());
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }
}

class CellularTest : public testing::TestWithParam<Cellular::Type> {
 public:
  CellularTest()
      : kHomeProviderCode("10001"),
        kHomeProviderCountry("us"),
        kHomeProviderName("HomeProviderName"),
        kServingOperatorCode("10002"),
        kServingOperatorCountry("ca"),
        kServingOperatorName("ServingOperatorName"),
        control_interface_(this),
        manager_(&control_interface_, &dispatcher_, &metrics_),
        modem_info_(&control_interface_, &manager_),
        device_info_(&manager_),
        dhcp_hostname_("chromeos"),
        mock_home_provider_info_(nullptr),
        mock_serving_operator_info_(nullptr),
        profile_(new NiceMock<MockProfile>(&manager_)) {
    cellular_service_provider_.set_profile_for_testing(profile_);
  }

  ~CellularTest() = default;

  void SetUp() override {
    EXPECT_CALL(manager_, device_info()).WillRepeatedly(Return(&device_info_));
    EXPECT_CALL(manager_, modem_info()).WillRepeatedly(Return(&modem_info_));
    device_ = new Cellular(&manager_, kTestDeviceName, kTestDeviceAddress, 3,
                           GetParam(), kDBusService, kDBusPath);
    PopulateProxies();
    metrics_.RegisterDevice(device_->interface_index(), Technology::kCellular);

    static_cast<Device*>(device_.get())->rtnl_handler_ = &rtnl_handler_;
    device_->set_dhcp_provider(&dhcp_provider_);
    device_->process_manager_ = &process_manager_;

    EXPECT_CALL(manager_, DeregisterService(_)).Times(AnyNumber());
    ON_CALL(manager_, dhcp_hostname()).WillByDefault(ReturnRef(dhcp_hostname_));
    EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
                GetActivationState(_, _))
        .WillRepeatedly(Return(PendingActivationStore::kStateActivated));
    EXPECT_CALL(manager_, cellular_service_provider())
        .WillRepeatedly(Return(&cellular_service_provider_));
    EXPECT_CALL(*profile_, GetConstStorage())
        .WillRepeatedly(Return(&profile_storage_));
    EXPECT_CALL(*profile_, GetStorage())
        .WillRepeatedly(Return(&profile_storage_));
  }

  void TearDown() override {
    metrics_.DeregisterDevice(device_->interface_index());
    device_->DestroyIPConfig();
    device_->set_state_for_testing(Cellular::State::kDisabled);
    GetCapability3gpp()->ReleaseProxies();
    device_->set_dhcp_provider(nullptr);
    // Break cycle between Cellular and CellularService.
    device_->service_ = nullptr;
    device_->SelectService(nullptr);
    device_ = nullptr;
  }

  // TODO(benchan): Instead of conditionally enabling many tests for specific
  // capability types via IsCellularTypeUnderTestOneOf, migrate more tests to
  // work under all capability types and probably migrate those tests for
  // specific capability types into their own test fixture subclasses.
  bool IsCellularTypeUnderTestOneOf(
      const std::set<Cellular::Type>& valid_types) const {
    return base::Contains(valid_types, GetParam());
  }

  void CreatePropertiesProxy() {
    dbus_properties_proxy_ =
        DBusPropertiesProxy::CreateDBusPropertiesProxyForTesting(
            std::make_unique<FakePropertiesProxy>());
    FakePropertiesProxy* fake_properties = static_cast<FakePropertiesProxy*>(
        dbus_properties_proxy_->GetDBusPropertiesProxyForTesting());
    // Ensure that GetAll calls to MM_DBUS_INTERFACE_MODEM and
    // MM_DBUS_INTERFACE_MODEM_MODEM3GPP succeed and return a valid dictionary.
    fake_properties->SetDictionaryForTesting(MM_DBUS_INTERFACE_MODEM,
                                             brillo::VariantDictionary());
    fake_properties->SetDictionaryForTesting(MM_DBUS_INTERFACE_MODEM_MODEM3GPP,
                                             brillo::VariantDictionary());
    // Set the Device property so that StartModem succeeds.
    fake_properties->SetForTesting(modemmanager::kModemManager1ModemInterface,
                                   MM_MODEM_PROPERTY_DEVICE,
                                   brillo::Any(std::string(kUid)));
  }

  void PopulateProxies() {
    CreatePropertiesProxy();
    mm1_modem_location_proxy_.reset(new mm1::MockModemLocationProxy());
    mm1_modem_3gpp_proxy_.reset(new mm1::MockModemModem3gppProxy());
    mm1_modem_3gpp_profile_manager_proxy_.reset(
        new mm1::MockModemModem3gppProfileManagerProxy());
    mm1_modem_cdma_proxy_.reset(new mm1::MockModemModemCdmaProxy());
    mm1_modem_proxy_.reset(new mm1::MockModemProxy());
    mm1_signal_proxy_.reset(new mm1::MockModemSignalProxy());
    mm1_simple_proxy_.reset(new mm1::MockModemSimpleProxy());
  }

  void SetMockMobileOperatorInfoObjects() {
    mock_home_provider_info_ =
        new NiceMock<MockMobileOperatorInfo>(&dispatcher_, "HomeProvider");
    // Takes ownership.
    device_->set_home_provider_info_for_testing(mock_home_provider_info_);

    mock_serving_operator_info_ =
        new NiceMock<MockMobileOperatorInfo>(&dispatcher_, "ServingOperator");
    // Takes ownership.
    device_->set_serving_operator_info_for_testing(mock_serving_operator_info_);
  }

  void InvokeEnable(bool enable,
                    Error* error,
                    const ResultCallback& callback,
                    int timeout) {
    callback.Run(Error());
  }
  void InvokeEnableReturningWrongState(bool enable,
                                       Error* error,
                                       const ResultCallback& callback,
                                       int timeout) {
    callback.Run(Error(Error::kWrongState));
  }
  void InvokeGetModemStatus(Error* error,
                            const KeyValueStoreCallback& callback,
                            int timeout) {
    KeyValueStore props;
    props.Set<std::string>("carrier", kTestCarrier);
    props.Set<std::string>("unknown-property", "irrelevant-value");
    callback.Run(props, Error());
  }
  void InvokeConnect(const KeyValueStore& props,
                     const RpcIdentifierCallback& callback,
                     int timeout) {
    EXPECT_EQ(Service::kStateAssociating, device_->service_->state());
    callback.Run(kTestBearerPath, Error());
  }
  void InvokeConnectFail(const KeyValueStore& props,
                         const RpcIdentifierCallback& callback,
                         int timeout) {
    EXPECT_EQ(Service::kStateAssociating, device_->service_->state());
    callback.Run(RpcIdentifier(), Error(Error::kNotOnHomeNetwork));
  }
  void InvokeDisconnect(const RpcIdentifier& bearer,
                        const ResultCallback& callback,
                        int timeout) {
    if (!callback.is_null())
      callback.Run(Error());
  }
  void InvokeDisconnectFail(const RpcIdentifier& bearer,
                            const ResultCallback& callback,
                            int timeout) {
    if (!callback.is_null())
      callback.Run(Error(Error::kOperationFailed));
  }
  void InvokeList(ResultVariantDictionariesOnceCallback callback, int timeout) {
    std::move(callback).Run(VariantDictionaries(), Error());
  }
  void InvokeSetPowerState(const uint32_t& power_state,
                           Error* error,
                           const ResultCallback& callback,
                           int timeout) {
    callback.Run(Error());
  }

  void ExpectDisconnectCapability3gpp() {
    device_->set_state_for_testing(Cellular::State::kConnected);
    EXPECT_CALL(*mm1_simple_proxy_, Disconnect(_, _, _))
        .WillOnce(Invoke(this, &CellularTest::InvokeDisconnect));
    GetCapability3gpp()->modem_simple_proxy_.reset(mm1_simple_proxy_.release());
  }

  void VerifyDisconnect() {
    EXPECT_EQ(Cellular::State::kRegistered, device_->state());
  }

  void StartPPP(int pid) {
    EXPECT_CALL(process_manager_, StartProcess(_, _, _, _, _, _))
        .WillOnce(Return(pid));
    device_->StartPPP("fake_serial_device");
    EXPECT_FALSE(device_->ipconfig());  // No DHCP client.
    EXPECT_FALSE(device_->selected_service());
    EXPECT_FALSE(device_->is_ppp_authenticating_);
    EXPECT_NE(nullptr, device_->ppp_task_);
    Mock::VerifyAndClearExpectations(&process_manager_);
  }

  void FakeUpConnectedPPP() {
    const char ifname[] = "fake-ppp-device";
    const int ifindex = 1;
    auto mock_ppp_device =
        base::MakeRefCounted<MockPPPDevice>(&manager_, ifname, ifindex);
    device_->ppp_device_ = mock_ppp_device;
    device_->set_state_for_testing(Cellular::State::kConnected);
  }

  void ExpectPPPStopped() {
    auto mock_ppp_device =
        static_cast<MockPPPDevice*>(device_->ppp_device_.get());
    EXPECT_CALL(*mock_ppp_device, DropConnection());
  }

  void VerifyPPPStopped() {
    EXPECT_EQ(nullptr, device_->ppp_task_);
    EXPECT_FALSE(device_->ppp_device_);
  }

  mm1::MockModemProxy* SetModemProxyExpectations() {
    EXPECT_CALL(*mm1_modem_proxy_, set_state_changed_callback(_))
        .Times(AnyNumber());
    return mm1_modem_proxy_.get();
  }

  mm1::MockModemModem3gppProfileManagerProxy*
  SetModem3gppProfileManagerProxyExpectations() {
    EXPECT_CALL(*mm1_modem_3gpp_profile_manager_proxy_, SetUpdatedCallback(_))
        .Times(AnyNumber());
    return mm1_modem_3gpp_profile_manager_proxy_.get();
  }

  mm1::MockModemProxy* SetupOnAfterResume() {
    EXPECT_CALL(manager_, UpdateEnabledTechnologies()).Times(AnyNumber());
    EXPECT_CALL(*static_cast<DeviceMockAdaptor*>(device_->adaptor()),
                EmitBoolChanged(_, _))
        .Times(AnyNumber());
    return SetModemProxyExpectations();
  }

  void VerifyOperatorMap(const Stringmap& operator_map,
                         const std::string& code,
                         const std::string& name,
                         const std::string& country) {
    Stringmap::const_iterator it;
    Stringmap::const_iterator endit = operator_map.end();

    it = operator_map.find(kOperatorCodeKey);
    if (code == "") {
      EXPECT_EQ(endit, it);
    } else {
      ASSERT_NE(endit, it);
      EXPECT_EQ(code, it->second);
    }
    it = operator_map.find(kOperatorNameKey);
    if (name == "") {
      EXPECT_EQ(endit, it);
    } else {
      ASSERT_NE(endit, it);
      EXPECT_EQ(name, it->second);
    }
    it = operator_map.find(kOperatorCountryKey);
    if (country == "") {
      EXPECT_EQ(endit, it);
    } else {
      ASSERT_NE(endit, it);
      EXPECT_EQ(country, it->second);
    }
  }

  void CallStartModemCallback(const Error& error) {
    device_->StartModemCallback(
        base::Bind(&CellularTest::TestCallback, base::Unretained(this)), error);
    dispatcher_.DispatchPendingEvents();
  }

  void CallStopModemCallback(const Error& error) {
    device_->StopModemCallback(
        base::Bind(&CellularTest::TestCallback, base::Unretained(this)), error);
  }

  void CallSetPrimarySimProperties(const Cellular::SimProperties& properties) {
    device_->SetPrimarySimProperties(properties);
  }

  void CallSetSimSlotProperties(
      const std::vector<Cellular::SimProperties>& properties, size_t primary) {
    device_->SetSimSlotProperties(properties, static_cast<int>(primary));
  }

  void CallSetSimProperties(
      const std::vector<Cellular::SimProperties>& properties, size_t primary) {
    device_->SetSimProperties(properties, static_cast<int>(primary));
  }

  std::unique_ptr<MockDHCPController> CreateMockDHCPController() {
    auto controller = std::make_unique<MockDHCPController>(&control_interface_,
                                                           kTestDeviceName);
    ON_CALL(*controller, ReleaseIP(_)).WillByDefault(Return(true));
    return controller;
  }

  MOCK_METHOD(void, TestCallback, (const Error&));

 protected:
  static const char kTestDeviceName[];
  static const char kTestDeviceAddress[];
  static const char kDBusService[];
  static const RpcIdentifier kDBusPath;
  static const char kTestCarrier[];
  static const char kTestCarrierSPN[];
  static const char kMEID[];
  static const char kIMEI[];
  static const char kIMSI[];
  static const char kMSISDN[];
  static const char kTestMobileProviderDBPath[];
  static const Stringmaps kTestNetworksCellular;
  static const int kStrength;

  // Must be std::string so that we can safely ReturnRef.
  const std::string kHomeProviderCode;
  const std::string kHomeProviderCountry;
  const std::string kHomeProviderName;
  const std::string kServingOperatorCode;
  const std::string kServingOperatorCountry;
  const std::string kServingOperatorName;

  class TestControl : public MockControl {
   public:
    explicit TestControl(CellularTest* test) : test_(test) {}

    std::unique_ptr<DBusPropertiesProxy> CreateDBusPropertiesProxy(
        const RpcIdentifier& path, const std::string& service) override {
      std::unique_ptr<DBusPropertiesProxy> proxy =
          std::move(test_->dbus_properties_proxy_);

      // Replace properties for subsequent requests.
      test_->CreatePropertiesProxy();
      return proxy;
    }

    std::unique_ptr<mm1::ModemLocationProxyInterface>
    CreateMM1ModemLocationProxy(const RpcIdentifier& path,
                                const std::string& service) override {
      if (!test_->mm1_modem_location_proxy_) {
        test_->mm1_modem_location_proxy_.reset(
            new mm1::MockModemLocationProxy());
      }
      return std::move(test_->mm1_modem_location_proxy_);
    }

    std::unique_ptr<mm1::ModemModem3gppProxyInterface>
    CreateMM1ModemModem3gppProxy(const RpcIdentifier& path,
                                 const std::string& service) override {
      if (!test_->mm1_modem_3gpp_proxy_)
        test_->mm1_modem_3gpp_proxy_.reset(new mm1::MockModemModem3gppProxy());
      return std::move(test_->mm1_modem_3gpp_proxy_);
    }

    std::unique_ptr<mm1::ModemModem3gppProfileManagerProxyInterface>
    CreateMM1ModemModem3gppProfileManagerProxy(
        const RpcIdentifier& path, const std::string& service) override {
      if (!test_->mm1_modem_3gpp_profile_manager_proxy_)
        test_->mm1_modem_3gpp_profile_manager_proxy_.reset(
            new mm1::MockModemModem3gppProfileManagerProxy());
      return std::move(test_->mm1_modem_3gpp_profile_manager_proxy_);
    }

    std::unique_ptr<mm1::ModemModemCdmaProxyInterface>
    CreateMM1ModemModemCdmaProxy(const RpcIdentifier& path,
                                 const std::string& service) override {
      if (!test_->mm1_modem_cdma_proxy_)
        test_->mm1_modem_cdma_proxy_.reset(new mm1::MockModemModemCdmaProxy());
      return std::move(test_->mm1_modem_cdma_proxy_);
    }

    std::unique_ptr<mm1::ModemProxyInterface> CreateMM1ModemProxy(
        const RpcIdentifier& path, const std::string& service) override {
      if (!test_->mm1_modem_proxy_)
        test_->mm1_modem_proxy_.reset(new mm1::MockModemProxy());
      return std::move(test_->mm1_modem_proxy_);
    }

    std::unique_ptr<mm1::ModemSimpleProxyInterface> CreateMM1ModemSimpleProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      if (!test_->mm1_simple_proxy_)
        test_->mm1_simple_proxy_.reset(new mm1::MockModemSimpleProxy());
      return std::move(test_->mm1_simple_proxy_);
    }

    std::unique_ptr<mm1::ModemSignalProxyInterface> CreateMM1ModemSignalProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      if (!test_->mm1_signal_proxy_)
        test_->mm1_signal_proxy_.reset(new mm1::MockModemSignalProxy());
      return std::move(test_->mm1_signal_proxy_);
    }

   private:
    CellularTest* test_;
  };

  void AllowCreateGsmCardProxyFromFactory() {
    create_gsm_card_proxy_from_factory_ = true;
  }

  CellularCapability3gpp* GetCapability3gpp() {
    return static_cast<CellularCapability3gpp*>(device_->capability_.get());
  }

  // Different tests simulate a cellular service being set using a real /mock
  // service.
  CellularService* SetService() {
    device_->service_ = new CellularService(
        &manager_, device_->imsi(), device_->iccid(), device_->GetSimCardId());
    device_->service_->SetDevice(device_.get());
    return device_->service_.get();
  }
  MockCellularService* SetMockService() {
    device_->service_ = new NiceMock<MockCellularService>(&manager_, device_);
    return static_cast<MockCellularService*>(device_->service_.get());
  }

  void SetCapability3gppActiveBearer(std::unique_ptr<CellularBearer> bearer) {
    GetCapability3gpp()->active_bearer_ = std::move(bearer);
  }

  void SetCapability3gppModemSimpleProxy() {
    GetCapability3gpp()->modem_simple_proxy_ = std::move(mm1_simple_proxy_);
  }

  void SetCapability3gppRegistrationState(
      const MMModem3gppRegistrationState registration_state) {
    GetCapability3gpp()->registration_state_ = registration_state;
  }

  void Capability3gppCallOnProfilesChanged(
      const CellularCapability3gpp::Profiles& profiles) {
    GetCapability3gpp()->OnProfilesChanged(profiles);
  }

  void InitCapability3gppProxies() { GetCapability3gpp()->InitProxies(); }

  CellularService* SetRegisteredWithService() {
    device_->set_iccid_for_testing(kIccid);
    device_->set_state_for_testing(Cellular::State::kRegistered);
    device_->set_modem_state_for_testing(Cellular::kModemStateRegistered);
    CellularService* service = SetService();
    cellular_service_provider_.LoadServicesForDevice(device_.get());
    return service;
  }

  void SetInhibited(bool inhibited) {
    device_->SetInhibited(inhibited, /*error=*/nullptr);
  }

  void SetScanning(bool scanning) { device_->SetScanningProperty(scanning); }

  EventDispatcherForTest dispatcher_;
  TestControl control_interface_;
  NiceMock<MockManager> manager_;
  NiceMock<MockMetrics> metrics_;
  MockModemInfo modem_info_;
  NiceMock<MockDeviceInfo> device_info_;
  NiceMock<MockProcessManager> process_manager_;
  NiceMock<MockRTNLHandler> rtnl_handler_;

  MockDHCPProvider dhcp_provider_;
  std::string dhcp_hostname_;

  bool create_gsm_card_proxy_from_factory_;
  std::unique_ptr<DBusPropertiesProxy> dbus_properties_proxy_;
  std::unique_ptr<mm1::MockModemModem3gppProxy> mm1_modem_3gpp_proxy_;
  std::unique_ptr<mm1::MockModemModem3gppProfileManagerProxy>
      mm1_modem_3gpp_profile_manager_proxy_;
  std::unique_ptr<mm1::MockModemModemCdmaProxy> mm1_modem_cdma_proxy_;
  std::unique_ptr<mm1::MockModemLocationProxy> mm1_modem_location_proxy_;
  std::unique_ptr<mm1::MockModemProxy> mm1_modem_proxy_;
  std::unique_ptr<mm1::MockModemSignalProxy> mm1_signal_proxy_;
  std::unique_ptr<mm1::MockModemSimpleProxy> mm1_simple_proxy_;
  MockMobileOperatorInfo* mock_home_provider_info_;
  MockMobileOperatorInfo* mock_serving_operator_info_;
  CellularRefPtr device_;
  CellularServiceProvider cellular_service_provider_{&manager_};
  FakeStore profile_storage_;
  scoped_refptr<NiceMock<MockProfile>> profile_;
};

const char CellularTest::kTestDeviceName[] = "usb0";
const char CellularTest::kTestDeviceAddress[] = "000102030405";
const char CellularTest::kDBusService[] = "org.freedesktop.ModemManager1";
const RpcIdentifier CellularTest::kDBusPath(
    "/org/freedesktop/ModemManager1/Modem/0");
const char CellularTest::kTestCarrier[] = "The Cellular Carrier";
const char CellularTest::kTestCarrierSPN[] = "Home Provider";
const char CellularTest::kMEID[] = "01234567EF8901";
const char CellularTest::kIMEI[] = "987654321098765";
const char CellularTest::kIMSI[] = "123456789012345";
const char CellularTest::kMSISDN[] = "12345678901";
const char CellularTest::kTestMobileProviderDBPath[] =
    "provider_db_unittest.bfd";
const Stringmaps CellularTest::kTestNetworksCellular = {
    {{kStatusProperty, "available"},
     {kNetworkIdProperty, "0000"},
     {kLongNameProperty, "some_long_name"},
     {kShortNameProperty, "short"}}};
const int CellularTest::kStrength = 90;

TEST_P(CellularTest, GetStorageIdentifier) {
  EXPECT_EQ("device_usb0", device_->GetStorageIdentifier());
}

TEST_P(CellularTest, HomeProviderServingOperator) {
  // Test that the the home provider information is correctly updated under
  // different scenarios w.r.t. information about the mobile network operators.
  SetMockMobileOperatorInfoObjects();
  CHECK(mock_home_provider_info_);
  CHECK(mock_serving_operator_info_);
  Stringmap home_provider;
  Stringmap serving_operator;

  InitCapability3gppProxies();

  // (1) Neither home provider nor serving operator known.
  EXPECT_CALL(*mock_home_provider_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(false));

  device_->CreateServices();

  home_provider = device_->home_provider();
  VerifyOperatorMap(home_provider, "", "", "");
  serving_operator = device_->service_->serving_operator();
  VerifyOperatorMap(serving_operator, "", "", "");
  Mock::VerifyAndClearExpectations(mock_home_provider_info_);
  Mock::VerifyAndClearExpectations(mock_serving_operator_info_);
  device_->DestroyAllServices();

  // (2) serving operator known.
  // When home provider is not known, serving operator proxies in.
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_serving_operator_info_, mccmnc())
      .WillRepeatedly(ReturnRef(kServingOperatorCode));
  EXPECT_CALL(*mock_serving_operator_info_, operator_name())
      .WillRepeatedly(ReturnRef(kServingOperatorName));
  EXPECT_CALL(*mock_serving_operator_info_, country())
      .WillRepeatedly(ReturnRef(kServingOperatorCountry));

  device_->CreateServices();

  home_provider = device_->home_provider();
  VerifyOperatorMap(home_provider, kServingOperatorCode, kServingOperatorName,
                    kServingOperatorCountry);
  serving_operator = device_->service_->serving_operator();
  VerifyOperatorMap(serving_operator, kServingOperatorCode,
                    kServingOperatorName, kServingOperatorCountry);
  Mock::VerifyAndClearExpectations(mock_home_provider_info_);
  Mock::VerifyAndClearExpectations(mock_serving_operator_info_);
  device_->DestroyAllServices();

  // (3) home provider known.
  // When serving operator is not known, home provider proxies in.
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mock_home_provider_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_home_provider_info_, mccmnc())
      .WillRepeatedly(ReturnRef(kHomeProviderCode));
  EXPECT_CALL(*mock_home_provider_info_, operator_name())
      .WillRepeatedly(ReturnRef(kHomeProviderName));
  EXPECT_CALL(*mock_home_provider_info_, country())
      .WillRepeatedly(ReturnRef(kHomeProviderCountry));

  device_->CreateServices();

  home_provider = device_->home_provider();
  VerifyOperatorMap(home_provider, kHomeProviderCode, kHomeProviderName,
                    kHomeProviderCountry);
  serving_operator = device_->service_->serving_operator();
  VerifyOperatorMap(serving_operator, kHomeProviderCode, kHomeProviderName,
                    kHomeProviderCountry);
  Mock::VerifyAndClearExpectations(mock_home_provider_info_);
  Mock::VerifyAndClearExpectations(mock_serving_operator_info_);
  device_->DestroyAllServices();

  // (4) Serving operator known, home provider known.
  EXPECT_CALL(*mock_home_provider_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_home_provider_info_, mccmnc())
      .WillRepeatedly(ReturnRef(kHomeProviderCode));
  EXPECT_CALL(*mock_home_provider_info_, operator_name())
      .WillRepeatedly(ReturnRef(kHomeProviderName));
  EXPECT_CALL(*mock_home_provider_info_, country())
      .WillRepeatedly(ReturnRef(kHomeProviderCountry));
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_serving_operator_info_, mccmnc())
      .WillRepeatedly(ReturnRef(kServingOperatorCode));
  EXPECT_CALL(*mock_serving_operator_info_, operator_name())
      .WillRepeatedly(ReturnRef(kServingOperatorName));
  EXPECT_CALL(*mock_serving_operator_info_, country())
      .WillRepeatedly(ReturnRef(kServingOperatorCountry));

  device_->CreateServices();

  home_provider = device_->home_provider();
  VerifyOperatorMap(home_provider, kHomeProviderCode, kHomeProviderName,
                    kHomeProviderCountry);
  serving_operator = device_->service_->serving_operator();
  VerifyOperatorMap(serving_operator, kServingOperatorCode,
                    kServingOperatorName, kServingOperatorCountry);
}

TEST_P(CellularTest, SetPrimarySimProperties) {
  // The default storage identifier should always be cellular_{iccid}
  Cellular::SimProperties sim_properties;
  sim_properties.eid = "test_eid";
  sim_properties.iccid = "test_iccid";
  sim_properties.imsi = "test_imsi";

  auto* adaptor = static_cast<DeviceMockAdaptor*>(device_->adaptor());
  EXPECT_CALL(*adaptor, EmitStringChanged(kEidProperty, sim_properties.eid))
      .Times(1);
  EXPECT_CALL(*adaptor, EmitStringChanged(kIccidProperty, sim_properties.iccid))
      .Times(1);
  EXPECT_CALL(*adaptor, EmitStringChanged(kImsiProperty, sim_properties.imsi))
      .Times(1);
  CallSetPrimarySimProperties(sim_properties);
  EXPECT_EQ("test_eid", device_->eid());
  EXPECT_EQ("test_iccid", device_->iccid());
  EXPECT_EQ("test_imsi", device_->imsi());
}

TEST_P(CellularTest, SetSimSlotProperties) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }
  std::vector<Cellular::SimProperties> slot_properties = {
      {0, "iccid1", "eid1", "operator_id1", "spn1", "imsi1"},
      {1, "iccid2", "eid2", "operator_id2", "spn2", "imsi2"},
  };
  KeyValueStore expected1, expected2;
  expected1.Set(kSIMSlotInfoEID, slot_properties[0].eid);
  expected1.Set(kSIMSlotInfoICCID, slot_properties[0].iccid);
  expected1.Set(kSIMSlotInfoPrimary, false);
  expected2.Set(kSIMSlotInfoEID, slot_properties[1].eid);
  expected2.Set(kSIMSlotInfoICCID, slot_properties[1].iccid);
  expected2.Set(kSIMSlotInfoPrimary, true);

  KeyValueStores expected;
  expected.push_back(expected1);
  expected.push_back(expected2);
  EXPECT_CALL(*static_cast<DeviceMockAdaptor*>(device_->adaptor()),
              EmitKeyValueStoresChanged(kSIMSlotInfoProperty, expected))
      .Times(1);
  CallSetSimSlotProperties(slot_properties, 1u);

  // Set the primary slot to 0 and ensure that a SimSlots properties change is
  // emitted.
  expected1.Set(kSIMSlotInfoPrimary, true);
  expected2.Set(kSIMSlotInfoPrimary, false);
  expected.clear();
  expected.push_back(expected1);
  expected.push_back(expected2);
  EXPECT_CALL(*static_cast<DeviceMockAdaptor*>(device_->adaptor()),
              EmitKeyValueStoresChanged(kSIMSlotInfoProperty, expected))
      .Times(1);
  CallSetSimSlotProperties(slot_properties, 0u);
}

TEST_P(CellularTest, StorageIdentifier) {
  // The default storage identifier should always be cellular_{iccid}
  InitCapability3gppProxies();
  Cellular::SimProperties sim_properties;
  sim_properties.iccid = "test_iccid";
  sim_properties.imsi = "test_imsi";
  CallSetPrimarySimProperties(sim_properties);
  device_->CreateServices();
  EXPECT_EQ("cellular_test_iccid", device_->service()->GetStorageIdentifier());
  device_->DestroyAllServices();
}

TEST_P(CellularTest, Connect) {
  Error error;
  device_->set_state_for_testing(Cellular::State::kModemStarted);
  SetService();
  device_->set_state_for_testing(Cellular::State::kConnected);
  device_->Connect(device_->service().get(), &error);
  EXPECT_EQ(Error::kAlreadyConnected, error.type());
  error.Populate(Error::kSuccess);

  error.Reset();
  device_->set_state_for_testing(Cellular::State::kLinked);
  device_->Connect(device_->service().get(), &error);
  EXPECT_EQ(Error::kAlreadyConnected, error.type());

  error.Reset();
  device_->set_state_for_testing(Cellular::State::kModemStarted);
  device_->Connect(device_->service().get(), &error);
  EXPECT_EQ(Error::kNotRegistered, error.type());

  error.Reset();
  device_->set_state_for_testing(Cellular::State::kDisabled);
  device_->Connect(device_->service().get(), &error);
  EXPECT_EQ(Error::kOperationFailed, error.type());

  error.Reset();
  device_->set_state_for_testing(Cellular::State::kRegistered);
  device_->service_->allow_roaming_ = false;
  device_->service_->roaming_state_ = kRoamingStateRoaming;
  device_->Connect(device_->service().get(), &error);
  EXPECT_EQ(Error::kNotOnHomeNetwork, error.type());

  // Check that connect fails if policy restricts roaming
  error.Reset();
  device_->service_->allow_roaming_ = true;
  device_->policy_allow_roaming_ = false;
  device_->Connect(device_->service().get(), &error);
  EXPECT_EQ(Error::kNotOnHomeNetwork, error.type());
  device_->policy_allow_roaming_ = true;

  error.Populate(Error::kSuccess);
  EXPECT_CALL(device_info_, GetFlags(device_->interface_index(), _))
      .Times(3)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mm1_simple_proxy_,
              Connect(_, _, CellularCapability::kTimeoutConnect))
      .Times(3)
      .WillRepeatedly(Invoke(this, &CellularTest::InvokeConnect));
  SetCapability3gppModemSimpleProxy();
  device_->service_->roaming_state_ = kRoamingStateHome;
  device_->set_state_for_testing(Cellular::State::kRegistered);
  device_->Connect(device_->service().get(), &error);
  EXPECT_TRUE(error.IsSuccess());
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(Cellular::State::kConnected, device_->state());

  device_->service_->allow_roaming_ = true;
  device_->service_->roaming_state_ = kRoamingStateRoaming;
  device_->set_state_for_testing(Cellular::State::kRegistered);
  device_->Connect(device_->service().get(), &error);
  EXPECT_TRUE(error.IsSuccess());
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(Cellular::State::kConnected, device_->state());

  // Check that provider_requires_roaming_ will override all other roaming
  // settings
  device_->service_->allow_roaming_ = false;
  device_->policy_allow_roaming_ = false;
  device_->provider_requires_roaming_ = true;
  device_->service_->roaming_state_ = kRoamingStateRoaming;
  device_->set_state_for_testing(Cellular::State::kRegistered);
  device_->Connect(device_->service().get(), &error);
  EXPECT_TRUE(error.IsSuccess());
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(Cellular::State::kConnected, device_->state());
}

TEST_P(CellularTest, SimSlotSwitch) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // Only provide a SIM in the second slot. Setup capability with all sim
  // properties.
  std::vector<Cellular::SimProperties> slot_properties = {
      {0, "", "eid1", "", "", ""},
      {1, "unknown-iccid", "", "", "", ""},
  };
  base::flat_map<RpcIdentifier, Cellular::SimProperties> sim_properties;
  sim_properties[RpcIdentifier("sim_path1")] = slot_properties[0];
  sim_properties[RpcIdentifier("sim_path2")] = slot_properties[1];
  GetCapability3gpp()->set_sim_properties_for_testing(sim_properties);

  // Simulate creation of capability and enabling the modem.
  mm1::MockModemProxy* mm1_modem_proxy = SetModemProxyExpectations();
  EXPECT_CALL(*mm1_modem_proxy, SetPrimarySimSlot(2u, _, _));
  EXPECT_CALL(*mm1_modem_proxy, Enable(true, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeEnable));
  InitCapability3gppProxies();
  device_->SetEnabled(true);
  device_->set_state_for_testing(Cellular::State::kModemStarted);
  CallSetSimProperties(slot_properties, 0u);

  // Call Connect on secondary slot
  Error error;
  device_->Connect(
      cellular_service_provider_.FindService("unknown-iccid").get(), &error);
  EXPECT_TRUE(error.IsSuccess());
  dispatcher_.DispatchPendingEvents();

  // Simulate MM state changes that occur when a slot switch occurs
  device_->OnModemStateChanged(Cellular::kModemStateDisabling);
  dispatcher_.DispatchPendingEvents();
  device_->OnModemStateChanged(Cellular::kModemStateDisabled);
  dispatcher_.DispatchPendingEvents();
  device_->OnModemDestroyed();
  // Check that existing services aren't destroyed even though the modem DBus
  // object is
  EXPECT_TRUE(cellular_service_provider_.FindService("unknown-iccid"));

  // Simulate MM changes that occur when a new MM DBus object appears after a
  // slot switch
  device_->UpdateModemProperties(kDBusPath, "");
  device_->OnModemStateChanged(Cellular::kModemStateDisabled);
  slot_properties[1].iccid = "8900000000000000000",
  GetCapability3gpp()->set_sim_properties_for_testing(sim_properties);
  CallSetSimProperties(slot_properties, 1u);
  device_->set_state_for_testing(Cellular::State::kModemStarted);
  device_->OnModemStateChanged(Cellular::kModemStateEnabling);
  dispatcher_.DispatchPendingEvents();
  device_->OnModemStateChanged(Cellular::kModemStateEnabled);
  dispatcher_.DispatchPendingEvents();
  device_->OnModemStateChanged(Cellular::kModemStateRegistered);
  dispatcher_.DispatchPendingEvents();

  // Cellular should call Connect once MM's 3GPP interface updates it's
  // registration state
  SetCapability3gppRegistrationState(MM_MODEM_3GPP_REGISTRATION_STATE_HOME);
  PopulateProxies();
  EXPECT_CALL(*mm1_simple_proxy_, Connect(_, _, _));
  SetCapability3gppModemSimpleProxy();
  device_->HandleNewRegistrationState();
  constexpr base::TimeDelta kTestTimeout =
      Cellular::kPendingConnectDelay + base::Seconds(10);
  dispatcher_.task_environment().FastForwardBy(kTestTimeout);
}

TEST_P(CellularTest, Disconnect) {
  Error error;
  device_->set_state_for_testing(Cellular::State::kRegistered);
  device_->Disconnect(&error, "in test");
  EXPECT_EQ(Error::kNotConnected, error.type());
  error.Reset();

  device_->set_state_for_testing(Cellular::State::kConnected);
  EXPECT_CALL(*mm1_simple_proxy_,
              Disconnect(_, _, CellularCapability::kTimeoutDisconnect))
      .WillOnce(Invoke(this, &CellularTest::InvokeDisconnect));
  SetCapability3gppModemSimpleProxy();
  device_->Disconnect(&error, "in test");
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(Cellular::State::kRegistered, device_->state());
}

TEST_P(CellularTest, DisconnectFailure) {
  // Test the case where the underlying modem state is set
  // to disconnecting, but shill thinks it's still connected
  Error error;
  device_->set_state_for_testing(Cellular::State::kConnected);
  EXPECT_CALL(*mm1_simple_proxy_,
              Disconnect(_, _, CellularCapability::kTimeoutDisconnect))
      .Times(2)
      .WillRepeatedly(Invoke(this, &CellularTest::InvokeDisconnectFail));
  SetCapability3gppModemSimpleProxy();
  device_->set_modem_state_for_testing(Cellular::kModemStateDisconnecting);
  device_->Disconnect(&error, "in test");
  EXPECT_EQ(Cellular::State::kConnected, device_->state());

  device_->set_modem_state_for_testing(Cellular::kModemStateConnected);
  device_->Disconnect(&error, "in test");
  EXPECT_EQ(Cellular::State::kRegistered, device_->state());
}

TEST_P(CellularTest, ConnectFailure) {
  SetRegisteredWithService();
  ASSERT_EQ(Service::kStateIdle, device_->service_->state());
  EXPECT_CALL(*mm1_simple_proxy_,
              Connect(_, _, CellularCapability::kTimeoutConnect))
      .WillOnce(Invoke(this, &CellularTest::InvokeConnectFail));
  SetCapability3gppModemSimpleProxy();
  Error error;
  device_->Connect(device_->service().get(), &error);
  EXPECT_EQ(Service::kStateFailure, device_->service_->state());
}

TEST_P(CellularTest, ConnectWhileInhibited) {
  SetRegisteredWithService();
  EXPECT_CALL(*mm1_simple_proxy_, Connect(_, _, _)).Times(0);
  SetCapability3gppModemSimpleProxy();

  // Connect while inhibited should fail.
  SetInhibited(true);
  Error error;
  device_->Connect(device_->service().get(), &error);
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(Error::kWrongState, error.type());
}

TEST_P(CellularTest, PendingConnect) {
  CellularService* service = SetRegisteredWithService();
  EXPECT_CALL(*mm1_simple_proxy_, Connect(_, _, _))
      .WillRepeatedly(Invoke(this, &CellularTest::InvokeConnect));
  SetCapability3gppModemSimpleProxy();

  // Connect while scanning should set a pending connect.
  SetScanning(true);
  Error error;
  service->Connect(&error, "test");
  EXPECT_TRUE(error.IsSuccess());
  dispatcher_.DispatchPendingEvents();
  EXPECT_NE(device_->state(), Cellular::State::kConnected);
  EXPECT_EQ(device_->connect_pending_iccid(), service->iccid());

  // Setting scanning to false should connect to the pending iccid.
  SetScanning(false);
  // Fast forward the task environment by the pending connect delay plus
  // time to complete the connect.
  constexpr base::TimeDelta kTestTimeout =
      Cellular::kPendingConnectDelay + base::Seconds(10);
  dispatcher_.task_environment().FastForwardBy(kTestTimeout);
  EXPECT_EQ(device_->state(), Cellular::State::kConnected);
  EXPECT_TRUE(device_->connect_pending_iccid().empty());
}

TEST_P(CellularTest, PendingDisconnect) {
  CellularService* service = SetRegisteredWithService();
  EXPECT_CALL(*mm1_simple_proxy_, Connect(_, _, _))
      .WillRepeatedly(Invoke(this, &CellularTest::InvokeConnect));
  SetCapability3gppModemSimpleProxy();

  // Connect while scanning should set a pending connect.
  SetScanning(true);
  Error error;
  service->Connect(&error, "test");
  EXPECT_TRUE(error.IsSuccess());
  dispatcher_.DispatchPendingEvents();
  EXPECT_NE(device_->state(), Cellular::State::kConnected);
  EXPECT_EQ(device_->connect_pending_iccid(), service->iccid());

  // Disconnecting from the service should cancel the pending connect.
  service->Disconnect(&error, "test");
  dispatcher_.DispatchPendingEvents();
  EXPECT_TRUE(device_->connect_pending_iccid().empty());
}

TEST_P(CellularTest, LinkEventInterfaceDown) {
  // If the network interface goes down, Cellular::LinkEvent should
  // drop the connection and destroy any services.
  device_->set_state_for_testing(Cellular::State::kLinked);
  CellularService* service = SetService();
  ASSERT_TRUE(service);
  EXPECT_EQ(device_->service(), service);
  device_->LinkEvent(0, 0);  // flags doesn't contain IFF_UP
  EXPECT_EQ(device_->service(), nullptr);
}

TEST_P(CellularTest, UseNoArpGateway) {
  EXPECT_CALL(dhcp_provider_, CreateIPv4Config(kTestDeviceName, _, false, _, _))
      .WillOnce(
          InvokeWithoutArgs([this]() { return CreateMockDHCPController(); }));
  device_->AcquireIPConfig();
}

TEST_P(CellularTest, ModemStateChangeValidConnected) {
  device_->set_state_for_testing(Cellular::State::kEnabled);
  device_->set_modem_state_for_testing(Cellular::kModemStateConnecting);
  SetService();
  device_->OnModemStateChanged(Cellular::kModemStateConnected);
  EXPECT_EQ(Cellular::State::kConnected, device_->state());
}

TEST_P(CellularTest, ModemStateChangeLostRegistration) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  CellularCapability3gpp* capability = GetCapability3gpp();
  capability->registration_state_ = MM_MODEM_3GPP_REGISTRATION_STATE_HOME;
  EXPECT_TRUE(capability->IsRegistered());
  device_->set_modem_state_for_testing(Cellular::kModemStateRegistered);
  device_->OnModemStateChanged(Cellular::kModemStateEnabled);
  EXPECT_FALSE(capability->IsRegistered());
}

TEST_P(CellularTest, StartModemCallback) {
  EXPECT_CALL(*this, TestCallback(IsSuccess()));
  device_->set_state_for_testing(Cellular::State::kEnabled);
  CallStartModemCallback(Error(Error::kSuccess));
  EXPECT_EQ(device_->state(), Cellular::State::kModemStarted);
}

TEST_P(CellularTest, StartModemCallbackFail) {
  EXPECT_CALL(*this, TestCallback(IsFailure()));
  device_->set_state_for_testing(Cellular::State::kEnabled);
  CallStartModemCallback(Error(Error::kOperationFailed));
  EXPECT_EQ(device_->state(), Cellular::State::kEnabled);
}

TEST_P(CellularTest, StopModemCallback) {
  EXPECT_CALL(*this, TestCallback(IsSuccess()));
  SetMockService();
  CallStopModemCallback(Error(Error::kSuccess));
  EXPECT_EQ(device_->state(), Cellular::State::kDisabled);
  EXPECT_EQ(device_->service(), nullptr);
}

TEST_P(CellularTest, StopModemCallbackFail) {
  EXPECT_CALL(*this, TestCallback(IsFailure()));
  SetMockService();
  CallStopModemCallback(Error(Error::kOperationFailed));
  EXPECT_EQ(device_->state(), Cellular::State::kDisabled);
  EXPECT_EQ(device_->service(), nullptr);
}

TEST_P(CellularTest, SetPolicyAllowRoaming) {
  EXPECT_TRUE(device_->policy_allow_roaming_);
  EXPECT_CALL(manager_, UpdateDevice(_));
  Error error;
  device_->SetPolicyAllowRoaming(false, &error);
  EXPECT_TRUE(error.IsSuccess());
  error.Reset();
  EXPECT_FALSE(device_->GetPolicyAllowRoaming(&error));
  EXPECT_TRUE(error.IsSuccess());
}

TEST_P(CellularTest, SetUseAttachApn) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }
  mm1::MockModemProxy* mm1_modem_proxy = mm1_modem_proxy_.get();
  mm1::MockModemModem3gppProfileManagerProxy*
      mm1_modem_3gpp_profile_manager_proxy =
          SetModem3gppProfileManagerProxyExpectations();
  InitCapability3gppProxies();
  // initial state: modem enabled, attach APN disabled
  EXPECT_CALL(*mm1_modem_proxy, Enable(true, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeEnable));
  EXPECT_CALL(*mm1_modem_3gpp_profile_manager_proxy, List(_, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeList));
  device_->SetEnabled(true);
  EXPECT_FALSE(device_->use_attach_apn_);

  // The modem is going to be disabled then enabled
  // in order to use the new attach APN.
  EXPECT_CALL(*mm1_modem_proxy, Enable(false, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeEnable));
  EXPECT_CALL(*mm1_modem_proxy, SetPowerState(_, _, _, _)).Times(0);
  // It will call again Enable(true,...) but with another proxy as the previous
  // one was released at the end of the Disabling process.

  Error error;
  device_->SetUseAttachApn(true, &error);
  dispatcher_.DispatchPendingEvents();  // StopModem yields a deferred task
  EXPECT_TRUE(error.IsSuccess());
  // We have (re)enabled the modem but as the final Enable() didn't invoke its
  // callback for the reason stated above we won't reach the final
  // kModemStarted state.
  EXPECT_EQ(device_->state(), Cellular::State::kModemStarting);
  EXPECT_TRUE(device_->use_attach_apn_);
}

TEST_P(CellularTest, SetInhibited) {
  PopulateProxies();

  // Invoke Cellular::StartModemCallback() to simulate the modem starting, which
  // is required before SetInhibit can succeed.
  EXPECT_CALL(*this, TestCallback(IsSuccess()));
  CallStartModemCallback(Error(Error::kSuccess));

  EXPECT_FALSE(device_->inhibited());
  SetInhibited(true);
  EXPECT_TRUE(device_->inhibited());
}

class TestRpcTaskDelegate : public RpcTaskDelegate,
                            public base::SupportsWeakPtr<TestRpcTaskDelegate> {
 public:
  virtual void GetLogin(std::string* user, std::string* password) {}
  virtual void Notify(const std::string& reason,
                      const std::map<std::string, std::string>& dict) {}
};

TEST_P(CellularTest, LinkEventUpWithPPP) {
  // If PPP is running, don't run DHCP as well.
  TestRpcTaskDelegate task_delegate;
  base::Callback<void(pid_t, int)> death_callback;
  auto mock_task = std::make_unique<NiceMock<MockExternalTask>>(
      modem_info_.control_interface(), &process_manager_,
      task_delegate.AsWeakPtr(), death_callback);
  EXPECT_CALL(*mock_task, OnDelete()).Times(AnyNumber());
  device_->ppp_task_ = std::move(mock_task);
  device_->set_state_for_testing(Cellular::State::kConnected);
  EXPECT_CALL(dhcp_provider_, CreateIPv4Config(kTestDeviceName, _, _, _, _))
      .Times(0);
  device_->LinkEvent(IFF_UP, 0);
}

TEST_P(CellularTest, LinkEventUpWithoutPPP) {
  // If PPP is not running, fire up DHCP.
  device_->set_state_for_testing(Cellular::State::kConnected);
  EXPECT_CALL(dhcp_provider_, CreateIPv4Config(kTestDeviceName, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        auto controller = CreateMockDHCPController();
        EXPECT_CALL(*controller, RequestIP());
        EXPECT_CALL(*controller, ReleaseIP(_)).Times(AnyNumber());
        return controller;
      }));
  device_->LinkEvent(IFF_UP, 0);
}

TEST_P(CellularTest, StartPPP) {
  const int kPID = 234;
  EXPECT_EQ(nullptr, device_->ppp_task_);
  StartPPP(kPID);
}

TEST_P(CellularTest, StartPPPAlreadyStarted) {
  const int kPID = 234;
  StartPPP(kPID);

  const int kPID2 = 235;
  StartPPP(kPID2);
}

TEST_P(CellularTest, StartPPPAfterEthernetUp) {
  CellularService* service(SetService());
  device_->set_state_for_testing(Cellular::State::kLinked);
  device_->set_dhcp_controller_for_testing(CreateMockDHCPController());
  device_->SelectService(service);
  const int kPID = 234;
  EXPECT_EQ(nullptr, device_->ppp_task_);
  StartPPP(kPID);
  EXPECT_EQ(Cellular::State::kLinked, device_->state());
}

TEST_P(CellularTest, GetLogin) {
  // Doesn't crash when there is no service.
  std::string username_to_pppd;
  std::string password_to_pppd;
  EXPECT_FALSE(device_->service());
  device_->GetLogin(&username_to_pppd, &password_to_pppd);

  // Provides expected username and password in normal case.
  const char kFakeUsername[] = "fake-user";
  const char kFakePassword[] = "fake-password";
  CellularService& service(*SetService());
  service.ppp_username_ = kFakeUsername;
  service.ppp_password_ = kFakePassword;
  device_->GetLogin(&username_to_pppd, &password_to_pppd);
}

TEST_P(CellularTest, Notify) {
  // Common setup.
  const int kPID = 91;
  SetMockService();
  StartPPP(kPID);

  const std::map<std::string, std::string> kEmptyArgs;
  device_->Notify(kPPPReasonAuthenticating, kEmptyArgs);
  EXPECT_TRUE(device_->is_ppp_authenticating_);
  device_->Notify(kPPPReasonAuthenticated, kEmptyArgs);
  EXPECT_FALSE(device_->is_ppp_authenticating_);

  // Normal connect.
  const std::string ifname1 = "fake-device";
  const int ifindex1 = 1;
  auto ppp_device1 = new MockPPPDevice(&manager_, ifname1, ifindex1);
  std::map<std::string, std::string> ppp_config;
  ppp_config[kPPPInterfaceName] = ifname1;
  EXPECT_CALL(device_info_, GetIndex(ifname1)).WillOnce(Return(ifindex1));
  EXPECT_CALL(device_info_, CreatePPPDevice(_, StrEq(ifname1), ifindex1))
      .WillOnce(Return(ppp_device1));
  EXPECT_CALL(device_info_,
              RegisterDevice(static_cast<DeviceRefPtr>(ppp_device1)));
  EXPECT_CALL(*ppp_device1, SetEnabled(true));
  EXPECT_CALL(*ppp_device1,
              SelectService(static_cast<ServiceRefPtr>(device_->service_)));
  EXPECT_CALL(*ppp_device1,
              UpdateIPConfigFromPPP(ppp_config, false /* blackhole_ipv6 */));
  device_->Notify(kPPPReasonConnect, ppp_config);
  Mock::VerifyAndClearExpectations(&device_info_);
  Mock::VerifyAndClearExpectations(ppp_device1);

  // Re-connect on same network device: if pppd sends us multiple connect
  // events, we behave rationally.
  EXPECT_CALL(device_info_, GetIndex(ifname1)).WillOnce(Return(ifindex1));
  EXPECT_CALL(device_info_, CreatePPPDevice(_, _, _)).Times(0);
  EXPECT_CALL(device_info_, RegisterDevice(_)).Times(0);
  EXPECT_CALL(*ppp_device1, SetEnabled(true));
  EXPECT_CALL(*ppp_device1,
              SelectService(static_cast<ServiceRefPtr>(device_->service_)));
  EXPECT_CALL(*ppp_device1,
              UpdateIPConfigFromPPP(ppp_config, false /* blackhole_ipv6 */));
  device_->Notify(kPPPReasonConnect, ppp_config);
  Mock::VerifyAndClearExpectations(&device_info_);
  Mock::VerifyAndClearExpectations(ppp_device1);

  // Re-connect on new network device: if we still have the PPPDevice
  // from a prior connect, this new connect should DTRT. This is
  // probably an unlikely case.
  const std::string ifname2 = "fake-device2";
  const int ifindex2 = 2;
  auto ppp_device2 = new MockPPPDevice(&manager_, ifname2, ifindex2);
  std::map<std::string, std::string> ppp_config2;
  ppp_config2[kPPPInterfaceName] = ifname2;
  EXPECT_CALL(device_info_, GetIndex(ifname2)).WillOnce(Return(ifindex2));
  EXPECT_CALL(device_info_, CreatePPPDevice(_, StrEq(ifname2), ifindex2))
      .WillOnce(Return(ppp_device2));
  EXPECT_CALL(device_info_,
              RegisterDevice(static_cast<DeviceRefPtr>(ppp_device2)));
  EXPECT_CALL(*ppp_device1, SelectService(ServiceRefPtr(nullptr)));
  EXPECT_CALL(*ppp_device2, SetEnabled(true));
  EXPECT_CALL(*ppp_device2,
              SelectService(static_cast<ServiceRefPtr>(device_->service_)));
  EXPECT_CALL(*ppp_device2,
              UpdateIPConfigFromPPP(ppp_config2, false /* blackhole_ipv6 */));
  device_->Notify(kPPPReasonConnect, ppp_config2);
  Mock::VerifyAndClearExpectations(&device_info_);
  Mock::VerifyAndClearExpectations(ppp_device1);
  Mock::VerifyAndClearExpectations(ppp_device2);

  // Disconnect should report no failure, since we had a
  // Notify(kPPPReasonAuthenticated, ...) and got no error from pppd.
  EXPECT_CALL(*ppp_device2, SetServiceFailure(Service::kFailureNone));
  device_->OnPPPDied(kPID, EXIT_OK);
  EXPECT_EQ(nullptr, device_->ppp_task_);

  // |Cellular::ppp_task_| is destroyed on the task loop. Must dispatch once to
  // cleanup.
  dispatcher_.DispatchPendingEvents();
}

TEST_P(CellularTest, PPPConnectionFailedBeforeAuth) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // Test that we properly set Service state in the case where pppd
  // disconnects before authenticating (as opposed to the Notify test,
  // where pppd disconnects after connecting).
  const int kPID = 52;
  const std::map<std::string, std::string> kEmptyArgs;
  MockCellularService* service = SetMockService();
  StartPPP(kPID);

  ExpectDisconnectCapability3gpp();
  EXPECT_CALL(*service, SetFailure(Service::kFailureUnknown));
  device_->OnPPPDied(kPID, EXIT_FATAL_ERROR);
  EXPECT_EQ(nullptr, device_->ppp_task_);
  VerifyDisconnect();

  // |Cellular::ppp_task_| is destroyed on the task loop. Must dispatch once to
  // cleanup.
  dispatcher_.DispatchPendingEvents();
}

TEST_P(CellularTest, PPPConnectionFailedDuringAuth) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // Test that we properly set Service state in the case where pppd
  // disconnects during authentication (as opposed to the Notify test,
  // where pppd disconnects after connecting).
  const int kPID = 52;
  const std::map<std::string, std::string> kEmptyArgs;
  MockCellularService* service = SetMockService();
  StartPPP(kPID);

  ExpectDisconnectCapability3gpp();
  // Even if pppd gives a generic error, if we know that the failure occurred
  // during authentication, we will consider it an auth error.
  EXPECT_CALL(*service, SetFailure(Service::kFailurePPPAuth));
  device_->Notify(kPPPReasonAuthenticating, kEmptyArgs);
  device_->OnPPPDied(kPID, EXIT_FATAL_ERROR);
  EXPECT_EQ(nullptr, device_->ppp_task_);
  VerifyDisconnect();

  // |Cellular::ppp_task_| is destroyed on the task loop. Must dispatch once to
  // cleanup.
  dispatcher_.DispatchPendingEvents();
}

TEST_P(CellularTest, PPPConnectionFailedAfterAuth) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // Test that we properly set Service state in the case where pppd
  // disconnects after authenticating, but before connecting (as
  // opposed to the Notify test, where pppd disconnects after
  // connecting).
  const int kPID = 52;
  const std::map<std::string, std::string> kEmptyArgs;
  MockCellularService* service = SetMockService();
  StartPPP(kPID);

  EXPECT_CALL(*service, SetFailure(Service::kFailureUnknown));
  ExpectDisconnectCapability3gpp();
  device_->Notify(kPPPReasonAuthenticating, kEmptyArgs);
  device_->Notify(kPPPReasonAuthenticated, kEmptyArgs);
  device_->OnPPPDied(kPID, EXIT_FATAL_ERROR);
  EXPECT_EQ(nullptr, device_->ppp_task_);
  VerifyDisconnect();

  // |Cellular::ppp_task_| is destroyed on the task loop. Must dispatch once to
  // cleanup.
  dispatcher_.DispatchPendingEvents();
}

TEST_P(CellularTest, PPPConnectionFailedAfterConnect) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // Test that we properly set Service state in the case where pppd fails after
  // connecting (as opposed to the Notify test, where pppd disconnects normally
  // after connecting).
  const int kPID = 52;
  const std::map<std::string, std::string> kEmptyArgs;
  MockCellularService* service = SetMockService();
  StartPPP(kPID);

  const std::string ifname = "ppp0";
  const int ifindex = 1;
  auto ppp_device = new MockPPPDevice(&manager_, ifname, ifindex);
  std::map<std::string, std::string> ppp_config;
  ppp_config[kPPPInterfaceName] = ifname;
  EXPECT_CALL(device_info_, GetIndex("ppp0")).WillOnce(Return(ifindex));
  EXPECT_CALL(device_info_, CreatePPPDevice(_, StrEq(ifname), ifindex))
      .WillOnce(Return(ppp_device));
  EXPECT_CALL(device_info_,
              RegisterDevice(static_cast<DeviceRefPtr>(ppp_device)));
  EXPECT_CALL(*ppp_device, SetEnabled(true));
  EXPECT_CALL(*ppp_device, SelectService(static_cast<ServiceRefPtr>(service)));
  EXPECT_CALL(*ppp_device,
              UpdateIPConfigFromPPP(_, false /* blackhole_ipv6 */));
  EXPECT_CALL(*ppp_device, SetServiceFailure(Service::kFailureUnknown));
  ExpectDisconnectCapability3gpp();
  device_->Notify(kPPPReasonAuthenticating, ppp_config);
  device_->Notify(kPPPReasonAuthenticated, ppp_config);
  device_->Notify(kPPPReasonConnect, ppp_config);
  device_->OnPPPDied(kPID, EXIT_FATAL_ERROR);
  EXPECT_EQ(nullptr, device_->ppp_task_);
  VerifyDisconnect();

  // |Cellular::ppp_task_| is destroyed on the task loop. Must dispatch once to
  // cleanup.
  dispatcher_.DispatchPendingEvents();
}

TEST_P(CellularTest, OnPPPDied) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  const int kPID = 1234;
  const int kExitStatus = 5;
  ExpectDisconnectCapability3gpp();
  device_->OnPPPDied(kPID, kExitStatus);
  VerifyDisconnect();
}

TEST_P(CellularTest, OnPPPDiedCleanupDevice) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // Test that OnPPPDied causes the ppp_device_ reference to be dropped.
  const int kPID = 123;
  const int kExitStatus = 5;
  StartPPP(kPID);
  FakeUpConnectedPPP();
  ExpectDisconnectCapability3gpp();
  device_->OnPPPDied(kPID, kExitStatus);
  VerifyPPPStopped();

  // |Cellular::ppp_task_| is destroyed on the task loop. Must dispatch once to
  // cleanup.
  dispatcher_.DispatchPendingEvents();
}

TEST_P(CellularTest, DropConnection) {
  auto dhcp_controller = CreateMockDHCPController();
  auto* dhcp_controller_ptr = dhcp_controller.get();
  device_->set_dhcp_controller_for_testing(std::move(dhcp_controller));
  EXPECT_CALL(*dhcp_controller_ptr, ReleaseIP(_));
  device_->DropConnection();
  Mock::VerifyAndClearExpectations(dhcp_controller_ptr);  // verify before dtor
  EXPECT_FALSE(device_->ipconfig());
}

TEST_P(CellularTest, DropConnectionPPP) {
  scoped_refptr<MockPPPDevice> ppp_device(
      new MockPPPDevice(&manager_, "ppp0", 123));
  // Calling device_->DropConnection() explicitly will trigger
  // DestroyCapability() which also triggers a (redundant and harmless)
  // ppp_device->DropConnection() call.
  EXPECT_CALL(*ppp_device, DropConnection()).Times(AtLeast(1));
  device_->ppp_device_ = ppp_device;
  device_->DropConnection();
}

TEST_P(CellularTest, ChangeServiceState) {
  MockCellularService* service(SetMockService());
  EXPECT_CALL(*service, SetState(_));
  EXPECT_CALL(*service, SetFailure(_));
  EXPECT_CALL(*service, SetFailureSilent(_));
  ON_CALL(*service, state()).WillByDefault(Return(Service::kStateUnknown));

  // Without PPP, these should be handled by our selected_service().
  device_->SelectService(service);
  device_->SetServiceState(Service::kStateConfiguring);
  device_->SetServiceFailure(Service::kFailurePPPAuth);
  device_->SetServiceFailureSilent(Service::kFailureUnknown);
  Mock::VerifyAndClearExpectations(service);  // before Cellular dtor
}

TEST_P(CellularTest, ChangeServiceStatePPP) {
  MockCellularService* service(SetMockService());
  scoped_refptr<MockPPPDevice> ppp_device(
      new MockPPPDevice(&manager_, "ppp0", 123));
  EXPECT_CALL(*ppp_device, SetServiceState(_));
  EXPECT_CALL(*ppp_device, SetServiceFailure(_));
  EXPECT_CALL(*ppp_device, SetServiceFailureSilent(_));
  EXPECT_CALL(*service, SetState(_)).Times(0);
  EXPECT_CALL(*service, SetFailure(_)).Times(0);
  EXPECT_CALL(*service, SetFailureSilent(_)).Times(0);
  device_->ppp_device_ = ppp_device;

  // With PPP, these should all be punted over to the |ppp_device|.
  // Note in particular that Cellular does not manipulate |service| in
  // this case.
  device_->SetServiceState(Service::kStateConfiguring);
  device_->SetServiceFailure(Service::kFailurePPPAuth);
  device_->SetServiceFailureSilent(Service::kFailureUnknown);
}

TEST_P(CellularTest, StopPPPOnDisconnect) {
  const int kPID = 123;
  Error error;
  StartPPP(kPID);
  FakeUpConnectedPPP();
  ExpectPPPStopped();
  device_->Disconnect(&error, "in test");
  VerifyPPPStopped();
}

TEST_P(CellularTest, StopPPPOnSuspend) {
  const int kPID = 123;
  StartPPP(kPID);
  FakeUpConnectedPPP();
  ExpectPPPStopped();
  device_->OnBeforeSuspend(ResultCallback());
  VerifyPPPStopped();
}

TEST_P(CellularTest, OnAfterResumeDisabledWantDisabled) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // The Device was disabled prior to resume, and the profile settings
  // indicate that the device should be disabled. We should leave
  // things alone.

  // Initial state.
  mm1::MockModemProxy* mm1_modem_proxy = SetupOnAfterResume();
  Error error;
  device_->SetEnabledPersistent(false, &error, ResultCallback());
  EXPECT_FALSE(device_->enabled_pending());
  EXPECT_FALSE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kDisabled, device_->state());

  // Resume, while device is disabled.
  EXPECT_CALL(*mm1_modem_proxy, Enable(_, _, _, _)).Times(0);
  device_->OnAfterResume();
  EXPECT_FALSE(device_->enabled_pending());
  EXPECT_FALSE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kDisabled, device_->state());
}

TEST_P(CellularTest, OnAfterResumeDisableInProgressWantDisabled) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // The Device was not disabled prior to resume, but the profile
  // settings indicate that the device _should be_ disabled. Most
  // likely, we started disabling the device, but that did not
  // complete before we suspended. We should leave things alone.

  // Initial state.
  mm1::MockModemProxy* mm1_modem_proxy = SetupOnAfterResume();
  mm1::MockModemModem3gppProfileManagerProxy*
      mm1_modem_3gpp_profile_manager_proxy =
          SetModem3gppProfileManagerProxyExpectations();
  Error error;
  EXPECT_CALL(*mm1_modem_proxy, Enable(true, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeEnable));
  EXPECT_CALL(*mm1_modem_3gpp_profile_manager_proxy, List(_, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeList));

  device_->SetEnabled(true);
  EXPECT_TRUE(device_->enabled_pending());
  EXPECT_EQ(Cellular::State::kModemStarted, device_->state());

  // Start disable.
  EXPECT_CALL(manager_, UpdateDevice(_));
  device_->SetEnabledPersistent(false, &error, ResultCallback());
  EXPECT_FALSE(device_->enabled_pending());
  EXPECT_FALSE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kModemStopping, device_->state());

  // Resume, with disable still in progress.
  device_->OnAfterResume();
  EXPECT_FALSE(device_->enabled_pending());
  EXPECT_FALSE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kModemStopping, device_->state());

  // Finish the disable operation.
  EXPECT_CALL(*mm1_modem_proxy, Enable(false, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeEnable));
  EXPECT_CALL(*mm1_modem_proxy, SetPowerState(_, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeSetPowerState));
  dispatcher_.DispatchPendingEvents();
  EXPECT_FALSE(device_->enabled_pending());
  EXPECT_FALSE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kDisabled, device_->state());
}

TEST_P(CellularTest, OnAfterResumeDisableQueuedWantEnabled) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // The Device was not disabled prior to resume, and the profile
  // settings indicate that the device should be enabled. In
  // particular, we went into suspend before we actually processed the
  // task queued by CellularCapability3gpp::StopModem.
  //
  // This is unlikely, and a case where we fail to do the right thing.
  // The tests exists to document this corner case, which we get wrong.

  // Initial state.
  auto dbus_properties_proxy = dbus_properties_proxy_.get();
  mm1::MockModemProxy* mm1_modem_proxy = SetupOnAfterResume();
  mm1::MockModemModem3gppProfileManagerProxy*
      mm1_modem_3gpp_profile_manager_proxy =
          SetModem3gppProfileManagerProxyExpectations();
  EXPECT_CALL(*mm1_modem_proxy, Enable(true, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeEnable));
  EXPECT_CALL(*mm1_modem_3gpp_profile_manager_proxy, List(_, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeList));
  device_->SetEnabled(true);
  EXPECT_TRUE(device_->enabled_pending());
  EXPECT_TRUE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kModemStarted, device_->state());

  // Start disable.
  device_->SetEnabled(false);
  EXPECT_FALSE(device_->enabled_pending());    // changes immediately
  EXPECT_TRUE(device_->enabled_persistent());  // no change
  EXPECT_EQ(Cellular::State::kModemStopping, device_->state());

  // Resume, with disable still in progress.
  EXPECT_CALL(*mm1_modem_proxy, Enable(true, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeEnableReturningWrongState));
  EXPECT_EQ(Cellular::State::kModemStopping, device_->state());
  device_->OnAfterResume();
  EXPECT_TRUE(device_->enabled_pending());     // changes immediately
  EXPECT_TRUE(device_->enabled_persistent());  // no change
  // Note: This used to be Disabled, however changes to Start behavior set the
  // Cellular State to Enabled when a WrongState error occurs.
  // TODO(b:185517971) Investigate and improve suspend/resume behavior.
  EXPECT_EQ(Cellular::State::kEnabled, device_->state());

  // Set up state that we need.
  KeyValueStore modem_properties;
  modem_properties.Set<int32_t>(MM_MODEM_PROPERTY_STATE,
                                Cellular::kModemStateDisabled);

  // Let the disable complete.
  EXPECT_CALL(*mm1_modem_proxy, Enable(false, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeEnable));
  EXPECT_CALL(*mm1_modem_proxy, SetPowerState(_, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeSetPowerState));
  static_cast<FakePropertiesProxy*>(
      dbus_properties_proxy->GetDBusPropertiesProxyForTesting())
      ->SetDictionaryForTesting(MM_DBUS_INTERFACE_MODEM,
                                modem_properties.properties());
  dispatcher_.DispatchPendingEvents();
  EXPECT_TRUE(device_->enabled_pending());     // last changed by OnAfterResume
  EXPECT_TRUE(device_->enabled_persistent());  // last changed by OnAfterResume
  EXPECT_EQ(Cellular::State::kDisabled, device_->state());

  // There's nothing queued up to restart the modem. Even though we
  // want to be running, we're stuck in the disabled state.
  dispatcher_.DispatchPendingEvents();
  EXPECT_TRUE(device_->enabled_pending());
  EXPECT_TRUE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kDisabled, device_->state());
}

TEST_P(CellularTest, OnAfterResumePowerDownInProgressWantEnabled) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // The Device was not fully disabled prior to resume, and the
  // profile settings indicate that the device should be enabled. In
  // this case, we have disabled the device, but are waiting for the
  // power-down (switch to low power) to complete.
  //
  // This test emulates the behavior of the Huawei E303 dongle, when
  // Manager::kTerminationActionsTimeoutMilliseconds is 9500
  // msec. (The dongle takes 10-11 seconds to go through the whole
  // disable, power-down sequence).
  //
  // Eventually, the power-down would complete, and the device would
  // be stuck in the disabled state. To counter-act that,
  // OnAfterResume tries to enable the device now, even though the
  // device is currently enabled.

  // Initial state.
  auto dbus_properties_proxy = dbus_properties_proxy_.get();
  mm1::MockModemProxy* mm1_modem_proxy = SetupOnAfterResume();
  mm1::MockModemModem3gppProfileManagerProxy*
      mm1_modem_3gpp_profile_manager_proxy =
          SetModem3gppProfileManagerProxyExpectations();
  EXPECT_CALL(*mm1_modem_proxy, Enable(true, _, _, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeEnable));
  EXPECT_CALL(*mm1_modem_3gpp_profile_manager_proxy, List(_, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeList));
  device_->SetEnabled(true);
  EXPECT_TRUE(device_->enabled_pending());
  EXPECT_TRUE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kModemStarted, device_->state());

  // Start disable.
  ResultCallback modem_proxy_enable_callback;
  EXPECT_CALL(*mm1_modem_proxy, Enable(false, _, _, _))
      .WillOnce(SaveArg<2>(&modem_proxy_enable_callback));
  device_->SetEnabled(false);
  dispatcher_.DispatchPendingEvents();  // SetEnabled yields a deferred task
  EXPECT_FALSE(device_->enabled_pending());    // changes immediately
  EXPECT_TRUE(device_->enabled_persistent());  // no change
  EXPECT_EQ(Cellular::State::kModemStopping, device_->state());

  // Let the disable complete. That will trigger power-down.
  //
  // Note that, unlike for mm1_modem_proxy->Enable, we don't save the
  // callback for mm1_modem_proxy->SetPowerState. We expect the callback not
  // to be executed, as explained in the comment about having a fresh
  // proxy OnAfterResume, below.
  Error error;
  ASSERT_TRUE(error.IsSuccess());
  EXPECT_CALL(*mm1_modem_proxy,
              SetPowerState(MM_MODEM_POWER_STATE_LOW, _, _, _))
      .WillOnce(SetErrorTypeInArgument<1>(Error::kOperationInitiated));
  modem_proxy_enable_callback.Run(error);

  // No response to power-down yet. It probably completed while the host
  // was asleep, and so the reply from the modem was lost.

  // Resume.
  ResultCallback new_callback;
  EXPECT_EQ(Cellular::State::kModemStopping, device_->state());
  EXPECT_CALL(*mm1_modem_proxy, Enable(true, _, _, _))
      .WillOnce(SaveArg<2>(&modem_proxy_enable_callback));
  device_->OnAfterResume();
  EXPECT_TRUE(device_->enabled_pending());     // changes immediately
  EXPECT_TRUE(device_->enabled_persistent());  // no change
  // OnAfterResume -> SetEnabledUnchecked -> Start
  EXPECT_EQ(Cellular::State::kModemStarting, device_->state());

  // Set up state that we need.
  KeyValueStore modem_properties;
  modem_properties.Set<int32_t>(MM_MODEM_PROPERTY_STATE,
                                Cellular::kModemStateEnabled);

  // Let the enable complete.
  EXPECT_CALL(*mm1_modem_3gpp_profile_manager_proxy, List(_, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeList));
  ASSERT_TRUE(error.IsSuccess());
  static_cast<FakePropertiesProxy*>(
      dbus_properties_proxy->GetDBusPropertiesProxyForTesting())
      ->SetDictionaryForTesting(MM_DBUS_INTERFACE_MODEM,
                                modem_properties.properties());
  ASSERT_TRUE(!modem_proxy_enable_callback.is_null());
  modem_proxy_enable_callback.Run(error);
  EXPECT_TRUE(device_->enabled_pending());
  EXPECT_TRUE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kModemStarted, device_->state());
}

TEST_P(CellularTest, OnAfterResumeDisabledWantEnabled) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  // This is the ideal case. The disable process completed before
  // going into suspend.
  mm1::MockModemProxy* mm1_modem_proxy = SetupOnAfterResume();
  mm1::MockModemModem3gppProfileManagerProxy*
      mm1_modem_3gpp_profile_manager_proxy =
          SetModem3gppProfileManagerProxyExpectations();
  EXPECT_FALSE(device_->enabled_pending());
  EXPECT_TRUE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kDisabled, device_->state());

  // Resume.
  ResultCallback modem_proxy_enable_callback;
  EXPECT_CALL(*mm1_modem_proxy, Enable(true, _, _, _))
      .WillOnce(SaveArg<2>(&modem_proxy_enable_callback));
  device_->OnAfterResume();

  // Complete enable.
  EXPECT_CALL(*mm1_modem_3gpp_profile_manager_proxy, List(_, _))
      .WillOnce(Invoke(this, &CellularTest::InvokeList));
  Error error;
  ASSERT_TRUE(error.IsSuccess());
  modem_proxy_enable_callback.Run(error);
  EXPECT_TRUE(device_->enabled_pending());
  EXPECT_TRUE(device_->enabled_persistent());
  EXPECT_EQ(Cellular::State::kModemStarted, device_->state());
}

TEST_P(CellularTest, EstablishLinkDHCP) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  auto bearer = std::make_unique<CellularBearer>(&control_interface_,
                                                 RpcIdentifier(""), "");
  bearer->set_ipv4_config_method(IPConfig::kMethodDHCP);
  SetCapability3gppActiveBearer(std::move(bearer));
  device_->set_state_for_testing(Cellular::State::kConnected);

  MockCellularService* service = SetMockService();
  ON_CALL(*service, state()).WillByDefault(Return(Service::kStateUnknown));

  EXPECT_CALL(device_info_, GetFlags(device_->interface_index(), _))
      .WillOnce(DoAll(SetArgPointee<1>(IFF_UP), Return(true)));
  EXPECT_CALL(dhcp_provider_, CreateIPv4Config(kTestDeviceName, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        auto controller = CreateMockDHCPController();
        EXPECT_CALL(*controller, RequestIP()).WillOnce(Return(true));
        return controller;
      }));
  EXPECT_CALL(*service, SetState(Service::kStateConfiguring));
  device_->EstablishLink();
  EXPECT_EQ(service, device_->selected_service());
  Mock::VerifyAndClearExpectations(service);  // before Cellular dtor
}

TEST_P(CellularTest, EstablishLinkPPP) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  auto bearer = std::make_unique<CellularBearer>(&control_interface_,
                                                 RpcIdentifier(""), "");
  bearer->set_ipv4_config_method(IPConfig::kMethodPPP);
  SetCapability3gppActiveBearer(std::move(bearer));
  device_->set_state_for_testing(Cellular::State::kConnected);

  const int kPID = 123;
  EXPECT_CALL(process_manager_, StartProcess(_, _, _, _, _, _))
      .WillOnce(Return(kPID));
  device_->EstablishLink();
  EXPECT_FALSE(device_->ipconfig());  // No DHCP client.
  EXPECT_FALSE(device_->selected_service());
  EXPECT_FALSE(device_->is_ppp_authenticating_);
  EXPECT_NE(nullptr, device_->ppp_task_);
}

TEST_P(CellularTest, EstablishLinkStatic) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  IPAddress::Family kAddressFamily = IPAddress::kFamilyIPv4;
  const char kAddress[] = "10.0.0.1";
  const char kGateway[] = "10.0.0.254";
  const int32_t kSubnetPrefix = 16;
  const char* const kDNS[] = {"10.0.0.2", "8.8.4.4", "8.8.8.8"};

  auto ipconfig_properties = std::make_unique<IPConfig::Properties>();
  ipconfig_properties->address_family = kAddressFamily;
  ipconfig_properties->address = kAddress;
  ipconfig_properties->gateway = kGateway;
  ipconfig_properties->subnet_prefix = kSubnetPrefix;
  ipconfig_properties->dns_servers =
      std::vector<std::string>{kDNS[0], kDNS[1], kDNS[2]};

  auto bearer = std::make_unique<CellularBearer>(&control_interface_,
                                                 RpcIdentifier(""), "");
  bearer->set_ipv4_config_method(IPConfig::kMethodStatic);
  bearer->set_ipv4_config_properties(std::move(ipconfig_properties));
  SetCapability3gppActiveBearer(std::move(bearer));
  device_->set_state_for_testing(Cellular::State::kConnected);

  MockCellularService* service = SetMockService();
  ON_CALL(*service, state()).WillByDefault(Return(Service::kStateUnknown));

  EXPECT_CALL(device_info_, GetFlags(device_->interface_index(), _))
      .WillOnce(DoAll(SetArgPointee<1>(IFF_UP), Return(true)));
  EXPECT_CALL(*service, SetState(Service::kStateConfiguring));
  device_->EstablishLink();
  EXPECT_EQ(service, device_->selected_service());
  ASSERT_NE(nullptr, device_->ipconfig());
  EXPECT_EQ(kAddressFamily, device_->ipconfig()->properties().address_family);
  EXPECT_EQ(kAddress, device_->ipconfig()->properties().address);
  EXPECT_EQ(kGateway, device_->ipconfig()->properties().gateway);
  EXPECT_EQ(kSubnetPrefix, device_->ipconfig()->properties().subnet_prefix);
  ASSERT_EQ(3, device_->ipconfig()->properties().dns_servers.size());
  EXPECT_EQ(kDNS[0], device_->ipconfig()->properties().dns_servers[0]);
  EXPECT_EQ(kDNS[1], device_->ipconfig()->properties().dns_servers[1]);
  EXPECT_EQ(kDNS[2], device_->ipconfig()->properties().dns_servers[2]);
  Mock::VerifyAndClearExpectations(service);  // before Cellular dtor
}

TEST_P(CellularTest, GetGeolocationObjects) {
  static const Cellular::LocationInfo kGoodLocations[] = {
      {"310", "410", "DE7E", "4985F6"},
      {"001", "010", "O100", "googol"},
      {"foo", "bar", "bazz", "quuux"}};
  static const Cellular::LocationInfo kBadLocations[] = {{"wat", "", "", ""},
                                                         {"", "", "", ""}};

  std::vector<GeolocationInfo> objects;

  for (const auto& location : kGoodLocations) {
    std::string raw_location = location.mcc + "," + location.mnc + "," +
                               location.lac + "," + location.ci;
    Error error;

    GeolocationInfo expected_info;
    expected_info[kGeoMobileCountryCodeProperty] = location.mcc;
    expected_info[kGeoMobileNetworkCodeProperty] = location.mnc;
    expected_info[kGeoLocationAreaCodeProperty] = location.lac;
    expected_info[kGeoCellIdProperty] = location.ci;

    device_->GetLocationCallback(raw_location, error);
    objects = device_->GetGeolocationObjects();

    ASSERT_EQ(objects.size(), 1);
    EXPECT_EQ(expected_info, objects[0]);
  }

  for (const auto& location : kBadLocations) {
    std::string raw_location = location.mcc + "," + location.mnc + "," +
                               location.lac + "," + location.ci;
    Error error;
    GeolocationInfo empty_info;

    device_->GetLocationCallback(raw_location, error);
    objects = device_->GetGeolocationObjects();

    ASSERT_EQ(objects.size(), 1);
    EXPECT_EQ(empty_info, objects[0]);
  }
}

// Helper class because gmock doesn't play nicely with unique_ptr
class FakeMobileOperatorInfo : public NiceMock<MockMobileOperatorInfo> {
 public:
  FakeMobileOperatorInfo(EventDispatcher* dispatcher,
                         std::vector<MobileOperatorInfo::MobileAPN> apn_list)
      : NiceMock<MockMobileOperatorInfo>(dispatcher, "Fake"),
        apn_list_(std::move(apn_list)) {}

  const std::vector<MobileOperatorInfo::MobileAPN>& apn_list() const override {
    return apn_list_;
  }

 private:
  std::vector<MobileOperatorInfo::MobileAPN> apn_list_;
};

TEST_P(CellularTest, SimpleApnList) {
  constexpr char kApn[] = "apn";
  constexpr char kUsername[] = "foo";
  constexpr char kPassword[] = "bar";

  std::vector<MobileOperatorInfo::MobileAPN> apn_list;
  MobileOperatorInfo::MobileAPN mobile_apn;
  mobile_apn.apn = kApn;
  mobile_apn.username = kUsername;
  mobile_apn.password = kPassword;
  apn_list.emplace_back(std::move(mobile_apn));
  FakeMobileOperatorInfo info(&dispatcher_, std::move(apn_list));

  device_->UpdateHomeProvider(&info);
  auto apn_list_prop = device_->apn_list();
  CHECK_EQ(1U, apn_list_prop.size());
  CHECK_EQ(kApn, apn_list_prop[0][kApnProperty]);
  CHECK_EQ(kUsername, apn_list_prop[0][kApnUsernameProperty]);
  CHECK_EQ(kPassword, apn_list_prop[0][kApnPasswordProperty]);
}

TEST_P(CellularTest, ProfilesApnList) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  constexpr char kApn1[] = "ota.apn";
  brillo::VariantDictionary profile;
  profile["apn"] = std::string(kApn1);
  Capability3gppCallOnProfilesChanged({profile});

  constexpr char kApn2[] = "normal.apn";
  std::vector<MobileOperatorInfo::MobileAPN> apn_list;
  MobileOperatorInfo::MobileAPN mobile_apn;
  mobile_apn.apn = kApn2;
  apn_list.emplace_back(std::move(mobile_apn));
  FakeMobileOperatorInfo info(&dispatcher_, std::move(apn_list));

  device_->UpdateHomeProvider(&info);
  auto apn_list_prop = device_->apn_list();
  CHECK_EQ(2U, apn_list_prop.size());
  // Profile APNs are likely deployed by the network. They should be tried
  // first, so they should be higher in the list.
  CHECK_EQ(kApn1, apn_list_prop[0][kApnProperty]);
  CHECK_EQ(kApn2, apn_list_prop[1][kApnProperty]);
}

TEST_P(CellularTest, MergeProfileAndOperatorApn) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  constexpr char kApn[] = "normal.apn";
  constexpr char kApnName[] = "Normal APN";
  brillo::VariantDictionary profile;
  profile["apn"] = std::string(kApn);
  Capability3gppCallOnProfilesChanged({profile});

  std::vector<MobileOperatorInfo::MobileAPN> apn_list;
  MobileOperatorInfo::MobileAPN mobile_apn;
  mobile_apn.apn = kApn;
  mobile_apn.operator_name_list.push_back({kApnName, ""});
  apn_list.emplace_back(std::move(mobile_apn));
  FakeMobileOperatorInfo info(&dispatcher_, std::move(apn_list));

  device_->UpdateHomeProvider(&info);
  auto apn_list_prop = device_->apn_list();
  CHECK_EQ(1U, apn_list_prop.size());
  CHECK_EQ(kApn, apn_list_prop[0][kApnProperty]);
  CHECK_EQ(kApnName, apn_list_prop[0][kApnNameProperty]);
}

TEST_P(CellularTest, DontMergeProfileAndOperatorApn) {
  if (!IsCellularTypeUnderTestOneOf({Cellular::kType3gpp})) {
    return;
  }

  constexpr char kApn[] = "normal.apn";
  constexpr char kUsernameFromProfile[] = "user1";
  brillo::VariantDictionary profile;
  profile["apn"] = std::string(kApn);
  profile["username"] = std::string(kUsernameFromProfile);
  Capability3gppCallOnProfilesChanged({profile});

  constexpr char kUsernameFromOperator[] = "user2";
  std::vector<MobileOperatorInfo::MobileAPN> apn_list;
  MobileOperatorInfo::MobileAPN mobile_apn;
  mobile_apn.apn = kApn;
  mobile_apn.username = kUsernameFromOperator;
  apn_list.emplace_back(std::move(mobile_apn));
  FakeMobileOperatorInfo info(&dispatcher_, std::move(apn_list));

  device_->UpdateHomeProvider(&info);
  auto apn_list_prop = device_->apn_list();
  CHECK_EQ(2U, apn_list_prop.size());
  // As before, profile APNs come first.
  CHECK_EQ(kApn, apn_list_prop[0][kApnProperty]);
  CHECK_EQ(kUsernameFromProfile, apn_list_prop[0][kApnUsernameProperty]);
  CHECK_EQ(kApn, apn_list_prop[1][kApnProperty]);
  CHECK_EQ(kUsernameFromOperator, apn_list_prop[1][kApnUsernameProperty]);
}

TEST_P(CellularTest, BuildApnTryList) {
  Stringmaps apn_list;
  Stringmap apn1, apn2;
  apn1[kApnProperty] = "apn1";
  apn1[cellular::kApnSource] = cellular::kApnSourceMoDb;
  apn2[kApnProperty] = "apn2";
  apn2[cellular::kApnSource] = cellular::kApnSourceMoDb;
  apn_list.push_back(apn1);
  apn_list.push_back(apn2);
  device_->SetApnList(apn_list);

  std::deque<Stringmap> apn_try_list = device_->BuildApnTryList();
  ASSERT_EQ(apn_try_list.size(), apn_list.size());
  EXPECT_EQ(apn_try_list[0], apn1);
  EXPECT_EQ(apn_try_list[1], apn2);

  // Add a custom APN
  CellularService* service = SetService();
  Stringmap custom_apn;
  custom_apn[kApnProperty] = "custom_apn";
  custom_apn[cellular::kApnSource] = cellular::kApnSourceUi;
  service->set_apn_info_for_testing(custom_apn);
  apn_try_list = device_->BuildApnTryList();
  ASSERT_EQ(apn_try_list.size(), apn_list.size() + 1u);
  EXPECT_EQ(apn_try_list[0], custom_apn);
  EXPECT_EQ(apn_try_list[1], apn1);
  EXPECT_EQ(apn_try_list[2], apn2);

  // Set the last good APN to an APN not in the current list
  Stringmap last_good_apn;
  last_good_apn[kApnProperty] = "last_good_apn";
  last_good_apn[cellular::kApnSource] = cellular::kApnSourceUi;
  service->SetLastGoodApn(last_good_apn);
  apn_try_list = device_->BuildApnTryList();
  ASSERT_EQ(apn_try_list.size(), apn_list.size() + 2u);
  EXPECT_EQ(apn_try_list[0], custom_apn);
  EXPECT_EQ(apn_try_list[1], apn1);
  EXPECT_EQ(apn_try_list[2], apn2);
  EXPECT_EQ(apn_try_list[3], last_good_apn);

  // Set the last good APN to an existing APN
  service->SetLastGoodApn(apn2);
  apn_try_list = device_->BuildApnTryList();
  ASSERT_EQ(apn_try_list.size(), apn_list.size() + 1u);
  EXPECT_EQ(apn_try_list[0], custom_apn);
  EXPECT_EQ(apn_try_list[1], apn1);
  EXPECT_EQ(apn_try_list[2], apn2);

  // Set the custom APN to an existing APN
  service->set_apn_info_for_testing(apn1);
  apn_try_list = device_->BuildApnTryList();
  ASSERT_EQ(apn_try_list.size(), apn_list.size());
  EXPECT_EQ(apn_try_list[0], apn1);
  EXPECT_EQ(apn_try_list[1], apn2);
}

TEST_P(CellularTest, CompareApns) {
  Stringmap apn1, apn2;
  EXPECT_TRUE(device_->CompareApns(apn1, apn2));
  apn1[kApnNameProperty] = "apn_name1";
  apn2[kApnNameProperty] = "apn_name2";
  EXPECT_TRUE(device_->CompareApns(apn1, apn2));

  apn1[cellular::kApnSource] = "test_source";
  EXPECT_TRUE(device_->CompareApns(apn1, apn2));
  EXPECT_TRUE(device_->CompareApns(apn2, apn1));

  apn2[cellular::kApnVersionProperty] = "test_version";
  EXPECT_TRUE(device_->CompareApns(apn1, apn2));
  EXPECT_TRUE(device_->CompareApns(apn2, apn1));

  apn1[kApnUsernameProperty] = "username";
  EXPECT_FALSE(device_->CompareApns(apn1, apn2));
  EXPECT_FALSE(device_->CompareApns(apn2, apn1));

  apn2[kApnUsernameProperty] = "username_two";
  EXPECT_FALSE(device_->CompareApns(apn1, apn2));
  EXPECT_FALSE(device_->CompareApns(apn2, apn1));

  apn2[kApnUsernameProperty] = "username";
  EXPECT_TRUE(device_->CompareApns(apn1, apn2));
  EXPECT_TRUE(device_->CompareApns(apn2, apn1));

  apn2[kApnLanguageProperty] = "language";
  EXPECT_TRUE(device_->CompareApns(apn1, apn2));
  EXPECT_TRUE(device_->CompareApns(apn2, apn1));

  apn2[cellular::kApnVersionProperty] = "version";
  EXPECT_TRUE(device_->CompareApns(apn1, apn2));
  EXPECT_TRUE(device_->CompareApns(apn2, apn1));

  apn1[kApnProperty] = "apn.test";
  EXPECT_FALSE(device_->CompareApns(apn1, apn2));
  EXPECT_FALSE(device_->CompareApns(apn2, apn1));

  apn2[kApnProperty] = "apn.test";
  EXPECT_TRUE(device_->CompareApns(apn1, apn2));
  EXPECT_TRUE(device_->CompareApns(apn2, apn1));
}

INSTANTIATE_TEST_SUITE_P(CellularTest,
                         CellularTest,
                         testing::Values(Cellular::kType3gpp,
                                         Cellular::kTypeCdma));

}  // namespace shill
