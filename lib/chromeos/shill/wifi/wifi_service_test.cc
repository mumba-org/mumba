// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_service.h"

#include <limits>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/test/simple_test_clock.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/event_dispatcher.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_certificate_file.h"
#include "shill/mock_control.h"
#include "shill/mock_eap_credentials.h"
#include "shill/mock_log.h"
#include "shill/mock_manager.h"
#include "shill/mock_profile.h"
#include "shill/mock_service.h"
#include "shill/net/mock_netlink_manager.h"
#include "shill/refptr_types.h"
#include "shill/service_property_change_test.h"
#include "shill/store/fake_store.h"
#include "shill/store/property_store_test.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/technology.h"
#include "shill/tethering.h"
#include "shill/wifi/mock_wake_on_wifi.h"
#include "shill/wifi/mock_wifi.h"
#include "shill/wifi/mock_wifi_provider.h"
#include "shill/wifi/wifi_endpoint.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::EndsWith;
using ::testing::HasSubstr;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::StrictMock;
using ::testing::StrNe;

namespace shill {

class WiFiServiceTest : public PropertyStoreTest {
 public:
  WiFiServiceTest()
      : mock_manager_(control_interface(), dispatcher(), metrics()),
        wifi_(new NiceMock<MockWiFi>(
            manager(), "wifi", fake_mac, 0, new MockWakeOnWiFi())),
        simple_ssid_(1, 'a'),
        simple_ssid_string_("a") {}
  ~WiFiServiceTest() override = default;

 protected:
  static const char fake_mac[];

  MockEapCredentials* SetMockEap(const WiFiServiceRefPtr& service) {
    MockEapCredentials* eap = new MockEapCredentials();
    service->eap_.reset(eap);  // Passes ownership.
    return eap;
  }
  bool SetPassphrase(WiFiServiceRefPtr service, const std::string& passphrase) {
    Error error;
    service->SetPassphrase(passphrase, &error);
    return error.IsSuccess();
  }
  bool CheckConnectable(const std::string& security_class,
                        const char* passphrase,
                        bool is_1x_connectable) {
    WiFiServiceRefPtr service = MakeSimpleService(security_class);
    if (passphrase)
      SetPassphrase(service, passphrase);
    MockEapCredentials* eap = SetMockEap(service);
    EXPECT_CALL(*eap, IsConnectable())
        .WillRepeatedly(Return(is_1x_connectable));
    const std::string kKeyManagement8021x(
        WPASupplicant::kKeyManagementIeee8021X);
    if (security_class == kSecurityWep && is_1x_connectable) {
      EXPECT_CALL(*eap, key_management())
          .WillRepeatedly(ReturnRef(kKeyManagement8021x));
    }
    service->OnEapCredentialsChanged(Service::kReasonCredentialsLoaded);
    return service->connectable();
  }
  WiFiEndpointRefPtr MakeEndpoint(
      const std::string& ssid,
      const std::string& bssid,
      uint16_t frequency,
      int16_t signal_dbm,
      const WiFiEndpoint::SecurityFlags& security_flags) {
    return WiFiEndpoint::MakeEndpoint(nullptr, wifi(), ssid, bssid,
                                      WPASupplicant::kNetworkModeInfrastructure,
                                      frequency, signal_dbm, security_flags);
  }
  WiFiEndpointRefPtr MakeOpenEndpoint(const std::string& ssid,
                                      const std::string& bssid,
                                      uint16_t frequency,
                                      int16_t signal_dbm) {
    return WiFiEndpoint::MakeOpenEndpoint(
        nullptr, wifi(), ssid, bssid, WPASupplicant::kNetworkModeInfrastructure,
        frequency, signal_dbm);
  }
  WiFiEndpointRefPtr MakeOpenEndpointWithWiFi(WiFiRefPtr wifi,
                                              const std::string& ssid,
                                              const std::string& bssid,
                                              uint16_t frequency,
                                              int16_t signal_dbm) {
    return WiFiEndpoint::MakeOpenEndpoint(
        nullptr, wifi, ssid, bssid, WPASupplicant::kNetworkModeInfrastructure,
        frequency, signal_dbm);
  }
  WiFiServiceRefPtr MakeServiceSSID(const std::string& security_class,
                                    const std::string& ssid) {
    const std::vector<uint8_t> ssid_bytes(ssid.begin(), ssid.end());
    return new WiFiService(manager(), &provider_, ssid_bytes, kModeManaged,
                           security_class, false);
  }
  WiFiServiceRefPtr MakeSimpleService(const std::string& security_class) {
    return new WiFiService(manager(), &provider_, simple_ssid_, kModeManaged,
                           security_class, false);
  }
  void SetWiFi(WiFiServiceRefPtr service, WiFiRefPtr wifi) {
    service->SetWiFi(wifi);  // Has side-effects.
  }
  void SetWiFiForService(WiFiServiceRefPtr service, WiFiRefPtr wifi) {
    service->wifi_ = wifi;
  }
  WiFiServiceRefPtr MakeServiceWithWiFi(const std::string& security_class) {
    WiFiServiceRefPtr service = MakeSimpleService(security_class);
    SetWiFiForService(service, wifi_);
    scoped_refptr<MockProfile> mock_profile(
        new NiceMock<MockProfile>(manager()));
    service->set_profile(mock_profile);
    return service;
  }
  WiFiServiceRefPtr MakeServiceWithMockManager() {
    return new WiFiService(&mock_manager_, &provider_, simple_ssid_,
                           kModeManaged, kSecurityNone, false);
  }
  scoped_refptr<MockWiFi> MakeSimpleWiFi(const std::string& link_name) {
    return new NiceMock<MockWiFi>(manager(), link_name, fake_mac, 0,
                                  new MockWakeOnWiFi());
  }
  ServiceMockAdaptor* GetAdaptor(WiFiService* service) {
    return static_cast<ServiceMockAdaptor*>(service->adaptor());
  }
  Error::Type TestConfigurePassphrase(const std::string& security_class,
                                      const char* passphrase) {
    WiFiServiceRefPtr service = MakeSimpleService(security_class);
    KeyValueStore args;
    if (passphrase) {
      args.Set<std::string>(kPassphraseProperty, passphrase);
    }
    Error error;
    service->Configure(args, &error);
    return error.type();
  }
  bool SortingOrderIs(const WiFiServiceRefPtr& service0,
                      const WiFiServiceRefPtr& service1) {
    bool decision;
    return service0->CompareWithSameTechnology(service1, &decision) && decision;
  }
  scoped_refptr<MockWiFi> wifi() { return wifi_; }
  MockManager* mock_manager() { return &mock_manager_; }
  MockWiFiProvider* provider() { return &provider_; }
  std::string GetAnyDeviceAddress() const {
    return WiFiService::kAnyDeviceAddress;
  }
  const std::vector<uint8_t>& simple_ssid() const { return simple_ssid_; }
  const std::string& simple_ssid_string() const { return simple_ssid_string_; }

  const Metrics::WiFiConnectionAttemptInfo GetConnectionAttemptInfo(
      const WiFiServiceRefPtr& service) const {
    return service->ConnectionAttemptInfo();
  }

 private:
  MockManager mock_manager_;
  MockNetlinkManager netlink_manager_;
  scoped_refptr<MockWiFi> wifi_;
  MockWiFiProvider provider_;
  const std::vector<uint8_t> simple_ssid_;
  const std::string simple_ssid_string_;
};

// static
const char WiFiServiceTest::fake_mac[] = "AaBBcCDDeeFF";

void SetWiFiProperties(FakeStore* store,
                       const std::string& id,
                       const std::vector<uint8_t>& ssid,
                       const std::string& security_class) {
  auto hex_ssid = base::HexEncode(ssid.data(), ssid.size());
  store->SetString(id, WiFiService::kStorageType, kTypeWifi);
  store->SetString(id, WiFiService::kStorageSSID, hex_ssid);
  store->SetString(id, WiFiService::kStorageSecurityClass, security_class);
  store->SetString(id, WiFiService::kStorageMode, kModeManaged);
}

class WiFiServiceSecurityTest : public WiFiServiceTest {
 public:
  // Create a service with a secured endpoint.
  WiFiServiceRefPtr SetupSecureService(const std::string& security) {
    auto security_class = WiFiService::ComputeSecurityClass(security);
    WiFiServiceRefPtr service = MakeSimpleService(security_class);

    // For security classes, we don't need an endpoint.
    if (security == security_class)
      return service;

    // For others, we need an endpoint to help specialize the Service.
    WiFiEndpoint::SecurityFlags flags;
    if (security == kSecurityWpa) {
      flags.wpa_psk = true;
    } else if (security == kSecurityRsn) {
      flags.rsn_psk = true;
    } else if (security == kSecurityWpa3) {
      flags.rsn_sae = true;
    } else {
      EXPECT_TRUE(false) << security;
      return nullptr;
    }
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(security, service->security());
    return service;
  }

  // Test that a service that is created with security |from_security|
  // gets its SecurityClass mapped to |to_security|.
  void TestSecurityMapping(const std::string& from_security,
                           const std::string& to_security_class) {
    WiFiServiceRefPtr wifi_service = SetupSecureService(from_security);
    EXPECT_EQ(to_security_class, wifi_service->security_class());
  }

  // Test whether a service of type |service_security| can load from a
  // storage interface containing an entry for |storage_security_class|.
  // Make sure the result meets |expectation|.  If |expectation| is
  // true, also make sure the service storage identifier changes to
  // match |storage_security_class|.
  bool TestLoadMapping(const std::string& service_security,
                       const std::string& storage_security_class,
                       bool expectation) {
    WiFiServiceRefPtr wifi_service = SetupSecureService(service_security);

    FakeStore store;
    const std::string kStorageId = "storage_id";
    SetWiFiProperties(&store, kStorageId, wifi_service->ssid(),
                      storage_security_class);
    bool is_loadable = wifi_service->IsLoadableFrom(store);
    EXPECT_EQ(expectation, is_loadable);
    bool is_loaded = wifi_service->Load(&store);
    EXPECT_EQ(expectation, is_loaded);
    const std::string expected_identifier(expectation ? kStorageId : "");
    EXPECT_EQ(expected_identifier,
              wifi_service->GetLoadableStorageIdentifier(store));

    if (expectation != is_loadable || expectation != is_loaded) {
      return false;
    } else if (!expectation) {
      return true;
    } else {
      return wifi_service->GetStorageIdentifier() == kStorageId;
    }
  }
};

class WiFiServiceUpdateFromEndpointsTest : public WiFiServiceTest {
 public:
  WiFiServiceUpdateFromEndpointsTest()
      : kOkEndpointStrength(WiFiService::SignalToStrength(kOkEndpointSignal)),
        kBadEndpointStrength(WiFiService::SignalToStrength(kBadEndpointSignal)),
        kGoodEndpointStrength(
            WiFiService::SignalToStrength(kGoodEndpointSignal)),
        service(MakeSimpleService(kSecurityNone)),
        adaptor(*GetAdaptor(service.get())) {
    ok_endpoint = MakeOpenEndpoint(simple_ssid_string(), kOkEndpointBssId,
                                   kOkEndpointFrequency, kOkEndpointSignal);
    good_endpoint =
        MakeOpenEndpoint(simple_ssid_string(), kGoodEndpointBssId,
                         kGoodEndpointFrequency, kGoodEndpointSignal);
    bad_endpoint = MakeOpenEndpoint(simple_ssid_string(), kBadEndpointBssId,
                                    kBadEndpointFrequency, kBadEndpointSignal);
  }

 protected:
  static const uint16_t kOkEndpointFrequency = 2422;
  static const uint16_t kBadEndpointFrequency = 2417;
  static const uint16_t kGoodEndpointFrequency = 2412;
  static const int16_t kOkEndpointSignal = -60;
  static const int16_t kBadEndpointSignal = -75;
  static const int16_t kGoodEndpointSignal = -50;
  static const char kOkEndpointBssId[];
  static const char kGoodEndpointBssId[];
  static const char kBadEndpointBssId[];
  // Can't be both static and const (because initialization requires a
  // function call). So choose to be just const.
  const uint8_t kOkEndpointStrength;
  const uint8_t kBadEndpointStrength;
  const uint8_t kGoodEndpointStrength;
  WiFiEndpointRefPtr ok_endpoint;
  WiFiEndpointRefPtr bad_endpoint;
  WiFiEndpointRefPtr good_endpoint;
  WiFiServiceRefPtr service;
  ServiceMockAdaptor& adaptor;
};

const char WiFiServiceUpdateFromEndpointsTest::kOkEndpointBssId[] =
    "00:00:00:00:00:01";
const char WiFiServiceUpdateFromEndpointsTest::kGoodEndpointBssId[] =
    "00:00:00:00:00:02";
const char WiFiServiceUpdateFromEndpointsTest::kBadEndpointBssId[] =
    "00:00:00:00:00:03";

TEST_F(WiFiServiceTest, Constructor) {
  const auto histogram = metrics()->GetFullMetricName(
      Metrics::kMetricTimeToJoinMillisecondsSuffix, Technology::kWiFi);
  EXPECT_CALL(*metrics(), AddServiceStateTransitionTimer(
                              _, histogram, Service::kStateAssociating,
                              Service::kStateConfiguring));
  MakeSimpleService(kSecurityNone);
}

TEST_F(WiFiServiceTest, StorageId) {
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityNone);
  const auto id = wifi_service->GetStorageIdentifier();
  for (char c : id) {
    EXPECT_TRUE(c == '_' || isxdigit(c) || (isalpha(c) && islower(c)));
  }
  size_t mac_pos = id.find(base::ToLowerASCII(GetAnyDeviceAddress()));
  EXPECT_NE(mac_pos, std::string::npos);
  EXPECT_NE(id.find(std::string(kModeManaged), mac_pos), std::string::npos);
}

TEST_F(WiFiServiceTest, LogName) {
  Service::SetNextSerialNumberForTesting(0);
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityNone);
  EXPECT_EQ("wifi_none_0", wifi_service->log_name());
  wifi_service = MakeSimpleService(kSecurityWep);
  EXPECT_EQ("wifi_wep_1", wifi_service->log_name());
  wifi_service = MakeSimpleService(kSecurityPsk);
  EXPECT_EQ("wifi_psk_2", wifi_service->log_name());
  wifi_service = MakeSimpleService(kSecurity8021x);
  EXPECT_EQ("wifi_802_1x_3", wifi_service->log_name());
}

// Make sure the passphrase is registered as a write only property
// by reading and comparing all string properties returned on the store.
TEST_F(WiFiServiceTest, PassphraseWriteOnly) {
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityPsk);
  brillo::VariantDictionary properties;
  wifi_service->store().GetProperties(&properties, nullptr);
  ASSERT_EQ(properties.find(kPassphraseProperty), properties.end());
}

// Make sure setting the passphrase via D-Bus Service.SetProperty validates
// the passphrase.
TEST_F(WiFiServiceTest, PassphraseSetPropertyValidation) {
  // We only spot check two password cases here to make sure the
  // SetProperty code path does validation.  We're not going to exhaustively
  // test for all types of passwords.
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityWep);
  Error error;
  wifi_service->mutable_store()->SetStringProperty(kPassphraseProperty,
                                                   "0:abcde", &error);
  EXPECT_TRUE(error.IsSuccess());
  wifi_service->mutable_store()->SetStringProperty(kPassphraseProperty,
                                                   "invalid", &error);
  EXPECT_EQ(Error::kInvalidPassphrase, error.type());
}

TEST_F(WiFiServiceTest, PassphraseSetPropertyOpenNetwork) {
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityNone);
  Error error;
  wifi_service->mutable_store()->SetStringProperty(kPassphraseProperty,
                                                   "invalid", &error);
  EXPECT_EQ(Error::kIllegalOperation, error.type());
}

TEST_F(WiFiServiceTest, NonUTF8SSID) {
  std::vector<uint8_t> ssid = {0xff};  // not a valid UTF-8 byte-sequence
  WiFiServiceRefPtr wifi_service = new WiFiService(
      manager(), provider(), ssid, kModeManaged, kSecurityNone, false);
  brillo::VariantDictionary properties;
  // if service doesn't propertly sanitize SSID, this will generate SIGABRT.
  EXPECT_TRUE(wifi_service->store().GetProperties(&properties, nullptr));
}

MATCHER(PSKSecurityArgs, "") {
  return arg.template Contains<std::string>(
             WPASupplicant::kPropertySecurityProtocol) &&
         arg.template Get<std::string>(
             WPASupplicant::kPropertySecurityProtocol) ==
             std::string("WPA RSN") &&
         arg.template Contains<std::string>(
             WPASupplicant::kPropertyPreSharedKey);
}

TEST_F(WiFiServiceTest, ConnectReportBSSes) {
  WiFiEndpointRefPtr endpoint1 =
      MakeOpenEndpoint("a", "00:00:00:00:00:01", 0, 0);
  WiFiEndpointRefPtr endpoint2 =
      MakeOpenEndpoint("a", "00:00:00:00:00:02", 0, 0);
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityNone);
  wifi_service->AddEndpoint(endpoint1);
  wifi_service->AddEndpoint(endpoint2);
  EXPECT_CALL(*metrics(), NotifyWifiAvailableBSSes(2));
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
}

TEST_F(WiFiServiceTest, ConnectConditions) {
  Error error;
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityNone);
  // With nothing else going on, the service should attempt to connect.
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(&error, "in test");
  Mock::VerifyAndClearExpectations(wifi().get());

  // But if we're already "connecting" or "connected" then we shouldn't attempt
  // again.
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _)).Times(0);
  wifi_service->SetState(Service::kStateAssociating);
  wifi_service->Connect(&error, "in test");
  wifi_service->SetState(Service::kStateConfiguring);
  wifi_service->Connect(&error, "in test");
  wifi_service->SetState(Service::kStateConnected);
  wifi_service->Connect(&error, "in test");
  wifi_service->SetState(Service::kStateNoConnectivity);
  wifi_service->Connect(&error, "in test");
  wifi_service->SetState(Service::kStateOnline);
  wifi_service->Connect(&error, "in test");
  Mock::VerifyAndClearExpectations(wifi().get());
}

TEST_F(WiFiServiceTest, ConnectTaskPSK) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityPsk);
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  SetPassphrase(wifi_service, "0:mumblemumblem");
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              PSKSecurityArgs());
}

TEST_F(WiFiServiceTest, ConnectTaskRawPMK) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityPsk);
  EXPECT_CALL(*wifi(), ConnectTo(service.get(), _));
  SetPassphrase(service, std::string(IEEE_80211::kWPAHexLen, '1'));
  service->Connect(nullptr, "in test");
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_FALSE(
      params.Contains<std::string>(WPASupplicant::kPropertyPreSharedKey));
  EXPECT_TRUE(params.Contains<std::vector<uint8_t>>(
      WPASupplicant::kPropertyPreSharedKey));
}

TEST_F(WiFiServiceTest, ConnectTask8021x) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurity8021x);
  service->mutable_eap()->set_identity("identity");
  service->mutable_eap()->set_password("mumble");
  service->OnEapCredentialsChanged(Service::kReasonCredentialsLoaded);
  EXPECT_CALL(*wifi(), ConnectTo(service.get(), _));
  service->Connect(nullptr, "in test");
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_TRUE(
      params.Contains<std::string>(WPASupplicant::kNetworkPropertyEapIdentity));
  EXPECT_TRUE(
      params.Contains<std::string>(WPASupplicant::kNetworkPropertyCaPath));
}

TEST_F(WiFiServiceTest, ConnectTask8021xWithMockEap) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurity8021x);
  MockEapCredentials* eap = SetMockEap(service);
  EXPECT_CALL(*eap, IsConnectable()).WillOnce(Return(true));
  EXPECT_CALL(*wifi(), ConnectTo(service.get(), _));
  service->OnEapCredentialsChanged(Service::kReasonCredentialsLoaded);
  service->Connect(nullptr, "in test");

  EXPECT_CALL(*eap, PopulateSupplicantProperties(_, _));
  // The mocked function does not actually set EAP parameters so we cannot
  // expect them to be set.
  service->GetSupplicantConfigurationParameters();
}

MATCHER_P(WEPSecurityArgsKeyIndex, index, "") {
  uint32_t index_u32 = index;
  return arg.template Contains<std::string>(WPASupplicant::kPropertyAuthAlg) &&
         arg.template Contains<std::vector<uint8_t>>(
             WPASupplicant::kPropertyWEPKey + base::NumberToString(index)) &&
         arg.template Contains<uint32_t>(
             WPASupplicant::kPropertyWEPTxKeyIndex) &&
         (arg.template Get<uint32_t>(WPASupplicant::kPropertyWEPTxKeyIndex) ==
          index_u32);
}

TEST_F(WiFiServiceTest, ConnectTaskWEP) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityWep);
  SetPassphrase(wifi_service, "0:abcdefghijklm");
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              WEPSecurityArgsKeyIndex(0));

  SetPassphrase(wifi_service, "abcdefghijklm");
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              WEPSecurityArgsKeyIndex(0));

  SetPassphrase(wifi_service, "1:abcdefghijklm");
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              WEPSecurityArgsKeyIndex(1));

  SetPassphrase(wifi_service, "2:abcdefghijklm");
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              WEPSecurityArgsKeyIndex(2));

  SetPassphrase(wifi_service, "3:abcdefghijklm");
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              WEPSecurityArgsKeyIndex(3));
}

// Dynamic WEP + 802.1x.
TEST_F(WiFiServiceTest, ConnectTaskDynamicWEP) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityWep);

  wifi_service->mutable_eap()->SetKeyManagement("IEEE8021X", nullptr);
  wifi_service->mutable_eap()->set_identity("something");
  wifi_service->mutable_eap()->set_password("mumble");
  wifi_service->OnEapCredentialsChanged(Service::kReasonCredentialsLoaded);
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  KeyValueStore params = wifi_service->GetSupplicantConfigurationParameters();
  EXPECT_TRUE(
      params.Contains<std::string>(WPASupplicant::kNetworkPropertyEapIdentity));
  EXPECT_TRUE(
      params.Contains<std::string>(WPASupplicant::kNetworkPropertyCaPath));
  EXPECT_FALSE(
      params.Contains<std::string>(WPASupplicant::kPropertySecurityProtocol));
}

TEST_F(WiFiServiceTest, ConnectTaskFT) {
  {
    WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityPsk);
#if !defined(DISABLE_WPA3_SAE)
    std::string ft_key_mgmt = "WPA-PSK SAE FT-PSK FT-SAE";
    std::string noft_key_mgmt = "WPA-PSK SAE";
#else
    std::string ft_key_mgmt = "WPA-PSK FT-PSK";
    std::string noft_key_mgmt = "WPA-PSK";
#endif  // DISABLE_WPA3_SAE

    wifi_service->Connect(nullptr, "in test");
    KeyValueStore params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ(ft_key_mgmt,
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));

    manager()->props_.ft_enabled = false;
    wifi_service->Connect(nullptr, "in test");
    params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ(noft_key_mgmt,
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));

    manager()->props_.ft_enabled = true;
    wifi_service->Connect(nullptr, "in test");
    params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ(ft_key_mgmt,
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));
  }
  {
    WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurity8021x);
    wifi_service->mutable_eap()->set_identity("identity");
    wifi_service->mutable_eap()->set_password("mumble");
    wifi_service->OnEapCredentialsChanged(Service::kReasonCredentialsLoaded);

    manager()->props_.ft_enabled = std::nullopt;
    wifi_service->Connect(nullptr, "in test");
    KeyValueStore params = wifi_service->GetSupplicantConfigurationParameters();
    std::string default_key_mgmt = "WPA-EAP WPA-EAP-SHA256 FT-EAP";
    EXPECT_EQ(default_key_mgmt,
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));

    manager()->props_.ft_enabled = false;
    wifi_service->Connect(nullptr, "in test");
    params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ("WPA-EAP WPA-EAP-SHA256",
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));

    manager()->props_.ft_enabled = true;
    wifi_service->Connect(nullptr, "in test");
    params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ(default_key_mgmt,
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));
  }
}

TEST_F(WiFiServiceTest, SetPassphraseResetHasEverConnected) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityPsk);
  const std::string kPassphrase = "abcdefgh";

  // A changed passphrase should reset has_ever_connected_ field.
  wifi_service->has_ever_connected_ = true;
  EXPECT_TRUE(wifi_service->has_ever_connected());
  SetPassphrase(wifi_service, kPassphrase);
  EXPECT_FALSE(wifi_service->has_ever_connected());
}

TEST_F(WiFiServiceTest, SetPassphraseRemovesCachedCredentials) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityPsk);

  const std::string kPassphrase = "abcdefgh";

  {
    // A changed passphrase should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    EXPECT_TRUE(SetPassphrase(wifi_service, kPassphrase));
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  {
    // An unchanged passphrase should not trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(0);
    EXPECT_TRUE(SetPassphrase(wifi_service, kPassphrase));
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  {
    // A modified passphrase should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    EXPECT_TRUE(SetPassphrase(wifi_service, kPassphrase + "X"));
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  {
    Error error;
    // A cleared passphrase should also trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    wifi_service->ClearPassphrase(&error);
    Mock::VerifyAndClearExpectations(wifi().get());
    EXPECT_TRUE(error.IsSuccess());
  }

  {
    // An invalid passphrase should not trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(0);
    EXPECT_FALSE(SetPassphrase(wifi_service, ""));
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  {
    // A change to EAP parameters in a PSK (non 802.1x) service will not
    // trigger cache removal.
    wifi_service->has_ever_connected_ = true;
    EXPECT_TRUE(wifi_service->has_ever_connected());
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get())).Times(0);
    wifi_service->OnEapCredentialsChanged(Service::kReasonPropertyUpdate);
    EXPECT_TRUE(wifi_service->has_ever_connected());
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  WiFiServiceRefPtr eap_wifi_service = MakeServiceWithWiFi(kSecurity8021x);

  {
    // Any change to EAP parameters (including a null one) will trigger cache
    // removal in an 802.1x service.  This is a lot less granular than the
    // passphrase checks above.
    // Changes in EAP parameters should also clear has_ever_connected_.
    eap_wifi_service->has_ever_connected_ = true;
    EXPECT_TRUE(eap_wifi_service->has_ever_connected());
    EXPECT_CALL(*wifi(), ClearCachedCredentials(eap_wifi_service.get()));
    eap_wifi_service->OnEapCredentialsChanged(Service::kReasonPropertyUpdate);
    EXPECT_FALSE(eap_wifi_service->has_ever_connected());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
}

// This test is somewhat redundant, since:
//
// a) we test that generic property setters return false on a null
//    change (e.g. in PropertyAccessorTest.SignedIntCorrectness)
// b) we test that custom EAP property setters return false on a null
//    change in EapCredentialsTest.CustomSetterNoopChange
// c) we test that the various custom accessors pass through the
//    return value of custom setters
//    (e.g. PropertyAccessorTest.CustomAccessorCorrectness)
// d) we test that PropertyStore skips the change callback when a
//    property setter return false (PropertyStoreTypedTest.SetProperty)
//
// Nonetheless, I think it's worth testing the WiFi+EAP case directly.
TEST_F(WiFiServiceTest, EapAuthPropertyChangeClearsCachedCredentials) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurity8021x);
  PropertyStore& property_store(*wifi_service->mutable_store());

  // Property with custom accessor.
  const std::string kPassword = "abcdefgh";
  {
    Error error;
    // A changed passphrase should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    property_store.SetStringProperty(kEapPasswordProperty, kPassword, &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
  {
    Error error;
    // An unchanged passphrase should not trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(0);
    property_store.SetStringProperty(kEapPasswordProperty, kPassword, &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
  {
    Error error;
    // A modified passphrase should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    property_store.SetStringProperty(kEapPasswordProperty, kPassword + "X",
                                     &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  // Property with generic accessor.
  const std::string kCertId = "abcdefgh";
  {
    Error error;
    // A changed cert id should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    property_store.SetStringProperty(kEapCertIdProperty, kCertId, &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
  {
    Error error;
    // An unchanged cert id should not trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(0);
    property_store.SetStringProperty(kEapCertIdProperty, kCertId, &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
  {
    Error error;
    // A modified cert id should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    property_store.SetStringProperty(kEapCertIdProperty, kCertId + "X", &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
}

TEST_F(WiFiServiceTest, LoadHidden) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);
  ASSERT_FALSE(service->hidden_ssid_);
  FakeStore store;
  const std::string storage_id = service->GetStorageIdentifier();
  SetWiFiProperties(&store, storage_id, simple_ssid(), kSecurityNone);
  store.SetBool(storage_id, WiFiService::kStorageHiddenSSID, true);
  EXPECT_TRUE(service->Load(&store));
  EXPECT_TRUE(service->hidden_ssid_);
}

TEST_F(WiFiServiceTest, SetPassphraseForNonPassphraseService) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);
  FakeStore store;
  const std::string storage_id = service->GetStorageIdentifier();
  SetWiFiProperties(&store, storage_id, simple_ssid(), kSecurityNone);

  EXPECT_TRUE(service->Load(&store));
  Error error;
  EXPECT_FALSE(service->SetPassphrase("password", &error));
  EXPECT_TRUE(error.type() == Error::kIllegalOperation);
}

TEST_F(WiFiServiceTest, LoadMultipleMatchingGroups) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityNone);
  std::string storage_id0 = "id0";
  std::string storage_id1 = "id1";
  FakeStore store;
  SetWiFiProperties(&store, storage_id0, simple_ssid(), kSecurityNone);
  SetWiFiProperties(&store, storage_id1, simple_ssid(), kSecurityNone);
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(service->GetStorageIdentifier(), storage_id0);
}

TEST_F(WiFiServiceSecurityTest, WPAMapping) {
  TestSecurityMapping(kSecurityWpa3, kSecurityPsk);
  TestSecurityMapping(kSecurityRsn, kSecurityPsk);
  TestSecurityMapping(kSecurityWpa, kSecurityPsk);
  TestSecurityMapping(kSecurityPsk, kSecurityPsk);
  TestSecurityMapping(kSecurityWep, kSecurityWep);
  TestSecurityMapping(kSecurityNone, kSecurityNone);
  TestSecurityMapping(kSecurity8021x, kSecurity8021x);
}

TEST_F(WiFiServiceSecurityTest, LoadMapping) {
  EXPECT_TRUE(TestLoadMapping(kSecurityWpa3, kSecurityPsk, true));
  EXPECT_TRUE(TestLoadMapping(kSecurityRsn, kSecurityPsk, true));
  EXPECT_TRUE(TestLoadMapping(kSecurityWpa, kSecurityPsk, true));
  EXPECT_TRUE(TestLoadMapping(kSecurityWep, kSecurityWep, true));
  EXPECT_TRUE(TestLoadMapping(kSecurityWep, kSecurityPsk, false));
}

TEST_F(WiFiServiceSecurityTest, EndpointsDisappear) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityPsk);
  WiFiEndpoint::SecurityFlags flags;
  flags.rsn_psk = true;
  WiFiEndpointRefPtr endpoint =
      MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
  service->AddEndpoint(endpoint);
  EXPECT_EQ(kSecurityRsn, service->security());
  EXPECT_EQ(kSecurityPsk, service->security_class());

  service->RemoveEndpoint(endpoint);
  EXPECT_EQ(kSecurityPsk, service->security());
  EXPECT_EQ(kSecurityPsk, service->security_class());
}

TEST_F(WiFiServiceTest, LoadAndUnloadPassphrase) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityPsk);
  FakeStore store;
  const std::string kStorageId = service->GetStorageIdentifier();
  SetWiFiProperties(&store, kStorageId, simple_ssid(), kSecurityPsk);
  const std::string kPassphrase = "passphrase";
  store.SetString(kStorageId, WiFiService::kStorageCredentialPassphrase,
                  kPassphrase);
  EXPECT_TRUE(service->need_passphrase_);
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(kPassphrase, service->passphrase_);
  EXPECT_TRUE(service->connectable());
  EXPECT_FALSE(service->need_passphrase_);
  service->Unload();
  EXPECT_EQ(std::string(""), service->passphrase_);
  EXPECT_FALSE(service->connectable());
  EXPECT_TRUE(service->need_passphrase_);
}

TEST_F(WiFiServiceTest, LoadPassphraseClearCredentials) {
  const std::string kOldPassphrase = "oldpassphrase";
  const std::string kPassphrase = "passphrase";

  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityPsk);
  FakeStore store;
  const std::string kStorageId = service->GetStorageIdentifier();
  SetWiFiProperties(&store, kStorageId, simple_ssid(), kSecurityPsk);
  store.SetString(kStorageId, WiFiService::kStorageCredentialPassphrase,
                  kPassphrase);
  store.SetBool(kStorageId, Service::kStorageHasEverConnected, true);

  // Set old passphrase for service
  EXPECT_TRUE(service->need_passphrase_);
  service->passphrase_ = kOldPassphrase;
  service->has_ever_connected_ = true;

  scoped_refptr<MockProfile> mock_profile =
      static_cast<MockProfile*>(service->profile().get());
  // Detect if the service is going to attempt to update the stored profile.
  EXPECT_CALL(*mock_profile, GetConstStorage()).Times(0);

  // The kOldPassphrase is different than the newly loaded passhprase,
  // so the credentials should be cleared.
  EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(1);
  EXPECT_CALL(*mock_profile, UpdateService(_)).Times(0);
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(kPassphrase, service->passphrase_);
  EXPECT_TRUE(service->has_ever_connected_);

  Mock::VerifyAndClearExpectations(wifi().get());
  Mock::VerifyAndClearExpectations(mock_profile.get());

  // Repeat Service::Load with same old and new passphrase. Since the old
  // and new passphrase match, verify the cache is not cleared during
  // profile load.
  service->set_profile(mock_profile);
  EXPECT_CALL(*mock_profile, GetConstStorage()).Times(0);
  EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(0);
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(kPassphrase, service->passphrase_);
  EXPECT_TRUE(service->has_ever_connected_);
}

TEST_F(WiFiServiceTest, LoadWithPasspointCredentials) {
  const std::string creds_id("an_id");
  const uint64_t match_priority = 3;
  PasspointCredentialsRefPtr credentials = new PasspointCredentials(creds_id);
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);

  FakeStore store;
  const std::string storage_id = service->GetStorageIdentifier();
  SetWiFiProperties(&store, storage_id, simple_ssid(), kSecurityNone);

  // No credentials stored.
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(nullptr, service->parent_credentials());

  // Set of credentials in the store.
  store.SetString(storage_id, WiFiService::kStoragePasspointCredentials,
                  creds_id);
  store.SetUint64(storage_id, WiFiService::kStoragePasspointMatchPriority,
                  match_priority);
  EXPECT_CALL(*provider(), FindCredentials(creds_id))
      .WillOnce(Return(credentials));
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(credentials, service->parent_credentials());
  EXPECT_EQ(match_priority, service->match_priority());

  // Set of credentials in the store, but not in the provider
  EXPECT_CALL(*provider(), FindCredentials(creds_id)).WillOnce(Return(nullptr));
  EXPECT_FALSE(service->Load(&store));
}

TEST_F(WiFiServiceTest, ConfigureMakesConnectable) {
  std::string guid("legit_guid");
  KeyValueStore args;
  args.Set<std::string>(kEapIdentityProperty, "legit_identity");
  args.Set<std::string>(kEapPasswordProperty, "legit_password");
  args.Set<std::string>(kEapMethodProperty, "PEAP");
  args.Set<std::string>(kGuidProperty, guid);
  Error error;

  WiFiServiceRefPtr service = MakeSimpleService(kSecurity8021x);
  // Hack the GUID in so that we don't have to mess about with WiFi to regsiter
  // our service.  This way, Manager will handle the lookup itself.
  service->SetGuid(guid, nullptr);
  manager()->RegisterService(service);
  EXPECT_FALSE(service->connectable());
  EXPECT_EQ(service, manager()->GetService(args, &error));
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_TRUE(service->connectable());
}

TEST_F(WiFiServiceTest, ConfigurePassphrase) {
  EXPECT_EQ(Error::kIllegalOperation,
            TestConfigurePassphrase(kSecurityNone, ""));
  EXPECT_EQ(Error::kIllegalOperation,
            TestConfigurePassphrase(kSecurityNone, "foo"));
  EXPECT_EQ(Error::kSuccess, TestConfigurePassphrase(kSecurityWep, nullptr));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityWep, ""));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityWep, "abcd"));
  EXPECT_EQ(Error::kSuccess, TestConfigurePassphrase(kSecurityWep, "abcde"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityWep, "abcdefghijklm"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityWep, "0:abcdefghijklm"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityWep, "0102030405"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityWep, "0x0102030405"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityWep, "O102030405"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityWep, "1:O102030405"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityWep, "1:0xO102030405"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityWep, "0xO102030405"));
  EXPECT_EQ(Error::kSuccess, TestConfigurePassphrase(
                                 kSecurityWep, "0102030405060708090a0b0c0d"));
  EXPECT_EQ(Error::kSuccess, TestConfigurePassphrase(
                                 kSecurityWep, "0102030405060708090A0B0C0D"));
  EXPECT_EQ(Error::kSuccess, TestConfigurePassphrase(
                                 kSecurityWep, "0:0102030405060708090a0b0c0d"));
  EXPECT_EQ(
      Error::kSuccess,
      TestConfigurePassphrase(kSecurityWep, "0:0x0102030405060708090a0b0c0d"));
  EXPECT_EQ(Error::kSuccess, TestConfigurePassphrase(kSecurityPsk, nullptr));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityPsk, "secure password"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityPsk, ""));
  EXPECT_EQ(
      Error::kSuccess,
      TestConfigurePassphrase(
          kSecurityPsk, std::string(IEEE_80211::kWPAAsciiMinLen, 'Z').c_str()));
  EXPECT_EQ(
      Error::kSuccess,
      TestConfigurePassphrase(
          kSecurityPsk, std::string(IEEE_80211::kWPAAsciiMaxLen, 'Z').c_str()));
  // subtle: invalid length for hex key, but valid as ascii passphrase
  EXPECT_EQ(
      Error::kSuccess,
      TestConfigurePassphrase(
          kSecurityPsk, std::string(IEEE_80211::kWPAHexLen - 1, '1').c_str()));
  EXPECT_EQ(
      Error::kSuccess,
      TestConfigurePassphrase(
          kSecurityPsk, std::string(IEEE_80211::kWPAHexLen, '1').c_str()));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(
                kSecurityPsk,
                std::string(IEEE_80211::kWPAAsciiMinLen - 1, 'Z').c_str()));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(
                kSecurityPsk,
                std::string(IEEE_80211::kWPAAsciiMaxLen + 1, 'Z').c_str()));
  EXPECT_EQ(
      Error::kInvalidPassphrase,
      TestConfigurePassphrase(
          kSecurityPsk, std::string(IEEE_80211::kWPAHexLen + 1, '1').c_str()));
}

TEST_F(WiFiServiceTest, ConfigureRedundantProperties) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kSSIDProperty, simple_ssid_string());
  args.Set<std::string>(kSecurityProperty, kSecurityNone);
  args.Set<std::string>(kWifiHexSsid,
                        "This is ignored even if it is invalid hex.");
  const std::string kGUID = "aguid";
  args.Set<std::string>(kGuidProperty, kGUID);

  EXPECT_EQ("", service->guid());
  Error error;
  service->Configure(args, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kGUID, service->guid());
}

TEST_F(WiFiServiceTest, SetRoamState) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityNone);
  service->SetRoamState(Service::kRoamStateConnected);
  EXPECT_EQ(Service::kRoamStateConnected, service->roam_state());
  service->SetState(Service::kStateConnected);
  EXPECT_EQ(Service::kRoamStateIdle, service->roam_state());
}

TEST_F(WiFiServiceTest, DisconnectWithWiFi) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityWep);
  // An inactive Service will not have OnDisconnected triggered.
  service->SetState(Service::kStateConnected);
  EXPECT_CALL(*wifi(), IsCurrentService(service.get())).WillOnce(Return(true));
  EXPECT_CALL(*wifi(), DisconnectFrom(service.get())).Times(1);
  Error error;
  service->Disconnect(&error, "in test");
}

TEST_F(WiFiServiceTest, DisconnectWithoutWiFi) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityWep);
  EXPECT_CALL(*wifi(), DisconnectFrom(_)).Times(0);
  service->SetState(Service::kStateAssociating);
  Error error;
  service->Disconnect(&error, "in test");
  EXPECT_EQ(Error::kOperationFailed, error.type());
}

TEST_F(WiFiServiceTest, DisconnectWithoutWiFiWhileAssociating) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityWep);
  EXPECT_CALL(*wifi(), DisconnectFrom(_)).Times(0);
  service->SetState(Service::kStateAssociating);
  ScopedMockLog log;
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("WiFi endpoints do not (yet) exist.")));
  Error error;
  service->Disconnect(&error, "in test");
  EXPECT_EQ(Error::kOperationFailed, error.type());
}

TEST_F(WiFiServiceTest, UnloadAndClearCacheWEP) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityWep);
  // An inactive Service will not have OnDisconnected triggered.
  service->SetState(Service::kStateConnected);
  EXPECT_CALL(*wifi(), IsCurrentService(service.get())).WillOnce(Return(true));
  EXPECT_CALL(*wifi(), ClearCachedCredentials(service.get())).Times(1);
  EXPECT_CALL(*wifi(), DisconnectFrom(service.get())).Times(1);
  service->Unload();
}

TEST_F(WiFiServiceTest, UnloadAndClearCache8021x) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurity8021x);
  // An inactive Service will not have OnDisconnected triggered.
  service->SetState(Service::kStateConnected);
  EXPECT_CALL(*wifi(), IsCurrentService(service.get())).WillOnce(Return(true));
  EXPECT_CALL(*wifi(), ClearCachedCredentials(service.get())).Times(1);
  EXPECT_CALL(*wifi(), DisconnectFrom(service.get())).Times(1);
  service->Unload();
}

TEST_F(WiFiServiceTest, Connectable) {
  // Open network should be connectable.
  EXPECT_TRUE(CheckConnectable(kSecurityNone, nullptr, false));

  // Open network should remain connectable if we try to set a password on it.
  EXPECT_TRUE(CheckConnectable(kSecurityNone, "abcde", false));

  // WEP network with passphrase set should be connectable.
  EXPECT_TRUE(CheckConnectable(kSecurityWep, "abcde", false));

  // WEP network without passphrase set should NOT be connectable.
  EXPECT_FALSE(CheckConnectable(kSecurityWep, nullptr, false));

  // A bad passphrase should not make a WEP network connectable.
  EXPECT_FALSE(CheckConnectable(kSecurityWep, "a", false));

  // Similar to WEP, for PSK.
  EXPECT_TRUE(CheckConnectable(kSecurityPsk, "abcdefgh", false));
  EXPECT_FALSE(CheckConnectable(kSecurityPsk, nullptr, false));
  EXPECT_FALSE(CheckConnectable(kSecurityPsk, "a", false));

  // 802.1x without connectable EAP credentials should NOT be connectable.
  EXPECT_FALSE(CheckConnectable(kSecurity8021x, nullptr, false));

  // 802.1x with connectable EAP credentials should be connectable.
  EXPECT_TRUE(CheckConnectable(kSecurity8021x, nullptr, true));

  // Dynamic WEP + 802.1X should be connectable under the same conditions.
  EXPECT_TRUE(CheckConnectable(kSecurityWep, nullptr, true));

  {
    WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityPsk);
    SetPassphrase(service, "abcdefgh");
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_psk = true;
    flags.rsn_sae = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    // WPA3-transitional; all devices should support.
    EXPECT_TRUE(service->connectable());
  }
  {
    WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityPsk);
    SetPassphrase(service, "abcdefgh");
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_sae = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    // WPA3-only; match device support.
    EXPECT_EQ(wifi()->SupportsWPA3(), service->connectable());
  }
}

TEST_F(WiFiServiceTest, IsAutoConnectable) {
  const char* reason;
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);
  EXPECT_CALL(*wifi(), IsIdle()).WillRepeatedly(Return(true));
  EXPECT_FALSE(service->HasEndpoints());
  EXPECT_FALSE(service->IsAutoConnectable(&reason));
  EXPECT_STREQ(WiFiService::kAutoConnMediumUnavailable, reason);

  reason = "";
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint("a", "00:00:00:00:00:01", 0, 0);
  service->AddEndpoint(endpoint);
  EXPECT_CALL(*wifi(), IsIdle()).WillRepeatedly(Return(true));
  EXPECT_TRUE(service->HasEndpoints());
  EXPECT_TRUE(service->IsAutoConnectable(&reason));
  EXPECT_STREQ("", reason);

  // WiFi only supports connecting to one Service at a time. So, to
  // avoid disrupting connectivity, we only allow auto-connection to
  // a WiFiService when the corresponding WiFi is idle.
  EXPECT_CALL(*wifi(), IsIdle()).WillRepeatedly(Return(false));
  EXPECT_TRUE(service->HasEndpoints());
  EXPECT_FALSE(service->IsAutoConnectable(&reason));
  EXPECT_STREQ(WiFiService::kAutoConnBusy, reason);
}

TEST_F(WiFiServiceTest, AutoConnect) {
  const char* reason;
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);
  EXPECT_FALSE(service->IsAutoConnectable(&reason));
  EXPECT_CALL(*wifi(), ConnectTo(_, _)).Times(0);
  service->AutoConnect();
  dispatcher()->DispatchPendingEvents();

  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint("a", "00:00:00:00:00:01", 0, 0);
  service->AddEndpoint(endpoint);
  EXPECT_CALL(*wifi(), IsIdle()).WillRepeatedly(Return(true));
  EXPECT_TRUE(service->IsAutoConnectable(&reason));
  EXPECT_CALL(*wifi(), ConnectTo(_, _));
  service->AutoConnect();
  dispatcher()->DispatchPendingEvents();

  Error error;
  service->UserInitiatedDisconnect("RPC", &error);
  dispatcher()->DispatchPendingEvents();
  EXPECT_FALSE(service->IsAutoConnectable(&reason));
}

TEST_F(WiFiServiceTest, PreferWPA2OverWPA) {
  std::string ssid0 = "a", ssid1 = "b";
  WiFiServiceRefPtr service0 = MakeServiceSSID(kSecurityPsk, ssid0);
  WiFiServiceRefPtr service1 = MakeServiceSSID(kSecurityPsk, ssid1);

  WiFiEndpoint::SecurityFlags rsn_flags;
  rsn_flags.rsn_psk = true;
  WiFiEndpoint::SecurityFlags wpa_flags;
  wpa_flags.wpa_psk = true;
  WiFiEndpointRefPtr rsn_endpoint =
      MakeEndpoint(ssid0, "00:00:00:00:00:01", 0, 0, rsn_flags);
  WiFiEndpointRefPtr wpa_endpoint =
      MakeEndpoint(ssid1, "00:00:00:00:00:02", 0, 0, wpa_flags);
  service0->AddEndpoint(rsn_endpoint);
  service1->AddEndpoint(wpa_endpoint);

  EXPECT_EQ(kSecurityRsn, service0->security());
  EXPECT_EQ(kSecurityWpa, service1->security());

  const auto& ret =
      Service::Compare(service0, service1, false, std::vector<Technology>());
  EXPECT_TRUE(ret.first);
}

TEST_F(WiFiServiceTest, ClearWriteOnlyDerivedProperty) {
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityWep);

  EXPECT_EQ("", wifi_service->passphrase_);

  Error error;
  const std::string kPassphrase = "0:abcde";
  wifi_service->mutable_store()->SetAnyProperty(
      kPassphraseProperty, brillo::Any(kPassphrase), &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kPassphrase, wifi_service->passphrase_);

  EXPECT_TRUE(wifi_service->mutable_store()->ClearProperty(kPassphraseProperty,
                                                           &error));
  EXPECT_EQ("", wifi_service->passphrase_);
}

TEST_F(WiFiServiceTest, SignalToStrength) {
  // Verify that our mapping is valid, in the sense that it preserves ordering.
  // We test that the current_map returns results as expect and fall into
  // correct category of Excellent, Good, Medium, Poor signal quality.
  for (int16_t i = std::numeric_limits<int16_t>::min();
       i < std::numeric_limits<int16_t>::max(); ++i) {
    int16_t current_mapped = WiFiService::SignalToStrength(i);
    int16_t next_mapped = WiFiService::SignalToStrength(i + 1);
    EXPECT_LE(current_mapped, next_mapped)
        << "(original values " << i << " " << i + 1 << ")";
    EXPECT_GE(current_mapped, Service::kStrengthMin);
    EXPECT_LE(current_mapped, Service::kStrengthMax);

    if (i >= -55) {
      // Excellent signal quality
      EXPECT_GE(current_mapped, 75);
      EXPECT_LE(current_mapped, Service::kStrengthMax);
    } else if (i < -55 && i >= -66) {
      // Good signal quality
      EXPECT_GE(current_mapped, 50);
      EXPECT_LE(current_mapped, 75);
    } else if (i < -66 && i >= -77) {
      // Medium signal quality
      EXPECT_GE(current_mapped, 25);
      EXPECT_LE(current_mapped, 50);
    } else if (i < -77 && i >= -88) {
      // Poor signal quality
      EXPECT_GE(current_mapped, Service::kStrengthMin);
      EXPECT_LE(current_mapped, 25);
    } else if (i < -88) {
      // No signal
      EXPECT_EQ(current_mapped, Service::kStrengthMin);
    }
  }
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, Strengths) {
  // If the chosen signal values don't map to distinct strength
  // values, then we can't expect our other tests to pass. So verify
  // their distinctness.
  EXPECT_TRUE(kOkEndpointStrength != kBadEndpointStrength);
  EXPECT_TRUE(kOkEndpointStrength != kGoodEndpointStrength);
  EXPECT_TRUE(kGoodEndpointStrength != kBadEndpointStrength);
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, Floating) {
  // Initial endpoint updates values.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, kOkEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kOkEndpointBssId));
  EXPECT_CALL(adaptor,
              EmitUint8Changed(kSignalStrengthProperty, kOkEndpointStrength));
  EXPECT_CALL(adaptor,
              EmitUint16Changed(kWifiPhyMode, Metrics::kWiFiNetworkPhyMode11b));
  service->AddEndpoint(ok_endpoint);
  EXPECT_EQ(1, service->GetEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Endpoint with stronger signal updates values.
  EXPECT_CALL(adaptor,
              EmitUint16Changed(kWifiFrequency, kGoodEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kGoodEndpointBssId));
  EXPECT_CALL(adaptor,
              EmitUint8Changed(kSignalStrengthProperty, kGoodEndpointStrength));
  // However, both endpoints are 11b.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiPhyMode, _)).Times(0);
  service->AddEndpoint(good_endpoint);
  EXPECT_EQ(2, service->GetEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Endpoint with lower signal does not change values.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiPhyMode, _)).Times(0);
  service->AddEndpoint(bad_endpoint);
  EXPECT_EQ(3, service->GetEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Removing non-optimal endpoint does not change values.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiPhyMode, _)).Times(0);
  service->RemoveEndpoint(bad_endpoint);
  EXPECT_EQ(2, service->GetEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Removing optimal endpoint updates values.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, kOkEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kOkEndpointBssId));
  EXPECT_CALL(adaptor,
              EmitUint8Changed(kSignalStrengthProperty, kOkEndpointStrength));
  // However, both endpoints are 11b.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiPhyMode, _)).Times(0);
  service->RemoveEndpoint(good_endpoint);
  EXPECT_EQ(1, service->GetEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Removing last endpoint updates values (and doesn't crash).
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _));
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _));
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiPhyMode,
                                         Metrics::kWiFiNetworkPhyModeUndef));
  service->RemoveEndpoint(ok_endpoint);
  EXPECT_EQ(0, service->GetEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, Connected) {
  EXPECT_CALL(adaptor, EmitUint16Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitStringChanged(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitUint8Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitBoolChanged(_, _)).Times(AnyNumber());
  service->AddEndpoint(bad_endpoint);
  service->AddEndpoint(ok_endpoint);
  EXPECT_EQ(2, service->GetEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Setting current endpoint forces adoption of its values, even if it
  // doesn't have the highest signal.
  EXPECT_CALL(adaptor,
              EmitUint16Changed(kWifiFrequency, kBadEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kBadEndpointBssId));
  EXPECT_CALL(adaptor,
              EmitUint8Changed(kSignalStrengthProperty, kBadEndpointStrength));
  service->NotifyCurrentEndpoint(bad_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Adding a better endpoint doesn't matter, when current endpoint is set.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  service->AddEndpoint(good_endpoint);
  EXPECT_EQ(3, service->GetEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Removing a better endpoint doesn't matter, when current endpoint is set.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  service->RemoveEndpoint(good_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Removing the current endpoint is safe and healthy.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, kOkEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kOkEndpointBssId));
  EXPECT_CALL(adaptor,
              EmitUint8Changed(kSignalStrengthProperty, kOkEndpointStrength));
  service->RemoveEndpoint(bad_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Clearing the current endpoint (without removing it) is also safe and
  // healthy.
  service->NotifyCurrentEndpoint(ok_endpoint);
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  service->NotifyCurrentEndpoint(nullptr);
  Mock::VerifyAndClearExpectations(&adaptor);
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, EndpointModified) {
  EXPECT_CALL(adaptor, EmitUint16Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitStringChanged(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitUint8Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitBoolChanged(_, _)).Times(AnyNumber());
  service->AddEndpoint(ok_endpoint);
  service->AddEndpoint(good_endpoint);
  EXPECT_EQ(2, service->GetEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Updating sub-optimal Endpoint doesn't update Service.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  ok_endpoint->signal_strength_ = (kOkEndpointSignal + kGoodEndpointSignal) / 2;
  service->NotifyEndpointUpdated(ok_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Updating optimal Endpoint updates appropriate Service property.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _));
  good_endpoint->signal_strength_ = kGoodEndpointSignal + 1;
  service->NotifyEndpointUpdated(good_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Change in optimal Endpoint updates Service properties.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, kOkEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kOkEndpointBssId));
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _));
  ok_endpoint->signal_strength_ = kGoodEndpointSignal + 2;
  service->NotifyEndpointUpdated(ok_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, PhysicalMode) {
  EXPECT_CALL(adaptor, EmitUint16Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitStringChanged(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitUint8Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitBoolChanged(_, _)).Times(AnyNumber());

  // No endpoints -> undef.
  EXPECT_EQ(Metrics::kWiFiNetworkPhyModeUndef, service->physical_mode());

  // Endpoint has unknown physical mode -> undef.
  ok_endpoint->physical_mode_ = Metrics::kWiFiNetworkPhyModeUndef;
  service->AddEndpoint(ok_endpoint);
  EXPECT_EQ(Metrics::kWiFiNetworkPhyModeUndef, service->physical_mode());

  // New endpoint with 802.11a -> 802.11a.
  good_endpoint->physical_mode_ = Metrics::kWiFiNetworkPhyMode11a;
  service->AddEndpoint(good_endpoint);
  EXPECT_EQ(Metrics::kWiFiNetworkPhyMode11a, service->physical_mode());

  // Remove 802.11a endpoint -> undef.
  service->RemoveEndpoint(good_endpoint);
  EXPECT_EQ(Metrics::kWiFiNetworkPhyModeUndef, service->physical_mode());

  // Change endpoint -> take endpoint's new value.
  ok_endpoint->physical_mode_ = Metrics::kWiFiNetworkPhyMode11n;
  service->NotifyEndpointUpdated(ok_endpoint);
  EXPECT_EQ(Metrics::kWiFiNetworkPhyMode11n, service->physical_mode());

  // No endpoints -> undef.
  service->RemoveEndpoint(ok_endpoint);
  EXPECT_EQ(Metrics::kWiFiNetworkPhyModeUndef, service->physical_mode());
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, WarningOnDisconnect) {
  service->AddEndpoint(ok_endpoint);
  service->SetState(Service::kStateAssociating);
  ScopedMockLog log;
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(logging::LOGGING_WARNING, _,
                       EndsWith("disconnect due to no remaining endpoints.")));
  service->RemoveEndpoint(ok_endpoint);
}

MATCHER_P(IsSetwiseEqual, expected_set, "") {
  std::set<uint16_t> arg_set(arg.begin(), arg.end());
  return arg_set == expected_set;
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, FrequencyList) {
  EXPECT_CALL(adaptor, EmitUint16Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitStringChanged(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitUint8Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitBoolChanged(_, _)).Times(AnyNumber());

  // No endpoints -> empty list.
  EXPECT_EQ(std::vector<uint16_t>(), service->frequency_list());

  // Add endpoint -> endpoint's frequency in list.
  EXPECT_CALL(adaptor, EmitUint16sChanged(
                           kWifiFrequencyListProperty,
                           std::vector<uint16_t>{kGoodEndpointFrequency}));
  service->AddEndpoint(good_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Add another endpoint -> both frequencies in list.
  // Order doesn't matter.
  std::set<uint16_t> expected_frequencies{kGoodEndpointFrequency,
                                          kOkEndpointFrequency};
  EXPECT_CALL(adaptor,
              EmitUint16sChanged(kWifiFrequencyListProperty,
                                 IsSetwiseEqual(expected_frequencies)));
  service->AddEndpoint(ok_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Remove endpoint -> other endpoint's frequency remains.
  EXPECT_CALL(adaptor,
              EmitUint16sChanged(kWifiFrequencyListProperty,
                                 std::vector<uint16_t>{kOkEndpointFrequency}));
  service->RemoveEndpoint(good_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Endpoint with same frequency -> frequency remains.
  // Notification may or may not occur -- don't care.
  // Frequency may or may not be repeated in list -- don't care.
  WiFiEndpointRefPtr same_freq_as_ok_endpoint = MakeOpenEndpoint(
      simple_ssid_string(), "aa:bb:cc:dd:ee:ff", ok_endpoint->frequency(), 0);
  service->AddEndpoint(same_freq_as_ok_endpoint);
  EXPECT_THAT(service->frequency_list(),
              IsSetwiseEqual(std::set<uint16_t>{kOkEndpointFrequency}));
  Mock::VerifyAndClearExpectations(&adaptor);

  // Remove endpoint with same frequency -> frequency remains.
  // Notification may or may not occur -- don't care.
  service->RemoveEndpoint(ok_endpoint);
  EXPECT_EQ(std::vector<uint16_t>{same_freq_as_ok_endpoint->frequency()},
            service->frequency_list());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Remove last endpoint. Frequency list goes empty.
  EXPECT_CALL(adaptor, EmitUint16sChanged(kWifiFrequencyListProperty,
                                          std::vector<uint16_t>{}));
  service->RemoveEndpoint(same_freq_as_ok_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);
}

TEST_F(WiFiServiceTest, UpdateSecurity) {
  // Cleartext and pre-shared-key crypto.
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);
    EXPECT_EQ(Service::kCryptoNone, service->crypto_algorithm());
    EXPECT_FALSE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityWep);
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_FALSE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityPsk);
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.wpa_psk = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(kSecurityWpa, service->security());
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_psk = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(kSecurityRsn, service->security());
    EXPECT_EQ(Service::kCryptoAes, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_sae = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(kSecurityWpa3, service->security());
    EXPECT_EQ(Service::kCryptoAes, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }

  // Crypto with 802.1X key management.
  {
    // WEP
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityWep);
    service->SetEAPKeyManagement("IEEE8021X");
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_TRUE(service->endpoint_auth());
  }
  {
    // WPA
    WiFiServiceRefPtr service = MakeSimpleService(kSecurity8021x);
    WiFiEndpoint::SecurityFlags flags;
    flags.wpa_8021x = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_TRUE(service->endpoint_auth());
  }
  {
    // RSN
    WiFiServiceRefPtr service = MakeSimpleService(kSecurity8021x);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_8021x = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(Service::kCryptoAes, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_TRUE(service->endpoint_auth());
  }
  {
    // AP supports both WPA and RSN.
    WiFiServiceRefPtr service = MakeSimpleService(kSecurity8021x);
    WiFiEndpoint::SecurityFlags flags;
    flags.wpa_8021x = true;
    flags.rsn_8021x = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(Service::kCryptoAes, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_TRUE(service->endpoint_auth());
  }
}

TEST_F(WiFiServiceTest, ComputeCipher8021x) {
  WiFiEndpoint::SecurityFlags open_flags;
  WiFiEndpoint::SecurityFlags wpa_flags;
  wpa_flags.wpa_psk = true;
  WiFiEndpoint::SecurityFlags rsn_flags;
  rsn_flags.rsn_psk = true;
  WiFiEndpoint::SecurityFlags wparsn_flags;
  wparsn_flags.wpa_psk = true;
  wparsn_flags.rsn_psk = true;

  // No endpoints.
  {
    const std::set<WiFiEndpointConstRefPtr> endpoints;
    EXPECT_EQ(Service::kCryptoNone, WiFiService::ComputeCipher8021x(endpoints));
  }

  // Single endpoint, various configs.
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, open_flags));
    EXPECT_EQ(Service::kCryptoNone, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, wpa_flags));
    EXPECT_EQ(Service::kCryptoRc4, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, rsn_flags));
    EXPECT_EQ(Service::kCryptoAes, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, wparsn_flags));
    EXPECT_EQ(Service::kCryptoAes, WiFiService::ComputeCipher8021x(endpoints));
  }

  // Multiple endpoints.
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, open_flags));
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, open_flags));
    EXPECT_EQ(Service::kCryptoNone, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, open_flags));
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, wpa_flags));
    EXPECT_EQ(Service::kCryptoNone, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, wpa_flags));
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, wpa_flags));
    EXPECT_EQ(Service::kCryptoRc4, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, wpa_flags));
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, rsn_flags));
    EXPECT_EQ(Service::kCryptoRc4, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, rsn_flags));
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, rsn_flags));
    EXPECT_EQ(Service::kCryptoAes, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, wparsn_flags));
    endpoints.insert(
        MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, wparsn_flags));
    EXPECT_EQ(Service::kCryptoAes, WiFiService::ComputeCipher8021x(endpoints));
  }
}

TEST_F(WiFiServiceTest, Unload) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityNone);
  EXPECT_CALL(*wifi(), DestroyIPConfigLease(service->GetStorageIdentifier()))
      .Times(1);
  service->Unload();
}

TEST_F(WiFiServiceTest, PropertyChanges) {
  WiFiServiceRefPtr service = MakeServiceWithMockManager();
  ServiceMockAdaptor* adaptor = GetAdaptor(service.get());
  // It is important to test these property changes before having wifi pointer
  // set because there are race scenarios where e.g. due to event queueing we
  // could end up transitioning to connected without having valid wifi device,
  // so shill needs to be ready for this.
  TestCommonPropertyChanges(service, adaptor);
  TestAutoConnectPropertyChange(service, adaptor);

  EXPECT_CALL(*adaptor, EmitRpcIdentifierChanged(kDeviceProperty, _));
  SetWiFi(service, wifi());
  Mock::VerifyAndClearExpectations(adaptor);

  EXPECT_CALL(*adaptor, EmitRpcIdentifierChanged(kDeviceProperty, _));
  service->ResetWiFi();
  Mock::VerifyAndClearExpectations(adaptor);
}

// Custom property setters should return false, and make no changes, if
// the new value is the same as the old value.
TEST_F(WiFiServiceTest, CustomSetterNoopChange) {
  WiFiServiceRefPtr service = MakeServiceWithMockManager();
  TestCustomSetterNoopChange(service, mock_manager());
}

TEST_F(WiFiServiceTest, SuspectedCredentialFailure) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityPsk);
  EXPECT_FALSE(service->has_ever_connected());
  EXPECT_EQ(0, service->suspected_credential_failures_);

  EXPECT_TRUE(service->AddSuspectedCredentialFailure());
  EXPECT_EQ(0, service->suspected_credential_failures_);

  service->has_ever_connected_ = true;
  for (int i = 0; i < WiFiService::kSuspectedCredentialFailureThreshold - 1;
       ++i) {
    EXPECT_FALSE(service->AddSuspectedCredentialFailure());
    EXPECT_EQ(i + 1, service->suspected_credential_failures_);
  }

  EXPECT_TRUE(service->AddSuspectedCredentialFailure());
  // Make sure the failure state does not reset just because we ask again.
  EXPECT_TRUE(service->AddSuspectedCredentialFailure());
  // Make sure the failure state resets because of a credential change.
  // A credential change changes the has_ever_connected to false and
  // immediately returns true when attempting to add the failure.
  Error error;
  service->SetPassphrase("Panchromatic Resonance", &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_TRUE(service->AddSuspectedCredentialFailure());
  EXPECT_EQ(0, service->suspected_credential_failures_);

  // Make sure that we still return true after resetting the failure
  // count.
  service->suspected_credential_failures_ = 3;
  EXPECT_EQ(3, service->suspected_credential_failures_);
  service->ResetSuspectedCredentialFailures();
  EXPECT_EQ(0, service->suspected_credential_failures_);
  EXPECT_TRUE(service->AddSuspectedCredentialFailure());
}

TEST_F(WiFiServiceTest, GetTethering) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);
  EXPECT_EQ(Service::TetheringState::kNotDetected, service->GetTethering());

  // Since the device isn't connected, we shouldn't even query the WiFi device.
  EXPECT_CALL(*wifi(), IsConnectedViaTether()).Times(0);
  SetWiFiForService(service, wifi());
  EXPECT_EQ(Service::TetheringState::kNotDetected, service->GetTethering());
  Mock::VerifyAndClearExpectations(wifi().get());

  scoped_refptr<MockProfile> mock_profile(new NiceMock<MockProfile>(manager()));
  service->set_profile(mock_profile);
  service->SetState(Service::kStateConnected);

  // A connected service should return "confirmed" iff the underlying device
  // reports it is tethered.
  EXPECT_CALL(*wifi(), IsConnectedViaTether())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_EQ(Service::TetheringState::kConfirmed, service->GetTethering());
  EXPECT_EQ(Service::TetheringState::kNotDetected, service->GetTethering());
  Mock::VerifyAndClearExpectations(wifi().get());

  // Add two endpoints that have a BSSID associated with some Android devices
  // in tethering mode.
  WiFiEndpointRefPtr endpoint_android1 =
      MakeOpenEndpoint("a", "02:1a:11:00:00:01", 2412, 0);
  service->AddEndpoint(endpoint_android1);
  WiFiEndpointRefPtr endpoint_android2 =
      MakeOpenEndpoint("a", "02:1a:11:00:00:02", 2412, 0);
  service->AddEndpoint(endpoint_android2);

  // Since there are two endpoints, we should not detect tethering mode.
  EXPECT_CALL(*wifi(), IsConnectedViaTether()).WillOnce(Return(false));
  EXPECT_EQ(Service::TetheringState::kNotDetected, service->GetTethering());

  // If the device reports that it is tethered, this should override any
  // findings gained from examining the endpoints.
  EXPECT_CALL(*wifi(), IsConnectedViaTether()).WillOnce(Return(true));
  EXPECT_EQ(Service::TetheringState::kConfirmed, service->GetTethering());

  // Continue in the un-tethered device case for a few more tests below.
  Mock::VerifyAndClearExpectations(wifi().get());
  EXPECT_CALL(*wifi(), IsConnectedViaTether()).WillRepeatedly(Return(false));

  // Removing an endpoint so we only have one should put us in the "Suspected"
  // state.
  service->RemoveEndpoint(endpoint_android1);
  EXPECT_EQ(Service::TetheringState::kSuspected, service->GetTethering());

  // Add a different endpoint which has a locally administered MAC address
  // but not one used by Android.
  service->RemoveEndpoint(endpoint_android2);
  WiFiEndpointRefPtr endpoint_ios =
      MakeOpenEndpoint("a", "02:00:00:00:00:01", 2412, 0);
  service->AddEndpoint(endpoint_ios);
  EXPECT_EQ(Service::TetheringState::kNotDetected, service->GetTethering());

  // If this endpoint reports the right vendor OUI, we should suspect
  // it to be tethered.  However since this evaluation normally only
  // happens in the endpoint constructor, we must force it to recalculate.
  endpoint_ios->vendor_information_.oui_set.insert(Tethering::kIosOui);
  endpoint_ios->CheckForTetheringSignature();
  EXPECT_EQ(Service::TetheringState::kSuspected, service->GetTethering());

  // If the device reports that it is tethered, this should override any
  // findings gained from examining the endpoints.
  Mock::VerifyAndClearExpectations(wifi().get());
  EXPECT_CALL(*wifi(), IsConnectedViaTether()).WillOnce(Return(true));
  EXPECT_EQ(Service::TetheringState::kConfirmed, service->GetTethering());
}

TEST_F(WiFiServiceTest, IsVisible) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityNone);
  ServiceMockAdaptor* adaptor = GetAdaptor(wifi_service.get());

  // Adding the first endpoint emits a change: Visible = true.
  EXPECT_CALL(*adaptor, EmitBoolChanged(kVisibleProperty, true));
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint("a", "00:00:00:00:00:01", 0, 0);
  wifi_service->AddEndpoint(endpoint);
  EXPECT_TRUE(wifi_service->IsVisible());
  Mock::VerifyAndClearExpectations(adaptor);

  // Removing the last endpoint emits a change: Visible = false.
  EXPECT_CALL(*adaptor, EmitBoolChanged(kVisibleProperty, false));
  wifi_service->RemoveEndpoint(endpoint);
  EXPECT_FALSE(wifi_service->IsVisible());
  Mock::VerifyAndClearExpectations(adaptor);

  // Entering the a connecting state emits a change: Visible = true
  // although the service has no endpoints.
  EXPECT_CALL(*adaptor, EmitBoolChanged(kVisibleProperty, true));
  wifi_service->SetState(Service::kStateAssociating);
  EXPECT_TRUE(wifi_service->IsVisible());
  Mock::VerifyAndClearExpectations(adaptor);

  // Moving between connecting / connected states does not trigger an Emit.
  EXPECT_CALL(*adaptor, EmitBoolChanged(kVisibleProperty, _)).Times(0);
  wifi_service->SetState(Service::kStateConfiguring);
  EXPECT_TRUE(wifi_service->IsVisible());
  Mock::VerifyAndClearExpectations(adaptor);

  // Entering the Idle state emits a change: Visible = false.
  EXPECT_CALL(*adaptor, EmitBoolChanged(kVisibleProperty, false));
  wifi_service->SetState(Service::kStateIdle);
  EXPECT_FALSE(wifi_service->IsVisible());
  Mock::VerifyAndClearExpectations(adaptor);
}

TEST_F(WiFiServiceTest, ChooseDevice) {
  scoped_refptr<MockWiFi> wifi = MakeSimpleWiFi("test_wifi");
  WiFiServiceRefPtr service = MakeServiceWithMockManager();

  EXPECT_CALL(*mock_manager(),
              GetEnabledDeviceWithTechnology(Technology(Technology::kWiFi)))
      .WillOnce(Return(wifi));
  EXPECT_EQ(wifi, service->ChooseDevice());
  Mock::VerifyAndClearExpectations(mock_manager());
}

TEST_F(WiFiServiceTest, SetMACPolicy) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityNone);
  Error ret;

  EXPECT_FALSE(wifi_service->SetMACPolicy("foo", &ret));
  EXPECT_FALSE(ret.IsSuccess());
  EXPECT_FALSE(wifi_service->SetMACPolicy("", &ret));
  EXPECT_FALSE(ret.IsSuccess());

  wifi()->random_mac_supported_ = true;
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyHardware, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::Hardware);
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyFullRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::FullRandom);
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyOUIRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::OUIRandom);
  EXPECT_TRUE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::PersistentRandom);
  EXPECT_TRUE(wifi_service->SetMACPolicy(
      kWifiRandomMacPolicyNonPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::NonPersistentRandom);

  wifi()->random_mac_supported_ = false;
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyHardware, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::Hardware);
  EXPECT_FALSE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyFullRandom, &ret));
  EXPECT_FALSE(ret.IsSuccess());
  EXPECT_FALSE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyOUIRandom, &ret));
  EXPECT_FALSE(ret.IsSuccess());
  EXPECT_FALSE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_FALSE(ret.IsSuccess());
  EXPECT_FALSE(wifi_service->SetMACPolicy(
      kWifiRandomMacPolicyNonPersistentRandom, &ret));
  EXPECT_FALSE(ret.IsSuccess());
}

bool verifyAddressCorrect(const MACAddress& addr) {
  static constexpr auto kMulticastBit = 1 << 0;
  static constexpr auto kLocallyAdministeredBit = 1 << 1;
  EXPECT_TRUE(addr.is_set());
  uint8_t msb;
  EXPECT_EQ(sscanf(addr.ToString().substr(0, 2).c_str(), "%02hhx", &msb), 1);
  EXPECT_EQ((msb & (kMulticastBit | kLocallyAdministeredBit)),
            kLocallyAdministeredBit);
  return addr.is_set() && ((msb & (kMulticastBit | kLocallyAdministeredBit)) ==
                           kLocallyAdministeredBit);
}

TEST_F(WiFiServiceTest, UpdateMACAddressNonPersistentPolicy) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityNone);
  wifi()->random_mac_supported_ = true;
  auto clock_ptr = std::make_unique<base::SimpleTestClock>();
  base::SimpleTestClock* clock = clock_ptr.get();
  wifi_service->clock_ = std::move(clock_ptr);
  Error ret;

  EXPECT_TRUE(wifi_service->SetMACPolicy(
      kWifiRandomMacPolicyNonPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::NonPersistentRandom);
  auto mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.update);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  auto addr = wifi_service->mac_address_.ToString();
  clock->Advance(MACAddress::kDefaultExpirationTime);
  // Set these times to first test MAC expiry path
  wifi_service->disconnect_time_ = clock->Now();
  wifi_service->dhcp4_lease_expiry_ = clock->Now() + base::Hours(1);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.update);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);

  // Make sure local admin bit is cleared.
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  // Cross the MAC expiry
  clock->Advance(base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.update);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);

  addr = wifi_service->mac_address_.ToString();
  // MAC is valid for 24h now so next rotation time is disconnect + 4h.
  // Let's test some point from (disconnect, lease_expiry) period.
  clock->Advance(base::Minutes(30));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.update);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);
  // Now [lease_expiry, disconnect + 4h) period - should still be no
  // change.
  clock->Advance(base::Hours(2));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.update);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);
  // Now cross the rotation deadline - address should change.
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  clock->Advance(base::Hours(2));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.update);
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);
}

TEST_F(WiFiServiceTest, UpdateMACAddressPersistentPolicy) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityNone);
  wifi()->random_mac_supported_ = true;
  auto clock_ptr = std::make_unique<base::SimpleTestClock>();
  base::SimpleTestClock* clock = clock_ptr.get();
  wifi_service->clock_ = std::move(clock_ptr);
  wifi_service->security_ = kSecurityPsk;
  wifi_service->was_portal_detected_ = 1;
  Error ret;

  EXPECT_TRUE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::PersistentRandom);

  auto mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.update);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  auto addr = wifi_service->mac_address_.ToString();
  // Check if lease/disconnect time does not cause rotation
  wifi_service->disconnect_time_ = clock->Now() - base::Hours(5);
  wifi_service->dhcp4_lease_expiry_ = clock->Now() - base::Hours(1);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.update);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);

  clock->Advance(MACAddress::kDefaultExpirationTime + base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.update);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);
  wifi_service->security_ = kSecurityNone;
  clock->Advance(MACAddress::kDefaultExpirationTime + base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.update);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);
  wifi_service->was_portal_detected_ = 0;

  wifi_service->mac_address_.Clear();
  clock->Advance(MACAddress::kDefaultExpirationTime + base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.update);
  addr = wifi_service->mac_address_.ToString();
  // Make sure local admin bit is cleared.
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  clock->Advance(MACAddress::kDefaultExpirationTime + base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.update);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);
}

TEST_F(WiFiServiceTest, UpdateMACAddressPolicySwitch) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityNone);
  wifi()->random_mac_supported_ = true;
  auto clock_ptr = std::make_unique<base::SimpleTestClock>();
  base::SimpleTestClock* clock = clock_ptr.get();
  wifi_service->clock_ = std::move(clock_ptr);
  wifi_service->security_ = kSecurityPsk;
  wifi_service->was_portal_detected_ = 1;
  Error ret;

  EXPECT_TRUE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::PersistentRandom);

  wifi_service->mac_address_.Randomize();
  EXPECT_FALSE(wifi_service->mac_address_.will_expire());
  auto addr = wifi_service->mac_address_.ToString();
  // Make sure local admin bit is cleared.
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  // Simulate changing policy.
  EXPECT_TRUE(wifi_service->SetMACPolicy(
      kWifiRandomMacPolicyNonPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::NonPersistentRandom);
  auto mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.update);
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  EXPECT_TRUE(wifi_service->mac_address_.will_expire());

  addr = wifi_service->mac_address_.ToString();
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  EXPECT_TRUE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::PersistentRandom);
  clock->Advance(MACAddress::kDefaultExpirationTime + base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.update);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);
  EXPECT_TRUE(wifi_service->mac_address_.will_expire());

  addr = wifi_service->mac_address_.ToString();
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  EXPECT_TRUE(wifi_service->SetMACPolicy(
      kWifiRandomMacPolicyNonPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::NonPersistentRandom);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.update);
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  EXPECT_TRUE(wifi_service->mac_address_.will_expire());
}

TEST_F(WiFiServiceTest, RandomizationNotSupported) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityNone);
  wifi()->random_mac_supported_ = false;
  Error ret;

  EXPECT_TRUE(service->SetMACPolicy(kWifiRandomMacPolicyHardware, &ret));
  EXPECT_FALSE(service->SetMACPolicy(kWifiRandomMacPolicyFullRandom, &ret));
  EXPECT_FALSE(service->SetMACPolicy(kWifiRandomMacPolicyOUIRandom, &ret));
  EXPECT_FALSE(
      service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_FALSE(
      service->SetMACPolicy(kWifiRandomMacPolicyNonPersistentRandom, &ret));
}

TEST_F(WiFiServiceTest, RandomizationBlocklist) {
  std::array<std::string, 5> ssid_blocklist = {
      "ACWiFi", "AA-Inflight", "gogoinflight", "DeltaWiFi", "DeltaWiFi.com"};

  for (auto& ssid : ssid_blocklist) {
    auto service = MakeServiceSSID(kSecurityPsk, ssid);
    Error ret;
    EXPECT_TRUE(service->SetMACPolicy(kWifiRandomMacPolicyHardware, &ret));
    EXPECT_FALSE(service->SetMACPolicy(kWifiRandomMacPolicyFullRandom, &ret));
    EXPECT_FALSE(service->SetMACPolicy(kWifiRandomMacPolicyOUIRandom, &ret));
    EXPECT_FALSE(
        service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
    EXPECT_FALSE(
        service->SetMACPolicy(kWifiRandomMacPolicyNonPersistentRandom, &ret));
  }
}

TEST_F(WiFiServiceTest, CompareWithSameTechnology) {
  PasspointCredentialsRefPtr credentials = new PasspointCredentials("an_id");

  WiFiServiceRefPtr a = MakeServiceWithWiFi(kSecurity8021x);
  WiFiServiceRefPtr b = MakeServiceWithWiFi(kSecurity8021x);

  // a does not have Passpoint credentials while b have some
  b->set_parent_credentials(credentials);
  EXPECT_TRUE(SortingOrderIs(a, b));
  EXPECT_FALSE(SortingOrderIs(b, a));

  // a and be have Passpoint credentials but a different match priority
  a->set_parent_credentials(credentials);
  a->set_match_priority(3);
  b->set_match_priority(0);
  EXPECT_TRUE(SortingOrderIs(b, a));
  a->set_match_priority(1);
  b->set_match_priority(2);
  EXPECT_TRUE(SortingOrderIs(a, b));

  // Both have the same Passpoint credentials and the same priority, there will
  // be no order.
  a->set_match_priority(0);
  b->set_match_priority(0);
  EXPECT_FALSE(SortingOrderIs(a, b));
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoSuccess) {
  WiFiEndpointRefPtr ep = MakeOpenEndpoint("a", "00:00:00:00:00:01", 0, 0);
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityNone);
  service->AddEndpoint(ep);

  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.ssid, "a");
  EXPECT_EQ(info.bssid, "00:00:00:00:00:01");
  EXPECT_EQ(info.security, Metrics::kWiFiSecurityNone);
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoNoBSSID) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityNone);
  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.ap_oui, 0xFFFFFFFF);
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoOUI) {
  WiFiEndpointRefPtr ep = MakeOpenEndpoint("a", "01:23:45:67:89:ab", 0, 0);
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityNone);
  service->AddEndpoint(ep);

  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.security, Metrics::kWiFiSecurityNone);
  if ((false)) {
    EXPECT_EQ(info.ap_oui, 0x00012345);
  }
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoLowBand) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);
  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr ep =
      MakeEndpoint("a", "00:00:00:00:00:01", 2412, -57, flags);
  service->AddEndpoint(ep);

  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.band, Metrics::kWiFiFrequencyRange24);
  EXPECT_EQ(info.channel, Metrics::kWiFiChannel2412);
  EXPECT_EQ(info.rssi, -57);
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoHighBand) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);
  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr ep =
      MakeEndpoint("a", "00:00:00:00:00:01", 5180, -71, flags);
  service->AddEndpoint(ep);

  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.band, Metrics::kWiFiFrequencyRange5);
  EXPECT_EQ(info.channel, Metrics::kWiFiChannel5180);
  EXPECT_EQ(info.rssi, -71);
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoUltraHighBand) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityNone);
  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr ep =
      MakeEndpoint("a", "00:00:00:00:00:01", 6115, -40, flags);
  service->AddEndpoint(ep);

  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.band, Metrics::kWiFiFrequencyRange6);
  EXPECT_EQ(info.channel, Metrics::kWiFiChannel6115);
  EXPECT_EQ(info.rssi, -40);
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoSecurity) {
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_sae = true;
    WiFiEndpointRefPtr ep = MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(ep);

    Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
    EXPECT_EQ(Metrics::WiFiSecurityStringToEnum(kSecurityWpa3), info.security);
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_psk = true;
    WiFiEndpointRefPtr ep = MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(ep);
    Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
    EXPECT_EQ(Metrics::WiFiSecurityStringToEnum(kSecurityRsn), info.security);
  }
}

}  // namespace shill
