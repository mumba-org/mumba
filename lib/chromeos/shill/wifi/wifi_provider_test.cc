// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_provider.h"

#include <string>
#include <vector>

#include <base/format_macros.h>
#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_profile.h"
#include "shill/net/ieee80211.h"
#include "shill/store/fake_store.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/technology.h"
#include "shill/test_event_dispatcher.h"
#include "shill/wifi/mock_passpoint_credentials.h"
#include "shill/wifi/mock_wifi_service.h"
#include "shill/wifi/passpoint_credentials.h"
#include "shill/wifi/wifi_endpoint.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StartsWith;
using ::testing::StrictMock;

namespace shill {

class WiFiProviderTest : public testing::Test {
 public:
  WiFiProviderTest()
      : manager_(&control_, &dispatcher_, &metrics_),
        provider_(&manager_),
        default_profile_(new NiceMock<MockProfile>(&manager_, "default")),
        user_profile_(new NiceMock<MockProfile>(&manager_, "user")),
        storage_entry_index_(0) {}

  ~WiFiProviderTest() override = default;

  void SetUp() override {
    EXPECT_CALL(*default_profile_, IsDefault()).WillRepeatedly(Return(true));
    EXPECT_CALL(*default_profile_, GetStorage())
        .WillRepeatedly(Return(&default_profile_storage_));
    EXPECT_CALL(*default_profile_, GetConstStorage())
        .WillRepeatedly(Return(&default_profile_storage_));

    EXPECT_CALL(*user_profile_, IsDefault()).WillRepeatedly(Return(false));
    EXPECT_CALL(*user_profile_, GetStorage())
        .WillRepeatedly(Return(&user_profile_storage_));
    EXPECT_CALL(*user_profile_, GetConstStorage())
        .WillRepeatedly(Return(&user_profile_storage_));

    // Default expectations for UMA metrics. Individual test cases
    // will override these, by adding later expectations.
    EXPECT_CALL(metrics_,
                SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, _,
                          Metrics::kMetricRememberedWiFiNetworkCountMin,
                          Metrics::kMetricRememberedWiFiNetworkCountMax,
                          Metrics::kMetricRememberedWiFiNetworkCountNumBuckets))
        .Times(AnyNumber());
    EXPECT_CALL(
        metrics_,
        SendToUMA(
            StartsWith("Network.Shill.WiFi.RememberedPrivateNetworkCount."), _,
            Metrics::kMetricRememberedWiFiNetworkCountMin,
            Metrics::kMetricRememberedWiFiNetworkCountMax,
            Metrics::kMetricRememberedWiFiNetworkCountNumBuckets))
        .Times(AnyNumber());
    EXPECT_CALL(
        metrics_,
        SendToUMA(
            StartsWith("Network.Shill.WiFi.RememberedSharedNetworkCount."), _,
            Metrics::kMetricRememberedWiFiNetworkCountMin,
            Metrics::kMetricRememberedWiFiNetworkCountMax,
            Metrics::kMetricRememberedWiFiNetworkCountNumBuckets))
        .Times(AnyNumber());
  }

  // Used by mock invocations of RegisterService() to maintain the side-effect
  // of assigning a profile to |service|.
  void BindServiceToDefaultProfile(const ServiceRefPtr& service) {
    service->set_profile(default_profile_);
  }
  void BindServiceToUserProfile(const ServiceRefPtr& service) {
    service->set_profile(user_profile_);
  }

 protected:
  using MockWiFiServiceRefPtr = scoped_refptr<MockWiFiService>;

  void CreateServicesFromProfile(Profile* profile) {
    provider_.CreateServicesFromProfile(profile);
  }

  const std::vector<WiFiServiceRefPtr> GetServices() {
    return provider_.services_;
  }

  const WiFiProvider::EndpointServiceMap& GetServiceByEndpoint() {
    return provider_.service_by_endpoint_;
  }

  bool GetRunning() { return provider_.running_; }

  void RemoveCredentials(const PasspointCredentialsRefPtr& credentials) {
    provider_.RemoveCredentials(credentials);
  }

  void AddStringParameterToStorage(FakeStore* storage,
                                   const std::string& id,
                                   const std::string& key,
                                   const std::string& value) {
    storage->SetString(id, key, value);
  }

  // Adds service to profile's storage. But does not set profile on the Service.
  std::string AddServiceToProfileStorage(Profile* profile,
                                         const char* ssid,
                                         const char* mode,
                                         const char* security_class,
                                         bool is_hidden,
                                         bool provide_hidden) {
    std::string id = base::StringPrintf("entry_%d", storage_entry_index_);
    auto* profile_storage = static_cast<FakeStore*>(profile->GetStorage());
    AddStringParameterToStorage(profile_storage, id, WiFiService::kStorageType,
                                kTypeWifi);
    if (ssid) {
      const std::string ssid_string(ssid);
      const std::string hex_ssid(
          base::HexEncode(ssid_string.data(), ssid_string.size()));
      AddStringParameterToStorage(profile_storage, id,
                                  WiFiService::kStorageSSID, hex_ssid);
    }
    if (mode) {
      AddStringParameterToStorage(profile_storage, id,
                                  WiFiService::kStorageMode, mode);
    }
    if (security_class) {
      AddStringParameterToStorage(profile_storage, id,
                                  WiFiService::kStorageSecurityClass,
                                  security_class);
    }
    if (provide_hidden) {
      profile_storage->SetBool(id, kWifiHiddenSsid, is_hidden);
    } else {
      profile_storage->DeleteKey(id, kWifiHiddenSsid);
    }
    storage_entry_index_++;
    return id;
  }

  void SetServiceParameters(const char* ssid,
                            const char* mode,
                            const char* security_class,
                            bool is_hidden,
                            bool provide_hidden,
                            KeyValueStore* args) {
    args->Set<std::string>(kTypeProperty, kTypeWifi);
    if (ssid) {
      // TODO(pstew): When Chrome switches to using kWifiHexSsid primarily for
      // GetService and friends, we should switch to doing so here ourselves.
      args->Set<std::string>(kSSIDProperty, ssid);
    }
    if (mode) {
      args->Set<std::string>(kModeProperty, mode);
    }
    if (security_class) {
      args->Set<std::string>(kSecurityClassProperty, security_class);
    }
    if (provide_hidden) {
      args->Set<bool>(kWifiHiddenSsid, is_hidden);
    }
  }

  ServiceRefPtr CreateTemporaryService(const char* ssid,
                                       const char* mode,
                                       const char* security,
                                       bool is_hidden,
                                       bool provide_hidden,
                                       Error* error) {
    KeyValueStore args;
    SetServiceParameters(ssid, mode, security, is_hidden, provide_hidden,
                         &args);
    return provider_.CreateTemporaryService(args, error);
  }

  WiFiServiceRefPtr GetService(const char* ssid,
                               const char* mode,
                               const char* security_class,
                               bool is_hidden,
                               bool provide_hidden,
                               Error* error) {
    KeyValueStore args;
    SetServiceParameters(ssid, mode, security_class, is_hidden, provide_hidden,
                         &args);
    return provider_.GetWiFiService(args, error);
  }

  WiFiServiceRefPtr GetWiFiService(const KeyValueStore& args, Error* error) {
    return provider_.GetWiFiService(args, error);
  }

  WiFiServiceRefPtr FindService(const std::vector<uint8_t>& ssid,
                                const std::string& mode,
                                const std::string& security) {
    return provider_.FindService(ssid, mode, security);
  }
  WiFiEndpointRefPtr MakeOpenEndpoint(const std::string& ssid,
                                      const std::string& bssid,
                                      uint16_t frequency,
                                      int16_t signal_dbm) {
    return WiFiEndpoint::MakeOpenEndpoint(
        nullptr, nullptr, ssid, bssid,
        WPASupplicant::kNetworkModeInfrastructure, frequency, signal_dbm);
  }
  WiFiEndpointRefPtr Make8021xEndpoint(const std::string& ssid,
                                       const std::string& bssid,
                                       uint16_t frequency,
                                       int16_t signal_dbm) {
    WiFiEndpoint::SecurityFlags rsn_flags;
    rsn_flags.rsn_8021x = true;
    return WiFiEndpoint::MakeEndpoint(nullptr, nullptr, ssid, bssid,
                                      WPASupplicant::kNetworkModeInfrastructure,
                                      frequency, signal_dbm, rsn_flags);
  }
  WiFiEndpointRefPtr MakeEndpoint(
      const std::string& ssid,
      const std::string& bssid,
      uint16_t frequency,
      int16_t signal_dbm,
      const WiFiEndpoint::SecurityFlags& security_flags) {
    return WiFiEndpoint::MakeEndpoint(nullptr, nullptr, ssid, bssid,
                                      WPASupplicant::kNetworkModeInfrastructure,
                                      frequency, signal_dbm, security_flags);
  }
  MockWiFiServiceRefPtr AddMockService(const std::vector<uint8_t>& ssid,
                                       const std::string& mode,
                                       const std::string& security,
                                       bool hidden_ssid) {
    MockWiFiServiceRefPtr service = new MockWiFiService(
        &manager_, &provider_, ssid, mode, security, hidden_ssid);
    provider_.services_.push_back(service);
    return service;
  }
  void AddEndpointToService(WiFiServiceRefPtr service,
                            const WiFiEndpointConstRefPtr& endpoint) {
    provider_.service_by_endpoint_[endpoint.get()] = service;
  }
  std::string AddCredentialsToProfileStorage(
      Profile* profile,
      const std::vector<std::string>& domains,
      const std::string& realm,
      const std::vector<uint64_t>& home_ois,
      const std::vector<uint64_t>& required_home_ois,
      const std::vector<uint64_t>& roaming_consortia,
      bool metered_override,
      const std::string& app_package_name) {
    std::string id = base::StringPrintf("entry_%d", storage_entry_index_);
    auto* profile_storage = static_cast<FakeStore*>(profile->GetStorage());
    PasspointCredentialsRefPtr creds = new PasspointCredentials(
        id, domains, realm, home_ois, required_home_ois, roaming_consortia,
        metered_override, app_package_name);
    creds->Save(profile_storage);
    storage_entry_index_++;
    return id;
  }
  PasspointCredentialsRefPtr GetCredentials(const std::string& id) {
    if (provider_.credentials_by_id_.find(id) ==
        provider_.credentials_by_id_.end()) {
      return nullptr;
    }
    return provider_.credentials_by_id_[id];
  }
  std::string AddCredentialsToProvider(
      const std::vector<std::string>& domains,
      const std::string& realm,
      const std::vector<uint64_t>& home_ois,
      const std::vector<uint64_t>& required_home_ois,
      const std::vector<uint64_t>& roaming_consortia,
      bool metered_override,
      const std::string& app_package_name) {
    std::string id = PasspointCredentials::GenerateIdentifier();
    PasspointCredentialsRefPtr creds = new PasspointCredentials(
        id, domains, realm, home_ois, required_home_ois, roaming_consortia,
        metered_override, app_package_name);
    provider_.AddCredentials(creds);
    return id;
  }

  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  StrictMock<MockManager> manager_;
  WiFiProvider provider_;
  scoped_refptr<MockProfile> default_profile_;
  scoped_refptr<MockProfile> user_profile_;
  FakeStore default_profile_storage_;
  FakeStore user_profile_storage_;
  int storage_entry_index_;  // shared across profiles
};

MATCHER_P(RefPtrMatch, ref, "") {
  return ref.get() == arg.get();
}

TEST_F(WiFiProviderTest, Start) {
  // Doesn't do anything really.  Just testing for no crash.
  EXPECT_TRUE(GetServices().empty());
  EXPECT_FALSE(GetRunning());
  provider_.Start();
  EXPECT_TRUE(GetServices().empty());
  EXPECT_TRUE(GetRunning());
  EXPECT_TRUE(GetServiceByEndpoint().empty());
  EXPECT_FALSE(provider_.disable_vht());
}

TEST_F(WiFiProviderTest, Stop) {
  MockWiFiServiceRefPtr service0 = AddMockService(
      std::vector<uint8_t>(1, '0'), kModeManaged, kSecurityNone, false);
  MockWiFiServiceRefPtr service1 = AddMockService(
      std::vector<uint8_t>(1, '1'), kModeManaged, kSecurityNone, false);
  WiFiEndpointRefPtr endpoint = MakeOpenEndpoint("", "00:00:00:00:00:00", 0, 0);
  AddEndpointToService(service0, endpoint);

  EXPECT_EQ(2, GetServices().size());
  EXPECT_FALSE(GetServiceByEndpoint().empty());
  EXPECT_CALL(*service0, ResetWiFi()).Times(1);
  EXPECT_CALL(*service1, ResetWiFi()).Times(1);
  EXPECT_CALL(manager_, DeregisterService(RefPtrMatch(service0))).Times(1);
  EXPECT_CALL(manager_, DeregisterService(RefPtrMatch(service1))).Times(1);
  provider_.Stop();
  // Verify now, so it's clear that this happened as a result of the call
  // above, and not anything in the destructor(s).
  Mock::VerifyAndClearExpectations(service0.get());
  Mock::VerifyAndClearExpectations(service1.get());
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_TRUE(GetServices().empty());
  EXPECT_TRUE(GetServiceByEndpoint().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileWithNoGroups) {
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileMissingSSID) {
  AddServiceToProfileStorage(default_profile_.get(), nullptr, kModeManaged,
                             kSecurityNone, false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileEmptySSID) {
  AddServiceToProfileStorage(default_profile_.get(), "", kModeManaged,
                             kSecurityNone, false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileMissingMode) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", nullptr,
                             kSecurityNone, false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileEmptyMode) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", "", kSecurityNone,
                             false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileMissingSecurity) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged,
                             nullptr, false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileEmptySecurity) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged, "",
                             false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileMissingHidden) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged,
                             kSecurityNone, false, false);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileSingle) {
  std::string kSSID("foo");
  AddServiceToProfileStorage(default_profile_.get(), kSSID.c_str(),
                             kModeManaged, kSecurityNone, false, true);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToDefaultProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 1,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets))
      .Times(2);
  CreateServicesFromProfile(default_profile_.get());
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());

  const WiFiServiceRefPtr service = GetServices().front();
  const std::string service_ssid(service->ssid().begin(),
                                 service->ssid().end());
  EXPECT_EQ(kSSID, service_ssid);
  EXPECT_EQ(kModeManaged, service->mode());
  EXPECT_TRUE(service->IsSecurityMatch(kSecurityNone));

  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_EQ(1, GetServices().size());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileHiddenButConnected) {
  std::string kSSID("foo");
  AddServiceToProfileStorage(default_profile_.get(), kSSID.c_str(),
                             kModeManaged, kSecurityNone, true, true);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToDefaultProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, IsTechnologyConnected(Technology(Technology::kWiFi)))
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, RequestScan(_, _)).Times(0);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 1,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets))
      .Times(2);
  CreateServicesFromProfile(default_profile_.get());
  Mock::VerifyAndClearExpectations(&manager_);

  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, IsTechnologyConnected(_)).Times(0);
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  CreateServicesFromProfile(default_profile_.get());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileHiddenNotConnected) {
  std::string kSSID("foo");
  AddServiceToProfileStorage(default_profile_.get(), kSSID.c_str(),
                             kModeManaged, kSecurityNone, true, true);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToDefaultProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, IsTechnologyConnected(Technology(Technology::kWiFi)))
      .WillOnce(Return(false));
  EXPECT_CALL(manager_, RequestScan(kTypeWifi, _)).Times(1);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 1,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets))
      .Times(2);
  CreateServicesFromProfile(default_profile_.get());
  Mock::VerifyAndClearExpectations(&manager_);

  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, IsTechnologyConnected(_)).Times(0);
  EXPECT_CALL(manager_, RequestScan(_, _)).Times(0);
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  CreateServicesFromProfile(default_profile_.get());
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfileNonWiFi) {
  const std::string kEntryName("name");
  Error error;
  EXPECT_EQ(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, kEntryName, &error));
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_THAT(error.message(),
              StartsWith("Unspecified or invalid network type"));
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfileMissingSSID) {
  std::string entry_name =
      AddServiceToProfileStorage(default_profile_.get(), nullptr, kModeManaged,
                                 kSecurityNone, false, true);
  Error error;
  EXPECT_EQ(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, entry_name, &error));
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_THAT(error.message(), StartsWith("Unspecified or invalid SSID"));
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfileMissingMode) {
  std::string entry_name = AddServiceToProfileStorage(
      default_profile_.get(), "foo", "", kSecurityNone, false, true);

  Error error;
  EXPECT_EQ(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, entry_name, &error));
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_THAT(error.message(), StartsWith("Network mode not specified"));
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfileMissingSecurity) {
  std::string entry_name = AddServiceToProfileStorage(
      default_profile_.get(), "foo", kModeManaged, "", false, true);

  Error error;
  EXPECT_EQ(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, entry_name, &error));
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_THAT(error.message(),
              StartsWith("Unspecified or invalid security class"));
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfileMissingHidden) {
  std::string entry_name = AddServiceToProfileStorage(
      default_profile_.get(), "foo", kModeManaged, kSecurityNone, false, false);

  Error error;
  EXPECT_EQ(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, entry_name, &error));
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_THAT(error.message(), StartsWith("Hidden SSID not specified"));
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfile) {
  std::string entry_name = AddServiceToProfileStorage(
      default_profile_.get(), "foo", kModeManaged, kSecurityNone, false, true);

  Error error;
  EXPECT_NE(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, entry_name, &error));
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(WiFiProviderTest, CreateTwoServices) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged,
                             kSecurityNone, false, true);
  AddServiceToProfileStorage(default_profile_.get(), "bar", kModeManaged,
                             kSecurityNone, true, true);
  EXPECT_CALL(manager_, RegisterService(_))
      .Times(2)
      .WillRepeatedly(
          Invoke(this, &WiFiProviderTest::BindServiceToDefaultProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, IsTechnologyConnected(Technology(Technology::kWiFi)))
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, RequestScan(kTypeWifi, _)).Times(0);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 2,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  CreateServicesFromProfile(default_profile_.get());
  Mock::VerifyAndClearExpectations(&manager_);

  EXPECT_EQ(2, GetServices().size());
}

TEST_F(WiFiProviderTest, ServiceSourceStats) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged,
                             kSecurityPsk, false /* is_hidden */,
                             true /* provide_hidden */);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToDefaultProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  // Processing default profile does not generate UMA metrics.
  EXPECT_CALL(
      metrics_,
      SendToUMA(StartsWith("Network.Shill.WiFi.RememberedSystemNetworkCount."),
                _, _, _, _))
      .Times(0);
  EXPECT_CALL(
      metrics_,
      SendToUMA(StartsWith("Network.Shill.WiFi.RememberedUserNetworkCount."), _,
                _, _, _))
      .Times(0);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricHiddenSSIDNetworkCount, _, _, _, _))
      .Times(0);
  EXPECT_CALL(metrics_,
              SendEnumToUMA(Metrics::kMetricHiddenSSIDEverConnected, _, _))
      .Times(0);
  CreateServicesFromProfile(default_profile_.get());
  Mock::VerifyAndClearExpectations(&manager_);

  AddServiceToProfileStorage(user_profile_.get(), "bar", kModeManaged,
                             kSecurityPsk, false /* is_hidden */,
                             true /* provide_hidden */);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToUserProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  // Processing user profile generates metrics for both, default profile,
  // and user profile.
  EXPECT_CALL(
      metrics_,
      SendToUMA(StartsWith("Network.Shill.WiFi.RememberedSystemNetworkCount."),
                0, Metrics::kMetricRememberedWiFiNetworkCountMin,
                Metrics::kMetricRememberedWiFiNetworkCountMax,
                Metrics::kMetricRememberedWiFiNetworkCountNumBuckets))
      .Times(3);  // none, wep, 802.1x
  EXPECT_CALL(
      metrics_,
      SendToUMA(StartsWith("Network.Shill.WiFi.RememberedUserNetworkCount."), 0,
                Metrics::kMetricRememberedWiFiNetworkCountMin,
                Metrics::kMetricRememberedWiFiNetworkCountMax,
                Metrics::kMetricRememberedWiFiNetworkCountNumBuckets))
      .Times(3);  // none, wep, 802.1x
  EXPECT_CALL(metrics_,
              SendToUMA("Network.Shill.WiFi.RememberedSystemNetworkCount.psk",
                        1, Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  EXPECT_CALL(metrics_,
              SendToUMA("Network.Shill.WiFi.RememberedUserNetworkCount.psk", 1,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricHiddenSSIDNetworkCount, 0,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  CreateServicesFromProfile(user_profile_.get());
}

TEST_F(WiFiProviderTest, ServiceSourceStatsHiddenSSID) {
  AddServiceToProfileStorage(user_profile_.get(), "foo", kModeManaged,
                             kSecurityPsk, true /* is_hidden */,
                             true /* provide_hidden */);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToUserProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, IsTechnologyConnected(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, RequestScan(kTypeWifi, _)).Times(1);
  // Processing user profile generates metrics for both, default profile,
  // and user profile.
  EXPECT_CALL(
      metrics_,
      SendToUMA(StartsWith("Network.Shill.WiFi.RememberedSystemNetworkCount."),
                0, Metrics::kMetricRememberedWiFiNetworkCountMin,
                Metrics::kMetricRememberedWiFiNetworkCountMax,
                Metrics::kMetricRememberedWiFiNetworkCountNumBuckets))
      .Times(4);  // none, wep, 802.1x, psk
  EXPECT_CALL(
      metrics_,
      SendToUMA(StartsWith("Network.Shill.WiFi.RememberedUserNetworkCount."), 0,
                Metrics::kMetricRememberedWiFiNetworkCountMin,
                Metrics::kMetricRememberedWiFiNetworkCountMax,
                Metrics::kMetricRememberedWiFiNetworkCountNumBuckets))
      .Times(3);  // none, wep, 802.1x
  EXPECT_CALL(metrics_,
              SendToUMA("Network.Shill.WiFi.RememberedUserNetworkCount.psk", 1,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricHiddenSSIDNetworkCount, 1,
                        Metrics::kMetricRememberedWiFiNetworkCountMin,
                        Metrics::kMetricRememberedWiFiNetworkCountMax,
                        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets));
  EXPECT_CALL(metrics_,
              SendBoolToUMA(Metrics::kMetricHiddenSSIDEverConnected, false));
  CreateServicesFromProfile(user_profile_.get());
}

TEST_F(WiFiProviderTest, GetServiceEmptyMode) {
  Error error;
  EXPECT_FALSE(
      GetService("foo", "", kSecurityNone, false, false, &error).get());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
}

TEST_F(WiFiProviderTest, GetServiceNoMode) {
  Error error;
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_TRUE(
      GetService("foo", nullptr, kSecurityNone, false, false, &error).get());
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(WiFiProviderTest, GetServiceBadMode) {
  Error error;
  EXPECT_FALSE(
      GetService("foo", "BogoMesh", kSecurityNone, false, false, &error).get());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("invalid service mode", error.message());
}

TEST_F(WiFiProviderTest, GetServiceAdhocNotSupported) {
  Error error;
  EXPECT_FALSE(
      GetService("foo", "adhoc", kSecurityNone, false, false, &error).get());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("invalid service mode", error.message());
}

TEST_F(WiFiProviderTest, GetServiceNoSSID) {
  Error error;
  EXPECT_FALSE(
      GetService(nullptr, kModeManaged, kSecurityNone, false, false, &error)
          .get());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("must specify SSID", error.message());
}

TEST_F(WiFiProviderTest, GetServiceEmptySSID) {
  Error error;
  EXPECT_FALSE(
      GetService("", kModeManaged, kSecurityNone, false, false, &error).get());
  EXPECT_EQ(Error::kInvalidNetworkName, error.type());
  EXPECT_EQ("SSID is too short", error.message());
}

TEST_F(WiFiProviderTest, GetServiceLongSSID) {
  Error error;
  std::string ssid(IEEE_80211::kMaxSSIDLen + 1, '0');
  EXPECT_FALSE(GetService(ssid.c_str(), kModeManaged, kSecurityNone, false,
                          false, &error)
                   .get());
  EXPECT_EQ(Error::kInvalidNetworkName, error.type());
  EXPECT_EQ("SSID is too long", error.message());
}

TEST_F(WiFiProviderTest, GetServiceJustLongEnoughSSID) {
  Error error;
  std::string ssid(IEEE_80211::kMaxSSIDLen, '0');
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_TRUE(GetService(ssid.c_str(), kModeManaged, kSecurityNone, false,
                         false, &error)
                  .get());
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(WiFiProviderTest, GetServiceBadSecurityClass) {
  Error error;
  EXPECT_FALSE(
      GetService("foo", kModeManaged, kSecurityRsn, false, false, &error)
          .get());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("invalid security class", error.message());
}

TEST_F(WiFiProviderTest, GetServiceMinimal) {
  Error error;
  const std::string kSSID("foo");
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  WiFiServiceRefPtr service =
      GetService(kSSID.c_str(), kModeManaged, nullptr, false, false, &error);
  EXPECT_NE(nullptr, service);
  EXPECT_TRUE(error.IsSuccess());
  const std::string service_ssid(service->ssid().begin(),
                                 service->ssid().end());
  EXPECT_EQ(kSSID, service_ssid);
  EXPECT_EQ(kModeManaged, service->mode());

  // These two should be set to their default values if not specified.
  EXPECT_TRUE(service->IsSecurityMatch(kSecurityNone));
  EXPECT_TRUE(service->hidden_ssid());
}

TEST_F(WiFiProviderTest, GetServiceFullySpecified) {
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  const std::string kSSID("bar");
  Error error;
  WiFiServiceRefPtr service0 = GetService(kSSID.c_str(), kModeManaged,
                                          kSecurityPsk, false, true, &error);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_TRUE(error.IsSuccess());
  const std::string service_ssid(service0->ssid().begin(),
                                 service0->ssid().end());
  EXPECT_EQ(kSSID, service_ssid);
  EXPECT_EQ(kModeManaged, service0->mode());
  EXPECT_TRUE(service0->IsSecurityMatch(kSecurityPsk));
  EXPECT_FALSE(service0->hidden_ssid());

  // Getting the same service parameters (even with a different hidden
  // parameter) should return the same service.
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  WiFiServiceRefPtr service1 =
      GetService(kSSID.c_str(), kModeManaged, kSecurityPsk, true, true, &error);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(service0, service1);
  EXPECT_EQ(1, GetServices().size());

  // Getting the same ssid with different other parameters should return
  // a different service.
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  WiFiServiceRefPtr service2 = GetService(kSSID.c_str(), kModeManaged,
                                          kSecurityNone, true, true, &error);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_NE(service0, service2);
  EXPECT_EQ(2, GetServices().size());
}

TEST_F(WiFiProviderTest, GetServiceByHexSsid) {
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  const std::string kSSID("bar");
  const std::string kHexSsid(base::HexEncode(kSSID.c_str(), kSSID.length()));

  KeyValueStore args;
  SetServiceParameters(nullptr, nullptr, kSecurityPsk, false, true, &args);
  args.Set<std::string>(kWifiHexSsid, kHexSsid);

  Error error;
  WiFiServiceRefPtr service = GetWiFiService(args, &error);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_TRUE(error.IsSuccess());
  const std::string service_ssid(service->ssid().begin(),
                                 service->ssid().end());
  EXPECT_EQ(kSSID, service_ssid);
  EXPECT_EQ(kModeManaged, service->mode());
  EXPECT_TRUE(service->IsSecurityMatch(kSecurityPsk));
  EXPECT_FALSE(service->hidden_ssid());

  // While here, make sure FindSimilarService also supports kWifiHexSsid.
  Error find_error;
  ServiceRefPtr find_service = provider_.FindSimilarService(args, &find_error);
  EXPECT_TRUE(find_error.IsSuccess());
  EXPECT_EQ(service, find_service);
}

TEST_F(WiFiProviderTest, GetServiceUnexpectedSecurityProperty) {
  const std::string kSSID("bar");
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kSSIDProperty, kSSID);
  args.Set<std::string>(kSecurityProperty, kSecurityRsn);
  args.Set<bool>(kWifiHiddenSsid, false);

  Error error;
  WiFiServiceRefPtr service;
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  service = GetWiFiService(args, &error);
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("Unexpected Security property", error.message());
}

TEST_F(WiFiProviderTest, GetServiceBogusSecurityClass) {
  const std::string kSSID("bar");
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kSSIDProperty, kSSID);
  args.Set<std::string>(kSecurityClassProperty, "rot-47");
  args.Set<bool>(kWifiHiddenSsid, false);

  Error error;
  WiFiServiceRefPtr service;
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  service = GetWiFiService(args, &error);
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
}

TEST_F(WiFiProviderTest, GetServiceNonSecurityClass) {
  const std::string kSSID("bar");
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kSSIDProperty, kSSID);
  // Using a non-class as a class should be rejected.
  args.Set<std::string>(kSecurityClassProperty, kSecurityRsn);
  args.Set<bool>(kWifiHiddenSsid, false);

  Error error;
  WiFiServiceRefPtr service;
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  service = GetWiFiService(args, &error);
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
}

TEST_F(WiFiProviderTest, FindSimilarService) {
  // Since CreateTemporyService uses exactly the same validation as
  // GetService, don't bother with testing invalid parameters.
  const std::string kSSID("foo");
  KeyValueStore args;
  SetServiceParameters(kSSID.c_str(), kModeManaged, kSecurityNone, true, true,
                       &args);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  Error get_service_error;
  WiFiServiceRefPtr service = GetWiFiService(args, &get_service_error);
  EXPECT_EQ(1, GetServices().size());

  {
    Error error;
    ServiceRefPtr find_service = provider_.FindSimilarService(args, &error);
    EXPECT_EQ(service, find_service);
    EXPECT_TRUE(error.IsSuccess());
  }

  args.Set<bool>(kWifiHiddenSsid, false);

  {
    Error error;
    ServiceRefPtr find_service = provider_.FindSimilarService(args, &error);
    EXPECT_EQ(service, find_service);
    EXPECT_TRUE(error.IsSuccess());
  }

  args.Set<std::string>(kSecurityClassProperty, kSecurityPsk);

  {
    Error error;
    ServiceRefPtr find_service = provider_.FindSimilarService(args, &error);
    EXPECT_EQ(nullptr, find_service);
    EXPECT_EQ(Error::kNotFound, error.type());
  }
}

TEST_F(WiFiProviderTest, CreateTemporaryService) {
  // Since CreateTemporyService uses exactly the same validation as
  // GetService, don't bother with testing invalid parameters.
  const std::string kSSID("foo");
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  Error error;
  WiFiServiceRefPtr service0 = GetService(kSSID.c_str(), kModeManaged,
                                          kSecurityNone, true, true, &error);
  EXPECT_EQ(1, GetServices().size());
  Mock::VerifyAndClearExpectations(&manager_);

  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  ServiceRefPtr service1 = CreateTemporaryService(
      kSSID.c_str(), kModeManaged, kSecurityNone, true, true, &error);

  // Test that a new service was created, but not registered with the
  // manager or added to the provider's service list.
  EXPECT_EQ(1, GetServices().size());
  EXPECT_TRUE(service0 != service1);
  EXPECT_TRUE(service1->HasOneRef());
}

TEST_F(WiFiProviderTest, FindServicePSK) {
  const std::string kSSID("an_ssid");
  Error error;
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  KeyValueStore args;
  SetServiceParameters(kSSID.c_str(), kModeManaged, kSecurityPsk, false, false,
                       &args);
  WiFiServiceRefPtr service = GetWiFiService(args, &error);
  ASSERT_NE(nullptr, service);
  const std::vector<uint8_t> ssid_bytes(kSSID.begin(), kSSID.end());
  WiFiServiceRefPtr wpa_service(
      FindService(ssid_bytes, kModeManaged, kSecurityWpa));
  EXPECT_EQ(service, wpa_service);
  WiFiServiceRefPtr rsn_service(
      FindService(ssid_bytes, kModeManaged, kSecurityRsn));
  EXPECT_EQ(service, rsn_service);
  WiFiServiceRefPtr psk_service(
      FindService(ssid_bytes, kModeManaged, kSecurityPsk));
  EXPECT_EQ(service, psk_service);
  WiFiServiceRefPtr wep_service(
      FindService(ssid_bytes, kModeManaged, kSecurityWep));
  EXPECT_EQ(nullptr, wep_service);
}

TEST_F(WiFiProviderTest, FindServiceForEndpoint) {
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  Error error;
  const std::string kSSID("an_ssid");
  WiFiServiceRefPtr service = GetService(kSSID.c_str(), kModeManaged,
                                         kSecurityNone, false, true, &error);
  ASSERT_NE(nullptr, service);
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint(kSSID, "00:00:00:00:00:00", 0, 0);
  WiFiServiceRefPtr endpoint_service =
      provider_.FindServiceForEndpoint(endpoint);
  // Just because a matching service exists, we shouldn't necessarily have
  // it returned.  We will test that this function returns the correct
  // service if the endpoint is added below.
  EXPECT_EQ(nullptr, endpoint_service);
}

TEST_F(WiFiProviderTest, OnEndpointAdded) {
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  EXPECT_FALSE(FindService(ssid0_bytes, kModeManaged, kSecurityNone));
  WiFiEndpointRefPtr endpoint0 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint0);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());
  WiFiServiceRefPtr service0(
      FindService(ssid0_bytes, kModeManaged, kSecurityNone));
  EXPECT_NE(nullptr, service0);
  EXPECT_TRUE(service0->HasEndpoints());
  EXPECT_EQ(1, GetServiceByEndpoint().size());
  WiFiServiceRefPtr endpoint_service =
      provider_.FindServiceForEndpoint(endpoint0);
  EXPECT_EQ(service0, endpoint_service);

  WiFiEndpointRefPtr endpoint1 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:01", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  provider_.OnEndpointAdded(endpoint1);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());

  const std::string ssid1("another_ssid");
  const std::vector<uint8_t> ssid1_bytes(ssid1.begin(), ssid1.end());
  EXPECT_FALSE(FindService(ssid1_bytes, kModeManaged, kSecurityNone));
  WiFiEndpointRefPtr endpoint2 =
      MakeOpenEndpoint(ssid1, "00:00:00:00:00:02", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint2);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(2, GetServices().size());

  WiFiServiceRefPtr service1(
      FindService(ssid1_bytes, kModeManaged, kSecurityNone));
  EXPECT_NE(nullptr, service1);
  EXPECT_TRUE(service1->HasEndpoints());
  EXPECT_TRUE(service1 != service0);
}

TEST_F(WiFiProviderTest, OnEndpointAddedWithSecurity) {
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  EXPECT_FALSE(FindService(ssid0_bytes, kModeManaged, kSecurityNone));
  WiFiEndpoint::SecurityFlags rsn_flags;
  rsn_flags.rsn_psk = true;
  WiFiEndpointRefPtr endpoint0 =
      MakeEndpoint(ssid0, "00:00:00:00:00:00", 0, 0, rsn_flags);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint0);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());
  WiFiServiceRefPtr service0(
      FindService(ssid0_bytes, kModeManaged, kSecurityWpa));
  EXPECT_NE(nullptr, service0);
  EXPECT_TRUE(service0->HasEndpoints());
  EXPECT_EQ(kSecurityRsn, service0->security());

  WiFiEndpoint::SecurityFlags wpa_flags;
  wpa_flags.wpa_psk = true;
  WiFiEndpointRefPtr endpoint1 =
      MakeEndpoint(ssid0, "00:00:00:00:00:01", 0, 0, wpa_flags);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  provider_.OnEndpointAdded(endpoint1);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());

  const std::string ssid1("another_ssid");
  const std::vector<uint8_t> ssid1_bytes(ssid1.begin(), ssid1.end());
  EXPECT_FALSE(FindService(ssid1_bytes, kModeManaged, kSecurityNone));
  WiFiEndpointRefPtr endpoint2 =
      MakeEndpoint(ssid1, "00:00:00:00:00:02", 0, 0, wpa_flags);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint2);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(2, GetServices().size());

  WiFiServiceRefPtr service1(
      FindService(ssid1_bytes, kModeManaged, kSecurityRsn));
  EXPECT_NE(nullptr, service1);
  EXPECT_TRUE(service1->HasEndpoints());
  EXPECT_EQ(kSecurityWpa, service1->security());
  EXPECT_TRUE(service1 != service0);
}

TEST_F(WiFiProviderTest, OnEndpointAddedMultiSecurity) {
  // Multiple security modes with the same SSID.
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());

  WiFiEndpoint::SecurityFlags rsn_flags;
  rsn_flags.rsn_psk = true;
  WiFiEndpointRefPtr endpoint0 =
      MakeEndpoint(ssid0, "00:00:00:00:00:00", 0, 0, rsn_flags);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint0);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());

  WiFiServiceRefPtr service0(
      FindService(ssid0_bytes, kModeManaged, kSecurityWpa));
  EXPECT_NE(nullptr, service0);
  EXPECT_TRUE(service0->HasEndpoints());
  EXPECT_EQ(kSecurityRsn, service0->security());

  WiFiEndpoint::SecurityFlags none_flags;
  WiFiEndpointRefPtr endpoint1 =
      MakeEndpoint(ssid0, "00:00:00:00:00:01", 0, 0, none_flags);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint1);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(2, GetServices().size());

  WiFiServiceRefPtr service1(
      FindService(ssid0_bytes, kModeManaged, kSecurityNone));
  EXPECT_NE(nullptr, service1);
  EXPECT_TRUE(service1->HasEndpoints());
  EXPECT_EQ(kSecurityNone, service1->security());
  EXPECT_EQ(kSecurityRsn, service0->security());
}

TEST_F(WiFiProviderTest, OnEndpointAddedWhileStopped) {
  // If we don't call provider_.Start(), OnEndpointAdded should have no effect.
  const std::string ssid("an_ssid");
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint(ssid, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(_)).Times(0);
  provider_.OnEndpointAdded(endpoint);
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, OnEndpointAddedToMockService) {
  // The previous test allowed the provider to create its own "real"
  // WiFiServices, which hides some of what we can test with mock
  // services.  Re-do an add-endpoint operation by seeding the provider
  // with a mock service.
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0_bytes, kModeManaged, kSecurityNone, false);
  const std::string ssid1("another_ssid");
  const std::vector<uint8_t> ssid1_bytes(ssid1.begin(), ssid1.end());
  MockWiFiServiceRefPtr service1 =
      AddMockService(ssid1_bytes, kModeManaged, kSecurityNone, false);
  EXPECT_EQ(service0, FindService(ssid0_bytes, kModeManaged, kSecurityNone));
  WiFiEndpointRefPtr endpoint0 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  EXPECT_CALL(*service0, AddEndpoint(RefPtrMatch(endpoint0))).Times(1);
  EXPECT_CALL(*service1, AddEndpoint(_)).Times(0);
  provider_.OnEndpointAdded(endpoint0);
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(service0.get());
  Mock::VerifyAndClearExpectations(service1.get());

  WiFiEndpointRefPtr endpoint1 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:01", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  EXPECT_CALL(*service0, AddEndpoint(RefPtrMatch(endpoint1))).Times(1);
  EXPECT_CALL(*service1, AddEndpoint(_)).Times(0);
  provider_.OnEndpointAdded(endpoint1);
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(service0.get());
  Mock::VerifyAndClearExpectations(service1.get());

  WiFiEndpointRefPtr endpoint2 =
      MakeOpenEndpoint(ssid1, "00:00:00:00:00:02", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service1))).Times(1);
  EXPECT_CALL(*service0, AddEndpoint(_)).Times(0);
  EXPECT_CALL(*service1, AddEndpoint(RefPtrMatch(endpoint2))).Times(1);
  provider_.OnEndpointAdded(endpoint2);
}

TEST_F(WiFiProviderTest, OnEndpointRemoved) {
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0_bytes, kModeManaged, kSecurityNone, false);
  const std::string ssid1("another_ssid");
  const std::vector<uint8_t> ssid1_bytes(ssid1.begin(), ssid1.end());
  MockWiFiServiceRefPtr service1 =
      AddMockService(ssid1_bytes, kModeManaged, kSecurityNone, false);
  EXPECT_EQ(2, GetServices().size());

  // Remove the last endpoint of a non-remembered service.
  WiFiEndpointRefPtr endpoint0 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  AddEndpointToService(service0, endpoint0);
  EXPECT_EQ(1, GetServiceByEndpoint().size());

  EXPECT_CALL(*service0, RemoveEndpoint(RefPtrMatch(endpoint0))).Times(1);
  EXPECT_CALL(*service1, RemoveEndpoint(_)).Times(0);
  EXPECT_CALL(*service0, HasEndpoints()).WillRepeatedly(Return(false));
  EXPECT_CALL(*service0, IsRemembered()).WillRepeatedly(Return(false));
  EXPECT_CALL(*service0, ResetWiFi()).Times(1);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(0);
  EXPECT_CALL(manager_, DeregisterService(RefPtrMatch(service0))).Times(1);
  provider_.OnEndpointRemoved(endpoint0);
  // Verify now, so it's clear that this happened as a result of the call
  // above, and not anything in the destructor(s).
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(service0.get());
  Mock::VerifyAndClearExpectations(service1.get());
  EXPECT_EQ(1, GetServices().size());
  EXPECT_EQ(service1, GetServices().front());
  EXPECT_TRUE(GetServiceByEndpoint().empty());
}

TEST_F(WiFiProviderTest, OnEndpointRemovedButHasEndpoints) {
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0_bytes, kModeManaged, kSecurityNone, false);
  EXPECT_EQ(1, GetServices().size());

  // Remove an endpoint of a non-remembered service.
  WiFiEndpointRefPtr endpoint0 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  AddEndpointToService(service0, endpoint0);
  EXPECT_EQ(1, GetServiceByEndpoint().size());

  EXPECT_CALL(*service0, RemoveEndpoint(RefPtrMatch(endpoint0))).Times(1);
  EXPECT_CALL(*service0, HasEndpoints()).WillRepeatedly(Return(true));
  EXPECT_CALL(*service0, IsRemembered()).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  EXPECT_CALL(*service0, ResetWiFi()).Times(0);
  EXPECT_CALL(manager_, DeregisterService(_)).Times(0);
  provider_.OnEndpointRemoved(endpoint0);
  // Verify now, so it's clear that this happened as a result of the call
  // above, and not anything in the destructor(s).
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(service0.get());
  EXPECT_EQ(1, GetServices().size());
  EXPECT_TRUE(GetServiceByEndpoint().empty());
}

TEST_F(WiFiProviderTest, OnEndpointRemovedButIsRemembered) {
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0_bytes, kModeManaged, kSecurityNone, false);
  EXPECT_EQ(1, GetServices().size());

  // Remove the last endpoint of a remembered service.
  WiFiEndpointRefPtr endpoint0 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  AddEndpointToService(service0, endpoint0);
  EXPECT_EQ(1, GetServiceByEndpoint().size());

  EXPECT_CALL(*service0, RemoveEndpoint(RefPtrMatch(endpoint0))).Times(1);
  EXPECT_CALL(*service0, HasEndpoints()).WillRepeatedly(Return(false));
  EXPECT_CALL(*service0, IsRemembered()).WillRepeatedly(Return(true));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  EXPECT_CALL(*service0, ResetWiFi()).Times(0);
  EXPECT_CALL(manager_, DeregisterService(_)).Times(0);
  provider_.OnEndpointRemoved(endpoint0);
  // Verify now, so it's clear that this happened as a result of the call
  // above, and not anything in the destructor(s).
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(service0.get());
  EXPECT_EQ(1, GetServices().size());
  EXPECT_TRUE(GetServiceByEndpoint().empty());
}

TEST_F(WiFiProviderTest, OnEndpointRemovedWhileStopped) {
  // If we don't call provider_.Start(), OnEndpointRemoved should not
  // cause a crash even if a service matching the endpoint does not exist.
  const std::string ssid("an_ssid");
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint(ssid, "00:00:00:00:00:00", 0, 0);
  provider_.OnEndpointRemoved(endpoint);
}

TEST_F(WiFiProviderTest, OnEndpointUpdated) {
  provider_.Start();

  // Create an endpoint and associate it with a mock service.
  const std::string ssid("an_ssid");
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint(ssid, "00:00:00:00:00:00", 0, 0);

  const std::vector<uint8_t> ssid_bytes(ssid.begin(), ssid.end());
  MockWiFiServiceRefPtr open_service =
      AddMockService(ssid_bytes, kModeManaged, kSecurityNone, false);
  EXPECT_CALL(*open_service, AddEndpoint(RefPtrMatch(endpoint)));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(open_service)));
  provider_.OnEndpointAdded(endpoint);
  Mock::VerifyAndClearExpectations(open_service.get());

  // WiFiProvider is running and endpoint matches this service.
  EXPECT_CALL(*open_service, NotifyEndpointUpdated(RefPtrMatch(endpoint)));
  EXPECT_CALL(*open_service, AddEndpoint(_)).Times(0);
  provider_.OnEndpointUpdated(endpoint);
  Mock::VerifyAndClearExpectations(open_service.get());

  // If the endpoint is changed in a way that causes it to match a different
  // service, the provider should transfer the endpoint from one service to
  // the other.
  MockWiFiServiceRefPtr rsn_service =
      AddMockService(ssid_bytes, kModeManaged, kSecurityPsk, false);
  EXPECT_CALL(*open_service, RemoveEndpoint(RefPtrMatch(endpoint)));
  // We are playing out a scenario where the open service is not removed
  // since it still claims to have more endpoints remaining.
  EXPECT_CALL(*open_service, HasEndpoints()).WillRepeatedly(Return(true));
  EXPECT_CALL(*rsn_service, AddEndpoint(RefPtrMatch(endpoint)));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(open_service)));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(rsn_service)));
  endpoint->set_security_mode(kSecurityRsn);
  provider_.OnEndpointUpdated(endpoint);
}

TEST_F(WiFiProviderTest, OnEndpointUpdatedWhileStopped) {
  // If we don't call provider_.Start(), OnEndpointUpdated should not
  // cause a crash even if a service matching the endpoint does not exist.
  const std::string ssid("an_ssid");
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint(ssid, "00:00:00:00:00:00", 0, 0);
  provider_.OnEndpointUpdated(endpoint);
}

TEST_F(WiFiProviderTest, OnServiceUnloaded) {
  // This function should never unregister services itself -- the Manager
  // will automatically deregister the service if OnServiceUnloaded()
  // returns true (via WiFiService::Unload()).
  EXPECT_CALL(manager_, DeregisterService(_)).Times(0);

  MockWiFiServiceRefPtr service = AddMockService(
      std::vector<uint8_t>(1, '0'), kModeManaged, kSecurityNone, false);
  EXPECT_EQ(1, GetServices().size());
  EXPECT_CALL(*service, HasEndpoints()).WillOnce(Return(true));
  EXPECT_CALL(*service, ResetWiFi()).Times(0);
  EXPECT_FALSE(provider_.OnServiceUnloaded(service, nullptr));
  EXPECT_EQ(1, GetServices().size());
  Mock::VerifyAndClearExpectations(service.get());

  EXPECT_CALL(*service, HasEndpoints()).WillOnce(Return(false));
  EXPECT_CALL(*service, ResetWiFi()).Times(1);
  EXPECT_TRUE(provider_.OnServiceUnloaded(service, nullptr));
  // Verify now, so it's clear that this happened as a result of the call
  // above, and not anything in the destructor(s).
  Mock::VerifyAndClearExpectations(service.get());
  EXPECT_TRUE(GetServices().empty());

  Mock::VerifyAndClearExpectations(&manager_);
}

TEST_F(WiFiProviderTest, GetHiddenSSIDList) {
  EXPECT_TRUE(provider_.GetHiddenSSIDList().empty());
  const std::vector<uint8_t> ssid0(1, '0');
  AddMockService(ssid0, kModeManaged, kSecurityNone, false);
  EXPECT_TRUE(provider_.GetHiddenSSIDList().empty());

  const std::vector<uint8_t> ssid1(1, '1');
  MockWiFiServiceRefPtr service1 =
      AddMockService(ssid1, kModeManaged, kSecurityNone, true);
  EXPECT_CALL(*service1, IsRemembered()).WillRepeatedly(Return(false));
  EXPECT_TRUE(provider_.GetHiddenSSIDList().empty());

  const std::vector<uint8_t> ssid2(1, '2');
  MockWiFiServiceRefPtr service2 =
      AddMockService(ssid2, kModeManaged, kSecurityNone, true);
  EXPECT_CALL(*service2, IsRemembered()).WillRepeatedly(Return(true));
  ByteArrays ssid_list = provider_.GetHiddenSSIDList();

  EXPECT_EQ(1, ssid_list.size());
  EXPECT_TRUE(ssid_list[0] == ssid2);

  const std::vector<uint8_t> ssid3(1, '3');
  MockWiFiServiceRefPtr service3 =
      AddMockService(ssid3, kModeManaged, kSecurityNone, false);
  EXPECT_CALL(*service3, IsRemembered()).WillRepeatedly(Return(true));

  ssid_list = provider_.GetHiddenSSIDList();
  EXPECT_EQ(1, ssid_list.size());
  EXPECT_TRUE(ssid_list[0] == ssid2);

  const std::vector<uint8_t> ssid4(1, '4');
  MockWiFiServiceRefPtr service4 =
      AddMockService(ssid4, kModeManaged, kSecurityNone, true);
  EXPECT_CALL(*service4, IsRemembered()).WillRepeatedly(Return(true));

  ssid_list = provider_.GetHiddenSSIDList();
  EXPECT_EQ(2, ssid_list.size());
  EXPECT_TRUE(ssid_list[0] == ssid2);
  EXPECT_TRUE(ssid_list[1] == ssid4);

  service4->source_ = Service::ONCSource::kONCSourceUserPolicy;
  const std::vector<uint8_t> ssid5(1, '5');
  MockWiFiServiceRefPtr service5 =
      AddMockService(ssid5, kModeManaged, kSecurityNone, true);
  EXPECT_CALL(*service5, IsRemembered()).WillRepeatedly(Return(true));
  service5->source_ = Service::ONCSource::kONCSourceDevicePolicy;
  ssid_list = provider_.GetHiddenSSIDList();
  EXPECT_EQ(3, ssid_list.size());
  EXPECT_TRUE(ssid_list[0] == ssid4);
  EXPECT_TRUE(ssid_list[1] == ssid5);
  EXPECT_TRUE(ssid_list[2] == ssid2);
}

TEST_F(WiFiProviderTest, ReportAutoConnectableServices) {
  MockWiFiServiceRefPtr service0 = AddMockService(
      std::vector<uint8_t>(1, '0'), kModeManaged, kSecurityNone, false);
  MockWiFiServiceRefPtr service1 = AddMockService(
      std::vector<uint8_t>(1, '1'), kModeManaged, kSecurityNone, false);
  service0->EnableAndRetainAutoConnect();
  service0->SetConnectable(true);
  service1->EnableAndRetainAutoConnect();
  service1->SetConnectable(true);

  EXPECT_CALL(*service0, IsAutoConnectable(_))
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(*service1, IsAutoConnectable(_)).WillRepeatedly(Return(false));

  // With 1 auto connectable service.
  EXPECT_CALL(metrics_, NotifyWifiAutoConnectableServices(1));
  provider_.ReportAutoConnectableServices();

  // With no auto connectable service.
  EXPECT_CALL(metrics_, NotifyWifiAutoConnectableServices(_)).Times(0);
  provider_.ReportAutoConnectableServices();
}

TEST_F(WiFiProviderTest, NumAutoConnectableServices) {
  MockWiFiServiceRefPtr service0 = AddMockService(
      std::vector<uint8_t>(1, '0'), kModeManaged, kSecurityNone, false);
  MockWiFiServiceRefPtr service1 = AddMockService(
      std::vector<uint8_t>(1, '1'), kModeManaged, kSecurityNone, false);
  service0->EnableAndRetainAutoConnect();
  service0->SetConnectable(true);
  service1->EnableAndRetainAutoConnect();
  service1->SetConnectable(true);

  EXPECT_CALL(*service0, IsAutoConnectable(_))
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(*service1, IsAutoConnectable(_)).WillRepeatedly(Return(true));

  // 2 auto-connectable services.
  EXPECT_EQ(2, provider_.NumAutoConnectableServices());

  // 1 auto-connectable service.
  EXPECT_EQ(1, provider_.NumAutoConnectableServices());
}

TEST_F(WiFiProviderTest, GetSsidsConfiguredForAutoConnect) {
  std::vector<uint8_t> ssid0(3, '0');
  std::vector<uint8_t> ssid1(5, '1');
  ByteString ssid0_bytes(ssid0);
  ByteString ssid1_bytes(ssid1);
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0, kModeManaged, kSecurityNone, false);
  MockWiFiServiceRefPtr service1 =
      AddMockService(ssid1, kModeManaged, kSecurityNone, false);
  // 2 services configured for auto-connect.
  service0->SetAutoConnect(true);
  service1->SetAutoConnect(true);
  std::vector<ByteString> service_list_0 =
      provider_.GetSsidsConfiguredForAutoConnect();
  EXPECT_EQ(2, service_list_0.size());
  EXPECT_TRUE(ssid0_bytes.Equals(service_list_0[0]));
  EXPECT_TRUE(ssid1_bytes.Equals(service_list_0[1]));

  // 1 service configured for auto-connect.
  service0->SetAutoConnect(false);
  service1->SetAutoConnect(true);
  std::vector<ByteString> service_list_1 =
      provider_.GetSsidsConfiguredForAutoConnect();
  EXPECT_EQ(1, service_list_1.size());
  EXPECT_TRUE(ssid1_bytes.Equals(service_list_1[0]));
}

TEST_F(WiFiProviderTest, LoadCredentialsFromProfileAndCheckContent) {
  std::vector<std::string> domains{"sp-blue.com", "sp-green.com"};
  std::string realm("sp-blue.com");
  std::vector<uint64_t> home_ois{0x123456789, 0x65798731, 0x1};
  std::vector<uint64_t> required_home_ois{0x111222333444, 0x99887744};
  std::vector<uint64_t> roaming_consortia{0x1010101010, 0x2020202020};
  std::string app_name("com.sp-blue.app");

  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .Times(2)
      .WillRepeatedly(Return(nullptr));

  // Add credentials to the user profile.
  std::string id = AddCredentialsToProfileStorage(
      user_profile_.get(), domains, realm, home_ois, required_home_ois,
      roaming_consortia,
      /*metered_override=*/true, app_name);
  provider_.LoadCredentialsFromProfile(user_profile_.get());

  // Check the credentials are correct.
  PasspointCredentialsRefPtr creds = GetCredentials(id);
  EXPECT_TRUE(creds != nullptr);
  EXPECT_EQ(id, creds->id());
  EXPECT_EQ(user_profile_.get(), creds->profile());
  EXPECT_EQ(domains, creds->domains());
  EXPECT_EQ(realm, creds->realm());
  EXPECT_EQ(home_ois, creds->home_ois());
  EXPECT_EQ(required_home_ois, creds->required_home_ois());
  EXPECT_EQ(roaming_consortia, creds->roaming_consortia());
  EXPECT_TRUE(creds->metered_override());
  EXPECT_EQ(app_name, creds->android_package_name());

  // Remove it
  provider_.UnloadCredentialsFromProfile(user_profile_.get());
  EXPECT_TRUE(!GetCredentials(id));
}

TEST_F(WiFiProviderTest, LoadUnloadCredentialsFromProfile) {
  std::vector<std::string> domains{"sp-blue.com", "sp-green.com"};
  std::string realm("sp-blue.com");
  std::vector<uint64_t> ois{0x123456789, 0x65798731, 0x1};
  std::string app_name("com.sp-blue.app");

  // We expect: two adds and two removes
  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .Times(4)
      .WillRepeatedly(Return(nullptr));

  // Add credentials to both Profiles.
  std::string id_default =
      AddCredentialsToProfileStorage(default_profile_.get(), domains, realm,
                                     /*home_ois=*/ois,
                                     /*required_home_ois=*/ois,
                                     /*roaming_consortia=*/ois,
                                     /*metered_override=*/true, app_name);
  provider_.LoadCredentialsFromProfile(default_profile_.get());
  std::string id_user =
      AddCredentialsToProfileStorage(user_profile_.get(), domains, realm,
                                     /*home_ois=*/ois,
                                     /*required_home_ois=*/ois,
                                     /*roaming_consortia=*/ois,
                                     /*metered_override=*/true, app_name);
  provider_.LoadCredentialsFromProfile(user_profile_.get());

  // Check both credentials are available
  PasspointCredentialsRefPtr creds;
  creds = GetCredentials(id_default);
  EXPECT_TRUE(creds != nullptr);
  EXPECT_EQ(default_profile_.get(), creds->profile());
  creds = GetCredentials(id_user);
  EXPECT_TRUE(creds != nullptr);
  EXPECT_EQ(user_profile_.get(), creds->profile());

  // Remove it
  provider_.UnloadCredentialsFromProfile(user_profile_.get());
  EXPECT_TRUE(GetCredentials(id_user) == nullptr);
  EXPECT_TRUE(GetCredentials(id_default) != nullptr);
  provider_.UnloadCredentialsFromProfile(default_profile_.get());
  EXPECT_TRUE(GetCredentials(id_default) == nullptr);
}

TEST_F(WiFiProviderTest, AddRemoveCredentials) {
  std::vector<std::string> domains{"sp-red.com", "sp-blue.com"};
  std::string realm("sp-red.com");
  std::vector<uint64_t> ois{0x1122334455, 0x97643165, 0x30};
  std::string app_name("com.sp-red.app");

  // We expect two calls, one during add, one during remove.
  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .Times(2)
      .WillRepeatedly(Return(nullptr));

  // Add a set of credentials.
  std::string id =
      AddCredentialsToProvider(domains, realm, ois, ois, ois, false, app_name);
  PasspointCredentialsRefPtr creds = GetCredentials(id);
  EXPECT_TRUE(creds != nullptr);

  // Check it is present
  std::vector<PasspointCredentialsRefPtr> list = provider_.GetCredentials();
  EXPECT_EQ(1, list.size());
  EXPECT_EQ(creds, list[0]);

  // Remove the set of credentials
  list.clear();
  RemoveCredentials(creds);
  list = provider_.GetCredentials();
  EXPECT_EQ(0, list.size());
}

TEST_F(WiFiProviderTest, ForgetCredentials) {
  provider_.Start();

  // Add a set of credentials
  PasspointCredentialsRefPtr creds0 = new MockPasspointCredentials("creds0");
  creds0->SetProfile(user_profile_);
  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .WillRepeatedly(Return(nullptr));
  provider_.AddCredentials(creds0);

  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0_bytes, kModeManaged, kSecurity8021x, false);
  const std::string ssid1("another_ssid");
  const std::vector<uint8_t> ssid1_bytes(ssid1.begin(), ssid1.end());
  MockWiFiServiceRefPtr service1 =
      AddMockService(ssid1_bytes, kModeManaged, kSecurity8021x, false);

  // Report endpoints
  WiFiEndpointRefPtr endpoint0 =
      Make8021xEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  WiFiEndpointRefPtr endpoint1 =
      Make8021xEndpoint(ssid1, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0)));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service1)));
  provider_.OnEndpointAdded(endpoint0);
  provider_.OnEndpointAdded(endpoint1);

  // Report two matches that will fill the two services
  std::vector<WiFiProvider::PasspointMatch> matches{
      {creds0, endpoint0, WiFiProvider::MatchPriority::kHome},
      {creds0, endpoint1, WiFiProvider::MatchPriority::kRoaming}};
  EXPECT_CALL(manager_, UpdateService(_)).Times(2);
  EXPECT_CALL(manager_, MoveServiceToProfile(_, _)).Times(2);
  provider_.OnPasspointCredentialsMatches(matches);

  // Ensure both services are removed.
  EXPECT_CALL(manager_, RemoveService(RefPtrMatch(service0)));
  EXPECT_CALL(manager_, RemoveService(RefPtrMatch(service1)));
  provider_.ForgetCredentials(creds0);
}

TEST_F(WiFiProviderTest, SimpleCredentialsMatchesOverride) {
  provider_.Start();

  // Add few sets of credentials
  PasspointCredentialsRefPtr creds0 = new MockPasspointCredentials("creds0");
  PasspointCredentialsRefPtr creds1 = new MockPasspointCredentials("creds1");
  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .WillRepeatedly(Return(nullptr));
  creds0->SetProfile(user_profile_);
  provider_.AddCredentials(creds0);
  creds1->SetProfile(user_profile_);
  provider_.AddCredentials(creds1);

  // Provide some scan results
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  WiFiEndpointRefPtr endpoint0 =
      Make8021xEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint0);

  // Report a match
  std::vector<WiFiProvider::PasspointMatch> match{
      {creds0, endpoint0, WiFiProvider::MatchPriority::kRoaming}};
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  EXPECT_CALL(manager_, MoveServiceToProfile(_, _)).Times(1);
  provider_.OnPasspointCredentialsMatches(match);

  // The best match for endpoint0 is cred0 with "Roaming" priority.
  WiFiServiceRefPtr service0(
      FindService(ssid0_bytes, kModeManaged, kSecurity8021x));
  EXPECT_EQ(WiFiProvider::MatchPriority::kRoaming, service0->match_priority());
  EXPECT_EQ(creds0, service0->parent_credentials());

  // Report a match that overrides the previous one.
  std::vector<WiFiProvider::PasspointMatch> better_match{
      {creds1, endpoint0, WiFiProvider::MatchPriority::kHome}};
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  EXPECT_CALL(manager_, MoveServiceToProfile(_, _)).Times(1);
  provider_.OnPasspointCredentialsMatches(better_match);

  service0 = FindService(ssid0_bytes, kModeManaged, kSecurity8021x);
  EXPECT_EQ(WiFiProvider::MatchPriority::kHome, service0->match_priority());
  EXPECT_EQ(creds1, service0->parent_credentials());
}

TEST_F(WiFiProviderTest, MultipleCredentialsMatches) {
  provider_.Start();

  // Add few sets of credentials
  PasspointCredentialsRefPtr creds0 = new MockPasspointCredentials("creds0");
  PasspointCredentialsRefPtr creds1 = new MockPasspointCredentials("creds1");
  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .WillRepeatedly(Return(nullptr));
  provider_.AddCredentials(creds0);
  provider_.AddCredentials(creds1);

  // Provide some scan results
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  WiFiEndpointRefPtr endpoint0 =
      Make8021xEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint0);

  // Report matches
  std::vector<WiFiProvider::PasspointMatch> matches{
      {creds0, endpoint0, WiFiProvider::MatchPriority::kHome},
      {creds1, endpoint0, WiFiProvider::MatchPriority::kRoaming}};
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnPasspointCredentialsMatches(matches);

  // The best match for endpoint0 is cred0 because of the "Home" priority.
  WiFiServiceRefPtr service0(
      FindService(ssid0_bytes, kModeManaged, kSecurity8021x));
  EXPECT_EQ(WiFiProvider::MatchPriority::kHome, service0->match_priority());
  EXPECT_EQ(creds0, service0->parent_credentials());
}

}  // namespace shill
