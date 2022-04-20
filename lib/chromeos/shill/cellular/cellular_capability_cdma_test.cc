// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_capability_cdma.h"

#include <string>
#include <utility>
#include <vector>

//#include <base/check.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <ModemManager/ModemManager.h>

#include "shill/cellular/cellular.h"
#include "shill/cellular/cellular_service.h"
#include "shill/cellular/mock_cellular_service.h"
#include "shill/cellular/mock_mm1_modem_modem3gpp_profile_manager_proxy.h"
#include "shill/cellular/mock_mm1_modem_modem3gpp_proxy.h"
#include "shill/cellular/mock_mm1_modem_modemcdma_proxy.h"
#include "shill/cellular/mock_mm1_modem_proxy.h"
#include "shill/cellular/mock_mm1_modem_simple_proxy.h"
#include "shill/cellular/mock_mm1_sim_proxy.h"
#include "shill/cellular/mock_mobile_operator_info.h"
#include "shill/cellular/mock_modem_info.h"
#include "shill/cellular/mock_pending_activation_store.h"
#include "shill/dbus/dbus_properties_proxy.h"
#include "shill/dbus/fake_properties_proxy.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/test_event_dispatcher.h"

using testing::_;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

namespace shill {

class CellularCapabilityCdmaTest : public testing::Test {
 public:
  explicit CellularCapabilityCdmaTest(EventDispatcher* dispatcher)
      : dispatcher_(dispatcher),
        control_interface_(this),
        manager_(&control_interface_, dispatcher, &metrics_),
        capability_(nullptr),
        device_adaptor_(nullptr),
        modem_info_(&control_interface_, &manager_),
        modem_3gpp_proxy_(new NiceMock<mm1::MockModemModem3gppProxy>()),
        modem_3gpp_profile_manager_proxy_(
            new NiceMock<mm1::MockModemModem3gppProfileManagerProxy>()),
        modem_cdma_proxy_(new NiceMock<mm1::MockModemModemCdmaProxy>()),
        modem_proxy_(new NiceMock<mm1::MockModemProxy>()),
        modem_simple_proxy_(new NiceMock<mm1::MockModemSimpleProxy>()),
        sim_proxy_(new NiceMock<mm1::MockSimProxy>()),
        properties_proxy_(
            DBusPropertiesProxy::CreateDBusPropertiesProxyForTesting(
                std::make_unique<FakePropertiesProxy>())),
        mock_home_provider_info_(nullptr),
        mock_serving_operator_info_(nullptr) {}

  ~CellularCapabilityCdmaTest() override { device_adaptor_ = nullptr; }

  void SetUp() override {
    EXPECT_CALL(manager_, modem_info()).WillRepeatedly(Return(&modem_info_));
    cellular_ = new Cellular(&manager_, "", kMachineAddress, 0,
                             Cellular::kTypeCdma, "", RpcIdentifier(""));
    service_ = new MockCellularService(&manager_, cellular_);
    capability_ =
        static_cast<CellularCapabilityCdma*>(cellular_->capability_.get());
    device_adaptor_ =
        static_cast<NiceMock<DeviceMockAdaptor>*>(cellular_->adaptor());
    cellular_->service_ = service_;
  }

  void TearDown() override {
    cellular_->SetServiceForTesting(nullptr);
    capability_ = nullptr;
    cellular_->service_ = nullptr;
    service_ = nullptr;
    CHECK(cellular_->HasOneRef());
    cellular_ = nullptr;
  }

  void SetService() {
    cellular_->service_ =
        new CellularService(&manager_, cellular_->imsi(), cellular_->iccid(),
                            cellular_->GetSimCardId());
  }

  void SetMockMobileOperatorInfoObjects() {
    CHECK(!mock_home_provider_info_);
    CHECK(!mock_serving_operator_info_);
    mock_home_provider_info_ =
        new MockMobileOperatorInfo(dispatcher_, "HomeProvider");
    mock_serving_operator_info_ =
        new MockMobileOperatorInfo(dispatcher_, "ServingOperator");
    cellular_->set_home_provider_info_for_testing(mock_home_provider_info_);
    cellular_->set_serving_operator_info_for_testing(
        mock_serving_operator_info_);
  }

  void SetupConnectProperties(KeyValueStore* properties) {
    capability_->SetupConnectProperties(properties);
  }

 protected:
  static const char kEsn[];
  static const char kMachineAddress[];
  static const char kMeid[];

  class TestControl : public MockControl {
   public:
    explicit TestControl(CellularCapabilityCdmaTest* test) : test_(test) {}

    // TODO(armansito): Some of these methods won't be necessary after 3GPP
    // gets refactored out of CellularCapability3gpp.
    std::unique_ptr<mm1::ModemModem3gppProxyInterface>
    CreateMM1ModemModem3gppProxy(const RpcIdentifier& /*path*/,
                                 const std::string& /*service*/) override {
      return std::move(test_->modem_3gpp_proxy_);
    }

    std::unique_ptr<mm1::ModemModem3gppProfileManagerProxyInterface>
    CreateMM1ModemModem3gppProfileManagerProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      return std::move(test_->modem_3gpp_profile_manager_proxy_);
    }

    std::unique_ptr<mm1::ModemModemCdmaProxyInterface>
    CreateMM1ModemModemCdmaProxy(const RpcIdentifier& /*path*/,
                                 const std::string& /*service*/) override {
      return std::move(test_->modem_cdma_proxy_);
    }

    std::unique_ptr<mm1::ModemProxyInterface> CreateMM1ModemProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      return std::move(test_->modem_proxy_);
    }

    std::unique_ptr<mm1::ModemSimpleProxyInterface> CreateMM1ModemSimpleProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      return std::move(test_->modem_simple_proxy_);
    }

    std::unique_ptr<mm1::SimProxyInterface> CreateMM1SimProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      return std::move(test_->sim_proxy_);
    }

    std::unique_ptr<DBusPropertiesProxy> CreateDBusPropertiesProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      return std::move(test_->properties_proxy_);
    }

   private:
    CellularCapabilityCdmaTest* test_;
  };

  EventDispatcher* dispatcher_;
  TestControl control_interface_;
  NiceMock<MockMetrics> metrics_;
  NiceMock<MockManager> manager_;
  CellularCapabilityCdma* capability_;
  NiceMock<DeviceMockAdaptor>* device_adaptor_;
  MockModemInfo modem_info_;
  // TODO(armansito): Remove |modem_3gpp_proxy_| after refactor.
  std::unique_ptr<mm1::MockModemModem3gppProxy> modem_3gpp_proxy_;
  std::unique_ptr<mm1::MockModemModem3gppProfileManagerProxy>
      modem_3gpp_profile_manager_proxy_;
  std::unique_ptr<mm1::MockModemModemCdmaProxy> modem_cdma_proxy_;
  std::unique_ptr<mm1::MockModemProxy> modem_proxy_;
  std::unique_ptr<mm1::MockModemSimpleProxy> modem_simple_proxy_;
  std::unique_ptr<mm1::MockSimProxy> sim_proxy_;
  std::unique_ptr<DBusPropertiesProxy> properties_proxy_;
  CellularRefPtr cellular_;
  MockCellularService* service_;

  // Set when required and passed to |cellular_|. Owned by |cellular_|.
  MockMobileOperatorInfo* mock_home_provider_info_;
  MockMobileOperatorInfo* mock_serving_operator_info_;
};

// static
const char CellularCapabilityCdmaTest::kEsn[] = "0000";
// static
const char CellularCapabilityCdmaTest::kMachineAddress[] = "TestMachineAddress";
// static
const char CellularCapabilityCdmaTest::kMeid[] = "11111111111111";

class CellularCapabilityCdmaMainTest : public CellularCapabilityCdmaTest {
 public:
  CellularCapabilityCdmaMainTest()
      : CellularCapabilityCdmaTest(&event_dispatcher_) {}

 private:
  EventDispatcherForTest event_dispatcher_;
};

TEST_F(CellularCapabilityCdmaMainTest, PropertiesChanged) {
  // Set up mock modem CDMA properties.
  KeyValueStore modem_cdma_properties;
  modem_cdma_properties.Set<std::string>(MM_MODEM_MODEMCDMA_PROPERTY_MEID,
                                         kMeid);
  modem_cdma_properties.Set<std::string>(MM_MODEM_MODEMCDMA_PROPERTY_ESN, kEsn);

  EXPECT_TRUE(cellular_->meid().empty());
  EXPECT_TRUE(cellular_->esn().empty());

  // Changing properties on wrong interface will not have an effect
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM,
                                   modem_cdma_properties);
  EXPECT_TRUE(cellular_->meid().empty());
  EXPECT_TRUE(cellular_->esn().empty());

  // Changing properties on the right interface gets reflected in the
  // capabilities object
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_MODEMCDMA,
                                   modem_cdma_properties);
  EXPECT_EQ(kMeid, cellular_->meid());
  EXPECT_EQ(kEsn, cellular_->esn());
}

TEST_F(CellularCapabilityCdmaMainTest, OnCdmaRegistrationChanged) {
  EXPECT_EQ(0, capability_->sid_);
  EXPECT_EQ(0, capability_->nid_);
  EXPECT_EQ(MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN,
            capability_->cdma_1x_registration_state_);
  EXPECT_EQ(MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN,
            capability_->cdma_evdo_registration_state_);

  const unsigned kSid = 2;
  const unsigned kNid = 1;
  SetMockMobileOperatorInfoObjects();
  EXPECT_CALL(*mock_serving_operator_info_,
              UpdateSID(base::NumberToString(kSid)));
  EXPECT_CALL(*mock_serving_operator_info_,
              UpdateNID(base::NumberToString(kNid)));
  capability_->OnCdmaRegistrationChanged(
      MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN,
      MM_MODEM_CDMA_REGISTRATION_STATE_HOME, kSid, kNid);
  EXPECT_EQ(kSid, capability_->sid_);
  EXPECT_EQ(kNid, capability_->nid_);
  EXPECT_EQ(MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN,
            capability_->cdma_1x_registration_state_);
  EXPECT_EQ(MM_MODEM_CDMA_REGISTRATION_STATE_HOME,
            capability_->cdma_evdo_registration_state_);

  EXPECT_TRUE(capability_->IsRegistered());
}

TEST_F(CellularCapabilityCdmaMainTest, UpdateServiceOLP) {
  const MobileOperatorInfo::OnlinePortal kOlp{
      "http://testurl", "POST", "esn=${esn}&mdn=${mdn}&meid=${meid}"};
  const std::vector<MobileOperatorInfo::OnlinePortal> kOlpList{kOlp};
  const std::string kUuidVzw = "c83d6597-dc91-4d48-a3a7-d86b80123751";
  const std::string kUuidFoo = "foo";

  SetMockMobileOperatorInfoObjects();
  cellular_->SetEsn("0");
  cellular_->SetMdn("10123456789");
  cellular_->SetMeid("4");

  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_serving_operator_info_, olp_list())
      .WillRepeatedly(ReturnRef(kOlpList));
  EXPECT_CALL(*mock_serving_operator_info_, uuid())
      .WillRepeatedly(ReturnRef(kUuidVzw));
  SetService();
  capability_->UpdateServiceOLP();
  // Copy to simplify assertions below.
  Stringmap vzw_olp = cellular_->service()->olp();
  EXPECT_EQ("http://testurl", vzw_olp[kPaymentPortalURL]);
  EXPECT_EQ("POST", vzw_olp[kPaymentPortalMethod]);
  EXPECT_EQ("esn=0&mdn=0123456789&meid=4", vzw_olp[kPaymentPortalPostData]);
  Mock::VerifyAndClearExpectations(mock_serving_operator_info_);

  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_serving_operator_info_, olp_list())
      .WillRepeatedly(ReturnRef(kOlpList));
  EXPECT_CALL(*mock_serving_operator_info_, uuid())
      .WillRepeatedly(ReturnRef(kUuidFoo));
  capability_->UpdateServiceOLP();
  // Copy to simplify assertions below.
  Stringmap olp = cellular_->service()->olp();
  EXPECT_EQ("http://testurl", olp[kPaymentPortalURL]);
  EXPECT_EQ("POST", olp[kPaymentPortalMethod]);
  EXPECT_EQ("esn=0&mdn=10123456789&meid=4", olp[kPaymentPortalPostData]);
}

TEST_F(CellularCapabilityCdmaMainTest, ActivateAutomatic) {
  const std::string activation_code{"1234"};
  SetMockMobileOperatorInfoObjects();

  mm1::MockModemModemCdmaProxy* cdma_proxy = modem_cdma_proxy_.get();
  capability_->InitProxies();

  // Cases when activation fails because |activation_code| is not available.
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*cdma_proxy, Activate(_, _, _, _)).Times(0);
  capability_->ActivateAutomatic();
  Mock::VerifyAndClearExpectations(mock_serving_operator_info_);
  Mock::VerifyAndClearExpectations(modem_cdma_proxy_.get());
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*cdma_proxy, Activate(_, _, _, _)).Times(0);
  capability_->ActivateAutomatic();
  Mock::VerifyAndClearExpectations(mock_serving_operator_info_);
  Mock::VerifyAndClearExpectations(modem_cdma_proxy_.get());

  // These expectations hold for all subsequent tests.
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_serving_operator_info_, activation_code())
      .WillRepeatedly(ReturnRef(activation_code));

  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(PendingActivationStore::kIdentifierMEID, _))
      .WillOnce(Return(PendingActivationStore::kStatePending))
      .WillOnce(Return(PendingActivationStore::kStateActivated));
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              SetActivationState(_, _, _))
      .Times(0);
  EXPECT_CALL(*cdma_proxy, Activate(_, _, _, _)).Times(0);
  capability_->ActivateAutomatic();
  capability_->ActivateAutomatic();
  Mock::VerifyAndClearExpectations(modem_info_.mock_pending_activation_store());
  Mock::VerifyAndClearExpectations(modem_cdma_proxy_.get());

  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(PendingActivationStore::kIdentifierMEID, _))
      .WillOnce(Return(PendingActivationStore::kStateUnknown))
      .WillOnce(Return(PendingActivationStore::kStateFailureRetry));
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              SetActivationState(_, _, PendingActivationStore::kStatePending))
      .Times(2);
  EXPECT_CALL(*cdma_proxy, Activate(_, _, _, _)).Times(2);
  capability_->ActivateAutomatic();
  capability_->ActivateAutomatic();
  Mock::VerifyAndClearExpectations(modem_info_.mock_pending_activation_store());
  Mock::VerifyAndClearExpectations(modem_cdma_proxy_.get());
}

TEST_F(CellularCapabilityCdmaMainTest, IsServiceActivationRequired) {
  const std::vector<MobileOperatorInfo::OnlinePortal> empty_list;
  const std::vector<MobileOperatorInfo::OnlinePortal> olp_list{
      {"some@url", "some_method", "some_post_data"}};
  SetMockMobileOperatorInfoObjects();

  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_NOT_ACTIVATED;
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(false));
  EXPECT_FALSE(capability_->IsServiceActivationRequired());
  Mock::VerifyAndClearExpectations(mock_serving_operator_info_);

  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_NOT_ACTIVATED;
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_serving_operator_info_, olp_list())
      .WillRepeatedly(ReturnRef(empty_list));
  EXPECT_FALSE(capability_->IsServiceActivationRequired());
  Mock::VerifyAndClearExpectations(mock_serving_operator_info_);

  // These expectations hold for all subsequent tests.
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_serving_operator_info_, olp_list())
      .WillRepeatedly(ReturnRef(olp_list));

  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_NOT_ACTIVATED;
  EXPECT_TRUE(capability_->IsServiceActivationRequired());
  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_ACTIVATING;
  EXPECT_FALSE(capability_->IsServiceActivationRequired());
  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_ACTIVATED;
  EXPECT_FALSE(capability_->IsServiceActivationRequired());
}

TEST_F(CellularCapabilityCdmaMainTest, UpdateServiceActivationStateProperty) {
  const std::vector<MobileOperatorInfo::OnlinePortal> olp_list{
      {"some@url", "some_method", "some_post_data"}};
  SetMockMobileOperatorInfoObjects();
  EXPECT_CALL(*mock_serving_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_serving_operator_info_, olp_list())
      .WillRepeatedly(ReturnRef(olp_list));

  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(_, _))
      .WillOnce(Return(PendingActivationStore::kStatePending))
      .WillRepeatedly(Return(PendingActivationStore::kStateUnknown));

  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_NOT_ACTIVATED;
  EXPECT_CALL(*service_, SetActivationState(kActivationStateActivating))
      .Times(1);
  capability_->UpdateServiceActivationStateProperty();
  Mock::VerifyAndClearExpectations(service_);

  EXPECT_CALL(*service_, SetActivationState(kActivationStateNotActivated))
      .Times(1);
  capability_->UpdateServiceActivationStateProperty();
  Mock::VerifyAndClearExpectations(service_);

  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_ACTIVATING;
  EXPECT_CALL(*service_, SetActivationState(kActivationStateActivating))
      .Times(1);
  capability_->UpdateServiceActivationStateProperty();
  Mock::VerifyAndClearExpectations(service_);

  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_ACTIVATED;
  EXPECT_CALL(*service_, SetActivationState(kActivationStateActivated))
      .Times(1);
  capability_->UpdateServiceActivationStateProperty();
  Mock::VerifyAndClearExpectations(service_);
  Mock::VerifyAndClearExpectations(modem_info_.mock_pending_activation_store());
}

TEST_F(CellularCapabilityCdmaMainTest, IsActivating) {
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(_, _))
      .WillOnce(Return(PendingActivationStore::kStatePending))
      .WillOnce(Return(PendingActivationStore::kStatePending))
      .WillOnce(Return(PendingActivationStore::kStateFailureRetry))
      .WillRepeatedly(Return(PendingActivationStore::kStateUnknown));

  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_NOT_ACTIVATED;
  EXPECT_TRUE(capability_->IsActivating());
  EXPECT_TRUE(capability_->IsActivating());
  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_ACTIVATING;
  EXPECT_TRUE(capability_->IsActivating());
  EXPECT_TRUE(capability_->IsActivating());
  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_NOT_ACTIVATED;
  EXPECT_FALSE(capability_->IsActivating());
}

TEST_F(CellularCapabilityCdmaMainTest, IsRegistered) {
  capability_->cdma_1x_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN;
  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN;
  EXPECT_FALSE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_REGISTERED;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_HOME;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_ROAMING;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_1x_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_REGISTERED;
  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_REGISTERED;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_HOME;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_ROAMING;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_1x_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_HOME;
  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_REGISTERED;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_HOME;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_ROAMING;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_1x_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_ROAMING;
  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_REGISTERED;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_HOME;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->cdma_evdo_registration_state_ =
      MM_MODEM_CDMA_REGISTRATION_STATE_ROAMING;
  EXPECT_TRUE(capability_->IsRegistered());
}

TEST_F(CellularCapabilityCdmaMainTest, SetupConnectProperties) {
  KeyValueStore map;
  SetupConnectProperties(&map);
  EXPECT_TRUE(map.properties().empty());
}

class CellularCapabilityCdmaDispatcherTest : public CellularCapabilityCdmaTest {
 public:
  CellularCapabilityCdmaDispatcherTest()
      : CellularCapabilityCdmaTest(&mock_dispatcher_) {}

 protected:
  MockEventDispatcher mock_dispatcher_;
};

TEST_F(CellularCapabilityCdmaDispatcherTest, UpdatePendingActivationState) {
  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_ACTIVATED;
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(), RemoveEntry(_, _))
      .Times(1);
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(_, _))
      .Times(0);
  EXPECT_CALL(mock_dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
      .Times(0);
  capability_->UpdatePendingActivationState();
  Mock::VerifyAndClearExpectations(modem_info_.mock_pending_activation_store());
  Mock::VerifyAndClearExpectations(dispatcher_);

  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_ACTIVATING;
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(), RemoveEntry(_, _))
      .Times(0);
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(_, _))
      .Times(2)
      .WillRepeatedly(Return(PendingActivationStore::kStateUnknown));
  EXPECT_CALL(mock_dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
      .Times(0);
  capability_->UpdatePendingActivationState();
  Mock::VerifyAndClearExpectations(modem_info_.mock_pending_activation_store());
  Mock::VerifyAndClearExpectations(dispatcher_);

  capability_->activation_state_ = MM_MODEM_CDMA_ACTIVATION_STATE_NOT_ACTIVATED;
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(), RemoveEntry(_, _))
      .Times(0);
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(_, _))
      .Times(2)
      .WillRepeatedly(Return(PendingActivationStore::kStatePending));
  EXPECT_CALL(mock_dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
      .Times(0);
  capability_->UpdatePendingActivationState();
  Mock::VerifyAndClearExpectations(modem_info_.mock_pending_activation_store());
  Mock::VerifyAndClearExpectations(dispatcher_);

  EXPECT_CALL(*modem_info_.mock_pending_activation_store(), RemoveEntry(_, _))
      .Times(0);
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(_, _))
      .Times(2)
      .WillRepeatedly(Return(PendingActivationStore::kStateFailureRetry));
  EXPECT_CALL(mock_dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
      .Times(1);
  capability_->UpdatePendingActivationState();
  Mock::VerifyAndClearExpectations(modem_info_.mock_pending_activation_store());
  Mock::VerifyAndClearExpectations(dispatcher_);

  EXPECT_CALL(*modem_info_.mock_pending_activation_store(), RemoveEntry(_, _))
      .Times(0);
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(_, _))
      .Times(4)
      .WillOnce(Return(PendingActivationStore::kStateActivated))
      .WillOnce(Return(PendingActivationStore::kStateActivated))
      .WillOnce(Return(PendingActivationStore::kStateUnknown))
      .WillOnce(Return(PendingActivationStore::kStateUnknown));
  EXPECT_CALL(mock_dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
      .Times(0);
  capability_->UpdatePendingActivationState();
  capability_->UpdatePendingActivationState();
  Mock::VerifyAndClearExpectations(modem_info_.mock_pending_activation_store());
  Mock::VerifyAndClearExpectations(dispatcher_);
}

}  // namespace shill
