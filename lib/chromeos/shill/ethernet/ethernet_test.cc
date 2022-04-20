// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/ethernet.h"

#include <netinet/ether.h>
#include <linux/if.h>  // NOLINT - Needs definitions from netinet/ether.h
#include <linux/sockios.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/callback.h>
#include <base/files/file_path.h>
#include <base/memory/ref_counted.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/ethernet/mock_ethernet_provider.h"
#include "shill/ethernet/mock_ethernet_service.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_log.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_profile.h"
#include "shill/mock_service.h"
#include "shill/net/mock_rtnl_handler.h"
#include "shill/net/mock_sockets.h"
#include "shill/network/mock_dhcp_controller.h"
#include "shill/network/mock_dhcp_provider.h"
#include "shill/testing.h"

#if !defined(DISABLE_WIRED_8021X)
#include "shill/ethernet/mock_eap_listener.h"
#include "shill/ethernet/mock_ethernet_eap_provider.h"
#include "shill/mock_eap_credentials.h"
#include "shill/supplicant/mock_supplicant_interface_proxy.h"
#include "shill/supplicant/mock_supplicant_process_proxy.h"
#include "shill/supplicant/supplicant_manager.h"
#include "shill/supplicant/wpa_supplicant.h"
#endif  // DISABLE_WIRED_8021X

using testing::_;
using testing::AnyNumber;
using testing::ByMove;
using testing::DoAll;
using testing::EndsWith;
using testing::Eq;
using testing::InSequence;
using testing::Invoke;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;
using testing::SetArgPointee;
using testing::StrictMock;
using testing::WithArg;

namespace shill {

class TestEthernet : public Ethernet {
 public:
  TestEthernet(Manager* manager,
               const std::string& link_name,
               const std::string& mac_address,
               int interface_index)
      : Ethernet(manager, link_name, mac_address, interface_index) {}

  ~TestEthernet() override = default;

  MOCK_METHOD(std::string,
              ReadMacAddressFromFile,
              (const base::FilePath& file_path),
              (override));
};

class EthernetTest : public testing::Test {
 public:
  EthernetTest()
      : manager_(&control_interface_, &dispatcher_, &metrics_),
        device_info_(&manager_),
        ethernet_(new TestEthernet(&manager_, ifname_, hwaddr_, ifindex_)),
#if !defined(DISABLE_WIRED_8021X)
        eap_listener_(new MockEapListener()),
        mock_eap_service_(new MockService(&manager_)),
        supplicant_interface_proxy_(
            new NiceMock<MockSupplicantInterfaceProxy>()),
        supplicant_process_proxy_(new NiceMock<MockSupplicantProcessProxy>()),
#endif  // DISABLE_WIRED_8021X
        mock_sockets_(new StrictMock<MockSockets>()),
        mock_service_(new MockEthernetService(
            &manager_, ethernet_->weak_ptr_factory_.GetWeakPtr())) {
  }
  ~EthernetTest() override {}

  void SetUp() override {
    ethernet_->rtnl_handler_ = &rtnl_handler_;
    ethernet_->sockets_.reset(mock_sockets_);  // Transfers ownership.

    ethernet_->set_dhcp_provider(&dhcp_provider_);
    ON_CALL(manager_, device_info()).WillByDefault(Return(&device_info_));
    EXPECT_CALL(manager_, UpdateEnabledTechnologies()).Times(AnyNumber());

#if !defined(DISABLE_WIRED_8021X)
    ethernet_->eap_listener_.reset(eap_listener_);  // Transfers ownership.
    EXPECT_CALL(manager_, ethernet_eap_provider())
        .WillRepeatedly(Return(&ethernet_eap_provider_));
    ethernet_eap_provider_.set_service(mock_eap_service_);
    // Transfers ownership.
    manager_.supplicant_manager()->set_proxy(supplicant_process_proxy_);
#endif  // DISABLE_WIRED_8021X

    EXPECT_CALL(manager_, ethernet_provider())
        .WillRepeatedly(Return(&ethernet_provider_));

    ON_CALL(*mock_service_, technology())
        .WillByDefault(Return(Technology::kEthernet));
  }

  void TearDown() override {
#if !defined(DISABLE_WIRED_8021X)
    ethernet_eap_provider_.set_service(nullptr);
    ethernet_->eap_listener_.reset();
#endif  // DISABLE_WIRED_8021X
    ethernet_->set_dhcp_provider(nullptr);
    ethernet_->sockets_.reset();
    Mock::VerifyAndClearExpectations(&manager_);
  }

  MOCK_METHOD(void, ErrorCallback, (const Error& error));

 protected:
  int ifindex_ = 123;
  std::string ifname_ = "eth0";
  std::string hwaddr_ = "000102030405";
  RpcIdentifier dbus_path_ = RpcIdentifier("/interface/path");
  std::string dhcp_hostname_ = "chromeos";

  bool GetLinkUp() { return ethernet_->link_up_; }
  void SetLinkUp(bool link_up) { ethernet_->link_up_ = link_up; }
  const ServiceRefPtr& GetSelectedService() {
    return ethernet_->selected_service();
  }
  ServiceRefPtr GetService() { return ethernet_->service_; }
  void SetService(const EthernetServiceRefPtr& service) {
    ethernet_->service_ = service;
  }
  const PropertyStore& GetStore() { return ethernet_->store(); }
  void StartEthernet() {
    ON_CALL(manager_, dhcp_hostname()).WillByDefault(ReturnRef(dhcp_hostname_));
    EXPECT_CALL(ethernet_provider_, CreateService(_))
        .WillOnce(Return(mock_service_));
    EXPECT_CALL(ethernet_provider_, RegisterService(Eq(mock_service_)));
    EXPECT_CALL(rtnl_handler_, SetInterfaceFlags(ifindex_, IFF_UP, IFF_UP));
    ethernet_->Start(nullptr, EnabledStateChangedCallback());
  }
  void StopEthernet() {
    EXPECT_CALL(ethernet_provider_, DeregisterService(Eq(mock_service_)));
    ethernet_->Stop(nullptr, EnabledStateChangedCallback());
  }
  void SetUsbEthernetMacAddressSource(const std::string& source,
                                      Error* error,
                                      const ResultCallback& callback) {
    ethernet_->SetUsbEthernetMacAddressSource(source, error, callback);
  }
  std::string GetUsbEthernetMacAddressSource(Error* error) {
    return ethernet_->GetUsbEthernetMacAddressSource(error);
  }

  void SetMacAddress(const std::string& mac_address) {
    ethernet_->set_mac_address(mac_address);
  }

  void SetBusType(const std::string& bus_type) {
    ethernet_->bus_type_ = bus_type;
  }

#if !defined(DISABLE_WIRED_8021X)
  bool GetIsEapAuthenticated() { return ethernet_->is_eap_authenticated_; }
  void SetIsEapAuthenticated(bool is_eap_authenticated) {
    ethernet_->is_eap_authenticated_ = is_eap_authenticated;
  }
  bool GetIsEapDetected() { return ethernet_->is_eap_detected_; }
  void SetIsEapDetected(bool is_eap_detected) {
    ethernet_->is_eap_detected_ = is_eap_detected;
  }
  const SupplicantInterfaceProxyInterface* GetSupplicantInterfaceProxy() {
    return ethernet_->supplicant_interface_proxy_.get();
  }
  const RpcIdentifier& GetSupplicantInterfacePath() {
    return ethernet_->supplicant_interface_path_;
  }
  const RpcIdentifier& GetSupplicantNetworkPath() {
    return ethernet_->supplicant_network_path_;
  }
  void SetSupplicantNetworkPath(const RpcIdentifier& network_path) {
    ethernet_->supplicant_network_path_ = network_path;
  }
  bool InvokeStartSupplicant() { return ethernet_->StartSupplicant(); }
  void InvokeStopSupplicant() { return ethernet_->StopSupplicant(); }
  bool InvokeStartEapAuthentication() {
    return ethernet_->StartEapAuthentication();
  }
  void StartSupplicant() {
    MockSupplicantInterfaceProxy* interface_proxy =
        ExpectCreateSupplicantInterfaceProxy();
    EXPECT_CALL(*supplicant_process_proxy_, CreateInterface(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(dbus_path_), Return(true)));
    EXPECT_TRUE(InvokeStartSupplicant());
    EXPECT_EQ(interface_proxy, GetSupplicantInterfaceProxy());
    EXPECT_EQ(dbus_path_, GetSupplicantInterfacePath());
  }
  void TriggerOnEapDetected() { ethernet_->OnEapDetected(); }
  void TriggerCertification(const std::string& subject, uint32_t depth) {
    ethernet_->CertificationTask(subject, depth);
  }
  void TriggerTryEapAuthentication() { ethernet_->TryEapAuthenticationTask(); }

  MockSupplicantInterfaceProxy* ExpectCreateSupplicantInterfaceProxy() {
    MockSupplicantInterfaceProxy* proxy = supplicant_interface_proxy_.get();
    EXPECT_CALL(control_interface_,
                CreateSupplicantInterfaceProxy(_, dbus_path_))
        .WillOnce(Return(ByMove(std::move(supplicant_interface_proxy_))));
    return proxy;
  }
#endif  // DISABLE_WIRED_8021X

  StrictMock<MockEventDispatcher> dispatcher_;
  MockControl control_interface_;
  NiceMock<MockMetrics> metrics_;
  MockManager manager_;
  MockDeviceInfo device_info_;
  scoped_refptr<TestEthernet> ethernet_;
  MockDHCPProvider dhcp_provider_;

#if !defined(DISABLE_WIRED_8021X)
  MockEthernetEapProvider ethernet_eap_provider_;

  // Owned by Ethernet instance, but tracked here for expectations.
  MockEapListener* eap_listener_;

  scoped_refptr<MockService> mock_eap_service_;
  std::unique_ptr<MockSupplicantInterfaceProxy> supplicant_interface_proxy_;
  MockSupplicantProcessProxy* supplicant_process_proxy_;
#endif  // DISABLE_WIRED_8021X

  // Owned by Ethernet instance, but tracked here for expectations.
  MockSockets* mock_sockets_;

  MockRTNLHandler rtnl_handler_;
  scoped_refptr<MockEthernetService> mock_service_;
  MockEthernetProvider ethernet_provider_;
};

TEST_F(EthernetTest, Construct) {
  EXPECT_FALSE(GetLinkUp());
#if !defined(DISABLE_WIRED_8021X)
  EXPECT_FALSE(GetIsEapAuthenticated());
  EXPECT_FALSE(GetIsEapDetected());
  EXPECT_TRUE(GetStore().Contains(kEapAuthenticationCompletedProperty));
  EXPECT_TRUE(GetStore().Contains(kEapAuthenticatorDetectedProperty));
#endif  // DISABLE_WIRED_8021X
  EXPECT_EQ(nullptr, GetService());
}

TEST_F(EthernetTest, StartStop) {
  StartEthernet();
  Service* service = GetService().get();
  EXPECT_EQ(service, mock_service_);
  StopEthernet();
}

TEST_F(EthernetTest, LinkEvent) {
  StartEthernet();

  // Link-down event while already down.
  EXPECT_CALL(manager_, DeregisterService(_)).Times(0);
#if !defined(DISABLE_WIRED_8021X)
  EXPECT_CALL(*eap_listener_, Start()).Times(0);
#endif  // DISABLE_WIRED_8021X
  ethernet_->LinkEvent(0, IFF_LOWER_UP);
  EXPECT_FALSE(GetLinkUp());
#if !defined(DISABLE_WIRED_8021X)
  EXPECT_FALSE(GetIsEapDetected());
#endif  // DISABLE_WIRED_8021X
  Mock::VerifyAndClearExpectations(&manager_);

  // Link-up event while down.
  int kFakeFd = 789;
  EXPECT_CALL(manager_, UpdateService(IsRefPtrTo(mock_service_)));
  EXPECT_CALL(*mock_service_, OnVisibilityChanged());
#if !defined(DISABLE_WIRED_8021X)
  EXPECT_CALL(*eap_listener_, Start());
#endif  // DISABLE_WIRED_8021X
  EXPECT_CALL(*mock_sockets_, Socket(_, _, _)).WillOnce(Return(kFakeFd));
  EXPECT_CALL(*mock_sockets_, Ioctl(kFakeFd, SIOCETHTOOL, _));
  EXPECT_CALL(*mock_sockets_, Close(kFakeFd));
  ethernet_->LinkEvent(IFF_LOWER_UP, 0);
  EXPECT_TRUE(GetLinkUp());
#if !defined(DISABLE_WIRED_8021X)
  EXPECT_FALSE(GetIsEapDetected());
#endif  // DISABLE_WIRED_8021X
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(mock_service_.get());

  // Link-up event while already up.
  EXPECT_CALL(manager_, UpdateService(_)).Times(0);
  EXPECT_CALL(*mock_service_, OnVisibilityChanged()).Times(0);
#if !defined(DISABLE_WIRED_8021X)
  EXPECT_CALL(*eap_listener_, Start()).Times(0);
#endif  // DISABLE_WIRED_8021X
  ethernet_->LinkEvent(IFF_LOWER_UP, 0);
  EXPECT_TRUE(GetLinkUp());
#if !defined(DISABLE_WIRED_8021X)
  EXPECT_FALSE(GetIsEapDetected());
#endif  // DISABLE_WIRED_8021X
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(mock_service_.get());

  // Link-down event while up.
#if !defined(DISABLE_WIRED_8021X)
  SetIsEapDetected(true);
  // This is done in SetUp, but we have to reestablish this after calling
  // VerifyAndClearExpectations() above.
  EXPECT_CALL(manager_, ethernet_eap_provider())
      .WillRepeatedly(Return(&ethernet_eap_provider_));
  EXPECT_CALL(ethernet_eap_provider_,
              ClearCredentialChangeCallback(ethernet_.get()));
  EXPECT_CALL(*eap_listener_, Stop());
#endif  // DISABLE_WIRED_8021X
  EXPECT_CALL(manager_, UpdateService(IsRefPtrTo(GetService().get())));
  EXPECT_CALL(*mock_service_, OnVisibilityChanged());
  ethernet_->LinkEvent(0, IFF_LOWER_UP);
  EXPECT_FALSE(GetLinkUp());
#if !defined(DISABLE_WIRED_8021X)
  EXPECT_FALSE(GetIsEapDetected());
#endif  // DISABLE_WIRED_8021X

  // Restore this expectation during shutdown.
  EXPECT_CALL(manager_, UpdateEnabledTechnologies()).Times(AnyNumber());
  EXPECT_CALL(manager_, ethernet_provider())
      .WillRepeatedly(Return(&ethernet_provider_));

  StopEthernet();
}

TEST_F(EthernetTest, ConnectToLinkDown) {
  StartEthernet();
  SetLinkUp(false);
  EXPECT_EQ(nullptr, GetSelectedService());
  EXPECT_CALL(dhcp_provider_, CreateIPv4Config(_, _, _, _, _)).Times(0);
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta())).Times(0);
  EXPECT_CALL(*mock_service_, SetState(_)).Times(0);
  ethernet_->ConnectTo(mock_service_.get());
  EXPECT_EQ(nullptr, GetSelectedService());
  StopEthernet();
}

TEST_F(EthernetTest, ConnectToFailure) {
  auto dhcp_controller = new MockDHCPController(&control_interface_, ifname_);
  StartEthernet();
  SetLinkUp(true);
  EXPECT_EQ(nullptr, GetSelectedService());
  EXPECT_CALL(dhcp_provider_, CreateIPv4Config(_, _, _, _, _))
      .WillOnce(
          Return(ByMove(std::unique_ptr<DHCPController>(dhcp_controller))));
  EXPECT_CALL(*dhcp_controller, RequestIP()).WillOnce(Return(false));
  EXPECT_CALL(dispatcher_,
              PostDelayedTask(
                  _, _, base::TimeDelta()));  // Posts ConfigureStaticIPTask.
  EXPECT_CALL(*mock_service_, SetState(Service::kStateFailure));
  ethernet_->ConnectTo(mock_service_.get());
  EXPECT_EQ(mock_service_, GetSelectedService());
  StopEthernet();
}

TEST_F(EthernetTest, ConnectToSuccess) {
  auto dhcp_controller = new MockDHCPController(&control_interface_, ifname_);
  StartEthernet();
  SetLinkUp(true);
  EXPECT_EQ(nullptr, GetSelectedService());
  EXPECT_CALL(dhcp_provider_, CreateIPv4Config(_, _, _, _, _))
      .WillOnce(
          Return(ByMove(std::unique_ptr<DHCPController>(dhcp_controller))));
  EXPECT_CALL(*dhcp_controller, RequestIP()).WillOnce(Return(true));
  EXPECT_CALL(dispatcher_,
              PostDelayedTask(
                  _, _, base::TimeDelta()));  // Posts ConfigureStaticIPTask.
  EXPECT_CALL(*mock_service_, SetState(Service::kStateConfiguring));
  ethernet_->ConnectTo(mock_service_.get());
  EXPECT_EQ(GetService(), GetSelectedService());
  Mock::VerifyAndClearExpectations(mock_service_.get());

  EXPECT_CALL(*mock_service_, SetState(Service::kStateIdle));
  ethernet_->DisconnectFrom(mock_service_.get());
  EXPECT_EQ(nullptr, GetSelectedService());
  StopEthernet();
}

#if !defined(DISABLE_WIRED_8021X)
TEST_F(EthernetTest, OnEapDetected) {
  EXPECT_FALSE(GetIsEapDetected());
  EXPECT_CALL(*eap_listener_, Stop());
  EXPECT_CALL(ethernet_eap_provider_,
              SetCredentialChangeCallback(ethernet_.get(), _));
  EXPECT_CALL(dispatcher_,
              PostDelayedTask(
                  _, _, base::TimeDelta()));  // Posts TryEapAuthenticationTask.
  TriggerOnEapDetected();
  EXPECT_TRUE(GetIsEapDetected());
}

TEST_F(EthernetTest, TryEapAuthenticationNotConnectableNotAuthenticated) {
  SetService(mock_service_);
  EXPECT_CALL(*mock_eap_service_, Is8021xConnectable()).WillOnce(Return(false));
  NiceScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _,
                       EndsWith("EAP Service lacks 802.1X credentials; "
                                "not doing EAP authentication.")));
  TriggerTryEapAuthentication();
  SetService(nullptr);
}

TEST_F(EthernetTest, TryEapAuthenticationNotConnectableAuthenticated) {
  SetService(mock_service_);
  SetIsEapAuthenticated(true);
  EXPECT_CALL(*mock_eap_service_, Is8021xConnectable()).WillOnce(Return(false));
  NiceScopedMockLog log;
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _,
                       EndsWith("EAP Service lost 802.1X credentials; "
                                "terminating EAP authentication.")));
  TriggerTryEapAuthentication();
  EXPECT_FALSE(GetIsEapAuthenticated());
}

TEST_F(EthernetTest, TryEapAuthenticationEapNotDetected) {
  SetService(mock_service_);
  EXPECT_CALL(*mock_eap_service_, Is8021xConnectable()).WillOnce(Return(true));
  NiceScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_WARNING, _,
                       EndsWith("EAP authenticator not detected; "
                                "not doing EAP authentication.")));
  TriggerTryEapAuthentication();
}

TEST_F(EthernetTest, StartSupplicant) {
  // Save the mock proxy pointers before the Ethernet instance accepts it.
  MockSupplicantInterfaceProxy* interface_proxy =
      supplicant_interface_proxy_.get();
  MockSupplicantProcessProxy* process_proxy = supplicant_process_proxy_;

  StartSupplicant();

  // Starting it again should not invoke another call to create an interface.
  Mock::VerifyAndClearExpectations(process_proxy);
  EXPECT_CALL(*process_proxy, CreateInterface(_, _)).Times(0);
  EXPECT_TRUE(InvokeStartSupplicant());

  // Also, the mock pointers should remain; if the MockProxyFactory was
  // invoked again, they would be nullptr.
  EXPECT_EQ(interface_proxy, GetSupplicantInterfaceProxy());
  EXPECT_EQ(dbus_path_, GetSupplicantInterfacePath());
}

TEST_F(EthernetTest, StartSupplicantWithInterfaceExistsException) {
  MockSupplicantProcessProxy* process_proxy = supplicant_process_proxy_;
  MockSupplicantInterfaceProxy* interface_proxy =
      ExpectCreateSupplicantInterfaceProxy();
  EXPECT_CALL(*process_proxy, CreateInterface(_, _)).WillOnce(Return(false));
  EXPECT_CALL(*process_proxy, GetInterface(ifname_, _))
      .WillOnce(DoAll(SetArgPointee<1>(dbus_path_), Return(true)));
  EXPECT_TRUE(InvokeStartSupplicant());
  EXPECT_EQ(interface_proxy, GetSupplicantInterfaceProxy());
  EXPECT_EQ(dbus_path_, GetSupplicantInterfacePath());
}

TEST_F(EthernetTest, StartSupplicantWithUnknownException) {
  MockSupplicantProcessProxy* process_proxy = supplicant_process_proxy_;
  EXPECT_CALL(*process_proxy, CreateInterface(_, _)).WillOnce(Return(false));
  EXPECT_CALL(*process_proxy, GetInterface(ifname_, _)).WillOnce(Return(false));
  EXPECT_FALSE(InvokeStartSupplicant());
  EXPECT_EQ(nullptr, GetSupplicantInterfaceProxy());
  EXPECT_EQ(RpcIdentifier(""), GetSupplicantInterfacePath());
}

TEST_F(EthernetTest, StartEapAuthentication) {
  MockSupplicantInterfaceProxy* interface_proxy =
      supplicant_interface_proxy_.get();

  StartSupplicant();
  SetService(mock_service_);

  EXPECT_CALL(*mock_service_, ClearEAPCertification());
  MockEapCredentials mock_eap_credentials;
  EXPECT_CALL(*mock_eap_service_, eap())
      .WillOnce(Return(&mock_eap_credentials));
  EXPECT_CALL(mock_eap_credentials, PopulateSupplicantProperties(_, _));
  EXPECT_CALL(*interface_proxy, RemoveNetwork(_)).Times(0);
  EXPECT_CALL(*interface_proxy, AddNetwork(_, _)).WillOnce(Return(false));
  EXPECT_CALL(*interface_proxy, SelectNetwork(_)).Times(0);
  EXPECT_CALL(*interface_proxy, EAPLogon()).Times(0);
  EXPECT_FALSE(InvokeStartEapAuthentication());
  Mock::VerifyAndClearExpectations(mock_service_.get());
  Mock::VerifyAndClearExpectations(mock_eap_service_.get());
  Mock::VerifyAndClearExpectations(interface_proxy);
  EXPECT_EQ(RpcIdentifier(""), GetSupplicantNetworkPath());

  EXPECT_CALL(*mock_service_, ClearEAPCertification());
  EXPECT_CALL(*interface_proxy, RemoveNetwork(_)).Times(0);
  EXPECT_CALL(*mock_eap_service_, eap())
      .WillOnce(Return(&mock_eap_credentials));
  EXPECT_CALL(mock_eap_credentials, PopulateSupplicantProperties(_, _));
  const RpcIdentifier kFirstNetworkPath("/network/first-path");
  EXPECT_CALL(*interface_proxy, AddNetwork(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFirstNetworkPath), Return(true)));
  EXPECT_CALL(*interface_proxy, SelectNetwork(Eq(kFirstNetworkPath)));
  EXPECT_CALL(*interface_proxy, EAPLogon());
  EXPECT_TRUE(InvokeStartEapAuthentication());
  Mock::VerifyAndClearExpectations(mock_service_.get());
  Mock::VerifyAndClearExpectations(mock_eap_service_.get());
  Mock::VerifyAndClearExpectations(&mock_eap_credentials);
  Mock::VerifyAndClearExpectations(interface_proxy);
  EXPECT_EQ(kFirstNetworkPath, GetSupplicantNetworkPath());

  EXPECT_CALL(*mock_service_, ClearEAPCertification());
  EXPECT_CALL(*interface_proxy, RemoveNetwork(Eq(kFirstNetworkPath)))
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_eap_service_, eap())
      .WillOnce(Return(&mock_eap_credentials));
  EXPECT_CALL(mock_eap_credentials, PopulateSupplicantProperties(_, _));
  const RpcIdentifier kSecondNetworkPath("/network/second-path");
  EXPECT_CALL(*interface_proxy, AddNetwork(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kSecondNetworkPath), Return(true)));
  EXPECT_CALL(*interface_proxy, SelectNetwork(Eq(kSecondNetworkPath)));
  EXPECT_CALL(*interface_proxy, EAPLogon());
  EXPECT_TRUE(InvokeStartEapAuthentication());
  EXPECT_EQ(kSecondNetworkPath, GetSupplicantNetworkPath());
}

TEST_F(EthernetTest, StopSupplicant) {
  MockSupplicantProcessProxy* process_proxy = supplicant_process_proxy_;
  MockSupplicantInterfaceProxy* interface_proxy =
      supplicant_interface_proxy_.get();
  StartSupplicant();
  SetIsEapAuthenticated(true);
  SetSupplicantNetworkPath(RpcIdentifier("/network/1"));
  EXPECT_CALL(*interface_proxy, EAPLogoff()).WillOnce(Return(true));
  EXPECT_CALL(*process_proxy, RemoveInterface(Eq(dbus_path_)))
      .WillOnce(Return(true));
  InvokeStopSupplicant();
  EXPECT_EQ(nullptr, GetSupplicantInterfaceProxy());
  EXPECT_EQ(RpcIdentifier(""), GetSupplicantInterfacePath());
  EXPECT_EQ(RpcIdentifier(""), GetSupplicantNetworkPath());
  EXPECT_FALSE(GetIsEapAuthenticated());
}

TEST_F(EthernetTest, Certification) {
  StartEthernet();
  const std::string kSubjectName("subject-name");
  const uint32_t kDepth = 123;
  // Should not crash due to no service_.
  TriggerCertification(kSubjectName, kDepth);
  EXPECT_CALL(*mock_service_, AddEAPCertification(kSubjectName, kDepth));
  SetService(mock_service_);
  TriggerCertification(kSubjectName, kDepth);
  StopEthernet();
}
#endif  // DISABLE_WIRED_8021X

TEST_F(EthernetTest, SetUsbEthernetMacAddressSourceInvalidArguments) {
  SetBusType(kDeviceBusTypeUsb);
  Error error(Error::kOperationInitiated);
  SetUsbEthernetMacAddressSource(
      "invalid_value", &error,
      base::Bind(&EthernetTest::ErrorCallback, base::Unretained(this)));
  EXPECT_EQ(error.type(), Error::kInvalidArguments);
}

TEST_F(EthernetTest, SetUsbEthernetMacAddressSourceNotSupportedForNonUsb) {
  SetBusType(kDeviceBusTypePci);
  Error error(Error::kOperationInitiated);
  EXPECT_CALL(*this, ErrorCallback(_)).Times(0);
  SetUsbEthernetMacAddressSource(
      kUsbEthernetMacAddressSourceUsbAdapterMac, &error,
      base::Bind(&EthernetTest::ErrorCallback, base::Unretained(this)));
  EXPECT_EQ(error.type(), Error::kIllegalOperation);
}

TEST_F(EthernetTest,
       SetUsbEthernetMacAddressSourceNotSupportedEmptyFileWithMac) {
  SetBusType(kDeviceBusTypeUsb);
  Error error(Error::kOperationInitiated);
  EXPECT_CALL(*this, ErrorCallback(_)).Times(0);
  SetUsbEthernetMacAddressSource(
      kUsbEthernetMacAddressSourceDesignatedDockMac, &error,
      base::Bind(&EthernetTest::ErrorCallback, base::Unretained(this)));
  EXPECT_EQ(error.type(), Error::kNotFound);
}

MATCHER_P(ErrorEquals, expected_error_type, "") {
  return arg.type() == expected_error_type;
}

TEST_F(EthernetTest, SetUsbEthernetMacAddressSourceNetlinkError) {
  SetBusType(kDeviceBusTypeUsb);

  constexpr char kBuiltinAdapterMacAddress[] = "abcdef123456";
  EXPECT_CALL(*ethernet_.get(), ReadMacAddressFromFile(_))
      .WillOnce(Return(kBuiltinAdapterMacAddress));

  EXPECT_CALL(rtnl_handler_, SetInterfaceMac(ethernet_->interface_index(),
                                             ByteString::CreateFromHexString(
                                                 kBuiltinAdapterMacAddress),
                                             _))
      .WillOnce(WithArg<2>(
          Invoke([](base::OnceCallback<void(int32_t)> response_callback) {
            ASSERT_TRUE(!response_callback.is_null());
            std::move(response_callback).Run(1 /* error */);
          })));

  EXPECT_CALL(*this, ErrorCallback(ErrorEquals(Error::kOperationFailed)));

  Error error(Error::kOperationInitiated);
  SetUsbEthernetMacAddressSource(
      kUsbEthernetMacAddressSourceBuiltinAdapterMac, &error,
      base::Bind(&EthernetTest::ErrorCallback, base::Unretained(this)));

  EXPECT_EQ(hwaddr_, ethernet_->mac_address());
}

TEST_F(EthernetTest, SetUsbEthernetMacAddressSource) {
  SetBusType(kDeviceBusTypeUsb);

  constexpr char kBuiltinAdapterMacAddress[] = "abcdef123456";
  EXPECT_CALL(*ethernet_.get(), ReadMacAddressFromFile(_))
      .WillOnce(Return(kBuiltinAdapterMacAddress));
  EXPECT_CALL(rtnl_handler_, SetInterfaceMac(ethernet_->interface_index(),
                                             ByteString::CreateFromHexString(
                                                 kBuiltinAdapterMacAddress),
                                             _))
      .WillOnce(WithArg<2>(
          Invoke([](base::OnceCallback<void(int32_t)> response_callback) {
            ASSERT_FALSE(response_callback.is_null());
            std::move(response_callback).Run(0 /* error */);
          })));

  EXPECT_CALL(*this, ErrorCallback(ErrorEquals(Error::kSuccess)));

  Error error(Error::kOperationInitiated);
  SetUsbEthernetMacAddressSource(
      kUsbEthernetMacAddressSourceBuiltinAdapterMac, &error,
      base::Bind(&EthernetTest::ErrorCallback, base::Unretained(this)));

  EXPECT_EQ(kBuiltinAdapterMacAddress, ethernet_->mac_address());
  EXPECT_EQ(GetUsbEthernetMacAddressSource(nullptr),
            kUsbEthernetMacAddressSourceBuiltinAdapterMac);
}

TEST_F(EthernetTest, SetMacAddressNoServiceStorageIdentifierChange) {
  constexpr char kMacAddress[] = "123456abcdef";

  scoped_refptr<StrictMock<MockProfile>> mock_profile(
      new StrictMock<MockProfile>(&manager_));
  mock_service_->set_profile(mock_profile);
  mock_service_->SetStorageIdentifier("some_ethernet_identifier");
  EXPECT_CALL(*mock_profile.get(), AbandonService(_)).Times(0);
  EXPECT_CALL(*mock_profile.get(), AdoptService(_)).Times(0);

  SetMacAddress(kMacAddress);
  EXPECT_EQ(kMacAddress, ethernet_->mac_address());

  // Must set nullptr to avoid mock objects leakage.
  mock_service_->set_profile(nullptr);
}

TEST_F(EthernetTest, SetMacAddressServiceStorageIdentifierChange) {
  StartEthernet();
  constexpr char kMacAddress[] = "123456abcdef";

  scoped_refptr<StrictMock<MockProfile>> mock_profile(
      new StrictMock<MockProfile>(&manager_));
  mock_service_->set_profile(mock_profile);
  EXPECT_CALL(*mock_profile.get(), AbandonService(IsRefPtrTo(mock_service_)));
  EXPECT_CALL(*mock_profile.get(), AdoptService(IsRefPtrTo(mock_service_)));

  SetMacAddress(kMacAddress);
  EXPECT_EQ(kMacAddress, ethernet_->mac_address());

  // Must set nullptr to avoid mock objects leakage.
  mock_service_->set_profile(nullptr);
  StopEthernet();
}

}  // namespace shill
