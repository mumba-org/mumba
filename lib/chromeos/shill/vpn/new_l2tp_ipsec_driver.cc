// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/new_l2tp_ipsec_driver.h"

#include <iterator>
#include <memory>
#include <string>
#include <utility>

#include <arpa/inet.h>  // for inet_ntop
#include <netdb.h>      // for getaddrinfo

#include <base/bind.h>
#include <brillo/type_list.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/error.h"
#include "shill/ipconfig.h"
#include "shill/manager.h"
#include "shill/vpn/ipsec_connection.h"
#include "shill/vpn/l2tp_connection.h"
#include "shill/vpn/vpn_service.h"

namespace shill {

namespace {

const char kL2TPIPsecLeftProtoPortProperty[] = "L2TPIPsec.LeftProtoPort";
const char kL2TPIPsecLengthBitProperty[] = "L2TPIPsec.LengthBit";
const char kL2TPIPsecRefusePapProperty[] = "L2TPIPsec.RefusePap";
const char kL2TPIPsecRequireAuthProperty[] = "L2TPIPsec.RequireAuth";
const char kL2TPIPsecRequireChapProperty[] = "L2TPIPsec.RequireChap";
const char kL2TPIPsecRightProtoPortProperty[] = "L2TPIPsec.RightProtoPort";

// Returns an empty string on error.
std::string ConvertSockAddrToIPString(const sockaddr_storage& address) {
  char str[INET6_ADDRSTRLEN] = {0};
  switch (address.ss_family) {
    case AF_INET:
      if (!inet_ntop(
              AF_INET,
              &(reinterpret_cast<const sockaddr_in*>(&address)->sin_addr), str,
              sizeof(str))) {
        PLOG(ERROR) << "inet_ntop failed";
        return "";
      }
      break;
    case AF_INET6:
      if (!inet_ntop(
              AF_INET6,
              &(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_addr),
              str, sizeof(str))) {
        PLOG(ERROR) << "inet_ntop failed";
        return "";
      }
      break;
    default:
      LOG(ERROR) << "Unknown address family: " << address.ss_family;
      return "";
  }
  return str;
}

// Returns an empty string on error.
std::string ResolveNameToIP(const std::string& name) {
  addrinfo* address_info = nullptr;
  // This function is called when the VPN service is connecting, and it makes
  // sense to let the query go through the dnsproxy.
  int s = getaddrinfo(name.c_str(), nullptr, nullptr, &address_info);
  if (s != 0) {
    LOG(ERROR) << "getaddrinfo failed: " << gai_strerror(s);
    return "";
  }
  sockaddr_storage address;
  memcpy(&address, address_info->ai_addr, address_info->ai_addrlen);
  freeaddrinfo(address_info);
  return ConvertSockAddrToIPString(address);
}

std::unique_ptr<IPsecConnection::Config> MakeIPsecConfig(
    const std::string& remote_ip, const KeyValueStore& args) {
  auto config = std::make_unique<IPsecConnection::Config>();

  config->ike_version = IPsecConnection::Config::IKEVersion::kV1;
  config->remote = remote_ip;
  config->psk = args.GetOptionalValue<std::string>(kL2TPIPsecPskProperty);
  config->ca_cert_pem_strings =
      args.GetOptionalValue<Strings>(kL2TPIPsecCaCertPemProperty);
  config->client_cert_id =
      args.GetOptionalValue<std::string>(kL2TPIPsecClientCertIdProperty);
  config->client_cert_slot =
      args.GetOptionalValue<std::string>(kL2TPIPsecClientCertSlotProperty);

  config->xauth_user =
      args.GetOptionalValue<std::string>(kL2TPIPsecXauthUserProperty);
  config->xauth_password =
      args.GetOptionalValue<std::string>(kL2TPIPsecXauthPasswordProperty);

  config->tunnel_group =
      args.GetOptionalValue<std::string>(kL2TPIPsecTunnelGroupProperty);

  // 17 = UDP, 1701 = L2TP.
  config->local_proto_port =
      args.Lookup<std::string>(kL2TPIPsecLeftProtoPortProperty, "17/1701");
  config->remote_proto_port =
      args.Lookup<std::string>(kL2TPIPsecRightProtoPortProperty, "17/1701");

  return config;
}

// KeyValueStore stores bool value as string "true" or "false". This function
// converts it to bool type, or returns |default_value|.
bool GetBool(const KeyValueStore& args,
             const std::string& key,
             bool default_value) {
  if (args.Contains<std::string>(key)) {
    return args.Get<std::string>(key) == "true";
  }
  return default_value;
}

std::unique_ptr<L2TPConnection::Config> MakeL2TPConfig(
    const std::string& remote_ip, const KeyValueStore& args) {
  auto config = std::make_unique<L2TPConnection::Config>();

  config->remote_ip = remote_ip;

  // Fields for xl2tpd.
  config->refuse_pap = GetBool(args, kL2TPIPsecRefusePapProperty, false);
  config->require_auth = GetBool(args, kL2TPIPsecRequireAuthProperty, true);
  config->require_chap = GetBool(args, kL2TPIPsecRequireChapProperty, true);
  config->length_bit = GetBool(args, kL2TPIPsecLengthBitProperty, true);

  // Fields for pppd.
  config->lcp_echo = !GetBool(args, kL2TPIPsecLcpEchoDisabledProperty, false);
  config->user = args.Lookup<std::string>(kL2TPIPsecUserProperty, "");
  config->password = args.Lookup<std::string>(kL2TPIPsecPasswordProperty, "");
  config->use_login_password =
      GetBool(args, kL2TPIPsecUseLoginPasswordProperty, false);

  return config;
}

void ReportConnectionEndReason(Metrics* metrics,
                               Service::ConnectFailure failure) {
  metrics->SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecSwanctlEndReason,
                         Metrics::ConnectFailureToServiceErrorEnum(failure),
                         Metrics::kMetricVpnL2tpIpsecSwanctlEndReasonMax);
}

}  // namespace

const VPNDriver::Property NewL2TPIPsecDriver::kProperties[] = {
    {kL2TPIPsecClientCertIdProperty, 0},
    {kL2TPIPsecClientCertSlotProperty, 0},
    {kL2TPIPsecPasswordProperty, Property::kCredential | Property::kWriteOnly},
    {kL2TPIPsecPinProperty, Property::kCredential},
    {kL2TPIPsecPskProperty, Property::kCredential | Property::kWriteOnly},
    {kL2TPIPsecUseLoginPasswordProperty, 0},
    {kL2TPIPsecUserProperty, 0},
    {kProviderHostProperty, 0},
    {kProviderTypeProperty, 0},
    {kL2TPIPsecCaCertPemProperty, Property::kArray},
    {kL2TPIPsecTunnelGroupProperty, 0},
    {kL2TPIPsecLeftProtoPortProperty, 0},
    {kL2TPIPsecLengthBitProperty, 0},
    {kL2TPIPsecRefusePapProperty, 0},
    {kL2TPIPsecRequireAuthProperty, 0},
    {kL2TPIPsecRequireChapProperty, 0},
    {kL2TPIPsecRightProtoPortProperty, 0},
    {kL2TPIPsecXauthUserProperty, Property::kCredential | Property::kWriteOnly},
    {kL2TPIPsecXauthPasswordProperty,
     Property::kCredential | Property::kWriteOnly},
    {kL2TPIPsecLcpEchoDisabledProperty, 0},
};

NewL2TPIPsecDriver::NewL2TPIPsecDriver(Manager* manager,
                                       ProcessManager* process_manager)
    : VPNDriver(manager, process_manager, kProperties, std::size(kProperties)) {
}

NewL2TPIPsecDriver::~NewL2TPIPsecDriver() {}

base::TimeDelta NewL2TPIPsecDriver::ConnectAsync(EventHandler* handler) {
  event_handler_ = handler;

  dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&NewL2TPIPsecDriver::StartIPsecConnection,
                                weak_factory_.GetWeakPtr()));

  return base::Seconds(60);
}

void NewL2TPIPsecDriver::StartIPsecConnection() {
  if (ipsec_connection_) {
    LOG(ERROR) << "The previous IPsecConnection is still running.";
    NotifyServiceOfFailure(Service::kFailureInternal);
    return;
  }

  const std::string remote_ip = ResolveNameToIP(
      const_args()->Lookup<std::string>(kProviderHostProperty, ""));
  if (remote_ip.empty()) {
    LOG(ERROR) << "Failed to resolve host property to IP.";
    NotifyServiceOfFailure(Service::kFailureInternal);
    return;
  }

  auto l2tp_connection = CreateL2TPConnection(
      MakeL2TPConfig(remote_ip, *const_args()), control_interface(),
      manager()->device_info(), manager()->dispatcher(), process_manager());

  auto callbacks = std::make_unique<IPsecConnection::Callbacks>(
      base::BindRepeating(&NewL2TPIPsecDriver::OnIPsecConnected,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&NewL2TPIPsecDriver::OnIPsecFailure,
                     weak_factory_.GetWeakPtr()),
      base::BindOnce(&NewL2TPIPsecDriver::OnIPsecStopped,
                     weak_factory_.GetWeakPtr()));

  ipsec_connection_ = CreateIPsecConnection(
      MakeIPsecConfig(remote_ip, *const_args()), std::move(callbacks),
      std::move(l2tp_connection), manager()->device_info(),
      manager()->dispatcher(), process_manager());

  ipsec_connection_->Connect();
}

std::unique_ptr<VPNConnection> NewL2TPIPsecDriver::CreateIPsecConnection(
    std::unique_ptr<IPsecConnection::Config> config,
    std::unique_ptr<VPNConnection::Callbacks> callbacks,
    std::unique_ptr<VPNConnection> l2tp_connection,
    DeviceInfo* device_info,
    EventDispatcher* dispatcher,
    ProcessManager* process_manager) {
  return std::make_unique<IPsecConnection>(
      std::move(config), std::move(callbacks), std::move(l2tp_connection),
      device_info, dispatcher, process_manager);
}

std::unique_ptr<VPNConnection> NewL2TPIPsecDriver::CreateL2TPConnection(
    std::unique_ptr<L2TPConnection::Config> config,
    ControlInterface* control_interface,
    DeviceInfo* device_info,
    EventDispatcher* dispatcher,
    ProcessManager* process_manager) {
  // Callbacks for L2TP will be set and handled in IPsecConnection.
  return std::make_unique<L2TPConnection>(
      std::move(config), /*callbacks=*/nullptr, control_interface, device_info,
      dispatcher, process_manager);
}

void NewL2TPIPsecDriver::Disconnect() {
  event_handler_ = nullptr;
  ReportConnectionEndReason(metrics(), Service::kFailureDisconnect);
  if (!ipsec_connection_) {
    LOG(ERROR) << "Disconnect() called but IPsecConnection is not running";
    return;
  }
  if (!ipsec_connection_->IsConnectingOrConnected()) {
    LOG(ERROR) << "Disconnect() called but IPsecConnection is in "
               << ipsec_connection_->state() << " state";
    return;
  }
  ipsec_connection_->Disconnect();
}

IPConfig::Properties NewL2TPIPsecDriver::GetIPProperties() const {
  return ip_properties_;
}

std::string NewL2TPIPsecDriver::GetProviderType() const {
  return kProviderL2tpIpsec;
}

void NewL2TPIPsecDriver::OnConnectTimeout() {
  LOG(INFO) << "Connect timeout";
  if (!ipsec_connection_) {
    LOG(ERROR)
        << "OnConnectTimeout() called but IPsecConnection is not running";
    return;
  }
  if (!ipsec_connection_->IsConnectingOrConnected()) {
    LOG(ERROR) << "OnConnectTimeout() called but IPsecConnection is in "
               << ipsec_connection_->state() << " state";
    return;
  }
  ipsec_connection_->Disconnect();
  NotifyServiceOfFailure(Service::kFailureConnect);
}

void NewL2TPIPsecDriver::OnBeforeSuspend(const ResultCallback& callback) {
  if (ipsec_connection_ && ipsec_connection_->IsConnectingOrConnected()) {
    ipsec_connection_->Disconnect();
    NotifyServiceOfFailure(Service::kFailureDisconnect);
  }
  callback.Run(Error(Error::kSuccess));
}

void NewL2TPIPsecDriver::OnDefaultPhysicalServiceEvent(
    DefaultPhysicalServiceEvent event) {
  if (!ipsec_connection_ || !ipsec_connection_->IsConnectingOrConnected()) {
    return;
  }
  switch (event) {
    case kDefaultPhysicalServiceUp:
      return;
    case kDefaultPhysicalServiceDown:
      ipsec_connection_->Disconnect();
      NotifyServiceOfFailure(Service::kFailureDisconnect);
      return;
    case kDefaultPhysicalServiceChanged:
      ipsec_connection_->Disconnect();
      NotifyServiceOfFailure(Service::kFailureDisconnect);
      return;
    default:
      NOTREACHED();
  }
}

void NewL2TPIPsecDriver::NotifyServiceOfFailure(
    Service::ConnectFailure failure) {
  LOG(ERROR) << "Driver failure due to "
             << Service::ConnectFailureToString(failure);
  if (event_handler_) {
    // Only reports metrics when |event_handler_| exists to ensure reporting
    // only once for each connection.
    ReportConnectionEndReason(metrics(), failure);
    event_handler_->OnDriverFailure(failure, Service::kErrorDetailsNone);
    event_handler_ = nullptr;
  }
}

void NewL2TPIPsecDriver::OnIPsecConnected(
    const std::string& link_name,
    int interface_index,
    const IPConfig::Properties& ip_properties) {
  if (!event_handler_) {
    LOG(ERROR) << "OnIPsecConnected() triggered in illegal service state";
    return;
  }
  LOG(INFO) << "VPN connection established";
  ReportConnectionMetrics();
  ip_properties_ = ip_properties;
  event_handler_->OnDriverConnected(link_name, interface_index);
}

void NewL2TPIPsecDriver::OnIPsecFailure(Service::ConnectFailure failure) {
  NotifyServiceOfFailure(failure);
}

void NewL2TPIPsecDriver::OnIPsecStopped() {
  ipsec_connection_ = nullptr;
}

KeyValueStore NewL2TPIPsecDriver::GetProvider(Error* error) {
  const bool require_passphrase =
      args()->Lookup<std::string>(kL2TPIPsecPasswordProperty, "").empty();

  const bool psk_empty =
      args()->Lookup<std::string>(kL2TPIPsecPskProperty, "").empty();
  const bool cert_empty =
      args()->Lookup<std::string>(kL2TPIPsecClientCertIdProperty, "").empty();
  const bool require_psk = psk_empty && cert_empty;

  KeyValueStore props = VPNDriver::GetProvider(error);
  props.Set<bool>(kPassphraseRequiredProperty, require_passphrase);
  props.Set<bool>(kL2TPIPsecPskRequiredProperty, require_psk);
  return props;
}

void NewL2TPIPsecDriver::ReportConnectionMetrics() {
  metrics()->SendEnumToUMA(Metrics::kMetricVpnDriver,
                           Metrics::kVpnDriverL2tpIpsec,
                           Metrics::kMetricVpnDriverMax);

  // We output an enum for each of the authentication types specified,
  // even if more than one is set at the same time.
  bool has_remote_authentication = false;
  if (args()->Contains<Strings>(kL2TPIPsecCaCertPemProperty) &&
      !args()->Get<Strings>(kL2TPIPsecCaCertPemProperty).empty()) {
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnRemoteAuthenticationType,
        Metrics::kVpnRemoteAuthenticationTypeL2tpIpsecCertificate,
        Metrics::kMetricVpnRemoteAuthenticationTypeMax);
    has_remote_authentication = true;
  }
  if (args()->Lookup<std::string>(kL2TPIPsecPskProperty, "") != "") {
    metrics()->SendEnumToUMA(Metrics::kMetricVpnRemoteAuthenticationType,
                             Metrics::kVpnRemoteAuthenticationTypeL2tpIpsecPsk,
                             Metrics::kMetricVpnRemoteAuthenticationTypeMax);
    has_remote_authentication = true;
  }
  if (!has_remote_authentication) {
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnRemoteAuthenticationType,
        Metrics::kVpnRemoteAuthenticationTypeL2tpIpsecDefault,
        Metrics::kMetricVpnRemoteAuthenticationTypeMax);
  }

  bool has_user_authentication = false;
  if (args()->Lookup<std::string>(kL2TPIPsecClientCertIdProperty, "") != "") {
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnUserAuthenticationType,
        Metrics::kVpnUserAuthenticationTypeL2tpIpsecCertificate,
        Metrics::kMetricVpnUserAuthenticationTypeMax);
    has_user_authentication = true;
  }
  if (args()->Lookup<std::string>(kL2TPIPsecPasswordProperty, "") != "" ||
      GetBool(*args(), kL2TPIPsecUseLoginPasswordProperty, false)) {
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnUserAuthenticationType,
        Metrics::kVpnUserAuthenticationTypeL2tpIpsecUsernamePassword,
        Metrics::kMetricVpnUserAuthenticationTypeMax);
    has_user_authentication = true;
  }
  if (!has_user_authentication) {
    metrics()->SendEnumToUMA(Metrics::kMetricVpnUserAuthenticationType,
                             Metrics::kVpnUserAuthenticationTypeL2tpIpsecNone,
                             Metrics::kMetricVpnUserAuthenticationTypeMax);
  }

  // Reports whether tunnel group is set or not (b/201478824).
  const auto tunnel_group_usage =
      args()->Lookup<std::string>(kL2TPIPsecTunnelGroupProperty, "") != ""
          ? Metrics::kVpnL2tpIpsecTunnelGroupUsageYes
          : Metrics::kVpnL2tpIpsecTunnelGroupUsageNo;
  metrics()->SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecTunnelGroupUsage,
                           tunnel_group_usage,
                           Metrics::kMetricVpnL2tpIpsecTunnelGroupUsageMax);

  // To access the methods only defined in the inherited class. The cast will
  // only fail in unit tests.
  const auto* conn = dynamic_cast<IPsecConnection*>(ipsec_connection_.get());
  if (conn) {
    // Cipher suite for IKE.
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnL2tpIpsecIkeEncryptionAlgorithm,
        conn->ike_encryption_algo(),
        Metrics::kMetricVpnL2tpIpsecIkeEncryptionAlgorithmMax);
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnL2tpIpsecIkeIntegrityAlgorithm,
        conn->ike_integrity_algo(),
        Metrics::kMetricVpnL2tpIpsecIkeIntegrityAlgorithmMax);
    metrics()->SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecIkeDHGroup,
                             conn->ike_dh_group(),
                             Metrics::kMetricVpnL2tpIpsecIkeDHGroupMax);

    // Cipher suite for ESP.
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnL2tpIpsecEspEncryptionAlgorithm,
        conn->esp_encryption_algo(),
        Metrics::kMetricVpnL2tpIpsecEspEncryptionAlgorithmMax);
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnL2tpIpsecEspIntegrityAlgorithm,
        conn->esp_integrity_algo(),
        Metrics::kMetricVpnL2tpIpsecEspIntegrityAlgorithmMax);
  }
}

}  // namespace shill
