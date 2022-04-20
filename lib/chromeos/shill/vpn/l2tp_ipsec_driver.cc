// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The term "L2TP/IPsec" refers to a pair of layered protocols used
// together to establish a tunneled VPN connection.  First, an "IPsec"
// link is created, which secures a single IP traffic pair between the
// client and server.  For this link to complete, one or two levels of
// authentication are performed.  The first, inner mandatory authentication
// ensures the two parties establishing the IPsec link are correct.  This
// can use a certificate exchange or a less secure "shared group key"
// (PSK) authentication.  An optional outer IPsec authentication can also be
// performed, which is not fully supported by shill's implementation.
// In order to support "tunnel groups" from some vendor VPNs shill supports
// supplying the authentication realm portion during the outer authentication.
//
// When IPsec authentication completes, traffic is tunneled through a
// layer 2 tunnel, called "L2TP".  Using the secured link, we tunnel a
// PPP link, through which a second layer of authentication is performed,
// using the provided "user" and "password" properties.

#include "shill/vpn/l2tp_ipsec_driver.h"

#include <iterator>
#include <memory>
#include <utility>

#include <base/bind.h>
//#include <base/check.h>
//#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <re2/re2.h>
#include <vpn-manager/service_error.h>

#include "shill/certificate_file.h"
#include "shill/device_info.h"
#include "shill/error.h"
#include "shill/external_task.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/ppp_daemon.h"
#include "shill/ppp_device.h"
#include "shill/process_manager.h"
#include "shill/scope_logger.h"
#include "shill/vpn/ipsec_connection.h"
#include "shill/vpn/vpn_service.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kVPN;
static std::string ObjectID(const L2TPIPsecDriver*) {
  return "(l2tp_ipsec_driver)";
}
}  // namespace Logging

namespace {

const char kL2TPIPsecIPsecTimeoutProperty[] = "L2TPIPsec.IPsecTimeout";
const char kL2TPIPsecLeftProtoPortProperty[] = "L2TPIPsec.LeftProtoPort";
const char kL2TPIPsecLengthBitProperty[] = "L2TPIPsec.LengthBit";
const char kL2TPIPsecRefusePapProperty[] = "L2TPIPsec.RefusePap";
const char kL2TPIPsecRekeyProperty[] = "L2TPIPsec.Rekey";
const char kL2TPIPsecRequireAuthProperty[] = "L2TPIPsec.RequireAuth";
const char kL2TPIPsecRequireChapProperty[] = "L2TPIPsec.RequireChap";
const char kL2TPIPsecRightProtoPortProperty[] = "L2TPIPsec.RightProtoPort";

constexpr base::TimeDelta kConnectTimeout = base::Minutes(1);

constexpr char kStrokePath[] = "/usr/libexec/ipsec/stroke";

Service::ConnectFailure ExitStatusToFailure(int status) {
  switch (status) {
    case vpn_manager::kServiceErrorNoError:
      return Service::kFailureNone;
    case vpn_manager::kServiceErrorInternal:
    case vpn_manager::kServiceErrorInvalidArgument:
      return Service::kFailureInternal;
    case vpn_manager::kServiceErrorResolveHostnameFailed:
      return Service::kFailureDNSLookup;
    case vpn_manager::kServiceErrorIpsecConnectionFailed:
    case vpn_manager::kServiceErrorL2tpConnectionFailed:
    case vpn_manager::kServiceErrorPppConnectionFailed:
      return Service::kFailureConnect;
    case vpn_manager::kServiceErrorIpsecPresharedKeyAuthenticationFailed:
      return Service::kFailureIPsecPSKAuth;
    case vpn_manager::kServiceErrorIpsecCertificateAuthenticationFailed:
      return Service::kFailureIPsecCertAuth;
    case vpn_manager::kServiceErrorPppAuthenticationFailed:
      return Service::kFailurePPPAuth;
    default:
      return Service::kFailureUnknown;
  }
}

void ReportConnectionEndReason(Metrics* metrics,
                               Service::ConnectFailure failure) {
  metrics->SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecStrokeEndReason,
                         Metrics::ConnectFailureToServiceErrorEnum(failure),
                         Metrics::kMetricVpnL2tpIpsecStrokeEndReasonMax);
}

}  // namespace

// static
const char L2TPIPsecDriver::kL2TPIPsecVPNPath[] = "/usr/sbin/l2tpipsec_vpn";
// static
const VPNDriver::Property L2TPIPsecDriver::kProperties[] = {
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
    {kL2TPIPsecIPsecTimeoutProperty, 0},
    {kL2TPIPsecLeftProtoPortProperty, 0},
    {kL2TPIPsecLengthBitProperty, 0},
    {kL2TPIPsecRefusePapProperty, 0},
    {kL2TPIPsecRekeyProperty, 0},
    {kL2TPIPsecRequireAuthProperty, 0},
    {kL2TPIPsecRequireChapProperty, 0},
    {kL2TPIPsecRightProtoPortProperty, 0},
    {kL2TPIPsecXauthUserProperty, Property::kCredential | Property::kWriteOnly},
    {kL2TPIPsecXauthPasswordProperty,
     Property::kCredential | Property::kWriteOnly},
    {kL2TPIPsecLcpEchoDisabledProperty, 0},
};

// static
bool L2TPIPsecDriver::ParseStrokeStatusAllOutput(
    const std::string& stroke_output,
    IPsecConnection::CipherSuite* ike_cipher,
    IPsecConnection::CipherSuite* esp_cipher) {
  CHECK(ike_cipher);
  CHECK(esp_cipher);

  // Does some basic check at first to make sure the SA is established. If the
  // check failed, we cannot any reasonable results so we don't need to report
  // an unknown to UMA.
  constexpr char kSAHeaderLine[] =
      "Security Associations (1 up, 0 connecting):";
  if (stroke_output.find(kSAHeaderLine) == std::string::npos) {
    LOG(ERROR) << "The output of stroke does not contain the SA header line, "
                  "output is: "
               << stroke_output;
    return false;
  }

  // Will log |stdout_str| if any part of the parsing fails.
  bool success = true;

  // The IKE part has a prompt before it and a space after it. See
  // l2tp_ipsec_driver_test.cc for the example. See `stroke_list.c:log_ike_sa()`
  // for how this part is output.
  std::string ike_matched_part;
  static constexpr LazyRE2 kIKECipherSuite = {
      R"(IKE proposal: ((?:[^/\s]+)(?:/[^/\s]+)*)\s+)"};
  if (!RE2::PartialMatch(stroke_output, *kIKECipherSuite, &ike_matched_part)) {
    LOG(ERROR) << "Failed to parse the IKE cipher suite";
    success = false;
  }
  *ike_cipher = IPsecConnection::ParseCipherSuite(ike_matched_part);

  // Matches the ESP part. There might be several child SAs at the same time.
  // For each child SA, the cipher suite for ESP will be output at the second
  // line, so we find the first line (the currently installed SA) at first and
  // then match the cipher part on the second line. Note that "managed" is the
  // name of the connection which is hard-coded in vpn-manager. See
  // l2tp_ipsec_driver_test.cc for the example. See
  // `stroke_list.c:log_child_sa()` for how this part is output.
  std::string esp_matched_part;
  static constexpr LazyRE2 kESPCipherSuite = {
      R"(managed{\d+}:  INSTALLED, TRANSPORT,[^\n]*\n +managed{\d+}:  ((?:[^/\s,]+)(?:/[^/\s,]+)*),)"};
  if (!RE2::PartialMatch(stroke_output, *kESPCipherSuite, &esp_matched_part)) {
    LOG(ERROR) << "Failed to parse the ESP cipher suite";
    success = false;
  }
  *esp_cipher = IPsecConnection::ParseCipherSuite(esp_matched_part);

  if (!success) {
    LOG(ERROR) << "The output of stroke is: " << stroke_output;
  }

  return true;
}

L2TPIPsecDriver::L2TPIPsecDriver(Manager* manager,
                                 ProcessManager* process_manager)
    : VPNDriver(manager, process_manager, kProperties, std::size(kProperties)),
      certificate_file_(new CertificateFile()),
      password_provider_(
          std::make_unique<password_provider::PasswordProvider>()),
      vpn_util_(VPNUtil::New()) {}

L2TPIPsecDriver::~L2TPIPsecDriver() {
  Cleanup();
}

base::TimeDelta L2TPIPsecDriver::ConnectAsync(EventHandler* handler) {
  event_handler_ = handler;
  Error error;
  if (!SpawnL2TPIPsecVPN(&error)) {
    dispatcher()->PostTask(
        FROM_HERE,
        base::BindOnce(&L2TPIPsecDriver::FailService,
                       weak_factory_.GetWeakPtr(), Service::kFailureInternal));
    return kTimeoutNone;
  }
  return kConnectTimeout;
}

void L2TPIPsecDriver::Disconnect() {
  SLOG(this, 2) << __func__;
  ReportConnectionEndReason(metrics(), Service::kFailureDisconnect);
  Cleanup();
  event_handler_ = nullptr;
}

IPConfig::Properties L2TPIPsecDriver::GetIPProperties() const {
  return ip_properties_;
}

void L2TPIPsecDriver::OnConnectTimeout() {
  FailService(Service::kFailureConnect);
}

std::string L2TPIPsecDriver::GetProviderType() const {
  return kProviderL2tpIpsec;
}

void L2TPIPsecDriver::FailService(Service::ConnectFailure failure) {
  SLOG(this, 2) << __func__ << "(" << Service::ConnectFailureToString(failure)
                << ")";
  Cleanup();
  if (event_handler_) {
    // Only reports metrics when |event_handler_| exists to ensure reporting
    // only once for each connection.
    ReportConnectionEndReason(metrics(), failure);
    event_handler_->OnDriverFailure(failure, Service::kErrorDetailsNone);
    event_handler_ = nullptr;
  }
}

void L2TPIPsecDriver::Cleanup() {
  DeleteTemporaryFiles();
  external_task_.reset();
}

void L2TPIPsecDriver::OnBeforeSuspend(const ResultCallback& callback) {
  if (event_handler_) {
    FailService(Service::kFailureDisconnect);
  }
  callback.Run(Error(Error::kSuccess));
}

void L2TPIPsecDriver::OnDefaultPhysicalServiceEvent(
    DefaultPhysicalServiceEvent event) {
  if (!event_handler_) {
    return;
  }
  if (event == kDefaultPhysicalServiceUp) {
    return;
  }
  FailService(Service::kFailureDisconnect);
}

void L2TPIPsecDriver::DeleteTemporaryFile(base::FilePath* temporary_file) {
  if (!temporary_file->empty()) {
    base::DeleteFile(*temporary_file);
    temporary_file->clear();
  }
}

void L2TPIPsecDriver::DeleteTemporaryFiles() {
  DeleteTemporaryFile(&psk_file_);
  DeleteTemporaryFile(&xauth_credentials_file_);
}

bool L2TPIPsecDriver::SpawnL2TPIPsecVPN(Error* error) {
  SLOG(this, 2) << __func__;
  auto external_task_local = std::make_unique<ExternalTask>(
      control_interface(), process_manager(), weak_factory_.GetWeakPtr(),
      base::Bind(&L2TPIPsecDriver::OnL2TPIPsecVPNDied,
                 weak_factory_.GetWeakPtr()));

  std::vector<std::string> options;
  const std::map<std::string, std::string> environment;  // No env vars passed.
  if (!InitOptions(&options, error)) {
    return false;
  }
  LOG(INFO) << "L2TP/IPsec VPN process options: "
            << base::JoinString(options, " ");

  constexpr uint64_t kCapMask = CAP_TO_MASK(CAP_NET_ADMIN) |
                                CAP_TO_MASK(CAP_NET_RAW) |
                                CAP_TO_MASK(CAP_NET_BIND_SERVICE);
  if (!external_task_local->StartInMinijail(
          base::FilePath(kL2TPIPsecVPNPath), &options, environment,
          VPNUtil::BuildMinijailOptions(kCapMask), error)) {
    return false;
  }
  external_task_ = std::move(external_task_local);
  return true;
}

bool L2TPIPsecDriver::InitOptions(std::vector<std::string>* options,
                                  Error* error) {
  const auto vpnhost = args()->Lookup<std::string>(kProviderHostProperty, "");
  if (vpnhost.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "VPN host not specified.");
    return false;
  }

  if (!InitPSKOptions(options, error)) {
    return false;
  }

  if (!InitXauthOptions(options, error)) {
    return false;
  }

  options->push_back(base::StringPrintf("--remote_host=%s", vpnhost.c_str()));
  options->push_back(
      base::StringPrintf("--pppd_plugin=%s", PPPDaemon::kShimPluginPath));
  // Disable pppd from configuring IP addresses, routes, DNS.
  options->push_back("--nosystemconfig");

  // Accept a PEM CA certificate.
  InitPEMOptions(options);

  AppendValueOption(kL2TPIPsecClientCertIdProperty, "--client_cert_id",
                    options);
  AppendValueOption(kL2TPIPsecClientCertSlotProperty, "--client_cert_slot",
                    options);
  AppendValueOption(kL2TPIPsecPinProperty, "--user_pin", options);
  AppendValueOption(kL2TPIPsecUserProperty, "--user", options);
  AppendValueOption(kL2TPIPsecIPsecTimeoutProperty, "--ipsec_timeout", options);
  AppendValueOption(kL2TPIPsecLeftProtoPortProperty, "--leftprotoport",
                    options);
  AppendFlag(kL2TPIPsecRekeyProperty, "--rekey", "--norekey", options);
  AppendValueOption(kL2TPIPsecRightProtoPortProperty, "--rightprotoport",
                    options);
  AppendFlag(kL2TPIPsecRequireChapProperty, "--require_chap",
             "--norequire_chap", options);
  // b/187984628: When UseLoginPassword is enabled, PAP must be refused to
  // prevent potential password leak to a malicious server.
  if (args()->Lookup<std::string>(kL2TPIPsecUseLoginPasswordProperty, "") ==
      "true") {
    args()->Set<std::string>(kL2TPIPsecRefusePapProperty, "true");
  }
  AppendFlag(kL2TPIPsecRefusePapProperty, "--refuse_pap", "--norefuse_pap",
             options);
  AppendFlag(kL2TPIPsecRequireAuthProperty, "--require_authentication",
             "--norequire_authentication", options);
  AppendFlag(kL2TPIPsecLengthBitProperty, "--length_bit", "--nolength_bit",
             options);
  AppendFlag(kL2TPIPsecLcpEchoDisabledProperty, "--noppp_lcp_echo",
             "--ppp_lcp_echo", options);
  AppendValueOption(kL2TPIPsecTunnelGroupProperty, "--tunnel_group", options);
  if (SLOG_IS_ON(VPN, 0)) {
    options->push_back(base::StringPrintf(
        "--log_level=%d", -ScopeLogger::GetInstance()->verbose_level()));
  }
  return true;
}

bool L2TPIPsecDriver::InitPSKOptions(std::vector<std::string>* options,
                                     Error* error) {
  const auto psk = args()->Lookup<std::string>(kL2TPIPsecPskProperty, "");
  if (!psk.empty()) {
    if (!base::CreateTemporaryFileInDir(manager()->run_path(), &psk_file_) ||
        !vpn_util_->WriteConfigFile(psk_file_, psk)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                            "Unable to setup psk file.");
      return false;
    }
    options->push_back(
        base::StringPrintf("--psk_file=%s", psk_file_.value().c_str()));
  }
  return true;
}

bool L2TPIPsecDriver::InitPEMOptions(std::vector<std::string>* options) {
  std::vector<std::string> ca_certs;
  if (args()->Contains<Strings>(kL2TPIPsecCaCertPemProperty)) {
    ca_certs = args()->Get<Strings>(kL2TPIPsecCaCertPemProperty);
  }
  if (ca_certs.empty()) {
    return false;
  }
  base::FilePath certfile = certificate_file_->CreatePEMFromStrings(ca_certs);
  if (certfile.empty()) {
    LOG(ERROR) << "Unable to extract certificates from PEM string.";
    return false;
  }
  options->push_back(
      base::StringPrintf("--server_ca_file=%s", certfile.value().c_str()));
  return true;
}

bool L2TPIPsecDriver::InitXauthOptions(std::vector<std::string>* options,
                                       Error* error) {
  const auto user =
      args()->Lookup<std::string>(kL2TPIPsecXauthUserProperty, "");
  const auto password =
      args()->Lookup<std::string>(kL2TPIPsecXauthPasswordProperty, "");
  if (user.empty() && password.empty()) {
    // Xauth credentials not configured.
    return true;
  }
  if (user.empty() || password.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "XAUTH credentials are partially configured.");
    return false;
  }
  const std::string xauth_credentials = user + "\n" + password + "\n";
  if (!base::CreateTemporaryFileInDir(manager()->run_path(),
                                      &xauth_credentials_file_) ||
      !vpn_util_->WriteConfigFile(xauth_credentials_file_, xauth_credentials)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                          "Unable to setup XAUTH credentials file.");
    return false;
  }
  options->push_back(base::StringPrintf(
      "--xauth_credentials_file=%s", xauth_credentials_file_.value().c_str()));
  return true;
}

bool L2TPIPsecDriver::AppendValueOption(const std::string& property,
                                        const std::string& option,
                                        std::vector<std::string>* options) {
  const auto value = args()->Lookup<std::string>(property, "");
  if (!value.empty()) {
    options->push_back(
        base::StringPrintf("%s=%s", option.c_str(), value.c_str()));
    return true;
  }
  return false;
}

bool L2TPIPsecDriver::AppendFlag(const std::string& property,
                                 const std::string& true_option,
                                 const std::string& false_option,
                                 std::vector<std::string>* options) {
  const auto value = args()->Lookup<std::string>(property, "");
  if (!value.empty()) {
    options->push_back(value == "true" ? true_option : false_option);
    return true;
  }
  return false;
}

void L2TPIPsecDriver::OnL2TPIPsecVPNDied(pid_t /*pid*/, int status) {
  FailService(ExitStatusToFailure(status));
  // TODO(petkov): Figure if we need to restart the connection.
}

void L2TPIPsecDriver::GetLogin(std::string* user, std::string* password) {
  LOG(INFO) << "Login requested.";
  const auto user_property =
      args()->Lookup<std::string>(kL2TPIPsecUserProperty, "");
  if (user_property.empty()) {
    LOG(ERROR) << "User not set.";
    return;
  }
  const std::string use_login_password =
      args()->Lookup<std::string>(kL2TPIPsecUseLoginPasswordProperty, "");
  if (use_login_password == "true") {
    std::unique_ptr<password_provider::Password> login_password =
        password_provider_->GetPassword();
    if (login_password == nullptr || login_password->size() == 0) {
      LOG(ERROR) << "Unable to retrieve user password";
      return;
    }
    *user = user_property;
    *password = std::string(login_password->GetRaw(), login_password->size());
    return;
  }
  const auto password_property =
      args()->Lookup<std::string>(kL2TPIPsecPasswordProperty, "");
  if (password_property.empty()) {
    LOG(ERROR) << "Password not set.";
    return;
  }
  *user = user_property;
  *password = password_property;
}

void L2TPIPsecDriver::Notify(const std::string& reason,
                             const std::map<std::string, std::string>& dict) {
  LOG(INFO) << "IP configuration received: " << reason;

  if (reason == kPPPReasonAuthenticating || reason == kPPPReasonAuthenticated) {
    // These are uninteresting intermediate states that do not indicate failure.
    return;
  }

  if (reason == kPPPReasonExit) {
    // PPP failure is handled on the disconnect signal.
    return;
  }

  if (reason != kPPPReasonConnect) {
    DCHECK_EQ(kPPPReasonDisconnect, reason);
    // TODO(crbug.com/989361) We should move into a disconnecting state, stop
    // this task if it exists, and wait for the task to fully shut down before
    // completing the disconnection. This should wait for the VPNDriver code to
    // be refactored, as the disconnect flow is a mess as it stands.
    external_task_.reset();
    FailService(Service::kFailureUnknown);
    return;
  }

  DeleteTemporaryFiles();

  std::string interface_name = PPPDevice::GetInterfaceName(dict);
  ip_properties_ = PPPDevice::ParseIPConfiguration(dict);
  metrics()->SendSparseToUMA(Metrics::kMetricPPPMTUValue, ip_properties_.mtu);

  // There is no IPv6 support for L2TP/IPsec VPN at this moment, so create a
  // blackhole route for IPv6 traffic after establishing a IPv4 VPN.
  // TODO(benchan): Generalize this when IPv6 support is added.
  ip_properties_.blackhole_ipv6 = true;

  // Reduce MTU to the minimum viable for IPv6, since the IPsec layer consumes
  // some variable portion of the payload.  Although this system does not yet
  // support IPv6, it is a reasonable value to start with, since the minimum
  // IPv6 packet size will plausibly be a size any gateway would support, and
  // is also larger than the IPv4 minimum size.
  ip_properties_.mtu = IPConfig::kMinIPv6MTU;

  ip_properties_.method = kTypeVPN;

  ReportConnectionMetrics();

  // Make sure DeviceInfo is aware of this interface before invoking the
  // connection success callback.
  int interface_index = manager()->device_info()->GetIndex(interface_name);
  if (interface_index != -1) {
    OnLinkReady(interface_name, interface_index);
  } else {
    manager()->device_info()->AddVirtualInterfaceReadyCallback(
        interface_name, base::BindOnce(&L2TPIPsecDriver::OnLinkReady,
                                       weak_factory_.GetWeakPtr()));
  }
}

void L2TPIPsecDriver::OnLinkReady(const std::string& link_name,
                                  int interface_index) {
  if (!event_handler_) {
    LOG(ERROR) << "OnLinkReady() triggered in illegal service state";
    return;
  }
  event_handler_->OnDriverConnected(link_name, interface_index);
}

bool L2TPIPsecDriver::IsPskRequired() const {
  return const_args()->Lookup<std::string>(kL2TPIPsecPskProperty, "").empty() &&
         const_args()
             ->Lookup<std::string>(kL2TPIPsecClientCertIdProperty, "")
             .empty();
}

KeyValueStore L2TPIPsecDriver::GetProvider(Error* error) {
  SLOG(this, 2) << __func__;
  KeyValueStore props = VPNDriver::GetProvider(error);
  props.Set<bool>(
      kPassphraseRequiredProperty,
      args()->Lookup<std::string>(kL2TPIPsecPasswordProperty, "").empty());
  props.Set<bool>(kL2TPIPsecPskRequiredProperty, IsPskRequired());
  return props;
}

void L2TPIPsecDriver::ReportConnectionMetrics() {
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
      args()->Lookup<std::string>(kL2TPIPsecUseLoginPasswordProperty, "") ==
          "true") {
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

  // Reports cipher suites for IKE and ESP asynchronously.
  int pid = process_manager()->StartProcessInMinijailWithStdout(
      FROM_HERE, base::FilePath(kStrokePath), {"statusall"}, /*env=*/{},
      VPNUtil::BuildMinijailOptions(/*capmask*/ 0),
      base::BindOnce(&L2TPIPsecDriver::ParseCipherSuitesAndReport,
                     weak_factory_.GetWeakPtr()));
  if (pid == -1) {
    LOG(ERROR) << "Failed to run stroke to get the information of SA";
  }
}

void L2TPIPsecDriver::ParseCipherSuitesAndReport(
    int exit_status, const std::string& stdout_str) {
  if (exit_status != 0) {
    LOG(ERROR) << "stroke failed with " << exit_status;
    return;
  }

  IPsecConnection::CipherSuite ike_cipher, esp_cipher;
  if (!ParseStrokeStatusAllOutput(stdout_str, &ike_cipher, &esp_cipher)) {
    return;
  }

  // Reports cipher suite for IKE.
  metrics()->SendEnumToUMA(
      Metrics::kMetricVpnL2tpIpsecIkeEncryptionAlgorithm,
      std::get<0>(ike_cipher),
      Metrics::kMetricVpnL2tpIpsecIkeEncryptionAlgorithmMax);
  metrics()->SendEnumToUMA(
      Metrics::kMetricVpnL2tpIpsecIkeIntegrityAlgorithm,
      std::get<1>(ike_cipher),
      Metrics::kMetricVpnL2tpIpsecIkeIntegrityAlgorithmMax);
  metrics()->SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecIkeDHGroup,
                           std::get<2>(ike_cipher),
                           Metrics::kMetricVpnL2tpIpsecIkeDHGroupMax);

  // Reports cipher suite for ESP.
  metrics()->SendEnumToUMA(
      Metrics::kMetricVpnL2tpIpsecEspEncryptionAlgorithm,
      std::get<0>(esp_cipher),
      Metrics::kMetricVpnL2tpIpsecEspEncryptionAlgorithmMax);
  metrics()->SendEnumToUMA(
      Metrics::kMetricVpnL2tpIpsecEspIntegrityAlgorithm,
      std::get<1>(esp_cipher),
      Metrics::kMetricVpnL2tpIpsecEspIntegrityAlgorithmMax);
}

}  // namespace shill
