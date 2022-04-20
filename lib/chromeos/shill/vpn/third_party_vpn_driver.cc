// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/third_party_vpn_driver.h"

#include <fcntl.h>
#include <unistd.h>

#include <iterator>
#include <utility>

//#include <base/check.h>
//#include <base/check_op.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/connection.h"
#include "shill/control_interface.h"
#include "shill/device_info.h"
#include "shill/error.h"
#include "shill/file_io.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/net/io_handler_factory.h"
#include "shill/store/property_accessor.h"
#include "shill/store/store_interface.h"
#include "shill/virtual_device.h"
#include "shill/vpn/vpn_service.h"

namespace shill {

namespace Logging {

static auto kModuleLogScope = ScopeLogger::kVPN;
static std::string ObjectID(const ThirdPartyVpnDriver* v) {
  return "(third_party_vpn_driver)";
}

}  // namespace Logging

namespace {

const int32_t kConstantMaxMtu = (1 << 16) - 1;
constexpr base::TimeDelta kConnectTimeout = base::Minutes(5);

std::string IPAddressFingerprint(const IPAddress& address) {
  static const char* const hex_to_bin[] = {
      "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111",
      "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"};
  std::string fingerprint;
  const size_t address_length = address.address().GetLength();
  const uint8_t* raw_address = address.address().GetConstData();
  for (size_t i = 0; i < address_length; ++i) {
    fingerprint += hex_to_bin[raw_address[i] >> 4];
    fingerprint += hex_to_bin[raw_address[i] & 0xf];
  }
  return fingerprint.substr(0, address.prefix());
}

}  // namespace

const VPNDriver::Property ThirdPartyVpnDriver::kProperties[] = {
    {kProviderHostProperty, 0},
    {kProviderTypeProperty, 0},
    {kExtensionNameProperty, 0},
    {kConfigurationNameProperty, 0}};

ThirdPartyVpnDriver* ThirdPartyVpnDriver::active_client_ = nullptr;

ThirdPartyVpnDriver::ThirdPartyVpnDriver(Manager* manager,
                                         ProcessManager* process_manager)
    : VPNDriver(manager, process_manager, kProperties, std::size(kProperties)),
      tun_fd_(-1),
      ip_properties_set_(false),
      io_handler_factory_(IOHandlerFactory::GetInstance()),
      parameters_expected_(false),
      reconnect_supported_(false) {
  file_io_ = FileIO::GetInstance();
}

ThirdPartyVpnDriver::~ThirdPartyVpnDriver() {
  Cleanup();
}

void ThirdPartyVpnDriver::InitPropertyStore(PropertyStore* store) {
  VPNDriver::InitPropertyStore(store);
  store->RegisterDerivedString(
      kObjectPathSuffixProperty,
      StringAccessor(
          new CustomWriteOnlyAccessor<ThirdPartyVpnDriver, std::string>(
              this, &ThirdPartyVpnDriver::SetExtensionId,
              &ThirdPartyVpnDriver::ClearExtensionId, nullptr)));
}

bool ThirdPartyVpnDriver::Load(const StoreInterface* storage,
                               const std::string& storage_id) {
  bool return_value = VPNDriver::Load(storage, storage_id);
  if (adaptor_interface_ == nullptr) {
    storage->GetString(storage_id, kObjectPathSuffixProperty,
                       &object_path_suffix_);
    adaptor_interface_ = control_interface()->CreateThirdPartyVpnAdaptor(this);
  }
  return return_value;
}

bool ThirdPartyVpnDriver::Save(StoreInterface* storage,
                               const std::string& storage_id,
                               bool save_credentials) {
  bool return_value = VPNDriver::Save(storage, storage_id, save_credentials);
  storage->SetString(storage_id, kObjectPathSuffixProperty,
                     object_path_suffix_);
  return return_value;
}

void ThirdPartyVpnDriver::ClearExtensionId(Error* error) {
  error->Populate(Error::kIllegalOperation,
                  "Clearing extension id is not allowed.");
}

bool ThirdPartyVpnDriver::SetExtensionId(const std::string& value,
                                         Error* error) {
  if (adaptor_interface_ == nullptr) {
    object_path_suffix_ = value;
    adaptor_interface_ = control_interface()->CreateThirdPartyVpnAdaptor(this);
    return true;
  }
  error->Populate(Error::kAlreadyExists, "Extension ID is set");
  return false;
}

void ThirdPartyVpnDriver::UpdateConnectionState(
    Service::ConnectState connection_state, std::string* error_message) {
  if (active_client_ != this) {
    error_message->append("Unexpected call");
    return;
  }
  if (event_handler_ && connection_state == Service::kStateFailure) {
    FailService(Service::kFailureInternal, Service::kErrorDetailsNone);
    return;
  }
  if (!event_handler_ || connection_state != Service::kStateOnline) {
    // We expect "failure" and "connected" messages from the client, but we
    // only set state for these "failure" messages. "connected" message (which
    // is corresponding to kStateOnline here) will simply be ignored.
    error_message->append("Invalid argument");
  }
}

void ThirdPartyVpnDriver::SendPacket(const std::vector<uint8_t>& ip_packet,
                                     std::string* error_message) {
  if (active_client_ != this) {
    error_message->append("Unexpected call");
    return;
  } else if (tun_fd_ < 0) {
    error_message->append("Device not open");
    return;
  } else if (file_io_->Write(tun_fd_, ip_packet.data(), ip_packet.size()) !=
             static_cast<ssize_t>(ip_packet.size())) {
    error_message->append("Partial write");
    adaptor_interface_->EmitPlatformMessage(
        static_cast<uint32_t>(PlatformMessage::kError));
  }
}

void ThirdPartyVpnDriver::ProcessIp(
    const std::map<std::string, std::string>& parameters,
    const char* key,
    std::string* target,
    bool mandatory,
    std::string* error_message) {
  // TODO(kaliamoorthi): Add IPV6 support.
  auto it = parameters.find(key);
  if (it != parameters.end()) {
    if (IPAddress(parameters.at(key)).family() == IPAddress::kFamilyIPv4) {
      *target = parameters.at(key);
    } else {
      error_message->append(key).append(" is not a valid IP;");
    }
  } else if (mandatory) {
    error_message->append(key).append(" is missing;");
  }
}

void ThirdPartyVpnDriver::ProcessIPArray(
    const std::map<std::string, std::string>& parameters,
    const char* key,
    char delimiter,
    std::vector<std::string>* target,
    bool mandatory,
    std::string* error_message,
    std::string* warning_message) {
  std::vector<std::string> string_array;
  auto it = parameters.find(key);
  if (it != parameters.end()) {
    string_array =
        base::SplitString(parameters.at(key), std::string{delimiter},
                          base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);

    // Eliminate invalid IPs
    for (auto value = string_array.begin(); value != string_array.end();) {
      if (IPAddress(*value).family() != IPAddress::kFamilyIPv4) {
        warning_message->append(*value + " for " + key + " is invalid;");
        value = string_array.erase(value);
      } else {
        ++value;
      }
    }

    if (!string_array.empty()) {
      target->swap(string_array);
    } else if (mandatory) {
      error_message->append(key).append(" has no valid values or is empty;");
    }
  } else if (mandatory) {
    error_message->append(key).append(" is missing;");
  }
}

void ThirdPartyVpnDriver::ProcessIPArrayCIDR(
    const std::map<std::string, std::string>& parameters,
    const char* key,
    char delimiter,
    std::vector<std::string>* target,
    bool mandatory,
    std::string* error_message,
    std::string* warning_message) {
  std::vector<std::string> string_array;
  IPAddress address(IPAddress::kFamilyIPv4);
  auto it = parameters.find(key);
  if (it != parameters.end()) {
    string_array =
        base::SplitString(parameters.at(key), std::string{delimiter},
                          base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);

    // Eliminate invalid IPs
    for (auto value = string_array.begin(); value != string_array.end();) {
      if (!address.SetAddressAndPrefixFromString(*value)) {
        warning_message->append(*value + " for " + key + " is invalid;");
        value = string_array.erase(value);
        continue;
      }
      const std::string cidr_key = IPAddressFingerprint(address);
      if (known_cidrs_.find(cidr_key) != known_cidrs_.end()) {
        warning_message->append("Duplicate entry for " + *value + " in " + key +
                                " found;");
        value = string_array.erase(value);
      } else {
        known_cidrs_.insert(cidr_key);
        ++value;
      }
    }

    if (!string_array.empty()) {
      target->swap(string_array);
    } else {
      error_message->append(key).append(" has no valid values or is empty;");
    }
  } else if (mandatory) {
    error_message->append(key).append(" is missing;");
  }
}

void ThirdPartyVpnDriver::ProcessSearchDomainArray(
    const std::map<std::string, std::string>& parameters,
    const char* key,
    char delimiter,
    std::vector<std::string>* target,
    bool mandatory,
    std::string* error_message) {
  std::vector<std::string> string_array;
  auto it = parameters.find(key);
  if (it != parameters.end()) {
    string_array =
        base::SplitString(parameters.at(key), std::string{delimiter},
                          base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);

    if (!string_array.empty()) {
      target->swap(string_array);
    } else {
      error_message->append(key).append(" has no valid values or is empty;");
    }
  } else if (mandatory) {
    error_message->append(key).append(" is missing;");
  }
}

void ThirdPartyVpnDriver::ProcessInt32(
    const std::map<std::string, std::string>& parameters,
    const char* key,
    int32_t* target,
    int32_t min_value,
    int32_t max_value,
    bool mandatory,
    std::string* error_message) {
  int32_t value = 0;
  auto it = parameters.find(key);
  if (it != parameters.end()) {
    if (base::StringToInt(parameters.at(key), &value) && value >= min_value &&
        value <= max_value) {
      *target = value;
    } else {
      error_message->append(key).append(" not in expected range;");
    }
  } else if (mandatory) {
    error_message->append(key).append(" is missing;");
  }
}

void ThirdPartyVpnDriver::ProcessBoolean(
    const std::map<std::string, std::string>& parameters,
    const char* key,
    bool* target,
    bool mandatory,
    std::string* error_message) {
  auto it = parameters.find(key);
  if (it != parameters.end()) {
    std::string str_value = parameters.at(key);
    if (str_value == "true") {
      *target = true;
    } else if (str_value == "false") {
      *target = false;
    } else {
      error_message->append(key).append(" not a valid boolean;");
    }
  } else if (mandatory) {
    error_message->append(key).append(" is missing;");
  }
}

void ThirdPartyVpnDriver::SetParameters(
    const std::map<std::string, std::string>& parameters,
    std::string* error_message,
    std::string* warning_message) {
  // TODO(kaliamoorthi): Add IPV6 support.
  if (!parameters_expected_ || active_client_ != this) {
    error_message->append("Unexpected call");
    return;
  }

  ip_properties_ = IPConfig::Properties();
  ip_properties_.address_family = IPAddress::kFamilyIPv4;

  ProcessIp(parameters, kAddressParameterThirdPartyVpn, &ip_properties_.address,
            true, error_message);
  ProcessIp(parameters, kBroadcastAddressParameterThirdPartyVpn,
            &ip_properties_.broadcast_address, false, error_message);

  ip_properties_.gateway = ip_properties_.address;

  ProcessInt32(parameters, kSubnetPrefixParameterThirdPartyVpn,
               &ip_properties_.subnet_prefix, 0, 32, true, error_message);
  ProcessInt32(parameters, kMtuParameterThirdPartyVpn, &ip_properties_.mtu,
               IPConfig::kMinIPv4MTU, kConstantMaxMtu, false, error_message);

  ProcessSearchDomainArray(parameters, kDomainSearchParameterThirdPartyVpn,
                           kNonIPDelimiter, &ip_properties_.domain_search,
                           false, error_message);
  ProcessIPArray(parameters, kDnsServersParameterThirdPartyVpn, kIPDelimiter,
                 &ip_properties_.dns_servers, false, error_message,
                 warning_message);

  known_cidrs_.clear();

  ProcessIPArrayCIDR(parameters, kExclusionListParameterThirdPartyVpn,
                     kIPDelimiter, &ip_properties_.exclusion_list, true,
                     error_message, warning_message);
  if (!ip_properties_.exclusion_list.empty()) {
    // The first excluded IP is used to find the default gateway. The logic that
    // finds the default gateway does not work for default route "0.0.0.0/0".
    // Hence, this code ensures that the first IP is not default.
    IPAddress address(ip_properties_.address_family);
    address.SetAddressAndPrefixFromString(ip_properties_.exclusion_list[0]);
    if (address.IsDefault() && !address.prefix()) {
      if (ip_properties_.exclusion_list.size() > 1) {
        swap(ip_properties_.exclusion_list[0],
             ip_properties_.exclusion_list[1]);
      } else {
        // When there is only a single entry which is a default address, it can
        // be cleared since the default behavior is to not route any traffic to
        // the tunnel interface.
        ip_properties_.exclusion_list.clear();
      }
    }
  }

  reconnect_supported_ = false;
  ProcessBoolean(parameters, kReconnectParameterThirdPartyVpn,
                 &reconnect_supported_, false, error_message);

  std::vector<std::string> inclusion_list;
  ProcessIPArrayCIDR(parameters, kInclusionListParameterThirdPartyVpn,
                     kIPDelimiter, &inclusion_list, true, error_message,
                     warning_message);

  IPAddress ip_address(ip_properties_.address_family);
  IPConfig::Route route;
  route.gateway = ip_properties_.gateway;
  for (const auto& value : inclusion_list) {
    ip_address.SetAddressAndPrefixFromString(value);
    ip_address.IntoString(&route.host);
    route.prefix = ip_address.prefix();
    ip_properties_.routes.push_back(route);
  }

  if (!error_message->empty()) {
    LOG(ERROR) << __func__ << ": " << error_message;
    return;
  }
  ip_properties_.default_route = false;
  ip_properties_.blackhole_ipv6 = true;
  ip_properties_.method = kTypeVPN;
  if (!ip_properties_set_) {
    ip_properties_set_ = true;
    metrics()->SendEnumToUMA(Metrics::kMetricVpnDriver,
                             Metrics::kVpnDriverThirdParty,
                             Metrics::kMetricVpnDriverMax);
  }

  if (event_handler_) {
    event_handler_->OnDriverConnected(interface_name_, interface_index_);
  } else {
    LOG(ERROR) << "Missing service callback";
  }
}

void ThirdPartyVpnDriver::OnInput(InputData* data) {
  if (data->len <= 0) {
    return;
  }

  // Not all Chrome apps can properly handle being passed IPv6 packets. This
  // usually should not be an issue because we prevent IPv6 traffic from being
  // routed to this VPN. However, the kernel itself can sometimes send IPv6
  // packets to an interface--even before we set up our routing
  // rules. Therefore, we drop non-IPv4 traffic here.
  //
  // See from RFC 791 Section 3.1 that the high nibble of the first byte in an
  // IP header represents the IP version (4 in this case).
  if ((data->buf[0] & 0xf0) != 0x40) {
    SLOG(this, 1) << "Dropping non-IPv4 packet";
    return;
  }

  // TODO(kaliamoorthi): This is not efficient, transfer the descriptor over to
  // chrome browser or use a pipe in between. Avoid using DBUS for packet
  // transfer.
  std::vector<uint8_t> ip_packet(data->buf, data->buf + data->len);
  adaptor_interface_->EmitPacketReceived(ip_packet);
}

void ThirdPartyVpnDriver::OnInputError(const std::string& error) {
  LOG(ERROR) << error;
  CHECK_EQ(active_client_, this);
  adaptor_interface_->EmitPlatformMessage(
      static_cast<uint32_t>(PlatformMessage::kError));
}

void ThirdPartyVpnDriver::Cleanup() {
  if (tun_fd_ > 0) {
    file_io_->Close(tun_fd_);
    tun_fd_ = -1;
  }
  io_handler_.reset();
  if (active_client_ == this) {
    adaptor_interface_->EmitPlatformMessage(
        static_cast<uint32_t>(PlatformMessage::kDisconnected));
    active_client_ = nullptr;
  }
  parameters_expected_ = false;
  reconnect_supported_ = false;

  if (!interface_name_.empty()) {
    manager()->device_info()->DeleteInterface(interface_index_);
    interface_name_.clear();
    interface_index_ = -1;
  }
}

base::TimeDelta ThirdPartyVpnDriver::ConnectAsync(EventHandler* handler) {
  SLOG(this, 2) << __func__;
  event_handler_ = handler;
  if (!manager()->device_info()->CreateTunnelInterface(base::BindOnce(
          &ThirdPartyVpnDriver::OnLinkReady, weak_factory_.GetWeakPtr()))) {
    dispatcher()->PostTask(
        FROM_HERE,
        base::BindOnce(&ThirdPartyVpnDriver::FailService,
                       weak_factory_.GetWeakPtr(), Service::kFailureInternal,
                       "Could not to create tunnel interface."));
    return kTimeoutNone;
  }
  return kConnectTimeout;
}

void ThirdPartyVpnDriver::OnLinkReady(const std::string& link_name,
                                      int interface_index) {
  SLOG(this, 2) << __func__;
  if (!event_handler_) {
    LOG(ERROR) << "event_handler_ is not set";
    return;
  }

  CHECK(adaptor_interface_);
  CHECK(!active_client_);

  interface_name_ = link_name;
  interface_index_ = interface_index;

  ip_properties_ = IPConfig::Properties();
  ip_properties_set_ = false;

  tun_fd_ = manager()->device_info()->OpenTunnelInterface(interface_name_);
  if (tun_fd_ < 0) {
    FailService(Service::kFailureInternal, "Unable to open tun interface");
    return;
  }
  io_handler_.reset(io_handler_factory_->CreateIOInputHandler(
      tun_fd_,
      base::Bind(&ThirdPartyVpnDriver::OnInput, base::Unretained(this)),
      base::Bind(&ThirdPartyVpnDriver::OnInputError, base::Unretained(this))));
  active_client_ = this;
  parameters_expected_ = true;
  adaptor_interface_->EmitPlatformMessage(
      static_cast<uint32_t>(PlatformMessage::kConnected));
}

IPConfig::Properties ThirdPartyVpnDriver::GetIPProperties() const {
  return ip_properties_;
}

void ThirdPartyVpnDriver::FailService(Service::ConnectFailure failure,
                                      const std::string& error_details) {
  SLOG(this, 2) << __func__ << "(" << error_details << ")";
  Cleanup();
  if (event_handler_) {
    event_handler_->OnDriverFailure(failure, error_details);
    event_handler_ = nullptr;
  }
}

void ThirdPartyVpnDriver::Disconnect() {
  SLOG(this, 2) << __func__;
  CHECK(adaptor_interface_);
  if (active_client_ == this) {
    Cleanup();
  }
  event_handler_ = nullptr;
}

std::string ThirdPartyVpnDriver::GetProviderType() const {
  return std::string(kProviderThirdPartyVpn);
}

void ThirdPartyVpnDriver::OnDefaultPhysicalServiceEvent(
    DefaultPhysicalServiceEvent event) {
  if (!event_handler_)
    return;

  if (event == kDefaultPhysicalServiceDown ||
      event == kDefaultPhysicalServiceChanged) {
    if (!reconnect_supported_) {
      FailService(Service::kFailureInternal,
                  "Underlying network disconnected.");
      return;
    }
  }

  PlatformMessage message;
  switch (event) {
    case kDefaultPhysicalServiceUp:
      message = PlatformMessage::kLinkUp;
      event_handler_->OnDriverReconnecting(kConnectTimeout);
      break;
    case kDefaultPhysicalServiceDown:
      message = PlatformMessage::kLinkDown;
      event_handler_->OnDriverReconnecting(kTimeoutNone);
      break;
    case kDefaultPhysicalServiceChanged:
      message = PlatformMessage::kLinkChanged;
      event_handler_->OnDriverReconnecting(kConnectTimeout);
      break;
    default:
      NOTREACHED();
  }

  adaptor_interface_->EmitPlatformMessage(static_cast<uint32_t>(message));
}

void ThirdPartyVpnDriver::OnBeforeSuspend(const ResultCallback& callback) {
  if (event_handler_ && reconnect_supported_) {
    // FIXME: Currently the VPN app receives this message at the same time
    // as the resume message, even if shill adds a delay to hold off the
    // suspend sequence.
    adaptor_interface_->EmitPlatformMessage(
        static_cast<uint32_t>(PlatformMessage::kSuspend));
  }
  callback.Run(Error(Error::kSuccess));
}

void ThirdPartyVpnDriver::OnAfterResume() {
  if (event_handler_ && reconnect_supported_) {
    // Transition back to Configuring state so that the app can perform
    // DNS lookups and reconnect.
    event_handler_->OnDriverReconnecting(kConnectTimeout);
    adaptor_interface_->EmitPlatformMessage(
        static_cast<uint32_t>(PlatformMessage::kResume));
  }
}

void ThirdPartyVpnDriver::OnConnectTimeout() {
  SLOG(this, 2) << __func__;
  if (!event_handler_) {
    LOG(DFATAL) << "event_handler_ is not set";
    return;
  }
  adaptor_interface_->EmitPlatformMessage(
      static_cast<uint32_t>(PlatformMessage::kError));
  FailService(Service::kFailureConnect, "Connection timed out");
}

}  // namespace shill
