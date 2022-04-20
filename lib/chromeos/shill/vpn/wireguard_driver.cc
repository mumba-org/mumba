// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/wireguard_driver.h"

#include <poll.h>

#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/base64.h>
#include <base/bind.h>
#include <base/callback_helpers.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <base/version.h>
#include <chromeos/dbus/service_constants.h>
#include <crypto/random.h>

#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/process_manager.h"
#include "shill/store/property_accessor.h"
#include "shill/store/store_interface.h"
#include "shill/vpn/vpn_util.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kVPN;
static std::string ObjectID(const WireGuardDriver*) {
  return "(wireguard_driver)";
}
}  // namespace Logging

namespace {

constexpr char kWireGuardPath[] = "/usr/sbin/wireguard";
constexpr char kWireGuardToolsPath[] = "/usr/bin/wg";
constexpr char kDefaultInterfaceName[] = "wg0";

// The name of the property which indicates where the key pair comes from. This
// property only appears in storage but not in D-Bus API.
constexpr char kWireGuardKeyPairSource[] = "WireGuard.KeyPairSource";

// Timeout value for spawning the userspace wireguard process and configuring
// the interface via wireguard-tools.
constexpr base::TimeDelta kConnectTimeout = base::Seconds(10);

// Key length of Curve25519.
constexpr int kWgKeyLength = 32;
constexpr int kWgBase64KeyLength = (((kWgKeyLength) + 2) / 3) * 4;

// Properties of a peer.
struct PeerProperty {
  // A name will be used in 1) D-Bus API, 2) profile storage, and 3) config file
  // passed to wireguard-tools.
  const char* const name;
  // Checked only before connecting. We allow a partially configured service
  // from crosh.
  const bool is_required;
};
constexpr PeerProperty kPeerProperties[] = {
    {kWireGuardPeerPublicKey, true},
    {kWireGuardPeerPresharedKey, false},
    {kWireGuardPeerEndpoint, true},
    {kWireGuardPeerAllowedIPs, false},
    {kWireGuardPeerPersistentKeepalive, false},
};

// Checks the given peers object is valid for kept by WireguardDriver (it means
// this peers can be persisted in the storage but may be not ready for
// connecting). Here we checks whether each peer has a unique and non-empty
// public key.
bool ValidatePeersForStorage(const Stringmaps& peers) {
  std::set<std::string> public_keys;
  for (auto& peer : peers) {
    const auto it = peer.find(kWireGuardPeerPublicKey);
    if (it == peer.end()) {
      return false;
    }
    const std::string& this_pubkey = it->second;
    if (this_pubkey.empty()) {
      return false;
    }
    if (public_keys.count(this_pubkey) != 0) {
      return false;
    }
    public_keys.insert(this_pubkey);
  }
  return true;
}

std::string GenerateBase64PrivateKey() {
  uint8_t key[kWgKeyLength];
  crypto::RandBytes(key, kWgKeyLength);

  // Converts the random bytes into a Curve25519 key, as per
  // https://cr.yp.to/ecdh.html
  key[0] &= 248;
  key[31] &= 127;
  key[31] |= 64;

  return base::Base64Encode(base::span<uint8_t>(key, kWgKeyLength));
}

// Invokes wireguard-tools to calculates the public key based on the given
// private key. Returns an empty string on error. Note that the call to
// wireguard-tools is blocking but with a timeout (kPollTimeout below).
std::string CalculateBase64PublicKey(const std::string& base64_private_key,
                                     ProcessManager* process_manager) {
  constexpr auto kPollTimeout = base::Milliseconds(200);

  constexpr uint64_t kCapMask = 0;
  int stdin_fd = -1;
  int stdout_fd = -1;
  pid_t pid = process_manager->StartProcessInMinijailWithPipes(
      FROM_HERE, base::FilePath(kWireGuardToolsPath), {"pubkey"},
      /*environment=*/{}, VPNUtil::BuildMinijailOptions(kCapMask),
      /*exit_callback=*/base::DoNothing(),
      {.stdin_fd = &stdin_fd, .stdout_fd = &stdout_fd});
  if (pid == -1) {
    LOG(ERROR) << "Failed to run 'wireguard-tools pubkey'";
    return "";
  }

  base::ScopedFD scoped_stdin(stdin_fd);
  base::ScopedFD scoped_stdout(stdout_fd);

  if (!base::WriteFileDescriptor(scoped_stdin.get(), base64_private_key)) {
    LOG(ERROR) << "Failed to send private key to wireguard-tools";
    process_manager->StopProcess(pid);
    return "";
  }
  scoped_stdin.reset();

  struct pollfd pollfds[] = {{
      .fd = scoped_stdout.get(),
      .events = POLLIN,
  }};
  int ret = poll(pollfds, 1, kPollTimeout.InMilliseconds());
  if (ret == -1) {
    PLOG(ERROR) << "poll() failed";
    process_manager->StopProcess(pid);
    return "";
  } else if (ret == 0) {
    LOG(ERROR) << "poll() timeout";
    process_manager->StopProcess(pid);
    return "";
  }

  char buf[kWgBase64KeyLength];
  ssize_t read_cnt =
      HANDLE_EINTR(read(scoped_stdout.get(), buf, size_t{kWgBase64KeyLength}));
  if (read_cnt == -1) {
    PLOG(ERROR) << "read() failed";
    process_manager->StopProcess(pid);
    return "";
  } else if (read_cnt != kWgBase64KeyLength) {
    LOG(ERROR) << "Failed to read enough chars for a public key. read_cnt="
               << read_cnt;
    process_manager->StopProcess(pid);
    return "";
  }

  return std::string{buf, std::string::size_type{kWgBase64KeyLength}};
}

// Checks if the input string value for a property contains any invalid
// characters which can pollute the config file. Currently only '\n' is checked,
// which may generate a new parsable line.
bool ValidateInputString(const std::string& value) {
  return value.find('\n') == value.npos;
}

}  // namespace

// static
const VPNDriver::Property WireGuardDriver::kProperties[] = {
    {kProviderHostProperty, 0},
    {kProviderTypeProperty, 0},

    // Properties for the interface. ListenPort is not here since we current
    // only support the "client mode". Local overlay addresses on the interface,
    // DNS servers, and MTU will be set via StaticIPConfig.
    {kWireGuardPrivateKey, Property::kEphemeral | Property::kWriteOnly},
    // TODO(b/177877860): This field is for software-backed keys only. May need
    // to change this logic when hardware-backed keys come.
    {kWireGuardPublicKey, Property::kReadOnly},
};

WireGuardDriver::WireGuardDriver(Manager* manager,
                                 ProcessManager* process_manager)
    : VPNDriver(manager, process_manager, kProperties, std::size(kProperties)),
      vpn_util_(VPNUtil::New()) {}

WireGuardDriver::~WireGuardDriver() {
  Cleanup();
}

base::TimeDelta WireGuardDriver::ConnectAsync(EventHandler* event_handler) {
  SLOG(this, 2) << __func__;
  event_handler_ = event_handler;
  // To make sure the connect procedure is executed asynchronously.
  dispatcher()->PostTask(
      FROM_HERE,
      base::BindOnce(&WireGuardDriver::CreateKernelWireGuardInterface,
                     weak_factory_.GetWeakPtr()));
  return kConnectTimeout;
}

void WireGuardDriver::Disconnect() {
  SLOG(this, 2) << __func__;
  Cleanup();
  event_handler_ = nullptr;
}

IPConfig::Properties WireGuardDriver::GetIPProperties() const {
  return ip_properties_;
}

std::string WireGuardDriver::GetProviderType() const {
  return kProviderWireGuard;
}

void WireGuardDriver::OnConnectTimeout() {
  FailService(Service::kFailureConnect, "Connect timeout");
}

void WireGuardDriver::InitPropertyStore(PropertyStore* store) {
  VPNDriver::InitPropertyStore(store);
  store->RegisterDerivedStringmaps(
      kWireGuardPeers,
      StringmapsAccessor(
          new CustomWriteOnlyAccessor<WireGuardDriver, Stringmaps>(
              this, &WireGuardDriver::UpdatePeers, &WireGuardDriver::ClearPeers,
              nullptr)));
}

KeyValueStore WireGuardDriver::GetProvider(Error* error) {
  KeyValueStore props = VPNDriver::GetProvider(error);
  Stringmaps copied_peers = peers_;
  for (auto& peer : copied_peers) {
    peer.erase(kWireGuardPeerPresharedKey);
  }
  props.Set<Stringmaps>(kWireGuardPeers, copied_peers);
  return props;
}

bool WireGuardDriver::Load(const StoreInterface* storage,
                           const std::string& storage_id) {
  if (!VPNDriver::Load(storage, storage_id)) {
    return false;
  }

  peers_.clear();

  std::vector<std::string> encoded_peers;
  if (!storage->GetStringList(storage_id, kWireGuardPeers, &encoded_peers)) {
    LOG(WARNING) << "Profile does not contain the " << kWireGuardPeers
                 << " property";
    return true;
  }

  for (const auto& peer_json : encoded_peers) {
    std::optional<base::Value> val = base::JSONReader::Read(peer_json);
    if (!val || !val->is_dict()) {
      LOG(ERROR) << "Failed to parse a peer. Skipped it.";
      continue;
    }
    Stringmap peer;
    for (const auto& property : kPeerProperties) {
      const std::string key = property.name;
      const auto* value = val->FindStringKey(key);
      if (value != nullptr) {
        peer[key] = *value;
      } else {
        peer[key] = "";
      }
    }
    peers_.push_back(peer);
  }

  if (!ValidatePeersForStorage(peers_)) {
    LOG(ERROR) << "Failed to load peers: missing PublicKey property or the "
                  "value is not unique";
    peers_.clear();
    return false;
  }

  // Loads |key_pair_source_|;
  int stored_value = 0;
  if (!storage->GetInt(storage_id, kWireGuardKeyPairSource, &stored_value)) {
    stored_value = Metrics::kVpnWireguardKeyPairSourceUnknown;
  }
  if (stored_value != Metrics::kVpnWireGuardKeyPairSourceUserInput &&
      stored_value != Metrics::kVpnWireGuardKeyPairSourceSoftwareGenerated) {
    LOG(ERROR) << kWireGuardKeyPairSource
               << " contains an invalid value or does not exist in storage: "
               << stored_value;
    stored_value = Metrics::kVpnWireguardKeyPairSourceUnknown;
  }
  key_pair_source_ =
      static_cast<Metrics::VpnWireGuardKeyPairSource>(stored_value);

  if (!storage->PKCS11GetString(storage_id, kWireGuardPrivateKey,
                                &saved_private_key_)) {
    LOG(ERROR) << "Failed to load private key from PKCS#11 store";
    return false;
  }
  args()->Set<std::string>(kWireGuardPrivateKey, saved_private_key_);

  return true;
}

bool WireGuardDriver::Save(StoreInterface* storage,
                           const std::string& storage_id,
                           bool save_credentials) {
  if (!save_credentials) {
    LOG(WARNING) << "save_credentials is false when saving to the storage.";
  }

  // Keys should be processed before calling VPNDriver::Save().
  auto private_key = args()->Lookup<std::string>(kWireGuardPrivateKey, "");
  if (private_key.empty()) {
    private_key = GenerateBase64PrivateKey();
    args()->Set<std::string>(kWireGuardPrivateKey, private_key);
    // The user cleared the private key.
    key_pair_source_ = Metrics::kVpnWireGuardKeyPairSourceSoftwareGenerated;
  } else if (private_key != saved_private_key_) {
    // Note that this branch is different with the if statement below: if the
    // private key in args() is not empty before we fill a random one in it, it
    // must be changed by the user, and this code path is the only way where the
    // user use its own private key.
    key_pair_source_ = Metrics::kVpnWireGuardKeyPairSourceUserInput;
  }
  if (private_key != saved_private_key_) {
    std::string public_key =
        CalculateBase64PublicKey(private_key, process_manager());
    if (public_key.empty()) {
      LOG(ERROR) << "Failed to calculate public key in Save().";
      return false;
    }
    args()->Set<std::string>(kWireGuardPublicKey, public_key);
    saved_private_key_ = private_key;
    if (!storage->PKCS11SetString(storage_id, kWireGuardPrivateKey,
                                  private_key)) {
      LOG(ERROR) << "Failed to save private key to PKCS#11 store";
      return false;
    }
  }

  // Handles peers.
  std::vector<std::string> encoded_peers;
  for (auto& peer : peers_) {
    base::Value root(base::Value::Type::DICTIONARY);
    for (const auto& property : kPeerProperties) {
      const auto& key = property.name;
      root.SetStringKey(key, peer[key]);
    }
    std::string peer_json;
    if (!base::JSONWriter::Write(root, &peer_json)) {
      LOG(ERROR) << "Failed to write a peer into json";
      return false;
    }
    encoded_peers.push_back(peer_json);
  }

  if (!storage->SetStringList(storage_id, kWireGuardPeers, encoded_peers)) {
    LOG(ERROR) << "Failed to write " << kWireGuardPeers
               << " property into profile";
    return false;
  }

  if (!storage->SetInt(storage_id, kWireGuardKeyPairSource, key_pair_source_)) {
    LOG(ERROR) << "Failed to write " << kWireGuardKeyPairSource
               << " property into profile";
    return false;
  }

  return VPNDriver::Save(storage, storage_id, save_credentials);
}

void WireGuardDriver::UnloadCredentials() {
  VPNDriver::UnloadCredentials();
  for (auto& peer : peers_) {
    // For a peer loaded by Load(), all properties should exist even if they are
    // empty, so we only clear the value here, instead of erasing the key.
    peer[kWireGuardPeerPresharedKey] = "";
  }
}

void WireGuardDriver::CreateKernelWireGuardInterface() {
  auto link_ready_callback = base::BindOnce(
      &WireGuardDriver::ConfigureInterface, weak_factory_.GetWeakPtr(),
      /*created_in_kernel=*/true);
  auto failure_callback =
      base::BindOnce(&WireGuardDriver::StartUserspaceWireGuardTunnel,
                     weak_factory_.GetWeakPtr());
  if (!manager()->device_info()->CreateWireGuardInterface(
          kDefaultInterfaceName, std::move(link_ready_callback),
          std::move(failure_callback))) {
    StartUserspaceWireGuardTunnel();
  }
}

void WireGuardDriver::StartUserspaceWireGuardTunnel() {
  LOG(INFO) << "Failed to create a wireguard interface in the kernel. Fallback "
               "to userspace tunnel.";

  // Claims the interface before the wireguard process creates it.
  // TODO(b/177876632): Actually when the tunnel interface is ready, it cannot
  // guarantee that the wireguard-tools can talk with the userspace wireguard
  // process now. We should also wait for another event that the UAPI socket
  // appears (which is a UNIX-domain socket created by the userspace wireguard
  // process at a fixed path: `/var/run/wireguard/wg0.sock`).
  manager()->device_info()->AddVirtualInterfaceReadyCallback(
      kDefaultInterfaceName,
      base::BindOnce(&WireGuardDriver::ConfigureInterface,
                     weak_factory_.GetWeakPtr(),
                     /*created_in_kernel=*/false));

  if (!SpawnWireGuard()) {
    FailService(Service::kFailureInternal, "Failed to spawn wireguard process");
  }
}

bool WireGuardDriver::SpawnWireGuard() {
  SLOG(this, 2) << __func__;

  // TODO(b/177876632): Change this part after we decide the userspace binary to
  // use. For wireguard-go, we need to change the way to invoke minijail; for
  // wireugard-rs, we need to add `--disable-drop-privileges` or change the
  // capmask.
  std::vector<std::string> args = {
      "--foreground",
      kDefaultInterfaceName,
  };
  constexpr uint64_t kCapMask = CAP_TO_MASK(CAP_NET_ADMIN);
  wireguard_pid_ = process_manager()->StartProcessInMinijail(
      FROM_HERE, base::FilePath(kWireGuardPath), args,
      /*environment=*/{}, VPNUtil::BuildMinijailOptions(kCapMask),
      base::BindOnce(&WireGuardDriver::WireGuardProcessExited,
                     weak_factory_.GetWeakPtr()));
  return wireguard_pid_ > -1;
}

void WireGuardDriver::WireGuardProcessExited(int exit_code) {
  wireguard_pid_ = -1;
  FailService(
      Service::kFailureInternal,
      base::StringPrintf("wireguard process exited unexpectedly with code=%d",
                         exit_code));
}

std::string WireGuardDriver::GenerateConfigFileContents() {
  std::vector<std::string> lines;

  // [Interface] section
  lines.push_back("[Interface]");
  const std::string private_key =
      args()->Lookup<std::string>(kWireGuardPrivateKey, "");
  if (!ValidateInputString(private_key)) {
    LOG(ERROR) << "PrivateKey contains invalid characters.";
    return "";
  }
  if (private_key.empty()) {
    LOG(ERROR) << "PrivateKey is required but is empty or not set.";
    return "";
  }
  lines.push_back(base::StrCat({"PrivateKey", "=", private_key}));
  // 0x4000 for bypass VPN, 0x0500 for source of host VPN.
  // See patchpanel/routing_service.h for their definitions.
  lines.push_back("FwMark=0x4500");

  lines.push_back("");

  // [Peer] sections
  for (auto& peer : peers_) {
    lines.push_back("[Peer]");
    for (const auto& property : kPeerProperties) {
      const std::string val = peer[property.name];
      if (!ValidateInputString(val)) {
        LOG(ERROR) << property.name << " contains invalid characters.";
        return "";
      }
      if (!val.empty()) {
        lines.push_back(base::StrCat({property.name, "=", val}));
      } else if (property.is_required) {
        LOG(ERROR) << property.name
                   << " in a peer is required but is empty or not set.";
        return "";
      }
    }
    lines.push_back("");
  }

  return base::JoinString(lines, "\n");
}

void WireGuardDriver::ConfigureInterface(bool created_in_kernel,
                                         const std::string& interface_name,
                                         int interface_index) {
  LOG(INFO) << "WireGuard interface " << interface_name << " was created "
            << (created_in_kernel ? "in kernel" : "by userspace program")
            << ". Start configuration";
  kernel_interface_open_ = created_in_kernel;

  if (!event_handler_) {
    LOG(ERROR) << "Missing event_handler_";
    Cleanup();
    return;
  }

  interface_index_ = interface_index;

  // Writes config file.
  std::string config_contents = GenerateConfigFileContents();
  if (config_contents.empty()) {
    FailService(Service::kFailureInternal,
                "Failed to generate config file contents");
    return;
  }
  auto [fd, path] = vpn_util_->WriteAnonymousConfigFile(config_contents);
  config_fd_ = std::move(fd);
  if (!config_fd_.is_valid()) {
    FailService(Service::kFailureInternal, "Failed to write config file");
    return;
  }

  // Executes wireguard-tools.
  std::vector<std::string> args = {"setconf", kDefaultInterfaceName,
                                   path.value()};
  constexpr uint64_t kCapMask = CAP_TO_MASK(CAP_NET_ADMIN);
  auto minijail_options = VPNUtil::BuildMinijailOptions(kCapMask);
  // Do not close nonstd fds to leave the anonymous config file open.
  minijail_options.close_nonstd_fds = false;
  pid_t pid = process_manager()->StartProcessInMinijail(
      FROM_HERE, base::FilePath(kWireGuardToolsPath), args,
      /*environment=*/{}, minijail_options,
      base::BindOnce(&WireGuardDriver::OnConfigurationDone,
                     weak_factory_.GetWeakPtr()));
  if (pid == -1) {
    FailService(Service::kFailureInternal, "Failed to run `wg setconf`");
    return;
  }
}

void WireGuardDriver::OnConfigurationDone(int exit_code) {
  SLOG(this, 2) << __func__ << ": exit_code=" << exit_code;

  // Closes the config file to remove it.
  config_fd_.reset();

  if (exit_code != 0) {
    FailService(
        Service::kFailureInternal,
        base::StringPrintf("Failed to run `wg setconf`, code=%d", exit_code));
    return;
  }

  if (!PopulateIPProperties()) {
    FailService(Service::kFailureInternal, "Failed to populate ip properties");
    return;
  }

  ReportConnectionMetrics();

  event_handler_->OnDriverConnected(kDefaultInterfaceName, interface_index_);
}

bool WireGuardDriver::PopulateIPProperties() {
  ip_properties_.default_route = false;

  // When we arrive here, the value of AllowedIPs has already been validated
  // by wireguard-tools. AllowedIPs is comma-separated list of CIDR-notation
  // addresses (e.g., "10.8.0.1/16,192.168.1.1/24").
  for (auto& peer : peers_) {
    std::string allowed_ips_str = peer[kWireGuardPeerAllowedIPs];
    std::vector<std::string> allowed_ip_list = base::SplitString(
        allowed_ips_str, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    for (const auto& allowed_ip_str : allowed_ip_list) {
      IPAddress allowed_ip;
      // Currently only supports IPv4 addresses.
      allowed_ip.set_family(IPAddress::kFamilyIPv4);
      if (!allowed_ip.SetAddressAndPrefixFromString(allowed_ip_str)) {
        LOG(DFATAL) << "Invalid allowed ip: " << allowed_ip_str;
        return false;
      }
      // We don't need a gateway here, so use the "default" address as the
      // gateways, and then RoutingTable will skip RTA_GATEWAY when installing
      // this entry.
      ip_properties_.routes.push_back({allowed_ip.GetNetworkPart().ToString(),
                                       static_cast<int>(allowed_ip.prefix()),
                                       /*gateway=*/"0.0.0.0"});
    }
  }
  ip_properties_.method = kTypeVPN;
  return true;
}

void WireGuardDriver::FailService(Service::ConnectFailure failure,
                                  const std::string& error_details) {
  LOG(ERROR) << "Driver error: " << error_details;
  Cleanup();
  if (event_handler_) {
    event_handler_->OnDriverFailure(failure, error_details);
    event_handler_ = nullptr;
  }
}

void WireGuardDriver::Cleanup() {
  if (wireguard_pid_ != -1) {
    process_manager()->StopProcess(wireguard_pid_);
    wireguard_pid_ = -1;
  }
  if (kernel_interface_open_) {
    manager()->device_info()->DeleteInterface(interface_index_);
    kernel_interface_open_ = false;
  }
  interface_index_ = -1;
  ip_properties_ = {};
  config_fd_.reset();
}

bool WireGuardDriver::UpdatePeers(const Stringmaps& new_peers, Error* error) {
  if (!ValidatePeersForStorage(new_peers)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidProperty,
        "Invalid peers: missing PublicKey property or the value is not unique");
    return false;
  }

  // If the preshared key of a peer in the new peers is unspecified (the caller
  // doesn't set that key), try to reset it to the old value.
  Stringmap pubkey_to_psk;
  for (auto& peer : peers_) {
    pubkey_to_psk[peer[kWireGuardPeerPublicKey]] =
        peer[kWireGuardPeerPresharedKey];
  }

  peers_ = new_peers;
  for (auto& peer : peers_) {
    if (peer.find(kWireGuardPeerPresharedKey) != peer.end()) {
      continue;
    }
    peer[kWireGuardPeerPresharedKey] =
        pubkey_to_psk[peer[kWireGuardPeerPublicKey]];
  }

  return true;
}

void WireGuardDriver::ClearPeers(Error* error) {
  peers_.clear();
}

void WireGuardDriver::ReportConnectionMetrics() {
  // VPN type.
  metrics()->SendEnumToUMA(Metrics::kMetricVpnDriver,
                           Metrics::kVpnDriverWireGuard,
                           Metrics::kMetricVpnDriverMax);

  // Key pair source.
  metrics()->SendEnumToUMA(Metrics::kMetricVpnWireGuardKeyPairSource,
                           key_pair_source_,
                           Metrics::kMetricVpnWireGuardKeyPairSourceMax);

  // Number of peers.
  metrics()->SendToUMA(Metrics::kMetricVpnWireGuardPeersNum, peers_.size(),
                       Metrics::kMetricVpnWireGuardPeersNumMin,
                       Metrics::kMetricVpnWireGuardPeersNumMax,
                       Metrics::kMetricVpnWireGuardPeersNumNumBuckets);

  // Allowed IPs type.
  // TODO(b/194243702): Collect metrics for IPv6 usages in Allowed IPs.
  auto allowed_ips_type = Metrics::kVpnWireGuardAllowedIPsTypeNoDefaultRoute;
  for (auto peer : peers_) {
    if (peer[kWireGuardPeerAllowedIPs].find("0.0.0.0/0") != std::string::npos) {
      allowed_ips_type = Metrics::kVpnWireGuardAllowedIPsTypeHasDefaultRoute;
      break;
    }
  }
  metrics()->SendEnumToUMA(Metrics::kMetricVpnWireGuardAllowedIPsType,
                           allowed_ips_type,
                           Metrics::kMetricVpnWireGuardAllowedIPsTypeMax);
}

// static
bool WireGuardDriver::IsSupported() {
  // WireGuard is current supported on kernel version >= 5.10
  return VPNUtil::CheckKernelVersion(base::Version("5.10"));
}

}  // namespace shill
