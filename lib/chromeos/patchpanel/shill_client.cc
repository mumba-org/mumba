// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/shill_client.h"

#include <base/bind.h>
//#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/variant_dictionary.h>
#include <chromeos/dbus/service_constants.h>

#include "patchpanel/net_util.h"

namespace patchpanel {

namespace {

ShillClient::Device::Type ParseDeviceType(const std::string& type_str) {
  static const std::map<std::string, ShillClient::Device::Type> str2enum{
      {shill::kTypeCellular, ShillClient::Device::Type::kCellular},
      {shill::kTypeEthernet, ShillClient::Device::Type::kEthernet},
      {shill::kTypeEthernetEap, ShillClient::Device::Type::kEthernetEap},
      {shill::kTypeGuestInterface, ShillClient::Device::Type::kGuestInterface},
      {shill::kTypeLoopback, ShillClient::Device::Type::kLoopback},
      {shill::kTypePPP, ShillClient::Device::Type::kPPP},
      {shill::kTypeTunnel, ShillClient::Device::Type::kTunnel},
      {shill::kTypeWifi, ShillClient::Device::Type::kWifi},
      {shill::kTypeVPN, ShillClient::Device::Type::kVPN},
  };

  const auto it = str2enum.find(type_str);
  return it != str2enum.end() ? it->second
                              : ShillClient::Device::Type::kUnknown;
}

const std::string DeviceTypeName(ShillClient::Device::Type type) {
  static const std::map<ShillClient::Device::Type, std::string> enum2str{
      {ShillClient::Device::Type::kUnknown, "Unknown"},
      {ShillClient::Device::Type::kCellular, "Cellular"},
      {ShillClient::Device::Type::kEthernet, "Ethernet"},
      {ShillClient::Device::Type::kEthernetEap, "EthernetEap"},
      {ShillClient::Device::Type::kGuestInterface, "GuestInterface"},
      {ShillClient::Device::Type::kLoopback, "Loopback"},
      {ShillClient::Device::Type::kPPP, "PPP"},
      {ShillClient::Device::Type::kTunnel, "Tunnel"},
      {ShillClient::Device::Type::kVPN, "VPN"},
      {ShillClient::Device::Type::kWifi, "Wifi"},
  };

  const auto it = enum2str.find(type);
  return it != enum2str.end() ? it->second : "Unknown";
}

}  // namespace

ShillClient::ShillClient(const scoped_refptr<dbus::Bus>& bus, System* system)
    : bus_(bus), system_(system) {
  manager_proxy_.reset(new org::chromium::flimflam::ManagerProxy(bus_));
  manager_proxy_->RegisterPropertyChangedSignalHandler(
      base::BindRepeating(&ShillClient::OnManagerPropertyChange,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&ShillClient::OnManagerPropertyChangeRegistration,
                     weak_factory_.GetWeakPtr()));
}

const std::string& ShillClient::default_logical_interface() const {
  return default_logical_device_.ifname;
}

const std::string& ShillClient::default_physical_interface() const {
  return default_physical_device_.ifname;
}

const ShillClient::Device& ShillClient::default_logical_device() const {
  return default_logical_device_;
}

const ShillClient::Device& ShillClient::default_physical_device() const {
  return default_physical_device_;
}

const std::vector<std::string> ShillClient::get_interfaces() const {
  std::vector<std::string> ifnames;
  for (const auto& [_, ifname] : devices_) {
    ifnames.push_back(ifname);
  }
  return ifnames;
}

bool ShillClient::has_interface(const std::string& ifname) const {
  for (const auto& kv : devices_) {
    if (kv.second == ifname) {
      return true;
    }
  }
  return false;
}

void ShillClient::ScanDevices() {
  brillo::VariantDictionary props;
  if (!manager_proxy_->GetProperties(&props, nullptr)) {
    LOG(ERROR) << "Unable to get Manager properties";
    return;
  }
  const auto it = props.find(shill::kDevicesProperty);
  if (it == props.end()) {
    LOG(WARNING) << "Manager properties is missing " << shill::kDevicesProperty;
    return;
  }
  UpdateDevices(it->second);
}

std::pair<ShillClient::Device, ShillClient::Device>
ShillClient::GetDefaultDevices() {
  brillo::VariantDictionary properties;
  if (!manager_proxy_->GetProperties(&properties, nullptr)) {
    LOG(ERROR) << "Unable to get manager properties";
    return {};
  }
  auto services =
      brillo::GetVariantValueOrDefault<std::vector<dbus::ObjectPath>>(
          properties, shill::kServicesProperty);

  Device default_logical_device = {};
  Device default_physical_device = {};
  for (const auto& service_path : services) {
    properties = GetServiceProperties(service_path);

    auto device_path = brillo::GetVariantValueOrDefault<dbus::ObjectPath>(
        properties, shill::kDeviceProperty);
    if (!device_path.IsValid()) {
      LOG(WARNING) << "Failed to obtain device for service ["
                   << service_path.value() << "]";
      return {};
    }

    auto it = properties.find(shill::kIsConnectedProperty);
    if (it == properties.end()) {
      LOG(ERROR) << "Service " << service_path.value() << " missing property "
                 << shill::kIsConnectedProperty;
      return {};
    }

    if (!it->second.TryGet<bool>()) {
      LOG(INFO) << "Ignoring non-connected Service " << service_path.value();
      return {};
    }

    std::string service_type = brillo::GetVariantValueOrDefault<std::string>(
        properties, shill::kTypeProperty);
    if (service_type.empty()) {
      LOG(ERROR) << "Service " << service_path.value() << " missing property "
                 << shill::kTypeProperty;
      return {};
    }

    auto device = GetDevice(service_path, device_path, service_type);
    if (device.type == ShillClient::Device::Type::kVPN) {
      default_logical_device = device;
    } else {
      default_physical_device = device;
      if (default_logical_device.type == ShillClient::Device::Type::kUnknown) {
        default_logical_device = device;
      }
      break;
    }
  }
  return std::make_pair(default_logical_device, default_physical_device);
}

void ShillClient::OnManagerPropertyChangeRegistration(
    const std::string& interface,
    const std::string& signal_name,
    bool success) {
  if (!success)
    LOG(FATAL) << "Unable to register for interface change events";
}

void ShillClient::OnManagerPropertyChange(const std::string& property_name,
                                          const brillo::Any& property_value) {
  if (property_name == shill::kDevicesProperty) {
    UpdateDevices(property_value);
  } else if (property_name != shill::kDefaultServiceProperty &&
             property_name != shill::kServicesProperty &&
             property_name != shill::kConnectionStateProperty) {
    return;
  }

  // All registered DefaultDeviceChangeHandler objects should be called if
  // the default network has changed or if shill::kDevicesProperty has changed.
  SetDefaultDevices(GetDefaultDevices());
}

void ShillClient::SetDefaultDevices(const std::pair<Device, Device>& devices) {
  auto default_logical_device = devices.first;
  auto default_physical_device = devices.second;
  if (default_logical_device_.ifname != default_logical_device.ifname) {
    LOG(INFO) << "Default network changed from " << default_logical_device_
              << " to " << default_logical_device;

    for (const auto& h : default_logical_device_handlers_) {
      if (!h.is_null())
        h.Run(default_logical_device, default_logical_device_);
    }
    default_logical_device_ = default_logical_device;
  }

  if (default_physical_device_.ifname != default_physical_device.ifname) {
    LOG(INFO) << "Default physical device changed from "
              << default_physical_device_ << " to " << default_physical_device;

    for (const auto& h : default_physical_device_handlers_) {
      if (!h.is_null())
        h.Run(default_physical_device, default_physical_device_);
    }
    default_physical_device_ = default_physical_device;
  }
}

brillo::VariantDictionary ShillClient::GetServiceProperties(
    const dbus::ObjectPath& service_path) {
  brillo::ErrorPtr error;
  brillo::VariantDictionary properties;
  org::chromium::flimflam::ServiceProxy service_proxy(bus_, service_path);
  if (!service_proxy.GetProperties(&properties, &error)) {
    LOG(ERROR) << "Failed to obtain service [" << service_path.value()
               << "] properties: " << error->GetMessage();
  }
  return properties;
}

brillo::VariantDictionary ShillClient::GetDeviceProperties(
    const dbus::ObjectPath& device_path) {
  brillo::VariantDictionary properties;
  org::chromium::flimflam::DeviceProxy device_proxy(bus_, device_path);
  if (!device_proxy.GetProperties(&properties, nullptr)) {
    LOG(ERROR) << "Can't retrieve properties for device";
  }
  return properties;
}

ShillClient::Device ShillClient::GetDevice(const dbus::ObjectPath& service_path,
                                           const dbus::ObjectPath& device_path,
                                           const std::string& service_type) {
  Device device = {};

  auto properties = GetDeviceProperties(device_path);
  device.ifname = brillo::GetVariantValueOrDefault<std::string>(
      properties, shill::kInterfaceProperty);
  if (device.ifname.empty()) {
    LOG(ERROR) << "Empty interface name for shill Device "
               << device_path.value();
    return {};
  }

  device.ifindex = system_->IfNametoindex(device.ifname);
  device.type = ParseDeviceType(service_type);
  device.service_path = service_path.value();
  return device;
}

void ShillClient::RegisterDefaultLogicalDeviceChangedHandler(
    const DefaultDeviceChangeHandler& handler) {
  default_logical_device_handlers_.emplace_back(handler);
  // Explicitly trigger the callback once to let it know of the the current
  // default interface. The previous interface is left empty.
  handler.Run(default_logical_device_, {});
}

void ShillClient::RegisterDefaultPhysicalDeviceChangedHandler(
    const DefaultDeviceChangeHandler& handler) {
  default_physical_device_handlers_.emplace_back(handler);
  // Explicitly trigger the callback once to let it know of the the current
  // default interface. The previous interface is left empty.
  handler.Run(default_physical_device_, {});
}

void ShillClient::RegisterDevicesChangedHandler(
    const DevicesChangeHandler& handler) {
  device_handlers_.emplace_back(handler);
}

void ShillClient::RegisterIPConfigsChangedHandler(
    const IPConfigsChangeHandler& handler) {
  ipconfigs_handlers_.emplace_back(handler);
}

void ShillClient::RegisterIPv6NetworkChangedHandler(
    const IPv6NetworkChangeHandler& handler) {
  ipv6_network_handlers_.emplace_back(handler);
}

void ShillClient::UpdateDevices(const brillo::Any& property_value) {
  std::map<std::string, std::string> new_devices;
  std::vector<std::string> added, removed;
  for (const auto& path :
       property_value.TryGet<std::vector<dbus::ObjectPath>>()) {
    std::string device = path.value();
    // Strip "/device/" prefix.
    device = device.substr(device.find_last_of('/') + 1);
    const std::string ifname = GetIfname(path);
    if (ifname.empty()) {
      LOG(WARNING) << "Found empty interface name for Device " << device;
      continue;
    }

    new_devices[device] = ifname;
    if (devices_.find(device) == devices_.end()) {
      added.push_back(ifname);
    }

    // Registers handler if we see this device for the first time.
    if (known_device_paths_.insert(std::make_pair(device, path)).second) {
      org::chromium::flimflam::DeviceProxy proxy(bus_, path);
      proxy.RegisterPropertyChangedSignalHandler(
          base::BindRepeating(&ShillClient::OnDevicePropertyChange,
                              weak_factory_.GetWeakPtr(), device),
          base::BindOnce(&ShillClient::OnDevicePropertyChangeRegistration,
                         weak_factory_.GetWeakPtr()));
      known_device_paths_[device] = path;
    }
  }

  for (const auto& [d, ifname] : devices_) {
    if (new_devices.find(d) == new_devices.end()) {
      removed.push_back(ifname);
      // Clear cached IPConfig for removed device.
      device_ipconfigs_.erase(d);
    }
  }

  devices_ = new_devices;

  // This can happen if the default network switched from one device to another.
  if (added.empty() && removed.empty())
    return;

  LOG(INFO) << "shill Devices changed: added={" << base::JoinString(added, ",")
            << "}, removed={" << base::JoinString(removed, ",") << "}";

  for (const auto& h : device_handlers_)
    h.Run(added, removed);
}

ShillClient::IPConfig ShillClient::ParseIPConfigsProperty(
    const std::string& device, const brillo::Any& property_value) {
  IPConfig ipconfig;
  for (const auto& path :
       property_value.TryGet<std::vector<dbus::ObjectPath>>()) {
    std::unique_ptr<org::chromium::flimflam::IPConfigProxy> ipconfig_proxy(
        new org::chromium::flimflam::IPConfigProxy(bus_, path));
    brillo::VariantDictionary ipconfig_props;

    if (!ipconfig_proxy->GetProperties(&ipconfig_props, nullptr)) {
      // It is possible that an IPConfig object is removed after we know its
      // path, especially when the interface is going down.
      LOG(WARNING) << "[" << device << "]: "
                   << "Unable to get properties for " << path.value();
      continue;
    }

    // Detects the type of IPConfig. For ipv4 and ipv6 configurations, there
    // should be at most one for each type.
    auto it = ipconfig_props.find(shill::kMethodProperty);
    if (it == ipconfig_props.end()) {
      LOG(WARNING) << "[" << device << "]: "
                   << "IPConfig properties is missing Method";
      continue;
    }
    const std::string& method = it->second.TryGet<std::string>();
    const bool is_ipv4_type =
        (method == shill::kTypeIPv4 || method == shill::kTypeDHCP ||
         method == shill::kTypeBOOTP || method == shill::kTypeZeroConf);
    const bool is_ipv6_type = (method == shill::kTypeIPv6);
    if (!is_ipv4_type && !is_ipv6_type) {
      LOG(WARNING) << "[" << device << "]: "
                   << "unknown type \"" << method << "\" for " << path.value();
      continue;
    }
    if ((is_ipv4_type && !ipconfig.ipv4_address.empty()) ||
        (is_ipv6_type && !ipconfig.ipv6_address.empty())) {
      LOG(WARNING) << "[" << device << "]: "
                   << "Duplicated ipconfig for " << method;
      continue;
    }

    // Gets the value of address, prefix_length, gateway, and dns_servers.
    it = ipconfig_props.find(shill::kAddressProperty);
    if (it == ipconfig_props.end()) {
      LOG(WARNING) << "[" << device << "]: "
                   << "IPConfig properties is missing Address";
      continue;
    }
    const std::string& address = it->second.TryGet<std::string>();

    it = ipconfig_props.find(shill::kPrefixlenProperty);
    if (it == ipconfig_props.end()) {
      LOG(WARNING) << "[" << device << "]: "
                   << "IPConfig properties is missing Prefixlen";
      continue;
    }
    int prefix_length = it->second.TryGet<int>();

    it = ipconfig_props.find(shill::kGatewayProperty);
    if (it == ipconfig_props.end()) {
      LOG(WARNING) << "[" << device << "]: "
                   << "IPConfig properties is missing Gateway";
      continue;
    }
    const std::string& gateway = it->second.TryGet<std::string>();

    it = ipconfig_props.find(shill::kNameServersProperty);
    if (it == ipconfig_props.end()) {
      LOG(WARNING) << "[" << device << "]: "
                   << "IPConfig properties is missing NameServers";
      // Shill will emit this property with empty value if it has no dns for
      // this device, so missing this property indicates an error.
      continue;
    }
    const std::vector<std::string>& dns_addresses =
        it->second.TryGet<std::vector<std::string>>();

    // Checks if this ipconfig is valid: address, gateway, and prefix_length
    // should not be empty.
    if (address.empty() || gateway.empty() || prefix_length == 0) {
      LOG(WARNING) << "[" << device << "]: "
                   << "Skipped invalid ipconfig: "
                   << "address.length()=" << address.length()
                   << ", gateway.length()=" << gateway.length()
                   << ", prefix_length=" << prefix_length;
      continue;
    }

    // Fills the IPConfig struct according to the type.
    if (is_ipv4_type) {
      ipconfig.ipv4_prefix_length = prefix_length;
      ipconfig.ipv4_address = address;
      ipconfig.ipv4_gateway = gateway;
      ipconfig.ipv4_dns_addresses = dns_addresses;
    } else {  // is_ipv6_type
      ipconfig.ipv6_prefix_length = prefix_length;
      ipconfig.ipv6_address = address;
      ipconfig.ipv6_gateway = gateway;
      ipconfig.ipv6_dns_addresses = dns_addresses;
    }
  }

  return ipconfig;
}

bool ShillClient::GetDeviceProperties(const std::string& ifname,
                                      Device* output) {
  DCHECK(output);

  std::string device = "";
  for (const auto& kv : devices_) {
    if (kv.second == ifname) {
      device = kv.first;
      break;
    }
  }
  if (device.empty()) {
    LOG(ERROR) << "Unknown interface name " << ifname;
    return false;
  }

  const auto& device_it = known_device_paths_.find(device);
  if (device_it == known_device_paths_.end()) {
    LOG(ERROR) << "Unknown shill Device " << device;
    return false;
  }

  org::chromium::flimflam::DeviceProxy proxy(bus_, device_it->second);
  brillo::VariantDictionary props;
  if (!proxy.GetProperties(&props, nullptr)) {
    LOG(WARNING) << "Unable to get shill Device properties for " << device;
    return false;
  }

  const auto& type_it = props.find(shill::kTypeProperty);
  if (type_it == props.end()) {
    LOG(WARNING) << "shill Device properties is missing Type for " << device;
    return false;
  }
  const std::string& type_str = type_it->second.TryGet<std::string>();
  output->type = ParseDeviceType(type_str);
  if (output->type == Device::Type::kUnknown)
    LOG(WARNING) << "Unknown shill Device type " << type_str << " for "
                 << device;

  const auto& interface_it = props.find(shill::kInterfaceProperty);
  if (interface_it == props.end()) {
    LOG(WARNING) << "shill Device properties is missing Interface for "
                 << device;
    return false;
  }
  output->ifname = interface_it->second.TryGet<std::string>();

  const auto& ipconfigs_it = props.find(shill::kIPConfigsProperty);
  if (ipconfigs_it == props.end()) {
    LOG(WARNING) << "shill Device properties is missing IPConfigs for "
                 << device;
    return false;
  }
  output->ipconfig = ParseIPConfigsProperty(device, ipconfigs_it->second);

  return true;
}

std::string ShillClient::GetIfname(const dbus::ObjectPath& device_path) {
  org::chromium::flimflam::DeviceProxy device_proxy(bus_, device_path);
  brillo::VariantDictionary props;
  if (!device_proxy.GetProperties(&props, nullptr)) {
    LOG(WARNING) << "Unable to get Device properties for "
                 << device_path.value();
    return "";
  }

  const auto& interface_it = props.find(shill::kInterfaceProperty);
  if (interface_it == props.end()) {
    LOG(WARNING) << "shill Device properties is missing Interface for "
                 << device_path.value();
    return "";
  }

  return interface_it->second.TryGet<std::string>();
}

void ShillClient::OnDevicePropertyChangeRegistration(
    const std::string& interface,
    const std::string& signal_name,
    bool success) {
  if (!success)
    LOG(ERROR) << "[" << interface << "]: "
               << "Unable to register listener for " << signal_name;
}

void ShillClient::OnDevicePropertyChange(const std::string& device,
                                         const std::string& property_name,
                                         const brillo::Any& property_value) {
  if (property_name != shill::kIPConfigsProperty)
    return;

  const auto& it = devices_.find(device);
  if (it == devices_.end()) {
    LOG(WARNING) << "Failed to obtain interface name for shill Device "
                 << device;
    return;
  }
  const IPConfig& ipconfig = ParseIPConfigsProperty(device, property_value);
  const auto& old_ipconfig_it = device_ipconfigs_.find(device);
  if (old_ipconfig_it != device_ipconfigs_.end() &&
      old_ipconfig_it->second == ipconfig) {
    // There is no IPConfig change, no need to run the handlers.
    return;
  }
  auto old_ipconfig = old_ipconfig_it != device_ipconfigs_.end()
                          ? old_ipconfig_it->second
                          : IPConfig{};
  device_ipconfigs_[device] = ipconfig;

  for (const auto& handler : ipconfigs_handlers_)
    handler.Run(it->second, ipconfig);

  // Compares if the new IPv6 network is the same as the old one by checking
  // its prefix.
  if (old_ipconfig.ipv6_prefix_length == ipconfig.ipv6_prefix_length &&
      IsIPv6PrefixEqual(StringToIPv6Address(old_ipconfig.ipv6_address),
                        StringToIPv6Address(ipconfig.ipv6_address),
                        ipconfig.ipv6_prefix_length)) {
    return;
  }
  for (const auto& handler : ipv6_network_handlers_)
    handler.Run(it->second, ipconfig.ipv6_address);
}

std::ostream& operator<<(std::ostream& stream, const ShillClient::Device& dev) {
  return stream << "{ifname: " << dev.ifname << ", ifindex: " << dev.ifindex
                << ", type: " << DeviceTypeName(dev.type)
                << ", service: " << dev.service_path << "}";
}

std::ostream& operator<<(std::ostream& stream,
                         const ShillClient::Device::Type type) {
  return stream << DeviceTypeName(type);
}

}  // namespace patchpanel
