// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/crostini_service.h"

#include <memory>
#include <utility>

//#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include "base/threading/thread_task_runner_handle.h"
#include <chromeos/constants/vm_tools.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>

#include "patchpanel/adb_proxy.h"
#include "patchpanel/guest_type.h"

namespace patchpanel {
namespace {
constexpr int32_t kInvalidID = 0;
constexpr int kDbusTimeoutMs = 200;
// The maximum number of ADB sideloading query failures before stopping.
constexpr int kAdbSideloadMaxTry = 5;
constexpr base::TimeDelta kAdbSideloadUpdateDelay = base::Milliseconds(5000);

std::string MakeKey(uint64_t vm_id, bool is_termina) {
  return base::StringPrintf("%s:%s", is_termina ? "t" : "p",
                            base::NumberToString(vm_id).c_str());
}
}  // namespace

CrostiniService::CrostiniService(
    AddressManager* addr_mgr,
    Datapath* datapath,
    Device::ChangeEventHandler device_changed_handler)
    : addr_mgr_(addr_mgr),
      datapath_(datapath),
      device_changed_handler_(device_changed_handler),
      adb_sideloading_enabled_(false) {
  DCHECK(addr_mgr_);
  DCHECK(datapath_);

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;

  bus_ = new dbus::Bus(options);
  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
  } else {
    CheckAdbSideloadingStatus();
  }
}

CrostiniService::~CrostiniService() {
  if (bus_)
    bus_->ShutdownAndBlock();
}

bool CrostiniService::Start(uint64_t vm_id, bool is_termina, int subnet_index) {
  if (vm_id == kInvalidID) {
    LOG(ERROR) << "Invalid VM id";
    return false;
  }

  const auto key = MakeKey(vm_id, is_termina);
  if (taps_.find(key) != taps_.end()) {
    LOG(WARNING) << "Already started for {id: " << vm_id << "}";
    return false;
  }

  auto tap = AddTAP(is_termina, subnet_index);
  if (!tap) {
    LOG(ERROR) << "Cannot start for {id: " << vm_id << "}";
    return false;
  }

  LOG(INFO) << "Crostini network service started for {id: " << vm_id << "}";
  auto source = is_termina ? TrafficSource::CROSVM : TrafficSource::PLUGINVM;
  datapath_->StartRoutingDevice("", tap->host_ifname(),
                                tap->config().host_ipv4_addr(), source,
                                true /*route_on_vpn*/);

  if (adb_sideloading_enabled_)
    StartAdbPortForwarding(tap->phys_ifname());

  device_changed_handler_.Run(
      *tap, Device::ChangeEvent::ADDED,
      is_termina ? GuestMessage::TERMINA_VM : GuestMessage::PLUGIN_VM);

  taps_.emplace(key, std::move(tap));
  return true;
}

void CrostiniService::Stop(uint64_t vm_id, bool is_termina) {
  const auto key = MakeKey(vm_id, is_termina);
  const auto it = taps_.find(key);
  if (it == taps_.end()) {
    LOG(WARNING) << "Unknown {id: " << vm_id << "}";
    return;
  }

  device_changed_handler_.Run(
      *it->second, Device::ChangeEvent::REMOVED,
      is_termina ? GuestMessage::TERMINA_VM : GuestMessage::PLUGIN_VM);

  const auto& ifname = it->second->host_ifname();
  auto source = is_termina ? TrafficSource::CROSVM : TrafficSource::PLUGINVM;
  datapath_->StopRoutingDevice("", ifname,
                               it->second->config().host_ipv4_addr(), source,
                               true /*route_on_vpn*/);
  if (adb_sideloading_enabled_)
    StopAdbPortForwarding(ifname);
  datapath_->RemoveInterface(ifname);
  taps_.erase(key);

  LOG(INFO) << "Crostini network service stopped for {id: " << vm_id << "}";
}

const Device* const CrostiniService::TAP(uint64_t vm_id,
                                         bool is_termina) const {
  const auto it = taps_.find(MakeKey(vm_id, is_termina));
  if (it == taps_.end()) {
    return nullptr;
  }
  return it->second.get();
}

std::vector<const Device*> CrostiniService::GetDevices() const {
  std::vector<const Device*> devices;
  for (const auto& [_, dev] : taps_) {
    devices.push_back(dev.get());
  }
  return devices;
}

std::unique_ptr<Device> CrostiniService::AddTAP(bool is_termina,
                                                int subnet_index) {
  auto guest_type = is_termina ? GuestType::VM_TERMINA : GuestType::VM_PLUGIN;
  auto ipv4_subnet = addr_mgr_->AllocateIPv4Subnet(guest_type, subnet_index);
  if (!ipv4_subnet) {
    LOG(ERROR) << "Subnet already in use or unavailable.";
    return nullptr;
  }
  auto host_ipv4_addr = ipv4_subnet->AllocateAtOffset(0);
  if (!host_ipv4_addr) {
    LOG(ERROR) << "Host address already in use or unavailable.";
    return nullptr;
  }
  auto guest_ipv4_addr = ipv4_subnet->AllocateAtOffset(1);
  if (!guest_ipv4_addr) {
    LOG(ERROR) << "VM address already in use or unavailable.";
    return nullptr;
  }
  std::unique_ptr<Subnet> lxd_subnet;
  if (is_termina) {
    lxd_subnet = addr_mgr_->AllocateIPv4Subnet(GuestType::LXD_CONTAINER);
    if (!lxd_subnet) {
      LOG(ERROR) << "lxd subnet already in use or unavailable.";
      return nullptr;
    }
  }

  const auto mac_addr = addr_mgr_->GenerateMacAddress(subnet_index);
  const std::string tap =
      datapath_->AddTAP("" /* auto-generate name */, &mac_addr,
                        host_ipv4_addr.get(), vm_tools::kCrosVmUser);
  if (tap.empty()) {
    LOG(ERROR) << "Failed to create TAP device.";
    return nullptr;
  }

  if (lxd_subnet) {
    // Setup lxd route for the container using the VM as a gateway.
    if (!datapath_->AddIPv4Route(ipv4_subnet->AddressAtOffset(1),
                                 lxd_subnet->AddressAtOffset(0),
                                 lxd_subnet->Netmask())) {
      LOG(ERROR) << "Failed to setup lxd route";
      return nullptr;
    }
  }

  auto config = std::make_unique<Device::Config>(
      mac_addr, std::move(ipv4_subnet), std::move(host_ipv4_addr),
      std::move(guest_ipv4_addr), std::move(lxd_subnet));

  return std::make_unique<Device>(guest_type, tap, tap, "", std::move(config));
}

void CrostiniService::StartAdbPortForwarding(const std::string& ifname) {
  if (!datapath_->AddAdbPortForwardRule(ifname)) {
    LOG(ERROR) << "Error adding ADB port forwarding rule for " << ifname;
    return;
  }

  if (!datapath_->AddAdbPortAccessRule(ifname)) {
    datapath_->DeleteAdbPortForwardRule(ifname);
    LOG(ERROR) << "Error adding ADB port access rule for " << ifname;
    return;
  }

  if (!datapath_->SetRouteLocalnet(ifname, true)) {
    LOG(ERROR) << "Failed to set up route localnet for " << ifname;
    return;
  }
}

void CrostiniService::StopAdbPortForwarding(const std::string& ifname) {
  datapath_->DeleteAdbPortForwardRule(ifname);
  datapath_->DeleteAdbPortAccessRule(ifname);
  datapath_->SetRouteLocalnet(ifname, false);
}

void CrostiniService::CheckAdbSideloadingStatus() {
  static int num_try = 0;
  if (num_try >= kAdbSideloadMaxTry) {
    LOG(WARNING) << "Failed to get ADB sideloading status after " << num_try
                 << " tries. ADB sideloading will not work";
    return;
  }

  dbus::ObjectProxy* proxy = bus_->GetObjectProxy(
      login_manager::kSessionManagerServiceName,
      dbus::ObjectPath(login_manager::kSessionManagerServicePath));
  dbus::MethodCall method_call(login_manager::kSessionManagerInterface,
                               login_manager::kSessionManagerQueryAdbSideload);
  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDbusTimeoutMs);

  if (!dbus_response) {
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&CrostiniService::CheckAdbSideloadingStatus,
                       weak_factory_.GetWeakPtr()),
        kAdbSideloadUpdateDelay);
    num_try++;
    return;
  }

  dbus::MessageReader reader(dbus_response.get());
  reader.PopBool(&adb_sideloading_enabled_);
  if (!adb_sideloading_enabled_)
    return;

  // If ADB sideloading is enabled, start ADB forwarding on all configured
  // Crostini's TAP interfaces.
  for (const auto& tap : taps_) {
    StartAdbPortForwarding(tap.second->phys_ifname());
  }
}

}  // namespace patchpanel
