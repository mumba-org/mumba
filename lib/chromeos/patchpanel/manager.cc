// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/manager.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <utility>

#include <base/bind.h>
//#include <base/check.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/threading/thread_task_runner_handle.h>
#include <brillo/key_value_store.h>
#include <brillo/minijail/minijail.h>
#include <metrics/metrics_library.h>

#include "patchpanel/guest_type.h"
#include "patchpanel/ipc.pb.h"
#include "patchpanel/mac_address_generator.h"
#include "patchpanel/metrics.h"
#include "patchpanel/net_util.h"
#include "patchpanel/routing_service.h"
#include "patchpanel/scoped_ns.h"
#include "patchpanel/system.h"

namespace patchpanel {
namespace {
constexpr int kSubprocessRestartDelayMs = 900;
// Delay to restart IPv6 in a namespace to trigger SLAAC in the kernel.
constexpr int kIPv6RestartDelayMs = 300;

// Passes |method_call| to |handler| and passes the response to
// |response_sender|. If |handler| returns nullptr, an empty response is
// created and sent.
void HandleSynchronousDBusMethodCall(
    base::RepeatingCallback<std::unique_ptr<dbus::Response>(dbus::MethodCall*)>
        handler,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  std::unique_ptr<dbus::Response> response = handler.Run(method_call);
  if (!response)
    response = dbus::Response::FromMethodCall(method_call);
  std::move(response_sender).Run(std::move(response));
}

bool IsIPv6NDProxyEnabled(ShillClient::Device::Type type) {
  static const std::set<ShillClient::Device::Type> ndproxy_allowed_types{
      ShillClient::Device::Type::kCellular,
      ShillClient::Device::Type::kEthernet,
      ShillClient::Device::Type::kEthernetEap,
      ShillClient::Device::Type::kWifi,
  };
  return ndproxy_allowed_types.find(type) != ndproxy_allowed_types.end();
}

void FillSubnetProto(const Subnet& virtual_subnet,
                     patchpanel::IPv4Subnet* output) {
  output->set_base_addr(virtual_subnet.BaseAddress());
  output->set_prefix_len(virtual_subnet.PrefixLength());
}

void FillDeviceProto(const Device& virtual_device,
                     patchpanel::NetworkDevice* output) {
  // TODO(hugobenichi) Consolidate guest_type in Device class and set
  // guest_type.
  output->set_ifname(virtual_device.host_ifname());
  output->set_phys_ifname(virtual_device.phys_ifname());
  output->set_guest_ifname(virtual_device.guest_ifname());
  output->set_ipv4_addr(virtual_device.config().guest_ipv4_addr());
  output->set_host_ipv4_addr(virtual_device.config().host_ipv4_addr());
}

void RecordDbusEvent(std::unique_ptr<MetricsLibraryInterface>& metrics,
                     DbusUmaEvent event) {
  metrics->SendEnumToUMA(kDbusUmaEventMetrics, event);
}

}  // namespace

Manager::Manager(std::unique_ptr<HelperProcess> adb_proxy,
                 std::unique_ptr<HelperProcess> mcast_proxy,
                 std::unique_ptr<HelperProcess> nd_proxy)
    : adb_proxy_(std::move(adb_proxy)),
      mcast_proxy_(std::move(mcast_proxy)),
      nd_proxy_(std::move(nd_proxy)) {
  system_ = std::make_unique<System>();
  datapath_ = std::make_unique<Datapath>(system_.get());
}

std::map<const std::string, bool> Manager::cached_feature_enabled_ = {};

bool Manager::ShouldEnableFeature(
    int min_android_sdk_version,
    int min_chrome_milestone,
    const std::vector<std::string>& supported_boards,
    const std::string& feature_name) {
  static const char kLsbReleasePath[] = "/etc/lsb-release";

  const auto& cached_result = cached_feature_enabled_.find(feature_name);
  if (cached_result != cached_feature_enabled_.end())
    return cached_result->second;

  auto check = [min_android_sdk_version, min_chrome_milestone,
                &supported_boards, &feature_name]() {
    brillo::KeyValueStore store;
    if (!store.Load(base::FilePath(kLsbReleasePath))) {
      LOG(ERROR) << "Could not read lsb-release";
      return false;
    }

    std::string value;
    if (!store.GetString("CHROMEOS_ARC_ANDROID_SDK_VERSION", &value)) {
      LOG(ERROR) << feature_name
                 << " disabled - cannot determine Android SDK version";
      return false;
    }
    int ver = 0;
    if (!base::StringToInt(value.c_str(), &ver)) {
      LOG(ERROR) << feature_name << " disabled - invalid Android SDK version";
      return false;
    }
    if (ver < min_android_sdk_version) {
      LOG(INFO) << feature_name << " disabled for Android SDK " << value;
      return false;
    }

    if (!store.GetString("CHROMEOS_RELEASE_CHROME_MILESTONE", &value)) {
      LOG(ERROR) << feature_name
                 << " disabled - cannot determine ChromeOS milestone";
      return false;
    }
    if (!base::StringToInt(value.c_str(), &ver)) {
      LOG(ERROR) << feature_name << " disabled - invalid ChromeOS milestone";
      return false;
    }
    if (ver < min_chrome_milestone) {
      LOG(INFO) << feature_name << " disabled for ChromeOS milestone " << value;
      return false;
    }

    if (!store.GetString("CHROMEOS_RELEASE_BOARD", &value)) {
      LOG(ERROR) << feature_name << " disabled - cannot determine board";
      return false;
    }
    if (!supported_boards.empty() &&
        std::find(supported_boards.begin(), supported_boards.end(), value) ==
            supported_boards.end()) {
      LOG(INFO) << feature_name << " disabled for board " << value;
      return false;
    }
    return true;
  };

  bool result = check();
  cached_feature_enabled_.emplace(feature_name, result);
  return result;
}

int Manager::OnInit() {
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

  // Handle subprocess lifecycle.
  process_reaper_.Register(this);

  CHECK(process_reaper_.WatchForChild(
      FROM_HERE, adb_proxy_->pid(),
      base::BindOnce(&Manager::OnSubprocessExited, weak_factory_.GetWeakPtr(),
                     adb_proxy_->pid())))
      << "Failed to watch adb-proxy child process";
  CHECK(process_reaper_.WatchForChild(
      FROM_HERE, mcast_proxy_->pid(),
      base::BindOnce(&Manager::OnSubprocessExited, weak_factory_.GetWeakPtr(),
                     nd_proxy_->pid())))
      << "Failed to watch multicast-proxy child process";
  CHECK(process_reaper_.WatchForChild(
      FROM_HERE, nd_proxy_->pid(),
      base::BindOnce(&Manager::OnSubprocessExited, weak_factory_.GetWeakPtr(),
                     nd_proxy_->pid())))
      << "Failed to watch nd-proxy child process";

  // Run after Daemon::OnInit().
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(&Manager::InitialSetup, weak_factory_.GetWeakPtr()));

  return DBusDaemon::OnInit();
}

void Manager::InitialSetup() {
  LOG(INFO) << "Setting up DBus service interface";
  dbus_svc_path_ = bus_->GetExportedObject(
      dbus::ObjectPath(patchpanel::kPatchPanelServicePath));
  if (!dbus_svc_path_) {
    LOG(FATAL) << "Failed to export " << patchpanel::kPatchPanelServicePath
               << " object";
  }

  metrics_ = std::make_unique<MetricsLibrary>();
  shill_client_ = std::make_unique<ShillClient>(bus_, system_.get());

  using ServiceMethod =
      std::unique_ptr<dbus::Response> (Manager::*)(dbus::MethodCall*);
  const std::map<const char*, ServiceMethod> kServiceMethods = {
      {patchpanel::kArcStartupMethod, &Manager::OnArcStartup},
      {patchpanel::kArcShutdownMethod, &Manager::OnArcShutdown},
      {patchpanel::kArcVmStartupMethod, &Manager::OnArcVmStartup},
      {patchpanel::kArcVmShutdownMethod, &Manager::OnArcVmShutdown},
      {patchpanel::kTerminaVmStartupMethod, &Manager::OnTerminaVmStartup},
      {patchpanel::kTerminaVmShutdownMethod, &Manager::OnTerminaVmShutdown},
      {patchpanel::kPluginVmStartupMethod, &Manager::OnPluginVmStartup},
      {patchpanel::kPluginVmShutdownMethod, &Manager::OnPluginVmShutdown},
      {patchpanel::kSetVpnIntentMethod, &Manager::OnSetVpnIntent},
      {patchpanel::kConnectNamespaceMethod, &Manager::OnConnectNamespace},
      {patchpanel::kGetTrafficCountersMethod, &Manager::OnGetTrafficCounters},
      {patchpanel::kModifyPortRuleMethod, &Manager::OnModifyPortRule},
      {patchpanel::kGetDevicesMethod, &Manager::OnGetDevices},
      {patchpanel::kSetVpnLockdown, &Manager::OnSetVpnLockdown},
      {patchpanel::kSetDnsRedirectionRuleMethod,
       &Manager::OnSetDnsRedirectionRule},
  };

  for (const auto& kv : kServiceMethods) {
    if (!dbus_svc_path_->ExportMethodAndBlock(
            patchpanel::kPatchPanelInterface, kv.first,
            base::BindRepeating(
                &HandleSynchronousDBusMethodCall,
                base::BindRepeating(kv.second, base::Unretained(this))))) {
      LOG(FATAL) << "Failed to export method " << kv.first;
    }
  }

  if (!bus_->RequestOwnershipAndBlock(patchpanel::kPatchPanelServiceName,
                                      dbus::Bus::REQUIRE_PRIMARY)) {
    LOG(FATAL) << "Failed to take ownership of "
               << patchpanel::kPatchPanelServiceName;
  }
  LOG(INFO) << "DBus service interface ready";

  routing_svc_ = std::make_unique<RoutingService>();
  counters_svc_ = std::make_unique<CountersService>(datapath_.get());

  datapath_->Start();

  shill_client_->RegisterDefaultLogicalDeviceChangedHandler(
      base::BindRepeating(&Manager::OnShillDefaultLogicalDeviceChanged,
                          weak_factory_.GetWeakPtr()));
  shill_client_->RegisterDefaultPhysicalDeviceChangedHandler(
      base::BindRepeating(&Manager::OnShillDefaultPhysicalDeviceChanged,
                          weak_factory_.GetWeakPtr()));
  shill_client_->RegisterDevicesChangedHandler(base::BindRepeating(
      &Manager::OnShillDevicesChanged, weak_factory_.GetWeakPtr()));
  shill_client_->RegisterIPConfigsChangedHandler(base::BindRepeating(
      &Manager::OnIPConfigsChanged, weak_factory_.GetWeakPtr()));
  shill_client_->RegisterIPv6NetworkChangedHandler(base::BindRepeating(
      &Manager::OnIPv6NetworkChanged, weak_factory_.GetWeakPtr()));

  nd_proxy_->RegisterNDProxyMessageHandler(base::BindRepeating(
      &Manager::OnNDProxyMessage, weak_factory_.GetWeakPtr()));

  GuestMessage::GuestType arc_guest =
      USE_ARCVM ? GuestMessage::ARC_VM : GuestMessage::ARC;
  arc_svc_ = std::make_unique<ArcService>(
      datapath_.get(), &addr_mgr_, arc_guest, metrics_.get(),
      base::BindRepeating(&Manager::OnGuestDeviceChanged,
                          weak_factory_.GetWeakPtr()));
  cros_svc_ = std::make_unique<CrostiniService>(
      &addr_mgr_, datapath_.get(),
      base::BindRepeating(&Manager::OnGuestDeviceChanged,
                          weak_factory_.GetWeakPtr()));
  network_monitor_svc_ = std::make_unique<NetworkMonitorService>(
      shill_client_.get(),
      base::BindRepeating(&Manager::OnNeighborReachabilityEvent,
                          weak_factory_.GetWeakPtr()));
  network_monitor_svc_->Start();
  nd_proxy_->Listen();
}

void Manager::OnShutdown(int* exit_code) {
  LOG(INFO) << "Shutting down and cleaning up";
  network_monitor_svc_.reset();
  cros_svc_.reset();
  arc_svc_.reset();
  // Tear down any remaining active lifeline file descriptors.
  std::vector<int> lifeline_fds;
  for (const auto& kv : connected_namespaces_) {
    lifeline_fds.push_back(kv.first);
  }
  for (const auto& kv : dns_redirection_rules_) {
    lifeline_fds.push_back(kv.first);
  }
  for (const int fdkey : lifeline_fds) {
    OnLifelineFdClosed(fdkey);
  }
  datapath_->Stop();
  if (bus_) {
    bus_->ShutdownAndBlock();
  }
  brillo::DBusDaemon::OnShutdown(exit_code);
}

void Manager::OnSubprocessExited(pid_t pid, const siginfo_t&) {
  LOG(ERROR) << "Subprocess " << pid << " exited unexpectedly -"
             << " attempting to restart";

  HelperProcess* proc;
  if (pid == adb_proxy_->pid()) {
    proc = adb_proxy_.get();
  } else if (pid == mcast_proxy_->pid()) {
    proc = mcast_proxy_.get();
  } else if (pid == nd_proxy_->pid()) {
    proc = nd_proxy_.get();
  } else {
    LOG(DFATAL) << "Unknown child process";
    return;
  }

  process_reaper_.ForgetChild(pid);

  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Manager::RestartSubprocess, weak_factory_.GetWeakPtr(),
                     proc),
      base::Milliseconds((2 << proc->restarts()) * kSubprocessRestartDelayMs));
}

void Manager::RestartSubprocess(HelperProcess* subproc) {
  if (subproc->Restart()) {
    DCHECK(process_reaper_.WatchForChild(
        FROM_HERE, subproc->pid(),
        base::BindOnce(&Manager::OnSubprocessExited, weak_factory_.GetWeakPtr(),
                       subproc->pid())))
        << "Failed to watch child process " << subproc->pid();
  }
}

void Manager::OnShillDefaultLogicalDeviceChanged(
    const ShillClient::Device& new_device,
    const ShillClient::Device& prev_device) {
  // Only take into account interface switches and ignore layer 3 property
  // changes.
  if (prev_device.ifname == new_device.ifname)
    return;

  if (prev_device.type == ShillClient::Device::Type::kVPN) {
    datapath_->StopVpnRouting(prev_device.ifname);
    counters_svc_->OnVpnDeviceRemoved(prev_device.ifname);
  }

  if (new_device.type == ShillClient::Device::Type::kVPN) {
    datapath_->StartVpnRouting(new_device.ifname);
    counters_svc_->OnVpnDeviceAdded(new_device.ifname);
  }

  // When the default logical network changes, Crostini's tap devices must leave
  // their current forwarding group for multicast and IPv6 ndproxy and join the
  // forwarding group of the new logical default network.
  for (const auto* tap_device : cros_svc_->GetDevices()) {
    StopForwarding(prev_device.ifname, tap_device->host_ifname());
    StartForwarding(new_device.ifname, tap_device->host_ifname());
  }

  // When the default logical network changes, ConnectedNamespaces' devices
  // which follow the logical network must leave their current forwarding group
  // for IPv6 ndproxy and join the forwarding group of the new logical default
  // network. This is marked by empty |outbound_ifname| and |route_on_vpn|
  // with the value of true.
  for (auto& [_, nsinfo] : connected_namespaces_) {
    if (!nsinfo.outbound_ifname.empty() || !nsinfo.route_on_vpn) {
      continue;
    }
    StopForwarding(prev_device.ifname, nsinfo.host_ifname,
                   ForwardingSet{.ipv6 = true});
    nsinfo.tracked_outbound_ifname = new_device.ifname;
    StartForwarding(new_device.ifname, nsinfo.host_ifname,
                    ForwardingSet{.ipv6 = true});

    // Disable and re-enable IPv6. This is necessary to trigger SLAAC in the
    // kernel to send RS. Add a delay for the forwarding to be set up.
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Manager::RestartIPv6, weak_factory_.GetWeakPtr(),
                       nsinfo.netns_name),
        base::Milliseconds(kIPv6RestartDelayMs));
  }
}

void Manager::OnShillDefaultPhysicalDeviceChanged(
    const ShillClient::Device& new_device,
    const ShillClient::Device& prev_device) {
  // Only take into account interface switches and ignore layer 3 property
  // changes.
  if (prev_device.ifname == new_device.ifname)
    return;

  // When the default physical network changes, ConnectedNamespaces' devices
  // which follow the physical network must leave their current forwarding group
  // for IPv6 ndproxy and join the forwarding group of the new physical default
  // network. This is marked by empty |outbound_ifname| and |route_on_vpn|
  // with the value of false.
  for (auto& [_, nsinfo] : connected_namespaces_) {
    if (!nsinfo.outbound_ifname.empty() || nsinfo.route_on_vpn) {
      continue;
    }
    StopForwarding(prev_device.ifname, nsinfo.host_ifname,
                   ForwardingSet{.ipv6 = true});
    nsinfo.tracked_outbound_ifname = new_device.ifname;
    StartForwarding(new_device.ifname, nsinfo.host_ifname,
                    ForwardingSet{.ipv6 = true});

    // Disable and re-enable IPv6. This is necessary to trigger SLAAC in the
    // kernel to send RS. Add a delay for the forwarding to be set up.
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Manager::RestartIPv6, weak_factory_.GetWeakPtr(),
                       nsinfo.netns_name),
        base::Milliseconds(kIPv6RestartDelayMs));
  }
}

void Manager::RestartIPv6(const std::string& netns_name) {
  auto ns = ScopedNS::EnterNetworkNS(netns_name);
  if (!ns) {
    LOG(ERROR) << "Invalid namespace name " << netns_name;
    return;
  }

  if (datapath_) {
    datapath_->RestartIPv6();
  }
}

void Manager::OnShillDevicesChanged(const std::vector<std::string>& added,
                                    const std::vector<std::string>& removed) {
  for (const std::string& ifname : removed) {
    for (auto& [_, nsinfo] : connected_namespaces_) {
      if (nsinfo.outbound_ifname != ifname) {
        continue;
      }
      StopForwarding(nsinfo.outbound_ifname, nsinfo.host_ifname,
                     ForwardingSet{.ipv6 = true});
    }
    StopForwarding(ifname, "" /* ifname_virtual */);
    datapath_->StopConnectionPinning(ifname);
    datapath_->RemoveRedirectDnsRule(ifname);
    counters_svc_->OnPhysicalDeviceRemoved(ifname);
    arc_svc_->RemoveDevice(ifname);
  }

  for (const std::string& ifname : added) {
    for (auto& [_, nsinfo] : connected_namespaces_) {
      if (nsinfo.outbound_ifname != ifname) {
        continue;
      }
      StartForwarding(nsinfo.outbound_ifname, nsinfo.host_ifname,
                      ForwardingSet{.ipv6 = true});
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
          FROM_HERE,
          base::BindOnce(&Manager::RestartIPv6, weak_factory_.GetWeakPtr(),
                         nsinfo.netns_name),
          base::Milliseconds(kIPv6RestartDelayMs));
    }
    datapath_->StartConnectionPinning(ifname);
    ShillClient::Device shill_device;
    if (!shill_client_->GetDeviceProperties(ifname, &shill_device))
      continue;

    if (!shill_device.ipconfig.ipv4_dns_addresses.empty())
      datapath_->AddRedirectDnsRule(
          ifname, shill_device.ipconfig.ipv4_dns_addresses.front());

    counters_svc_->OnPhysicalDeviceAdded(ifname);
    arc_svc_->AddDevice(ifname, shill_device.type);
  }
}

void Manager::OnIPConfigsChanged(const std::string& ifname,
                                 const ShillClient::IPConfig& ipconfig) {
  if (ipconfig.ipv4_dns_addresses.empty()) {
    datapath_->RemoveRedirectDnsRule(ifname);
  } else {
    datapath_->AddRedirectDnsRule(ifname, ipconfig.ipv4_dns_addresses.front());
  }
}

void Manager::OnIPv6NetworkChanged(const std::string& ifname,
                                   const std::string& ipv6_address) {
  if (ipv6_address.empty())
    return;

  for (auto& [_, nsinfo] : connected_namespaces_) {
    if (nsinfo.outbound_ifname != ifname) {
      continue;
    }

    // Disable and re-enable IPv6 inside the namespace. This is necessary to
    // trigger SLAAC in the kernel to send RS.
    RestartIPv6(nsinfo.netns_name);
  }
}

void Manager::OnGuestDeviceChanged(const Device& virtual_device,
                                   Device::ChangeEvent event,
                                   GuestMessage::GuestType guest_type) {
  dbus::Signal signal(kPatchPanelInterface, kNetworkDeviceChangedSignal);
  NetworkDeviceChangedSignal proto;
  proto.set_event(event == Device::ChangeEvent::ADDED
                      ? NetworkDeviceChangedSignal::DEVICE_ADDED
                      : NetworkDeviceChangedSignal::DEVICE_REMOVED);
  auto* dev = proto.mutable_device();
  FillDeviceProto(virtual_device, dev);
  if (const auto* subnet = virtual_device.config().ipv4_subnet()) {
    FillSubnetProto(*subnet, dev->mutable_ipv4_subnet());
  }
  switch (guest_type) {
    case GuestMessage::ARC:
      dev->set_guest_type(NetworkDevice::ARC);
      break;
    case GuestMessage::ARC_VM:
      dev->set_guest_type(NetworkDevice::ARCVM);
      break;
    case GuestMessage::TERMINA_VM:
      dev->set_guest_type(NetworkDevice::TERMINA_VM);
      break;
    case GuestMessage::PLUGIN_VM:
      dev->set_guest_type(NetworkDevice::PLUGIN_VM);
      break;
    default:
      dev->set_guest_type(NetworkDevice::UNKNOWN);
      LOG(ERROR) << "Unknown patchpanel Device type";
      return;
  }

  if (dev->guest_type() != NetworkDevice::UNKNOWN) {
    const std::string& upstream_device =
        (guest_type == GuestMessage::ARC || guest_type == GuestMessage::ARC_VM)
            ? virtual_device.phys_ifname()
            : shill_client_->default_logical_interface();

    if (event == Device::ChangeEvent::ADDED) {
      StartForwarding(upstream_device, virtual_device.host_ifname());
    } else if (event == Device::ChangeEvent::REMOVED) {
      StopForwarding(upstream_device, virtual_device.host_ifname());
    }
  }

  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  dbus_svc_path_->SendSignal(&signal);
}

bool Manager::StartArc(pid_t pid) {
  if (!arc_svc_->Start(pid))
    return false;

  GuestMessage msg;
  msg.set_event(GuestMessage::START);
  msg.set_type(GuestMessage::ARC);
  msg.set_arc_pid(pid);
  SendGuestMessage(msg);

  return true;
}

void Manager::StopArc() {
  GuestMessage msg;
  msg.set_event(GuestMessage::STOP);
  msg.set_type(GuestMessage::ARC);
  SendGuestMessage(msg);

  // After the ARC container has stopped, the pid is not known anymore.
  // The pid argument is ignored by ArcService.
  arc_svc_->Stop(0);
}

bool Manager::StartArcVm(uint32_t cid) {
  if (!arc_svc_->Start(cid))
    return false;

  GuestMessage msg;
  msg.set_event(GuestMessage::START);
  msg.set_type(GuestMessage::ARC_VM);
  msg.set_arcvm_vsock_cid(cid);
  SendGuestMessage(msg);

  return true;
}

void Manager::StopArcVm(uint32_t cid) {
  GuestMessage msg;
  msg.set_event(GuestMessage::STOP);
  msg.set_type(GuestMessage::ARC_VM);
  msg.set_arcvm_vsock_cid(cid);
  SendGuestMessage(msg);

  arc_svc_->Stop(cid);
}

bool Manager::StartCrosVm(uint64_t vm_id,
                          GuestMessage::GuestType vm_type,
                          uint32_t subnet_index) {
  DCHECK(vm_type == GuestMessage::TERMINA_VM ||
         vm_type == GuestMessage::PLUGIN_VM);

  if (!cros_svc_->Start(vm_id, vm_type == GuestMessage::TERMINA_VM,
                        subnet_index))
    return false;

  GuestMessage msg;
  msg.set_event(GuestMessage::START);
  msg.set_type(vm_type);
  SendGuestMessage(msg);

  return true;
}

void Manager::StopCrosVm(uint64_t vm_id, GuestMessage::GuestType vm_type) {
  GuestMessage msg;
  msg.set_event(GuestMessage::STOP);
  msg.set_type(vm_type);
  SendGuestMessage(msg);

  cros_svc_->Stop(vm_id, vm_type == GuestMessage::TERMINA_VM);
}

std::unique_ptr<dbus::Response> Manager::OnGetDevices(
    dbus::MethodCall* method_call) {
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::GetDevicesRequest request;
  patchpanel::GetDevicesResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse request";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  static const auto arc_guest_type =
      USE_ARCVM ? NetworkDevice::ARCVM : NetworkDevice::ARC;
  for (const auto* arc_device : arc_svc_->GetDevices()) {
    auto* dev = response.add_devices();
    FillDeviceProto(*arc_device, dev);
    dev->set_guest_type(arc_guest_type);
    if (const auto* subnet = arc_device->config().ipv4_subnet()) {
      FillSubnetProto(*subnet, dev->mutable_ipv4_subnet());
    }
  }

  for (const auto* crosvm_device : cros_svc_->GetDevices()) {
    auto* dev = response.add_devices();
    FillDeviceProto(*crosvm_device, dev);
    switch (crosvm_device->type()) {
      case GuestType::VM_TERMINA:
        dev->set_guest_type(NetworkDevice::TERMINA_VM);
        break;
      case GuestType::VM_PLUGIN:
        dev->set_guest_type(NetworkDevice::PLUGIN_VM);
        break;
      default:
        LOG(ERROR)
            << "Unexpected patchpanel Device type for CrostiniService Device: "
            << crosvm_device->type();
        continue;
    }
    if (const auto* subnet = crosvm_device->config().ipv4_subnet()) {
      FillSubnetProto(*subnet, dev->mutable_ipv4_subnet());
    }
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnArcStartup(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "ARC++ starting up";
  RecordDbusEvent(metrics_, DbusUmaEvent::kArcStartup);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::ArcStartupRequest request;
  patchpanel::ArcStartupResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse request";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (!StartArc(request.pid()))
    LOG(ERROR) << "Failed to start ARC++ network service";

  RecordDbusEvent(metrics_, DbusUmaEvent::kArcStartupSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnArcShutdown(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "ARC++ shutting down";
  RecordDbusEvent(metrics_, DbusUmaEvent::kArcShutdown);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::ArcShutdownRequest request;
  patchpanel::ArcShutdownResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse request";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  StopArc();

  RecordDbusEvent(metrics_, DbusUmaEvent::kArcShutdownSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnArcVmStartup(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "ARCVM starting up";
  RecordDbusEvent(metrics_, DbusUmaEvent::kArcVmStartup);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::ArcVmStartupRequest request;
  patchpanel::ArcVmStartupResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse request";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (!StartArcVm(request.cid())) {
    LOG(ERROR) << "Failed to start ARCVM network service";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Populate the response with the interface configurations of the known ARC
  // Devices
  for (const auto* config : arc_svc_->GetDeviceConfigs()) {
    if (config->tap_ifname().empty())
      continue;

    // TODO(hugobenichi) Use FillDeviceProto.
    auto* dev = response.add_devices();
    dev->set_ifname(config->tap_ifname());
    dev->set_ipv4_addr(config->guest_ipv4_addr());
    dev->set_guest_type(NetworkDevice::ARCVM);
  }

  RecordDbusEvent(metrics_, DbusUmaEvent::kArcVmStartupSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnArcVmShutdown(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "ARCVM shutting down";
  RecordDbusEvent(metrics_, DbusUmaEvent::kArcVmShutdown);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::ArcVmShutdownRequest request;
  patchpanel::ArcVmShutdownResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse request";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  StopArcVm(request.cid());

  RecordDbusEvent(metrics_, DbusUmaEvent::kArcVmShutdownSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnTerminaVmStartup(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Termina VM starting up";
  RecordDbusEvent(metrics_, DbusUmaEvent::kTerminaVmStartup);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::TerminaVmStartupRequest request;
  patchpanel::TerminaVmStartupResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse request";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  const int32_t cid = request.cid();
  if (!StartCrosVm(cid, GuestMessage::TERMINA_VM)) {
    LOG(ERROR) << "Failed to start Termina VM network service";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  const auto* const tap = cros_svc_->TAP(cid, true /*is_termina*/);
  if (!tap) {
    LOG(DFATAL) << "Termina TAP Device missing";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  const auto* termina_subnet = tap->config().ipv4_subnet();
  if (!termina_subnet) {
    LOG(DFATAL) << "Missing required Termina IPv4 subnet for {cid: " << cid
                << "}";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  const auto* lxd_subnet = tap->config().lxd_ipv4_subnet();
  if (!lxd_subnet) {
    LOG(DFATAL) << "Missing required lxd container IPv4 subnet for {cid: "
                << cid << "}";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  auto* dev = response.mutable_device();
  dev->set_guest_type(NetworkDevice::TERMINA_VM);
  FillDeviceProto(*tap, dev);
  FillSubnetProto(*termina_subnet, dev->mutable_ipv4_subnet());
  FillSubnetProto(*lxd_subnet, response.mutable_container_subnet());

  RecordDbusEvent(metrics_, DbusUmaEvent::kTerminaVmStartupSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnTerminaVmShutdown(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Termina VM shutting down";
  RecordDbusEvent(metrics_, DbusUmaEvent::kTerminaVmShutdown);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::TerminaVmShutdownRequest request;
  patchpanel::TerminaVmShutdownResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse request";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  StopCrosVm(request.cid(), GuestMessage::TERMINA_VM);

  RecordDbusEvent(metrics_, DbusUmaEvent::kTerminaVmShutdownSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnPluginVmStartup(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Plugin VM starting up";
  RecordDbusEvent(metrics_, DbusUmaEvent::kPluginVmStartup);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::PluginVmStartupRequest request;
  patchpanel::PluginVmStartupResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse request";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  const uint64_t vm_id = request.id();
  if (!StartCrosVm(vm_id, GuestMessage::PLUGIN_VM, request.subnet_index())) {
    LOG(ERROR) << "Failed to start Plugin VM network service";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  const auto* const tap = cros_svc_->TAP(vm_id, false /*is_termina*/);
  if (!tap) {
    LOG(DFATAL) << "Plugin VM TAP Device missing";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  const auto* subnet = tap->config().ipv4_subnet();
  if (!subnet) {
    LOG(DFATAL) << "Missing required subnet for {cid: " << vm_id << "}";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  auto* dev = response.mutable_device();
  dev->set_guest_type(NetworkDevice::PLUGIN_VM);
  FillDeviceProto(*tap, dev);
  FillSubnetProto(*subnet, dev->mutable_ipv4_subnet());

  RecordDbusEvent(metrics_, DbusUmaEvent::kPluginVmStartupSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnPluginVmShutdown(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Plugin VM shutting down";
  RecordDbusEvent(metrics_, DbusUmaEvent::kPluginVmShutdown);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::PluginVmShutdownRequest request;
  patchpanel::PluginVmShutdownResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse request";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  StopCrosVm(request.id(), GuestMessage::PLUGIN_VM);

  RecordDbusEvent(metrics_, DbusUmaEvent::kPluginVmShutdownSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnSetVpnIntent(
    dbus::MethodCall* method_call) {
  RecordDbusEvent(metrics_, DbusUmaEvent::kSetVpnIntent);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::SetVpnIntentRequest request;
  patchpanel::SetVpnIntentResponse response;

  bool success = reader.PopArrayOfBytesAsProto(&request);
  if (!success) {
    LOG(ERROR) << "Unable to parse SetVpnIntentRequest";
    // Do not return yet to make sure we close the received fd.
  }

  base::ScopedFD client_socket;
  reader.PopFileDescriptor(&client_socket);

  if (success)
    success = routing_svc_->SetVpnFwmark(client_socket.get(), request.policy());

  response.set_success(success);

  RecordDbusEvent(metrics_, DbusUmaEvent::kSetVpnIntentSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnConnectNamespace(
    dbus::MethodCall* method_call) {
  RecordDbusEvent(metrics_, DbusUmaEvent::kConnectNamespace);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::ConnectNamespaceRequest request;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ConnectNamespaceRequest";
    // Do not return yet to make sure we close the received fd and
    // validate other arguments.
    writer.AppendProtoAsArrayOfBytes(patchpanel::ConnectNamespaceResponse());
    return dbus_response;
  }

  base::ScopedFD client_fd;
  reader.PopFileDescriptor(&client_fd);
  if (!client_fd.is_valid()) {
    LOG(ERROR) << "Invalid file descriptor";
    writer.AppendProtoAsArrayOfBytes(patchpanel::ConnectNamespaceResponse());
    return dbus_response;
  }

  pid_t pid = request.pid();
  if (pid == 1 || pid == getpid()) {
    LOG(ERROR) << "Privileged namespace pid " << pid;
    writer.AppendProtoAsArrayOfBytes(patchpanel::ConnectNamespaceResponse());
    return dbus_response;
  }
  if (pid != ConnectedNamespace::kNewNetnsPid) {
    auto ns = ScopedNS::EnterNetworkNS(pid);
    if (!ns) {
      LOG(ERROR) << "Invalid namespace pid " << pid;
      writer.AppendProtoAsArrayOfBytes(patchpanel::ConnectNamespaceResponse());
      return dbus_response;
    }
  }

  const std::string& outbound_ifname = request.outbound_physical_device();
  if (!outbound_ifname.empty() &&
      !shill_client_->has_interface(outbound_ifname)) {
    LOG(ERROR) << "Invalid outbound ifname " << outbound_ifname;
    writer.AppendProtoAsArrayOfBytes(patchpanel::ConnectNamespaceResponse());
    return dbus_response;
  }

  const auto response = ConnectNamespace(std::move(client_fd), request);
  if (!response->netns_name().empty()) {
    RecordDbusEvent(metrics_, DbusUmaEvent::kConnectNamespaceSuccess);
  }

  writer.AppendProtoAsArrayOfBytes(*response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnGetTrafficCounters(
    dbus::MethodCall* method_call) {
  RecordDbusEvent(metrics_, DbusUmaEvent::kGetTrafficCounters);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::TrafficCountersRequest request;
  patchpanel::TrafficCountersResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse TrafficCountersRequest";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  const std::set<std::string> shill_devices{request.devices().begin(),
                                            request.devices().end()};
  const auto counters = counters_svc_->GetCounters(shill_devices);
  for (const auto& kv : counters) {
    auto* traffic_counter = response.add_counters();
    const auto& key = kv.first;
    const auto& counter = kv.second;
    traffic_counter->set_source(key.source);
    traffic_counter->set_device(key.ifname);
    traffic_counter->set_ip_family(key.ip_family);
    traffic_counter->set_rx_bytes(counter.rx_bytes);
    traffic_counter->set_rx_packets(counter.rx_packets);
    traffic_counter->set_tx_bytes(counter.tx_bytes);
    traffic_counter->set_tx_packets(counter.tx_packets);
  }

  RecordDbusEvent(metrics_, DbusUmaEvent::kGetTrafficCountersSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnModifyPortRule(
    dbus::MethodCall* method_call) {
  RecordDbusEvent(metrics_, DbusUmaEvent::kModifyPortRule);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::ModifyPortRuleRequest request;
  patchpanel::ModifyPortRuleResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ModifyPortRequest";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  bool success = datapath_->ModifyPortRule(request);
  response.set_success(success);
  if (success) {
    RecordDbusEvent(metrics_, DbusUmaEvent::kModifyPortRuleSuccess);
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnSetVpnLockdown(
    dbus::MethodCall* method_call) {
  RecordDbusEvent(metrics_, DbusUmaEvent::kSetVpnLockdown);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::SetVpnLockdownRequest request;
  patchpanel::SetVpnLockdownResponse response;

  if (reader.PopArrayOfBytesAsProto(&request)) {
    datapath_->SetVpnLockdown(request.enable_vpn_lockdown());
  } else {
    LOG(ERROR) << "Unable to parse SetVpnLockdownRequest";
  }

  RecordDbusEvent(metrics_, DbusUmaEvent::kSetVpnLockdownSuccess);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Manager::OnSetDnsRedirectionRule(
    dbus::MethodCall* method_call) {
  RecordDbusEvent(metrics_, DbusUmaEvent::kSetDnsRedirectionRule);

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  patchpanel::SetDnsRedirectionRuleRequest request;
  patchpanel::SetDnsRedirectionRuleResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse SetDnsRedirectionRuleRequest";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  base::ScopedFD client_fd;
  reader.PopFileDescriptor(&client_fd);
  if (!client_fd.is_valid()) {
    LOG(ERROR) << "Invalid file descriptor";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  bool success = RedirectDns(std::move(client_fd), request);
  response.set_success(success);
  if (success) {
    RecordDbusEvent(metrics_, DbusUmaEvent::kSetDnsRedirectionRuleSuccess);
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

void Manager::OnNeighborReachabilityEvent(
    int ifindex,
    const shill::IPAddress& ip_addr,
    NeighborLinkMonitor::NeighborRole role,
    NeighborReachabilityEventSignal::EventType event_type) {
  if (!ip_addr.IsValid()) {
    LOG(DFATAL) << "ip_addr is not valid";
    return;
  }

  using SignalProto = NeighborReachabilityEventSignal;
  SignalProto proto;
  proto.set_ifindex(ifindex);
  proto.set_ip_addr(ip_addr.ToString());
  proto.set_type(event_type);
  switch (role) {
    case NeighborLinkMonitor::NeighborRole::kGateway:
      proto.set_role(SignalProto::GATEWAY);
      break;
    case NeighborLinkMonitor::NeighborRole::kDNSServer:
      proto.set_role(SignalProto::DNS_SERVER);
      break;
    case NeighborLinkMonitor::NeighborRole::kGatewayAndDNSServer:
      proto.set_role(SignalProto::GATEWAY_AND_DNS_SERVER);
      break;
    default:
      NOTREACHED();
  }

  dbus::Signal signal(kPatchPanelInterface, kNeighborReachabilityEventSignal);
  dbus::MessageWriter writer(&signal);
  if (!writer.AppendProtoAsArrayOfBytes(proto)) {
    LOG(ERROR) << "Failed to encode proto NeighborReachabilityEventSignal";
    return;
  }

  dbus_svc_path_->SendSignal(&signal);
}

std::unique_ptr<patchpanel::ConnectNamespaceResponse> Manager::ConnectNamespace(
    base::ScopedFD client_fd,
    const patchpanel::ConnectNamespaceRequest& request) {
  auto response = std::make_unique<patchpanel::ConnectNamespaceResponse>();

  std::unique_ptr<Subnet> subnet =
      addr_mgr_.AllocateIPv4Subnet(GuestType::MINIJAIL_NETNS);
  if (!subnet) {
    LOG(ERROR) << "Exhausted IPv4 subnet space";
    return response;
  }

  // Dup the client fd into our own: this guarantees that the fd number will
  // be stable and tied to the actual kernel resources used by the client.
  // The duped fd will be watched for read events.
  base::ScopedFD local_client_fd(AddLifelineFd(client_fd.get()));
  if (!local_client_fd.is_valid()) {
    LOG(ERROR) << "Failed to create lifeline fd";
    return response;
  }

  const std::string ifname_id = std::to_string(connected_namespaces_next_id_);
  ConnectedNamespace nsinfo = {};
  nsinfo.pid = request.pid();
  nsinfo.netns_name = "connected_netns_" + ifname_id;
  nsinfo.source = ProtoToTrafficSource(request.traffic_source());
  if (nsinfo.source == TrafficSource::UNKNOWN)
    nsinfo.source = TrafficSource::SYSTEM;
  nsinfo.outbound_ifname = request.outbound_physical_device();
  nsinfo.route_on_vpn = request.route_on_vpn();
  nsinfo.host_ifname = "arc_ns" + ifname_id;
  nsinfo.peer_ifname = "veth" + ifname_id;
  nsinfo.peer_subnet = std::move(subnet);
  nsinfo.host_mac_addr = addr_mgr_.GenerateMacAddress();
  nsinfo.peer_mac_addr = addr_mgr_.GenerateMacAddress();
  if (nsinfo.host_mac_addr == nsinfo.peer_mac_addr) {
    LOG(ERROR) << "Failed to generate unique MAC address for connected "
                  "namespace host and peer interface";
  }

  if (!datapath_->StartRoutingNamespace(nsinfo)) {
    LOG(ERROR) << "Failed to setup datapath";
    if (!DeleteLifelineFd(local_client_fd.release()))
      LOG(ERROR) << "Failed to delete lifeline fd";
    return response;
  }

  // Prepare the response before storing ConnectedNamespace.
  response->set_peer_ifname(nsinfo.peer_ifname);
  response->set_peer_ipv4_address(nsinfo.peer_subnet->AddressAtOffset(1));
  response->set_host_ifname(nsinfo.host_ifname);
  response->set_host_ipv4_address(nsinfo.peer_subnet->AddressAtOffset(0));
  response->set_netns_name(nsinfo.netns_name);
  auto* response_subnet = response->mutable_ipv4_subnet();
  response_subnet->set_base_addr(nsinfo.peer_subnet->BaseAddress());
  response_subnet->set_prefix_len(nsinfo.peer_subnet->PrefixLength());

  LOG(INFO) << "Connected network namespace " << nsinfo;

  // Get the ConnectedNamespace outbound interface name.
  nsinfo.tracked_outbound_ifname = nsinfo.outbound_ifname;
  if (nsinfo.outbound_ifname.empty()) {
    if (nsinfo.route_on_vpn) {
      nsinfo.tracked_outbound_ifname =
          shill_client_->default_logical_interface();
    } else {
      nsinfo.tracked_outbound_ifname =
          shill_client_->default_physical_interface();
    }
  }
  // Start forwarding for IPv6.
  StartForwarding(nsinfo.tracked_outbound_ifname, nsinfo.host_ifname,
                  ForwardingSet{.ipv6 = true});
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Manager::RestartIPv6, weak_factory_.GetWeakPtr(),
                     nsinfo.netns_name),
      base::Milliseconds(kIPv6RestartDelayMs));

  // Store ConnectedNamespace
  connected_namespaces_next_id_++;
  int fdkey = local_client_fd.release();
  connected_namespaces_.emplace(fdkey, std::move(nsinfo));

  return response;
}

int Manager::AddLifelineFd(int dbus_fd) {
  int fd = dup(dbus_fd);
  if (fd < 0) {
    PLOG(ERROR) << "dup failed";
    return -1;
  }

  lifeline_fd_controllers_[fd] = base::FileDescriptorWatcher::WatchReadable(
      fd, base::BindRepeating(&Manager::OnLifelineFdClosed,
                              // The callback will not outlive the object.
                              base::Unretained(this), fd));

  return fd;
}

bool Manager::DeleteLifelineFd(int dbus_fd) {
  auto iter = lifeline_fd_controllers_.find(dbus_fd);
  if (iter == lifeline_fd_controllers_.end()) {
    return false;
  }

  iter->second.reset();  // Destruct the controller, which removes the callback.
  lifeline_fd_controllers_.erase(iter);

  // AddLifelineFd() calls dup(), so this function should close the fd.
  // We still return true since at this point the FileDescriptorWatcher object
  // has been destructed.
  if (IGNORE_EINTR(close(dbus_fd)) < 0) {
    PLOG(ERROR) << "close";
  }

  return true;
}

void Manager::OnLifelineFdClosed(int client_fd) {
  // The process that requested this port has died/exited.
  DeleteLifelineFd(client_fd);

  // Remove the rules tied to the lifeline fd.
  auto connected_namespace_it = connected_namespaces_.find(client_fd);
  if (connected_namespace_it != connected_namespaces_.end()) {
    StopForwarding(connected_namespace_it->second.tracked_outbound_ifname,
                   connected_namespace_it->second.host_ifname,
                   ForwardingSet{.ipv6 = true});
    datapath_->StopRoutingNamespace(connected_namespace_it->second);
    LOG(INFO) << "Disconnected network namespace "
              << connected_namespace_it->second;
    // This release the allocated IPv4 subnet.
    connected_namespaces_.erase(connected_namespace_it);
    return;
  }
  auto dns_redirection_it = dns_redirection_rules_.find(client_fd);
  if (dns_redirection_it != dns_redirection_rules_.end()) {
    datapath_->StopDnsRedirection(dns_redirection_it->second);
    LOG(INFO) << "Stopped DNS redirection " << dns_redirection_it->second;
    dns_redirection_rules_.erase(dns_redirection_it);
    return;
  }
  LOG(ERROR) << "No client_fd found for " << client_fd;
}

bool Manager::RedirectDns(
    base::ScopedFD client_fd,
    const patchpanel::SetDnsRedirectionRuleRequest& request) {
  // Dup the client fd into our own: this guarantees that the fd number will
  // be stable and tied to the actual kernel resources used by the client.
  // The duped fd will be watched for read events.
  base::ScopedFD local_client_fd(AddLifelineFd(client_fd.get()));
  if (!local_client_fd.is_valid()) {
    LOG(ERROR) << "Failed to create lifeline fd";
    return false;
  }

  DnsRedirectionRule rule{.type = request.type(),
                          .input_ifname = request.input_ifname(),
                          .proxy_address = request.proxy_address()};

  for (const auto& nameserver : request.nameservers()) {
    rule.nameservers.emplace_back(nameserver);
  }

  if (!datapath_->StartDnsRedirection(rule)) {
    LOG(ERROR) << "Failed to setup datapath";
    if (!DeleteLifelineFd(local_client_fd.release()))
      LOG(ERROR) << "Failed to delete lifeline fd";
    return false;
  }

  // Store DNS proxy's redirection request.
  int fdkey = local_client_fd.release();
  dns_redirection_rules_.emplace(fdkey, std::move(rule));

  return true;
}

void Manager::SendGuestMessage(const GuestMessage& msg) {
  IpHelperMessage ipm;
  *ipm.mutable_guest_message() = msg;
  adb_proxy_->SendMessage(ipm);
  mcast_proxy_->SendMessage(ipm);
  nd_proxy_->SendMessage(ipm);
}

void Manager::StartForwarding(const std::string& ifname_physical,
                              const std::string& ifname_virtual,
                              const ForwardingSet& fs) {
  if (ifname_physical.empty() || ifname_virtual.empty())
    return;

  IpHelperMessage ipm;
  DeviceMessage* msg = ipm.mutable_device_message();
  msg->set_dev_ifname(ifname_physical);
  msg->set_br_ifname(ifname_virtual);

  ShillClient::Device upstream_shill_device;
  shill_client_->GetDeviceProperties(ifname_physical, &upstream_shill_device);

  // b/187462665, b/187918638: If the physical interface is a cellular
  // modem, the network connection is expected to work as a point to point
  // link where neighbor discovery of the remote gateway is not possible.
  // Therefore force guests are told to see the host as their next hop.
  if (upstream_shill_device.type == ShillClient::Device::Type::kCellular) {
    msg->set_force_local_next_hop(true);
  }

  if (fs.ipv6 && IsIPv6NDProxyEnabled(upstream_shill_device.type)) {
    ndproxy_ifnames_[ifname_physical].insert(ifname_virtual);
    LOG(INFO) << "Starting IPv6 forwarding from " << ifname_physical << " to "
              << ifname_virtual;

    if (!datapath_->MaskInterfaceFlags(ifname_physical, IFF_ALLMULTI)) {
      LOG(WARNING) << "Failed to setup all multicast mode for interface "
                   << ifname_physical;
    }
    if (!datapath_->MaskInterfaceFlags(ifname_virtual, IFF_ALLMULTI)) {
      LOG(WARNING) << "Failed to setup all multicast mode for interface "
                   << ifname_virtual;
    }
    nd_proxy_->SendMessage(ipm);
  }

  if (fs.multicast && IsMulticastInterface(ifname_physical)) {
    multicast_ifnames_[ifname_physical].insert(ifname_virtual);
    LOG(INFO) << "Starting multicast forwarding from " << ifname_physical
              << " to " << ifname_virtual;
    mcast_proxy_->SendMessage(ipm);
  }
}

void Manager::StopForwarding(const std::string& ifname_physical,
                             const std::string& ifname_virtual,
                             const ForwardingSet& fs) {
  if (ifname_physical.empty())
    return;

  IpHelperMessage ipm;
  DeviceMessage* msg = ipm.mutable_device_message();
  msg->set_dev_ifname(ifname_physical);
  msg->set_teardown(true);
  if (!ifname_virtual.empty()) {
    msg->set_br_ifname(ifname_virtual);
  }

  if (fs.ipv6) {
    if (ifname_virtual.empty()) {
      ndproxy_ifnames_.erase(ifname_physical);
      LOG(INFO) << "Stopping IPv6 forwarding on " << ifname_physical;
    } else {
      auto ndproxy_it = ndproxy_ifnames_.find(ifname_physical);
      if (ndproxy_it != ndproxy_ifnames_.end()) {
        ndproxy_it->second.erase(ifname_virtual);
        LOG(INFO) << "Stopping IPv6 forwarding from " << ifname_physical
                  << " to " << ifname_virtual;
      }
    }
    nd_proxy_->SendMessage(ipm);
  }

  if (fs.multicast) {
    if (ifname_virtual.empty()) {
      multicast_ifnames_.erase(ifname_physical);
      LOG(INFO) << "Stopping multicast forwarding on " << ifname_physical;
    } else {
      auto multicast_it = multicast_ifnames_.find(ifname_physical);
      if (multicast_it != multicast_ifnames_.end()) {
        multicast_it->second.erase(ifname_virtual);
        LOG(INFO) << "Stopping multicast forwarding from " << ifname_physical
                  << " to " << ifname_virtual;
      }
    }
    mcast_proxy_->SendMessage(ipm);
  }
}

void Manager::OnNDProxyMessage(const NDProxyMessage& msg) {
  LOG_IF(DFATAL, msg.ifname().empty())
      << "Received DeviceMessage w/ empty dev_ifname";
  switch (msg.type()) {
    case NDProxyMessage::ADD_ROUTE:
      if (!datapath_->AddIPv6HostRoute(msg.ifname(), msg.ip6addr(), 128)) {
        LOG(WARNING) << "Failed to setup the IPv6 route for interface "
                     << msg.ifname() << ", addr " << msg.ip6addr();
      }
      break;
    case NDProxyMessage::ADD_ADDR:
      if (!datapath_->AddIPv6Address(msg.ifname(), msg.ip6addr())) {
        LOG(WARNING) << "Failed to setup the IPv6 address for interface "
                     << msg.ifname() << ", addr " << msg.ip6addr();
      }
      break;
    case NDProxyMessage::DEL_ADDR:
      datapath_->RemoveIPv6Address(msg.ifname(), msg.ip6addr());
      break;
    default:
      LOG(ERROR) << "Unknown NDProxy event " << msg.type();
      NOTREACHED();
  }
}

}  // namespace patchpanel
