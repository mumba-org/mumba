// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_MANAGER_H_
#define PATCHPANEL_MANAGER_H_

#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/process/process_reaper.h>
#include <chromeos/dbus/service_constants.h>
#include <metrics/metrics_library.h>
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "patchpanel/address_manager.h"
#include "patchpanel/arc_service.h"
#include "patchpanel/counters_service.h"
#include "patchpanel/crostini_service.h"
#include "patchpanel/datapath.h"
#include "patchpanel/helper_process.h"
#include "patchpanel/network_monitor_service.h"
#include "patchpanel/routing_service.h"
#include "patchpanel/shill_client.h"
#include "patchpanel/socket.h"
#include "patchpanel/subnet.h"
#include "patchpanel/system.h"

namespace patchpanel {

// Struct to specify which forwarders to start and stop.
struct ForwardingSet {
  bool ipv6;
  bool multicast;
};

// Main class that runs the mainloop and responds to LAN interface changes.
class Manager final : public brillo::DBusDaemon {
 public:
  Manager(std::unique_ptr<HelperProcess> adb_proxy,
          std::unique_ptr<HelperProcess> mcast_proxy,
          std::unique_ptr<HelperProcess> nd_proxy);
  Manager(const Manager&) = delete;
  Manager& operator=(const Manager&) = delete;

  ~Manager() = default;

  void StartForwarding(const std::string& ifname_physical,
                       const std::string& ifname_virtual,
                       const ForwardingSet& fs = {.ipv6 = true,
                                                  .multicast = true});

  void StopForwarding(const std::string& ifname_physical,
                      const std::string& ifname_virtual,
                      const ForwardingSet& fs = {.ipv6 = true,
                                                 .multicast = true});

  // This function is used to enable specific features only on selected
  // combination of Android version, Chrome version, and boards.
  // Empty |supportedBoards| means that the feature should be enabled on all
  // board.
  static bool ShouldEnableFeature(
      int min_android_sdk_version,
      int min_chrome_milestone,
      const std::vector<std::string>& supported_boards,
      const std::string& feature_name);

 protected:
  int OnInit() override;

 private:
  void OnShillDefaultLogicalDeviceChanged(
      const ShillClient::Device& new_device,
      const ShillClient::Device& prev_device);
  void OnShillDefaultPhysicalDeviceChanged(
      const ShillClient::Device& new_device,
      const ShillClient::Device& prev_device);
  void OnShillDevicesChanged(const std::vector<std::string>& added,
                             const std::vector<std::string>& removed);
  void OnIPConfigsChanged(const std::string& ifname,
                          const ShillClient::IPConfig& ipconfig);
  void OnIPv6NetworkChanged(const std::string& ifname,
                            const std::string& ipv6_address);

  void OnGuestDeviceChanged(const Device& virtual_device,
                            Device::ChangeEvent event,
                            GuestMessage::GuestType guest_type);

  void InitialSetup();

  bool StartArc(pid_t pid);
  void StopArc();
  bool StartArcVm(uint32_t cid);
  void StopArcVm(uint32_t cid);
  bool StartCrosVm(uint64_t vm_id,
                   GuestMessage::GuestType vm_type,
                   uint32_t subnet_index = kAnySubnetIndex);
  void StopCrosVm(uint64_t vm_id, GuestMessage::GuestType vm_type);

  // Callback from ProcessReaper to notify Manager that one of the
  // subprocesses died.
  void OnSubprocessExited(pid_t pid, const siginfo_t& info);
  void RestartSubprocess(HelperProcess* subproc);

  // Callback from Daemon to notify that the message loop exits and before
  // Daemon::Run() returns.
  void OnShutdown(int* exit_code) override;

  // Callback from NDProxy telling us to add a new IPv6 route to guest or IPv6
  // address to guest-facing interface.
  void OnNDProxyMessage(const NDProxyMessage& msg);

  // Handles DBus request for querying the list of virtual devices managed by
  // patchpanel.
  std::unique_ptr<dbus::Response> OnGetDevices(dbus::MethodCall* method_call);

  // Handles DBus notification indicating ARC++ is booting up.
  std::unique_ptr<dbus::Response> OnArcStartup(dbus::MethodCall* method_call);

  // Handles DBus notification indicating ARC++ is spinning down.
  std::unique_ptr<dbus::Response> OnArcShutdown(dbus::MethodCall* method_call);

  // Handles DBus notification indicating ARCVM is booting up.
  std::unique_ptr<dbus::Response> OnArcVmStartup(dbus::MethodCall* method_call);

  // Handles DBus notification indicating ARCVM is spinning down.
  std::unique_ptr<dbus::Response> OnArcVmShutdown(
      dbus::MethodCall* method_call);

  // Handles DBus notification indicating a Termina VM is booting up.
  std::unique_ptr<dbus::Response> OnTerminaVmStartup(
      dbus::MethodCall* method_call);

  // Handles DBus notification indicating a Termina VM is spinning down.
  std::unique_ptr<dbus::Response> OnTerminaVmShutdown(
      dbus::MethodCall* method_call);

  // Handles DBus notification indicating a Plugin VM is booting up.
  std::unique_ptr<dbus::Response> OnPluginVmStartup(
      dbus::MethodCall* method_call);

  // Handles DBus notification indicating a Plugin VM is spinning down.
  std::unique_ptr<dbus::Response> OnPluginVmShutdown(
      dbus::MethodCall* method_call);

  // Handles DBus requests for setting a VPN intent fwmark on a socket.
  std::unique_ptr<dbus::Response> OnSetVpnIntent(dbus::MethodCall* method_call);

  // Handles DBus requests for connect and routing an existing network
  // namespace created via minijail or through rtnetlink RTM_NEWNSID.
  std::unique_ptr<dbus::Response> OnConnectNamespace(
      dbus::MethodCall* method_call);

  // Handles DBus requests for querying traffic counters.
  std::unique_ptr<dbus::Response> OnGetTrafficCounters(
      dbus::MethodCall* method_call);

  // Handles DBus requests for creating iptables rules requests from
  // permission_broker.
  std::unique_ptr<dbus::Response> OnModifyPortRule(
      dbus::MethodCall* method_call);

  // Handles DBus requests for starting and stopping VPN lockdown.
  std::unique_ptr<dbus::Response> OnSetVpnLockdown(
      dbus::MethodCall* method_call);

  // Handles DBus requests for creating iptables rules requests from dns-proxy.
  std::unique_ptr<dbus::Response> OnSetDnsRedirectionRule(
      dbus::MethodCall* method_call);

  // Sends out DBus signal for notifying neighbor reachability event.
  void OnNeighborReachabilityEvent(
      int ifindex,
      const shill::IPAddress& ip_addr,
      NeighborLinkMonitor::NeighborRole role,
      NeighborReachabilityEventSignal::EventType event_type);

  std::unique_ptr<patchpanel::ConnectNamespaceResponse> ConnectNamespace(
      base::ScopedFD client_fd,
      const patchpanel::ConnectNamespaceRequest& request);

  // Helper functions for process lifetime tracking.
  int AddLifelineFd(int dbus_fd);
  bool DeleteLifelineFd(int dbus_fd);

  // Detects if any file descriptor committed in patchpanel's DBus API has been
  // invalidated by the caller. Calls OnLifelineFdClosed for any invalid fd
  // found.
  void OnLifelineFdClosed(int client_fd);

  bool RedirectDns(base::ScopedFD client_fd,
                   const patchpanel::SetDnsRedirectionRuleRequest& request);

  // Disable and re-enable IPv6 inside a namespace.
  void RestartIPv6(const std::string& netns_name);

  // Dispatch |msg| to child processes.
  void SendGuestMessage(const GuestMessage& msg);

  friend std::ostream& operator<<(std::ostream& stream, const Manager& manager);

  // Unique instance of patchpanel::System shared for all subsystems.
  std::unique_ptr<System> system_;
  // UMA metrics client.
  std::unique_ptr<MetricsLibraryInterface> metrics_;
  // Shill Dbus client.
  std::unique_ptr<ShillClient> shill_client_;
  // High level routing and iptables controller service.
  std::unique_ptr<Datapath> datapath_;
  // Routing service.
  std::unique_ptr<RoutingService> routing_svc_;
  // ARC++/ARCVM service.
  std::unique_ptr<ArcService> arc_svc_;
  // Crostini and other VM service.
  std::unique_ptr<CrostiniService> cros_svc_;
  // Patchpanel DBus service.
  dbus::ExportedObject* dbus_svc_path_;  // Owned by |bus_|.
  // Other services.
  brillo::ProcessReaper process_reaper_;
  // adb connection forwarder service.
  std::unique_ptr<HelperProcess> adb_proxy_;
  // IPv4 and IPv6 Multicast forwarder service.
  std::unique_ptr<HelperProcess> mcast_proxy_;
  // IPv6 neighbor discovery forwarder service.
  std::unique_ptr<HelperProcess> nd_proxy_;
  // Traffic counter service.
  std::unique_ptr<CountersService> counters_svc_;
  // L2 neighbor monitor service.
  std::unique_ptr<NetworkMonitorService> network_monitor_svc_;
  // IPv4 prefix and address manager.
  AddressManager addr_mgr_;

  // |cached_feature_enabled| stores the cached result of if a feature should be
  // enabled.
  static std::map<const std::string, bool> cached_feature_enabled_;

  // TODO(b/174538233) Introduce ForwardingGroup to properly track the state of
  // traffic forwarding (ndproxy, multicast) between upstream devices managed by
  // shill and downstream devices managed by patchpanel.
  // Map of shill interfaces to downstream interfaces managed by patchpanel for
  // which multicast forwarding was enabled. This information cannot always be
  // retrieved from the IFF_MULTICAST flag of the upstream interface managed by
  // shill if it does not exist anymore.
  std::map<std::string, std::set<std::string>> multicast_ifnames_;
  // Map of shill interfaces to downstream interfaces managed by patchpanel for
  // which IPv6 neighbor discovery proxy was enabled. This information cannot
  // always be retrieved from the technology type of the upstream interface
  // managed by shill if it does not exist anymore.
  std::map<std::string, std::set<std::string>> ndproxy_ifnames_;

  // All namespaces currently connected through patchpanel ConnectNamespace
  // API, keyed by file descriptors committed by clients when calling
  // ConnectNamespace.
  std::map<int, ConnectedNamespace> connected_namespaces_;
  int connected_namespaces_next_id_{0};

  // All rules currently created through patchpanel RedirectDns
  // API, keyed by file descriptors committed by clients when calling the
  // API.
  std::map<int, DnsRedirectionRule> dns_redirection_rules_;

  // For each fd (process) committed through a patchpanel's DBus API, keep
  // track of the FileDescriptorWatcher::Controller object associated with it.
  std::map<int, std::unique_ptr<base::FileDescriptorWatcher::Controller>>
      lifeline_fd_controllers_;

  base::WeakPtrFactory<Manager> weak_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_MANAGER_H_
