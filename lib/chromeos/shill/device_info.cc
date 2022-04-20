// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/device_info.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/bind.h>
//#include <base/check.h>
//#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/userdb_utils.h>
#include <chromeos/constants/vm_tools.h>

#include "shill/connection.h"
#include "shill/device.h"
#include "shill/ethernet/ethernet.h"
#include "shill/ethernet/virtio_ethernet.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/net/ndisc.h"
#include "shill/net/rtnl_handler.h"
#include "shill/net/rtnl_link_stats.h"
#include "shill/net/rtnl_listener.h"
#include "shill/net/rtnl_message.h"
#include "shill/net/shill_time.h"
#include "shill/power_manager.h"
#include "shill/routing_table.h"
#include "shill/vpn/vpn_provider.h"

#if !defined(DISABLE_CELLULAR)
#include "shill/cellular/modem_info.h"
#endif  // DISABLE_CELLULAR

#if !defined(DISABLE_WIFI)
#include "shill/net/netlink_attribute.h"
#include "shill/net/netlink_manager.h"
#include "shill/net/nl80211_message.h"
#include "shill/wifi/wifi.h"
#endif  // DISABLE_WIFI

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDevice;
static std::string ObjectID(const DeviceInfo* d) {
  return "(device_info)";
}
}  // namespace Logging

namespace {

// Device name prefix for modem pseudo devices used in testing.
constexpr char kModemPseudoDeviceNamePrefix[] = "pseudomodem";

// Device name prefix for virtual ethernet devices used in testing.
constexpr char kEthernetPseudoDeviceNamePrefix[] = "pseudoethernet";

// Root of the kernel sysfs directory holding network device info.
constexpr char kDeviceInfoRoot[] = "/sys/class/net";

// Name of the "cdc_ether" driver.  This driver is not included in the
// kModemDrivers list because we need to do additional checking.
constexpr char kDriverCdcEther[] = "cdc_ether";

// Name of the "cdc_ncm" driver.  This driver is not included in the
// kModemDrivers list because we need to do additional checking.
constexpr char kDriverCdcNcm[] = "cdc_ncm";

// Name of the virtio network driver.
constexpr char kDriverVirtioNet[] = "virtio_net";

// Sysfs path to a device uevent file.
constexpr char kInterfaceUevent[] = "uevent";

// Content of a device uevent file that indicates it is a bridge device.
constexpr char kInterfaceUeventBridgeSignature[] = "DEVTYPE=bridge\n";

// Content of a device uevent file that indicates it is a WiFi device.
constexpr char kInterfaceUeventWifiSignature[] = "DEVTYPE=wlan\n";

// Sysfs path to a device via its interface name.
constexpr char kInterfaceDevice[] = "device";

// Sysfs path to the driver of a device via its interface name.
constexpr char kInterfaceDriver[] = "device/driver";

// Sysfs path to the driver of an FM350 device via its interface name. This is
// a temporary fix until the mtkt7xx driver exposes the driver symlink at the
// same "device/driver" endpoint as expected (b/225373673)
constexpr char kInterfaceDriverMtkt7xx[] = "device/device/driver";

// Sysfs path to the vendor ID file via its interface name.
constexpr char kInterfaceVendorId[] = "device/vendor";

// Sysfs path to the device ID file via its interface name.
constexpr char kInterfaceDeviceId[] = "device/device";

// Sysfs path to the subsystem ID file via its interface name.
constexpr char kInterfaceSubsystemId[] = "device/subsystem_device";

// Sysfs path to the file that is used to determine the owner of the interface.
constexpr char kInterfaceOwner[] = "owner";

// Sysfs path to the file that is used to determine if this is tun device.
constexpr char kInterfaceTunFlags[] = "tun_flags";

// Sysfs path to the file that is used to determine if a wifi device is
// operating in monitor mode.
constexpr char kInterfaceType[] = "type";

// Device name prefixes for virtual devices that should be ignored.
// TODO(chromium:899004): Using network device name is a bit fragile. Find
// other signals to identify these network devices.
const char* const kIgnoredDeviceNamePrefixes[] = {
    // TODO(garrick): Workaround for (chromium:917923): 'arc_' is the prefix
    // used for all ARC++ multinet bridge interface. These should be ignored
    // for now.
    "arc_",
    "veth",
};

// As of Linux v5.4, these "kinds" are not part of a UAPI header definition, so
// we open-code them here, with some reference to where and when we found them
// in the Linux kernel tree (version numbers are just a snapshot in time, not
// necessarily when they were first supported). These strings are also usually
// annotated in the kernel source tree via MODULE_ALIAS_RTNL_LINK() macros.
const char* const kIgnoredDeviceKinds[] = {
    "ifb",  // v5.4, drivers/net/ifb.c:289
};
// v5.4, drivers/net/veth.c:1393
constexpr char kKindVeth[] = "veth";
// v5.4, drivers/net/ethernet/qualcomm/rmnet/rmnet_config.c:369
constexpr char kKindRmnet[] = "rmnet";
// v5.10, drivers/net/wireguard/device.c:254, |device_type.name| is set to
// KBUILD_MODNAME, which is "wireguard".
constexpr char kKindWireGuard[] = "wireguard";
// v4.19+, net/xfrm/xfrm_interface.c
constexpr char kKindXfrm[] = "xfrm";

// Modem drivers that we support.
const char* const kModemDrivers[] = {
    // For modems which expose MBIM to userspace (Fibocom L850-GL, NL668-AM,
    // FM101, etc.)
    "cdc_mbim",
    // For modems which expose QMI to userspace. This may not be usable if
    // USE=qmi is not set.
    "qmi_wwan",
    // For Mediatek-based PCIe modems (Fibocom FM350, etc.)
    "mtk_t7xx",
};

// Path to the tun device.
constexpr char kTunDeviceName[] = "/dev/net/tun";

// Time to wait before registering devices which need extra time to detect.
constexpr base::TimeDelta kDelayedDeviceCreation = base::Seconds(5);

// Time interval for polling for link statistics.
constexpr base::TimeDelta kRequestLinkStatisticsInterval = base::Seconds(20);

// IFLA_XFRM_LINK and IFLA_XFRM_IF_ID are defined in
// /usr/include/linux/if_link.h on 4.19+ kernels.
constexpr int kIflaXfrmLink = 1;
constexpr int kIflaXfrmIfId = 2;

// Non-functional Device subclass used for non-operable or blocked devices
class DeviceStub : public Device {
 public:
  DeviceStub(Manager* manager,
             const std::string& link_name,
             const std::string& address,
             int interface_index,
             Technology technology)
      : Device(manager, link_name, address, interface_index, technology) {}
  DeviceStub(const DeviceStub&) = delete;
  DeviceStub& operator=(const DeviceStub&) = delete;

  void Start(Error* /*error*/,
             const EnabledStateChangedCallback& /*callback*/) override {}
  void Stop(Error* /*error*/,
            const EnabledStateChangedCallback& /*callback*/) override {}
  void Initialize() override {}

  void OnIPv6ConfigUpdated() override {}
};

}  // namespace

DeviceInfo::DeviceInfo(Manager* manager)
    : manager_(manager),
      device_info_root_(kDeviceInfoRoot),
      routing_table_(RoutingTable::GetInstance()),
      rtnl_handler_(RTNLHandler::GetInstance()),
#if !defined(DISABLE_WIFI)
      netlink_manager_(NetlinkManager::GetInstance()),
#endif  // DISABLE_WIFI
      sockets_(new Sockets()),
      time_(Time::GetInstance()) {
  if (manager) {
    // |manager| may be null in tests.
    dispatcher_ = manager->dispatcher();
    metrics_ = manager->metrics();
  }
}

DeviceInfo::~DeviceInfo() = default;

void DeviceInfo::BlockDevice(const std::string& device_name) {
  blocked_list_.insert(device_name);
  // Remove the current device info if it exist, since it will be out-dated.
  DeregisterDevice(GetIndex(device_name));
  // Request link info update to allow device info to be recreated.
  if (manager_->running()) {
    rtnl_handler_->RequestDump(RTNLHandler::kRequestLink);
  }
}

void DeviceInfo::AllowDevice(const std::string& device_name) {
  blocked_list_.erase(device_name);
  // Remove the current device info if it exist, since it will be out-dated.
  DeregisterDevice(GetIndex(device_name));
  // Request link info update to allow device info to be recreated.
  if (manager_->running()) {
    rtnl_handler_->RequestDump(RTNLHandler::kRequestLink);
  }
}

bool DeviceInfo::IsDeviceBlocked(const std::string& device_name) {
  return base::Contains(blocked_list_, device_name);
}

void DeviceInfo::Start() {
  link_listener_.reset(
      new RTNLListener(RTNLHandler::kRequestLink,
                       base::BindRepeating(&DeviceInfo::LinkMsgHandler,
                                           base::Unretained(this))));
  address_listener_.reset(
      new RTNLListener(RTNLHandler::kRequestAddr,
                       base::BindRepeating(&DeviceInfo::AddressMsgHandler,
                                           base::Unretained(this))));
  rdnss_listener_.reset(
      new RTNLListener(RTNLHandler::kRequestRdnss,
                       base::BindRepeating(&DeviceInfo::RdnssMsgHandler,
                                           base::Unretained(this))));
  rtnl_handler_->RequestDump(RTNLHandler::kRequestLink |
                             RTNLHandler::kRequestAddr);
  request_link_statistics_callback_.Reset(base::Bind(
      &DeviceInfo::RequestLinkStatistics, weak_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(FROM_HERE,
                               request_link_statistics_callback_.callback(),
                               kRequestLinkStatisticsInterval);
}

void DeviceInfo::Stop() {
  link_listener_.reset();
  address_listener_.reset();
  infos_.clear();
  request_link_statistics_callback_.Cancel();
  delayed_devices_callback_.Cancel();
  delayed_devices_.clear();
}

std::vector<std::string> DeviceInfo::GetUninitializedTechnologies() const {
  std::set<std::string> unique_technologies;
  std::set<Technology> initialized_technologies;
  for (const auto& info : infos_) {
    Technology technology = info.second.technology;
    if (info.second.device) {
      // If there is more than one device for a technology and at least
      // one of them has been initialized, make sure that it doesn't get
      // listed as uninitialized.
      initialized_technologies.insert(technology);
      unique_technologies.erase(technology.GetName());
      continue;
    }
    if (technology.IsPrimaryConnectivityTechnology() &&
        !base::Contains(initialized_technologies, technology))
      unique_technologies.insert(technology.GetName());
  }
  return std::vector<std::string>(unique_technologies.begin(),
                                  unique_technologies.end());
}

void DeviceInfo::RegisterDevice(const DeviceRefPtr& device) {
  SLOG(this, 1) << __func__ << "(" << device->link_name() << ", "
                << device->interface_index() << ")";
  device->Initialize();
  delayed_devices_.erase(device->interface_index());
  CHECK(!GetDevice(device->interface_index()).get());
  infos_[device->interface_index()].device = device;
  if (metrics_->IsDeviceRegistered(device->interface_index(),
                                   device->technology())) {
    metrics_->NotifyDeviceInitialized(device->interface_index());
  } else {
    metrics_->RegisterDevice(device->interface_index(), device->technology());
  }
  if (device->technology() != Technology::kBlocked &&
      device->technology() != Technology::kUnknown) {
    routing_table_->RegisterDevice(device->interface_index(),
                                   device->link_name());
  }
  if (device->technology().IsPrimaryConnectivityTechnology()) {
    manager_->RegisterDevice(device);
  }

  // Provide |device| with any information that was received prior to its
  // construction/registration.
  const auto& address = GetPrimaryIPv6Address(device->interface_index());
  if (address) {
    device->OnIPv6AddressChanged(address);
  }
}

base::FilePath DeviceInfo::GetDeviceInfoPath(
    const std::string& iface_name, const std::string& path_name) const {
  return device_info_root_.Append(iface_name).Append(path_name);
}

bool DeviceInfo::GetDeviceInfoContents(const std::string& iface_name,
                                       const std::string& path_name,
                                       std::string* contents_out) const {
  return base::ReadFileToString(GetDeviceInfoPath(iface_name, path_name),
                                contents_out);
}

bool DeviceInfo::GetDeviceInfoSymbolicLink(const std::string& iface_name,
                                           const std::string& path_name,
                                           base::FilePath* path_out) const {
  return base::ReadSymbolicLink(GetDeviceInfoPath(iface_name, path_name),
                                path_out);
}

int DeviceInfo::GetDeviceArpType(const std::string& iface_name) const {
  std::string type_string;
  int arp_type;

  if (!GetDeviceInfoContents(iface_name, kInterfaceType, &type_string) ||
      !base::TrimString(type_string, "\n", &type_string) ||
      !base::StringToInt(type_string, &arp_type)) {
    return ARPHRD_VOID;
  }
  return arp_type;
}

Technology DeviceInfo::GetDeviceTechnology(
    const std::string& iface_name,
    const std::optional<std::string>& kind) const {
  int arp_type = GetDeviceArpType(iface_name);

  if (kind.has_value()) {
    SLOG(this, 2) << iface_name << ": device is kind '" << kind.value() << "'";
  }

  if (IsGuestDevice(iface_name)) {
    SLOG(this, 2) << iface_name << ": device is a guest device";
    return Technology::kGuestInterface;
  }

  if (kind.has_value()) {
    // Ignore certain KINDs of devices.
    for (const char* ignoreKind : kIgnoredDeviceKinds) {
      if (ignoreKind == kind.value()) {
        SLOG(this, 2) << __func__ << ": device " << iface_name
                      << " ignored, kind \"" << ignoreKind << "\"";
        return Technology::kUnknown;
      }
    }
  }

  // Special case for devices which should be ignored.
  for (const char* prefix : kIgnoredDeviceNamePrefixes) {
    if (iface_name.find(prefix) == 0) {
      SLOG(this, 2) << __func__ << ": device " << iface_name
                    << " should be ignored";
      return Technology::kUnknown;
    }
  }

  if (kind.has_value() && kind.value() == kKindWireGuard) {
    SLOG(this, 2) << __func__ << ": device " << iface_name
                  << " is a wireguard device. Treat it as a tunnel.";
    return Technology::kTunnel;
  }

  if (kind.has_value() && kind.value() == kKindXfrm) {
    SLOG(this, 2) << __func__ << ": device " << iface_name
                  << " is a xfrm device. Treat it as a tunnel.";
    return Technology::kTunnel;
  }

  // Special case for pseudo modem veth pairs which are used for testing.
  if (iface_name.find(kModemPseudoDeviceNamePrefix) == 0) {
    SLOG(this, 2) << __func__ << ": device " << iface_name
                  << " is a pseudo modem for testing";
    return Technology::kCellular;
  }

  // Special case for pseudo ethernet devices which are used for testing.
  if (iface_name.find(kEthernetPseudoDeviceNamePrefix) == 0) {
    SLOG(this, 2) << __func__ << ": device " << iface_name
                  << " is a virtual ethernet device for testing";
    return Technology::kEthernet;
  }

  // No point delaying veth devices just because they don't have a device
  // symlink. Treat it as Ethernet directly.
  if (kind.has_value() && kind.value() == kKindVeth) {
    SLOG(this, 2) << __func__ << ": device " << iface_name << " is kind veth";
    return Technology::kEthernet;
  }

  // 'rmnet' is Qualcomm's data-path cellular netdevice.
  if (kind.has_value() && kind.value() == kKindRmnet) {
    SLOG(this, 2) << __func__ << ": device " << iface_name << " is kind rmnet";
    return Technology::kCellular;
  }

  if (arp_type == ARPHRD_IEEE80211_RADIOTAP) {
    SLOG(this, 2) << __func__ << ": wifi device " << iface_name
                  << " is in monitor mode";
    return Technology::kWiFiMonitor;
  }

  std::string contents;
  if (!GetDeviceInfoContents(iface_name, kInterfaceUevent, &contents)) {
    LOG(INFO) << __func__ << ": device " << iface_name << " has no uevent file";
    return Technology::kUnknown;
  }

  // If the "uevent" file contains the string "DEVTYPE=wlan\n" at the
  // start of the file or after a newline, we can safely assume this
  // is a wifi device.
  if (contents.find(kInterfaceUeventWifiSignature) != std::string::npos) {
    SLOG(this, 2) << __func__ << ": device " << iface_name
                  << " has wifi signature in uevent file";
    return Technology::kWiFi;
  }

  // Similarly, if the uevent file contains "DEVTYPE=bridge\n" then we can
  // safely assume this is a bridge device and can be treated as ethernet.
  if (contents.find(kInterfaceUeventBridgeSignature) != std::string::npos) {
    SLOG(this, 2) << __func__ << ": device " << iface_name
                  << " has bridge signature in uevent file";
    return Technology::kEthernet;
  }

  base::FilePath driver_path;
  if (!GetDeviceInfoSymbolicLink(iface_name, kInterfaceDriver, &driver_path) &&
      !GetDeviceInfoSymbolicLink(iface_name, kInterfaceDriverMtkt7xx,
                                 &driver_path)) {
    SLOG(this, 2) << __func__ << ": device " << iface_name
                  << " has no device symlink";
    if (arp_type == ARPHRD_LOOPBACK) {
      SLOG(this, 2) << __func__ << ": device " << iface_name
                    << " is a loopback device";
      return Technology::kLoopback;
    }
    if (arp_type == ARPHRD_PPP) {
      SLOG(this, 2) << __func__ << ": device " << iface_name
                    << " is a ppp device";
      return Technology::kPPP;
    }
    // Devices like Qualcomm's IPA (IP Accelerator) should not be managed by
    // Shill.
    if (arp_type == ARPHRD_RAWIP) {
      SLOG(this, 2) << __func__ << ": device " << iface_name
                    << " is a raw IP device";
      return Technology::kUnknown;
    }
    std::string tun_flags_str;
    int tun_flags = 0;
    if (GetDeviceInfoContents(iface_name, kInterfaceTunFlags, &tun_flags_str) &&
        base::TrimString(tun_flags_str, "\n", &tun_flags_str) &&
        base::HexStringToInt(tun_flags_str, &tun_flags) &&
        (tun_flags & IFF_TUN)) {
      SLOG(this, 2) << __func__ << ": device " << iface_name
                    << " is tun device";
      return Technology::kTunnel;
    }

    // We don't know what sort of device it is.
    return Technology::kNoDeviceSymlink;
  }

  std::string driver_name(driver_path.BaseName().value());
  // See if driver for this interface is in a list of known modem driver names.
  for (auto modem_driver : kModemDrivers) {
    if (driver_name == modem_driver) {
      SLOG(this, 2) << __func__ << ": device " << iface_name
                    << " is matched with modem driver " << driver_name;
      return Technology::kCellular;
    }
  }

  // For cdc_ether / cdc_ncm devices, make sure it's a modem because this driver
  // can be used for other ethernet devices.
  if (driver_name == kDriverCdcEther || driver_name == kDriverCdcNcm) {
    if (IsCdcEthernetModemDevice(iface_name)) {
      LOG(INFO) << __func__ << ": device " << iface_name << " is a "
                << driver_name << " modem device";
      return Technology::kCellular;
    }
    SLOG(this, 2) << __func__ << ": device " << iface_name << " is a "
                  << driver_name << " device";
    return Technology::kCDCEthernet;
  }

  // Special case for the virtio driver, used when run under KVM. See also
  // the comment in VirtioEthernet::Start.
  if (driver_name == kDriverVirtioNet) {
    SLOG(this, 2) << __func__ << ": device " << iface_name
                  << " is virtio ethernet";
    return Technology::kVirtioEthernet;
  }

  SLOG(this, 2) << __func__ << ": device " << iface_name << ", with driver "
                << driver_name << ", is defaulted to type ethernet";
  return Technology::kEthernet;
}

bool DeviceInfo::IsCdcEthernetModemDevice(const std::string& iface_name) const {
  // A cdc_ether / cdc_ncm device is a modem device if it also exposes tty
  // interfaces. To determine this, we look for the existence of the tty
  // interface in the USB device sysfs tree.
  //
  // A typical sysfs dir hierarchy for a cdc_ether / cdc_ncm modem USB device is
  // as follows:
  //
  //   /sys/devices/pci0000:00/0000:00:1d.7/usb1/1-2
  //     1-2:1.0
  //       tty
  //         ttyACM0
  //     1-2:1.1
  //       net
  //         usb0
  //     1-2:1.2
  //       tty
  //         ttyACM1
  //       ...
  //
  // /sys/class/net/usb0/device symlinks to
  // /sys/devices/pci0000:00/0000:00:1d.7/usb1/1-2/1-2:1.1
  //
  // Note that some modem devices have the tty directory one level deeper
  // (eg. E362), so the device tree for the tty interface is:
  // /sys/devices/pci0000:00/0000:00:1d.7/usb/1-2/1-2:1.0/ttyUSB0/tty/ttyUSB0

  base::FilePath device_file = GetDeviceInfoPath(iface_name, kInterfaceDevice);
  base::FilePath device_path;
  if (!base::ReadSymbolicLink(device_file, &device_path)) {
    SLOG(this, 2) << __func__ << ": device " << iface_name
                  << " has no device symlink";
    return false;
  }
  if (!device_path.IsAbsolute()) {
    device_path =
        base::MakeAbsoluteFilePath(device_file.DirName().Append(device_path));
  }

  // Look for tty interface by enumerating all directories under the parent
  // USB device and see if there's a subdirectory "tty" inside.  In other
  // words, using the example dir hierarchy above, find
  // /sys/devices/pci0000:00/0000:00:1d.7/usb1/1-2/.../tty.
  // If this exists, then this is a modem device.
  return HasSubdir(device_path.DirName(), base::FilePath("tty"));
}

// static
bool DeviceInfo::HasSubdir(const base::FilePath& base_dir,
                           const base::FilePath& subdir) {
  const auto type = static_cast<base::FileEnumerator::FileType>(
      base::FileEnumerator::DIRECTORIES | base::FileEnumerator::SHOW_SYM_LINKS);
  base::FileEnumerator dir_enum(base_dir, true, type);
  for (auto curr_dir = dir_enum.Next(); !curr_dir.empty();
       curr_dir = dir_enum.Next()) {
    if (curr_dir.BaseName() == subdir)
      return true;
  }
  return false;
}

DeviceRefPtr DeviceInfo::CreateDevice(const std::string& link_name,
                                      const std::string& address,
                                      int interface_index,
                                      Technology technology) {
  SLOG(this, 1) << __func__ << ": " << link_name << " Address: " << address
                << " Index: " << interface_index;
  DeviceRefPtr device;
  delayed_devices_.erase(interface_index);
  infos_[interface_index].technology = technology;
  bool flush = true;

  switch (technology) {
    case Technology::kCellular:
#if defined(DISABLE_CELLULAR)
      LOG(WARNING) << "Cellular support is not implemented. "
                   << "Ignore cellular device " << link_name << " at index "
                   << interface_index << ".";
      return nullptr;
#else
      // Cellular devices are managed by ModemInfo.
      SLOG(this, 2) << "Cellular link " << link_name << " at index "
                    << interface_index << " -- notifying ModemInfo.";

      // The MAC address provided by RTNL is not reliable for Gobi 2K modems.
      // Clear it here, and it will be fetched from the kernel in
      // GetMacAddress().
      infos_[interface_index].mac_address.Clear();
      manager_->modem_info()->OnDeviceInfoAvailable(link_name);
      break;
#endif  // DISABLE_CELLULAR
    case Technology::kEthernet:
      device = new Ethernet(manager_, link_name, address, interface_index);
      device->EnableIPv6Privacy();
      break;
    case Technology::kVirtioEthernet:
      device =
          new VirtioEthernet(manager_, link_name, address, interface_index);
      device->EnableIPv6Privacy();
      break;
    case Technology::kWiFi:
#if defined(DISABLE_WIFI)
      LOG(WARNING) << "WiFi support is not implemented. Ignore WiFi link "
                   << link_name << " at index " << interface_index << ".";
      return nullptr;
#else
      // Defer creating this device until we get information about the
      // type of WiFi interface.
      GetWiFiInterfaceInfo(interface_index);
      break;
#endif  // DISABLE_WIFI
    case Technology::kArcBridge:
      // Shill doesn't touch the IP configuration for the ARC bridge.
      flush = false;
      break;
    case Technology::kPPP:
    case Technology::kTunnel:
      // Tunnel and PPP devices are managed by the VPN code (PPP for
      // l2tpipsec). Notify the corresponding VPNService of the interface's
      // presence through the pre-registered callback.
      // Since CreateDevice is only called once in the lifetime of an
      // interface index, this notification will only occur the first
      // time the device is seen.
      if (pending_links_.find(link_name) != pending_links_.end()) {
        SLOG(this, 2) << "Tunnel / PPP link " << link_name << " at index "
                      << interface_index << " -- triggering callback.";
        std::move(pending_links_[link_name]).Run(link_name, interface_index);
        pending_links_.erase(link_name);
      } else if (technology == Technology::kTunnel) {
        // If no one claims this tunnel, it is probably
        // left over from a previous instance and should not exist.
        SLOG(this, 2) << "Tunnel link " << link_name << " at index "
                      << interface_index << " is unused. Deleting.";
        DeleteInterface(interface_index);
      }
      break;
    case Technology::kLoopback:
      // Loopback devices are largely ignored, but we should make sure the
      // link is enabled.
      SLOG(this, 2) << "Bringing up loopback device " << link_name
                    << " at index " << interface_index;
      rtnl_handler_->SetInterfaceFlags(interface_index, IFF_UP, IFF_UP);
      return nullptr;
    case Technology::kCDCEthernet:
      // CDCEthernet devices are of indeterminate type when they are
      // initially created.  Some time later, tty devices may or may
      // not appear under the same USB device root, which will identify
      // it as a modem.  Alternatively, ModemManager may discover the
      // device and create and register a Cellular device.  In either
      // case, we should delay creating a Device until we can make a
      // better determination of what type this Device should be.
    case Technology::kNoDeviceSymlink:  // FALLTHROUGH
      // The same is true for devices that do not report a device
      // symlink.  It has been observed that tunnel devices may not
      // immediately contain a tun_flags component in their
      // /sys/class/net entry.
      LOG(INFO) << "Delaying creation of device for " << link_name
                << " at index " << interface_index;
      DelayDeviceCreation(interface_index);
      return nullptr;
    case Technology::kGuestInterface:
      return nullptr;
    default:
      // We will not manage this device in shill.  Do not create a device
      // object or do anything to change its state.  We create a stub object
      // which is useful for testing.
      return new DeviceStub(manager_, link_name, address, interface_index,
                            technology);
  }

  if (flush) {
    // Reset the routing table and addresses.
    routing_table_->FlushRoutes(interface_index);
    FlushAddresses(interface_index);
  }

  manager_->UpdateUninitializedTechnologies();

  return device;
}

// static
bool DeviceInfo::GetLinkNameFromMessage(const RTNLMessage& msg,
                                        std::string* link_name) {
  if (!msg.HasAttribute(IFLA_IFNAME))
    return false;

  ByteString link_name_bytes(msg.GetAttribute(IFLA_IFNAME));
  link_name->assign(
      reinterpret_cast<const char*>(link_name_bytes.GetConstData()));

  return true;
}

bool DeviceInfo::IsRenamedBlockedDevice(const RTNLMessage& msg) {
  int interface_index = msg.interface_index();
  const Info* info = GetInfo(interface_index);
  if (!info)
    return false;

  if (!info->device || info->device->technology() != Technology::kBlocked)
    return false;

  std::string interface_name;
  if (!GetLinkNameFromMessage(msg, &interface_name))
    return false;

  if (interface_name == info->name)
    return false;

  LOG(INFO) << __func__ << ": interface index " << interface_index
            << " renamed from " << info->name << " to " << interface_name;
  return true;
}

void DeviceInfo::AddLinkMsgHandler(const RTNLMessage& msg) {
  SLOG(this, 2) << __func__ << " index: " << msg.interface_index();

  DCHECK(msg.type() == RTNLMessage::kTypeLink &&
         msg.mode() == RTNLMessage::kModeAdd);
  int dev_index = msg.interface_index();
  Technology technology = Technology::kUnknown;
  unsigned int flags = msg.link_status().flags;
  unsigned int change = msg.link_status().change;

  if (IsRenamedBlockedDevice(msg)) {
    // Treat renamed blocked devices as new devices.
    DeregisterDevice(dev_index);
  }

  bool new_device = !infos_[dev_index].received_add_link;
  SLOG(this, 2) << __func__
                << base::StringPrintf(
                       "(index=%d, flags=0x%x, change=0x%x), new_device=%d",
                       dev_index, flags, change, new_device);
  infos_[dev_index].received_add_link = true;
  infos_[dev_index].flags = flags;

  RetrieveLinkStatistics(dev_index, msg);

  DeviceRefPtr device = GetDevice(dev_index);
  if (new_device) {
    CHECK(!device);
    std::string link_name;
    if (!GetLinkNameFromMessage(msg, &link_name)) {
      LOG(ERROR) << "Add Link message does not contain a link name!";
      return;
    }
    SLOG(this, 2) << "add link index " << dev_index << " name " << link_name;
    infos_[dev_index].name = link_name;
    indices_[link_name] = dev_index;

    if (!link_name.empty()) {
      if (link_name == VPNProvider::kArcBridgeIfName) {
        technology = Technology::kArcBridge;
      } else if (IsDeviceBlocked(link_name)) {
        technology = Technology::kBlocked;
      } else if (!manager_->DeviceManagementAllowed(link_name)) {
        technology = Technology::kBlocked;
        BlockDevice(link_name);
      } else {
        technology = GetDeviceTechnology(link_name, msg.link_status().kind);
      }
    }
    std::string address;
    if (msg.HasAttribute(IFLA_ADDRESS)) {
      infos_[dev_index].mac_address = msg.GetAttribute(IFLA_ADDRESS);
      address = infos_[dev_index].mac_address.HexEncode();
      SLOG(this, 2) << "link index " << dev_index << " address " << address;
    } else if (technology == Technology::kWiFi ||
               technology == Technology::kEthernet) {
      LOG(ERROR) << "Add link message does not have IFLA_ADDRESS, link: "
                 << link_name << ", Technology: " << technology.GetName();
      return;
    }
    metrics_->RegisterDevice(dev_index, technology);
    device = CreateDevice(link_name, address, dev_index, technology);
    if (device) {
      RegisterDevice(device);
    }
  }
  if (device) {
    device->LinkEvent(flags, change);
  }
}

void DeviceInfo::DelLinkMsgHandler(const RTNLMessage& msg) {
  SLOG(this, 2) << __func__ << "(index=" << msg.interface_index() << ")";

  DCHECK(msg.type() == RTNLMessage::kTypeLink &&
         msg.mode() == RTNLMessage::kModeDelete);
  SLOG(this, 2) << __func__
                << base::StringPrintf("(index=%d, flags=0x%x, change=0x%x)",
                                      msg.interface_index(),
                                      msg.link_status().flags,
                                      msg.link_status().change);

  std::string link_name;
  if (!GetLinkNameFromMessage(msg, &link_name)) {
    LOG(ERROR) << "Del Link message does not contain a link name!";
    return;
  }

  DeregisterDevice(msg.interface_index());
}

DeviceRefPtr DeviceInfo::GetDevice(int interface_index) const {
  const Info* info = GetInfo(interface_index);
  return info ? info->device : nullptr;
}

int DeviceInfo::GetIndex(const std::string& interface_name) const {
  std::map<std::string, int>::const_iterator it = indices_.find(interface_name);
  return it == indices_.end() ? -1 : it->second;
}

bool DeviceInfo::GetMacAddress(int interface_index, ByteString* address) const {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return false;
  }
  // |mac_address| from RTNL is not used for some devices, in which case it will
  // be empty here.
  if (!info->mac_address.IsEmpty()) {
    *address = info->mac_address;
    return true;
  }

  // Ask the kernel for the MAC address.
  *address = GetMacAddressFromKernel(interface_index);
  return !address->IsEmpty();
}

ByteString DeviceInfo::GetMacAddressFromKernel(int interface_index) const {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return ByteString();
  }

  const int fd = sockets_->Socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    PLOG(ERROR) << __func__ << ": Unable to open socket";
    return ByteString();
  }

  ScopedSocketCloser socket_closer(sockets_.get(), fd);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_ifindex = interface_index;
  strcpy(ifr.ifr_ifrn.ifrn_name, info->name.c_str());  // NOLINT(runtime/printf)
  int err = sockets_->Ioctl(fd, SIOCGIFHWADDR, &ifr);
  if (err < 0) {
    PLOG(ERROR) << __func__ << ": Unable to read MAC address";
    return ByteString();
  }

  return ByteString(ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
}

bool DeviceInfo::GetMacAddressOfPeer(int interface_index,
                                     const IPAddress& peer,
                                     ByteString* mac_address) const {
  const Info* info = GetInfo(interface_index);
  if (!info || !peer.IsValid()) {
    return false;
  }

  if (peer.family() != IPAddress::kFamilyIPv4) {
    NOTIMPLEMENTED() << ": only implemented for IPv4";
    return false;
  }

  const int fd = sockets_->Socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    PLOG(ERROR) << __func__ << ": Unable to open socket";
    return false;
  }

  ScopedSocketCloser socket_closer(sockets_.get(), fd);
  struct arpreq areq;
  memset(&areq, 0, sizeof(areq));

  strncpy(areq.arp_dev, info->name.c_str(), sizeof(areq.arp_dev) - 1);
  areq.arp_dev[sizeof(areq.arp_dev) - 1] = '\0';

  struct sockaddr_in* protocol_address =
      reinterpret_cast<struct sockaddr_in*>(&areq.arp_pa);
  protocol_address->sin_family = AF_INET;
  CHECK_EQ(sizeof(protocol_address->sin_addr.s_addr), peer.GetLength());
  memcpy(&protocol_address->sin_addr.s_addr, peer.address().GetConstData(),
         sizeof(protocol_address->sin_addr.s_addr));

  struct sockaddr_in* effective_mac_address =
      reinterpret_cast<struct sockaddr_in*>(&areq.arp_ha);
  effective_mac_address->sin_family = ARPHRD_ETHER;

  int err = sockets_->Ioctl(fd, SIOCGARP, &areq);
  if (err < 0) {
    PLOG(ERROR) << __func__ << ": Unable to perform ARP lookup";
    return false;
  }

  ByteString peer_address(areq.arp_ha.sa_data, IFHWADDRLEN);

  if (peer_address.IsZero()) {
    LOG(INFO) << __func__ << ": ARP lookup is still in progress";
    return false;
  }

  CHECK(mac_address);
  *mac_address = peer_address;
  return true;
}

std::vector<IPAddress> DeviceInfo::GetAddresses(int interface_index) const {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    // Note that VirtualDevices may exist even after a relevant execution of
    // DelLinkMsgHandler, as the VirtualDevice client could retain ownership of
    // the instance. Therefore we handle this condition gracefully rather than
    // using a CHECK.
    LOG(WARNING) << "Attempted to get addresses from unknown interface index: "
                 << interface_index;
    return {};
  }

  std::vector<IPAddress> addresses;
  for (auto address_data : info->ip_addresses) {
    if (address_data.address.IsValid()) {
      addresses.push_back(address_data.address);
    }
  }
  return addresses;
}

void DeviceInfo::FlushAddresses(int interface_index) const {
  SLOG(this, 2) << __func__ << "(" << interface_index << ")";
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return;
  }
  for (const auto& address_info : info->ip_addresses) {
    if (address_info.address.family() == IPAddress::kFamilyIPv4 ||
        (address_info.scope == RT_SCOPE_UNIVERSE &&
         (address_info.flags & ~IFA_F_TEMPORARY) == 0)) {
      SLOG(this, 2) << __func__ << ": removing ip address "
                    << address_info.address.ToString() << " from interface "
                    << interface_index;
      rtnl_handler_->RemoveInterfaceAddress(interface_index,
                                            address_info.address);
    }
  }
}

bool DeviceInfo::HasOtherAddress(int interface_index,
                                 const IPAddress& this_address) const {
  SLOG(this, 3) << __func__ << "(" << interface_index << ")";
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return false;
  }
  bool has_other_address = false;
  bool has_this_address = false;
  for (const auto& local_address : info->ip_addresses) {
    if (local_address.address.family() != this_address.family()) {
      continue;
    }
    if (local_address.address.address().Equals(this_address.address())) {
      has_this_address = true;
    } else if (this_address.family() == IPAddress::kFamilyIPv4) {
      has_other_address = true;
    } else if ((local_address.scope == RT_SCOPE_UNIVERSE &&
                (local_address.flags & IFA_F_TEMPORARY) == 0)) {
      has_other_address = true;
    }
  }
  return has_other_address && !has_this_address;
}

const IPAddress* DeviceInfo::GetPrimaryIPv6Address(int interface_index) {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return nullptr;
  }
  bool has_temporary_address = false;
  bool has_current_address = false;
  const IPAddress* address = nullptr;
  for (const auto& local_address : info->ip_addresses) {
    if (local_address.address.family() != IPAddress::kFamilyIPv6 ||
        local_address.scope != RT_SCOPE_UNIVERSE) {
      continue;
    }

    // Prefer non-deprecated addresses to deprecated addresses to match the
    // kernel's preference.
    bool is_current_address = ((local_address.flags & IFA_F_DEPRECATED) == 0);
    if (has_current_address && !is_current_address) {
      continue;
    }

    // Prefer temporary addresses to non-temporary addresses to match the
    // kernel's preference.
    bool is_temporary_address = ((local_address.flags & IFA_F_TEMPORARY) != 0);
    if (has_temporary_address && !is_temporary_address) {
      continue;
    }

    address = &local_address.address;
    has_temporary_address = is_temporary_address;
    has_current_address = is_current_address;
  }

  return address;
}

bool DeviceInfo::GetIPv6DnsServerAddresses(int interface_index,
                                           std::vector<IPAddress>* address_list,
                                           uint32_t* life_time) {
  const Info* info = GetInfo(interface_index);
  if (!info || info->ipv6_dns_server_addresses.empty()) {
    return false;
  }

  // Determine the remaining DNS server life time.
  if (info->ipv6_dns_server_lifetime_seconds == ND_OPT_LIFETIME_INFINITY) {
    *life_time = ND_OPT_LIFETIME_INFINITY;
  } else {
    time_t cur_time;
    if (!time_->GetSecondsBoottime(&cur_time)) {
      NOTREACHED();
    }
    uint32_t time_elapsed = static_cast<uint32_t>(
        cur_time - info->ipv6_dns_server_received_time_seconds);
    if (time_elapsed >= info->ipv6_dns_server_lifetime_seconds) {
      *life_time = 0;
    } else {
      *life_time = info->ipv6_dns_server_lifetime_seconds - time_elapsed;
    }
  }
  *address_list = info->ipv6_dns_server_addresses;
  return true;
}

bool DeviceInfo::GetWiFiHardwareIds(int interface_index,
                                    int* vendor_id,
                                    int* product_id,
                                    int* subsystem_id) const {
  SLOG(this, 3) << __func__ << "(" << interface_index << ")";
  const Info* info = GetInfo(interface_index);
  if (!info) {
    LOG(ERROR) << "No DeviceInfo for interface index " << interface_index;
    return false;
  }
  if (info->technology != Technology::kWiFi) {
    LOG(ERROR) << info->name << " adapter reports for technology "
               << info->technology.GetName() << " not supported.";
    return false;
  }
  SLOG(this, 2) << info->name << " detecting adapter information";

  if (!base::PathIsReadable(
          GetDeviceInfoPath(info->name, kInterfaceVendorId))) {
    // TODO(b/203692510): Support integrated chipsets without PCIe/CNVi/SDIO
    // that do not have a "vendor" file.
    LOG(WARNING) << "No vendor ID found";
    return false;
  }
  bool ret = true;
  std::string content;
  int content_int;
  if (!GetDeviceInfoContents(info->name, kInterfaceVendorId, &content) ||
      !base::TrimString(content, "\n", &content) ||
      !base::HexStringToInt(content, &content_int)) {
    ret = false;
  } else {
    *vendor_id = content_int;
  }
  if (!GetDeviceInfoContents(info->name, kInterfaceDeviceId, &content) ||
      !base::TrimString(content, "\n", &content) ||
      !base::HexStringToInt(content, &content_int)) {
    ret = false;
  } else {
    *product_id = content_int;
  }
  // Devices with SDIO WiFi chipsets may not have a |subsystem_device| file.
  // Use 0 in that case.
  if (!base::PathIsReadable(
          GetDeviceInfoPath(info->name, kInterfaceSubsystemId))) {
    *subsystem_id = 0;
    return ret;
  }
  if (!GetDeviceInfoContents(info->name, kInterfaceSubsystemId, &content) ||
      !base::TrimString(content, "\n", &content) ||
      !base::HexStringToInt(content, &content_int)) {
    ret = false;
  } else {
    *subsystem_id = content_int;
  }
  return ret;
}

bool DeviceInfo::GetFlags(int interface_index, unsigned int* flags) const {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return false;
  }
  *flags = info->flags;
  return true;
}

bool DeviceInfo::GetByteCounts(int interface_index,
                               uint64_t* rx_bytes,
                               uint64_t* tx_bytes) const {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return false;
  }
  *rx_bytes = info->rx_bytes;
  *tx_bytes = info->tx_bytes;
  return true;
}

void DeviceInfo::AddVirtualInterfaceReadyCallback(
    const std::string& interface_name, LinkReadyCallback callback) {
  if (pending_links_.erase(interface_name) > 0) {
    PLOG(WARNING) << "Callback for RTNL link ready event of " << interface_name
                  << " already existed, overwritten";
  }
  pending_links_.emplace(interface_name, std::move(callback));
}

bool DeviceInfo::CreateTunnelInterface(LinkReadyCallback callback) {
  int fd = HANDLE_EINTR(open(kTunDeviceName, O_RDWR | O_CLOEXEC));
  if (fd < 0) {
    PLOG(ERROR) << "failed to open " << kTunDeviceName;
    return false;
  }
  base::ScopedFD scoped_fd(fd);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (HANDLE_EINTR(ioctl(fd, TUNSETIFF, &ifr))) {
    PLOG(ERROR) << "failed to create tunnel interface";
    return false;
  }

  if (HANDLE_EINTR(ioctl(fd, TUNSETPERSIST, 1))) {
    PLOG(ERROR) << "failed to set tunnel interface to be persistent";
    return false;
  }

  if (callback) {
    std::string ifname(ifr.ifr_name);
    AddVirtualInterfaceReadyCallback(ifname, std::move(callback));
  }
  return true;
}

int DeviceInfo::OpenTunnelInterface(const std::string& interface_name) const {
  int fd = HANDLE_EINTR(open(kTunDeviceName, O_RDWR | O_CLOEXEC));
  if (fd < 0) {
    PLOG(ERROR) << "failed to open " << kTunDeviceName;
    return -1;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (HANDLE_EINTR(ioctl(fd, TUNSETIFF, &ifr))) {
    PLOG(ERROR) << "failed to set tunnel interface name";
    return -1;
  }

  return fd;
}

bool DeviceInfo::CreateWireGuardInterface(const std::string& interface_name,
                                          LinkReadyCallback link_ready_callback,
                                          base::OnceClosure failure_callback) {
  if (!rtnl_handler_->AddInterface(
          interface_name, kKindWireGuard, {},
          base::BindOnce(&DeviceInfo::OnCreateInterfaceResponse,
                         weak_factory_.GetWeakPtr(), interface_name,
                         std::move(failure_callback)))) {
    return false;
  }
  AddVirtualInterfaceReadyCallback(interface_name,
                                   std::move(link_ready_callback));
  return true;
}

bool DeviceInfo::CreateXFRMInterface(const std::string& interface_name,
                                     int underlying_if_index,
                                     int xfrm_if_id,
                                     LinkReadyCallback link_ready_callback,
                                     base::OnceClosure failure_callback) {
  RTNLAttrMap attrs;
  attrs[kIflaXfrmLink] = ByteString::CreateFromCPUUInt32(underlying_if_index);
  attrs[kIflaXfrmIfId] = ByteString::CreateFromCPUUInt32(xfrm_if_id);
  const ByteString link_info_data = RTNLMessage::PackAttrs(attrs);
  if (!rtnl_handler_->AddInterface(
          interface_name, kKindXfrm, link_info_data,
          base::BindOnce(&DeviceInfo::OnCreateInterfaceResponse,
                         weak_factory_.GetWeakPtr(), interface_name,
                         std::move(failure_callback)))) {
    return false;
  }
  AddVirtualInterfaceReadyCallback(interface_name,
                                   std::move(link_ready_callback));
  return true;
}

PPPDevice* DeviceInfo::CreatePPPDevice(Manager* manager,
                                       const std::string& ifname,
                                       int ifindex) {
#if !defined(DISABLE_CELLULAR) || !defined(DISABLE_VPN)
  return new PPPDevice(manager, ifname, ifindex);
#else
  return nullptr;
#endif
}

void DeviceInfo::OnCreateInterfaceResponse(const std::string& interface_name,
                                           base::OnceClosure failure_callback,
                                           int32_t error) {
  if (error == 0) {
    // |error| == 0 means ACK. Needs to do nothing here. We expect getting the
    // new interface message latter.
    return;
  }

  LOG(ERROR) << "Failed to create wireguard interface " << interface_name
             << ", error code=" << error;
  if (pending_links_.erase(interface_name) != 1) {
    LOG(WARNING)
        << "Failed to remove link ready callback from |pending_links_| for "
        << interface_name;
  }
  std::move(failure_callback).Run();
}

bool DeviceInfo::DeleteInterface(int interface_index) const {
  return rtnl_handler_->RemoveInterface(interface_index);
}

const DeviceInfo::Info* DeviceInfo::GetInfo(int interface_index) const {
  std::map<int, Info>::const_iterator iter = infos_.find(interface_index);
  if (iter == infos_.end()) {
    return nullptr;
  }
  return &iter->second;
}

void DeviceInfo::DeregisterDevice(int interface_index) {
  auto iter = infos_.find(interface_index);
  if (iter == infos_.end()) {
    SLOG(this, 2) << __func__ << ": Unknown device index: " << interface_index;
    return;
  }

  SLOG(this, 1) << __func__ << " index: " << interface_index;
  // Deregister the device if not deregistered yet.
  if (iter->second.device.get()) {
    manager_->DeregisterDevice(iter->second.device);
    metrics_->DeregisterDevice(interface_index);
    routing_table_->DeregisterDevice(iter->second.device->interface_index(),
                                     iter->second.device->link_name());
  }
  indices_.erase(iter->second.name);
  infos_.erase(iter);
  delayed_devices_.erase(interface_index);
}

void DeviceInfo::LinkMsgHandler(const RTNLMessage& msg) {
  DCHECK(msg.type() == RTNLMessage::kTypeLink);
  if (msg.mode() == RTNLMessage::kModeAdd) {
    AddLinkMsgHandler(msg);
  } else if (msg.mode() == RTNLMessage::kModeDelete) {
    DelLinkMsgHandler(msg);
  } else {
    NOTREACHED();
  }
}

void DeviceInfo::AddressMsgHandler(const RTNLMessage& msg) {
  SLOG(this, 2) << __func__;
  DCHECK(msg.type() == RTNLMessage::kTypeAddress);
  const RTNLMessage::AddressStatus& status = msg.address_status();
  IPAddress address(msg.family(),
                    msg.HasAttribute(IFA_LOCAL) ? msg.GetAttribute(IFA_LOCAL)
                                                : msg.GetAttribute(IFA_ADDRESS),
                    status.prefix_len);

  int interface_index = msg.interface_index();
  SLOG_IF(Device, 2, msg.HasAttribute(IFA_LOCAL))
      << "Found local address attribute for interface " << interface_index;

  auto& address_list = infos_[interface_index].ip_addresses;
  std::vector<AddressData>::iterator iter;
  for (iter = address_list.begin(); iter != address_list.end(); ++iter) {
    if (address.Equals(iter->address)) {
      break;
    }
  }
  if (iter != address_list.end()) {
    if (msg.mode() == RTNLMessage::kModeDelete) {
      SLOG(this, 2) << "Delete address for interface " << interface_index;
      address_list.erase(iter);
    } else {
      iter->flags = status.flags;
      iter->scope = status.scope;
    }
  } else if (msg.mode() == RTNLMessage::kModeAdd) {
    address_list.push_back(AddressData(address, status.flags, status.scope));
    SLOG(this, 2) << "Add address " << address.ToString() << " for interface "
                  << interface_index;
  }

  DeviceRefPtr device = GetDevice(interface_index);
  if (!device)
    return;

  if (address.family() == IPAddress::kFamilyIPv6 &&
      status.scope == RT_SCOPE_UNIVERSE) {
    device->OnIPv6AddressChanged(GetPrimaryIPv6Address(interface_index));
  }

  if (device->connection()) {
    // Connection::UpdateRoutingPolicy uses DeviceInfo::GetAddresses to
    // determine an interface's assigned addresses. Thus a modification to
    // |address_list| should cause UpdateRoutingPolicy to retrigger.
    //
    // If in the future, IPConfig is modified to contain the entire IP
    // configuration for a Connection (which it necessarily cannot currently do
    // when an interface has both IPv4 and v6), then Connection will no longer
    // need to rely on DeviceInfo and this can be removed.
    device->connection()->UpdateRoutingPolicy();
  }
}

void DeviceInfo::RdnssMsgHandler(const RTNLMessage& msg) {
  SLOG(this, 2) << __func__;
  DCHECK(msg.type() == RTNLMessage::kTypeRdnss);
  int interface_index = msg.interface_index();
  if (!base::Contains(infos_, interface_index)) {
    SLOG(this, 2) << "Got RDNSS option for unknown index " << interface_index;
  }

  const RTNLMessage::RdnssOption& rdnss_option = msg.rdnss_option();
  infos_[interface_index].ipv6_dns_server_lifetime_seconds =
      rdnss_option.lifetime;
  infos_[interface_index].ipv6_dns_server_addresses = rdnss_option.addresses;
  if (!time_->GetSecondsBoottime(
          &infos_[interface_index].ipv6_dns_server_received_time_seconds)) {
    NOTREACHED();
  }

  // Notify device of the IPv6 DNS server addresses update.
  DeviceRefPtr device = GetDevice(interface_index);
  if (device) {
    device->OnIPv6DnsServerAddressesChanged();
  }
}

void DeviceInfo::DelayDeviceCreation(int interface_index) {
  delayed_devices_.insert(interface_index);
  delayed_devices_callback_.Reset(base::Bind(
      &DeviceInfo::DelayedDeviceCreationTask, weak_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(FROM_HERE, delayed_devices_callback_.callback(),
                               kDelayedDeviceCreation);
}

// Re-evaluate the technology type for each delayed device.
void DeviceInfo::DelayedDeviceCreationTask() {
  while (!delayed_devices_.empty()) {
    const auto it = delayed_devices_.begin();
    int dev_index = *it;
    delayed_devices_.erase(it);

    DCHECK(base::Contains(infos_, dev_index));
    DCHECK(!GetDevice(dev_index));

    const std::string& link_name = infos_[dev_index].name;
    Technology technology = GetDeviceTechnology(link_name, std::nullopt);

    if (technology == Technology::kCDCEthernet) {
      LOG(INFO) << "In " << __func__ << ": device " << link_name
                << " is now assumed to be regular Ethernet.";
      technology = Technology::kEthernet;
    } else if (technology == Technology::kNoDeviceSymlink) {
      if (manager_->ignore_unknown_ethernet()) {
        SLOG(this, 2) << __func__ << ": device " << link_name
                      << ", without driver name will be ignored";
        technology = Technology::kUnknown;
      } else {
        // Act the same as if there was a driver symlink, but we did not
        // recognize the driver name.
        SLOG(this, 2) << __func__ << ": device " << link_name
                      << ", without driver name is defaulted to type ethernet";
        technology = Technology::kEthernet;
      }
    } else if (technology != Technology::kCellular &&
               technology != Technology::kTunnel &&
               technology != Technology::kGuestInterface) {
      LOG(WARNING) << "In " << __func__ << ": device " << link_name
                   << " is unexpected technology " << technology;
    }

    std::string address = infos_[dev_index].mac_address.HexEncode();
    int arp_type = GetDeviceArpType(link_name);

    // NB: ARHRD_RAWIP was introduced in kernel 4.14.
    if (technology != Technology::kTunnel &&
        technology != Technology::kUnknown && arp_type != ARPHRD_RAWIP) {
      DCHECK(!address.empty());
    }

    DeviceRefPtr device =
        CreateDevice(link_name, address, dev_index, technology);
    if (device) {
      RegisterDevice(device);
    }
  }
}

void DeviceInfo::RetrieveLinkStatistics(int interface_index,
                                        const RTNLMessage& msg) {
  if (!msg.HasAttribute(IFLA_STATS64)) {
    return;
  }
  ByteString stats_bytes(msg.GetAttribute(IFLA_STATS64));
  struct old_rtnl_link_stats64 stats;
  if (stats_bytes.GetLength() < sizeof(stats)) {
    LOG(WARNING) << "Link statistics size is too small: "
                 << stats_bytes.GetLength() << " < " << sizeof(stats);
    return;
  }

  memcpy(&stats, stats_bytes.GetConstData(), sizeof(stats));
  SLOG(this, 2) << "Link statistics for "
                << " interface index " << interface_index << ": "
                << "receive: " << stats.rx_bytes << "; "
                << "transmit: " << stats.tx_bytes << ".";
  infos_[interface_index].rx_bytes = stats.rx_bytes;
  infos_[interface_index].tx_bytes = stats.tx_bytes;
}

void DeviceInfo::RequestLinkStatistics() {
  rtnl_handler_->RequestDump(RTNLHandler::kRequestLink);
  dispatcher_->PostDelayedTask(FROM_HERE,
                               request_link_statistics_callback_.callback(),
                               kRequestLinkStatisticsInterval);
}

#if !defined(DISABLE_WIFI)
void DeviceInfo::GetWiFiInterfaceInfo(int interface_index) {
  GetInterfaceMessage msg;
  if (!msg.attributes()->SetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                              interface_index)) {
    LOG(ERROR) << "Unable to set interface index attribute for "
                  "GetInterface message.  Interface type cannot be "
                  "determined!";
    return;
  }
  netlink_manager_->SendNl80211Message(
      &msg,
      base::Bind(&DeviceInfo::OnWiFiInterfaceInfoReceived,
                 weak_factory_.GetWeakPtr()),
      base::Bind(&NetlinkManager::OnAckDoNothing),
      base::Bind(&NetlinkManager::OnNetlinkMessageError));
}

void DeviceInfo::OnWiFiInterfaceInfoReceived(const Nl80211Message& msg) {
  if (msg.command() != NL80211_CMD_NEW_INTERFACE) {
    LOG(ERROR) << "Message is not a new interface response";
    return;
  }

  uint32_t interface_index;
  if (!msg.const_attributes()->GetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                                    &interface_index)) {
    LOG(ERROR) << "Message contains no interface index";
    return;
  }
  uint32_t interface_type;
  if (!msg.const_attributes()->GetU32AttributeValue(NL80211_ATTR_IFTYPE,
                                                    &interface_type)) {
    LOG(ERROR) << "Message contains no interface type";
    return;
  }
  const Info* info = GetInfo(interface_index);
  if (!info) {
    LOG(ERROR) << "Could not find device info for interface index "
               << interface_index;
    return;
  }
  if (info->device) {
    LOG(ERROR) << "Device already created for interface index "
               << interface_index;
    return;
  }
  if (interface_type != NL80211_IFTYPE_STATION) {
    LOG(INFO) << "Ignoring WiFi device " << info->name << " at interface index "
              << interface_index << " since it is not in station mode.";
    return;
  }
  LOG(INFO) << "Creating WiFi device for station mode interface " << info->name
            << " at interface index " << interface_index;
  std::string address = info->mac_address.HexEncode();

#if !defined(DISABLE_WAKE_ON_WIFI)
  auto wake_on_wifi = std::make_unique<WakeOnWiFi>(
      netlink_manager_, dispatcher_, metrics_,
      base::Bind(&DeviceInfo::RecordDarkResumeWakeReason,
                 weak_factory_.GetWeakPtr()));
#else
  auto wake_on_wifi = std::unique_ptr<WakeOnWiFi>(nullptr);
#endif  // DISABLE_WAKE_ON_WIFI
  DeviceRefPtr device = new WiFi(manager_, info->name, address, interface_index,
                                 std::move(wake_on_wifi));
  device->EnableIPv6Privacy();
  RegisterDevice(device);
}

void DeviceInfo::RecordDarkResumeWakeReason(const std::string& wake_reason) {
  manager_->power_manager()->RecordDarkResumeWakeReason(wake_reason);
}

#endif  // DISABLE_WIFI

bool DeviceInfo::SetHostname(const std::string& hostname) const {
  if (sethostname(hostname.c_str(), hostname.length())) {
    PLOG(ERROR) << "Failed to set hostname to: " << hostname;
    return false;
  }

  return true;
}

// Verifies if a device is guest by checking if the owner of the device
// identified by |interface_name| has the same UID as the user that runs the
// Crostini VMs.
bool DeviceInfo::IsGuestDevice(const std::string& interface_name) const {
  std::string owner;
  if (!GetDeviceInfoContents(interface_name, kInterfaceOwner, &owner)) {
    return false;
  }
  uint32_t owner_id;
  base::TrimWhitespaceASCII(owner, base::TRIM_ALL, &owner);
  if (!base::StringToUint(owner, &owner_id)) {
    return false;
  }

  uid_t crosvm_user_uid;
  if (!GetUserId(vm_tools::kCrosVmUser, &crosvm_user_uid)) {
    LOG(WARNING) << "unable to get uid for " << vm_tools::kCrosVmUser;
    return false;
  }

  return owner_id == crosvm_user_uid;
}

void DeviceInfo::OnPatchpanelClientReady() {
  manager_->patchpanel_client()->RegisterNeighborReachabilityEventHandler(
      base::BindRepeating(&DeviceInfo::OnNeighborReachabilityEvent,
                          weak_factory_.GetWeakPtr()));
}

void DeviceInfo::OnNeighborReachabilityEvent(
    const patchpanel::NeighborReachabilityEventSignal& signal) {
  SLOG(this, 2) << __func__ << ": interface index: " << signal.ifindex()
                << ", ip address: " << signal.ip_addr()
                << ", role: " << signal.role() << ", type: " << signal.type();
  using SignalProto = patchpanel::NeighborReachabilityEventSignal;

  auto device = GetDevice(signal.ifindex());
  if (!device) {
    LOG(ERROR) << "Device not found for interface index " << signal.ifindex();
    return;
  }

  IPAddress address(signal.ip_addr());
  if (!address.IsValid()) {
    LOG(ERROR) << "Invalid IP address " << signal.ip_addr();
    return;
  }

  switch (signal.type()) {
    case SignalProto::FAILED:
    case SignalProto::REACHABLE:
      device->OnNeighborReachabilityEvent(address, signal.role(),
                                          signal.type());
      return;
    default:
      LOG(ERROR) << "Invalid NeighborRecabilityEvent type " << signal.type();
  }
}

bool DeviceInfo::GetUserId(const std::string& user_name, uid_t* uid) const {
  return brillo::userdb::GetUserInfo(user_name, uid, nullptr);
}

DeviceInfo::Info::Info()
    : flags(0),
      rx_bytes(0),
      tx_bytes(0),
      received_add_link(false),
      technology(Technology::kUnknown) {}

}  // namespace shill
