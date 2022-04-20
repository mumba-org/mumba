// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_SYSTEM_H_
#define PATCHPANEL_SYSTEM_H_

#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <map>
#include <string>

namespace patchpanel {

// cros lint will yell to force using int16/int64 instead of long here, however
// note that unsigned long IS the correct signature for ioctl in Linux kernel -
// it's 32 bits on 32-bit platform and 64 bits on 64-bit one.
using ioctl_req_t = unsigned long;  // NOLINT(runtime/int)

// Class used for:
//  - holding all utility functions with side effects on the environment.
//  - wrapping commonly used system calls.
// This class facilitates mocking these functions in unit tests.
class System {
 public:
  // Enum used for restricting the possible paths that SysNetSet can write to.
  enum SysNet {
    // Used for modifying "net.ipv4.ip_forward"
    IPv4Forward = 1,
    // Used for modifying "net.ipv4.ip_local_port_range"
    IPLocalPortRange,
    // Used for modifying "net.ipv4.conf.%s.route_localnet", requires an
    // interface
    // argument
    IPv4RouteLocalnet,
    // Used for modifying "net.ipv6.conf.%s.accept_ra", requires an interface
    // argument
    IPv6AcceptRA,
    // Used for modifying "net.ipv6.conf.all.forwarding"
    IPv6Forward,
    // Used for enabling netfilter connection tracking helper modules.
    ConntrackHelper,
    // Used for modifying "net.ipv6.conf.all.disable_ipv6"
    IPv6Disable,
  };

  System() = default;
  System(const System&) = delete;
  System& operator=(const System&) = delete;
  virtual ~System() = default;

  // Write |content| to a "/proc/sys/net/" path as specified by |target|
  virtual bool SysNetSet(SysNet target,
                         const std::string& content,
                         const std::string& iface = "");

  virtual int Ioctl(int fd, ioctl_req_t request, const char* argp);
  int Ioctl(int fd, ioctl_req_t request, uint64_t arg);
  int Ioctl(int fd, ioctl_req_t request, struct ifreq* ifr);
  int Ioctl(int fd, ioctl_req_t request, struct rtentry* route);

  virtual pid_t WaitPid(pid_t pid, int* wstatus, int options = 0);

  // Return the interface name of the network interface with index |ifindex|, or
  // empty string if it fails.
  virtual std::string IfIndextoname(int ifindex);
  // Return the index of the interface with name |ifname|, or 0 if it fails.
  virtual uint32_t IfNametoindex(const std::string& ifname);

  static bool Write(const std::string& path, const std::string& content);

 private:
  // A map used for remembering the interface index of an interface. This
  // information is necessary when cleaning up the state of various subsystems
  // in patchpanel that directly references the interface index. However after
  // receiving the interface removal event (RTM_DELLINK event or shill DBus
  // event), the interface index cannot be retrieved anymore. A new entry is
  // only added when a new upstream network interface appears, and entries are
  // not removed.
  std::map<std::string, int> if_nametoindex_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_SYSTEM_H_
