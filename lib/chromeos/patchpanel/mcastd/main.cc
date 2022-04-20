// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/bind.h>
#include <base/command_line.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <brillo/daemons/daemon.h>

#include "patchpanel/multicast_forwarder.h"

// Stand-alone daemon to proxy mDNS and SSDP packets between a pair of
// interfaces. Usage: mcastd $physical_ifname $guest_ifname
int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  base::CommandLine::StringVector args = cl->GetArgs();
  if (args.size() < 2) {
    LOG(ERROR) << "Usage: " << cl->GetProgram().BaseName().value()
               << " [physical interface name] [guest interface name]";
    return EXIT_FAILURE;
  }

  brillo::Daemon daemon;

  auto mdns_fwd = std::make_unique<patchpanel::MulticastForwarder>(
      args[0], patchpanel::kMdnsMcastAddress, patchpanel::kMdnsMcastAddress6,
      patchpanel::kMdnsPort);
  mdns_fwd->Init();

  auto ssdp_fwd = std::make_unique<patchpanel::MulticastForwarder>(
      args[0], patchpanel::kSsdpMcastAddress, patchpanel::kSsdpMcastAddress6,
      patchpanel::kSsdpPort);
  ssdp_fwd->Init();

  // Crostini depends on another daemon (LXD) creating the guest bridge
  // interface. This can take a few seconds, so retry if necessary.
  bool added_mdns = false, added_ssdp = false;
  for (int i = 0; i < 10; i++) {
    added_mdns = added_mdns || mdns_fwd->AddGuest(args[1]);
    added_ssdp = added_ssdp || ssdp_fwd->AddGuest(args[1]);
    if (added_mdns && added_ssdp)
      break;
    usleep(1000 * 1000 /* 1 second */);
  }
  if (!added_mdns)
    LOG(ERROR) << "mDNS forwarder could not be started on " << args[0]
               << " and " << args[1];
  if (!added_ssdp)
    LOG(ERROR) << "SSDP forwarder could not be started on " << args[0]
               << " and " << args[1];
  if (!added_mdns || !added_ssdp)
    return EXIT_FAILURE;

  return daemon.Run();
}
