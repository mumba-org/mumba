// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_GUEST_TYPE_H_
#define PATCHPANEL_GUEST_TYPE_H_

#include <ostream>

namespace patchpanel {

// Enum reprensenting the different types of downstream guests managed by
// patchpanel. The guest types corresponding to patchpanel Devices
// created by patchpanel directly are: ARC0, ARC_NET, VM_TERMINA, VM_PLUGIN.
// LXD_CONTAINER corresponds to user containers created inside a Termina VM.
// MINIJAIL_NETNS corresponds to a network namespace attached to the datapath
// with patchpanel ConnectNamespace API.
enum class GuestType {
  // ARC++ or ARCVM management interface.
  ARC0,
  // ARC++ or ARCVM virtual networks connected to shill Devices.
  ARC_NET,
  /// Crostini VM root namespace.
  VM_TERMINA,
  // Crostini plugin VMs.
  VM_PLUGIN,
  // Crostini VM user containers.
  LXD_CONTAINER,
  // Other network namespaces hosting minijailed host processes.
  MINIJAIL_NETNS,
};

std::ostream& operator<<(std::ostream& stream, const GuestType guest_type);

}  // namespace patchpanel

#endif  // PATCHPANEL_GUEST_TYPE_H_
