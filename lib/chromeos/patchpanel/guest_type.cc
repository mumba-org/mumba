// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/guest_type.h"

namespace patchpanel {

std::ostream& operator<<(std::ostream& stream, const GuestType guest_type) {
  switch (guest_type) {
    case GuestType::ARC0:
      return stream << "ARC0";
    case GuestType::ARC_NET:
      return stream << "ARC_NET";
    case GuestType::VM_TERMINA:
      return stream << "VM_TERMINA";
    case GuestType::VM_PLUGIN:
      return stream << "VM_PLUGIN";
    case GuestType::LXD_CONTAINER:
      return stream << "LXD_CONTAINER";
    case GuestType::MINIJAIL_NETNS:
      return stream << "MINIJAIL_NETNS";
    default:
      return stream << "UNKNOWN";
  }
}

}  // namespace patchpanel
