// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VM_LAUNCH_INTERFACE_H_
#define VM_TOOLS_CONCIERGE_VM_LAUNCH_INTERFACE_H_

#include <string>

#include <base/memory/scoped_refptr.h>

#include "vm_tools/common/vm_id.h"

namespace dbus {
class Bus;
class ObjectProxy;
}  // namespace dbus

namespace vm_tools {
namespace concierge {

enum VmInfo_VmType : int;

class VmLaunchInterface {
 public:
  explicit VmLaunchInterface(scoped_refptr<dbus::Bus> bus);
  ~VmLaunchInterface();

  VmLaunchInterface(const VmLaunchInterface&) = delete;
  VmLaunchInterface& operator=(const VmLaunchInterface&) = delete;

  // Requests a custom wayland server for VMs of type |classification| from
  // chrome, which will be used by the VM with the given |vm_id|. This process
  // is document in go/secure-exo-ids. Returns a path to the server's socket on
  // success, or "" on failure.
  std::string GetWaylandSocketForVm(const VmId& vm_id,
                                    VmInfo_VmType classification);

 private:
  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectProxy* proxy_;  // owned by |bus_|
};

}  // namespace concierge
}  // namespace vm_tools

#endif  //  VM_TOOLS_CONCIERGE_VM_LAUNCH_INTERFACE_H_
