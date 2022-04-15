// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_USB_CONTROL_H_
#define VM_TOOLS_CONCIERGE_USB_CONTROL_H_

#include <stdint.h>
#include <string>
#include <vector>

namespace vm_tools {
namespace concierge {

// Response type of usb command.
enum UsbControlResponseType {
  OK,                   // Format: "ok <port_id>"
  NO_AVAILABLE_PORT,    // Format: "no_available_port"
  NO_SUCH_DEVICE,       // Format: "no_such_device"
  NO_SUCH_PORT,         // Format: "no_such_port"
  FAIL_TO_OPEN_DEVICE,  // Format: "fail_to_open_device"
  DEVICES,              // Format: "devices <port> <vid> <pid>"
  ERROR,                // Format: "error <reason>"
};

// A device connected to guest kernel.
struct UsbDevice {
  uint8_t port;
  uint16_t vid;
  uint16_t pid;
};

// Response type from crosvm usb control commands.
struct UsbControlResponse {
  UsbControlResponseType type;
  std::string reason;              // type_ == ERROR
  std::vector<UsbDevice> devices;  // type_ == DEVICES
  uint8_t port;                    // type_ == OK
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_USB_CONTROL_H_
