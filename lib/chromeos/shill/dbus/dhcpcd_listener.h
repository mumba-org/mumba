// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_DHCPCD_LISTENER_H_
#define SHILL_DBUS_DHCPCD_LISTENER_H_

#include <string>

#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <brillo/variant_dictionary.h>
#include <dbus/bus.h>
#include <dbus/message.h>

#include "shill/network/dhcpcd_listener_interface.h"

namespace shill {

class DHCPProvider;
class EventDispatcher;

// The DHCPCD listener is a singleton proxy that listens to signals from all
// DHCP clients and dispatches them through the DHCP provider to the appropriate
// client based on the PID.
class DHCPCDListener final : public DHCPCDListenerInterface {
 public:
  DHCPCDListener(const scoped_refptr<dbus::Bus>& bus,
                 EventDispatcher* dispatcher,
                 DHCPProvider* provider);
  DHCPCDListener(const DHCPCDListener&) = delete;
  DHCPCDListener& operator=(const DHCPCDListener&) = delete;

  ~DHCPCDListener() override;

 private:
  static const char kDBusInterfaceName[];
  static const char kSignalEvent[];
  static const char kSignalStatusChanged[];

  // Redirects the function call to HandleMessage
  static DBusHandlerResult HandleMessageThunk(DBusConnection* connection,
                                              DBusMessage* raw_message,
                                              void* user_data);

  // Handles incoming messages.
  DBusHandlerResult HandleMessage(DBusConnection* connection,
                                  DBusMessage* raw_message);

  // Signal handlers.
  void EventSignal(const std::string& sender,
                   uint32_t pid,
                   const std::string& reason,
                   const brillo::VariantDictionary& configurations);
  void StatusChangedSignal(const std::string& sender,
                           uint32_t pid,
                           const std::string& status);

  scoped_refptr<dbus::Bus> bus_;
  EventDispatcher* dispatcher_;
  DHCPProvider* provider_;
  const std::string match_rule_;

  base::WeakPtrFactory<DHCPCDListener> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_DHCPCD_LISTENER_H_
