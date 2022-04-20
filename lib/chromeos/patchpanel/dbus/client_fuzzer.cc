// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <net/if.h>

#include <base/callback_helpers.h>
#include <base/logging.h>
#include <dbus/message.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "patchpanel/dbus/client.h"

namespace patchpanel {

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
};

class FakeObjectProxy : public dbus::ObjectProxy {
 public:
  explicit FakeObjectProxy(dbus::Bus* bus)
      : dbus::ObjectProxy(bus, "svc", dbus::ObjectPath("/obj/path"), 0) {}

  std::unique_ptr<dbus::Response> CallMethodAndBlockWithErrorDetails(
      dbus::MethodCall* method_call,
      int timeout_ms,
      dbus::ScopedDBusError* error) override {
    return nullptr;
  }

  std::unique_ptr<dbus::Response> CallMethodAndBlock(
      dbus::MethodCall* method_call, int timeout_ms) override {
    return nullptr;
  }

  void CallMethod(dbus::MethodCall* method_call,
                  int timeout_ms,
                  ResponseCallback callback) override {}

  void CallMethodWithErrorResponse(dbus::MethodCall* method_call,
                                   int timeout_ms,
                                   ResponseOrErrorCallback callback) override {}

  void CallMethodWithErrorCallback(dbus::MethodCall* method_call,
                                   int timeout_ms,
                                   ResponseCallback callback,
                                   ErrorCallback error_callback) override {}

  void ConnectToSignal(const std::string& interface_name,
                       const std::string& signal_name,
                       SignalCallback signal_callback,
                       OnConnectedCallback on_connected_callback) override {}

  void WaitForServiceToBeAvailable(
      WaitForServiceToBeAvailableCallback callback) override {}

  void Detach() override {}
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  dbus::Bus::Options options;
  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);
  scoped_refptr<dbus::ObjectProxy> proxy(new FakeObjectProxy(bus.get()));
  auto client = Client::New(bus, proxy.get());
  FuzzedDataProvider provider(data, size);

  while (provider.remaining_bytes() > 0) {
    client->NotifyArcStartup(provider.ConsumeIntegral<pid_t>());
    client->NotifyArcVmStartup(provider.ConsumeIntegral<uint32_t>());
    client->NotifyArcVmShutdown(provider.ConsumeIntegral<uint32_t>());
    NetworkDevice device;
    device.set_ifname(provider.ConsumeRandomLengthString(IFNAMSIZ * 2));
    device.set_ipv4_addr(provider.ConsumeIntegral<uint32_t>());
    device.mutable_ipv4_subnet()->set_base_addr(
        provider.ConsumeIntegral<uint32_t>());
    device.mutable_ipv4_subnet()->set_prefix_len(
        provider.ConsumeIntegral<uint32_t>());
    IPv4Subnet subnet;
    subnet.set_base_addr(provider.ConsumeIntegral<uint32_t>());
    subnet.set_prefix_len(provider.ConsumeIntegral<uint32_t>());
    client->NotifyTerminaVmStartup(provider.ConsumeIntegral<uint32_t>(),
                                   &device, &subnet);
    client->NotifyTerminaVmShutdown(provider.ConsumeIntegral<uint32_t>());
    client->NotifyPluginVmStartup(provider.ConsumeIntegral<uint64_t>(),
                                  provider.ConsumeIntegral<int>(), &device);
    client->NotifyPluginVmShutdown(provider.ConsumeIntegral<uint64_t>());
    // TODO(garrick): Enable the following once the memory leaks in Chrome OS
    // DBus are resolved.
    //    client->DefaultVpnRouting(provider.ConsumeIntegral<int>());
    //    client->RouteOnVpn(provider.ConsumeIntegral<int>());
    //    client->BypassVpn(provider.ConsumeIntegral<int>());
    client->ConnectNamespace(provider.ConsumeIntegral<pid_t>(),
                             provider.ConsumeRandomLengthString(100),
                             provider.ConsumeBool(), provider.ConsumeBool(),
                             TrafficCounter::SYSTEM);
    std::set<std::string> devices_for_counters;
    for (int i = 0; i < 10; i++) {
      if (provider.ConsumeBool()) {
        devices_for_counters.insert(
            provider.ConsumeRandomLengthString(IFNAMSIZ * 2));
      }
    }
    client->GetTrafficCounters(devices_for_counters, base::DoNothing());
  }
  bus->ShutdownAndBlock();
  return 0;
}

}  // namespace patchpanel
