// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

//#include <base/check.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/threading/thread.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/system/invitation.h>

#include "arc/vm/sensor_service/dbus_adaptors/org.chromium.ArcSensorService.h"
#include "arc/vm/sensor_service/sensor_service_impl.h"

namespace {

class DBusAdaptor : public org::chromium::ArcSensorServiceAdaptor,
                    public org::chromium::ArcSensorServiceInterface {
 public:
  explicit DBusAdaptor(scoped_refptr<dbus::Bus> bus)
      : org::chromium::ArcSensorServiceAdaptor(this),
        dbus_object_(nullptr, bus, GetObjectPath()) {}

  ~DBusAdaptor() override = default;

  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;

  void RegisterAsync(
      const brillo::dbus_utils::AsyncEventSequencer::CompletionAction& cb) {
    RegisterWithDBusObject(&dbus_object_);
    dbus_object_.RegisterAsync(cb);
  }

  // org::chromium::ArcSensorServiceInterface overrides:
  bool BootstrapMojoConnection(brillo::ErrorPtr* error,
                               const base::ScopedFD& in_handle,
                               const std::string& in_token) override {
    mojo::IncomingInvitation invitation =
        mojo::IncomingInvitation::Accept(mojo::PlatformChannelEndpoint(
            mojo::PlatformHandle(base::ScopedFD(dup(in_handle.get())))));
    mojo::ScopedMessagePipeHandle child_pipe =
        invitation.ExtractMessagePipe(in_token);

    service_ = std::make_unique<arc::SensorServiceImpl>();
    if (!service_->Initialize(mojo::PendingReceiver<arc::mojom::SensorService>(
            std::move(child_pipe)))) {
      LOG(ERROR) << "Failed to initialize SensorServiceImpl.";
      return false;
    }
    return true;
  }

 private:
  brillo::dbus_utils::DBusObject dbus_object_;
  std::unique_ptr<arc::SensorServiceImpl> service_;
};

class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon() : DBusServiceDaemon(arc::sensor::kArcSensorServiceServiceName) {}
  ~Daemon() override = default;

  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    adaptor_ = std::make_unique<DBusAdaptor>(bus_);
    adaptor_->RegisterAsync(
        sequencer->GetHandler("RegisterAsync() failed.", true));
  }

 private:
  std::unique_ptr<DBusAdaptor> adaptor_;
};

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  base::Thread mojo_ipc_thread("mojo IPC thread");
  CHECK(mojo_ipc_thread.StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0)));
  mojo::core::Init();
  mojo::core::ScopedIPCSupport ipc_support(
      mojo_ipc_thread.task_runner(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);

  return Daemon().Run();
}
