// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_manager_host.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"
#include "net/rpc/server/rpc_socket_client.h"
#include "net/rpc/server/proxy_rpc_handler.h"
#include "core/host/ui/tablist/tablist.h"
#include "core/host/ui/tablist/dock_tablist.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/navigator_params.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_commands.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/url_data_manager.h"
#include "core/host/application/application_controller.h"
#include "ui/base/window_open_disposition.h"
#include "url/gurl.h"

namespace host {

ApplicationManagerHost::ApplicationManagerHost(ApplicationController* application_controller):
 application_manager_host_binding_(this),
 application_controller_(application_controller),
 shutdown_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED) {

}

ApplicationManagerHost::~ApplicationManagerHost() {

}

void ApplicationManagerHost::Shutdown() {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationManagerHost::ShutdownOnIO, 
      base::Unretained(this)));
  shutdown_event_.Wait();
}

void ApplicationManagerHost::ShutdownOnIO() {
  if (application_manager_host_binding_.is_bound()) {
    application_manager_host_binding_.Close();
  }
  application_manager_client_interface_.reset();
  shutdown_event_.Signal();
}

common::mojom::ApplicationManagerClient* ApplicationManagerHost::GetApplicationManagerClientInterface() {
  return application_manager_client_interface_.get();
}

void ApplicationManagerHost::AddBinding(common::mojom::ApplicationManagerHostAssociatedRequest request) {
  application_manager_host_binding_.Bind(std::move(request));
}

void ApplicationManagerHost::ApplicationLaunch(common::mojom::ApplicationInstancePtr instance, ApplicationLaunchCallback cb) {
  HostThread::PostTask(HostThread::UI,
    FROM_HERE,
    base::Bind(&ApplicationManagerHost::LaunchApplicationImpl, 
      base::Unretained(this),
      base::Passed(std::move(instance)),
      base::Passed(std::move(cb))));
}

void ApplicationManagerHost::ApplicationTerminate(const std::string& scheme, int32_t id, ApplicationTerminateCallback cb) {
  HostThread::PostTask(HostThread::UI,
    FROM_HERE,
    base::Bind(&ApplicationManagerHost::TerminateApplicationImpl, 
      base::Unretained(this),
      scheme,
      id,
      base::Passed(std::move(cb))));
}

void ApplicationManagerHost::ApplicationActivate(const std::string& scheme, int32_t id, ApplicationActivateCallback cb) {
  HostThread::PostTask(HostThread::UI,
    FROM_HERE,
    base::Bind(&ApplicationManagerHost::ActivateApplicationImpl, 
      base::Unretained(this),
      scheme,
      id,
      base::Passed(std::move(cb))));
}

void ApplicationManagerHost::ApplicationClose(const std::string& scheme, int32_t id, ApplicationCloseCallback cb) {
  HostThread::PostTask(HostThread::UI,
    FROM_HERE,
    base::Bind(&ApplicationManagerHost::CloseApplicationImpl, 
      base::Unretained(this),
      scheme,
      id,
      base::Passed(std::move(cb))));
}

void ApplicationManagerHost::LaunchApplicationImpl(common::mojom::ApplicationInstancePtr instance, ApplicationLaunchCallback cb) {
  bool uuid_ok = false;
  std::string app_name = instance->name;
  GURL url = GURL(instance->url);
  bool headless = instance->headless;
  Dock::Type window_mode = static_cast<Dock::Type>(instance->window_mode);
  gfx::Rect initial_bounds = instance->initial_bounds;
  WindowOpenDisposition window_open_disposition = instance->window_open_disposition;
  bool fullscreen = instance->fullscreen;

  base::UUID app_uuid = base::UUID::from_string(instance->uuid, &uuid_ok);

  if (!uuid_ok) {
    DLOG(INFO) << "ApplicationManagerHost::ApplicationLaunch: uuid " << instance->uuid << " is not valid. cancelling";
    ReplyLaunchWithStatus(common::mojom::ApplicationStatus::kError, std::move(cb));
    return;
  }

  if (!url.is_valid()) {
    DLOG(INFO) << "ApplicationManagerHost::ApplicationLaunch: URL " << url << " is not valid. cancelling";
    ReplyLaunchWithStatus(common::mojom::ApplicationStatus::kError, std::move(cb));
    return;
  }

  application_controller_->LaunchApplicationAck(
    instance->id, 
    app_name, 
    url, 
    app_uuid, 
    window_mode,
    initial_bounds,
    window_open_disposition,
    fullscreen,
    headless,
    std::move(cb));
}

void ApplicationManagerHost::ActivateApplicationImpl(const std::string& scheme, int32_t id, ApplicationActivateCallback cb) {
  bool ok = application_controller_->ActivateApplication(scheme, id);
  if (!ok) {
    ReplyActivateWithStatus(common::mojom::ApplicationStatus::kError, std::move(cb));
    return;
  }
  ReplyActivateWithStatus(common::mojom::ApplicationStatus::kOk, std::move(cb));
}

void ApplicationManagerHost::TerminateApplicationImpl(const std::string& scheme, int32_t id, ApplicationTerminateCallback cb) {
  bool ok = application_controller_->TerminateApplication(scheme, id);
  if (!ok) {
    ReplyTerminateWithStatus(common::mojom::ApplicationStatus::kError, std::move(cb));
    return;
  }
  ReplyTerminateWithStatus(common::mojom::ApplicationStatus::kOk, std::move(cb));
}

void ApplicationManagerHost::CloseApplicationImpl(const std::string& scheme, int32_t id, ApplicationCloseCallback cb) {
  bool ok = application_controller_->CloseApplicationAck(scheme, id);
  if (!ok) {
    ReplyCloseWithStatus(common::mojom::ApplicationStatus::kError, std::move(cb));
    return;
  }
  ReplyCloseWithStatus(common::mojom::ApplicationStatus::kOk, std::move(cb));
}

void ApplicationManagerHost::ReplyLaunchWithStatus(common::mojom::ApplicationStatus status, ApplicationLaunchCallback cb) {
  HostThread::PostTask(HostThread::IO,
    FROM_HERE,
    base::BindOnce(std::move(cb), status)); 
}

void ApplicationManagerHost::ReplyActivateWithStatus(common::mojom::ApplicationStatus status, ApplicationActivateCallback cb) {
   HostThread::PostTask(HostThread::IO,
    FROM_HERE,
    base::BindOnce(std::move(cb), status)); 
}

void ApplicationManagerHost::ReplyTerminateWithStatus(common::mojom::ApplicationStatus status, ApplicationTerminateCallback cb) {
  HostThread::PostTask(HostThread::IO,
    FROM_HERE,
    base::BindOnce(std::move(cb), status)); 
}

void ApplicationManagerHost::ReplyCloseWithStatus(common::mojom::ApplicationStatus status, ApplicationCloseCallback cb) {
  HostThread::PostTask(HostThread::IO,
    FROM_HERE,
    base::BindOnce(std::move(cb), status)); 
}

}