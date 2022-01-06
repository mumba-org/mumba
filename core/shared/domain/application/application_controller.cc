// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/application/application_controller.h"

#include "core/shared/domain/application/application.h"
#include "core/shared/domain/application/application_instance.h"
#include "core/shared/common/mojom/application.mojom.h"

namespace domain {

ApplicationController::ApplicationController(Delegate* delegate):
  delegate_(delegate) {
}

ApplicationController::~ApplicationController() {

}

// in theory we are running launched by the handler in the application manager client
// so we dont need to worry about the thread we are in, if we are blocking something
// because the handler did dispatch this op into a secondary thread that can block
// without stopping the whole process.
int ApplicationController::CreateInstance(Application* caller, 
  int32_t id, 
  const std::string& url,
  WindowMode window_mode,
  gfx::Rect initial_bounds,
  ui::mojom::WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless) {
  
  ApplicationInstance* app_instance = delegate_->CreateApplicationInstance(
    caller, 
    id, 
    url, 
    window_mode, 
    initial_bounds, 
    window_open_disposition, 
    fullscreen, 
    headless);
  // //DLOG(INFO) << "ApplicationController::LaunchApplication: main_thread = " << main_thread; 
  common::mojom::ApplicationManagerHost* manager_host = delegate_->GetApplicationManagerHost();
  delegate_->GetIOTaskRunner()->PostTask(
     FROM_HERE,
     base::BindOnce(&ApplicationController::LaunchApplicationOnIO,
                    base::Unretained(this),
                    base::Unretained(app_instance),
                    base::Unretained(manager_host)));
  return app_instance->id();
}

void ApplicationController::CloseApplication(Application* caller, int id) {
  common::mojom::ApplicationManagerHost* manager_host = delegate_->GetApplicationManagerHost();
  delegate_->GetIOTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&ApplicationController::CloseApplicationOnIO,
                   base::Unretained(this),
                   base::Unretained(caller),
                   id,
                   base::Unretained(manager_host)));
}

void ApplicationController::KillApplication(Application* caller, int id) {
  common::mojom::ApplicationManagerHost* manager_host = delegate_->GetApplicationManagerHost();
  delegate_->GetIOTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&ApplicationController::KillApplicationOnIO,
                   base::Unretained(this),
                   base::Unretained(caller),
                   id,
                   base::Unretained(manager_host)));
}

void ApplicationController::ActivateApplication(Application* caller, int id) {
  common::mojom::ApplicationManagerHost* manager_host = delegate_->GetApplicationManagerHost();
  delegate_->GetIOTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&ApplicationController::ActivateApplicationOnIO,
                   base::Unretained(this),
                   base::Unretained(caller),
                   id,
                   base::Unretained(manager_host)));
}

void ApplicationController::LaunchApplicationOnIO(ApplicationInstance* app_instance, common::mojom::ApplicationManagerHost* manager_host) {
  common::mojom::ApplicationInstancePtr instance = common::mojom::ApplicationInstance::New();
  instance->id = app_instance->id();
  DCHECK(app_instance->application());  
  instance->name = app_instance->application()->name();
  instance->url = app_instance->url();
  instance->uuid = app_instance->uuid().to_string();
  instance->headless = app_instance->headless();
  instance->fullscreen = app_instance->fullscreen();
  instance->initial_bounds = app_instance->initial_bounds();
  instance->window_mode = static_cast<common::mojom::WindowMode>(app_instance->window_mode());
  instance->window_open_disposition = static_cast<WindowOpenDisposition>(app_instance->window_open_disposition());

  // NOTE: accessing manager_ here might cause concurrency issues..
  // we need a good locking mechanism to access manager in a multi-thread safe way
  // (or we could do this through 'domain context')
  DCHECK(manager_host);
  manager_host->ApplicationLaunch(
    std::move(instance), 
    base::Bind(&ApplicationController::OnLaunchApplicationReply,
      base::Unretained(this),
      base::Unretained(app_instance)));
}

void ApplicationController::KillApplicationOnIO(Application* caller, int id, common::mojom::ApplicationManagerHost* manager_host) {
  // NOTE: accessing manager_ here might cause concurrency issues..
  // we need a good locking mechanism to access manager in a multi-thread safe way
  // (or we could do this through 'domain context')
  DCHECK(manager_host);
  manager_host->ApplicationTerminate(
    caller->name(),
    id,
    base::Bind(&ApplicationController::OnKillApplicationReply,
      base::Unretained(this),
      base::Unretained(caller),
      id));
}

void ApplicationController::ActivateApplicationOnIO(Application* caller, int id, common::mojom::ApplicationManagerHost* manager_host) {
  DCHECK(manager_host);
  manager_host->ApplicationActivate(
    caller->name(),
    id,
    base::Bind(&ApplicationController::OnActivateApplicationReply,
      base::Unretained(this),
      base::Unretained(caller),
      id));
}

void ApplicationController::CloseApplicationOnIO(Application* caller, int id, common::mojom::ApplicationManagerHost* manager_host) {
  // NOTE: accessing manager_ here might cause concurrency issues..
  // we need a good locking mechanism to access manager in a multi-thread safe way
  // (or we could do this through 'domain context')
  DCHECK(manager_host);
  manager_host->ApplicationClose(
    caller->name(),
    id,
    base::Bind(&ApplicationController::OnCloseApplicationReply,
      base::Unretained(this),
      base::Unretained(caller),
      id));
}

void ApplicationController::OnLaunchApplicationReply(
  ApplicationInstance* app_instance,
  common::mojom::ApplicationStatus status) {
  //DLOG(INFO) << "ApplicationController::OnLaunchApplicationReply: OK ? " << (status == common::mojom::ApplicationStatus::kOk);
  if (status == common::mojom::ApplicationStatus::kOk) {
    delegate_->OnApplicationLaunched(app_instance->url(), app_instance);
  } else {
    delegate_->OnApplicationLaunchError(app_instance->url(), app_instance, -1);
  }
}

void ApplicationController::OnKillApplicationReply(Application* caller, int id, common::mojom::ApplicationStatus status) {
  if (status == common::mojom::ApplicationStatus::kOk) {
    delegate_->OnApplicationKilled(caller->name(), id, static_cast<int>(status));
  }
}

void ApplicationController::OnActivateApplicationReply(Application* caller, int id, common::mojom::ApplicationStatus status) {
  if (status == common::mojom::ApplicationStatus::kOk) {
    delegate_->OnApplicationActivated(caller->name(), id);
  }
}

void ApplicationController::OnCloseApplicationReply(Application* caller, int id, common::mojom::ApplicationStatus status) {
  if (status == common::mojom::ApplicationStatus::kOk) {
    delegate_->OnApplicationClosed(caller->name(), id, static_cast<int>(status));
  }
}

}