// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/application/application_manager_client.h"

#include "base/uuid.h"
#include "base/files/file_path.h"
#include "base/task_scheduler/post_task.h"
#include "core/domain/domain_process.h"
#include "core/domain/domain_context.h"
#include "core/domain/domain_main_thread.h"
#include "core/shared/domain/application/application.h"
#include "core/domain/application/application_manager.h"
#include "ipc/ipc_sync_channel.h"

namespace domain {

class ApplicationManagerClient::Handler : public base::RefCountedThreadSafe<Handler> {
public:
  Handler() {}

  int LaunchApplication(
    scoped_refptr<DomainContext> context, 
    int32_t id, 
    const std::string& url,
    int window_mode,
    const gfx::Rect& initial_bounds,
    WindowOpenDisposition window_open_disposition,
    bool fullscreen,
    bool headless) {
    //DLOG(INFO) << "LaunchApplication";
    ApplicationManager* manager = context->application_manager();
    DCHECK(manager);
    Application* app = manager->GetApplicationByUrl(url);
    if (!app) {
      //DLOG(ERROR) << "launching application " << url << " failed. not found/not registered";
      return false;
    }
    //DLOG(INFO) << "LaunchApplication: calling app->Launch()";
    return app->CreateInstance(
      id, 
      url, 
      static_cast<domain::WindowMode>(window_mode),
      initial_bounds,
      static_cast<ui::mojom::WindowOpenDisposition>(window_open_disposition),
      fullscreen,
      headless);
  }

  bool CloseApplication(scoped_refptr<DomainContext> context, const std::string& scheme, int32_t id) {
    //const std::string& name = handle->name;
    ApplicationManager* manager = context->application_manager();
    Application* app = manager->GetApplication(scheme);
    if (!app) {
      //DLOG(ERROR) << "CloseApplication: failed to close application id " << id;
      return false;
    }
    app->CloseInstance(id);
    return true;
  }

  bool ActivateApplication(scoped_refptr<DomainContext> context, const std::string& scheme, int32_t id) {
    ApplicationManager* manager = context->application_manager();
    Application* app = manager->GetApplication(scheme);
    if (!app) {
      //DLOG(ERROR) << "CloseApplication: failed to close application id " << id;
      return false;
    }
    app->ActivateInstance(id);
    return true;
  }

  bool KillApplication(scoped_refptr<DomainContext> context, const std::string& scheme, int32_t id) {
    //const std::string& name = handle->name;
    ApplicationManager* manager = context->application_manager();
    Application* app = manager->GetApplication(scheme);
    if (!app) {
      //DLOG(ERROR) << "KillApplication: failed to kill application " << id;
      return false;
    }
    app->KillInstance(id);
    return true;
  }

  void RegisterApplications(scoped_refptr<DomainContext> context, std::vector<common::mojom::ApplicationInfoPtr> apps) {
    ApplicationManager* manager = context->application_manager();
    for (auto it = apps.begin(); it != apps.end(); ++it) {
      bool uuid_ok = false;
      base::UUID uuid = base::UUID::from_string((*it)->uuid, &uuid_ok);
      if (!uuid_ok) {
        continue;
      }
      Application* app = manager->CreateApplication((*it)->name, uuid, GURL((*it)->url));
      //DLOG(INFO) << "RegisterApplications: registered application '" << app->name() << "'";
    }
  }

  bool GetApplicationState(scoped_refptr<DomainContext> context, const std::string& scheme, int id) {
    return false;
  }

  bool GetApplicationIcon(scoped_refptr<DomainContext> context, const std::string& scheme) {
    return false; 
  }

private:
  friend class base::RefCountedThreadSafe<Handler>;
  ~Handler() {}
};

ApplicationManagerClient::ApplicationManagerClient():
  binding_(this),
  handler_(new Handler()),
  weak_factory_(this) {}
 
ApplicationManagerClient::~ApplicationManagerClient() {}

void ApplicationManagerClient::Bind(common::mojom::ApplicationManagerClientAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

common::mojom::ApplicationManagerHost* ApplicationManagerClient::GetApplicationManagerHost() {
  if (!application_manager_host_) {
    DomainMainThread* thread = DomainMainThread::current();
    thread->GetChannel()->GetRemoteAssociatedInterface(&application_manager_host_);
  }
  return application_manager_host_.get();
}

void ApplicationManagerClient::ClientApplicationGetIcon(const std::string& scheme, ClientApplicationGetIconCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::GetApplicationIcon,
       handler_,
       main_thread->domain_context(),
       scheme),
     base::Bind(&ApplicationManagerClient::ReplyGetApplicationIcon,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ApplicationManagerClient::ClientApplicationGetState(const std::string& scheme, int32_t id, ClientApplicationGetStateCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::GetApplicationState,
       handler_,
       main_thread->domain_context(),
       scheme,
       id),
     base::Bind(&ApplicationManagerClient::ReplyGetApplicationState,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ApplicationManagerClient::ClientApplicationLaunch(
  int32_t id, 
  const std::string& url, 
  int window_mode,
  const gfx::Rect& initial_bounds,
  WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless,
  ClientApplicationLaunchCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::LaunchApplication,
       handler_,
       main_thread->domain_context(),
       id,
       url,
       window_mode,
       initial_bounds,
       window_open_disposition,
       fullscreen,
       headless),
     base::Bind(&ApplicationManagerClient::ReplyApplicationLaunch,
      weak_factory_.GetWeakPtr(),
      main_thread->domain_context(),
      base::Passed(std::move(callback))));
}

void ApplicationManagerClient::ClientApplicationTerminate(const std::string& scheme, int32_t id, ClientApplicationTerminateCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::KillApplication,
       handler_,
       main_thread->domain_context(),
       scheme,
       id),
     base::Bind(&ApplicationManagerClient::ReplyApplicationTerminate,
      weak_factory_.GetWeakPtr(),
      main_thread->domain_context(),
      base::Passed(std::move(callback))));
}

void ApplicationManagerClient::ClientApplicationActivate(const std::string& scheme, int32_t id, ClientApplicationActivateCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::ActivateApplication,
       handler_,
       main_thread->domain_context(),
       scheme,
       id),
     base::Bind(&ApplicationManagerClient::ReplyApplicationActivate,
      weak_factory_.GetWeakPtr(),
      main_thread->domain_context(),
      base::Passed(std::move(callback))));
}

void ApplicationManagerClient::ClientApplicationClose(const std::string& scheme, int32_t id, ClientApplicationCloseCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::CloseApplication,
       handler_,
       main_thread->domain_context(),
       scheme,
       id),
     base::Bind(&ApplicationManagerClient::ReplyApplicationClose,
      weak_factory_.GetWeakPtr(),
      main_thread->domain_context(),
      base::Passed(std::move(callback))));
}

void ApplicationManagerClient::ClientRegisterApplications(std::vector<common::mojom::ApplicationInfoPtr> apps) {
  DomainMainThread* main_thread = DomainMainThread::current();
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::MayBlock() },
     base::BindOnce(
       &Handler::RegisterApplications,
       handler_,
       main_thread->domain_context(),
       base::Passed(std::move(apps))));
}

void ApplicationManagerClient::ReplyApplicationLaunch(scoped_refptr<DomainContext> context, ClientApplicationLaunchCallback callback, int id) {
  //DLOG(INFO) << "ReplyApplicationLaunch: id = " << id;
  common::mojom::ApplicationInstancePtr instance = common::mojom::ApplicationInstance::New();
  instance->id = id;
  std::move(callback).Run(common::mojom::ApplicationStatus::kOk, std::move(instance));    
}

void ApplicationManagerClient::ReplyApplicationTerminate(scoped_refptr<DomainContext> context, ClientApplicationTerminateCallback callback, bool result) {
  std::move(callback).Run(result ? common::mojom::ApplicationStatus::kOk : common::mojom::ApplicationStatus::kError);
}

void ApplicationManagerClient::ReplyApplicationClose(scoped_refptr<DomainContext> context, ClientApplicationCloseCallback callback, bool result) {
  std::move(callback).Run(result ? common::mojom::ApplicationStatus::kOk : common::mojom::ApplicationStatus::kError);
}

void ApplicationManagerClient::ReplyApplicationActivate(scoped_refptr<DomainContext> context, ClientApplicationActivateCallback callback, bool result) {
  std::move(callback).Run(result ? common::mojom::ApplicationStatus::kOk : common::mojom::ApplicationStatus::kError);
}

void ApplicationManagerClient::ReplyGetApplicationIcon(ClientApplicationGetIconCallback callback, bool result) {

}

void ApplicationManagerClient::ReplyGetApplicationState(ClientApplicationGetStateCallback callback, bool result) {

}

}