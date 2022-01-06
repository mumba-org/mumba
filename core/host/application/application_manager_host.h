// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_MANAGER_HOST_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_MANAGER_HOST_H_

#include <string>
#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace host {
class DomainProcessHost;
class ApplicationController;

// Each shell process has a ApplicationManager ipc proxy
// that is able to launch applications at will
class ApplicationManagerHost : public common::mojom::ApplicationManagerHost {
public:
  ApplicationManagerHost(ApplicationController* application_controller);
  ~ApplicationManagerHost() override;

  common::mojom::ApplicationManagerClient* GetApplicationManagerClientInterface();

  void AddBinding(common::mojom::ApplicationManagerHostAssociatedRequest request);

  void ApplicationLaunch(common::mojom::ApplicationInstancePtr instance, ApplicationLaunchCallback cb) override;
  void ApplicationTerminate(const std::string& scheme, int32_t id, ApplicationTerminateCallback cb) override;
  void ApplicationActivate(const std::string& scheme, int32_t id, ApplicationActivateCallback cb) override;
  void ApplicationClose(const std::string& scheme, int32_t id, ApplicationCloseCallback cb) override;

  void Shutdown();
  
private:
  friend class DomainProcessHost;

  void ShutdownOnIO();

  void LaunchApplicationImpl(common::mojom::ApplicationInstancePtr instance, ApplicationLaunchCallback cb);
  void TerminateApplicationImpl(const std::string& scheme, int32_t id, ApplicationTerminateCallback cb);
  void ActivateApplicationImpl(const std::string& scheme, int32_t id, ApplicationActivateCallback cb);
  void CloseApplicationImpl(const std::string& scheme, int32_t id, ApplicationCloseCallback cb);
  
  void ReplyLaunchWithStatus(common::mojom::ApplicationStatus status, ApplicationLaunchCallback cb);
  void ReplyCloseWithStatus(common::mojom::ApplicationStatus status, ApplicationCloseCallback cb);
  void ReplyTerminateWithStatus(common::mojom::ApplicationStatus status, ApplicationTerminateCallback cb);
  void ReplyActivateWithStatus(common::mojom::ApplicationStatus status, ApplicationActivateCallback cb);

  mojo::AssociatedBinding<common::mojom::ApplicationManagerHost> application_manager_host_binding_;
  common::mojom::ApplicationManagerClientAssociatedPtr application_manager_client_interface_;
  ApplicationController* application_controller_;
  base::WaitableEvent shutdown_event_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationManagerHost);
};

}

#endif