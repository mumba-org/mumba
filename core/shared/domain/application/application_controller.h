// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_APPLICATION_APPLICATION_CONTROLLER_H_
#define MUMBA_DOMAIN_APPLICATION_APPLICATION_CONTROLLER_H_

#include "base/macros.h"
#include "core/shared/domain/application/application_instance.h"
#include "core/shared/domain/application/window_instance.h"
#include "core/shared/common/content_export.h"

namespace domain {
class Application;

class CONTENT_EXPORT ApplicationController {
public:
  class CONTENT_EXPORT Delegate {
  public:
    virtual ~Delegate() {}
    virtual scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner() const = 0;
    virtual ApplicationInstance* CreateApplicationInstance(
      Application* parent, 
      int32_t id, 
      const std::string& url,
      WindowMode window_mode,
      gfx::Rect initial_bounds,
      ui::mojom::WindowOpenDisposition window_open_disposition,
      bool fullscreen,
      bool headless) = 0;
    virtual common::mojom::ApplicationManagerHost* GetApplicationManagerHost() = 0;
    virtual void OnApplicationLaunched(const std::string& url, ApplicationInstance* instance) = 0;
    virtual void OnApplicationClosed(const std::string& url, int id, int exit_code) = 0;
    virtual void OnApplicationKilled(const std::string& url, int id, int exit_code) = 0;
    virtual void OnApplicationActivated(const std::string& url, int id) = 0;
    virtual void OnApplicationLaunchError(const std::string& url, ApplicationInstance* instance, int err_code) = 0;
    virtual void OnApplicationRunError(const std::string& url, ApplicationInstance* instance, int err_code) = 0;
    virtual void OnWindowLaunched(const std::string& url, WindowInstance* instance) = 0;
    virtual void OnWindowKilled(const std::string& url, int id) = 0;
  };
  ApplicationController(Delegate* delegate);
  ~ApplicationController();

  int CreateInstance(Application* caller, 
                     int32_t id, 
                     const std::string& url,
                     WindowMode window_mode,
                     gfx::Rect initial_bounds,
                     ui::mojom::WindowOpenDisposition window_open_disposition,
                     bool fullscreen,
                     bool headless);
  void CloseApplication(Application* caller, int id);
  void KillApplication(Application* caller, int id);
  void ActivateApplication(Application* caller, int id);

private:

  void LaunchApplicationOnIO(ApplicationInstance* app_instance, common::mojom::ApplicationManagerHost* manager_host);
  void KillApplicationOnIO(Application* caller, int id, common::mojom::ApplicationManagerHost* manager_host);
  void ActivateApplicationOnIO(Application* caller, int id, common::mojom::ApplicationManagerHost* manager_host);
  void CloseApplicationOnIO(Application* caller, int id, common::mojom::ApplicationManagerHost* manager_host);

  void OnLaunchApplicationReply(ApplicationInstance* app_instance,
    common::mojom::ApplicationStatus status);
  void OnKillApplicationReply(Application* caller, int id, common::mojom::ApplicationStatus status);
  void OnActivateApplicationReply(Application* caller, int id, common::mojom::ApplicationStatus status);
  void OnCloseApplicationReply(Application* caller, int id, common::mojom::ApplicationStatus status);

  Delegate* delegate_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationController);
};

}

#endif