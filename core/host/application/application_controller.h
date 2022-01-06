// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_CONTROLLER_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_CONTROLLER_H_

#include "base/macros.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/host/application/domain.h"
#include "core/host/ui/dock.h"
#include "lib/url/gurl.h"
#include "ui/base/window_open_disposition.h"

using ApplicationReplyCallback = base::OnceCallback<void(::common::mojom::ApplicationStatus)>;

namespace host {
class Workspace;
class Volume;
class RunnableManager;

struct LaunchOptions {
  base::Callback<void(int)> user_callback;
  bool embedded_view = false;
  Dock::Type window_mode = Dock::TYPE_POPUP;
  gfx::Rect initial_bounds = gfx::Rect(0, 0, 800, 600);
  WindowOpenDisposition window_open_disposition = WindowOpenDisposition::NEW_WINDOW;
  bool fullscreen = false;
  bool headless = false;
};

// owned by Workspace
class ApplicationController : public Domain::Observer {
public:
  ApplicationController(scoped_refptr<Workspace> workspace);
  ~ApplicationController();

  const std::string& install_output() const {
    return install_output_;
  }

  void InstallApplication(const std::string& identifier, base::Callback<void(int)> callback);
  void LaunchApplication(const GURL& url, LaunchOptions options, base::Callback<void(int)> callback, int app_id = -1);
  bool ActivateApplication(const std::string& scheme, int app_id);
  bool TerminateApplication(const std::string& scheme, int app_id);
  void TerminateAllApplications(const std::string& scheme);
  bool CloseApplication(int app_id); 
  bool CloseApplicationAck(const std::string& scheme, int app_id); 
  // launching an app is a two-way request. The first one routes to the Domain
  // then if the Domain decides its ok to launch the given application, it ping back here
  // asking for the real launch
  void LaunchApplicationAck(
    int app_id,
    const std::string& app_name, 
    const GURL& app_url, 
    const base::UUID& app_uuid, 
    Dock::Type window_mode,
    gfx::Rect initial_bounds,
    WindowOpenDisposition window_open_disposition,
    bool fullscreen,
    bool headless,
    ApplicationReplyCallback cb);

private:

  struct PendingNotification {
    Application* target = nullptr;
    ApplicationReplyCallback callback;
    base::Callback<void(int)> user_callback;
  };

  void LaunchApplicationReply(const std::string& app_name, 
                              common::mojom::ApplicationStatus status, 
                              common::mojom::ApplicationInstancePtr instance);
  
  void InstallApplicationFromPath(const base::FilePath& path, base::Callback<void(int)> cb);
  void InstallApplicationFromDHTAddress(const std::string& dht_address, base::Callback<void(int)> cb);

  void AddPendingNotification(Application* app, ApplicationReplyCallback cb, base::Callback<void(int)> user_callback);
  void ProcessPendingNotification(Application* app, common::mojom::ApplicationStatus status);

  // Domain::Observer
  void OnApplicationInitialized(Domain* domain, Application* application) override;
  void OnApplicationLaunched(Domain* domain, Application* application) override;
  void OnApplicationShutdown(Domain* domain, Application* application) override;

  void OnInstallVolumeReply(base::Callback<void(int)> cb, std::pair<bool, Volume*> result);
  void CreateDomain(Volume* volume, base::Callback<void(int)> cb);
  void OnApplicationInstalled(base::Callback<void(int)> cb, int result);

  void SendCloseApplication(Domain* domain, int id);
  void CloseApplicationReply(common::mojom::ApplicationStatus status);

  scoped_refptr<Workspace> workspace_;
  RunnableManager* runnable_manager_;
  std::vector<std::unique_ptr<PendingNotification>> pending_notifications_;
  std::map<int, LaunchOptions> launch_options_;
  int pending_launches_;
  std::string install_output_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationController);
};

}

#endif
