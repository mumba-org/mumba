// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_APPLICATION_APPLICATION_MANAGER_CLIENT_H_
#define MUMBA_DOMAIN_APPLICATION_APPLICATION_MANAGER_CLIENT_H_

#include "base/macros.h"

#include "base/atomic_sequence_num.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {
class DomainContext;
class DomainMainThread;

class ApplicationManagerClient : public common::mojom::ApplicationManagerClient {
public:
  ApplicationManagerClient();
  ~ApplicationManagerClient() override;

  void Bind(common::mojom::ApplicationManagerClientAssociatedRequest request);

  void ClientApplicationGetIcon(const std::string& scheme, ClientApplicationGetIconCallback callback) override;
  void ClientApplicationGetState(const std::string& scheme, int32_t id, ClientApplicationGetStateCallback callback) override;
  void ClientApplicationLaunch(
    int32_t id, 
    const std::string& url, 
    int window_mode,
    const gfx::Rect& initial_bounds,
    WindowOpenDisposition window_open_disposition,
    bool fullscreen,
    bool headless,
    ClientApplicationLaunchCallback callback) override;
  void ClientApplicationClose(const std::string& scheme, int32_t id, ClientApplicationCloseCallback callback) override;
  void ClientApplicationActivate(const std::string& scheme, int32_t id, ClientApplicationActivateCallback callback) override;
  void ClientApplicationTerminate(const std::string& scheme, int32_t id, ClientApplicationTerminateCallback callback) override;
  void ClientRegisterApplications(std::vector<common::mojom::ApplicationInfoPtr> apps) override;

  common::mojom::ApplicationManagerHost* GetApplicationManagerHost();

private:
  friend class DomainMainThread;

  void ReplyApplicationLaunch(scoped_refptr<DomainContext> context, ClientApplicationLaunchCallback callback, int id);
  void ReplyApplicationClose(scoped_refptr<DomainContext> context, ClientApplicationCloseCallback callback, bool result);
  void ReplyApplicationTerminate(scoped_refptr<DomainContext> context, ClientApplicationTerminateCallback callback, bool result);
  void ReplyApplicationActivate(scoped_refptr<DomainContext> context, ClientApplicationActivateCallback callback, bool result);
  void ReplyGetApplicationIcon(ClientApplicationGetIconCallback callback, bool result);
  void ReplyGetApplicationState(ClientApplicationGetStateCallback callback, bool result);

  class Handler;

  mojo::AssociatedBinding<common::mojom::ApplicationManagerClient> binding_;

  // proxy to the host
  common::mojom::ApplicationManagerHostAssociatedPtr application_manager_host_;
  
  scoped_refptr<Handler> handler_;

  base::WeakPtrFactory<ApplicationManagerClient> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationManagerClient);
};


}

#endif