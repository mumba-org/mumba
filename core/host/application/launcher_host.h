// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_LAUNCHER_HOST_H_
#define MUMBA_HOST_APPLICATION_LAUNCHER_HOST_H_

#include "base/macros.h"
#include "core/shared/common/mojom/launcher.mojom.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"

namespace host {

class LauncherHost : public common::mojom::LauncherHost {
public:
  LauncherHost();
  ~LauncherHost() override;
  
  common::mojom::LauncherClient* GetLauncherClientInterface();

  void AddBinding(common::mojom::LauncherHostAssociatedRequest request);

  void WindowLaunch(WindowLaunchCallback callback) override;
  void WindowClose(common::mojom::WindowHandlePtr window, WindowCloseCallback callback) override;
  void PageNew(common::mojom::WindowHandlePtr window, const std::string& url, PageNewCallback callback) override;
  void PageClose(common::mojom::PageHandlePtr page, PageCloseCallback callback) override;
  void PageList(common::mojom::WindowHandlePtr window, PageListCallback callback) override;

private:
  friend class DomainProcessHost;
  
  common::mojom::LauncherClientAssociatedPtr launcher_client_interface_;
  mojo::AssociatedBinding<common::mojom::LauncherHost> launcher_host_binding_;

  DISALLOW_COPY_AND_ASSIGN(LauncherHost);
};

}

#endif